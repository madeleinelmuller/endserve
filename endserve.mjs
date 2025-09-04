#!/usr/bin/env node
import fs from 'fs';
import path from 'path';
import { pathToFileURL } from 'url';
import express from 'express';
import cookieParser from 'cookie-parser';
import helmet from 'helmet';
import { createProxyMiddleware } from 'http-proxy-middleware';
import rateLimit from 'express-rate-limit';
import readline from 'readline/promises';
import { stdin as input, stdout as output } from 'process';

// Tiny argument parser --------------------------------------------------------
function parseArgs(argv) {
  const args = { proxy: [] };
  for (let i = 0; i < argv.length; i++) {
    let a = argv[i];
    if (!a.startsWith('--')) {
      (args._ ||= []).push(a);
      continue;
    }
    a = a.slice(2);
    let [key, val] = a.split('=');
    if (val === undefined) {
      if (i + 1 < argv.length && !argv[i + 1].startsWith('--')) {
        val = argv[++i];
      } else {
        val = true;
      }
    }
    key === 'proxy' ? args.proxy.push(val) : (args[key] = val);
  }
  return args;
}

// Setup subcommand ------------------------------------------------------------
async function runSetup() {
  const rl = readline.createInterface({ input, output });
  const ask = async (q, d) => {
    const a = (await rl.question(q)).trim();
    return a || d;
  };
  const site = await ask('Site directory (default ./public): ', './public');
  const index = await ask('Index file (default index.html): ', 'index.html');
  const port = parseInt(await ask('Port (default 8080): ', '8080'), 10) || 8080;
  const auth = await ask('Username:Password for login (empty for none): ', '');
  const ratelimit =
    parseInt(await ask('Rate limit per minute (default 120): ', '120'), 10) ||
    120;
  const proxyStr = await ask(
    'Proxy mappings (comma-separated mount=target): ',
    ''
  );
  rl.close();
  const config = {
    site,
    index,
    port,
    auth: auth || undefined,
    ratelimit,
    proxy: proxyStr
      ? proxyStr
          .split(',')
          .map((s) => s.trim())
          .filter(Boolean)
      : [],
  };
  await fs.promises.writeFile(
    '.endserve.json',
    JSON.stringify(config, null, 2)
  );
  console.log('Saved config to .endserve.json');
  console.log('Next: node endserve.mjs --use-config');
}

// Server ---------------------------------------------------------------------
async function runServer(args) {
  let fileConfig = {};
  if (args.useConfig) {
    try {
      fileConfig = JSON.parse(fs.readFileSync('.endserve.json', 'utf8'));
    } catch {
      console.warn('Warning: .endserve.json not found or invalid.');
    }
  }

  const proxyStrings = [
    ...(fileConfig.proxy || []),
    ...(args.proxy || []),
  ];
  const site = args.site ?? fileConfig.site;
  const index = args.index ?? fileConfig.index ?? 'index.html';
  const port = parseInt(args.port ?? fileConfig.port ?? 8080, 10);
  const auth = args.auth ?? fileConfig.auth;
  const basicAuth = args.basicAuth ?? fileConfig.basicAuth;
  const ratelimit = parseInt(
    args.ratelimit ?? fileConfig.ratelimit ?? 120,
    10
  );
  const handler = args.handler ?? fileConfig.handler;
  const handlerMount = args.handlerMount ?? fileConfig.handlerMount ?? '/api';
  const cookieName = args.cookie ?? fileConfig.cookie ?? 'endserve_session';
  const prod =
    args.prod || fileConfig.prod || process.env.NODE_ENV === 'production';

  const app = express();
  app.use(helmet({ contentSecurityPolicy: false }));
  if (auth) app.use(cookieParser());

  // Basic Auth ---------------------------------------------------------------
  if (basicAuth) {
    const [bu, bp] = basicAuth.split(':');
    app.use((req, res, next) => {
      const hdr = req.headers.authorization || '';
      const token = hdr.split(' ')[1] || '';
      const [u, p] = Buffer.from(token, 'base64').toString().split(':');
      if (u === bu && p === bp) return next();
      res.set('WWW-Authenticate', 'Basic realm="Restricted"');
      return res.status(401).send('Authentication required.');
    });
  }

  // Cookie Auth --------------------------------------------------------------
  let authUser, authPass;
  const cookieOpts = {
    httpOnly: true,
    sameSite: 'lax',
    secure: !!prod,
    maxAge: 6 * 60 * 60 * 1000,
  };
  if (auth) [authUser, authPass] = auth.split(':');

  function requireCookieAuth(req, res, next) {
    if (!auth) return next();
    if (req.cookies[cookieName] === 'ok') return next();
    if (req.method === 'GET' && req.path === '/') return res.redirect('/login');
    return res.status(401).send('Unauthorized');
  }

  if (auth) {
    app.get('/login', (req, res) => {
      if (req.cookies[cookieName] === 'ok') return res.redirect('/');
      res.send(
        `<!DOCTYPE html><html><body><h2>Login</h2><form method="POST"><div><input name="username" placeholder="Username"/></div><div><input type="password" name="password" placeholder="Password"/></div><button type="submit">Login</button></form></body></html>`
      );
    });
    app.post(
      '/login',
      express.urlencoded({ extended: false }),
      (req, res) => {
        const { username, password } = req.body || {};
        if (username === authUser && password === authPass) {
          res.cookie(cookieName, 'ok', cookieOpts);
          return res.redirect('/');
        }
        res.send('Invalid credentials');
      }
    );
    app.get('/logout', (req, res) => {
      res.clearCookie(cookieName, { ...cookieOpts, maxAge: 0 });
      res.redirect('/login');
    });
  }

  // Rate limiter -------------------------------------------------------------
  const apiLimiter = rateLimit({ windowMs: 60 * 1000, max: ratelimit });

  // Proxies ------------------------------------------------------------------
  const proxyMiddlewares = [];
  proxyStrings.forEach((pstr) => {
    const [mount, target] = pstr.split('=');
    if (mount && target) {
      const proxy = createProxyMiddleware({
        target,
        ws: true,
        changeOrigin: false,
      });
      app.use(mount, requireCookieAuth, apiLimiter, proxy);
      proxyMiddlewares.push({ mount, proxy });
      console.log(`Proxy: ${mount} -> ${target}`);
    }
  });

  // Handler ------------------------------------------------------------------
  if (handler) {
    const resolved = path.isAbsolute(handler)
      ? handler
      : path.join(process.cwd(), handler);
    if (!fs.existsSync(resolved)) {
      console.error('Handler file not found:', resolved);
    } else {
      app.use(handlerMount, requireCookieAuth, apiLimiter);
      const mod = (await import(pathToFileURL(resolved).href)).default;
      await mod(app, { mount: handlerMount });
      console.log(`Handler: ${resolved} mounted at ${handlerMount}`);
    }
  }

  // Static site or placeholder ----------------------------------------------
  if (site) {
    const resolvedSite = path.isAbsolute(site)
      ? site
      : path.join(process.cwd(), site);
    if (!fs.existsSync(resolvedSite)) {
      console.error('Error: --site folder not found:', resolvedSite);
      process.exit(1);
    }
    app.use('/', requireCookieAuth, express.static(resolvedSite, { index }));
    console.log(`Static site: ${resolvedSite} (index: ${index})`);
  } else {
    app.get('/', requireCookieAuth, (req, res) => {
      res.send(
        `<!DOCTYPE html><html><body><h1>endserve</h1><p>No static site configured.</p><p>Try your proxied routes or custom handler.</p><p><a href="/logout">Logout</a></p></body></html>`
      );
    });
  }

  // Start server -------------------------------------------------------------
  const server = app.listen(port, () => {
    console.log(`Listening on http://localhost:${port}`);
    if (basicAuth) console.log('Basic Auth enabled');
    if (auth) console.log('Cookie login enabled');
    if (!basicAuth && !auth) console.log('No authentication');
  });

  // WebSocket upgrades -------------------------------------------------------
  server.on('upgrade', (req, socket, head) => {
    for (const { mount, proxy } of proxyMiddlewares) {
      if (req.url.startsWith(mount)) return proxy.upgrade(req, socket, head);
    }
  });
}

// Entrypoint -----------------------------------------------------------------
(async () => {
  const argv = process.argv.slice(2);
  if (argv[0] === 'setup') {
    await runSetup();
    return;
  }
  const args = parseArgs(argv);
  await runServer(args);
})();

/* USAGE

Install deps:
  npm init -y
  npm i express cookie-parser helmet http-proxy-middleware express-rate-limit

Serve a site with LM Studio proxy and login:
  node endserve.mjs --site=./public --proxy="/v1=http://127.0.0.1:1234" --auth "maddie:S3riousPass" --port=8080

Guided setup:
  node endserve.mjs setup
  node endserve.mjs --use-config

Custom handler example (myhandler.mjs):
  export default function(app, { mount }) {
    app.get(`${mount}/hello`, (req, res) => res.json({ hi: 'there' }));
  }
  node endserve.mjs --handler=./myhandler.mjs --handlerMount=/api

Basic Auth wall example:
  node endserve.mjs --site=./public --basicAuth "user:pass"

Expose via ngrok:
  ngrok http http://localhost:8080

Cookies are HttpOnly, SameSite=Lax, and Secure when --prod or NODE_ENV=production.
Keep LM Studio bound to 127.0.0.1 and use proxies instead of exposing it directly.

*/
