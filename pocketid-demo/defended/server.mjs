// Defended relying party: passkey-bound sessions. The sender-constraining key is the passkey
// credential ITSELF (held in the authenticator), not a key generated in the page. A session is
// bound to the public key of the credential that signed the login, and exercising the session
// requires a fresh WebAuthn proof-of-possession assertion for each request. Nothing the page's
// JavaScript can read or choose binds the session, so a page running attacker code cannot
// substitute or exfiltrate the binding key.
//
// Runs in the same two roles as the attack demo so the EXISTING relay can be pointed at it:
//   ROLE=victim   PORT=1421  Acme (defended): /login + enrollment, the RP, the resource server.
//   ROLE=attacker PORT=1423  the attacker's site + dead-drop + /api proxy to the victim RP.
//
// The payoff: the relay still completes the login ceremony and the attacker mints a REAL session
// token for the victim -- and it is inert, because /api/me needs a passkey proof the attacker's
// machine cannot produce (no authenticator) and the victim's page cannot hand over (the key
// never leaves the authenticator).
//
// Authorized demo use only: your own machine and disposable test users.
import http from 'node:http';
import { readFile } from 'node:fs/promises';
import { webcrypto as wc, createHash, randomBytes } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const subtle = wc.subtle;
const ROLE = process.env.ROLE === 'attacker' ? 'attacker' : 'victim';
const PORT = Number(process.env.PORT || (ROLE === 'attacker' ? 1423 : 1421));
const VICTIM_ORIGIN = process.env.VICTIM_ORIGIN || 'http://localhost:1421';
const RP_HOST = new URL(VICTIM_ORIGIN).host;
const RP_ID = new URL(VICTIM_ORIGIN).hostname;
const __dirname = path.dirname(fileURLToPath(import.meta.url));

// ---------- codecs / crypto helpers -------------------------------------------
const b64url = (buf) => Buffer.from(buf).toString('base64url');
const fromB64url = (s) => Buffer.from(s, 'base64url');
const sha256 = (buf) => createHash('sha256').update(buf).digest();

function derToRawEcdsa(der) {
  let o = 0;
  if (der[o++] !== 0x30) throw new Error('bad der');
  if (der[o] & 0x80) o += (der[o] & 0x7f) + 1; else o++;
  const readInt = () => {
    if (der[o++] !== 0x02) throw new Error('bad der int');
    let len = der[o++]; let v = der.subarray(o, o + len); o += len;
    while (v.length > 32 && v[0] === 0x00) v = v.subarray(1);
    const out = Buffer.alloc(32); v.copy(out, 32 - v.length);
    return out;
  };
  return Buffer.concat([readInt(), readInt()]);
}
async function importEcVerifyKeySpki(spki) {
  return subtle.importKey('spki', spki, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify']);
}
// RFC 7638 thumbprint of a credential's EC public key (for display + session matching).
async function credThumbprint(spkiBuf) {
  const key = await importEcVerifyKeySpki(spkiBuf);
  const jwk = await subtle.exportKey('jwk', key);
  return b64url(sha256(Buffer.from(`{"crv":"${jwk.crv}","kty":"${jwk.kty}","x":"${jwk.x}","y":"${jwk.y}"}`)));
}

// ---------- in-memory state (disposable) --------------------------------------
const users = new Map();        // userId -> { userId, username, displayName }
const credsById = new Map();    // credId(b64url) -> { userId, spki(Buffer), alg, jkt }
const loginNonces = new Map();  // nonce -> issuedAt  (login ceremony, one-time)
const popNonces = new Map();    // nonce -> issuedAt  (per-request proof, one-time)
const sessions = new Map();     // token -> { userId, credId, jkt, at }

const now = () => Date.now();
setInterval(() => {
  const t = now();
  for (const m of [loginNonces, popNonces]) for (const [n, at] of m) if (t - at > 120000) m.delete(n);
}, 30000).unref();

// ---------- http plumbing -----------------------------------------------------
const json = (res, code, body) => { res.writeHead(code, { 'content-type': 'application/json', 'cache-control': 'no-store' }); res.end(JSON.stringify(body)); };
const readBody = (req) => new Promise((r) => { let d = ''; req.on('data', (c) => (d += c)); req.on('end', () => r(d)); });
async function serveFile(res, file, type = 'text/html; charset=utf-8') {
  try { res.writeHead(200, { 'content-type': type, 'cache-control': 'no-store' }); res.end(await readFile(path.join(__dirname, 'public', file))); }
  catch { json(res, 404, { error: 'not found' }); }
}
const cors = (res) => {
  res.setHeader('access-control-allow-origin', VICTIM_ORIGIN);
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

// ---------- WebAuthn assertion verification -----------------------------------
// Verifies the signature over `expectedChallenge` by a known credential; returns the credId.
async function verifyAssertion(assertion, expectedChallenge, { requireCredId } = {}) {
  const cred = credsById.get(assertion.rawId);
  if (!cred) return { ok: false, why: 'unknown credential' };
  if (requireCredId && assertion.rawId !== requireCredId) return { ok: false, why: 'wrong credential for this session' };
  if (cred.alg !== -7) return { ok: false, why: 'only ES256 credentials in this PoC' };

  const clientDataJSON = fromB64url(assertion.response.clientDataJSON);
  let cData; try { cData = JSON.parse(clientDataJSON.toString('utf8')); } catch { return { ok: false, why: 'bad clientData' }; }
  if (cData.type !== 'webauthn.get') return { ok: false, why: 'wrong clientData type' };
  if (cData.origin !== VICTIM_ORIGIN) return { ok: false, why: `origin ${cData.origin}` };
  if (cData.challenge !== expectedChallenge) return { ok: false, why: 'challenge mismatch' };

  const authData = fromB64url(assertion.response.authenticatorData);
  if (!sha256(Buffer.from(RP_ID)).equals(authData.subarray(0, 32))) return { ok: false, why: 'rpIdHash mismatch' };
  if (!(authData[32] & 0x01)) return { ok: false, why: 'user-present flag not set' };

  const signed = Buffer.concat([authData, sha256(clientDataJSON)]);
  const rawSig = derToRawEcdsa(fromB64url(assertion.response.signature));
  const key = await importEcVerifyKeySpki(cred.spki);
  const ok = await subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, rawSig, signed);
  if (!ok) return { ok: false, why: 'bad signature' };
  return { ok: true, cred };
}

// ---------- server ------------------------------------------------------------
const server = http.createServer(async (req, res) => {
  const pth = new URL(req.url, 'http://localhost').pathname;

  if (ROLE === 'attacker') {
    if (req.method === 'OPTIONS' && pth.startsWith('/x/')) { cors(res); res.writeHead(204); return res.end(); }
    if (pth === '/' || pth === '/attacker') return serveFile(res, 'attacker.html');
    if (pth === '/passkey-provider.js') return serveFile(res, 'passkey-provider.js', 'text/javascript');
    if (pth.startsWith('/x/')) return deadDrop(req, res, pth);
    return proxy(req, res); // /login/*, /api/* -> victim RP (Host/Origin rewritten)
  }

  // ---- victim RP ----
  if (pth === '/') { res.writeHead(302, { location: '/login' }); return res.end(); }
  if (pth === '/login') return serveFile(res, 'login.html');
  if (pth === '/passkey-provider.js') return serveFile(res, 'passkey-provider.js', 'text/javascript');

  if (pth === '/register/start' && req.method === 'POST') {
    const b = JSON.parse((await readBody(req)) || '{}');
    if (!b.username) return json(res, 400, { error: 'username required' });
    const userId = b64url(sha256(Buffer.from('u:' + b.username))).slice(0, 22);
    users.set(userId, { userId, username: b.username, displayName: b.displayName || b.username });
    const challenge = b64url(randomBytes(32)); loginNonces.set(challenge, now());
    return json(res, 200, {
      challenge, rp: { id: RP_ID, name: 'Acme Workspace (defended)' },
      user: { id: userId, name: b.username, displayName: b.displayName || b.username },
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
      authenticatorSelection: { residentKey: 'required', requireResidentKey: true, userVerification: 'required' },
    });
  }
  if (pth === '/register/finish' && req.method === 'POST') {
    const b = JSON.parse((await readBody(req)) || '{}');
    const c = b.credential;
    if (!c || c.publicKeyAlgorithm !== -7) return json(res, 400, { ok: false, error: 'need an ES256 credential' });
    if (!users.has(b.userId)) return json(res, 400, { ok: false, error: 'unknown user' });
    const spki = fromB64url(c.publicKeySpki);
    credsById.set(c.rawId, { userId: b.userId, spki, alg: c.publicKeyAlgorithm, jkt: await credThumbprint(spki) });
    return json(res, 200, { ok: true });
  }

  if (pth === '/login/start' && req.method === 'POST') {
    const challenge = b64url(randomBytes(32)); loginNonces.set(challenge, now());
    return json(res, 200, { challenge, rpId: RP_ID });
  }
  if (pth === '/login/finish' && req.method === 'POST') {
    const b = JSON.parse((await readBody(req)) || '{}');
    if (!b.assertion) return json(res, 400, { ok: false, error: 'assertion required' });
    const challenge = (() => { try { return JSON.parse(fromB64url(b.assertion.response.clientDataJSON)).challenge; } catch { return null; } })();
    if (!challenge || !loginNonces.has(challenge)) return json(res, 401, { ok: false, error: 'unknown or expired challenge' });
    let v; try { v = await verifyAssertion(b.assertion, challenge); } catch (e) { return json(res, 400, { ok: false, error: e.message }); }
    if (!v.ok) return json(res, 401, { ok: false, error: v.why });
    loginNonces.delete(challenge);
    const token = b64url(randomBytes(24));
    // Bind the session to the credential that actually signed. The page supplies no key.
    sessions.set(token, { userId: v.cred.userId, credId: b.assertion.rawId, jkt: v.cred.jkt, at: now() });
    return json(res, 200, { ok: true, token, token_type: 'Passkey' });
  }

  // Per-request proof-of-possession nonce.
  if (pth === '/api/pop-challenge' && req.method === 'POST') {
    const nonce = b64url(randomBytes(32)); popNonces.set(nonce, now());
    return json(res, 200, { nonce });
  }

  // Resource server: passkey-bound. Needs `Authorization: Passkey <token>` AND a fresh WebAuthn
  // proof assertion (header `X-Passkey-Proof`) signed by the credential the session is bound to,
  // over SHA256("GET <htu> <nonce>").
  if (pth === '/api/me') {
    const auth = req.headers['authorization'] || '';
    const m = /^Passkey (.+)$/.exec(auth);
    const sess = m && sessions.get(m[1]);
    if (!sess) return json(res, 401, { error: 'no passkey-bound session token' });
    const proofHdr = req.headers['x-passkey-proof'];
    if (!proofHdr) return json(res, 401, { error: 'missing passkey proof (this session needs a fresh authenticator assertion per request)' });
    let proof; try { proof = JSON.parse(fromB64url(String(proofHdr)).toString('utf8')); } catch { return json(res, 400, { error: 'unparseable proof' }); }
    const htu = VICTIM_ORIGIN + '/api/me';
    // The signed challenge must match one of our live pop nonces, bound to method + htu.
    let matched = null;
    const cd = (() => { try { return JSON.parse(fromB64url(proof.response.clientDataJSON)); } catch { return null; } })();
    if (cd) for (const nonce of popNonces.keys()) {
      if (b64url(sha256(Buffer.from('GET ' + htu + ' ' + nonce))) === cd.challenge) { matched = nonce; break; }
    }
    if (!matched) return json(res, 401, { error: 'proof not bound to this request (or nonce expired/spent)' });
    let v; try { v = await verifyAssertion(proof, cd.challenge, { requireCredId: sess.credId }); } catch (e) { return json(res, 400, { error: e.message }); }
    if (!v.ok) return json(res, 401, { error: 'proof rejected: ' + v.why });
    popNonces.delete(matched);
    const u = users.get(sess.userId) || {};
    return json(res, 200, { userId: sess.userId, username: u.username, displayName: u.displayName, jkt: sess.jkt });
  }

  return json(res, 404, { error: 'not found' });
});

// ---- attacker dead-drop (same shape as the attack demo) ----------------------
let offer = null; const drops = [];
async function deadDrop(req, res, pth) {
  if (pth === '/x/offer' && req.method === 'POST') {
    const b = JSON.parse((await readBody(req)) || '{}'); if (!b.challenge) return json(res, 400, { error: 'no challenge' });
    offer = { challenge: b.challenge, rpId: b.rpId || RP_ID, at: now() }; cors(res); return json(res, 200, { ok: true });
  }
  if (pth === '/x/offer' && req.method === 'GET') { cors(res); return json(res, 200, offer || {}); }
  if (pth === '/x/assertion' && req.method === 'POST') {
    const b = JSON.parse((await readBody(req)) || '{}'); if (!b.assertion) return json(res, 400, { error: 'no assertion' });
    drops.push({ assertion: b.assertion, at: now() }); cors(res); return json(res, 200, { ok: true });
  }
  if (pth === '/x/assertion' && req.method === 'GET') { cors(res); return json(res, 200, drops.shift() || {}); }
  if (pth === '/x/reset' && req.method === 'POST') { offer = null; drops.length = 0; cors(res); return json(res, 200, { ok: true }); }
  cors(res); return json(res, 404, { error: 'not found' });
}

server.listen(PORT, () => console.log(`defended ${ROLE} on http://localhost:${PORT}  (RP ${VICTIM_ORIGIN})`));
