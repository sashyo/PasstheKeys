// Defended relying party: a self-contained, zero-dependency WebAuthn RP that sender-constrains
// its sessions to a browser-held DPoP key (see public/passkey-provider.js for the client half).
//
// It runs in the same two roles as the attack demo so the EXISTING relay can be pointed at it:
//   ROLE=victim   PORT=1421  Acme (defended): /login + enrollment, the RP, the resource server.
//   ROLE=attacker PORT=1423  the attacker's site + dead-drop + /api proxy to the victim RP.
//
// The payoff: the relay still completes the WebAuthn ceremony and the attacker mints a REAL
// session token for the victim -- and it is inert, because the token is bound to the victim's
// DPoP jkt and every resource call requires a DPoP proof the attacker cannot produce.
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
const RP_HOST = new URL(VICTIM_ORIGIN).host;               // where the victim RP really listens
const RP_ID = new URL(VICTIM_ORIGIN).hostname;             // WebAuthn rpId
const __dirname = path.dirname(fileURLToPath(import.meta.url));

// ---------- tiny codecs / crypto helpers --------------------------------------
const b64url = (buf) => Buffer.from(buf).toString('base64url');
const fromB64url = (s) => Buffer.from(s, 'base64url');
const sha256 = (buf) => createHash('sha256').update(buf).digest();

// DER-encoded ECDSA (SEQUENCE{INTEGER r, INTEGER s}) -> raw 64-byte r||s for P-256.
function derToRawEcdsa(der) {
  let o = 0;
  if (der[o++] !== 0x30) throw new Error('bad der');
  if (der[o] & 0x80) o += (der[o] & 0x7f) + 1; else o++;        // skip SEQUENCE length
  const readInt = () => {
    if (der[o++] !== 0x02) throw new Error('bad der int');
    let len = der[o++]; let v = der.subarray(o, o + len); o += len;
    while (v.length > 32 && v[0] === 0x00) v = v.subarray(1);    // strip sign padding
    const out = Buffer.alloc(32); v.copy(out, 32 - v.length);    // left-pad to 32
    return out;
  };
  return Buffer.concat([readInt(), readInt()]);
}

async function importEcVerifyKeySpki(spki) {
  return subtle.importKey('spki', spki, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
}
async function importEcVerifyKeyJwk(jwk) {
  return subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
}
async function jwkThumbprint(jwk) {
  const canon = `{"crv":"${jwk.crv}","kty":"${jwk.kty}","x":"${jwk.x}","y":"${jwk.y}"}`;
  return b64url(sha256(Buffer.from(canon)));
}

// ---------- in-memory state (disposable) --------------------------------------
const users = new Map();        // userId -> { userId, username, displayName }
const credsById = new Map();    // credId(b64url) -> { userId, spki(Buffer), alg }
const liveNonces = new Map();   // nonce(b64url) -> issuedAt  (one-time, short-lived)
const sessions = new Map();     // token -> { userId, jkt, at }
const seenJti = new Map();      // jti -> exp  (DPoP replay cache)

const now = () => Date.now();
setInterval(() => {
  const t = now();
  for (const [n, at] of liveNonces) if (t - at > 120000) liveNonces.delete(n);
  for (const [j, exp] of seenJti) if (t > exp) seenJti.delete(j);
}, 30000).unref();

// ---------- http plumbing -----------------------------------------------------
const json = (res, code, body, extra = {}) => {
  res.writeHead(code, { 'content-type': 'application/json', 'cache-control': 'no-store', ...extra });
  res.end(JSON.stringify(body));
};
const readBody = (req) => new Promise((r) => { let d = ''; req.on('data', (c) => (d += c)); req.on('end', () => r(d)); });
async function serveFile(res, file, type = 'text/html; charset=utf-8') {
  try { res.writeHead(200, { 'content-type': type, 'cache-control': 'no-store' }); res.end(await readFile(path.join(__dirname, 'public', file))); }
  catch { json(res, 404, { error: 'not found' }); }
}
const cors = (res) => {
  res.setHeader('access-control-allow-origin', VICTIM_ORIGIN);
  res.setHeader('access-control-allow-methods', 'GET,POST,OPTIONS');
  res.setHeader('access-control-allow-headers', 'content-type,authorization,dpop');
};

// Attacker-side reverse proxy to the victim RP, rewriting Host/Origin so the RP validates
// the relayed calls as if they came from the victim origin (mirrors the attack demo's proxy).
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

// ---------- DPoP proof verification (RFC 9449, ES256 only) ---------------------
async function verifyDpopProof(proof, { htm, htu, expectedJkt }) {
  if (!proof) return { ok: false, why: 'missing DPoP proof' };
  const parts = proof.split('.');
  if (parts.length !== 3) return { ok: false, why: 'malformed proof' };
  let header, claims;
  try { header = JSON.parse(fromB64url(parts[0])); claims = JSON.parse(fromB64url(parts[1])); }
  catch { return { ok: false, why: 'unparseable proof' }; }
  if (header.typ !== 'dpop+jwt' || header.alg !== 'ES256' || !header.jwk) return { ok: false, why: 'bad header' };
  const jkt = await jwkThumbprint(header.jwk);
  if (expectedJkt && jkt !== expectedJkt) return { ok: false, why: 'proof key is not the bound key' };
  if (claims.htm !== htm || claims.htu !== htu) return { ok: false, why: 'htm/htu mismatch' };
  if (Math.abs(Math.floor(now() / 1000) - (claims.iat || 0)) > 60) return { ok: false, why: 'stale proof' };
  if (!claims.jti || seenJti.has(claims.jti)) return { ok: false, why: 'replayed proof' };
  const key = await importEcVerifyKeyJwk(header.jwk);
  const ok = await subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key,
    fromB64url(parts[2]), Buffer.from(parts[0] + '.' + parts[1]));
  if (!ok) return { ok: false, why: 'bad proof signature' };
  seenJti.set(claims.jti, now() + 120000);
  return { ok: true, jkt };
}

// ---------- WebAuthn assertion verification -----------------------------------
async function verifyAssertion({ assertion, dpopPublicJwk }) {
  const cred = credsById.get(assertion.rawId);
  if (!cred) return { ok: false, why: 'unknown credential' };
  if (cred.alg !== -7) return { ok: false, why: 'only ES256 credentials in this PoC' };

  const clientDataJSON = fromB64url(assertion.response.clientDataJSON);
  let cData; try { cData = JSON.parse(clientDataJSON.toString('utf8')); } catch { return { ok: false, why: 'bad clientData' }; }
  if (cData.type !== 'webauthn.get') return { ok: false, why: 'wrong clientData type' };
  if (cData.origin !== VICTIM_ORIGIN) return { ok: false, why: `origin ${cData.origin}` };

  // The binding check: the signed challenge must equal SHA256(ourNonce + "." + jkt) for the
  // DPoP key we were handed, AND ourNonce must be a live, unspent nonce we issued.
  const jkt = await jwkThumbprint(dpopPublicJwk);
  let matchedNonce = null;
  for (const nonce of liveNonces.keys()) {
    if (b64url(sha256(Buffer.from(nonce + '.' + jkt))) === cData.challenge) { matchedNonce = nonce; break; }
  }
  if (!matchedNonce) return { ok: false, why: 'challenge not bound to this DPoP key (or nonce expired/spent)' };

  const authData = fromB64url(assertion.response.authenticatorData);
  if (!sha256(Buffer.from(RP_ID)).equals(authData.subarray(0, 32))) return { ok: false, why: 'rpIdHash mismatch' };
  if (!(authData[32] & 0x01)) return { ok: false, why: 'user-present flag not set' };

  const signed = Buffer.concat([authData, sha256(clientDataJSON)]);
  const rawSig = derToRawEcdsa(fromB64url(assertion.response.signature));
  const key = await importEcVerifyKeySpki(cred.spki);
  const ok = await subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, rawSig, signed);
  if (!ok) return { ok: false, why: 'bad assertion signature' };

  liveNonces.delete(matchedNonce); // one-time
  return { ok: true, userId: cred.userId, jkt };
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
    const challenge = b64url(randomBytes(32)); liveNonces.set(challenge, now());
    return json(res, 200, {
      challenge, rp: { id: RP_ID, name: 'Acme Workspace (defended)' },
      user: { id: userId, name: b.username, displayName: b.displayName || b.username },
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
      // Usernameless login sends an empty allowCredentials, so the passkey must be discoverable.
      authenticatorSelection: { residentKey: 'required', requireResidentKey: true, userVerification: 'required' },
    });
  }
  if (pth === '/register/finish' && req.method === 'POST') {
    const b = JSON.parse((await readBody(req)) || '{}');
    const c = b.credential;
    if (!c || c.publicKeyAlgorithm !== -7) return json(res, 400, { ok: false, error: 'need an ES256 credential' });
    if (!users.has(b.userId)) return json(res, 400, { ok: false, error: 'unknown user' });
    credsById.set(c.rawId, { userId: b.userId, spki: fromB64url(c.publicKeySpki), alg: c.publicKeyAlgorithm });
    return json(res, 200, { ok: true });
  }

  if (pth === '/login/start' && req.method === 'POST') {
    const challenge = b64url(randomBytes(32)); liveNonces.set(challenge, now());
    return json(res, 200, { challenge, rpId: RP_ID });
  }
  if (pth === '/login/finish' && req.method === 'POST') {
    const b = JSON.parse((await readBody(req)) || '{}');
    if (!b.assertion || !b.dpopPublicJwk) return json(res, 400, { ok: false, error: 'assertion and dpopPublicJwk required' });
    let v; try { v = await verifyAssertion(b); } catch (e) { return json(res, 400, { ok: false, error: e.message }); }
    if (!v.ok) return json(res, 401, { ok: false, error: v.why });
    const token = b64url(randomBytes(24));
    sessions.set(token, { userId: v.userId, jkt: v.jkt, at: now() });
    // Note: finish intentionally does NOT demand possession here. The binding is cryptographic
    // (the signed challenge committed to jkt), and enforcement happens at the resource below.
    return json(res, 200, { ok: true, token, token_type: 'DPoP' });
  }

  // Resource server: sender-constrained. Needs `Authorization: DPoP <token>` AND a fresh
  // `DPoP:` proof whose key thumbprint equals the token's bound jkt.
  if (pth === '/api/me') {
    const auth = req.headers['authorization'] || '';
    const m = /^DPoP (.+)$/.exec(auth);
    const sess = m && sessions.get(m[1]);
    if (!sess) return json(res, 401, { error: 'no DPoP-bound session token' });
    const htu = VICTIM_ORIGIN + '/api/me';
    const pv = await verifyDpopProof(req.headers['dpop'], { htm: req.method, htu, expectedJkt: sess.jkt });
    if (!pv.ok) return json(res, 401, { error: 'DPoP proof rejected: ' + pv.why });
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
    drops.push({ assertion: b.assertion, dpopPublicJwk: b.dpopPublicJwk || null, at: now() }); cors(res); return json(res, 200, { ok: true });
  }
  if (pth === '/x/assertion' && req.method === 'GET') { cors(res); return json(res, 200, drops.shift() || {}); }
  if (pth === '/x/reset' && req.method === 'POST') { offer = null; drops.length = 0; cors(res); return json(res, 200, { ok: true }); }
  cors(res); return json(res, 404, { error: 'not found' });
}

server.listen(PORT, () => console.log(`defended ${ROLE} on http://localhost:${PORT}  (RP ${VICTIM_ORIGIN})`));
