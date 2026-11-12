// Headless end-to-end check of the defended RP crypto: emulates a WebAuthn authenticator and
// a browser DPoP key in Node, then runs three scenarios against a running victim RP (PORT 1421):
//   1. Legit     -> login finishes and /api/me with a matching DPoP proof returns the user.
//   2. Relay     -> attacker finishes with the victim's DPoP *public* key; token mints but
//                   /api/me with the attacker's own proof is refused (inert session).
//   3. Substitute-> attacker swaps in its own DPoP key at finish; login finish is rejected.
// Start the RP first:  ROLE=victim PORT=1421 node server.mjs
import { webcrypto as wc, createHash, randomBytes } from 'node:crypto';
const subtle = wc.subtle;
const ORIGIN = process.env.VICTIM_ORIGIN || 'http://localhost:1421';
const RP_ID = new URL(ORIGIN).hostname;
const b64url = (b) => Buffer.from(b).toString('base64url');
const sha256 = (b) => createHash('sha256').update(b).digest();
const post = async (p, body) => (await fetch(ORIGIN + p, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body || {}) })).json();

function rawToDer(raw) {
  const trim = (b) => { let i = 0; while (i < b.length - 1 && b[i] === 0) i++; b = b.subarray(i); if (b[0] & 0x80) b = Buffer.concat([Buffer.from([0]), b]); return b; };
  const r = trim(Buffer.from(raw.subarray(0, 32))), s = trim(Buffer.from(raw.subarray(32, 64)));
  return Buffer.concat([Buffer.from([0x30, 2 + r.length + 2 + s.length, 0x02, r.length]), r, Buffer.from([0x02, s.length]), s]);
}
async function newDpop() {
  const pair = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign']);
  const jwk = await subtle.exportKey('jwk', pair.publicKey); delete jwk.key_ops; delete jwk.ext;
  const jkt = b64url(sha256(Buffer.from(`{"crv":"${jwk.crv}","kty":"${jwk.kty}","x":"${jwk.x}","y":"${jwk.y}"}`)));
  const proof = async (htm, htu) => {
    const h = b64url(Buffer.from(JSON.stringify({ typ: 'dpop+jwt', alg: 'ES256', jwk })));
    const c = b64url(Buffer.from(JSON.stringify({ htm, htu, iat: Math.floor(Date.now() / 1000), jti: b64url(randomBytes(16)) })));
    const sig = await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, pair.privateKey, Buffer.from(h + '.' + c));
    return h + '.' + c + '.' + b64url(new Uint8Array(sig));
  };
  return { jwk, jkt, proof };
}
async function newAuthenticator() {
  const pair = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const spki = b64url(await subtle.exportKey('spki', pair.publicKey));
  const credId = b64url(randomBytes(16));
  const assert = async (boundChallengeB64) => {
    const clientDataJSON = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge: boundChallengeB64, origin: ORIGIN, crossOrigin: false }));
    const authData = Buffer.concat([sha256(Buffer.from(RP_ID)), Buffer.from([0x05]), Buffer.from([0, 0, 0, 1])]);
    const raw = new Uint8Array(await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, pair.privateKey, Buffer.concat([authData, sha256(clientDataJSON)])));
    return { id: credId, rawId: credId, type: 'public-key', response: { clientDataJSON: b64url(clientDataJSON), authenticatorData: b64url(authData), signature: b64url(rawToDer(raw)), userHandle: null } };
  };
  return { credId, spki, assert };
}
const bind = (nonce, jkt) => b64url(sha256(Buffer.from(nonce + '.' + jkt)));
const line = (ok, msg) => console.log(`${ok ? 'PASS' : 'FAIL'}  ${msg}`);
let failed = 0; const check = (ok, msg) => { if (!ok) failed++; line(ok, msg); };

async function main() {
  // Enroll one victim with a DPoP-bound passkey.
  const victimDpop = await newDpop();
  const auth = await newAuthenticator();
  const rs = await post('/register/start', { username: 'alice' });
  const regChallengeBound = bind(rs.challenge, victimDpop.jkt); // provider folds jkt into reg challenge too
  void regChallengeBound; // registration here stores the pubkey via getPublicKey(); challenge not re-checked
  const rf = await post('/register/finish', { userId: rs.user.id, credential: { id: auth.credId, rawId: auth.credId, type: 'public-key', publicKeySpki: auth.spki, publicKeyAlgorithm: -7 } });
  check(rf.ok, 'enroll: register/finish accepted the credential');

  // 1) Legit login.
  {
    const start = await post('/login/start', {});
    const assertion = await auth.assert(bind(start.challenge, victimDpop.jkt));
    const fin = await post('/login/finish', { assertion, dpopPublicJwk: victimDpop.jwk });
    check(fin.ok && fin.token, '1 legit: login/finish minted a token');
    const htu = ORIGIN + '/api/me';
    const r = await fetch(htu, { headers: { authorization: 'DPoP ' + fin.token, dpop: await victimDpop.proof('GET', htu) } });
    const me = await r.json();
    check(r.ok && me.username === 'alice' && me.jkt === victimDpop.jkt, '1 legit: /api/me returns alice with a matching DPoP proof');
  }

  // 2) Relay: attacker starts the ceremony, victim signs it, attacker finishes with victim's
  //    PUBLIC key, then tries the token with its OWN proof.
  {
    const start = await post('/login/start', {});                 // attacker's nonce
    const assertion = await auth.assert(bind(start.challenge, victimDpop.jkt)); // victim signs (jkt = victim)
    const fin = await post('/login/finish', { assertion, dpopPublicJwk: victimDpop.jwk });
    check(fin.ok && fin.token, '2 relay: token still mints (the ceremony itself is not blocked)');
    const attacker = await newDpop();
    const htu = ORIGIN + '/api/me';
    const r = await fetch(htu, { headers: { authorization: 'DPoP ' + fin.token, dpop: await attacker.proof('GET', htu) } });
    check(r.status === 401, '2 relay: /api/me rejects the attacker proof (session is inert)  -> ' + (await r.json()).error);
    const r2 = await fetch(htu, { headers: { authorization: 'DPoP ' + fin.token } }); // no proof
    check(r2.status === 401, '2 relay: /api/me rejects a bare bearer token (no DPoP proof)');
  }

  // 3) Key substitution: attacker tries to bind the session to ITS key at finish.
  {
    const start = await post('/login/start', {});
    const assertion = await auth.assert(bind(start.challenge, victimDpop.jkt)); // signed challenge commits to victim jkt
    const attacker = await newDpop();
    const fin = await post('/login/finish', { assertion, dpopPublicJwk: attacker.jwk }); // swap key
    check(!fin.ok, '3 substitute: login/finish rejects a mismatched DPoP key  -> ' + fin.error);
  }

  console.log(failed ? `\n${failed} check(s) FAILED` : '\nAll checks passed');
  process.exit(failed ? 1 : 0);
}
main().catch((e) => { console.error(e); process.exit(1); });
