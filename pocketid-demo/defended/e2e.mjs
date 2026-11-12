// Headless end-to-end check of the passkey-bound RP: emulates WebAuthn authenticators in Node
// and runs three scenarios against a running victim RP (PORT 1421):
//   1. Legit  -> login + a fresh passkey proof unlock /api/me.
//   2. Relay  -> attacker finishes the login (token mints) but /api/me is refused: no proof,
//                because the attacker has no authenticator and the key never left the victim.
//   3. Forged -> even a VALID passkey proof from the attacker's OWN credential is refused for
//                the victim's session (bound to a different credential).
// Start the RP first:  ROLE=victim PORT=1421 node server.mjs
import { webcrypto as wc, createHash, randomBytes } from 'node:crypto';
const subtle = wc.subtle;
const ORIGIN = process.env.VICTIM_ORIGIN || 'http://localhost:1421';
const RP_ID = new URL(ORIGIN).hostname;
const HTU = ORIGIN + '/api/me';
const b64url = (b) => Buffer.from(b).toString('base64url');
const sha256 = (b) => createHash('sha256').update(b).digest();
const post = async (p, body) => (await fetch(ORIGIN + p, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body || {}) })).json();

function rawToDer(raw) {
  const trim = (b) => { let i = 0; while (i < b.length - 1 && b[i] === 0) i++; b = b.subarray(i); if (b[0] & 0x80) b = Buffer.concat([Buffer.from([0]), b]); return b; };
  const r = trim(Buffer.from(raw.subarray(0, 32))), s = trim(Buffer.from(raw.subarray(32, 64)));
  return Buffer.concat([Buffer.from([0x30, 2 + r.length + 2 + s.length, 0x02, r.length]), r, Buffer.from([0x02, s.length]), s]);
}
async function newAuthenticator() {
  const pair = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const spki = b64url(await subtle.exportKey('spki', pair.publicKey));
  const credId = b64url(randomBytes(16));
  // Sign a clientData whose challenge is the given base64url value (login nonce or pop challenge).
  const assert = async (challengeB64) => {
    const clientDataJSON = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge: challengeB64, origin: ORIGIN, crossOrigin: false }));
    const authData = Buffer.concat([sha256(Buffer.from(RP_ID)), Buffer.from([0x05]), Buffer.from([0, 0, 0, 1])]);
    const raw = new Uint8Array(await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, pair.privateKey, Buffer.concat([authData, sha256(clientDataJSON)])));
    return { id: credId, rawId: credId, type: 'public-key', response: { clientDataJSON: b64url(clientDataJSON), authenticatorData: b64url(authData), signature: b64url(rawToDer(raw)), userHandle: null } };
  };
  return { credId, spki, assert };
}
async function enroll(username, auth) {
  const rs = await post('/register/start', { username });
  const rf = await post('/register/finish', { userId: rs.user.id, credential: { id: auth.credId, rawId: auth.credId, type: 'public-key', publicKeySpki: auth.spki, publicKeyAlgorithm: -7 } });
  return rf.ok;
}
// Build a proof-of-possession for GET /api/me with a given authenticator.
async function popProof(auth) {
  const { nonce } = await post('/api/pop-challenge', {});
  const challenge = b64url(sha256(Buffer.from('GET ' + HTU + ' ' + nonce)));
  return b64url(Buffer.from(JSON.stringify(await auth.assert(challenge))));
}
const getMe = (token, proofB64) => fetch(HTU, { headers: { authorization: 'Passkey ' + token, ...(proofB64 ? { 'x-passkey-proof': proofB64 } : {}) } });

let failed = 0; const check = (ok, msg) => { if (!ok) failed++; console.log(`${ok ? 'PASS' : 'FAIL'}  ${msg}`); };

async function main() {
  const victim = await newAuthenticator();
  check(await enroll('alice', victim), 'enroll: register/finish accepted the passkey');

  // 1) Legit: login, then unlock /api/me with a fresh proof.
  {
    const start = await post('/login/start', {});
    const fin = await post('/login/finish', { assertion: await victim.assert(start.challenge) });
    check(fin.ok && fin.token, '1 legit: login/finish minted a passkey-bound token');
    const r = await getMe(fin.token, await popProof(victim));
    const me = await r.json();
    check(r.ok && me.username === 'alice', '1 legit: /api/me returns alice with a fresh passkey proof');
  }

  // 2) Relay: attacker finishes the login, but cannot produce a proof.
  {
    const start = await post('/login/start', {});              // attacker's nonce
    const fin = await post('/login/finish', { assertion: await victim.assert(start.challenge) }); // victim signs
    check(fin.ok && fin.token, '2 relay: token still mints (the ceremony is not blocked)');
    const r = await getMe(fin.token, null);                    // no proof: attacker has none
    check(r.status === 401, '2 relay: /api/me refuses the token without a passkey proof  -> ' + (await r.json()).error);
  }

  // 3) Forged: a valid proof from the attacker's OWN passkey does not unlock the victim session.
  {
    const start = await post('/login/start', {});
    const fin = await post('/login/finish', { assertion: await victim.assert(start.challenge) }); // victim session
    const attacker = await newAuthenticator();
    await enroll('mallory', attacker);                          // attacker enrolls its own passkey
    const r = await getMe(fin.token, await popProof(attacker)); // valid proof, wrong credential
    check(r.status === 401, '3 forged: a proof from a different passkey is refused  -> ' + (await r.json()).error);
  }

  console.log(failed ? `\n${failed} check(s) FAILED` : '\nAll checks passed');
  process.exit(failed ? 1 : 0);
}
main().catch((e) => { console.error(e); process.exit(1); });
