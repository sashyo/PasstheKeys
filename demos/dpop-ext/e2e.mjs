// Headless model of the `dpop` extension: emulates an extended authenticator in Node and runs
// the scenarios against a running victim RP (PORT 1521).
//   1. Legit  -> login names SK in the signed authData; /api/me unlocks with an SK proof.
//   2. Relay  -> attacker finishes the relayed login (token mints, bound to the victim's SK) but
//                /api/me is refused: SK is sealed in the victim's authenticator.
//   3. Substitute -> attacker cannot make the victim's authenticator name a key it holds; a
//                self-made assertion carrying the attacker's SK is rejected (unknown credential).
// Start the RP first:  ROLE=victim PORT=1521 node server.mjs
import { webcrypto as wc, createHash, randomBytes } from 'node:crypto';
const subtle = wc.subtle;
// ORIGIN is what the RP pins (the WebAuthn clientData origin, RP_ID and htu). BASE is only where we
// connect: loopback, so this works even where Node's DNS does not resolve *.localhost names.
const ORIGIN = process.env.VICTIM_ORIGIN || 'http://victim.localhost:1521';
const BASE = process.env.VICTIM_BASE || `http://127.0.0.1:${new URL(ORIGIN).port || 1521}`;
const RP_ID = new URL(ORIGIN).hostname;
const HTU = ORIGIN + '/api/me';
const b64url = (b) => Buffer.from(b).toString('base64url');
const sha256 = (b) => createHash('sha256').update(b).digest();
const post = async (p, body) => (await fetch(BASE + p, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body || {}) })).json();

const genKey = () => subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
const rawPub = async (k) => Buffer.from(await subtle.exportKey('raw', k.publicKey));
const sign = async (priv, data) => Buffer.from(new Uint8Array(await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, priv, data)));

// A proof assertion signed by SK over a given challenge (no SK_pub in authData).
async function skProof(skPriv, challengeB64) {
  const clientDataJSON = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge: challengeB64, origin: ORIGIN }));
  const authData = Buffer.concat([sha256(Buffer.from(RP_ID)), Buffer.from([0x01]), Buffer.from([0, 0, 0, 1])]);
  const signature = await sign(skPriv, Buffer.concat([authData, sha256(clientDataJSON)]));
  return { type: 'public-key', response: { clientDataJSON: b64url(clientDataJSON), authenticatorData: b64url(authData), signature: b64url(signature), userHandle: null } };
}

// An emulated extended authenticator holding one identity credential.
async function newAuthenticator() {
  const cred = await genKey();
  const credId = b64url(randomBytes(16));
  const pub = await rawPub(cred);
  // Login assertion with the dpop extension: generate SK, name SK_pub in the signed authData.
  const loginAssert = async (challengeB64) => {
    const sk = await genKey();
    const skPub = await rawPub(sk);
    const clientDataJSON = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge: challengeB64, origin: ORIGIN }));
    const authData = Buffer.concat([sha256(Buffer.from(RP_ID)), Buffer.from([0x81]), Buffer.from([0, 0, 0, 1]), skPub]); // 0x80 dpop | 0x01 up
    const signature = await sign(cred.privateKey, Buffer.concat([authData, sha256(clientDataJSON)]));
    const jkt = b64url(sha256(skPub));
    // Standard WebAuthn assertion: SK_pub rides only in the SIGNED authenticatorData; the
    // response carries no jkt echo (clientExtensionResults stays empty).
    const assertion = {
      id: credId, rawId: credId, type: 'public-key',
      response: { clientDataJSON: b64url(clientDataJSON), authenticatorData: b64url(authData), signature: b64url(signature), userHandle: null },
      clientExtensionResults: {},
    };
    return { assertion, jkt, proof: (ch) => skProof(sk.privateKey, ch) };
  };
  return { credId, pub, loginAssert };
}
async function enroll(username, auth) {
  const rb = await post('/register/begin', { username });
  return (await post('/register/finish', { userId: rb.publicKey.user.id, credId: auth.credId, publicKey: b64url(auth.pub), passkeyToken: rb.passkeyToken })).ok;
}
async function popProof(session) {
  const { nonce } = await post('/api/pop-challenge', {});
  const proof = await session.proof(b64url(sha256(Buffer.from('GET ' + HTU + ' ' + nonce))));
  return b64url(Buffer.from(JSON.stringify(proof)));
}
const getMe = (token, proofB64) => fetch(BASE + '/api/me', { headers: { authorization: 'Passkey ' + token, ...(proofB64 ? { 'x-dpop-proof': proofB64 } : {}) } });

let failed = 0; const check = (ok, msg) => { if (!ok) failed++; console.log(`${ok ? 'PASS' : 'FAIL'}  ${msg}`); };

async function main() {
  const victim = await newAuthenticator();
  check(await enroll('alice', victim), 'enroll: register/finish accepted the credential');

  // 1) Legit
  {
    const begin = await post('/login/begin', {});
    const s = await victim.loginAssert(begin.publicKey.challenge);
    const fin = await post('/login/finish', { assertion: s.assertion, passkeyToken: begin.passkeyToken });
    check(fin.ok && fin.token && fin.jkt === s.jkt, '1 legit: finish bound the session to the signed SK (jkt matches)');
    const r = await getMe(fin.token, await popProof(s));
    const me = await r.json();
    check(r.ok && me.username === 'alice', '1 legit: /api/me unlocks with an SK proof');
  }

  // 2) Relay: attacker finishes, but SK is sealed in the victim's authenticator.
  {
    const begin = await post('/login/begin', {});                 // attacker's ceremony
    const s = await victim.loginAssert(begin.publicKey.challenge); // victim signs; names victim SK
    const fin = await post('/login/finish', { assertion: s.assertion, passkeyToken: begin.passkeyToken });
    check(fin.ok && fin.token, '2 relay: token mints (bound to the victim SK)');
    const r1 = await getMe(fin.token, null);
    check(r1.status === 401, '2 relay: /api/me refuses with no proof  -> ' + (await r1.json()).error);
    // attacker tries a proof from its OWN fresh SK
    const evil = await newAuthenticator();
    const es = await evil.loginAssert('x');
    const r2 = await getMe(fin.token, await popProof(es));
    check(r2.status === 401, '2 relay: a proof from the attacker SK is refused  -> ' + (await r2.json()).error);
  }

  // 3) Substitution: attacker cannot make the victim's session bind to a key it holds.
  {
    const begin = await post('/login/begin', {});
    const evil = await newAuthenticator();                        // attacker's own (unregistered) authenticator
    const es = await evil.loginAssert(begin.publicKey.challenge); // carries the attacker's SK, signed by attacker cred
    const fin = await post('/login/finish', { assertion: es.assertion, passkeyToken: begin.passkeyToken });
    check(!fin.ok, '3 substitute: assertion carrying the attacker SK is rejected  -> ' + fin.error);
  }

  console.log(failed ? `\n${failed} check(s) FAILED` : '\nAll checks passed');
  process.exit(failed ? 1 : 0);
}
main().catch((e) => { console.error(e); process.exit(1); });
