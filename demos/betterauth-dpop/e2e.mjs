// Headless model of the Better Auth `dpop` plugin. No HTTP server and no browser: it drives the
// Better Auth instance via auth.handler() with an authenticator emulated in Node, for BOTH toggle
// modes.
//   enforce=false (exploit): a relayed assertion mints a session that /dpop/me accepts -> TAKEOVER.
//   enforce=true  (fix):     the session is dpop-bound; /dpop/me needs an SK proof the attacker
//                            cannot produce -> the relayed session is INERT.
import { betterAuth } from 'better-auth';
import { memoryAdapter } from 'better-auth/adapters/memory';
import { dpop } from './dpop-plugin.mjs';
import { webcrypto as wc, createHash, randomBytes } from 'node:crypto';

const subtle = wc.subtle;
const ORIGIN = 'http://victim.localhost:5411';
const RP_ID = 'victim.localhost';
const HTU = ORIGIN + '/api/auth/dpop/me';
const b64url = (b) => Buffer.from(b).toString('base64url');
const sha256 = (b) => createHash('sha256').update(b).digest();

const makeAuth = (enforce) => betterAuth({
  database: memoryAdapter({ user: [], session: [], account: [], verification: [] }),
  secret: 'passthekeys-demo-secret-passthekeys-demo-0123456789',
  baseURL: ORIGIN,
  emailAndPassword: { enabled: true },
  trustedOrigins: [ORIGIN],
  plugins: [dpop({ enforce, origin: ORIGIN })],
});

// A tiny client with a cookie jar, hitting the instance through auth.handler().
function client(auth) {
  const jar = new Map();
  const cookieHeader = () => [...jar].map(([k, v]) => `${k}=${v}`).join('; ');
  const absorb = (res) => { for (const sc of res.headers.getSetCookie?.() || []) { const [kv] = sc.split(';'); const i = kv.indexOf('='); jar.set(kv.slice(0, i), kv.slice(i + 1)); } };
  const call = async (path, { method = 'GET', body, headers = {} } = {}) => {
    const h = { origin: ORIGIN, ...headers };
    if (body !== undefined) h['content-type'] = 'application/json';
    if (jar.size) h.cookie = cookieHeader();
    const res = await auth.handler(new Request(ORIGIN + '/api/auth' + path, { method, headers: h, body: body !== undefined ? JSON.stringify(body) : undefined }));
    absorb(res);
    const text = await res.text();
    let json = null; try { json = JSON.parse(text); } catch {}
    return { status: res.status, json, text };
  };
  return { call, jar };
}

const genKey = () => subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
const rawPub = async (k) => Buffer.from(await subtle.exportKey('raw', k.publicKey));
const sign = async (priv, data) => Buffer.from(new Uint8Array(await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, priv, data)));

// Emulated extended authenticator: one identity credential; each login mints a fresh SK and names
// SK_pub in the SIGNED authenticatorData (dpop bit 0x80).
async function newAuthenticator() {
  const cred = await genKey();
  const credId = b64url(randomBytes(16));
  const pub = await rawPub(cred);
  const clientData = (challenge) => Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge, origin: ORIGIN }));
  const loginAssert = async (challenge) => {
    const sk = await genKey();
    const skPub = await rawPub(sk);
    const cd = clientData(challenge);
    const authData = Buffer.concat([sha256(Buffer.from(RP_ID)), Buffer.from([0x81]), Buffer.from([0, 0, 0, 1]), skPub]);
    const signature = await sign(cred.privateKey, Buffer.concat([authData, sha256(cd)]));
    const assertion = { id: credId, rawId: credId, type: 'public-key', clientExtensionResults: {}, response: { clientDataJSON: b64url(cd), authenticatorData: b64url(authData), signature: b64url(signature), userHandle: null } };
    const proof = async (ch) => {
      const pcd = clientData(ch);
      const pad = Buffer.concat([sha256(Buffer.from(RP_ID)), Buffer.from([0x01]), Buffer.from([0, 0, 0, 1])]);
      const psig = await sign(sk.privateKey, Buffer.concat([pad, sha256(pcd)]));
      return { type: 'public-key', response: { clientDataJSON: b64url(pcd), authenticatorData: b64url(pad), signature: b64url(psig), userHandle: null } };
    };
    return { assertion, jkt: b64url(sha256(skPub)), proof };
  };
  return { credId, pub, loginAssert };
}

let failed = 0; const check = (ok, msg) => { if (!ok) failed++; console.log(`${ok ? 'PASS' : 'FAIL'}  ${msg}`); };

async function enroll(c, auth, username, authn) {
  const begin = (await c.call('/dpop/register/begin', { method: 'POST', body: { username } })).json;
  const fin = await c.call('/dpop/register/finish', { method: 'POST', body: { userId: begin.publicKey.user.id, credId: authn.credId, publicKey: b64url(authn.pub), passkeyToken: begin.passkeyToken } });
  return fin.json?.ok;
}
async function popProof(c, session) {
  const { nonce } = (await c.call('/dpop/pop-challenge', { method: 'POST' })).json;
  const proof = await session.proof(b64url(sha256(Buffer.from('GET ' + HTU + ' ' + nonce))));
  return b64url(Buffer.from(JSON.stringify(proof)));
}

async function runFix() {
  console.log('\n== enforce = true (fix) ==');
  const auth = makeAuth(true);
  const victim = await newAuthenticator();
  const legit = client(auth);
  check(await enroll(legit, auth, 'alice', victim), 'enroll: credential registered');

  // 1) Legit: the real user signs in and uses the token with a proof.
  const begin = (await legit.call('/dpop/login/begin', { method: 'POST' })).json;
  const s = await victim.loginAssert(begin.publicKey.challenge);
  const fin = await legit.call('/dpop/login/finish', { method: 'POST', body: { assertion: s.assertion, passkeyToken: begin.passkeyToken } });
  check(fin.json?.ok && fin.json.enforced && fin.json.jkt === s.jkt, '1 legit: session bound to the signed SK (jkt matches)');
  const me = await legit.call('/dpop/me', { headers: { 'x-dpop-proof': await popProof(legit, s) } });
  check(me.status === 200 && me.json.username === 'alice', '1 legit: /dpop/me unlocks with an SK proof');

  // 2) Relay: attacker finishes the victim's relayed assertion in its OWN cookie jar.
  const attacker = client(auth);
  const ab = (await attacker.call('/dpop/login/begin', { method: 'POST' })).json;    // attacker's ceremony
  const as = await victim.loginAssert(ab.publicKey.challenge);                        // victim signs it
  const af = await attacker.call('/dpop/login/finish', { method: 'POST', body: { assertion: as.assertion, passkeyToken: ab.passkeyToken } });
  check(af.json?.ok, '2 relay: attacker mints a Better Auth session');
  const r1 = await attacker.call('/dpop/me');                                         // no proof
  check(r1.status === 401, '2 relay: /dpop/me refuses with no proof  -> ' + r1.json?.error);
  const evil = await newAuthenticator();
  const es = await evil.loginAssert('x');
  const r2 = await attacker.call('/dpop/me', { headers: { 'x-dpop-proof': await popProof(attacker, es) } });
  check(r2.status === 401, '2 relay: a proof from the attacker SK is refused  -> ' + r2.json?.error);

  // 3) Substitution: attacker's own (unregistered) authenticator naming its SK is rejected.
  const sb = (await attacker.call('/dpop/login/begin', { method: 'POST' })).json;
  const ev2 = await newAuthenticator();
  const evAssert = await ev2.loginAssert(sb.publicKey.challenge);
  const sf = await attacker.call('/dpop/login/finish', { method: 'POST', body: { assertion: evAssert.assertion, passkeyToken: sb.passkeyToken } });
  check(sf.json?.ok === false, '3 substitute: assertion carrying the attacker SK is rejected  -> ' + sf.json?.error);
}

async function runExploit() {
  console.log('\n== enforce = false (exploit) ==');
  const auth = makeAuth(false);
  const victim = await newAuthenticator();
  const legit = client(auth);
  await enroll(legit, auth, 'bob', victim);
  const attacker = client(auth);
  const ab = (await attacker.call('/dpop/login/begin', { method: 'POST' })).json;
  const as = await victim.loginAssert(ab.publicKey.challenge);
  const af = await attacker.call('/dpop/login/finish', { method: 'POST', body: { assertion: as.assertion, passkeyToken: ab.passkeyToken } });
  check(af.json?.ok, 'exploit: attacker mints a session from the relayed assertion');
  const me = await attacker.call('/dpop/me');                                         // no proof needed
  check(me.status === 200 && me.json.username === 'bob', 'exploit: attacker lands in the victim account (TAKEOVER)');
}

async function main() {
  await runFix();
  await runExploit();
  console.log(failed ? `\n${failed} check(s) FAILED` : '\nAll checks passed');
  process.exit(failed ? 1 : 0);
}
main().catch((e) => { console.error(e); process.exit(1); });
