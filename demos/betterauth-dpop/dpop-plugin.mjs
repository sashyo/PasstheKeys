// A Better Auth plugin that adds the `dpop` WebAuthn extension (see ../dpop-ext/SPEC.md) to Better
// Auth. The authenticator mints a fresh per-session key SK and names SK_pub inside the signed
// authenticatorData; this plugin binds the Better Auth session to jkt = thumbprint(SK_pub) and
// requires a per-request proof signed by SK on the protected route.
//
// Better Auth owns users and sessions; this plugin adds the sender-constraint. Better Auth's
// built-in passkey plugin can't be used for this: it verifies real browser WebAuthn via
// @simplewebauthn, and no real browser/authenticator implements the dpop extension, so the demo
// drives a simulated separate-origin authenticator (public/authenticator.html).
//
// The `enforce` option is the demo's exploit/fix toggle:
//   enforce:false -> plain passkey login; a relayed assertion mints a usable session (TAKEOVER).
//   enforce:true  -> the session is dpop-bound and /dpop/me needs an SK proof; a relayed session
//                    mints a token but it is INERT (the attacker can't produce proofs).
import { createAuthEndpoint, sessionMiddleware, APIError } from 'better-auth/api';
import { setSessionCookie } from 'better-auth/cookies';
import { webcrypto as wc, createHash, randomBytes } from 'node:crypto';
import * as z from 'zod';

const subtle = wc.subtle;
const b64url = (buf) => Buffer.from(buf).toString('base64url');
const fromB64url = (s) => Buffer.from(s, 'base64url');
const sha256 = (buf) => createHash('sha256').update(buf).digest();
const importRawVerify = (raw) => subtle.importKey('raw', raw, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
const verifyRaw = (key, sig, data) => subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, sig, data);

// authenticatorData = rpIdHash(32) | flags(1) | signCount(4) | [SK_pub(65) if dpop bit 0x80]
function parseAuthData(buf) {
  const rpIdHash = buf.subarray(0, 32), flags = buf[32];
  const out = { rpIdHash, up: !!(flags & 0x01), dpop: !!(flags & 0x80) };
  if (out.dpop) out.skPub = buf.subarray(37, 37 + 65);
  return out;
}

// Verify a WebAuthn assertion signature over `expectedChallenge` with a given raw EC public key.
async function verifySig(assertion, pubRaw, expectedChallenge, ORIGIN, RP_ID) {
  const clientDataJSON = fromB64url(assertion.response.clientDataJSON);
  let cData; try { cData = JSON.parse(clientDataJSON.toString('utf8')); } catch { return { ok: false, why: 'bad clientData' }; }
  if (cData.type !== 'webauthn.get') return { ok: false, why: 'wrong clientData type' };
  if (cData.origin !== ORIGIN) return { ok: false, why: `origin ${cData.origin}` };
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

const headerOf = (ctx, name) => {
  const h = ctx.headers || ctx.request?.headers;
  return h && typeof h.get === 'function' ? h.get(name) : undefined;
};

export const dpop = (opts = {}) => {
  const enforce = opts.enforce !== false;              // default: fix on
  const ORIGIN = opts.origin;                          // e.g. http://victim.localhost:1521
  const RP_ID = opts.rpId || new URL(ORIGIN).hostname; // victim.localhost
  const HTU = ORIGIN + '/api/auth/dpop/me';

  // Demo-local stores (single victim process).
  const credsById = new Map(); // credId  -> { userId, pub(Buffer) }
  const tokens = new Map();    // passkeyToken -> { kind, challenge, at }
  const popNonces = new Map(); // nonce -> at
  const bind = new Map();      // sessionToken -> { skPub(Buffer), jkt }
  const now = () => Date.now();
  setInterval(() => { const t = now(); for (const m of [tokens, popNonces]) for (const [k, v] of m) if (t - v.at > 120000) m.delete(k); }, 30000).unref();
  const issue = (kind, challenge) => { const id = b64url(randomBytes(18)); tokens.set(id, { kind, challenge, at: now() }); return id; };

  return {
    id: 'dpop',
    endpoints: {
      // ---- which mode is this app running in (for the UI banner) ----
      dpopMode: createAuthEndpoint('/dpop/mode', { method: 'GET' }, async (ctx) => ctx.json({ enforce })),

      // ---- enrollment: create the identity passkey credential (and the user) ----
      dpopRegisterBegin: createAuthEndpoint('/dpop/register/begin', { method: 'POST', body: z.object({ username: z.string().min(1) }) }, async (ctx) => {
        const username = ctx.body.username;
        const email = `${username}@dpop.local`;
        let user = await ctx.context.internalAdapter.findUserByEmail(email);
        user = user?.user || user;
        if (!user) user = await ctx.context.internalAdapter.createUser({ email, name: username, emailVerified: true });
        const challenge = b64url(randomBytes(32));
        const passkeyToken = issue('register', challenge);
        return ctx.json({ passkeyToken, publicKey: { challenge, rp: { id: RP_ID, name: 'Acme (dpop)' }, user: { id: user.id, name: username, displayName: username } } });
      }),
      dpopRegisterFinish: createAuthEndpoint('/dpop/register/finish', { method: 'POST', body: z.object({ userId: z.string(), credId: z.string(), publicKey: z.string(), passkeyToken: z.string() }) }, async (ctx) => {
        const tok = tokens.get(ctx.body.passkeyToken);
        if (!tok || tok.kind !== 'register') return ctx.json({ ok: false, error: 'bad passkeyToken' }, { status: 400 });
        credsById.set(ctx.body.credId, { userId: ctx.body.userId, pub: fromB64url(ctx.body.publicKey) });
        tokens.delete(ctx.body.passkeyToken);
        return ctx.json({ ok: true });
      }),

      // ---- login: verify the assertion, bind the Better Auth session to the signed SK ----
      dpopLoginBegin: createAuthEndpoint('/dpop/login/begin', { method: 'POST' }, async (ctx) => {
        const challenge = b64url(randomBytes(32));
        const passkeyToken = issue('login', challenge);
        return ctx.json({ passkeyToken, publicKey: { challenge, rpId: RP_ID, extensions: { dpop: true } } });
      }),
      dpopLoginFinish: createAuthEndpoint('/dpop/login/finish', { method: 'POST', body: z.object({ assertion: z.any(), passkeyToken: z.string() }) }, async (ctx) => {
        const tok = tokens.get(ctx.body.passkeyToken);
        if (!tok || tok.kind !== 'login') return ctx.json({ ok: false, error: 'bad or expired passkeyToken' }, { status: 401 });
        const cred = ctx.body.assertion && credsById.get(ctx.body.assertion.rawId);
        if (!cred) return ctx.json({ ok: false, error: 'unknown credential' }, { status: 401 });
        let v; try { v = await verifySig(ctx.body.assertion, cred.pub, tok.challenge, ORIGIN, RP_ID); } catch (e) { return ctx.json({ ok: false, error: e.message }, { status: 400 }); }
        if (!v.ok) return ctx.json({ ok: false, error: v.why }, { status: 401 });
        // The fix hinges on this: the key is read ONLY from the signed authenticatorData, never from
        // anything the page could choose. With enforce off we skip the binding entirely.
        if (enforce && (!v.ad.dpop || !v.ad.skPub)) return ctx.json({ ok: false, error: 'assertion carries no dpop key (SK_pub)' }, { status: 401 });
        tokens.delete(ctx.body.passkeyToken);
        const session = await ctx.context.internalAdapter.createSession(cred.userId);
        if (!session) return ctx.json({ ok: false, error: 'could not create session' }, { status: 500 });
        const user = await ctx.context.internalAdapter.findUserById(cred.userId);
        await setSessionCookie(ctx, { session, user });
        let jkt = null;
        if (enforce && v.ad.skPub) { jkt = b64url(sha256(v.ad.skPub)); bind.set(session.token, { skPub: Buffer.from(v.ad.skPub), jkt }); }
        return ctx.json({ ok: true, enforced: enforce, jkt });
      }),

      // ---- per-request proof-of-possession plumbing ----
      dpopPopChallenge: createAuthEndpoint('/dpop/pop-challenge', { method: 'POST' }, async (ctx) => {
        const nonce = b64url(randomBytes(32)); popNonces.set(nonce, now());
        return ctx.json({ nonce });
      }),
      dpopMe: createAuthEndpoint('/dpop/me', { method: 'GET', use: [sessionMiddleware] }, async (ctx) => {
        const { session, user } = ctx.context.session;
        if (enforce) {
          const deny = (msg, status = 'UNAUTHORIZED') => { throw new APIError(status, { error: msg, message: msg }); };
          const b = bind.get(session.token);
          if (!b) deny('session is not dpop-bound');
          const proofHdr = headerOf(ctx, 'x-dpop-proof');
          if (!proofHdr) deny('missing dpop proof (SK assertion required per request)');
          let proof; try { proof = JSON.parse(fromB64url(String(proofHdr)).toString('utf8')); } catch { deny('unparseable proof', 'BAD_REQUEST'); }
          const cd = (() => { try { return JSON.parse(fromB64url(proof.response.clientDataJSON)); } catch { return null; } })();
          let matched = null;
          if (cd) for (const nonce of popNonces.keys()) if (b64url(sha256(Buffer.from('GET ' + HTU + ' ' + nonce))) === cd.challenge) { matched = nonce; break; }
          if (!matched) deny('proof not bound to this request (or nonce expired/spent)');
          let v; try { v = await verifySig(proof, b.skPub, cd.challenge, ORIGIN, RP_ID); } catch (e) { deny(e.message, 'BAD_REQUEST'); }
          if (!v.ok) deny('proof rejected: ' + v.why);
          popNonces.delete(matched);
          return ctx.json({ userId: user.id, username: user.name, jkt: b.jkt });
        }
        return ctx.json({ userId: user.id, username: user.name, jkt: null });
      }),
    },
  };
};
