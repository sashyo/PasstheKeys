// PasskeyProvider: passkey-bound sessions, where the sender-constraining key is the passkey
// credential ITSELF. There is no key generated in the page. The authenticator holds the private
// key and never exposes it; the session is bound to the credential that signs the login, and
// each request is authorized by a fresh WebAuthn proof-of-possession assertion.
//
// This is the only construction that survives a page running attacker code: a key the page
// could generate, derive (even via the WebAuthn PRF extension) or read, the page could also
// hand to the attacker. A key sealed in the authenticator cannot be relayed -- the attacker's
// machine has no authenticator, and the compromised page can obtain at most one more user-
// approved assertion, never the key.
//
// Zero dependencies; ES module for the browser.

const subtle = crypto.subtle;
const te = new TextEncoder();

function bufToB64url(buf) {
  const b = new Uint8Array(buf); let s = '';
  for (const x of b) s += String.fromCharCode(x);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function b64urlToBuf(s) {
  s = s.replace(/-/g, '+').replace(/_/g, '/'); while (s.length % 4) s += '=';
  const b = atob(s), a = new Uint8Array(b.length);
  for (let i = 0; i < b.length; i++) a[i] = b.charCodeAt(i);
  return a.buffer;
}
async function sha256(bytes) { return new Uint8Array(await subtle.digest('SHA-256', bytes)); }

function serializeAssertion(cred) {
  const r = cred.response;
  return {
    id: cred.id, rawId: bufToB64url(cred.rawId), type: cred.type, clientExtensionResults: {},
    response: {
      clientDataJSON: bufToB64url(r.clientDataJSON),
      authenticatorData: bufToB64url(r.authenticatorData),
      signature: bufToB64url(r.signature),
      userHandle: r.userHandle ? bufToB64url(r.userHandle) : null,
    },
  };
}

export class PasskeyProvider {
  // Register a discoverable passkey. The credential public key is read via getPublicKey()
  // (SPKI DER) so the server verifies later assertions with no attestation parsing.
  async register(start) {
    const pub = {
      challenge: b64urlToBuf(start.challenge),
      rp: start.rp,
      user: { ...start.user, id: b64urlToBuf(start.user.id) },
      pubKeyCredParams: start.pubKeyCredParams || [{ type: 'public-key', alg: -7 }],
      authenticatorSelection: start.authenticatorSelection || { residentKey: 'required', userVerification: 'required' },
      timeout: 60000,
      attestation: 'none',
    };
    const cred = await navigator.credentials.create({ publicKey: pub });
    const r = cred.response;
    return {
      credential: {
        id: cred.id, rawId: bufToB64url(cred.rawId), type: cred.type,
        publicKeySpki: bufToB64url(r.getPublicKey()),
        publicKeyAlgorithm: r.getPublicKeyAlgorithm(),
      },
    };
  }

  // Authenticate: sign the server's login challenge as-is. No page key is folded in; the server
  // binds the resulting session to whichever credential produced this signature.
  async authenticate(start) {
    const cred = await navigator.credentials.get({
      publicKey: {
        challenge: b64urlToBuf(start.challenge),
        rpId: start.rpId || location.hostname,
        userVerification: 'required',
        timeout: 60000,
        allowCredentials: (start.allowCredentials || []).map((c) => ({ id: b64urlToBuf(c.id), type: 'public-key' })),
      },
    });
    return { assertion: serializeAssertion(cred) };
  }

  // Produce a proof-of-possession for one request: fetch a one-time nonce, then have the
  // authenticator sign SHA256("<method> <htu> <nonce>"). The returned assertion is single-use
  // and bound to this exact request, so it cannot be pre-minted or replayed.
  async prove(method, htu) {
    const origin = new URL(htu).origin;
    const { nonce } = await (await fetch(origin + '/api/pop-challenge', { method: 'POST' })).json();
    const challenge = await sha256(te.encode(method + ' ' + htu + ' ' + nonce));
    const cred = await navigator.credentials.get({
      publicKey: {
        challenge, rpId: location.hostname, userVerification: 'required', timeout: 60000, allowCredentials: [],
      },
    });
    return serializeAssertion(cred);
  }
}
