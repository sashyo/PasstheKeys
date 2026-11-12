// PasskeyProvider: sender-constrains a WebAuthn credential with a browser-held DPoP key.
//
// The idea in one line: on every passkey ceremony we generate (once) a NON-EXTRACTABLE
// DPoP keypair in this browser, and we fold its JWK thumbprint (jkt) into the challenge
// the authenticator signs. The authenticator only ever signs `authenticatorData ||
// SHA256(clientDataJSON)`, and `challenge` is the one field JS controls that is guaranteed
// to land inside that signature -- so the nonce slot is exactly where the binding has to go.
//
//   signedChallenge = SHA256( serverNonce + "." + jkt )
//
// The server recomputes that from the nonce it issued and the DPoP public key it is handed,
// checks it equals the challenge inside the signed clientDataJSON, then binds the session to
// jkt and requires a DPoP proof (RFC 9449) on every later request. A relayed/stolen assertion
// commits to THIS browser's jkt, whose private key never leaves it -- so the resulting session
// is inert for anyone else.
//
// Zero dependencies; ES module for the browser. Keys live in IndexedDB as CryptoKey handles
// (private key extractable:false, so script -- even attacker script on this origin -- cannot
// read it out).

const subtle = crypto.subtle;
const te = new TextEncoder();

// ---- small codecs -------------------------------------------------------------
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

// ---- WebAuthn (de)serialization ----------------------------------------------
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

// RFC 7638 JWK thumbprint (SHA-256, base64url), EC P-256 member order crv,kty,x,y.
async function jwkThumbprint(jwk) {
  const canon = `{"crv":"${jwk.crv}","kty":"${jwk.kty}","x":"${jwk.x}","y":"${jwk.y}"}`;
  return bufToB64url(await sha256(te.encode(canon)));
}

// ---- IndexedDB handle store (stores CryptoKey objects, not raw bytes) ---------
function idb(dbName) {
  return new Promise((res, rej) => {
    const req = indexedDB.open(dbName, 1);
    req.onupgradeneeded = () => req.result.createObjectStore('keys');
    req.onsuccess = () => res(req.result);
    req.onerror = () => rej(req.error);
  });
}
function idbGet(db, k) {
  return new Promise((res, rej) => {
    const t = db.transaction('keys', 'readonly').objectStore('keys').get(k);
    t.onsuccess = () => res(t.result); t.onerror = () => rej(t.error);
  });
}
function idbPut(db, k, v) {
  return new Promise((res, rej) => {
    const t = db.transaction('keys', 'readwrite').objectStore('keys').put(v, k);
    t.onsuccess = () => res(); t.onerror = () => rej(t.error);
  });
}

export class PasskeyProvider {
  constructor({ dbName = 'passkey-dpop' } = {}) { this.dbName = dbName; this._dpop = null; }

  // Get-or-create the per-browser DPoP keypair. Private key is non-extractable: it can sign
  // but can never be serialized out, so relaying the page's data cannot carry it off-origin.
  async dpop() {
    if (this._dpop) return this._dpop;
    const db = await idb(this.dbName);
    let pair = await idbGet(db, 'dpop');
    if (!pair) {
      // Private key non-extractable; the pair persists as CryptoKey handles (not raw bytes).
      pair = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
      await idbPut(db, 'dpop', pair);
    }
    const publicJwk = await subtle.exportKey('jwk', pair.publicKey);
    delete publicJwk.key_ops; delete publicJwk.ext;
    const jkt = await jwkThumbprint(publicJwk);
    this._dpop = { priv: pair.privateKey, publicJwk, jkt };
    return this._dpop;
  }

  // Fold jkt into the nonce the authenticator will sign.
  async bindChallenge(serverNonceB64url, jkt) {
    return bufToB64url(await sha256(te.encode(serverNonceB64url + '.' + jkt)));
  }

  // Authenticate: wrap navigator.credentials.get so the signed challenge is the DPoP-bound one.
  // `start` is the server's /login/start payload: { challenge, rpId, allowCredentials? }.
  async authenticate(start) {
    const { publicJwk, jkt } = await this.dpop();
    const bound = await this.bindChallenge(start.challenge, jkt);
    const cred = await navigator.credentials.get({
      publicKey: {
        challenge: b64urlToBuf(bound),
        rpId: start.rpId || location.hostname,
        userVerification: 'required',
        timeout: 60000,
        allowCredentials: (start.allowCredentials || []).map((c) => ({
          id: b64urlToBuf(c.id), type: 'public-key',
        })),
      },
    });
    return { assertion: serializeAssertion(cred), dpopPublicJwk: publicJwk, jkt };
  }

  // Register: wrap navigator.credentials.create. We read the credential public key via the
  // WebAuthn getPublicKey() API (SPKI DER) so the server verifies later assertions with no
  // CBOR/attestation parsing. The DPoP binding is also folded into the registration challenge.
  async register(start) {
    const { publicJwk, jkt } = await this.dpop();
    const bound = await this.bindChallenge(start.challenge, jkt);
    const pub = {
      challenge: b64urlToBuf(bound),
      rp: start.rp,
      user: { ...start.user, id: b64urlToBuf(start.user.id) },
      pubKeyCredParams: start.pubKeyCredParams || [{ type: 'public-key', alg: -7 }],
      authenticatorSelection: start.authenticatorSelection || { userVerification: 'required' },
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
        clientDataJSON: bufToB64url(r.clientDataJSON),
      },
      dpopPublicJwk: publicJwk, jkt,
    };
  }

  // RFC 9449 DPoP proof: a compact ES256 JWT, header carries the public JWK, claims bind the
  // request (htm/htu), freshness (iat) and uniqueness (jti). Signed by the non-extractable key.
  async dpopProof(htm, htu) {
    const { priv, publicJwk } = await this.dpop();
    const header = { typ: 'dpop+jwt', alg: 'ES256', jwk: publicJwk };
    const claims = {
      htm, htu,
      iat: Math.floor(Date.now() / 1000),
      jti: bufToB64url(crypto.getRandomValues(new Uint8Array(16)).buffer),
    };
    const enc = (o) => bufToB64url(te.encode(JSON.stringify(o)));
    const signingInput = enc(header) + '.' + enc(claims);
    // webcrypto ECDSA sign returns raw r||s (JOSE/P1363), exactly what a JWS wants.
    const sig = await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, priv, te.encode(signingInput));
    return signingInput + '.' + bufToB64url(sig);
  }

  async thumbprint() { return (await this.dpop()).jkt; }
}
