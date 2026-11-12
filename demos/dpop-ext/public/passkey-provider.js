// Page-side helper for the `dpop` extension demo. It does NOT hold any key. It embeds the
// extended-authenticator iframe (a separate origin) and drives it over postMessage; the keys
// live in the authenticator, unreadable here. See SPEC.md and public/authenticator.html.

const te = new TextEncoder();
const b64url = (buf) => { const b = new Uint8Array(buf); let s = ''; for (const x of b) s += String.fromCharCode(x); return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); };
const sha256 = async (bytes) => new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));

export class PasskeyProvider {
  constructor({ authOrigin } = {}) {
    this.authOrigin = authOrigin || 'http://authenticator.localhost:1525';
    this._pending = new Map();
    this._seq = 0;
    this._ready = null;
  }

  // Embed the authenticator iframe and wait for its ready signal.
  init() {
    if (this._ready) return this._ready;
    this._ready = new Promise((resolve) => {
      const frame = document.createElement('iframe');
      frame.style.display = 'none';
      frame.src = this.authOrigin + '/auth';
      this._frame = frame;
      window.addEventListener('message', (e) => {
        if (e.origin !== this.authOrigin) return;        // only trust the authenticator origin
        if (e.data && e.data.dpopAuthReady) return resolve();
        const p = e.data && this._pending.get(e.data.id);
        if (!p) return;
        this._pending.delete(e.data.id);
        e.data.ok ? p.resolve(e.data.result) : p.reject(new Error(e.data.error || 'authenticator error'));
      });
      document.body.appendChild(frame);
    });
    return this._ready;
  }

  _rpc(op, args) {
    const id = 'r' + (++this._seq);
    return new Promise((resolve, reject) => {
      this._pending.set(id, { resolve, reject });
      this._frame.contentWindow.postMessage({ id, op, args }, this.authOrigin);
    });
  }

  async register(username) { await this.init(); return this._rpc('register', { username }); }

  // Returns { assertion, handle }. assertion is a standard WebAuthn response; handle refers to
  // the fresh session key the authenticator just generated (the page never sees the key).
  async login(challenge) { await this.init(); return this._rpc('login', { rpId: location.hostname, origin: location.origin, challenge }); }

  // Produce a proof-of-possession for one request: sign SHA256("<method> <htu> <nonce>") with
  // the session key held by the authenticator.
  async prove(handle, method, htu, nonce) {
    await this.init();
    const challenge = b64url(await sha256(te.encode(method + ' ' + htu + ' ' + nonce)));
    const { proof } = await this._rpc('proof', { handle, rpId: location.hostname, origin: location.origin, challenge });
    return proof;
  }
}
