# `dpop` WebAuthn extension demo: authenticator-named, per-session binding key

The passkey-as-key fix in [../defended/](../defended/) is page-safe but reuses the long-lived
login credential. This demo prototypes a **WebAuthn extension** (`dpop`) that lets the
**authenticator generate a fresh per-session key `SK`** and **name it inside the signed
`authenticatorData`**, so the relying party can sender-constrain the session to `SK` while:

- `SK`'s private key never leaves the authenticator (no exfiltration), and
- the page cannot substitute a key it controls (the authenticator, not the page, names `SK`).

See [SPEC.md](SPEC.md) for the extension itself. This closes both failure modes that sink a
page-held or page-named key.

## How it works (one screen)

- **Login** `get()` with `extensions: { dpop: true }`: the authenticator generates `SK`, puts
  `SK_pub` into the **signed** `authenticatorData` (flag `0x80`), and keeps `SK` sealed.
- **`login/finish`**: the RP reads `SK_pub` from the signed `authenticatorData` and binds the
  session token to `jkt = thumbprint(SK_pub)`. Nothing in the client-controlled part of the
  response names the key.
- **`/api/me`**: requires `Authorization: Passkey <token>` plus a fresh proof assertion signed
  by `SK` over `SHA256("GET <htu> <nonce>")`.

Relay: the compromised page relays the login assertion, which names the **victim's** `SK`. The
attacker finishes and mints a real token bound to that `SK`, but cannot produce proofs (the key
is sealed in the victim's authenticator) and cannot swap in its own key (it rides in the signed
`authenticatorData`). The token is inert.

## Modeling note

Real browsers do not implement `dpop`, so the extended authenticator is **simulated as a page
served from a separate origin** ([public/authenticator.html](public/authenticator.html)),
embedded as an iframe. Same-origin policy makes its keys unreadable to the relying-party page,
which can only drive it over `postMessage` - the stand-in for an authenticator's hardware
boundary. Private keys are also generated non-extractable. This is a protocol prototype, not a
browser/authenticator implementation.

## Run

```bash
cd dpop-ext
ROLE=victim        PORT=1521 node server.mjs
ROLE=attacker      PORT=1523 VICTIM_ORIGIN=http://localhost:1521 node server.mjs
ROLE=authenticator PORT=1525 node server.mjs
# open http://localhost:1521/login  (sign in works; "Simulate compromised page" stays locked)
```

## Checks

Headless model (emulated authenticator in Node), asserts the three outcomes:

```bash
ROLE=victim PORT=1521 node server.mjs      # in one shell
node e2e.mjs                                # in another
```

Legit login binds to the signed `SK` and `/api/me` unlocks with an `SK` proof; the relay mints a
token but `/api/me` is refused; and an assertion carrying the attacker's `SK` (self-signed by an
unregistered credential) is rejected.

## Diagram

[flow.puml](flow.puml) is the sequence diagram; [flow-detailed.puml](flow-detailed.puml) is the
verbose version showing the per-session `SK` generation step by step.

## PoC simplifications

Zero-dependency, so: ES256 only; raw EC public keys and raw ECDSA signatures (not COSE/DER);
`SK_pub` appended raw after `signCount` (standing in for the CBOR extensions block); the
authenticator iframe stands in for real authenticator hardware. See [SPEC.md](SPEC.md).
