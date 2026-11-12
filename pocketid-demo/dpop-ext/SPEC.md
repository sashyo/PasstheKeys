# A WebAuthn extension for passkey-named, per-session binding keys (`dpop`)

## Problem this solves

Sender-constraining a session (DPoP-style) needs a key the client proves possession of on
every request. For it to survive a page that is **running the attacker's code**, that key must
be neither:

- **readable** by the page (or the page exfiltrates it), nor
- **nameable** by the page (or the page binds the session to a key the attacker holds).

A key generated in the page (webcrypto, PRF-derived, `largeBlob`-vaulted) fails the first test.
A separate key whose thumbprint the page folds into the login challenge fails the second: a
compromised page folds in the attacker's key, the passkey blind-signs it, and the server binds
to it. Stock WebAuthn has no operation where an existing credential **names** a separate key, so
neither test can be passed with a separate key today. This extension adds exactly that.

## The extension

`dpop` is a WebAuthn **client/authenticator extension** evaluated during `get()`
(authentication).

### Input (client -> authenticator)

```
extensions: { dpop: true }
```

### Authenticator behavior

On an assertion with `dpop` present, the authenticator:

1. Generates a **fresh ephemeral keypair `SK`** (P-256), internal to the authenticator. New per
   assertion, so the session binding key is different every login.
2. Emits `SK`'s public key as a **signed** extension output: `SK_pub` is placed in
   `authenticatorData` (the extensions region), which the assertion signature already covers. So
   the **credential key signs over `SK_pub`** - the authenticator names it; the page cannot
   alter it without invalidating the identity assertion.
3. Retains `SK`'s private key, sealed, for the lifetime of the session. It never leaves the
   authenticator. The authenticator will sign later proof assertions with `SK` (silent or with
   user verification, per policy); it never exports `SK`.

### Output (authenticator -> client -> server)

A **standard** WebAuthn assertion, whose `authenticatorData` now carries `SK_pub` in its signed
extensions region. Nothing extra is added to the assertion JSON: `clientExtensionResults` stays
empty, and there is no `jkt` field in the response. The relying party derives the `jkt` solely
from the **signed** `authenticatorData`, so the key is named only by the thing the authenticator
signed - never by anything the page could set. The client forwards the assertion unchanged; it
never sees `SK`'s private key and cannot choose `SK_pub`. (The `jkt` is returned to the client by
the RP's own `login/finish` response, not carried in the assertion.)

## Relying-party flow (begin / finish)

- **Register** (unchanged): store the identity credential's public key.
- **Login `begin`**: returns `{ passkeyToken, publicKey }`, where `passkeyToken` is an opaque,
  short-lived handle for the ceremony (it binds the challenge) and `publicKey` holds the
  `get()` options (`challenge`, `rpId`, `extensions: { dpop: true }`).
- **Login `finish`**: body is `{ assertion, passkeyToken }`. The RP checks the `passkeyToken` is
  live and that the signed `clientDataJSON.challenge` matches it, verifies the identity
  assertion, reads `SK_pub` from the signed `authenticatorData`, binds the session token to
  `jkt = thumbprint(SK_pub)`, and returns `{ token, jkt }`.
- **Resource**: require `Authorization: Passkey <token>` plus a fresh **proof assertion** signed
  by `SK` over `SHA256("<method> <htu> <nonce>")` (one-time `nonce`). Verify it against the bound
  `SK_pub`. Single-use and request-bound, so it cannot be pre-minted or replayed.

## Why the relay is inert

- **No exfiltration:** `SK`'s private key never leaves the authenticator; the page cannot read
  it.
- **No substitution:** `SK_pub` rides inside the credential-signed `authenticatorData`. In the
  relay the victim's authenticator names the **victim's** `SK_pub`; the attacker cannot make it
  name a key the attacker holds, and cannot forge the identity signature. The attacker finishes
  the login and is bound to a key whose private half is sealed in the victim's authenticator, so
  it can produce no proof.
- **Residual (honest):** while the victim's page is live and compromised it can ask the
  authenticator to sign one more single-use proof and forward it - a one-shot, user-approved
  action, never the key and never a durable, relayable session.

## PoC encodings (this demo only)

Simplified to stay zero-dependency; a real extension would use COSE/CBOR.

- EC P-256 everywhere. Public keys: raw uncompressed point (65 bytes), base64url.
- `jkt = base64url(SHA256(SK_pub_raw))`.
- Signatures: raw `r || s` (IEEE P1363, 64 bytes), base64url.
- `authenticatorData = rpIdHash(32) || flags(1) || signCount(4) || [SK_pub(65) if dpop]`.
  Flag bits: `0x01` user-present, `0x80` "dpop output present".
- `clientDataJSON = {"type","challenge","origin"}`; signed message is
  `authenticatorData || SHA256(clientDataJSON)`.

## Modeling the authenticator in the browser demo

Real browsers/authenticators do not implement `dpop`, so the demo simulates the extended
authenticator as a page served from a **separate origin**, embedded as an iframe. Same-origin
policy makes its memory unreadable to the relying-party page, so a compromised RP page can ask
it to sign (via `postMessage`) but can never read `SK` or the credential key, nor make it name a
different `SK`. That boundary stands in for the authenticator's hardware boundary.
