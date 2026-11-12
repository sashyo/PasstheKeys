# Defended demo: passkey-bound sessions

This is the fix for the login-takeover in the parent demo. Same relay attack, run against a
relying party that **binds the session to the passkey credential itself**. The attacker still
completes the WebAuthn ceremony and mints a real token for the victim, and the token is
**inert** because every resource call needs a fresh passkey proof the attacker's machine cannot
produce and the victim's page cannot hand over.

## Why not a key in the page

An earlier version generated a DPoP keypair in the browser and bound the session to it. That is
wrong for this threat model: the page is **already running the attacker's code**, so it would
generate the key itself, make it extractable, and ship the private key to the attacker along
with the assertion. Any key the page can generate, derive (even via the WebAuthn PRF
extension), or read, the page can also hand over. The binding key has to live **below the page**,
where page JavaScript cannot choose or read it: in the authenticator.

## The mechanism

The sender-constraining key is the **passkey credential**. Its private key lives in the
authenticator and never leaves it; the authenticator only ever signs assertions with it.

- Registration: the server stores the credential's public key and computes its thumbprint
  `jkt` ([RFC 7638](https://www.rfc-editor.org/rfc/rfc7638)).
- Login (`/login/finish`): the server verifies the assertion and **binds the session token to
  the public key of the credential that signed it**. The page supplies no key, so a compromised
  page cannot substitute one.
- Resource (`/api/me`): requires `Authorization: Passkey <token>` **and** a fresh proof-of-
  possession assertion (`X-Passkey-Proof`) signed by the bound credential over
  `SHA256("GET <htu> <nonce>")`, where `<nonce>` is a one-time value from `/api/pop-challenge`.
  The proof is single-use and request-bound, so it cannot be pre-minted or replayed.

[public/passkey-provider.js](public/passkey-provider.js) (`PasskeyProvider`) exposes
`register`, `authenticate` (signs the raw login challenge, no key folded in), and
`prove(method, htu)` (fetches a nonce and returns a per-request proof assertion).

Why the relay fails: the attacker finishes the login and gets a session bound to the victim's
passkey, but to call `/api/me` it needs a fresh assertion from that passkey. The attacker's
machine has no authenticator for it, and the key never left the victim's device, so the token
is inert. A compromised page can coax at most **one more** user-approved proof out of the
authenticator (single-use, one request), never the key itself and never a durable, relayable
session.

> Scope: self-contained zero-dependency RP (ES256 credentials only). Pocket ID is upstream and
> cannot be modified to bind its own sessions, so the defended flow is a relying party we own
> sitting next to it. Requiring a passkey tap per request is heavy; a production system would
> amortize it (short-lived proof-bound tokens, or browser-level device binding such as DBSC).
> Authorized demo use only: your own machine and disposable test users.

## Run

```bash
cd defended
ROLE=victim   PORT=1421 node server.mjs    # Acme (defended): /login, the RP, /api/me
ROLE=attacker PORT=1423 VICTIM_ORIGIN=http://localhost:1421 node server.mjs   # attacker site + drop
```

1. Open <http://localhost:1421/login>, create an account, add a passkey.
2. Click **Sign in with passkey** - you land on "Welcome" (two passkey taps: one to log in, one
   to prove possession for `/api/me`), with the bound passkey thumbprint shown. The defended
   flow works for the real user.
3. Open <http://localhost:1423/attacker> ("waiting for a sign-in").
4. Back on `/login`, click **Simulate compromised page (relay my sign-in)**. The attacker tab
   finishes the login and shows **"Session captured, but locked"**: the token minted, and
   `/api/me` refused it because there is no passkey proof.

## Headless check (no browser)

Emulates authenticators and both parties in Node and asserts the three outcomes:

```bash
ROLE=victim PORT=1421 node server.mjs        # in one shell
node e2e.mjs                                  # in another
```

Expected: legit login + proof returns the user; the relay mints a token but `/api/me` is
refused with no proof; and a valid proof from a **different** passkey is refused for the
victim's session.

## Browser check + demo video (Playwright, virtual authenticator)

These spawn their own victim RP + attacker site on ports 14021/14023, so nothing else needs
to be running.

```bash
npm install && npx playwright install chromium   # dev only
node defended/e2e-browser.mjs    # headful-equivalent: legit sign-in passes, relay stays locked
node defended/record.mjs         # writes defended/videos/{victim,attacker}.webm
node defended/record-split.mjs   # same-size panes + stitched videos/combined.mp4
```

`victim.webm` shows one person enrolling, signing in DPoP-bound ("Welcome"), then their page
being compromised and relaying the sign-in. `attacker.webm` shows that tab flipping to
**"Session captured, but locked."**

`record-split.mjs` records both tabs at the same size (`split-victim.webm`,
`split-attacker.webm`) and, if a full `ffmpeg` is on `PATH`, stitches them side by side into
`videos/combined.mp4` (victim left, attacker right). Playwright's bundled ffmpeg is a minimal
vpx-only build with no `hstack` filter, so it is not used; without a full ffmpeg the two panes
are written and the exact stitch command is printed. All of `videos/` is gitignored.

## Diagram

[flow.puml](flow.puml) is the sequence diagram for this defended path (render with any
PlantUML tool).

