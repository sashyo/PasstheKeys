# Defended demo: sender-constrained passkey sessions (DPoP-bound)

This is the fix for the login-takeover in the parent demo. Same relay attack, run against a
relying party that **binds the session to a DPoP key the signing browser keeps**. The attacker
still completes the WebAuthn ceremony and mints a real token for the victim, and the token is
**inert** because every resource call needs a DPoP proof the attacker cannot produce.

## The mechanism

A WebAuthn authenticator only signs `authenticatorData || SHA256(clientDataJSON)`. The one
field JavaScript controls that is guaranteed to land inside that signature is the **challenge**
(the nonce). So that is where the binding goes.

[public/passkey-provider.js](public/passkey-provider.js) (`PasskeyProvider`) does, per ceremony:

1. Get-or-create a **non-extractable** DPoP keypair in this browser (IndexedDB CryptoKey
   handle; script cannot read the private key out, even attacker script on this origin).
2. Compute its JWK thumbprint `jkt` (RFC 7638).
3. Sign `challenge = SHA256(serverNonce + "." + jkt)` instead of the raw nonce.
4. Hand the server `{ assertion, dpopPublicJwk }`.

[server.mjs](server.mjs) at `/login/finish` recomputes `SHA256(ourNonce + "." + thumbprint(dpopPublicJwk))`,
checks it equals the challenge inside the signed `clientDataJSON`, verifies the assertion
signature, then **binds the session token to `jkt`**. `/api/me` requires `Authorization: DPoP
<token>` plus a fresh `DPoP:` proof (RFC 9449) whose key thumbprint equals the bound `jkt`.

Why the relay fails: the victim's provider folds in the **victim's own** `jkt`, and the private
key never leaves the victim's browser. A relayed assertion commits to the victim's `jkt`; a
swapped key breaks the challenge match; and a stolen token is useless without the private key.

> Scope: self-contained zero-dependency RP (ES256 credentials only). Pocket ID is upstream and
> cannot be modified to bind its own sessions, so the defended flow is a relying party we own
> sitting next to it. Authorized demo use only: your own machine and disposable test users.

## Run

```bash
cd defended
ROLE=victim   PORT=1421 node server.mjs    # Acme (defended): /login, the RP, /api/me
ROLE=attacker PORT=1423 VICTIM_ORIGIN=http://localhost:1421 node server.mjs   # attacker site + drop
```

1. Open <http://localhost:1421/login>, create an account, add a passkey.
2. Click **Sign in with passkey** - you land on "Welcome", with the bound `jkt` shown. The
   defended flow works for the real user.
3. Open <http://localhost:1423/attacker> ("waiting for a sign-in").
4. Back on `/login`, click **Simulate compromised page (relay my sign-in)**. The attacker tab
   finishes the login and shows **"Session captured - but locked"**: the token minted, and
   `/api/me` refused the attacker's proof.

## Headless check (no browser)

Emulates the authenticator and both parties in Node and asserts the three outcomes:

```bash
ROLE=victim PORT=1421 node server.mjs        # in one shell
node e2e.mjs                                  # in another
```

Expected: legit `/api/me` returns the user; relay mints a token but `/api/me` is refused; key
substitution is rejected at finish.

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

