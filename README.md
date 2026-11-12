# Passkey login takeover demo (Pocket ID)

On an already-breached login page, one victim passkey sign-in can be relayed so an
attacker ends up logged in **as that user**. The attacker screen is a live dashboard of
captured sessions. Passkeys stop phishing and remote replay; they do not protect a page
that is already running the attacker's code. The reusable prize is the **unbound session
token**, so the real fix is to bind it (DPoP / sender-constraining).

This repo ships both halves: the **exploit** (below) and a **working fix** that makes the
same relay useless, in [pocketid-demo/defended/](pocketid-demo/defended/). Jump to
[The fix](#the-fix-sender-constrained-sessions-dpop).

> Authorized demo use only: your own instance and disposable test users.

## Prerequisites

- Docker (Docker Desktop or Docker Engine)
- Node 18+

## Run

```bash
cd pocketid-demo
cp .env.example .env          # then set ENCRYPTION_KEY:  openssl rand -base64 24
docker compose up -d          # Pocket ID on :1412
node server.mjs               # the app on :1411 (no npm install needed to run)
```

## Try it

1. Open <http://localhost:1411/login>. Expand **"First time here? Create an Account"**,
   fill it in, and add a passkey (Windows Hello / Touch ID / security key).
2. Open <http://localhost:1411/attacker> on another screen. It says "waiting for a sign-in".
3. Back on `/login`, click **Sign in with passkey**. A row appears on the dashboard.
   Open it for **Welcome, &lt;you&gt;**, the stolen token, and its expiry countdown.

Every sign-in, by anyone, adds a row. With `STATIC_API_KEY` set, **anyone can create an
account** from the login page (open sign-up), so many people can join the demo. Without
it, "Create an Account" only works for the first user (Pocket ID's setup).

## How it works

- The app owns `http://localhost:1411` and reverse-proxies `/api/*` to Pocket ID, so the
  passkey ceremony happens on the origin Pocket ID expects (`APP_URL`).
- The attacker backend (`server.mjs`) stages a Pocket ID challenge per victim; the
  victim's backdoored page signs it; the backend calls `login/finish` to mint the
  victim's session. That finish response hands over both the token and the identity.
- `/x/stage`, `/x/drop`, `/x/sessions`, `/x/reset` are the attacker side. `/api/*` is
  Pocket ID.

## The fix: sender-constrained sessions (DPoP)

The attack wins because the session token is a bearer token: whoever holds it is the user.
The fix is to **bind the session to a key the signing browser keeps**, so a relayed or stolen
token is inert. A full working version lives in [pocketid-demo/defended/](pocketid-demo/defended/)
(self-contained, zero-dependency relying party; [its README](pocketid-demo/defended/README.md)
has the details, and [defended/flow.puml](pocketid-demo/defended/flow.puml) is the sequence
diagram).

How it binds, in one line: a WebAuthn authenticator only signs `authenticatorData ||
SHA256(clientDataJSON)`, and the challenge is the one field JS controls that is guaranteed to
be inside that signature, so the binding goes in the nonce slot:

```
signedChallenge = SHA256( serverNonce + "." + jkt )     # jkt = thumbprint of a DPoP key
```

The browser's `PasskeyProvider` generates a **non-extractable** DPoP keypair (IndexedDB) and
folds its thumbprint `jkt` into the signed challenge. The relying party checks the signed
challenge commits to that key, **binds the session token to `jkt`**, and requires a fresh
[RFC 9449](https://www.rfc-editor.org/rfc/rfc9449) DPoP proof on every resource call. Running
the same relay against it: the attacker finishes the ceremony and mints a real token for the
victim, but `/api/me` refuses it (`proof key is not the bound key`) because the private key
never left the victim's browser; swapping in the attacker's own key breaks the challenge match
and the login is rejected.

Pocket ID is upstream (`ghcr.io/pocket-id/pocket-id:latest`) and cannot be modified to bind
its own sessions, so the defended flow is a relying party we own sitting next to it.

```bash
cd pocketid-demo/defended
ROLE=victim   PORT=1421 node server.mjs                                       # Acme (defended)
ROLE=attacker PORT=1423 VICTIM_ORIGIN=http://localhost:1421 node server.mjs   # attacker + drop
# open http://localhost:1421/login  (sign in works; "Simulate compromised page" stays locked)
# checks:  node e2e.mjs   |   node e2e-browser.mjs        (Playwright, virtual authenticator)
# videos:  node record.mjs   |   node record-split.mjs    (writes videos/combined.mp4)
```

## Reset

```bash
cd pocketid-demo
docker compose down -v && docker compose up -d   # wipe all users and passkeys
```

## Automated test (optional)

```bash
npm install && npx playwright install chromium   # Playwright, dev only
npm run e2e                                       # headless virtual-authenticator run
```

## Public or cross-machine demo

Passkeys bind to the hostname, so serve the app over a real HTTPS host and set `APP_URL`
to it. To host it on Azure Container Apps, see [DEPLOY.md](DEPLOY.md). Quick test tunnel:

```bash
cloudflared tunnel --url http://localhost:1411   # copy the https URL it prints
# set APP_URL=<that url> in pocketid-demo/.env, then: docker compose up -d --force-recreate
```
