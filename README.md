# Passkey login takeover demo (Pocket ID)

On an already-breached login page, one victim passkey sign-in can be relayed so an
attacker ends up logged in **as that user**. The attacker screen is a live dashboard of
captured sessions. Passkeys stop phishing and remote replay; they do not protect a page
that is already running the attacker's code. The reusable prize is the **unbound session
token**, so the real fix is to sender-constrain it: bind the session to the passkey, below the
page.

## Quick links

**The fix** (the point of this repo) - sender-constrain the session so a stolen or relayed token is inert:

- **[Passkey-bound sessions](pocketid-demo/defended/)** - the fix that runs in browsers today: the
  session binds to the passkey credential that signed the login, and every request needs a fresh
  passkey proof. See [the write-up below](#the-fix-passkey-bound-sessions).
- **[`dpop` WebAuthn extension](pocketid-demo/dpop-ext/)** - a prototype extension where the
  authenticator mints and *names* a fresh per-session key inside the signed `authenticatorData`,
  closing both key exfiltration and key substitution. Read the [SPEC](pocketid-demo/dpop-ext/SPEC.md)
  and the [flow](pocketid-demo/dpop-ext/flow.puml).

**The exploit** it defends against (two layers):

- **Frontend takeover** - a compromised login page relays your passkey sign-in and the attacker
  lands in your account ([try it](#try-it); code in [pocketid-demo/](pocketid-demo/)).
- **Backend token replay** - the unbound session token is a bearer token: leak it server-side and
  replay it anywhere. The fix makes it useless without the bound key.

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

## The fix: passkey-bound sessions

The attack wins because the session token is a bearer token: whoever holds it is the user. The
fix is to **bind the session to the passkey credential itself**, so a relayed token is inert. A
full working version lives in [pocketid-demo/defended/](pocketid-demo/defended/) (self-contained,
zero-dependency relying party; [its README](pocketid-demo/defended/README.md) has the details,
and [defended/flow.puml](pocketid-demo/defended/flow.puml) is the sequence diagram).

The key must live **below the page**. This threat model is "the page is already running the
attacker's code," so any key the page generates, derives (even via the WebAuthn PRF extension),
or reads, the page can also hand to the attacker. The one key a compromised page can neither
choose nor exfiltrate is the passkey credential's private key, which lives in the authenticator
and only ever signs assertions. So that is the binding key:

- the server binds the session to the **public key of the credential that signed the login**
  (the page supplies no key);
- `/api/me` requires `Authorization: Passkey <token>` **and** a fresh proof-of-possession
  assertion signed by that credential over `SHA256("GET <htu> <nonce>")` (one-time nonce).

Running the same relay against it: the attacker finishes the ceremony and mints a real token for
the victim, but `/api/me` refuses it (`missing passkey proof`) because a request needs a fresh
assertion from the victim's authenticator, which the attacker's machine does not have and the
page cannot extract. A compromised page can coax at most one more user-approved, single-use
proof out of the authenticator, never the key or a durable session.

Pocket ID is upstream (`ghcr.io/pocket-id/pocket-id:latest`) and cannot be modified to bind its
own sessions, so the defended flow is a relying party we own sitting next to it. Requiring a
passkey tap per request is heavy; a production system would amortize it (short-lived proof-bound
tokens, or browser-level device binding such as DBSC).

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
