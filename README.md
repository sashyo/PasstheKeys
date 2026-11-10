# Passkey login takeover demo (Pocket ID)

On an already-breached login page, one victim passkey sign-in can be relayed so an
attacker ends up logged in **as that user**. The attacker screen is a live dashboard of
captured sessions. Passkeys stop phishing and remote replay; they do not protect a page
that is already running the attacker's code. The reusable prize is the **unbound session
token**, so the real fix is to bind it (DPoP / sender-constraining).

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

Every sign-in, by anyone, adds a row. For more names, create more users in Pocket ID's
admin UI (sign in as the first user, then Settings) and have each add a passkey.

## How it works

- The app owns `http://localhost:1411` and reverse-proxies `/api/*` to Pocket ID, so the
  passkey ceremony happens on the origin Pocket ID expects (`APP_URL`).
- The attacker backend (`server.mjs`) stages a Pocket ID challenge per victim; the
  victim's backdoored page signs it; the backend calls `login/finish` to mint the
  victim's session. That finish response hands over both the token and the identity.
- `/x/stage`, `/x/drop`, `/x/sessions`, `/x/reset` are the attacker side. `/api/*` is
  Pocket ID.

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
to it. Quick test tunnel:

```bash
cloudflared tunnel --url http://localhost:1411   # copy the https URL it prints
# set APP_URL=<that url> in pocketid-demo/.env, then: docker compose up -d --force-recreate
```
