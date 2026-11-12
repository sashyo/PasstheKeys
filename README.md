<p align="center"><img src="logo.svg" alt="Pass the Keys" width="170"></p>
<h1 align="center">Pass the Keys</h1>
<p align="center"><b>Passkey login-takeover: the exploit and the fix</b></p>

A passkey sign-in on a **compromised login page** can be relayed so an attacker ends up logged in
**as that user**. Passkeys stop phishing and remote replay; they do not protect a page already
running the attacker's code. The reusable prize is the **unbound session token**, so the fix is to
**sender-constrain** it: bind the session to a key the page can neither read nor swap.

Two [Better Auth](https://better-auth.com) apps: the **exploit** (a plain passkey login that gets
relayed) and the **fix** (the same login with a `dpop` plugin that sender-constrains the session).
Node-only, **no Docker, no database**. One command each.

## Setup (once)

```bash
npm install
```

## 1. Run the exploit

```bash
npm run exploit
```

Then:

1. Open **http://victim.localhost:5411/login** (the victim) and
   **http://attacker.localhost:5413/attacker** (the attacker) side by side.
2. On the victim page, expand **"First time here? Create an Account"**, fill it in, and add a
   passkey.
3. Click **Sign in with passkey**. Your page fails - but the **attacker tab flips to
   "Welcome, &lt;you&gt;"**. The attacker is now in your account.

The attacker gets a passkey challenge, the victim's compromised page signs it, and the attacker
submits that signature to mint the victim's session. Ctrl+C stops it.

## 2. Run the fix and watch the same attack fail

```bash
npm run fix
```

A second app on its own ports. Open **http://victim.localhost:1521/login** and
**http://attacker.localhost:1523/attacker**, create an account + passkey, then:

- **Sign in with passkey** - you land on **"Welcome"**. The fix works for the real user.
- **Simulate compromised page (relay my sign-in)** - the attacker tab shows **"Session captured,
  but locked"**: the relay completes and Better Auth mints a session, but it is **inert**.

## Why the fix works

The exploit wins because the session is a bearer token: whoever holds it is the user. The fix is a
**`dpop` Better Auth plugin** implementing a WebAuthn extension where the **authenticator mints a
fresh per-session key and names it** inside the signed `authenticatorData`. The plugin binds the
Better Auth session to that key (`jkt`), and every request needs a fresh proof signed by it.

The key lives in the authenticator, **below the page**, so a page running the attacker's code can
neither read it (no exfiltration) nor point the binding at a key the attacker holds (no
substitution). The relayed login still mints a session, but without the key it is inert.

Details: [demos/betterauth-dpop/](demos/betterauth-dpop/) and the extension spec in
[demos/dpop-ext/SPEC.md](demos/dpop-ext/SPEC.md).

## What's here

| Directory | What |
|---|---|
| [demos/betterauth-exploit/](demos/betterauth-exploit/) | **the exploit**: the passkey relay on Better Auth (ports 5411/5413) |
| [demos/betterauth-dpop/](demos/betterauth-dpop/) | **the fix**: the same login with the `dpop` Better Auth plugin (ports 1521/1523/1525) |
| [demos/dpop-ext/SPEC.md](demos/dpop-ext/SPEC.md) | the `dpop` WebAuthn extension spec and flow diagrams |

Headless proof of the fix (no browser): `npm run fix:test`.

> Authorized demo use only: your own machine and disposable test users.
