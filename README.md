<p align="center"><img src="logo.svg" alt="Pass the Keys" width="170"></p>
<h1 align="center">Pass the Keys</h1>
<p align="center"><b>Passkey login-takeover: the exploit and the fix</b></p>

A passkey sign-in on a **compromised login page** can be relayed so an attacker ends up logged in
**as that user**. Passkeys stop phishing and remote replay; they do not protect a page already
running the attacker's code. The reusable prize is the **unbound session token**, so the fix is to
**sender-constrain** it: bind the session to a key the page can neither read nor swap.

Node-only, **no Docker**. One command per demo.

## Setup (once)

```bash
npm install
```

## 1. Run the exploit

```bash
npm run exploit
```

Then:

1. Open **http://localhost:5411/login** (the victim) and **http://127.0.0.1:5413/attacker** (the
   attacker) side by side.
2. On the victim page, expand **"First time here? Create an Account"**, fill it in, and add a
   passkey.
3. Click **Sign in with passkey**. Your page fails - but the **attacker tab flips to
   "Welcome, &lt;you&gt;"**. The attacker is now in your account.

The attacker gets a passkey challenge from the login server, the victim's backdoored page signs
it, and the attacker submits that signature to mint the victim's session. (Runs over
[Better Auth](https://better-auth.com) + SQLite.) Ctrl+C stops it.

## 2. Run the fix and watch the same attack fail

```bash
npm run fix
```

Then:

1. Open **http://localhost:1521/login** (victim) and **http://127.0.0.1:1523/attacker** (attacker).
2. Create an account + passkey, then click **Sign in with passkey** - you land on **"Welcome"**.
   The fix works for the real user.
3. Click **Simulate compromised page (relay my sign-in)**. The attacker tab shows **"Session
   captured, but locked"**: the relay completes and a token is minted, but it is **inert**.

## Why the fix works

The exploit wins because the session is a bearer token: whoever holds it is the user. The fix is a
**`dpop` WebAuthn extension** where the **authenticator mints a fresh per-session key and names it**
inside the signed `authenticatorData`. The server binds the session to that key, and every request
needs a fresh proof signed by it.

The key lives in the authenticator, **below the page**, so a page running the attacker's code can
neither read it (no exfiltration) nor point the binding at a key the attacker holds (no
substitution). The relayed login still mints a token, but without the key it is inert.

Details: [demos/dpop-ext/SPEC.md](demos/dpop-ext/SPEC.md) and [the flow](demos/dpop-ext/flow.puml).

## What's here

| Directory | What |
|---|---|
| [demos/betterauth-exploit/](demos/betterauth-exploit/) | the attack (Better Auth + SQLite, no Docker) |
| [demos/dpop-ext/](demos/dpop-ext/) | the fix: the `dpop` WebAuthn extension |

Headless proof (no browser): `npm run fix:test`.

> Authorized demo use only: your own machine and disposable test users.
