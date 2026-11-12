# Passkey login-takeover: the exploit and the fix

A passkey sign-in on a **compromised login page** can be relayed so an attacker ends up logged in
**as that user**. Passkeys stop phishing and remote replay; they do not protect a page already
running the attacker's code. The reusable prize is the **unbound session token**, so the fix is to
**sender-constrain** it: bind the session to the passkey, below the page.

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

Two flavors of the same idea - pick either:

```bash
npm run defended     # passkey-bound sessions (works in browsers today)
npm run ext          # the dpop WebAuthn extension (prototype)
```

Then (ports differ per demo; the command prints the two URLs):

1. Open the victim `/login` and the attacker `/attacker` pages it prints.
2. Create an account + passkey, then click **Sign in with passkey** - you land on **"Welcome"**.
   The fix works for the real user.
3. Click **Simulate compromised page (relay my sign-in)**. The attacker tab shows **"Session
   captured, but locked"**: the relay completes and a token is minted, but it is **inert**.

| `npm run` | URLs it prints |
|---|---|
| `defended` | victim `http://localhost:1421/login` · attacker `http://127.0.0.1:1423/attacker` |
| `ext` | victim `http://localhost:1521/login` · attacker `http://127.0.0.1:1523/attacker` |

## Why the fix works

The session is bound to **the passkey credential itself** - a key that lives in the authenticator,
which a compromised page can neither read nor swap. The server binds the session to the public key
of the credential that signed the login, and every request needs a fresh passkey proof. A relayed
or stolen token is useless without that key.

- **[defended/](demos/defended/)** binds to the long-lived login passkey (deployable today).
- **[dpop-ext/](demos/dpop-ext/)** prototypes a WebAuthn extension where the authenticator mints a
  fresh per-session key and names it in the signed `authenticatorData`. See the
  [SPEC](demos/dpop-ext/SPEC.md) and [flow](demos/dpop-ext/flow.puml).

## What's here

| Directory | What |
|---|---|
| [demos/betterauth-exploit/](demos/betterauth-exploit/) | the attack (Better Auth + SQLite, no Docker) |
| [demos/defended/](demos/defended/) | fix 1: passkey-bound sessions |
| [demos/dpop-ext/](demos/dpop-ext/) | fix 2: the `dpop` WebAuthn extension |

Headless proofs (no browser): `npm run defended:test`, `npm run ext:test`.

> Authorized demo use only: your own machine and disposable test users.
