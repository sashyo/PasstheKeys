# Passkey login-takeover: the exploit and the fix

On an already-breached login page, one victim passkey sign-in can be **relayed** so an attacker
ends up logged in **as that user**. Passkeys stop phishing and remote replay; they do not protect
a page that is already running the attacker's code. The reusable prize is the **unbound session**
(a bearer cookie/token), so the real fix is to **sender-constrain** it: bind the session to the
passkey, below the page.

Everything here is **Node-only, no Docker**.

## Quick links

**The fix** (the point of this repo) - sender-constrain the session so a stolen or relayed token is inert:

- **[Passkey-bound sessions](demos/defended/)** - runs in browsers today: the session binds
  to the passkey credential that signed the login, and every request needs a fresh passkey proof.
- **[`dpop` WebAuthn extension](demos/dpop-ext/)** - a prototype extension where the
  authenticator mints and *names* a fresh per-session key inside the signed `authenticatorData`,
  closing both key exfiltration and key substitution. See the [SPEC](demos/dpop-ext/SPEC.md)
  and the [flow](demos/dpop-ext/flow.puml).

**The exploit** it defends against (two layers):

- **Frontend takeover** - a compromised login page relays your passkey sign-in and the attacker
  lands in your account: [demos/betterauth-exploit/](demos/betterauth-exploit/).
- **Backend token replay** - the unbound session is a bearer token: leak it server-side and replay
  it anywhere. The fix makes it useless without the bound key.

> Authorized demo use only: your own machine and disposable test users.

## Layout

| Directory | What | Run |
|---|---|---|
| [betterauth-exploit/](demos/betterauth-exploit/) | the attack, over [Better Auth](https://better-auth.com) (SQLite, no Docker) | `npm run exploit:migrate && npm run exploit` |
| [defended/](demos/defended/) | fix 1: passkey-bound sessions | `npm run defended` |
| [dpop-ext/](demos/dpop-ext/) | fix 2: the `dpop` WebAuthn extension | `npm run ext` |

## The exploit (Better Auth, Docker-free)

```bash
npm install                                        # better-auth, @better-auth/passkey, better-sqlite3
cd demos/betterauth-exploit
node migrate.mjs                                   # create the SQLite tables (once)
ROLE=victim   PORT=5411 node server.mjs            # Acme on http://localhost:5411
ROLE=attacker PORT=5413 VICTIM_ORIGIN=http://localhost:5411 node server.mjs   # attacker on http://127.0.0.1:5413
```

1. Open <http://localhost:5411/login>, create an account, add a passkey.
2. Open <http://127.0.0.1:5413/attacker> on another screen ("waiting for a sign-in").
3. Back on `/login`, click **Sign in with passkey**. Your tab fails - but the attacker tab flips
   to **"Welcome, &lt;you&gt;"**. The attacker holds your session.

Better Auth issues the login challenge in a signed cookie; the attacker GETs it, the victim's
backdoored page signs it, and the attacker POSTs the assertion to mint the victim's session. The
victim runs on `localhost` and the attacker on `127.0.0.1` so their cookie jars stay separate.
Details in [its README](demos/betterauth-exploit/README.md).

## The fix: passkey-bound sessions

The attack wins because the session is a bearer token: whoever holds it is the user. The fix is to
**bind the session to the passkey credential itself**, so a relayed token is inert. The key must
live **below the page**: this threat model is "the page is already running the attacker's code,"
so any key the page generates, derives (even via the WebAuthn PRF extension), or reads, the page
can also hand to the attacker. The one key a compromised page can neither choose nor exfiltrate is
the passkey credential's private key, which lives in the authenticator and only ever signs
assertions. So that is the binding key:

- the server binds the session to the **public key of the credential that signed the login** (the
  page supplies no key);
- `/api/me` requires `Authorization: Passkey <token>` **and** a fresh proof-of-possession assertion
  signed by that credential over `SHA256("GET <htu> <nonce>")` (one-time nonce).

Run the same relay against it and the attacker mints a real token but `/api/me` refuses it
(`missing passkey proof`): the proof needs a fresh assertion from the victim's authenticator, which
the attacker's machine does not have and the page cannot extract. Full write-up and a headless
proof (`node e2e.mjs`) in [demos/defended/](demos/defended/).

## The fix, taken further: the `dpop` WebAuthn extension

Passkey-bound sessions reuse the long-lived login credential. The
[`dpop` extension](demos/dpop-ext/) prototypes having the **authenticator mint a fresh
per-session key and name it** inside the signed `authenticatorData`, so the binding key is neither
readable nor choosable by the page. See the [SPEC](demos/dpop-ext/SPEC.md),
[flow](demos/dpop-ext/flow.puml), and a headless proof (`node e2e.mjs`).

## Prerequisites

- Node 18+
- `npm install` at the repo root (pulls `better-auth`, `@better-auth/passkey`, `better-sqlite3`;
  the native module installs a prebuilt binary, no compiler needed). The two fix demos are
  zero-dependency Node and need nothing installed to run.
