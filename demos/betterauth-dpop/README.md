# The fix: Better Auth + the `dpop` extension

A [Better Auth](https://better-auth.com) app whose `dpop` plugin ([dpop-plugin.mjs](dpop-plugin.mjs))
adds the sender-constraining WebAuthn extension. The authenticator mints a fresh per-session key
`SK`, names `SK_pub` inside the signed `authenticatorData`, and the plugin binds the Better Auth
session to `jkt = thumbprint(SK_pub)` and requires a per-request proof signed by `SK`.

This is the **fix** half of the project; the exploit is its own Better Auth app
([../betterauth-exploit/](../betterauth-exploit/), `npm run exploit`). Run the fix with the same
relay and it fails.

> No Docker, no database, no native modules. In-memory store; **restarting the server wipes all
> accounts and passkeys** - see the note below. Authorized demo use only.

## Run

```bash
npm run fix
```

Starts three roles on three hosts (all resolve to `127.0.0.1` in the browser):

- **victim** `http://victim.localhost:1521/login` - Acme, Better Auth mounted at `/api/auth`
- **attacker** `http://attacker.localhost:1523/attacker` - attacker site, dead-drop, `/api/auth` proxy
- **authenticator** `http://authenticator.localhost:1525` - the simulated extended authenticator (iframe origin)

Open the victim and attacker URLs side by side, create an account + passkey on the victim, then use
**Sign in with passkey** (works) and **Simulate compromised page** (the attacker tab lands
"captured, but locked").

## Heads-up: restart = re-enroll

The store is in memory, so **restarting the server forgets every account and passkey**. The
simulated authenticator keeps its credential in the browser, so after a restart you may see
`unknown credential` on sign-in - just expand **Create an account** and enroll again (enrolling
replaces the authenticator's credential, so there is never a stale one).

## Why a custom plugin and a simulated authenticator

Better Auth's built-in passkey plugin verifies **real** browser WebAuthn via `@simplewebauthn`, and
no real browser or authenticator implements a `dpop` extension that mints and names a per-session
key. So the demo drives a **simulated** authenticator served from its own origin
([public/authenticator.html](public/authenticator.html)), embedded as an iframe; same-origin policy
keeps its keys unreadable to the RP page (the hardware-boundary stand-in). The `dpop` plugin verifies
those assertions itself and creates a normal Better Auth session bound to the signed key. Better Auth
owns users and sessions; the plugin adds the sender-constraint. See
[../dpop-ext/SPEC.md](../dpop-ext/SPEC.md) for the extension itself.

## How the fix defeats the relay

The compromised page relays the login assertion, which names the **victim's** `SK`. The attacker
finishes and Better Auth mints a real session bound to that `SK` (`jkt`), but:

- it cannot produce proofs - `SK` is sealed in the victim's authenticator (no exfiltration), and
- it cannot point the binding at a key it holds - `SK_pub` rides in the **signed** `authenticatorData` (no substitution).

So `/api/auth/dpop/me` requires a fresh `SK` proof the attacker can't make, and the stolen session is
inert.

## Checks

Headless model (authenticator emulated in Node), with **no browser**:

```bash
npm run fix:test
```

It exercises the plugin in both states (the `enforce` option) to prove the fix matters: with
enforcement on, legit login binds to the signed `SK` and `/dpop/me` unlocks with a proof, while the
relayed session is refused without a proof, with a proof from the attacker's own key, and a
substituted assertion is rejected; with enforcement off, the same relay takes over.

## PoC simplifications

Zero crypto deps, so: ES256 only; raw EC public keys and raw ECDSA signatures (not COSE/DER);
`SK_pub` appended raw after `signCount` (standing in for the CBOR extensions block); the authenticator
iframe stands in for real authenticator hardware; the plugin's challenge/binding stores are in-memory.
