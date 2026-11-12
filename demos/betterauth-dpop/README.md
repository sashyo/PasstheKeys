# Better Auth + the `dpop` extension: one app, one toggle

The exploit and the fix in a single [Better Auth](https://better-auth.com) app. A `dpop` Better
Auth plugin ([dpop-plugin.mjs](dpop-plugin.mjs)) adds the sender-constraining WebAuthn extension:
the authenticator mints a fresh per-session key `SK`, names `SK_pub` inside the signed
`authenticatorData`, and the plugin binds the Better Auth session to `jkt = thumbprint(SK_pub)` and
requires a per-request proof signed by `SK`.

One environment variable flips the demo:

| Mode | `DPOP_ENFORCE` | What happens |
|---|---|---|
| **exploit** | `0` | plain passkey login; a relayed assertion mints a **usable** session (account takeover) |
| **fix** | `1` | the session is **dpop-bound**; the relayed session mints a token but it is **inert** |

> No Docker, no database, no native modules. In-memory store; restarting wipes all state.
> Authorized demo use only: your own machine and disposable test users.

## Run

```bash
npm run exploit    # dpop OFF — the relay takes over the attacker tab
npm run fix        # dpop ON  — the same relay lands "captured, but locked"
```

Each starts three roles on three hosts (all resolve to `127.0.0.1` in the browser):

- **victim** `http://victim.localhost:5411/login` — Acme, Better Auth mounted at `/api/auth`
- **attacker** `http://attacker.localhost:5413/attacker` — attacker site, dead-drop, `/api/auth` proxy
- **authenticator** `http://authenticator.localhost:5415` — the simulated extended authenticator (iframe origin)

Open the victim and attacker URLs side by side, create an account + passkey on the victim, then use
**Sign in with passkey** (works) and **Simulate compromised page** (relays to the attacker tab).

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

- it cannot produce proofs — `SK` is sealed in the victim's authenticator (no exfiltration), and
- it cannot point the binding at a key it holds — `SK_pub` rides in the **signed** `authenticatorData` (no substitution).

So `/api/auth/dpop/me` requires a fresh `SK` proof the attacker can't make, and the stolen session is
inert.

## Checks

Headless model (authenticator emulated in Node), runs **both** modes with no browser:

```bash
npm run fix:test
```

Asserts: legit login binds to the signed `SK` and `/dpop/me` unlocks with a proof; the relayed
session is refused without a proof and with a proof from the attacker's own key; a substituted
assertion is rejected; and with enforcement off the relay takes over.

## PoC simplifications

Zero crypto deps, so: ES256 only; raw EC public keys and raw ECDSA signatures (not COSE/DER);
`SK_pub` appended raw after `signCount` (standing in for the CBOR extensions block); the authenticator
iframe stands in for real authenticator hardware; the plugin's challenge/binding stores are in-memory.
