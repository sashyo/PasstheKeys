---
desk: ideas
title: "I Tried to Break a Passkey. So I Took the Token Instead."
dek: A passkey stops the attacker who is far away. On a page they already control, it signs whatever it is handed and mints a token bound to nothing. A hands-on look at where passkey security actually ends.
date: 2026-11-10
author: Sasha
art: key
draft: true
---
We are told passkeys are unphishable, and against a fake site that is true. But on the real site a passkey is remarkably trusting. It signs whatever challenge the page puts in front of it, and the session that unlocks is a token bound to nothing. The strength is only at a distance. Up close, where the attacker already is, it signs the wrong thing and hands out a key that fits any lock.

## The tempting idea, and the one that actually works

The story people tell is simple: steal the proof your passkey makes when you log in, carry it to another site, and walk in as you. That version really does not work, and it is worth knowing why, because it is the one thing passkeys do brilliantly. The proof is stamped with the exact web address it was made on. Take it anywhere else and the address no longer matches, so it is thrown out. A fake login page cannot reuse a passkey the way it reuses a password.

But that is a story about distance. It assumes the attacker is far away, pulling your proof toward them. Flip it around. What if their code is already on the real page, the one with the right address? Then they do not move the proof at all. They change what you sign, right there, and let your own device hand them a clean, valid login. I built exactly that against a real login on my own test instance. It works.

## What a passkey actually checks

When you sign in, your device makes a small signed blob, and it binds four things into it: which key signed, which site, the exact address it was signed on, and a one-time number the server issued for that login, the challenge. That binding is real and it is strong. It is also the whole of what a passkey promises. Notice what is not on the list. It does not check where the challenge came from, or what signing it will authorize, or what becomes of the session afterward. The device signs the number it is handed. It never asks who wrote that number down.

From a distance that gap is harmless, because the attacker cannot get their challenge onto the real page or get the signature back off it. On the real page, the gap is the whole attack.

## Swapping the number, up close

Here is the move. My code is on the login page. Assume a cross-site-scripting hole, a bad browser extension, a poisoned dependency; pick your breach. I start my own login and catch the fresh challenge the server hands me. I slip that challenge into your sign-in in place of yours. You tap your fingerprint on the real site, see an ordinary welcome, and notice nothing. Your device just signed my challenge, on the right address, with your key. I carry that signature back to the server and finish my login. I am now you.

The sharp part: I never needed an account. The login hands out an anonymous challenge and learns who you are from whoever signs it. So this is not me riding your session. It is me getting a brand new one, as you, minted on demand.

Two honest notes. It needs the breach first; from a distance a passkey is still unphishable, and that is worth a great deal. And yes, once my code runs on your authenticated page I have other ways to cause trouble. But look at what the passkey did here on its own: it handed a valid login for someone else to a party that offered nothing but a number. It checked the address and the signature, and never once asked whether it was signing the right thing.

## And the token it mints is bound to nothing

Now the multiplier. The signature was single use, locked to one moment, useless to carry off. But the thing the server hands back the instant it succeeds, your session token, is locked to nothing at all.

It is a plain bearer token. Whoever holds it is treated as you. Send it from another laptop, another country, a script with no passkey and no device, and the server says yes. Worse, the long-lived credential that mints those tokens travels just as well. Grab it once and print fresh tokens from anywhere, long after any single one expires. "But tokens expire in a minute" buys nothing when the thing that makes them is in the attacker's pocket.

> The passkey signs the wrong thing. The token it earns fits any lock.

## Bind the token

The fix is not to make the passkey cleverer about what it signs, though that would help. It is to give the token the one property the passkey has and the token lacks: a tie to the device that earned it, so presenting it from anywhere else fails. That is sender-constraining, DPoP in the standards, and it is what Tide does. In our [3D login piece](#/record/0016-logging-in) you can watch a hacker copy a Tide token and get nowhere. This post is the other half: an unbound token going everywhere. Bind it, and a stolen token, or a credential lifted from a breached page, is dead weight on any machine but yours.

## What I actually built

All of it runs against my own instance with throwaway users, nothing real touched. A login page for an ordinary-looking app, backdoored the way a breached page would be. Anyone can create an account and add a passkey. When they sign in, that one tap is relayed, and on a second screen an attacker's dashboard fills with captured sessions, one row per person, each a live token with a ticking expiry. Open a row and it greets you by their name, read straight from their account with their own stolen token.

## The takeaway

Passkeys are not broken, and they are not magic. They stop the attacker who is far away, which is most attackers, and they do it better than anything before them. They do not protect a page the attacker is already standing on, and there they are startlingly literal: they sign the number in front of them and hand back a token tied to nothing. The far door is bolted. The near one swings open, and the thing it lets out is the token.

So bind the token.
