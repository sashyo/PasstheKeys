---
desk: ideas
title: "I Tried to Break a Passkey. So I Took the Token Instead."
dek: A passkey stops the attacker who is far away. On a page they already control, it signs whatever it is handed and mints a token bound to nothing. A hands-on look at where passkey security actually ends.
date: 2026-11-10
author: Sasha
art: key
draft: true
---
We are told passkeys are unphishable, and against a fake site that is true. But on the real site a passkey is remarkably trusting. It signs whatever challenge the page puts in front of it, and the session that unlocks is a token bound to nothing. The strength is only at a distance. Up close, where the attacker already is, it signs the wrong thing and hands out a key that fits any lock. I spent a few days standing up close. Here is what I walked out with.

## The one thing passkeys get right

Start with the part that works, because it really does. When you sign in with a passkey, your device makes a small signed blob, and it stamps the exact web address into it, letter for letter. Carry that blob to any other site and the address no longer matches, so it is thrown out on sight. This is why a lookalike login page can harvest your passkey all day and never reuse it. Phishing kits replay passwords and one-time codes by the hour. A passkey, they cannot touch. Credit where it is due: from across the internet, this is a wall.

## What they never check

Now the part nobody mentions. A passkey binds four things: which key signed, which site, which address, and a one-time number the server issued, the challenge. That is the whole promise. Read the list again and notice what is missing. The device does not check where that number came from. It does not check what signing it will let through. It does not care what becomes of the session afterward. You tap your finger, it signs the number in front of it, and it never asks who wrote the number down.

At a distance, that gap is harmless. The attacker cannot get their number onto the real page, or get your signature back off it. So the gap just sits there, out of reach.

Unless the attacker is already on the page.

## So I stood on the page

Picture my code running on the real login screen. Pick your way in: a cross-site-scripting hole, a sketchy browser extension, one poisoned dependency in a pile of thousands. The passkey's crypto stays perfectly intact. I just have to be on the page when you use it.

I start my own login, and the server hands me a fresh challenge. I take that number and quietly drop it into your sign-in, where your number used to be. You tap your fingerprint on the real site, see a normal welcome, and carry on with your day. Your device just signed my number, on the right address, with your key. I carry the signature back and finish the login I started. I am you now.

The part that still unsettles me: I never had an account. The login hands out an anonymous challenge and learns who you are from whoever signs. The session I walk away with is brand new, minted on demand, and it wears your name.

Two honest things. It needs the breach first; from a distance a passkey still shrugs me off, and that is worth a lot. And once my code is on your authenticated page, I have other mischief available. But look hard at what the passkey did, on its own: it handed a working login for someone else to a stranger who offered nothing but a number. It checked the address and the signature, and never once asked whether it was signing the right thing.

## The token fits any lock

Here is where it gets worse, and where it stops being about passkeys at all. The signature I harvested was single use, locked to one moment, useless to keep. But the thing the server hands back the instant it works, your session token, is locked to nothing.

It is a plain bearer token. Hold it and you are treated as the user, full stop. Send it from another laptop, another country, a script with no device and no passkey, and the server says yes. The credential that mints those tokens travels just as well; lift it once and print new tokens from anywhere, long after any single one dies. "Tokens expire in a minute" is cold comfort when the machine that makes them is in my pocket.

> The passkey signs the wrong thing. The token it earns fits any lock.

## Tide watches both doors

A passkey proves you are present and stops there. Tide keeps watching, on both sides of the signature.

Going in, before Tide's network will use a key, every node runs the request through a Forseti contract: a small program that checks the request is the one it is meant to honor, the right shape, the right person, the right action. A number that wandered in from somewhere else, aimed at something you never intended, does not get honored. The page is pinned to its own hashes with subresource integrity too, so the swapped-in script that starts this whole attack never loads to begin with.

Coming out, the token is bound to the device that earned it, sender-constrained, DPoP in the standards. Carry it to another laptop and it is dead on arrival. In our [3D login piece](#/record/0016-logging-in) you can watch a hacker copy a Tide token and get precisely nowhere. This post is the other half of that story: an unbound token going everywhere.

The passkey never asked where the number came from, what it authorized, or what became of the session. Tide asks all three.

## What I built

All of it runs on my own instance, throwaway users, nothing real touched. There is an ordinary-looking app with an ordinary login, backdoored the way a breached page would be. Anyone can create an account and add a passkey. The moment they sign in, that one tap is relayed, and on a second screen an attacker's dashboard fills up, one row per person, each row a live token with a countdown ticking toward zero. Open a row and it greets you by their name, read straight off their account with their own stolen token.

Nobody faked a passkey. Nobody had to.

## The far door and the near one

Passkeys are not broken, and they are not magic. They stop the attacker who is far away, which is most of them, and they do it better than anything we had before. They do not protect a page the attacker is already standing on, and there they are startlingly literal. They sign the number in front of them. They hand back a token tied to nothing. The far door is bolted. The near one swings open, and what walks out is the token.

A passkey never watches that door. Tide watches both.
