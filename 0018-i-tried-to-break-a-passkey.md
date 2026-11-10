---
desk: ideas
title: "I Tried to Break a Passkey. So I Took the Token Instead."
dek: Passkeys shrug off phishing and replay. The session token they hand out does not. A hands-on look at where passkey security ends, against a real login.
date: 2026-11-10
author: Sasha
art: key
draft: true
---
Hi, Sasha here. Serial vibe coder, back with a confession: I spent a few days trying to break a passkey, and I failed. I want to walk you through exactly how I failed, because the wall I kept hitting is the reason passkeys are worth having, and the one crack I found is the reason Tide binds your token.

## The tempting idea

The story people love is this one: steal the proof your passkey makes when you log in, replay it somewhere else, and walk in as you. If that worked, a passkey would be no safer than a password on a sticky note. So I tried it, against a real login on my own test instance.

It does not work. Here is why, because the why is the whole thing.

## The proof is glued to one moment

When you sign in with a passkey, your device makes a small signed blob. Four things are baked into that signature and cannot be peeled off: which key signed it, which site it was for, the exact web address it was signed on, and a one-time number the server handed out for that single login, called a challenge (or a nonce).

Take that blob anywhere else and it dies on all four at once. A different site has never seen your key and issued a different challenge. The same site a minute later has already used the challenge up. It is not a reusable ticket. It is a receipt for one specific moment that has already passed.

## "Fine, I'll just swap the nonce"

If the proof is glued to a nonce, the obvious move is to change the nonce. So I built a little hook that swaps the challenge the device signs, mid-login, and pointed it at a real sign-in.

The server rejected it, every time. The reason is simple once you see it. There are always two copies of the nonce, and I only ever control one.

The server makes the nonce and keeps its own copy, tied to that one login. My browser gets a copy too, just to hand to the device. I can scribble on my copy all I like. The server still checks against the copy in its own memory, which I cannot reach, and I cannot re-sign after the fact, because signing needs the private key, and that key never leaves the device.

> The nonce is public on purpose. The server sends it to you in the clear. Reading it, copying it, swapping it: none of that helps, because the authority lives in the server's memory and the device's key, and you hold neither.

The web address is glued in the same way, and that part is what kills phishing. If I lure you to my lookalike site and get you to sign, your device stamps my address into the signature, and the real site throws it out. This is why the phishing kits that happily replay passwords and one-time codes simply cannot replay a passkey.

## The one way through, and its asking price

There is exactly one way to get a usable proof: you sign on the real site, with my code already running inside it. That means the site is already breached, through a cross-site-scripting hole, a bad browser extension, a poisoned dependency, or broken transport.

I built that demo too, and it is unsettling to watch. I stage a challenge, and here is the kicker, I need no account of my own, because a usernameless login hands out an anonymous challenge and takes its identity from whoever signs. You visit the booby-trapped login, click sign in, approve your fingerprint, and see an ordinary welcome screen. You notice nothing. Meanwhile your freshly signed proof is already on its way to me.

Two honest notes. This needs the breach first. Passkeys resist phishing, they were never meant to survive a site already running the attacker's code, and nothing on the login screen can. And once I am that deep inside your session, I do not even need the passkey dance.

## Because the real prize was never the passkey

Here is the part that actually matters. The passkey proof is locked to one moment and useless to carry off. But the thing you get the instant it succeeds, your session token, is locked to nothing.

That token is a plain bearer token. Whoever holds it is treated as you. Send it from another laptop, another country, a script that owns no passkey and no device, and the server says yes. Worse, the long-lived credential that mints those tokens is portable too. Grab it once and you can print fresh tokens from anywhere, long after any single one expires. The usual comfort, "but tokens expire in a minute", buys nothing when the minting credential just makes more.

So every road I went down ended in the same place.

> You cannot fake the passkey. You do not need to. You take the token.

## Bind the token

The passkey already has the property the token is missing: it is tied to the device. The fix is to give the token the same treatment, so that presenting it from anywhere else fails. That is what sender-constraining means, DPoP in the standards, and it is what Tide does. In our [3D login piece](#/record/0016-logging-in) you can watch a hacker copy a Tide token and get nowhere. This post is the other half of that story: watch an unbound token go everywhere.

In the proof-of-concept, one endpoint takes a plain bearer token and another wants proof the caller actually holds the device key. The same stolen token sails through the first and bounces off the second. Bind the token, and a stolen token, or a credential harvested from a breached site, is dead weight on any machine but yours.

## What I actually built

All of this runs against my own development instance with throwaway test users. Nothing here touches a real account or a system I do not own. There is a nonce-swap test that comes back rejected, a two-machine demo where a friend signs in on their laptop and the proof lands on mine, and the token side, where a copied token works from a stranger's process and the bound endpoint turns it away.

## The takeaway

Passkeys deliver on their promise. Remote replay, nonce swapping and phishing all bounce off the challenge and the address and the key. They do not protect a site that is already breached, and nothing at the login layer does. And the portable prize behind every login was never the passkey. It is the token.

So bind the token.
