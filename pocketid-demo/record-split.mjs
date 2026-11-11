// Record victim and attacker tabs at the same size, for a side-by-side clip.
// Stitch: ffmpeg -i split-victim -i split-attacker -filter_complex hstack.
// The victim's passkey prompt is held on screen (auto-presence is turned off so the
// "Approve the passkey prompt" state shows), then completed, so the passkey step is visible.
import { chromium } from 'playwright';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import fs from 'node:fs';

const APP = process.env.APP || 'http://localhost:1411';   // the website (Acme)
const ATT = process.env.ATT || 'http://127.0.0.1:1413';    // the attacker's separate site
const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const VDIR = path.join(__dirname, 'videos');
const SIZE = { width: 720, height: 880 };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const u = 'jordan' + Date.now().toString().slice(-4);
const V = { first: 'Jordan', last: 'Avery', username: u, email: u + '@demo.local' };

async function ctx(browser, auth) {
  const c = await browser.newContext({ userAgent: UA, viewport: SIZE, recordVideo: { dir: VDIR, size: SIZE } });
  await c.addInitScript(() => { Object.defineProperty(navigator, 'webdriver', { get: () => false }); });
  const page = await c.newPage();
  let cdp = null, authId = null;
  if (auth) {
    cdp = await c.newCDPSession(page);
    await cdp.send('WebAuthn.enable');
    const r = await cdp.send('WebAuthn.addVirtualAuthenticator', { options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } });
    authId = r.authenticatorId;
  }
  return { c, page, cdp, authId };
}

fs.mkdirSync(VDIR, { recursive: true });
const browser = await chromium.launch({ headless: true });
const att = await ctx(browser, false);
const vic = await ctx(browser, true);
try {
  // Clean the dead-drop so no stale nonce is in play.
  await att.c.request.post(`${ATT}/x/reset`).catch(() => {});

  await att.page.goto(`${ATT}/attacker`, { waitUntil: 'domcontentloaded' }); // attacker's own site, arms its nonce
  await vic.page.goto(`${APP}/login?slow`, { waitUntil: 'domcontentloaded' }); // ?slow holds the passkey prompt on camera
  await sleep(2200); // both idle: login form on the left, "waiting" on the right

  // Victim creates an account + passkey (presence auto-on, so enrollment just works).
  await vic.page.click('#setup summary');
  for (const [sel, val] of [['#first', V.first], ['#last', V.last], ['#username', V.username], ['#email', V.email]]) { await vic.page.fill(sel, val); await sleep(240); }
  await sleep(400);
  await vic.page.click('#enroll');
  await vic.page.waitForFunction(() => /passkey added/i.test(document.getElementById('setupStatus')?.textContent || ''), null, { timeout: 30000 });
  await sleep(1200);

  // Sign in. The ?slow page holds the "Approve the passkey prompt" state on screen for a
  // beat (the passkey step), then the virtual authenticator signs automatically.
  await att.page.waitForFunction(async () => { try { return !!(await (await fetch('/x/offer')).json()).challenge; } catch { return false; } }, null, { timeout: 10000 });
  await vic.page.click('#go');
  await vic.page.waitForFunction(() => /approve the passkey/i.test(document.getElementById('status')?.textContent || ''), null, { timeout: 10000 });

  // Victim's own sign-in fails; the attacker finishes and lands in their account.
  await vic.page.waitForFunction(() => /did not work/i.test(document.getElementById('status')?.textContent || ''), null, { timeout: 15000 });
  await att.page.waitForFunction(() => document.getElementById('home')?.style.display === 'block', null, { timeout: 15000 });
  await sleep(4500); // hold on victim-failed vs attacker-in
} finally {
  const vv = vic.page.video(), av = att.page.video();
  await vic.c.close();
  await att.c.close();
  const dst = {};
  for (const [name, v] of [['victim', vv], ['attacker', av]]) {
    const p = await v?.path(); if (!p) continue;
    const d = path.join(VDIR, `split-${name}.webm`); try { fs.renameSync(p, d); dst[name] = d; } catch { dst[name] = p; }
  }
  await browser.close();
  console.log('panes:'); for (const k in dst) console.log('  ' + dst[k]);
}
