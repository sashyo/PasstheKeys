// Record a clean demo video of the PasstheKeys flow (no overlays, real UI).
//   attacker.webm : the dashboard, waiting, then rows appearing as people sign in,
//                   then opening one to reveal Welcome + the stolen token.
//   victim.webm   : one person creating an account and signing in on the app.
// Uses a virtual authenticator so no real biometric prompt is needed.
import { chromium } from 'playwright';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import fs from 'node:fs';

const APP = process.env.APP || 'http://localhost:1411';
const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const VDIR = path.join(__dirname, 'videos');
const SIZE = { width: 1280, height: 820 };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const VICTIMS = [
  { first: 'Jordan', last: 'Avery', username: 'jordan', email: 'jordan@demo.local' },
  { first: 'Priya', last: 'Nair', username: 'priya', email: 'priya@demo.local' },
  { first: 'Marco', last: 'Bianchi', username: 'marco', email: 'marco@demo.local' },
];

async function ctx(browser, record, auth) {
  const c = await browser.newContext({ userAgent: UA, viewport: SIZE, ...(record ? { recordVideo: { dir: VDIR, size: SIZE } } : {}) });
  await c.addInitScript(() => { Object.defineProperty(navigator, 'webdriver', { get: () => false }); });
  const page = await c.newPage();
  if (auth) {
    const cdp = await c.newCDPSession(page);
    await cdp.send('WebAuthn.enable');
    await cdp.send('WebAuthn.addVirtualAuthenticator', { options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } });
  }
  return { c, page };
}

async function enrollAndSignIn(page, v, { slow } = {}) {
  await page.goto(`${APP}/login`, { waitUntil: 'domcontentloaded' });
  await sleep(slow ? 900 : 300);
  await page.click('#setup summary');
  for (const [sel, val] of [['#first', v.first], ['#last', v.last], ['#username', v.username], ['#email', v.email]]) {
    await page.fill(sel, val); if (slow) await sleep(220);
  }
  await page.click('#enroll');
  await page.waitForFunction(() => /passkey added/i.test(document.getElementById('setupStatus')?.textContent || ''), null, { timeout: 30000 });
  await sleep(slow ? 1100 : 400);
  await page.click('#go');
  await page.waitForFunction(() => document.getElementById('home')?.style.display === 'block', null, { timeout: 20000 });
  await sleep(slow ? 1600 : 500);
}

fs.mkdirSync(VDIR, { recursive: true });
const browser = await chromium.launch({ headless: true });
const att = await ctx(browser, true, false);
let victimVideo = null;
try {
  await att.page.goto(`${APP}/attacker`, { waitUntil: 'domcontentloaded' });
  await sleep(3000); // let the "waiting for a sign-in" state breathe

  for (let i = 0; i < VICTIMS.length; i++) {
    const v = VICTIMS[i];
    const record = i === 0; // record the first victim's screen as the victim clip
    const vc = await ctx(browser, record, true);
    await enrollAndSignIn(vc.page, v, { slow: record });
    if (record) { victimVideo = vc.page.video(); }
    await vc.c.close();
    await sleep(3200); // let the new row land + settle on the attacker video
  }

  // Open the most recent capture to reveal Welcome + token + countdown.
  await att.page.click('[data-open]');
  await att.page.waitForSelector('.bigname', { timeout: 5000 });
  await sleep(5000);
} finally {
  const names = [];
  const vp = await att.page.video()?.path();
  await att.c.close();
  if (vp) { const d = path.join(VDIR, 'attacker.webm'); try { fs.renameSync(vp, d); names.push(d); } catch { names.push(vp); } }
  if (victimVideo) { const p = await victimVideo.path(); const d = path.join(VDIR, 'victim.webm'); try { fs.renameSync(p, d); names.push(d); } catch { names.push(p); } }
  await browser.close();
  console.log('\nVideos:'); for (const n of names) console.log('  ' + n);
}
