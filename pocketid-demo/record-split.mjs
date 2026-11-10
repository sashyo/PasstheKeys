// Record victim and attacker at the same time, same frame size, for a side-by-side clip.
// Stitch the two outputs with: ffmpeg -i victim -i attacker -filter_complex hstack.
import { chromium } from 'playwright';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import fs from 'node:fs';

const APP = process.env.APP || 'http://localhost:1411';
const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const VDIR = path.join(__dirname, 'videos');
const SIZE = { width: 720, height: 880 };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const V = { first: 'Jordan', last: 'Avery', username: 'jordan', email: 'jordan@demo.local' };

async function ctx(browser, auth) {
  const c = await browser.newContext({ userAgent: UA, viewport: SIZE, recordVideo: { dir: VDIR, size: SIZE } });
  await c.addInitScript(() => { Object.defineProperty(navigator, 'webdriver', { get: () => false }); });
  const page = await c.newPage();
  if (auth) {
    const cdp = await c.newCDPSession(page);
    await cdp.send('WebAuthn.enable');
    await cdp.send('WebAuthn.addVirtualAuthenticator', { options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } });
  }
  return { c, page };
}

fs.mkdirSync(VDIR, { recursive: true });
const browser = await chromium.launch({ headless: true });
const att = await ctx(browser, false);
const vic = await ctx(browser, true);
try {
  await att.page.goto(`${APP}/attacker`, { waitUntil: 'domcontentloaded' });
  await vic.page.goto(`${APP}/login`, { waitUntil: 'domcontentloaded' });
  await sleep(2500); // both idle: login form on the left, "waiting" on the right

  // Victim creates an account + passkey.
  await vic.page.click('#setup summary');
  for (const [sel, val] of [['#first', V.first], ['#last', V.last], ['#username', V.username], ['#email', V.email]]) { await vic.page.fill(sel, val); await sleep(260); }
  await sleep(500);
  await vic.page.click('#enroll');
  await vic.page.waitForFunction(() => /passkey added/i.test(document.getElementById('setupStatus')?.textContent || ''), null, { timeout: 30000 });
  await sleep(1400);

  // Victim signs in with one tap; the row lands on the attacker pane.
  await vic.page.click('#go');
  await vic.page.waitForFunction(() => document.getElementById('home')?.style.display === 'block', null, { timeout: 20000 });
  await att.page.waitForSelector('[data-open]', { timeout: 10000 });
  await sleep(2800);

  // Attacker opens the capture to reveal Welcome + token + countdown.
  await att.page.click('[data-open]');
  await att.page.waitForSelector('.bigname', { timeout: 5000 });
  await sleep(4500);
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
