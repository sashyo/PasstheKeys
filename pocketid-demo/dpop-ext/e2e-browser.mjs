// Browser end-to-end check of the `dpop` extension demo. Spawns the three origins (victim RP,
// attacker site, authenticator iframe) and runs two scenarios in a real browser:
//   1. Legit : enroll + sign in -> the authenticator names SK in signed authData, /api/me unlocks.
//   2. Relay : the compromised page relays the sign-in; the attacker finishes but /api/me is
//              refused -> "Session captured, but locked".
// The authenticator keys live in a separate-origin iframe (webcrypto, non-extractable), so no
// virtual authenticator is needed. Needs Playwright:  npm install && npx playwright install chromium
import { chromium } from 'playwright';
import { spawn } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const VIC = 15221, ATT = 15223, AUTH = 15225;
const APP = `http://localhost:${VIC}`, ATT_O = `http://localhost:${ATT}`, AUTH_O = `http://localhost:${AUTH}`;
const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';
const log = (...a) => console.log('·', ...a);
const loginUrl = (extra = '') => `${APP}/login?auth=${encodeURIComponent(AUTH_O)}${extra}`;

function startServer(role, port) {
  const child = spawn(process.execPath, [path.join(__dirname, 'server.mjs')],
    { env: { ...process.env, ROLE: role, PORT: String(port), VICTIM_ORIGIN: APP, AUTH_ORIGIN: AUTH_O }, stdio: ['ignore', 'pipe', 'pipe'] });
  child.stderr.on('data', (d) => process.stdout.write(`  [${role} err] ${d}`));
  return child;
}
async function waitReady(url, tries = 50) {
  for (let i = 0; i < tries; i++) { try { const r = await fetch(url); if (r.ok || r.status === 302) return; } catch {} await new Promise((r) => setTimeout(r, 150)); }
  throw new Error('server not ready: ' + url);
}
async function newPage(browser, tag) {
  const ctx = await browser.newContext({ userAgent: UA, viewport: { width: 1100, height: 860 } });
  const page = await ctx.newPage();
  page.on('pageerror', (e) => console.log(`  [${tag} pageerror] ${e.message}`));
  page.on('console', (m) => { if (/error|fail|exception|reject/i.test(m.text())) console.log(`  [${tag}] ${m.text()}`); });
  return { ctx, page };
}
async function enroll(page, username) {
  await page.goto(loginUrl(), { waitUntil: 'domcontentloaded' });
  await page.click('#setup summary');
  await page.fill('#username', username);
  await page.click('#enroll');
  await page.waitForFunction(() => /passkey added/i.test(document.getElementById('setupStatus')?.textContent || ''), null, { timeout: 30000 });
}

const servers = [startServer('victim', VIC), startServer('attacker', ATT), startServer('authenticator', AUTH)];
let pass1 = false, pass2 = false, browser;
try {
  await waitReady(`${APP}/login`); await waitReady(`${ATT_O}/attacker`); await waitReady(`${AUTH_O}/auth`);
  browser = await chromium.launch({ headless: true });

  // 1) Legit
  {
    const vic = await newPage(browser, 'victim-legit');
    await enroll(vic.page, 'alice' + Date.now().toString().slice(-5));
    await vic.page.click('#go');
    await vic.page.waitForFunction(() => document.getElementById('home')?.style.display === 'block', null, { timeout: 20000 });
    const name = (await vic.page.textContent('#hname'))?.trim();
    const jkt = (await vic.page.textContent('#hjkt'))?.trim();
    log('legit ->', JSON.stringify({ name, jkt }));
    pass1 = /^Welcome,/.test(name || '') && /^bound jkt \(SK\): .+/.test(jkt || '');
    await vic.ctx.close();
  }

  // 2) Relay
  {
    const vic = await newPage(browser, 'victim-relay');
    await enroll(vic.page, 'bob' + Date.now().toString().slice(-5));
    await vic.page.goto(loginUrl(`&drop=${encodeURIComponent(ATT_O)}`), { waitUntil: 'domcontentloaded' });

    const att = await newPage(browser, 'attacker');
    await att.page.goto(`${ATT_O}/attacker`, { waitUntil: 'domcontentloaded' });
    await att.page.waitForFunction(async () => { try { const o = await (await fetch('/x/offer')).json(); return !!(o.publicKey && o.publicKey.challenge); } catch { return false; } }, null, { timeout: 10000 });
    log('attacker armed');

    await vic.page.click('#evil');
    await vic.page.waitForFunction(() => /relayed/i.test(document.getElementById('status')?.textContent || ''), null, { timeout: 20000 });

    await att.page.waitForFunction(() => document.getElementById('result')?.style.display === 'block', null, { timeout: 15000 });
    const why = (await att.page.textContent('#why'))?.trim();
    const detail = (await att.page.textContent('#detail'))?.trim();
    log('attacker outcome ->', JSON.stringify({ why, detail }));
    pass2 = /refused \(401\)/.test(why || '') && /missing passkey proof/.test(detail || '');
    await att.ctx.close(); await vic.ctx.close();
  }
} catch (e) {
  console.error('FAILED:', e.message);
} finally {
  if (browser) await browser.close();
  for (const s of servers) s.kill();
  const ok = pass1 && pass2;
  console.log(`\n1 legit : ${pass1 ? 'PASS' : 'FAIL'}  (authenticator-named SK, /api/me unlocks)`);
  console.log(`2 relay : ${pass2 ? 'PASS' : 'FAIL'}  (relayed login mints a token, /api/me refuses it)`);
  console.log(ok ? '\nAll browser checks passed' : '\nFAIL (see above)');
  process.exit(ok ? 0 : 1);
}
