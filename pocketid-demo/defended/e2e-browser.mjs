// Browser end-to-end check of the defended demo, with a Chrome virtual authenticator.
// Spawns its own victim RP + attacker site on dedicated ports, then runs two scenarios:
//   1. Legit : victim enrolls a discoverable passkey, signs in, and the resource page loads
//              via a passkey proof -> lands on "Welcome", bound passkey shown.
//   2. Relay : victim runs the "compromised page" relay; the attacker tab finishes the login
//              and the stolen token is refused by /api/me -> "Session captured - but locked".
// Needs Playwright (dev only):  npm install && npx playwright install chromium
import { chromium } from 'playwright';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const VIC_PORT = 14021, ATT_PORT = 14023;
const APP = `http://localhost:${VIC_PORT}`;    // victim RP (Acme, defended)
const ATT = `http://localhost:${ATT_PORT}`;    // attacker site + dead-drop
const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';
const log = (...a) => console.log('·', ...a);

function startServer(role, port) {
  const child = spawn(process.execPath, [path.join(__dirname, 'server.mjs')], {
    env: { ...process.env, ROLE: role, PORT: String(port), VICTIM_ORIGIN: APP },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  child.stderr.on('data', (d) => process.stdout.write(`  [${role} err] ${d}`));
  return child;
}
async function waitReady(url, tries = 50) {
  for (let i = 0; i < tries; i++) {
    try { const r = await fetch(url); if (r.ok || r.status === 302) return; } catch {}
    await new Promise((r) => setTimeout(r, 150));
  }
  throw new Error('server not ready: ' + url);
}

async function newCtx(browser, withAuth, tag) {
  const ctx = await browser.newContext({ userAgent: UA, viewport: { width: 1100, height: 860 } });
  const page = await ctx.newPage();
  page.on('pageerror', (e) => console.log(`  [${tag} pageerror] ${e.message}`));
  page.on('console', (m) => { if (/error|fail|exception|reject/i.test(m.text())) console.log(`  [${tag}] ${m.text()}`); });
  if (withAuth) {
    const client = await ctx.newCDPSession(page);
    await client.send('WebAuthn.enable');
    await client.send('WebAuthn.addVirtualAuthenticator', { options: {
      protocol: 'ctap2', transport: 'internal', hasResidentKey: true,
      hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } });
  }
  return { ctx, page };
}

async function enroll(page, username) {
  await page.goto(`${APP}/login`, { waitUntil: 'domcontentloaded' });
  await page.click('#setup summary');
  await page.fill('#username', username);
  await page.click('#enroll');
  await page.waitForFunction(() => /passkey added/i.test(document.getElementById('setupStatus')?.textContent || ''), null, { timeout: 30000 });
}

const victimSrv = startServer('victim', VIC_PORT);
const attackerSrv = startServer('attacker', ATT_PORT);
let pass1 = false, pass2 = false, browser;
try {
  await waitReady(`${APP}/login`);
  await waitReady(`${ATT}/attacker`);

  browser = await chromium.launch({ headless: true });

  // ---- 1) Legit passkey-bound sign-in -------------------------------------------
  {
    const vic = await newCtx(browser, true, 'victim-legit');
    await enroll(vic.page, 'alice' + Date.now().toString().slice(-5));
    await vic.page.click('#go');
    await vic.page.waitForFunction(() => document.getElementById('home')?.style.display === 'block', null, { timeout: 20000 });
    const name = (await vic.page.textContent('#hname'))?.trim();
    const jkt = (await vic.page.textContent('#hjkt'))?.trim();
    log('legit sign-in ->', JSON.stringify({ name, jkt }));
    pass1 = /^Welcome,/.test(name || '') && /^bound to passkey: .+/.test(jkt || '');
    await vic.ctx.close();
  }

  // ---- 2) Relay against the defended RP --------------------------------------
  {
    const vic = await newCtx(browser, true, 'victim-relay');
    await enroll(vic.page, 'bob' + Date.now().toString().slice(-5));
    // point the "compromised" page's drop at the attacker origin
    await vic.page.goto(`${APP}/login?drop=${encodeURIComponent(ATT)}`, { waitUntil: 'domcontentloaded' });

    const att = await newCtx(browser, false, 'attacker');
    await att.page.goto(`${ATT}/attacker`, { waitUntil: 'domcontentloaded' });
    await att.page.waitForFunction(async () => {
      try { const o = await (await fetch('/x/offer')).json(); return !!o.challenge; } catch { return false; }
    }, null, { timeout: 10000 });
    log('attacker armed (nonce published)');

    await vic.page.click('#evil');
    await vic.page.waitForFunction(() => /relayed/i.test(document.getElementById('status')?.textContent || ''), null, { timeout: 20000 });

    await att.page.waitForFunction(() => document.getElementById('result')?.style.display === 'block', null, { timeout: 15000 });
    const why = (await att.page.textContent('#why'))?.trim();
    const detail = (await att.page.textContent('#detail'))?.trim();
    log('attacker outcome ->', JSON.stringify({ why, detail }));
    // The ceremony completed (token minted) but the resource refused: no passkey proof.
    pass2 = /refused \(401\)/.test(why || '') && /missing passkey proof/.test(detail || '');
    await att.ctx.close(); await vic.ctx.close();
  }
} catch (e) {
  console.error('FAILED:', e.message);
} finally {
  if (browser) await browser.close();
  victimSrv.kill(); attackerSrv.kill();
  const ok = pass1 && pass2;
  console.log(`\n1 legit  : ${pass1 ? 'PASS' : 'FAIL'}  (passkey-bound sign-in works for the real user)`);
  console.log(`2 relay  : ${pass2 ? 'PASS' : 'FAIL'}  (relayed login mints a token, but /api/me refuses it)`);
  console.log(ok ? '\nAll browser checks passed' : '\nFAIL (see above)');
  process.exit(ok ? 0 : 1);
}
