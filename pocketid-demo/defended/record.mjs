// Record a clean demo video of the DEFENDED flow (no overlays, real UI). Spawns its own
// victim RP + attacker site, then films two screens:
//   victim.webm   : one person enrolls, signs in (passkey-bound) -> "Welcome", then their page is
//                   compromised and relays the sign-in to the attacker.
//   attacker.webm : the attacker tab waiting, then flipping to "Session captured - but locked"
//                   when it finishes the relayed login and /api/me refuses the stolen token.
// Uses a virtual authenticator, so no real biometric prompt is needed.
// Needs Playwright (dev only):  npm install && npx playwright install chromium
import { chromium } from 'playwright';
import { spawn } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import fs from 'node:fs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const VIC_PORT = 14021, ATT_PORT = 14023;
const APP = `http://localhost:${VIC_PORT}`;
const ATT = `http://localhost:${ATT_PORT}`;
const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';
const VDIR = path.join(__dirname, 'videos');
const SIZE = { width: 1280, height: 820 };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const V = { username: 'jordan', displayName: 'Jordan Avery' };

function startServer(role, port) {
  const child = spawn(process.execPath, [path.join(__dirname, 'server.mjs')],
    { env: { ...process.env, ROLE: role, PORT: String(port), VICTIM_ORIGIN: APP }, stdio: ['ignore', 'ignore', 'inherit'] });
  return child;
}
async function waitReady(url, tries = 50) {
  for (let i = 0; i < tries; i++) { try { const r = await fetch(url); if (r.ok || r.status === 302) return; } catch {} await sleep(150); }
  throw new Error('server not ready: ' + url);
}
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

fs.mkdirSync(VDIR, { recursive: true });
const victimSrv = startServer('victim', VIC_PORT);
const attackerSrv = startServer('attacker', ATT_PORT);
const browser = await chromium.launch({ headless: true });
let att = null, vic = null, victimVideo = null, attackerVideo = null;
try {
  await waitReady(`${APP}/login`); await waitReady(`${ATT}/attacker`);

  att = await ctx(browser, true, false);
  attackerVideo = att.page.video();
  await att.page.goto(`${ATT}/attacker`, { waitUntil: 'domcontentloaded' });
  await sleep(3000); // let "waiting for a sign-in" breathe

  vic = await ctx(browser, true, true);
  victimVideo = vic.page.video();

  // Enroll + legit passkey-bound sign-in (shows the defended flow works for the real user).
  await vic.page.goto(`${APP}/login`, { waitUntil: 'domcontentloaded' });
  await sleep(800);
  await vic.page.click('#setup summary'); await sleep(500);
  await vic.page.fill('#username', V.username); await sleep(400);
  await vic.page.click('#enroll');
  await vic.page.waitForFunction(() => /passkey added/i.test(document.getElementById('setupStatus')?.textContent || ''), null, { timeout: 30000 });
  await sleep(1200);
  await vic.page.click('#go');
  await vic.page.waitForFunction(() => document.getElementById('home')?.style.display === 'block', null, { timeout: 20000 });
  await sleep(3500); // hold on "Welcome, Jordan" + bound passkey

  // Now the page is compromised: relay the sign-in to the attacker's waiting login.
  await vic.page.goto(`${APP}/login?drop=${encodeURIComponent(ATT)}`, { waitUntil: 'domcontentloaded' });
  await sleep(1200);
  await vic.page.click('#evil');
  await vic.page.waitForFunction(() => /relayed/i.test(document.getElementById('status')?.textContent || ''), null, { timeout: 20000 });
  await sleep(2500);

  // Attacker finishes the relayed login; the stolen token is refused -> locked.
  await att.page.waitForFunction(() => document.getElementById('result')?.style.display === 'block', null, { timeout: 15000 });
  await sleep(5000);

  await vic.c.close(); // flush victim video
} finally {
  const names = [];
  const save = async (video, name) => {
    if (!video) return;
    try { const p = await video.path(); const d = path.join(VDIR, name); fs.renameSync(p, d); names.push(d); }
    catch (e) { console.error(name + ':', e.message); }
  };
  try { if (att) await att.c.close(); } catch {} // flush attacker video
  await save(attackerVideo, 'attacker.webm');
  await save(victimVideo, 'victim.webm');
  await browser.close(); victimSrv.kill(); attackerSrv.kill();
  console.log('\nVideos:'); for (const n of names) console.log('  ' + n);
}
