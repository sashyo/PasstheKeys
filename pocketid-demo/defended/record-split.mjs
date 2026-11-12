// Record victim and attacker tabs at the same size for a side-by-side DEFENDED clip, then
// stitch them with ffmpeg (hstack) into videos/combined.mp4. Spawns its own servers.
//   left  (victim)   : enroll, sign in passkey-bound ("Welcome"), then the page is compromised
//                      and relays the sign-in.
//   right (attacker) : waiting, then "Session captured, but locked" when the stolen token is
//                      refused by /api/me.
// Needs Playwright (dev only):  npm install && npx playwright install chromium
import { chromium } from 'playwright';
import { spawn, spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import fs from 'node:fs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const VIC_PORT = 14021, ATT_PORT = 14023;
const APP = `http://localhost:${VIC_PORT}`;
const ATT = `http://localhost:${ATT_PORT}`;
const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';
const VDIR = path.join(__dirname, 'videos');
const SIZE = { width: 720, height: 880 };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const V = { username: 'jordan' + Date.now().toString().slice(-4) };

function startServer(role, port) {
  return spawn(process.execPath, [path.join(__dirname, 'server.mjs')],
    { env: { ...process.env, ROLE: role, PORT: String(port), VICTIM_ORIGIN: APP }, stdio: ['ignore', 'ignore', 'inherit'] });
}
async function waitReady(url, tries = 50) {
  for (let i = 0; i < tries; i++) { try { const r = await fetch(url); if (r.ok || r.status === 302) return; } catch {} await sleep(150); }
  throw new Error('server not ready: ' + url);
}
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
// An ffmpeg that can hstack. (Playwright's bundled ffmpeg is a minimal vpx-only build with no
// filters, so it cannot stitch -- we never fall back to it.) Tries PATH, then common Windows
// install locations, and only accepts a build whose filter list includes hstack.
function hasHstack(cmd) {
  const f = spawnSync(cmd, ['-hide_banner', '-filters'], { encoding: 'utf8' });
  return f.status === 0 && /\bhstack\b/.test(f.stdout || '');
}
function findFfmpeg() {
  if (hasHstack('ffmpeg')) return 'ffmpeg';
  const roots = [
    path.join(process.env.LOCALAPPDATA || '', 'Microsoft', 'WinGet', 'Packages'),
    path.join(process.env.ProgramData || 'C:\\ProgramData', 'chocolatey', 'bin'),
  ];
  for (const root of roots) {
    try {
      const stack = [root];
      while (stack.length) {
        const dir = stack.pop();
        for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
          const p = path.join(dir, e.name);
          if (e.isDirectory() && /ffmpeg|winget|bin|build/i.test(e.name)) stack.push(p);
          else if (e.isFile() && e.name.toLowerCase() === 'ffmpeg.exe' && hasHstack(p)) return p;
        }
      }
    } catch {}
  }
  return null;
}

fs.mkdirSync(VDIR, { recursive: true });
const victimSrv = startServer('victim', VIC_PORT);
const attackerSrv = startServer('attacker', ATT_PORT);
const browser = await chromium.launch({ headless: true });
const att = await ctx(browser, false);
const vic = await ctx(browser, true);
try {
  await waitReady(`${APP}/login`); await waitReady(`${ATT}/attacker`);
  await att.c.request.post(`${ATT}/x/reset`).catch(() => {});

  await att.page.goto(`${ATT}/attacker`, { waitUntil: 'domcontentloaded' }); // arms its nonce
  await vic.page.goto(`${APP}/login`, { waitUntil: 'domcontentloaded' });
  await sleep(2200); // login form left, "waiting" right

  // Enroll + legit passkey-bound sign-in (it works for the real user).
  await vic.page.click('#setup summary'); await sleep(400);
  await vic.page.fill('#username', V.username); await sleep(400);
  await vic.page.click('#enroll');
  await vic.page.waitForFunction(() => /passkey added/i.test(document.getElementById('setupStatus')?.textContent || ''), null, { timeout: 30000 });
  await sleep(900);
  await vic.page.click('#go');
  await vic.page.waitForFunction(() => document.getElementById('home')?.style.display === 'block', null, { timeout: 20000 });
  await sleep(3000); // hold on "Welcome" + bound passkey

  // Page compromised: relay the sign-in to the attacker's waiting login.
  await vic.page.goto(`${APP}/login?drop=${encodeURIComponent(ATT)}`, { waitUntil: 'domcontentloaded' });
  await sleep(1000);
  await att.page.waitForFunction(async () => { try { return !!(await (await fetch('/x/offer')).json()).challenge; } catch { return false; } }, null, { timeout: 10000 });
  await vic.page.click('#evil');
  await vic.page.waitForFunction(() => /relayed/i.test(document.getElementById('status')?.textContent || ''), null, { timeout: 20000 });

  // Attacker finishes; the stolen token is refused -> locked.
  await att.page.waitForFunction(() => document.getElementById('result')?.style.display === 'block', null, { timeout: 15000 });
  await sleep(4500); // hold on victim-relayed vs attacker-locked
} finally {
  const vv = vic.page.video(), av = att.page.video();
  await vic.c.close(); await att.c.close();
  const dst = {};
  for (const [name, v] of [['victim', vv], ['attacker', av]]) {
    const p = await v?.path(); if (!p) continue;
    const d = path.join(VDIR, `split-${name}.webm`); try { fs.renameSync(p, d); dst[name] = d; } catch { dst[name] = p; }
  }
  await browser.close(); victimSrv.kill(); attackerSrv.kill();
  console.log('panes:'); for (const k in dst) console.log('  ' + dst[k]);

  if (dst.victim && dst.attacker) {
    const ff = findFfmpeg();
    const out = path.join(VDIR, 'combined.mp4');
    if (!ff) {
      console.log('\nffmpeg not found. Stitch the panes with:\n  ffmpeg -y -i "' + dst.victim + '" -i "' + dst.attacker + '" -filter_complex hstack=inputs=2 "' + out + '"');
    } else {
      const r = spawnSync(ff, ['-y', '-i', dst.victim, '-i', dst.attacker, '-filter_complex', 'hstack=inputs=2', out], { stdio: 'ignore' });
      console.log(r.status === 0 ? '\ncombined:\n  ' + out : '\nffmpeg failed (status ' + r.status + '); panes are above.');
    }
  }
}
