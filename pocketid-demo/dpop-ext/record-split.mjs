// Record victim and attacker tabs side by side for the dpop-extension demo, then stitch them
// into videos/combined.mp4 with ffmpeg (hstack). Spawns the three origins itself.
//   left  (victim)   : enroll, sign in (dpop-bound "Welcome"), then the page is compromised and
//                      relays the sign-in.
//   right (attacker) : waiting, then "Session captured, but locked".
// Needs Playwright:  npm install && npx playwright install chromium
import { chromium } from 'playwright';
import { spawn, spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import fs from 'node:fs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const VIC = 15231, ATT = 15233, AUTH = 15235;
const APP = `http://localhost:${VIC}`, ATT_O = `http://localhost:${ATT}`, AUTH_O = `http://localhost:${AUTH}`;
const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';
const VDIR = path.join(__dirname, 'videos');
const SIZE = { width: 720, height: 880 };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const loginUrl = (extra = '') => `${APP}/login?auth=${encodeURIComponent(AUTH_O)}${extra}`;

function startServer(role, port) {
  return spawn(process.execPath, [path.join(__dirname, 'server.mjs')],
    { env: { ...process.env, ROLE: role, PORT: String(port), VICTIM_ORIGIN: APP, AUTH_ORIGIN: AUTH_O }, stdio: ['ignore', 'ignore', 'inherit'] });
}
async function waitReady(url, tries = 50) {
  for (let i = 0; i < tries; i++) { try { const r = await fetch(url); if (r.ok || r.status === 302) return; } catch {} await sleep(150); }
  throw new Error('server not ready: ' + url);
}
async function ctx(browser) {
  const c = await browser.newContext({ userAgent: UA, viewport: SIZE, recordVideo: { dir: VDIR, size: SIZE } });
  await c.addInitScript(() => { Object.defineProperty(navigator, 'webdriver', { get: () => false }); });
  return { c, page: await c.newPage() };
}
function hasHstack(cmd) { const f = spawnSync(cmd, ['-hide_banner', '-filters'], { encoding: 'utf8' }); return f.status === 0 && /\bhstack\b/.test(f.stdout || ''); }
function findFfmpeg() {
  if (hasHstack('ffmpeg')) return 'ffmpeg';
  const roots = [path.join(process.env.LOCALAPPDATA || '', 'Microsoft', 'WinGet', 'Packages'), path.join(process.env.ProgramData || 'C:\\ProgramData', 'chocolatey', 'bin')];
  for (const root of roots) { try { const st = [root]; while (st.length) { const d = st.pop(); for (const e of fs.readdirSync(d, { withFileTypes: true })) { const p = path.join(d, e.name); if (e.isDirectory() && /ffmpeg|winget|bin|build/i.test(e.name)) st.push(p); else if (e.isFile() && e.name.toLowerCase() === 'ffmpeg.exe' && hasHstack(p)) return p; } } } catch {} }
  return null;
}

fs.mkdirSync(VDIR, { recursive: true });
const servers = [startServer('victim', VIC), startServer('attacker', ATT), startServer('authenticator', AUTH)];
const browser = await chromium.launch({ headless: true });
let att = null, vic = null, victimVideo = null, attackerVideo = null;
try {
  await waitReady(`${APP}/login`); await waitReady(`${ATT_O}/attacker`); await waitReady(`${AUTH_O}/auth`);

  att = await ctx(browser); attackerVideo = att.page.video();
  await att.page.goto(`${ATT_O}/attacker`, { waitUntil: 'domcontentloaded' });
  await sleep(3000);

  vic = await ctx(browser); victimVideo = vic.page.video();
  const u = 'jordan' + Date.now().toString().slice(-4);
  await vic.page.goto(loginUrl(), { waitUntil: 'domcontentloaded' });
  await sleep(800);
  await vic.page.click('#setup summary'); await sleep(400);
  await vic.page.fill('#username', u); await sleep(400);
  await vic.page.click('#enroll');
  await vic.page.waitForFunction(() => /passkey added/i.test(document.getElementById('setupStatus')?.textContent || ''), null, { timeout: 30000 });
  await sleep(900);
  await vic.page.click('#go');
  await vic.page.waitForFunction(() => document.getElementById('home')?.style.display === 'block', null, { timeout: 20000 });
  await sleep(3000); // hold on "Welcome" + bound jkt

  await vic.page.goto(loginUrl(`&drop=${encodeURIComponent(ATT_O)}`), { waitUntil: 'domcontentloaded' });
  await sleep(1000);
  await att.page.waitForFunction(async () => { try { return !!(await (await fetch('/x/offer')).json()).publicKey?.challenge; } catch { return false; } }, null, { timeout: 10000 });
  await vic.page.click('#evil');
  await vic.page.waitForFunction(() => /relayed/i.test(document.getElementById('status')?.textContent || ''), null, { timeout: 20000 });
  await att.page.waitForFunction(() => document.getElementById('result')?.style.display === 'block', null, { timeout: 15000 });
  await sleep(4500);

  await vic.c.close();
} finally {
  const names = [];
  const save = async (video, name) => { if (!video) return; try { const p = await video.path(); const d = path.join(VDIR, name); fs.renameSync(p, d); names.push(d); } catch (e) { console.error(name + ':', e.message); } };
  try { if (att) await att.c.close(); } catch {}
  await save(attackerVideo, 'split-attacker.webm');
  await save(victimVideo, 'split-victim.webm');
  await browser.close(); for (const s of servers) s.kill();
  console.log('panes:'); for (const n of names) console.log('  ' + n);
  const v = path.join(VDIR, 'split-victim.webm'), a = path.join(VDIR, 'split-attacker.webm'), out = path.join(VDIR, 'combined.mp4');
  if (fs.existsSync(v) && fs.existsSync(a)) {
    const ff = findFfmpeg();
    if (!ff) console.log('\nffmpeg not found. Stitch with:\n  ffmpeg -y -i "' + v + '" -i "' + a + '" -filter_complex hstack=inputs=2 "' + out + '"');
    else { const r = spawnSync(ff, ['-y', '-i', v, '-i', a, '-filter_complex', 'hstack=inputs=2', out], { stdio: 'ignore' }); console.log(r.status === 0 ? '\ncombined:\n  ' + out : '\nffmpeg failed (' + r.status + ')'); }
  }
}
