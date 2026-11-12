// The fix app: one Better Auth app with the `dpop` plugin enforced. Sign in works; a relayed
// sign-in lands "captured, but locked". Starts the victim RP, the attacker site, and the
// separate-origin authenticator together. (The exploit is its own app: `npm run exploit`.)
import { spawn } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const dir = path.dirname(fileURLToPath(import.meta.url));
const node = process.execPath;
const APP = 'http://victim.localhost:1521';

const base = { ...process.env, VICTIM_ORIGIN: APP, BA_BASEURL: APP, DPOP_ENFORCE: '1', QUIET: '1' };
const victim = spawn(node, ['server.mjs'], { cwd: dir, stdio: 'inherit', env: { ...base, ROLE: 'victim', PORT: '1521' } });
const attacker = spawn(node, ['server.mjs'], { cwd: dir, stdio: 'inherit', env: { ...base, ROLE: 'attacker', PORT: '1523' } });
const authn = spawn(node, ['server.mjs'], { cwd: dir, stdio: 'inherit', env: { ...base, ROLE: 'authenticator', PORT: '1525' } });

setTimeout(() => {
  console.log('\n──────────────────────────────────────────────');
  console.log('  Victim  (you):     http://victim.localhost:1521/login');
  console.log('  Attacker (watch):  http://attacker.localhost:1523/attacker');
  console.log('  Sign in works; "Simulate compromised page" stays locked.');
  console.log('  Ctrl+C to stop.');
  console.log('──────────────────────────────────────────────\n');
}, 500);

let stopping = false;
const stop = (code = 0) => { if (stopping) return; stopping = true; victim.kill(); attacker.kill(); authn.kill(); process.exit(code); };
process.on('SIGINT', () => stop(0)); process.on('SIGTERM', () => stop(0));
for (const [who, child] of [['victim', victim], ['attacker', attacker], ['authenticator', authn]])
  child.on('exit', (code) => { if (code) console.error(`\n${who} server exited; stopping.`); stop(code || 0); });
