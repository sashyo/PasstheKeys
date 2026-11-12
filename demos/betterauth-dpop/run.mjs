// One command, one app, one toggle. `node run.mjs exploit` runs with the dpop plugin OFF (a relayed
// passkey login takes over the account); `node run.mjs fix` runs with it ON (the relayed session is
// inert). Starts the victim RP, the attacker site, and the separate-origin authenticator together.
import { spawn } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const dir = path.dirname(fileURLToPath(import.meta.url));
const node = process.execPath;
const MODE = process.argv[2] === 'exploit' ? 'exploit' : 'fix';
const ENFORCE = MODE === 'fix' ? '1' : '0';
const APP = 'http://victim.localhost:5411';

const base = { ...process.env, VICTIM_ORIGIN: APP, BA_BASEURL: APP, DPOP_ENFORCE: ENFORCE, QUIET: '1' };
const victim = spawn(node, ['server.mjs'], { cwd: dir, stdio: 'inherit', env: { ...base, ROLE: 'victim', PORT: '5411' } });
const attacker = spawn(node, ['server.mjs'], { cwd: dir, stdio: 'inherit', env: { ...base, ROLE: 'attacker', PORT: '5413' } });
const authn = spawn(node, ['server.mjs'], { cwd: dir, stdio: 'inherit', env: { ...base, ROLE: 'authenticator', PORT: '5415' } });

setTimeout(() => {
  const banner = MODE === 'fix'
    ? 'dpop ON (fix): sign in works; "Simulate compromised page" stays locked.'
    : 'dpop OFF (exploit): "Simulate compromised page" takes over the attacker tab.';
  console.log('\n──────────────────────────────────────────────');
  console.log(`  Mode: ${MODE.toUpperCase()}`);
  console.log('  Victim  (you):     http://victim.localhost:5411/login');
  console.log('  Attacker (watch):  http://attacker.localhost:5413/attacker');
  console.log(`  ${banner}`);
  console.log('  Ctrl+C to stop.');
  console.log('──────────────────────────────────────────────\n');
}, 500);

let stopping = false;
const stop = (code = 0) => { if (stopping) return; stopping = true; victim.kill(); attacker.kill(); authn.kill(); process.exit(code); };
process.on('SIGINT', () => stop(0)); process.on('SIGTERM', () => stop(0));
for (const [who, child] of [['victim', victim], ['attacker', attacker], ['authenticator', authn]])
  child.on('exit', (code) => { if (code) console.error(`\n${who} server exited; stopping.`); stop(code || 0); });
