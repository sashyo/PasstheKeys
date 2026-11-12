// One command to run the passkey-bound fix: start the victim RP and the attacker site together.
// Open the two URLs it prints. Ctrl+C stops both.
import { spawn } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const dir = path.dirname(fileURLToPath(import.meta.url));
const node = process.execPath;
const APP = 'http://localhost:1421';

const victim = spawn(node, ['server.mjs'], { cwd: dir, stdio: 'inherit', env: { ...process.env, ROLE: 'victim', PORT: '1421', VICTIM_ORIGIN: APP } });
const attacker = spawn(node, ['server.mjs'], { cwd: dir, stdio: 'inherit', env: { ...process.env, ROLE: 'attacker', PORT: '1423', VICTIM_ORIGIN: APP } });

setTimeout(() => {
  console.log('\n──────────────────────────────────────────────');
  console.log('  Victim  (you):     http://localhost:1421/login');
  console.log('  Attacker (watch):  http://127.0.0.1:1423/attacker');
  console.log('  Sign in works; "Simulate compromised page" stays locked.');
  console.log('  Ctrl+C to stop.');
  console.log('──────────────────────────────────────────────\n');
}, 500);

const stop = () => { victim.kill(); attacker.kill(); process.exit(0); };
process.on('SIGINT', stop); process.on('SIGTERM', stop);
