// One command to run the dpop-extension fix: start the victim RP, the attacker site, and the
// separate-origin authenticator together. Open the two URLs it prints. Ctrl+C stops all three.
import { spawn } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const dir = path.dirname(fileURLToPath(import.meta.url));
const node = process.execPath;
const APP = 'http://localhost:1521';
const AUTH = 'http://localhost:1525';

const base = { ...process.env, VICTIM_ORIGIN: APP, AUTH_ORIGIN: AUTH };
const victim = spawn(node, ['server.mjs'], { cwd: dir, stdio: 'inherit', env: { ...base, ROLE: 'victim', PORT: '1521' } });
const attacker = spawn(node, ['server.mjs'], { cwd: dir, stdio: 'inherit', env: { ...base, ROLE: 'attacker', PORT: '1523' } });
const authn = spawn(node, ['server.mjs'], { cwd: dir, stdio: 'inherit', env: { ...base, ROLE: 'authenticator', PORT: '1525' } });

setTimeout(() => {
  console.log('\n──────────────────────────────────────────────');
  console.log('  Victim  (you):     http://localhost:1521/login');
  console.log('  Attacker (watch):  http://127.0.0.1:1523/attacker');
  console.log('  Sign in works; "Simulate compromised page" stays locked.');
  console.log('  Ctrl+C to stop.');
  console.log('──────────────────────────────────────────────\n');
}, 500);

const stop = () => { victim.kill(); attacker.kill(); authn.kill(); process.exit(0); };
process.on('SIGINT', stop); process.on('SIGTERM', stop);
