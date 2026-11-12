// Better Auth for the unified demo: one app, one toggle. The `dpop` plugin (./dpop-plugin.mjs)
// adds the sender-constraining WebAuthn extension. DPOP_ENFORCE flips the demo:
//   DPOP_ENFORCE=0  -> vulnerable: a relayed passkey login mints a usable session (takeover).
//   DPOP_ENFORCE=1  -> fixed: the session is dpop-bound and the relayed session is inert.
// In-memory store, no database file, no native modules.
import { betterAuth } from 'better-auth';
import { memoryAdapter } from 'better-auth/adapters/memory';
import { dpop } from './dpop-plugin.mjs';

const BASE_URL = process.env.BA_BASEURL || 'http://victim.localhost:1521';
const ENFORCE = process.env.DPOP_ENFORCE !== '0'; // default on; run.mjs sets it per mode

const db = { user: [], session: [], account: [], verification: [] };

export const auth = betterAuth({
  database: memoryAdapter(db),
  secret: process.env.BA_SECRET || 'passthekeys-demo-secret-passthekeys-demo-0123456789',
  baseURL: BASE_URL,
  emailAndPassword: { enabled: true },
  trustedOrigins: [BASE_URL],
  plugins: [dpop({ enforce: ENFORCE, origin: BASE_URL })],
});

export const DPOP_ENFORCE = ENFORCE;
