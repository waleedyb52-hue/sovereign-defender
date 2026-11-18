// CLASSIFICATION BUDGET CHECK — the real server with a 1 MiB/min budget, real requests
//
//   node audit/budget_check.mjs
//
// Starts server.ts with SD_CLASSIFY_BUDGET_MB_PER_MIN=1, then as one caller (the ADMIN API
// key from loopback):
//   1. a 700 KB payload            -> 200 (within budget)
//   2. another 700 KB payload      -> 429 CLASSIFICATION_BUDGET_EXCEEDED with Retry-After
//   3. the same, declared as verified evaluation traffic -> 200 (exempt)
// and exits 1 if any of these does not hold. Runs on any OS; CI runs it.
import { spawn } from 'node:child_process';

const B = 'http://127.0.0.1:3000';
const KEY = process.env.ADMIN_API_KEY || 'test_admin_key_123';
const sleep = ms => new Promise(r => setTimeout(r, ms));

if (await fetch(`${B}/api/health`).then(r => r.ok).catch(() => false)) {
  console.error('A server is already listening on :3000; stop it first.');
  process.exit(2);
}
const env = { ...process.env, ADMIN_API_KEY: KEY, SD_CLASSIFY_BUDGET_MB_PER_MIN: '1' };
delete env.GEMINI_API_KEY;
const server = spawn(process.execPath, ['--import', 'tsx', 'server.ts'], { env, stdio: 'ignore' });
const stop = () => { try { server.kill(); } catch { /* gone */ } };
process.on('exit', stop);

let up = false;
for (let i = 0; i < 120 && !up; i++) { await sleep(500); up = await fetch(`${B}/api/health`).then(r => r.ok).catch(() => false); }
if (!up) { console.error('server did not start'); process.exit(2); }

const post = (payload, extra = {}) => fetch(`${B}/api/v1/agent/ai-analyze`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json', 'x-api-key': KEY, ...extra },
  body: JSON.stringify({ packet: { srcIp: '198.51.100.77', vector: 'UNKNOWN', payload } })
});
const big = n => `budget probe ${Date.now()}-${n} ` + 'a'.repeat(700 * 1024);

const r1 = await post(big(1));
const r2 = await post(big(2));
const b2 = await r2.json().catch(() => null);
const r3 = await post(big(3), { 'x-sd-evaluation-source': '1' });

const result = {
  first: r1.status,
  second: r2.status, secondError: b2?.error ?? null, retryAfter: r2.headers.get('retry-after'),
  verifiedEvaluation: r3.status
};
const ok = r1.status === 200 && r2.status === 429 && b2?.error === 'CLASSIFICATION_BUDGET_EXCEEDED' &&
  Number(r2.headers.get('retry-after')) > 0 && r3.status === 200;
console.log(JSON.stringify(result));
console.log(ok
  ? `PASS: 1 MiB/min budget — 700 KB admitted, the next 700 KB refused (429, Retry-After ${result.retryAfter} s), verified evaluation exempt.`
  : 'FAIL');
stop();
await sleep(300);
process.exit(ok ? 0 : 1);
