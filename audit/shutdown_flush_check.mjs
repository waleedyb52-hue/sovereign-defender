// SHUTDOWN FLUSH CHECK — the real server, real requests, a real SIGTERM, rows counted on disk
//
//   node audit/shutdown_flush_check.mjs
//
// Starts server.ts with the write-behind interval set to 10 minutes, so classifications sit
// in the in-memory review buffer. Sends N classification requests (ordinary traffic, not
// evaluation traffic, so they are queued), confirms none has reached data/adjudication.db
// yet, sends SIGTERM to the server process, and checks that all N are on disk afterwards and
// that the server exited 0.
//
// Needs POSIX signals: on Windows one process cannot send SIGTERM to another (child.kill()
// is TerminateProcess there), so the check reports SKIPPED and exits 0. CI runs it on Linux.
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';

if (process.platform === 'win32') {
  console.log('SKIPPED: needs POSIX signals (runs in CI on Linux).');
  process.exit(0);
}

const N = 20;
const B = 'http://127.0.0.1:3000';
const KEY = process.env.ADMIN_API_KEY || 'test_admin_key_123';
const DB = path.join(process.cwd(), 'data', 'adjudication.db');
const sleep = ms => new Promise(r => setTimeout(r, ms));
const count = () => {
  if (!fs.existsSync(DB)) return 0;
  const db = new DatabaseSync(DB);
  try { return Number(db.prepare('SELECT COUNT(*) AS n FROM pending_detections').get().n); } finally { db.close(); }
};

if (await fetch(`${B}/api/health`).then(r => r.ok).catch(() => false)) {
  console.error('A server is already listening on :3000; stop it first.');
  process.exit(2);
}

const env = { ...process.env, ADMIN_API_KEY: KEY, SD_ADJUDICATION_FLUSH_MS: '600000' };
delete env.GEMINI_API_KEY;
const server = spawn(process.execPath, ['--import', 'tsx', 'server.ts'], { env, stdio: ['ignore', 'pipe', 'pipe'] });
let log = '';
server.stdout.on('data', d => { log += d; });
server.stderr.on('data', d => { log += d; });

let up = false;
for (let i = 0; i < 120 && !up; i++) { await sleep(500); up = await fetch(`${B}/api/health`).then(r => r.ok).catch(() => false); }
if (!up) { console.error('server did not start\n' + log.slice(-2000)); server.kill('SIGKILL'); process.exit(2); }

const before = count();
const nonce = Date.now();
for (let i = 0; i < N; i++) {
  const r = await fetch(`${B}/api/v1/agent/ai-analyze`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-api-key': KEY },
    body: JSON.stringify({ packet: { srcIp: `198.51.100.${i + 1}`, vector: 'UNKNOWN', payload: `shutdown flush check ${nonce} #${i}` } })
  });
  if (r.status !== 200) { console.error(`request ${i} returned ${r.status}`); server.kill('SIGKILL'); process.exit(1); }
}
const buffered = count();

const exited = new Promise(resolve => server.on('exit', (code, signal) => resolve({ code, signal })));
server.kill('SIGTERM');
const result = await Promise.race([exited, sleep(15000).then(() => ({ code: 'timeout' }))]);
if (result.code === 'timeout') { server.kill('SIGKILL'); }
const after = count();

const ok = buffered === before && after === before + N && result.code === 0;
console.log(JSON.stringify({ rowsBeforeRequests: before, rowsWhileBuffered: buffered, rowsAfterSigterm: after, expectedAfter: before + N, exit: result }, null, 2));
console.log(ok ? `PASS: SIGTERM wrote all ${N} buffered review rows; server exited 0.` : 'FAIL');
if (!ok) console.log(log.slice(-2000));
process.exit(ok ? 0 : 1);
