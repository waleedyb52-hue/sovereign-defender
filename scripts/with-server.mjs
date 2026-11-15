// Runs one or more commands against a freshly started server, then stops it.
//
//   node scripts/with-server.mjs "<command 1>" ["<command 2>" ...]
//
// A fresh process per measurement matters: the route keeps a 5-minute verdict cache and
// per-source rate limiters in memory, so figures taken against a long-running server are
// not comparable with figures taken against a new one. GEMINI_API_KEY is removed from the
// child environment so the sovereign path is what gets measured.
//
// SD_SERVER_MODE=built runs `node dist/server.cjs` (after `npm run build`) instead of tsx.
// Exits with the first non-zero command status, after stopping the server.
import { spawn, spawnSync } from 'node:child_process';

const commands = process.argv.slice(2);
if (!commands.length) { console.error('Usage: node scripts/with-server.mjs "<command>" [...]'); process.exit(2); }
const B = 'http://127.0.0.1:3000';
const sleep = ms => new Promise(r => setTimeout(r, ms));

if (await fetch(`${B}/api/health`).then(r => r.ok).catch(() => false)) {
  console.error('A server is already listening on :3000. Stop it first; this script measures a fresh one.');
  process.exit(2);
}

const env = { ...process.env, ADMIN_API_KEY: process.env.ADMIN_API_KEY || 'test_admin_key_123' };
delete env.GEMINI_API_KEY;
const built = process.env.SD_SERVER_MODE === 'built';
const args = built ? ['dist/server.cjs'] : ['--import', 'tsx', 'server.ts'];
if (built) env.NODE_ENV = env.NODE_ENV || 'production';
const server = spawn(process.execPath, args, { env, stdio: ['ignore', 'ignore', 'ignore'] });
const stop = () => { try { server.kill(); } catch { /* already gone */ } };
process.on('exit', stop);
process.on('SIGINT', () => { stop(); process.exit(130); });

let up = false;
const t0 = Date.now();
for (let i = 0; i < 180 && !up; i++) {
  await sleep(500);
  up = await fetch(`${B}/api/health`).then(r => r.ok).catch(() => false);
}
if (!up) { console.error('server did not become healthy within 90 s'); stop(); process.exit(2); }
console.error(`[with-server] ${built ? 'built' : 'dev'} server healthy after ${((Date.now() - t0) / 1000).toFixed(1)} s (pid ${server.pid})`);

let status = 0;
for (const cmd of commands) {
  console.error(`[with-server] $ ${cmd}`);
  const r = spawnSync(cmd, { shell: true, stdio: 'inherit', env });
  if (r.status !== 0 && status === 0) status = r.status ?? 1;
}
stop();
await sleep(300);
process.exit(status);
