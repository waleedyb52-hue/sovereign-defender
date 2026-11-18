// ZERO-EGRESS CHECK — starts the server under the egress probe, exercises it, reports.
//
//   node scripts/zero-egress-check.mjs [out.json]
//
// Starts `server.ts` with scripts/egress-probe.mjs preloaded and GEMINI_API_KEY removed from
// the environment (the sovereign default), waits for /api/health, sends classifier traffic,
// keeps observing for SD_EGRESS_SOAK_SEC (default 60) so scheduled jobs get a chance to fire,
// then stops the server and exits 1 if any EXTERNAL connection was attempted.
//
// Install-time and build-time traffic (npm, git) is out of scope by construction: nothing is
// installed here, only the already-installed application is run.
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const OUT = process.argv[2] || 'egress_result.json';
const SOAK = Number(process.env.SD_EGRESS_SOAK_SEC || 60);
const PORT = 3000;
const B = `http://127.0.0.1:${PORT}`;
const KEY = process.env.ADMIN_API_KEY || 'test_admin_key_123';
const LOG = path.join(os.tmpdir(), `sd-egress-${process.pid}.jsonl`);
const sleep = ms => new Promise(r => setTimeout(r, ms));

const env = { ...process.env, ADMIN_API_KEY: KEY, SD_EGRESS_LOG: LOG };
delete env.GEMINI_API_KEY;
const child = spawn(process.execPath, ['--import', './scripts/egress-probe.mjs', '--import', 'tsx', 'server.ts'],
  { env, stdio: ['ignore', 'ignore', 'inherit'] });

const stop = () => { try { child.kill(); } catch { /* already gone */ } };
process.on('exit', stop);

let up = false;
for (let i = 0; i < 120 && !up; i++) {
  await sleep(500);
  up = await fetch(`${B}/api/health`).then(r => r.ok).catch(() => false);
}
if (!up) { console.error('server did not start'); stop(); process.exit(2); }

const payloads = ["' OR 1=1 --", '<script>alert(1)</script>', '../../etc/passwd', 'hello world', 'q=shoes&page=2'];
let sent = 0;
for (let i = 0; i < 50; i++) {
  await fetch(`${B}/api/v1/agent/ai-analyze`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-api-key': KEY },
    body: JSON.stringify({ packet: { srcIp: `10.41.0.${i}`, dstIp: '10.0.1.10', port: 443, protocol: 'HTTPS', vector: 'UNKNOWN', payload: `${payloads[i % payloads.length]} ${i}` } })
  }).then(() => sent++).catch(() => {});
}
const posture = await fetch(`${B}/api/v1/soc/inference-posture`, { headers: { 'x-api-key': KEY } }).then(r => r.json()).catch(() => null);
await sleep(SOAK * 1000);
stop();
await sleep(500);

const events = fs.existsSync(LOG) ? fs.readFileSync(LOG, 'utf-8').split('\n').filter(Boolean).map(l => JSON.parse(l)) : [];
const external = events.filter(e => e.scope === 'EXTERNAL');
const lan = events.filter(e => e.scope === 'LAN');
const result = {
  finishedAt: new Date().toISOString(), node: process.version, platform: process.platform,
  soakSeconds: SOAK, classifierRequestsSent: sent,
  postureReportsZeroExternalApiCalls: posture?.zeroExternalApiCalls ?? null,
  externalAttempts: external.length, lanAttempts: lan.length,
  externalDestinations: [...new Set(external.map(e => `${e.kind}:${e.host ?? e.address}${e.port ? ':' + e.port : ''}`))],
  lanDestinations: [...new Set(lan.map(e => `${e.kind}:${e.address}${e.port ? ':' + e.port : ''}`))],
  events: external.slice(0, 50),
  limits: 'In-process probe: child processes and native modules are not observed. Confirm with a host packet capture.'
};
fs.writeFileSync(OUT, JSON.stringify(result, null, 2) + '\n');
console.log(JSON.stringify({ ...result, events: undefined }, null, 2));
console.log(external.length === 0 ? '\nZERO EGRESS: no external connection attempted.' : `\nEGRESS DETECTED: ${external.length} external attempt(s).`);
process.exit(external.length === 0 ? 0 : 1);
