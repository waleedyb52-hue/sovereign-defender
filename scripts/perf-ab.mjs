// INTERLEAVED A/B PERFORMANCE COMPARISON — same machine, same database, alternating runs
//
//   node scripts/perf-ab.mjs <ENV_NAME> <valueA> <valueB> [rounds=3] [out.json]
//   node scripts/perf-ab.mjs SD_ADJUDICATION_WRITE_BEHIND off on 3 audit/results/perf_ab_writebehind.json
//   node scripts/perf-ab.mjs --checkout <dirA> <dirB> 3 out.json
//
// With --checkout, A and B are two working trees (e.g. `git worktree add`), and each run starts
// server.ts from that tree, so two commits can be compared the same way as two settings.
//
// Two back-to-back runs of the SAME code on this laptop differed by 19% in throughput
// (audit/results/baseline_perf_*.json), so a single before/after pair cannot support a 20%
// claim. This runs A, B, A, B, ... each against a freshly started server, and reports the
// median and the full range per variant, so thermal drift and background load fall on both
// sides equally. A gain is only claimed when the ranges do not overlap.
//
// Load: unique payloads (the verdict cache is never what is timed) from distinct source
// addresses, 100 concurrent clients, REQUESTS per run, through /api/v1/agent/ai-analyze.
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import { performance } from 'node:perf_hooks';

const [name, valueA, valueB, roundsArg, OUT] = process.argv.slice(2);
if (!name || valueA === undefined || valueB === undefined) {
  console.error('Usage: node scripts/perf-ab.mjs <ENV_NAME> <valueA> <valueB> [rounds] [out.json]');
  process.exit(2);
}
const ROUNDS = Number(roundsArg || 3);
const CLIENTS = Number(process.env.SD_AB_CLIENTS || 100);
const REQUESTS = Number(process.env.SD_AB_REQUESTS || 3000);
const B = 'http://127.0.0.1:3000';
const KEY = process.env.ADMIN_API_KEY || 'test_admin_key_123';
const sleep = ms => new Promise(r => setTimeout(r, ms));
const pct = (a, p) => { const s = [...a].sort((x, y) => x - y); return +s[Math.min(s.length - 1, Math.ceil((p / 100) * s.length) - 1)].toFixed(1); };
const median = a => pct(a, 50);
let serial = Date.now() % 100000;

const byCheckout = name === '--checkout';

async function oneRun(value) {
  const env = byCheckout ? { ...process.env, ADMIN_API_KEY: KEY } : { ...process.env, ADMIN_API_KEY: KEY, [name]: value };
  delete env.GEMINI_API_KEY;
  const server = spawn(process.execPath, ['--import', 'tsx', 'server.ts'], { env, stdio: 'ignore', cwd: byCheckout ? value : process.cwd() });
  try {
    let up = false;
    for (let i = 0; i < 180 && !up; i++) { await sleep(500); up = await fetch(`${B}/api/health`).then(r => r.ok).catch(() => false); }
    if (!up) throw new Error('server did not start');
    const send = async k => {
      const t = performance.now();
      const r = await fetch(`${B}/api/v1/agent/ai-analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-api-key': KEY },
        body: JSON.stringify({ packet: { srcIp: `198.18.${(k >> 8) & 255}.${k & 255}`, dstIp: '10.0.1.10', port: 443, protocol: 'HTTPS', vector: 'UNKNOWN', payload: `order ${k} ref=${(k * 2654435761) >>> 0} qty=${k % 17} note=bench-${serial}` } }),
        signal: AbortSignal.timeout(30000)
      }).catch(() => null);
      if (r) await r.text();
      return { ms: performance.now() - t, ok: !!r && r.status === 200 };
    };
    for (let i = 0; i < 200; i++) await send(serial++);            // warm-up, not timed
    const lat = []; let bad = 0; let next = 0;
    const mem0 = await fetch(`${B}/api/v1/soc/inference-posture`, { headers: { 'x-api-key': KEY } }).then(r => r.json()).catch(() => null);
    const t0 = performance.now();
    await Promise.all(Array.from({ length: CLIENTS }, async () => {
      while (next++ < REQUESTS) { const r = await send(serial++); lat.push(r.ms); if (!r.ok) bad++; }
    }));
    const seconds = (performance.now() - t0) / 1000;
    const mem1 = await fetch(`${B}/api/v1/soc/inference-posture`, { headers: { 'x-api-key': KEY } }).then(r => r.json()).catch(() => null);
    return {
      reqPerSec: +(lat.length / seconds).toFixed(1), p50: pct(lat, 50), p95: pct(lat, 95), p99: pct(lat, 99),
      failed: bad, requests: lat.length, rssMbBefore: mem0?.processMemory?.rssMb ?? null, rssMbAfter: mem1?.processMemory?.rssMb ?? null
    };
  } finally {
    server.kill();
    await sleep(1500);
  }
}

const runs = { A: [], B: [] };
for (let r = 0; r < ROUNDS; r++) {
  for (const [label, value] of [['A', valueA], ['B', valueB]]) {
    const res = await oneRun(value);
    runs[label].push(res);
    console.error(`round ${r + 1} ${label} (${name}=${value}): ${res.reqPerSec} req/s  p50 ${res.p50}  p95 ${res.p95}  p99 ${res.p99}  failed ${res.failed}  rss ${res.rssMbAfter} MB`);
  }
}
const summary = label => {
  const a = runs[label];
  const col = k => a.map(x => x[k]);
  return {
    reqPerSec: { median: median(col('reqPerSec')), min: Math.min(...col('reqPerSec')), max: Math.max(...col('reqPerSec')) },
    p50: median(col('p50')), p95: median(col('p95')), p99: median(col('p99')),
    failed: col('failed').reduce((x, y) => x + y, 0), rssMbAfter: median(col('rssMbAfter').map(x => x ?? 0))
  };
};
const A = summary('A'), Bs = summary('B');
const gain = ((Bs.reqPerSec.median - A.reqPerSec.median) / A.reqPerSec.median) * 100;
const separated = Bs.reqPerSec.min > A.reqPerSec.max;
const out = {
  finishedAt: new Date().toISOString(),
  host: { platform: process.platform, node: process.version, cpu: os.cpus()[0].model, logicalCpus: os.cpus().length, totalMemGb: +(os.totalmem() / 2 ** 30).toFixed(1) },
  protocol: { variable: name, A: valueA, B: valueB, rounds: ROUNDS, clients: CLIENTS, requestsPerRun: REQUESTS, serverMode: 'dev (tsx), fresh process per run', order: 'A,B alternating' },
  A, B: Bs, throughputGainPercent: +gain.toFixed(1), rangesSeparated: separated, runs
};
if (OUT) fs.writeFileSync(OUT, JSON.stringify(out, null, 2) + '\n');
console.log(JSON.stringify({ A, B: Bs, throughputGainPercent: out.throughputGainPercent, rangesSeparated: separated }, null, 2));
