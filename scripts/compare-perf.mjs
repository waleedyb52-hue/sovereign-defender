// PERFORMANCE COMPARISON — two result files from audit/perf_benchmark.mjs.
//
//   node scripts/compare-perf.mjs <baseline.json> <candidate.json> [--min-throughput-gain=20]
//
// Only meaningful when both files were produced on the same machine, same Node version, same
// server mode (dev vs built) and with nothing else loading the host. It refuses when platform
// or Node version differ. Exits 1 when throughput at the highest concurrency gains less than
// the requested percentage, when p95 there is worse than baseline by more than 10%, or when
// any request returned a non-200 status.
import fs from 'node:fs';

const [a, b, ...flags] = process.argv.slice(2);
if (!a || !b) {
  console.error('Usage: node scripts/compare-perf.mjs <baseline.json> <candidate.json> [--min-throughput-gain=N]');
  process.exit(2);
}
const base = JSON.parse(fs.readFileSync(a, 'utf-8'));
const cand = JSON.parse(fs.readFileSync(b, 'utf-8'));
const minGain = Number((flags.find(f => f.startsWith('--min-throughput-gain=')) || '=0').split('=')[1]);
if (base.host?.platform !== cand.host?.platform || base.host?.node !== cand.host?.node) {
  console.error(`Not comparable: ${JSON.stringify(base.host)} vs ${JSON.stringify(cand.host)}`);
  process.exit(2);
}

const failures = [];
const rel = (x, y) => ((y - x) / x) * 100;
const f = x => (x >= 0 ? '+' : '') + x.toFixed(1) + '%';

console.log(`\n  host ${JSON.stringify(cand.host)}\n`);
console.log('  clients   req/s (base -> cand)        p50 ms            p95 ms            p99 ms');
for (const br of base.classifyConcurrent) {
  const cr = cand.classifyConcurrent.find(r => r.concurrency === br.concurrency);
  if (!cr) continue;
  console.log(`  ${String(br.concurrency).padStart(7)}   ${br.reqPerSec} -> ${cr.reqPerSec} (${f(rel(br.reqPerSec, cr.reqPerSec))})   ${br.p50} -> ${cr.p50}   ${br.p95} -> ${cr.p95}   ${br.p99} -> ${cr.p99}`);
  const bad = Object.keys(cr.statusCodes || {}).filter(code => code !== '200');
  if (bad.length) failures.push(`non-200 responses at ${cr.concurrency} clients: ${JSON.stringify(cr.statusCodes)}`);
}

const top = base.classifyConcurrent.at(-1);
const topC = cand.classifyConcurrent.find(r => r.concurrency === top.concurrency);
const gain = rel(top.reqPerSec, topC.reqPerSec);
if (gain < minGain) failures.push(`throughput gain at ${top.concurrency} clients is ${f(gain)}, below the required +${minGain}%`);
if (topC.p95 > top.p95 * 1.1) failures.push(`p95 at ${top.concurrency} clients worsened: ${top.p95} -> ${topC.p95} ms`);

const seq = r => r.classifySequential?.p50;
if (seq(base) && seq(cand)) {
  console.log(`\n  single-request classify p50: ${seq(base)} -> ${seq(cand)} ms (${f(rel(seq(base), seq(cand)))})`);
}
console.log(failures.length ? `\n  GATE: FAIL\n${failures.map(x => '    - ' + x).join('\n')}` : '\n  GATE: PASS');
process.exit(failures.length ? 1 : 0);
