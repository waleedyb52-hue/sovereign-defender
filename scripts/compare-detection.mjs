// DETECTION COMPARISON — two result files from audit/eval_external_httpparams.ts.
//
//   node scripts/compare-detection.mjs <baseline.json> <candidate.json> [--min-recall-gain=20]
//
// Prints the before/after table and exits 1 when the candidate fails the release gate:
//   - overall recall is lower than the baseline, or below the requested gain (percentage points)
//   - any attack class loses more than 1 percentage point of recall
//   - false-positive rate exceeds SD_MAX_FPR (default 0.001 = 10 per 10,000 benign values)
// Both files must describe the same dataset file (same SHA-256), otherwise it refuses: a
// comparison across different data is not a comparison.
import fs from 'node:fs';

const [a, b, ...flags] = process.argv.slice(2);
if (!a || !b) {
  console.error('Usage: node scripts/compare-detection.mjs <baseline.json> <candidate.json> [--min-recall-gain=N]');
  process.exit(2);
}
const base = JSON.parse(fs.readFileSync(a, 'utf-8'));
const cand = JSON.parse(fs.readFileSync(b, 'utf-8'));
const minGain = Number((flags.find(f => f.startsWith('--min-recall-gain=')) || '=0').split('=')[1]);
const maxFpr = Number(process.env.SD_MAX_FPR || 0.001);
if (base.sha256 !== cand.sha256) {
  console.error(`Different datasets:\n  ${base.sha256}\n  ${cand.sha256}`);
  process.exit(2);
}

const p = x => (x * 100).toFixed(2) + '%';
const d = x => (x >= 0 ? '+' : '') + (x * 100).toFixed(2) + ' pp';
const failures = [];
const row = (name, x, y) => console.log(`  ${name.padEnd(18)} ${p(x).padStart(8)}  ->  ${p(y).padStart(8)}   ${d(y - x)}`);

console.log(`\n  dataset sha256 ${base.sha256}\n  samples ${base.samples}${cand.sealedRun ? '   (SEALED RUN)' : ''}\n`);
row('recall', base.all.recall, cand.all.recall);
row('precision', base.all.precision, cand.all.precision);
row('F1', base.all.f1, cand.all.f1);
row('FPR', base.all.fpr, cand.all.fpr);
console.log(`  ${'MCC'.padEnd(18)} ${base.all.mcc.toFixed(4).padStart(8)}  ->  ${cand.all.mcc.toFixed(4).padStart(8)}`);
console.log(`  ${'confusion'.padEnd(18)} TP ${base.all.tp} FN ${base.all.fn} FP ${base.all.fp} TN ${base.all.tn}  ->  TP ${cand.all.tp} FN ${cand.all.fn} FP ${cand.all.fp} TN ${cand.all.tn}`);
console.log(`  recall 95% CI      [${p(cand.all.recallCI[0])} – ${p(cand.all.recallCI[1])}]\n`);
for (const t of Object.keys(base.byType)) {
  if (t === 'norm' || !cand.byType[t]) continue;
  row(t, base.byType[t].rate, cand.byType[t].rate);
  if (cand.byType[t].rate < base.byType[t].rate - 0.01) failures.push(`${t} recall regressed by more than 1 pp`);
}
const gain = (cand.all.recall - base.all.recall) * 100;
if (gain < 0) failures.push('overall recall is lower than the baseline');
if (gain < minGain) failures.push(`recall gain ${gain.toFixed(2)} pp is below the required ${minGain} pp`);
if (cand.all.fpr > maxFpr) failures.push(`FPR ${p(cand.all.fpr)} exceeds the ${p(maxFpr)} ceiling (${cand.all.fp} false alarms)`);
if (cand.failedRequests > 0) failures.push(`${cand.failedRequests} requests failed during the candidate run`);

console.log(failures.length ? `\n  GATE: FAIL\n${failures.map(f => '    - ' + f).join('\n')}` : '\n  GATE: PASS');
process.exit(failures.length ? 1 : 0);
