/**
 * IN-PROCESS DEVELOPMENT SCORING — fast iteration figures, never reportable ones
 *
 * Calls classifyPayload() directly on files that may be read (dev half, benign dev samples)
 * so a rule change can be scored in seconds. It refuses any file whose name contains
 * "sealed". Two decision thresholds are printed because the two are both real:
 *   55  classifyPayload().malicious - what a request with no `vector` field is judged at
 *   25  what /api/v1/agent/ai-analyze applies when the caller sends vector=UNKNOWN, which is
 *       what every evaluation harness in this repository sends
 * Reportable figures still come from audit/eval_external_httpparams.ts against a live server.
 *
 * Run:  npx tsx audit/eval_dev_inprocess.ts <file.csv> [--no-structure] [--fp=N] [--miss=TYPE:N]
 */
import fs from 'fs';
import { classifyPayload } from '../server/services/payloadClassifier.service.js';
import crypto from 'crypto';
import { enforceGate, gateFloors, gateRequested } from './regressionGate.js';

const args = process.argv.slice(2);
const file = args.find(a => !a.startsWith('--'));
if (!file || !fs.existsSync(file)) { console.error('Usage: npx tsx audit/eval_dev_inprocess.ts <file.csv> [--no-structure] [--fp=N] [--miss=TYPE:N]'); process.exit(2); }
if (/sealed/i.test(file)) { console.error('Refusing to read a sealed file.'); process.exit(2); }
const sqlStructure = !args.includes('--no-structure');
const showFp = Number((args.find(a => a.startsWith('--fp=')) || '=0').split('=')[1]);
const missArg = (args.find(a => a.startsWith('--miss=')) || '').slice(7).split(':');

function parseCsv(text: string): string[][] {
  const rows: string[][] = []; let row: string[] = []; let field = ''; let quoted = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (quoted) { if (c === '"') { if (text[i + 1] === '"') { field += '"'; i++; } else quoted = false; } else field += c; }
    else if (c === '"') quoted = true;
    else if (c === ',') { row.push(field); field = ''; }
    else if (c === '\n' || c === '\r') { if (c === '\r' && text[i + 1] === '\n') i++; row.push(field); rows.push(row); row = []; field = ''; }
    else field += c;
  }
  if (field || row.length) { row.push(field); rows.push(row); }
  return rows;
}
const table = parseCsv(fs.readFileSync(file, 'utf-8')).filter(r => r.length >= 4);
const header = table.shift()!;
const [iP, iT, iL] = ['payload', 'attack_type', 'label'].map(h => header.indexOf(h));
const t0 = performance.now();
const rows = table.map(r => ({ p: r[iP], t: r[iT], bad: r[iL] === 'anom', c: classifyPayload(r[iP], { sqlStructure }) }));
const ms = performance.now() - t0;

const pct = (k: number, n: number) => (n ? ((k / n) * 100).toFixed(2) + '%' : 'n/a');
console.log(`\n${file}   structure=${sqlStructure ? 'on' : 'off'}   ${rows.length} rows in ${ms.toFixed(0)} ms (${(ms / rows.length * 1000).toFixed(1)} us/row)`);
for (const thr of [55, 25]) {
  const hit = (r: (typeof rows)[number]) => r.c.score >= thr;
  const bad = rows.filter(r => r.bad), good = rows.filter(r => !r.bad);
  const tp = bad.filter(hit).length, fp = good.filter(hit).length;
  console.log(`  threshold ${thr}: recall ${pct(tp, bad.length)} (${tp}/${bad.length})   false alarms ${fp}/${good.length} (${pct(fp, good.length)})`);
  for (const type of [...new Set(bad.map(r => r.t))]) {
    const set = bad.filter(r => r.t === type);
    console.log(`      ${type.padEnd(16)} ${pct(set.filter(hit).length, set.length)}  (${set.filter(hit).length}/${set.length})`);
  }
}
if (gateRequested) {
  // The floors were measured on one specific file; a gate run on any other file is refused
  // rather than compared, so a renamed or re-split dataset cannot pass by accident.
  const floors = gateFloors('httpParamsDev');
  const sha = crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
  if (sha !== floors.sha256) {
    console.error(`\n  GATE: refused — ${file} is not the dev half the floors were measured on (${sha})`);
    process.exit(1);
  }
  if (!sqlStructure) {
    console.error('\n  GATE: refused — run with the shipped configuration (no --no-structure)');
    process.exit(1);
  }
  const at = (thr: number, pred: (r: (typeof rows)[number]) => boolean) => rows.filter(r => pred(r) && r.c.score >= thr).length;
  const checks: Array<[string, number, number, 'min' | 'max']> = [
    ['true positives at 55', at(55, r => r.bad), floors.minTPAt55, 'min'],
    ['true positives at 25', at(25, r => r.bad), floors.minTPAt25, 'min'],
    ['false positives at 25', at(25, r => !r.bad), floors.maxFPAt25, 'max']
  ];
  for (const [cls, min] of Object.entries(floors.perClassMinTPAt25 as Record<string, number>)) {
    checks.push([`${cls} true positives at 25`, at(25, r => r.bad && r.t === cls), min, 'min']);
  }
  enforceGate('httpParamsDev', checks);
}
if (showFp) {
  console.log('\n  benign values scoring >= 25:');
  for (const r of rows.filter(r => !r.bad && r.c.score >= 25).slice(0, showFp)) console.log(`    [${r.c.score}] ${r.p.slice(0, 140)}   {${r.c.signatures.join(' | ')}}`);
}
if (missArg.length === 2) {
  const set = rows.filter(r => r.bad && r.t === missArg[0] && r.c.score < 25);
  const n = Number(missArg[1]); const step = Math.max(1, Math.floor(set.length / n));
  console.log(`\n  ${missArg[0]} still missed at 25: ${set.length}`);
  for (let i = 0; i < set.length && i / step < n; i += step) console.log(`    [${set[i].c.score}] ${set[i].p.slice(0, 150)}   {${set[i].c.signatures.join(' | ')}}`);
}
