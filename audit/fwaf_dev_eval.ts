/**
 * SECOND-SOURCE DEVELOPMENT SCORING — attack recall on hash-ranked Fwaf chunks, in-process
 *
 * The Fwaf sealed test is ranks 0..4,999 of badqueries.txt and 0..9,999 of goodqueries.txt
 * (audit/build_external2.mjs); this script refuses to touch them. It scores other chunks:
 *
 *   --chunk dev         attack ranks  5,000..14,999   read freely while writing rules
 *   --chunk validation  attack ranks 15,000..24,999   never read; scored before and after only
 *   --benign            good ranks   20,000..119,999  false-positive stress (same as fp_stress_dev)
 *
 * Prints recall at score 25 (the route's threshold for vector=UNKNOWN) and 55, and — for the
 * dev chunk only, with --show=N — up to N missed lines per bucket. The validation chunk never
 * prints a line, so it cannot inform a rule.
 *
 * Run:  npx tsx audit/fwaf_dev_eval.ts <dir with badqueries.txt goodqueries.txt> --chunk dev [--show=N] [out.json]
 */
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { classifyPayload } from '../server/services/payloadClassifier.service.js';

const args = process.argv.slice(2);
// "--chunk dev" and "--chunk=dev" both work; the chunk name is never taken for a path.
const chunkAt = args.indexOf('--chunk');
const chunk = (args.find(a => a.startsWith('--chunk=')) ?? (chunkAt >= 0 ? '--chunk=' + args[chunkAt + 1] : '--chunk=dev')).split('=')[1];
const positional = args.filter((a, i) => !a.startsWith('--') && i !== chunkAt + 1);
const dir = positional[0];
const out = positional[1];
const show = Number((args.find(a => a.startsWith('--show=')) || '=0').split('=')[1]);
if (!dir) { console.error('Usage: npx tsx audit/fwaf_dev_eval.ts <dir> --chunk dev|validation|benign [--show=N] [out.json]'); process.exit(2); }

const sha = (s: string) => crypto.createHash('sha256').update(s).digest('hex');
const ranked = (file: string) => {
  const lines = [...new Set(fs.readFileSync(path.join(dir, file), 'utf-8').split(/\r?\n/).map(l => l.trim()).filter(l => l.length > 0 && l.length <= 4000))];
  return lines.map(l => [sha(l), l] as const).sort((a, b) => (a[0] < b[0] ? -1 : 1)).map(x => x[1]);
};

const RANGES: Record<string, [string, number, number, boolean]> = {
  dev: ['badqueries.txt', 5_000, 15_000, true],
  validation: ['badqueries.txt', 15_000, 25_000, true],
  benign: ['goodqueries.txt', 20_000, 120_000, false]
};
if (!RANGES[chunk]) { console.error(`unknown chunk ${chunk}`); process.exit(2); }
const [file, from, to, attacks] = RANGES[chunk];
const rows = ranked(file).slice(from, to);

const scores = rows.map(r => ({ r, c: classifyPayload(r) }));
const at = (thr: number) => scores.filter(s => s.c.score >= thr).length;
const result = {
  chunk, file, ranks: `${from}..${from + rows.length - 1}`, n: rows.length,
  flaggedAt25: at(25), flaggedAt55: at(55),
  rateAt25: +(at(25) / rows.length).toFixed(4), rateAt55: +(at(55) / rows.length).toFixed(4),
  meaning: attacks ? 'recall (attack lines)' : 'flag rate on benign-labelled lines (labels are noisy)'
};
console.log(JSON.stringify(result, null, 2));
if (out) fs.writeFileSync(out, JSON.stringify(result, null, 2) + '\n');

if (show && chunk === 'dev') {
  const missed = scores.filter(s => s.c.score < 25).map(s => s.r);
  const step = Math.max(1, Math.floor(missed.length / show));
  console.log(`\n${missed.length} missed; every ${step}th:`);
  for (let i = 0; i < missed.length && i / step < show; i += step) console.log('  ' + missed[i].slice(0, 160));
}
if (show && chunk === 'benign') {
  console.log('\nflagged at 25:');
  for (const s of scores.filter(s => s.c.score >= 25).slice(0, show)) console.log(`  [${s.c.score}] ${s.r.slice(0, 140)}  {${s.c.signatures.join(' | ')}}`);
}
