/**
 * FALSE-POSITIVE STRESS — a large benign development sample, with and without structure
 *
 * Reads goodqueries.txt from the second external source, skips the 20,000 hash-ranked lines
 * reserved for the sealed test and the dev-benign file (audit/build_external2.mjs), and
 * classifies the next N in-process, once with structural SQL analysis and once without.
 * What matters is the DIFFERENCE: lines flagged only because of the new component. The
 * source's "good" label is noisy (it contains real attacks), so every newly flagged line is
 * printed for a human to judge rather than counted as a false alarm automatically.
 *
 * Run:  npx tsx audit/fp_stress_dev.ts data/external2/goodqueries.txt [N=100000] [out.json]
 */
import fs from 'fs';
import crypto from 'crypto';
import { classifyPayload } from '../server/services/payloadClassifier.service.js';

const file = process.argv[2];
const N = Number(process.argv[3] || 100000);
if (!file || !fs.existsSync(file)) { console.error('Usage: npx tsx audit/fp_stress_dev.ts <goodqueries.txt> [N] [out.json]'); process.exit(2); }
const sha = (s: string) => crypto.createHash('sha256').update(s).digest('hex');
const lines = [...new Set(fs.readFileSync(file, 'utf-8').split(/\r?\n/).map(l => l.trim()).filter(l => l.length > 0 && l.length <= 4000))];
const sample = lines.map(l => [sha(l), l] as const).sort((a, b) => (a[0] < b[0] ? -1 : 1)).slice(20000, 20000 + N).map(x => x[1]);

const out: any = { source: file, skippedReservedRanks: 20000, n: sample.length, thresholds: {} };
const newly: Array<{ score: number; payload: string; signatures: string[] }> = [];
for (const thr of [55, 25]) {
  let before = 0, after = 0, added = 0;
  for (const p of sample) {
    const a = classifyPayload(p, { sqlStructure: false }).score >= thr;
    const c = classifyPayload(p, { sqlStructure: true });
    const b = c.score >= thr;
    if (a) before++;
    if (b) after++;
    if (b && !a) { added++; if (thr === 25) newly.push({ score: c.score, payload: p.slice(0, 200), signatures: c.signatures }); }
  }
  out.thresholds[thr] = { flaggedWithoutStructure: before, flaggedWithStructure: after, flaggedOnlyByStructure: added };
}
out.flaggedOnlyByStructure = newly;
if (process.argv[4]) fs.writeFileSync(process.argv[4], JSON.stringify(out, null, 2) + '\n');
console.log(JSON.stringify(out.thresholds, null, 2));
for (const r of newly) console.log(`[${r.score}] ${r.payload}   {${r.signatures.join(' | ')}}`);
