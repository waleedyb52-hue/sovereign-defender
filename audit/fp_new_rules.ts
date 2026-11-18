/**
 * NEW-RULE FALSE-POSITIVE CHECK — which benign-labelled dev lines do the newest rules flag?
 *
 * Classifies the second source's benign development lines (goodqueries ranks 20,000..119,999,
 * never the sealed ranks 0..9,999) and the HttpParams dev-half benign values, and lists every
 * line flagged at score >= 25 whose signatures include one of the labels given on the command
 * line. The point is to read each one and decide: a real false positive, or an attack the
 * source mislabelled as good. Counts only with --no-samples.
 *
 * Run:  npx tsx audit/fp_new_rules.ts data/external2 "label one" "label two" ... [--no-samples]
 */
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { classifyPayload } from '../server/services/payloadClassifier.service.js';

const args = process.argv.slice(2);
const noSamples = args.includes('--no-samples');
const [dir, ...labels] = args.filter(a => !a.startsWith('--'));
const sha = (s: string) => crypto.createHash('sha256').update(s).digest('hex');
const good = [...new Set(fs.readFileSync(path.join(dir, 'goodqueries.txt'), 'utf-8').split(/\r?\n/).map(l => l.trim()).filter(l => l.length > 0 && l.length <= 4000))]
  .map(l => [sha(l), l] as const).sort((a, b) => (a[0] < b[0] ? -1 : 1)).slice(20_000, 120_000).map(x => x[1]);

const hits: Record<string, string[]> = {};
for (const line of good) {
  const c = classifyPayload(line);
  if (c.score < 25) continue;
  for (const l of labels) if (c.signatures.includes(l)) (hits[l] ||= []).push(`[${c.score}] ${line.slice(0, 150)}`);
}
for (const l of labels) {
  console.log(`\n== ${l}: ${hits[l]?.length ?? 0} benign-labelled lines flagged`);
  if (!noSamples) for (const h of hits[l] ?? []) console.log('   ' + h);
}
