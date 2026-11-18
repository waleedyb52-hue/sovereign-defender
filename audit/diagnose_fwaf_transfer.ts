/**
 * WHY THE GAIN DID NOT TRANSFER — diagnostic on second-source attacks outside the sealed test
 *
 * badqueries.txt lines ranked 5,000 .. 5,000+N by SHA-256 are disjoint from the sealed test
 * subset (ranks 0 .. 4,999, audit/build_external2.mjs). This script classifies them with the
 * frozen classifier, then buckets the misses by coarse shape so the report can say what the
 * second source contains that the first does not. It changes nothing and is not a score:
 * the shapes below are heuristics for describing data, not detection rules.
 *
 * Run:  npx tsx audit/diagnose_fwaf_transfer.ts data/external2/badqueries.txt [N=10000] [out.json] [--no-samples]
 *
 * --no-samples: counts only; no example lines in the JSON or on the console. The second source
 * states no licence, so result files committed to the repository are written this way.
 */
import fs from 'fs';
import crypto from 'crypto';
import { classifyPayload } from '../server/services/payloadClassifier.service.js';

const noSamples = process.argv.includes('--no-samples');
const positional = process.argv.slice(2).filter(a => !a.startsWith('--'));
const file = positional[0];
const N = Number(positional[1] || 10000);
if (!file || !fs.existsSync(file) || /sealed/i.test(file)) {
  console.error('Usage: npx tsx audit/diagnose_fwaf_transfer.ts <badqueries.txt> [N] [out.json]');
  process.exit(2);
}
const sha = (s: string) => crypto.createHash('sha256').update(s).digest('hex');
const lines = [...new Set(fs.readFileSync(file, 'utf-8').split(/\r?\n/).map(l => l.trim()).filter(l => l.length > 0 && l.length <= 4000))];
const sample = lines.map(l => [sha(l), l] as const).sort((a, b) => (a[0] < b[0] ? -1 : 1)).slice(5000, 5000 + N).map(x => x[1]);

const SHAPES: Array<[string, RegExp]> = [
  ['script/event-handler markup (XSS-like)', /<\s*\/?\s*(script|img|svg|iframe|body|a|div|style|object|embed|input|marquee|meta|link|frame)\b|on\w+\s*=|javascript:|alert\s*\(|%3c/i],
  ['traversal or sensitive file path', /\.\.[\/\\%]|%2e%2e|\/etc\/|boot\.ini|win\.ini|web-inf|\.htaccess|\.htpasswd/i],
  ['SQL words', /\b(select|union|insert|drop|or\s+\d|and\s+\d|order\s+by|benchmark|sleep)\b/i],
  ['shell / command shapes', /[;|`]\s*(id|ls|cat|uname|whoami|wget|curl|ping|nc|sh)\b|\$\(|cmd=|exec=/i],
  ['scanner probe of a known script path (no payload)', /^\/[\w\-./]*\.(php|cgi|pl|asp|aspx|jsp|cfm|exe|dll|nsf|sh)(\?[\w=&.\-]*)?$/i],
  ['remote file inclusion / URL in parameter', /=\s*(https?|ftp):\/\//i],
  ['plain path, no parameters', /^\/[\w\-./~]*$/]
];

let detected = 0;
const missed: string[] = [];
for (const p of sample) { if (classifyPayload(p).score >= 25) detected++; else missed.push(p); }
const buckets: Record<string, number> = {};
let unassigned = 0;
const examplesBy: Record<string, string[]> = {};
for (const p of missed) {
  const hit = SHAPES.find(([, re]) => re.test(p));
  const k = hit ? hit[0] : 'other';
  if (!hit) unassigned++;
  buckets[k] = (buckets[k] || 0) + 1;
  (examplesBy[k] ||= []).length < 4 && examplesBy[k].push(p.slice(0, 120));
}
const out = {
  source: file, ranks: `5000..${5000 + sample.length - 1} (disjoint from the sealed test)`, n: sample.length,
  detectedAt25: detected, recallAt25: +(detected / sample.length).toFixed(4), missed: missed.length,
  missedByShape: Object.fromEntries(Object.entries(buckets).sort((a, b) => b[1] - a[1])),
  ...(noSamples ? {} : { examples: examplesBy })
};
if (positional[2]) fs.writeFileSync(positional[2], JSON.stringify(out, null, 2) + '\n');
console.log(JSON.stringify(out, null, 2));
