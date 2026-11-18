#!/usr/bin/env node
/**
 * Independent evaluation set from the Zenodo record 17178461 ("A Thirty-Day Dataset of
 * Malicious HTTP Requests Blocked by OWASP ModSecurity on a Production Web Server",
 * CC BY 4.0, published 2025-09-22). The protocol is fixed in
 * docs/INDEPENDENT_2026_EVALUATION.md before any score exists.
 *
 * Input: the extracted owasp.zip (one modsec_audit.anon.log per day, native serial format).
 * Output (outside the repository; the data is never committed):
 *   <out>/modsec_test.jsonl     the half scored now
 *   <out>/modsec_reserve.jsonl  the half kept untouched for a later independent check
 *   audit/results/modsec_independent_manifest.json  hashes and counts only, no payloads
 *
 * What the classifier receives: the request line's target (path + query) and, when the log
 * holds one, the request body after a newline. Headers are NOT sent: the endpoint scores a
 * payload, not a header set. Requests that ModSecurity blocked only for header or protocol
 * reasons are reported in their own group, never dropped.
 *
 * The ModSecurity rule ids (section H) are the label. They are written to the class field
 * and never reach the classifier.
 *
 * Usage: node audit/build_modsec_independent.mjs <extracted-dir> <out-dir>
 */
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

const [srcDir, outDir] = process.argv.slice(2);
if (!srcDir || !outDir) {
  console.error('Usage: node audit/build_modsec_independent.mjs <extracted-dir> <out-dir>');
  process.exit(2);
}

// CRS rule-id prefix -> attack family. 949/959/980 are score-evaluation rules, not detections.
const FAMILY = [
  ['942', 'sqli'], ['941', 'xss'], ['932', 'rce'], ['930', 'lfi'], ['931', 'rfi'],
  ['933', 'php'], ['934', 'generic'], ['944', 'java'], ['943', 'session'],
  ['921', 'protocol-attack'], ['920', 'protocol-enforcement'], ['922', 'multipart'],
  ['913', 'scanner'], ['911', 'method']
];
const PAYLOAD_FAMILIES = new Set(['sqli', 'xss', 'rce', 'lfi', 'rfi', 'php', 'generic', 'java', 'session']);
const familyOf = id => (FAMILY.find(([p]) => id.startsWith(p)) || [null, null])[1];

const sha = b => crypto.createHash('sha256').update(b).digest('hex');
const files = fs.readdirSync(srcDir).sort()
  .map(d => path.join(srcDir, d, 'modsec_audit.anon.log'))
  .filter(f => fs.existsSync(f));

const manifestFiles = [];
const unique = new Map(); // payload -> { families:Set }
let records = 0, noRequestLine = 0;

for (const f of files) {
  const raw = fs.readFileSync(f);
  manifestFiles.push({ file: path.relative(srcDir, f).replace(/\\/g, '/'), bytes: raw.length, sha256: sha(raw) });
  const lines = raw.toString('utf-8').split(/\r?\n/);
  let sec = null, reqLine = null, body = [], ids = [];
  const flush = () => {
    if (sec === null) return;
    records++;
    if (!reqLine) { noRequestLine++; return; }
    const m = /^([A-Z]+)\s+(\S+)/.exec(reqLine);
    if (!m) { noRequestLine++; return; }
    const b = body.join('\n').trim();
    const payload = b ? `${m[2]}\n${b}` : m[2];
    const fams = new Set(ids.map(familyOf).filter(Boolean));
    const cur = unique.get(payload);
    if (cur) for (const x of fams) cur.families.add(x);
    else unique.set(payload, { families: fams });
  };
  for (const line of lines) {
    const mark = /^--[0-9a-zA-Z]+-([A-Z])--$/.exec(line);
    if (mark) {
      if (mark[1] === 'A') { flush(); reqLine = null; body = []; ids = []; }
      sec = mark[1];
      continue;
    }
    if (sec === 'B' && reqLine === null && line.trim()) reqLine = line;
    else if (sec === 'C') body.push(line);
    else if (sec === 'H') for (const x of line.matchAll(/\[id "(\d+)"\]/g)) ids.push(x[1]);
  }
  flush();
}

// Primary class: first payload family in priority order; otherwise "non-payload" (blocked by
// ModSecurity for header, protocol or scanner reasons only), otherwise "unattributed".
const PRIORITY = ['sqli', 'xss', 'rce', 'lfi', 'rfi', 'php', 'java', 'generic', 'session'];
fs.mkdirSync(outDir, { recursive: true });
const test = [], reserve = [];
const counts = { test: {}, reserve: {} };
for (const [payload, { families }] of unique) {
  const primary = PRIORITY.find(p => families.has(p)) ?? (families.size ? 'non-payload' : 'unattributed');
  const row = JSON.stringify({ payload, label: 1, cls: primary, families: [...families].sort() });
  // Fixed split, re-derivable by anyone: first byte of SHA-256(payload), even = test.
  const half = (crypto.createHash('sha256').update(payload).digest()[0] & 1) === 0 ? 'test' : 'reserve';
  (half === 'test' ? test : reserve).push(row);
  counts[half][primary] = (counts[half][primary] ?? 0) + 1;
}
fs.writeFileSync(path.join(outDir, 'modsec_test.jsonl'), test.join('\n') + '\n');
fs.writeFileSync(path.join(outDir, 'modsec_reserve.jsonl'), reserve.join('\n') + '\n');

const manifest = {
  source: 'Zenodo 17178461 — A Thirty-Day Dataset of Malicious HTTP Requests Blocked by OWASP ModSecurity on a Production Web Server',
  license: 'CC BY 4.0',
  published: '2025-09-22',
  archive: { name: 'owasp.zip', bytes: 29524147, md5: '95b7a8237abc163d8ca31e49f7318efd', sha256: '3c4c976f58cd2da61a543a237ede770529ceee59cdb09295a5998d420a8b30b8' },
  logFiles: manifestFiles,
  records,
  recordsWithoutRequestLine: noRequestLine,
  uniquePayloads: unique.size,
  duplicatesRemoved: records - noRequestLine - unique.size,
  split: 'SHA-256(payload)[0] & 1 == 0 -> test, else reserve',
  test: { n: test.length, sha256: sha(test.join('\n') + '\n'), byClass: counts.test },
  reserve: { n: reserve.length, sha256: sha(reserve.join('\n') + '\n'), byClass: counts.reserve, note: 'not scored; kept for a later independent check' },
  payloadFamilies: [...PAYLOAD_FAMILIES],
  builtAt: new Date().toISOString()
};
fs.writeFileSync('audit/results/modsec_independent_manifest.json', JSON.stringify(manifest, null, 2));
console.log(JSON.stringify({ records, noRequestLine, unique: unique.size, test: test.length, reserve: reserve.length, byClass: counts.test }, null, 1));
