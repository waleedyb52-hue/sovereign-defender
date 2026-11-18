/**
 * EXTERNAL DATASET SPLIT — one development half, one sealed half
 *
 * Until now HttpParamsDataset was never used to write a rule, which is what made the 40.9%
 * recall figure clean. Improving SQLi detection needs evidence about what is being missed,
 * and reading the misses of a set and then re-scoring on that same set is memorisation
 * (DEVELOPMENT_PLAN.md, principle 3). This script makes the cut once, before any rule changes:
 *
 *   dev half     may be read, analysed and used to design rules. A score on it afterwards is
 *                a REGRESSION figure, never evidence of generalisation.
 *   sealed half  is only ever scored in aggregate. Nobody opens it, no harness prints samples
 *                from it (SD_EVAL_SEALED=1), and no rule is tuned against its result.
 *
 * The assignment is a pure function of the payload text — the low bit of the first byte of
 * SHA-256(payload) — so it needs no seed file, anyone can re-derive it from the published
 * dataset, and identical payloads always land in the same half (no duplicate can straddle
 * the boundary and leak).
 *
 * Run:  npx tsx audit/split_external.ts <payload_full.csv> <outDir> [manifest.json]
 */

import fs from 'fs';
import path from 'path';
import crypto from 'crypto';

/** RFC 4180: quoted fields, doubled quotes, commas and newlines inside quotes. */
function parseCsv(text: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let field = '';
  let quoted = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (quoted) {
      if (c === '"') {
        if (text[i + 1] === '"') { field += '"'; i++; } else quoted = false;
      } else field += c;
    } else if (c === '"') quoted = true;
    else if (c === ',') { row.push(field); field = ''; }
    else if (c === '\n' || c === '\r') {
      if (c === '\r' && text[i + 1] === '\n') i++;
      row.push(field); rows.push(row); row = []; field = '';
    } else field += c;
  }
  if (field || row.length) { row.push(field); rows.push(row); }
  return rows;
}

const sha = (b: Buffer | string) => crypto.createHash('sha256').update(b).digest('hex');
const quote = (f: string) => `"${f.replace(/"/g, '""')}"`;
const toCsv = (header: string[], rows: string[][]) =>
  [header, ...rows].map(r => r.map(quote).join(',')).join('\n') + '\n';

const [file, outDir, manifestPath] = process.argv.slice(2);
if (!file || !outDir || !fs.existsSync(file)) {
  console.error('Usage: npx tsx audit/split_external.ts <payload_full.csv> <outDir> [manifest.json]');
  process.exit(2);
}

const raw = fs.readFileSync(file);
const table = parseCsv(raw.toString('utf-8')).filter(r => r.length >= 4);
const header = table.shift()!;
const iP = header.indexOf('payload');
const iT = header.indexOf('attack_type');

const dev: string[][] = [];
const sealed: string[][] = [];
for (const r of table) {
  const bit = crypto.createHash('sha256').update(r[iP], 'utf-8').digest()[0] & 1;
  (bit === 0 ? dev : sealed).push(r);
}

const countByType = (rows: string[][]) => {
  const out: Record<string, number> = {};
  for (const r of rows) out[r[iT]] = (out[r[iT]] || 0) + 1;
  return out;
};

fs.mkdirSync(outDir, { recursive: true });
const devCsv = toCsv(header, dev);
const sealedCsv = toCsv(header, sealed);
fs.writeFileSync(path.join(outDir, 'httpparams_dev.csv'), devCsv);
fs.writeFileSync(path.join(outDir, 'httpparams_sealed.csv'), sealedCsv);

const manifest = {
  dataset: 'HttpParamsDataset (Morzeux, 2016, MIT) — payload_full.csv',
  source: 'https://github.com/Morzeux/HttpParamsDataset',
  rule: 'half = SHA-256(payload utf-8)[0] & 1 ; 0 -> dev, 1 -> sealed',
  sourceSha256: sha(raw),
  rows: table.length,
  dev: { file: 'httpparams_dev.csv', rows: dev.length, sha256: sha(devCsv), byType: countByType(dev) },
  sealed: { file: 'httpparams_sealed.csv', rows: sealed.length, sha256: sha(sealedCsv), byType: countByType(sealed) },
  policy: [
    'dev: may be inspected and used to design rules; any later score on it is a regression figure.',
    'sealed: aggregate scoring only, with SD_EVAL_SEALED=1 so no sample is printed or written.',
    'A rule changed after seeing a sealed-half result retires the sealed half as independent evidence.'
  ]
};
if (manifestPath) fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2) + '\n');
console.log(JSON.stringify(manifest, null, 2));
