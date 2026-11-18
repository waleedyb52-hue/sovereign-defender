// SECOND EXTERNAL SOURCE — Fwaf query corpus, a different author and generator than HttpParamsDataset
//
//   node audit/build_external2.mjs <dir with goodqueries.txt + badqueries.txt> [manifest.json]
//
// Source: github.com/faizann24/Fwaf-Machine-Learning-driven-Web-Application-Firewall (2017).
// The repository states no licence, so the files are used for local measurement only and are
// never committed or redistributed (data/ is git-ignored). Labels are the authors' and are
// known to be noisy; that is reported with every figure rather than cleaned by hand, because
// cleaning a test set by inspection is a way of fitting to it.
//
// Three disjoint subsets, selected by SHA-256 of the line so anyone can re-derive them:
//   fwaf_test_sealed.csv   10,000 good + 5,000 bad   aggregate scoring only, never opened
//   fwaf_dev_benign.csv    10,000 good               may be read: false-positive tuning
//   (no attack dev set is taken from this source: its attacks stay entirely unseen)
// Selection: lines are de-duplicated, ranked by hash, and the lowest ranks are taken; the test
// subset takes the lowest ranks, the dev subset the next ones, so they cannot overlap.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

const [dir, manifestPath] = process.argv.slice(2);
if (!dir) { console.error('Usage: node audit/build_external2.mjs <dir> [manifest.json]'); process.exit(2); }
const sha = b => crypto.createHash('sha256').update(b).digest('hex');
const quote = f => `"${String(f).replace(/"/g, '""')}"`;

function ranked(file) {
  const raw = fs.readFileSync(path.join(dir, file));
  const lines = [...new Set(raw.toString('utf-8').split(/\r?\n/).map(l => l.trim()).filter(l => l.length > 0 && l.length <= 4000))];
  const withHash = lines.map(l => [sha(l), l]).sort((a, b) => (a[0] < b[0] ? -1 : 1));
  return { sha256: sha(raw), unique: lines.length, rows: withHash.map(x => x[1]) };
}
const csv = rows => ['"payload","length","attack_type","label"', ...rows.map(r => [r.payload, r.payload.length, r.type, r.label].map(quote).join(','))].join('\n') + '\n';

const good = ranked('goodqueries.txt');
const bad = ranked('badqueries.txt');
const test = [
  ...good.rows.slice(0, 10000).map(p => ({ payload: p, type: 'norm', label: 'norm' })),
  ...bad.rows.slice(0, 5000).map(p => ({ payload: p, type: 'attack', label: 'anom' }))
];
const devBenign = good.rows.slice(10000, 20000).map(p => ({ payload: p, type: 'norm', label: 'norm' }));

const testCsv = csv(test), devCsv = csv(devBenign);
fs.writeFileSync(path.join(dir, 'fwaf_test_sealed.csv'), testCsv);
fs.writeFileSync(path.join(dir, 'fwaf_dev_benign.csv'), devCsv);
const manifest = {
  source: 'https://github.com/faizann24/Fwaf-Machine-Learning-driven-Web-Application-Firewall',
  licence: 'none stated - local measurement only, not redistributed',
  goodqueries: { sha256: good.sha256, uniqueLines: good.unique },
  badqueries: { sha256: bad.sha256, uniqueLines: bad.unique },
  rule: 'unique trimmed lines ranked by SHA-256(line); test = lowest 10,000 good + lowest 5,000 bad; dev benign = next 10,000 good',
  test: { file: 'fwaf_test_sealed.csv', rows: test.length, sha256: sha(testCsv) },
  devBenign: { file: 'fwaf_dev_benign.csv', rows: devBenign.length, sha256: sha(devCsv) },
  caveats: [
    'Labels are the dataset authors\' and are noisy in both directions.',
    'Attack class is not labelled, so per-class recall is unavailable on this source.',
    'Dev benign and test benign come from the same corpus: near-duplicates across the two are possible.'
  ]
};
if (manifestPath) fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2) + '\n');
console.log(JSON.stringify(manifest, null, 2));
