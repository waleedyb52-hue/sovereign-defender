#!/usr/bin/env node
/**
 * Derives the pre-registered primary figure from an eval_independent.ts result file:
 * route-verdict recall over the CRS payload families, with a 95% Wilson interval, and the
 * same for score >= 55. Reads only the aggregate JSON; writes a generated summary file.
 *
 * Usage: node audit/summarize_independent.mjs <result.json> <summary.json>
 */
import fs from 'node:fs';

const [inPath, outPath] = process.argv.slice(2);
const r = JSON.parse(fs.readFileSync(inPath, 'utf-8'));
const PAYLOAD = ['sqli', 'xss', 'rce', 'lfi', 'rfi', 'php', 'java', 'generic', 'session'];
const OTHER = ['non-payload', 'unattributed'];

function wilson(k, n) {
  if (n === 0) return null;
  const z = 1.96, p = k / n, d = 1 + (z * z) / n, c = p + (z * z) / (2 * n);
  const m = z * Math.sqrt((p * (1 - p)) / n + (z * z) / (4 * n * n));
  return [+((c - m) / d).toFixed(6), +((c + m) / d).toFixed(6)];
}
function group(classes, rule) {
  let tp = 0, n = 0;
  for (const c of classes) {
    const m = r.byClass[c]?.[rule];
    if (!m) continue;
    tp += m.tp; n += m.tp + m.fn;
  }
  return { n, tp, fn: n - tp, recall: n ? +(tp / n).toFixed(6) : null, recallCI: wilson(tp, n) };
}
const out = {
  source: inPath, datasetSha256: r.sha256, commit: r.commit, outcomes: r.outcomes,
  primary: { definition: 'route-verdict recall over CRS payload families (pre-registered)', ...group(PAYLOAD, 'route') },
  payloadFamiliesAtScore55: group(PAYLOAD, 'score55'),
  nonPayloadGroups: Object.fromEntries(OTHER.map(c => [c, group([c], 'route')])),
  perClassRoute: Object.fromEntries(PAYLOAD.concat(OTHER).filter(c => r.byClass[c]).map(c => [c, group([c], 'route')])),
  perClassScore55: Object.fromEntries(PAYLOAD.concat(OTHER).filter(c => r.byClass[c]).map(c => [c, group([c], 'score55')])),
  generatedAt: new Date().toISOString()
};
fs.writeFileSync(outPath, JSON.stringify(out, null, 2));
console.log(JSON.stringify({ primary: out.primary, at55: out.payloadFamiliesAtScore55, perClassRoute: out.perClassRoute }, null, 1));
