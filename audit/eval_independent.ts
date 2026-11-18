/**
 * Independent-set evaluation through the real API server. Protocol fixed in
 * docs/INDEPENDENT_2026_EVALUATION.md before any score was produced.
 *
 * Input: JSONL rows { payload, label: 0|1, cls } (built by an adapter such as
 * audit/build_modsec_independent.mjs). The label and class never reach the classifier:
 * every request carries vector UNKNOWN, no threatScore, and a neutral source address.
 *
 * Each payload is sent ONCE (no retry, 30 s timeout). The outcome of every request is kept:
 *   ok        the server answered 200 with a verdict
 *   http413   payload over the size limit
 *   http429   rate or budget limit
 *   http5xx   server error
 *   httpOther any other status
 *   timeout   no answer within 30 s
 *   network   connection error
 *   unparsable 200 without a verdict
 *
 * Three decision rules are reported side by side, all fixed in advance:
 *   route     the verdict the endpoint returns (anything other than ALLOW = detection);
 *             for vector UNKNOWN the route blocks at classifier score >= 25
 *   score>=25 the classifier score reached 25
 *   score>=55 the classifier score reached 55 (the classifier's own BLOCK_THRESHOLD)
 * A request that did not return ok is scored against the system (attack -> missed,
 * benign -> false alarm) in the headline figures, and is also counted on its own.
 *
 * Output is aggregate only: no payload is printed or written.
 *
 * Run: ADMIN_API_KEY=... npx tsx audit/eval_independent.ts <rows.jsonl> <out.json> "<dataset name>"
 */
import fs from 'fs';
import crypto from 'crypto';

const BASE = 'http://127.0.0.1:3000';
const KEY = process.env.ADMIN_API_KEY || 'test_admin_key_123';
const CONCURRENCY = 8;

type Outcome = 'ok' | 'http413' | 'http429' | 'http5xx' | 'httpOther' | 'timeout' | 'network' | 'unparsable';
interface Row { payload: string; label: number; cls: string; }
interface Result { label: number; cls: string; outcome: Outcome; verdict?: string; score?: number; }

async function classify(payload: string, n: number): Promise<Omit<Result, 'label' | 'cls'>> {
  try {
    const res = await fetch(`${BASE}/api/v1/agent/ai-analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-key': KEY, 'x-sd-evaluation-source': '1' },
      body: JSON.stringify({
        packet: {
          srcIp: `10.60.${(n >> 8) & 255}.${n & 255}`,
          dstIp: '10.0.1.10',
          port: 443,
          protocol: 'HTTPS',
          vector: 'UNKNOWN',
          payload
        }
      }),
      signal: AbortSignal.timeout(30000)
    });
    if (res.status === 413) return { outcome: 'http413' };
    if (res.status === 429) return { outcome: 'http429' };
    if (res.status >= 500) return { outcome: 'http5xx' };
    if (!res.ok) return { outcome: 'httpOther' };
    const d: any = await res.json().catch(() => null);
    if (!d?.verdict) return { outcome: 'unparsable' };
    const score = typeof d.detection?.score === 'number' ? d.detection.score : undefined;
    return { outcome: 'ok', verdict: String(d.verdict), score };
  } catch (e: any) {
    return { outcome: e?.name === 'TimeoutError' ? 'timeout' : 'network' };
  }
}

function wilson(k: number, n: number): [number, number] {
  if (n === 0) return [0, 0];
  const z = 1.96, p = k / n, d = 1 + (z * z) / n, c = p + (z * z) / (2 * n);
  const m = z * Math.sqrt((p * (1 - p)) / n + (z * z) / (4 * n * n));
  return [+((c - m) / d).toFixed(6), +((c + m) / d).toFixed(6)];
}

type Rule = 'route' | 'score25' | 'score55';
function flagged(r: Result, rule: Rule): boolean {
  if (r.outcome !== 'ok') return r.label === 0; // failure counts against the system
  if (rule === 'route') return r.verdict !== 'ALLOW';
  const s = r.score ?? -1;
  return rule === 'score25' ? s >= 25 : s >= 55;
}

function metrics(set: Result[], rule: Rule) {
  const tp = set.filter(r => r.label === 1 && flagged(r, rule)).length;
  const fn = set.filter(r => r.label === 1 && !flagged(r, rule)).length;
  const fp = set.filter(r => r.label === 0 && flagged(r, rule)).length;
  const tn = set.filter(r => r.label === 0 && !flagged(r, rule)).length;
  const P = tp + fn, N = fp + tn;
  const recall = P ? tp / P : null;
  const precision = tp + fp ? tp / (tp + fp) : null;
  const fpr = N ? fp / N : null;
  const specificity = N ? tn / N : null;
  const f1 = recall !== null && precision !== null && precision + recall > 0 ? (2 * precision * recall) / (precision + recall) : null;
  const denom = Math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn));
  const mcc = denom > 0 ? (tp * tn - fp * fn) / denom : null;
  const balancedAccuracy = recall !== null && specificity !== null ? (recall + specificity) / 2 : null;
  return {
    n: set.length, tp, fn, fp, tn, recall, precision, f1, fpr, mcc, balancedAccuracy,
    recallCI: P ? wilson(tp, P) : null,
    precisionCI: tp + fp ? wilson(tp, tp + fp) : null,
    fprCI: N ? wilson(fp, N) : null,
    note: N === 0 ? 'no benign rows in this set: precision, FPR, MCC and balanced accuracy are not defined' : undefined
  };
}

(async () => {
  const [file, outPath, name] = process.argv.slice(2);
  if (!file || !outPath || !fs.existsSync(file)) {
    console.error('Usage: npx tsx audit/eval_independent.ts <rows.jsonl> <out.json> "<dataset name>"');
    process.exit(2);
  }
  const health = await fetch(`${BASE}/api/health`).catch(() => null);
  if (!health?.ok) { console.error(`Server not reachable at ${BASE}.`); process.exit(2); }

  const raw = fs.readFileSync(file);
  const sha256 = crypto.createHash('sha256').update(raw).digest('hex');
  const rows: Row[] = raw.toString('utf-8').split('\n').filter(Boolean).map(l => JSON.parse(l));

  const t0 = Date.now();
  const results: Result[] = new Array(rows.length);
  let next = 0;
  await Promise.all(Array.from({ length: CONCURRENCY }, async () => {
    for (;;) {
      const i = next++;
      if (i >= rows.length) return;
      results[i] = { label: rows[i].label, cls: rows[i].cls, ...(await classify(rows[i].payload, i)) };
      if (i > 0 && i % 5000 === 0) console.error(`  ${i}/${rows.length}`);
    }
  }));
  const seconds = (Date.now() - t0) / 1000;

  const outcomes: Record<string, number> = {};
  for (const r of results) outcomes[r.outcome] = (outcomes[r.outcome] ?? 0) + 1;
  const rules: Rule[] = ['route', 'score25', 'score55'];
  const overall = Object.fromEntries(rules.map(rule => [rule, metrics(results, rule)]));
  const byClass: Record<string, any> = {};
  for (const c of [...new Set(results.map(r => r.cls))].sort()) {
    const set = results.filter(r => r.cls === c);
    byClass[c] = Object.fromEntries(rules.map(rule => [rule, metrics(set, rule)]));
    byClass[c].failedRequests = set.filter(r => r.outcome !== 'ok').length;
  }

  const out = {
    dataset: name ?? file, sha256, samples: rows.length,
    commit: process.env.SD_EVAL_COMMIT ?? 'unset',
    category: 'independent — scored once on frozen code and protocol',
    outcomes, seconds: +seconds.toFixed(1), samplesPerSecond: +(rows.length / seconds).toFixed(1),
    overall, byClass, finishedAt: new Date().toISOString()
  };
  fs.writeFileSync(outPath, JSON.stringify(out, null, 2));
  const pct = (x: number | null) => (x === null ? 'n/a' : (x * 100).toFixed(2) + '%');
  console.log(`\n${name ?? file}\n  sha256 ${sha256}\n  samples ${rows.length}  outcomes ${JSON.stringify(outcomes)}  ${seconds.toFixed(1)} s`);
  for (const rule of rules) {
    const m = overall[rule];
    console.log(`  [${rule}] TP ${m.tp} FN ${m.fn} FP ${m.fp} TN ${m.tn}  recall ${pct(m.recall)} ${JSON.stringify(m.recallCI)}  precision ${pct(m.precision)}  FPR ${pct(m.fpr)}  MCC ${m.mcc?.toFixed(4) ?? 'n/a'}`);
  }
  for (const [c, v] of Object.entries(byClass)) {
    console.log(`    ${c.padEnd(22)} n=${String(v.route.n).padEnd(6)} route ${pct(v.route.recall ?? v.route.specificity ?? null)}  >=55 ${pct(v.score55.recall)}  failed ${v.failedRequests}`);
  }
  process.exit(0);
})();
