/**
 * RETRACT EVALUATION PAYLOADS FROM THE CORPUS
 *
 * A contamination that actually happened, and how it is being undone.
 *
 * The evaluation harnesses send their payloads to /api/v1/agent/ai-analyze, which
 * is the correct way to test the live classifier. That endpoint also queues what it
 * sees for adjudication. So Set A and Set B strings flowed into the queue, and when
 * 80 labels were written from the lead's criteria, 36 of them were Set B payloads
 * and 33 were Set A.
 *
 * Why that matters more than it looks
 *   A learner trained on this corpus would have seen Set B. Every later Set B score
 *   on that learner would then be measuring recall of its own training data, which
 *   is the defect this project opened by rejecting — arriving through a path nobody
 *   was watching. The guard protecting the newest temporal fold was in place and
 *   did nothing, because the leak was upstream of folds entirely: evaluation data
 *   became training data before any fold existed.
 *
 * How the retraction works
 *   The store is append-only, so nothing is deleted. Each affected label gets a
 *   retraction row that supersedes it and carries the reason. The label leaves the
 *   active set; both rows stay readable. A reviewer can see exactly what was
 *   withdrawn, when, and why — which is the difference between correcting a corpus
 *   and quietly pruning one to improve a number.
 *
 * Run:  npx tsx audit/retract_evaluation_labels.ts --dry-run
 *       npx tsx audit/retract_evaluation_labels.ts
 */

import fs from 'fs';
import path from 'path';

const BASE = 'http://127.0.0.1:3000';
const KEY = process.env.ADMIN_API_KEY || 'test_admin_key_123';
const ADJ = `${BASE}/api/v1/soc/adjudication`;
const auth = { 'x-api-key': KEY, 'Content-Type': 'application/json' };
const ROOT = process.cwd();
const DRY = process.argv.includes('--dry-run');

const HARNESSES = [
  { file: 'audit/eval_harness.ts', set: 'SET_A' },
  { file: 'audit/eval_holdout_b.ts', set: 'SET_B' },
  { file: 'audit/ground_truth_scenarios.ts', set: 'GROUND_TRUTH_SCENARIOS' },
  { file: 'audit/seed_adjudication_drill.ts', set: 'DRILL' }
];

/**
 * Payload literals declared in a harness.
 *
 * Read from the files rather than duplicated here, so this cannot drift out of step
 * with the sets it is protecting.
 */
function literalsFrom(rel: string): string[] {
  let src = '';
  try {
    src = fs.readFileSync(path.join(ROOT, rel), 'utf-8');
  } catch {
    return [];
  }
  const out: string[] = [];
  // payload: '...' | "..."  and bare array entries in the drill lists.
  for (const m of src.matchAll(/payload(?:Sample)?:\s*(['"])([\s\S]*?)(?<!\\)\1/g)) out.push(m[2]);
  for (const m of src.matchAll(/probePayload:\s*(['"])([\s\S]*?)(?<!\\)\1/g)) out.push(m[2]);
  return out;
}

/** Payloads are sanitised and truncated in transit, so compare on a normalised prefix. */
const norm = (v: string) => v.replace(/\s+/g, ' ').slice(0, 60);

interface LabelRecord {
  id: string;
  payloadSample: string;
  analystLabel: string;
  actorKind: string;
  source: string;
  adjudicatedBy: string;
  supersedes: string | null;
}

(async () => {
  const health = await fetch(`${BASE}/api/health`).catch(() => null);
  if (!health?.ok) {
    console.error(`Server not reachable at ${BASE}.`);
    process.exit(2);
  }

  const index = new Map<string, string>();
  console.log('\n' + '='.repeat(78));
  console.log('  RETRACT EVALUATION PAYLOADS FROM THE CORPUS');
  console.log('='.repeat(78));
  console.log('\n  HARNESS PAYLOADS INDEXED');
  for (const h of HARNESSES) {
    const lits = literalsFrom(h.file);
    for (const l of lits) if (l.trim()) index.set(norm(l), h.set);
    console.log(`    ${h.set.padEnd(24)} ${String(lits.length).padStart(3)} literals from ${h.file}`);
  }

  const hr = await fetch(`${ADJ}/history?limit=1000`, { headers: auth });
  const hist: any = await hr.json();
  const labels: LabelRecord[] = hist.items ?? [];

  // Only active labels matter: already-superseded or retracted rows are out.
  const superseded = new Set(labels.map(l => l.supersedes).filter(Boolean) as string[]);
  const active = labels.filter(l => !superseded.has(l.id) && !/^RETRACTED:/.test(String((l as any).notes ?? '')));

  const hits = active
    .map(l => ({ label: l, set: index.get(norm(l.payloadSample)) }))
    .filter((x): x is { label: LabelRecord; set: string } => Boolean(x.set));

  const bySet = hits.reduce<Record<string, number>>((a, h) => ({ ...a, [h.set]: (a[h.set] ?? 0) + 1 }), {});

  console.log(`\n  CORPUS: ${active.length} active label(s)`);
  console.log(`  MATCHING A HARNESS PAYLOAD: ${hits.length}`);
  for (const [set, n] of Object.entries(bySet)) console.log(`    ${set.padEnd(24)} ${n}`);

  if (hits.length === 0) {
    console.log('\n  Nothing to retract. The corpus holds no evaluation payloads.\n');
    process.exit(0);
  }

  console.log('\n  SAMPLE OF WHAT WOULD BE WITHDRAWN');
  for (const h of hits.slice(0, 6)) {
    console.log(`    [${h.set}] ${h.label.analystLabel.padEnd(9)} ${h.label.payloadSample.slice(0, 50)}`);
  }

  if (DRY) {
    console.log('\n  DRY RUN — nothing written.\n');
    process.exit(0);
  }

  let ok = 0;
  let failed = 0;
  for (const h of hits) {
    const res = await fetch(`${ADJ}/retract`, {
      method: 'POST',
      headers: auth,
      body: JSON.stringify({
        labelId: h.label.id,
        retractedBy: 'corpus-hygiene',
        reason:
          `Payload is a declared ${h.set} evaluation literal. It reached the queue because the harness ` +
          `sends to /api/v1/agent/ai-analyze, which also queues for adjudication. Training on it would ` +
          `make ${h.set} contaminated for any learner scored against it. Withdrawn, not deleted.`
      })
    });
    const d: any = await res.json().catch(() => ({}));
    if (d.success) ok++;
    else {
      failed++;
      if (failed <= 3) console.log(`    failed ${h.label.id}: ${d.error ?? 'unknown'}`);
    }
  }

  console.log(`\n  RETRACTED ${ok}${failed ? `, ${failed} failed` : ''}`);

  const st: any = await (await fetch(`${ADJ}/stats`, { headers: auth })).json();
  console.log('\n  CORPUS AFTER');
  console.log(`    active labels             : ${st.totalLabels} (${st.malicious} malicious / ${st.benign} benign)`);
  console.log(`    retractions (auditable)   : ${st.retractions}`);
  console.log(`    revisions                 : ${st.revisions}`);
  console.log(`    evaluationSourcesRejected : ${st.evaluationSourcesRejected}`);
  console.log(`    operatorGrounded          : ${st.operatorGrounded}`);
  console.log(`    sufficient                : ${st.sufficient}${st.shortfall ? ` (${st.shortfall})` : ''}`);

  const f: any = await (await fetch(`${ADJ}/folds`, { headers: auth })).json();
  console.log(`\n  FOLDS  sufficient: ${f.sufficient}`);
  if (!f.sufficient) console.log(`    ${f.shortfall}`);
  else for (const fold of f.folds) console.log(`    fold ${fold.index}  n=${fold.n}  ${fold.role}`);

  console.log('\n  ' + '-'.repeat(74));
  console.log('  Set A and Set B are held-out again. The corpus is smaller and honest, which');
  console.log('  is the correct direction: it lost the labels that were never usable.');
  console.log('  Nothing was deleted — every retraction is readable with its reason.\n');

  process.exit(0);
})();
