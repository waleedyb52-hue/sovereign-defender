/**
 * EVALUATION AGAINST OPERATOR-ADJUDICATED DATA
 *
 * Sets A and B were written by the same process that wrote the rules. That is
 * their permanent ceiling: however carefully they are constructed, they measure
 * a detector against its author's imagination. This harness measures it against
 * labels the author did not produce.
 *
 * The two-step, and why it is not ceremony
 *   1. Fetch the test fold with labels withheld.
 *   2. Classify every sample and commit the predictions.
 *   3. Fetch the labels and score.
 *
 *   At the moment of classification the answers are not in this process. That
 *   is the structural version of plan principle 2 — the label never reaches the
 *   classifier — and it is enforced by the API shape rather than by this file
 *   being careful.
 *
 * What this harness will NOT do
 *   Print a figure from a corpus too small to support one. If the adjudicated
 *   set is thin, it says exactly what is missing and exits. An honest "not yet"
 *   is the deliverable until the corpus exists.
 *
 * Run:  npx tsx audit/eval_from_adjudicated.ts
 */

const BASE = 'http://127.0.0.1:3000';
const KEY = process.env.ADMIN_API_KEY || 'test_admin_key_123';
const ADJ = `${BASE}/api/v1/soc/adjudication`;

type Label = 'MALICIOUS' | 'BENIGN';

const auth = { 'x-api-key': KEY, 'Content-Type': 'application/json' };
const pct = (n: number) => (n * 100).toFixed(1) + '%';

async function classify(payload: string, nonce: number): Promise<Label> {
  const res = await fetch(`${BASE}/api/v1/agent/ai-analyze`, {
    method: 'POST',
    headers: auth,
    body: JSON.stringify({
      packet: {
        srcIp: `10.80.${nonce % 250}.${(nonce * 7) % 250}`,
        dstIp: '10.0.1.10',
        port: 443,
        protocol: 'HTTPS',
        vector: 'UNKNOWN',
        payload
      }
    })
  });
  const d: any = await res.json().catch(() => ({}));
  return String(d?.verdict ?? 'UNKNOWN') === 'ALLOW' ? 'BENIGN' : 'MALICIOUS';
}

(async () => {
  const health = await fetch(`${BASE}/api/health`).catch(() => null);
  if (!health?.ok) { console.error(`Server not reachable at ${BASE}.`); process.exit(2); }

  console.log('\n' + '='.repeat(72));
  console.log('  EVALUATION ON OPERATOR-ADJUDICATED DATA');
  console.log('='.repeat(72));

  const statsRes = await fetch(`${ADJ}/stats`, { headers: auth });
  const stats: any = await statsRes.json().catch(() => ({}));
  if (!statsRes.ok) {
    console.error(`\n  Could not read corpus stats (HTTP ${statsRes.status}). Is ADMIN_API_KEY set?\n`);
    process.exit(2);
  }

  console.log(`\n  CORPUS`);
  console.log(`    adjudicated labels   ${stats.totalLabels}  (${stats.malicious} malicious / ${stats.benign} benign)`);
  console.log(`    awaiting a ruling    ${stats.pendingCount}`);
  console.log(`    distinct adjudicators ${stats.distinctAdjudicators}`);
  console.log(`    revisions            ${stats.revisions}`);
  console.log(`    label store durable  ${stats.durable ? 'yes' : 'no (in-memory fallback)'}`);
  if (stats.earliestDetectedAt) {
    console.log(`    time span            ${stats.earliestDetectedAt} -> ${stats.latestDetectedAt}`);
  }
  console.log(`    machine errors the analyst found: ${stats.machineFalsePositives} FP, ${stats.machineFalseNegatives} FN`);
  console.log(`    by origin            ${JSON.stringify(stats.bySource ?? {})}`);
  console.log(`    by adjudicator kind  ${JSON.stringify(stats.byActorKind ?? {})}`);

  // The provenance warning goes above the figure, not in a footnote. A score
  // computed over drill labels is a test of this harness, not a measurement of
  // the detector against real operator judgement, and conflating the two would
  // recreate the original 100% problem in a new costume.
  if (stats.totalLabels > 0 && !stats.operatorGrounded) {
    console.log(`
  *** NOT OPERATOR-GROUNDED ***`);
    console.log(`      Some or all labels below did not come from a human analyst.`);
    console.log(`      Any figure here validates the pipeline, not the detector.`);
  }
  console.log(`    agreement with machine ${stats.agreementRate === null ? 'withheld (corpus too small)' : pct(stats.agreementRate)}`);

  // Step 1 — the test fold, labels withheld.
  const blindRes = await fetch(`${ADJ}/export/test`, { headers: auth });
  const blind: any = await blindRes.json().catch(() => ({}));

  if (!blind.success) {
    console.log(`\n  NO FIGURE REPORTED`);
    console.log(`    ${blind.reason ?? blind.error ?? 'test fold unavailable'}`);
    console.log(`\n  This is the correct output, not a failure. Phase 2 is complete when`);
    console.log(`  operators have adjudicated enough live traffic to fill the folds.`);
    console.log(`  Until then the platform reports what is missing rather than a number.\n`);
    process.exit(0);
  }

  console.log(`\n  TEST FOLD  n=${blind.count}  labelsWithheld=${blind.labelsWithheld}`);
  if (!blind.labelsWithheld) {
    console.error('\n  ABORT: the test fold arrived with labels attached. Scoring now would');
    console.error('  be meaningless — the classifier could have seen the answers.\n');
    process.exit(3);
  }

  // Step 2 — classify and commit, while the answers are still unavailable here.
  const predictions = new Map<string, Label>();
  let i = 0;
  for (const s of blind.samples as Array<{ id: string; payload: string }>) {
    predictions.set(s.id, await classify(s.payload, i++));
  }
  console.log(`    predictions committed for ${predictions.size} samples`);

  // Step 3 — now the labels.
  const truthRes = await fetch(`${ADJ}/export/test?withLabels=1`, { headers: auth });
  const truth: any = await truthRes.json().catch(() => ({}));
  if (!truth.success) { console.error('\n  Could not read labels for scoring.\n'); process.exit(2); }

  let tp = 0, fp = 0, tn = 0, fn = 0;
  const misses: Array<{ payload: string; truth: Label }> = [];
  for (const s of truth.samples as Array<{ id: string; payload: string; label: Label }>) {
    const pred = predictions.get(s.id);
    if (!pred) continue;
    if (s.label === 'MALICIOUS' && pred === 'MALICIOUS') tp++;
    else if (s.label === 'BENIGN' && pred === 'MALICIOUS') { fp++; misses.push({ payload: s.payload, truth: s.label }); }
    else if (s.label === 'BENIGN' && pred === 'BENIGN') tn++;
    else { fn++; misses.push({ payload: s.payload, truth: s.label }); }
  }

  const precision = tp + fp ? tp / (tp + fp) : 0;
  const recall = tp + fn ? tp / (tp + fn) : 0;
  const f1 = precision + recall ? (2 * precision * recall) / (precision + recall) : 0;
  const fpr = fp + tn ? fp / (fp + tn) : 0;

  console.log(`\n  SCORED AGAINST OPERATOR LABELS`);
  console.log(`    TP ${tp}  FP ${fp}  TN ${tn}  FN ${fn}`);
  console.log(`    precision ${pct(precision)}   recall ${pct(recall)}   F1 ${pct(f1)}`);
  console.log(`    false-positive rate ${pct(fpr)}`);

  if (misses.length) {
    console.log(`\n  DISAGREEMENTS WITH THE OPERATOR  (${misses.length})`);
    for (const m of misses.slice(0, 15)) {
      console.log(`    operator said ${m.truth.padEnd(9)} ${m.payload.slice(0, 54).replace(/\r?\n/g, ' ')}`);
    }
    if (misses.length > 15) console.log(`    ... and ${misses.length - 15} more`);
  }

  console.log('\n  ' + '-'.repeat(68));
  console.log('  Scored on the newest temporal fold only, which no rule may be written');
  console.log('  against. Tuning data is served from a separate endpoint that cannot');
  console.log('  return this fold.\n');
  process.exit(0);
})();
