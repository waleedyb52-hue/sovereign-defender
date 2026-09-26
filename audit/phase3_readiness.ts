/**
 * PHASE 3 READINESS — computed, not asserted
 *
 * A single percentage for "are we ready for continual learning under drift".
 *
 * The figure is derived the same way every other number in this project has to
 * be: each item is checked against running state or the repository, and the
 * arithmetic is printed so the total can be disagreed with. A readiness number
 * that cannot be audited is a mood, and this project has spent its whole history
 * removing those.
 *
 * Weighting rationale
 *   Prerequisites carry 40%. They gate everything: without a bias-controlled
 *   harness and temporally-folded labelled data, a model update cannot be
 *   evaluated at all, so building the learner first would produce something
 *   unmeasurable.
 *
 *   Components carry 60%, because that is the actual Phase 3 work.
 *
 *   Within each group items are equally weighted, except the labelled corpus,
 *   which is weighted double. It is the only hard blocker — every other missing
 *   item can be built today, while that one needs an analyst and cannot be
 *   engineered around.
 *
 * Run:  npx tsx audit/phase3_readiness.ts
 */

import fs from 'fs';
import path from 'path';

const BASE = 'http://127.0.0.1:3000';
const KEY = process.env.ADMIN_API_KEY || 'test_admin_key_123';
const ROOT = process.cwd();
const auth = { 'x-api-key': KEY };

type State = 'DONE' | 'PARTIAL' | 'MISSING' | 'BLOCKED';

interface Item {
  id: string;
  label: string;
  group: 'PREREQUISITE' | 'COMPONENT';
  weight: number;
  state: State;
  /** Fraction of this item's weight earned. */
  credit: number;
  evidence: string;
}

/**
 * Whether the repository implements something matching `pattern`.
 *
 * This file is excluded from its own scan. The first version was not, and it
 * reported drift detection, strategic retention and a promotion gate as present
 * — because the literal strings `driftDetect`, `strategicRetention` and
 * `promoteModel` appear in the regexes below. A readiness calculator that counts
 * its own source as evidence inflates the score by 40 points, which is exactly
 * the class of self-measurement this project exists to eliminate.
 */
const SELF = path.join(ROOT, 'audit', 'phase3_readiness.ts');

function repoHas(pattern: RegExp, dirs = ['server', 'audit', 'src']): boolean {
  const walk = (dir: string, out: string[] = []): string[] => {
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return out;
    }
    for (const e of entries) {
      const p = path.join(dir, e.name);
      if (e.isDirectory()) walk(p, out);
      else if (/\.(ts|tsx)$/.test(e.name)) out.push(p);
    }
    return out;
  };
  const files = dirs.flatMap(d => walk(path.join(ROOT, d))).filter(f => path.resolve(f) !== path.resolve(SELF));
  for (const f of files) {
    try {
      if (pattern.test(fs.readFileSync(f, 'utf-8'))) return true;
    } catch {
      /* unreadable file is not evidence */
    }
  }
  return false;
}

async function getJson(p: string): Promise<any | null> {
  try {
    const r = await fetch(BASE + p, { headers: auth });
    if (!r.ok) return null;
    return await r.json();
  } catch {
    return null;
  }
}

const pct = (n: number) => (n * 100).toFixed(1) + '%';

(async () => {
  const health = await fetch(`${BASE}/api/health`).catch(() => null);
  if (!health?.ok) {
    console.error(`Server not reachable at ${BASE}. Readiness cannot be measured against a dead process.`);
    process.exit(2);
  }

  const items: Item[] = [];
  const add = (i: Omit<Item, 'credit'> & { credit?: number }) =>
    items.push({ ...i, credit: i.credit ?? (i.state === 'DONE' ? 1 : i.state === 'PARTIAL' ? 0.5 : 0) });

  /* ── Prerequisites (40 points) ───────────────────────────────────────── */

  // 1. Bias-controlled harness with a clean held-out set.
  const hasSetA = fs.existsSync(path.join(ROOT, 'audit/eval_harness.ts'));
  const hasSetB = fs.existsSync(path.join(ROOT, 'audit/eval_holdout_b.ts'));
  add({
    id: 'harness',
    label: 'Bias-controlled evaluation harness (Set A regression + Set B clean)',
    group: 'PREREQUISITE',
    weight: 8,
    state: hasSetA && hasSetB ? 'DONE' : hasSetA ? 'PARTIAL' : 'MISSING',
    evidence: `eval_harness.ts=${hasSetA}, eval_holdout_b.ts=${hasSetB}; Set B Tier 2 measures class generalisation at 25%.`
  });

  // 2. Temporal fold machinery — TESSERACT ordering.
  const folds = await getJson('/api/v1/soc/adjudication/folds');
  const foldMachineryExists = folds !== null;
  add({
    id: 'folds',
    label: 'Temporal fold machinery, derived from timestamps',
    group: 'PREREQUISITE',
    weight: 8,
    state: foldMachineryExists ? 'DONE' : 'MISSING',
    evidence: foldMachineryExists
      ? `endpoint live; sufficient=${folds.sufficient}${folds.shortfall ? ` (${folds.shortfall})` : ''}`
      : 'no /folds endpoint'
  });

  // 3. The labelled corpus. Weighted double: the only item that cannot be
  //    engineered around.
  const stats = await getJson('/api/v1/soc/adjudication/stats');
  const labels = Number(stats?.totalLabels ?? 0);
  const needed = Number(stats?.minLabelsForStableFigure ?? 100);
  const grounded = Boolean(stats?.operatorGrounded);
  const corpusCredit = Math.min(1, labels / needed) * (grounded ? 1 : labels > 0 ? 0.5 : 0);
  add({
    id: 'corpus',
    label: 'Operator-adjudicated corpus (the hard blocker)',
    group: 'PREREQUISITE',
    weight: 16,
    state: labels >= needed && grounded ? 'DONE' : labels > 0 ? 'PARTIAL' : 'BLOCKED',
    credit: corpusCredit,
    evidence: `${labels}/${needed} labels, operatorGrounded=${grounded}, ${stats?.pendingCount ?? 0} awaiting a ruling.`
  });

  // 4. Provenance on every reported figure.
  const cluster = await getJson('/api/v1/soc/ebpf/cluster-nodes');
  const hasProvenance = Boolean(cluster?.statistics?.provenance?.fields);
  add({
    id: 'provenance',
    label: 'Per-figure provenance (MEASURED / SEEDED / UNAVAILABLE)',
    group: 'PREREQUISITE',
    weight: 8,
    state: hasProvenance ? 'DONE' : 'MISSING',
    evidence: hasProvenance
      ? `mode=${cluster.statistics.provenance.mode}; every eBPF field carries an origin tag.`
      : 'no provenance block on telemetry'
  });

  /* ── Components (60 points) ──────────────────────────────────────────── */

  // 5. Drift detection — unsupervised, so it is NOT blocked on labels.
  const hasDrift = repoHas(/driftDetect|DriftDetector|klDivergence|populationStability|jensenShannon/i);
  add({
    id: 'drift',
    label: 'Drift detection on the incoming distribution (unsupervised — not label-blocked)',
    group: 'COMPONENT',
    weight: 15,
    state: hasDrift ? 'DONE' : 'MISSING',
    evidence: hasDrift ? 'drift implementation found' : 'no drift detector in the tree; buildable now without labels.'
  });

  // 6. Strategic retention — a policy, also not label-blocked.
  const hasRetention = repoHas(/strategicRetention|retentionPolicy|reservoirSample|catastrophicForgetting/i);
  add({
    id: 'retention',
    label: 'Strategic retention policy (not label-blocked)',
    group: 'COMPONENT',
    weight: 10,
    state: hasRetention ? 'DONE' : 'MISSING',
    evidence: hasRetention ? 'retention policy found' : 'no retention policy; buildable now.'
  });

  // 7. The learned component itself.
  // Anchored on the real names. The first version used a generic class/method
  // pattern that missed ContinualLearner entirely, so a component that exists was
  // reported as absent — the mirror of the self-reference bug that reported absent
  // components as present.
  const hasLearner = repoHas(/class ContinualLearner/) && repoHas(/predictProbability/);
  add({
    id: 'learner',
    label: 'Learned component that updates from adjudicated data',
    group: 'COMPONENT',
    weight: 20,
    // Built and unit-tested earns half, never full. Phase 3's criterion is a
    // measurable AUT improvement on operator data, and code that has never been
    // validated against that data has not met it. Awarding full marks for an
    // unvalidated model is how a project convinces itself it is finished.
    state: hasLearner ? 'PARTIAL' : 'BLOCKED',
    credit: hasLearner ? 0.5 : 0,
    evidence: hasLearner
      ? `ContinualLearner built and unit-tested; UNVALIDATED — no operator data to measure AUT against (${labels}/${needed} labels).`
      : `no learner; cannot be evaluated until the corpus fills (${labels}/${needed}).`
  });

  // 8. Promotion gate. Same discipline: refusing correctly on an empty corpus is
  //    half credit. A gate that has never judged a real challenger on real folds is
  //    untested exactly where it matters.
  const hasGate = repoHas(/export function decidePromotion/) && repoHas(/forgettingCheck/);
  add({
    id: 'gate',
    label: 'Promotion gated on beating the incumbent on the held-out fold',
    group: 'COMPONENT',
    weight: 15,
    state: hasGate ? 'PARTIAL' : 'BLOCKED',
    credit: hasGate ? 0.5 : 0,
    evidence: hasGate
      ? 'decidePromotion built with a catastrophic-forgetting check; verified to refuse on an empty corpus, never exercised on operator folds.'
      : 'no gate; requires a scored held-out fold, which requires labels.'
  });

  /* ── Report ──────────────────────────────────────────────────────────── */

  const totalWeight = items.reduce((a, i) => a + i.weight, 0);
  const earned = items.reduce((a, i) => a + i.weight * i.credit, 0);
  const readiness = earned / totalWeight;

  const prereq = items.filter(i => i.group === 'PREREQUISITE');
  const comp = items.filter(i => i.group === 'COMPONENT');
  const groupScore = (g: Item[]) =>
    g.reduce((a, i) => a + i.weight * i.credit, 0) / g.reduce((a, i) => a + i.weight, 0);

  console.log('\n' + '='.repeat(76));
  console.log('  PHASE 3 READINESS — CONTINUAL LEARNING UNDER DRIFT');
  console.log('='.repeat(76));

  for (const group of ['PREREQUISITE', 'COMPONENT'] as const) {
    const rows = items.filter(i => i.group === group);
    console.log(`\n  ${group}S  (${rows.reduce((a, i) => a + i.weight, 0)} points)`);
    for (const i of rows) {
      const bar = i.state === 'DONE' ? '[####]' : i.credit >= 0.5 ? '[##--]' : i.credit > 0 ? '[#---]' : '[----]';
      console.log(`    ${bar} ${i.state.padEnd(8)} ${String(Math.round(i.weight * i.credit)).padStart(2)}/${String(i.weight).padStart(2)}  ${i.label}`);
      console.log(`           ${i.evidence}`);
    }
  }

  console.log('\n' + '-'.repeat(76));
  console.log(`  Prerequisites  ${pct(groupScore(prereq))}`);
  console.log(`  Components     ${pct(groupScore(comp))}`);
  console.log(`  Earned         ${earned.toFixed(1)} of ${totalWeight} points`);
  console.log('');
  console.log(`  PHASE 3 READINESS:  ${pct(readiness)}`);
  console.log('');

  const blocked = items.filter(i => i.state === 'BLOCKED');
  const buildable = items.filter(i => i.state === 'MISSING');

  if (buildable.length) {
    console.log(`  BUILDABLE NOW — not waiting on anything (${buildable.length})`);
    for (const i of buildable) console.log(`    - ${i.label}`);
  }
  if (blocked.length) {
    console.log(`\n  BLOCKED — needs the corpus first (${blocked.length})`);
    for (const i of blocked) console.log(`    - ${i.label}`);
  }

  console.log('\n  ' + '-'.repeat(72));
  console.log('  The corpus is the only item that cannot be engineered around: it needs');
  console.log('  an analyst ruling on live traffic. Everything else on the buildable list');
  console.log(`  can start today. ${stats?.pendingCount ?? 0} detections are already queued and waiting.`);
  console.log('');

  process.exit(0);
})();
