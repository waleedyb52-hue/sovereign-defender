import { extractFeatures, type PayloadFeatures } from './driftDetection.service.js';

/**
 * CONTINUAL LEARNER AND PROMOTION GATE
 *
 * The learned component Phase 3 calls for, plus the gate that decides whether an
 * update is allowed to replace the incumbent.
 *
 * What this is, and what it is not
 *   It is a logistic model over the same features the drift detector extracts,
 *   trained by online gradient descent so it can update incrementally rather than
 *   retraining from scratch. That choice is deliberate: the deployment target is a
 *   sovereign install with no GPU and no external service, so a linear model that
 *   trains in milliseconds on CPU is the honest fit. A transformer here would be
 *   architecture theatre.
 *
 *   It is NOT validated. The acceptance criterion for Phase 3 is a measurable AUT
 *   improvement over the frozen baseline on operator-adjudicated data postdating
 *   both, and that data does not exist yet. So `validationState` reports
 *   UNVALIDATED and `canPromote()` refuses on an empty corpus. The machinery is
 *   built and tested; the claim it would support is not made.
 *
 * Why the gate refuses by default
 *   A promotion path that defaults to allowing an update will, on the first
 *   ambiguous evaluation, ship a worse model. So every guard here is a reason to
 *   refuse, and promotion requires all of them to be satisfied at once:
 *
 *     1. The challenger beats the incumbent on the held-out fold.
 *     2. It does not regress on earlier folds by more than a small margin — this
 *        is the catastrophic-forgetting check, and it is the one most often
 *        skipped in published continual-learning work.
 *     3. The held-out fold is large enough for the comparison to mean anything.
 *     4. The labels are operator-grounded.
 *
 *   Failing any one of them returns the reason rather than a boolean, so a refusal
 *   can be argued with.
 */

export interface LabelledSample {
  payload: string;
  label: 'MALICIOUS' | 'BENIGN';
  /** Fold index; lower is older. Used for the forgetting check. */
  fold?: number;
}

/** Feature vector order is fixed — a reordering silently invalidates saved weights. */
const FEATURE_ORDER = [
  'lengthLog',
  'entropy',
  'punctuationRatio',
  'digitRatio',
  'uppercaseRatio',
  'percentEncodingsLog',
  'ruleScore'
] as const;

function vectorise(f: PayloadFeatures): number[] {
  return [
    Math.log2((f.length || 1) + 1) / 12, // log-scaled and normalised to roughly [0,1]
    f.entropy / 8,
    f.punctuationRatio,
    f.digitRatio,
    f.uppercaseRatio,
    Math.log2(f.percentEncodings + 1) / 6,
    f.score / 100
  ];
}

export interface ModelSnapshot {
  id: string;
  weights: number[];
  bias: number;
  trainedOn: number;
  epochs: number;
  createdAt: string;
  featureOrder: readonly string[];
}

export interface EvaluationResult {
  n: number;
  tp: number;
  fp: number;
  tn: number;
  fn: number;
  precision: number;
  recall: number;
  f1: number;
  falsePositiveRate: number;
}

export type ValidationState = 'UNVALIDATED' | 'VALIDATED_ON_DRILL' | 'VALIDATED_ON_OPERATOR_DATA';

export interface PromotionDecision {
  promote: boolean;
  /** Every refusal carries its reason so it can be argued with. */
  reasons: string[];
  challenger: EvaluationResult | null;
  incumbent: EvaluationResult | null;
  /** Per-fold regression check. Negative delta means the challenger got worse. */
  forgettingCheck: Array<{ fold: number; incumbentF1: number; challengerF1: number; delta: number }>;
  validationState: ValidationState;
}

/** F1 the challenger must exceed the incumbent by before promotion is considered. */
export const MIN_F1_GAIN = 0.01;
/** Allowed F1 regression on any earlier fold. Beyond this is catastrophic forgetting. */
export const MAX_FOLD_REGRESSION = 0.03;
/** Below this the held-out fold cannot support a comparison. */
export const MIN_HOLDOUT_SAMPLES = 20;

export class ContinualLearner {
  private weights: number[] = new Array(FEATURE_ORDER.length).fill(0);
  private bias = 0;
  private trainedOn = 0;
  private epochsRun = 0;
  private incumbent: ModelSnapshot | null = null;

  private static sigmoid(z: number): number {
    // Clamped to avoid overflow on extreme logits.
    if (z >= 0) return 1 / (1 + Math.exp(-Math.min(z, 30)));
    const e = Math.exp(Math.max(z, -30));
    return e / (1 + e);
  }

  predictProbability(payload: string): number {
    const v = vectorise(extractFeatures(payload));
    let z = this.bias;
    for (let i = 0; i < v.length; i++) z += this.weights[i] * v[i];
    return ContinualLearner.sigmoid(z);
  }

  predict(payload: string, threshold = 0.5): 'MALICIOUS' | 'BENIGN' {
    return this.predictProbability(payload) >= threshold ? 'MALICIOUS' : 'BENIGN';
  }

  /**
   * Online gradient descent.
   *
   * Class weighting is applied because attacks are the minority in any realistic
   * stream, and unweighted training on a 2% positive rate converges to predicting
   * BENIGN for everything — which scores 98% accuracy and detects nothing. That
   * failure is base-rate neglect, pitfall P4 in Arp et al.
   */
  train(samples: LabelledSample[], opts: { epochs?: number; learningRate?: number } = {}): void {
    if (samples.length === 0) return;
    const epochs = opts.epochs ?? 12;
    const lr = opts.learningRate ?? 0.25;

    const positives = samples.filter(s => s.label === 'MALICIOUS').length;
    const negatives = samples.length - positives;
    const posWeight = positives > 0 ? Math.min(10, negatives / positives) : 1;

    const rows = samples.map(s => ({
      v: vectorise(extractFeatures(s.payload)),
      y: s.label === 'MALICIOUS' ? 1 : 0
    }));

    for (let e = 0; e < epochs; e++) {
      for (const { v, y } of rows) {
        let z = this.bias;
        for (let i = 0; i < v.length; i++) z += this.weights[i] * v[i];
        const p = ContinualLearner.sigmoid(z);
        const w = y === 1 ? posWeight : 1;
        const err = (p - y) * w;
        for (let i = 0; i < v.length; i++) this.weights[i] -= lr * err * v[i];
        this.bias -= lr * err;
      }
      this.epochsRun++;
    }
    this.trainedOn += samples.length;
  }

  evaluate(samples: LabelledSample[], threshold = 0.5): EvaluationResult {
    let tp = 0;
    let fp = 0;
    let tn = 0;
    let fn = 0;
    for (const s of samples) {
      const pred = this.predict(s.payload, threshold);
      if (s.label === 'MALICIOUS' && pred === 'MALICIOUS') tp++;
      else if (s.label === 'BENIGN' && pred === 'MALICIOUS') fp++;
      else if (s.label === 'BENIGN' && pred === 'BENIGN') tn++;
      else fn++;
    }
    const precision = tp + fp ? tp / (tp + fp) : 0;
    const recall = tp + fn ? tp / (tp + fn) : 0;
    return {
      n: samples.length,
      tp,
      fp,
      tn,
      fn,
      precision: Number(precision.toFixed(4)),
      recall: Number(recall.toFixed(4)),
      f1: Number((precision + recall ? (2 * precision * recall) / (precision + recall) : 0).toFixed(4)),
      falsePositiveRate: Number((fp + tn ? fp / (fp + tn) : 0).toFixed(4))
    };
  }

  snapshot(): ModelSnapshot {
    return {
      id: `model_${Date.now().toString(36)}`,
      weights: [...this.weights],
      bias: this.bias,
      trainedOn: this.trainedOn,
      epochs: this.epochsRun,
      createdAt: new Date().toISOString(),
      featureOrder: FEATURE_ORDER
    };
  }

  restore(snap: ModelSnapshot): boolean {
    // A snapshot whose feature order differs is not loadable: the weights would be
    // applied to the wrong columns and the model would be silently wrong.
    if (snap.featureOrder?.length !== FEATURE_ORDER.length) return false;
    if (snap.featureOrder.some((f, i) => f !== FEATURE_ORDER[i])) return false;
    this.weights = [...snap.weights];
    this.bias = snap.bias;
    this.trainedOn = snap.trainedOn;
    this.epochsRun = snap.epochs;
    return true;
  }

  setIncumbent(snap: ModelSnapshot): void {
    this.incumbent = snap;
  }

  getIncumbent(): ModelSnapshot | null {
    return this.incumbent;
  }

  getStatistics() {
    return {
      featureOrder: FEATURE_ORDER,
      weights: this.weights.map(w => Number(w.toFixed(4))),
      bias: Number(this.bias.toFixed(4)),
      trainedOnSamples: this.trainedOn,
      epochsRun: this.epochsRun,
      hasIncumbent: this.incumbent !== null,
      provenance: { mode: 'TRAINED_ON_SUPPLIED_LABELS', seeded: false }
    };
  }

  reset(): void {
    this.weights = new Array(FEATURE_ORDER.length).fill(0);
    this.bias = 0;
    this.trainedOn = 0;
    this.epochsRun = 0;
    this.incumbent = null;
  }
}

/**
 * Decide whether a challenger replaces the incumbent.
 *
 * Every branch is a refusal. The default answer is no.
 */
export function decidePromotion(input: {
  challenger: ContinualLearner;
  incumbentSnapshot: ModelSnapshot | null;
  holdout: LabelledSample[];
  earlierFolds: LabelledSample[][];
  operatorGrounded: boolean;
}): PromotionDecision {
  const reasons: string[] = [];
  const { challenger, incumbentSnapshot, holdout, earlierFolds, operatorGrounded } = input;

  const validationState: ValidationState = !operatorGrounded
    ? holdout.length > 0
      ? 'VALIDATED_ON_DRILL'
      : 'UNVALIDATED'
    : 'VALIDATED_ON_OPERATOR_DATA';

  if (holdout.length < MIN_HOLDOUT_SAMPLES) {
    reasons.push(
      `Held-out fold has ${holdout.length} samples; ${MIN_HOLDOUT_SAMPLES} required before a comparison means anything.`
    );
  }
  if (!operatorGrounded) {
    reasons.push(
      'Labels are not operator-grounded. A promotion decided on drill data would measure the pipeline, not the detector.'
    );
  }

  const challengerResult = holdout.length ? challenger.evaluate(holdout) : null;

  let incumbentResult: EvaluationResult | null = null;
  const incumbentModel = new ContinualLearner();
  if (incumbentSnapshot && incumbentModel.restore(incumbentSnapshot)) {
    incumbentResult = holdout.length ? incumbentModel.evaluate(holdout) : null;
  } else if (incumbentSnapshot) {
    reasons.push('Incumbent snapshot has an incompatible feature order and cannot be compared.');
  }

  // Forgetting check across earlier folds. Skipped in much of the published work,
  // and it is where a continual learner usually fails.
  const forgettingCheck: PromotionDecision['forgettingCheck'] = [];
  if (incumbentResult) {
    earlierFolds.forEach((fold, idx) => {
      if (fold.length === 0) return;
      const inc = incumbentModel.evaluate(fold).f1;
      const chal = challenger.evaluate(fold).f1;
      const delta = Number((chal - inc).toFixed(4));
      forgettingCheck.push({ fold: idx, incumbentF1: inc, challengerF1: chal, delta });
      if (delta < -MAX_FOLD_REGRESSION) {
        reasons.push(
          `Catastrophic forgetting on fold ${idx}: F1 fell ${Math.abs(delta).toFixed(3)}, limit ${MAX_FOLD_REGRESSION}.`
        );
      }
    });
  }

  if (challengerResult && incumbentResult) {
    const gain = challengerResult.f1 - incumbentResult.f1;
    if (gain < MIN_F1_GAIN) {
      reasons.push(
        `Challenger F1 ${challengerResult.f1} does not beat incumbent ${incumbentResult.f1} by the required ${MIN_F1_GAIN}.`
      );
    }
  } else if (!incumbentSnapshot) {
    // First model. Still refused unless the data is trustworthy — a first model
    // promoted on untrustworthy data becomes the incumbent everything else is
    // measured against.
    if (operatorGrounded && holdout.length >= MIN_HOLDOUT_SAMPLES) {
      reasons.length = 0;
    } else {
      reasons.push('No incumbent exists, and the first model may only be promoted on a sufficient operator-grounded fold.');
    }
  }

  return {
    promote: reasons.length === 0,
    reasons,
    challenger: challengerResult,
    incumbent: incumbentResult,
    forgettingCheck,
    validationState
  };
}

export const globalContinualLearner = new ContinualLearner();
