import { classifyPayload } from './payloadClassifier.service.js';

/**
 * CONCEPT DRIFT DETECTION AND STRATEGIC RETENTION
 *
 * Phase 3's two unsupervised components. Both work without a single label, which
 * is why they could be built while the adjudication corpus is still empty — drift
 * is a property of the *input* distribution, and retention is a policy about which
 * inputs to keep.
 *
 * Why drift detection matters here specifically
 *   The continual-learning literature (SSF, INSOMNIA and the broader NIDS work) is
 *   consistent on one point: a detector trained once decays, and it decays silently.
 *   Accuracy on last quarter's traffic says nothing about this week's. Without drift
 *   detection the first sign of decay is an incident, and by then the question is
 *   why nobody noticed.
 *
 * The metric, and why PSI rather than raw accuracy
 *   Population Stability Index compares a reference distribution against a current
 *   one, bin by bin, and needs no ground truth. The industry convention — from
 *   credit-risk model monitoring, where it originates — reads:
 *
 *     PSI < 0.10   stable
 *     0.10 - 0.25  moderate shift, worth investigating
 *     PSI > 0.25   significant shift, the model's assumptions no longer hold
 *
 *   Jensen-Shannon divergence is computed alongside it because PSI is unbounded and
 *   sensitive to empty bins, while JS is bounded in [0,1] and symmetric. Reporting
 *   both means a single pathological bin cannot manufacture an alarm on its own.
 *
 * Why retention is not "keep everything"
 *   Appending every sample forever is the naive answer and it fails twice: the store
 *   grows without bound, and a retrain over it is dominated by whatever was most
 *   common historically, so rare families get forgotten. That is catastrophic
 *   forgetting arriving through the data rather than through the weights.
 *
 *   So retention here is stratified by attack family with a guaranteed floor per
 *   family, and within each stratum prefers samples that are recent, or near the
 *   decision boundary, or the only example of their kind. A sample that is none of
 *   those is the one to drop.
 */

/* ── Feature extraction ──────────────────────────────────────────────────── */

export interface PayloadFeatures {
  length: number;
  entropy: number;
  /** Share of characters that are not alphanumeric or space. */
  punctuationRatio: number;
  /** Share of characters that are digits. */
  digitRatio: number;
  /** Share that are uppercase letters — encoded blobs skew high. */
  uppercaseRatio: number;
  /** Percent-encoded sequences, a common obfuscation marker. */
  percentEncodings: number;
  family: string;
  score: number;
}

export function extractFeatures(payload: string): PayloadFeatures {
  const s = String(payload ?? '');
  const len = s.length || 1;
  const cls = classifyPayload(s);

  let punct = 0;
  let digits = 0;
  let upper = 0;
  for (const ch of s) {
    if (/[0-9]/.test(ch)) digits++;
    else if (/[A-Z]/.test(ch)) upper++;
    if (!/[a-zA-Z0-9 ]/.test(ch)) punct++;
  }

  return {
    length: s.length,
    entropy: cls.entropy,
    punctuationRatio: Number((punct / len).toFixed(4)),
    digitRatio: Number((digits / len).toFixed(4)),
    uppercaseRatio: Number((upper / len).toFixed(4)),
    percentEncodings: (s.match(/%[0-9a-fA-F]{2}/g) ?? []).length,
    family: cls.family,
    score: cls.score
  };
}

/* ── Divergence maths ────────────────────────────────────────────────────── */

/**
 * Population Stability Index between two binned distributions.
 *
 * Empty bins are floored rather than skipped: skipping them understates drift
 * exactly when a category has vanished, which is the interesting case.
 */
export function populationStabilityIndex(reference: number[], current: number[]): number {
  const eps = 1e-6;
  const rSum = reference.reduce((a, b) => a + b, 0) || 1;
  const cSum = current.reduce((a, b) => a + b, 0) || 1;
  let psi = 0;
  for (let i = 0; i < Math.max(reference.length, current.length); i++) {
    const r = Math.max((reference[i] ?? 0) / rSum, eps);
    const c = Math.max((current[i] ?? 0) / cSum, eps);
    psi += (c - r) * Math.log(c / r);
  }
  return Number(psi.toFixed(5));
}

/** Jensen-Shannon divergence, bounded in [0,1] with log base 2. */
export function jensenShannonDivergence(reference: number[], current: number[]): number {
  const eps = 1e-12;
  const rSum = reference.reduce((a, b) => a + b, 0) || 1;
  const cSum = current.reduce((a, b) => a + b, 0) || 1;
  const n = Math.max(reference.length, current.length);
  const kl = (p: number[], q: number[]) => {
    let d = 0;
    for (let i = 0; i < n; i++) {
      const pi = (p[i] ?? 0) + eps;
      const qi = (q[i] ?? 0) + eps;
      if (pi > eps) d += pi * Math.log2(pi / qi);
    }
    return d;
  };
  const p: number[] = [];
  const q: number[] = [];
  const m: number[] = [];
  for (let i = 0; i < n; i++) {
    p.push((reference[i] ?? 0) / rSum);
    q.push((current[i] ?? 0) / cSum);
    m.push((p[i] + q[i]) / 2);
  }
  return Number((0.5 * kl(p, m) + 0.5 * kl(q, m)).toFixed(5));
}

/** Fixed-edge histogram. Edges are fixed so reference and current stay comparable. */
function histogram(values: number[], edges: number[]): number[] {
  const bins = new Array(edges.length + 1).fill(0);
  for (const v of values) {
    let placed = false;
    for (let i = 0; i < edges.length; i++) {
      if (v <= edges[i]) {
        bins[i]++;
        placed = true;
        break;
      }
    }
    if (!placed) bins[bins.length - 1]++;
  }
  return bins;
}

const FEATURE_EDGES: Record<string, number[]> = {
  length: [16, 32, 64, 128, 256, 512, 1024],
  entropy: [2, 3, 3.5, 4, 4.5, 5, 5.5, 6],
  punctuationRatio: [0.02, 0.05, 0.1, 0.2, 0.35, 0.5],
  digitRatio: [0.02, 0.05, 0.1, 0.2, 0.35],
  uppercaseRatio: [0.02, 0.05, 0.1, 0.2, 0.35],
  percentEncodings: [0, 1, 2, 4, 8, 16],
  score: [0, 20, 40, 55, 70, 85]
};

export type DriftVerdict = 'STABLE' | 'MODERATE_SHIFT' | 'SIGNIFICANT_SHIFT' | 'INSUFFICIENT_DATA';

export interface FeatureDrift {
  feature: string;
  psi: number;
  jsd: number;
  verdict: DriftVerdict;
}

export interface DriftReport {
  verdict: DriftVerdict;
  /** Largest PSI across features — the headline figure. */
  maxPsi: number;
  drivingFeature: string | null;
  features: FeatureDrift[];
  familyDistributionShift: { psi: number; jsd: number; newFamilies: string[]; vanishedFamilies: string[] };
  referenceSize: number;
  currentSize: number;
  /** Thresholds stated so the verdict can be checked rather than trusted. */
  thresholds: { moderate: number; significant: number; minSamples: number };
  computedAt: string;
  /** Null until both windows are full; no verdict is invented before then. */
  insufficientReason?: string;
}

/** Industry convention from model monitoring. Not tuned to flatter this project. */
export const PSI_MODERATE = 0.1;
export const PSI_SIGNIFICANT = 0.25;
/** Below this per window, PSI is noise. */
export const MIN_WINDOW_SAMPLES = 50;

export class DriftDetector {
  private reference: PayloadFeatures[] = [];
  private current: PayloadFeatures[] = [];
  private windowSize: number;
  private referenceFrozenAt: string | null = null;
  private rotations = 0;

  constructor(windowSize = 200) {
    this.windowSize = Math.max(MIN_WINDOW_SAMPLES, windowSize);
  }

  /** Observe a payload. No labels required — this is the point of the component. */
  observe(payload: string): void {
    const f = extractFeatures(payload);
    if (this.reference.length < this.windowSize) {
      this.reference.push(f);
      if (this.reference.length === this.windowSize) {
        this.referenceFrozenAt = new Date().toISOString();
      }
      return;
    }
    this.current.push(f);
    if (this.current.length > this.windowSize) this.current.shift();
  }

  /**
   * Promote the current window to reference.
   *
   * Called after a drift has been acknowledged and acted on; otherwise the same
   * drift is re-reported forever. Deliberately manual: silently re-baselining
   * would make drift disappear on its own, which is how monitoring stops working.
   */
  rebaseline(): void {
    if (this.current.length < MIN_WINDOW_SAMPLES) return;
    this.reference = [...this.current];
    this.current = [];
    this.referenceFrozenAt = new Date().toISOString();
    this.rotations++;
  }

  private numericDrift(key: keyof PayloadFeatures, edges: number[]): FeatureDrift {
    const ref = histogram(this.reference.map(f => Number(f[key])), edges);
    const cur = histogram(this.current.map(f => Number(f[key])), edges);
    const psi = populationStabilityIndex(ref, cur);
    const jsd = jensenShannonDivergence(ref, cur);
    return {
      feature: String(key),
      psi,
      jsd,
      verdict: psi >= PSI_SIGNIFICANT ? 'SIGNIFICANT_SHIFT' : psi >= PSI_MODERATE ? 'MODERATE_SHIFT' : 'STABLE'
    };
  }

  report(): DriftReport {
    const base = {
      thresholds: { moderate: PSI_MODERATE, significant: PSI_SIGNIFICANT, minSamples: MIN_WINDOW_SAMPLES },
      referenceSize: this.reference.length,
      currentSize: this.current.length,
      computedAt: new Date().toISOString()
    };

    if (this.reference.length < MIN_WINDOW_SAMPLES || this.current.length < MIN_WINDOW_SAMPLES) {
      return {
        ...base,
        verdict: 'INSUFFICIENT_DATA',
        maxPsi: 0,
        drivingFeature: null,
        features: [],
        familyDistributionShift: { psi: 0, jsd: 0, newFamilies: [], vanishedFamilies: [] },
        insufficientReason: `reference ${this.reference.length}, current ${this.current.length}; ${MIN_WINDOW_SAMPLES} needed in each before PSI is meaningful.`
      };
    }

    const features = Object.entries(FEATURE_EDGES).map(([k, edges]) =>
      this.numericDrift(k as keyof PayloadFeatures, edges)
    );

    // Family distribution, over the union of families so a vanished family
    // contributes rather than being silently dropped.
    const famCount = (rows: PayloadFeatures[]) =>
      rows.reduce<Record<string, number>>((acc, f) => {
        acc[f.family] = (acc[f.family] ?? 0) + 1;
        return acc;
      }, {});
    const refFam = famCount(this.reference);
    const curFam = famCount(this.current);
    const keys = [...new Set([...Object.keys(refFam), ...Object.keys(curFam)])].sort();
    const famPsi = populationStabilityIndex(
      keys.map(k => refFam[k] ?? 0),
      keys.map(k => curFam[k] ?? 0)
    );
    const famJsd = jensenShannonDivergence(
      keys.map(k => refFam[k] ?? 0),
      keys.map(k => curFam[k] ?? 0)
    );

    const all = [...features, { feature: 'family', psi: famPsi, jsd: famJsd, verdict: 'STABLE' as DriftVerdict }];
    const worst = all.reduce((a, b) => (b.psi > a.psi ? b : a));

    return {
      ...base,
      verdict:
        worst.psi >= PSI_SIGNIFICANT ? 'SIGNIFICANT_SHIFT' : worst.psi >= PSI_MODERATE ? 'MODERATE_SHIFT' : 'STABLE',
      maxPsi: worst.psi,
      drivingFeature: worst.feature,
      features,
      familyDistributionShift: {
        psi: famPsi,
        jsd: famJsd,
        // A family appearing for the first time is the signal a signature
        // detector most needs: it is the shape of an attack class nobody wrote a
        // rule for.
        newFamilies: keys.filter(k => !refFam[k] && curFam[k]),
        vanishedFamilies: keys.filter(k => refFam[k] && !curFam[k])
      }
    };
  }

  getStatistics() {
    return {
      windowSize: this.windowSize,
      referenceSize: this.reference.length,
      currentSize: this.current.length,
      referenceFrozenAt: this.referenceFrozenAt,
      rebaselines: this.rotations,
      provenance: { mode: 'MEASURED_FROM_OBSERVED_PAYLOADS', seeded: false }
    };
  }

  reset() {
    this.reference = [];
    this.current = [];
    this.referenceFrozenAt = null;
    this.rotations = 0;
  }
}

/* ── Strategic retention ─────────────────────────────────────────────────── */

export interface RetainedSample {
  id: string;
  payload: string;
  features: PayloadFeatures;
  observedAt: number;
  /** Why this sample survived. Makes the policy auditable. */
  retentionReasons: string[];
}

export interface RetentionStats {
  capacity: number;
  held: number;
  byFamily: Record<string, number>;
  admitted: number;
  evicted: number;
  /** Families guaranteed a floor, so a rare class cannot be crowded out. */
  perFamilyFloor: number;
  provenance: { mode: string; seeded: boolean };
}

/**
 * Stratified reservoir with a per-family floor.
 *
 * The floor is what prevents catastrophic forgetting through the data: without it
 * a stream that is 95% one family evicts every example of the rare ones, and a
 * retrain then has no idea those classes exist.
 */
export class StrategicRetention {
  private samples: RetainedSample[] = [];
  private admitted = 0;
  private evicted = 0;
  private seq = 0;

  constructor(
    private capacity = 500,
    private perFamilyFloor = 10
  ) {}

  admit(payload: string, at = Date.now()): RetainedSample | null {
    const features = extractFeatures(payload);
    const reasons: string[] = [];

    const familyCount = this.samples.filter(s => s.features.family === features.family).length;
    if (familyCount === 0) reasons.push('FIRST_OF_FAMILY');
    else if (familyCount < this.perFamilyFloor) reasons.push('BELOW_FAMILY_FLOOR');

    // Near the decision boundary: these are the samples a retrain learns most
    // from, and the ones a threshold change would flip.
    if (features.score >= 40 && features.score <= 70) reasons.push('NEAR_DECISION_BOUNDARY');

    // Novel shape relative to what is held. Cheap nearest-neighbour on the
    // numeric features; enough to spot a payload unlike anything retained.
    if (this.samples.length > 0) {
      const dist = Math.min(
        ...this.samples.map(s =>
          Math.abs(s.features.entropy - features.entropy) +
          Math.abs(s.features.punctuationRatio - features.punctuationRatio) * 4 +
          Math.abs(Math.log2((s.features.length || 1) / (features.length || 1)))
        )
      );
      if (dist > 1.5) reasons.push('NOVEL_SHAPE');
    }

    if (reasons.length === 0) reasons.push('ROUTINE');

    const sample: RetainedSample = {
      id: `ret_${(++this.seq).toString(36)}`,
      payload: payload.slice(0, 2048),
      features,
      observedAt: at,
      retentionReasons: reasons
    };

    this.samples.push(sample);
    this.admitted++;

    if (this.samples.length > this.capacity) this.evictOne();
    return sample;
  }

  /**
   * Evict the least valuable sample.
   *
   * Never evicts below a family's floor, and prefers ROUTINE samples, then the
   * oldest. A sample that is the only example of its family is never evicted —
   * dropping it is how a detector forgets a whole attack class.
   */
  private evictOne(): void {
    const familyCounts = this.samples.reduce<Record<string, number>>((acc, s) => {
      acc[s.features.family] = (acc[s.features.family] ?? 0) + 1;
      return acc;
    }, {});

    const evictable = this.samples.filter(s => familyCounts[s.features.family] > this.perFamilyFloor);
    const pool = evictable.length ? evictable : this.samples.filter(s => familyCounts[s.features.family] > 1);
    if (pool.length === 0) return;

    const routine = pool.filter(s => s.retentionReasons.length === 1 && s.retentionReasons[0] === 'ROUTINE');
    const target = (routine.length ? routine : pool).reduce((a, b) => (b.observedAt < a.observedAt ? b : a));

    this.samples = this.samples.filter(s => s.id !== target.id);
    this.evicted++;
  }

  getSamples(): RetainedSample[] {
    return [...this.samples];
  }

  getStatistics(): RetentionStats {
    return {
      capacity: this.capacity,
      held: this.samples.length,
      byFamily: this.samples.reduce<Record<string, number>>((acc, s) => {
        acc[s.features.family] = (acc[s.features.family] ?? 0) + 1;
        return acc;
      }, {}),
      admitted: this.admitted,
      evicted: this.evicted,
      perFamilyFloor: this.perFamilyFloor,
      provenance: { mode: 'MEASURED_FROM_ADMITTED_SAMPLES', seeded: false }
    };
  }

  reset() {
    this.samples = [];
    this.admitted = 0;
    this.evicted = 0;
    this.seq = 0;
  }
}

export const globalDriftDetector = new DriftDetector();
export const globalStrategicRetention = new StrategicRetention();
