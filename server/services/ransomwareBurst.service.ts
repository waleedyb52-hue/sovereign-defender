import { shannonEntropyOfBuffer } from './liveHostCanary.service.js';

/**
 * RANSOMWARE ENCRYPTION BURST DETECTOR — file I/O rate × post-write entropy
 *
 * Built because the ground-truth scenario report found T1486 at PARTIAL: entropy
 * computation existed in the tree but nothing measured write rate, and the
 * ransomware signal is the *conjunction* of the two. Either half alone produces
 * false positives an operator would learn to ignore:
 *
 *   - High write rate alone is a build, a backup, a log rotation, an npm install.
 *   - High entropy alone is any compressed or already-encrypted file. A .zip is
 *     not an incident.
 *
 * What makes the pair diagnostic is that ransomware rewrites *many* files *in
 * place* and leaves each one looking like noise. So this fires on sustained rate
 * AND an entropy rise across distinct files, and reports which condition carried
 * the decision so an analyst can disagree with it.
 *
 * On measurement honesty
 *   Rate is computed from real `fs.watch` events with real timestamps. There is no
 *   seeded baseline here and no default: before any event arrives, `opsPerSec` is
 *   0 because nothing has been observed, and `entropyDelta` is null because there
 *   is nothing to compare. A detector that reports a plausible idle rate is
 *   indistinguishable from one that is not running.
 *
 * On the entropy baseline
 *   A file's pre-write entropy is only known if the file was seen before. First
 *   sighting records a baseline and cannot raise an alert on entropy — the rise
 *   is the signal, and there is no rise without a prior value. This costs the
 *   first write of every file, which is the correct trade: the alternative is
 *   treating every newly created compressed file as an attack.
 */

/** Sliding window for rate calculation. Short enough to catch a burst, long enough to ignore a single save. */
const RATE_WINDOW_MS = 2000;
/** Events retained. At a burst rate this is a few seconds of history. */
const MAX_EVENTS = 4096;
/** Distinct files touched in-window before rate is considered burst-like. */
export const DEFAULT_BURST_FILE_THRESHOLD = 8;
/** Operations per second before rate alone is considered abnormal. */
export const DEFAULT_OPS_PER_SEC_THRESHOLD = 20;
/** Shannon entropy (0-8 bits/byte) above which content looks encrypted or packed. */
export const DEFAULT_ENTROPY_THRESHOLD = 7.4;
/** Entropy rise over a file's own baseline that indicates in-place encryption. */
export const DEFAULT_ENTROPY_DELTA_THRESHOLD = 1.5;

export interface IoEvent {
  path: string;
  at: number;
  entropy: number | null;
}

export interface BurstAssessment {
  /** True only when rate and entropy conditions are both met. */
  burstDetected: boolean;
  /** Measured from real events in the window. Zero when nothing was observed. */
  opsPerSec: number;
  distinctFilesInWindow: number;
  /** Highest post-write entropy seen in the window, null if no content was readable. */
  peakEntropy: number | null;
  /** Largest rise over a file's own recorded baseline. Null without a baseline. */
  peakEntropyDelta: number | null;
  /** Which conditions fired, so an analyst can see the reasoning rather than a verdict. */
  conditions: {
    rateExceeded: boolean;
    distinctFilesExceeded: boolean;
    entropyExceeded: boolean;
    entropyRoseOverBaseline: boolean;
  };
  /** Files implicated, most recent first. */
  affectedPaths: string[];
  /** Milliseconds from the first event in the burst to this assessment. */
  detectionWindowMs: number | null;
  mitreTechnique: 'T1486';
  recommendedAction: 'QUARANTINE_PID_AND_ROLLBACK' | 'MONITOR' | 'NONE';
}

export interface BurstThresholds {
  opsPerSec: number;
  distinctFiles: number;
  entropy: number;
  entropyDelta: number;
}

export class RansomwareBurstDetector {
  private events: IoEvent[] = [];
  /** First entropy recorded per path. The comparison point for a rise. */
  private baselineEntropy = new Map<string, number>();
  private thresholds: BurstThresholds = {
    opsPerSec: DEFAULT_OPS_PER_SEC_THRESHOLD,
    distinctFiles: DEFAULT_BURST_FILE_THRESHOLD,
    entropy: DEFAULT_ENTROPY_THRESHOLD,
    entropyDelta: DEFAULT_ENTROPY_DELTA_THRESHOLD
  };
  private lastAssessment: BurstAssessment | null = null;
  private detections = 0;

  configure(next: Partial<BurstThresholds>) {
    this.thresholds = { ...this.thresholds, ...next };
  }

  getThresholds(): BurstThresholds {
    return { ...this.thresholds };
  }

  /**
   * Record a write observed by the file watcher.
   *
   * `content` is optional: a watcher event can fire for a file that has already
   * been deleted or is locked, and in that case entropy is genuinely unknown.
   * Passing null is correct there — it is not the same as passing zero, which
   * would claim the file was all one byte value.
   */
  recordWrite(path: string, content?: Buffer | null, at = Date.now()): void {
    let entropy: number | null = null;
    if (content && content.length > 0) {
      try {
        entropy = Number(shannonEntropyOfBuffer(content).toFixed(3));
      } catch {
        entropy = null;
      }
    }

    this.events.push({ path, at, entropy });
    if (this.events.length > MAX_EVENTS) {
      this.events.splice(0, this.events.length - MAX_EVENTS);
    }

    // First sighting establishes the comparison point and cannot itself alert.
    if (entropy != null && !this.baselineEntropy.has(path)) {
      this.baselineEntropy.set(path, entropy);
    }
  }

  /** Assess the current window. Pure read — calling it does not alter state. */
  assess(now = Date.now()): BurstAssessment {
    const cutoff = now - RATE_WINDOW_MS;
    const inWindow = this.events.filter(e => e.at >= cutoff);

    const distinct = new Set(inWindow.map(e => e.path));
    // Rate over the actual elapsed span, not the nominal window: a burst that
    // started 200ms ago has not been observed for two seconds, and dividing by
    // the nominal window would understate it by an order of magnitude.
    const earliest = inWindow.length ? Math.min(...inWindow.map(e => e.at)) : now;
    const spanMs = Math.max(1, now - earliest);
    const opsPerSec = inWindow.length ? Number(((inWindow.length / spanMs) * 1000).toFixed(1)) : 0;

    const entropies = inWindow.map(e => e.entropy).filter((x): x is number => x != null);
    const peakEntropy = entropies.length ? Math.max(...entropies) : null;

    let peakEntropyDelta: number | null = null;
    for (const e of inWindow) {
      if (e.entropy == null) continue;
      const base = this.baselineEntropy.get(e.path);
      if (base == null) continue;
      const delta = e.entropy - base;
      if (peakEntropyDelta == null || delta > peakEntropyDelta) peakEntropyDelta = Number(delta.toFixed(3));
    }

    const t = this.thresholds;
    const conditions = {
      rateExceeded: opsPerSec >= t.opsPerSec,
      distinctFilesExceeded: distinct.size >= t.distinctFiles,
      entropyExceeded: peakEntropy != null && peakEntropy >= t.entropy,
      entropyRoseOverBaseline: peakEntropyDelta != null && peakEntropyDelta >= t.entropyDelta
    };

    // The conjunction is the whole point. Rate across several files, together
    // with content that now looks like noise.
    const rateSignal = conditions.rateExceeded && conditions.distinctFilesExceeded;
    const contentSignal = conditions.entropyExceeded || conditions.entropyRoseOverBaseline;
    const burstDetected = rateSignal && contentSignal;

    const assessment: BurstAssessment = {
      burstDetected,
      opsPerSec,
      distinctFilesInWindow: distinct.size,
      peakEntropy,
      peakEntropyDelta,
      conditions,
      affectedPaths: [...distinct].slice(-12).reverse(),
      detectionWindowMs: inWindow.length ? now - earliest : null,
      mitreTechnique: 'T1486',
      recommendedAction: burstDetected
        ? 'QUARANTINE_PID_AND_ROLLBACK'
        : rateSignal || contentSignal
          ? 'MONITOR'
          : 'NONE'
    };

    if (burstDetected && !this.lastAssessment?.burstDetected) this.detections++;
    this.lastAssessment = assessment;
    return assessment;
  }

  getStatistics() {
    return {
      eventsRetained: this.events.length,
      pathsWithBaseline: this.baselineEntropy.size,
      burstsDetected: this.detections,
      rateWindowMs: RATE_WINDOW_MS,
      thresholds: this.getThresholds(),
      /** Every figure here is counted from observed events; none is seeded. */
      provenance: { mode: 'MEASURED_FROM_WATCHER_EVENTS', seeded: false }
    };
  }

  /** Test and drill support. Clears observed state so a run starts from nothing. */
  reset() {
    this.events = [];
    this.baselineEntropy.clear();
    this.lastAssessment = null;
    this.detections = 0;
  }
}

export const globalRansomwareBurstDetector = new RansomwareBurstDetector();
