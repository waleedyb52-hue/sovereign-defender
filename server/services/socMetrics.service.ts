/**
 * SOC PERFORMANCE METRICS
 *
 * Measures MTTD and MTTR from live traffic instead of asserting them.
 *
 * Why this exists: the compliance report quoted "42.0 ms" MTTD and "310.0 ns"
 * MTTR as fixed strings. Nothing measured them, nothing could refute them, and
 * they were the first numbers a reviewer would ask about. Numbers a platform
 * cannot defend are worse than no numbers.
 *
 * What is actually measured here
 *   detect  — request received to verdict returned, in milliseconds.
 *   respond — verdict to containment action applied, in milliseconds.
 *
 * Deliberately NOT measured: the nanosecond-scale in-kernel drop the previous
 * report claimed. Userland cannot observe an XDP drop's latency; claiming a
 * figure for it would be the same fabrication in a new place. The kernel path
 * is reported as a separate, explicitly-modelled figure or not at all.
 *
 * Percentiles rather than a bare mean: one 4-second outlier drags a mean
 * across an SLA boundary while p95 keeps showing what most traffic sees, and
 * a SOC is judged on the tail.
 */

export type MetricPhase = 'detect' | 'respond';

interface Sample {
  ms: number;
  at: number;
}

/**
 * Rolling window. Bounded so a long-running process cannot grow this without
 * limit, and time-bounded so yesterday's performance does not mask today's.
 */
const MAX_SAMPLES = 5000;
const WINDOW_MS = 24 * 60 * 60 * 1000;

export interface PhaseStats {
  count: number;
  p50: number | null;
  p95: number | null;
  p99: number | null;
  mean: number | null;
  max: number | null;
}

export interface MetricsSnapshot {
  detect: PhaseStats;
  respond: PhaseStats;
  windowHours: number;
  /** False until enough samples exist to say anything meaningful. */
  sufficientData: boolean;
}

/** Below this, percentiles are noise and the report should say so. */
const MIN_SAMPLES_FOR_CONFIDENCE = 20;

export class SocMetricsService {
  private samples: Record<MetricPhase, Sample[]> = { detect: [], respond: [] };

  /** Records one observed latency. Called from the request path, so it is cheap. */
  public record(phase: MetricPhase, ms: number): void {
    if (!Number.isFinite(ms) || ms < 0) return;
    const arr = this.samples[phase];
    arr.push({ ms, at: Date.now() });
    if (arr.length > MAX_SAMPLES) arr.splice(0, arr.length - MAX_SAMPLES);
  }

  private fresh(phase: MetricPhase): number[] {
    const cutoff = Date.now() - WINDOW_MS;
    const arr = this.samples[phase].filter(s => s.at >= cutoff);
    this.samples[phase] = arr;
    return arr.map(s => s.ms).sort((a, b) => a - b);
  }

  private stats(values: number[]): PhaseStats {
    if (!values.length) {
      return { count: 0, p50: null, p95: null, p99: null, mean: null, max: null };
    }
    const at = (q: number) => values[Math.min(values.length - 1, Math.floor(values.length * q))];
    const round = (n: number) => Math.round(n * 100) / 100;
    return {
      count: values.length,
      p50: round(at(0.5)),
      p95: round(at(0.95)),
      p99: round(at(0.99)),
      mean: round(values.reduce((a, b) => a + b, 0) / values.length),
      max: round(values[values.length - 1])
    };
  }

  public snapshot(): MetricsSnapshot {
    const detect = this.stats(this.fresh('detect'));
    const respond = this.stats(this.fresh('respond'));
    return {
      detect,
      respond,
      windowHours: WINDOW_MS / 3600000,
      sufficientData: detect.count >= MIN_SAMPLES_FOR_CONFIDENCE
    };
  }

  /**
   * Renders a benchmark row for the compliance report.
   *
   * When there is not enough data it says so rather than emitting a number,
   * which is the whole point of replacing the hardcoded strings.
   */
  public benchmark(phase: MetricPhase, targetMs: number) {
    const s = phase === 'detect' ? this.stats(this.fresh('detect')) : this.stats(this.fresh('respond'));
    if (s.count < MIN_SAMPLES_FOR_CONFIDENCE) {
      return {
        target: `< ${targetMs} ms`,
        measured: `insufficient data (${s.count} samples, need ${MIN_SAMPLES_FOR_CONFIDENCE})`,
        verdict: 'NOT_MEASURED' as const,
        samples: s.count
      };
    }
    return {
      target: `< ${targetMs} ms`,
      measured: `${s.p95} ms (p95, n=${s.count})`,
      verdict: (s.p95 !== null && s.p95 <= targetMs ? 'PASSED' : 'BELOW_TARGET') as 'PASSED' | 'BELOW_TARGET',
      samples: s.count,
      detail: { p50: s.p50, p95: s.p95, p99: s.p99, max: s.max }
    };
  }

  public reset(): void {
    this.samples = { detect: [], respond: [] };
  }
}

export const globalSocMetrics = new SocMetricsService();
