/**
 * PER-CALLER CLASSIFICATION BUDGET
 *
 * After the srcIp fix, the self-DoS limiter guards only the external model's quota. The local
 * classifier is bounded per request (1 MiB, linear-time rules) but not per caller: one
 * authenticated client could send 1 MiB payloads back to back and keep the single event loop
 * busy. This is a token bucket measured in characters classified, keyed on who the server
 * knows the caller to be (principal + TCP peer, never a value from the request body).
 *
 * Cost of a request = max(payload length, MIN_CHARGE). The floor makes request count matter
 * too, so a flood of empty requests is not free. Capacity and refill are one minute's budget.
 * With the default 64 MiB per minute, measured signature cost (about 0.04–0.1 s per MB) caps
 * one caller near 3–6 s of CPU per minute; normal console use and the benchmarks stay far
 * below it (perf_benchmark.mjs at ~600 req/s of ~100-char payloads charges about 9 MiB/min).
 */

export interface BudgetDecision {
  ok: boolean;
  /** Seconds until this request would fit; 0 when ok. */
  retryAfterSec: number;
  /** Characters left in the caller's bucket after this decision. */
  remaining: number;
}

export class ClassificationBudget {
  private buckets = new Map<string, { tokens: number; at: number }>();
  private readonly refillPerMs: number;

  constructor(
    private readonly capacityChars: number,
    private readonly minChargeChars = 256,
    private readonly maxTrackedCallers = 10_000
  ) {
    this.refillPerMs = capacityChars / 60_000;
  }

  charge(callerKey: string, payloadChars: number, now = Date.now()): BudgetDecision {
    const cost = Math.max(this.minChargeChars, payloadChars);
    let b = this.buckets.get(callerKey);
    if (!b) {
      if (this.buckets.size >= this.maxTrackedCallers) this.prune(now);
      b = { tokens: this.capacityChars, at: now };
      this.buckets.set(callerKey, b);
    } else {
      b.tokens = Math.min(this.capacityChars, b.tokens + Math.max(0, now - b.at) * this.refillPerMs);
      b.at = now;
    }
    if (b.tokens >= cost) {
      b.tokens -= cost;
      return { ok: true, retryAfterSec: 0, remaining: Math.floor(b.tokens) };
    }
    const deficit = cost - b.tokens;
    return { ok: false, retryAfterSec: Math.max(1, Math.ceil(deficit / this.refillPerMs / 1000)), remaining: Math.floor(b.tokens) };
  }

  /** Callers whose bucket has refilled are indistinguishable from new ones; drop them. */
  private prune(now: number) {
    for (const [k, b] of this.buckets) {
      if (b.tokens + (now - b.at) * this.refillPerMs >= this.capacityChars) this.buckets.delete(k);
    }
    // Still full of active callers: drop the oldest entries rather than grow without bound.
    if (this.buckets.size >= this.maxTrackedCallers) {
      const excess = this.buckets.size - this.maxTrackedCallers + 1;
      let i = 0;
      for (const k of this.buckets.keys()) { if (i++ >= excess) break; this.buckets.delete(k); }
    }
  }

  get trackedCallers(): number { return this.buckets.size; }
}

/** SD_CLASSIFY_BUDGET_MB_PER_MIN, default 64; 0 disables the budget. */
export function budgetFromEnv(): ClassificationBudget | null {
  const raw = process.env.SD_CLASSIFY_BUDGET_MB_PER_MIN;
  const mb = raw === undefined || raw === '' ? 64 : Number(raw);
  if (!Number.isFinite(mb) || mb <= 0) return null;
  return new ClassificationBudget(Math.round(mb * 1024 * 1024));
}
