export class TokenBucketBackpressure {
  public bucketCapacity: number = 600;
  public currentTokens: number = 600;
  public refillRatePerSec: number = 150;
  private lastRefillTimestamp: number = Date.now();

  public isLoadSheddingActive: boolean = false;
  public pressureMode: 'NORMAL' | 'ELEVATED_THROTTLE' | 'CRITICAL_LOAD_SHEDDING' = 'NORMAL';

  public totalRequestsReceived: number = 18450;
  public shedTelemetryPacketsCount: number = 320;
  public prioritizedSecurityVerdictsCount: number = 18130;
  public currentSystemPps: number = 85;

  constructor(capacity: number = 600, refillRate: number = 150) {
    this.bucketCapacity = capacity;
    this.currentTokens = capacity;
    this.refillRatePerSec = refillRate;
  }

  private refill(): void {
    const now = Date.now();
    const elapsedSec = (now - this.lastRefillTimestamp) / 1000;
    if (elapsedSec > 0) {
      const addedTokens = elapsedSec * this.refillRatePerSec;
      this.currentTokens = Math.min(this.bucketCapacity, this.currentTokens + addedTokens);
      this.lastRefillTimestamp = now;
    }

    // Determine pressure mode based on water-level
    const fillRatio = this.currentTokens / this.bucketCapacity;
    if (fillRatio > 0.35) {
      this.pressureMode = 'NORMAL';
      this.isLoadSheddingActive = false;
    } else if (fillRatio > 0.12) {
      this.pressureMode = 'ELEVATED_THROTTLE';
      this.isLoadSheddingActive = true;
    } else {
      this.pressureMode = 'CRITICAL_LOAD_SHEDDING';
      this.isLoadSheddingActive = true;
    }
  }

  /**
   * Evaluates request against Token Bucket.
   * Priority requests (active protection verdicts, kernel drop signals) are ALWAYS processed.
   * Non-critical telemetry logging is shed during high saturation.
   */
  public evaluateRequest(isPriorityVerdict: boolean = true, cost: number = 1): {
    allowed: boolean;
    shed: boolean;
    remainingTokens: number;
    mode: 'NORMAL' | 'ELEVATED_THROTTLE' | 'CRITICAL_LOAD_SHEDDING';
  } {
    this.refill();
    this.totalRequestsReceived++;

    // Priority Security Verdicts bypass load shedding
    if (isPriorityVerdict) {
      this.currentTokens = Math.max(0, this.currentTokens - cost);
      this.prioritizedSecurityVerdictsCount++;
      return {
        allowed: true,
        shed: false,
        remainingTokens: Math.floor(this.currentTokens),
        mode: this.pressureMode
      };
    }

    // Non-priority passive telemetry inspection under load
    if (this.pressureMode === 'CRITICAL_LOAD_SHEDDING') {
      this.shedTelemetryPacketsCount++;
      return {
        allowed: false,
        shed: true,
        remainingTokens: Math.floor(this.currentTokens),
        mode: this.pressureMode
      };
    }

    if (this.pressureMode === 'ELEVATED_THROTTLE' && Math.random() < 0.5) {
      this.shedTelemetryPacketsCount++;
      return {
        allowed: false,
        shed: true,
        remainingTokens: Math.floor(this.currentTokens),
        mode: this.pressureMode
      };
    }

    this.currentTokens = Math.max(0, this.currentTokens - cost);
    return {
      allowed: true,
      shed: false,
      remainingTokens: Math.floor(this.currentTokens),
      mode: this.pressureMode
    };
  }

  public simulateDdosSpike(spikePps: number = 1800): void {
    this.currentSystemPps = spikePps;
    this.currentTokens = Math.max(5, this.currentTokens - 550);
    this.refill();
  }

  public tune(capacity?: number, refillRate?: number): void {
    if (capacity && capacity > 50) this.bucketCapacity = capacity;
    if (refillRate && refillRate > 10) this.refillRatePerSec = refillRate;
    this.refill();
  }

  public getStats() {
    this.refill();
    const fillPercentage = Math.round((this.currentTokens / this.bucketCapacity) * 100);

    return {
      bucketCapacity: this.bucketCapacity,
      currentTokens: Math.floor(this.currentTokens),
      fillPercentage,
      refillRatePerSec: this.refillRatePerSec,
      isLoadSheddingActive: this.isLoadSheddingActive,
      pressureMode: this.pressureMode,
      totalRequestsReceived: this.totalRequestsReceived,
      shedTelemetryPacketsCount: this.shedTelemetryPacketsCount,
      prioritizedSecurityVerdictsCount: this.prioritizedSecurityVerdictsCount,
      currentSystemPps: this.currentSystemPps
    };
  }
}

export const globalTokenBucket = new TokenBucketBackpressure();
