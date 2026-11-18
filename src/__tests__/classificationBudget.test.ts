import { describe, expect, it } from 'vitest';
import { ClassificationBudget } from '../../server/classificationBudget.js';

const MiB = 1024 * 1024;

describe('per-caller classification budget', () => {
  it('admits requests until the minute budget is spent, then refuses with a retry time', () => {
    const b = new ClassificationBudget(2 * MiB);
    const t = 1_000_000;
    expect(b.charge('a', MiB, t).ok).toBe(true);
    expect(b.charge('a', MiB, t).ok).toBe(true);
    const refused = b.charge('a', MiB, t);
    expect(refused.ok).toBe(false);
    // 1 MiB short at 2 MiB/min refill = 30 s.
    expect(refused.retryAfterSec).toBe(30);
  });

  it('refills over time', () => {
    const b = new ClassificationBudget(2 * MiB);
    const t = 1_000_000;
    b.charge('a', 2 * MiB, t);
    expect(b.charge('a', MiB, t + 10_000).ok).toBe(false);
    expect(b.charge('a', MiB, t + 30_000).ok).toBe(true);
  });

  it('callers have separate buckets', () => {
    const b = new ClassificationBudget(MiB);
    const t = 1_000_000;
    expect(b.charge('analyst-1@10.0.0.2', MiB, t).ok).toBe(true);
    expect(b.charge('analyst-1@10.0.0.2', 1, t).ok).toBe(false);
    expect(b.charge('analyst-2@10.0.0.3', MiB, t).ok).toBe(true);
  });

  it('charges a floor per request, so a flood of empty requests is not free', () => {
    const b = new ClassificationBudget(256 * 10, 256);
    const t = 1_000_000;
    for (let i = 0; i < 10; i++) expect(b.charge('a', 0, t).ok).toBe(true);
    expect(b.charge('a', 0, t).ok).toBe(false);
  });

  it('never tracks more than the configured number of callers', () => {
    const b = new ClassificationBudget(MiB, 256, 100);
    for (let i = 0; i < 1000; i++) b.charge(`caller-${i}`, 10, 1_000_000 + i);
    expect(b.trackedCallers).toBeLessThanOrEqual(100);
  });
});
