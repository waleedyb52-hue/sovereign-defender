import { describe, expect, it } from 'vitest';
import { AdjudicationService } from '../../server/services/adjudication.service.js';

/**
 * The pending queue is written behind (batched) to take a synchronous SQLite transaction off
 * the request path. These tests pin the guarantees that must not move with it: nothing a
 * caller reads can miss a buffered row, repeat sightings still count, a ruling is still
 * written immediately, and evaluation traffic still never enters the queue.
 */
const base = {
  machineVerdict: 'BLOCK' as const,
  machineScore: 80,
  machineFamily: 'SQL_INJECTION',
  machineSignatures: ['boolean test between two constants'],
  srcIp: '198.51.100.7'
};

describe('adjudication pending queue — write-behind', () => {
  it('a buffered detection is visible to the queue immediately', () => {
    const store = new AdjudicationService(':memory:');
    const id = store.recordPending({ ...base, payload: "x') or 4=4" });
    expect(id).toBeTruthy();
    const q = store.queue(10);
    expect(q.map(r => r.id)).toContain(id);
  });

  it('repeat sightings of one payload keep one row and add up', () => {
    const store = new AdjudicationService(':memory:');
    const a = store.recordPending({ ...base, payload: 'repeat me' });
    const b = store.recordPending({ ...base, payload: 'repeat me', srcIp: '198.51.100.8' });
    expect(b).toBe(a);
    store.flushPending();
    const c = store.recordPending({ ...base, payload: 'repeat me' });
    expect(c).toBe(a);
    const row = store.queue(10).find(r => r.id === a)!;
    expect(row.seenCount).toBe(3);
  });

  it('a ruling on a buffered detection is written synchronously and leaves the queue', () => {
    const store = new AdjudicationService(':memory:');
    const id = store.recordPending({ ...base, payload: 'rule on me' })!;
    const res = store.adjudicate({ detectionId: id, analystLabel: 'MALICIOUS', adjudicatedBy: 'analyst-1' });
    expect(res.ok).toBe(true);
    expect(store.queue(10).map(r => r.id)).not.toContain(id);
    // Once ruled on, the same payload is not queued again.
    expect(store.recordPending({ ...base, payload: 'rule on me' })).toBeNull();
  });

  it('only the server-verified evaluation flag keeps traffic out of the queue', () => {
    const store = new AdjudicationService(':memory:');
    // A claimed source address is the caller's statement and must not exclude anything.
    for (const ip of ['10.20.0.1', '10.30.1.2', '10.40.3.4', '10.80.0.9', '10.90.5.5']) {
      expect(store.recordPending({ ...base, payload: `claimed ${ip}`, srcIp: ip })).not.toBeNull();
    }
    // The flag the route sets after verifying ADMIN + direct loopback + declared evaluation.
    expect(store.recordPending({ ...base, payload: 'verified evaluation', isEvaluationSource: true })).toBeNull();
    const queued = store.queue(50).map(r => r.payloadSample);
    expect(queued).toHaveLength(5);
    expect(queued).not.toContain('verified evaluation');
  });

  it('stats count buffered rows', () => {
    const store = new AdjudicationService(':memory:');
    store.recordPending({ ...base, payload: 'one' });
    store.recordPending({ ...base, payload: 'two' });
    expect(store.stats().pendingCount).toBe(2);
  });
});
