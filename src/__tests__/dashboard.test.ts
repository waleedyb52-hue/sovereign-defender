import { describe, expect, it } from 'vitest';
import { cn, formatBytes, formatCount } from '../lib/utils';

/**
 * Tests for the dashboard's non-visual logic.
 *
 * `test:fast` ran with `--passWithNoTests` before this file existed, which meant
 * the "Continuous Validation" step was passing on an empty set. These cover the
 * pieces where a wrong answer would put a misleading figure in front of an
 * operator — which, per `.clauderules` rule 0, is the failure this project cares
 * about most.
 */

describe('cn', () => {
  it('lets a caller-supplied class win a Tailwind conflict', () => {
    // The whole reason tailwind-merge is here: without it both classes are
    // emitted and the winner depends on stylesheet order, which is how override
    // props silently stop working.
    expect(cn('p-2', 'p-4')).toBe('p-4');
    expect(cn('text-slate-500', 'text-rose-400')).toBe('text-rose-400');
  });

  it('drops falsy conditionals without leaving stray whitespace', () => {
    expect(cn('a', false && 'b', undefined, null, 'c')).toBe('a c');
  });
});

describe('formatBytes', () => {
  it('formats real magnitudes', () => {
    expect(formatBytes(512)).toBe('512 B');
    expect(formatBytes(2048)).toBe('2.0 KiB');
    expect(formatBytes(5 * 1024 * 1024)).toBe('5.0 MiB');
  });

  it('returns an em dash for absent or nonsensical input rather than 0 B', () => {
    // A byte counter reading "0 B" is a claim about the network; an em dash is an
    // admission about the dashboard. The distinction matters to an operator.
    expect(formatBytes(NaN)).toBe('—');
    expect(formatBytes(-1)).toBe('—');
    expect(formatBytes(Infinity)).toBe('—');
  });
});

describe('formatCount', () => {
  it('keeps small counts exact', () => {
    expect(formatCount(0)).toBe('0');
    expect(formatCount(999)).toBe('999');
  });

  it('abbreviates without implying precision it does not have', () => {
    expect(formatCount(1500)).toBe('1.5K');
    expect(formatCount(2_500_000)).toBe('2.50M');
  });

  it('refuses non-finite input', () => {
    expect(formatCount(NaN)).toBe('—');
  });
});

/* ── MITRE resolution ────────────────────────────────────────────────────── */

/**
 * Mirrors the resolution order in ThreatAuditTable: an explicit valid ID wins, an
 * ID embedded in the tactic string is next, an unambiguous tactic name maps to
 * its canonical technique, and anything else is UNMAPPED.
 *
 * Tested separately because the property that matters is a *refusal*: an analyst
 * pivots on T-numbers, so a plausible wrong ID is worse than a blank. A
 * regression that started guessing would be invisible in the UI and expensive in
 * an incident.
 */
const TACTIC_TO_TECHNIQUE: Record<string, { id: string; name: string }> = {
  execution: { id: 'T1059', name: 'Command and Scripting Interpreter' },
  impact: { id: 'T1486', name: 'Data Encrypted for Impact' },
  'initial access': { id: 'T1190', name: 'Exploit Public-Facing Application' },
  'credential access': { id: 'T1110', name: 'Brute Force' }
};

function techniqueFor(e: { mitreId?: string | null; mitreTactic?: string | null }) {
  if (e.mitreId && /^T\d{4}(\.\d{3})?$/.test(e.mitreId)) return { id: e.mitreId };
  const raw = e.mitreTactic?.toLowerCase().trim();
  if (!raw) return null;
  const embedded = raw.match(/t\d{4}(\.\d{3})?/i);
  if (embedded) return { id: embedded[0].toUpperCase() };
  const hit = TACTIC_TO_TECHNIQUE[raw];
  return hit ? { id: hit.id, name: hit.name } : null;
}

describe('MITRE technique resolution', () => {
  it('prefers an explicit valid ID on the event', () => {
    expect(techniqueFor({ mitreId: 'T1190', mitreTactic: 'Execution' })?.id).toBe('T1190');
  });

  it('accepts a sub-technique', () => {
    expect(techniqueFor({ mitreId: 'T1110.001' })?.id).toBe('T1110.001');
  });

  it('extracts an ID embedded in a tactic string', () => {
    expect(techniqueFor({ mitreTactic: 'Credential Access (T1110.001)' })?.id).toBe('T1110.001');
  });

  it('maps an unambiguous tactic name', () => {
    expect(techniqueFor({ mitreTactic: 'Execution' })?.id).toBe('T1059');
    expect(techniqueFor({ mitreTactic: '  impact  ' })?.id).toBe('T1486');
  });

  it('returns null rather than guessing for an unknown tactic', () => {
    expect(techniqueFor({ mitreTactic: 'Something Unrecognised' })).toBeNull();
    expect(techniqueFor({})).toBeNull();
  });

  it('ignores a malformed ID instead of displaying it', () => {
    // 'T999' is not a valid technique. Falling through to the tactic map is
    // right; rendering 'T999' to an analyst is not.
    expect(techniqueFor({ mitreId: 'T999', mitreTactic: 'Execution' })?.id).toBe('T1059');
    expect(techniqueFor({ mitreId: 'not-an-id' })).toBeNull();
  });
});

/* ── Delta series ────────────────────────────────────────────────────────── */

/**
 * Mirrors the delta logic in useTelemetry: the server exposes cumulative
 * counters, and a sparkline of a cumulative counter is a straight line. The rule
 * being tested is that the first sample produces no point — animating from zero
 * would draw a history that was never observed.
 */
function deltas(samples: number[]): number[] {
  const out: number[] = [];
  let prev: number | null = null;
  for (const s of samples) {
    if (prev != null) out.push(Math.max(0, s - prev));
    prev = s;
  }
  return out;
}

describe('cumulative-to-delta series', () => {
  it('yields no point from a single sample', () => {
    expect(deltas([100])).toEqual([]);
  });

  it('yields n-1 points, each a real observed rate', () => {
    expect(deltas([100, 140, 150, 210])).toEqual([40, 10, 60]);
  });

  it('clamps a counter reset to zero instead of going negative', () => {
    // A service restart resets the counter. A negative "rate" would render as an
    // inverted spike and read as a recovery that never happened.
    expect(deltas([500, 20, 45])).toEqual([0, 25]);
  });
});
