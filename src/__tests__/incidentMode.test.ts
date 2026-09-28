import { describe, expect, it } from 'vitest';
import { deriveIncident, type IncidentAlert } from '../components/soc/tactical/useIncidentMode';
import type { ContainmentRecord } from '../components/soc/tactical/useContainment';

const NOW = Date.parse('2026-09-28T12:00:00Z');
const at = (minAgo: number) => new Date(NOW - minAgo * 60_000).toISOString();
const alert = (minAgo: number, severity = 'CRITICAL', srcIp: string | null = '203.0.113.9', mitre: string | null = 'T1486'): IncidentAlert => ({
  at: at(minAgo), severity, srcIp, source: 'FIM', title: 't', mitre
});
const containment = (minAgo: number, active = true, seeded = false, ip = '203.0.113.9'): ContainmentRecord => ({
  id: 'C' + minAgo, ip, reason: null, ioc: null, severity: null, active, at: at(minAgo), releasedAt: null, seeded
});

describe('deriveIncident', () => {
  it('stays off with no critical events and no real containment', () => {
    const s = deriveIncident([alert(1, 'HIGH'), alert(2, 'MEDIUM')], [], NOW);
    expect(s.active).toBe(false);
  });

  it('turns on for a recent critical and dates the incident from it', () => {
    const s = deriveIncident([alert(3)], [], NOW);
    expect(s.active).toBe(true);
    expect(s.since).toBe(at(3));
    expect(s.criticalCount).toBe(1);
    expect(s.topIp).toBe('203.0.113.9');
  });

  it('turns off once the last critical is older than the window', () => {
    expect(deriveIncident([alert(11)], [], NOW).active).toBe(false);
  });

  it('groups criticals closer than the window into one run and starts at the first', () => {
    const s = deriveIncident([alert(25), alert(16), alert(8), alert(1)], [], NOW);
    expect(s.since).toBe(at(25));
    expect(s.criticalCount).toBe(4);
  });

  it('starts a new incident after a gap longer than the window', () => {
    const s = deriveIncident([alert(40), alert(5)], [], NOW);
    expect(s.since).toBe(at(5));
    expect(s.criticalCount).toBe(1);
  });

  it('ignores seeded containments, but a real active one keeps the incident on', () => {
    expect(deriveIncident([], [containment(30, true, true)], NOW).active).toBe(false);
    const real = deriveIncident([], [containment(30)], NOW);
    expect(real.active).toBe(true);
    expect(real.activeContainments).toBe(1);
  });

  it('reports time-to-contain only for a containment that followed detection', () => {
    const before = deriveIncident([alert(5)], [containment(9)], NOW);
    expect(before.containedAt).toBeNull();
    const after = deriveIncident([alert(5)], [containment(2)], NOW);
    expect(after.containedAt).toBe(at(2));
  });

  it('names the address with the most criticals in the run', () => {
    const s = deriveIncident([alert(4, 'CRITICAL', '198.51.100.1'), alert(3, 'CRITICAL', '198.51.100.2'), alert(2, 'CRITICAL', '198.51.100.2')], [], NOW);
    expect(s.topIp).toBe('198.51.100.2');
  });
});
