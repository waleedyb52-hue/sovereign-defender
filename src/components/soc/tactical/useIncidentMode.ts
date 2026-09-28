import { useCallback, useEffect, useMemo, useState } from 'react';
import type { ContainmentRecord } from './useContainment';

/**
 * INCIDENT MODE — derived from real events only.
 *
 * On when either holds:
 *   - a CRITICAL event arrived within the last WINDOW minutes (unified feed: WAF, FIM,
 *     tripwires, ARP spoofing, anything the platform raises), or
 *   - a real (non-seeded) containment is active.
 * Off again, by itself, when neither holds. Nothing here is a timer or a script.
 *
 * The incident starts at the first critical of the current run — criticals closer together
 * than WINDOW belong to one incident — and that timestamp is its identity, so the shared
 * acknowledgement survives a page reload. "T+" is time since detection, measured from the
 * event's own timestamp; time-to-contain is shown only when a containment actually
 * followed it.
 */

const WINDOW_MS = 10 * 60_000;

export interface IncidentAlert {
  at: string;
  severity: string;
  srcIp: string | null;
  source: string | null;
  title: string;
  mitre: string | null;
}

export interface IncidentState {
  active: boolean;
  since: string | null;
  criticalCount: number;
  sources: string[];
  topIp: string | null;
  techniques: string[];
  containedAt: string | null;
  activeContainments: number;
}

export function deriveIncident(alerts: IncidentAlert[], containments: ContainmentRecord[], now: number): IncidentState {
  const crit = alerts
    .filter(a => a.severity === 'CRITICAL' && Number.isFinite(Date.parse(a.at)))
    .sort((a, b) => Date.parse(a.at) - Date.parse(b.at));
  const realActive = containments.filter(c => c.active && !c.seeded);

  // Walk back from the newest critical while the gaps stay under WINDOW: that is the run.
  let run: IncidentAlert[] = [];
  if (crit.length && now - Date.parse(crit[crit.length - 1].at) < WINDOW_MS) {
    run = [crit[crit.length - 1]];
    for (let i = crit.length - 2; i >= 0; i--) {
      if (Date.parse(run[0].at) - Date.parse(crit[i].at) < WINDOW_MS) run.unshift(crit[i]);
      else break;
    }
  }

  const active = run.length > 0 || realActive.length > 0;
  if (!active) {
    return { active: false, since: null, criticalCount: 0, sources: [], topIp: null, techniques: [], containedAt: null, activeContainments: 0 };
  }

  const since =
    run[0]?.at ??
    realActive.map(c => c.at).filter((x): x is string => Boolean(x)).sort()[0] ??
    null;

  const ipCounts = new Map<string, number>();
  for (const a of run) if (a.srcIp) ipCounts.set(a.srcIp, (ipCounts.get(a.srcIp) ?? 0) + 1);
  const topIp = [...ipCounts.entries()].sort((a, b) => b[1] - a[1])[0]?.[0] ?? realActive[0]?.ip ?? null;

  const containedAt =
    since != null
      ? containments
          .filter(c => !c.seeded && c.at && Date.parse(c.at) >= Date.parse(since))
          .map(c => c.at as string)
          .sort()[0] ?? null
      : null;

  return {
    active,
    since,
    criticalCount: run.length,
    sources: [...new Set(run.map(a => a.source).filter((s): s is string => Boolean(s)))],
    topIp,
    techniques: [...new Set(run.map(a => a.mitre).filter((s): s is string => Boolean(s)))].slice(0, 4),
    containedAt,
    activeContainments: realActive.length
  };
}

/** The derived state, plus the shared acknowledgement for the current incident. */
export function useIncidentMode(alerts: IncidentAlert[], containments: ContainmentRecord[]) {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, []);

  const state = useMemo(() => deriveIncident(alerts, containments, now), [alerts, containments, now]);
  const [ack, setAck] = useState<{ by: string; at: string } | null>(null);

  const since = state.since;
  useEffect(() => {
    setAck(null);
    if (!since) return;
    let live = true;
    const load = () =>
      fetch(`/api/v1/incidents/ack?since=${encodeURIComponent(since)}`)
        .then(r => (r.ok ? r.json() : null))
        .then(j => live && j?.ack && setAck(j.ack))
        .catch(() => undefined);
    void load();
    const t = setInterval(load, 10_000);
    return () => {
      live = false;
      clearInterval(t);
    };
  }, [since]);

  const acknowledge = useCallback(async () => {
    if (!state.since) return;
    const res = await fetch('/api/v1/incidents/ack', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ since: state.since, count: state.criticalCount, topIp: state.topIp })
    });
    const j = await res.json().catch(() => null);
    if (j?.ack) setAck(j.ack);
  }, [state.since, state.criticalCount, state.topIp]);

  return { ...state, now, ack, acknowledge };
}

export type IncidentMode = ReturnType<typeof useIncidentMode>;

export default useIncidentMode;
