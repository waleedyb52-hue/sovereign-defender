import type { AssetRow } from './useAssets';
import type { PhaseId } from './useWargames';

/**
 * DIGITAL TWIN — a drill projected onto the network you actually have.
 *
 * Each wargame phase exercises a kind of access. This maps it to the services that kind of
 * access goes through, then asks the real inventory which devices expose them:
 *
 *   EXPOSED  a sweep found one of those ports open on the device
 *   CLEAR    a sweep probed the device and found none of them open
 *   UNKNOWN  no sweep has reached the device — nothing is assumed either way
 *
 * UNKNOWN is the honest answer for a device only seen in the ARP cache, and it is shown
 * as such: calling it clear would under-report exposure, calling it exposed would invent
 * it. The projection is labelled a simulation wherever it appears. It reads real ports;
 * it does not claim the attack would succeed.
 */

export type TwinState = 'EXPOSED' | 'CLEAR' | 'UNKNOWN';

export interface TwinScenario {
  id: PhaseId;
  mitre: string;
  en: string;
  ar: string;
  /** Services the scenario's access goes through. Empty = the enrolled hosts themselves. */
  ports: number[];
  targetsHosts?: boolean;
}

export const TWIN_SCENARIOS: TwinScenario[] = [
  { id: 'phase1-ddos', mitre: 'T1498', en: 'Volumetric flood — public-facing services', ar: 'طوفان حجمي — الخدمات المكشوفة للويب', ports: [80, 443, 8080, 8443] },
  { id: 'phase2-apt', mitre: 'T1021', en: 'Lateral movement — remote-access services', ar: 'حركة جانبية — خدمات الوصول عن بُعد', ports: [22, 23, 3389, 445, 5985, 5986, 5900] },
  { id: 'phase3-ebpf', mitre: 'T1562', en: 'Impair defences — the monitoring hosts', ar: 'تعطيل الدفاعات — مضيفو المراقبة', ports: [], targetsHosts: true },
  { id: 'phase4-insider', mitre: 'T1213', en: 'Insider data access — databases and shares', ar: 'وصول داخلي للبيانات — قواعد البيانات والمشاركات', ports: [1433, 3306, 5432, 6379, 27017, 445, 139] }
];

export interface TwinRow {
  ip: string;
  vendor: string | null;
  state: TwinState;
  ports: number[];
  host: boolean;
}

export interface TwinProjection {
  scenario: TwinScenario;
  rows: TwinRow[];
  exposed: number;
  clear: number;
  unknown: number;
}

export function projectExposure(assets: AssetRow[], scenarioId: PhaseId): TwinProjection {
  const scenario = TWIN_SCENARIOS.find(s => s.id === scenarioId) ?? TWIN_SCENARIOS[0];
  const rows: TwinRow[] = [];
  const seen = new Set<string>();

  for (const a of assets) {
    if (a.kind !== 'HOST') continue;
    if (scenario.targetsHosts && a.primaryIp && !seen.has(a.primaryIp)) {
      seen.add(a.primaryIp);
      // The sensor host is, by definition, a monitoring host: it is the target itself.
      rows.push({ ip: a.primaryIp, vendor: a.platform, state: 'EXPOSED', ports: [], host: true });
    }
    if (scenario.targetsHosts) continue;

    for (const n of a.posture?.neighbours ?? []) {
      if (seen.has(n.ip)) continue;
      seen.add(n.ip);
      const swept = n.sweepState === 'RESPONDED' || n.sweepState === 'NO_RESPONSE' || (n.openPorts?.length ?? 0) > 0;
      const hits = (n.openPorts ?? []).filter(p => scenario.ports.includes(p));
      rows.push({
        ip: n.ip,
        vendor: n.vendor,
        state: hits.length ? 'EXPOSED' : swept ? 'CLEAR' : 'UNKNOWN',
        ports: hits,
        host: false
      });
    }
  }

  const order: Record<TwinState, number> = { EXPOSED: 0, UNKNOWN: 1, CLEAR: 2 };
  rows.sort((x, y) => order[x.state] - order[y.state] || x.ip.localeCompare(y.ip));
  return {
    scenario,
    rows,
    exposed: rows.filter(r => r.state === 'EXPOSED').length,
    clear: rows.filter(r => r.state === 'CLEAR').length,
    unknown: rows.filter(r => r.state === 'UNKNOWN').length
  };
}

/** The drill that is running maps to its scenario; otherwise the first one is previewed. */
export const scenarioForPhase = (activePhase: number): PhaseId =>
  (['phase1-ddos', 'phase2-apt', 'phase3-ebpf', 'phase4-insider'] as PhaseId[])[Math.max(0, Math.min(3, activePhase - 1))] ?? 'phase1-ddos';
