import { useCallback, useEffect, useState } from 'react';
import { z } from 'zod';

/**
 * WARGAMING SANDBOX
 *
 * The backend already exposes a phased wargames API. This hook is its reader and its
 * only trigger point in the cockpit:
 *
 *   GET  /wargames/status          active phase, live vector count, APT state
 *   POST /wargames/phase1-ddos     volumetric flood drill
 *   POST /wargames/phase2-apt      APT foothold and lateral movement
 *   POST /wargames/phase3-ebpf     kernel-layer containment drill
 *   POST /wargames/phase4-insider  insider privilege-abuse drill
 *   POST /wargames/reset           tear the sandbox down
 *
 * The separation this enforces is the point of the whole mode, and it is a safety
 * property rather than a styling one:
 *
 *   An operator who cannot tell a drill from a real intrusion will either ignore a
 *   real one or escalate an exercise to a national response. Both have happened in
 *   real SOCs. So drills can only be launched from the wargaming environment, the
 *   surface switches to amber while any phase is active, and the cockpit refuses to
 *   leave that mode silently — leaving with a phase running is blocked until the
 *   sandbox is reset, because a drill left running under a cyan "LIVE SOC" header is
 *   exactly the confusion the mode exists to prevent.
 *
 * `activePhase > 0` is the server's own statement that a drill is live, so the banner
 * follows the server rather than local UI state. If the operator reloads the page
 * mid-drill, the warning is still there.
 */

const WargamesStatus = z.object({
  activePhase: z.number().nullish(),
  activeVectorsCount: z.number().nullish(),
  modBotsCount: z.number().nullish(),
  hasApt: z.boolean().nullish(),
  aptDropped: z.boolean().nullish(),
  ebpfRealBlacklistCount: z.number().nullish()
});

export type PhaseId = 'phase1-ddos' | 'phase2-apt' | 'phase3-ebpf' | 'phase4-insider';

export interface PhaseSpec {
  id: PhaseId;
  labelAr: string;
  labelEn: string;
  mitreAr: string;
  mitreEn: string;
}

/** Ordered as the drill escalates, with the ATT&CK stage each exercises. */
export const PHASES: PhaseSpec[] = [
  { id: 'phase1-ddos', labelAr: 'المرحلة ١ — طوفان حجمي', labelEn: 'PHASE 1 — VOLUMETRIC FLOOD', mitreAr: 'T1498 حجب الخدمة الشبكي', mitreEn: 'T1498 Network DoS' },
  { id: 'phase2-apt', labelAr: 'المرحلة ٢ — تهديد متقدّم مستمر', labelEn: 'PHASE 2 — APT FOOTHOLD', mitreAr: 'T1078 حسابات صحيحة', mitreEn: 'T1078 Valid Accounts' },
  { id: 'phase3-ebpf', labelAr: 'المرحلة ٣ — احتواء عند النواة', labelEn: 'PHASE 3 — KERNEL CONTAINMENT', mitreAr: 'T1562 إضعاف الدفاعات', mitreEn: 'T1562 Impair Defenses' },
  { id: 'phase4-insider', labelAr: 'المرحلة ٤ — إساءة صلاحيات داخلية', labelEn: 'PHASE 4 — INSIDER ABUSE', mitreAr: 'T1548 تجاوز التحكّم بالصلاحيات', mitreEn: 'T1548 Privilege Abuse' }
];

export function useWargames(apiKey?: string, pollMs = 4000) {
  const [status, setStatus] = useState<z.infer<typeof WargamesStatus> | null>(null);
  const [unreachable, setUnreachable] = useState(false);
  const [busy, setBusy] = useState<PhaseId | 'reset' | null>(null);
  const [lastResult, setLastResult] = useState<string | null>(null);

  const headers = useCallback(
    (): HeadersInit => ({ 'Content-Type': 'application/json', ...(apiKey ? { 'x-api-key': apiKey } : {}) }),
    [apiKey]
  );

  const load = useCallback(async () => {
    try {
      const res = await fetch('/api/v1/wargames/status', { headers: apiKey ? { 'x-api-key': apiKey } : undefined });
      if (!res.ok) throw new Error(String(res.status));
      setStatus(WargamesStatus.parse(await res.json()));
      setUnreachable(false);
    } catch {
      setUnreachable(true);
    }
  }, [apiKey]);

  useEffect(() => {
    load();
    const t = setInterval(load, pollMs);
    return () => clearInterval(t);
  }, [load, pollMs]);

  const launch = useCallback(
    async (phase: PhaseId) => {
      setBusy(phase);
      setLastResult(null);
      try {
        const res = await fetch(`/api/v1/wargames/${phase}`, { method: 'POST', headers: headers(), body: '{}' });
        const body = await res.json().catch(() => null);
        // The server's own words. A drill that failed to start must not be reported as
        // started — an operator would then read a quiet board as a defence that held.
        setLastResult(res.ok ? (body?.message ?? `${phase} launched`) : `${phase} rejected (${res.status})`);
      } catch (err) {
        setLastResult(`${phase} failed: ${err instanceof Error ? err.message : 'network error'}`);
      } finally {
        setBusy(null);
        void load();
      }
    },
    [headers, load]
  );

  const reset = useCallback(async () => {
    setBusy('reset');
    setLastResult(null);
    try {
      const res = await fetch('/api/v1/wargames/reset', { method: 'POST', headers: headers(), body: '{}' });
      setLastResult(res.ok ? 'sandbox reset' : `reset rejected (${res.status})`);
    } catch (err) {
      setLastResult(`reset failed: ${err instanceof Error ? err.message : 'network error'}`);
    } finally {
      setBusy(null);
      void load();
    }
  }, [headers, load]);

  const activePhase = status?.activePhase ?? 0;

  return {
    unreachable,
    activePhase,
    /** The server's statement that something is running, not a local flag. */
    drillActive: activePhase > 0 || Boolean(status?.hasApt),
    activeVectors: status?.activeVectorsCount ?? null,
    modBots: status?.modBotsCount ?? null,
    hasApt: status?.hasApt ?? null,
    aptDropped: status?.aptDropped ?? null,
    blacklistCount: status?.ebpfRealBlacklistCount ?? null,
    busy,
    lastResult,
    launch,
    reset,
    refresh: () => void load()
  };
}

export default useWargames;
