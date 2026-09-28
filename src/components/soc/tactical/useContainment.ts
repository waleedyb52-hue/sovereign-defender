import { useCallback, useEffect, useState } from 'react';
import { z } from 'zod';

/**
 * CONTAINMENT — the isolate / release loop behind every ISOLATE_NODE control.
 *
 *   GET  /api/v1/soc/ebpf/containment-records   every record, active and released
 *   POST /api/v1/soc/ebpf/contain-ip            { targetIp, reason }
 *   POST /api/v1/soc/ebpf/release-ip            { targetIp }
 *
 * WHY THIS HOOK EXISTS. The cockpit used to post `{ ip, reason }` to contain-ip. The
 * route reads `targetIp` and answers 400 without it, so every ISOLATE_NODE press from
 * the cockpit was refused. The refusal was at least reported rather than dressed up as
 * success, but a kill switch that has never once isolated anything is the component
 * `.clauderules` §8 names as the worst this product can ship. The request body now
 * matches the route, and it is built in one place so the two cannot drift apart again.
 *
 * RELEASE is here for the same rule: every isolation must be reversible from the surface
 * that made it. There was no release path in the cockpit at all.
 *
 * SEEDED RECORDS. The service ships three demo containments for review, marked
 * `interceptLatencySource: 'SEEDED'`. They are carried through as `seeded` so the list
 * can say so. An operator shown "194.26.29.112 · ACTIVE" with no qualifier would assume
 * their platform blocked it.
 */

const Record_ = z.object({
  id: z.string(),
  targetIp: z.string(),
  reason: z.string().nullish(),
  reasonAr: z.string().nullish(),
  triggeredByIoc: z.string().nullish(),
  severity: z.string().nullish(),
  status: z.string(),
  isolatedAt: z.string().nullish(),
  releasedAt: z.string().nullish(),
  nodeName: z.string().nullish(),
  interceptLatencySource: z.string().nullish()
});

const Records = z.object({ records: z.array(Record_).default([]) });

const ContainResponse = z.object({
  success: z.boolean().optional(),
  record: z.object({ id: z.string(), targetIp: z.string(), status: z.string() }).partial().optional()
});

const ReleaseResponse = z.object({ success: z.boolean().optional() });

export interface ContainmentRecord {
  id: string;
  ip: string;
  reason: string | null;
  ioc: string | null;
  severity: string | null;
  active: boolean;
  at: string | null;
  releasedAt: string | null;
  seeded: boolean;
}

export interface ContainmentOutcome {
  ok: boolean;
  ip: string;
  kind: 'CONTAIN' | 'RELEASE';
  /** The server's own words, or the transport failure verbatim. */
  message: string;
  at: string;
}

const PATH = '/api/v1/soc/ebpf';

export function useContainment(apiKey?: string, pollMs = 6000) {
  const [records, setRecords] = useState<ContainmentRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [busyIp, setBusyIp] = useState<string | null>(null);
  const [last, setLast] = useState<ContainmentOutcome | null>(null);

  const headers = useCallback(
    (json: boolean): HeadersInit => ({
      ...(json ? { 'Content-Type': 'application/json' } : {}),
      ...(apiKey ? { 'x-api-key': apiKey } : {})
    }),
    [apiKey]
  );

  const load = useCallback(async () => {
    try {
      const res = await fetch(`${PATH}/containment-records`, { headers: headers(false) });
      if (!res.ok) throw new Error(`containment-records -> ${res.status}`);
      const body = Records.parse(await res.json());
      setRecords(
        body.records.map(r => ({
          id: r.id,
          ip: r.targetIp,
          reason: r.reason ?? null,
          ioc: r.triggeredByIoc ?? null,
          severity: r.severity ?? null,
          active: r.status === 'ACTIVE_BLACKHOLE',
          at: r.isolatedAt ?? null,
          releasedAt: r.releasedAt ?? null,
          seeded: r.interceptLatencySource === 'SEEDED'
        }))
      );
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'containment-records unreachable');
    } finally {
      setLoading(false);
    }
  }, [headers]);

  useEffect(() => {
    void load();
    const t = setInterval(() => void load(), pollMs);
    return () => clearInterval(t);
  }, [load, pollMs]);

  const post = useCallback(
    async (kind: 'CONTAIN' | 'RELEASE', ip: string, reason?: string): Promise<ContainmentOutcome> => {
      setBusyIp(ip);
      let outcome: ContainmentOutcome;
      try {
        const res = await fetch(`${PATH}/${kind === 'CONTAIN' ? 'contain-ip' : 'release-ip'}`, {
          method: 'POST',
          headers: headers(true),
          body: JSON.stringify(kind === 'CONTAIN' ? { targetIp: ip, reason } : { targetIp: ip })
        });
        const raw = await res.json().catch(() => null);
        if (!res.ok) {
          const detail = raw && typeof raw.error === 'string' ? `: ${raw.error}` : '';
          outcome = { ok: false, ip, kind, message: `refused (${res.status})${detail}`, at: new Date().toISOString() };
        } else if (kind === 'CONTAIN') {
          const body = ContainResponse.safeParse(raw);
          const id = body.success ? body.data.record?.id : undefined;
          outcome = {
            ok: true,
            ip,
            kind,
            message: id ? `record ${id} · ACTIVE_BLACKHOLE` : 'accepted, no record returned',
            at: new Date().toISOString()
          };
        } else {
          // release-ip answers 200 with success:false when nothing was active for that
          // address. That is a no-op, not a release, and must not read as one.
          const body = ReleaseResponse.safeParse(raw);
          const released = body.success && body.data.success === true;
          outcome = {
            ok: released,
            ip,
            kind,
            message: released ? 'rule removed · RELEASED' : 'no active containment for this address',
            at: new Date().toISOString()
          };
        }
      } catch (err) {
        outcome = {
          ok: false,
          ip,
          kind,
          message: `failed: ${err instanceof Error ? err.message : 'network error'}`,
          at: new Date().toISOString()
        };
      }
      setLast(outcome);
      setBusyIp(null);
      await load();
      return outcome;
    },
    [headers, load]
  );

  const active = records.filter(r => r.active);

  return {
    loading,
    error,
    records,
    active,
    /** Addresses under an active containment, for the topology and the feed. */
    activeIps: new Set(active.map(r => r.ip)),
    busyIp,
    last,
    contain: (ip: string, reason: string) => post('CONTAIN', ip, reason),
    release: (ip: string) => post('RELEASE', ip),
    refresh: () => void load()
  };
}

export type Containment = ReturnType<typeof useContainment>;

export default useContainment;
