import { useEffect, useState } from 'react';
import { z } from 'zod';

/**
 * History for one address, fetched when its dossier opens:
 *   GET /api/v1/memory/context?ip=   prior incidents from the threat-memory corpus + IOC hit
 *   GET /api/v1/audit?target=        what operators have done to it (ANALYST and above)
 */

const Incident = z
  .object({
    id: z.string(),
    timestamp: z.string(),
    source: z.string(),
    severity: z.string(),
    title: z.string(),
    mitreTechnique: z.string().nullish(),
    actionTaken: z.string().nullish()
  })
  .passthrough();

const Memory = z.object({
  retrieved: z.object({
    sameActor: z.array(Incident).default([]),
    iocHit: z
      .object({
        indicator: z.string(),
        type: z.string(),
        category: z.string(),
        confidence: z.number(),
        sightings: z.number(),
        firstSeen: z.string(),
        lastSeen: z.string(),
        source: z.string()
      })
      .nullable(),
    totalCorpus: z.number()
  })
});

const Audit = z.object({
  entries: z.array(
    z.object({ seq: z.number(), at: z.string(), actor: z.string(), action: z.string(), outcome: z.string() }).passthrough()
  )
});

export type MemoryIncident = z.infer<typeof Incident>;

export function useIpHistory(ip: string | null, withAudit: boolean) {
  const [memory, setMemory] = useState<z.infer<typeof Memory>['retrieved'] | null>(null);
  const [audit, setAudit] = useState<z.infer<typeof Audit>['entries'] | null>(null);
  const [errors, setErrors] = useState<string[]>([]);

  useEffect(() => {
    if (!ip) return;
    let live = true;
    setMemory(null);
    setAudit(null);
    setErrors([]);
    const fail = (e: string) => live && setErrors(x => [...x, e]);

    fetch(`/api/v1/memory/context?ip=${encodeURIComponent(ip)}`)
      .then(r => (r.ok ? r.json() : Promise.reject(new Error(`/memory/context -> ${r.status}`))))
      .then(j => live && setMemory(Memory.parse(j).retrieved))
      .catch(e => fail(e instanceof Error ? e.message : '/memory/context failed'));

    if (withAudit) {
      fetch(`/api/v1/audit?limit=50&target=${encodeURIComponent(ip)}`)
        .then(r => (r.ok ? r.json() : Promise.reject(new Error(`/audit -> ${r.status}`))))
        .then(j => live && setAudit(Audit.parse(j).entries))
        .catch(e => fail(e instanceof Error ? e.message : '/audit failed'));
    }
    return () => {
      live = false;
    };
  }, [ip, withAudit]);

  return { memory, audit, errors };
}

export default useIpHistory;
