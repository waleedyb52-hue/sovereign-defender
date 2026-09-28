import { useCallback, useEffect, useState } from 'react';
import { z } from 'zod';

/** RANSOMWARE TRIPWIRE — GET /api/v1/tripwire, POST /api/v1/tripwire/protect|unprotect. */

const Incident = z.object({
  id: z.string(),
  at: z.string(),
  kind: z.enum(['TRIPWIRE_MODIFIED', 'TRIPWIRE_ENCRYPTED', 'TRIPWIRE_REMOVED', 'ENCRYPTION_BURST']),
  dir: z.string(),
  file: z.string().nullable(),
  entropy: z.number().nullable(),
  count: z.number().nullable(),
  evidencePath: z.string().nullable(),
  mitre: z.string(),
  detail: z.string()
});

const Status = z.object({
  entropyThreshold: z.number(),
  burstRule: z.object({ files: z.number(), windowSec: z.number() }),
  dirs: z.array(
    z.object({
      dir: z.string(),
      addedAt: z.string(),
      addedBy: z.string(),
      source: z.enum(['OPERATOR', 'ENV']),
      watching: z.boolean(),
      decoys: z.array(z.object({ path: z.string(), intact: z.boolean() }))
    })
  ),
  totals: z.object({ events: z.number(), tripwires: z.number(), bursts: z.number() }),
  incidents: z.array(Incident)
});

export type TripwireStatus = z.infer<typeof Status>;
export type TripwireIncident = z.infer<typeof Incident>;

async function post(path: string, body: unknown): Promise<string | null> {
  const res = await fetch(path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  if (res.ok) return null;
  const j = await res.json().catch(() => null);
  return j?.message ?? `${path} -> ${res.status}`;
}

export function useTripwire(pollMs = 5_000) {
  const [status, setStatus] = useState<TripwireStatus | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const res = await fetch('/api/v1/tripwire');
      if (!res.ok) throw new Error(`/api/v1/tripwire -> ${res.status}`);
      setStatus(Status.parse(await res.json()));
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'tripwire unreachable');
    }
  }, []);

  useEffect(() => {
    void load();
    const t = setInterval(() => void load(), pollMs);
    return () => clearInterval(t);
  }, [load, pollMs]);

  const act = async (fn: () => Promise<string | null>) => {
    const problem = await fn();
    await load();
    return problem;
  };

  return {
    status,
    error,
    protect: (dir: string) => act(() => post('/api/v1/tripwire/protect', { dir })),
    unprotect: (dir: string) => act(() => post('/api/v1/tripwire/unprotect', { dir }))
  };
}

export type Tripwire = ReturnType<typeof useTripwire>;

export default useTripwire;
