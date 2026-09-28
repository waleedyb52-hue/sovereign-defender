import { useCallback, useEffect, useState } from 'react';
import { z } from 'zod';

/**
 * AUDIT TRAIL — reads GET /api/v1/audit and GET /api/v1/audit/verify.
 *
 * Verification is on demand and never automatic on a timer: each verify is itself an
 * audited act, and a poller would fill the log with its own checks.
 */

const Entry = z.object({
  seq: z.number(),
  at: z.string(),
  actor: z.string(),
  role: z.string().nullable(),
  ip: z.string().nullable(),
  action: z.string(),
  target: z.string().nullable(),
  outcome: z.enum(['SUCCESS', 'DENIED', 'FAILURE']),
  detail: z.record(z.string(), z.unknown()).nullable(),
  prevHash: z.string(),
  hash: z.string()
});

const ListResponse = z.object({ durable: z.boolean(), entries: z.array(Entry) });

const Verification = z.object({
  ok: z.boolean(),
  checked: z.number(),
  brokenAt: z.number().nullable(),
  reason: z.string().nullable(),
  headSeq: z.number().nullable(),
  headHash: z.string().nullable(),
  keySource: z.enum(['ENV', 'KEY_FILE', 'EPHEMERAL']),
  durable: z.boolean()
});

export type AuditEntry = z.infer<typeof Entry>;
export type AuditVerification = z.infer<typeof Verification> & { at: string };

export type AuditFilter = 'ALL' | 'CONTAIN' | 'RELEASE' | 'LOGIN' | 'DENIED';

export function useAuditTrail(filter: AuditFilter, pollMs = 15_000) {
  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const [durable, setDurable] = useState<boolean | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [verification, setVerification] = useState<AuditVerification | null>(null);
  const [verifying, setVerifying] = useState(false);

  const load = useCallback(async () => {
    try {
      const q = filter === 'ALL' || filter === 'DENIED' ? '' : `&action=${filter}`;
      const res = await fetch(`/api/v1/audit?limit=200${q}`);
      if (!res.ok) throw new Error(`/api/v1/audit -> ${res.status}`);
      const body = ListResponse.parse(await res.json());
      setEntries(filter === 'DENIED' ? body.entries.filter(e => e.outcome !== 'SUCCESS') : body.entries);
      setDurable(body.durable);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'audit trail unreachable');
    } finally {
      setLoading(false);
    }
  }, [filter]);

  useEffect(() => {
    setLoading(true);
    void load();
    const t = setInterval(() => void load(), pollMs);
    return () => clearInterval(t);
  }, [load, pollMs]);

  const verify = useCallback(async () => {
    setVerifying(true);
    try {
      const res = await fetch('/api/v1/audit/verify');
      if (!res.ok) throw new Error(`/api/v1/audit/verify -> ${res.status}`);
      const body = z.object({ verification: Verification }).parse(await res.json());
      setVerification({ ...body.verification, at: new Date().toISOString() });
      void load();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'verification failed to run');
    } finally {
      setVerifying(false);
    }
  }, [load]);

  return { entries, durable, loading, error, verification, verifying, verify, refresh: () => void load() };
}

export default useAuditTrail;
