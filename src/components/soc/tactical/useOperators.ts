import { useCallback, useEffect, useState } from 'react';
import { z } from 'zod';

/** OPERATORS — ADMIN view of accounts and live sessions. */

const Operator = z.object({
  id: z.string(),
  username: z.string(),
  displayName: z.string(),
  role: z.enum(['VIEWER', 'ANALYST', 'ADMIN']),
  disabled: z.boolean(),
  createdAt: z.string(),
  createdBy: z.string().nullable(),
  lastLoginAt: z.string().nullable()
});

const Session = z.object({
  id: z.string(),
  username: z.string(),
  role: z.string(),
  ip: z.string(),
  lastSeenAt: z.number(),
  expiresAt: z.string()
});

export type OperatorRow = z.infer<typeof Operator>;
export type SessionRow = z.infer<typeof Session>;

async function send(method: 'POST' | 'PATCH', path: string, body: unknown): Promise<string | null> {
  const res = await fetch(path, { method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  if (res.ok) return null;
  const j = await res.json().catch(() => null);
  return j?.message ?? `${path} -> ${res.status}`;
}

export function useOperators() {
  const [operators, setOperators] = useState<OperatorRow[]>([]);
  const [sessions, setSessions] = useState<SessionRow[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    try {
      const [o, s] = await Promise.all([fetch('/api/v1/auth/operators'), fetch('/api/v1/auth/sessions')]);
      if (!o.ok) throw new Error(`/api/v1/auth/operators -> ${o.status}`);
      setOperators(z.object({ operators: z.array(Operator) }).parse(await o.json()).operators);
      if (s.ok) setSessions(z.object({ sessions: z.array(Session.passthrough()) }).parse(await s.json()).sessions);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'operators unreachable');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
    const t = setInterval(() => void load(), 20_000);
    return () => clearInterval(t);
  }, [load]);

  const act = async (fn: () => Promise<string | null>) => {
    const problem = await fn();
    await load();
    return problem;
  };

  return {
    operators,
    sessions,
    error,
    loading,
    create: (input: { username: string; displayName: string; role: string; password: string }) =>
      act(() => send('POST', '/api/v1/auth/operators', input)),
    setRole: (id: string, role: string) => act(() => send('PATCH', `/api/v1/auth/operators/${id}`, { role })),
    setDisabled: (id: string, disabled: boolean) => act(() => send('PATCH', `/api/v1/auth/operators/${id}`, { disabled }))
  };
}

export default useOperators;
