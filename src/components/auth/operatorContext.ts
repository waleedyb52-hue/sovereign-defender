import React from 'react';
import { z } from 'zod';

/**
 * The signed-in operator, available anywhere under <AuthGate>.
 *
 * `can(role)` mirrors the server's rule — VIEWER reads, ANALYST acts, ADMIN administers —
 * so a control the server would refuse is disabled before it is pressed. The server still
 * decides; this only keeps the console from offering what it will not do.
 */

export type Role = 'VIEWER' | 'ANALYST' | 'ADMIN';
const RANK: Record<Role, number> = { VIEWER: 1, ANALYST: 2, ADMIN: 3 };

export const SessionResponse = z.object({
  authenticated: z.boolean(),
  operator: z
    .object({
      id: z.string(),
      username: z.string(),
      displayName: z.string(),
      role: z.enum(['VIEWER', 'ANALYST', 'ADMIN']),
      sessionId: z.string(),
      expiresAt: z.string()
    })
    .nullable(),
  setupRequired: z.boolean(),
  setupFromHere: z.boolean(),
  transport: z.enum(['TLS', 'CLEARTEXT']),
  storeDurable: z.boolean()
});

export type SessionInfo = z.infer<typeof SessionResponse>;
export type Operator = NonNullable<SessionInfo['operator']>;

export interface OperatorContextValue {
  operator: Operator;
  transport: 'TLS' | 'CLEARTEXT';
  can: (need: Role) => boolean;
  signOut: () => Promise<void>;
  refresh: () => void;
}

export const OperatorContext = React.createContext<OperatorContextValue | null>(null);

export function useOperator(): OperatorContextValue {
  const v = React.useContext(OperatorContext);
  if (!v) throw new Error('useOperator must be used inside <AuthGate>');
  return v;
}

export const roleAtLeast = (have: Role, need: Role) => RANK[have] >= RANK[need];

/** POST helper for the auth routes: JSON body, same-origin cookie, server message surfaced. */
export async function postJson(path: string, body: unknown): Promise<{ ok: boolean; status: number; json: any }> {
  const res = await fetch(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'same-origin',
    body: JSON.stringify(body)
  });
  const json = await res.json().catch(() => null);
  return { ok: res.ok, status: res.status, json };
}
