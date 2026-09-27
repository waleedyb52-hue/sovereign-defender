import { useCallback, useEffect, useState } from 'react';
import { z } from 'zod';

/**
 * ASSET FLEET
 *
 * Reads the asset registry: real machines that enrolled by running the host sensor, and
 * network ranges an operator declared.
 *
 * `durable` is carried through to the UI on purpose. The registry degrades to an
 * in-memory store if the data directory is unwritable, and a fleet that will vanish on
 * the next restart must say so — an inventory an operator trusts and then loses is worse
 * than one they knew was temporary.
 *
 * Liveness is computed server-side from heartbeat age, never self-reported, because a
 * sensor that dies cannot send `status: offline`. The UI renders that verdict as-is
 * rather than re-deriving it, so the fleet count and the asset badge can never disagree.
 */

const Posture = z.object({
  listeningPorts: z.number().nullable(),
  establishedConnections: z.number().nullable(),
  processes: z.number().nullable(),
  loggedInUsers: z.number().nullable(),
  uptimeSec: z.number().nullable(),
  extra: z.record(z.string(), z.number()).nullable()
});

const Asset = z.object({
  id: z.string(),
  kind: z.enum(['HOST', 'NETWORK_RANGE']),
  label: z.string(),
  hostname: z.string().nullable(),
  platform: z.string().nullable(),
  arch: z.string().nullable(),
  primaryIp: z.string().nullable(),
  interfaces: z.array(z.string()),
  cidr: z.string().nullable(),
  enrolledAt: z.string(),
  lastSeenAt: z.string().nullable(),
  heartbeatIntervalSec: z.number(),
  sensorVersion: z.string().nullable(),
  isolated: z.boolean(),
  isolatedAt: z.string().nullable(),
  flowsIngested: z.number(),
  posture: Posture.nullable(),
  liveness: z.enum(['ONLINE', 'STALE', 'OFFLINE', 'NEVER_REPORTED'])
});

const Summary = z.object({
  durable: z.boolean(),
  total: z.number(),
  hosts: z.number(),
  networks: z.number(),
  online: z.number(),
  stale: z.number(),
  offline: z.number(),
  neverReported: z.number(),
  isolated: z.number(),
  flowsIngested: z.number()
});

const FleetResponse = z.object({ summary: Summary, assets: z.array(Asset) });

export type AssetRow = z.infer<typeof Asset>;
export type FleetSummary = z.infer<typeof Summary>;

export function useAssets(apiKey?: string, pollMs = 5000) {
  const [assets, setAssets] = useState<AssetRow[]>([]);
  const [summary, setSummary] = useState<FleetSummary | null>(null);
  const [unreachable, setUnreachable] = useState(false);
  const [busy, setBusy] = useState(false);
  const [lastResult, setLastResult] = useState<string | null>(null);
  const [enrollment, setEnrollment] = useState<{ token: string; expiresAt: string; command: string } | null>(null);

  const headers = useCallback(
    (): HeadersInit => ({ 'Content-Type': 'application/json', ...(apiKey ? { 'x-api-key': apiKey } : {}) }),
    [apiKey]
  );

  const load = useCallback(async () => {
    try {
      const res = await fetch('/api/v1/assets', { headers: apiKey ? { 'x-api-key': apiKey } : undefined });
      if (!res.ok) throw new Error(String(res.status));
      const parsed = FleetResponse.parse(await res.json());
      setAssets(parsed.assets);
      setSummary(parsed.summary);
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

  /** Mints a single-use token. The plaintext exists only in this response. */
  const mintToken = useCallback(async () => {
    setBusy(true);
    setLastResult(null);
    try {
      const res = await fetch('/api/v1/assets/enrollment-token', { method: 'POST', headers: headers(), body: '{}' });
      const body = await res.json();
      if (!res.ok) throw new Error(body?.error ?? String(res.status));
      setEnrollment({
        token: body.token,
        expiresAt: body.expiresAt,
        command: `node sensor/sovereign-sensor.mjs --server ${window.location.origin} --token ${body.token}`
      });
    } catch (err) {
      setLastResult(`token failed: ${err instanceof Error ? err.message : 'network error'}`);
    } finally {
      setBusy(false);
    }
  }, [headers]);

  const declareNetwork = useCallback(
    async (cidr: string, label?: string) => {
      setBusy(true);
      setLastResult(null);
      try {
        const res = await fetch('/api/v1/assets/network', {
          method: 'POST',
          headers: headers(),
          body: JSON.stringify({ cidr, label })
        });
        const body = await res.json();
        setLastResult(res.ok ? `declared ${cidr}` : (body?.error ?? `rejected (${res.status})`));
      } catch (err) {
        setLastResult(`failed: ${err instanceof Error ? err.message : 'network error'}`);
      } finally {
        setBusy(false);
        void load();
      }
    },
    [headers, load]
  );

  /**
   * Isolation. The server reports separately whether the registry flag was set and
   * whether the kernel rule was actually applied, and both are surfaced — a flag
   * without an enforced rule is a claim the network does not honour, and an operator
   * has to be told which of the two happened.
   */
  const setIsolated = useCallback(
    async (id: string, isolate: boolean) => {
      setBusy(true);
      setLastResult(null);
      try {
        const res = await fetch(`/api/v1/assets/${id}/isolate`, {
          method: 'POST',
          headers: headers(),
          body: JSON.stringify({ isolate })
        });
        const body = await res.json();
        if (!res.ok) setLastResult(body?.error ?? `rejected (${res.status})`);
        else if (body.enforced) setLastResult(`${id} ${isolate ? 'isolated' : 'released'} — kernel rule applied`);
        else setLastResult(`${id} flagged but NOT enforced: ${body.containmentError ?? 'unknown reason'}`);
      } catch (err) {
        setLastResult(`failed: ${err instanceof Error ? err.message : 'network error'}`);
      } finally {
        setBusy(false);
        void load();
      }
    },
    [headers, load]
  );

  const remove = useCallback(
    async (id: string) => {
      setBusy(true);
      try {
        await fetch(`/api/v1/assets/${id}`, { method: 'DELETE', headers: headers() });
        setLastResult(`${id} removed`);
      } catch (err) {
        setLastResult(`failed: ${err instanceof Error ? err.message : 'network error'}`);
      } finally {
        setBusy(false);
        void load();
      }
    },
    [headers, load]
  );

  return {
    assets,
    summary,
    unreachable,
    busy,
    lastResult,
    enrollment,
    clearEnrollment: () => setEnrollment(null),
    mintToken,
    declareNetwork,
    setIsolated,
    remove,
    refresh: () => void load()
  };
}

export default useAssets;
