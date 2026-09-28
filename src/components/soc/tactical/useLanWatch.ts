import { useCallback, useEffect, useState } from 'react';
import { z } from 'zod';

/** LAN WATCH — GET /api/v1/lan-watch, POST /api/v1/lan-watch/:mac/approve. */

const Device = z.object({
  mac: z.string(),
  lastIp: z.string().nullable(),
  ips: z.array(z.string()),
  vendor: z.string().nullable(),
  randomized: z.boolean(),
  state: z.enum(['BASELINE', 'NEW', 'APPROVED']),
  firstSeen: z.string(),
  lastSeen: z.string(),
  seenBy: z.array(z.string()),
  approvedBy: z.string().nullable(),
  approvedAt: z.string().nullable()
});

const Event = z.object({
  id: z.string(),
  at: z.string(),
  kind: z.enum(['NEW_DEVICE', 'GATEWAY_MAC_CHANGED', 'ARP_SPOOF_SUSPECTED', 'BASELINE_RECORDED']),
  severity: z.string(),
  assetId: z.string(),
  ip: z.string().nullable(),
  mac: z.string().nullable(),
  detail: z.string(),
  mitre: z.string().nullable()
});

const Status = z.object({
  durable: z.boolean(),
  devices: z.array(Device),
  newCount: z.number(),
  gateways: z.array(z.object({ assetId: z.string(), ip: z.string(), mac: z.string(), since: z.string() })),
  spoofDetection: z.record(z.string(), z.enum(['ACTIVE', 'NO_GATEWAY_DATA'])),
  activeSpoofs: z.number(),
  events: z.array(Event)
});

export type LanDevice = z.infer<typeof Device>;
export type LanEvent = z.infer<typeof Event>;
export type LanStatus = z.infer<typeof Status>;

export function useLanWatch(pollMs = 10_000) {
  const [status, setStatus] = useState<LanStatus | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busyMac, setBusyMac] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const res = await fetch('/api/v1/lan-watch');
      if (!res.ok) throw new Error(`/api/v1/lan-watch -> ${res.status}`);
      setStatus(Status.parse(await res.json()));
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'lan-watch unreachable');
    }
  }, []);

  useEffect(() => {
    void load();
    const t = setInterval(() => void load(), pollMs);
    return () => clearInterval(t);
  }, [load, pollMs]);

  const approve = useCallback(
    async (mac: string) => {
      setBusyMac(mac);
      try {
        await fetch(`/api/v1/lan-watch/${encodeURIComponent(mac)}/approve`, { method: 'POST' });
      } finally {
        setBusyMac(null);
        await load();
      }
    },
    [load]
  );

  const byMac = new Map((status?.devices ?? []).map(d => [d.mac.toLowerCase(), d]));
  /** Spoof and gateway events are the ones that warrant a banner. */
  const alarms = (status?.events ?? []).filter(e => e.kind === 'ARP_SPOOF_SUSPECTED' || e.kind === 'GATEWAY_MAC_CHANGED');

  return { status, error, busyMac, approve, byMac, alarms, refresh: () => void load() };
}

export type LanWatch = ReturnType<typeof useLanWatch>;

export default useLanWatch;
