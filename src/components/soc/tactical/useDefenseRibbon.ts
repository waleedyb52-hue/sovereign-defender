import { useCallback, useEffect, useState } from 'react';
import { z } from 'zod';

/**
 * DEFENCE RIBBON SOURCES
 *
 * `useCyberDefendData` covers analytics, cluster, agent, posture, drift, retention and
 * telemetry. The unified cockpit's ribbon and kill-chain rail need four more, each of
 * which already exists on the backend and was previously reachable only from the
 * console page it was written for:
 *
 *   /api/v1/traffic/waf/metrics        L7 rule state, RPS, XDP drops, kernel latency
 *   /api/v1/fim/status                 file-integrity coverage and alert counts
 *   /api/v1/soc/sensors/kernel-integrity   syscall-table verdict, MITRE T1014
 *   /api/v1/soc/attack-chains          observed kill chains, for the rail
 *
 * Same discipline as the sibling hook, and it matters more here than anywhere: the
 * ribbon is the first thing an operator reads, and a ribbon that shows a confident
 * zero for a sensor that never answered is worse than one that shows nothing. Every
 * field resolves to null on absence, `missing` names the endpoints that failed, and
 * the kernel-integrity verdict carries the backend's own `unavailableReason` verbatim
 * rather than being flattened to a pass or a fail. On this host that reason is that
 * /proc/kallsyms does not exist on win32 — which is a real answer, and not the same
 * thing as an integrity failure.
 */

const WafMetrics = z.object({
  rps: z.number().nullish(),
  totalRequests: z.number().nullish(),
  droppedPackets: z.number().nullish(),
  ebpfLatencyUs: z.number().nullish(),
  activeBlockedSubnetsCount: z.number().nullish(),
  wafConfig: z.record(z.string(), z.union([z.boolean(), z.number()])).nullish()
});

const WafResponse = z.object({ metrics: WafMetrics });

const FimResponse = z.object({
  active: z.boolean().nullish(),
  monitoredDirectory: z.string().nullish(),
  monitoredFilesCount: z.number().nullish(),
  totalAlerts: z.number().nullish(),
  criticalAlerts: z.number().nullish(),
  quarantinedCount: z.number().nullish()
});

const IntegrityResponse = z.object({
  result: z.object({
    checkedAt: z.string().nullish(),
    mitreTechnique: z.string().nullish(),
    status: z.string().nullish(),
    unavailableReason: z.string().nullish(),
    missingInterfaces: z.array(z.string()).nullish(),
    kernelLockdown: z.union([z.string(), z.boolean()]).nullish()
  })
});

const ChainStage = z.object({
  stage: z.string(),
  timestamp: z.string().nullish(),
  description: z.string().nullish(),
  technique: z.string().nullish()
});

const ChainsResponse = z.object({
  totalChains: z.number().nullish(),
  chains: z
    .array(
      z.object({
        sessionId: z.string(),
        actorIp: z.string().nullish(),
        threatScore: z.number().nullish(),
        firstSeen: z.string().nullish(),
        lastSeen: z.string().nullish(),
        status: z.string().nullish(),
        stagesCompleted: z.array(ChainStage).default([])
      })
    )
    .default([])
});

export interface RibbonChainStage {
  stage: string;
  technique: string | null;
  at: string | null;
  description: string | null;
}

export interface RibbonChain {
  sessionId: string;
  actorIp: string | null;
  threatScore: number | null;
  status: string | null;
  firstSeen: string | null;
  lastSeen: string | null;
  stages: RibbonChainStage[];
}

async function getJson<T>(path: string, schema: z.ZodType<T>, key?: string): Promise<T> {
  const res = await fetch(path, { headers: key ? { 'x-api-key': key } : undefined });
  if (!res.ok) throw new Error(`${path} -> ${res.status}`);
  return schema.parse(await res.json());
}

export function useDefenseRibbon(apiKey?: string, pollMs = 5000) {
  const [waf, setWaf] = useState<z.infer<typeof WafResponse> | null>(null);
  const [fim, setFim] = useState<z.infer<typeof FimResponse> | null>(null);
  const [integrity, setIntegrity] = useState<z.infer<typeof IntegrityResponse> | null>(null);
  const [chains, setChains] = useState<z.infer<typeof ChainsResponse> | null>(null);
  const [missing, setMissing] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    const jobs: Array<[string, Promise<unknown>]> = [
      ['/traffic/waf/metrics', getJson('/api/v1/traffic/waf/metrics', WafResponse, apiKey)],
      ['/fim/status', getJson('/api/v1/fim/status', FimResponse, apiKey)],
      ['/soc/sensors/kernel-integrity', getJson('/api/v1/soc/sensors/kernel-integrity', IntegrityResponse, apiKey)],
      ['/soc/attack-chains', getJson('/api/v1/soc/attack-chains', ChainsResponse, apiKey)]
    ];

    const settled = await Promise.allSettled(jobs.map(j => j[1]));
    const failed: string[] = [];

    settled.forEach((r, i) => {
      const name = jobs[i][0];
      if (r.status === 'rejected') {
        failed.push(name);
        return;
      }
      switch (i) {
        case 0:
          setWaf(r.value as z.infer<typeof WafResponse>);
          break;
        case 1:
          setFim(r.value as z.infer<typeof FimResponse>);
          break;
        case 2:
          setIntegrity(r.value as z.infer<typeof IntegrityResponse>);
          break;
        case 3:
          setChains(r.value as z.infer<typeof ChainsResponse>);
          break;
      }
    });

    setMissing(failed);
    setLoading(false);
  }, [apiKey]);

  useEffect(() => {
    load();
    const t = setInterval(load, pollMs);
    return () => clearInterval(t);
  }, [load, pollMs]);

  const m = waf?.metrics;
  const cfg = m?.wafConfig ?? null;

  /**
   * Enabled L7 rules, counted from the config the backend actually returns.
   *
   * Counted rather than hardcoded: the ribbon claims "N of M rules active", and if M
   * were a literal it would keep claiming the same denominator after a rule was added
   * or removed on the server. Only boolean entries count — the config also carries
   * numeric settings like rateLimitThresholdRpm, which are thresholds, not rules.
   */
  const l7Total = cfg ? Object.values(cfg).filter(v => typeof v === 'boolean').length : null;
  const l7Active = cfg ? Object.values(cfg).filter(v => v === true).length : null;

  const ir = integrity?.result;

  return {
    loading,
    missing,

    // rps and ebpfLatencyUs are Math.random() on the server (httpTrafficTelemetry
    // getWafMetrics), so they are withheld rather than passed on as readings.
    waf: {
      rps: null,
      totalRequests: m?.totalRequests ?? null,
      droppedPackets: m?.droppedPackets ?? null,
      latencyUs: null,
      blockedSubnets: m?.activeBlockedSubnetsCount ?? null,
      l7Active,
      l7Total,
      rules: cfg
        ? Object.entries(cfg)
            .filter(([, v]) => typeof v === 'boolean')
            .map(([name, v]) => ({ name, on: v === true }))
        : []
    },

    fim: {
      active: fim?.active ?? null,
      directory: fim?.monitoredDirectory ?? null,
      files: fim?.monitoredFilesCount ?? null,
      alerts: fim?.totalAlerts ?? null,
      critical: fim?.criticalAlerts ?? null,
      quarantined: fim?.quarantinedCount ?? null
    },

    integrity: {
      status: ir?.status ?? null,
      mitre: ir?.mitreTechnique ?? null,
      // Carried verbatim. "Cannot be checked on this platform" is a different
      // statement from "checked and failed", and collapsing the two is how a
      // console ends up asserting an integrity guarantee it never verified.
      reason: ir?.unavailableReason ?? null,
      missingInterfaces: ir?.missingInterfaces ?? [],
      checkedAt: ir?.checkedAt ?? null
    },

    chains: (chains?.chains ?? []).map<RibbonChain>(c => ({
      sessionId: c.sessionId,
      actorIp: c.actorIp ?? null,
      threatScore: c.threatScore ?? null,
      status: c.status ?? null,
      firstSeen: c.firstSeen ?? null,
      lastSeen: c.lastSeen ?? null,
      stages: (c.stagesCompleted ?? []).map(s => ({
        stage: s.stage,
        technique: s.technique ?? null,
        at: s.timestamp ?? null,
        description: s.description ?? null
      }))
    })),
    totalChains: chains?.totalChains ?? null,

    refresh: () => void load()
  };
}

export default useDefenseRibbon;
