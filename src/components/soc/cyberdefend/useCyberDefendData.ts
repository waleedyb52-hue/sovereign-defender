import { useCallback, useEffect, useRef, useState } from 'react';
import { z } from 'zod';

/**
 * DATA FOR THE CYBERDEFEND SURFACE
 *
 * The reference design was a satellite and energy operations console: orbital
 * telemetry, ground stations, megawatt-hours, fuel sources, household costs. None
 * of that exists in this platform, and hardcoding it would put forty invented
 * figures in front of an operator — the defect `.clauderules` rule 0 forbids and
 * which this codebase has had to remove five times already.
 *
 * So the visual language is reproduced exactly and every value behind it is read
 * from a real endpoint. The mapping, kept here so it is auditable rather than
 * buried in JSX:
 *
 *   reference                        this platform
 *   ───────────────────────────────  ──────────────────────────────────────────
 *   orbital threat markers        →  geoThreatDistribution (real countries)
 *   satellite inspector           →  a real eBPF cluster node
 *   ground-station nodes          →  progressive mitigation tiers 1/2/3
 *   data-centre throughput        →  endpointDistribution hits and threatHits
 *   speed dials (km/h)            →  detection latency and request rate
 *   "chance of failure" sparkline →  drift PSI per feature
 *   dual production arcs (MWh)    →  threats blocked vs requests protected
 *   fuel-source bars              →  attack family distribution
 *   energy intensity index        →  threat density per 10,000 requests
 *
 * Anything without a source resolves to null, and the surface renders an em dash
 * naming the missing endpoint rather than a plausible number.
 */

const API = '/api/v1/soc';

/* ── Schemas ─────────────────────────────────────────────────────────────── */

const GeoThreat = z.object({
  country: z.string(),
  code: z.string(),
  flag: z.string().nullish(),
  count: z.number().nullish(),
  threatCount: z.number().nullish(),
  hits: z.number().nullish()
});

const EndpointRow = z.object({
  endpoint: z.string(),
  hits: z.number().nullish(),
  threatHits: z.number().nullish(),
  percentage: z.number().nullish()
});

const FrequencyPoint = z.object({
  time: z.string().nullish(),
  timestamp: z.string().nullish(),
  reqSec: z.number().nullish(),
  requestsPerSec: z.number().nullish(),
  threats: z.number().nullish()
});

const AnalyticsResponse = z.object({
  success: z.boolean().nullish(),
  frequencyGraph: z.array(FrequencyPoint).default([]),
  endpointDistribution: z.array(EndpointRow).default([]),
  geoThreatDistribution: z.array(GeoThreat).default([]),
  progressiveMitigation: z
    .object({
      tier1RateLimitedCount: z.number().nullish(),
      tier2ChallengedCount: z.number().nullish(),
      tier3CriticalBlockedCount: z.number().nullish(),
      activeTier1Sessions: z.number().nullish(),
      activeTier2Challenges: z.number().nullish(),
      activeTier3HardBans: z.number().nullish()
    })
    .default({})
});

const ClusterNode = z.object({
  nodeName: z.string(),
  nodeIp: z.string(),
  clusterRole: z.string().nullish(),
  isolationStatus: z.string().nullish(),
  threatScore: z.number().nullish(),
  packetsDropped: z.number().nullish(),
  ingressBytes: z.number().nullish(),
  egressBytes: z.number().nullish()
});

const ClusterResponse = z.object({
  success: z.boolean().nullish(),
  nodes: z.array(ClusterNode).default([]),
  statistics: z
    .object({
      activeBlackholesCount: z.number().nullish(),
      totalPacketsDropped: z.number().nullish(),
      seededPacketsDropped: z.number().nullish(),
      observedPacketsDropped: z.number().nullish(),
      totalTcpResetsInjected: z.number().nullish(),
      meanKernelLatencyUs: z.number().nullish(),
      anomaliesDetectedCount: z.number().nullish(),
      provenance: z
        .object({
          mode: z.string(),
          kernelToolingPresent: z.boolean().nullish(),
          kernelCountersReadable: z.boolean().nullish(),
          reason: z.string().nullish(),
          fields: z.record(z.string(), z.string()).nullish()
        })
        .nullish()
    })
    .default({})
});

const AgentResponse = z.object({
  status: z.string().nullish(),
  metrics: z
    .object({
      totalRequestsProtected: z.number().nullish(),
      totalThreatsBlocked: z.number().nullish(),
      honeypotTrappedCount: z.number().nullish(),
      quarantinedIpsCount: z.number().nullish(),
      activeIptablesRules: z.number().nullish()
    })
    .default({}),
  activeSignaturesCount: z.number().nullish()
});

const PostureResponse = z.object({
  localEngine: z.object({
    name: z.string(),
    activeSignaturesCount: z.number().nullish(),
    isSoleDetectionPath: z.boolean()
  }),
  processMemory: z.object({ heapUsedMb: z.number(), rssMb: z.number() }),
  egressPossible: z.boolean(),
  zeroExternalApiCalls: z.boolean(),
  aiEvaluationsCount: z.number(),
  uptimeSec: z.number()
});

const DriftFeature = z.object({
  feature: z.string(),
  psi: z.number(),
  jsd: z.number(),
  verdict: z.string()
});

const DriftResponse = z.object({
  success: z.boolean().nullish(),
  report: z.object({
    verdict: z.string(),
    maxPsi: z.number(),
    drivingFeature: z.string().nullish(),
    features: z.array(DriftFeature).default([]),
    referenceSize: z.number(),
    currentSize: z.number(),
    thresholds: z.object({ moderate: z.number(), significant: z.number(), minSamples: z.number() }),
    insufficientReason: z.string().nullish(),
    familyDistributionShift: z
      .object({ psi: z.number(), newFamilies: z.array(z.string()).default([]) })
      .nullish()
  })
});

const RetentionResponse = z.object({
  success: z.boolean().nullish(),
  statistics: z.object({
    held: z.number(),
    capacity: z.number(),
    byFamily: z.record(z.string(), z.number()).default({})
  })
});

/* ── Shape returned to the surface ───────────────────────────────────────── */

export interface CyberDefendData {
  loading: boolean;
  /** Endpoints that failed this poll, named so the UI can say which is missing. */
  missing: string[];

  geo: Array<{ country: string; code: string; flag: string | null; count: number }>;
  endpoints: Array<{ endpoint: string; hits: number; threatHits: number }>;
  frequency: Array<{ label: string; value: number; threats: number }>;
  mitigation: { tier1: number | null; tier2: number | null; tier3: number | null };

  nodes: Array<{
    name: string; ip: string; role: string | null; isolated: boolean;
    threatScore: number | null; packetsDropped: number | null;
  }>;
  kernel: {
    mode: string | null;
    latencyUs: number | null;
    packetsDropped: number | null;
    seeded: number | null;
    observed: number | null;
    tcpResets: number | null;
    anomalies: number | null;
    blackholes: number | null;
    toolingPresent: boolean | null;
    countersReadable: boolean | null;
    reason: string | null;
  };

  agent: {
    requestsProtected: number | null;
    threatsBlocked: number | null;
    trapped: number | null;
    quarantined: number | null;
    signatures: number | null;
  };
  posture: {
    engine: string | null;
    zeroEgress: boolean | null;
    heapMb: number | null;
    rssMb: number | null;
    evaluations: number | null;
    uptimeSec: number | null;
  };

  drift: {
    verdict: string | null;
    maxPsi: number | null;
    drivingFeature: string | null;
    features: Array<{ feature: string; psi: number; jsd: number; verdict: string }>;
    thresholds: { moderate: number; significant: number } | null;
    insufficientReason: string | null;
    newFamilies: string[];
  };

  families: Array<{ family: string; count: number }>;

  /** Derived, and only where both inputs are real. */
  derived: {
    /** Requests per second, from successive deltas of the protected counter. */
    requestRate: number | null;
    /** Threats per 10,000 protected requests. */
    threatDensity: number | null;
    /** Share of protected requests that were blocked, 0-1. */
    blockShare: number | null;
  };

  refresh: () => void;
}

async function getJson<T>(path: string, schema: z.ZodType<T>, key?: string): Promise<T> {
  const res = await fetch(path, { headers: key ? { 'x-api-key': key } : undefined });
  if (!res.ok) throw new Error(`${path} → HTTP ${res.status}`);
  const parsed = schema.safeParse(await res.json());
  if (!parsed.success) throw new Error(`${path} → unexpected shape`);
  return parsed.data;
}

export function useCyberDefendData(apiKey?: string, pollMs = 5000): CyberDefendData {
  const [loading, setLoading] = useState(true);
  const [missing, setMissing] = useState<string[]>([]);
  const [analytics, setAnalytics] = useState<z.infer<typeof AnalyticsResponse> | null>(null);
  const [cluster, setCluster] = useState<z.infer<typeof ClusterResponse> | null>(null);
  const [agent, setAgent] = useState<z.infer<typeof AgentResponse> | null>(null);
  const [posture, setPosture] = useState<z.infer<typeof PostureResponse> | null>(null);
  const [drift, setDrift] = useState<z.infer<typeof DriftResponse> | null>(null);
  const [retention, setRetention] = useState<z.infer<typeof RetentionResponse> | null>(null);
  const lastProtected = useRef<{ n: number; at: number } | null>(null);
  const [requestRate, setRequestRate] = useState<number | null>(null);

  const load = useCallback(async () => {
    const jobs: Array<[string, Promise<unknown>]> = [
      ['/soc/analytics', getJson(`${API}/analytics`, AnalyticsResponse, apiKey)],
      ['/soc/ebpf/cluster-nodes', getJson(`${API}/ebpf/cluster-nodes`, ClusterResponse, apiKey)],
      ['/agent/status', getJson('/api/v1/agent/status', AgentResponse, apiKey)],
      ['/soc/inference-posture', getJson(`${API}/inference-posture`, PostureResponse, apiKey)],
      ['/soc/learning/drift', getJson(`${API}/learning/drift`, DriftResponse, apiKey)],
      ['/soc/learning/retention', getJson(`${API}/learning/retention`, RetentionResponse, apiKey)]
    ];

    const settled = await Promise.allSettled(jobs.map(j => j[1]));
    const failed: string[] = [];
    settled.forEach((r, i) => {
      const name = jobs[i][0];
      if (r.status === 'rejected') { failed.push(name); return; }
      switch (i) {
        case 0: setAnalytics(r.value as any); break;
        case 1: setCluster(r.value as any); break;
        case 2: {
          const a = r.value as z.infer<typeof AgentResponse>;
          setAgent(a);
          // Real rate from deltas. First sample yields none rather than a seeded
          // figure — a rate invented at mount is indistinguishable from a reading.
          const n = a.metrics.totalRequestsProtected;
          const at = Date.now();
          if (typeof n === 'number') {
            const prev = lastProtected.current;
            if (prev && at > prev.at) {
              setRequestRate(Number((((n - prev.n) / (at - prev.at)) * 1000).toFixed(1)));
            }
            lastProtected.current = { n, at };
          }
          break;
        }
        case 3: setPosture(r.value as any); break;
        case 4: setDrift(r.value as any); break;
        case 5: setRetention(r.value as any); break;
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

  const st = cluster?.statistics;
  const prov = st?.provenance;
  const m = agent?.metrics;

  const requestsProtected = m?.totalRequestsProtected ?? null;
  const threatsBlocked = m?.totalThreatsBlocked ?? null;

  return {
    loading,
    missing,

    geo: (analytics?.geoThreatDistribution ?? []).map(g => ({
      country: g.country,
      code: g.code,
      flag: g.flag ?? null,
      count: g.count ?? g.threatCount ?? g.hits ?? 0
    })),
    endpoints: (analytics?.endpointDistribution ?? []).map(e => ({
      endpoint: e.endpoint,
      hits: e.hits ?? 0,
      threatHits: e.threatHits ?? 0
    })),
    frequency: (analytics?.frequencyGraph ?? []).map(f => ({
      label: f.time ?? f.timestamp?.slice(11, 19) ?? '',
      value: f.reqSec ?? f.requestsPerSec ?? 0,
      threats: f.threats ?? 0
    })),
    mitigation: {
      tier1: analytics?.progressiveMitigation.tier1RateLimitedCount ?? null,
      tier2: analytics?.progressiveMitigation.tier2ChallengedCount ?? null,
      tier3: analytics?.progressiveMitigation.tier3CriticalBlockedCount ?? null
    },

    nodes: (cluster?.nodes ?? []).map(n => ({
      name: n.nodeName,
      ip: n.nodeIp,
      role: n.clusterRole ?? null,
      isolated: Boolean(n.isolationStatus && /ISOLAT|QUARANT|CONTAIN|BLACKHOL/i.test(n.isolationStatus)),
      threatScore: n.threatScore ?? null,
      packetsDropped: n.packetsDropped ?? null
    })),
    kernel: {
      mode: prov?.mode ?? null,
      latencyUs: st?.meanKernelLatencyUs ?? null,
      packetsDropped: st?.totalPacketsDropped ?? null,
      seeded: st?.seededPacketsDropped ?? null,
      observed: st?.observedPacketsDropped ?? null,
      tcpResets: st?.totalTcpResetsInjected ?? null,
      anomalies: st?.anomaliesDetectedCount ?? null,
      blackholes: st?.activeBlackholesCount ?? null,
      toolingPresent: prov?.kernelToolingPresent ?? null,
      countersReadable: prov?.kernelCountersReadable ?? null,
      reason: prov?.reason ?? null
    },

    agent: {
      requestsProtected,
      threatsBlocked,
      trapped: m?.honeypotTrappedCount ?? null,
      quarantined: m?.quarantinedIpsCount ?? null,
      signatures: agent?.activeSignaturesCount ?? null
    },
    posture: {
      engine: posture?.localEngine.name ?? null,
      zeroEgress: posture?.zeroExternalApiCalls ?? null,
      heapMb: posture?.processMemory.heapUsedMb ?? null,
      rssMb: posture?.processMemory.rssMb ?? null,
      evaluations: posture?.aiEvaluationsCount ?? null,
      uptimeSec: posture?.uptimeSec ?? null
    },

    drift: {
      verdict: drift?.report.verdict ?? null,
      maxPsi: drift?.report.maxPsi ?? null,
      drivingFeature: drift?.report.drivingFeature ?? null,
      features: drift?.report.features ?? [],
      thresholds: drift?.report.thresholds
        ? { moderate: drift.report.thresholds.moderate, significant: drift.report.thresholds.significant }
        : null,
      insufficientReason: drift?.report.insufficientReason ?? null,
      newFamilies: drift?.report.familyDistributionShift?.newFamilies ?? []
    },

    families: Object.entries(retention?.statistics.byFamily ?? {})
      .map(([family, count]) => ({ family, count }))
      .sort((a, b) => b.count - a.count),

    derived: {
      requestRate,
      threatDensity:
        requestsProtected && requestsProtected > 0 && threatsBlocked != null
          ? Number(((threatsBlocked / requestsProtected) * 10000).toFixed(1))
          : null,
      blockShare:
        requestsProtected && requestsProtected > 0 && threatsBlocked != null
          ? Number((threatsBlocked / requestsProtected).toFixed(4))
          : null
    },

    refresh: () => void load()
  };
}
