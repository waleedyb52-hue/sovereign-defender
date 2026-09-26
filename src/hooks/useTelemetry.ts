import { useCallback, useEffect, useRef, useState } from 'react';
import { z } from 'zod';

/**
 * TELEMETRY HOOKS — transport, validation and shaping, kept out of components
 *
 * Two rules from `.clauderules` are enforced here rather than left to the panels:
 *
 *   Rule 0 — a number on screen is real or declared unavailable. Every hook
 *   returns `loading`, `error` and `stale` alongside its data, and returns `null`
 *   rather than a zero when a field is genuinely absent. A panel that receives
 *   null must render an empty state; it has nothing to round to.
 *
 *   Rule 9 — parsing never lives in a component. Responses are validated with
 *   zod at the boundary, so a shape change upstream surfaces as an error state
 *   instead of `undefined` reaching JSX and rendering as blank confidence.
 *
 * The sparkline problem, and why series are derived rather than requested
 *   The server exposes cumulative counters — `totalPacketsDropped` climbs and
 *   never resets. A sparkline of a cumulative counter is a straight line and
 *   tells an operator nothing, so these hooks sample on an interval and plot the
 *   *deltas* between samples. That makes the series real observations of rate.
 *   The cost is that history starts empty: on first mount there is exactly one
 *   sample and no delta, so `series` is short and `collecting` is true. Panels
 *   must show that state rather than animate from zero, because animating from
 *   zero would draw a history that was never observed.
 */

const POLL_MS = 4000;
/** Points retained per series. At 4s cadence this is a ~2 minute window. */
const SERIES_WINDOW = 30;

/* ── Schemas ─────────────────────────────────────────────────────────────── */

/**
 * Per-figure provenance, as the service now reports it.
 *
 * Parsed as a first-class field rather than an optional extra: the console has
 * to be able to tell a kernel counter from a seeded literal, and until this
 * existed it could not. `meanKernelLatencyUs` arrives null on a host with no
 * kernel path, which is the honest value — it was previously a hardcoded 0.34
 * that the HUD rendered as a measured microsecond figure.
 */
const EbpfProvenance = z.object({
  kernelNative: z.boolean(),
  mode: z.string(),
  reason: z.string(),
  fields: z.record(z.string(), z.string())
});

const EbpfStats = z.object({
  activeBlackholesCount: z.number().nullish(),
  totalHistoricIsolations: z.number().nullish(),
  totalPacketsDropped: z.number().nullish(),
  observedPacketsDropped: z.number().nullish(),
  seededPacketsDropped: z.number().nullish(),
  totalTcpResetsInjected: z.number().nullish(),
  meanKernelLatencyUs: z.number().nullish(),
  anomaliesDetectedCount: z.number().nullish(),
  provenance: EbpfProvenance.nullish()
});

export const ClusterNodeSchema = z.object({
  nodeName: z.string(),
  nodeIp: z.string(),
  clusterRole: z.string().nullish(),
  isolationStatus: z.string().nullish(),
  ingressBytes: z.number().nullish(),
  egressBytes: z.number().nullish(),
  packetsDropped: z.number().nullish(),
  threatScore: z.number().nullish()
});
export type ClusterNode = z.infer<typeof ClusterNodeSchema>;

const ClusterResponse = z.object({
  success: z.boolean(),
  nodes: z.array(ClusterNodeSchema).default([]),
  statistics: EbpfStats.default({})
});

const FimResponse = z.object({
  success: z.boolean(),
  active: z.boolean().nullish(),
  monitoredFilesCount: z.number().nullish(),
  totalAlerts: z.number().nullish(),
  criticalAlerts: z.number().nullish(),
  quarantinedCount: z.number().nullish()
});

const AgentResponse = z.object({
  status: z.string().nullish(),
  metrics: z
    .object({
      totalRequestsProtected: z.number().nullish(),
      totalThreatsBlocked: z.number().nullish(),
      honeypotTrappedCount: z.number().nullish(),
      aiEvaluationsCount: z.number().nullish(),
      quarantinedIpsCount: z.number().nullish(),
      activeIptablesRules: z.number().nullish()
    })
    .default({}),
  activeSignaturesCount: z.number().nullish()
});

const PostureResponse = z.object({
  success: z.boolean(),
  localEngine: z.object({
    name: z.string(),
    activeSignaturesCount: z.number().nullish(),
    isSoleDetectionPath: z.boolean()
  }),
  processMemory: z.object({ heapUsedMb: z.number(), rssMb: z.number() }),
  externalModel: z.object({ configured: z.boolean(), provider: z.string().nullish() }),
  egressPossible: z.boolean(),
  zeroExternalApiCalls: z.boolean(),
  aiEvaluationsCount: z.number(),
  uptimeSec: z.number()
});

export const ThreatEventSchema = z.object({
  id: z.string(),
  timestamp: z.string(),
  source: z.string().nullish(),
  severity: z.string().nullish(),
  title: z.string().nullish(),
  titleAr: z.string().nullish(),
  details: z.string().nullish(),
  mitreTactic: z.string().nullish(),
  mitreId: z.string().nullish(),
  actionTaken: z.string().nullish(),
  actionTakenAr: z.string().nullish(),
  srcIp: z.string().nullish(),
  sourceIp: z.string().nullish()
});
export type ThreatEvent = z.infer<typeof ThreatEventSchema>;

const TimelineResponse = z.object({
  success: z.boolean().nullish(),
  events: z.array(ThreatEventSchema).default([]),
  emergencyLockdown: z.boolean().nullish()
});

/* ── Fetch plumbing ──────────────────────────────────────────────────────── */

function apiKey(): string | undefined {
  try {
    return (
      (typeof window !== 'undefined' && (window as any).__SD_API_KEY__) ||
      localStorage.getItem('sd_api_key') ||
      undefined
    );
  } catch {
    // Private-window or blocked storage. Same-origin auth still applies.
    return undefined;
  }
}

async function getJson<T>(path: string, schema: z.ZodType<T>, signal?: AbortSignal): Promise<T> {
  const k = apiKey();
  const res = await fetch(path, {
    signal,
    headers: k ? { 'x-api-key': k } : undefined
  });
  if (!res.ok) throw new Error(`${path} → HTTP ${res.status}`);
  const raw = await res.json();
  const parsed = schema.safeParse(raw);
  if (!parsed.success) {
    // Surfaced as an error rather than coerced. A silently-defaulted response is
    // how a dashboard ends up displaying zeros it never received.
    throw new Error(`${path} → unexpected shape: ${parsed.error.issues[0]?.message ?? 'invalid'}`);
  }
  return parsed.data;
}

/** Rolling delta series built from successive cumulative samples. */
function useDeltaSeries() {
  const last = useRef<Map<string, number>>(new Map());
  const [series, setSeries] = useState<Record<string, number[]>>({});

  const push = useCallback((key: string, cumulative: number | null | undefined) => {
    if (cumulative == null || !Number.isFinite(cumulative)) return;
    const prev = last.current.get(key);
    last.current.set(key, cumulative);
    if (prev == null) return; // first sample yields no delta, and none is invented
    const delta = Math.max(0, cumulative - prev);
    setSeries(s => {
      const next = [...(s[key] ?? []), delta];
      return { ...s, [key]: next.slice(-SERIES_WINDOW) };
    });
  }, []);

  return { series, push };
}

/* ── The composite telemetry hook ────────────────────────────────────────── */

export interface TelemetryState {
  loading: boolean;
  error: string | null;
  /** True when the last poll failed but earlier data is still being shown. */
  stale: boolean;
  ebpf: {
    packetsDropped: number | null;
    observedPacketsDropped: number | null;
    seededPacketsDropped: number | null;
    kernelLatencyUs: number | null;
    activeBlackholes: number | null;
    anomalies: number | null;
    /** Null until the service reports it; drives the SEEDED / SIMULATED labels. */
    provenance: {
      kernelNative: boolean;
      mode: string;
      reason: string;
      fields: Record<string, string>;
    } | null;
  };
  fim: {
    monitoredFiles: number | null;
    criticalAlerts: number | null;
    quarantined: number | null;
    active: boolean | null;
  };
  tarpit: { trapped: number | null; quarantinedIps: number | null };
  inference: {
    engine: string | null;
    signatures: number | null;
    heapMb: number | null;
    rssMb: number | null;
    evaluations: number | null;
    zeroExternalApiCalls: boolean | null;
    isSoleDetectionPath: boolean | null;
    externalProvider: string | null;
  };
  nodes: ClusterNode[];
  /** Delta series keyed by metric. Short or absent until two samples exist. */
  series: Record<string, number[]>;
  /** True while fewer than two points are available for any series. */
  collecting: boolean;
  refresh: () => void;
}

export function useTelemetry(pollMs = POLL_MS): TelemetryState {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [stale, setStale] = useState(false);
  const [cluster, setCluster] = useState<z.infer<typeof ClusterResponse> | null>(null);
  const [fim, setFim] = useState<z.infer<typeof FimResponse> | null>(null);
  const [agent, setAgent] = useState<z.infer<typeof AgentResponse> | null>(null);
  const [posture, setPosture] = useState<z.infer<typeof PostureResponse> | null>(null);
  const { series, push } = useDeltaSeries();
  const tick = useRef(0);

  const load = useCallback(
    async (signal?: AbortSignal) => {
      // Settled rather than all: one dead endpoint must not blank the entire HUD.
      const [c, f, a, p] = await Promise.allSettled([
        getJson('/api/v1/soc/ebpf/cluster-nodes', ClusterResponse, signal),
        getJson('/api/v1/fim/status', FimResponse, signal),
        getJson('/api/v1/agent/status', AgentResponse, signal),
        getJson('/api/v1/soc/inference-posture', PostureResponse, signal)
      ]);

      const failures: string[] = [];
      if (c.status === 'fulfilled') setCluster(c.value);
      else failures.push(String(c.reason?.message ?? c.reason));
      if (f.status === 'fulfilled') setFim(f.value);
      else failures.push(String(f.reason?.message ?? f.reason));
      if (a.status === 'fulfilled') setAgent(a.value);
      else failures.push(String(a.reason?.message ?? a.reason));
      if (p.status === 'fulfilled') setPosture(p.value);
      else failures.push(String(p.reason?.message ?? p.reason));

      if (c.status === 'fulfilled') {
        push('packetsDropped', c.value.statistics.totalPacketsDropped);
        push('tcpResets', c.value.statistics.totalTcpResetsInjected);
      }
      if (f.status === 'fulfilled') push('fimAlerts', f.value.totalAlerts);
      if (a.status === 'fulfilled') {
        push('tarpit', a.value.metrics.honeypotTrappedCount);
        push('blocked', a.value.metrics.totalThreatsBlocked);
      }

      setError(failures.length === 4 ? failures[0] : null);
      setStale(failures.length > 0 && failures.length < 4);
      setLoading(false);
      tick.current++;
    },
    [push]
  );

  useEffect(() => {
    const ac = new AbortController();
    load(ac.signal);
    const id = setInterval(() => load(ac.signal), pollMs);
    return () => {
      ac.abort();
      clearInterval(id);
    };
  }, [load, pollMs]);

  const st = cluster?.statistics;
  return {
    loading,
    error,
    stale,
    ebpf: {
      packetsDropped: st?.totalPacketsDropped ?? null,
      observedPacketsDropped: st?.observedPacketsDropped ?? null,
      seededPacketsDropped: st?.seededPacketsDropped ?? null,
      kernelLatencyUs: st?.meanKernelLatencyUs ?? null,
      activeBlackholes: st?.activeBlackholesCount ?? null,
      anomalies: st?.anomaliesDetectedCount ?? null,
      provenance: st?.provenance ?? null
    },
    fim: {
      monitoredFiles: fim?.monitoredFilesCount ?? null,
      criticalAlerts: fim?.criticalAlerts ?? null,
      quarantined: fim?.quarantinedCount ?? null,
      active: fim?.active ?? null
    },
    tarpit: {
      trapped: agent?.metrics.honeypotTrappedCount ?? null,
      quarantinedIps: agent?.metrics.quarantinedIpsCount ?? null
    },
    inference: {
      engine: posture?.localEngine.name ?? null,
      signatures:
        posture?.localEngine.activeSignaturesCount ?? agent?.activeSignaturesCount ?? null,
      heapMb: posture?.processMemory.heapUsedMb ?? null,
      rssMb: posture?.processMemory.rssMb ?? null,
      evaluations: posture?.aiEvaluationsCount ?? agent?.metrics.aiEvaluationsCount ?? null,
      zeroExternalApiCalls: posture?.zeroExternalApiCalls ?? null,
      isSoleDetectionPath: posture?.localEngine.isSoleDetectionPath ?? null,
      externalProvider: posture?.externalModel.provider ?? null
    },
    nodes: cluster?.nodes ?? [],
    series,
    collecting: tick.current < 2,
    refresh: () => void load()
  };
}

/* ── Threat feed ─────────────────────────────────────────────────────────── */

export interface ThreatFeedState {
  loading: boolean;
  error: string | null;
  events: ThreatEvent[];
  emergencyLockdown: boolean;
  /** Ids seen for the first time in the latest poll — drives the row-entry glow. */
  freshIds: Set<string>;
  refresh: () => void;
}

export function useThreatFeed(pollMs = 6000): ThreatFeedState {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [events, setEvents] = useState<ThreatEvent[]>([]);
  const [lockdown, setLockdown] = useState(false);
  const [freshIds, setFreshIds] = useState<Set<string>>(new Set());
  const known = useRef<Set<string>>(new Set());
  const first = useRef(true);

  const load = useCallback(async (signal?: AbortSignal) => {
    try {
      const d = await getJson('/api/v1/soc/unified-telemetry', TimelineResponse, signal);
      const incoming = d.events ?? [];

      // On the very first load nothing is "new" — highlighting the whole table
      // on mount would be a fake arrival animation.
      const fresh = new Set<string>();
      if (!first.current) {
        for (const e of incoming) if (!known.current.has(e.id)) fresh.add(e.id);
      }
      for (const e of incoming) known.current.add(e.id);
      first.current = false;

      setEvents(incoming);
      setLockdown(Boolean(d.emergencyLockdown));
      setFreshIds(fresh);
      setError(null);
    } catch (e: any) {
      if (e?.name !== 'AbortError') setError(String(e?.message ?? e));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    const ac = new AbortController();
    load(ac.signal);
    const id = setInterval(() => load(ac.signal), pollMs);
    return () => {
      ac.abort();
      clearInterval(id);
    };
  }, [load, pollMs]);

  // Clear the highlight after the glow has decayed.
  useEffect(() => {
    if (!freshIds.size) return;
    const t = setTimeout(() => setFreshIds(new Set()), 2000);
    return () => clearTimeout(t);
  }, [freshIds]);

  return {
    loading,
    error,
    events,
    emergencyLockdown: lockdown,
    freshIds,
    refresh: () => void load()
  };
}

/* ── Isolation ───────────────────────────────────────────────────────────── */

/**
 * Host isolation against the real containment endpoints.
 *
 * `.clauderules` §8: a kill switch that animates without isolating is the worst
 * component this product could ship. So this calls `contain-ip`, reports what the
 * server actually returned, and exposes `release` because every isolation must
 * be reversible.
 */
export function useIsolation() {
  const [pending, setPending] = useState<string | null>(null);
  const [result, setResult] = useState<{ ok: boolean; message: string; target: string } | null>(
    null
  );

  const post = useCallback(async (path: string, body: unknown) => {
    const k = apiKey();
    const res = await fetch(path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...(k ? { 'x-api-key': k } : {}) },
      body: JSON.stringify(body)
    });
    const d = await res.json().catch(() => ({}));
    return { httpOk: res.ok, status: res.status, body: d };
  }, []);

  const isolate = useCallback(
    async (targetIp: string, reason = 'OPERATOR_INITIATED_ISOLATION') => {
      setPending(targetIp);
      setResult(null);
      try {
        const r = await post('/api/v1/soc/ebpf/contain-ip', { targetIp, reason });
        const ok = r.httpOk && r.body?.success !== false;
        setResult({
          ok,
          target: targetIp,
          message: ok
            ? String(r.body?.message ?? r.body?.record?.id ?? 'Containment rule installed.')
            : String(r.body?.error ?? r.body?.message ?? `HTTP ${r.status}`)
        });
        return ok;
      } catch (e: any) {
        setResult({ ok: false, target: targetIp, message: String(e?.message ?? e) });
        return false;
      } finally {
        setPending(null);
      }
    },
    [post]
  );

  const release = useCallback(
    async (targetIp: string) => {
      setPending(targetIp);
      try {
        const r = await post('/api/v1/soc/ebpf/release-ip', { targetIp });
        const ok = r.httpOk && r.body?.success !== false;
        setResult({
          ok,
          target: targetIp,
          message: ok ? 'Containment released.' : String(r.body?.error ?? `HTTP ${r.status}`)
        });
        return ok;
      } finally {
        setPending(null);
      }
    },
    [post]
  );

  return { isolate, release, pending, result, clearResult: () => setResult(null) };
}
