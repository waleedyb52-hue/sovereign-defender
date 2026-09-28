import { useCallback, useEffect, useState } from 'react';
import { z } from 'zod';

/**
 * SECURITY ARSENAL SOURCES
 *
 * The six arsenal modules, each wired to endpoints the backend already serves. None of
 * this is new capability; it is the first time these feeds are read from one place
 * instead of from the console page each was written for.
 *
 *   eBPF / XDP        /ebpf/real-stats           ring-0 counters, latency, throughput
 *   AI WAF L7         /traffic/waf/metrics       rule state, drops
 *                     /soc/ai-agent/analyses     per-payload verdicts and confidence
 *                     /safeguards/stats          FP protections, injections neutralised
 *   FIM               /fim/files                 real SHA-256 per monitored file
 *                     /fim/merkle-status         Merkle root over the monitored set
 *   Scanners          /scanner/history           completed audits, ports, findings
 *   Threat intel      /forensics/threat-intel/iocs   the local IOC store
 *                     /soc/threat-intel/stats    external source breaker state
 *                     /honeypot/sessions         decoy sessions (seeded fixtures on boot)
 *                     /soc/deception/entrapped   actors the shadow router diverted
 *   ZTNA              /insider-zero-trust/actions    privileged actions and verdicts
 *                     /mitigation/status         progressive tiers, active hard bans
 *
 * Three things this hook refuses to smooth over, because the modules would otherwise
 * assert more than the platform knows:
 *
 *   The eBPF driver reports CONTAINER_EMULATION on this host. Its counters are
 *   therefore emulated, and `ebpfEmulated` is exposed so each figure can be labelled.
 *   Latency of 350ns from an emulation layer is not a kernel measurement, and printing
 *   it in neon beside a real RPS is how a demo becomes a false claim.
 *
 *   The IOC store is LOCAL. The design brief asked for a live STIX/TAXII ticker, and
 *   this platform is zero-egress by construction — `zeroExternalApiCalls` is one of its
 *   compliance claims. So the ticker shows the local store and the external sources'
 *   breaker state side by side, with the lookup count, which on this host is zero. A
 *   ticker that implied a live external feed would contradict the platform's own
 *   sovereignty claim, which is a worse defect than an empty ticker.
 *
 *   FIM watches a real directory, and it is not /etc/shadow. The monitored root is
 *   surfaced verbatim so the terminal cannot be mistaken for system-wide coverage.
 */

const num = z.number().nullish();
const str = z.string().nullish();

const EbpfStats = z.object({
  stats: z.object({
    rxPackets: num, rxBytes: num, droppedPackets: num, droppedBytes: num,
    passedPackets: num, passedBytes: num, activeBlacklistEntries: num,
    throughputGbps: num, throughputPps: num, avgLatencyNs: num,
    driverMode: str, interfaceName: str, kernelPinnedMapPath: str, lastUpdated: str
  })
});

const WafMetrics = z.object({
  metrics: z.object({
    rps: num, totalRequests: num, droppedPackets: num, ebpfLatencyUs: num,
    activeBlockedSubnetsCount: num,
    wafConfig: z.record(z.string(), z.union([z.boolean(), z.number()])).nullish()
  })
});

const AiAnalyses = z.object({
  total: num,
  analyses: z.array(z.object({
    id: str, timestamp: str, verdict: str, threatType: str,
    confidence: num, payloadExcerpt: str, sourceIp: str, mitreId: str, action: str
  }).partial()).default([])
});

const Safeguards = z.object({
  promptInjectionsNeutralized: num,
  tier2DegradedFalsePositiveProtections: num,
  selfDosEarlyDropsCount: num,
  confidenceThresholdTier3Required: num
}).partial();

const FimFiles = z.object({
  files: z.array(z.object({
    path: z.string(), name: str, sizeBytes: num, lastModified: str,
    sha256: str, status: str, category: str
  })).default([])
});

const FimMerkle = z.object({
  merkle: z.object({
    merkleRootHash: str, lastCalculated: str, leafNodesCount: num, algorithm: str
  })
});

const ScanHistory = z.object({
  history: z.array(z.object({
    id: str, startedAt: str, target: str, openPorts: z.array(z.any()).nullish(),
    findings: z.array(z.any()).nullish(), severityCounts: z.record(z.string(), z.number()).nullish()
  }).passthrough()).default([])
});

const Iocs = z.object({
  iocs: z.array(z.object({
    id: z.string(), type: str, value: str, threatActor: str, malwareFamily: str,
    threatScore: num, severity: str, firstSeen: str, lastSeen: str,
    mitreTactic: str, mitreTechnique: str, description: str
  })).default([])
});

const TiStats = z.object({
  cache: z.object({ entries: num, hits: num, misses: num, hitRatePercent: num }).partial(),
  breakers: z.array(z.object({
    source: z.string(), state: str, consecutiveFailures: num, totalFailures: num, totalSuccesses: num
  })).default([]),
  totalLookups: num,
  degradedLookups: num
});

// The server sends each captured command as { cmd, time, decoyResponse, riskLevel }.
// This was declared as string[], so every response failed validation and the source
// was reported silent. Both shapes are accepted now.
const CapturedCommand = z.union([
  z.string(),
  z.object({ cmd: z.string(), time: str, riskLevel: str }).passthrough()
]);

const Honeypot = z.object({
  totalTrappedCount: num,
  sessions: z.array(z.object({
    sessionId: z.string(), attackerIp: str, decoyService: str, connectedAt: str,
    lastActivityAt: str, keystrokesCount: num,
    capturedCommands: z.array(CapturedCommand).nullish(),
    decoyCanariesTripped: z.array(z.any()).nullish(), status: str
  })).default([])
});

/** Actors the shadow router diverted from live traffic into a decoy. */
const Entrapped = z.object({
  entrapped: z.array(z.object({
    sessionId: z.string(), actorIp: str, divertedAt: num, lastInteractionAt: num,
    interactions: num, intentScoreAtDiversion: num, sophisticationBand: str,
    techniques: z.array(z.string()).nullish(),
    canaries: z.array(z.object({ kind: str, redeemed: z.boolean().nullish() }).partial()).nullish()
  })).default([]),
  stats: z.object({
    router: z.object({ activeSessions: num, totalDiverted: num, totalInteractions: num }).partial().nullish()
  }).partial().nullish()
});

const Ztna = z.object({
  totalActions: num,
  pendingFrozenCount: num,
  actions: z.array(z.object({
    id: z.string(), timestamp: str, actionType: str, targetResource: str,
    commandSnippet: str, riskScore: num, status: str,
    actor: z.record(z.string(), z.any()).nullish()
  })).default([])
});

const Mitigation = z.object({
  metrics: z.object({
    tier1RateLimitedCount: num, tier2ChallengedCount: num, tier3CriticalBlockedCount: num,
    activeTier1Sessions: num, activeTier2Challenges: num, activeTier3HardBans: num
  }).partial()
});

async function get<T>(path: string, schema: z.ZodType<T>, key?: string): Promise<T> {
  const res = await fetch(path, { headers: key ? { 'x-api-key': key } : undefined });
  if (!res.ok) throw new Error(`${path} -> ${res.status}`);
  return schema.parse(await res.json());
}

const A = '/api/v1';

export function useArsenal(apiKey?: string, pollMs = 6000) {
  const [s, setS] = useState<{
    ebpf?: z.infer<typeof EbpfStats>; waf?: z.infer<typeof WafMetrics>;
    ai?: z.infer<typeof AiAnalyses>; safe?: z.infer<typeof Safeguards>;
    fim?: z.infer<typeof FimFiles>; merkle?: z.infer<typeof FimMerkle>;
    scans?: z.infer<typeof ScanHistory>; iocs?: z.infer<typeof Iocs>;
    ti?: z.infer<typeof TiStats>; hp?: z.infer<typeof Honeypot>;
    dec?: z.infer<typeof Entrapped>;
    zt?: z.infer<typeof Ztna>; mit?: z.infer<typeof Mitigation>;
  }>({});
  const [missing, setMissing] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
  /** Wall-clock of the last completed poll, so consumers can sample once per poll. */
  const [loadedAt, setLoadedAt] = useState<number | null>(null);

  const load = useCallback(async () => {
    const jobs = [
      ['ebpf', '/ebpf/real-stats', get(`${A}/ebpf/real-stats`, EbpfStats, apiKey)],
      ['waf', '/traffic/waf/metrics', get(`${A}/traffic/waf/metrics`, WafMetrics, apiKey)],
      ['ai', '/soc/ai-agent/analyses', get(`${A}/soc/ai-agent/analyses`, AiAnalyses, apiKey)],
      ['safe', '/safeguards/stats', get(`${A}/safeguards/stats`, Safeguards, apiKey)],
      ['fim', '/fim/files', get(`${A}/fim/files`, FimFiles, apiKey)],
      ['merkle', '/fim/merkle-status', get(`${A}/fim/merkle-status`, FimMerkle, apiKey)],
      ['scans', '/scanner/history', get(`${A}/scanner/history`, ScanHistory, apiKey)],
      ['iocs', '/forensics/threat-intel/iocs', get(`${A}/forensics/threat-intel/iocs`, Iocs, apiKey)],
      ['ti', '/soc/threat-intel/stats', get(`${A}/soc/threat-intel/stats`, TiStats, apiKey)],
      ['hp', '/honeypot/sessions', get(`${A}/honeypot/sessions`, Honeypot, apiKey)],
      ['dec', '/soc/deception/entrapped', get(`${A}/soc/deception/entrapped`, Entrapped, apiKey)],
      ['zt', '/insider-zero-trust/actions', get(`${A}/insider-zero-trust/actions`, Ztna, apiKey)],
      ['mit', '/mitigation/status', get(`${A}/mitigation/status`, Mitigation, apiKey)]
    ] as const;

    const settled = await Promise.allSettled(jobs.map(j => j[2]));
    const failed: string[] = [];
    const next: Record<string, unknown> = {};

    settled.forEach((res, i) => {
      if (res.status === 'rejected') failed.push(jobs[i][1]);
      else next[jobs[i][0]] = res.value;
    });

    setS(prev => ({ ...prev, ...next }));
    setMissing(failed);
    setLoading(false);
    setLoadedAt(Date.now());
  }, [apiKey]);

  useEffect(() => {
    load();
    const t = setInterval(load, pollMs);
    return () => clearInterval(t);
  }, [load, pollMs]);

  const e = s.ebpf?.stats;
  const cfg = s.waf?.metrics.wafConfig ?? null;
  const rules = cfg
    ? Object.entries(cfg).filter(([, v]) => typeof v === 'boolean').map(([name, v]) => ({ name, on: v === true }))
    : [];

  /**
   * True when the kernel path is emulated rather than native, which is what the
   * driver itself reports. Every eBPF figure is labelled from this rather than from a
   * guess about the host, so the label follows the driver if the host changes.
   */
  const ebpfEmulated = e?.driverMode != null && /EMULAT|SIMUL/i.test(e.driverMode);

  return {
    loading,
    missing,
    loadedAt,
    refresh: () => void load(),

    ebpf: {
      rxPackets: e?.rxPackets ?? null,
      dropped: e?.droppedPackets ?? null,
      passed: e?.passedPackets ?? null,
      blacklist: e?.activeBlacklistEntries ?? null,
      throughputPps: e?.throughputPps ?? null,
      throughputGbps: e?.throughputGbps ?? null,
      latencyNs: e?.avgLatencyNs ?? null,
      driverMode: e?.driverMode ?? null,
      iface: e?.interfaceName ?? null,
      pinnedMap: e?.kernelPinnedMapPath ?? null,
      emulated: ebpfEmulated,
      dropRatio:
        e?.rxPackets && e.rxPackets > 0 && e.droppedPackets != null
          ? e.droppedPackets / e.rxPackets
          : null
    },

    // `rps` and `ebpfLatencyUs` from /traffic/waf/metrics are not forwarded: the service
    // returns `38 + Math.random() * 12` and `0.38 + Math.random() * 0.12` for them. A real
    // request rate is derived from deltas in useCyberDefendData (`derived.requestRate`).
    waf: {
      totalRequests: s.waf?.metrics.totalRequests ?? null,
      dropped: s.waf?.metrics.droppedPackets ?? null,
      blockedSubnets: s.waf?.metrics.activeBlockedSubnetsCount ?? null,
      rules,
      rulesOn: rules.length ? rules.filter(r => r.on).length : null,
      rulesTotal: rules.length || null,
      injectionsNeutralized: s.safe?.promptInjectionsNeutralized ?? null,
      fpProtections: s.safe?.tier2DegradedFalsePositiveProtections ?? null,
      selfDosDrops: s.safe?.selfDosEarlyDropsCount ?? null,
      tier3Threshold: s.safe?.confidenceThresholdTier3Required ?? null,
      analysesTotal: s.ai?.total ?? null,
      analyses: (s.ai?.analyses ?? []).map(a => ({
        id: a.id ?? null,
        at: a.timestamp ?? null,
        verdict: a.verdict ?? null,
        threatType: a.threatType ?? null,
        confidence: a.confidence ?? null,
        excerpt: a.payloadExcerpt ?? null,
        srcIp: a.sourceIp ?? null,
        mitre: a.mitreId ?? null,
        action: a.action ?? null
      }))
    },

    fim: {
      files: (s.fim?.files ?? []).map(f => ({
        path: f.path,
        name: f.name ?? f.path.split(/[\\/]/).pop() ?? f.path,
        sha256: f.sha256 ?? null,
        status: f.status ?? null,
        category: f.category ?? null,
        sizeBytes: f.sizeBytes ?? null,
        lastModified: f.lastModified ?? null
      })),
      merkleRoot: s.merkle?.merkle.merkleRootHash || null,
      merkleLeaves: s.merkle?.merkle.leafNodesCount ?? null,
      merkleAt: s.merkle?.merkle.lastCalculated ?? null,
      algorithm: s.merkle?.merkle.algorithm ?? null
    },

    scans: {
      history: s.scans?.history ?? [],
      count: s.scans?.history.length ?? null
    },

    intel: {
      iocs: (s.iocs?.iocs ?? []).map(i => ({
        id: i.id,
        type: i.type ?? null,
        value: i.value ?? null,
        actor: i.threatActor ?? null,
        family: i.malwareFamily ?? null,
        score: i.threatScore ?? null,
        severity: i.severity ?? null,
        tactic: i.mitreTactic ?? null,
        technique: i.mitreTechnique ?? null
      })),
      breakers: (s.ti?.breakers ?? []).map(b => ({
        source: b.source,
        state: b.state ?? null,
        failures: b.totalFailures ?? null,
        successes: b.totalSuccesses ?? null
      })),
      // Zero here is the sovereignty claim holding, not a broken feed.
      totalLookups: s.ti?.totalLookups ?? null,
      cacheEntries: s.ti?.cache.entries ?? null,
      honeypotTrapped: s.hp?.totalTrappedCount ?? null,
      sessions: (s.hp?.sessions ?? []).map(h => ({
        id: h.sessionId,
        ip: h.attackerIp ?? null,
        service: h.decoyService ?? null,
        keystrokes: h.keystrokesCount ?? null,
        commands: (h.capturedCommands ?? []).map(c =>
          typeof c === 'string'
            ? { cmd: c, risk: null, time: null }
            : { cmd: c.cmd, risk: c.riskLevel ?? null, time: c.time ?? null }
        ),
        canaries: (h.decoyCanariesTripped ?? []).length,
        status: h.status ?? null,
        at: h.connectedAt ?? null,
        lastAt: h.lastActivityAt ?? null
      })),
      shadow: {
        diverted: s.dec?.stats?.router?.totalDiverted ?? null,
        interactions: s.dec?.stats?.router?.totalInteractions ?? null,
        actors: (s.dec?.entrapped ?? []).map(e => ({
          id: e.sessionId,
          ip: e.actorIp ?? null,
          divertedAt: e.divertedAt ?? null,
          lastAt: e.lastInteractionAt ?? null,
          interactions: e.interactions ?? null,
          intent: e.intentScoreAtDiversion ?? null,
          band: e.sophisticationBand ?? null,
          technique: e.techniques?.[0] ?? null,
          canariesRedeemed: (e.canaries ?? []).filter(c => c.redeemed).length
        }))
      }
    },

    ztna: {
      total: s.zt?.totalActions ?? null,
      pendingFrozen: s.zt?.pendingFrozenCount ?? null,
      actions: (s.zt?.actions ?? []).map(a => ({
        id: a.id,
        at: a.timestamp ?? null,
        kind: a.actionType ?? null,
        target: a.targetResource ?? null,
        snippet: a.commandSnippet ?? null,
        risk: a.riskScore ?? null,
        status: a.status ?? null,
        actor: (a.actor?.username ?? a.actor?.name ?? a.actor?.id ?? null) as string | null
      })),
      tier1: s.mit?.metrics.tier1RateLimitedCount ?? null,
      tier2: s.mit?.metrics.tier2ChallengedCount ?? null,
      tier3: s.mit?.metrics.tier3CriticalBlockedCount ?? null,
      activeHardBans: s.mit?.metrics.activeTier3HardBans ?? null,
      activeChallenges: s.mit?.metrics.activeTier2Challenges ?? null
    }
  };
}

export default useArsenal;
