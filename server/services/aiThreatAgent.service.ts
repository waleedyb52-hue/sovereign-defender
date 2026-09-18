import crypto from 'crypto';
import { globalUnifiedTelemetryService } from './unifiedTelemetry.service';
import { globalHttpTrafficTelemetryService } from './httpTrafficTelemetry.service';
import { globalEbpfEngine } from '../ebpfEngine';
import { globalThreatIntelService } from './threatIntel.service.js';
import { globalForensicAgent } from './aiForensicsAgent.service.js';
import type { ReputationEnrichment, ForensicIncidentReport } from '../types/threatIntel.types.js';
import type {
  NetworkTelemetryPayload,
  NetworkProtocol,
  ThreatScore,
  ThreatScoreBreakdown,
  AgentAction,
  AIAnalysisReport
} from '../types/aiAgent.types';

// =============================================================================
// AI COGNITIVE THREAT AGENT (v1.0)
// Production-grade ingestion + heuristic analysis + autonomous mitigation
// engine for raw network telemetry submitted by external sensors (Scapy /
// Nmap / arbitrary packet-capture tooling) via POST /api/v1/soc/ingest-telemetry.
//
// Pipeline: ingest() -> analyzeContext() -> calculateThreatScore() -> decide()
//           -> execute() -> publish to Unified Telemetry Bus
// =============================================================================

const FREQUENCY_WINDOW_MS = 30_000; // 30s sliding window used for rate/DDoS analysis
const MAX_TRACKED_TIMESTAMPS_PER_IP = 500; // bounded so long-lived IP records can't leak memory
const CORRELATION_WINDOW_MS = 5 * 60_000; // group prior analyses for the same actor within 5 minutes
const MAX_ANALYSIS_HISTORY = 300;
/**
 * Alert-storm suppression: a sustained flood produces one decision per packet.
 * Publishing every one of them would evict all other subsystems' events from
 * the shared telemetry ring buffer, so repeat verdicts for the same
 * actor+action are collapsed into a single event carrying a suppressed count.
 * The full per-packet audit trail is still retained in analysisHistory.
 */
const PUBLISH_COOLDOWN_MS = 10_000;

// --- Kernel mitigation tuning (eBPF bridge) ---------------------------------
/** Score band that maps to RATE_LIMIT, used to scale throttle severity. */
const RATE_LIMIT_BAND_MIN = 21;
const RATE_LIMIT_BAND_MAX = 50;
/** Sustained packets/sec granted at the gentlest and harshest ends of the band. */
const RATE_LIMIT_MAX_PPS = 20;
const RATE_LIMIT_MIN_PPS = 2;
const RATE_LIMIT_TTL_SECONDS = 300; // 5 minutes
const NULL_ROUTE_TTL_SECONDS = 86_400; // 24 hours
const HONEYPOT_REDIRECT_TTL_SECONDS = 3_600; // 1 hour

/** Known-malicious payload signatures, ordered roughly by exploit severity. */
const MALICIOUS_SIGNATURES: Array<{ category: string; weight: number; pattern: RegExp }> = [
  { category: 'WEBSHELL_RCE', weight: 42, pattern: /(eval\(base64_decode|passthru\s*\(|system\s*\(|shell_exec\s*\(|assert\s*\()/i },
  { category: 'COMMAND_INJECTION', weight: 40, pattern: /(;\s*(rm|cat|wget|curl|nc|bash|sh)\s|\|\s*sh\b|`[^`]+`|\$\([^)]+\))/i },
  { category: 'SQL_INJECTION', weight: 38, pattern: /(\bunion\b\s+select\b|\bor\b\s*['"]?1['"]?\s*=\s*['"]?1|;\s*drop\s+table\b|\bxp_cmdshell\b|'\s*--)/i },
  { category: 'XSS', weight: 33, pattern: /(<script[^>]*>|onerror\s*=|onload\s*=|javascript:)/i },
  { category: 'PATH_TRAVERSAL', weight: 28, pattern: /(\.\.\/|\.\.\\|\/etc\/passwd|\/proc\/self\/environ)/i },
  { category: 'RECON_TOOL_SIGNATURE', weight: 20, pattern: /(sqlmap|nikto|nmap|masscan|dirbuster|hydra|gobuster)/i }
];

interface IpHistoryRecord {
  timestamps: number[];
  ports: Set<number>;
  lastSignatureCategory?: string;
}

interface AnalysisContext {
  now: number;
  requestsInWindow: number;
  distinctPortsSeen: number;
  signatureMatch?: { category: string; weight: number };
}

function generateIncidentId(): string {
  return `AI-${crypto.randomBytes(5).toString('hex').toUpperCase()}`;
}

// =============================================================================
// LAYER 1: THREAT ANALYZER - heuristic + pattern-matching cognition engine
// =============================================================================
class ThreatAnalyzer {
  private ipHistory: Map<string, IpHistoryRecord> = new Map();

  /** Records the payload into the rolling per-IP history and returns it. */
  public ingest(payload: NetworkTelemetryPayload): IpHistoryRecord {
    const now = this.resolveTimestamp(payload.timestamp);
    const record = this.ipHistory.get(payload.sourceIP) ?? { timestamps: [], ports: new Set<number>() };

    record.timestamps.push(now);
    if (record.timestamps.length > MAX_TRACKED_TIMESTAMPS_PER_IP) {
      record.timestamps.splice(0, record.timestamps.length - MAX_TRACKED_TIMESTAMPS_PER_IP);
    }
    record.ports.add(payload.port);

    this.ipHistory.set(payload.sourceIP, record);
    return record;
  }

  /** Derives contextual features (frequency, scanning behavior, signature hits) for scoring. */
  public analyzeContext(payload: NetworkTelemetryPayload, record: IpHistoryRecord): AnalysisContext {
    const now = this.resolveTimestamp(payload.timestamp);
    const windowStart = now - FREQUENCY_WINDOW_MS;
    const requestsInWindow = record.timestamps.filter(t => t >= windowStart).length;
    const distinctPortsSeen = record.ports.size;

    const signatureMatch = payload.payloadSignature
      ? MALICIOUS_SIGNATURES.find(sig => sig.pattern.test(payload.payloadSignature as string))
      : undefined;

    if (signatureMatch) {
      record.lastSignatureCategory = signatureMatch.category;
    }

    return {
      now,
      requestsInWindow,
      distinctPortsSeen,
      signatureMatch: signatureMatch ? { category: signatureMatch.category, weight: signatureMatch.weight } : undefined
    };
  }

  /** Combines every independent signal into a bounded, auditable 0-100 composite score. */
  public calculateThreatScore(payload: NetworkTelemetryPayload, context: AnalysisContext): ThreatScoreBreakdown {
    const frequencyScore = this.scoreFrequency(context.requestsInWindow);
    const signatureScore = context.signatureMatch ? context.signatureMatch.weight : 0;
    const portScanScore = this.scorePortScan(context.distinctPortsSeen);
    const packetAnomalyScore = this.scorePacketAnomaly(payload, context.requestsInWindow);

    const rawTotal = frequencyScore + signatureScore + portScanScore + packetAnomalyScore;
    const finalScore = Math.max(0, Math.min(100, Math.round(rawTotal)));

    return { frequencyScore, signatureScore, portScanScore, packetAnomalyScore, finalScore };
  }

  /** Linear ramp: <=2 req/s is background noise, >=40 req/s saturates the DDoS ceiling. */
  private scoreFrequency(requestsInWindow: number): number {
    const requestsPerSecond = requestsInWindow / (FREQUENCY_WINDOW_MS / 1000);
    if (requestsPerSecond <= 2) return 0;
    if (requestsPerSecond >= 40) return 40;
    return Math.round(((requestsPerSecond - 2) / (40 - 2)) * 40);
  }

  /** Linear ramp: <=3 distinct ports is normal client behavior, >=20 is a clear sweep. */
  private scorePortScan(distinctPorts: number): number {
    if (distinctPorts <= 3) return 0;
    if (distinctPorts >= 20) return 25;
    return Math.round(((distinctPorts - 3) / (20 - 3)) * 25);
  }

  /** Tiny packets arriving at high rate on a connection-oriented protocol resemble a SYN flood. */
  private scorePacketAnomaly(payload: NetworkTelemetryPayload, requestsInWindow: number): number {
    const isTinyPacket = payload.packetSize > 0 && payload.packetSize <= 64;
    const isHighRate = requestsInWindow >= 15;
    if (!isTinyPacket || !isHighRate) return 0;
    const connectionOriented: NetworkProtocol[] = ['TCP', 'UDP'];
    return connectionOriented.includes(payload.protocol) ? 15 : 8;
  }

  private resolveTimestamp(timestamp: string): number {
    const parsed = new Date(timestamp).getTime();
    return Number.isFinite(parsed) ? parsed : Date.now();
  }
}

// =============================================================================
// LAYER 2: DECISION ENGINE - autonomous action matrix + mitigation execution
// =============================================================================
class DecisionEngine {
  private rateLimitedIps: Map<string, number> = new Map(); // ip -> throttle expiry (epoch ms)
  private nullRoutedIps: Set<string> = new Set();

  public decide(score: ThreatScore): AgentAction {
    if (score >= 96) return 'TRIGGER_EMERGENCY_LOCKDOWN';
    if (score >= 81) return 'REDIRECT_TO_HONEYPOT';
    if (score >= 51) return 'NULL_ROUTE';
    if (score >= 21) return 'RATE_LIMIT';
    return 'ALLOW';
  }

  public execute(
    action: AgentAction,
    payload: NetworkTelemetryPayload,
    breakdown: ThreatScoreBreakdown
  ): { actionTaken: string; actionTakenAr: string } {
    switch (action) {
      case 'ALLOW':
        return this.executeAllow(payload);
      case 'RATE_LIMIT':
        return this.executeRateLimit(payload, breakdown);
      case 'NULL_ROUTE':
        return this.executeNullRoute(payload);
      case 'REDIRECT_TO_HONEYPOT':
        return this.executeRedirectToHoneypot(payload);
      case 'TRIGGER_EMERGENCY_LOCKDOWN':
        return this.executeEmergencyLockdown(payload, breakdown);
      default:
        return this.executeAllow(payload);
    }
  }

  private executeAllow(payload: NetworkTelemetryPayload): { actionTaken: string; actionTakenAr: string } {
    console.log(`[AI-AGENT] ALLOW ${payload.sourceIP} -> traffic pattern within normal baseline, no mitigation required.`);
    return { actionTaken: 'AI_AGENT_TRAFFIC_ALLOWED', actionTakenAr: 'تم السماح بالمرور الطبيعي بواسطة الوكيل الذكي' };
  }

  private executeRateLimit(
    payload: NetworkTelemetryPayload,
    breakdown: ThreatScoreBreakdown
  ): { actionTaken: string; actionTakenAr: string } {
    const throttledUntil = Date.now() + RATE_LIMIT_TTL_SECONDS * 1000;
    this.rateLimitedIps.set(payload.sourceIP, throttledUntil);

    // Throttle severity scales with the score: the top of the RATE_LIMIT band
    // is squeezed to a trickle, the bottom keeps near-normal throughput.
    const span = RATE_LIMIT_BAND_MAX - RATE_LIMIT_BAND_MIN;
    const position = Math.min(1, Math.max(0, (breakdown.finalScore - RATE_LIMIT_BAND_MIN) / span));
    const ratePps = Math.round(RATE_LIMIT_MAX_PPS - position * (RATE_LIMIT_MAX_PPS - RATE_LIMIT_MIN_PPS));
    const burstCapacity = ratePps * 2;

    // Kernel enforcement happens BEFORE the verdict reaches the telemetry bus.
    const enforcement = globalEbpfEngine.enforceRateLimit(
      payload.sourceIP,
      `AI Agent Token-Bucket Throttle (threat score ${breakdown.finalScore}/100)`,
      ratePps,
      burstCapacity,
      RATE_LIMIT_TTL_SECONDS
    );

    console.log(`[AI-AGENT] RATE_LIMIT token bucket armed in eBPF map for ${payload.sourceIP}: ${enforcement.ratePps} pps sustained / ${enforcement.burstCapacity} burst until ${enforcement.expiresAt}.`);
    return { actionTaken: 'AI_AGENT_RATE_LIMIT_ENFORCED', actionTakenAr: 'تم تفعيل تقييد المعدل بواسطة الوكيل الذكي' };
  }

  private executeNullRoute(payload: NetworkTelemetryPayload): { actionTaken: string; actionTakenAr: string } {
    // Idempotent: an already null-routed actor must not re-install the same
    // kernel rule on every subsequent packet of a sustained flood.
    if (!this.nullRoutedIps.has(payload.sourceIP)) {
      this.nullRoutedIps.add(payload.sourceIP);

      // Kernel enforcement first: pin XDP_DROP into the BPF map so the very
      // next packet is discarded at the driver, then record it downstream.
      const enforcement = globalEbpfEngine.enforceNullRoute(
        payload.sourceIP,
        'AI Agent Autonomous Null-Route: confirmed attack signature/behavior threshold exceeded.',
        NULL_ROUTE_TTL_SECONDS
      );

      globalHttpTrafficTelemetryService.banIp(
        payload.sourceIP,
        'AI Agent Autonomous Null-Route: confirmed attack signature/behavior threshold exceeded.',
        'حظر تلقائي بواسطة الوكيل الذكي: تجاوز عتبة السلوك الهجومي المؤكد.',
        'AI_AUTONOMOUS_AGENT'
      );
      console.log(`[AI-AGENT] NULL_ROUTE pinned into eBPF ${enforcement.map}: all packets from ${payload.sourceIP} dropped at XDP layer until ${enforcement.expiresAt}.`);
    }
    return { actionTaken: 'AI_AGENT_NULL_ROUTE_ENFORCED', actionTakenAr: 'تم تفعيل إسقاط الحزم الجذري بواسطة الوكيل الذكي' };
  }

  private executeRedirectToHoneypot(payload: NetworkTelemetryPayload): { actionTaken: string; actionTakenAr: string } {
    const enforcement = globalEbpfEngine.enforceHoneypotRedirect(
      payload.sourceIP,
      'AI Agent Deception Routing: advanced threat diverted for behavioral study.',
      HONEYPOT_REDIRECT_TTL_SECONDS
    );
    console.log(`[AI-AGENT] REDIRECT_TO_HONEYPOT installed in eBPF ${enforcement.map}: ${payload.sourceIP} diverted into the isolated deception environment until ${enforcement.expiresAt}.`);
    return { actionTaken: 'AI_AGENT_HONEYPOT_REDIRECTION', actionTakenAr: 'تمت إعادة توجيه المصدر إلى بيئة الخداع المعزولة' };
  }

  private executeEmergencyLockdown(
    payload: NetworkTelemetryPayload,
    breakdown: ThreatScoreBreakdown
  ): { actionTaken: string; actionTakenAr: string } {
    // Idempotent: only engage the infrastructure-wide lockdown once, and only
    // install the actor ban if it is not already null-routed.
    if (!globalUnifiedTelemetryService.isEmergencyLockdownActive()) {
      // Flip the kernel gate first so traffic stops at the driver immediately,
      // then mirror the state into the application-layer lockdown flag.
      globalEbpfEngine.enforceEmergencyLockdown(
        true,
        `AI Agent Emergency Lockdown: zero-day/critical breach from ${payload.sourceIP} (score ${breakdown.finalScore}/100)`
      );
      globalUnifiedTelemetryService.setEmergencyLockdown(true);
      console.log(`[AI-AGENT] TRIGGER_EMERGENCY_LOCKDOWN: critical breach score ${breakdown.finalScore}/100 from ${payload.sourceIP}. Infrastructure-wide lockdown engaged.`);
    }
    if (!this.nullRoutedIps.has(payload.sourceIP)) {
      this.nullRoutedIps.add(payload.sourceIP);
      globalEbpfEngine.enforceNullRoute(
        payload.sourceIP,
        `AI Agent Emergency Lockdown Trigger: zero-day/critical breach behavior (score ${breakdown.finalScore}/100).`,
        NULL_ROUTE_TTL_SECONDS
      );
      globalHttpTrafficTelemetryService.banIp(
        payload.sourceIP,
        `AI Agent Emergency Lockdown Trigger: zero-day/critical breach behavior detected (score ${breakdown.finalScore}/100).`,
        'تفعيل الإغلاق الطارئ للبنية التحتية بواسطة الوكيل الذكي: رصد سلوك اختراق حرج.',
        'AI_AUTONOMOUS_AGENT'
      );
    }
    return { actionTaken: 'AI_AGENT_EMERGENCY_LOCKDOWN_TRIGGERED', actionTakenAr: 'تم تفعيل الإغلاق الطارئ الشامل للبنية التحتية' };
  }

  public isRateLimited(ip: string): boolean {
    const until = this.rateLimitedIps.get(ip);
    return !!until && until > Date.now();
  }

  public isNullRouted(ip: string): boolean {
    return this.nullRoutedIps.has(ip);
  }
}

// =============================================================================
// TOP-LEVEL SERVICE: wires ingestion -> analysis -> decision -> telemetry bus
// =============================================================================
class AIThreatAgentService {
  private readonly analyzer = new ThreatAnalyzer();
  private readonly decisionEngine = new DecisionEngine();
  private analysisHistory: AIAnalysisReport[] = [];
  /** incidentId -> intelligence context, so the SOC can join a verdict to its enrichment. */
  private lastEnrichment: Map<string, {
    reputation: ReputationEnrichment;
    compositeScore: number;
    forensicIncidentId: string | null;
  }> = new Map();
  /** `${sourceIP}::${action}` -> last publish time + verdicts suppressed since then. */
  private publishThrottle: Map<string, { lastPublishedAt: number; suppressedCount: number }> = new Map();

  /**
   * Full cognitive pipeline for one telemetry event. Never throws for
   * malformed input beyond a single descriptive Error - callers (the
   * ingestion route) are expected to catch and translate that into a 400
   * response so a bad packet from a sensor can never take the process down.
   */
  public processTelemetry(rawPayload: unknown): AIAnalysisReport {
    const payload = this.validateAndNormalize(rawPayload);

    let breakdown: ThreatScoreBreakdown;
    let action: AgentAction;
    let executionResult: { actionTaken: string; actionTakenAr: string };

    try {
      const record = this.analyzer.ingest(payload);
      const context = this.analyzer.analyzeContext(payload, record);
      breakdown = this.analyzer.calculateThreatScore(payload, context);

      // --- THREAT INTELLIGENCE ENRICHMENT ---------------------------
      // Resolved before the DecisionEngine runs so the verdict is driven by
      // the reputation-weighted composite score rather than behavior alone.
      // The hub is synchronous and breaker-guarded, so a degraded upstream
      // feed can never add latency here or block the mitigation path.
      const intel = globalThreatIntelService.lookup(payload.sourceIP, 'IPV4');
      const composite = globalThreatIntelService.computeCompositeScore(
        breakdown.finalScore,
        intel.reputation
      );

      // The composite never de-escalates a behavioral verdict: reputation can
      // only corroborate an attack, never vouch for one already in progress.
      const effectiveScore = Math.max(breakdown.finalScore, Math.round(composite.compositeScore));

      action = this.decisionEngine.decide(effectiveScore);
      executionResult = this.decisionEngine.execute(action, payload, breakdown);

      const report = this.buildReport(payload, context, breakdown, action);
      this.recordAnalysis(report);
      this.publishToUnifiedTelemetry(payload, report, executionResult);

      // --- AUTONOMOUS FORENSIC INVESTIGATION ------------------------
      // Runs after enforcement and telemetry so a forensic failure can never
      // delay a mitigation or suppress the alert. Returns null below the
      // escalation bar, so it is safe to call unconditionally.
      const forensicReport = globalForensicAgent.investigate({
        incidentId: report.incidentId,
        payload,
        behavioralScore: breakdown.finalScore,
        compositeScore: composite.compositeScore,
        chosenAction: action,
        reputation: intel.reputation,
        remediationsEnforced: [executionResult.actionTaken]
      });

      this.lastEnrichment.set(report.incidentId, {
        reputation: intel.reputation,
        compositeScore: composite.compositeScore,
        forensicIncidentId: forensicReport ? forensicReport.incidentId : null
      });
      this.trimEnrichmentCache();

      return report;
    } catch (err: any) {
      // Analysis-layer failure (should be rare given the guards above) -
      // log it and degrade gracefully rather than crashing the ingestion route.
      console.warn(`[AI-AGENT] Analysis pipeline error for ${payload.sourceIP}:`, err?.message || err);
      throw new Error(`AI analysis pipeline failed: ${err?.message || 'unknown error'}`);
    }
  }

  /**
   * Bounds the enrichment side-table to the same horizon as analysisHistory,
   * so a sustained flood cannot grow it without limit.
   */
  private trimEnrichmentCache(): void {
    if (this.lastEnrichment.size <= MAX_ANALYSIS_HISTORY) return;
    const excess = this.lastEnrichment.size - MAX_ANALYSIS_HISTORY;
    let removed = 0;
    for (const key of this.lastEnrichment.keys()) {
      this.lastEnrichment.delete(key);
      if (++removed >= excess) break;
    }
  }

  /** Intelligence context recorded alongside one verdict, if still retained. */
  public getEnrichmentFor(incidentId: string): {
    reputation: ReputationEnrichment;
    compositeScore: number;
    forensicIncidentId: string | null;
  } | null {
    return this.lastEnrichment.get(incidentId) ?? null;
  }

  /** Sealed forensic report for one incident, when an investigation was opened. */
  public getForensicReport(incidentId: string): ForensicIncidentReport | null {
    return globalForensicAgent.getReport(incidentId);
  }

  public getRecentAnalyses(limit: number = 50): AIAnalysisReport[] {
    return this.analysisHistory.slice(0, Math.max(1, Math.min(limit, MAX_ANALYSIS_HISTORY)));
  }

  /**
   * The eBPF map is the authoritative record of what is actually enforced -
   * it applies TTL expiry and LRU eviction that the agent's own bookkeeping
   * does not - so kernel state wins whenever the two could disagree.
   */
  public isIpRateLimited(ip: string): boolean {
    return globalEbpfEngine.getMitigationState(ip).rateLimited;
  }

  public isIpNullRouted(ip: string): boolean {
    return globalEbpfEngine.isNullRouted(ip);
  }

  /** Full kernel-layer mitigation posture for one actor. */
  public getKernelMitigationState(ip: string) {
    return globalEbpfEngine.getMitigationState(ip);
  }

  // ---------------------------------------------------------------------
  // Validation (Step 2 hardening: never let malformed JSON reach the analyzer)
  // ---------------------------------------------------------------------
  private validateAndNormalize(raw: unknown): NetworkTelemetryPayload {
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
      throw new Error('Telemetry payload must be a single JSON object.');
    }
    const r = raw as Record<string, unknown>;

    if (typeof r.sourceIP !== 'string' || !r.sourceIP.trim()) {
      throw new Error('"sourceIP" (string) is required.');
    }
    if (typeof r.destinationIP !== 'string' || !r.destinationIP.trim()) {
      throw new Error('"destinationIP" (string) is required.');
    }

    const validProtocols: NetworkProtocol[] = ['TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS', 'DNS'];
    const protocolCandidate = typeof r.protocol === 'string' ? r.protocol.toUpperCase() : '';
    if (!validProtocols.includes(protocolCandidate as NetworkProtocol)) {
      throw new Error(`"protocol" must be one of: ${validProtocols.join(', ')}.`);
    }

    const port = Number(r.port);
    if (!Number.isFinite(port) || port < 0 || port > 65535) {
      throw new Error('"port" must be a number between 0 and 65535.');
    }

    const packetSize = Number(r.packetSize);
    if (!Number.isFinite(packetSize) || packetSize < 0) {
      throw new Error('"packetSize" must be a non-negative number.');
    }

    const timestamp = typeof r.timestamp === 'string' && !Number.isNaN(new Date(r.timestamp).getTime())
      ? r.timestamp
      : new Date().toISOString();

    return {
      sourceIP: r.sourceIP.trim(),
      destinationIP: r.destinationIP.trim(),
      protocol: protocolCandidate as NetworkProtocol,
      port,
      packetSize,
      payloadSignature: typeof r.payloadSignature === 'string' ? r.payloadSignature.slice(0, 4000) : undefined,
      timestamp
    };
  }

  // ---------------------------------------------------------------------
  // Report construction
  // ---------------------------------------------------------------------
  private buildReport(
    payload: NetworkTelemetryPayload,
    context: AnalysisContext,
    breakdown: ThreatScoreBreakdown,
    action: AgentAction
  ): AIAnalysisReport {
    const correlatedEvents = this.analysisHistory
      .filter(r => r.sourceIP === payload.sourceIP && (Date.now() - new Date(r.timestamp).getTime()) <= CORRELATION_WINDOW_MS)
      .slice(0, 5)
      .map(r => r.incidentId);

    return {
      incidentId: generateIncidentId(),
      correlatedEvents,
      threatScore: breakdown.finalScore,
      scoreBreakdown: breakdown,
      chosenAction: action,
      confidenceLevel: this.calculateConfidence(breakdown),
      reasoning: this.buildReasoning(payload, context, breakdown, action),
      reasoningAr: this.buildReasoningAr(payload, breakdown, action),
      sourceIP: payload.sourceIP,
      timestamp: new Date().toISOString()
    };
  }

  /** More independent signals firing in agreement -> higher confidence in the verdict. */
  private calculateConfidence(breakdown: ThreatScoreBreakdown): number {
    const activeSignals = [breakdown.frequencyScore, breakdown.signatureScore, breakdown.portScanScore, breakdown.packetAnomalyScore]
      .filter(score => score > 0).length;
    const baseline = 0.55;
    const perSignalBonus = 0.14;
    return Math.min(0.98, Math.round((baseline + activeSignals * perSignalBonus) * 100) / 100);
  }

  private buildReasoning(
    payload: NetworkTelemetryPayload,
    context: AnalysisContext,
    breakdown: ThreatScoreBreakdown,
    action: AgentAction
  ): string {
    const windowSeconds = FREQUENCY_WINDOW_MS / 1000;
    const parts: string[] = [
      `Source ${payload.sourceIP} generated ${context.requestsInWindow} requests in the last ${windowSeconds}s window (frequency score ${breakdown.frequencyScore}/40).`
    ];
    if (breakdown.signatureScore > 0 && context.signatureMatch) {
      parts.push(`Payload matched a known ${context.signatureMatch.category} signature (signature score ${breakdown.signatureScore}).`);
    }
    if (breakdown.portScanScore > 0) {
      parts.push(`Actor has touched ${context.distinctPortsSeen} distinct ports, consistent with reconnaissance/port-scanning (score ${breakdown.portScanScore}/25).`);
    }
    if (breakdown.packetAnomalyScore > 0) {
      parts.push(`Packet size (${payload.packetSize}B) combined with elevated request rate resembles a flood/DoS pattern (score ${breakdown.packetAnomalyScore}/15).`);
    }
    parts.push(`Composite threat score: ${breakdown.finalScore}/100 -> autonomous decision: ${action}.`);
    return parts.join(' ');
  }

  private buildReasoningAr(payload: NetworkTelemetryPayload, breakdown: ThreatScoreBreakdown, action: AgentAction): string {
    return `قام الوكيل الذكي بتحليل حركة المرور القادمة من ${payload.sourceIP} وحدد نتيجة تهديد إجمالية بلغت ${breakdown.finalScore}/100، `
      + `مما استوجب اتخاذ قرار تلقائي: ${action}.`;
  }

  private recordAnalysis(report: AIAnalysisReport): void {
    this.analysisHistory.unshift(report);
    if (this.analysisHistory.length > MAX_ANALYSIS_HISTORY) {
      this.analysisHistory.length = MAX_ANALYSIS_HISTORY;
    }
  }

  // ---------------------------------------------------------------------
  // Step 5: push the finalized decision onto the Unified Telemetry Bus so
  // the SOC dashboard (BlueTeamConsole / ThreatIncidentTimeline) reflects
  // the exact autonomous action the AI agent took, in real time.
  // ---------------------------------------------------------------------
  private publishToUnifiedTelemetry(
    payload: NetworkTelemetryPayload,
    report: AIAnalysisReport,
    executionResult: { actionTaken: string; actionTakenAr: string }
  ): void {
    const throttleKey = `${payload.sourceIP}::${report.chosenAction}`;
    const now = Date.now();
    const throttleState = this.publishThrottle.get(throttleKey);

    if (throttleState && now - throttleState.lastPublishedAt < PUBLISH_COOLDOWN_MS) {
      // Same verdict for the same actor inside the cooldown: collapse it.
      throttleState.suppressedCount += 1;
      return;
    }

    const suppressedDuplicates = throttleState?.suppressedCount ?? 0;
    this.publishThrottle.set(throttleKey, { lastPublishedAt: now, suppressedCount: 0 });

    const suppressionNote = suppressedDuplicates > 0
      ? ` (${suppressedDuplicates} further identical verdicts suppressed in the last ${PUBLISH_COOLDOWN_MS / 1000}s)`
      : '';

    globalUnifiedTelemetryService.recordEvent({
      source: 'AI_DEFENSE',
      severity: this.mapScoreToSeverity(report.threatScore),
      title: `[AI Agent] ${report.chosenAction} decision for ${payload.sourceIP} (Score: ${report.threatScore}/100)`,
      titleAr: `[الوكيل الذكي] قرار ${report.chosenAction} بخصوص ${payload.sourceIP} (النتيجة: ${report.threatScore}/100)`,
      details: report.reasoning + suppressionNote,
      detailsAr: report.reasoningAr,
      actorIp: payload.sourceIP,
      mitreTactic: this.mapActionToMitreTactic(report.chosenAction),
      mitreTechnique: this.mapReportToMitreTechnique(report),
      actionTaken: executionResult.actionTaken,
      actionTakenAr: executionResult.actionTakenAr,
      metadata: {
        incidentId: report.incidentId,
        correlatedEvents: report.correlatedEvents,
        suppressedDuplicates,
        threatScore: report.threatScore,
        confidenceLevel: report.confidenceLevel,
        scoreBreakdown: report.scoreBreakdown,
        protocol: payload.protocol,
        port: payload.port,
        destinationIP: payload.destinationIP,
        packetSize: payload.packetSize
      }
    });
  }

  private mapScoreToSeverity(score: ThreatScore): 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO' {
    if (score >= 81) return 'CRITICAL';
    if (score >= 51) return 'HIGH';
    if (score >= 21) return 'MEDIUM';
    return 'INFO';
  }

  private mapActionToMitreTactic(action: AgentAction): string {
    switch (action) {
      case 'TRIGGER_EMERGENCY_LOCKDOWN': return 'Impact';
      case 'REDIRECT_TO_HONEYPOT': return 'Defense Evasion';
      case 'NULL_ROUTE': return 'Command and Control';
      case 'RATE_LIMIT': return 'Discovery';
      default: return 'Reconnaissance';
    }
  }

  private mapReportToMitreTechnique(report: AIAnalysisReport): string {
    if (report.scoreBreakdown.signatureScore > 0) return 'T1190 - Exploit Public-Facing Application';
    if (report.scoreBreakdown.portScanScore > 0) return 'T1595.001 - Scanning IP Blocks';
    if (report.scoreBreakdown.packetAnomalyScore > 0) return 'T1498 - Network Denial of Service';
    return 'T1071 - Application Layer Protocol';
  }
}

export const globalAIThreatAgentService = new AIThreatAgentService();
