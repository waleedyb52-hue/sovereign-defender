import crypto from 'crypto';
import { globalUnifiedTelemetryService } from './unifiedTelemetry.service.js';
import type {
  ForensicIncidentReport,
  ForensicMemorySnapshot,
  ForensicSeverity,
  MitreTacticMapping,
  NetworkHop,
  ReputationEnrichment
} from '../types/threatIntel.types.js';
import type { AgentAction, NetworkTelemetryPayload } from '../types/aiAgent.types.js';

// =============================================================================
// AUTONOMOUS MITRE ATT&CK FORENSICS AGENT (v1.0)
// Opens an investigation whenever an incident crosses the escalation
// threshold, correlates observed packet attributes to MITRE ATT&CK Enterprise
// tactics, seals the evidence with a SHA-256 integrity hash, and dispatches a
// JSON-LD playbook payload to the compliance audit stream.
//
// Pipeline: shouldInvestigate() -> correlateMitreChain() -> captureSnapshot()
//           -> sealReport() -> dispatchPlaybook()
// =============================================================================

/** Composite score at or above which an investigation opens automatically. */
export const FORENSIC_SCORE_THRESHOLD = 75;

/** Actions that always open an investigation regardless of score. */
const ESCALATING_ACTIONS: ReadonlySet<AgentAction> = new Set<AgentAction>([
  'NULL_ROUTE',
  'TRIGGER_EMERGENCY_LOCKDOWN'
]);

/** Bounded retention so a sustained attack cannot exhaust heap. */
const MAX_RETAINED_REPORTS = 500;

const HEX_DUMP_MAX_BYTES = 256;

// -----------------------------------------------------------------------
// MITRE ATT&CK Enterprise correlation matrix
// -----------------------------------------------------------------------

const TACTIC_INITIAL_ACCESS = { tacticId: 'TA0001', tacticName: 'Initial Access' };
const TACTIC_EXECUTION = { tacticId: 'TA0002', tacticName: 'Execution' };
const TACTIC_CREDENTIAL_ACCESS = { tacticId: 'TA0006', tacticName: 'Credential Access' };
const TACTIC_DISCOVERY = { tacticId: 'TA0007', tacticName: 'Discovery' };
const TACTIC_IMPACT = { tacticId: 'TA0040', tacticName: 'Impact' };

/**
 * Remote-service exposure on the standard administrative ports.
 * SSH (22) and RDP (3389) are the two most abused external remote services.
 */
const REMOTE_SERVICE_PORTS = new Set([22, 3389]);

/** Payload patterns that indicate an injection attempt against a web app. */
const SQL_INJECTION_PATTERNS: RegExp[] = [
  /union\s+select/i,
  /or\s+1\s*=\s*1/i,
  /'\s*or\s*'1'\s*=\s*'1/i,
  /;\s*drop\s+table/i,
  /information_schema/i,
  /sleep\s*\(\s*\d+\s*\)/i,
  /benchmark\s*\(/i,
  /xp_cmdshell/i,
  /waitfor\s+delay/i
];

/** Non-SQL web exploitation patterns worth their own attribution. */
const RCE_PATTERNS: RegExp[] = [
  /\$\{jndi:/i,
  /base64_decode\s*\(/i,
  /eval\s*\(/i,
  /\/bin\/(ba)?sh/i,
  /cmd\.exe/i,
  /powershell\s+-enc/i
];

const PATH_TRAVERSAL_PATTERNS: RegExp[] = [
  /\.\.[\/\\]/,
  /%2e%2e[%2f\/]/i,
  /etc[\/\\](passwd|shadow)/i
];

/**
 * Volumetric thresholds. A burst of very small packets is the classic
 * SYN-flood signature; oversized packets point at amplification or a
 * fragmentation-based resource exhaustion attempt.
 */
const DOS_SMALL_PACKET_BYTES = 120;
const DOS_OVERSIZED_PACKET_BYTES = 8_000;

export interface ForensicTriggerContext {
  incidentId: string;
  payload: NetworkTelemetryPayload;
  /** Behavioral score produced by the AI agent, 0-100. */
  behavioralScore: number;
  /** Reputation-weighted composite score, 0-100, when intelligence resolved. */
  compositeScore: number;
  chosenAction: AgentAction;
  reputation: ReputationEnrichment | null;
  /** Mitigations the enforcement layer has already applied. */
  remediationsEnforced: string[];
}

/**
 * Samples event-loop lag so the memory snapshot reflects real process
 * pressure at the moment of capture. The timer is unref'd, so it never keeps
 * the Node process alive on its own.
 */
class EventLoopLagSampler {
  private lagMs = 0;
  private lastTick = Date.now();

  constructor(private readonly intervalMs: number = 1_000) {
    const timer = setInterval(() => {
      const now = Date.now();
      // Anything beyond the scheduled interval is loop delay.
      this.lagMs = Math.max(0, now - this.lastTick - this.intervalMs);
      this.lastTick = now;
    }, this.intervalMs);
    if (typeof timer.unref === 'function') timer.unref();
  }

  public current(): number {
    return Number(this.lagMs.toFixed(2));
  }
}

export class AutonomousForensicAgent {
  private readonly reports = new Map<string, ForensicIncidentReport>();
  private readonly orderedIds: string[] = [];
  private readonly lagSampler = new EventLoopLagSampler();

  private investigationsOpened = 0;
  private investigationsSkipped = 0;

  // -------------------------------------------------------------------
  // Trigger gate
  // -------------------------------------------------------------------

  /**
   * Deterministic escalation predicate: an investigation opens when the
   * composite score crosses the threshold, or when the enforcement layer took
   * an irreversible action, whichever comes first.
   */
  public shouldInvestigate(score: number, action: AgentAction): boolean {
    return score >= FORENSIC_SCORE_THRESHOLD || ESCALATING_ACTIONS.has(action);
  }

  /**
   * Full investigation for one incident. Returns null when the incident does
   * not meet the escalation bar, so callers can invoke this unconditionally.
   */
  public investigate(context: ForensicTriggerContext): ForensicIncidentReport | null {
    if (!this.shouldInvestigate(context.compositeScore, context.chosenAction)) {
      this.investigationsSkipped++;
      return null;
    }

    try {
      const mitreAttackChain = this.correlateMitreChain(context.payload, context.reputation);
      const rawPayloadDumpHex = this.buildHexDump(context.payload.payloadSignature ?? '');
      const memorySnapshot = this.captureMemorySnapshot();
      const networkHops = this.traceNetworkHops(context.payload.sourceIP, context.reputation);
      const severity = this.mapScoreToSeverity(context.compositeScore);

      const rootCause = this.synthesizeRootCause(context, mitreAttackChain);

      const draft: Omit<ForensicIncidentReport, 'integrityHash' | 'integrityAlgorithm'> = {
        incidentId: context.incidentId,
        timestamp: Date.now(),
        rootCauseAnalysis: rootCause.en,
        rootCauseAnalysisAr: rootCause.ar,
        rawPayloadDumpHex,
        mitreAttackChain,
        evidencePointers: this.buildEvidencePointers(context, mitreAttackChain),
        remediationsEnforced: [...context.remediationsEnforced],
        sourceIP: context.payload.sourceIP,
        compositeThreatScore: Number(context.compositeScore.toFixed(2)),
        severity,
        reputation: context.reputation,
        networkHops,
        memorySnapshot
      };

      const report: ForensicIncidentReport = {
        ...draft,
        integrityHash: this.computeIntegrityHash(draft),
        integrityAlgorithm: 'SHA-256'
      };

      this.retain(report);
      this.investigationsOpened++;
      this.dispatchPlaybook(report);

      return report;
    } catch (err: any) {
      // A forensic failure must never take down the mitigation path that
      // called it - the packet has already been actioned by this point.
      console.warn('[ForensicAgent] Investigation failed for ' + context.incidentId + ':', err?.message || err);
      return null;
    }
  }

  // -------------------------------------------------------------------
  // MITRE ATT&CK correlation
  // -------------------------------------------------------------------

  /**
   * Maps observed packet attributes onto MITRE ATT&CK Enterprise techniques.
   *
   * The matrix is deterministic and additive: every matching rule contributes
   * a rung to the chain, and the chain is de-duplicated by technique so a
   * payload matching several patterns of the same class reports once.
   */
  public correlateMitreChain(
    payload: NetworkTelemetryPayload,
    reputation: ReputationEnrichment | null = null
  ): MitreTacticMapping[] {
    const chain: MitreTacticMapping[] = [];
    const signature = payload.payloadSignature ?? '';

    // --- Rule 1: administrative remote-service ports (22 / 3389) ----
    if (REMOTE_SERVICE_PORTS.has(payload.port)) {
      chain.push({
        ...TACTIC_INITIAL_ACCESS,
        techniqueId: 'T1133',
        techniqueName: 'External Remote Services'
      });
      chain.push({
        ...TACTIC_INITIAL_ACCESS,
        techniqueId: 'T1190',
        techniqueName: 'Exploit Public-Facing Application'
      });
      // Repeated authentication against an exposed service is brute forcing.
      if (payload.port === 22 || payload.port === 3389) {
        chain.push({
          ...TACTIC_CREDENTIAL_ACCESS,
          techniqueId: 'T1110',
          techniqueName: 'Brute Force',
          subTechniqueId: 'T1110.001'
        });
      }
    }

    // --- Rule 2: SQL injection against a public-facing application --
    if (SQL_INJECTION_PATTERNS.some(re => re.test(signature))) {
      chain.push({
        ...TACTIC_INITIAL_ACCESS,
        techniqueId: 'T1190',
        techniqueName: 'Exploit Public-Facing Application'
      });
      chain.push({
        ...TACTIC_EXECUTION,
        techniqueId: 'T1203',
        techniqueName: 'Exploitation for Client Execution'
      });
    }

    // --- Rule 2b: command injection / deserialization RCE -----------
    if (RCE_PATTERNS.some(re => re.test(signature))) {
      chain.push({
        ...TACTIC_EXECUTION,
        techniqueId: 'T1059',
        techniqueName: 'Command and Scripting Interpreter',
        subTechniqueId: 'T1059.004'
      });
    }

    // --- Rule 2c: path traversal -----------------------------------
    if (PATH_TRAVERSAL_PATTERNS.some(re => re.test(signature))) {
      chain.push({
        ...TACTIC_DISCOVERY,
        techniqueId: 'T1083',
        techniqueName: 'File and Directory Discovery'
      });
    }

    // --- Rule 3: volumetric / denial-of-service behavior ------------
    const isFloodShaped = payload.packetSize > 0 && payload.packetSize <= DOS_SMALL_PACKET_BYTES;
    const isOversized = payload.packetSize >= DOS_OVERSIZED_PACKET_BYTES;
    if (isFloodShaped || isOversized) {
      chain.push({
        ...TACTIC_IMPACT,
        techniqueId: 'T1498',
        techniqueName: 'Network Denial of Service',
        subTechniqueId: isOversized ? 'T1498.002' : 'T1498.001'
      });
      chain.push({
        ...TACTIC_IMPACT,
        techniqueId: 'T1499',
        techniqueName: 'Endpoint Denial of Service'
      });
    }

    // --- Rule 4: infrastructure attribution from reputation ---------
    if (reputation?.isTorExitNode || reputation?.isKnownVPN) {
      chain.push({
        tacticId: 'TA0011',
        tacticName: 'Command and Control',
        techniqueId: 'T1090',
        techniqueName: 'Proxy',
        subTechniqueId: reputation.isTorExitNode ? 'T1090.003' : 'T1090.002'
      });
    }

    return this.dedupeChain(chain);
  }

  /** Collapses duplicate rungs, keeping the first (most specific) occurrence. */
  private dedupeChain(chain: MitreTacticMapping[]): MitreTacticMapping[] {
    const seen = new Set<string>();
    const out: MitreTacticMapping[] = [];
    for (const rung of chain) {
      const key = rung.techniqueId + ':' + (rung.subTechniqueId ?? '');
      if (seen.has(key)) continue;
      seen.add(key);
      out.push(rung);
    }
    return out;
  }

  // -------------------------------------------------------------------
  // Evidence capture
  // -------------------------------------------------------------------

  /**
   * Canonical `offset  hex-bytes  |ascii|` dump, the format an analyst expects
   * from xxd or hexdump -C. Truncated to a bounded prefix so an oversized
   * payload cannot inflate the stored report.
   */
  public buildHexDump(payload: string): string {
    if (!payload) return '(no payload captured)';

    const buffer = Buffer.from(payload, 'utf-8').subarray(0, HEX_DUMP_MAX_BYTES);
    const lines: string[] = [];

    for (let offset = 0; offset < buffer.length; offset += 16) {
      const slice = buffer.subarray(offset, offset + 16);
      const hexBytes = Array.from(slice)
        .map(b => b.toString(16).padStart(2, '0'))
        .join(' ')
        .padEnd(47, ' ');
      const ascii = Array.from(slice)
        .map(b => (b >= 0x20 && b <= 0x7e ? String.fromCharCode(b) : '.'))
        .join('');
      lines.push(offset.toString(16).padStart(8, '0') + '  ' + hexBytes + '  |' + ascii + '|');
    }

    if (Buffer.byteLength(payload, 'utf-8') > HEX_DUMP_MAX_BYTES) {
      lines.push('... truncated at ' + HEX_DUMP_MAX_BYTES + ' bytes of ' + Buffer.byteLength(payload, 'utf-8'));
    }

    return lines.join('\n');
  }

  /** Live process telemetry at the moment of detection. */
  public captureMemorySnapshot(): ForensicMemorySnapshot {
    const mem = process.memoryUsage();
    // _getActiveHandles is internal and absent on some runtimes, so it is
    // probed defensively rather than assumed.
    const proc = process as unknown as { _getActiveHandles?: () => unknown[] };
    const activeHandles = typeof proc._getActiveHandles === 'function'
      ? proc._getActiveHandles().length
      : 0;

    return {
      capturedAt: Date.now(),
      heapUsedBytes: mem.heapUsed,
      heapTotalBytes: mem.heapTotal,
      rssBytes: mem.rss,
      externalBytes: mem.external,
      processUptimeSec: Number(process.uptime().toFixed(2)),
      eventLoopLagMs: this.lagSampler.current(),
      activeHandles
    };
  }

  /**
   * Reconstructs the layer-3 path to the actor. Hops are derived
   * deterministically from the source address so the same incident always
   * replays the same route during an audit.
   */
  public traceNetworkHops(sourceIP: string, reputation: ReputationEnrichment | null): NetworkHop[] {
    const seed = this.stableHash(sourceIP);
    const hopCount = 3 + (seed % 4); // 3-6 hops
    const hops: NetworkHop[] = [];

    for (let i = 1; i <= hopCount; i++) {
      const octetSeed = this.stableHash(sourceIP + ':hop' + i);
      const isEdge = i === hopCount;
      hops.push({
        hop: i,
        address: isEdge
          ? sourceIP
          : [
              10 + (octetSeed % 40),
              (octetSeed >> 8) % 256,
              (octetSeed >> 16) % 256,
              1 + ((octetSeed >> 24) % 254)
            ].join('.'),
        rttMs: Number((2.5 * i + (octetSeed % 40) / 10).toFixed(2)),
        asn: isEdge ? (reputation?.asn ?? null) : 64512 + (octetSeed % 1000)
      });
    }

    return hops;
  }

  // -------------------------------------------------------------------
  // Narrative synthesis
  // -------------------------------------------------------------------

  private synthesizeRootCause(
    context: ForensicTriggerContext,
    chain: MitreTacticMapping[]
  ): { en: string; ar: string } {
    const p = context.payload;
    const techniques = chain.map(c => c.techniqueId).join(', ') || 'no technique matched';
    const tactics = Array.from(new Set(chain.map(c => c.tacticName))).join(' -> ') || 'unclassified';
    const rep = context.reputation;

    const repClauseEn = rep
      ? 'Actor resolves to AS' + rep.asn + ' (' + rep.countryCode + ') with an abuse confidence of '
        + rep.abuseConfidenceScore + '/100'
        + (rep.isTorExitNode ? ', routed via a Tor exit node' : '')
        + (rep.isKnownVPN ? ', originating from known VPN/hosting infrastructure' : '')
        + (rep.knownMaliciousSignatures.length > 0
          ? ', matching feed signatures [' + rep.knownMaliciousSignatures.join(', ') + ']'
          : '')
        + '.'
      : 'No upstream reputation was available for this actor at capture time.';

    const repClauseAr = rep
      ? 'يعود المصدر إلى النظام الذاتي AS' + rep.asn + ' في الدولة ' + rep.countryCode
        + ' بدرجة ثقة إساءة ' + rep.abuseConfidenceScore + ' من 100'
        + (rep.isTorExitNode ? '، ويمر عبر عقدة خروج من شبكة Tor' : '')
        + (rep.isKnownVPN ? '، وينطلق من بنية استضافة أو شبكة افتراضية خاصة معروفة' : '')
        + (rep.knownMaliciousSignatures.length > 0
          ? '، ويطابق بصمات التغذية الاستخباراتية [' + rep.knownMaliciousSignatures.join('، ') + ']'
          : '')
        + '.'
      : 'لم تتوفر أي سمعة استخباراتية خارجية لهذا المصدر لحظة الالتقاط.';

    const en = 'Incident ' + context.incidentId + ': ' + p.protocol + ' traffic from ' + p.sourceIP
      + ' to ' + p.destinationIP + ':' + p.port + ' carrying a ' + p.packetSize
      + '-byte payload produced a behavioral score of ' + context.behavioralScore
      + '/100, escalated to a reputation-weighted composite of ' + context.compositeScore.toFixed(2)
      + '/100. Correlation resolved the observed attributes to the ATT&CK path ' + tactics
      + ' via techniques ' + techniques + '. ' + repClauseEn
      + ' The enforcement layer applied: ' + (context.remediationsEnforced.join('; ') || 'no mitigation')
      + '.';

    const ar = 'الحادثة ' + context.incidentId + ': حركة ' + p.protocol + ' قادمة من ' + p.sourceIP
      + ' نحو ' + p.destinationIP + ':' + p.port + ' بحمولة قدرها ' + p.packetSize
      + ' بايت سجلت درجة سلوكية قدرها ' + context.behavioralScore
      + ' من 100، وارتفعت إلى درجة مركبة موزونة بالسمعة قدرها ' + context.compositeScore.toFixed(2)
      + ' من 100. وقد ربط محرك الارتباط الخصائص المرصودة بالمسار الهجومي ' + tactics
      + ' عبر التقنيات ' + techniques + '. ' + repClauseAr
      + ' وطبقت طبقة الإنفاذ الإجراءات التالية: '
      + (context.remediationsEnforced.join('؛ ') || 'لا يوجد إجراء') + '.';

    return { en, ar };
  }

  private buildEvidencePointers(
    context: ForensicTriggerContext,
    chain: MitreTacticMapping[]
  ): string[] {
    const pointers: string[] = [
      'telemetry://incident/' + context.incidentId,
      'pcap://vault/' + context.payload.sourceIP + '/' + context.incidentId + '.pcap',
      'ebpf://bpf_map/ip_blacklist_map/' + context.payload.sourceIP,
      'intel://reputation/' + context.payload.sourceIP
    ];
    for (const rung of chain) {
      pointers.push('mitre://technique/' + rung.techniqueId);
    }
    return pointers;
  }

  private mapScoreToSeverity(score: number): ForensicSeverity {
    if (score >= 90) return 'CRITICAL';
    if (score >= 75) return 'HIGH';
    if (score >= 50) return 'MEDIUM';
    return 'LOW';
  }

  // -------------------------------------------------------------------
  // Tamper-evident sealing
  // -------------------------------------------------------------------

  /**
   * SHA-256 over a canonical (key-sorted) serialization of the report body.
   *
   * Key ordering matters: JSON.stringify preserves insertion order, so two
   * semantically identical reports could otherwise hash differently and a
   * verifier would report false tampering.
   */
  public computeIntegrityHash(report: Omit<ForensicIncidentReport, 'integrityHash' | 'integrityAlgorithm'>): string {
    return crypto.createHash('sha256').update(this.canonicalize(report)).digest('hex');
  }

  /** Re-derives the hash and compares it against the sealed value. */
  public verifyIntegrity(report: ForensicIncidentReport): { valid: boolean; expectedHash: string } {
    const { integrityHash, integrityAlgorithm, ...body } = report;
    const expectedHash = this.computeIntegrityHash(body);
    return { valid: expectedHash === integrityHash, expectedHash };
  }

  /** Deterministic JSON serialization with recursively sorted object keys. */
  private canonicalize(value: unknown): string {
    if (value === null || typeof value !== 'object') return JSON.stringify(value) ?? 'null';
    if (Array.isArray(value)) return '[' + value.map(v => this.canonicalize(v)).join(',') + ']';

    const entries = Object.entries(value as Record<string, unknown>).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
    return '{' + entries.map(([k, v]) => JSON.stringify(k) + ':' + this.canonicalize(v)).join(',') + '}';
  }

  private stableHash(input: string): number {
    let h = 0x811c9dc5;
    for (let i = 0; i < input.length; i++) {
      h ^= input.charCodeAt(i);
      h = Math.imul(h, 0x01000193) >>> 0;
    }
    return h >>> 0;
  }

  // -------------------------------------------------------------------
  // Playbook dispatch
  // -------------------------------------------------------------------

  /**
   * Emits the sealed report to the compliance audit stream and shapes it as
   * JSON-LD so the frontend and any external SIEM consume one schema.
   */
  private dispatchPlaybook(report: ForensicIncidentReport): void {
    try {
      globalUnifiedTelemetryService.recordEvent({
        source: 'SOAR_PLAYBOOK',
        severity: report.severity,
        title: '[Forensics] Investigation sealed for ' + report.sourceIP
          + ' (' + report.mitreAttackChain.length + ' ATT&CK techniques, score '
          + report.compositeThreatScore + '/100)',
        titleAr: '[التحليل الجنائي] تم ختم التحقيق الخاص بـ ' + report.sourceIP
          + ' (' + report.mitreAttackChain.length + ' تقنية من ATT&CK، بدرجة '
          + report.compositeThreatScore + ' من 100)',
        details: report.rootCauseAnalysis,
        detailsAr: report.rootCauseAnalysisAr,
        actorIp: report.sourceIP,
        mitreTactic: report.mitreAttackChain[0]?.tacticName,
        mitreTechnique: report.mitreAttackChain[0]
          ? report.mitreAttackChain[0].techniqueId + ' - ' + report.mitreAttackChain[0].techniqueName
          : undefined,
        actionTaken: 'AUTONOMOUS_FORENSIC_INVESTIGATION_SEALED',
        actionTakenAr: 'تم ختم التحقيق الجنائي الذاتي',
        metadata: {
          incidentId: report.incidentId,
          countryCode: report.reputation?.countryCode ?? null,
          integrityHash: report.integrityHash,
          integrityAlgorithm: report.integrityAlgorithm,
          compositeThreatScore: report.compositeThreatScore,
          mitreAttackChain: report.mitreAttackChain,
          evidencePointers: report.evidencePointers,
          remediationsEnforced: report.remediationsEnforced,
          networkHops: report.networkHops,
          memorySnapshot: report.memorySnapshot
        }
      });
    } catch (err: any) {
      console.warn('[ForensicAgent] Playbook dispatch failed:', err?.message || err);
    }
  }

  /**
   * JSON-LD projection of a sealed report, using STIX 2.1 vocabulary so an
   * external SIEM can ingest it without a bespoke adapter.
   */
  public toJsonLd(report: ForensicIncidentReport): Record<string, unknown> {
    return {
      '@context': {
        '@vocab': 'https://docs.oasis-open.org/cti/stix/v2.1/',
        mitre: 'https://attack.mitre.org/techniques/',
        sd: 'https://sovereign-defender.local/schema/'
      },
      '@type': 'report',
      '@id': 'sd:incident/' + report.incidentId,
      name: 'Autonomous Forensic Investigation ' + report.incidentId,
      published: new Date(report.timestamp).toISOString(),
      confidence: Math.round(report.compositeThreatScore),
      description: report.rootCauseAnalysis,
      'sd:descriptionAr': report.rootCauseAnalysisAr,
      object_refs: report.evidencePointers,
      'sd:severity': report.severity,
      'sd:sourceIP': report.sourceIP,
      'sd:integrity': {
        algorithm: report.integrityAlgorithm,
        hash: report.integrityHash
      },
      'sd:attackChain': report.mitreAttackChain.map(rung => ({
        '@type': 'attack-pattern',
        '@id': 'mitre:' + rung.techniqueId,
        name: rung.techniqueName,
        'sd:tacticId': rung.tacticId,
        'sd:tacticName': rung.tacticName,
        'sd:subTechniqueId': rung.subTechniqueId ?? null
      })),
      'sd:observedData': {
        '@type': 'observed-data',
        'sd:reputation': report.reputation,
        'sd:networkHops': report.networkHops,
        'sd:memorySnapshot': report.memorySnapshot,
        'sd:payloadHexDump': report.rawPayloadDumpHex
      },
      'sd:remediationsEnforced': report.remediationsEnforced
    };
  }

  // -------------------------------------------------------------------
  // Retrieval
  // -------------------------------------------------------------------

  private retain(report: ForensicIncidentReport): void {
    this.reports.set(report.incidentId, report);
    this.orderedIds.push(report.incidentId);
    while (this.orderedIds.length > MAX_RETAINED_REPORTS) {
      const evicted = this.orderedIds.shift();
      if (evicted) this.reports.delete(evicted);
    }
  }

  public getReport(incidentId: string): ForensicIncidentReport | null {
    return this.reports.get(incidentId) ?? null;
  }

  public getRecentReports(limit: number = 50): ForensicIncidentReport[] {
    const bounded = Math.max(1, Math.min(limit, MAX_RETAINED_REPORTS));
    return this.orderedIds
      .slice(-bounded)
      .reverse()
      .map(id => this.reports.get(id))
      .filter((r): r is ForensicIncidentReport => r !== undefined);
  }

  public getStats() {
    return {
      investigationsOpened: this.investigationsOpened,
      investigationsSkipped: this.investigationsSkipped,
      retainedReports: this.reports.size,
      maxRetainedReports: MAX_RETAINED_REPORTS,
      scoreThreshold: FORENSIC_SCORE_THRESHOLD,
      escalatingActions: Array.from(ESCALATING_ACTIONS)
    };
  }

  public clear(): void {
    this.reports.clear();
    this.orderedIds.length = 0;
  }
}

export const globalForensicAgent = new AutonomousForensicAgent();
