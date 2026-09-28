import { globalThreatMemory } from './threatMemory.service.js';
import crypto from 'crypto';

// =============================================================================
// UNIFIED SOC TELEMETRY BUS (v6.0)
// Central nervous system for all defensive subsystems (FIM, WAF/eBPF, Target
// Scanner, AI Defense, Honeypots, Insider Zero Trust, In-Transit Inspection,
// SOAR playbooks, Topology/Lockdown). Every subsystem funnels its alerts
// through recordEvent(), which fans out into three consumable views:
//   1. Raw event stream  -> /api/v1/soc/unified-telemetry
//   2. Correlated timeline incidents -> /api/v1/soc/threat-timeline
//   3. Per-actor MITRE ATT&CK chain sessions -> /api/v1/soc/attack-chains
// =============================================================================

export type TelemetrySeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export type TelemetrySource =
  | 'WAF_EBPF'
  | 'FIM'
  | 'TARGET_SCANNER'
  | 'AI_DEFENSE'
  | 'SYSTEM_LOCKDOWN'
  | 'HONEYPOT'
  | 'INSIDER_ZERO_TRUST'
  | 'IN_TRANSIT_INSPECTION'
  | 'SOAR_PLAYBOOK'
  | 'LAN_WATCH';

export interface TelemetryEvent {
  id: string;
  timestamp: string;
  source: TelemetrySource;
  severity: TelemetrySeverity;
  title: string;
  titleAr: string;
  details: string;
  detailsAr?: string;
  actorIp?: string;
  sessionId?: string;
  mitreTactic?: string;
  mitreTechnique?: string;
  actionTaken: string;
  actionTakenAr?: string;
  metadata?: Record<string, any>;
}

export type RecordEventInput = Omit<TelemetryEvent, 'id' | 'timestamp'>;

export type IncidentType = 'BLOCKED_ATTACK' | 'SYSTEM_ALERT';

export type IncidentCategory =
  | 'SQL_INJECTION'
  | 'XSS_ATTACK'
  | 'RCE_EXPLOIT'
  | 'PATH_TRAVERSAL'
  | 'DDOS_SYN_FLOOD'
  | 'HONEYPOT_HIT'
  | 'AI_PROMPT_INJECTION'
  | 'FIM_TAMPER'
  | 'ZERO_TRUST_LOCKDOWN'
  | 'PROCESS_ANOMALY'
  | 'BASELINE_DRIFT'
  | 'SCANNER_CVE'
  | 'BRUTE_FORCE';

export interface TimelineIncident {
  id: string;
  type: IncidentType;
  timestamp: string;
  title: string;
  titleAr: string;
  details: string;
  detailsAr?: string;
  severity: TelemetrySeverity;
  category: IncidentCategory;
  actorIp?: string;
  country?: string;
  target?: string;
  mitreTactic?: string;
  mitreTechnique?: string;
  actionTaken: string;
  actionTakenAr: string;
  payloadSnippet?: string;
  correlatedWithId?: string;
  correlationReason?: string;
  correlationReasonAr?: string;
  impactScore: number;
}

export interface AttackChainStage {
  stage: string;
  timestamp: string;
  description: string;
  technique: string;
}

export interface AttackChainSession {
  sessionId: string;
  actorIp: string;
  firstSeen: string;
  lastSeen: string;
  threatScore: number;
  stagesCompleted: AttackChainStage[];
  status: 'ACTIVE_TRACKING' | 'CONTAINED' | 'NEUTRALIZED';
}

export interface TimelineStats {
  totalIncidents: number;
  blockedCount: number;
  alertCount: number;
  correlatedPairs: number;
  criticalCount: number;
  highCount: number;
  averageImpactScore: number;
}

interface EventFilter {
  severity?: string;
  source?: string;
  search?: string;
}

const MAX_EVENTS = 500;
const MAX_INCIDENTS = 400;

const CONTAINMENT_KEYWORDS = [
  'DROP', 'BAN', 'BLOCK', 'QUARANTINE', 'KILL', 'ISOLAT', 'BLACKHOLE',
  'EVICT', 'RST', 'FROZEN', 'LOCKOUT', 'SANDBOX',
  // Autonomous AI agent mitigations: traffic is dropped or diverted away
  // from production, so these are genuine blocks rather than passive alerts.
  'NULL_ROUTE', 'LOCKDOWN', 'REDIRECTION'
];

const SEVERITY_IMPACT_SCORE: Record<TelemetrySeverity, number> = {
  CRITICAL: 96,
  HIGH: 80,
  MEDIUM: 55,
  LOW: 30,
  INFO: 12
};

function generateId(prefix: string): string {
  return `${prefix}-${crypto.randomBytes(5).toString('hex').toUpperCase()}`;
}

function classifyIncidentType(actionTaken: string): IncidentType {
  const upper = (actionTaken || '').toUpperCase();
  return CONTAINMENT_KEYWORDS.some(k => upper.includes(k)) ? 'BLOCKED_ATTACK' : 'SYSTEM_ALERT';
}

function classifyCategory(input: RecordEventInput): IncidentCategory {
  // Underscores are normalized to spaces so machine-style labels such as
  // "COMMAND_INJECTION" or "WEBSHELL_RCE" match the same phrases as prose.
  const text = `${input.title} ${input.details} ${input.mitreTechnique || ''}`
    .toUpperCase()
    .replace(/_/g, ' ');

  if (input.source === 'FIM') return 'FIM_TAMPER';
  if (input.source === 'TARGET_SCANNER') return 'SCANNER_CVE';
  if (input.source === 'HONEYPOT') return 'HONEYPOT_HIT';
  if (input.source === 'INSIDER_ZERO_TRUST') return 'ZERO_TRUST_LOCKDOWN';

  // AI_DEFENSE covers both the LLM prompt-injection shield and the autonomous
  // network threat agent, so only classify as prompt injection when the event
  // is genuinely about the model layer; otherwise fall through to the
  // content-driven network classification below.
  if (input.source === 'AI_DEFENSE' && (text.includes('PROMPT') || text.includes('LLM') || text.includes('GEMINI') || text.includes('JAILBREAK'))) {
    return 'AI_PROMPT_INJECTION';
  }

  if (text.includes('SQL')) return 'SQL_INJECTION';
  if (text.includes('XSS') || text.includes('CROSS-SITE') || text.includes('CROSS SITE')) return 'XSS_ATTACK';
  // NOTE: "RCE" must be matched on a word boundary - a naive substring match
  // also fires on ordinary words like "source", "resource" and "enforced".
  if (
    text.includes('WEBSHELL') ||
    /\bRCE\b/.test(text) ||
    text.includes('REMOTE CODE EXECUTION') ||
    text.includes('COMMAND INJECTION') ||
    text.includes('SCRIPTING INTERPRETER')
  ) return 'RCE_EXPLOIT';
  if (text.includes('TRAVERSAL') || text.includes('../')) return 'PATH_TRAVERSAL';
  if (text.includes('DDOS') || text.includes('SYN FLOOD') || text.includes('FLOOD') || text.includes('DENIAL OF SERVICE')) return 'DDOS_SYN_FLOOD';
  if (text.includes('BRUTE') || text.includes('CREDENTIAL STUFFING') || text.includes('VELOCITY')) return 'BRUTE_FORCE';
  if (text.includes('PORT-SCANNING') || text.includes('PORT SCAN') || text.includes('SCANNING') || text.includes('RECONNAISSANCE')) return 'SCANNER_CVE';
  if (text.includes('BASELINE') || text.includes('DRIFT') || text.includes('ANOMALY')) return 'BASELINE_DRIFT';

  return 'PROCESS_ANOMALY';
}

class UnifiedTelemetryService {
  private events: TelemetryEvent[] = [];
  private incidents: TimelineIncident[] = [];
  private attackChains: Map<string, AttackChainSession> = new Map();
  private emergencyLockdownActive: boolean = false;

  // ---------------------------------------------------------------------
  // Ingestion
  // ---------------------------------------------------------------------
  public recordEvent(input: RecordEventInput): TelemetryEvent {
    const { event } = this.ingest(input);
    return event;
  }

  private ingest(input: RecordEventInput): { event: TelemetryEvent; incident: TimelineIncident } {
    const timestamp = new Date().toISOString();

    const event: TelemetryEvent = {
      ...input,
      id: generateId('EVT'),
      timestamp,
      actionTakenAr: input.actionTakenAr || input.actionTaken
    };

    this.events.unshift(event);
    if (this.events.length > MAX_EVENTS) this.events.length = MAX_EVENTS;

    // Persist to the local corpus. The in-memory ring buffer above is capped
    // and dies with the process; this is what gives the AI a history to
    // retrieve from, and what survives a restart.
    try {
      globalThreatMemory.record({
        id: event.id,
        timestamp: event.timestamp,
        source: event.source,
        severity: event.severity,
        title: event.title,
        titleAr: event.titleAr,
        details: event.details,
        detailsAr: event.detailsAr,
        actorIp: event.actorIp,
        mitreTactic: event.mitreTactic,
        mitreTechnique: event.mitreTechnique,
        actionTaken: event.actionTaken,
        actionTakenAr: event.actionTakenAr,
        metadata: event.metadata
      });
    } catch { /* the store never blocks live telemetry */ }

    const incident = this.buildIncidentFromEvent(event);
    this.incidents.unshift(incident);
    if (this.incidents.length > MAX_INCIDENTS) this.incidents.length = MAX_INCIDENTS;

    if (event.actorIp) {
      this.updateAttackChain(event);
    }

    return { event, incident };
  }

  private buildIncidentFromEvent(event: TelemetryEvent): TimelineIncident {
    return {
      id: generateId('INC'),
      type: classifyIncidentType(event.actionTaken),
      timestamp: event.timestamp,
      title: event.title,
      titleAr: event.titleAr,
      details: event.details,
      detailsAr: event.detailsAr,
      severity: event.severity,
      category: classifyCategory(event),
      actorIp: event.actorIp,
      target: event.metadata?.targetHost || event.metadata?.target,
      mitreTactic: event.mitreTactic,
      mitreTechnique: event.mitreTechnique,
      actionTaken: event.actionTaken,
      actionTakenAr: event.actionTakenAr || event.actionTaken,
      payloadSnippet: event.metadata?.payloadSnippet || event.metadata?.payload,
      impactScore: SEVERITY_IMPACT_SCORE[event.severity] ?? 40
    };
  }

  private updateAttackChain(event: TelemetryEvent): void {
    if (!event.actorIp) return;
    const key = event.actorIp;
    const existing = this.attackChains.get(key);
    const score = SEVERITY_IMPACT_SCORE[event.severity] ?? 40;
    const isContained = classifyIncidentType(event.actionTaken) === 'BLOCKED_ATTACK';

    if (!existing) {
      const stages: AttackChainStage[] = [];
      if (event.mitreTactic) {
        stages.push({
          stage: event.mitreTactic,
          timestamp: event.timestamp,
          description: event.title,
          technique: event.mitreTechnique || 'Unknown Technique'
        });
      }
      this.attackChains.set(key, {
        sessionId: generateId('CHAIN'),
        actorIp: key,
        firstSeen: event.timestamp,
        lastSeen: event.timestamp,
        threatScore: score,
        stagesCompleted: stages,
        status: isContained ? 'CONTAINED' : 'ACTIVE_TRACKING'
      });
      return;
    }

    existing.lastSeen = event.timestamp;
    existing.threatScore = Math.max(existing.threatScore, score);
    if (event.mitreTactic && !existing.stagesCompleted.some(s => s.stage === event.mitreTactic)) {
      existing.stagesCompleted.push({
        stage: event.mitreTactic,
        timestamp: event.timestamp,
        description: event.title,
        technique: event.mitreTechnique || 'Unknown Technique'
      });
    }
    if (isContained) {
      existing.status = 'CONTAINED';
    } else if (existing.status !== 'CONTAINED') {
      existing.status = 'ACTIVE_TRACKING';
    }
  }

  // ---------------------------------------------------------------------
  // Raw event stream
  // ---------------------------------------------------------------------
  public getEvents(filter: EventFilter = {}): TelemetryEvent[] {
    let list = this.events;

    if (filter.severity) {
      const sev = filter.severity.toUpperCase();
      list = list.filter(e => e.severity === sev);
    }
    if (filter.source) {
      const src = filter.source.toUpperCase();
      list = list.filter(e => e.source === src);
    }
    if (filter.search) {
      const q = filter.search.toLowerCase();
      list = list.filter(e =>
        e.title.toLowerCase().includes(q) ||
        e.titleAr.includes(q) ||
        e.details.toLowerCase().includes(q) ||
        (e.actorIp && e.actorIp.toLowerCase().includes(q)) ||
        e.actionTaken.toLowerCase().includes(q) ||
        e.source.toLowerCase().includes(q)
      );
    }

    return list;
  }

  // ---------------------------------------------------------------------
  // Correlated threat timeline
  // ---------------------------------------------------------------------
  public getTimelineIncidents(): TimelineIncident[] {
    return this.incidents;
  }

  public getTimelineStats(): TimelineStats {
    const total = this.incidents.length;
    const blocked = this.incidents.filter(i => i.type === 'BLOCKED_ATTACK').length;
    const alerts = total - blocked;
    const correlated = this.incidents.filter(i => !!i.correlatedWithId).length;
    const critical = this.incidents.filter(i => i.severity === 'CRITICAL').length;
    const high = this.incidents.filter(i => i.severity === 'HIGH').length;
    const avgImpact = total > 0
      ? Math.round(this.incidents.reduce((sum, i) => sum + i.impactScore, 0) / total)
      : 0;

    return {
      totalIncidents: total,
      blockedCount: blocked,
      alertCount: alerts,
      correlatedPairs: Math.floor(correlated / 2),
      criticalCount: critical,
      highCount: high,
      averageImpactScore: avgImpact
    };
  }

  public simulateIncidentPair(vector?: string): { attackIncident: TimelineIncident; alertIncident: TimelineIncident } {
    const normalizedVector = (vector || 'RCE').toUpperCase();
    const attackerIps = ['194.26.29.112', '185.220.101.5', '45.154.255.89', '103.145.13.2'];
    const actorIp = attackerIps[Math.floor(Math.random() * attackerIps.length)];

    const vectorProfiles: Record<string, { source: TelemetrySource; title: string; titleAr: string; details: string; detailsAr: string; tactic: string; technique: string; blockAction: string; blockActionAr: string; }> = {
      RCE: {
        source: 'WAF_EBPF',
        title: `Remote Code Execution Attempt Blocked from ${actorIp}`,
        titleAr: `تم حظر محاولة تنفيذ أوامر عن بُعد من ${actorIp}`,
        details: 'Malicious multipart upload attempted to disguise a PHP web shell as an image/jpeg payload.',
        detailsAr: 'حاول المهاجم رفع قذيفة ويب PHP متنكرة بصيغة صورة عبر رفع متعدد الأجزاء.',
        tactic: 'Execution',
        technique: 'T1059.004 - Command and Scripting Interpreter',
        blockAction: 'EBPF_KERNEL_DROP_AND_BAN',
        blockActionAr: 'تم الحظر الجذري بواسطة eBPF'
      },
      SQLI: {
        source: 'WAF_EBPF',
        title: `SQL Injection Payload Blocked from ${actorIp}`,
        titleAr: `تم حظر حقن استعلامات SQL من ${actorIp}`,
        details: `Detected boolean-based SQLi payload: id=1' OR '1'='1 against /api/v1/users endpoint.`,
        detailsAr: 'تم رصد محاولة حقن SQL منطقية عبر نقطة نهاية المستخدمين.',
        tactic: 'Initial Access',
        technique: 'T1190 - Exploit Public-Facing Application',
        blockAction: 'WAF_BLOCK_AND_TCP_RST',
        blockActionAr: 'تم الحظر وإنهاء الاتصال'
      },
      HONEYPOT: {
        source: 'HONEYPOT',
        title: `Honeytoken Trap Triggered by ${actorIp}`,
        titleAr: `تم تفعيل فخ الطُعم الرقمي بواسطة ${actorIp}`,
        details: 'Attacker accessed a deceptive /.env honeytoken endpoint, triggering automatic isolation.',
        detailsAr: 'وصل المهاجم إلى نقطة طُعم زائفة مما أدى إلى العزل التلقائي.',
        tactic: 'Reconnaissance',
        technique: 'T1595.002 - Vulnerability Scanning',
        blockAction: 'HONEYTOKEN_AUTOBAN_ENFORCED',
        blockActionAr: 'تم تنفيذ الحظر التلقائي للطُعم'
      }
    };

    const profile = vectorProfiles[normalizedVector] || vectorProfiles.RCE;

    const { incident: attackIncident } = this.ingest({
      source: profile.source,
      severity: 'CRITICAL',
      title: profile.title,
      titleAr: profile.titleAr,
      details: profile.details,
      detailsAr: profile.detailsAr,
      actorIp,
      mitreTactic: profile.tactic,
      mitreTechnique: profile.technique,
      actionTaken: profile.blockAction,
      actionTakenAr: profile.blockActionAr
    });

    const { incident: alertIncident } = this.ingest({
      source: 'SYSTEM_LOCKDOWN',
      severity: 'HIGH',
      title: `SOC Correlation Alert: ${normalizedVector} Attack Chain Flagged for ${actorIp}`,
      titleAr: `تنبيه ارتباط مركز العمليات الأمنية: تم رصد سلسلة هجوم من ${actorIp}`,
      details: `Real-time correlation engine linked this alert to the immediately preceding blocked ${normalizedVector} attempt.`,
      detailsAr: 'ربط محرك الارتباط الفوري هذا التنبيه بمحاولة الهجوم المحظورة السابقة مباشرة.',
      actorIp,
      mitreTactic: profile.tactic,
      mitreTechnique: profile.technique,
      actionTaken: 'MITRE_HEATMAP_UPDATE',
      actionTakenAr: 'تم تحديث خريطة ميتري الحرارية'
    });

    attackIncident.correlatedWithId = alertIncident.id;
    alertIncident.correlatedWithId = attackIncident.id;
    attackIncident.correlationReason = alertIncident.correlationReason =
      'Causal correlation established between ingress attack drop and immediate defensive telemetry alarm.';
    attackIncident.correlationReasonAr = alertIncident.correlationReasonAr =
      'تم ربط سببي بين حظر الهجوم الوارد والتنبيه الدفاعي الفوري.';

    return { attackIncident, alertIncident };
  }

  // ---------------------------------------------------------------------
  // MITRE ATT&CK chain sessions
  // ---------------------------------------------------------------------
  public getAttackChains(): AttackChainSession[] {
    return Array.from(this.attackChains.values())
      .sort((a, b) => new Date(b.lastSeen).getTime() - new Date(a.lastSeen).getTime());
  }

  // ---------------------------------------------------------------------
  // Emergency infrastructure lockdown
  // ---------------------------------------------------------------------
  public isEmergencyLockdownActive(): boolean {
    return this.emergencyLockdownActive;
  }

  public setEmergencyLockdown(active: boolean): boolean {
    this.emergencyLockdownActive = active;
    return this.emergencyLockdownActive;
  }

  // ---------------------------------------------------------------------
  // Reset
  // ---------------------------------------------------------------------
  public clearAll(): void {
    this.events = [];
    this.incidents = [];
    this.attackChains.clear();
    this.emergencyLockdownActive = false;
  }
}

export const globalUnifiedTelemetryService = new UnifiedTelemetryService();
