import crypto from 'crypto';
import { globalUnifiedTelemetryService } from './unifiedTelemetry.service.js';
import { globalTelemetryWsServer } from '../wsServer.js';
import { globalShadowDecoyRouter, type CanaryToken } from './shadowDecoyRouter.service.js';
import type { IntentAnalysisResult, IndicatorCategory } from './preAttackIntent.service.js';

// =============================================================================
// ADVERSARY PROFILER & LIVE TELEMETRY STREAM (v1.0)
//
// Every action a trapped actor takes inside the grid is recorded, mapped onto
// MITRE ATT&CK, scored for sophistication, and streamed to the SOC.
//
// Pipeline: record() -> mapToAttackMatrix() -> sophistication() -> stream
// =============================================================================

export interface AdversaryAction {
  actionId: string;
  timestamp: number;
  sessionId: string;
  actorIp: string;
  method: string;
  path: string;
  /** The raw, still-encoded input exactly as it arrived. */
  rawPayload: string;
  /** What the de-obfuscation pipeline resolved it to. */
  decodedPayload: string;
  obfuscationDepth: number;
  intentScore: number;
  /** What the decoy returned, so the transcript reads like a real session. */
  decoyResponseKind: string;
  decoyStatusCode: number;
  appliedLatencyMs: number;
  mitreTechniques: string[];
  tactic: string;
  canariesTouched: string[];
}

export interface AdversaryProfile {
  sessionId: string;
  actorIp: string;
  firstSeenAt: number;
  lastSeenAt: number;
  actionCount: number;
  /** 0-100. How capable the operator behind the keyboard appears. */
  sophisticationIndex: number;
  sophisticationBand: 'SCRIPT_KIDDIE' | 'COMMODITY_TOOLING' | 'COMPETENT_OPERATOR' | 'ADVANCED_PERSISTENT';
  peakIntentScore: number;
  maxObfuscationDepth: number;
  distinctCategories: IndicatorCategory[];
  /** Ordered ATT&CK tactics observed, i.e. the kill chain walked so far. */
  killChain: string[];
  techniques: string[];
  canariesExposed: string[];
  canariesRedeemed: string[];
  /** Rolling transcript for the shadow terminal view. */
  transcript: AdversaryAction[];
}

/** Ordered ATT&CK tactics used to render the kill chain progression. */
const TACTIC_ORDER = [
  'Reconnaissance',
  'Initial Access',
  'Execution',
  'Discovery',
  'Credential Access',
  'Collection',
  'Lateral Movement',
  'Exfiltration',
  'Impact'
];

/** Maps an intent category onto its ATT&CK tactic and technique set. */
const CATEGORY_TO_ATTACK: Record<IndicatorCategory, { tactic: string; techniques: string[] }> = {
  STEALTH_RECON: { tactic: 'Reconnaissance', techniques: ['T1595.002 - Active Scanning: Vulnerability Scanning', 'T1592 - Gather Victim Host Information'] },
  SCANNER_FINGERPRINT: { tactic: 'Reconnaissance', techniques: ['T1595.002 - Active Scanning: Vulnerability Scanning'] },
  SQL_INJECTION: { tactic: 'Initial Access', techniques: ['T1190 - Exploit Public-Facing Application'] },
  NOSQL_INJECTION: { tactic: 'Initial Access', techniques: ['T1190 - Exploit Public-Facing Application'] },
  TEMPLATE_INJECTION: { tactic: 'Initial Access', techniques: ['T1190 - Exploit Public-Facing Application'] },
  COMMAND_INJECTION: { tactic: 'Execution', techniques: ['T1059.004 - Command and Scripting Interpreter: Unix Shell'] },
  PATH_TRAVERSAL: { tactic: 'Discovery', techniques: ['T1083 - File and Directory Discovery'] },
  OBFUSCATION_ABUSE: { tactic: 'Defense Evasion', techniques: ['T1027 - Obfuscated Files or Information'] }
};

/** Path shapes that reveal which discovery technique is in play. */
const DISCOVERY_SIGNALS: Array<{ pattern: RegExp; technique: string; tactic: string }> = [
  { pattern: /\/etc\/passwd|\/etc\/shadow|users?\b|accounts?\b/i, technique: 'T1087 - Account Discovery', tactic: 'Discovery' },
  { pattern: /uname|hostname|\/proc\/version|systeminfo/i, technique: 'T1082 - System Information Discovery', tactic: 'Discovery' },
  { pattern: /\bls\b|dir=|listing|\.\.\//i, technique: 'T1083 - File and Directory Discovery', tactic: 'Discovery' },
  { pattern: /id_rsa|\.ssh|credentials|\.env|token|secret/i, technique: 'T1552 - Unsecured Credentials', tactic: 'Credential Access' },
  { pattern: /ssh |scp |rsync |psexec|wmic/i, technique: 'T1021 - Remote Services', tactic: 'Lateral Movement' },
  { pattern: /select .* from|dump|export|tar |zip /i, technique: 'T1005 - Data from Local System', tactic: 'Collection' },
  { pattern: /curl |wget |nc |\/dev\/tcp\//i, technique: 'T1048 - Exfiltration Over Alternative Protocol', tactic: 'Exfiltration' }
];

const MAX_TRANSCRIPT_ENTRIES = 120;
const MAX_PROFILES = 300;

export class AdversaryProfiler {
  private readonly profiles = new Map<string, AdversaryProfile>();
  private totalActions = 0;

  // -------------------------------------------------------------------
  // Recording
  // -------------------------------------------------------------------

  /**
   * Records one action taken inside the decoy and streams it to the SOC.
   *
   * Called on every interaction, so it must stay synchronous and cheap; the
   * telemetry publish and websocket broadcast are both fire-and-forget and
   * individually guarded, because a SOC transport failure must never break
   * the deception.
   */
  public record(input: {
    sessionId: string;
    actorIp: string;
    method: string;
    path: string;
    rawPayload: string;
    intent: IntentAnalysisResult;
    decoyResponseKind: string;
    decoyStatusCode: number;
    appliedLatencyMs: number;
    canariesExposed?: string[];
  }): AdversaryAction {
    this.totalActions++;

    const { techniques, tactic } = this.mapToAttackMatrix(input.intent, input.path, input.rawPayload);

    const action: AdversaryAction = {
      actionId: 'ADV-' + crypto.randomBytes(5).toString('hex').toUpperCase(),
      timestamp: Date.now(),
      sessionId: input.sessionId,
      actorIp: input.actorIp,
      method: input.method,
      path: input.path.slice(0, 512),
      rawPayload: input.rawPayload.slice(0, 1024),
      decodedPayload: input.intent.normalizedInput.slice(0, 1024),
      obfuscationDepth: input.intent.obfuscationDepth,
      intentScore: input.intent.adversaryIntentScore,
      decoyResponseKind: input.decoyResponseKind,
      decoyStatusCode: input.decoyStatusCode,
      appliedLatencyMs: input.appliedLatencyMs,
      mitreTechniques: techniques,
      tactic,
      canariesTouched: input.canariesExposed ?? []
    };

    const profile = this.upsertProfile(action, input.intent);
    this.stream(action, profile);
    return action;
  }

  /**
   * Maps observed behaviour onto the ATT&CK matrix.
   *
   * Two sources are combined: the intent analyzer's category (what the
   * payload *is*) and the path/command shape (what the attacker is *reaching
   * for*). A single request can legitimately populate several techniques, so
   * results are deduplicated rather than reduced to one.
   */
  public mapToAttackMatrix(
    intent: IntentAnalysisResult,
    path: string,
    rawPayload: string
  ): { techniques: string[]; tactic: string } {
    const techniques = new Set<string>();
    const tactics: string[] = [];

    for (const indicator of intent.indicators) {
      const mapped = CATEGORY_TO_ATTACK[indicator.category];
      if (mapped) {
        mapped.techniques.forEach(t => techniques.add(t));
        tactics.push(mapped.tactic);
      }
      techniques.add(indicator.mitreTechnique);
    }

    const haystack = path + ' ' + rawPayload + ' ' + intent.normalizedInput;
    for (const signal of DISCOVERY_SIGNALS) {
      if (signal.pattern.test(haystack)) {
        techniques.add(signal.technique);
        tactics.push(signal.tactic);
      }
    }

    if (techniques.size === 0) {
      techniques.add('T1595 - Active Scanning');
      tactics.push('Reconnaissance');
    }

    // The reported tactic is the furthest point reached along the kill chain,
    // which is what an analyst needs to know: how deep the actor has got.
    const furthest = tactics.reduce((deepest, t) => {
      const a = TACTIC_ORDER.indexOf(t);
      const b = TACTIC_ORDER.indexOf(deepest);
      return a > b ? t : deepest;
    }, tactics[0] ?? 'Reconnaissance');

    return { techniques: Array.from(techniques), tactic: furthest };
  }

  /**
   * Attacker sophistication, 0-100.
   *
   * Weighted from four observable proxies for operator skill:
   *   - obfuscation depth (35): stacking encodings is a deliberate, learned
   *     evasion behaviour rather than something a copied payload does.
   *   - technique breadth (25): moving across distinct ATT&CK tactics shows
   *     methodology, not a single copy-pasted exploit.
   *   - kill-chain depth (25): how far along the chain they progressed.
   *   - tooling penalty (-15): a recognised scanner user-agent means an
   *     off-the-shelf tool is driving, which caps the ceiling.
   *
   * The scale is deliberately blunt. It ranks operators against each other
   * for triage; it is not a claim about attribution.
   */
  public sophistication(profile: AdversaryProfile, usedKnownScanner: boolean): number {
    const obfuscation = Math.min(1, profile.maxObfuscationDepth / 4) * 35;
    const breadth = Math.min(1, profile.distinctCategories.length / 5) * 25;

    const deepestIndex = profile.killChain.reduce(
      (max, t) => Math.max(max, TACTIC_ORDER.indexOf(t)), 0
    );
    const chainDepth = Math.min(1, deepestIndex / (TACTIC_ORDER.length - 1)) * 25;

    // A high intent score alone is not sophistication - a trivially obvious
    // payload scores high on intent while showing no skill at all.
    const persistence = Math.min(1, profile.actionCount / 25) * 15;

    const penalty = usedKnownScanner ? 15 : 0;
    return Math.max(0, Math.min(100, Math.round(obfuscation + breadth + chainDepth + persistence - penalty)));
  }

  private bandFor(index: number): AdversaryProfile['sophisticationBand'] {
    if (index >= 75) return 'ADVANCED_PERSISTENT';
    if (index >= 50) return 'COMPETENT_OPERATOR';
    if (index >= 25) return 'COMMODITY_TOOLING';
    return 'SCRIPT_KIDDIE';
  }

  private upsertProfile(action: AdversaryAction, intent: IntentAnalysisResult): AdversaryProfile {
    let profile = this.profiles.get(action.sessionId);

    if (!profile) {
      profile = {
        sessionId: action.sessionId,
        actorIp: action.actorIp,
        firstSeenAt: action.timestamp,
        lastSeenAt: action.timestamp,
        actionCount: 0,
        sophisticationIndex: 0,
        sophisticationBand: 'SCRIPT_KIDDIE',
        peakIntentScore: 0,
        maxObfuscationDepth: 0,
        distinctCategories: [],
        killChain: [],
        techniques: [],
        canariesExposed: [],
        canariesRedeemed: [],
        transcript: []
      };
      this.profiles.set(action.sessionId, profile);

      while (this.profiles.size > MAX_PROFILES) {
        const oldest = this.profiles.keys().next().value as string | undefined;
        if (oldest === undefined) break;
        this.profiles.delete(oldest);
      }
    }

    profile.lastSeenAt = action.timestamp;
    profile.actionCount++;
    profile.peakIntentScore = Math.max(profile.peakIntentScore, action.intentScore);
    profile.maxObfuscationDepth = Math.max(profile.maxObfuscationDepth, action.obfuscationDepth);

    for (const ind of intent.indicators) {
      if (!profile.distinctCategories.includes(ind.category)) profile.distinctCategories.push(ind.category);
    }
    for (const t of action.mitreTechniques) {
      if (!profile.techniques.includes(t)) profile.techniques.push(t);
    }
    if (!profile.killChain.includes(action.tactic)) {
      profile.killChain.push(action.tactic);
      // Keep the chain in canonical order so the UI renders progression.
      profile.killChain.sort((a, b) => TACTIC_ORDER.indexOf(a) - TACTIC_ORDER.indexOf(b));
    }
    for (const c of action.canariesTouched) {
      if (!profile.canariesExposed.includes(c)) profile.canariesExposed.push(c);
    }

    profile.transcript.push(action);
    while (profile.transcript.length > MAX_TRANSCRIPT_ENTRIES) profile.transcript.shift();

    const usedScanner = profile.distinctCategories.includes('SCANNER_FINGERPRINT');
    profile.sophisticationIndex = this.sophistication(profile, usedScanner);
    profile.sophisticationBand = this.bandFor(profile.sophisticationIndex);

    return profile;
  }

  // -------------------------------------------------------------------
  // Streaming
  // -------------------------------------------------------------------

  private stream(action: AdversaryAction, profile: AdversaryProfile): void {
    try {
      globalUnifiedTelemetryService.recordEvent({
        source: 'HONEYPOT',
        severity: profile.sophisticationIndex >= 60 ? 'HIGH' : 'MEDIUM',
        title: '[Deception Grid] ' + action.tactic + ' - ' + action.method + ' ' + action.path.slice(0, 70)
          + ' (intent ' + action.intentScore + '/100)',
        titleAr: '[شبكة الخداع] ' + action.tactic + ' - ' + action.method + ' ' + action.path.slice(0, 70)
          + ' (النية ' + action.intentScore + ' من 100)',
        details: 'Entrapped actor executed a ' + action.decoyResponseKind + ' probe. Decoded payload: '
          + action.decodedPayload.slice(0, 200)
          + (action.canariesTouched.length > 0 ? ' | Canaries exposed: ' + action.canariesTouched.join(', ') : ''),
        detailsAr: 'نفذ الفاعل المحتجز فحصاً من نوع ' + action.decoyResponseKind + '. الحمولة بعد فك التشفير: '
          + action.decodedPayload.slice(0, 200)
          + (action.canariesTouched.length > 0 ? ' | الطُعوم المكشوفة: ' + action.canariesTouched.join(', ') : ''),
        actorIp: action.actorIp,
        sessionId: action.sessionId,
        mitreTactic: action.tactic,
        mitreTechnique: action.mitreTechniques[0],
        actionTaken: 'DECEPTION_GRID_ENTRAPMENT_OBSERVED',
        actionTakenAr: 'رصد نشاط داخل شبكة الخداع',
        metadata: {
          actionId: action.actionId,
          obfuscationDepth: action.obfuscationDepth,
          sophisticationIndex: profile.sophisticationIndex,
          sophisticationBand: profile.sophisticationBand,
          killChain: profile.killChain,
          techniques: action.mitreTechniques,
          decoyResponseKind: action.decoyResponseKind,
          decoyStatusCode: action.decoyStatusCode,
          appliedLatencyMs: action.appliedLatencyMs,
          canariesTouched: action.canariesTouched,
          rawPayload: action.rawPayload.slice(0, 400),
          decodedPayload: action.decodedPayload.slice(0, 400)
        }
      });
    } catch (err: any) {
      console.warn('[AdversaryProfiler] Telemetry publish failed:', err?.message || err);
    }

    try {
      globalTelemetryWsServer.broadcast('deception:action', { action, profileSummary: {
        sessionId: profile.sessionId,
        sophisticationIndex: profile.sophisticationIndex,
        sophisticationBand: profile.sophisticationBand,
        killChain: profile.killChain,
        actionCount: profile.actionCount
      } });
    } catch (err: any) {
      console.warn('[AdversaryProfiler] WS broadcast failed:', err?.message || err);
    }
  }

  /** Records a canary redemption against the session that leaked it. */
  public noteCanaryRedemption(token: CanaryToken, seenFrom: string): void {
    const profile = this.profiles.get(token.boundSessionId);
    if (profile && !profile.canariesRedeemed.includes(token.canaryId)) {
      profile.canariesRedeemed.push(token.canaryId);
    }

    try {
      globalUnifiedTelemetryService.recordEvent({
        source: 'HONEYPOT',
        severity: 'CRITICAL',
        title: '[Canary Redeemed] ' + token.kind + ' ' + token.canaryId + ' presented from ' + seenFrom,
        titleAr: '[استُخدم طُعم] ' + token.kind + ' ' + token.canaryId + ' قُدم من ' + seenFrom,
        details: 'A honey credential planted inside decoy session ' + token.boundSessionId
          + ' has been used. This is conclusive proof of exfiltration and attributes the leak to that session.',
        detailsAr: 'استُخدم اعتماد خادع مزروع داخل جلسة الخداع ' + token.boundSessionId
          + '. هذا دليل قاطع على التسريب وينسب التسرب إلى تلك الجلسة تحديداً.',
        actorIp: seenFrom,
        sessionId: token.boundSessionId,
        mitreTactic: 'Credential Access',
        mitreTechnique: 'T1552 - Unsecured Credentials',
        actionTaken: 'CANARY_TOKEN_REDEMPTION_DETECTED',
        actionTakenAr: 'رصد استخدام طُعم مزروع',
        metadata: { canaryId: token.canaryId, kind: token.kind, plantedPath: token.plantedPath, boundSessionId: token.boundSessionId }
      });
    } catch (err: any) {
      console.warn('[AdversaryProfiler] Canary telemetry failed:', err?.message || err);
    }
  }

  // -------------------------------------------------------------------
  // Query surface
  // -------------------------------------------------------------------

  public getProfile(sessionId: string): AdversaryProfile | null {
    return this.profiles.get(sessionId) ?? null;
  }

  public getProfiles(limit: number = 50): AdversaryProfile[] {
    return Array.from(this.profiles.values())
      .sort((a, b) => b.lastSeenAt - a.lastSeenAt)
      .slice(0, Math.max(1, Math.min(limit, MAX_PROFILES)));
  }

  /** Flattened, newest-first transcript across all trapped sessions. */
  public getGlobalTranscript(limit: number = 80): AdversaryAction[] {
    const all: AdversaryAction[] = [];
    for (const p of this.profiles.values()) all.push(...p.transcript);
    return all.sort((a, b) => b.timestamp - a.timestamp).slice(0, limit);
  }

  public getStats() {
    const profiles = Array.from(this.profiles.values());
    const bands: Record<string, number> = {
      SCRIPT_KIDDIE: 0, COMMODITY_TOOLING: 0, COMPETENT_OPERATOR: 0, ADVANCED_PERSISTENT: 0
    };
    let peakSophistication = 0;
    for (const p of profiles) {
      bands[p.sophisticationBand] = (bands[p.sophisticationBand] ?? 0) + 1;
      if (p.sophisticationIndex > peakSophistication) peakSophistication = p.sophisticationIndex;
    }
    return {
      trackedProfiles: profiles.length,
      totalActions: this.totalActions,
      bands,
      peakSophistication,
      canaries: globalShadowDecoyRouter.getStats().canariesMinted
    };
  }

  public clear(): void {
    this.profiles.clear();
    this.totalActions = 0;
  }
}

export const globalAdversaryProfiler = new AdversaryProfiler();
