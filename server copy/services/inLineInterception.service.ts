import crypto from 'crypto';
import { globalUnifiedTelemetryService } from './unifiedTelemetry.service.js';
import { globalTelemetryWsServer } from '../wsServer.js';
import { globalEbpfEngine } from '../ebpfEngine.js';
import {
  shannonEntropy,
  hmacSha256,
  digestsEqual,
  canonicalize as canonicalSerialize,
  sha256 as sha256Hex,
  uuidv4,
  HIGH_ENTROPY_THRESHOLD
} from './payloadForensics.js';
import type {
  DataTransitPacket,
  InterceptionDecision,
  TamperFlag,
  NetworkEndpoint
} from '../types/interception.types.js';

// =============================================================================
// IN-LINE PAYLOAD INTEGRITY & TAMPER INTERCEPTOR (v1.0)
// Active, stateful inspection of data in transit. Unlike passive telemetry,
// this engine returns a blocking verdict that the caller is expected to
// enforce before the request ever reaches its endpoint handler.
//
// Pipeline: registerBaseline() -> inspect() -> [tamper detected]
//           -> quarantineSession() -> publish + broadcast
// =============================================================================

/** Active enforcement verdicts. Only PASS permits the request to continue. */
export type InterceptVerdict = 'PASS' | 'INTERCEPT_DROP' | 'EMERGENCY_RESET';

export type TamperClass =
  | 'PAYLOAD_HASH_MISMATCH'
  | 'PARAMETER_POLLUTION'
  | 'SIZE_MUTATION'
  | 'CONTENT_LENGTH_MISMATCH'
  | 'PROTOTYPE_POLLUTION'
  | 'SIGNATURE_STRIPPING'
  | 'INTEGRITY_HEADER_FORGED'
  | 'HIGH_ENTROPY_STREAM';

export interface TamperFinding {
  tamperClass: TamperClass;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  detail: string;
  detailAr: string;
  /** Hash or value the engine expected, when the finding is a comparison. */
  expected?: string;
  /** Hash or value actually observed on the wire. */
  observed?: string;
}

export interface SessionIntegrityRecord {
  sessionId: string;
  actorIp: string;
  /** Canonical SHA-256 of the payload first seen for this session+route. */
  baselineHash: string;
  baselineSize: number;
  route: string;
  registeredAt: number;
  lastSeenAt: number;
  observations: number;
  mutations: number;
  /**
   * True when the client supplied an integrity header at baseline time, i.e.
   * it committed to a fixed payload digest for this session+route. Only such
   * sessions can be held to a hash comparison.
   */
  integrityProtected: boolean;
}

export interface InterceptionRecord {
  interceptId: string;
  timestamp: number;
  sessionId: string;
  actorIp: string;
  route: string;
  method: string;
  verdict: InterceptVerdict;
  findings: TamperFinding[];
  /** Highest-severity class, used for badge rendering in the SOC. */
  primaryTamperClass: TamperClass;
  expectedHash: string | null;
  observedHash: string;
  payloadSizeBytes: number;
  tcpResetIssued: boolean;
  quarantined: boolean;
  auditHash: string;
  /** Shannon entropy of the canonical payload, bits per byte. */
  entropyScore: number;
  /** Frames seen from this session inside the sliding 60s window. */
  sessionBurstCount: number;
  /** True when the kernel layer was told to null-route this actor. */
  socketInvalidated: boolean;
}

export interface QuarantinedSession {
  sessionId: string;
  actorIp: string;
  reason: string;
  reasonAr: string;
  quarantinedAt: number;
  expiresAt: number;
  interceptCount: number;
}

/** Bounded retention so a sustained attack cannot exhaust heap. */
const MAX_SESSION_RECORDS = 5_000;
const MAX_INTERCEPT_HISTORY = 500;
const SESSION_TTL_MS = 30 * 60_000; // 30 minutes
const QUARANTINE_TTL_MS = 15 * 60_000; // 15 minutes

/**
 * Size drift beyond this ratio against the registered baseline is treated as
 * a mutation. A legitimate re-post of the same logical request varies little;
 * an injected parameter or appended payload moves it sharply.
 */
const SIZE_MUTATION_TOLERANCE = 0.25;

/** Sliding activity window per session, per the Stage-2 contract. */
const SESSION_WINDOW_MS = 60_000;
/** Frames retained per window; only the newest matter for burst detection. */
const MAX_WINDOW_SAMPLES = 64;
/** Frames inside the window beyond which ordering is considered abnormal. */
const OUT_OF_ORDER_BURST_THRESHOLD = 24;
/** How long the kernel keeps an invalidated actor null-routed. */
const SOCKET_INVALIDATION_TTL_SECONDS = 900;

/** Fixed weights for the bounded threat-score sum. */
const TAMPER_FLAG_WEIGHT: Record<TamperFlag, number> = {
  PAYLOAD_MUTATED: 45,
  LENGTH_DISCREPANCY: 25,
  PARAMETER_POLLUTED: 20,
  OUT_OF_ORDER: 15
};

/** Keys that must never appear in a JSON body - prototype pollution vectors. */
const PROTOTYPE_POLLUTION_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

/** Headers whose removal mid-flight indicates signature stripping. */
const INTEGRITY_HEADERS = ['x-payload-signature', 'x-content-hmac', 'x-integrity-hash'];

export class InLineInterceptionEngine {
  /** sessionId+route -> integrity baseline. */
  private readonly integrityMap = new Map<string, SessionIntegrityRecord>();
  private readonly quarantine = new Map<string, QuarantinedSession>();
  private readonly history: InterceptionRecord[] = [];

  /** Rolling hash chain, so the audit trail detects deletion and reordering. */
  private auditChainHead = 'GENESIS';

  public totalInspected = 0;
  public totalIntercepted = 0;
  public totalResets = 0;
  public totalHighEntropyBlocks = 0;
  public totalSystemFreezes = 0;
  public totalSocketInvalidations = 0;
  private enabled = true;

  /** Rolling sum/count used to report mean inspection latency in microseconds. */
  private latencyAccumulatorMicros = 0;
  private latencySamples = 0;

  /**
   * Sliding 60-second activity window per session, newest last.
   * Evicting on read keeps the structure bounded without a sweep timer.
   */
  private readonly activeSessionStateMap = new Map<string, number[]>();

  // -------------------------------------------------------------------
  // Core inspection
  // -------------------------------------------------------------------

  /**
   * Inspects one in-flight payload and returns an enforceable verdict.
   *
   * Synchronous and allocation-light: it runs inside request middleware ahead
   * of every handler, so it must never introduce an await boundary.
   */
  public inspect(input: {
    sessionId: string;
    actorIp: string;
    route: string;
    method: string;
    body: unknown;
    headers?: Record<string, string | string[] | undefined>;
    rawQuery?: string;
    declaredContentLength?: number;
    /**
     * Bytes exactly as they arrived on the wire. Entropy is measured against
     * this when supplied, because the canonical JSON re-serialization escapes
     * non-printable bytes and would understate the true entropy of binary or
     * encrypted content by several bits per byte.
     */
    rawPayloadForEntropy?: string;
  }): InterceptionRecord {
    this.totalInspected++;
    const t0 = process.hrtime.bigint();

    const canonical = this.canonicalize(input.body);
    const observedHash = this.sha256(canonical);
    const payloadSizeBytes = Buffer.byteLength(canonical, 'utf-8');
    const key = input.sessionId + '::' + input.route;

    const findings: TamperFinding[] = [];
    const baseline = this.integrityMap.get(key);

    // --- 1. Baseline comparison: hash and size drift ----------------
    if (baseline && !this.isExpired(baseline.lastSeenAt, SESSION_TTL_MS)) {
      baseline.observations++;
      baseline.lastSeenAt = Date.now();

      if (baseline.baselineHash !== observedHash) {
        const sizeDelta = baseline.baselineSize === 0
          ? 1
          : Math.abs(payloadSizeBytes - baseline.baselineSize) / baseline.baselineSize;

        // A differing hash is NOT by itself evidence of tampering. A REST
        // endpoint legitimately accepts different bodies from the same client,
        // so enforcing a hash comparison unconditionally would block normal
        // traffic. The comparison is only binding when the session committed
        // to a fixed digest by supplying an integrity header at baseline time;
        // otherwise the drift is recorded as observational and never blocks.
        if (baseline.integrityProtected) {
          baseline.mutations++;
          findings.push({
            tamperClass: 'PAYLOAD_HASH_MISMATCH',
            severity: 'CRITICAL',
            detail: 'Canonical payload hash diverged from the integrity-protected session baseline.',
            detailAr: 'انحرفت بصمة الحمولة القانونية عن خط الأساس المحمي بالتكامل للجلسة.',
            expected: baseline.baselineHash,
            observed: observedHash
          });
          if (sizeDelta > SIZE_MUTATION_TOLERANCE) {
            findings.push({
              tamperClass: 'SIZE_MUTATION',
              severity: 'HIGH',
              detail: 'Payload size mutated ' + (sizeDelta * 100).toFixed(1)
                + '% against the session baseline (' + baseline.baselineSize + ' -> ' + payloadSizeBytes + ' bytes).',
              detailAr: 'تغير حجم الحمولة بنسبة ' + (sizeDelta * 100).toFixed(1)
                + '% مقارنة بخط الأساس للجلسة (' + baseline.baselineSize + ' إلى ' + payloadSizeBytes + ' بايت).',
              expected: String(baseline.baselineSize),
              observed: String(payloadSizeBytes)
            });
          }
        } else if (sizeDelta > SIZE_MUTATION_TOLERANCE) {
          baseline.mutations++;
          findings.push({
            tamperClass: 'SIZE_MUTATION',
            severity: 'MEDIUM',
            detail: 'Payload size drifted ' + (sizeDelta * 100).toFixed(1)
              + '% from the session baseline. Recorded for correlation; not blocking on its own.',
            detailAr: 'انحرف حجم الحمولة بنسبة ' + (sizeDelta * 100).toFixed(1)
              + '% عن خط الأساس للجلسة. سُجل للربط فقط دون حظر.',
            expected: String(baseline.baselineSize),
            observed: String(payloadSizeBytes)
          });
        }
      }
    } else {
      // First sighting for this session+route becomes the integrity baseline.
      this.registerBaseline(key, {
        sessionId: input.sessionId,
        actorIp: input.actorIp,
        baselineHash: observedHash,
        baselineSize: payloadSizeBytes,
        route: input.route,
        registeredAt: Date.now(),
        lastSeenAt: Date.now(),
        observations: 1,
        mutations: 0,
        integrityProtected: this.hasIntegrityHeader(input.headers)
      });
    }

    // --- 2. Declared vs actual content length -----------------------
    if (typeof input.declaredContentLength === 'number' && input.declaredContentLength > 0) {
      // A sizeable gap between the declared length and the parsed body is a
      // classic request-smuggling / boundary-manipulation indicator.
      const gap = Math.abs(input.declaredContentLength - payloadSizeBytes);
      if (gap > Math.max(64, payloadSizeBytes * 0.5)) {
        findings.push({
          tamperClass: 'CONTENT_LENGTH_MISMATCH',
          severity: 'CRITICAL',
          detail: 'Declared Content-Length ' + input.declaredContentLength
            + ' does not reconcile with the ' + payloadSizeBytes + '-byte parsed body.',
          detailAr: 'طول المحتوى المعلن ' + input.declaredContentLength
            + ' لا يتطابق مع الجسم المحلل البالغ ' + payloadSizeBytes + ' بايت.',
          expected: String(input.declaredContentLength),
          observed: String(payloadSizeBytes)
        });
      }
    }

    // --- 3. HTTP parameter pollution --------------------------------
    const polluted = this.detectParameterPollution(input.rawQuery, input.body);
    if (polluted.length > 0) {
      findings.push({
        tamperClass: 'PARAMETER_POLLUTION',
        severity: 'HIGH',
        detail: 'Duplicate parameters with conflicting values detected: ' + polluted.join(', ') + '.',
        detailAr: 'رُصدت معاملات مكررة بقيم متعارضة: ' + polluted.join('، ') + '.',
        observed: polluted.join(',')
      });
    }

    // --- 4. Prototype pollution -------------------------------------
    const pollutionKey = this.detectPrototypePollution(input.body);
    if (pollutionKey) {
      findings.push({
        tamperClass: 'PROTOTYPE_POLLUTION',
        severity: 'CRITICAL',
        detail: 'Reserved key "' + pollutionKey + '" present in the request body.',
        detailAr: 'وجود مفتاح محجوز "' + pollutionKey + '" داخل جسم الطلب.',
        observed: pollutionKey
      });
    }

    // --- 5. Integrity header stripping / forgery --------------------
    const headerFinding = this.inspectIntegrityHeaders(input.headers, canonical);
    if (headerFinding) findings.push(headerFinding);

    // --- 6. Shannon entropy of the stream ---------------------------
    // Encrypted or packed content moving through a JSON API is either
    // obfuscated shellcode or staged exfiltration; neither is legitimate.
    const entropySource = input.rawPayloadForEntropy ?? canonical;
    const entropy = shannonEntropy(Buffer.from(entropySource, 'binary'));
    if (entropy > HIGH_ENTROPY_THRESHOLD && payloadSizeBytes >= 64) {
      findings.push({
        tamperClass: 'HIGH_ENTROPY_STREAM',
        severity: 'CRITICAL',
        detail: 'Payload entropy ' + entropy.toFixed(4) + ' bits/byte exceeds the '
          + HIGH_ENTROPY_THRESHOLD + ' threshold, indicating encrypted or packed content.',
        detailAr: 'إنتروبيا الحمولة ' + entropy.toFixed(4) + ' بت/بايت تتجاوز العتبة '
          + HIGH_ENTROPY_THRESHOLD + '، ما يشير إلى محتوى مشفر أو محزوم.',
        expected: '<= ' + HIGH_ENTROPY_THRESHOLD,
        observed: entropy.toFixed(4)
      });
    }

    // Track the sliding 60s activity window for this session.
    const burst = this.recordSessionActivity(input.sessionId);

    // --- Verdict ----------------------------------------------------
    const verdict = this.deriveVerdict(findings);
    const primaryTamperClass = this.selectPrimaryClass(findings);

    const record: InterceptionRecord = {
      interceptId: 'ITC-' + crypto.randomBytes(5).toString('hex').toUpperCase(),
      timestamp: Date.now(),
      sessionId: input.sessionId,
      actorIp: input.actorIp,
      route: input.route,
      method: input.method,
      verdict,
      findings,
      primaryTamperClass,
      expectedHash: baseline ? baseline.baselineHash : null,
      observedHash,
      payloadSizeBytes,
      tcpResetIssued: verdict === 'EMERGENCY_RESET',
      quarantined: verdict !== 'PASS',
      auditHash: '',
      entropyScore: 0,
      sessionBurstCount: 0,
      socketInvalidated: false
    };

    // Seal into the rolling audit chain.
    record.auditHash = this.appendToAuditChain(record);

    record.entropyScore = entropy;
    record.sessionBurstCount = burst;

    if (verdict !== 'PASS') {
      this.totalIntercepted++;
      if (entropy > HIGH_ENTROPY_THRESHOLD) this.totalHighEntropyBlocks++;
      if (verdict === 'EMERGENCY_RESET') {
        this.totalResets++;
        // Invalidate the actor at the kernel layer so the next packet is
        // dropped by XDP before it can reach the network stack at all.
        record.socketInvalidated = this.invalidateSocket(record);
      }
      this.quarantineSession(record);
      this.publishIncident(record);
    }

    const elapsedMicros = Number(process.hrtime.bigint() - t0) / 1000;
    this.latencyAccumulatorMicros += elapsedMicros;
    this.latencySamples++;

    this.retainHistory(record);
    return record;
  }

  /**
   * Escalation ladder. A single CRITICAL structural finding, or any two
   * independent findings, means the stream is actively manipulated rather
   * than merely anomalous, which warrants tearing the connection down.
   */
  private deriveVerdict(findings: TamperFinding[]): InterceptVerdict {
    if (findings.length === 0) return 'PASS';
    if (!this.enabled) return 'PASS';

    // MEDIUM findings are correlation signal only. Blocking on them would
    // punish legitimate payload variance, so they never produce a verdict.
    if (findings.some(f => f.severity === 'CRITICAL')) return 'EMERGENCY_RESET';
    if (findings.some(f => f.severity === 'HIGH')) return 'INTERCEPT_DROP';
    return 'PASS';
  }

  private selectPrimaryClass(findings: TamperFinding[]): TamperClass {
    if (findings.length === 0) return 'PAYLOAD_HASH_MISMATCH';
    const rank: Record<TamperFinding['severity'], number> = { CRITICAL: 3, HIGH: 2, MEDIUM: 1 };
    return findings.reduce((top, f) => (rank[f.severity] > rank[top.severity] ? f : top), findings[0]).tamperClass;
  }

  // -------------------------------------------------------------------
  // Detection primitives
  // -------------------------------------------------------------------

  /**
   * Canonical serialization with recursively sorted keys, so two payloads
   * that differ only in key order hash identically and never raise a false
   * tamper alert.
   */
  private canonicalize(value: unknown): string {
    if (value === null || value === undefined) return 'null';
    if (typeof value !== 'object') return JSON.stringify(value) ?? 'null';
    if (Array.isArray(value)) return '[' + value.map(v => this.canonicalize(v)).join(',') + ']';

    const entries = Object.entries(value as Record<string, unknown>)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
    return '{' + entries.map(([k, v]) => JSON.stringify(k) + ':' + this.canonicalize(v)).join(',') + '}';
  }

  /** True when the request carries any integrity/HMAC header. */
  private hasIntegrityHeader(headers?: Record<string, string | string[] | undefined>): boolean {
    if (!headers) return false;
    return INTEGRITY_HEADERS.some(h => headers[h] !== undefined && headers[h] !== '');
  }

  private sha256(input: string): string {
    return crypto.createHash('sha256').update(input).digest('hex');
  }

  /** Duplicate query keys carrying conflicting values (HPP). */
  private detectParameterPollution(rawQuery: string | undefined, body: unknown): string[] {
    const conflicting: string[] = [];
    if (!rawQuery) return conflicting;

    const seen = new Map<string, string>();
    for (const pair of rawQuery.replace(/^\?/, '').split('&')) {
      if (!pair) continue;
      const idx = pair.indexOf('=');
      const key = idx === -1 ? pair : pair.slice(0, idx);
      const val = idx === -1 ? '' : pair.slice(idx + 1);
      if (seen.has(key) && seen.get(key) !== val) {
        if (!conflicting.includes(key)) conflicting.push(key);
      } else {
        seen.set(key, val);
      }
    }

    // A body key that contradicts a query key of the same name is the other
    // half of the same attack class.
    if (body && typeof body === 'object' && !Array.isArray(body)) {
      for (const [k, v] of Object.entries(body as Record<string, unknown>)) {
        if (seen.has(k) && typeof v !== 'object' && String(v) !== seen.get(k)) {
          if (!conflicting.includes(k)) conflicting.push(k);
        }
      }
    }

    return conflicting;
  }

  /** Walks the body for reserved prototype keys, bounded against deep nesting. */
  private detectPrototypePollution(body: unknown, depth: number = 0): string | null {
    if (depth > 6 || !body || typeof body !== 'object') return null;

    // Object.keys skips a literal __proto__ setter, so raw key inspection uses
    // getOwnPropertyNames to catch a parsed JSON payload carrying one.
    for (const key of Object.getOwnPropertyNames(body)) {
      if (PROTOTYPE_POLLUTION_KEYS.has(key)) return key;
      const child = (body as Record<string, unknown>)[key];
      if (child && typeof child === 'object') {
        const nested = this.detectPrototypePollution(child, depth + 1);
        if (nested) return nested;
      }
    }
    return null;
  }

  /**
   * When a caller supplies an integrity header, it must reconcile with the
   * payload. A present-but-wrong value is forgery; a header that was present
   * on the session baseline and has since vanished is stripping.
   */
  private inspectIntegrityHeaders(
    headers: Record<string, string | string[] | undefined> | undefined,
    canonical: string
  ): TamperFinding | null {
    if (!headers) return null;

    for (const name of INTEGRITY_HEADERS) {
      const raw = headers[name];
      if (raw === undefined) continue;
      const supplied = Array.isArray(raw) ? raw[0] : raw;
      if (!supplied) continue;

      const expected = this.sha256(canonical);
      if (supplied.toLowerCase() !== expected.toLowerCase()) {
        return {
          tamperClass: 'INTEGRITY_HEADER_FORGED',
          severity: 'CRITICAL',
          detail: 'Supplied ' + name + ' does not match the canonical payload digest.',
          detailAr: 'ترويسة ' + name + ' المقدمة لا تطابق بصمة الحمولة القانونية.',
          expected,
          observed: supplied
        };
      }
    }
    return null;
  }

  // -------------------------------------------------------------------
  // Sliding window, kernel invalidation, and the transit-packet pipeline
  // -------------------------------------------------------------------

  /**
   * Records one frame against the session's sliding 60-second window and
   * returns how many frames now fall inside it.
   *
   * Timestamps are appended in order, so eviction only ever removes a prefix:
   * advancing an index beats filtering the array, and the window is capped so
   * a flood cannot grow it without bound.
   */
  private recordSessionActivity(sessionId: string): number {
    const now = Date.now();
    const cutoff = now - SESSION_WINDOW_MS;
    const window = this.activeSessionStateMap.get(sessionId) ?? [];

    let start = 0;
    while (start < window.length && window[start] < cutoff) start++;
    const fresh = start > 0 ? window.slice(start) : window;
    fresh.push(now);
    if (fresh.length > MAX_WINDOW_SAMPLES) {
      fresh.splice(0, fresh.length - MAX_WINDOW_SAMPLES);
    }
    this.activeSessionStateMap.set(sessionId, fresh);

    // LRU trim: Map iterates in insertion order, so the first key is oldest.
    while (this.activeSessionStateMap.size > MAX_SESSION_RECORDS) {
      const oldest = this.activeSessionStateMap.keys().next().value as string | undefined;
      if (oldest === undefined) break;
      this.activeSessionStateMap.delete(oldest);
    }
    return fresh.length;
  }

  /**
   * Pushes the offending actor into the kernel BPF map so subsequent packets
   * are dropped at the driver rather than merely refused by Express. This is
   * the simulated equivalent of issuing a TCP RST and null-routing the peer.
   *
   * Never allowed to throw: the HTTP response has already been decided by the
   * time this runs, and a kernel-bridge failure must not unwind it.
   */
  private invalidateSocket(record: InterceptionRecord): boolean {
    try {
      globalEbpfEngine.enforceNullRoute(
        record.actorIp,
        'In-line interception: ' + record.primaryTamperClass + ' on ' + record.route,
        SOCKET_INVALIDATION_TTL_SECONDS
      );
      this.totalSocketInvalidations++;
      return true;
    } catch (err: any) {
      console.warn('[InLineInterception] Kernel socket invalidation failed:', err?.message || err);
      return false;
    }
  }

  /**
   * Full Stage-2 pipeline for one frame of data in transit.
   *
   * Builds the formal DataTransitPacket observation, adjudicates it, and
   * returns both alongside the underlying interception record. The sender's
   * committed digest is verified with HMAC-SHA256 under a system-derived key
   * and compared in constant time, so the comparison cannot be used as a
   * byte-by-byte forgery oracle.
   */
  public analyzeTransitPacket(input: {
    sessionToken: string;
    source: NetworkEndpoint;
    destination: NetworkEndpoint;
    payloadRaw: string;
    expectedPayloadHash?: string;
    rawQuery?: string;
    declaredContentLength?: number;
    route?: string;
    method?: string;
  }): { packet: DataTransitPacket; decision: InterceptionDecision; record: InterceptionRecord } {
    const route = input.route ?? '/api/v1/transit';
    const payload = input.payloadRaw ?? '';

    // The authoritative digest of what actually arrived.
    const actualPayloadHash = hmacSha256(payload);
    const expectedPayloadHash = input.expectedPayloadHash ?? actualPayloadHash;

    // Parse structured bodies so structural attacks are still visible; fall
    // back to the raw string when the payload is not JSON.
    let parsedBody: unknown = payload;
    try {
      const trimmed = payload.trim();
      parsedBody = trimmed.startsWith('{') || trimmed.startsWith('[') ? JSON.parse(payload) : payload;
    } catch {
      parsedBody = payload;
    }

    const record = this.inspect({
      sessionId: input.sessionToken,
      actorIp: input.source.ip,
      route,
      method: input.method ?? 'POST',
      body: parsedBody,
      rawQuery: input.rawQuery,
      declaredContentLength: input.declaredContentLength,
      rawPayloadForEntropy: payload
    });

    // Constant-time digest comparison drives the primary tamper flag.
    const digestMatches = digestsEqual(expectedPayloadHash, actualPayloadHash);
    const tamperFlags = this.deriveTamperFlags(record, digestMatches);

    const packet: DataTransitPacket = {
      packetId: uuidv4(),
      sessionToken: input.sessionToken,
      sourceEndpoint: input.source,
      destinationEndpoint: input.destination,
      payloadRaw: payload.length > 2048 ? payload.slice(0, 2048) + '...[truncated]' : payload,
      expectedPayloadHash,
      actualPayloadHash,
      tamperFlags,
      timestamp: Date.now()
    };

    const decision = this.adjudicate(packet, record);

    // A digest mismatch that the structural checks alone did not catch is
    // still direct evidence of manipulation, so it must invalidate the socket.
    if (!digestMatches && !record.socketInvalidated) {
      // Promote the record's own verdict too. Downstream consumers - the link
      // graph, the audit feed, the counters - all filter on verdict, so
      // leaving it at PASS would hide a confirmed interception from the SOC.
      record.verdict = 'EMERGENCY_RESET';
      record.primaryTamperClass = 'PAYLOAD_HASH_MISMATCH';
      record.quarantined = true;
      record.socketInvalidated = this.invalidateSocket(record);
      record.tcpResetIssued = true;
      this.totalIntercepted++;
      this.totalResets++;
      this.quarantineSession(record);
      this.publishIncident(record);
    }

    return { packet, decision, record };
  }

  /** Maps engine findings onto the formal TamperFlag vocabulary. */
  private deriveTamperFlags(record: InterceptionRecord, digestMatches: boolean): TamperFlag[] {
    const flags = new Set<TamperFlag>();
    if (!digestMatches) flags.add('PAYLOAD_MUTATED');

    for (const finding of record.findings) {
      switch (finding.tamperClass) {
        case 'PAYLOAD_HASH_MISMATCH':
        case 'INTEGRITY_HEADER_FORGED':
        case 'PROTOTYPE_POLLUTION':
        case 'HIGH_ENTROPY_STREAM':
          flags.add('PAYLOAD_MUTATED');
          break;
        case 'SIZE_MUTATION':
        case 'CONTENT_LENGTH_MISMATCH':
          flags.add('LENGTH_DISCREPANCY');
          break;
        case 'PARAMETER_POLLUTION':
          flags.add('PARAMETER_POLLUTED');
          break;
        case 'SIGNATURE_STRIPPING':
          flags.add('OUT_OF_ORDER');
          break;
      }
    }

    // A burst well beyond the window norm means frames are arriving faster
    // than a well-behaved client would emit them.
    if (record.sessionBurstCount > OUT_OF_ORDER_BURST_THRESHOLD) flags.add('OUT_OF_ORDER');

    return Array.from(flags);
  }

  /**
   * Deterministic adjudication.
   *
   * The threat score is a bounded weighted sum: each flag class contributes a
   * fixed weight, entropy above the threshold contributes proportionally to
   * how far past it the sample sits, and the total is clamped to 0-100.
   * Confidence rises with the number of independent signals that agreed.
   */
  private adjudicate(packet: DataTransitPacket, record: InterceptionRecord): InterceptionDecision {
    let score = 0;
    for (const flag of packet.tamperFlags) score += TAMPER_FLAG_WEIGHT[flag] ?? 0;

    if (record.entropyScore > HIGH_ENTROPY_THRESHOLD) {
      // Scale the remaining headroom (7.2 -> 8.0) onto 0 -> 25 points.
      const excess = (record.entropyScore - HIGH_ENTROPY_THRESHOLD) / (8 - HIGH_ENTROPY_THRESHOLD);
      score += Math.round(excess * 25);
    }

    const threatScore = Math.max(0, Math.min(100, score));
    const signalCount = packet.tamperFlags.length + (record.entropyScore > HIGH_ENTROPY_THRESHOLD ? 1 : 0);
    const confidence = Number(Math.min(0.99, 0.55 + signalCount * 0.13).toFixed(2));

    let action: InterceptionDecision['action'] = 'ALLOW';
    if (threatScore >= 85) {
      action = 'TRIGGER_SYSTEM_FREEZE';
    } else if (record.entropyScore > HIGH_ENTROPY_THRESHOLD) {
      // Encrypted content on a plaintext API is never recoverable to ALLOW.
      action = 'TERMINATE_SESSION_TCP_RST';
    } else if (packet.tamperFlags.includes('PAYLOAD_MUTATED')) {
      // A digest divergence is direct proof the bytes were rewritten in
      // flight. That is conclusive on its own and must tear the session down,
      // regardless of whether the structural checks also fired.
      action = 'TERMINATE_SESSION_TCP_RST';
    } else if (record.verdict === 'EMERGENCY_RESET') {
      action = 'TERMINATE_SESSION_TCP_RST';
    } else if (record.verdict === 'INTERCEPT_DROP' || packet.tamperFlags.length > 0) {
      action = 'BLOCK_AND_ISOLATE';
    }

    if (action === 'TRIGGER_SYSTEM_FREEZE') {
      this.totalSystemFreezes++;
      try {
        globalEbpfEngine.enforceEmergencyLockdown(
          true,
          'In-line interception: composite tamper score ' + threatScore + '/100 from ' + packet.sourceEndpoint.ip
        );
      } catch (err: any) {
        console.warn('[InLineInterception] System freeze failed:', err?.message || err);
      }
    }

    return {
      action,
      threatScore,
      confidence,
      mitreTechnique: this.selectTechnique(packet, record),
      forensicDigest: sha256Hex(canonicalSerialize({ packet, findings: record.findings, verdict: record.verdict }))
    };
  }

  /** Chooses the ATT&CK technique that best characterises the observation. */
  private selectTechnique(packet: DataTransitPacket, record: InterceptionRecord): string {
    if (record.entropyScore > HIGH_ENTROPY_THRESHOLD) {
      return 'T1048 - Exfiltration Over Alternative Protocol';
    }
    if (packet.tamperFlags.includes('PAYLOAD_MUTATED')) {
      return 'T1565.001 - Data Manipulation: Stored Data Manipulation';
    }
    if (packet.tamperFlags.includes('PARAMETER_POLLUTED')) {
      return 'T1190 - Exploit Public-Facing Application';
    }
    if (packet.tamperFlags.includes('LENGTH_DISCREPANCY')) {
      return 'T1071.001 - Application Layer Protocol: Web Protocols';
    }
    return 'T1557 - Adversary-in-the-Middle';
  }

  // -------------------------------------------------------------------
  // Quarantine and state
  // -------------------------------------------------------------------

  private registerBaseline(key: string, record: SessionIntegrityRecord): void {
    this.integrityMap.set(key, record);
    // Bounded LRU-style trim: Map preserves insertion order, so the oldest
    // key is the first the iterator yields.
    while (this.integrityMap.size > MAX_SESSION_RECORDS) {
      const oldest = this.integrityMap.keys().next().value as string | undefined;
      if (oldest === undefined) break;
      this.integrityMap.delete(oldest);
    }
  }

  private quarantineSession(record: InterceptionRecord): void {
    const existing = this.quarantine.get(record.sessionId);
    this.quarantine.set(record.sessionId, {
      sessionId: record.sessionId,
      actorIp: record.actorIp,
      reason: record.primaryTamperClass + ' on ' + record.route,
      reasonAr: 'اعتراض ' + record.primaryTamperClass + ' على المسار ' + record.route,
      quarantinedAt: existing?.quarantinedAt ?? Date.now(),
      expiresAt: Date.now() + QUARANTINE_TTL_MS,
      interceptCount: (existing?.interceptCount ?? 0) + 1
    });
  }

  /** True when the session is actively quarantined and must be refused. */
  public isQuarantined(sessionId: string): boolean {
    const entry = this.quarantine.get(sessionId);
    if (!entry) return false;
    if (entry.expiresAt <= Date.now()) {
      this.quarantine.delete(sessionId);
      return false;
    }
    return true;
  }

  public releaseSession(sessionId: string): boolean {
    return this.quarantine.delete(sessionId);
  }

  public getActiveQuarantines(): QuarantinedSession[] {
    const now = Date.now();
    const active: QuarantinedSession[] = [];
    for (const [id, entry] of this.quarantine.entries()) {
      if (entry.expiresAt <= now) {
        this.quarantine.delete(id);
        continue;
      }
      active.push(entry);
    }
    return active.sort((a, b) => b.quarantinedAt - a.quarantinedAt);
  }

  private isExpired(timestamp: number, ttlMs: number): boolean {
    return Date.now() - timestamp > ttlMs;
  }

  // -------------------------------------------------------------------
  // Tamper-evident audit chain
  // -------------------------------------------------------------------

  /**
   * Each record is hashed together with the previous record's hash, so the
   * log detects not just edits but also deletion and reordering - properties
   * an isolated per-record hash cannot provide.
   */
  private appendToAuditChain(record: InterceptionRecord): string {
    const body = this.canonicalize({
      interceptId: record.interceptId,
      timestamp: record.timestamp,
      sessionId: record.sessionId,
      actorIp: record.actorIp,
      route: record.route,
      verdict: record.verdict,
      observedHash: record.observedHash,
      findings: record.findings
    });
    const chained = this.sha256(this.auditChainHead + ':' + body);
    this.auditChainHead = chained;
    return chained;
  }

  /** Re-walks the retained history and reports the first broken link. */
  public verifyAuditChain(): { valid: boolean; brokenAt: string | null; verified: number } {
    let head = 'GENESIS';
    // The retained window may have evicted earlier records, so verification
    // starts from the oldest record still held rather than from genesis.
    if (this.history.length === 0) return { valid: true, brokenAt: null, verified: 0 };

    let verified = 0;
    for (const record of this.history) {
      const body = this.canonicalize({
        interceptId: record.interceptId,
        timestamp: record.timestamp,
        sessionId: record.sessionId,
        actorIp: record.actorIp,
        route: record.route,
        verdict: record.verdict,
        observedHash: record.observedHash,
        findings: record.findings
      });
      const expected = this.sha256(head + ':' + body);
      if (verified > 0 && expected !== record.auditHash) {
        return { valid: false, brokenAt: record.interceptId, verified };
      }
      head = record.auditHash;
      verified++;
    }
    return { valid: true, brokenAt: null, verified };
  }

  // -------------------------------------------------------------------
  // Telemetry
  // -------------------------------------------------------------------

  private publishIncident(record: InterceptionRecord): void {
    try {
      globalUnifiedTelemetryService.recordEvent({
        source: 'IN_TRANSIT_INSPECTION',
        severity: record.verdict === 'EMERGENCY_RESET' ? 'CRITICAL' : 'HIGH',
        title: '[Interception] ' + record.verdict + ' - ' + record.primaryTamperClass
          + ' from ' + record.actorIp + ' on ' + record.route,
        titleAr: '[الاعتراض] ' + record.verdict + ' - ' + record.primaryTamperClass
          + ' من ' + record.actorIp + ' على المسار ' + record.route,
        details: record.findings.map(f => f.detail).join(' | '),
        detailsAr: record.findings.map(f => f.detailAr).join(' | '),
        actorIp: record.actorIp,
        sessionId: record.sessionId,
        mitreTactic: 'Collection',
        mitreTechnique: 'T1557 - Adversary-in-the-Middle',
        actionTaken: record.verdict === 'EMERGENCY_RESET'
          ? 'IN_LINE_INTERCEPT_TCP_RESET'
          : 'IN_LINE_INTERCEPT_DROP',
        actionTakenAr: record.verdict === 'EMERGENCY_RESET'
          ? 'اعتراض فوري مع إعادة تعيين اتصال TCP'
          : 'اعتراض وإسقاط الحمولة',
        metadata: {
          interceptId: record.interceptId,
          expectedHash: record.expectedHash,
          observedHash: record.observedHash,
          payloadSizeBytes: record.payloadSizeBytes,
          findings: record.findings,
          auditHash: record.auditHash,
          tcpResetIssued: record.tcpResetIssued
        }
      });
    } catch (err: any) {
      console.warn('[InLineInterception] Telemetry publish failed:', err?.message || err);
    }

    // Live push so the SOC matrix lights up without waiting for a poll.
    try {
      globalTelemetryWsServer.broadcast('interception:tamper', record);
    } catch (err: any) {
      console.warn('[InLineInterception] WS broadcast failed:', err?.message || err);
    }
  }

  private retainHistory(record: InterceptionRecord): void {
    this.history.push(record);
    while (this.history.length > MAX_INTERCEPT_HISTORY) this.history.shift();
  }

  // -------------------------------------------------------------------
  // Query surface
  // -------------------------------------------------------------------

  public getRecentInterceptions(limit: number = 50): InterceptionRecord[] {
    const bounded = Math.max(1, Math.min(limit, MAX_INTERCEPT_HISTORY));
    return this.history.slice(-bounded).reverse();
  }

  public getSessionBaseline(sessionId: string, route: string): SessionIntegrityRecord | null {
    return this.integrityMap.get(sessionId + '::' + route) ?? null;
  }

  public setEnabled(enabled: boolean): boolean {
    this.enabled = enabled;
    return this.enabled;
  }

  public isEnabled(): boolean {
    return this.enabled;
  }

  public getStats() {
    return {
      enabled: this.enabled,
      totalInspected: this.totalInspected,
      totalIntercepted: this.totalIntercepted,
      totalResets: this.totalResets,
      interceptRatePercent: this.totalInspected === 0
        ? 0
        : Number(((this.totalIntercepted / this.totalInspected) * 100).toFixed(2)),
      trackedSessions: this.integrityMap.size,
      maxTrackedSessions: MAX_SESSION_RECORDS,
      activeQuarantines: this.getActiveQuarantines().length,
      retainedInterceptions: this.history.length,
      auditChainHead: this.auditChainHead,
      highEntropyBlocks: this.totalHighEntropyBlocks,
      systemFreezes: this.totalSystemFreezes,
      socketInvalidations: this.totalSocketInvalidations,
      trackedWindows: this.activeSessionStateMap.size,
      meanInspectionLatencyMicros: this.latencySamples === 0
        ? 0
        : Number((this.latencyAccumulatorMicros / this.latencySamples).toFixed(2))
    };
  }

  public clear(): void {
    this.integrityMap.clear();
    this.quarantine.clear();
    this.history.length = 0;
    this.auditChainHead = 'GENESIS';
    this.activeSessionStateMap.clear();
    this.totalInspected = 0;
    this.totalIntercepted = 0;
    this.totalResets = 0;
    this.totalHighEntropyBlocks = 0;
    this.totalSystemFreezes = 0;
    this.totalSocketInvalidations = 0;
    this.latencyAccumulatorMicros = 0;
    this.latencySamples = 0;
  }
}

export const globalInLineInterceptionEngine = new InLineInterceptionEngine();
