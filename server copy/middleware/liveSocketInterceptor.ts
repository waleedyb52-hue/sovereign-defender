import type express from 'express';
import crypto from 'crypto';
import { globalUnifiedTelemetryService } from '../services/unifiedTelemetry.service.js';
import { globalTelemetryWsServer } from '../wsServer.js';
import { globalEbpfEngine } from '../ebpfEngine.js';
import { globalHttpTrafficTelemetryService } from '../services/httpTrafficTelemetry.service.js';

// =============================================================================
// LIVE WIRE-LEVEL SOCKET INTERCEPTOR (v1.0)
//
// Inspects the real request before it becomes application data, and destroys
// the real TCP socket when the raw bytes are hostile.
//
// STREAM-SAFETY DESIGN NOTE
// -------------------------
// A middleware that consumes req via req.on('data') to inspect the body will
// starve express.json(), which reads the same stream afterwards - every POST
// would then hang until it timed out. This module therefore splits the work
// across the only two points that can see raw bytes without stealing them:
//
//   1. preParseGate()  - runs BEFORE any body parser. It never touches the
//                        body stream at all, only the wire-level metadata
//                        that is already parsed by Node's HTTP layer: method,
//                        raw URL, and headers. URL-borne attacks (traversal,
//                        command injection, SQLi in the query string) are
//                        killed here, before a single body byte is read.
//
//   2. rawBodyVerifier() - passed to express.json({ verify }). Body parsers
//                        hand this the complete raw Buffer BEFORE parsing it,
//                        so the real bytes are inspected and the real HMAC is
//                        computed without competing for the stream. Throwing
//                        here aborts parsing; the paired error handler then
//                        destroys the socket.
//
// This is the difference between "inspects raw bytes" and "breaks the server".
// =============================================================================

export type WireThreatClass =
  | 'DIRECTORY_TRAVERSAL'
  | 'COMMAND_INJECTION'
  | 'SQL_INJECTION'
  | 'XSS_INJECTION'
  | 'NULL_BYTE_INJECTION'
  | 'HEADER_SMUGGLING'
  | 'OVERSIZED_FRAME';

export interface WireInterceptRecord {
  interceptId: string;
  timestamp: number;
  sourceIp: string;
  method: string;
  rawUrl: string;
  threatClass: WireThreatClass;
  matchedPattern: string;
  matchedIn: 'URL' | 'HEADER' | 'BODY';
  /** Real HMAC-SHA256 over the raw bytes actually received. */
  rawHmacSha256: string | null;
  rawByteLength: number;
  socketDestroyed: boolean;
  bannedIp: boolean;
  xdpDropDispatched: boolean;
}

/** Per-process HMAC key over raw wire buffers. */
const WIRE_HMAC_KEY: Buffer = process.env.WIRE_HMAC_SECRET
  ? crypto.createHash('sha256').update(process.env.WIRE_HMAC_SECRET).digest()
  : crypto.randomBytes(32);

const MAX_RECORDS = 400;
/** Frames beyond this are refused outright rather than inspected. */
const MAX_FRAME_BYTES = 8 * 1024 * 1024;

/**
 * Paths exempt from wire-level termination.
 *
 * The SOC console legitimately transports attack strings as DATA - the FIM
 * drill posts a web shell, the interception drill posts traversal sequences,
 * the deception probe posts obfuscated payloads. Destroying those sockets
 * would make the defender unable to operate their own platform. Vite's dev
 * client is exempt for the same practical reason.
 */
const WIRE_EXEMPT_PREFIXES = [
  '/api/v1/soc/',
  // The defense control surface legitimately carries hostile-looking data:
  // /poison/scan submits recovered leak text for watermark matching, which
  // can contain anything at all. Scanning it would terminate the analyst.
  '/api/v1/soc/defense/',
  '/api/v1/soc/admin/',
  '/api/v1/fim/',
  '/api/v1/agent/',
  '/api/v1/tools/',
  '/api/v1/traffic/',
  '/api/v1/quarantine/',
  '/api/v1/topology/',
  '/api/v1/insider-zero-trust/',
  '/@vite', '/@react-refresh', '/src/', '/node_modules/', '/assets/'
];

const IMMUNE_IPS = new Set(['127.0.0.1', '::1', '10.0.0.1', '10.0.0.2']);

/**
 * Deterministic signature matrix applied to raw, unparsed input.
 *
 * Patterns are intentionally narrow. A wire-level rule that fires wrongly
 * does not merely log - it tears down a live TCP connection, so the cost of a
 * false positive here is a broken page for a real user.
 */
const WIRE_SIGNATURES: Array<{ cls: WireThreatClass; pattern: RegExp; label: string }> = [
  { cls: 'DIRECTORY_TRAVERSAL', pattern: /(\.\.[\/\\]){2,}/, label: 'repeated ../ traversal' },
  { cls: 'DIRECTORY_TRAVERSAL', pattern: /\.\.[\/\\](etc|windows|proc|root|home)[\/\\]/i, label: '../ into a system directory' },
  { cls: 'DIRECTORY_TRAVERSAL', pattern: /%2e%2e(%2f|%5c)/i, label: 'encoded ../ traversal' },
  { cls: 'COMMAND_INJECTION', pattern: /[;|&`]\s*(whoami|cat|curl|wget|nc|bash|sh|id|uname|chmod)\b/i, label: 'shell metacharacter + command' },
  { cls: 'COMMAND_INJECTION', pattern: /\$\(\s*(whoami|id|cat|curl|wget|uname)/i, label: 'command substitution' },
  { cls: 'COMMAND_INJECTION', pattern: /\/etc\/(passwd|shadow|sudoers)\b/i, label: 'credential file access' },
  { cls: 'COMMAND_INJECTION', pattern: /(bash\s+-i\s*>&|\/dev\/tcp\/)/i, label: 'reverse shell' },
  { cls: 'SQL_INJECTION', pattern: /union[\s\/*]+(all[\s\/*]+)?select/i, label: 'UNION SELECT' },
  { cls: 'SQL_INJECTION', pattern: /;\s*drop\s+(table|database)\b/i, label: 'stacked DROP' },
  { cls: 'SQL_INJECTION', pattern: /(sleep\s*\(\s*\d+\s*\)|benchmark\s*\(|pg_sleep\s*\()/i, label: 'time-based blind SQLi' },
  { cls: 'XSS_INJECTION', pattern: /<script[\s>]|javascript:\s*[a-z]|on(error|load)\s*=\s*["']?\s*[a-z]/i, label: 'script injection' },
  { cls: 'NULL_BYTE_INJECTION', pattern: /%00/, label: 'encoded null byte' }
];

/** Headers whose duplication or contradiction indicates request smuggling. */
function detectHeaderSmuggling(headers: express.Request['headers']): string | null {
  const te = headers['transfer-encoding'];
  const cl = headers['content-length'];
  if (te && cl) return 'Transfer-Encoding and Content-Length both present';
  if (Array.isArray(cl) && cl.length > 1) return 'duplicate Content-Length headers';
  if (typeof te === 'string' && /chunked.*chunked/i.test(te)) return 'duplicated chunked encoding';
  return null;
}

export class LiveSocketInterceptor {
  private readonly records: WireInterceptRecord[] = [];
  public totalInspected = 0;
  public totalTerminated = 0;
  public totalBodyBytesHashed = 0;
  private enabled = true;

  public isExempt(path: string): boolean {
    return WIRE_EXEMPT_PREFIXES.some(p => path.startsWith(p));
  }

  public resolveIp(req: express.Request): string {
    const ip = req.ip || req.socket?.remoteAddress || '127.0.0.1';
    return ip.replace(/^::ffff:/, '').trim();
  }

  /** Real HMAC-SHA256 over the exact bytes received on the wire. */
  public hmacRaw(buffer: Buffer): string {
    return crypto.createHmac('sha256', WIRE_HMAC_KEY).update(buffer).digest('hex');
  }

  /**
   * Runs the signature matrix over raw input AND a percent-decoded copy.
   *
   * Scanning only the raw wire bytes is trivially evaded: `UNION%20SELECT`
   * never matches /union\s+select/ because the separator is still literal
   * "%20". Verified in testing - that exact payload walked past the raw-only
   * scanner. Both readings are therefore searched, and decoding is repeated
   * (bounded) so double-encoded payloads collapse too.
   */
  public scan(raw: string): { cls: WireThreatClass; label: string; matched: string } | null {
    const surfaces = [raw];

    let decoded = raw;
    for (let i = 0; i < 3; i++) {
      const next = this.safeDecode(decoded);
      if (next === decoded) break;
      decoded = next;
      surfaces.push(decoded);
    }
    // Plus-decoding, since form encoding uses '+' for space.
    if (decoded.includes('+')) surfaces.push(decoded.replace(/\+/g, ' '));

    for (const sig of WIRE_SIGNATURES) {
      for (const surface of surfaces) {
        const m = surface.match(sig.pattern);
        if (m) return { cls: sig.cls, label: sig.label, matched: String(m[0]).slice(0, 120) };
      }
    }
    return null;
  }

  /** Percent-decode that never throws on deliberately malformed sequences. */
  private safeDecode(input: string): string {
    try {
      return decodeURIComponent(input);
    } catch {
      return input.replace(/%[0-9a-fA-F]{2}/g, m => {
        try { return decodeURIComponent(m); } catch { return m; }
      });
    }
  }

  /**
   * Terminates the connection at the transport layer.
   *
   * A best-effort 403 is written first so a legitimate client that tripped a
   * rule still sees a reason, then the socket is destroyed on the next tick.
   * Destroying inside the current tick can abort the write mid-flight, and
   * destroy() is wrapped because the peer may already have gone away - an
   * uncaught throw here would take down the request handler.
   */
  public terminate(
    req: express.Request,
    res: express.Response,
    record: WireInterceptRecord
  ): void {
    try {
      if (!res.headersSent) {
        res.status(403);
        res.setHeader('X-Defender-Wire', 'TERMINATED');
        res.setHeader('X-Defender-Threat', record.threatClass);
        res.json({
          success: false,
          error: 'WIRE_LEVEL_TERMINATION',
          threatClass: record.threatClass,
          message: 'Connection terminated at the transport layer by live wire inspection.',
          messageAr: 'أُنهي الاتصال عند طبقة النقل بواسطة الفحص المباشر للحزم.'
        });
      }
    } catch {
      /* response already gone; the destroy below is what matters */
    }

    setImmediate(() => {
      try {
        req.socket?.destroy();
        record.socketDestroyed = true;
      } catch (err: any) {
        console.warn('[WireInterceptor] Socket destroy failed:', err?.message || err);
      }
    });
    this.totalTerminated++;
  }

  /** Live network containment: real ban list entry plus an XDP drop event. */
  public contain(record: WireInterceptRecord): void {
    try {
      globalHttpTrafficTelemetryService.banIp(
        record.sourceIp,
        'Wire-level termination: ' + record.threatClass + ' (' + record.matchedPattern + ')',
        'إنهاء على مستوى الحزمة: ' + record.threatClass,
        'LIVE_WIRE_INTERCEPTOR'
      );
      record.bannedIp = true;
    } catch (err: any) {
      console.warn('[WireInterceptor] Ban failed:', err?.message || err);
    }

    try {
      globalEbpfEngine.enforceNullRoute(
        record.sourceIp,
        'Wire interceptor: ' + record.threatClass,
        3600
      );
      record.xdpDropDispatched = true;
    } catch (err: any) {
      console.warn('[WireInterceptor] XDP dispatch failed:', err?.message || err);
    }
  }

  public publish(record: WireInterceptRecord): void {
    this.records.push(record);
    while (this.records.length > MAX_RECORDS) this.records.shift();

    try {
      globalUnifiedTelemetryService.recordEvent({
        source: 'IN_TRANSIT_INSPECTION',
        severity: 'CRITICAL',
        title: '[Wire] TCP termination - ' + record.threatClass + ' from ' + record.sourceIp
          + ' on ' + record.method + ' ' + record.rawUrl.slice(0, 60),
        titleAr: '[الحزم] إنهاء اتصال TCP - ' + record.threatClass + ' من ' + record.sourceIp,
        details: 'Matched "' + record.matchedPattern + '" in the raw ' + record.matchedIn
          + '. Socket destroyed, source banned, XDP drop dispatched.',
        detailsAr: 'طابق النمط "' + record.matchedPattern + '" في ' + record.matchedIn
          + ' الخام. دُمّر المقبس وحُظر المصدر وأُرسل أمر الإسقاط.',
        actorIp: record.sourceIp,
        mitreTactic: 'Initial Access',
        mitreTechnique: 'T1190 - Exploit Public-Facing Application',
        actionTaken: 'LIVE_WIRE_TCP_TERMINATION',
        actionTakenAr: 'إنهاء الاتصال على مستوى النقل',
        metadata: {
          interceptId: record.interceptId,
          threatClass: record.threatClass,
          matchedPattern: record.matchedPattern,
          matchedIn: record.matchedIn,
          rawHmacSha256: record.rawHmacSha256,
          rawByteLength: record.rawByteLength,
          socketDestroyed: record.socketDestroyed,
          bannedIp: record.bannedIp,
          xdpDropDispatched: record.xdpDropDispatched,
          realSocketTermination: true
        }
      });
    } catch (err: any) {
      console.warn('[WireInterceptor] Telemetry failed:', err?.message || err);
    }

    try {
      globalTelemetryWsServer.broadcast('wire:termination', record);
    } catch { /* transport optional */ }
  }

  public buildRecord(seed: Partial<WireInterceptRecord> & {
    sourceIp: string; method: string; rawUrl: string;
    threatClass: WireThreatClass; matchedPattern: string; matchedIn: 'URL' | 'HEADER' | 'BODY';
  }): WireInterceptRecord {
    return {
      interceptId: 'WIRE-' + crypto.randomBytes(5).toString('hex').toUpperCase(),
      timestamp: Date.now(),
      rawHmacSha256: null,
      rawByteLength: 0,
      socketDestroyed: false,
      bannedIp: false,
      xdpDropDispatched: false,
      ...seed
    };
  }

  public setEnabled(v: boolean): boolean { this.enabled = v; return this.enabled; }
  public isEnabled(): boolean { return this.enabled; }
  public getRecords(limit = 50): WireInterceptRecord[] {
    return this.records.slice(-Math.max(1, Math.min(limit, MAX_RECORDS))).reverse();
  }
  public getStats() {
    return {
      enabled: this.enabled,
      totalInspected: this.totalInspected,
      totalTerminated: this.totalTerminated,
      totalBodyBytesHashed: this.totalBodyBytesHashed,
      terminationRatePercent: this.totalInspected === 0 ? 0
        : Number(((this.totalTerminated / this.totalInspected) * 100).toFixed(2)),
      signatureCount: WIRE_SIGNATURES.length,
      retainedRecords: this.records.length,
      hmacKeySource: process.env.WIRE_HMAC_SECRET ? 'operator-supplied' : 'per-boot random'
    };
  }
}

export const globalLiveSocketInterceptor = new LiveSocketInterceptor();

// -----------------------------------------------------------------------
// Middleware 1: pre-parser wire gate (runs before ANY body parser)
// -----------------------------------------------------------------------

/**
 * Inspects wire metadata that Node has already parsed - method, raw URL and
 * headers - without reading a single byte of the body stream. This is what
 * makes it safe to run ahead of express.json().
 */
export function preParseGate(
  req: express.Request,
  res: express.Response,
  next: express.NextFunction
) {
  try {
    const interceptor = globalLiveSocketInterceptor;
    if (!interceptor.isEnabled()) return next();

    const rawUrl = req.originalUrl || req.url || '/';
    const pathOnly = rawUrl.split('?')[0];
    if (interceptor.isExempt(pathOnly)) return next();

    const sourceIp = interceptor.resolveIp(req);
    if (IMMUNE_IPS.has(sourceIp)) return next();

    interceptor.totalInspected++;

    // --- Request smuggling in the real header set -----------------
    const smuggling = detectHeaderSmuggling(req.headers);
    if (smuggling) {
      const record = interceptor.buildRecord({
        sourceIp, method: req.method, rawUrl,
        threatClass: 'HEADER_SMUGGLING', matchedPattern: smuggling, matchedIn: 'HEADER'
      });
      interceptor.contain(record);
      interceptor.publish(record);
      return interceptor.terminate(req, res, record);
    }

    // --- Oversized frame ------------------------------------------
    const declared = Number(req.headers['content-length']);
    if (Number.isFinite(declared) && declared > MAX_FRAME_BYTES) {
      const record = interceptor.buildRecord({
        sourceIp, method: req.method, rawUrl,
        threatClass: 'OVERSIZED_FRAME',
        matchedPattern: declared + ' bytes declared', matchedIn: 'HEADER',
        rawByteLength: declared
      });
      interceptor.publish(record);
      return interceptor.terminate(req, res, record);
    }

    // --- Signature matrix over the raw, unparsed URL ---------------
    const urlHit = interceptor.scan(rawUrl);
    if (urlHit) {
      const record = interceptor.buildRecord({
        sourceIp, method: req.method, rawUrl,
        threatClass: urlHit.cls, matchedPattern: urlHit.label + ' -> ' + urlHit.matched,
        matchedIn: 'URL'
      });
      interceptor.contain(record);
      interceptor.publish(record);
      return interceptor.terminate(req, res, record);
    }

    // --- Signature matrix over attacker-controlled headers ---------
    for (const name of ['user-agent', 'referer', 'x-forwarded-for', 'cookie', 'x-api-version']) {
      const value = req.headers[name];
      const str = Array.isArray(value) ? value.join(' ') : (value ?? '');
      if (!str) continue;
      const hit = interceptor.scan(String(str));
      if (hit) {
        const record = interceptor.buildRecord({
          sourceIp, method: req.method, rawUrl,
          threatClass: hit.cls,
          matchedPattern: name + ': ' + hit.label + ' -> ' + hit.matched,
          matchedIn: 'HEADER'
        });
        interceptor.contain(record);
        interceptor.publish(record);
        return interceptor.terminate(req, res, record);
      }
    }

    return next();
  } catch (err: any) {
    // Fail open: a bug in wire inspection must not black-hole the API.
    console.warn('[WireInterceptor] preParseGate error, failing open:', err?.message || err);
    return next();
  }
}

// -----------------------------------------------------------------------
// Middleware 2: raw body verifier (handed the real Buffer by the parser)
// -----------------------------------------------------------------------

/** Marker thrown from the verifier so the error handler can identify it. */
export interface WireVerifyError extends Error {
  wireRecord?: WireInterceptRecord;
}

/**
 * Passed to express.json({ verify }). Body parsers invoke this with the
 * complete raw Buffer BEFORE JSON.parse runs, which is the only hook that
 * sees real body bytes without competing for the stream.
 */
export function rawBodyVerifier(
  req: express.Request,
  _res: express.Response,
  buf: Buffer
): void {
  const interceptor = globalLiveSocketInterceptor;
  if (!interceptor.isEnabled() || !buf || buf.length === 0) return;

  const rawUrl = (req as express.Request).originalUrl || (req as express.Request).url || '/';
  const pathOnly = rawUrl.split('?')[0];
  if (interceptor.isExempt(pathOnly)) return;

  const sourceIp = interceptor.resolveIp(req);
  if (IMMUNE_IPS.has(sourceIp)) return;

  // Real HMAC-SHA256 over the exact wire bytes.
  const rawHmacSha256 = interceptor.hmacRaw(buf);
  interceptor.totalBodyBytesHashed += buf.length;
  (req as any).rawBodyHmac = rawHmacSha256;
  (req as any).rawBodyLength = buf.length;

  const hit = interceptor.scan(buf.toString('utf-8'));
  if (!hit) return;

  const record = interceptor.buildRecord({
    sourceIp, method: req.method, rawUrl,
    threatClass: hit.cls,
    matchedPattern: hit.label + ' -> ' + hit.matched,
    matchedIn: 'BODY',
    rawHmacSha256,
    rawByteLength: buf.length
  });
  interceptor.contain(record);
  interceptor.publish(record);

  const err = new Error('WIRE_LEVEL_TERMINATION') as WireVerifyError;
  err.wireRecord = record;
  throw err;
}

/**
 * Error handler paired with rawBodyVerifier.
 *
 * body-parser converts a throw from verify() into a 403-ish entity error; this
 * handler recognises the marker and escalates it to a real socket destroy.
 */
export function wireVerifyErrorHandler(
  err: WireVerifyError,
  req: express.Request,
  res: express.Response,
  next: express.NextFunction
) {
  if (!err || !err.wireRecord) return next(err);
  return globalLiveSocketInterceptor.terminate(req, res, err.wireRecord);
}
