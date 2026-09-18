import express from 'express';
import crypto from 'crypto';
import {
  globalInLineInterceptionEngine,
  type InterceptVerdict
} from '../services/inLineInterception.service.js';
import {
  globalFileDlpEngine,
  type FileOperation
} from '../services/fileDlpInterception.service.js';
import { globalLinkAnalysisBuilder } from '../services/linkAnalysis.service.js';
import { shannonEntropy, magicBytesHex } from '../services/payloadForensics.js';
import type {
  FileOperationVector,
  FileOperationType,
  InterceptionStatusCounters
} from '../types/interception.types.js';

// =============================================================================
// INTERCEPTION ROUTES & IN-LINE MIDDLEWARE (v1.0)
// Mounts the active interception surface: a middleware that inspects mutating
// requests before they reach any handler, plus the SOC control endpoints.
// =============================================================================

export const interceptionRouter = express.Router();

/** Methods that carry a mutable body worth inspecting. */
const MUTATING_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

/**
 * Routes exempt from in-line inspection.
 *
 * The simulation endpoints must be exempt: they deliberately submit tampered
 * payloads, and inspecting them would quarantine the analyst's own session
 * before the simulation could ever run. Telemetry ingestion is exempt because
 * sensors legitimately post structurally different bodies to the same route,
 * which the baseline comparison would otherwise read as mutation.
 */
const INSPECTION_EXEMPT_PREFIXES = [
  '/api/v1/soc/intercept/',
  '/api/v1/soc/ingest-telemetry',
  '/api/v1/agent/protect'
];

/**
 * Mirrors the engine's canonical serialization so a simulated client can sign
 * a payload the same way the interceptor will verify it.
 */
function canonicalize(value: unknown): string {
  if (value === null || value === undefined) return 'null';
  if (typeof value !== 'object') return JSON.stringify(value) ?? 'null';
  if (Array.isArray(value)) return '[' + value.map(v => canonicalize(v)).join(',') + ']';
  const entries = Object.entries(value as Record<string, unknown>)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return '{' + entries.map(([k, v]) => JSON.stringify(k) + ':' + canonicalize(v)).join(',') + '}';
}

function signCanonical(value: unknown): string {
  return crypto.createHash('sha256').update(canonicalize(value)).digest('hex');
}

function resolveActorIp(req: express.Request): string {
  const ip = req.ip || req.socket.remoteAddress || '127.0.0.1';
  return ip.replace(/^::ffff:/, '').trim();
}

/**
 * Derives a stable session identity for integrity tracking.
 *
 * Prefers an explicit session header, then a bearer/api key, and finally falls
 * back to actor IP plus user-agent so an anonymous client still gets a
 * consistent baseline rather than a new one on every request.
 */
export function resolveSessionId(req: express.Request): string {
  const explicit = req.headers['x-session-id'];
  if (typeof explicit === 'string' && explicit.trim()) return explicit.trim();

  const auth = req.headers['authorization'];
  const apiKey = req.headers['x-api-key'];
  const credential = (typeof auth === 'string' && auth) || (typeof apiKey === 'string' && apiKey) || '';
  if (credential) {
    return 'cred:' + crypto.createHash('sha256').update(credential).digest('hex').slice(0, 24);
  }

  const ua = String(req.headers['user-agent'] ?? 'unknown');
  return 'anon:' + crypto.createHash('sha256').update(resolveActorIp(req) + '|' + ua).digest('hex').slice(0, 24);
}

/**
 * Active in-line interception middleware.
 *
 * Runs ahead of endpoint handlers on mutating requests and enforces the
 * engine's verdict. A quarantined session is refused outright; a tampered
 * payload is dropped, and EMERGENCY_RESET additionally destroys the socket so
 * the peer observes a TCP reset rather than a clean HTTP response.
 */
export function inLineInterceptionMiddleware(
  req: express.Request,
  res: express.Response,
  next: express.NextFunction
) {
  try {
    if (!globalInLineInterceptionEngine.isEnabled()) return next();
    if (!MUTATING_METHODS.has(req.method)) return next();

    const routePath = req.path || req.originalUrl || '/';
    if (INSPECTION_EXEMPT_PREFIXES.some(prefix => routePath.startsWith(prefix))) {
      return next();
    }

    const sessionId = resolveSessionId(req);
    const actorIp = resolveActorIp(req);

    // A session already quarantined never gets a second chance at a handler.
    if (globalInLineInterceptionEngine.isQuarantined(sessionId)) {
      return res.status(403).json({
        success: false,
        error: 'SESSION_QUARANTINED',
        message: 'This session is quarantined by the in-line interception engine following a data tampering violation.',
        messageAr: 'هذه الجلسة معزولة بواسطة محرك الاعتراض المباشر إثر مخالفة تلاعب بالبيانات.',
        sessionId
      });
    }

    const declared = Number(req.headers['content-length']);
    const record = globalInLineInterceptionEngine.inspect({
      sessionId,
      actorIp,
      route: routePath,
      method: req.method,
      body: req.body,
      headers: req.headers as Record<string, string | string[] | undefined>,
      rawQuery: typeof req.originalUrl === 'string' ? req.originalUrl.split('?')[1] : undefined,
      declaredContentLength: Number.isFinite(declared) ? declared : undefined
    });

    if (record.verdict === 'PASS') {
      // Surface the intercept id so a client can correlate a later block.
      res.setHeader('X-Interception-Id', record.interceptId);
      res.setHeader('X-Defender-Intercept', 'CLEAN');
      return next();
    }

    return enforceVerdict(res, record.verdict, record);
  } catch (err: any) {
    // Interception must fail open rather than take the API down: a bug here
    // would otherwise block every mutating request on the platform.
    console.warn('[Interception] Middleware error, failing open:', err?.message || err);
    return next();
  }
}

/** Applies the blocking verdict, including socket destruction on reset. */
function enforceVerdict(
  res: express.Response,
  verdict: InterceptVerdict,
  record: { interceptId: string; primaryTamperClass: string; findings: Array<{ detail: string; detailAr: string }> }
) {
  const payload = {
    success: false,
    error: verdict,
    interceptId: record.interceptId,
    tamperClass: record.primaryTamperClass,
    message: 'In-line interception blocked this request: ' + record.findings.map(f => f.detail).join(' | '),
    messageAr: 'اعترض المحرك المباشر هذا الطلب: ' + record.findings.map(f => f.detailAr).join(' | ')
  };

  // Signal the block in a header as well as the body, so proxies and clients
  // that never parse the payload can still see the verdict.
  res.setHeader('X-Defender-Intercept', 'BLOCKED');
  res.setHeader('X-Defender-Tamper-Class', record.primaryTamperClass);

  if (verdict === 'EMERGENCY_RESET') {
    // Emit the verdict, then tear the connection down so the peer sees an
    // abortive close (TCP RST) instead of an orderly response.
    res.status(409).json(payload);
    setImmediate(() => {
      try {
        res.socket?.destroy();
      } catch {
        /* socket already gone */
      }
    });
    return;
  }

  return res.status(403).json(payload);
}

// =============================================================================
// CONTROL & MONITORING ENDPOINTS
// =============================================================================

/** Simulates in-flight data manipulation to verify the interceptor. */
interceptionRouter.post('/simulate-tamper', (req, res) => {
  try {
    const {
      sessionId = 'sim-' + crypto.randomBytes(4).toString('hex'),
      actorIp = '203.0.113.77',
      route = '/api/v1/transfer',
      scenario = 'PAYLOAD_MUTATION',
      originalPayload,
      tamperedPayload
    } = req.body || {};

    const validScenarios = ['PAYLOAD_MUTATION', 'PARAMETER_POLLUTION', 'PROTOTYPE_POLLUTION', 'CONTENT_LENGTH_MISMATCH', 'FORGED_INTEGRITY_HEADER'];
    if (!validScenarios.includes(scenario)) {
      return res.status(400).json({
        success: false,
        error: 'INVALID_SCENARIO',
        message: 'scenario must be one of: ' + validScenarios.join(', ') + '.',
        messageAr: 'يجب أن يكون السيناريو أحد التالي: ' + validScenarios.join('، ') + '.'
      });
    }

    const baseline = originalPayload ?? { accountId: 'ACC-88121', amount: 250, currency: 'USD' };

    // PAYLOAD_MUTATION models a real adversary-in-the-middle: the client signs
    // its payload, so the session is integrity-protected, and the attacker
    // rewrites the body in flight while replaying the original signature.
    // Without that opt-in a differing body is just normal REST variance, which
    // the engine deliberately does not treat as tampering.
    const signsPayload = scenario === 'PAYLOAD_MUTATION';
    const baselineSignature = signsPayload ? signCanonical(baseline) : null;

    const baselineRecord = globalInLineInterceptionEngine.inspect({
      sessionId, actorIp, route, method: 'POST', body: baseline,
      headers: baselineSignature ? { 'x-payload-signature': baselineSignature } : undefined
    });

    // Now replay the same session with the manipulation applied.
    let mutated: unknown = tamperedPayload;
    let rawQuery: string | undefined;
    let headers: Record<string, string | string[] | undefined> | undefined;
    let declaredContentLength: number | undefined;

    switch (scenario) {
      case 'PAYLOAD_MUTATION':
        mutated = mutated ?? {
          accountId: 'ACC-88121',
          amount: 999999,
          currency: 'USD',
          beneficiaryOverride: 'attacker-controlled-account',
          injectedRoutingChain: 'relay-1;relay-2;relay-3'
        };
        // The attacker cannot recompute the signature, so the original one is
        // replayed and now contradicts the rewritten body.
        headers = baselineSignature ? { 'x-payload-signature': baselineSignature } : undefined;
        break;
      case 'PARAMETER_POLLUTION':
        mutated = mutated ?? baseline;
        rawQuery = 'accountId=ACC-88121&amount=250&amount=999999&currency=USD';
        break;
      case 'PROTOTYPE_POLLUTION':
        mutated = mutated ?? JSON.parse('{"accountId":"ACC-88121","amount":250,"__proto__":{"isAdmin":true}}');
        break;
      case 'CONTENT_LENGTH_MISMATCH':
        mutated = mutated ?? baseline;
        declaredContentLength = 65_536;
        break;
      case 'FORGED_INTEGRITY_HEADER':
        mutated = mutated ?? baseline;
        headers = { 'x-payload-signature': 'deadbeef'.repeat(8) };
        break;
    }

    const tamperRecord = globalInLineInterceptionEngine.inspect({
      sessionId, actorIp, route, method: 'POST',
      body: mutated, headers, rawQuery, declaredContentLength
    });

    return res.json({
      success: true,
      scenario,
      baseline: {
        interceptId: baselineRecord.interceptId,
        verdict: baselineRecord.verdict,
        observedHash: baselineRecord.observedHash,
        payloadSizeBytes: baselineRecord.payloadSizeBytes
      },
      interception: tamperRecord,
      sessionQuarantined: globalInLineInterceptionEngine.isQuarantined(sessionId),
      hashDiff: {
        expected: tamperRecord.expectedHash,
        observed: tamperRecord.observedHash,
        diverged: tamperRecord.expectedHash !== tamperRecord.observedHash
      }
    });
  } catch (err: any) {
    console.warn('[Interception] Tamper simulation failed:', err?.message || err);
    return res.status(500).json({ success: false, error: 'SIMULATION_FAILED', message: err?.message || 'Unknown error.' });
  }
});

/** Simulates a file operation against the DLP policy engine. */
interceptionRouter.post('/simulate-file-action', (req, res) => {
  try {
    const {
      operation,
      filePath,
      actorIp = '203.0.113.77',
      token = 'tok-' + crypto.randomBytes(6).toString('hex'),
      mimeType,
      sizeBytes,
      processName,
      contentSample
    } = req.body || {};

    const validOps: FileOperation[] = ['FILE_DOWNLOAD', 'FILE_UPLOAD', 'FILE_MODIFICATION', 'FILE_DELETION'];
    if (!validOps.includes(operation)) {
      return res.status(400).json({
        success: false,
        error: 'INVALID_OPERATION',
        message: 'operation must be one of: ' + validOps.join(', ') + '.',
        messageAr: 'يجب أن تكون العملية إحدى التالي: ' + validOps.join('، ') + '.'
      });
    }
    if (!filePath || typeof filePath !== 'string') {
      return res.status(400).json({
        success: false,
        error: 'MISSING_FILE_PATH',
        message: 'A "filePath" string is required.',
        messageAr: 'مطلوب تحديد مسار الملف كنص.'
      });
    }

    const record = globalFileDlpEngine.evaluate({
      operation, filePath, actorIp, token, mimeType, sizeBytes, processName, contentSample
    });

    return res.json({
      success: true,
      record,
      tokenLocked: globalFileDlpEngine.isTokenLocked(token),
      stats: globalFileDlpEngine.getStats()
    });
  } catch (err: any) {
    console.warn('[Interception] File action simulation failed:', err?.message || err);
    return res.status(500).json({ success: false, error: 'SIMULATION_FAILED', message: err?.message || 'Unknown error.' });
  }
});

/** Live view of everything currently intercepted, blocked or quarantined. */
interceptionRouter.get('/active-blocks', (req, res) => {
  const limit = Math.max(1, Math.min(Number(req.query.limit) || 50, 200));

  return res.json({
    success: true,
    quarantinedSessions: globalInLineInterceptionEngine.getActiveQuarantines(),
    lockedTokens: globalFileDlpEngine.getLockedTokens(),
    recentInterceptions: globalInLineInterceptionEngine.getRecentInterceptions(limit),
    recentFileBlocks: globalFileDlpEngine.getRecentRecords(limit, true),
    stats: {
      inLine: globalInLineInterceptionEngine.getStats(),
      fileDlp: globalFileDlpEngine.getStats()
    },
    auditIntegrity: {
      inLine: globalInLineInterceptionEngine.verifyAuditChain(),
      fileDlp: globalFileDlpEngine.verifyAuditChain()
    }
  });
});

/** Releases a quarantined session or a locked token after analyst review. */
interceptionRouter.post('/release', (req, res) => {
  const { sessionId, token } = req.body || {};
  if (!sessionId && !token) {
    return res.status(400).json({
      success: false,
      error: 'MISSING_TARGET',
      message: 'Provide a "sessionId" or a "token" to release.',
      messageAr: 'يرجى تحديد معرف الجلسة أو الرمز المراد الإفراج عنه.'
    });
  }

  const released = {
    session: sessionId ? globalInLineInterceptionEngine.releaseSession(String(sessionId)) : false,
    token: token ? globalFileDlpEngine.releaseToken(String(token)) : false
  };
  return res.json({ success: true, released });
});

/** Enables or disables either engine without restarting the process. */
interceptionRouter.post('/engine-state', (req, res) => {
  const { engine, enabled } = req.body || {};
  if (engine !== 'IN_LINE' && engine !== 'FILE_DLP') {
    return res.status(400).json({
      success: false,
      error: 'INVALID_ENGINE',
      message: 'engine must be "IN_LINE" or "FILE_DLP".'
    });
  }

  const state = engine === 'IN_LINE'
    ? globalInLineInterceptionEngine.setEnabled(Boolean(enabled))
    : globalFileDlpEngine.setEnabled(Boolean(enabled));

  return res.json({ success: true, engine, enabled: state });
});

// =============================================================================
// STAGE 4: deterministic verification endpoints
// =============================================================================

/**
 * Deep in-transit inspection. Accepts a raw payload plus the digest the sender
 * committed to and returns the full DataTransitPacket / InterceptionDecision
 * analysis, including the kernel action taken.
 */
interceptionRouter.post('/stream-tamper', (req, res) => {
  try {
    const {
      sessionToken = 'stream-' + crypto.randomBytes(4).toString('hex'),
      payloadRaw,
      expectedPayloadHash,
      source,
      destination,
      route = '/api/v1/transit',
      rawQuery,
      declaredContentLength
    } = req.body || {};

    if (typeof payloadRaw !== 'string' || payloadRaw.length === 0) {
      return res.status(400).json({
        success: false,
        error: 'MISSING_PAYLOAD',
        message: 'A non-empty "payloadRaw" string is required.',
        messageAr: 'مطلوب إرسال حمولة نصية غير فارغة في الحقل payloadRaw.'
      });
    }

    const result = globalInLineInterceptionEngine.analyzeTransitPacket({
      sessionToken: String(sessionToken),
      source: {
        ip: source?.ip ?? resolveActorIp(req),
        port: Number(source?.port) || 0,
        asn: source?.asn !== undefined ? Number(source.asn) : undefined
      },
      destination: {
        ip: destination?.ip ?? '10.0.0.1',
        port: Number(destination?.port) || 443
      },
      payloadRaw,
      expectedPayloadHash: typeof expectedPayloadHash === 'string' ? expectedPayloadHash : undefined,
      rawQuery: typeof rawQuery === 'string' ? rawQuery : undefined,
      declaredContentLength: Number.isFinite(Number(declaredContentLength)) ? Number(declaredContentLength) : undefined,
      route: String(route)
    });

    const blocked = result.decision.action !== 'ALLOW';
    res.setHeader('X-Defender-Intercept', blocked ? 'BLOCKED' : 'CLEAN');
    res.setHeader('X-Defender-Packet-Id', result.packet.packetId);

    return res.status(blocked ? 403 : 200).json({
      success: true,
      blocked,
      packet: result.packet,
      decision: result.decision,
      interception: {
        interceptId: result.record.interceptId,
        verdict: result.record.verdict,
        findings: result.record.findings,
        entropyScore: result.record.entropyScore,
        sessionBurstCount: result.record.sessionBurstCount,
        socketInvalidated: result.record.socketInvalidated,
        tcpResetIssued: result.record.tcpResetIssued,
        auditHash: result.record.auditHash
      },
      hashDiff: {
        expected: result.packet.expectedPayloadHash,
        observed: result.packet.actualPayloadHash,
        diverged: result.packet.expectedPayloadHash !== result.packet.actualPayloadHash
      },
      sessionQuarantined: globalInLineInterceptionEngine.isQuarantined(String(sessionToken))
    });
  } catch (err: any) {
    console.warn('[Interception] stream-tamper failed:', err?.message || err);
    return res.status(500).json({ success: false, error: 'STREAM_ANALYSIS_FAILED', message: err?.message || 'Unknown error.' });
  }
});

/**
 * Deep file DLP adjudication across the four enforcement vectors.
 *
 * `contentBase64` carries the real bytes when available, which is what makes
 * magic-byte and entropy analysis meaningful; `content` accepts plain text for
 * convenience when driving the endpoint by hand.
 */
interceptionRouter.post('/file-action', (req, res) => {
  try {
    const {
      operationType,
      targetPath,
      fileMimeType = 'application/octet-stream',
      fileSizeBytes,
      content,
      contentBase64,
      actorIdentity,
      processId = 0,
      magicBytesHex: suppliedMagic
    } = req.body || {};

    const validOps: FileOperationType[] = ['FILE_READ_EXFIL', 'FILE_WRITE_INJECT', 'FILE_MODIFY_TAMPER', 'FILE_DELETE_PURGE'];
    if (!validOps.includes(operationType)) {
      return res.status(400).json({
        success: false,
        error: 'INVALID_OPERATION_TYPE',
        message: 'operationType must be one of: ' + validOps.join(', ') + '.',
        messageAr: 'يجب أن يكون نوع العملية أحد التالي: ' + validOps.join('، ') + '.'
      });
    }
    if (typeof targetPath !== 'string' || !targetPath.trim()) {
      return res.status(400).json({
        success: false,
        error: 'MISSING_TARGET_PATH',
        message: 'A non-empty "targetPath" string is required.',
        messageAr: 'مطلوب تحديد مسار الهدف كنص غير فارغ.'
      });
    }

    let buffer: Buffer | undefined;
    if (typeof contentBase64 === 'string' && contentBase64.length > 0) {
      buffer = Buffer.from(contentBase64, 'base64');
    } else if (typeof content === 'string' && content.length > 0) {
      buffer = Buffer.from(content, 'utf-8');
    }

    const vector: FileOperationVector = {
      operationType,
      targetPath: targetPath.trim(),
      fileSizeBytes: Number.isFinite(Number(fileSizeBytes)) ? Number(fileSizeBytes) : (buffer?.length ?? 0),
      fileMimeType: String(fileMimeType),
      magicBytesHex: typeof suppliedMagic === 'string' && suppliedMagic
        ? suppliedMagic
        : (buffer ? magicBytesHex(buffer) : ''),
      entropyScore: buffer ? shannonEntropy(buffer) : 0,
      actorIdentity: {
        uid: actorIdentity?.uid ?? 'tok-' + crypto.randomBytes(5).toString('hex'),
        sourceIp: actorIdentity?.sourceIp ?? resolveActorIp(req),
        userAgent: actorIdentity?.userAgent ?? String(req.headers['user-agent'] ?? 'unknown'),
        role: actorIdentity?.role ?? 'guest'
      },
      processId: Number(processId) || 0
    };

    const result = globalFileDlpEngine.enforceVector(vector, buffer);
    const blocked = result.decision.action !== 'ALLOW';

    res.setHeader('X-Defender-Intercept', blocked ? 'BLOCKED' : 'CLEAN');
    res.setHeader('X-Defender-Vector', vector.operationType);

    return res.status(blocked ? 403 : 200).json({
      success: true,
      blocked,
      vector: { ...vector, entropyScore: result.record.entropyScore },
      decision: result.decision,
      record: result.record,
      // Present only for QUARANTINE_HONEYFILE: the decoy actually served.
      honeyfile: result.honeyfile,
      tokenLocked: globalFileDlpEngine.isTokenLocked(vector.actorIdentity.uid)
    });
  } catch (err: any) {
    console.warn('[Interception] file-action failed:', err?.message || err);
    return res.status(500).json({ success: false, error: 'FILE_ACTION_FAILED', message: err?.message || 'Unknown error.' });
  }
});

/** Live incident graph for the Canvas link-analysis renderer. */
interceptionRouter.get('/link-graph', (req, res) => {
  try {
    const windowMs = Math.max(60_000, Math.min(Number(req.query.windowMs) || 900_000, 3_600_000));
    const graph = globalLinkAnalysisBuilder.build(windowMs);
    return res.json({
      success: true,
      windowMs,
      ...graph,
      summary: globalLinkAnalysisBuilder.summarize(graph)
    });
  } catch (err: any) {
    console.warn('[Interception] link-graph failed:', err?.message || err);
    return res.status(500).json({ success: false, error: 'GRAPH_BUILD_FAILED', message: err?.message || 'Unknown error.' });
  }
});

/** Aggregate interception counters. */
interceptionRouter.get('/status', (req, res) => {
  const inLine = globalInLineInterceptionEngine.getStats();
  const dlp = globalFileDlpEngine.getStats();

  const counters: InterceptionStatusCounters = {
    totalPacketsInspected: inLine.totalInspected,
    tamperedDropped: inLine.totalIntercepted,
    tcpResetsIssued: inLine.totalResets,
    dlpOperationsEvaluated: dlp.totalEvaluated,
    dlpBlocks: dlp.totalBlocked,
    honeyfilesServed: dlp.honeyfilesServed,
    systemFreezesTriggered: inLine.systemFreezes + dlp.systemFreezes,
    activeQuarantinedSessions: inLine.activeQuarantines,
    activeLockedTokens: dlp.lockedTokens,
    meanInspectionLatencyMicros: inLine.meanInspectionLatencyMicros
  };

  return res.json({
    success: true,
    counters,
    engines: { inLine, fileDlp: dlp },
    auditIntegrity: {
      inLine: globalInLineInterceptionEngine.verifyAuditChain(),
      fileDlp: globalFileDlpEngine.verifyAuditChain()
    }
  });
});
