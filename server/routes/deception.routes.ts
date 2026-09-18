import express from 'express';
import crypto from 'crypto';
import { globalPreAttackIntentAnalyzer } from '../services/preAttackIntent.service.js';
import { globalShadowDecoyRouter } from '../services/shadowDecoyRouter.service.js';
import { globalAdversaryProfiler } from '../services/adversaryProfiler.service.js';

// =============================================================================
// DECEPTION GRID ROUTES & TRANSPARENT SHADOW PROXY (v1.0)
// =============================================================================

export const deceptionRouter = express.Router();

/**
 * Paths the shadow proxy never inspects or diverts.
 *
 * The SOC's own surface is exempt for a decisive reason: its endpoints
 * legitimately carry attack payloads as *data* - the FIM drill posts a web
 * shell, the interception drill posts traversal strings, the scanner posts
 * SQLi. Analyzing those would trap the defender inside their own decoy and
 * blind the console. Static assets are exempt because the Vite dev client
 * requests paths containing dots and encoded characters constantly.
 */
const DECEPTION_EXEMPT_PREFIXES = [
  '/api/v1/soc/',
  '/api/v1/fim/',
  '/api/v1/agent/',
  '/api/v1/tools/',
  '/api/v1/traffic/',
  '/api/v1/quarantine/',
  '/api/v1/topology/',
  '/api/v1/insider-zero-trust/',
  '/@vite',
  '/@react-refresh',
  '/src/',
  '/node_modules/',
  '/assets/'
];

/** Internal addresses that are never diverted, whatever they send. */
const DECEPTION_IMMUNE_IPS = new Set(['127.0.0.1', '::1', '10.0.0.1', '10.0.0.2']);

function resolveActorIp(req: express.Request): string {
  const ip = req.ip || req.socket.remoteAddress || '127.0.0.1';
  return ip.replace(/^::ffff:/, '').trim();
}

/** Stable session identity, mirroring the interception layer's scheme. */
export function resolveDeceptionSessionId(req: express.Request): string {
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

/** Sleep helper used to reproduce genuine backend latency. */
function delay(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, Math.max(0, ms)));
}

/**
 * Transparent forking middleware.
 *
 * Runs ahead of normal route dispatch. A flagged actor is served entirely
 * from the synthetic engine and never learns it happened: no 401, no 403, no
 * marker header, and a response delay drawn from the genuine backend's own
 * latency distribution.
 */
export async function shadowDecoyMiddleware(
  req: express.Request,
  res: express.Response,
  next: express.NextFunction
) {
  try {
    const path = req.path || req.originalUrl || '/';
    if (DECEPTION_EXEMPT_PREFIXES.some(prefix => path.startsWith(prefix))) return next();

    const actorIp = resolveActorIp(req);
    if (DECEPTION_IMMUNE_IPS.has(actorIp)) return next();

    const sessionId = resolveDeceptionSessionId(req);
    const alreadyTrapped = globalShadowDecoyRouter.isDiverted(sessionId);

    // Genuine traffic doubles as the latency training signal: timing real
    // responses is what lets the decoy imitate them convincingly later.
    if (!alreadyTrapped) {
      const startedAt = Date.now();
      res.once('finish', () => {
        globalShadowDecoyRouter.latencyProfiler.observe(req.method, path, Date.now() - startedAt);
      });
    }

    const intent = globalPreAttackIntentAnalyzer.analyze({
      sessionToken: sessionId,
      actorIp,
      method: req.method,
      url: req.originalUrl || path,
      body: req.body,
      userAgent: String(req.headers['user-agent'] ?? ''),
      headers: req.headers as Record<string, string | string[] | undefined>
    });

    if (!alreadyTrapped && intent.action !== 'ACTION_DIVERT_TO_DECEPTION_GRID') {
      return next();
    }

    // --- Fork into the grid ---------------------------------------
    if (!alreadyTrapped) {
      globalShadowDecoyRouter.divert({
        sessionId,
        actorIp,
        intentScore: intent.adversaryIntentScore,
        presentedToken: typeof req.headers['authorization'] === 'string' ? req.headers['authorization'] : null,
        userAgent: String(req.headers['user-agent'] ?? '')
      });
    }

    const decoy = globalShadowDecoyRouter.respond({
      sessionId,
      method: req.method,
      path,
      body: req.body,
      query: req.query as Record<string, unknown>,
      decodedPath: intent.normalizedInput
    });

    globalAdversaryProfiler.record({
      sessionId,
      actorIp,
      method: req.method,
      path,
      rawPayload: (req.originalUrl || path) + ' ' + (req.body ? JSON.stringify(req.body).slice(0, 512) : ''),
      intent,
      decoyResponseKind: decoy.kind,
      decoyStatusCode: decoy.statusCode,
      appliedLatencyMs: decoy.appliedLatencyMs,
      canariesExposed: decoy.canariesExposed
    });

    // Latency matching: wait the sampled interval before answering so the
    // decoy's timing distribution matches the real backend's.
    await delay(decoy.appliedLatencyMs);

    for (const [k, v] of Object.entries(decoy.headers)) res.setHeader(k, v);
    return res.status(decoy.statusCode).send(decoy.body);
  } catch (err: any) {
    // Fail open. A bug in the deception layer must never take the real
    // application down for legitimate users.
    console.warn('[DeceptionGrid] Middleware error, failing open:', err?.message || err);
    return next();
  }
}

// =============================================================================
// SOC CONTROL & VERIFICATION ENDPOINTS
// =============================================================================

/**
 * End-to-end verification of the full pipeline:
 * obfuscated payload -> intent analysis -> diversion -> synthetic response
 * -> profiling -> telemetry dispatch.
 */
deceptionRouter.post('/test/deception-probe', async (req, res) => {
  try {
    const {
      payload,
      path = '/api/v1/users',
      method = 'GET',
      sessionId = 'probe-' + crypto.randomBytes(4).toString('hex'),
      actorIp = '203.0.113.200',
      userAgent = 'Mozilla/5.0'
    } = req.body || {};

    if (typeof payload !== 'string' || payload.length === 0) {
      return res.status(400).json({
        success: false,
        error: 'MISSING_PAYLOAD',
        message: 'A non-empty "payload" string is required (it may be obfuscated).',
        messageAr: 'مطلوب إرسال حمولة نصية غير فارغة، ويمكن أن تكون مموهة.'
      });
    }

    const probeUrl = path + (path.includes('?') ? '&' : '?') + 'q=' + payload;

    // 1. Intent analysis with full de-obfuscation.
    const intent = globalPreAttackIntentAnalyzer.analyze({
      sessionToken: sessionId, actorIp, method, url: probeUrl, userAgent
    });

    const diverted = intent.action === 'ACTION_DIVERT_TO_DECEPTION_GRID';
    let decoy = null;
    let profile = null;
    let session = null;

    if (diverted) {
      // 2. Fork and clone the session.
      session = globalShadowDecoyRouter.divert({
        sessionId, actorIp, intentScore: intent.adversaryIntentScore, userAgent
      });

      // 3. Synthesize the decoy response.
      decoy = globalShadowDecoyRouter.respond({
        sessionId, method, path: probeUrl, decodedPath: intent.normalizedInput
      });

      // 4. Profile and stream to the SOC.
      globalAdversaryProfiler.record({
        sessionId, actorIp, method, path: probeUrl,
        rawPayload: payload,
        intent,
        decoyResponseKind: decoy.kind,
        decoyStatusCode: decoy.statusCode,
        appliedLatencyMs: decoy.appliedLatencyMs,
        canariesExposed: decoy.canariesExposed
      });
      profile = globalAdversaryProfiler.getProfile(sessionId);

      // Reproduce the real latency the live path would have applied.
      await delay(Math.min(decoy.appliedLatencyMs, 400));
    }

    return res.json({
      success: true,
      stage1_intent: {
        analysisId: intent.analysisId,
        rawInput: intent.rawInput,
        normalizedInput: intent.normalizedInput,
        deobfuscationLayers: intent.layers.map(l => l.technique),
        obfuscationDepth: intent.obfuscationDepth,
        indicators: intent.indicators.map(i => ({ id: i.id, category: i.category, lr: i.likelihoodRatio, matched: i.matched })),
        adversaryIntentScore: intent.adversaryIntentScore,
        priorProbability: intent.priorProbability,
        posteriorProbability: intent.posteriorProbability,
        action: intent.action
      },
      stage2_diversion: diverted && session ? {
        diverted: true,
        clonedContext: session.context,
        canariesPlanted: session.canaries.map(c => ({ canaryId: c.canaryId, kind: c.kind, plantedPath: c.plantedPath })),
        intentScoreAtDiversion: session.intentScoreAtDiversion
      } : { diverted: false },
      stage3_decoyResponse: decoy ? {
        kind: decoy.kind,
        statusCode: decoy.statusCode,
        headers: decoy.headers,
        appliedLatencyMs: decoy.appliedLatencyMs,
        canariesExposed: decoy.canariesExposed,
        bodyPreview: typeof decoy.body === 'string' ? decoy.body.slice(0, 900) : decoy.body
      } : null,
      stage4_profile: profile ? {
        sophisticationIndex: profile.sophisticationIndex,
        sophisticationBand: profile.sophisticationBand,
        killChain: profile.killChain,
        techniques: profile.techniques,
        actionCount: profile.actionCount,
        canariesExposed: profile.canariesExposed
      } : null
    });
  } catch (err: any) {
    console.warn('[DeceptionGrid] Probe failed:', err?.message || err);
    return res.status(500).json({ success: false, error: 'PROBE_FAILED', message: err?.message || 'Unknown error.' });
  }
});

/** Live entrapped actors, their cloned identity, and sophistication rating. */
deceptionRouter.get('/entrapped', (req, res) => {
  const limit = Math.max(1, Math.min(Number(req.query.limit) || 50, 200));
  const sessions = globalShadowDecoyRouter.getActiveSessions();
  const profiles = globalAdversaryProfiler.getProfiles(limit);

  const merged = sessions.map(s => {
    const p = profiles.find(x => x.sessionId === s.sessionId);
    return {
      sessionId: s.sessionId,
      actorIp: s.actorIp,
      divertedAt: s.divertedAt,
      lastInteractionAt: s.lastInteractionAt,
      interactions: s.interactions,
      intentScoreAtDiversion: s.intentScoreAtDiversion,
      clonedContext: s.context,
      canaries: s.canaries.map(c => ({ canaryId: c.canaryId, kind: c.kind, plantedPath: c.plantedPath, redeemed: c.redeemed })),
      syntheticFileCount: s.syntheticFileCount,
      sophisticationIndex: p?.sophisticationIndex ?? 0,
      sophisticationBand: p?.sophisticationBand ?? 'SCRIPT_KIDDIE',
      killChain: p?.killChain ?? [],
      techniques: p?.techniques ?? []
    };
  });

  return res.json({
    success: true,
    entrapped: merged,
    stats: {
      router: globalShadowDecoyRouter.getStats(),
      profiler: globalAdversaryProfiler.getStats(),
      intent: globalPreAttackIntentAnalyzer.getStats()
    }
  });
});

/** Raw shadow-terminal transcript of what trapped actors are running. */
deceptionRouter.get('/transcript', (req, res) => {
  const limit = Math.max(1, Math.min(Number(req.query.limit) || 80, 200));
  const sessionId = typeof req.query.sessionId === 'string' ? req.query.sessionId : null;

  const entries = sessionId
    ? (globalAdversaryProfiler.getProfile(sessionId)?.transcript ?? []).slice().reverse().slice(0, limit)
    : globalAdversaryProfiler.getGlobalTranscript(limit);

  return res.json({ success: true, sessionId, entries });
});

/** Deception flow graph: actor -> decoy asset -> canary -> technique. */
deceptionRouter.get('/flow-graph', (req, res) => {
  const nodes: Array<{ id: string; label: string; type: string; riskWeight: number }> = [];
  const edges: Array<{ source: string; target: string; relationship: string }> = [];
  const seenNodes = new Set<string>();

  const addNode = (id: string, label: string, type: string, riskWeight: number) => {
    if (seenNodes.has(id)) return;
    seenNodes.add(id);
    nodes.push({ id, label, type, riskWeight });
  };
  const addEdge = (source: string, target: string, relationship: string) => {
    if (!seenNodes.has(source) || !seenNodes.has(target)) return;
    const key = source + '->' + target + ':' + relationship;
    if (edges.some(e => e.source + '->' + e.target + ':' + e.relationship === key)) return;
    edges.push({ source, target, relationship });
  };

  for (const profile of globalAdversaryProfiler.getProfiles(40)) {
    const actorId = 'actor:' + profile.actorIp;
    addNode(actorId, profile.actorIp, 'ACTOR', Math.max(60, profile.sophisticationIndex));

    // Most recent probes become the decoy assets touched.
    for (const action of profile.transcript.slice(-6)) {
      const assetId = 'asset:' + action.path.split('?')[0];
      addNode(assetId, action.path.split('?')[0].slice(0, 40), 'DECOY_ASSET', 45);
      addEdge(actorId, assetId, 'PROBED');

      for (const technique of action.mitreTechniques.slice(0, 2)) {
        const techId = 'technique:' + technique.split(' - ')[0];
        addNode(techId, technique.split(' - ')[0], 'TECHNIQUE', 65);
        addEdge(assetId, techId, 'MAPS_TO');
      }
    }

    const session = globalShadowDecoyRouter.getSession(profile.sessionId);
    for (const canary of session?.canaries ?? []) {
      if (!profile.canariesExposed.includes(canary.canaryId)) continue;
      const canaryId = 'canary:' + canary.canaryId;
      addNode(canaryId, canary.kind, 'CANARY', canary.redeemed ? 100 : 55);
      addEdge(actorId, canaryId, canary.redeemed ? 'REDEEMED' : 'TRAPPED_BY');
    }
  }

  return res.json({ success: true, nodes, edges });
});

/** Reports a value seen elsewhere, to test whether it is a planted canary. */
deceptionRouter.post('/canary/redeem', (req, res) => {
  const { value, seenFrom = 'external' } = req.body || {};
  if (typeof value !== 'string' || !value) {
    return res.status(400).json({ success: false, error: 'MISSING_VALUE', message: 'A "value" string is required.' });
  }
  const token = globalShadowDecoyRouter.redeemCanary(value, String(seenFrom));
  if (token) globalAdversaryProfiler.noteCanaryRedemption(token, String(seenFrom));

  return res.json({
    success: true,
    isCanary: !!token,
    token: token ? { canaryId: token.canaryId, kind: token.kind, boundSessionId: token.boundSessionId, redeemedAt: token.redeemedAt } : null
  });
});

/** Releases a trapped session after analyst review. */
deceptionRouter.post('/release', (req, res) => {
  const { sessionId } = req.body || {};
  if (typeof sessionId !== 'string' || !sessionId) {
    return res.status(400).json({ success: false, error: 'MISSING_SESSION_ID', message: 'A "sessionId" string is required.' });
  }
  return res.json({ success: true, released: globalShadowDecoyRouter.release(sessionId) });
});

/** Aggregate deception grid status. */
deceptionRouter.get('/status', (req, res) => {
  return res.json({
    success: true,
    router: globalShadowDecoyRouter.getStats(),
    profiler: globalAdversaryProfiler.getStats(),
    intent: globalPreAttackIntentAnalyzer.getStats(),
    canaries: globalShadowDecoyRouter.getAllCanaries().map(c => ({
      canaryId: c.canaryId, kind: c.kind, plantedPath: c.plantedPath,
      boundSessionId: c.boundSessionId, redeemed: c.redeemed, redeemedFrom: c.redeemedFrom
    }))
  });
});
