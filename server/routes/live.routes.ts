import express from 'express';
import crypto from 'crypto';
import { globalLiveHostCanary } from '../services/liveHostCanary.service.js';
import { globalLiveThreatIntel } from '../services/liveThreatIntel.service.js';
import { globalLiveDeceptionSandbox, type SandboxMode } from '../services/liveDeceptionSandbox.service.js';
import { globalLiveSocketInterceptor } from '../middleware/liveSocketInterceptor.js';

// =============================================================================
// LIVE SUBSYSTEM ROUTES (v1.0)
// Control and observation surface for the four live engines.
// =============================================================================

export const liveRouter = express.Router();

// -----------------------------------------------------------------------
// Stage 1: real host file integrity
// -----------------------------------------------------------------------

liveRouter.get('/host/status', (_req, res) => {
  return res.json({
    success: true,
    stats: globalLiveHostCanary.getStats(),
    ledger: globalLiveHostCanary.getLedger(),
    verification: globalLiveHostCanary.verifyAll()
  });
});

liveRouter.get('/host/incidents', (req, res) => {
  const limit = Math.max(1, Math.min(Number(req.query.limit) || 50, 200));
  return res.json({ success: true, incidents: globalLiveHostCanary.getIncidents(limit) });
});

// -----------------------------------------------------------------------
// Stage 2: wire interceptor
// -----------------------------------------------------------------------

liveRouter.get('/wire/status', (req, res) => {
  const limit = Math.max(1, Math.min(Number(req.query.limit) || 50, 200));
  return res.json({
    success: true,
    stats: globalLiveSocketInterceptor.getStats(),
    records: globalLiveSocketInterceptor.getRecords(limit)
  });
});

liveRouter.post('/wire/engine-state', (req, res) => {
  const { enabled } = req.body || {};
  return res.json({ success: true, enabled: globalLiveSocketInterceptor.setEnabled(Boolean(enabled)) });
});

// -----------------------------------------------------------------------
// Stage 3: live threat intelligence
// -----------------------------------------------------------------------

liveRouter.get('/intel/lookup/:ip', async (req, res) => {
  try {
    const ip = String(req.params.ip || '').trim();
    if (!ip) {
      return res.status(400).json({ success: false, error: 'MISSING_IP', message: 'An IP address is required.' });
    }
    const result = await globalLiveThreatIntel.enrich(ip);
    return res.json({ success: true, ...result });
  } catch (err: any) {
    console.warn('[LiveRoutes] intel lookup failed:', err?.message || err);
    return res.status(500).json({ success: false, error: 'INTEL_LOOKUP_FAILED', message: err?.message || 'Unknown error.' });
  }
});

liveRouter.get('/intel/status', (_req, res) => {
  return res.json({ success: true, ...globalLiveThreatIntel.getStats() });
});

liveRouter.post('/intel/refresh-tor', async (_req, res) => {
  const set = await globalLiveThreatIntel.loadTorExitNodes(true);
  return res.json({ success: true, loaded: set !== null, nodeCount: set?.size ?? 0 });
});

// -----------------------------------------------------------------------
// Stage 4: interactive deception sandbox
// -----------------------------------------------------------------------

/** Executes one attacker command inside the isolated in-memory machine. */
liveRouter.post('/sandbox/exec', (req, res) => {
  try {
    const {
      sessionId = 'sbx-' + crypto.randomBytes(4).toString('hex'),
      input,
      mode = 'SHELL',
      actorIp
    } = req.body || {};

    if (typeof input !== 'string') {
      return res.status(400).json({
        success: false, error: 'MISSING_INPUT',
        message: 'An "input" string is required.',
        messageAr: 'مطلوب إرسال نص الأمر في الحقل input.'
      });
    }
    if (mode !== 'SHELL' && mode !== 'SQL') {
      return res.status(400).json({ success: false, error: 'INVALID_MODE', message: 'mode must be "SHELL" or "SQL".' });
    }

    const ip = actorIp || (req.ip || req.socket.remoteAddress || '127.0.0.1').replace(/^::ffff:/, '');
    const command = globalLiveDeceptionSandbox.execute(String(sessionId), String(ip), input, mode as SandboxMode);
    const session = globalLiveDeceptionSandbox.getSession(String(sessionId));

    return res.json({
      success: true,
      command,
      prompt: session
        ? (session.mode === 'SQL' ? 'analytics=> ' : session.user + '@' + session.hostname + ':' + session.cwd + '$ ')
        : '$ ',
      canariesRevealed: session ? Array.from(session.canariesRevealed) : []
    });
  } catch (err: any) {
    console.warn('[LiveRoutes] sandbox exec failed:', err?.message || err);
    return res.status(500).json({ success: false, error: 'SANDBOX_EXEC_FAILED', message: err?.message || 'Unknown error.' });
  }
});

liveRouter.get('/sandbox/sessions', (_req, res) => {
  return res.json({ success: true, sessions: globalLiveDeceptionSandbox.getSessions(), stats: globalLiveDeceptionSandbox.getStats() });
});

liveRouter.get('/sandbox/transcript', (req, res) => {
  const sessionId = typeof req.query.sessionId === 'string' ? req.query.sessionId : undefined;
  const limit = Math.max(1, Math.min(Number(req.query.limit) || 100, 300));
  return res.json({ success: true, sessionId: sessionId ?? null, commands: globalLiveDeceptionSandbox.getTranscript(sessionId, limit) });
});

liveRouter.post('/sandbox/destroy', (req, res) => {
  const { sessionId } = req.body || {};
  if (typeof sessionId !== 'string' || !sessionId) {
    return res.status(400).json({ success: false, error: 'MISSING_SESSION_ID' });
  }
  return res.json({ success: true, destroyed: globalLiveDeceptionSandbox.destroy(sessionId) });
});

// -----------------------------------------------------------------------
// Aggregate posture
// -----------------------------------------------------------------------

/**
 * Reports what is genuinely live versus degraded.
 *
 * Each capability states its real backing and, where a capability cannot be
 * fully live in this environment, why - so an operator is never left assuming
 * a degraded source is a confirmed one.
 */
liveRouter.get('/status', (_req, res) => {
  const host = globalLiveHostCanary.getStats();
  const intel = globalLiveThreatIntel.getStats();

  return res.json({
    success: true,
    platform: process.platform,
    nodeVersion: process.version,
    capabilities: {
      realFilesystemWatch: {
        live: host.running,
        backing: 'fs.watch bound to ' + host.watchedRoot,
        guardedFiles: host.guardedFiles
      },
      realSocketTermination: {
        live: globalLiveSocketInterceptor.isEnabled(),
        backing: 'req.socket.destroy() on the real TCP handle'
      },
      realReverseDns: {
        live: true,
        backing: 'node:dns resolver.reverse() + forward confirmation'
      },
      realTorDirectory: {
        live: intel.torDirectory.loaded,
        backing: 'https://check.torproject.org/torbulkexitlist (public, unauthenticated)',
        nodeCount: intel.torDirectory.nodeCount
      },
      abuseIpDbReputation: {
        live: intel.abuseIpDb.credentialConfigured,
        backing: 'AbuseIPDB v2',
        degradedReason: intel.abuseIpDb.credentialConfigured
          ? null
          : 'ABUSEIPDB_API_KEY not set - no reputation is fabricated in its absence.'
      },
      kernelXdpDrop: {
        live: process.platform === 'linux',
        backing: 'eBPF/XDP via bpftool',
        degradedReason: process.platform === 'linux'
          ? null
          : 'Host is ' + process.platform + '; XDP requires a privileged Linux host. Drops are mirrored in the in-memory BPF map instead.'
      },
      interactiveSandbox: {
        live: true,
        backing: 'in-memory interpreter; executes no real commands'
      }
    },
    engines: {
      host,
      wire: globalLiveSocketInterceptor.getStats(),
      intel,
      sandbox: globalLiveDeceptionSandbox.getStats()
    }
  });
});
