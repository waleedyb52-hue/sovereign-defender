import express from 'express';
import path from 'path';
import { globalKernelMitigationDriver, type MitigationAction } from '../services/kernelMitigationDriver.js';
import { globalDataPoisoningEngine, type PoisonDataset } from '../services/dataPoisoning.service.js';
import { globalSelfHealingLedger } from '../services/selfHealingLedger.service.js';
import { globalThreatIntelKeyManager, type IntelProvider } from '../services/threatIntelKeyManager.js';

// =============================================================================
// AUTONOMOUS DEFENSE ROUTES (v1.0)
// Control surface for the dual-kernel driver, poisoning engine, self-healing
// ledger, and threat-intel key orchestrator.
// =============================================================================

export const defenseRouter = express.Router();
export const adminRouter = express.Router();

const VALID_ACTIONS: MitigationAction[] = ['DROP', 'THROTTLE', 'RESET'];
const VALID_DATASETS: PoisonDataset[] = ['USER_RECORDS', 'CREDENTIALS', 'FINANCIAL_LEDGER', 'API_KEYS', 'CUSTOMER_PII'];
const VALID_PROVIDERS: IntelProvider[] = ['ABUSEIPDB', 'VIRUSTOTAL', 'OTX', 'GREYNOISE'];

// -----------------------------------------------------------------------
// Stage 1: dual-kernel mitigation driver
// -----------------------------------------------------------------------

defenseRouter.get('/kernel/status', async (_req, res) => {
  try {
    return res.json({ success: true, ...(await globalKernelMitigationDriver.getStatus()) });
  } catch (err: any) {
    return res.status(500).json({ success: false, error: 'KERNEL_STATUS_FAILED', message: err?.message || 'Unknown error.' });
  }
});

defenseRouter.post('/kernel/mitigate', async (req, res) => {
  try {
    const { ip, action = 'DROP', reason, ttlSeconds, ratePps, burst } = req.body || {};
    if (typeof ip !== 'string' || !ip.trim()) {
      return res.status(400).json({ success: false, error: 'MISSING_IP', messageAr: 'مطلوب عنوان IP.' });
    }
    if (!VALID_ACTIONS.includes(action)) {
      return res.status(400).json({ success: false, error: 'INVALID_ACTION', message: 'action must be DROP, THROTTLE or RESET.' });
    }
    const result = await globalKernelMitigationDriver.mitigateIp(ip.trim(), action, { reason, ttlSeconds, ratePps, burst });
    return res.json({ success: result.success, ...result });
  } catch (err: any) {
    return res.status(500).json({ success: false, error: 'MITIGATION_FAILED', message: err?.message || 'Unknown error.' });
  }
});

defenseRouter.post('/kernel/revoke', async (req, res) => {
  const { ip } = req.body || {};
  if (typeof ip !== 'string' || !ip.trim()) {
    return res.status(400).json({ success: false, error: 'MISSING_IP' });
  }
  return res.json({ success: true, ...(await globalKernelMitigationDriver.revoke(ip.trim())) });
});

defenseRouter.get('/kernel/drops', (_req, res) => {
  return res.json({ success: true, drops: globalKernelMitigationDriver.getActiveDrops() });
});

/** Enumerates the host firewall rules this driver created. */
defenseRouter.get('/kernel/host-rules', async (_req, res) => {
  return res.json({ success: true, rules: await globalKernelMitigationDriver.listHostRules() });
});

defenseRouter.post('/kernel/revoke-all-host-rules', async (_req, res) => {
  return res.json({ success: true, ...(await globalKernelMitigationDriver.revokeAllHostRules()) });
});

// -----------------------------------------------------------------------
// Stage 2: deceptive data poisoning
// -----------------------------------------------------------------------

defenseRouter.post('/poison/arm', (req, res) => {
  const { sessionId, reason = 'Operator-armed countermeasure' } = req.body || {};
  if (typeof sessionId !== 'string' || !sessionId) {
    return res.status(400).json({ success: false, error: 'MISSING_SESSION_ID' });
  }
  return res.json({ success: true, ...globalDataPoisoningEngine.arm(sessionId, String(reason)) });
});

defenseRouter.post('/poison/disarm', (req, res) => {
  const { sessionId } = req.body || {};
  if (typeof sessionId !== 'string' || !sessionId) {
    return res.status(400).json({ success: false, error: 'MISSING_SESSION_ID' });
  }
  return res.json({ success: true, disarmed: globalDataPoisoningEngine.disarm(sessionId) });
});

/**
 * Dispatches a poisoned payload.
 *
 * Requires the session to be armed first. An unarmed session is refused
 * rather than silently poisoned, so this endpoint cannot become the thing
 * that accidentally serves corrupted data to a real user.
 */
defenseRouter.post('/poison/dispatch', (req, res) => {
  try {
    const { sessionId, actorIp, dataset = 'USER_RECORDS', recordCount = 25 } = req.body || {};
    if (typeof sessionId !== 'string' || !sessionId) {
      return res.status(400).json({ success: false, error: 'MISSING_SESSION_ID' });
    }
    if (!VALID_DATASETS.includes(dataset)) {
      return res.status(400).json({ success: false, error: 'INVALID_DATASET', validDatasets: VALID_DATASETS });
    }
    if (!globalDataPoisoningEngine.isArmed(sessionId)) {
      return res.status(409).json({
        success: false,
        error: 'SESSION_NOT_ARMED',
        message: 'Arm the session before dispatching a poisoned payload.',
        messageAr: 'يجب تسليح الجلسة قبل إرسال حمولة مسمومة.'
      });
    }
    const ip = actorIp || (req.ip || req.socket.remoteAddress || '0.0.0.0').replace(/^::ffff:/, '');
    const payload = globalDataPoisoningEngine.generate(sessionId, String(ip), dataset, Number(recordCount) || 25);
    return res.json({ success: true, payload });
  } catch (err: any) {
    return res.status(500).json({ success: false, error: 'POISON_DISPATCH_FAILED', message: err?.message || 'Unknown error.' });
  }
});

defenseRouter.post('/poison/scan', (req, res) => {
  const { text, seenFrom = 'manual-submission' } = req.body || {};
  if (typeof text !== 'string') {
    return res.status(400).json({ success: false, error: 'MISSING_TEXT' });
  }
  const sightings = globalDataPoisoningEngine.scanForWatermarks(text, String(seenFrom));
  return res.json({ success: true, sightings, matched: sightings.length });
});

defenseRouter.get('/poison/status', (_req, res) => {
  return res.json({
    success: true,
    stats: globalDataPoisoningEngine.getStats(),
    issued: globalDataPoisoningEngine.getIssued(25),
    sightings: globalDataPoisoningEngine.getSightings(25)
  });
});

// -----------------------------------------------------------------------
// Stage 3: self-healing ledger
// -----------------------------------------------------------------------

defenseRouter.get('/healing/status', (_req, res) => {
  return res.json({
    success: true,
    stats: globalSelfHealingLedger.getStats(),
    chain: globalSelfHealingLedger.verifyChain(),
    artifacts: globalSelfHealingLedger.getArtifacts()
  });
});

defenseRouter.get('/healing/ledger', (req, res) => {
  const limit = Math.max(1, Math.min(Number(req.query.limit) || 100, 500));
  return res.json({ success: true, entries: globalSelfHealingLedger.getLedger(limit) });
});

defenseRouter.post('/healing/protect', (req, res) => {
  const { filePath } = req.body || {};
  if (typeof filePath !== 'string' || !filePath) {
    return res.status(400).json({ success: false, error: 'MISSING_FILE_PATH' });
  }
  const artifact = globalSelfHealingLedger.protectFile(path.resolve(process.cwd(), filePath), 'operator');
  if (!artifact) {
    return res.status(404).json({ success: false, error: 'FILE_UNREADABLE', messageAr: 'تعذّرت قراءة الملف المطلوب حمايته.' });
  }
  const { authenticBytes, ...safe } = artifact;
  return res.json({ success: true, artifact: { ...safe, sizeBytes: authenticBytes.length } });
});

defenseRouter.post('/healing/verify', (req, res) => {
  const { subject } = req.body || {};
  if (typeof subject === 'string' && subject) {
    return res.json({ success: true, results: [globalSelfHealingLedger.verifyAndHeal(subject, 'operator')] });
  }
  return res.json({ success: true, results: globalSelfHealingLedger.verifyAll('operator') });
});

/** Records an approved change so the healer does not revert a real deployment. */
defenseRouter.post('/healing/authorise', (req, res) => {
  const { subject, content, actor = 'operator', note } = req.body || {};
  if (typeof subject !== 'string' || typeof content !== 'string') {
    return res.status(400).json({ success: false, error: 'MISSING_SUBJECT_OR_CONTENT' });
  }
  const updated = globalSelfHealingLedger.authoriseUpdate(subject, content, String(actor), note);
  if (!updated) {
    return res.status(404).json({ success: false, error: 'ARTIFACT_NOT_PROTECTED' });
  }
  return res.json({ success: true, subject, contentSha256: updated.contentSha256 });
});

// -----------------------------------------------------------------------
// Stage 4: threat intel resolution
// -----------------------------------------------------------------------

defenseRouter.get('/intel/resolve/:ip', async (req, res) => {
  try {
    const ip = String(req.params.ip || '').trim();
    if (!ip) return res.status(400).json({ success: false, error: 'MISSING_IP' });
    return res.json({ success: true, ...(await globalThreatIntelKeyManager.resolve(ip)) });
  } catch (err: any) {
    return res.status(500).json({ success: false, error: 'RESOLVE_FAILED', message: err?.message || 'Unknown error.' });
  }
});

defenseRouter.get('/intel/keys/status', (_req, res) => {
  return res.json({ success: true, ...globalThreatIntelKeyManager.getStatus() });
});

// -----------------------------------------------------------------------
// SOC admin: runtime key injection
// -----------------------------------------------------------------------

/**
 * POST /api/v1/soc/admin/configure-keys
 *
 * Accepts keys in the request BODY only, never a query parameter: URLs land
 * in access logs, proxy logs, and browser history. The response echoes a
 * fingerprint and the last four characters so an operator can confirm which
 * key loaded, and never the key itself.
 */
adminRouter.post('/configure-keys', (req, res) => {
  try {
    const { keys, installedBy = 'soc-operator' } = req.body || {};
    if (!keys || typeof keys !== 'object' || Array.isArray(keys)) {
      return res.status(400).json({
        success: false,
        error: 'MISSING_KEYS',
        message: 'Provide a "keys" object mapping provider to key value.',
        messageAr: 'أرسل كائن "keys" يربط اسم المزود بقيمة المفتاح.'
      });
    }

    const installed: Array<{ provider: string; fingerprint: string; lastFour: string }> = [];
    const rejected: Array<{ provider: string; reason: string }> = [];

    for (const [provider, value] of Object.entries(keys)) {
      const p = provider.toUpperCase() as IntelProvider;
      if (!VALID_PROVIDERS.includes(p)) {
        rejected.push({ provider, reason: 'unsupported provider' });
        continue;
      }
      if (typeof value !== 'string' || value.trim().length < 8) {
        rejected.push({ provider, reason: 'key missing or implausibly short' });
        continue;
      }
      const rec = globalThreatIntelKeyManager.installKey(p, value.trim(), String(installedBy));
      installed.push({ provider: p, fingerprint: rec.fingerprint, lastFour: rec.lastFour });
    }

    return res.json({
      success: installed.length > 0,
      installed,
      rejected,
      keyValuesEchoed: false,
      note: 'Keys are held in memory only; never logged, persisted, or returned by any read API.',
      noteAr: 'تُحفظ المفاتيح في الذاكرة فقط ولا تُسجل ولا تُخزَّن ولا تُعاد عبر أي واجهة قراءة.',
      status: globalThreatIntelKeyManager.getStatus()
    });
  } catch (err: any) {
    return res.status(500).json({ success: false, error: 'KEY_CONFIGURATION_FAILED', message: err?.message || 'Unknown error.' });
  }
});

adminRouter.post('/revoke-key', (req, res) => {
  const { provider } = req.body || {};
  const p = String(provider || '').toUpperCase() as IntelProvider;
  if (!VALID_PROVIDERS.includes(p)) {
    return res.status(400).json({ success: false, error: 'INVALID_PROVIDER', validProviders: VALID_PROVIDERS });
  }
  return res.json({ success: true, revoked: globalThreatIntelKeyManager.revokeKey(p), provider: p });
});

adminRouter.get('/keys', (_req, res) => {
  return res.json({ success: true, keys: globalThreatIntelKeyManager.getKeyRecords(), keyValuesExposed: false });
});
