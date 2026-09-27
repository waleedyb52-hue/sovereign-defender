import express from 'express';
import {
  globalAdjudication,
  MIN_LABELS_FOR_STABLE_FIGURE,
  DEFAULT_FOLDS,
  type AnalystLabel,
  type ActorKind,
  type LabelSource
} from '../services/adjudication.service.js';

/**
 * ADJUDICATION ROUTES — the operator surface for labelling live detections
 *
 * Mounted behind adminAuthMiddleware in server.ts. That is not decoration:
 * whoever can reach these endpoints can write the ground truth the platform
 * measures itself against, which makes this a higher-privilege surface than
 * most of the SOC, not a lower one.
 *
 * The tuning and test exports are deliberately different shapes. `/export/tuning`
 * hands back payloads with their labels, because that is data a developer is
 * allowed to study. `/export/test` withholds labels unless the caller explicitly
 * asks to score, and the response says so in `labelsWithheld`. The asymmetry is
 * the point — it is the plan's third principle expressed as an API.
 */

export const adjudicationRouter = express.Router();

/** Pending detections awaiting a ruling, most-repeated first. */
adjudicationRouter.get('/queue', (req, res) => {
  const limit = Number(req.query.limit ?? 50);
  const items = globalAdjudication.queue(Number.isFinite(limit) ? limit : 50);
  res.json({
    success: true,
    storeAvailable: globalAdjudication.available,
    durable: globalAdjudication.durable,
    count: items.length,
    items
  });
});

/**
 * Record an analyst ruling.
 *
 * `agreed` is not accepted from the body under any name — the service derives
 * it. A client able to assert agreement could manufacture the platform's own
 * accuracy figure.
 */
adjudicationRouter.post('/adjudicate', (req, res) => {
  const b = req.body ?? {};
  const label = String(b.analystLabel ?? '').toUpperCase();

  if (!b.detectionId) {
    return res.status(400).json({
      success: false,
      error: 'DETECTION_ID_REQUIRED',
      messageAr: 'مُعرّف الكشف مطلوب لتسجيل الحُكم.'
    });
  }
  if (label !== 'MALICIOUS' && label !== 'BENIGN') {
    return res.status(400).json({
      success: false,
      error: 'INVALID_LABEL',
      message: 'analystLabel must be MALICIOUS or BENIGN.',
      messageAr: 'التصنيف يجب أن يكون MALICIOUS أو BENIGN.'
    });
  }

  const result = globalAdjudication.adjudicate({
    detectionId: String(b.detectionId),
    analystLabel: label as AnalystLabel,
    adjudicatedBy: String(b.adjudicatedBy ?? ''),
    actorKind: (b.actorKind as ActorKind) ?? 'HUMAN_ANALYST',
    source: (b.source as LabelSource) ?? 'LIVE_TRAFFIC',
    notes: b.notes ? String(b.notes) : undefined,
    revises: b.revises ? String(b.revises) : undefined
  });

  if (result.ok) {
    return res.json({
      success: true,
      label: result.label,
      // Surfaced because it is the interesting case: the analyst overturned the
      // machine, which is a labelled error the platform did not previously know
      // it had.
      overturnedMachine: !result.label.agreed
    });
  }

  const failure = 'error' in result ? result.error : 'ADJUDICATION_FAILED';
  const status =
    failure === 'DETECTION_NOT_FOUND' || failure === 'REVISED_LABEL_NOT_FOUND' ? 404 :
    failure === 'ADJUDICATOR_IDENTITY_REQUIRED' || failure === 'INVALID_LABEL' ? 400 :
    failure === 'LABEL_ALREADY_SUPERSEDED' ? 409 : 500;
  return res.status(status).json({ success: false, error: failure });
});

/**
 * Corpus health.
 *
 * Returns `sufficient: false` with a stated shortfall rather than a figure,
 * whenever the corpus is too small. Phase 1's first principle, applied to the
 * labelling pipeline itself.
 */
adjudicationRouter.get('/stats', (_req, res) => {
  const s = globalAdjudication.stats();
  res.json({
    success: true,
    storeAvailable: globalAdjudication.available,
    durable: globalAdjudication.durable,
    minLabelsForStableFigure: MIN_LABELS_FOR_STABLE_FIGURE,
    ...s
  });
});

/** Temporal fold layout. TESSERACT ordering, recomputed from timestamps. */
adjudicationRouter.get('/folds', (req, res) => {
  const k = Number(req.query.folds ?? DEFAULT_FOLDS);
  res.json({ success: true, ...globalAdjudication.folds(Number.isFinite(k) ? k : DEFAULT_FOLDS) });
});

/** Data a developer may study while writing rules. Never includes the test fold. */
adjudicationRouter.get('/export/tuning', (req, res) => {
  const k = Number(req.query.folds ?? DEFAULT_FOLDS);
  const out = globalAdjudication.exportForTuning(Number.isFinite(k) ? k : DEFAULT_FOLDS);
  if (!out.ok) {
    return res.status(409).json({
      success: false,
      error: 'INSUFFICIENT_CORPUS',
      reason: out.reason,
      messageAr: 'حجم البيانات المُحكَّمة غير كافٍ لإنتاج تقسيم زمني قابل للدفاع عنه.'
    });
  }
  res.json({
    success: true,
    role: 'TUNING',
    excludesTestFold: true,
    count: out.samples.length,
    samples: out.samples
  });
});

/**
 * The test fold. Labels withheld unless `withLabels=1`.
 *
 * A caller scoring honestly fetches without labels, classifies, then re-fetches
 * with them. The two-step exists so that at the moment of classification the
 * answer is not in the caller's hands.
 */
adjudicationRouter.get('/export/test', (req, res) => {
  const withLabels = req.query.withLabels === '1' || req.query.withLabels === 'true';
  const k = Number(req.query.folds ?? DEFAULT_FOLDS);
  const out = globalAdjudication.exportForTest({
    withLabels,
    foldCount: Number.isFinite(k) ? k : DEFAULT_FOLDS
  });
  if (!out.ok) {
    return res.status(409).json({
      success: false,
      error: 'INSUFFICIENT_CORPUS',
      reason: out.reason,
      messageAr: 'حجم البيانات المُحكَّمة غير كافٍ لإنتاج طبقة اختبار قابلة للدفاع عنها.'
    });
  }
  res.json({
    success: true,
    role: 'TEST',
    labelsWithheld: !withLabels,
    count: out.samples.length,
    samples: out.samples
  });
});

/**
 * Withdraw a label from the corpus.
 *
 * Not a delete. A retraction row is inserted that supersedes the target and carries
 * the reason, so both remain readable. The reason is mandatory: a label that
 * disappears without one is indistinguishable from data pruned to improve a
 * number, and this store exists to make that impossible.
 */
adjudicationRouter.post('/retract', (req, res) => {
  const b = req.body ?? {};
  const result = globalAdjudication.retract(
    String(b.labelId ?? ''),
    String(b.reason ?? ''),
    String(b.retractedBy ?? '')
  );
  if ('retractionId' in result) {
    return res.json({ success: true, retractionId: result.retractionId, labelId: String(b.labelId) });
  }
  const err = 'error' in result ? result.error : 'RETRACTION_FAILED';
  const status =
    err === 'LABEL_NOT_FOUND' ? 404 :
    err === 'RETRACTION_REASON_REQUIRED' || err === 'RETRACTOR_IDENTITY_REQUIRED' ? 400 :
    err === 'LABEL_ALREADY_SUPERSEDED_OR_RETRACTED' || err === 'CANNOT_RETRACT_A_RETRACTION' ? 409 : 500;
  return res.status(status).json({ success: false, error: err });
});

/** Audit trail, superseded rows included. */
adjudicationRouter.get('/history', (req, res) => {
  const limit = Number(req.query.limit ?? 200);
  const items = globalAdjudication.history(Number.isFinite(limit) ? limit : 200);
  res.json({ success: true, count: items.length, items });
});
