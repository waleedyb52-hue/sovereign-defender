import { DatabaseSync, type StatementSync } from 'node:sqlite';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';

/**
 * OPERATOR ADJUDICATION — labelled data that is honest about its own origin
 *
 * Phase 1 produced an evaluation harness and a number the platform can defend.
 * It also exposed the limit of that number: every sample in it was authored by
 * the same process that wrote the rules. Set B Tier 2 measured the consequence
 * — 25% recall on attack classes nobody wrote a rule for. No amount of further
 * rule-writing fixes that, because the problem is the data, not the regexes.
 *
 * This service produces the missing ingredient: labels that came from outside
 * the authoring process. An analyst confirms or overturns a machine verdict,
 * and that decision becomes ground truth.
 *
 * Four properties are load-bearing, and each is enforced structurally rather
 * than documented and hoped for.
 *
 * 1. APPEND-ONLY.
 *    A label is never updated in place. Revising one inserts a new row that
 *    supersedes the old, and the old row stays readable. In a security product
 *    the ability to prove a label was not quietly rewritten matters as much as
 *    the label itself. `activeLabels()` reads only unsuperseded rows; the full
 *    history remains for audit.
 *
 * 2. PROVENANCE ON EVERY ROW.
 *    Who or what produced the label, when, and from which source. A label
 *    without provenance is an assertion, and this plan does not report
 *    assertions as measurements.
 *
 * 3. TEMPORAL FOLDS, DERIVED NOT STORED.
 *    TESSERACT (USENIX Security 2019) requires that training data strictly
 *    precede test data; a random split leaks the future into the past and
 *    inflates every figure. Folds here are recomputed from `detected_at` on
 *    every call, so they cannot drift out of step with the data the way a
 *    stored fold column silently does.
 *
 * 4. THE TEST FOLD IS STRUCTURALLY UNREACHABLE FOR TUNING.
 *    This is the part a comment cannot enforce. Plan principle 3 says test data
 *    is never used to develop rules, so `exportForTuning()` cannot return the
 *    newest fold at all. It is not a filter a caller may pass a flag to defeat
 *    — the newest fold is excluded before the slice is taken. Reading it needs
 *    `exportForTest()`, which withholds labels unless the caller is scoring
 *    predictions it has already committed to.
 *
 * And the constraint inherited from Phase 1: where there is not enough data to
 * support a figure, this service returns `sufficient: false` and states what is
 * missing. It never interpolates a number to look finished.
 */

export type AnalystLabel = 'MALICIOUS' | 'BENIGN';
export type MachineVerdict = 'BLOCK' | 'ALLOW' | 'UNKNOWN';
export type ActorKind = 'HUMAN_ANALYST' | 'AUTOMATED_IMPORT' | 'REPLAY_HARNESS';
export type LabelSource = 'LIVE_TRAFFIC' | 'REPLAY' | 'IMPORT' | 'DRILL';

/** Below this, no aggregate figure is reported at all. */
export const MIN_LABELS_FOR_STABLE_FIGURE = 100;
/** A fold thinner than this cannot carry a defensible per-fold number. */
export const MIN_PER_FOLD = 20;
/** Default temporal fold count. Fold 0 is oldest; the last fold is test-only. */
export const DEFAULT_FOLDS = 4;
/** Payload text is bounded before storage — an analyst needs a sample, not a corpus. */
const PAYLOAD_SAMPLE_MAX = 2048;
/**
 * SOURCE RANGES RESERVED FOR EVALUATION HARNESSES
 *
 * Traffic from these prefixes never enters the adjudication queue.
 *
 * This exists because of a contamination that actually happened. The evaluation
 * harnesses send their payloads to /api/v1/agent/ai-analyze, which is the correct
 * way to test the live classifier — and that endpoint also queues what it sees for
 * adjudication. So Set A and Set B payloads flowed into the queue, and 36 of the
 * first 80 labels written turned out to be Set B strings. A learner trained on that
 * corpus would have seen Set B, which would make every later Set B score on the
 * learner meaningless.
 *
 * Nobody was watching that path. The guard protecting the newest temporal fold from
 * tuning was in place and did nothing here, because the leak was upstream of folds
 * entirely: evaluation data was becoming training data before any fold existed.
 *
 * WHO DECIDES THAT TRAFFIC IS EVALUATION — the server, not the request body
 *
 * The first version of this guard keyed on `packet.srcIp`, a field the caller writes. Any
 * authenticated caller could keep a payload out of analyst review by claiming a 10.20.x
 * source, and genuine detections from a network that happens to use 10.20/16, 10.30/16,
 * 10.40/16, 10.80/16 or 10.90/16 — common enterprise ranges — never reached the queue.
 *
 * The decision is now made by the route from facts the server verifies itself (see
 * `isVerifiedEvaluationRequest` in server.ts): the request carries EVALUATION_SOURCE_HEADER,
 * the caller authenticated as ADMIN, and the TCP peer is a direct loopback connection with
 * no forwarding headers. The route passes the result as `isEvaluationSource`; nothing in the
 * packet can set it. The harnesses send the header:
 *   eval_harness.ts (Set A), eval_holdout_b.ts (Set B), eval_external_httpparams.ts,
 *   eval_from_adjudicated.ts.
 * seed_adjudication_drill.ts deliberately does not: it exists to put traffic in the queue.
 *
 * EVALUATION_SOURCE_PREFIXES is kept only to recognise labels written before this change
 * (audit/retract_evaluation_labels.ts); it no longer excludes anything at the queue entry.
 */
export const EVALUATION_SOURCE_PREFIXES = ['10.20.', '10.30.', '10.40.', '10.80.', '10.90.'] as const;
export const EVALUATION_SOURCE_HEADER = 'x-sd-evaluation-source';

/** Whether a stored source address falls in a historical harness range. Not a queue guard. */
export function isEvaluationSource(srcIp: string): boolean {
  const ip = String(srcIp ?? '');
  return EVALUATION_SOURCE_PREFIXES.some(p => ip.startsWith(p));
}

/** Ceiling on the unadjudicated queue, so live traffic cannot grow it without limit. */
const PENDING_CAP = 5000;

/**
 * WRITE-BEHIND FOR THE PENDING QUEUE
 *
 * recordPending() runs on every uncached classification. Written straight through it was
 * three statement compilations, an INSERT in its own transaction (one WAL sync each) and a
 * COUNT(*) over the queue, all synchronous on the event loop: a CPU profile under load put
 * more busy time in this one function than in everything else on the request path combined.
 *
 * Pending rows are now collected in memory and written in one transaction at most every
 * FLUSH_INTERVAL_MS, or sooner when FLUSH_MAX_ROWS accumulate. Only the pending queue is
 * deferred. Labels - the append-only, provenance-bearing record - are still written
 * synchronously by adjudicate(), and every method that reads the queue flushes first, so no
 * caller can observe the buffer. What is given up is durability of the last few
 * milliseconds of suggestions-for-review if the process is killed, never of a ruling.
 *
 * SD_ADJUDICATION_WRITE_BEHIND=off restores the write-through path, so the two can be
 * measured against each other on the same machine and database (scripts/perf-ab.mjs).
 */
const WRITE_BEHIND = process.env.SD_ADJUDICATION_WRITE_BEHIND !== 'off';
/**
 * SD_ADJUDICATION_FLUSH_MS lengthens the interval for the shutdown tests, which need rows to
 * still be in the buffer when the signal arrives. Clamped; production leaves it unset.
 */
const FLUSH_INTERVAL_MS = Math.min(600_000, Math.max(10, Number(process.env.SD_ADJUDICATION_FLUSH_MS) || 50));
const FLUSH_MAX_ROWS = 256;

interface BufferedPending {
  id: string;
  hash: string;
  sample: string;
  verdict: string;
  score: number;
  family: string;
  sigs: string;
  srcIp: string;
  detectedAt: string;
  /** Sightings accumulated while buffered. */
  seen: number;
}

/** One exit hook for every store, so buffered rows are written on a normal shutdown. */
const liveStores = new Set<{ flushPending(): void }>();
let exitHookInstalled = false;
function registerForExitFlush(store: { flushPending(): void }) {
  liveStores.add(store);
  if (exitHookInstalled) return;
  exitHookInstalled = true;
  process.on('exit', () => { for (const st of liveStores) st.flushPending(); });
}

export interface PendingDetection {
  id: string;
  payloadSha256: string;
  payloadSample: string;
  machineVerdict: MachineVerdict;
  machineScore: number;
  machineFamily: string;
  machineSignatures: string[];
  srcIp: string;
  detectedAt: string;
  seenCount: number;
}

export interface AdjudicationInput {
  detectionId: string;
  analystLabel: AnalystLabel;
  adjudicatedBy: string;
  actorKind?: ActorKind;
  source?: LabelSource;
  notes?: string;
  /** Supply when revising an existing label; the prior row is superseded, not erased. */
  revises?: string;
}

export interface LabelRecord {
  id: string;
  detectionId: string;
  payloadSha256: string;
  payloadSample: string;
  machineVerdict: MachineVerdict;
  machineScore: number;
  machineFamily: string;
  analystLabel: AnalystLabel;
  /** Did the analyst uphold the machine, or overturn it? Derived, never supplied. */
  agreed: boolean;
  adjudicatedBy: string;
  actorKind: ActorKind;
  source: LabelSource;
  notes: string | null;
  detectedAt: string;
  adjudicatedAt: string;
  supersedes: string | null;
}

export interface AdjudicationStats {
  totalLabels: number;
  malicious: number;
  benign: number;
  /** How often the analyst upheld the machine. Null while n is too small to mean anything. */
  agreementRate: number | null;
  machineFalsePositives: number;
  machineFalseNegatives: number;
  revisions: number;
  /** Count of retracted labels. Visible so a shrinking corpus is never silent. */
  retractions: number;
  distinctAdjudicators: number;
  /**
   * Label counts by origin. Reported prominently because a corpus built from
   * drills is not a corpus built from operators, and a figure computed over the
   * former must never be presented as the latter.
   */
  bySource: Record<string, number>;
  byActorKind: Record<string, number>;
  /** True only when every active label came from a human analyst. */
  operatorGrounded: boolean;
  earliestDetectedAt: string | null;
  latestDetectedAt: string | null;
  pendingCount: number;
  /** Detections refused as evaluation traffic, so the filter can be audited. */
  evaluationSourcesRejected: number;
  sufficient: boolean;
  /** Present only when insufficient — states plainly what is missing. */
  shortfall?: string;
}

export interface FoldSplit {
  foldCount: number;
  folds: Array<{ index: number; n: number; from: string; to: string; role: 'TUNING' | 'TEST' }>;
  sufficient: boolean;
  shortfall?: string;
}

export class AdjudicationService {
  private db: DatabaseSync;
  private ready = false;
  private persistent = false;
  /** Detections refused as evaluation traffic. Reported, so the filter is auditable. */
  private evaluationSourcesRejected = 0;
  /** Pending rows not yet written, keyed by payload hash. See WRITE-BEHIND above. */
  private pendingBuffer = new Map<string, BufferedPending>();
  private flushTimer: ReturnType<typeof setTimeout> | null = null;
  private stmtSettled: StatementSync | null = null;
  private stmtExisting: StatementSync | null = null;
  private stmtUpsert: StatementSync | null = null;

  constructor(dbPath?: string) {
    const target = dbPath ?? path.join(process.cwd(), 'data', 'adjudication.db');
    try {
      fs.mkdirSync(path.dirname(target), { recursive: true });
      this.db = new DatabaseSync(target);
      this.persistent = target !== ':memory:';
    } catch (err: any) {
      // Graceful degradation, per the platform resilience rule: an unwritable
      // disk must not take the SOC down. An in-memory store keeps the surface
      // functional for the session, and `durable` reports that it is not saved.
      console.warn('[adjudication] falling back to in-memory store:', err?.message);
      this.db = new DatabaseSync(':memory:');
      this.persistent = false;
    }
    this.migrate();
    if (WRITE_BEHIND) registerForExitFlush(this);
  }

  private migrate() {
    try {
      if (this.persistent) this.db.exec('PRAGMA journal_mode = WAL');
      this.db.exec(`
        CREATE TABLE IF NOT EXISTS pending_detections (
          id              TEXT PRIMARY KEY,
          payload_sha256  TEXT NOT NULL UNIQUE,
          payload_sample  TEXT NOT NULL,
          machine_verdict TEXT NOT NULL,
          machine_score   REAL NOT NULL,
          machine_family  TEXT NOT NULL,
          machine_sigs    TEXT NOT NULL,
          src_ip          TEXT NOT NULL,
          detected_at     TEXT NOT NULL,
          seen_count      INTEGER NOT NULL DEFAULT 1
        )
      `);
      this.db.exec(`
        CREATE TABLE IF NOT EXISTS labels (
          id              TEXT PRIMARY KEY,
          detection_id    TEXT NOT NULL,
          payload_sha256  TEXT NOT NULL,
          payload_sample  TEXT NOT NULL,
          machine_verdict TEXT NOT NULL,
          machine_score   REAL NOT NULL,
          machine_family  TEXT NOT NULL,
          analyst_label   TEXT NOT NULL,
          agreed          INTEGER NOT NULL,
          adjudicated_by  TEXT NOT NULL,
          actor_kind      TEXT NOT NULL,
          source          TEXT NOT NULL,
          notes           TEXT,
          detected_at     TEXT NOT NULL,
          adjudicated_at  TEXT NOT NULL,
          supersedes      TEXT,
          -- Non-null marks a row as a RETRACTION rather than a label. See the
          -- retract() method for why this exists: superseding replaces one label
          -- with another and leaves a label active, which cannot express
          -- withdrawing one from the corpus entirely.
          retraction_reason TEXT
        )
      `);
      // Temporal ordering is the hot path for every fold computation.
      // Additive migration for stores created before retraction existed.
      try {
        const cols = this.db.prepare('PRAGMA table_info(labels)').all() as any[];
        if (!cols.some(c => String(c.name) === 'retraction_reason')) {
          this.db.exec('ALTER TABLE labels ADD COLUMN retraction_reason TEXT');
        }
      } catch { /* fresh store already has it */ }

      this.db.exec('CREATE INDEX IF NOT EXISTS idx_labels_detected ON labels(detected_at)');
      this.db.exec('CREATE INDEX IF NOT EXISTS idx_labels_supersedes ON labels(supersedes)');
      this.db.exec('CREATE INDEX IF NOT EXISTS idx_pending_detected ON pending_detections(detected_at)');
      this.ready = true;
    } catch (err: any) {
      console.warn('[adjudication] migration failed, service degraded:', err?.message);
      this.ready = false;
    }
  }

  get available() { return this.ready; }
  get durable() { return this.persistent; }

  private static sha256(s: string) {
    return crypto.createHash('sha256').update(s, 'utf8').digest('hex');
  }

  /**
   * Record a detection as awaiting adjudication.
   *
   * Deduplicated on the payload hash rather than on the event: an analyst should
   * rule on a payload once, not once per source address. Repeat sightings bump
   * `seen_count`, which is also the signal for which payloads deserve an
   * analyst's attention first.
   */
  recordPending(input: {
    payload: string;
    machineVerdict: MachineVerdict;
    machineScore: number;
    machineFamily: string;
    machineSignatures: string[];
    srcIp: string;
    detectedAt?: string;
    /**
     * Set by the route from server-verified facts (ADMIN caller, direct loopback, declared
     * evaluation). Never derived from the packet: `srcIp` is the caller's claim.
     */
    isEvaluationSource?: boolean;
  }): string | null {
    if (!this.ready) return null;
    const payload = String(input.payload ?? '');
    if (!payload.trim()) return null;

    // Evaluation traffic is refused here, at the only entry point into the queue.
    // Filtering later — in the export, or in a fold — would be too late: the label
    // would already exist, and a label is the thing that contaminates.
    if (input.isEvaluationSource === true) {
      this.evaluationSourcesRejected++;
      return null;
    }

    const hash = AdjudicationService.sha256(payload);
    if (WRITE_BEHIND) return this.recordPendingBuffered(hash, payload, input);
    try {
      // Already adjudicated? Then it is not pending, and re-queuing it would
      // invite a second contradictory label for the same payload.
      const settled = this.db.prepare(
        'SELECT 1 FROM labels WHERE payload_sha256 = ? LIMIT 1'
      ).get(hash);
      if (settled) return null;

      const existing = this.db.prepare('SELECT id FROM pending_detections WHERE payload_sha256 = ?').get(hash) as any;
      if (existing?.id) {
        this.db.prepare('UPDATE pending_detections SET seen_count = seen_count + 1 WHERE payload_sha256 = ?').run(hash);
        return String(existing.id);
      }

      const id = 'det_' + crypto.randomBytes(9).toString('hex');
      this.db.prepare(`
        INSERT INTO pending_detections
          (id, payload_sha256, payload_sample, machine_verdict, machine_score,
           machine_family, machine_sigs, src_ip, detected_at, seen_count)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
      `).run(
        id, hash, payload.slice(0, PAYLOAD_SAMPLE_MAX),
        input.machineVerdict, Number(input.machineScore) || 0,
        input.machineFamily || 'UNKNOWN',
        JSON.stringify(input.machineSignatures ?? []),
        input.srcIp || '0.0.0.0',
        input.detectedAt ?? new Date().toISOString()
      );

      // Oldest-first eviction keeps the queue bounded. Newer detections reflect
      // the current traffic distribution, so they are what an analyst should be
      // ruling on when the queue has to be trimmed.
      const n = Number((this.db.prepare('SELECT COUNT(*) AS n FROM pending_detections').get() as any)?.n ?? 0);
      if (n > PENDING_CAP) {
        this.db.prepare(
          'DELETE FROM pending_detections WHERE id IN (SELECT id FROM pending_detections ORDER BY detected_at ASC LIMIT ?)'
        ).run(n - PENDING_CAP);
      }
      return id;
    } catch (err: any) {
      console.warn('[adjudication] recordPending failed:', err?.message);
      return null;
    }
  }

  /** Same decisions as the write-through path above, with the write deferred to flushPending(). */
  private recordPendingBuffered(
    hash: string,
    payload: string,
    input: { machineVerdict: MachineVerdict; machineScore: number; machineFamily: string; machineSignatures: string[]; srcIp: string; detectedAt?: string }
  ): string | null {
    const buffered = this.pendingBuffer.get(hash);
    if (buffered) { buffered.seen++; return buffered.id; }
    try {
      this.stmtSettled ??= this.db.prepare('SELECT 1 FROM labels WHERE payload_sha256 = ? LIMIT 1');
      if (this.stmtSettled.get(hash)) return null;
      this.stmtExisting ??= this.db.prepare('SELECT id FROM pending_detections WHERE payload_sha256 = ?');
      const existing = this.stmtExisting.get(hash) as any;
      const id = existing?.id ? String(existing.id) : 'det_' + crypto.randomBytes(9).toString('hex');
      this.pendingBuffer.set(hash, {
        id, hash, sample: payload.slice(0, PAYLOAD_SAMPLE_MAX),
        verdict: input.machineVerdict, score: Number(input.machineScore) || 0,
        family: input.machineFamily || 'UNKNOWN',
        sigs: JSON.stringify(input.machineSignatures ?? []),
        srcIp: input.srcIp || '0.0.0.0',
        detectedAt: input.detectedAt ?? new Date().toISOString(),
        seen: 1
      });
      if (this.pendingBuffer.size >= FLUSH_MAX_ROWS) this.flushPending();
      else if (!this.flushTimer) {
        this.flushTimer = setTimeout(() => this.flushPending(), FLUSH_INTERVAL_MS);
        this.flushTimer.unref?.();
      }
      return id;
    } catch (err: any) {
      console.warn('[adjudication] recordPending failed:', err?.message);
      return null;
    }
  }

  /**
   * Write buffered pending rows in one transaction. Safe to call at any time and from the
   * process exit hook; a failure rolls back and drops the batch with a warning, which costs
   * review suggestions and never a detection or a label.
   */
  flushPending(): void {
    if (this.flushTimer) { clearTimeout(this.flushTimer); this.flushTimer = null; }
    if (!this.pendingBuffer.size || !this.ready) return;
    const batch = [...this.pendingBuffer.values()];
    this.pendingBuffer.clear();
    try {
      // A sighting of a payload already queued adds to its count; a new payload inserts.
      this.stmtUpsert ??= this.db.prepare(`
        INSERT INTO pending_detections
          (id, payload_sha256, payload_sample, machine_verdict, machine_score,
           machine_family, machine_sigs, src_ip, detected_at, seen_count)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(payload_sha256) DO UPDATE SET seen_count = seen_count + excluded.seen_count
      `);
      this.db.exec('BEGIN IMMEDIATE');
      for (const r of batch) {
        this.stmtUpsert.run(r.id, r.hash, r.sample, r.verdict, r.score, r.family, r.sigs, r.srcIp, r.detectedAt, r.seen);
      }
      const n = Number((this.db.prepare('SELECT COUNT(*) AS n FROM pending_detections').get() as any)?.n ?? 0);
      if (n > PENDING_CAP) {
        this.db.prepare(
          'DELETE FROM pending_detections WHERE id IN (SELECT id FROM pending_detections ORDER BY detected_at ASC LIMIT ?)'
        ).run(n - PENDING_CAP);
      }
      this.db.exec('COMMIT');
    } catch (err: any) {
      try { this.db.exec('ROLLBACK'); } catch { /* nothing open */ }
      console.warn('[adjudication] flushPending failed:', err?.message);
    }
  }

  /** Queue for the analyst, most-repeated first — highest evaluation value per decision. */
  queue(limit = 50): PendingDetection[] {
    if (!this.ready) return [];
    this.flushPending();
    try {
      const rows = this.db.prepare(
        'SELECT * FROM pending_detections ORDER BY seen_count DESC, detected_at DESC LIMIT ?'
      ).all(Math.max(1, Math.min(500, limit))) as any[];
      return rows.map(r => ({
        id: String(r.id),
        payloadSha256: String(r.payload_sha256),
        payloadSample: String(r.payload_sample),
        machineVerdict: String(r.machine_verdict) as MachineVerdict,
        machineScore: Number(r.machine_score),
        machineFamily: String(r.machine_family),
        machineSignatures: JSON.parse(String(r.machine_sigs || '[]')),
        srcIp: String(r.src_ip),
        detectedAt: String(r.detected_at),
        seenCount: Number(r.seen_count)
      }));
    } catch { return []; }
  }

  /**
   * Turn an analyst decision into a label.
   *
   * `agreed` is computed here from the machine verdict and the analyst's call,
   * never accepted from the caller. A client that could assert agreement could
   * manufacture an accuracy figure, which is the exact failure Phase 1 exists
   * to prevent.
   */
  adjudicate(input: AdjudicationInput): { ok: true; label: LabelRecord } | { ok: false; error: string } {
    if (!this.ready) return { ok: false, error: 'ADJUDICATION_STORE_UNAVAILABLE' };
    this.flushPending();
    if (input.analystLabel !== 'MALICIOUS' && input.analystLabel !== 'BENIGN') {
      return { ok: false, error: 'INVALID_LABEL' };
    }
    if (!input.adjudicatedBy || !String(input.adjudicatedBy).trim()) {
      // Provenance is not optional. An anonymous label is an assertion.
      return { ok: false, error: 'ADJUDICATOR_IDENTITY_REQUIRED' };
    }

    try {
      const det = this.db.prepare('SELECT * FROM pending_detections WHERE id = ?').get(input.detectionId) as any;
      let base: any = det;

      // A revision reads its subject from the label table, because the pending
      // row is already gone once the first label was written.
      if (!base && input.revises) {
        const prior = this.db.prepare('SELECT * FROM labels WHERE id = ?').get(input.revises) as any;
        if (prior) {
          base = {
            payload_sha256: prior.payload_sha256,
            payload_sample: prior.payload_sample,
            machine_verdict: prior.machine_verdict,
            machine_score: prior.machine_score,
            machine_family: prior.machine_family,
            detected_at: prior.detected_at
          };
        }
      }
      if (!base) return { ok: false, error: 'DETECTION_NOT_FOUND' };

      if (input.revises) {
        const prior = this.db.prepare('SELECT id FROM labels WHERE id = ?').get(input.revises);
        if (!prior) return { ok: false, error: 'REVISED_LABEL_NOT_FOUND' };
        const already = this.db.prepare('SELECT id FROM labels WHERE supersedes = ?').get(input.revises);
        if (already) return { ok: false, error: 'LABEL_ALREADY_SUPERSEDED' };
      }

      const machineVerdict = String(base.machine_verdict) as MachineVerdict;
      const machineSaysMalicious = machineVerdict === 'BLOCK';
      const analystSaysMalicious = input.analystLabel === 'MALICIOUS';
      const agreed = machineSaysMalicious === analystSaysMalicious;

      const id = 'lbl_' + crypto.randomBytes(9).toString('hex');
      const adjudicatedAt = new Date().toISOString();

      this.db.prepare(`
        INSERT INTO labels
          (id, detection_id, payload_sha256, payload_sample, machine_verdict, machine_score,
           machine_family, analyst_label, agreed, adjudicated_by, actor_kind, source,
           notes, detected_at, adjudicated_at, supersedes)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        id, input.detectionId, String(base.payload_sha256), String(base.payload_sample),
        machineVerdict, Number(base.machine_score), String(base.machine_family),
        input.analystLabel, agreed ? 1 : 0,
        String(input.adjudicatedBy).slice(0, 120),
        input.actorKind ?? 'HUMAN_ANALYST',
        input.source ?? 'LIVE_TRAFFIC',
        input.notes ? String(input.notes).slice(0, 1000) : null,
        String(base.detected_at), adjudicatedAt,
        input.revises ?? null
      );

      if (det) this.db.prepare('DELETE FROM pending_detections WHERE id = ?').run(input.detectionId);

      return {
        ok: true,
        label: {
          id, detectionId: input.detectionId,
          payloadSha256: String(base.payload_sha256),
          payloadSample: String(base.payload_sample),
          machineVerdict, machineScore: Number(base.machine_score),
          machineFamily: String(base.machine_family),
          analystLabel: input.analystLabel, agreed,
          adjudicatedBy: String(input.adjudicatedBy),
          actorKind: input.actorKind ?? 'HUMAN_ANALYST',
          source: input.source ?? 'LIVE_TRAFFIC',
          notes: input.notes ?? null,
          detectedAt: String(base.detected_at),
          adjudicatedAt, supersedes: input.revises ?? null
        }
      };
    } catch (err: any) {
      return { ok: false, error: 'ADJUDICATION_FAILED: ' + (err?.message ?? 'unknown') };
    }
  }

  /**
   * Withdraw a label from the corpus, permanently and auditably.
   *
   * Inserts a retraction row that supersedes the target. The target leaves the
   * active set because it is superseded; the retraction leaves it because its
   * `retraction_reason` is non-null. Nothing is updated and nothing is deleted, so
   * a reviewer can still see what was withdrawn and why.
   *
   * A reason is mandatory. A label that vanishes without a recorded reason is
   * indistinguishable from data being quietly dropped to improve a number, which
   * is the behaviour this entire store exists to make impossible.
   */
  retract(labelId: string, reason: string, retractedBy: string): { ok: true; retractionId: string } | { ok: false; error: string } {
    if (!this.ready) return { ok: false, error: 'ADJUDICATION_STORE_UNAVAILABLE' };
    if (!reason?.trim()) return { ok: false, error: 'RETRACTION_REASON_REQUIRED' };
    if (!retractedBy?.trim()) return { ok: false, error: 'RETRACTOR_IDENTITY_REQUIRED' };

    try {
      const target = this.db.prepare('SELECT * FROM labels WHERE id = ?').get(labelId) as any;
      if (!target) return { ok: false, error: 'LABEL_NOT_FOUND' };
      if (target.retraction_reason) return { ok: false, error: 'CANNOT_RETRACT_A_RETRACTION' };

      const already = this.db.prepare('SELECT id FROM labels WHERE supersedes = ?').get(labelId);
      if (already) return { ok: false, error: 'LABEL_ALREADY_SUPERSEDED_OR_RETRACTED' };

      const id = 'ret_' + crypto.randomBytes(9).toString('hex');
      this.db.prepare(`
        INSERT INTO labels
          (id, detection_id, payload_sha256, payload_sample, machine_verdict, machine_score,
           machine_family, analyst_label, agreed, adjudicated_by, actor_kind, source,
           notes, detected_at, adjudicated_at, supersedes, retraction_reason)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        id,
        String(target.detection_id),
        String(target.payload_sha256),
        String(target.payload_sample),
        String(target.machine_verdict),
        Number(target.machine_score),
        String(target.machine_family),
        String(target.analyst_label),
        Number(target.agreed),
        String(retractedBy).slice(0, 120),
        String(target.actor_kind),
        String(target.source),
        `RETRACTED: ${String(reason).slice(0, 800)}`,
        String(target.detected_at),
        new Date().toISOString(),
        labelId,
        String(reason).slice(0, 800)
      );
      return { ok: true, retractionId: id };
    } catch (err: any) {
      return { ok: false, error: 'RETRACTION_FAILED: ' + (err?.message ?? 'unknown') };
    }
  }

  /** Unsuperseded labels in temporal order. The basis of every figure below. */
  private activeLabels(): any[] {
    if (!this.ready) return [];
    try {
      return this.db.prepare(`
        SELECT * FROM labels
        WHERE id NOT IN (SELECT supersedes FROM labels WHERE supersedes IS NOT NULL)
          AND retraction_reason IS NULL
        ORDER BY detected_at ASC
      `).all() as any[];
    } catch { return []; }
  }

  stats(): AdjudicationStats {
    const tally = (xs: string[]) => xs.reduce<Record<string, number>>((acc, x) => {
      acc[x] = (acc[x] ?? 0) + 1;
      return acc;
    }, {});
    const rows = this.activeLabels();
    const total = rows.length;
    const malicious = rows.filter(r => r.analyst_label === 'MALICIOUS').length;
    const agreedN = rows.filter(r => Number(r.agreed) === 1).length;

    // Machine error accounting, taken from the analyst's ruling rather than
    // from our own classifier grading itself.
    const fp = rows.filter(r => r.machine_verdict === 'BLOCK' && r.analyst_label === 'BENIGN').length;
    const fn = rows.filter(r => r.machine_verdict !== 'BLOCK' && r.analyst_label === 'MALICIOUS').length;

    let revisions = 0, pending = 0, retractions = 0;
    this.flushPending();
    try {
      revisions = Number((this.db.prepare('SELECT COUNT(*) AS n FROM labels WHERE supersedes IS NOT NULL AND retraction_reason IS NULL').get() as any)?.n ?? 0);
      retractions = Number((this.db.prepare('SELECT COUNT(*) AS n FROM labels WHERE retraction_reason IS NOT NULL').get() as any)?.n ?? 0);
      pending = Number((this.db.prepare('SELECT COUNT(*) AS n FROM pending_detections').get() as any)?.n ?? 0);
    } catch { /* degraded store: counts stay zero rather than guessed */ }

    const sufficient = total >= MIN_LABELS_FOR_STABLE_FIGURE;
    const out: AdjudicationStats = {
      totalLabels: total,
      malicious,
      benign: total - malicious,
      // Reported only once it can mean something. Below the threshold this is
      // null, not a percentage computed from a handful of rows.
      agreementRate: sufficient ? agreedN / total : null,
      machineFalsePositives: fp,
      machineFalseNegatives: fn,
      revisions,
      /** Labels withdrawn from the corpus, each with a recorded reason. */
      retractions,
      distinctAdjudicators: new Set(rows.map(r => String(r.adjudicated_by))).size,
      bySource: tally(rows.map(r => String(r.source))),
      byActorKind: tally(rows.map(r => String(r.actor_kind))),
      operatorGrounded: total > 0 && rows.every(r => String(r.actor_kind) === 'HUMAN_ANALYST'),
      earliestDetectedAt: total ? String(rows[0].detected_at) : null,
      latestDetectedAt: total ? String(rows[total - 1].detected_at) : null,
      pendingCount: pending,
      /**
       * Detections refused because they came from an evaluation harness.
       * Surfaced rather than hidden: a filter nobody can see is a filter nobody
       * can check, and this one is load-bearing for every held-out claim.
       */
      evaluationSourcesRejected: this.evaluationSourcesRejected,
      sufficient
    };
    if (!sufficient) {
      out.shortfall = `${total} adjudicated labels; ${MIN_LABELS_FOR_STABLE_FIGURE} needed before a figure is reported`;
    }
    return out;
  }

  /**
   * Temporal fold layout, recomputed from timestamps on every call.
   *
   * Contiguous and time-ordered: fold 0 holds the oldest labels, the last fold
   * the newest. That last fold is the test fold and nothing else may use it.
   */
  folds(foldCount = DEFAULT_FOLDS): FoldSplit {
    const rows = this.activeLabels();
    const k = Math.max(2, Math.min(10, foldCount));
    const per = Math.floor(rows.length / k);

    if (per < MIN_PER_FOLD) {
      return {
        foldCount: k, folds: [], sufficient: false,
        shortfall: `${rows.length} labels across ${k} folds gives ${per} per fold; ${MIN_PER_FOLD} needed. A fold this thin cannot carry a defensible number.`
      };
    }

    const folds: FoldSplit['folds'] = [];
    for (let i = 0; i < k; i++) {
      const start = i * per;
      const end = i === k - 1 ? rows.length : start + per;
      const slice = rows.slice(start, end);
      folds.push({
        index: i,
        n: slice.length,
        from: String(slice[0].detected_at),
        to: String(slice[slice.length - 1].detected_at),
        role: i === k - 1 ? 'TEST' : 'TUNING'
      });
    }
    return { foldCount: k, folds, sufficient: true };
  }

  /**
   * Data a developer may look at while writing rules.
   *
   * The newest fold is excluded before the slice is taken — there is no
   * parameter that returns it from here. That is deliberate: plan principle 3
   * says test data must never inform a rule, and a flag a caller can flip is
   * not a guarantee.
   */
  exportForTuning(foldCount = DEFAULT_FOLDS): {
    ok: boolean; reason?: string;
    samples: Array<{ payload: string; label: AnalystLabel; detectedAt: string; fold: number }>;
  } {
    const split = this.folds(foldCount);
    if (!split.sufficient) return { ok: false, reason: split.shortfall, samples: [] };

    const rows = this.activeLabels();
    const k = split.foldCount;
    const per = Math.floor(rows.length / k);
    const cutoff = (k - 1) * per; // everything from here on is the test fold

    return {
      ok: true,
      samples: rows.slice(0, cutoff).map((r, i) => ({
        payload: String(r.payload_sample),
        label: String(r.analyst_label) as AnalystLabel,
        detectedAt: String(r.detected_at),
        fold: Math.min(Math.floor(i / per), k - 2)
      }))
    };
  }

  /**
   * The test fold.
   *
   * Labels are withheld by default, so a caller must classify first and ask for
   * the answers afterwards. This is the same discipline the Phase 1 harness
   * applies to itself: the label cannot reach the classifier, because at the
   * moment of classification the caller does not hold it.
   */
  exportForTest(opts: { withLabels?: boolean; foldCount?: number } = {}): {
    ok: boolean; reason?: string;
    samples: Array<{ id: string; payload: string; detectedAt: string; label?: AnalystLabel }>;
  } {
    const split = this.folds(opts.foldCount ?? DEFAULT_FOLDS);
    if (!split.sufficient) return { ok: false, reason: split.shortfall, samples: [] };

    const rows = this.activeLabels();
    const per = Math.floor(rows.length / split.foldCount);
    const testRows = rows.slice((split.foldCount - 1) * per);

    return {
      ok: true,
      samples: testRows.map(r => {
        const s: { id: string; payload: string; detectedAt: string; label?: AnalystLabel } = {
          id: String(r.id),
          payload: String(r.payload_sample),
          detectedAt: String(r.detected_at)
        };
        if (opts.withLabels) s.label = String(r.analyst_label) as AnalystLabel;
        return s;
      })
    };
  }

  /** Full history including superseded rows — the audit trail, for review. */
  history(limit = 200): LabelRecord[] {
    if (!this.ready) return [];
    try {
      const rows = this.db.prepare('SELECT * FROM labels ORDER BY adjudicated_at DESC LIMIT ?')
        .all(Math.max(1, Math.min(1000, limit))) as any[];
      return rows.map(r => ({
        id: String(r.id), detectionId: String(r.detection_id),
        payloadSha256: String(r.payload_sha256), payloadSample: String(r.payload_sample),
        machineVerdict: String(r.machine_verdict) as MachineVerdict,
        machineScore: Number(r.machine_score), machineFamily: String(r.machine_family),
        analystLabel: String(r.analyst_label) as AnalystLabel,
        agreed: Number(r.agreed) === 1,
        adjudicatedBy: String(r.adjudicated_by),
        actorKind: String(r.actor_kind) as ActorKind,
        source: String(r.source) as LabelSource,
        notes: r.notes ? String(r.notes) : null,
        detectedAt: String(r.detected_at), adjudicatedAt: String(r.adjudicated_at),
        supersedes: r.supersedes ? String(r.supersedes) : null
      }));
    } catch { return []; }
  }
}

export const globalAdjudication = new AdjudicationService();
