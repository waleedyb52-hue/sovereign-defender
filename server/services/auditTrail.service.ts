import { DatabaseSync } from 'node:sqlite';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';

/**
 * AUDIT TRAIL — tamper-evident record of every privileged act.
 *
 * Who isolated a host, who released it, who signed in, who failed to, who created an
 * operator, who rotated the key. NIST SP 800-53 AU-2/AU-3 (what to record, and enough of
 * it to reconstruct the event), AU-9 (protect it from modification), AU-10 (bind each act
 * to an identity).
 *
 * HOW TAMPERING IS MADE VISIBLE
 *
 *   Chain  Each row stores the SHA-256 of its own canonical content plus the hash of the
 *          row before it. Editing or deleting any row breaks every hash after it.
 *
 *   MAC    Each hash is also HMAC-SHA256'd under a key the rows never contain. A plain
 *          chain can be recomputed end to end by whoever rewrote it; the MAC cannot be,
 *          without the key.
 *
 *   SQL    Triggers abort UPDATE and DELETE on the table, so the application — and any
 *          code path added to it later — cannot rewrite history by accident.
 *
 * WHAT THIS DOES NOT CLAIM. Someone with write access to the data directory can read the
 * key file, drop the triggers and forge a consistent chain. The defence against that is
 * outside the host: the verify result reports the head hash, and an operator who records
 * it elsewhere (a ticket, a printout, a second system) can later prove the log was not
 * rewritten behind it. Supplying AUDIT_HMAC_KEY from the environment instead of the key
 * file moves the key off the disk. The UI states this rather than calling the log
 * "immutable", which on a single host it cannot be.
 */

export type AuditOutcome = 'SUCCESS' | 'DENIED' | 'FAILURE';

export interface AuditInput {
  actor: string;
  role: string | null;
  ip: string | null;
  action: string;
  target?: string | null;
  outcome: AuditOutcome;
  detail?: Record<string, unknown> | null;
}

export interface AuditEntry {
  seq: number;
  at: string;
  actor: string;
  role: string | null;
  ip: string | null;
  action: string;
  target: string | null;
  outcome: AuditOutcome;
  detail: Record<string, unknown> | null;
  prevHash: string;
  hash: string;
}

export interface AuditVerification {
  ok: boolean;
  checked: number;
  brokenAt: number | null;
  reason: string | null;
  headSeq: number | null;
  headHash: string | null;
  keySource: 'ENV' | 'KEY_FILE' | 'EPHEMERAL';
  durable: boolean;
}

const GENESIS = '0'.repeat(64);

/** Canonical form: a fixed-order array, so key order in an object can never change a hash. */
function canonical(e: Omit<AuditEntry, 'hash' | 'detail'> & { detailJson: string | null }): string {
  return JSON.stringify([e.seq, e.at, e.actor, e.role, e.ip, e.action, e.target, e.outcome, e.detailJson, e.prevHash]);
}

export class AuditTrailService {
  private db: DatabaseSync;
  private persistent = false;
  private key: Buffer;
  private keySource: AuditVerification['keySource'];

  constructor(dbPath?: string) {
    const target = dbPath ?? path.join(process.cwd(), 'data', 'audit.db');
    try {
      fs.mkdirSync(path.dirname(target), { recursive: true });
      this.db = new DatabaseSync(target);
      this.persistent = target !== ':memory:';
    } catch (err: any) {
      console.warn('[audit] falling back to in-memory audit trail:', err?.message);
      this.db = new DatabaseSync(':memory:');
      this.persistent = false;
    }
    ({ key: this.key, source: this.keySource } = this.loadKey(target));
    this.migrate();
  }

  private loadKey(dbFile: string): { key: Buffer; source: AuditVerification['keySource'] } {
    const env = process.env.AUDIT_HMAC_KEY;
    if (env && env.length >= 32) return { key: Buffer.from(env, 'utf8'), source: 'ENV' };

    if (!this.persistent) return { key: crypto.randomBytes(32), source: 'EPHEMERAL' };

    const keyFile = path.join(path.dirname(dbFile), '.audit_hmac_key');
    try {
      if (fs.existsSync(keyFile)) {
        const k = Buffer.from(fs.readFileSync(keyFile, 'utf8').trim(), 'hex');
        if (k.length === 32) return { key: k, source: 'KEY_FILE' };
      }
      const k = crypto.randomBytes(32);
      // 0600: owner read/write only. Windows ignores the mode; the file still sits inside
      // the gitignored data directory.
      fs.writeFileSync(keyFile, k.toString('hex'), { mode: 0o600 });
      return { key: k, source: 'KEY_FILE' };
    } catch (err: any) {
      console.warn('[audit] key file unavailable, using an ephemeral key:', err?.message);
      return { key: crypto.randomBytes(32), source: 'EPHEMERAL' };
    }
  }

  private migrate() {
    if (this.persistent) {
      try {
        this.db.exec('PRAGMA journal_mode = WAL');
      } catch {
        /* optimisation only */
      }
    }
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS audit_log (
        seq       INTEGER PRIMARY KEY,
        at        TEXT NOT NULL,
        actor     TEXT NOT NULL,
        role      TEXT,
        ip        TEXT,
        action    TEXT NOT NULL,
        target    TEXT,
        outcome   TEXT NOT NULL,
        detail    TEXT,
        prev_hash TEXT NOT NULL,
        hash      TEXT NOT NULL,
        mac       TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS audit_action ON audit_log(action);
      CREATE INDEX IF NOT EXISTS audit_actor ON audit_log(actor);
      CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit_log
        BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
      CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit_log
        BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
    `);
  }

  private mac(hash: string): string {
    return crypto.createHmac('sha256', this.key).update(hash).digest('hex');
  }

  /**
   * Append one entry. Synchronous on purpose: node:sqlite is synchronous and Node runs
   * this on one thread, so read-head-then-insert cannot interleave with another append.
   * An audit write that fails is logged loudly and never throws into the caller — the
   * privileged act already happened, and crashing the request would hide it further.
   */
  public append(input: AuditInput): AuditEntry | null {
    try {
      const head = this.db.prepare('SELECT seq, hash FROM audit_log ORDER BY seq DESC LIMIT 1').get() as
        | { seq: number; hash: string }
        | undefined;
      const seq = (head?.seq ?? 0) + 1;
      const prevHash = head?.hash ?? GENESIS;
      const at = new Date().toISOString();
      const detailJson = input.detail ? JSON.stringify(input.detail) : null;
      const base = {
        seq,
        at,
        actor: input.actor,
        role: input.role ?? null,
        ip: input.ip ?? null,
        action: input.action,
        target: input.target ?? null,
        outcome: input.outcome,
        prevHash
      };
      const hash = crypto.createHash('sha256').update(canonical({ ...base, detailJson })).digest('hex');
      this.db
        .prepare(
          `INSERT INTO audit_log (seq, at, actor, role, ip, action, target, outcome, detail, prev_hash, hash, mac)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
        )
        .run(seq, at, base.actor, base.role, base.ip, base.action, base.target, base.outcome, detailJson, prevHash, hash, this.mac(hash));
      return { ...base, detail: input.detail ?? null, hash };
    } catch (err: any) {
      console.error('[audit] APPEND FAILED — a privileged action went unrecorded:', input.action, err?.message);
      return null;
    }
  }

  public list(opts: { limit?: number; beforeSeq?: number; action?: string; actor?: string } = {}): AuditEntry[] {
    const limit = Math.max(1, Math.min(opts.limit ?? 100, 500));
    const where: string[] = [];
    const args: Array<string | number> = [];
    if (opts.beforeSeq) {
      where.push('seq < ?');
      args.push(opts.beforeSeq);
    }
    if (opts.action) {
      where.push('action = ?');
      args.push(opts.action);
    }
    if (opts.actor) {
      where.push('actor = ?');
      args.push(opts.actor);
    }
    const rows = this.db
      .prepare(
        `SELECT * FROM audit_log ${where.length ? 'WHERE ' + where.join(' AND ') : ''} ORDER BY seq DESC LIMIT ?`
      )
      .all(...args, limit) as any[];
    return rows.map(r => ({
      seq: Number(r.seq),
      at: String(r.at),
      actor: String(r.actor),
      role: r.role ?? null,
      ip: r.ip ?? null,
      action: String(r.action),
      target: r.target ?? null,
      outcome: r.outcome as AuditOutcome,
      detail: r.detail ? safeJson(r.detail) : null,
      prevHash: String(r.prev_hash),
      hash: String(r.hash)
    }));
  }

  /** Walk the whole chain from genesis. Cost is linear; it runs on demand, not per request. */
  public verify(): AuditVerification {
    const rows = this.db.prepare('SELECT * FROM audit_log ORDER BY seq ASC').all() as any[];
    let prev = GENESIS;
    let expectSeq = 1;
    for (const r of rows) {
      const seq = Number(r.seq);
      const fail = (reason: string): AuditVerification => ({
        ok: false,
        checked: seq - 1,
        brokenAt: seq,
        reason,
        headSeq: rows.length ? Number(rows[rows.length - 1].seq) : null,
        headHash: rows.length ? String(rows[rows.length - 1].hash) : null,
        keySource: this.keySource,
        durable: this.persistent
      });
      if (seq !== expectSeq) return fail(`sequence gap: expected ${expectSeq}, found ${seq}`);
      if (r.prev_hash !== prev) return fail('previous-hash link does not match the prior entry');
      const hash = crypto
        .createHash('sha256')
        .update(
          canonical({
            seq,
            at: r.at,
            actor: r.actor,
            role: r.role ?? null,
            ip: r.ip ?? null,
            action: r.action,
            target: r.target ?? null,
            outcome: r.outcome,
            detailJson: r.detail ?? null,
            prevHash: r.prev_hash
          })
        )
        .digest('hex');
      if (hash !== r.hash) return fail('content does not match its stored hash');
      const expectedMac = Buffer.from(this.mac(hash), 'hex');
      const storedMac = Buffer.from(String(r.mac), 'hex');
      // Length first: timingSafeEqual throws on unequal lengths, and a truncated MAC is
      // itself a tamper signal, not an exception.
      if (storedMac.length !== expectedMac.length || !crypto.timingSafeEqual(expectedMac, storedMac)) {
        return fail('HMAC does not verify under the current key');
      }
      prev = hash;
      expectSeq++;
    }
    const head = rows[rows.length - 1];
    return {
      ok: true,
      checked: rows.length,
      brokenAt: null,
      reason: null,
      headSeq: head ? Number(head.seq) : null,
      headHash: head ? String(head.hash) : null,
      keySource: this.keySource,
      durable: this.persistent
    };
  }

  public durable(): boolean {
    return this.persistent;
  }
}

function safeJson(s: string): Record<string, unknown> | null {
  try {
    return JSON.parse(s);
  } catch {
    return null;
  }
}

export const globalAuditTrail = new AuditTrailService();
