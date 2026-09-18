import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { globalUnifiedTelemetryService } from './unifiedTelemetry.service.js';
import { globalTelemetryWsServer } from '../wsServer.js';

// =============================================================================
// CRYPTOGRAPHIC SELF-HEALING LEDGER (v1.0)
//
// An append-only, hash-chained ledger of authentic configuration state, held
// in memory and used to restore files atomically the moment they are mutated
// without authorisation - with no server restart and no operator action.
//
// WHY A CHAIN AND NOT A MAP OF HASHES
// -----------------------------------
// A per-file digest detects edits only. Chaining each entry to the previous
// one also detects deletion and reordering of the ledger itself, so an
// attacker who reaches process memory cannot quietly remove the record of the
// file they are about to change without breaking verification.
//
// WHY RESTORE IS ATOMIC
// ---------------------
// Restoration writes to a temporary file in the same directory and then
// renames it over the target. rename(2) is atomic within a filesystem, so a
// reader can never observe a half-written config; a plain write could be
// interrupted and leave the service with a truncated file, converting a
// tampering incident into an outage.
// =============================================================================

export type LedgerEntryKind = 'GENESIS' | 'BASELINE' | 'AUTHORISED_UPDATE' | 'HEAL' | 'LOCKDOWN';

export interface LedgerEntry {
  sequence: number;
  entryId: string;
  timestamp: number;
  kind: LedgerEntryKind;
  /** Logical key, usually an absolute path. */
  subject: string;
  /** SHA-256 of the authentic content at this point in the chain. */
  contentSha256: string;
  contentLength: number;
  /** Hash of the previous entry: what makes the ledger tamper-evident. */
  previousEntryHash: string;
  /** SHA-256 over this entry's canonical body plus previousEntryHash. */
  entryHash: string;
  actor: string;
  note: string;
}

export interface ProtectedArtifact {
  subject: string;
  absolutePath: string | null;
  /** Authentic bytes, held immutably in memory. */
  authenticBytes: Buffer;
  contentSha256: string;
  registeredAt: number;
  lastVerifiedAt: number;
  healCount: number;
  locked: boolean;
}

export interface HealResult {
  artifactId: string;
  timestamp: number;
  subject: string;
  detected: boolean;
  expectedSha256: string;
  observedSha256: string | null;
  healed: boolean;
  healMethod: 'ATOMIC_RENAME' | 'DIRECT_WRITE' | 'MEMORY_ONLY' | 'NONE';
  writeLocked: boolean;
  durationMs: number;
  ledgerSequence: number;
  actionsTaken: string[];
}

const MAX_LEDGER_ENTRIES = 5000;

export class SelfHealingLedger {
  private readonly artifacts = new Map<string, ProtectedArtifact>();
  private readonly ledger: LedgerEntry[] = [];
  private headHash = 'GENESIS';
  private sequence = 0;

  public totalHeals = 0;
  public totalDetections = 0;
  public totalLockdowns = 0;

  constructor() {
    this.append('GENESIS', '__ledger__', crypto.createHash('sha256').update('genesis').digest('hex'), 0, 'system', 'Ledger initialised');
  }

  // -------------------------------------------------------------------
  // Chain primitives
  // -------------------------------------------------------------------

  private append(
    kind: LedgerEntryKind, subject: string, contentSha256: string,
    contentLength: number, actor: string, note: string
  ): LedgerEntry {
    const previousEntryHash = this.headHash;
    const sequence = this.sequence++;
    const body = JSON.stringify({ sequence, kind, subject, contentSha256, contentLength, actor, note });
    const entryHash = crypto.createHash('sha256').update(previousEntryHash + ':' + body).digest('hex');

    const entry: LedgerEntry = {
      sequence,
      entryId: 'LDG-' + sequence.toString(36).toUpperCase() + '-' + entryHash.slice(0, 6).toUpperCase(),
      timestamp: Date.now(),
      kind, subject, contentSha256, contentLength,
      previousEntryHash, entryHash, actor, note
    };

    this.headHash = entryHash;
    this.ledger.push(entry);
    // The chain is append-only, but memory is finite. Trimming from the front
    // means verification starts from the oldest retained entry rather than
    // genesis, which verifyChain() accounts for explicitly.
    while (this.ledger.length > MAX_LEDGER_ENTRIES) this.ledger.shift();
    return entry;
  }

  /**
   * Re-walks the retained chain.
   *
   * Two checks per entry: that the entry still hashes to its stored digest,
   * and that its previousEntryHash equals the prior entry's digest. The second
   * is what detects deletion and reordering - without it, every surviving
   * entry would remain internally self-consistent after a removal.
   */
  public verifyChain(): { valid: boolean; brokenAt: string | null; verified: number; startedFromGenesis: boolean } {
    let expectedPrevious: string | null = null;
    let verified = 0;

    for (const e of this.ledger) {
      const body = JSON.stringify({
        sequence: e.sequence, kind: e.kind, subject: e.subject,
        contentSha256: e.contentSha256, contentLength: e.contentLength,
        actor: e.actor, note: e.note
      });
      const recomputed = crypto.createHash('sha256').update(e.previousEntryHash + ':' + body).digest('hex');
      if (recomputed !== e.entryHash) {
        return { valid: false, brokenAt: e.entryId, verified, startedFromGenesis: this.ledger[0]?.kind === 'GENESIS' };
      }
      if (expectedPrevious !== null && e.previousEntryHash !== expectedPrevious) {
        return { valid: false, brokenAt: e.entryId, verified, startedFromGenesis: this.ledger[0]?.kind === 'GENESIS' };
      }
      expectedPrevious = e.entryHash;
      verified++;
    }
    return { valid: true, brokenAt: null, verified, startedFromGenesis: this.ledger[0]?.kind === 'GENESIS' };
  }

  // -------------------------------------------------------------------
  // Registration
  // -------------------------------------------------------------------

  /** Records a file's authentic state from disk. */
  public protectFile(absolutePath: string, actor = 'system'): ProtectedArtifact | null {
    try {
      const bytes = fs.readFileSync(absolutePath);
      return this.protect(absolutePath, bytes, absolutePath, actor);
    } catch (err: any) {
      console.warn('[SelfHealing] Cannot protect ' + absolutePath + ':', err?.message || err);
      return null;
    }
  }

  /** Records any in-memory artifact (a honeypot manifest, a policy blob). */
  public protect(subject: string, content: Buffer | string, absolutePath: string | null = null, actor = 'system'): ProtectedArtifact {
    const bytes = Buffer.isBuffer(content) ? Buffer.from(content) : Buffer.from(content, 'utf-8');
    const contentSha256 = crypto.createHash('sha256').update(bytes).digest('hex');

    const artifact: ProtectedArtifact = {
      subject,
      absolutePath,
      authenticBytes: bytes,
      contentSha256,
      registeredAt: Date.now(),
      lastVerifiedAt: Date.now(),
      healCount: 0,
      locked: false
    };
    this.artifacts.set(subject, artifact);
    this.append('BASELINE', subject, contentSha256, bytes.length, actor, 'Authentic baseline recorded');
    return artifact;
  }

  /**
   * Records an operator-authorised change.
   *
   * Without this the engine would fight legitimate deployments, reverting
   * every intentional config change and turning a defensive control into an
   * outage generator. Authorised updates move the baseline forward and are
   * themselves entered into the chain, so the audit trail distinguishes an
   * approved change from a reverted attack.
   */
  public authoriseUpdate(subject: string, content: Buffer | string, actor: string, note = 'Authorised update'): ProtectedArtifact | null {
    const artifact = this.artifacts.get(subject);
    if (!artifact) return null;

    const bytes = Buffer.isBuffer(content) ? Buffer.from(content) : Buffer.from(content, 'utf-8');
    artifact.authenticBytes = bytes;
    artifact.contentSha256 = crypto.createHash('sha256').update(bytes).digest('hex');
    artifact.lastVerifiedAt = Date.now();
    artifact.locked = false;

    this.append('AUTHORISED_UPDATE', subject, artifact.contentSha256, bytes.length, actor, note);
    return artifact;
  }

  // -------------------------------------------------------------------
  // Detection and healing
  // -------------------------------------------------------------------

  /**
   * Verifies one artifact and heals it if it diverged.
   *
   * Called by the FIM watcher on a real filesystem event, or on demand.
   */
  public verifyAndHeal(subject: string, actor = 'unknown'): HealResult {
    const started = Date.now();
    const artifact = this.artifacts.get(subject);

    if (!artifact) {
      return {
        artifactId: 'SH-NONE', timestamp: Date.now(), subject,
        detected: false, expectedSha256: '', observedSha256: null,
        healed: false, healMethod: 'NONE', writeLocked: false,
        durationMs: Date.now() - started, ledgerSequence: this.sequence,
        actionsTaken: ['artifact is not under protection']
      };
    }

    const actions: string[] = [];
    let observedSha256: string | null = null;
    let detected = false;

    // In-memory artifacts cannot drift; only file-backed ones can.
    if (!artifact.absolutePath) {
      return {
        artifactId: 'SH-MEM', timestamp: Date.now(), subject,
        detected: false, expectedSha256: artifact.contentSha256, observedSha256: artifact.contentSha256,
        healed: false, healMethod: 'MEMORY_ONLY', writeLocked: false,
        durationMs: Date.now() - started, ledgerSequence: this.sequence,
        actionsTaken: ['in-memory artifact; nothing on disk to drift']
      };
    }

    let exists = false;
    try { exists = fs.existsSync(artifact.absolutePath); } catch { exists = false; }

    if (exists) {
      try {
        const current = fs.readFileSync(artifact.absolutePath);
        observedSha256 = crypto.createHash('sha256').update(current).digest('hex');
        detected = observedSha256 !== artifact.contentSha256;
      } catch (err: any) {
        actions.push('read failed: ' + String(err?.message || err).slice(0, 80));
        detected = true;
      }
    } else {
      detected = true;
      actions.push('file absent from disk');
    }

    if (!detected) {
      artifact.lastVerifiedAt = Date.now();
      return {
        artifactId: 'SH-OK', timestamp: Date.now(), subject,
        detected: false, expectedSha256: artifact.contentSha256, observedSha256,
        healed: false, healMethod: 'NONE', writeLocked: artifact.locked,
        durationMs: Date.now() - started, ledgerSequence: this.sequence,
        actionsTaken: ['verified intact']
      };
    }

    // --- Heal -------------------------------------------------------
    this.totalDetections++;
    const heal = this.atomicRestore(artifact, actions);
    const locked = this.lockDown(artifact, actions);

    if (heal.healed) {
      this.totalHeals++;
      artifact.healCount++;
      artifact.lastVerifiedAt = Date.now();
    }

    const entry = this.append(
      'HEAL', subject, artifact.contentSha256, artifact.authenticBytes.length, actor,
      'Unauthorised mutation detected (observed ' + (observedSha256?.slice(0, 16) ?? 'absent')
      + '); ' + (heal.healed ? 'state restored atomically' : 'restore FAILED')
    );

    const result: HealResult = {
      artifactId: entry.entryId,
      timestamp: Date.now(),
      subject,
      detected: true,
      expectedSha256: artifact.contentSha256,
      observedSha256,
      healed: heal.healed,
      healMethod: heal.method,
      writeLocked: locked,
      durationMs: Date.now() - started,
      ledgerSequence: entry.sequence,
      actionsTaken: actions
    };

    this.emit(result);
    return result;
  }

  /**
   * Atomic restore: write a sibling temp file, fsync it, then rename over.
   *
   * The temp file must live in the same directory so the rename stays within
   * one filesystem - a cross-device rename is not atomic and silently
   * degrades to copy+unlink.
   */
  private atomicRestore(artifact: ProtectedArtifact, actions: string[]): { healed: boolean; method: HealResult['healMethod'] } {
    const target = artifact.absolutePath!;
    const dir = path.dirname(target);
    const tmp = path.join(dir, '.' + path.basename(target) + '.heal-' + crypto.randomBytes(4).toString('hex') + '.tmp');

    try {
      // Clear a read-only bit left by a previous lockdown, or the restore
      // itself would be denied by the OS.
      try { if (fs.existsSync(target)) fs.chmodSync(target, 0o666); } catch { /* best effort */ }

      const fd = fs.openSync(tmp, 'w');
      try {
        fs.writeSync(fd, artifact.authenticBytes);
        // Force the bytes to stable storage before the rename, so a crash
        // between the two cannot leave an empty file in place of the config.
        fs.fsyncSync(fd);
      } finally {
        fs.closeSync(fd);
      }

      fs.renameSync(tmp, target);
      actions.push('ATOMIC_RESTORE_VIA_RENAME');
      return { healed: true, method: 'ATOMIC_RENAME' };
    } catch (err: any) {
      actions.push('atomic restore failed: ' + String(err?.message || err).slice(0, 80));
      try { if (fs.existsSync(tmp)) fs.unlinkSync(tmp); } catch { /* leave no debris */ }

      // Fall back to a direct write: less safe, but a restored file beats a
      // tampered one.
      try {
        fs.writeFileSync(target, artifact.authenticBytes);
        actions.push('DIRECT_WRITE_FALLBACK');
        return { healed: true, method: 'DIRECT_WRITE' };
      } catch (err2: any) {
        actions.push('direct write also failed: ' + String(err2?.message || err2).slice(0, 80));
        return { healed: false, method: 'NONE' };
      }
    }
  }

  /** Revokes write permission on the restored artifact, as far as the OS allows. */
  private lockDown(artifact: ProtectedArtifact, actions: string[]): boolean {
    if (!artifact.absolutePath) return false;
    try {
      fs.chmodSync(artifact.absolutePath, 0o444);
      artifact.locked = true;
      this.totalLockdowns++;
      actions.push(process.platform === 'win32'
        ? 'WRITE_LOCK_APPLIED (win32 read-only attribute; not a full ACL revoke)'
        : 'WRITE_LOCK_APPLIED (0444)');
      return true;
    } catch (err: any) {
      actions.push('write lock unavailable: ' + String(err?.message || err).slice(0, 60));
      return false;
    }
  }

  /** Verifies every protected artifact in one pass. */
  public verifyAll(actor = 'sweep'): HealResult[] {
    return Array.from(this.artifacts.keys()).map(s => this.verifyAndHeal(s, actor));
  }

  // -------------------------------------------------------------------
  // Telemetry
  // -------------------------------------------------------------------

  private emit(result: HealResult): void {
    try {
      globalUnifiedTelemetryService.recordEvent({
        source: 'FIM',
        severity: 'CRITICAL',
        title: '[Self-Healing] SELF_HEALING_TRIGGERED on ' + path.basename(result.subject)
          + ' - ' + (result.healed ? 'restored in ' + result.durationMs + 'ms' : 'RESTORE FAILED'),
        titleAr: '[المعالجة الذاتية] تفعيل الاستعادة على ' + path.basename(result.subject)
          + ' - ' + (result.healed ? 'استُعيد خلال ' + result.durationMs + ' مللي ثانية' : 'فشلت الاستعادة'),
        details: 'Expected ' + result.expectedSha256.slice(0, 16) + '..., observed '
          + (result.observedSha256?.slice(0, 16) ?? 'absent') + '.... Method: ' + result.healMethod
          + '. Ledger sequence ' + result.ledgerSequence + '. Actions: ' + result.actionsTaken.join(', '),
        detailsAr: 'البصمة المتوقعة ' + result.expectedSha256.slice(0, 16) + ' مقابل المرصودة '
          + (result.observedSha256?.slice(0, 16) ?? 'محذوف') + '. الإجراءات: ' + result.actionsTaken.join(', '),
        mitreTactic: 'Defense Evasion',
        mitreTechnique: 'T1565.001 - Data Manipulation: Stored Data Manipulation',
        actionTaken: 'SELF_HEALING_TRIGGERED',
        actionTakenAr: 'تم تفعيل المعالجة الذاتية',
        metadata: {
          artifactId: result.artifactId,
          subject: result.subject,
          healed: result.healed,
          healMethod: result.healMethod,
          writeLocked: result.writeLocked,
          durationMs: result.durationMs,
          ledgerSequence: result.ledgerSequence,
          actionsTaken: result.actionsTaken,
          chainValid: this.verifyChain().valid
        }
      });
    } catch (err: any) {
      console.warn('[SelfHealing] Telemetry failed:', err?.message || err);
    }

    try {
      globalTelemetryWsServer.broadcast('selfhealing:triggered', result);
    } catch { /* transport optional */ }
  }

  // -------------------------------------------------------------------
  // Query surface
  // -------------------------------------------------------------------

  public getLedger(limit = 100): LedgerEntry[] {
    return this.ledger.slice(-limit).reverse();
  }

  public getArtifacts(): Array<Omit<ProtectedArtifact, 'authenticBytes'> & { sizeBytes: number }> {
    return Array.from(this.artifacts.values()).map(({ authenticBytes, ...rest }) => ({
      ...rest, sizeBytes: authenticBytes.length
    }));
  }

  public getStats() {
    const chain = this.verifyChain();
    return {
      protectedArtifacts: this.artifacts.size,
      ledgerEntries: this.ledger.length,
      headHash: this.headHash,
      chainValid: chain.valid,
      chainVerified: chain.verified,
      totalDetections: this.totalDetections,
      totalHeals: this.totalHeals,
      totalLockdowns: this.totalLockdowns,
      lockedArtifacts: Array.from(this.artifacts.values()).filter(a => a.locked).length
    };
  }

  public unlock(subject: string): boolean {
    const a = this.artifacts.get(subject);
    if (!a?.absolutePath) return false;
    try {
      fs.chmodSync(a.absolutePath, 0o666);
      a.locked = false;
      return true;
    } catch { return false; }
  }
}

export const globalSelfHealingLedger = new SelfHealingLedger();
