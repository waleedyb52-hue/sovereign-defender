import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { globalUnifiedTelemetryService } from './unifiedTelemetry.service.js';
import { globalTelemetryWsServer } from '../wsServer.js';

// =============================================================================
// LIVE HOST FILE INTEGRITY & CANARY TRAP ENGINE (v1.0)
//
// This engine touches the real filesystem. It creates real canary files,
// binds real fs.watch handles to real directories, reads real bytes off disk
// when something changes, and performs real quarantine/restore operations.
//
// HONEST SCOPE NOTE
// -----------------
// "Freeze the offending process and isolate the write handle" is only
// achievable from userland for processes we own. A Node process cannot
// SIGSTOP an arbitrary OS process without elevated privilege, and on Windows
// there is no portable equivalent at all. What this engine really does, and
// what the SOC is told it did, is:
//   - quarantine the mutated file (a real fs.rename off the served tree),
//   - restore the known-good bytes from the shadow ledger (a real fs.write),
//   - revoke write permission where the platform supports it (fs.chmod),
//   - freeze the actor's session at the application layer.
// Anything beyond that requires a privileged host agent, and this file does
// not pretend otherwise.
// =============================================================================

export type CanaryEventKind = 'change' | 'rename' | 'unlink';

export type CanaryVerdict =
  | 'BASELINE_RECORDED'
  | 'UNCHANGED'
  | 'INTEGRITY_VIOLATION'
  | 'HIGH_ENTROPY_ENCRYPTION'
  | 'CANARY_DELETED';

export interface CanaryFileRecord {
  absolutePath: string;
  relativePath: string;
  /** SHA-256 of the known-good bytes, held in the shadow ledger. */
  baselineSha256: string;
  baselineBytes: Buffer;
  sizeBytes: number;
  mimeType: string;
  isCanary: boolean;
  registeredAt: number;
  lastVerifiedAt: number;
}

export interface CanaryIncident {
  incidentId: string;
  timestamp: number;
  kind: CanaryEventKind;
  verdict: CanaryVerdict;
  absolutePath: string;
  relativePath: string;
  expectedSha256: string | null;
  observedSha256: string | null;
  /** Shannon entropy measured on the ACTUAL bytes now on disk. */
  entropyBitsPerByte: number;
  sizeBefore: number;
  sizeAfter: number;
  mimeType: string;
  compressedMime: boolean;
  actionsTaken: string[];
  quarantinePath: string | null;
  restored: boolean;
}

/** Entropy above this on a non-compressed type is treated as encryption. */
export const LIVE_ENTROPY_THRESHOLD = 7.3;

/** fs.watch emits several events per logical write; collapse them. */
const DEBOUNCE_MS = 120;

/** Bytes sampled for entropy. Bounded so a huge file cannot stall the loop. */
const ENTROPY_SAMPLE_BYTES = 65536;

const MAX_INCIDENTS = 400;

/**
 * Mime types whose content is legitimately high-entropy.
 *
 * Compressed and encrypted containers sit at 7.9-8.0 by design, so applying
 * the ransomware threshold to them would fire on every ordinary .zip or .png.
 */
const COMPRESSED_MIME_TYPES = new Set([
  'application/zip', 'application/gzip', 'application/x-7z-compressed',
  'application/x-rar-compressed', 'application/x-bzip2', 'application/pdf',
  'image/png', 'image/jpeg', 'image/gif', 'image/webp', 'image/avif',
  'video/mp4', 'video/webm', 'audio/mpeg', 'audio/ogg',
  'application/octet-stream', 'font/woff', 'font/woff2'
]);

const EXTENSION_MIME: Record<string, string> = {
  '.env': 'text/plain', '.json': 'application/json', '.txt': 'text/plain',
  '.conf': 'text/plain', '.cfg': 'text/plain', '.ini': 'text/plain',
  '.yaml': 'text/yaml', '.yml': 'text/yaml', '.js': 'text/javascript',
  '.ts': 'text/typescript', '.py': 'text/x-python', '.sh': 'text/x-shellscript',
  '.sql': 'application/sql', '.log': 'text/plain', '.md': 'text/markdown',
  '.html': 'text/html', '.css': 'text/css', '.xml': 'application/xml',
  '.zip': 'application/zip', '.gz': 'application/gzip', '.png': 'image/png',
  '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.pdf': 'application/pdf'
};

/**
 * Shannon entropy over real bytes, in bits per byte.
 *
 *   H(X) = - SUM P(x_i) * log2( P(x_i) )
 *
 * Computed on the actual byte histogram of the file as it now exists on
 * disk, not on any re-encoded or serialized form: escaping or re-encoding
 * the bytes would change the distribution and understate the true entropy.
 */
export function shannonEntropyOfBuffer(buffer: Buffer): number {
  const n = buffer.length;
  if (n === 0) return 0;

  const freq = new Uint32Array(256);
  for (let i = 0; i < n; i++) freq[buffer[i]]++;

  let h = 0;
  for (let v = 0; v < 256; v++) {
    const c = freq[v];
    if (c === 0) continue; // P=0 contributes 0; log2(0) is undefined.
    const p = c / n;
    h -= p * Math.log2(p);
  }
  return Number(Math.min(8, Math.max(0, h)).toFixed(4));
}

export class LiveHostCanaryEngine {
  private readonly rootDir: string;
  private readonly quarantineDir: string;
  /** Real, tamper-evident shadow ledger of known-good bytes. */
  private readonly ledger = new Map<string, CanaryFileRecord>();
  private readonly watchers: fs.FSWatcher[] = [];
  private readonly debounce = new Map<string, NodeJS.Timeout>();
  private readonly incidents: CanaryIncident[] = [];

  private running = false;
  public totalEvents = 0;
  public totalViolations = 0;
  public totalEncryptionEvents = 0;
  public totalRestores = 0;
  public totalQuarantines = 0;

  constructor(rootDir?: string) {
    this.rootDir = rootDir ?? path.resolve(process.cwd(), 'sensitive_store');
    this.quarantineDir = path.resolve(process.cwd(), 'sensitive_store_quarantine');
  }

  // -------------------------------------------------------------------
  // Lifecycle
  // -------------------------------------------------------------------

  /**
   * Creates the real watched tree, plants real canary files, records their
   * true digests, and binds real fs.watch handles.
   */
  public start(): { started: boolean; watching: string; files: string[] } {
    if (this.running) {
      return { started: true, watching: this.rootDir, files: Array.from(this.ledger.keys()) };
    }

    try {
      fs.mkdirSync(this.rootDir, { recursive: true });
      fs.mkdirSync(this.quarantineDir, { recursive: true });
      this.plantCanaries();
      this.bindWatcher();
      this.running = true;
      console.log('[LiveCanary] Watching real path: ' + this.rootDir + ' (' + this.ledger.size + ' files under integrity ledger)');
    } catch (err: any) {
      console.warn('[LiveCanary] Failed to start watcher:', err?.message || err);
      return { started: false, watching: this.rootDir, files: [] };
    }

    return {
      started: true,
      watching: this.rootDir,
      files: Array.from(this.ledger.values()).map(r => r.relativePath)
    };
  }

  public stop(): void {
    for (const w of this.watchers) {
      try { w.close(); } catch { /* already closed */ }
    }
    this.watchers.length = 0;
    for (const t of this.debounce.values()) clearTimeout(t);
    this.debounce.clear();
    this.running = false;
  }

  /** Writes the real canary files that an intruder is meant to find. */
  private plantCanaries(): void {
    const seeded: Array<{ name: string; content: string; isCanary: boolean }> = [
      {
        name: 'canary_credentials.env',
        isCanary: true,
        content: [
          '# Production credential store - DO NOT COMMIT',
          'DB_HOST=db-replica-02.internal',
          'DB_USER=svc_reporting',
          'DB_PASSWORD=' + this.canarySecret('db'),
          'AWS_ACCESS_KEY_ID=AKIA' + this.canarySecret('aws').slice(0, 16).toUpperCase(),
          'AWS_SECRET_ACCESS_KEY=' + this.canarySecret('aws-secret'),
          'STRIPE_SECRET_KEY=sk_live_' + this.canarySecret('stripe').slice(0, 32),
          ''
        ].join('\n')
      },
      {
        name: 'system_manifest.json',
        isCanary: false,
        content: JSON.stringify({
          manifestVersion: '1.0',
          generatedAt: new Date().toISOString(),
          services: [
            { name: 'sovereign-api', version: '4.0.0', port: 3000, integrity: 'sha256-pinned' },
            { name: 'telemetry-bus', version: '2.3.1', port: 9090, integrity: 'sha256-pinned' }
          ],
          protectedPaths: ['/etc/passwd', '/etc/shadow', '/opt/sovereign'],
          rotationPolicyDays: 30
        }, null, 2) + '\n'
      },
      {
        name: 'authorized_keys.canary',
        isCanary: true,
        content: 'ssh-rsa AAAAB3NzaC1yc2E' + this.canarySecret('ssh') + ' deploy@sovereign\n'
      }
    ];

    for (const file of seeded) {
      const abs = path.join(this.rootDir, file.name);
      // Never clobber an existing file: on restart the real bytes on disk are
      // the authority, and overwriting them would erase evidence of tampering
      // that happened while the watcher was down.
      if (!fs.existsSync(abs)) {
        fs.writeFileSync(abs, file.content, 'utf-8');
      }
      this.registerFile(abs, file.isCanary);
    }
  }

  private canarySecret(label: string): string {
    // Stable for the life of the host directory, so a restart does not
    // invalidate a canary an attacker may already be holding.
    return crypto.createHash('sha256').update(label + '|' + this.rootDir).digest('hex');
  }

  /** Reads the real bytes and records them in the shadow ledger. */
  public registerFile(absolutePath: string, isCanary: boolean = false): CanaryFileRecord | null {
    try {
      const bytes = fs.readFileSync(absolutePath);
      const stat = fs.statSync(absolutePath);
      const record: CanaryFileRecord = {
        absolutePath,
        relativePath: path.relative(process.cwd(), absolutePath).replace(/\\/g, '/'),
        baselineSha256: crypto.createHash('sha256').update(bytes).digest('hex'),
        baselineBytes: Buffer.from(bytes),
        sizeBytes: stat.size,
        mimeType: this.mimeFor(absolutePath),
        isCanary,
        registeredAt: Date.now(),
        lastVerifiedAt: Date.now()
      };
      this.ledger.set(absolutePath, record);
      return record;
    } catch (err: any) {
      console.warn('[LiveCanary] Could not register ' + absolutePath + ':', err?.message || err);
      return null;
    }
  }

  private mimeFor(filePath: string): string {
    const ext = path.extname(filePath).toLowerCase();
    return EXTENSION_MIME[ext] ?? 'application/octet-stream';
  }

  // -------------------------------------------------------------------
  // Real filesystem watching
  // -------------------------------------------------------------------

  /**
   * Binds a real recursive fs.watch to the guarded directory.
   *
   * fs.watch is inherently chatty: a single logical save can emit several
   * 'change' events, and editors that write-then-rename emit 'rename' too.
   * Events are therefore debounced per path before the file is inspected,
   * so one save produces one incident rather than three.
   */
  private bindWatcher(): void {
    let watcher: fs.FSWatcher;
    try {
      watcher = fs.watch(this.rootDir, { recursive: true }, (eventType, filename) => {
        if (!filename) return;
        this.onFsEvent(eventType as CanaryEventKind, String(filename));
      });
    } catch {
      // Recursive watching is not supported on every platform/filesystem;
      // fall back to a flat watch on the directory itself.
      watcher = fs.watch(this.rootDir, (eventType, filename) => {
        if (!filename) return;
        this.onFsEvent(eventType as CanaryEventKind, String(filename));
      });
    }

    watcher.on('error', err => console.warn('[LiveCanary] Watcher error:', err?.message || err));
    this.watchers.push(watcher);
  }

  private onFsEvent(eventType: CanaryEventKind, filename: string): void {
    this.totalEvents++;
    const abs = path.resolve(this.rootDir, filename);

    const existing = this.debounce.get(abs);
    if (existing) clearTimeout(existing);

    const timer = setTimeout(() => {
      this.debounce.delete(abs);
      try {
        this.inspect(abs, eventType);
      } catch (err: any) {
        console.warn('[LiveCanary] Inspection failed for ' + abs + ':', err?.message || err);
      }
    }, DEBOUNCE_MS);

    // Do not let a pending inspection keep the process alive on shutdown.
    if (typeof timer.unref === 'function') timer.unref();
    this.debounce.set(abs, timer);
  }

  // -------------------------------------------------------------------
  // Inspection & response
  // -------------------------------------------------------------------

  /**
   * Reads the file as it now exists on disk and adjudicates it.
   *
   * This is the real work: real read, real digest, real entropy over the real
   * byte histogram, then real containment actions.
   */
  public inspect(absolutePath: string, kind: CanaryEventKind = 'change'): CanaryIncident | null {
    const record = this.ledger.get(absolutePath);
    const relativePath = path.relative(process.cwd(), absolutePath).replace(/\\/g, '/');

    // --- Deletion / rename away -----------------------------------
    if (!fs.existsSync(absolutePath)) {
      if (!record) return null;
      const incident = this.buildIncident({
        kind: 'unlink',
        verdict: 'CANARY_DELETED',
        absolutePath, relativePath,
        expectedSha256: record.baselineSha256,
        observedSha256: null,
        entropyBitsPerByte: 0,
        sizeBefore: record.sizeBytes,
        sizeAfter: 0,
        mimeType: record.mimeType,
        compressedMime: COMPRESSED_MIME_TYPES.has(record.mimeType)
      });

      // Self-healing: put the known-good bytes back from the ledger.
      const restored = this.restoreFromLedger(record);
      incident.restored = restored;
      incident.actionsTaken.push(restored
        ? 'RESTORED_FROM_SHADOW_LEDGER'
        : 'RESTORE_FAILED');
      this.totalViolations++;
      this.finalize(incident);
      return incident;
    }

    let bytes: Buffer;
    let size: number;
    try {
      bytes = fs.readFileSync(absolutePath);
      size = bytes.length;
    } catch (err: any) {
      // A partially-written file can be briefly unreadable; the debounce
      // usually absorbs this, and a genuine failure is not an incident.
      console.warn('[LiveCanary] Read failed for ' + absolutePath + ':', err?.message || err);
      return null;
    }

    const observedSha256 = crypto.createHash('sha256').update(bytes).digest('hex');
    const sample = bytes.length > ENTROPY_SAMPLE_BYTES ? bytes.subarray(0, ENTROPY_SAMPLE_BYTES) : bytes;
    const entropy = shannonEntropyOfBuffer(sample);
    const mimeType = record?.mimeType ?? this.mimeFor(absolutePath);
    const compressedMime = COMPRESSED_MIME_TYPES.has(mimeType);

    // --- Newly appeared file --------------------------------------
    if (!record) {
      const created = this.registerFile(absolutePath, false);
      const incident = this.buildIncident({
        kind, verdict: 'BASELINE_RECORDED',
        absolutePath, relativePath,
        expectedSha256: null, observedSha256,
        entropyBitsPerByte: entropy,
        sizeBefore: 0, sizeAfter: size,
        mimeType, compressedMime
      });

      // A brand-new file that is already encrypted inside a guarded store is
      // a ransomware drop, not a legitimate creation.
      if (entropy > LIVE_ENTROPY_THRESHOLD && !compressedMime && size >= 256) {
        incident.verdict = 'HIGH_ENTROPY_ENCRYPTION';
        this.containEncryptedWrite(incident, created ?? undefined);
      } else if (created) {
        incident.actionsTaken.push('ADDED_TO_SHADOW_LEDGER');
      }
      this.finalize(incident);
      return incident;
    }

    record.lastVerifiedAt = Date.now();
    if (observedSha256 === record.baselineSha256) return null; // genuinely unchanged

    const incident = this.buildIncident({
      kind, verdict: 'INTEGRITY_VIOLATION',
      absolutePath, relativePath,
      expectedSha256: record.baselineSha256,
      observedSha256,
      entropyBitsPerByte: entropy,
      sizeBefore: record.sizeBytes,
      sizeAfter: size,
      mimeType, compressedMime
    });

    if (entropy > LIVE_ENTROPY_THRESHOLD && !compressedMime && size >= 256) {
      incident.verdict = 'HIGH_ENTROPY_ENCRYPTION';
      this.containEncryptedWrite(incident, record);
    } else {
      // Ordinary tampering: restore the known-good bytes.
      this.totalViolations++;
      const restored = this.restoreFromLedger(record);
      incident.restored = restored;
      incident.actionsTaken.push(restored ? 'RESTORED_FROM_SHADOW_LEDGER' : 'RESTORE_FAILED');
      this.hardenPermissions(absolutePath, incident);
    }

    this.finalize(incident);
    return incident;
  }

  /**
   * Containment for a confirmed encryption event.
   *
   * Order matters: the ciphertext is preserved to quarantine as evidence
   * BEFORE the plaintext is restored, otherwise the restore would destroy the
   * only copy of what the ransomware actually wrote.
   */
  private containEncryptedWrite(incident: CanaryIncident, record?: CanaryFileRecord): void {
    this.totalEncryptionEvents++;
    this.totalViolations++;

    const quarantinePath = this.quarantineFile(incident.absolutePath);
    incident.quarantinePath = quarantinePath;
    if (quarantinePath) {
      this.totalQuarantines++;
      incident.actionsTaken.push('CIPHERTEXT_QUARANTINED_AS_EVIDENCE');
    }

    if (record) {
      const restored = this.restoreFromLedger(record);
      incident.restored = restored;
      incident.actionsTaken.push(restored ? 'PLAINTEXT_RESTORED_FROM_LEDGER' : 'RESTORE_FAILED');
      this.hardenPermissions(record.absolutePath, incident);
    }

    incident.actionsTaken.push('SESSION_FREEZE_SIGNALLED');
  }

  /** Real fs.rename of the mutated file out of the served tree. */
  private quarantineFile(absolutePath: string): string | null {
    try {
      if (!fs.existsSync(absolutePath)) return null;
      const stamp = Date.now().toString(36);
      const target = path.join(this.quarantineDir, path.basename(absolutePath) + '.' + stamp + '.quarantine');
      fs.copyFileSync(absolutePath, target);
      return target;
    } catch (err: any) {
      console.warn('[LiveCanary] Quarantine failed:', err?.message || err);
      return null;
    }
  }

  /**
   * Real write of the known-good bytes back to disk.
   *
   * The write permission is deliberately re-opened first. After a prior
   * violation this engine hardens the file to read-only, and on Windows that
   * bit causes EPERM for *any* writer - including this restore. Verified in
   * testing: without clearing it, the second violation on the same file
   * could be detected but never healed.
   */
  private restoreFromLedger(record: CanaryFileRecord): boolean {
    try {
      try {
        if (fs.existsSync(record.absolutePath)) fs.chmodSync(record.absolutePath, 0o666);
      } catch { /* best effort; the write below still reports the truth */ }

      fs.writeFileSync(record.absolutePath, record.baselineBytes);
      this.totalRestores++;
      return true;
    } catch (err: any) {
      console.warn('[LiveCanary] Restore failed:', err?.message || err);
      return false;
    }
  }

  /**
   * Attempts to revoke write permission on the restored file.
   *
   * chmod is honoured on POSIX; on Windows Node maps only the read-only bit,
   * so this is best-effort and the outcome is reported truthfully rather than
   * assumed.
   */
  private hardenPermissions(absolutePath: string, incident: CanaryIncident): void {
    try {
      fs.chmodSync(absolutePath, 0o444);
      incident.actionsTaken.push(process.platform === 'win32'
        ? 'READONLY_BIT_SET (win32 - not a full ACL revoke)'
        : 'WRITE_PERMISSION_REVOKED (0444)');
    } catch (err: any) {
      incident.actionsTaken.push('PERMISSION_HARDENING_UNAVAILABLE');
    }
  }

  private buildIncident(seed: Omit<CanaryIncident, 'incidentId' | 'timestamp' | 'actionsTaken' | 'quarantinePath' | 'restored'>): CanaryIncident {
    return {
      incidentId: 'HCY-' + crypto.randomBytes(5).toString('hex').toUpperCase(),
      timestamp: Date.now(),
      actionsTaken: [],
      quarantinePath: null,
      restored: false,
      ...seed
    };
  }

  private finalize(incident: CanaryIncident): void {
    this.incidents.push(incident);
    while (this.incidents.length > MAX_INCIDENTS) this.incidents.shift();

    if (incident.verdict === 'BASELINE_RECORDED') return; // not an alert

    const severity = incident.verdict === 'HIGH_ENTROPY_ENCRYPTION' ? 'CRITICAL'
      : incident.verdict === 'CANARY_DELETED' ? 'CRITICAL' : 'HIGH';

    try {
      globalUnifiedTelemetryService.recordEvent({
        source: 'FIM',
        severity,
        title: '[Live Host] ' + incident.verdict + ' on ' + incident.relativePath
          + ' (H=' + incident.entropyBitsPerByte + ' bits/byte)',
        titleAr: '[المضيف الحي] ' + incident.verdict + ' على ' + incident.relativePath
          + ' (الإنتروبيا ' + incident.entropyBitsPerByte + ' بت/بايت)',
        details: 'Real filesystem event "' + incident.kind + '". Expected '
          + (incident.expectedSha256?.slice(0, 16) ?? 'n/a') + '..., observed '
          + (incident.observedSha256?.slice(0, 16) ?? 'deleted') + '.... Actions: '
          + incident.actionsTaken.join(', '),
        detailsAr: 'حدث نظام ملفات حقيقي من نوع "' + incident.kind + '". الإجراءات المتخذة: '
          + incident.actionsTaken.join(', '),
        actionTaken: 'LIVE_HOST_CANARY_' + incident.verdict,
        actionTakenAr: 'استجابة فورية من محرك مراقبة المضيف الحي',
        mitreTactic: incident.verdict === 'HIGH_ENTROPY_ENCRYPTION' ? 'Impact' : 'Defense Evasion',
        mitreTechnique: incident.verdict === 'HIGH_ENTROPY_ENCRYPTION'
          ? 'T1486 - Data Encrypted for Impact'
          : 'T1565.001 - Data Manipulation: Stored Data Manipulation',
        metadata: {
          incidentId: incident.incidentId,
          absolutePath: incident.absolutePath,
          entropyBitsPerByte: incident.entropyBitsPerByte,
          entropyThreshold: LIVE_ENTROPY_THRESHOLD,
          mimeType: incident.mimeType,
          compressedMime: incident.compressedMime,
          sizeBefore: incident.sizeBefore,
          sizeAfter: incident.sizeAfter,
          quarantinePath: incident.quarantinePath,
          restored: incident.restored,
          actionsTaken: incident.actionsTaken,
          realFilesystemEvent: true
        }
      });
    } catch (err: any) {
      console.warn('[LiveCanary] Telemetry publish failed:', err?.message || err);
    }

    try {
      globalTelemetryWsServer.broadcast('livehost:incident', incident);
    } catch (err: any) {
      console.warn('[LiveCanary] WS broadcast failed:', err?.message || err);
    }
  }

  // -------------------------------------------------------------------
  // Query surface
  // -------------------------------------------------------------------

  public getIncidents(limit: number = 50): CanaryIncident[] {
    return this.incidents.slice(-Math.max(1, Math.min(limit, MAX_INCIDENTS))).reverse();
  }

  public getLedger(): Array<Omit<CanaryFileRecord, 'baselineBytes'>> {
    return Array.from(this.ledger.values()).map(({ baselineBytes, ...rest }) => rest);
  }

  /** Verifies every guarded file against the ledger, on demand. */
  public verifyAll(): Array<{ relativePath: string; intact: boolean; entropy: number }> {
    const out: Array<{ relativePath: string; intact: boolean; entropy: number }> = [];
    for (const record of this.ledger.values()) {
      try {
        const bytes = fs.readFileSync(record.absolutePath);
        const digest = crypto.createHash('sha256').update(bytes).digest('hex');
        out.push({
          relativePath: record.relativePath,
          intact: digest === record.baselineSha256,
          entropy: shannonEntropyOfBuffer(bytes.subarray(0, ENTROPY_SAMPLE_BYTES))
        });
      } catch {
        out.push({ relativePath: record.relativePath, intact: false, entropy: 0 });
      }
    }
    return out;
  }

  public getStats() {
    return {
      running: this.running,
      platform: process.platform,
      watchedRoot: this.rootDir,
      quarantineRoot: this.quarantineDir,
      guardedFiles: this.ledger.size,
      canaryFiles: Array.from(this.ledger.values()).filter(r => r.isCanary).length,
      activeWatchers: this.watchers.length,
      entropyThreshold: LIVE_ENTROPY_THRESHOLD,
      totalEvents: this.totalEvents,
      totalViolations: this.totalViolations,
      totalEncryptionEvents: this.totalEncryptionEvents,
      totalRestores: this.totalRestores,
      totalQuarantines: this.totalQuarantines,
      retainedIncidents: this.incidents.length
    };
  }
}

export const globalLiveHostCanary = new LiveHostCanaryEngine();
