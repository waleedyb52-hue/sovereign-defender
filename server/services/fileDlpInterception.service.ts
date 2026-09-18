import crypto from 'crypto';
import path from 'path';
import { globalUnifiedTelemetryService } from './unifiedTelemetry.service.js';
import { globalTelemetryWsServer } from '../wsServer.js';
import { globalEbpfEngine } from '../ebpfEngine.js';
import {
  shannonEntropy,
  analyzeMagicBytes,
  sha256 as sha256Hex,
  canonicalize as canonicalSerialize,
  HIGH_ENTROPY_THRESHOLD
} from './payloadForensics.js';
import type {
  FileOperationVector,
  FileOperationType,
  InterceptionAction,
  InterceptionDecision
} from '../types/interception.types.js';

/** Decoy content served in place of a quarantined exfiltration target. */
export interface HoneyfilePayload {
  servedPath: string;
  watermark: string;
  contentType: string;
  sizeBytes: number;
  body: string;
  bandwidthBytesPerSec: number;
}

// =============================================================================
// ACTIVE FILE DLP & TAMPER PROTECTION (v1.0)
// Policy-based interception of file operations across four threat vectors.
// Rules are indexed into hash maps so evaluation is O(1) on the operation
// path, extension and MIME type rather than a linear scan of the ruleset.
//
// Pipeline: evaluate() -> [violation] -> block + lockdown token
//           -> chained audit record -> publish + broadcast
// =============================================================================

export type FileOperation = 'FILE_DOWNLOAD' | 'FILE_UPLOAD' | 'FILE_MODIFICATION' | 'FILE_DELETION';

export type DlpAction = 'ALLOW' | 'BLOCK' | 'QUARANTINE';

export type DlpViolationClass =
  | 'EXFILTRATION_DETECTED'
  | 'WEBSHELL_UPLOAD'
  | 'EXECUTABLE_UPLOAD'
  | 'CONFIG_TAMPERING'
  | 'BINARY_SIGNATURE_TAMPERING'
  | 'DESTRUCTION_ATTEMPT'
  | 'MASS_READ_ANOMALY'
  | 'SENSITIVE_PATH_ACCESS'
  | 'RANSOMWARE_SWEEP';

export interface DlpRule {
  ruleId: string;
  operations: FileOperation[];
  violationClass: DlpViolationClass;
  action: DlpAction;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  description: string;
  descriptionAr: string;
  mitreTechnique: string;
}

export interface FileOperationRequest {
  operation: FileOperation;
  filePath: string;
  actorIp: string;
  /** Session or bearer token identifying the acting principal. */
  token: string;
  mimeType?: string;
  sizeBytes?: number;
  processName?: string;
  /** Content sample used for signature inspection on uploads. */
  contentSample?: string;
}

export interface DlpInterceptionRecord {
  recordId: string;
  timestamp: number;
  operation: FileOperation;
  filePath: string;
  fileName: string;
  actorIp: string;
  token: string;
  processName: string;
  mimeType: string | null;
  sizeBytes: number;
  action: DlpAction;
  blocked: boolean;
  violationClass: DlpViolationClass | null;
  matchedRuleId: string | null;
  matchReason: string;
  matchReasonAr: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'INFO';
  mitreTechnique: string | null;
  tokenLockedDown: boolean;
  /** SHA-256 chained over the previous record, so the log is tamper-evident. */
  auditHash: string;
  previousAuditHash: string;
  /** Shannon entropy of the inspected sample, bits per byte. */
  entropyScore: number;
  magicBytesHex: string;
  /** Full-fidelity action, before collapsing onto the legacy DlpAction. */
  actionDetailed: InterceptionAction;
}

export interface LockedToken {
  token: string;
  actorIp: string;
  reason: string;
  reasonAr: string;
  lockedAt: number;
  expiresAt: number;
  violationCount: number;
}

const MAX_AUDIT_RECORDS = 500;
const TOKEN_LOCKDOWN_TTL_MS = 20 * 60_000; // 20 minutes

/** Sliding window used to spot mass-read exfiltration behavior. */
const MASS_READ_WINDOW_MS = 60_000;
const MASS_READ_THRESHOLD = 12;

/** Stage-3 exfiltration ceilings. */
const EXFIL_WINDOW_MS = 60_000;
/** > 15 MB inside the window triggers honeyfile quarantine. */
const EXFIL_VOLUME_CEILING_BYTES = 15 * 1024 * 1024;
/** > 5 reads/sec sustained across the window (5 * 60s). */
const EXFIL_RATE_CEILING = 5 * 60;
/** High-entropy writes inside the window that constitute an active sweep. */
const RANSOMWARE_SWEEP_THRESHOLD = 5;
const DLP_NULL_ROUTE_TTL_SECONDS = 1800;

/** Extensions whose deletion is always refused (config, database, logs). */
const PURGE_PROTECTED_EXTENSIONS = new Set([
  '.sqlite', '.sqlite3', '.db', '.log', '.conf', '.cfg', '.ini', '.yaml', '.yml',
  '.env', '.sh', '.ps1', '.service', '.sql', '.bak'
]);

/** Bridges the Stage-3 vector vocabulary onto the legacy operation names. */
const VECTOR_TO_OPERATION: Record<FileOperationType, FileOperation> = {
  FILE_READ_EXFIL: 'FILE_DOWNLOAD',
  FILE_WRITE_INJECT: 'FILE_UPLOAD',
  FILE_MODIFY_TAMPER: 'FILE_MODIFICATION',
  FILE_DELETE_PURGE: 'FILE_DELETION'
};

/** Directories whose contents are sensitive regardless of file type. */
const PROTECTED_DIRECTORIES = [
  '/etc',
  '/root',
  '/var/www',
  '/usr/bin',
  '/usr/sbin',
  'fim_sandbox',
  'config',
  'secrets'
];

/** Extensions that must never be written into a web-servable location. */
const EXECUTABLE_UPLOAD_EXTENSIONS = [
  '.php', '.phtml', '.jsp', '.jspx', '.asp', '.aspx',
  '.exe', '.dll', '.so', '.sh', '.bat', '.ps1', '.cmd', '.elf'
];

/** MIME types that indicate an executable or script payload. */
const BLOCKED_UPLOAD_MIMES = [
  'application/x-httpd-php',
  'application/x-msdownload',
  'application/x-sh',
  'application/x-executable',
  'application/vnd.microsoft.portable-executable',
  'text/x-php',
  'text/x-shellscript'
];

/** Files whose modification indicates configuration or credential tampering. */
const CRITICAL_CONFIG_FILES = [
  'passwd', 'shadow', 'sudoers', 'hosts', 'authorized_keys',
  'nginx.conf', 'nginx_security.conf', 'production.env', '.env',
  'auth_daemon.py', 'id_rsa'
];

/** Extensions treated as sensitive data for exfiltration purposes. */
const SENSITIVE_DATA_EXTENSIONS = ['.env', '.pem', '.key', '.p12', '.pfx', '.kdbx', '.sql', '.bak', '.dump'];

/** Web shell content signatures inspected on upload. */
const WEBSHELL_SIGNATURES: RegExp[] = [
  /eval\s*\(\s*base64_decode\s*\(/i,
  /system\s*\(\s*\$_(GET|POST|REQUEST)/i,
  /shell_exec\s*\(/i,
  /passthru\s*\(/i,
  /assert\s*\(\s*\$_/i,
  /<\?php[\s\S]*\$_(GET|POST|REQUEST)\s*\[/i,
  /Runtime\.getRuntime\(\)\.exec/i
];

/** Magic-byte prefixes identifying a binary executable. */
const BINARY_MAGIC_PREFIXES: Array<{ magic: string; label: string }> = [
  { magic: '\x7fELF', label: 'ELF executable' },
  { magic: 'MZ', label: 'PE/DOS executable' },
  { magic: '\xca\xfe\xba\xbe', label: 'Mach-O fat binary' },
  { magic: '#!/', label: 'Interpreter shebang' }
];

export class FileDlpInterceptionEngine {
  // --- O(1) rule indexes ------------------------------------------
  /** Exact normalized path -> rule. */
  private readonly pathIndex = new Map<string, DlpRule>();
  /** Directory segment -> rule, probed by walking the path's own segments. */
  private readonly directoryIndex = new Map<string, DlpRule>();
  /** Lowercased extension -> rule. */
  private readonly extensionIndex = new Map<string, DlpRule>();
  /** Lowercased MIME type -> rule. */
  private readonly mimeIndex = new Map<string, DlpRule>();
  /** Bare filename -> rule. */
  private readonly filenameIndex = new Map<string, DlpRule>();

  private readonly auditLog: DlpInterceptionRecord[] = [];
  private readonly lockedTokens = new Map<string, LockedToken>();
  /** token -> recent read timestamps, for mass-read detection. */
  private readonly readWindows = new Map<string, number[]>();
  /** uid -> rolling read-volume ledger for the exfiltration ceiling. */
  private readonly volumeWindows = new Map<string, Array<{ at: number; bytes: number }>>();
  /** uid -> timestamps of high-entropy writes, the ransomware sweep signal. */
  private readonly encryptedWriteWindows = new Map<string, number[]>();
  /** normalized path -> known-good SHA-256 baseline. */
  private readonly baselineManifest = new Map<string, string>();

  public totalHoneyfilesServed = 0;
  public totalSystemFreezes = 0;
  public totalSocketInvalidations = 0;

  private auditChainHead = 'GENESIS';
  private enabled = true;
  /** Monotonic counter for record ids: collision-free and far cheaper than a CSPRNG call. */
  private recordSequence = 0;

  public totalEvaluated = 0;
  public totalBlocked = 0;

  constructor() {
    this.buildRuleIndexes();
  }

  // -------------------------------------------------------------------
  // Ruleset construction
  // -------------------------------------------------------------------

  /**
   * Compiles the policy into hash indexes once at startup. Evaluation then
   * costs a handful of Map lookups instead of scanning every rule, which
   * matters because this sits in the request path.
   */
  private buildRuleIndexes(): void {
    for (const dir of PROTECTED_DIRECTORIES) {
      this.directoryIndex.set(this.normalizeSegment(dir), {
        ruleId: 'DLP-DIR-' + this.normalizeSegment(dir).toUpperCase().replace(/[^A-Z0-9]/g, ''),
        operations: ['FILE_DOWNLOAD', 'FILE_MODIFICATION', 'FILE_DELETION', 'FILE_UPLOAD'],
        violationClass: 'SENSITIVE_PATH_ACCESS',
        action: 'BLOCK',
        severity: 'HIGH',
        description: 'Operation targets the protected directory "' + dir + '".',
        descriptionAr: 'العملية تستهدف الدليل المحمي "' + dir + '".',
        mitreTechnique: 'T1083 - File and Directory Discovery'
      });
    }

    for (const ext of EXECUTABLE_UPLOAD_EXTENSIONS) {
      this.extensionIndex.set(ext, {
        ruleId: 'DLP-EXT-' + ext.replace('.', '').toUpperCase(),
        operations: ['FILE_UPLOAD'],
        violationClass: 'EXECUTABLE_UPLOAD',
        action: 'BLOCK',
        severity: 'CRITICAL',
        description: 'Upload of executable/script type "' + ext + '" into a served location.',
        descriptionAr: 'رفع ملف تنفيذي أو برمجي من نوع "' + ext + '" إلى موقع قابل للتقديم.',
        mitreTechnique: 'T1505.003 - Server Software Component: Web Shell'
      });
    }

    for (const ext of SENSITIVE_DATA_EXTENSIONS) {
      // Sensitive data extensions matter on read, not on write.
      this.extensionIndex.set(ext, {
        ruleId: 'DLP-SENS-' + ext.replace('.', '').toUpperCase(),
        operations: ['FILE_DOWNLOAD'],
        violationClass: 'EXFILTRATION_DETECTED',
        action: 'BLOCK',
        severity: 'CRITICAL',
        description: 'Download of sensitive artifact type "' + ext + '".',
        descriptionAr: 'تنزيل ملف حساس من نوع "' + ext + '".',
        mitreTechnique: 'T1041 - Exfiltration Over C2 Channel'
      });
    }

    for (const mime of BLOCKED_UPLOAD_MIMES) {
      this.mimeIndex.set(mime, {
        ruleId: 'DLP-MIME-' + mime.replace(/[^a-z0-9]/gi, '').toUpperCase().slice(0, 18),
        operations: ['FILE_UPLOAD'],
        violationClass: 'EXECUTABLE_UPLOAD',
        action: 'BLOCK',
        severity: 'CRITICAL',
        description: 'Upload declares executable MIME type "' + mime + '".',
        descriptionAr: 'الرفع يعلن نوع MIME تنفيذي "' + mime + '".',
        mitreTechnique: 'T1505.003 - Server Software Component: Web Shell'
      });
    }

    for (const file of CRITICAL_CONFIG_FILES) {
      this.filenameIndex.set(file.toLowerCase(), {
        ruleId: 'DLP-FILE-' + file.toUpperCase().replace(/[^A-Z0-9]/g, ''),
        operations: ['FILE_MODIFICATION', 'FILE_DELETION', 'FILE_DOWNLOAD'],
        violationClass: 'CONFIG_TAMPERING',
        action: 'BLOCK',
        severity: 'CRITICAL',
        description: 'Operation targets the protected system artifact "' + file + '".',
        descriptionAr: 'العملية تستهدف ملف النظام المحمي "' + file + '".',
        mitreTechnique: 'T1565.001 - Data Manipulation: Stored Data Manipulation'
      });
    }
  }

  private normalizeSegment(segment: string): string {
    return segment.replace(/^[\/\\]+|[\/\\]+$/g, '').toLowerCase();
  }

  /** Normalizes a path for consistent indexing across OS separators. */
  private normalizePath(filePath: string): string {
    return filePath.replace(/\\/g, '/').toLowerCase();
  }

  // -------------------------------------------------------------------
  // Evaluation
  // -------------------------------------------------------------------

  /**
   * Evaluates one file operation and returns an enforceable decision.
   *
   * Every index probe below is a Map lookup. The directory check walks the
   * operation's own path segments, which is bounded by path depth rather than
   * by ruleset size, so adding rules never slows evaluation.
   */
  public evaluate(request: FileOperationRequest): DlpInterceptionRecord {
    this.totalEvaluated++;

    const normalized = this.normalizePath(request.filePath);
    const fileName = path.basename(normalized);
    const ext = path.extname(normalized).toLowerCase();
    const mime = request.mimeType?.toLowerCase() ?? null;

    let matched: DlpRule | null = null;
    let reason = '';
    let reasonAr = '';

    // --- 1. Exact path rule (O(1)) ---------------------------------
    const exact = this.pathIndex.get(normalized);
    if (exact && exact.operations.includes(request.operation)) {
      matched = exact;
      reason = exact.description;
      reasonAr = exact.descriptionAr;
    }

    // --- 2. Protected filename (O(1)) ------------------------------
    if (!matched) {
      const byName = this.filenameIndex.get(fileName);
      if (byName && byName.operations.includes(request.operation)) {
        matched = byName;
        reason = byName.description;
        reasonAr = byName.descriptionAr;
      }
    }

    // --- 3. Protected directory (O(path depth)) --------------------
    if (!matched) {
      for (const segment of normalized.split('/')) {
        if (!segment) continue;
        const byDir = this.directoryIndex.get(segment);
        if (byDir && byDir.operations.includes(request.operation)) {
          matched = byDir;
          reason = byDir.description;
          reasonAr = byDir.descriptionAr;
          break;
        }
      }
    }

    // --- 4. Extension rule (O(1)) ----------------------------------
    if (!matched && ext) {
      const byExt = this.extensionIndex.get(ext);
      if (byExt && byExt.operations.includes(request.operation)) {
        matched = byExt;
        reason = byExt.description;
        reasonAr = byExt.descriptionAr;
      }
    }

    // --- 5. MIME rule (O(1)) ---------------------------------------
    if (!matched && mime) {
      const byMime = this.mimeIndex.get(mime);
      if (byMime && byMime.operations.includes(request.operation)) {
        matched = byMime;
        reason = byMime.description;
        reasonAr = byMime.descriptionAr;
      }
    }

    // --- 6. Content inspection on upload ---------------------------
    if (!matched && request.operation === 'FILE_UPLOAD' && request.contentSample) {
      const shell = WEBSHELL_SIGNATURES.find(re => re.test(request.contentSample as string));
      if (shell) {
        matched = {
          ruleId: 'DLP-CONTENT-WEBSHELL',
          operations: ['FILE_UPLOAD'],
          violationClass: 'WEBSHELL_UPLOAD',
          action: 'BLOCK',
          severity: 'CRITICAL',
          description: 'Uploaded content matches a known web shell signature.',
          descriptionAr: 'المحتوى المرفوع يطابق بصمة قذيفة ويب معروفة.',
          mitreTechnique: 'T1505.003 - Server Software Component: Web Shell'
        };
        reason = matched.description;
        reasonAr = matched.descriptionAr;
      } else {
        const binary = BINARY_MAGIC_PREFIXES.find(b => request.contentSample!.startsWith(b.magic));
        if (binary) {
          matched = {
            ruleId: 'DLP-CONTENT-BINARY',
            operations: ['FILE_UPLOAD'],
            violationClass: 'BINARY_SIGNATURE_TAMPERING',
            action: 'BLOCK',
            severity: 'CRITICAL',
            description: 'Upload carries ' + binary.label + ' magic bytes.',
            descriptionAr: 'الرفع يحمل بصمة ثنائية من نوع ' + binary.label + '.',
            mitreTechnique: 'T1105 - Ingress Tool Transfer'
          };
          reason = matched.description;
          reasonAr = matched.descriptionAr;
        }
      }
    }

    // --- 7. Destruction behavior -----------------------------------
    if (!matched && request.operation === 'FILE_DELETION') {
      matched = {
        ruleId: 'DLP-DESTRUCTION',
        operations: ['FILE_DELETION'],
        violationClass: 'DESTRUCTION_ATTEMPT',
        action: 'QUARANTINE',
        severity: 'HIGH',
        description: 'Deletion of a monitored artifact is held for review (ransomware / defense-evasion pattern).',
        descriptionAr: 'حذف ملف مراقب يُحتجز للمراجعة (نمط فدية أو تهرب دفاعي).',
        mitreTechnique: 'T1070.004 - Indicator Removal: File Deletion'
      };
      reason = matched.description;
      reasonAr = matched.descriptionAr;
    }

    // --- 8. Mass-read exfiltration heuristic -----------------------
    if (request.operation === 'FILE_DOWNLOAD') {
      const burst = this.recordRead(request.token);
      if (!matched && burst >= MASS_READ_THRESHOLD) {
        matched = {
          ruleId: 'DLP-MASSREAD',
          operations: ['FILE_DOWNLOAD'],
          violationClass: 'MASS_READ_ANOMALY',
          action: 'BLOCK',
          severity: 'HIGH',
          description: burst + ' reads in ' + (MASS_READ_WINDOW_MS / 1000)
            + 's exceeds the exfiltration threshold of ' + MASS_READ_THRESHOLD + '.',
          descriptionAr: burst + ' عملية قراءة خلال ' + (MASS_READ_WINDOW_MS / 1000)
            + ' ثانية تتجاوز عتبة التسريب البالغة ' + MASS_READ_THRESHOLD + '.',
          mitreTechnique: 'T1530 - Data from Cloud Storage Object'
        };
        reason = matched.description;
        reasonAr = matched.descriptionAr;
      }
    }

    const action: DlpAction = !this.enabled ? 'ALLOW' : (matched ? matched.action : 'ALLOW');
    const blocked = action !== 'ALLOW';

    const previousAuditHash = this.auditChainHead;
    const record: DlpInterceptionRecord = {
      recordId: 'DLP-' + Date.now().toString(36).toUpperCase() + '-' + (++this.recordSequence).toString(36).toUpperCase(),
      timestamp: Date.now(),
      operation: request.operation,
      filePath: request.filePath,
      fileName: path.basename(request.filePath),
      actorIp: request.actorIp,
      token: request.token,
      processName: request.processName ?? 'unknown',
      mimeType: request.mimeType ?? null,
      sizeBytes: request.sizeBytes ?? 0,
      action,
      blocked,
      violationClass: matched ? matched.violationClass : null,
      matchedRuleId: matched ? matched.ruleId : null,
      matchReason: blocked ? reason : 'No policy rule matched; operation permitted.',
      matchReasonAr: blocked ? reasonAr : 'لم تطابق أي قاعدة سياسة؛ سُمح بالعملية.',
      severity: matched ? matched.severity : 'INFO',
      mitreTechnique: matched ? matched.mitreTechnique : null,
      tokenLockedDown: false,
      auditHash: '',
      previousAuditHash,
      entropyScore: 0,
      magicBytesHex: '',
      actionDetailed: action === 'BLOCK' ? 'BLOCK_AND_ISOLATE' : action === 'QUARANTINE' ? 'QUARANTINE_HONEYFILE' : 'ALLOW'
    };

    if (blocked) {
      this.totalBlocked++;
      record.tokenLockedDown = this.lockdownToken(request.token, request.actorIp, record);
    }

    record.auditHash = this.appendToAuditChain(record);
    this.retainAudit(record);

    if (blocked) this.publishIncident(record);

    return record;
  }

  // -------------------------------------------------------------------
  // STAGE 3: deep vector enforcement
  // -------------------------------------------------------------------

  /**
   * Adjudicates one FileOperationVector against the four enforcement vectors.
   *
   * This is the deep path: it reconciles declared MIME against real magic
   * bytes, measures Shannon entropy over the first 4096 bytes, enforces read
   * rate and volume ceilings, and verifies modifications against the baseline
   * manifest. Every check is bounded work, so cost does not grow with file
   * size or with the number of policy rules.
   */
  public enforceVector(
    vector: FileOperationVector,
    content?: Buffer | string
  ): { decision: InterceptionDecision; record: DlpInterceptionRecord; honeyfile: HoneyfilePayload | null } {
    this.totalEvaluated++;

    const reasons: string[] = [];
    const reasonsAr: string[] = [];
    let action: InterceptionAction = 'ALLOW';
    let violationClass: DlpViolationClass | null = null;
    let mitreTechnique = 'T1083 - File and Directory Discovery';
    let score = 0;

    const normalized = vector.targetPath.replace(/\\/g, '/').toLowerCase();
    const fileName = normalized.split('/').filter(Boolean).pop() ?? normalized;
    const ext = fileName.includes('.') ? fileName.slice(fileName.lastIndexOf('.')) : '';

    // Prefer measured entropy over any client-supplied figure: the caller is
    // untrusted, so a self-reported low score must never suppress detection.
    const entropy = content !== undefined
      ? shannonEntropy(content)
      : Math.max(0, Math.min(8, vector.entropyScore ?? 0));

    switch (vector.operationType) {
      // ---------------------------------------------------------------
      case 'FILE_DELETE_PURGE': {
        const protectedTarget = PURGE_PROTECTED_EXTENSIONS.has(ext)
          || this.filenameIndex.has(fileName)
          || CRITICAL_CONFIG_FILES.includes(fileName);
        if (protectedTarget) {
          action = 'BLOCK_AND_ISOLATE';
          violationClass = 'DESTRUCTION_ATTEMPT';
          mitreTechnique = 'T1485 - Data Destruction';
          score = 92;
          reasons.push('Deletion of protected artifact "' + fileName + '" refused; write privileges revoked.');
          reasonsAr.push('رُفض حذف الملف المحمي "' + fileName + '" وسُحبت صلاحيات الكتابة.');
        }
        break;
      }

      // ---------------------------------------------------------------
      case 'FILE_WRITE_INJECT': {
        const analysis = analyzeMagicBytes(content ?? '', vector.fileMimeType, vector.magicBytesHex);
        if (analysis.mimeSpoofed || analysis.executableContent) {
          action = 'BLOCK_AND_ISOLATE';
          violationClass = analysis.embeddedScripts.length > 0 ? 'WEBSHELL_UPLOAD' : 'BINARY_SIGNATURE_TAMPERING';
          mitreTechnique = 'T1505.003 - Server Software Component: Web Shell';
          score = 95;
          reasons.push(analysis.detail + ' Upload aborted and source address blocked.');
          reasonsAr.push('تعارض نوع المحتوى المعلن مع البايتات الفعلية؛ أُلغي الرفع وحُظر العنوان المصدر.');
        } else if (this.extensionIndex.has(ext)) {
          action = 'BLOCK_AND_ISOLATE';
          violationClass = 'EXECUTABLE_UPLOAD';
          mitreTechnique = 'T1105 - Ingress Tool Transfer';
          score = 88;
          reasons.push('Upload of executable type "' + ext + '" into a served location.');
          reasonsAr.push('رفع ملف تنفيذي من نوع "' + ext + '" إلى موقع قابل للتقديم.');
        }
        break;
      }

      // ---------------------------------------------------------------
      case 'FILE_READ_EXFIL': {
        const burst = this.recordRead(vector.actorIdentity.uid);
        const volume = this.recordVolume(vector.actorIdentity.uid, vector.fileSizeBytes);

        if (volume > EXFIL_VOLUME_CEILING_BYTES || burst > EXFIL_RATE_CEILING) {
          action = 'QUARANTINE_HONEYFILE';
          violationClass = 'EXFILTRATION_DETECTED';
          mitreTechnique = 'T1048 - Exfiltration Over Alternative Protocol';
          score = 84;
          reasons.push('Read volume ' + (volume / 1048576).toFixed(2) + ' MB across ' + burst
            + ' requests in the window exceeds the exfiltration ceiling; decoy content served and bandwidth throttled to zero.');
          reasonsAr.push('حجم القراءة ' + (volume / 1048576).toFixed(2) + ' ميغابايت عبر ' + burst
            + ' طلباً يتجاوز سقف التسريب؛ قُدم محتوى خادع وخُفض النطاق إلى الصفر.');
        } else if (this.extensionIndex.get(ext)?.violationClass === 'EXFILTRATION_DETECTED') {
          action = 'BLOCK_AND_ISOLATE';
          violationClass = 'EXFILTRATION_DETECTED';
          mitreTechnique = 'T1041 - Exfiltration Over C2 Channel';
          score = 80;
          reasons.push('Download of sensitive artifact type "' + ext + '".');
          reasonsAr.push('تنزيل ملف حساس من نوع "' + ext + '".');
        }
        break;
      }

      // ---------------------------------------------------------------
      case 'FILE_MODIFY_TAMPER': {
        const verdict = this.verifyAgainstManifest(normalized, content);
        if (verdict.status === 'MISMATCH') {
          action = 'BLOCK_AND_ISOLATE';
          violationClass = 'CONFIG_TAMPERING';
          mitreTechnique = 'T1565.001 - Data Manipulation: Stored Data Manipulation';
          score = 90;
          reasons.push('Baseline manifest mismatch for "' + fileName + '" (expected ' + verdict.expected?.slice(0, 16)
            + '..., observed ' + verdict.observed?.slice(0, 16) + '...). Modification reverted and write lock applied.');
          reasonsAr.push('عدم تطابق مع بيان خط الأساس للملف "' + fileName
            + '"؛ أُعيد التعديل وطُبق قفل الكتابة.');
        } else if (verdict.status !== 'MATCH' && this.filenameIndex.has(fileName)) {
          // Only reached when the manifest did not positively confirm the
          // content. A write whose digest equals the recorded baseline changed
          // nothing, so blocking it would be a false positive on a no-op.
          action = 'BLOCK_AND_ISOLATE';
          violationClass = 'CONFIG_TAMPERING';
          mitreTechnique = 'T1565.001 - Data Manipulation: Stored Data Manipulation';
          score = 86;
          reasons.push('Modification of protected system artifact "' + fileName + '".');
          reasonsAr.push('تعديل ملف نظام محمي "' + fileName + '".');
        }
        break;
      }
    }

    // ---------------------------------------------------------------
    // Ransomware sweep detector, applied across every write-side vector.
    if (
      entropy > HIGH_ENTROPY_THRESHOLD &&
      (vector.operationType === 'FILE_MODIFY_TAMPER' || vector.operationType === 'FILE_WRITE_INJECT')
    ) {
      const sweep = this.recordEncryptedWrite(vector.actorIdentity.uid);
      score = Math.max(score, 88);
      // Only claim a ransomware sweep when entropy is the *primary* signal.
      // A PE or web shell upload also reads as high entropy, and relabelling
      // it here would hand the analyst the wrong incident class.
      if (violationClass === null || sweep >= RANSOMWARE_SWEEP_THRESHOLD) {
        violationClass = 'RANSOMWARE_SWEEP';
        mitreTechnique = 'T1486 - Data Encrypted for Impact';
      }
      reasons.push('Entropy ' + entropy.toFixed(4) + ' bits/byte indicates encrypted content ('
        + sweep + ' high-entropy writes in the window).');
      reasonsAr.push('الإنتروبيا ' + entropy.toFixed(4) + ' بت/بايت تشير إلى محتوى مشفر ('
        + sweep + ' عملية كتابة عالية الإنتروبيا خلال النافذة).');

      // A sustained sweep is an active ransomware run, not a single bad file.
      action = sweep >= RANSOMWARE_SWEEP_THRESHOLD ? 'TRIGGER_SYSTEM_FREEZE' : 'BLOCK_AND_ISOLATE';
      if (action === 'TRIGGER_SYSTEM_FREEZE') {
        score = 100;
        this.totalSystemFreezes++;
        try {
          globalEbpfEngine.enforceEmergencyLockdown(
            true,
            'File DLP: ransomware encryption sweep from ' + vector.actorIdentity.sourceIp
          );
        } catch (err: any) {
          console.warn('[FileDLP] System freeze failed:', err?.message || err);
        }
      }
    }

    if (!this.enabled) {
      action = 'ALLOW';
      violationClass = null;
      score = 0;
    }

    const blocked = action !== 'ALLOW';
    const severity: DlpInterceptionRecord['severity'] = score >= 90 ? 'CRITICAL' : score >= 75 ? 'HIGH' : blocked ? 'MEDIUM' : 'INFO';

    const previousAuditHash = this.auditChainHead;
    const record: DlpInterceptionRecord = {
      recordId: 'DLP-' + Date.now().toString(36).toUpperCase() + '-' + (++this.recordSequence).toString(36).toUpperCase(),
      timestamp: Date.now(),
      operation: VECTOR_TO_OPERATION[vector.operationType],
      filePath: vector.targetPath,
      fileName,
      actorIp: vector.actorIdentity.sourceIp,
      token: vector.actorIdentity.uid,
      processName: 'pid:' + vector.processId,
      mimeType: vector.fileMimeType ?? null,
      sizeBytes: vector.fileSizeBytes ?? 0,
      action: action === 'ALLOW' ? 'ALLOW' : action === 'QUARANTINE_HONEYFILE' ? 'QUARANTINE' : 'BLOCK',
      blocked,
      violationClass,
      matchedRuleId: violationClass ? 'DLP-VECTOR-' + vector.operationType : null,
      matchReason: reasons.join(' ') || 'No enforcement vector matched; operation permitted.',
      matchReasonAr: reasonsAr.join(' ') || 'لم يطابق أي ناقل إنفاذ؛ سُمح بالعملية.',
      severity,
      mitreTechnique,
      tokenLockedDown: false,
      auditHash: '',
      previousAuditHash,
      entropyScore: entropy,
      magicBytesHex: vector.magicBytesHex ?? '',
      actionDetailed: action
    };

    let honeyfile: HoneyfilePayload | null = null;
    if (blocked) {
      this.totalBlocked++;
      record.tokenLockedDown = this.lockdownToken(vector.actorIdentity.uid, vector.actorIdentity.sourceIp, record);

      if (action === 'QUARANTINE_HONEYFILE') {
        honeyfile = this.serveHoneyfile(vector);
        this.totalHoneyfilesServed++;
      } else {
        // Block-and-isolate pushes the actor into the kernel drop map.
        try {
          globalEbpfEngine.enforceNullRoute(
            vector.actorIdentity.sourceIp,
            'File DLP: ' + (violationClass ?? 'POLICY_VIOLATION') + ' on ' + fileName,
            DLP_NULL_ROUTE_TTL_SECONDS
          );
          this.totalSocketInvalidations++;
        } catch (err: any) {
          console.warn('[FileDLP] Kernel null-route failed:', err?.message || err);
        }
      }
    }

    record.auditHash = this.appendToAuditChain(record);
    this.retainAudit(record);
    if (blocked) this.publishIncident(record);

    const decision: InterceptionDecision = {
      action,
      threatScore: Math.max(0, Math.min(100, score)),
      confidence: Number(Math.min(0.99, blocked ? 0.72 + reasons.length * 0.09 : 0.6).toFixed(2)),
      mitreTechnique,
      forensicDigest: sha256Hex(canonicalSerialize({ vector, record: { ...record, auditHash: undefined } }))
    };

    return { decision, record, honeyfile };
  }

  /**
   * Generates decoy content for a quarantined exfiltration attempt.
   *
   * The decoy is deterministic per (actor, path) so an attacker polling the
   * same resource sees a stable file rather than obviously synthetic noise,
   * and every decoy is watermarked so it can be recognised if it ever
   * resurfaces in a leak.
   */
  private serveHoneyfile(vector: FileOperationVector): HoneyfilePayload {
    const watermark = sha256Hex(vector.actorIdentity.uid + '|' + vector.targetPath).slice(0, 32);
    const body = [
      '# CONFIDENTIAL - INTERNAL USE ONLY',
      '# document-ref: ' + watermark,
      '',
      'db.primary.host=10.0.0.0',
      'db.primary.user=svc_reporting',
      'db.primary.password=<redacted-by-policy>',
      'api.partner.key=sk_live_' + watermark.slice(0, 24),
      '',
      '# Records: 0 rows exported. Access to this artifact is recorded.'
    ].join('\n');

    return {
      servedPath: vector.targetPath,
      watermark,
      contentType: 'text/plain',
      sizeBytes: Buffer.byteLength(body, 'utf-8'),
      body,
      bandwidthBytesPerSec: 0
    };
  }

  /** Rolling volume ledger per actor over the exfiltration window. */
  private recordVolume(uid: string, bytes: number): number {
    const now = Date.now();
    const cutoff = now - EXFIL_WINDOW_MS;
    const ledger = this.volumeWindows.get(uid) ?? [];

    let start = 0;
    while (start < ledger.length && ledger[start].at < cutoff) start++;
    const fresh = start > 0 ? ledger.slice(start) : ledger;
    fresh.push({ at: now, bytes: Math.max(0, bytes || 0) });
    if (fresh.length > 512) fresh.splice(0, fresh.length - 512);
    this.volumeWindows.set(uid, fresh);

    while (this.volumeWindows.size > 2_000) {
      const oldest = this.volumeWindows.keys().next().value as string | undefined;
      if (oldest === undefined) break;
      this.volumeWindows.delete(oldest);
    }
    return fresh.reduce((sum, e) => sum + e.bytes, 0);
  }

  /** Counts high-entropy writes per actor, the ransomware sweep signal. */
  private recordEncryptedWrite(uid: string): number {
    const now = Date.now();
    const cutoff = now - EXFIL_WINDOW_MS;
    const window = this.encryptedWriteWindows.get(uid) ?? [];

    let start = 0;
    while (start < window.length && window[start] < cutoff) start++;
    const fresh = start > 0 ? window.slice(start) : window;
    fresh.push(now);
    if (fresh.length > RANSOMWARE_SWEEP_THRESHOLD * 2) {
      fresh.splice(0, fresh.length - RANSOMWARE_SWEEP_THRESHOLD * 2);
    }
    this.encryptedWriteWindows.set(uid, fresh);
    return fresh.length;
  }

  /**
   * Compares content against the recorded baseline manifest.
   *
   * An unknown path is recorded rather than rejected: the first sighting
   * establishes the baseline, and only a later divergence from it counts as
   * tampering. Rejecting unknown paths outright would block every legitimate
   * new file the platform ever writes.
   */
  private verifyAgainstManifest(
    normalizedPath: string,
    content?: Buffer | string
  ): { status: 'MATCH' | 'MISMATCH' | 'BASELINE_RECORDED'; expected?: string; observed?: string } {
    if (content === undefined) return { status: 'MATCH' };
    const observed = sha256Hex(Buffer.isBuffer(content) ? content.toString('utf-8') : content);
    const expected = this.baselineManifest.get(normalizedPath);

    if (expected === undefined) {
      this.baselineManifest.set(normalizedPath, observed);
      while (this.baselineManifest.size > 10_000) {
        const oldest = this.baselineManifest.keys().next().value as string | undefined;
        if (oldest === undefined) break;
        this.baselineManifest.delete(oldest);
      }
      return { status: 'BASELINE_RECORDED', observed };
    }
    return expected === observed
      ? { status: 'MATCH', expected, observed }
      : { status: 'MISMATCH', expected, observed };
  }

  /** Registers or replaces a known-good baseline digest for a path. */
  public registerBaseline(targetPath: string, content: Buffer | string): string {
    const normalized = targetPath.replace(/\\/g, '/').toLowerCase();
    const digest = sha256Hex(Buffer.isBuffer(content) ? content.toString('utf-8') : content);
    this.baselineManifest.set(normalized, digest);
    return digest;
  }

  // -------------------------------------------------------------------
  // Mass-read window
  // -------------------------------------------------------------------

  private recordRead(token: string): number {
    const now = Date.now();
    const window = this.readWindows.get(token) ?? [];
    const cutoff = now - MASS_READ_WINDOW_MS;

    // Only the most recent MASS_READ_THRESHOLD timestamps can ever change the
    // verdict, so the window is capped at that length. Without the cap a busy
    // token accumulates one entry per read and every subsequent read filters
    // the whole array, making the hot path O(n) in reads and unbounded in
    // memory. Dropping from the front keeps both constant.
    let start = 0;
    while (start < window.length && window[start] < cutoff) start++;
    const fresh = start > 0 ? window.slice(start) : window;
    fresh.push(now);
    if (fresh.length > MASS_READ_THRESHOLD) {
      fresh.splice(0, fresh.length - MASS_READ_THRESHOLD);
    }
    this.readWindows.set(token, fresh);

    // Bound the map so idle tokens cannot accumulate indefinitely.
    while (this.readWindows.size > 2_000) {
      const oldest = this.readWindows.keys().next().value as string | undefined;
      if (oldest === undefined) break;
      this.readWindows.delete(oldest);
    }
    return fresh.length;
  }

  // -------------------------------------------------------------------
  // Token lockdown
  // -------------------------------------------------------------------

  private lockdownToken(token: string, actorIp: string, record: DlpInterceptionRecord): boolean {
    const existing = this.lockedTokens.get(token);
    this.lockedTokens.set(token, {
      token,
      actorIp,
      reason: record.violationClass + ' on ' + record.fileName,
      reasonAr: 'انتهاك ' + record.violationClass + ' على الملف ' + record.fileName,
      lockedAt: existing?.lockedAt ?? Date.now(),
      expiresAt: Date.now() + TOKEN_LOCKDOWN_TTL_MS,
      violationCount: (existing?.violationCount ?? 0) + 1
    });
    return true;
  }

  public isTokenLocked(token: string): boolean {
    const entry = this.lockedTokens.get(token);
    if (!entry) return false;
    if (entry.expiresAt <= Date.now()) {
      this.lockedTokens.delete(token);
      return false;
    }
    return true;
  }

  public releaseToken(token: string): boolean {
    return this.lockedTokens.delete(token);
  }

  public getLockedTokens(): LockedToken[] {
    const now = Date.now();
    const active: LockedToken[] = [];
    for (const [token, entry] of this.lockedTokens.entries()) {
      if (entry.expiresAt <= now) {
        this.lockedTokens.delete(token);
        continue;
      }
      active.push(entry);
    }
    return active.sort((a, b) => b.lockedAt - a.lockedAt);
  }

  // -------------------------------------------------------------------
  // Tamper-evident audit chain
  // -------------------------------------------------------------------

  private appendToAuditChain(record: DlpInterceptionRecord): string {
    const body = JSON.stringify({
      recordId: record.recordId,
      timestamp: record.timestamp,
      operation: record.operation,
      filePath: record.filePath,
      actorIp: record.actorIp,
      token: record.token,
      action: record.action,
      violationClass: record.violationClass,
      matchedRuleId: record.matchedRuleId
    });
    const chained = crypto.createHash('sha256').update(record.previousAuditHash + ':' + body).digest('hex');
    this.auditChainHead = chained;
    return chained;
  }

  /**
   * Re-walks the retained log and reports the first broken link.
   *
   * Each record is checked twice: that its own contents still hash to its
   * stored digest, and that its previousAuditHash actually equals the prior
   * record's digest. The second check is what makes the log tamper-evident
   * against deletion and reordering - verifying only a record against its own
   * embedded previous-hash would let a deleted record go unnoticed, because
   * every surviving record would still be internally self-consistent.
   */
  public verifyAuditChain(): { valid: boolean; brokenAt: string | null; verified: number } {
    let verified = 0;
    let expectedPrevious: string | null = null;

    for (const record of this.auditLog) {
      if (expectedPrevious !== null && record.previousAuditHash !== expectedPrevious) {
        return { valid: false, brokenAt: record.recordId, verified };
      }
      const body = JSON.stringify({
        recordId: record.recordId,
        timestamp: record.timestamp,
        operation: record.operation,
        filePath: record.filePath,
        actorIp: record.actorIp,
        token: record.token,
        action: record.action,
        violationClass: record.violationClass,
        matchedRuleId: record.matchedRuleId
      });
      const expected = crypto.createHash('sha256').update(record.previousAuditHash + ':' + body).digest('hex');
      if (expected !== record.auditHash) {
        return { valid: false, brokenAt: record.recordId, verified };
      }
      expectedPrevious = record.auditHash;
      verified++;
    }
    return { valid: true, brokenAt: null, verified };
  }

  private retainAudit(record: DlpInterceptionRecord): void {
    this.auditLog.push(record);
    while (this.auditLog.length > MAX_AUDIT_RECORDS) this.auditLog.shift();
  }

  // -------------------------------------------------------------------
  // Telemetry
  // -------------------------------------------------------------------

  private publishIncident(record: DlpInterceptionRecord): void {
    try {
      globalUnifiedTelemetryService.recordEvent({
        source: 'FIM',
        severity: record.severity === 'INFO' ? 'LOW' : record.severity,
        title: '[DLP] ' + record.action + ': ' + record.violationClass
          + ' - ' + record.operation + ' on ' + record.fileName,
        titleAr: '[منع تسريب البيانات] ' + record.action + ': ' + record.violationClass
          + ' - ' + record.operation + ' على الملف ' + record.fileName,
        details: record.matchReason + ' Actor ' + record.actorIp
          + ' (token ' + record.token.slice(0, 12) + '...) was locked down.',
        detailsAr: record.matchReasonAr + ' تم عزل الفاعل ' + record.actorIp
          + ' (الرمز ' + record.token.slice(0, 12) + '...).',
        actorIp: record.actorIp,
        sessionId: record.token,
        mitreTactic: this.mapOperationToTactic(record.operation),
        mitreTechnique: record.mitreTechnique ?? undefined,
        actionTaken: 'DLP_' + record.action + '_' + record.operation,
        actionTakenAr: record.action === 'BLOCK'
          ? 'تم حظر العملية وعزل الرمز'
          : 'تم احتجاز العملية للمراجعة',
        metadata: {
          recordId: record.recordId,
          matchedRuleId: record.matchedRuleId,
          violationClass: record.violationClass,
          filePath: record.filePath,
          mimeType: record.mimeType,
          sizeBytes: record.sizeBytes,
          processName: record.processName,
          auditHash: record.auditHash,
          previousAuditHash: record.previousAuditHash,
          tokenLockedDown: record.tokenLockedDown
        }
      });
    } catch (err: any) {
      console.warn('[FileDLP] Telemetry publish failed:', err?.message || err);
    }

    try {
      globalTelemetryWsServer.broadcast('interception:file', record);
    } catch (err: any) {
      console.warn('[FileDLP] WS broadcast failed:', err?.message || err);
    }
  }

  private mapOperationToTactic(operation: FileOperation): string {
    switch (operation) {
      case 'FILE_DOWNLOAD': return 'Exfiltration';
      case 'FILE_UPLOAD': return 'Persistence';
      case 'FILE_MODIFICATION': return 'Impact';
      case 'FILE_DELETION': return 'Defense Evasion';
      default: return 'Collection';
    }
  }

  // -------------------------------------------------------------------
  // Query surface
  // -------------------------------------------------------------------

  public getRecentRecords(limit: number = 50, blockedOnly: boolean = false): DlpInterceptionRecord[] {
    const source = blockedOnly ? this.auditLog.filter(r => r.blocked) : this.auditLog;
    const bounded = Math.max(1, Math.min(limit, MAX_AUDIT_RECORDS));
    return source.slice(-bounded).reverse();
  }

  public setEnabled(enabled: boolean): boolean {
    this.enabled = enabled;
    return this.enabled;
  }

  public isEnabled(): boolean {
    return this.enabled;
  }

  public getStats() {
    const byOperation: Record<string, number> = {
      FILE_DOWNLOAD: 0, FILE_UPLOAD: 0, FILE_MODIFICATION: 0, FILE_DELETION: 0
    };
    for (const r of this.auditLog) {
      if (r.blocked) byOperation[r.operation] = (byOperation[r.operation] ?? 0) + 1;
    }

    return {
      enabled: this.enabled,
      totalEvaluated: this.totalEvaluated,
      totalBlocked: this.totalBlocked,
      blockRatePercent: this.totalEvaluated === 0
        ? 0
        : Number(((this.totalBlocked / this.totalEvaluated) * 100).toFixed(2)),
      blockedByOperation: byOperation,
      lockedTokens: this.getLockedTokens().length,
      retainedAuditRecords: this.auditLog.length,
      auditChainHead: this.auditChainHead,
      honeyfilesServed: this.totalHoneyfilesServed,
      systemFreezes: this.totalSystemFreezes,
      socketInvalidations: this.totalSocketInvalidations,
      baselineManifestEntries: this.baselineManifest.size,
      ruleIndexSizes: {
        exactPaths: this.pathIndex.size,
        directories: this.directoryIndex.size,
        extensions: this.extensionIndex.size,
        mimeTypes: this.mimeIndex.size,
        filenames: this.filenameIndex.size
      }
    };
  }

  public clear(): void {
    this.auditLog.length = 0;
    this.lockedTokens.clear();
    this.readWindows.clear();
    this.auditChainHead = 'GENESIS';
    this.totalEvaluated = 0;
    this.totalBlocked = 0;
  }
}

export const globalFileDlpEngine = new FileDlpInterceptionEngine();
