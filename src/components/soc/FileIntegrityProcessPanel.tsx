import React, { useState, useEffect, useCallback, useMemo } from 'react';
import {
  FileCheck,
  ShieldAlert,
  ShieldCheck,
  FileWarning,
  Lock,
  Unlock,
  RotateCcw,
  Trash2,
  Play,
  RefreshCw,
  Fingerprint,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Terminal,
  FileCode,
  Activity,
  Search,
  Eye,
  Power,
  Hash,
  Clock,
  Layers
} from 'lucide-react';

// =============================================================================
// CRYPTOGRAPHIC FILE INTEGRITY MONITORING (FIM) & PROCESS FORENSICS PANEL
// Mirrors the server-side contract exposed by server/services/fim.service.ts
// through the /api/v1/fim/* endpoints.
// =============================================================================

export type FimChangeType = 'CREATE' | 'MODIFY' | 'DELETE' | 'PERMISSION_CHANGE';
export type FimSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
export type FimAlertStatus = 'DETECTED' | 'QUARANTINED' | 'ROLLEDBACK' | 'DISMISSED';

export interface FimAlert {
  id: string;
  timestamp: string;
  filePath: string;
  fileName: string;
  changeType: FimChangeType;
  previousHash: string;
  currentHash: string;
  diffSnippet: string;
  threatCategory: string;
  severity: FimSeverity;
  threatScore: number;
  mitreTechnique: string;
  aiAnalyzed: boolean;
  intentClassification: string;
  analysisEn: string;
  analysisAr: string;
  status: FimAlertStatus;
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

export interface FimStatus {
  active: boolean;
  monitoredDirectory: string;
  monitoredFilesCount: number;
  totalAlerts: number;
  criticalAlerts: number;
  quarantinedCount: number;
}

export interface FileIntegrityProcessPanelProps {
  lang: 'ar' | 'en';
}

const SEVERITY_STYLES: Record<FimSeverity, string> = {
  CRITICAL: 'bg-rose-950/80 text-rose-300 border-rose-600/50',
  HIGH: 'bg-orange-950/80 text-orange-300 border-orange-600/50',
  MEDIUM: 'bg-amber-950/80 text-amber-300 border-amber-600/50',
  LOW: 'bg-sky-950/80 text-sky-300 border-sky-600/50'
};

const FILE_STATUS_STYLES: Record<FimMonitoredFile['status'], string> = {
  INTACT: 'bg-emerald-950/70 text-emerald-300 border-emerald-700/50',
  TAMPERED: 'bg-rose-950/70 text-rose-300 border-rose-700/50',
  QUARANTINED: 'bg-purple-950/70 text-purple-300 border-purple-700/50',
  DELETED: 'bg-slate-800 text-slate-400 border-slate-700'
};

const ALERT_STATUS_STYLES: Record<FimAlertStatus, string> = {
  DETECTED: 'bg-rose-500/20 text-rose-300 border-rose-500/40',
  QUARANTINED: 'bg-purple-500/20 text-purple-300 border-purple-500/40',
  ROLLEDBACK: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40',
  DISMISSED: 'bg-slate-700/40 text-slate-400 border-slate-600/40'
};

const CATEGORY_LABELS: Record<FimMonitoredFile['category'], { en: string; ar: string }> = {
  CONFIG: { en: 'Config', ar: 'تكوين' },
  AUTH: { en: 'Auth', ar: 'صلاحيات' },
  SYSTEM: { en: 'System', ar: 'نظام' },
  SCRIPT: { en: 'Script', ar: 'برمجي' },
  WEB: { en: 'Web', ar: 'ويب' }
};

function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return '0 B';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

function shortHash(hash: string | undefined): string {
  if (!hash) return '--';
  return hash.length > 16 ? `${hash.substring(0, 16)}…` : hash;
}

export const FileIntegrityProcessPanel: React.FC<FileIntegrityProcessPanelProps> = ({ lang }) => {
  const isAr = lang === 'ar';

  const [status, setStatus] = useState<FimStatus | null>(null);
  const [files, setFiles] = useState<FimMonitoredFile[]>([]);
  const [alerts, setAlerts] = useState<FimAlert[]>([]);
  const [selectedAlert, setSelectedAlert] = useState<FimAlert | null>(null);

  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [busyAlertId, setBusyAlertId] = useState<string | null>(null);
  const [isSimulating, setIsSimulating] = useState<boolean>(false);
  const [isTogglingWatcher, setIsTogglingWatcher] = useState<boolean>(false);
  const [feedback, setFeedback] = useState<{ type: 'success' | 'error'; message: string } | null>(null);

  const [searchQuery, setSearchQuery] = useState<string>('');
  const [severityFilter, setSeverityFilter] = useState<'ALL' | FimSeverity>('ALL');

  // ---------------------------------------------------------------------
  // Data loading
  // ---------------------------------------------------------------------
  const fetchAll = useCallback(async (showSpinner: boolean = false) => {
    if (showSpinner) setIsLoading(true);
    try {
      const [statusRes, filesRes, alertsRes] = await Promise.all([
        fetch('/api/v1/fim/status'),
        fetch('/api/v1/fim/files'),
        fetch('/api/v1/fim/alerts')
      ]);

      if (statusRes.ok) {
        const data = await statusRes.json();
        if (data && data.success !== false) {
          const { success, ...rest } = data;
          setStatus(rest as FimStatus);
        }
      }
      if (filesRes.ok) {
        const data = await filesRes.json();
        if (Array.isArray(data.files)) setFiles(data.files);
      }
      if (alertsRes.ok) {
        const data = await alertsRes.json();
        if (Array.isArray(data.alerts)) setAlerts(data.alerts);
      }
    } catch (err) {
      console.warn('FIM panel fetch error:', err);
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchAll(true);
  }, [fetchAll]);

  // Live polling so tamper events surface without a manual refresh.
  useEffect(() => {
    const interval = setInterval(() => fetchAll(false), 6000);
    return () => clearInterval(interval);
  }, [fetchAll]);

  // Keep the open detail pane in sync with refreshed alert data.
  useEffect(() => {
    if (!selectedAlert) return;
    const latest = alerts.find(a => a.id === selectedAlert.id);
    if (latest && latest.status !== selectedAlert.status) {
      setSelectedAlert(latest);
    }
  }, [alerts, selectedAlert]);

  // ---------------------------------------------------------------------
  // Actions
  // ---------------------------------------------------------------------
  const postJson = async (url: string, body: Record<string, unknown>) => {
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
    return { ok: res.ok, data: await res.json().catch(() => ({})) };
  };

  const handleAlertAction = async (alertId: string, action: 'quarantine' | 'rollback' | 'dismiss') => {
    setBusyAlertId(alertId);
    setFeedback(null);
    try {
      const { ok, data } = await postJson(`/api/v1/fim/${action}`, { alertId });
      if (ok && data.success) {
        setFeedback({ type: 'success', message: data.message || (isAr ? 'تم تنفيذ الإجراء بنجاح.' : 'Action completed successfully.') });
        await fetchAll(false);
      } else {
        setFeedback({
          type: 'error',
          message: data.message || data.error || (isAr ? 'تعذر تنفيذ الإجراء.' : 'The action could not be completed.')
        });
      }
    } catch (err) {
      setFeedback({ type: 'error', message: isAr ? 'فشل الاتصال بخدمة مراقبة التكامل.' : 'Failed to reach the file integrity service.' });
    } finally {
      setBusyAlertId(null);
    }
  };

  const handleSimulateTamper = async (type: 'WEBSHELL' | 'SUDOERS' | 'BACKDOOR' | 'DELETION') => {
    setIsSimulating(true);
    setFeedback(null);
    try {
      const { ok, data } = await postJson('/api/v1/fim/simulate-tamper', { type });
      if (ok && data.success) {
        setFeedback({ type: 'success', message: data.message || (isAr ? 'تم توليد حدث العبث بنجاح.' : 'Tamper event generated.') });
        await fetchAll(false);
      } else {
        setFeedback({
          type: 'error',
          message: data.message || (isAr ? 'تعذر توليد حدث العبث.' : 'Could not generate the tamper event.')
        });
      }
    } catch (err) {
      setFeedback({ type: 'error', message: isAr ? 'فشل الاتصال بخدمة المحاكاة.' : 'Failed to reach the simulation service.' });
    } finally {
      setIsSimulating(false);
    }
  };

  const handleToggleWatcher = async () => {
    if (!status) return;
    setIsTogglingWatcher(true);
    setFeedback(null);
    try {
      const { ok, data } = await postJson('/api/v1/fim/toggle', { enabled: !status.active });
      if (ok && data.success) {
        setFeedback({ type: 'success', message: data.message || (isAr ? 'تم تحديث حالة المراقب.' : 'Watcher state updated.') });
        await fetchAll(false);
      } else {
        setFeedback({ type: 'error', message: data.message || (isAr ? 'تعذر تبديل حالة المراقب.' : 'Could not toggle the watcher.') });
      }
    } catch (err) {
      setFeedback({ type: 'error', message: isAr ? 'فشل الاتصال بالمراقب.' : 'Failed to reach the watcher.' });
    } finally {
      setIsTogglingWatcher(false);
    }
  };

  // ---------------------------------------------------------------------
  // Derived data
  // ---------------------------------------------------------------------
  const filteredAlerts = useMemo(() => {
    let list = [...alerts];
    if (severityFilter !== 'ALL') {
      list = list.filter(a => a.severity === severityFilter);
    }
    const q = searchQuery.trim().toLowerCase();
    if (q) {
      list = list.filter(a =>
        a.fileName.toLowerCase().includes(q) ||
        a.filePath.toLowerCase().includes(q) ||
        a.threatCategory.toLowerCase().includes(q) ||
        a.mitreTechnique.toLowerCase().includes(q) ||
        a.intentClassification.toLowerCase().includes(q)
      );
    }
    return list.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
  }, [alerts, severityFilter, searchQuery]);

  const tamperedCount = useMemo(() => files.filter(f => f.status === 'TAMPERED').length, [files]);
  const intactCount = useMemo(() => files.filter(f => f.status === 'INTACT').length, [files]);
  const openAlertCount = useMemo(() => alerts.filter(a => a.status === 'DETECTED').length, [alerts]);

  const integrityPercent = useMemo(() => {
    if (files.length === 0) return 100;
    return Math.round((intactCount / files.length) * 100);
  }, [files.length, intactCount]);

  // ---------------------------------------------------------------------
  // Render
  // ---------------------------------------------------------------------
  return (
    <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-2xl backdrop-blur-md space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 pb-4 border-b border-slate-800">
        <div className="flex items-center gap-3">
          <div className="p-2.5 bg-gradient-to-br from-cyan-500/20 to-emerald-500/20 border border-cyan-500/30 rounded-lg">
            <Fingerprint className={`w-5 h-5 text-cyan-400 ${status?.active ? 'animate-pulse' : ''}`} />
          </div>
          <div>
            <div className="flex items-center gap-2 flex-wrap">
              <h3 className="text-base font-bold text-slate-100">
                {isAr
                  ? 'مراقبة تكامل الملفات التشفيرية والتحليل الجنائي للعمليات'
                  : 'Cryptographic File Integrity & Process Forensics'}
              </h3>
              <span
                className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                  status?.active
                    ? 'bg-emerald-950/80 text-emerald-300 border-emerald-700/50'
                    : 'bg-slate-800 text-slate-400 border-slate-700'
                }`}
              >
                {status?.active ? (isAr ? 'المراقب نشط' : 'Watcher Active') : (isAr ? 'المراقب متوقف' : 'Watcher Idle')}
              </span>
            </div>
            <p className="text-xs text-slate-400">
              {isAr
                ? 'بصمات SHA-256 وشجرة ميركل للكشف الفوري عن أي تعديل غير مصرح به على ملفات النظام الحساسة'
                : 'SHA-256 baselines and Merkle-tree hashing detect unauthorized changes to sensitive system files in real time.'}
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={handleToggleWatcher}
            disabled={isTogglingWatcher || !status}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold border transition flex items-center gap-1.5 disabled:opacity-50 ${
              status?.active
                ? 'bg-rose-950/60 hover:bg-rose-900/80 text-rose-200 border-rose-800/60'
                : 'bg-emerald-950/60 hover:bg-emerald-900/80 text-emerald-200 border-emerald-800/60'
            }`}
          >
            <Power className="w-3.5 h-3.5" />
            <span>
              {status?.active ? (isAr ? 'إيقاف المراقب' : 'Disable Watcher') : (isAr ? 'تشغيل المراقب' : 'Enable Watcher')}
            </span>
          </button>
          <button
            onClick={() => fetchAll(true)}
            className="p-1.5 rounded-lg bg-slate-800 text-slate-400 hover:text-slate-200 transition"
            title={isAr ? 'تحديث' : 'Refresh'}
          >
            <RefreshCw className={`w-4 h-4 ${isLoading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* Metric tiles */}
      <div className="grid grid-cols-2 lg:grid-cols-5 gap-3">
        <div className="p-3 bg-slate-950/80 border border-slate-800 rounded-xl">
          <div className="flex items-center gap-1.5 text-[11px] text-slate-400">
            <Layers className="w-3.5 h-3.5 text-cyan-400" />
            <span>{isAr ? 'ملفات مراقبة' : 'Monitored'}</span>
          </div>
          <div className="text-xl font-bold text-slate-100 font-mono mt-1">{status?.monitoredFilesCount ?? files.length}</div>
        </div>

        <div className="p-3 bg-slate-950/80 border border-slate-800 rounded-xl">
          <div className="flex items-center gap-1.5 text-[11px] text-slate-400">
            <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
            <span>{isAr ? 'سليمة' : 'Intact'}</span>
          </div>
          <div className="text-xl font-bold text-emerald-300 font-mono mt-1">{intactCount}</div>
        </div>

        <div className="p-3 bg-slate-950/80 border border-slate-800 rounded-xl">
          <div className="flex items-center gap-1.5 text-[11px] text-slate-400">
            <FileWarning className="w-3.5 h-3.5 text-rose-400" />
            <span>{isAr ? 'تم العبث بها' : 'Tampered'}</span>
          </div>
          <div className="text-xl font-bold text-rose-300 font-mono mt-1">{tamperedCount}</div>
        </div>

        <div className="p-3 bg-slate-950/80 border border-slate-800 rounded-xl">
          <div className="flex items-center gap-1.5 text-[11px] text-slate-400">
            <Lock className="w-3.5 h-3.5 text-purple-400" />
            <span>{isAr ? 'معزولة' : 'Quarantined'}</span>
          </div>
          <div className="text-xl font-bold text-purple-300 font-mono mt-1">{status?.quarantinedCount ?? 0}</div>
        </div>

        <div className="p-3 bg-slate-950/80 border border-slate-800 rounded-xl">
          <div className="flex items-center gap-1.5 text-[11px] text-slate-400">
            <Activity className="w-3.5 h-3.5 text-amber-400" />
            <span>{isAr ? 'نسبة التكامل' : 'Integrity'}</span>
          </div>
          <div
            className={`text-xl font-bold font-mono mt-1 ${
              integrityPercent >= 90 ? 'text-emerald-300' : integrityPercent >= 70 ? 'text-amber-300' : 'text-rose-300'
            }`}
          >
            {integrityPercent}%
          </div>
        </div>
      </div>

      {/* Adversarial tamper drills */}
      <div className="p-4 bg-slate-950/80 border border-slate-800 rounded-xl space-y-2">
        <div className="flex items-center justify-between flex-wrap gap-2">
          <div className="flex items-center gap-2 text-xs font-bold text-slate-300">
            <Terminal className="w-4 h-4 text-cyan-400" />
            <span>{isAr ? 'محاكاة هجمات العبث بالملفات الحساسة' : 'Simulate File Tamper Attacks'}</span>
          </div>
          <span className="text-[11px] text-slate-500">
            {isAr ? 'يولّد حدثاً حقيقياً في صندوق الاختبار المعزول' : 'Generates a real event inside the isolated sandbox'}
          </span>
        </div>

        <div className="flex flex-wrap items-center gap-2 pt-1">
          <button
            onClick={() => handleSimulateTamper('WEBSHELL')}
            disabled={isSimulating}
            className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-rose-950/60 hover:bg-rose-900/80 text-rose-200 border border-rose-800/60 transition flex items-center gap-1.5 disabled:opacity-50"
          >
            <FileCode className="w-3.5 h-3.5 text-rose-400" />
            <span>{isAr ? 'زرع قذيفة ويب PHP' : 'Plant PHP WebShell'}</span>
          </button>

          <button
            onClick={() => handleSimulateTamper('SUDOERS')}
            disabled={isSimulating}
            className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-amber-950/60 hover:bg-amber-900/80 text-amber-200 border border-amber-800/60 transition flex items-center gap-1.5 disabled:opacity-50"
          >
            <Unlock className="w-3.5 h-3.5 text-amber-400" />
            <span>{isAr ? 'تعديل ملف sudoers' : 'Modify sudoers'}</span>
          </button>

          <button
            onClick={() => handleSimulateTamper('BACKDOOR')}
            disabled={isSimulating}
            className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-purple-950/60 hover:bg-purple-900/80 text-purple-200 border border-purple-800/60 transition flex items-center gap-1.5 disabled:opacity-50"
          >
            <ShieldAlert className="w-3.5 h-3.5 text-purple-400" />
            <span>{isAr ? 'تثبيت باب خلفي' : 'Install Backdoor'}</span>
          </button>

          <button
            onClick={() => handleSimulateTamper('DELETION')}
            disabled={isSimulating}
            className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-slate-800/80 hover:bg-slate-700/80 text-slate-200 border border-slate-700 transition flex items-center gap-1.5 disabled:opacity-50"
          >
            <Trash2 className="w-3.5 h-3.5 text-slate-400" />
            <span>{isAr ? 'حذف ملف حرج' : 'Delete Critical File'}</span>
          </button>

          {isSimulating && (
            <span className="text-[11px] text-cyan-300 flex items-center gap-1.5">
              <Play className="w-3.5 h-3.5 animate-pulse" />
              {isAr ? 'جارٍ التنفيذ…' : 'Running…'}
            </span>
          )}
        </div>
      </div>

      {/* Feedback banner */}
      {feedback && (
        <div
          className={`p-3 rounded-xl border text-xs flex items-start gap-2.5 ${
            feedback.type === 'success'
              ? 'bg-emerald-950/60 border-emerald-700/50 text-emerald-200'
              : 'bg-rose-950/60 border-rose-700/50 text-rose-200'
          }`}
        >
          {feedback.type === 'success' ? (
            <CheckCircle2 className="w-4 h-4 shrink-0 mt-0.5" />
          ) : (
            <XCircle className="w-4 h-4 shrink-0 mt-0.5" />
          )}
          <span className="flex-1">{feedback.message}</span>
          <button onClick={() => setFeedback(null)} className="text-slate-400 hover:text-slate-200">
            <XCircle className="w-3.5 h-3.5" />
          </button>
        </div>
      )}

      {/* Monitored baseline table */}
      <div className="space-y-2">
        <div className="flex items-center gap-2 text-xs font-bold text-slate-300">
          <FileCheck className="w-4 h-4 text-emerald-400" />
          <span>{isAr ? 'خط الأساس التشفيري للملفات المراقبة' : 'Cryptographic Baseline of Monitored Files'}</span>
          {status?.monitoredDirectory && (
            <span className="text-[10px] font-mono text-slate-500 truncate max-w-[280px]" title={status.monitoredDirectory}>
              {status.monitoredDirectory}
            </span>
          )}
        </div>

        <div className="overflow-x-auto border border-slate-800 rounded-xl">
          <table className="w-full text-xs min-w-[720px]">
            <thead className="bg-slate-950/80 text-slate-400">
              <tr>
                <th className="text-start px-3 py-2 font-semibold">{isAr ? 'الملف' : 'File'}</th>
                <th className="text-start px-3 py-2 font-semibold">{isAr ? 'الفئة' : 'Category'}</th>
                <th className="text-start px-3 py-2 font-semibold">{isAr ? 'بصمة SHA-256' : 'SHA-256'}</th>
                <th className="text-start px-3 py-2 font-semibold">{isAr ? 'الحجم' : 'Size'}</th>
                <th className="text-start px-3 py-2 font-semibold">{isAr ? 'الحالة' : 'Status'}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/80">
              {files.length === 0 && (
                <tr>
                  <td colSpan={5} className="px-3 py-6 text-center text-slate-500">
                    {isLoading ? (isAr ? 'جارٍ التحميل…' : 'Loading…') : (isAr ? 'لا توجد ملفات مراقبة حالياً.' : 'No monitored files yet.')}
                  </td>
                </tr>
              )}
              {files.map(file => (
                <tr key={file.path} className="hover:bg-slate-800/40 transition">
                  <td className="px-3 py-2">
                    <div className="font-semibold text-slate-200">{file.name}</div>
                    <div className="text-[10px] font-mono text-slate-500 truncate max-w-[240px]" title={file.path}>
                      {file.path}
                    </div>
                  </td>
                  <td className="px-3 py-2">
                    <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-slate-800 text-slate-300 border border-slate-700">
                      {isAr ? CATEGORY_LABELS[file.category]?.ar ?? file.category : CATEGORY_LABELS[file.category]?.en ?? file.category}
                    </span>
                  </td>
                  <td className="px-3 py-2">
                    <div className="flex items-center gap-1.5 font-mono text-[10px] text-cyan-300/90">
                      <Hash className="w-3 h-3 text-slate-600 shrink-0" />
                      <span title={file.sha256}>{shortHash(file.sha256)}</span>
                    </div>
                    {file.rollingChunksCount !== undefined && (
                      <div className="text-[10px] text-slate-600">
                        {isAr ? `${file.rollingChunksCount} كتلة ميركل` : `${file.rollingChunksCount} Merkle chunks`}
                      </div>
                    )}
                  </td>
                  <td className="px-3 py-2 font-mono text-slate-400">{formatBytes(file.sizeBytes)}</td>
                  <td className="px-3 py-2">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${FILE_STATUS_STYLES[file.status]}`}>
                      {file.status}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Alert stream + detail */}
      <div className="space-y-2">
        <div className="flex items-center justify-between gap-2 flex-wrap">
          <div className="flex items-center gap-2 text-xs font-bold text-slate-300">
            <ShieldAlert className="w-4 h-4 text-rose-400" />
            <span>{isAr ? 'تنبيهات العبث المكتشفة' : 'Detected Tamper Alerts'}</span>
            {openAlertCount > 0 && (
              <span className="px-2 py-0.5 rounded-full text-[10px] font-mono font-bold bg-rose-500/20 text-rose-300 border border-rose-500/40 animate-pulse">
                {openAlertCount} {isAr ? 'مفتوح' : 'open'}
              </span>
            )}
          </div>

          <div className="flex items-center gap-2">
            <div className="relative">
              <Search className="w-3.5 h-3.5 text-slate-500 absolute start-2.5 top-1/2 -translate-y-1/2 pointer-events-none" />
              <input
                value={searchQuery}
                onChange={e => setSearchQuery(e.target.value)}
                placeholder={isAr ? 'بحث في التنبيهات…' : 'Search alerts…'}
                className="ps-8 pe-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-cyan-700 w-44"
              />
            </div>
            <select
              value={severityFilter}
              onChange={e => setSeverityFilter(e.target.value as 'ALL' | FimSeverity)}
              className="px-2 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-300 focus:outline-none focus:border-cyan-700"
            >
              <option value="ALL">{isAr ? 'كل الدرجات' : 'All severities'}</option>
              <option value="CRITICAL">CRITICAL</option>
              <option value="HIGH">HIGH</option>
              <option value="MEDIUM">MEDIUM</option>
              <option value="LOW">LOW</option>
            </select>
          </div>
        </div>

        <div className="grid grid-cols-1 xl:grid-cols-2 gap-3">
          {/* Alert list */}
          <div className="space-y-2 max-h-[430px] overflow-y-auto pe-1">
            {filteredAlerts.length === 0 && (
              <div className="p-6 text-center text-xs text-slate-500 bg-slate-950/60 border border-slate-800 rounded-xl">
                {isLoading
                  ? (isAr ? 'جارٍ التحميل…' : 'Loading…')
                  : (isAr ? 'لا توجد تنبيهات مطابقة. النظام سليم.' : 'No matching alerts. System integrity holding.')}
              </div>
            )}

            {filteredAlerts.map(alert => {
              const isSelected = selectedAlert?.id === alert.id;
              const isBusy = busyAlertId === alert.id;
              return (
                <div
                  key={alert.id}
                  onClick={() => setSelectedAlert(alert)}
                  className={`p-3 rounded-xl border cursor-pointer transition ${
                    isSelected
                      ? 'bg-slate-800/70 border-cyan-600/60'
                      : 'bg-slate-950/70 border-slate-800 hover:border-slate-700'
                  }`}
                >
                  <div className="flex items-start justify-between gap-2">
                    <div className="min-w-0">
                      <div className="flex items-center gap-1.5 flex-wrap">
                        <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold border ${SEVERITY_STYLES[alert.severity]}`}>
                          {alert.severity}
                        </span>
                        <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-slate-800 text-slate-300 border border-slate-700">
                          {alert.changeType}
                        </span>
                        <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold border ${ALERT_STATUS_STYLES[alert.status]}`}>
                          {alert.status}
                        </span>
                      </div>
                      <div className="text-xs font-bold text-slate-200 mt-1 truncate" title={alert.fileName}>
                        {alert.fileName}
                      </div>
                      <div className="text-[10px] text-slate-500 truncate" title={alert.filePath}>
                        {alert.filePath}
                      </div>
                      <div className="text-[11px] text-slate-400 mt-1">
                        {alert.intentClassification} · <span className="font-mono text-amber-300/90">{alert.mitreTechnique}</span>
                      </div>
                    </div>

                    <div className="text-end shrink-0">
                      <div className="text-sm font-bold font-mono text-rose-300">{alert.threatScore}</div>
                      <div className="text-[10px] text-slate-600">/100</div>
                    </div>
                  </div>

                  {/* Action row - only meaningful while the alert is still open */}
                  {alert.status === 'DETECTED' && (
                    <div className="flex items-center gap-1.5 mt-2 pt-2 border-t border-slate-800">
                      <button
                        onClick={e => { e.stopPropagation(); handleAlertAction(alert.id, 'quarantine'); }}
                        disabled={isBusy}
                        className="px-2 py-1 rounded-lg text-[11px] font-semibold bg-purple-950/60 hover:bg-purple-900/80 text-purple-200 border border-purple-800/60 transition flex items-center gap-1 disabled:opacity-50"
                      >
                        <Lock className="w-3 h-3" />
                        {isAr ? 'عزل' : 'Quarantine'}
                      </button>
                      <button
                        onClick={e => { e.stopPropagation(); handleAlertAction(alert.id, 'rollback'); }}
                        disabled={isBusy}
                        className="px-2 py-1 rounded-lg text-[11px] font-semibold bg-emerald-950/60 hover:bg-emerald-900/80 text-emerald-200 border border-emerald-800/60 transition flex items-center gap-1 disabled:opacity-50"
                      >
                        <RotateCcw className="w-3 h-3" />
                        {isAr ? 'استرجاع' : 'Rollback'}
                      </button>
                      <button
                        onClick={e => { e.stopPropagation(); handleAlertAction(alert.id, 'dismiss'); }}
                        disabled={isBusy}
                        className="px-2 py-1 rounded-lg text-[11px] font-semibold bg-slate-800/80 hover:bg-slate-700/80 text-slate-300 border border-slate-700 transition flex items-center gap-1 disabled:opacity-50"
                      >
                        <XCircle className="w-3 h-3" />
                        {isAr ? 'تجاهل' : 'Dismiss'}
                      </button>
                      {isBusy && <RefreshCw className="w-3 h-3 text-cyan-400 animate-spin" />}
                    </div>
                  )}
                </div>
              );
            })}
          </div>

          {/* Detail pane */}
          <div className="bg-slate-950/70 border border-slate-800 rounded-xl p-4 max-h-[430px] overflow-y-auto">
            {selectedAlert ? (
              <div className="space-y-3">
                <div className="flex items-center justify-between gap-2 pb-2 border-b border-slate-800">
                  <div className="flex items-center gap-2 text-xs font-bold text-slate-200">
                    <Eye className="w-4 h-4 text-cyan-400" />
                    <span>{isAr ? 'تفاصيل التنبيه الجنائية' : 'Forensic Alert Detail'}</span>
                  </div>
                  <span className="text-[10px] font-mono text-slate-500">{selectedAlert.id}</span>
                </div>

                <div className="grid grid-cols-2 gap-2 text-[11px]">
                  <div>
                    <div className="text-slate-500">{isAr ? 'التصنيف' : 'Category'}</div>
                    <div className="text-slate-200 font-semibold">{selectedAlert.threatCategory}</div>
                  </div>
                  <div>
                    <div className="text-slate-500">{isAr ? 'تقنية MITRE' : 'MITRE Technique'}</div>
                    <div className="text-amber-300 font-mono">{selectedAlert.mitreTechnique}</div>
                  </div>
                  <div>
                    <div className="text-slate-500">{isAr ? 'وقت الرصد' : 'Detected At'}</div>
                    <div className="text-slate-300 font-mono flex items-center gap-1">
                      <Clock className="w-3 h-3 text-slate-600" />
                      {new Date(selectedAlert.timestamp).toLocaleString(isAr ? 'ar' : 'en')}
                    </div>
                  </div>
                  <div>
                    <div className="text-slate-500">{isAr ? 'تحليل الذكاء الاصطناعي' : 'AI Analyzed'}</div>
                    <div className={selectedAlert.aiAnalyzed ? 'text-emerald-300' : 'text-slate-400'}>
                      {selectedAlert.aiAnalyzed ? (isAr ? 'نعم' : 'Yes') : (isAr ? 'لا' : 'No')}
                    </div>
                  </div>
                </div>

                {/* Hash transition */}
                <div className="space-y-1">
                  <div className="text-[11px] text-slate-500">{isAr ? 'تغيّر البصمة التشفيرية' : 'Cryptographic Hash Transition'}</div>
                  <div className="p-2 rounded-lg bg-slate-900 border border-slate-800 font-mono text-[10px] space-y-1">
                    <div className="flex items-center gap-1.5">
                      <span className="text-slate-600 w-12 shrink-0">{isAr ? 'قبل' : 'before'}</span>
                      <span className="text-emerald-300/80 break-all">{selectedAlert.previousHash || '--'}</span>
                    </div>
                    <div className="flex items-center gap-1.5">
                      <span className="text-slate-600 w-12 shrink-0">{isAr ? 'بعد' : 'after'}</span>
                      <span className="text-rose-300/90 break-all">{selectedAlert.currentHash || '--'}</span>
                    </div>
                  </div>
                </div>

                {/* Diff */}
                {selectedAlert.diffSnippet && (
                  <div className="space-y-1">
                    <div className="text-[11px] text-slate-500">{isAr ? 'مقتطف التغيير' : 'Change Diff'}</div>
                    <pre className="p-2 rounded-lg bg-slate-900 border border-slate-800 text-[10px] text-slate-300 overflow-x-auto whitespace-pre-wrap break-all max-h-40">
                      {selectedAlert.diffSnippet}
                    </pre>
                  </div>
                )}

                {/* Narrative analysis */}
                <div className="space-y-1">
                  <div className="text-[11px] text-slate-500">{isAr ? 'التحليل التفسيري' : 'Analyst Narrative'}</div>
                  <p className="text-[11px] text-slate-300 leading-relaxed">
                    {isAr ? selectedAlert.analysisAr || selectedAlert.analysisEn : selectedAlert.analysisEn}
                  </p>
                </div>

                {selectedAlert.quarantinedPath && (
                  <div className="p-2 rounded-lg bg-purple-950/40 border border-purple-800/50 text-[11px] text-purple-200 flex items-start gap-1.5">
                    <Lock className="w-3.5 h-3.5 shrink-0 mt-0.5" />
                    <span className="font-mono break-all">{selectedAlert.quarantinedPath}</span>
                  </div>
                )}
              </div>
            ) : (
              <div className="h-full min-h-[200px] flex flex-col items-center justify-center text-center text-slate-500 gap-2">
                <AlertTriangle className="w-8 h-8 text-slate-700" />
                <p className="text-xs">
                  {isAr
                    ? 'اختر تنبيهاً من القائمة لعرض الأدلة الجنائية الكاملة.'
                    : 'Select an alert to inspect its full forensic evidence.'}
                </p>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default FileIntegrityProcessPanel;
