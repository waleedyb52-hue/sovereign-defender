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
  const [feedback, setFeedback] = useState<{ type: 'success' | 'error'; message: string } | null>(
    null
  );

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

  const handleAlertAction = async (
    alertId: string,
    action: 'quarantine' | 'rollback' | 'dismiss'
  ) => {
    setBusyAlertId(alertId);
    setFeedback(null);
    try {
      const { ok, data } = await postJson(`/api/v1/fim/${action}`, { alertId });
      if (ok && data.success) {
        setFeedback({
          type: 'success',
          message:
            data.message || (isAr ? 'تم تنفيذ الإجراء بنجاح.' : 'Action completed successfully.')
        });
        await fetchAll(false);
      } else {
        setFeedback({
          type: 'error',
          message:
            data.message ||
            data.error ||
            (isAr ? 'تعذر تنفيذ الإجراء.' : 'The action could not be completed.')
        });
      }
    } catch (err) {
      setFeedback({
        type: 'error',
        message: isAr
          ? 'فشل الاتصال بخدمة مراقبة التكامل.'
          : 'Failed to reach the file integrity service.'
      });
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
        setFeedback({
          type: 'success',
          message: data.message || (isAr ? 'تم توليد حدث العبث بنجاح.' : 'Tamper event generated.')
        });
        await fetchAll(false);
      } else {
        setFeedback({
          type: 'error',
          message:
            data.message ||
            (isAr ? 'تعذر توليد حدث العبث.' : 'Could not generate the tamper event.')
        });
      }
    } catch (err) {
      setFeedback({
        type: 'error',
        message: isAr ? 'فشل الاتصال بخدمة المحاكاة.' : 'Failed to reach the simulation service.'
      });
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
        setFeedback({
          type: 'success',
          message: data.message || (isAr ? 'تم تحديث حالة المراقب.' : 'Watcher state updated.')
        });
        await fetchAll(false);
      } else {
        setFeedback({
          type: 'error',
          message:
            data.message || (isAr ? 'تعذر تبديل حالة المراقب.' : 'Could not toggle the watcher.')
        });
      }
    } catch (err) {
      setFeedback({
        type: 'error',
        message: isAr ? 'فشل الاتصال بالمراقب.' : 'Failed to reach the watcher.'
      });
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
      list = list.filter(
        a =>
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
  const openAlertCount = useMemo(
    () => alerts.filter(a => a.status === 'DETECTED').length,
    [alerts]
  );

  const integrityPercent = useMemo(() => {
    if (files.length === 0) return 100;
    return Math.round((intactCount / files.length) * 100);
  }, [files.length, intactCount]);

  // ---------------------------------------------------------------------
  // Render
  // ---------------------------------------------------------------------
  return (
    <div className="space-y-6 rounded-xl border border-slate-800 bg-slate-900/90 p-5 shadow-2xl backdrop-blur-md">
      {/* Header */}
      <div className="flex flex-col items-start justify-between gap-4 border-b border-slate-800 pb-4 md:flex-row md:items-center">
        <div className="flex items-center gap-3">
          <div className="rounded-lg border border-cyan-500/30 bg-gradient-to-br from-cyan-500/20 to-emerald-500/20 p-2.5">
            <Fingerprint
              className={`h-5 w-5 text-cyan-400 ${status?.active ? 'animate-pulse' : ''}`}
            />
          </div>
          <div>
            <div className="flex flex-wrap items-center gap-2">
              <h3 className="text-base font-bold text-slate-100">
                {isAr
                  ? 'مراقبة تكامل الملفات التشفيرية والتحليل الجنائي للعمليات'
                  : 'Cryptographic File Integrity & Process Forensics'}
              </h3>
              <span
                className={`rounded border px-2 py-0.5 text-[10px] font-bold ${
                  status?.active
                    ? 'border-emerald-700/50 bg-emerald-950/80 text-emerald-300'
                    : 'border-slate-700 bg-slate-800 text-slate-400'
                }`}
              >
                {status?.active
                  ? isAr
                    ? 'المراقب نشط'
                    : 'Watcher Active'
                  : isAr
                    ? 'المراقب متوقف'
                    : 'Watcher Idle'}
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
            className={`flex items-center gap-1.5 rounded-lg border px-3 py-1.5 text-xs font-semibold transition disabled:opacity-50 ${
              status?.active
                ? 'border-rose-800/60 bg-rose-950/60 text-rose-200 hover:bg-rose-900/80'
                : 'border-emerald-800/60 bg-emerald-950/60 text-emerald-200 hover:bg-emerald-900/80'
            }`}
          >
            <Power className="h-3.5 w-3.5" />
            <span>
              {status?.active
                ? isAr
                  ? 'إيقاف المراقب'
                  : 'Disable Watcher'
                : isAr
                  ? 'تشغيل المراقب'
                  : 'Enable Watcher'}
            </span>
          </button>
          <button
            onClick={() => fetchAll(true)}
            className="rounded-lg bg-slate-800 p-1.5 text-slate-400 transition hover:text-slate-200"
            title={isAr ? 'تحديث' : 'Refresh'}
          >
            <RefreshCw className={`h-4 w-4 ${isLoading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* Metric tiles */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-5">
        <div className="rounded-xl border border-slate-800 bg-slate-950/80 p-3">
          <div className="flex items-center gap-1.5 text-[11px] text-slate-400">
            <Layers className="h-3.5 w-3.5 text-cyan-400" />
            <span>{isAr ? 'ملفات مراقبة' : 'Monitored'}</span>
          </div>
          <div className="mt-1 font-mono text-xl font-bold text-slate-100">
            {status?.monitoredFilesCount ?? files.length}
          </div>
        </div>

        <div className="rounded-xl border border-slate-800 bg-slate-950/80 p-3">
          <div className="flex items-center gap-1.5 text-[11px] text-slate-400">
            <ShieldCheck className="h-3.5 w-3.5 text-emerald-400" />
            <span>{isAr ? 'سليمة' : 'Intact'}</span>
          </div>
          <div className="mt-1 font-mono text-xl font-bold text-emerald-300">{intactCount}</div>
        </div>

        <div className="rounded-xl border border-slate-800 bg-slate-950/80 p-3">
          <div className="flex items-center gap-1.5 text-[11px] text-slate-400">
            <FileWarning className="h-3.5 w-3.5 text-rose-400" />
            <span>{isAr ? 'تم العبث بها' : 'Tampered'}</span>
          </div>
          <div className="mt-1 font-mono text-xl font-bold text-rose-300">{tamperedCount}</div>
        </div>

        <div className="rounded-xl border border-slate-800 bg-slate-950/80 p-3">
          <div className="flex items-center gap-1.5 text-[11px] text-slate-400">
            <Lock className="h-3.5 w-3.5 text-purple-400" />
            <span>{isAr ? 'معزولة' : 'Quarantined'}</span>
          </div>
          <div className="mt-1 font-mono text-xl font-bold text-purple-300">
            {status?.quarantinedCount ?? 0}
          </div>
        </div>

        <div className="rounded-xl border border-slate-800 bg-slate-950/80 p-3">
          <div className="flex items-center gap-1.5 text-[11px] text-slate-400">
            <Activity className="h-3.5 w-3.5 text-amber-400" />
            <span>{isAr ? 'نسبة التكامل' : 'Integrity'}</span>
          </div>
          <div
            className={`mt-1 font-mono text-xl font-bold ${
              integrityPercent >= 90
                ? 'text-emerald-300'
                : integrityPercent >= 70
                  ? 'text-amber-300'
                  : 'text-rose-300'
            }`}
          >
            {integrityPercent}%
          </div>
        </div>
      </div>

      {/* Adversarial tamper drills */}
      <div className="space-y-2 rounded-xl border border-slate-800 bg-slate-950/80 p-4">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2 text-xs font-bold text-slate-300">
            <Terminal className="h-4 w-4 text-cyan-400" />
            <span>
              {isAr ? 'محاكاة هجمات العبث بالملفات الحساسة' : 'Simulate File Tamper Attacks'}
            </span>
          </div>
          <span className="text-[11px] text-slate-500">
            {isAr
              ? 'يولّد حدثاً حقيقياً في صندوق الاختبار المعزول'
              : 'Generates a real event inside the isolated sandbox'}
          </span>
        </div>

        <div className="flex flex-wrap items-center gap-2 pt-1">
          <button
            onClick={() => handleSimulateTamper('WEBSHELL')}
            disabled={isSimulating}
            className="flex items-center gap-1.5 rounded-lg border border-rose-800/60 bg-rose-950/60 px-3 py-1.5 text-xs font-semibold text-rose-200 transition hover:bg-rose-900/80 disabled:opacity-50"
          >
            <FileCode className="h-3.5 w-3.5 text-rose-400" />
            <span>{isAr ? 'زرع قذيفة ويب PHP' : 'Plant PHP WebShell'}</span>
          </button>

          <button
            onClick={() => handleSimulateTamper('SUDOERS')}
            disabled={isSimulating}
            className="flex items-center gap-1.5 rounded-lg border border-amber-800/60 bg-amber-950/60 px-3 py-1.5 text-xs font-semibold text-amber-200 transition hover:bg-amber-900/80 disabled:opacity-50"
          >
            <Unlock className="h-3.5 w-3.5 text-amber-400" />
            <span>{isAr ? 'تعديل ملف sudoers' : 'Modify sudoers'}</span>
          </button>

          <button
            onClick={() => handleSimulateTamper('BACKDOOR')}
            disabled={isSimulating}
            className="flex items-center gap-1.5 rounded-lg border border-purple-800/60 bg-purple-950/60 px-3 py-1.5 text-xs font-semibold text-purple-200 transition hover:bg-purple-900/80 disabled:opacity-50"
          >
            <ShieldAlert className="h-3.5 w-3.5 text-purple-400" />
            <span>{isAr ? 'تثبيت باب خلفي' : 'Install Backdoor'}</span>
          </button>

          <button
            onClick={() => handleSimulateTamper('DELETION')}
            disabled={isSimulating}
            className="flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800/80 px-3 py-1.5 text-xs font-semibold text-slate-200 transition hover:bg-slate-700/80 disabled:opacity-50"
          >
            <Trash2 className="h-3.5 w-3.5 text-slate-400" />
            <span>{isAr ? 'حذف ملف حرج' : 'Delete Critical File'}</span>
          </button>

          {isSimulating && (
            <span className="flex items-center gap-1.5 text-[11px] text-cyan-300">
              <Play className="h-3.5 w-3.5 animate-pulse" />
              {isAr ? 'جارٍ التنفيذ…' : 'Running…'}
            </span>
          )}
        </div>
      </div>

      {/* Feedback banner */}
      {feedback && (
        <div
          className={`flex items-start gap-2.5 rounded-xl border p-3 text-xs ${
            feedback.type === 'success'
              ? 'border-emerald-700/50 bg-emerald-950/60 text-emerald-200'
              : 'border-rose-700/50 bg-rose-950/60 text-rose-200'
          }`}
        >
          {feedback.type === 'success' ? (
            <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0" />
          ) : (
            <XCircle className="mt-0.5 h-4 w-4 shrink-0" />
          )}
          <span className="flex-1">{feedback.message}</span>
          <button onClick={() => setFeedback(null)} className="text-slate-400 hover:text-slate-200">
            <XCircle className="h-3.5 w-3.5" />
          </button>
        </div>
      )}

      {/* Monitored baseline table */}
      <div className="space-y-2">
        <div className="flex items-center gap-2 text-xs font-bold text-slate-300">
          <FileCheck className="h-4 w-4 text-emerald-400" />
          <span>
            {isAr
              ? 'خط الأساس التشفيري للملفات المراقبة'
              : 'Cryptographic Baseline of Monitored Files'}
          </span>
          {status?.monitoredDirectory && (
            <span
              className="max-w-[280px] truncate font-mono text-[10px] text-slate-500"
              title={status.monitoredDirectory}
            >
              {status.monitoredDirectory}
            </span>
          )}
        </div>

        <div className="overflow-x-auto rounded-xl border border-slate-800">
          <table className="w-full min-w-[720px] text-xs">
            <thead className="bg-slate-950/80 text-slate-400">
              <tr>
                <th className="px-3 py-2 text-start font-semibold">{isAr ? 'الملف' : 'File'}</th>
                <th className="px-3 py-2 text-start font-semibold">
                  {isAr ? 'الفئة' : 'Category'}
                </th>
                <th className="px-3 py-2 text-start font-semibold">
                  {isAr ? 'بصمة SHA-256' : 'SHA-256'}
                </th>
                <th className="px-3 py-2 text-start font-semibold">{isAr ? 'الحجم' : 'Size'}</th>
                <th className="px-3 py-2 text-start font-semibold">{isAr ? 'الحالة' : 'Status'}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/80">
              {files.length === 0 && (
                <tr>
                  <td colSpan={5} className="px-3 py-6 text-center text-slate-500">
                    {isLoading
                      ? isAr
                        ? 'جارٍ التحميل…'
                        : 'Loading…'
                      : isAr
                        ? 'لا توجد ملفات مراقبة حالياً.'
                        : 'No monitored files yet.'}
                  </td>
                </tr>
              )}
              {files.map(file => (
                <tr key={file.path} className="transition hover:bg-slate-800/40">
                  <td className="px-3 py-2">
                    <div className="font-semibold text-slate-200">{file.name}</div>
                    <div
                      className="max-w-[240px] truncate font-mono text-[10px] text-slate-500"
                      title={file.path}
                    >
                      {file.path}
                    </div>
                  </td>
                  <td className="px-3 py-2">
                    <span className="rounded border border-slate-700 bg-slate-800 px-2 py-0.5 text-[10px] font-bold text-slate-300">
                      {isAr
                        ? (CATEGORY_LABELS[file.category]?.ar ?? file.category)
                        : (CATEGORY_LABELS[file.category]?.en ?? file.category)}
                    </span>
                  </td>
                  <td className="px-3 py-2">
                    <div className="flex items-center gap-1.5 font-mono text-[10px] text-cyan-300/90">
                      <Hash className="h-3 w-3 shrink-0 text-slate-600" />
                      <span title={file.sha256}>{shortHash(file.sha256)}</span>
                    </div>
                    {file.rollingChunksCount !== undefined && (
                      <div className="text-[10px] text-slate-600">
                        {isAr
                          ? `${file.rollingChunksCount} كتلة ميركل`
                          : `${file.rollingChunksCount} Merkle chunks`}
                      </div>
                    )}
                  </td>
                  <td className="px-3 py-2 font-mono text-slate-400">
                    {formatBytes(file.sizeBytes)}
                  </td>
                  <td className="px-3 py-2">
                    <span
                      className={`rounded border px-2 py-0.5 text-[10px] font-bold ${FILE_STATUS_STYLES[file.status]}`}
                    >
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
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2 text-xs font-bold text-slate-300">
            <ShieldAlert className="h-4 w-4 text-rose-400" />
            <span>{isAr ? 'تنبيهات العبث المكتشفة' : 'Detected Tamper Alerts'}</span>
            {openAlertCount > 0 && (
              <span className="animate-pulse rounded-full border border-rose-500/40 bg-rose-500/20 px-2 py-0.5 font-mono text-[10px] font-bold text-rose-300">
                {openAlertCount} {isAr ? 'مفتوح' : 'open'}
              </span>
            )}
          </div>

          <div className="flex items-center gap-2">
            <div className="relative">
              <Search className="pointer-events-none absolute start-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-500" />
              <input
                value={searchQuery}
                onChange={e => setSearchQuery(e.target.value)}
                placeholder={isAr ? 'بحث في التنبيهات…' : 'Search alerts…'}
                className="w-44 rounded-lg border border-slate-800 bg-slate-950 py-1.5 ps-8 pe-3 text-xs text-slate-200 placeholder:text-slate-600 focus:border-cyan-700 focus:outline-none"
              />
            </div>
            <select
              value={severityFilter}
              onChange={e => setSeverityFilter(e.target.value as 'ALL' | FimSeverity)}
              className="rounded-lg border border-slate-800 bg-slate-950 px-2 py-1.5 text-xs text-slate-300 focus:border-cyan-700 focus:outline-none"
            >
              <option value="ALL">{isAr ? 'كل الدرجات' : 'All severities'}</option>
              <option value="CRITICAL">CRITICAL</option>
              <option value="HIGH">HIGH</option>
              <option value="MEDIUM">MEDIUM</option>
              <option value="LOW">LOW</option>
            </select>
          </div>
        </div>

        <div className="grid grid-cols-1 gap-3 xl:grid-cols-2">
          {/* Alert list */}
          <div className="max-h-[430px] space-y-2 overflow-y-auto pe-1">
            {filteredAlerts.length === 0 && (
              <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-6 text-center text-xs text-slate-500">
                {isLoading
                  ? isAr
                    ? 'جارٍ التحميل…'
                    : 'Loading…'
                  : isAr
                    ? 'لا توجد تنبيهات مطابقة. النظام سليم.'
                    : 'No matching alerts. System integrity holding.'}
              </div>
            )}

            {filteredAlerts.map(alert => {
              const isSelected = selectedAlert?.id === alert.id;
              const isBusy = busyAlertId === alert.id;
              return (
                <div
                  key={alert.id}
                  onClick={() => setSelectedAlert(alert)}
                  className={`cursor-pointer rounded-xl border p-3 transition ${
                    isSelected
                      ? 'border-cyan-600/60 bg-slate-800/70'
                      : 'border-slate-800 bg-slate-950/70 hover:border-slate-700'
                  }`}
                >
                  <div className="flex items-start justify-between gap-2">
                    <div className="min-w-0">
                      <div className="flex flex-wrap items-center gap-1.5">
                        <span
                          className={`rounded border px-1.5 py-0.5 text-[10px] font-bold ${SEVERITY_STYLES[alert.severity]}`}
                        >
                          {alert.severity}
                        </span>
                        <span className="rounded border border-slate-700 bg-slate-800 px-1.5 py-0.5 text-[10px] font-bold text-slate-300">
                          {alert.changeType}
                        </span>
                        <span
                          className={`rounded border px-1.5 py-0.5 text-[10px] font-bold ${ALERT_STATUS_STYLES[alert.status]}`}
                        >
                          {alert.status}
                        </span>
                      </div>
                      <div
                        className="mt-1 truncate text-xs font-bold text-slate-200"
                        title={alert.fileName}
                      >
                        {alert.fileName}
                      </div>
                      <div className="truncate text-[10px] text-slate-500" title={alert.filePath}>
                        {alert.filePath}
                      </div>
                      <div className="mt-1 text-[11px] text-slate-400">
                        {alert.intentClassification} ·{' '}
                        <span className="font-mono text-amber-300/90">{alert.mitreTechnique}</span>
                      </div>
                    </div>

                    <div className="shrink-0 text-end">
                      <div className="font-mono text-sm font-bold text-rose-300">
                        {alert.threatScore}
                      </div>
                      <div className="text-[10px] text-slate-600">/100</div>
                    </div>
                  </div>

                  {/* Action row - only meaningful while the alert is still open */}
                  {alert.status === 'DETECTED' && (
                    <div className="mt-2 flex items-center gap-1.5 border-t border-slate-800 pt-2">
                      <button
                        onClick={e => {
                          e.stopPropagation();
                          handleAlertAction(alert.id, 'quarantine');
                        }}
                        disabled={isBusy}
                        className="flex items-center gap-1 rounded-lg border border-purple-800/60 bg-purple-950/60 px-2 py-1 text-[11px] font-semibold text-purple-200 transition hover:bg-purple-900/80 disabled:opacity-50"
                      >
                        <Lock className="h-3 w-3" />
                        {isAr ? 'عزل' : 'Quarantine'}
                      </button>
                      <button
                        onClick={e => {
                          e.stopPropagation();
                          handleAlertAction(alert.id, 'rollback');
                        }}
                        disabled={isBusy}
                        className="flex items-center gap-1 rounded-lg border border-emerald-800/60 bg-emerald-950/60 px-2 py-1 text-[11px] font-semibold text-emerald-200 transition hover:bg-emerald-900/80 disabled:opacity-50"
                      >
                        <RotateCcw className="h-3 w-3" />
                        {isAr ? 'استرجاع' : 'Rollback'}
                      </button>
                      <button
                        onClick={e => {
                          e.stopPropagation();
                          handleAlertAction(alert.id, 'dismiss');
                        }}
                        disabled={isBusy}
                        className="flex items-center gap-1 rounded-lg border border-slate-700 bg-slate-800/80 px-2 py-1 text-[11px] font-semibold text-slate-300 transition hover:bg-slate-700/80 disabled:opacity-50"
                      >
                        <XCircle className="h-3 w-3" />
                        {isAr ? 'تجاهل' : 'Dismiss'}
                      </button>
                      {isBusy && <RefreshCw className="h-3 w-3 animate-spin text-cyan-400" />}
                    </div>
                  )}
                </div>
              );
            })}
          </div>

          {/* Detail pane */}
          <div className="max-h-[430px] overflow-y-auto rounded-xl border border-slate-800 bg-slate-950/70 p-4">
            {selectedAlert ? (
              <div className="space-y-3">
                <div className="flex items-center justify-between gap-2 border-b border-slate-800 pb-2">
                  <div className="flex items-center gap-2 text-xs font-bold text-slate-200">
                    <Eye className="h-4 w-4 text-cyan-400" />
                    <span>{isAr ? 'تفاصيل التنبيه الجنائية' : 'Forensic Alert Detail'}</span>
                  </div>
                  <span className="font-mono text-[10px] text-slate-500">{selectedAlert.id}</span>
                </div>

                <div className="grid grid-cols-2 gap-2 text-[11px]">
                  <div>
                    <div className="text-slate-500">{isAr ? 'التصنيف' : 'Category'}</div>
                    <div className="font-semibold text-slate-200">
                      {selectedAlert.threatCategory}
                    </div>
                  </div>
                  <div>
                    <div className="text-slate-500">{isAr ? 'تقنية MITRE' : 'MITRE Technique'}</div>
                    <div className="font-mono text-amber-300">{selectedAlert.mitreTechnique}</div>
                  </div>
                  <div>
                    <div className="text-slate-500">{isAr ? 'وقت الرصد' : 'Detected At'}</div>
                    <div className="flex items-center gap-1 font-mono text-slate-300">
                      <Clock className="h-3 w-3 text-slate-600" />
                      {new Date(selectedAlert.timestamp).toLocaleString(isAr ? 'ar' : 'en')}
                    </div>
                  </div>
                  <div>
                    <div className="text-slate-500">
                      {isAr ? 'تحليل الذكاء الاصطناعي' : 'AI Analyzed'}
                    </div>
                    <div
                      className={selectedAlert.aiAnalyzed ? 'text-emerald-300' : 'text-slate-400'}
                    >
                      {selectedAlert.aiAnalyzed ? (isAr ? 'نعم' : 'Yes') : isAr ? 'لا' : 'No'}
                    </div>
                  </div>
                </div>

                {/* Hash transition */}
                <div className="space-y-1">
                  <div className="text-[11px] text-slate-500">
                    {isAr ? 'تغيّر البصمة التشفيرية' : 'Cryptographic Hash Transition'}
                  </div>
                  <div className="space-y-1 rounded-lg border border-slate-800 bg-slate-900 p-2 font-mono text-[10px]">
                    <div className="flex items-center gap-1.5">
                      <span className="w-12 shrink-0 text-slate-600">
                        {isAr ? 'قبل' : 'before'}
                      </span>
                      <span className="break-all text-emerald-300/80">
                        {selectedAlert.previousHash || '--'}
                      </span>
                    </div>
                    <div className="flex items-center gap-1.5">
                      <span className="w-12 shrink-0 text-slate-600">{isAr ? 'بعد' : 'after'}</span>
                      <span className="break-all text-rose-300/90">
                        {selectedAlert.currentHash || '--'}
                      </span>
                    </div>
                  </div>
                </div>

                {/* Diff */}
                {selectedAlert.diffSnippet && (
                  <div className="space-y-1">
                    <div className="text-[11px] text-slate-500">
                      {isAr ? 'مقتطف التغيير' : 'Change Diff'}
                    </div>
                    <pre className="max-h-40 overflow-x-auto rounded-lg border border-slate-800 bg-slate-900 p-2 text-[10px] break-all whitespace-pre-wrap text-slate-300">
                      {selectedAlert.diffSnippet}
                    </pre>
                  </div>
                )}

                {/* Narrative analysis */}
                <div className="space-y-1">
                  <div className="text-[11px] text-slate-500">
                    {isAr ? 'التحليل التفسيري' : 'Analyst Narrative'}
                  </div>
                  <p className="text-[11px] leading-relaxed text-slate-300">
                    {isAr
                      ? selectedAlert.analysisAr || selectedAlert.analysisEn
                      : selectedAlert.analysisEn}
                  </p>
                </div>

                {selectedAlert.quarantinedPath && (
                  <div className="flex items-start gap-1.5 rounded-lg border border-purple-800/50 bg-purple-950/40 p-2 text-[11px] text-purple-200">
                    <Lock className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                    <span className="font-mono break-all">{selectedAlert.quarantinedPath}</span>
                  </div>
                )}
              </div>
            ) : (
              <div className="flex h-full min-h-[200px] flex-col items-center justify-center gap-2 text-center text-slate-500">
                <AlertTriangle className="h-8 w-8 text-slate-700" />
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
