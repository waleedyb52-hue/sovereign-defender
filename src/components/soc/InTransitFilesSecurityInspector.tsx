import React, { useState, useEffect, useCallback } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  FileCode,
  Zap,
  Activity,
  AlertTriangle,
  RefreshCw,
  Search,
  Lock,
  Radio,
  FileCheck,
  Download,
  Flame,
  Check,
  Copy,
  Sliders,
  ExternalLink,
  ChevronDown,
  ChevronUp,
  FileText
} from 'lucide-react';

export type FileSecurityVerdict = 'SCANNING' | 'CLEAN' | 'SUSPICIOUS' | 'QUARANTINED';

export interface InTransitFileRecord {
  id: string;
  filename: string;
  originalPath: string;
  fileSizeBytes: number;
  mimeType: string;
  sha256: string;
  entropyScore: number;
  verdict: FileSecurityVerdict;
  detectedThreat?: string;
  matchedRule?: string;
  sourceIp: string;
  destinationNode: string;
  interceptedAt: string;
  inspectedAt?: string;
  quarantinePath?: string;
  sandboxAnalysis?: {
    isPacked: boolean;
    hasEmbeddedExecutable: boolean;
    highEntropySections: number;
    threatClassification: string;
    detailsAr: string;
  };
}

export interface InTransitFilesTelemetryProps {
  lang: 'ar' | 'en';
}

export const InTransitFilesSecurityInspector: React.FC<InTransitFilesTelemetryProps> = ({
  lang
}) => {
  const isAr = lang === 'ar';

  const [files, setFiles] = useState<InTransitFileRecord[]>([]);
  const [stats, setStats] = useState({
    totalInspected: 4,
    totalQuarantined: 2,
    totalClean: 2,
    averageEntropy: 6.32,
    activeYaraRulesCount: 5,
    preTransitLatencyUs: 0.38
  });
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [isSimulating, setIsSimulating] = useState<boolean>(false);
  const [searchFilter, setSearchFilter] = useState<string>('');
  const [selectedVerdict, setSelectedVerdict] = useState<'ALL' | 'QUARANTINED' | 'CLEAN'>('ALL');
  const [expandedFileId, setExpandedFileId] = useState<string | null>(null);
  const [copiedHash, setCopiedHash] = useState<string | null>(null);

  // Fetch in-transit files
  const fetchInTransitFiles = useCallback(async () => {
    try {
      const res = await fetch('/api/v1/security/in-transit-files');
      if (res.ok) {
        const data = await res.json();
        if (data.files) setFiles(data.files);
        if (data.statistics) setStats(data.statistics);
      }
    } catch (err) {
      console.warn('Failed to fetch in-transit files:', err);
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchInTransitFiles();
    const interval = setInterval(fetchInTransitFiles, 4000);
    return () => clearInterval(interval);
  }, [fetchInTransitFiles]);

  // Simulate file transmission drill
  const handleSimulateFile = async (scenario: 'WEBSHELL_RCE' | 'PACKED_STAGER' | 'CLEAN_DOC') => {
    setIsSimulating(true);
    try {
      const res = await fetch('/api/v1/security/simulate-transit-file', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scenario })
      });
      if (res.ok) {
        await fetchInTransitFiles();
      }
    } catch (err) {
      console.error('File simulation error:', err);
    } finally {
      setIsSimulating(false);
    }
  };

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedHash(text);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  const filteredFiles = files.filter(f => {
    const matchesSearch =
      f.filename.toLowerCase().includes(searchFilter.toLowerCase()) ||
      f.sourceIp.includes(searchFilter) ||
      (f.matchedRule && f.matchedRule.toLowerCase().includes(searchFilter.toLowerCase()));

    if (selectedVerdict === 'ALL') return matchesSearch;
    return matchesSearch && f.verdict === selectedVerdict;
  });

  return (
    <div
      className="space-y-4 rounded-2xl border border-slate-800 bg-slate-900 p-4 shadow-xl sm:p-5 shadow-[0_0_20px_rgba(0,255,255,0.08)]"
      dir={isAr ? 'rtl' : 'ltr'}
    >
      {/* 1. Header & Live Indicator */}
      <div className="flex flex-col gap-3 border-b border-slate-800 pb-3 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex items-center gap-3">
          <div className="rounded-xl border border-cyan-500/40 bg-cyan-950/80 p-2.5 text-cyan-300 shadow-md shadow-cyan-950/50">
            <FileCheck className="h-5 w-5 text-cyan-400" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-sm font-bold tracking-wide text-white">
                {isAr
                  ? 'الفحص العميق للملفات قبل الوصول (Pre-Transit Deep Inspection)'
                  : 'Pre-Transit Deep File Inspection & Shannon Entropy Engine'}
              </h2>
              <span className="rounded border border-cyan-500/40 bg-cyan-500/20 px-2 py-0.5 font-mono text-[10px] font-bold text-cyan-300">
                MoD Zero-Trust
              </span>
            </div>
            <p className="mt-0.5 font-mono text-[11px] text-slate-400">
              {isAr
                ? 'اعتراض الملفات في الذاكرة RAM ومنع وصولها للقرص حتى اجتياز فحص إنتروبيا شانون وقواعد YARA'
                : 'In-memory interception halts lateral transfers before volume commit with Shannon Entropy & compiled YARA'}
            </p>
          </div>
        </div>

        {/* Simulation Buttons */}
        <div className="flex flex-wrap items-center gap-2">
          <button
            onClick={() => handleSimulateFile('WEBSHELL_RCE')}
            disabled={isSimulating}
            className="flex items-center gap-1.5 rounded-lg border border-rose-500/40 bg-rose-950/70 px-2.5 py-1 font-mono text-xs font-bold text-rose-300 transition hover:bg-rose-900/80"
            title={isAr ? 'محاكاة رفع شل ويب C99' : 'Simulate C99 Webshell Upload'}
          >
            <Flame className="h-3.5 w-3.5 text-rose-400" />
            <span>{isAr ? 'محاكاة شل ويب C99' : 'Test Webshell'}</span>
          </button>

          <button
            onClick={() => handleSimulateFile('PACKED_STAGER')}
            disabled={isSimulating}
            className="flex items-center gap-1.5 rounded-lg border border-amber-500/40 bg-amber-950/70 px-2.5 py-1 font-mono text-xs font-bold text-amber-300 transition hover:bg-amber-900/80"
            title={isAr ? 'محاكاة حمولة مشفرة عالية الإنتروبيا' : 'Simulate High-Entropy Stager'}
          >
            <Zap className="h-3.5 w-3.5 text-amber-400" />
            <span>{isAr ? 'محاكاة كود مشفر (H>7.2)' : 'Test High Entropy'}</span>
          </button>

          <button
            onClick={() => handleSimulateFile('CLEAN_DOC')}
            disabled={isSimulating}
            className="flex items-center gap-1.5 rounded-lg border border-emerald-500/40 bg-emerald-950/70 px-2.5 py-1 font-mono text-xs font-bold text-emerald-300 transition hover:bg-emerald-900/80"
            title={isAr ? 'محاكاة ملف وثيقة آمن' : 'Simulate Benign Document'}
          >
            <ShieldCheck className="h-3.5 w-3.5 text-emerald-400" />
            <span>{isAr ? 'ملف سليم' : 'Test Clean File'}</span>
          </button>

          <button
            onClick={fetchInTransitFiles}
            disabled={isLoading}
            className="rounded-lg bg-slate-800 p-1.5 text-slate-300 transition hover:bg-slate-700"
            title={isAr ? 'تحديث' : 'Refresh'}
          >
            <RefreshCw className={`h-3.5 w-3.5 ${isLoading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* 2. Key Inspection Metrics */}
      <div className="grid grid-cols-2 gap-2.5 font-mono text-xs sm:grid-cols-4">
        <div className="rounded-xl border border-slate-800 bg-slate-950 p-2.5 shadow-[0_0_20px_rgba(0,255,255,0.08)]">
          <span className="block text-[10px] text-slate-400">
            {isAr ? 'الملفات المحجورة أمنياً' : 'QUARANTINED FILES'}
          </span>
          <div className="mt-1 flex items-center gap-2">
            <Lock className="h-4 w-4 text-rose-400" />
            <span className="text-base font-bold text-rose-300">{stats.totalQuarantined}</span>
            <span className="text-[10px] font-bold text-rose-500">⚠️ RESTRICTED</span>
          </div>
        </div>

        <div className="rounded-xl border border-slate-800 bg-slate-950 p-2.5 shadow-[0_0_20px_rgba(0,255,255,0.08)]">
          <span className="block text-[10px] text-slate-400">
            {isAr ? 'الملفات المفحوصة والسليمة' : 'CLEAN FILES VERIFIED'}
          </span>
          <div className="mt-1 flex items-center gap-2">
            <ShieldCheck className="h-4 w-4 text-emerald-400" />
            <span className="text-base font-bold text-emerald-300">{stats.totalClean}</span>
            <span className="text-[10px] font-bold text-emerald-500">✅ COMMITTED</span>
          </div>
        </div>

        <div className="rounded-xl border border-slate-800 bg-slate-950 p-2.5 shadow-[0_0_20px_rgba(0,255,255,0.08)]">
          <span className="block text-[10px] text-slate-400">
            {isAr ? 'متوسط إنتروبيا شانون' : 'AVG SHANNON ENTROPY'}
          </span>
          <div className="mt-1 flex items-center gap-2">
            <Activity className="h-4 w-4 text-cyan-400" />
            <span className="text-base font-bold text-cyan-300">{stats.averageEntropy} / 8.00</span>
          </div>
        </div>

        <div className="rounded-xl border border-slate-800 bg-slate-950 p-2.5 shadow-[0_0_20px_rgba(0,255,255,0.08)]">
          <span className="block text-[10px] text-slate-400">
            {isAr ? 'زمن فحص الذاكرة' : 'PRE-COMMIT SCAN SPEED'}
          </span>
          <div className="mt-1 flex items-center gap-2">
            <Zap className="h-4 w-4 text-cyan-400" />
            <span className="text-base font-bold text-cyan-300">
              {stats.preTransitLatencyUs} µs
            </span>
          </div>
        </div>
      </div>

      {/* 3. Search & Filter Bar */}
      <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-slate-800 bg-slate-950/70 p-2.5 shadow-[0_0_20px_rgba(0,255,255,0.08)]">
        <div className="relative">
          <Search className="absolute top-2.5 left-2.5 h-3.5 w-3.5 text-slate-400" />
          <input
            type="text"
            value={searchFilter}
            onChange={e => setSearchFilter(e.target.value)}
            placeholder={
              isAr
                ? 'بحث باسم الملف، العنوان، أو القاعدة المطابقة...'
                : 'Filter filename, IP, YARA rule...'
            }
            className="w-64 rounded-lg border border-slate-700 bg-slate-900 py-1 pr-3 pl-8 font-mono text-xs text-slate-200 outline-none focus:border-cyan-400 shadow-[0_0_20px_rgba(0,255,255,0.08)]"
          />
        </div>

        <div className="flex items-center gap-1.5 font-mono text-xs">
          <button
            onClick={() => setSelectedVerdict('ALL')}
            className={`rounded-lg px-2.5 py-1 transition ${
              selectedVerdict === 'ALL'
                ? 'border border-cyan-500/50 bg-cyan-950 font-bold text-cyan-300'
                : 'bg-slate-900 text-slate-400'
            }`}
          >
            {isAr ? 'الكل' : 'ALL'} ({files.length})
          </button>
          <button
            onClick={() => setSelectedVerdict('QUARANTINED')}
            className={`rounded-lg px-2.5 py-1 transition ${
              selectedVerdict === 'QUARANTINED'
                ? 'border border-rose-500/50 bg-rose-950 font-bold text-rose-300'
                : 'bg-slate-900 text-slate-400'
            }`}
          >
            {isAr ? 'المحجورة ⚠️' : 'Quarantined ⚠️'} (
            {files.filter(f => f.verdict === 'QUARANTINED').length})
          </button>
          <button
            onClick={() => setSelectedVerdict('CLEAN')}
            className={`rounded-lg px-2.5 py-1 transition ${
              selectedVerdict === 'CLEAN'
                ? 'border border-emerald-500/50 bg-emerald-950 font-bold text-emerald-300'
                : 'bg-slate-900 text-slate-400'
            }`}
          >
            {isAr ? 'السليمة ✅' : 'Clean ✅'} ({files.filter(f => f.verdict === 'CLEAN').length})
          </button>
        </div>
      </div>

      {/* 4. Stream Cards with Dynamic Visual Badges */}
      <div className="space-y-2.5">
        {filteredFiles.map(file => {
          const isQuarantined = file.verdict === 'QUARANTINED';
          const isScanning = file.verdict === 'SCANNING';
          const isExpanded = expandedFileId === file.id;

          return (
            <div
              key={file.id}
              className={`space-y-2.5 rounded-xl border p-3.5 transition ${
                isQuarantined
                  ? 'border-rose-500/40 bg-rose-950/20 shadow-md shadow-rose-950/30 hover:border-rose-400'
                  : isScanning
                    ? 'animate-pulse border-cyan-500/40 bg-cyan-950/20'
                    : 'border-slate-800 bg-slate-950 hover:border-slate-700 shadow-[0_0_20px_rgba(0,255,255,0.08)]'
              }`}
            >
              <div className="flex flex-col justify-between gap-2.5 sm:flex-row sm:items-center">
                {/* File Title & Dynamic Badges */}
                <div className="flex items-center gap-2.5">
                  <div
                    className={`rounded-lg p-2 ${
                      isQuarantined ? 'bg-rose-900/60 text-rose-300' : 'bg-slate-800 text-slate-300'
                    }`}
                  >
                    {isQuarantined ? (
                      <FileCode className="h-4 w-4 text-rose-400" />
                    ) : (
                      <FileText className="h-4 w-4 text-emerald-400" />
                    )}
                  </div>

                  <div>
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="font-mono text-xs font-bold text-slate-100">
                        {file.filename}
                      </span>

                      {/* DYNAMIC VISUAL STATE INDICATORS */}
                      {isScanning && (
                        <span className="flex items-center gap-1 rounded border border-cyan-500/50 bg-cyan-950 px-2 py-0.5 font-mono text-[10px] font-bold text-cyan-300">
                          <span className="h-1.5 w-1.5 animate-spin rounded-full bg-cyan-400" />
                          Deep Scanning... 🌀
                        </span>
                      )}

                      {isQuarantined && (
                        <span className="flex items-center gap-1 rounded border border-rose-500/60 bg-rose-950 px-2 py-0.5 font-mono text-[10px] font-bold text-rose-300 shadow-sm">
                          <AlertTriangle className="h-3 w-3 text-rose-400" />
                          Quarantined ⚠️
                        </span>
                      )}

                      {file.verdict === 'CLEAN' && (
                        <span className="flex items-center gap-1 rounded border border-emerald-500/50 bg-emerald-950 px-2 py-0.5 font-mono text-[10px] font-bold text-emerald-300">
                          <Check className="h-3 w-3 text-emerald-400" />
                          Clean ✅
                        </span>
                      )}

                      {/* Shannon Entropy Badge */}
                      <span
                        className={`py-0.2 rounded border px-1.5 font-mono text-[10px] font-bold ${
                          file.entropyScore >= 7.2
                            ? 'border-rose-500/50 bg-rose-950 text-rose-300'
                            : file.entropyScore >= 6.0
                              ? 'border-amber-500/50 bg-amber-950 text-amber-300'
                              : 'border-slate-700 bg-slate-900 text-slate-300 shadow-[0_0_20px_rgba(0,255,255,0.08)]'
                        }`}
                      >
                        Entropy: {file.entropyScore}/8.00{' '}
                        {file.entropyScore >= 7.2 ? '🔥 Packed' : ''}
                      </span>
                    </div>

                    <div className="mt-1 flex flex-wrap items-center gap-2 font-mono text-[10px] text-slate-400">
                      <span>
                        Source: <strong className="text-cyan-300">{file.sourceIp}</strong>
                      </span>
                      <span>→</span>
                      <span>
                        Target: <strong className="text-slate-300">{file.destinationNode}</strong>
                      </span>
                      <span>•</span>
                      <span>Size: {(file.fileSizeBytes / 1024).toFixed(1)} KB</span>
                      <span>•</span>
                      <span>{new Date(file.interceptedAt).toLocaleTimeString()}</span>
                    </div>
                  </div>
                </div>

                {/* Right Expand / Details toggle */}
                <div className="flex items-center gap-2 self-end sm:self-center">
                  <button
                    onClick={() => setExpandedFileId(isExpanded ? null : file.id)}
                    className="flex items-center gap-1 rounded-lg border border-slate-700 bg-slate-900 px-2.5 py-1 font-mono text-xs text-slate-300 transition hover:bg-slate-800 shadow-[0_0_20px_rgba(0,255,255,0.08)]"
                  >
                    <span>
                      {isExpanded
                        ? isAr
                          ? 'إخفاء'
                          : 'Collapse'
                        : isAr
                          ? 'تفاصيل الساندبوكس'
                          : 'Sandbox Forensics'}
                    </span>
                    {isExpanded ? (
                      <ChevronUp className="h-3 w-3" />
                    ) : (
                      <ChevronDown className="h-3 w-3" />
                    )}
                  </button>
                </div>
              </div>

              {/* Threat Description banner if Quarantined */}
              {isQuarantined && file.detectedThreat && (
                <div className="flex items-center justify-between rounded-lg border border-rose-500/30 bg-rose-950/50 p-2 font-mono text-xs text-rose-200">
                  <span>
                    ⚠️ <strong>{isAr ? 'التهديد المرصود:' : 'Intercepted Threat:'}</strong>{' '}
                    {file.detectedThreat}
                  </span>
                  {file.matchedRule && (
                    <span className="rounded border border-rose-500/40 bg-rose-900/80 px-2 py-0.5 text-[10px]">
                      Rule: {file.matchedRule}
                    </span>
                  )}
                </div>
              )}

              {/* Expanded Sandbox & Forensics Drawer */}
              {isExpanded && (
                <div className="animate-fadeIn space-y-2.5 rounded-xl border border-slate-800 bg-slate-950 p-3 font-mono text-xs shadow-[0_0_20px_rgba(0,255,255,0.08)]">
                  <div className="grid grid-cols-1 gap-2 text-slate-300 sm:grid-cols-2">
                    <div>
                      <span className="block text-[10px] text-slate-400">SHA-256 Hash:</span>
                      <div className="mt-0.5 flex items-center gap-1.5">
                        <span className="max-w-[280px] truncate text-[11px] text-cyan-300">
                          {file.sha256}
                        </span>
                        <button
                          onClick={() => handleCopy(file.sha256)}
                          className="text-slate-400 hover:text-white"
                          title="Copy SHA-256"
                        >
                          {copiedHash === file.sha256 ? (
                            <Check className="h-3 w-3 text-emerald-400" />
                          ) : (
                            <Copy className="h-3 w-3" />
                          )}
                        </button>
                      </div>
                    </div>

                    <div>
                      <span className="block text-[10px] text-slate-400">
                        {isAr ? 'مسار الحجر بالساندبوكس:' : 'Quarantine Sandbox Path:'}
                      </span>
                      <span className="mt-0.5 block truncate text-[11px] text-amber-300">
                        {file.quarantinePath ||
                          (isAr ? 'غير محجور (ملف مسموح به)' : 'Not Quarantined (Approved file)')}
                      </span>
                    </div>
                  </div>

                  {file.sandboxAnalysis && (
                    <div className="space-y-1 rounded-lg border border-slate-800 bg-slate-900/90 p-2.5 shadow-[0_0_20px_rgba(0,255,255,0.08)]">
                      <span className="block text-[10px] font-bold tracking-wider text-slate-400 uppercase">
                        {isAr
                          ? 'تقرير بيئة التحليل الرملية (Cyber Threat Sandbox)'
                          : 'Sandbox Behavioral Analysis Report'}
                      </span>
                      <p className="text-xs text-slate-300">
                        {isAr
                          ? file.sandboxAnalysis.detailsAr
                          : file.sandboxAnalysis.threatClassification}
                      </p>
                      <div className="flex flex-wrap items-center gap-3 pt-1 text-[10px] text-slate-400">
                        <span>
                          Binary Packed:{' '}
                          <strong
                            className={
                              file.sandboxAnalysis.isPacked ? 'text-rose-400' : 'text-emerald-400'
                            }
                          >
                            {file.sandboxAnalysis.isPacked ? 'YES (Obfuscated)' : 'NO'}
                          </strong>
                        </span>
                        <span>•</span>
                        <span>
                          Embedded Executable:{' '}
                          <strong
                            className={
                              file.sandboxAnalysis.hasEmbeddedExecutable
                                ? 'text-rose-400'
                                : 'text-emerald-400'
                            }
                          >
                            {file.sandboxAnalysis.hasEmbeddedExecutable ? 'DETECTED' : 'NONE'}
                          </strong>
                        </span>
                        <span>•</span>
                        <span>
                          Classification:{' '}
                          <strong className="text-cyan-300">
                            {file.sandboxAnalysis.threatClassification}
                          </strong>
                        </span>
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};
