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

export const InTransitFilesSecurityInspector: React.FC<InTransitFilesTelemetryProps> = ({ lang }) => {
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
    const matchesSearch = f.filename.toLowerCase().includes(searchFilter.toLowerCase()) ||
      f.sourceIp.includes(searchFilter) ||
      (f.matchedRule && f.matchedRule.toLowerCase().includes(searchFilter.toLowerCase()));
    
    if (selectedVerdict === 'ALL') return matchesSearch;
    return matchesSearch && f.verdict === selectedVerdict;
  });

  return (
    <div className="rounded-2xl bg-slate-900 border border-slate-800 p-4 sm:p-5 shadow-xl space-y-4" dir={isAr ? 'rtl' : 'ltr'}>
      
      {/* 1. Header & Live Indicator */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 pb-3 border-b border-slate-800">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-xl bg-cyan-950/80 border border-cyan-500/40 text-cyan-300 shadow-md shadow-cyan-950/50">
            <FileCheck className="w-5 h-5 text-cyan-400" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-sm font-bold text-white tracking-wide">
                {isAr ? 'الفحص العميق للملفات قبل الوصول (Pre-Transit Deep Inspection)' : 'Pre-Transit Deep File Inspection & Shannon Entropy Engine'}
              </h2>
              <span className="px-2 py-0.5 text-[10px] font-mono font-bold rounded bg-cyan-500/20 text-cyan-300 border border-cyan-500/40">
                MoD Zero-Trust
              </span>
            </div>
            <p className="text-[11px] text-slate-400 font-mono mt-0.5">
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
            className="px-2.5 py-1 bg-rose-950/70 hover:bg-rose-900/80 text-rose-300 border border-rose-500/40 rounded-lg text-xs font-mono font-bold transition flex items-center gap-1.5"
            title={isAr ? 'محاكاة رفع شل ويب C99' : 'Simulate C99 Webshell Upload'}
          >
            <Flame className="w-3.5 h-3.5 text-rose-400" />
            <span>{isAr ? 'محاكاة شل ويب C99' : 'Test Webshell'}</span>
          </button>

          <button
            onClick={() => handleSimulateFile('PACKED_STAGER')}
            disabled={isSimulating}
            className="px-2.5 py-1 bg-amber-950/70 hover:bg-amber-900/80 text-amber-300 border border-amber-500/40 rounded-lg text-xs font-mono font-bold transition flex items-center gap-1.5"
            title={isAr ? 'محاكاة حمولة مشفرة عالية الإنتروبيا' : 'Simulate High-Entropy Stager'}
          >
            <Zap className="w-3.5 h-3.5 text-amber-400" />
            <span>{isAr ? 'محاكاة كود مشفر (H>7.2)' : 'Test High Entropy'}</span>
          </button>

          <button
            onClick={() => handleSimulateFile('CLEAN_DOC')}
            disabled={isSimulating}
            className="px-2.5 py-1 bg-emerald-950/70 hover:bg-emerald-900/80 text-emerald-300 border border-emerald-500/40 rounded-lg text-xs font-mono font-bold transition flex items-center gap-1.5"
            title={isAr ? 'محاكاة ملف وثيقة آمن' : 'Simulate Benign Document'}
          >
            <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
            <span>{isAr ? 'ملف سليم' : 'Test Clean File'}</span>
          </button>

          <button
            onClick={fetchInTransitFiles}
            disabled={isLoading}
            className="p-1.5 rounded-lg bg-slate-800 text-slate-300 hover:bg-slate-700 transition"
            title={isAr ? 'تحديث' : 'Refresh'}
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* 2. Key Inspection Metrics */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5 font-mono text-xs">
        
        <div className="bg-slate-950 p-2.5 rounded-xl border border-slate-800">
          <span className="text-[10px] text-slate-400 block">{isAr ? 'الملفات المحجورة أمنياً' : 'QUARANTINED FILES'}</span>
          <div className="flex items-center gap-2 mt-1">
            <Lock className="w-4 h-4 text-rose-400" />
            <span className="text-base font-bold text-rose-300">{stats.totalQuarantined}</span>
            <span className="text-[10px] text-rose-500 font-bold">⚠️ RESTRICTED</span>
          </div>
        </div>

        <div className="bg-slate-950 p-2.5 rounded-xl border border-slate-800">
          <span className="text-[10px] text-slate-400 block">{isAr ? 'الملفات المفحوصة والسليمة' : 'CLEAN FILES VERIFIED'}</span>
          <div className="flex items-center gap-2 mt-1">
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
            <span className="text-base font-bold text-emerald-300">{stats.totalClean}</span>
            <span className="text-[10px] text-emerald-500 font-bold">✅ COMMITTED</span>
          </div>
        </div>

        <div className="bg-slate-950 p-2.5 rounded-xl border border-slate-800">
          <span className="text-[10px] text-slate-400 block">{isAr ? 'متوسط إنتروبيا شانون' : 'AVG SHANNON ENTROPY'}</span>
          <div className="flex items-center gap-2 mt-1">
            <Activity className="w-4 h-4 text-cyan-400" />
            <span className="text-base font-bold text-cyan-300">{stats.averageEntropy} / 8.00</span>
          </div>
        </div>

        <div className="bg-slate-950 p-2.5 rounded-xl border border-slate-800">
          <span className="text-[10px] text-slate-400 block">{isAr ? 'زمن فحص الذاكرة' : 'PRE-COMMIT SCAN SPEED'}</span>
          <div className="flex items-center gap-2 mt-1">
            <Zap className="w-4 h-4 text-purple-400" />
            <span className="text-base font-bold text-purple-300">{stats.preTransitLatencyUs} µs</span>
          </div>
        </div>

      </div>

      {/* 3. Search & Filter Bar */}
      <div className="flex flex-wrap items-center justify-between gap-3 bg-slate-950/70 p-2.5 rounded-xl border border-slate-800">
        
        <div className="relative">
          <Search className="w-3.5 h-3.5 text-slate-400 absolute top-2.5 left-2.5" />
          <input
            type="text"
            value={searchFilter}
            onChange={(e) => setSearchFilter(e.target.value)}
            placeholder={isAr ? 'بحث باسم الملف، العنوان، أو القاعدة المطابقة...' : 'Filter filename, IP, YARA rule...'}
            className="pl-8 pr-3 py-1 bg-slate-900 border border-slate-700 rounded-lg text-xs text-slate-200 w-64 focus:border-cyan-400 outline-none font-mono"
          />
        </div>

        <div className="flex items-center gap-1.5 font-mono text-xs">
          <button
            onClick={() => setSelectedVerdict('ALL')}
            className={`px-2.5 py-1 rounded-lg transition ${
              selectedVerdict === 'ALL' ? 'bg-cyan-950 text-cyan-300 border border-cyan-500/50 font-bold' : 'bg-slate-900 text-slate-400'
            }`}
          >
            {isAr ? 'الكل' : 'ALL'} ({files.length})
          </button>
          <button
            onClick={() => setSelectedVerdict('QUARANTINED')}
            className={`px-2.5 py-1 rounded-lg transition ${
              selectedVerdict === 'QUARANTINED' ? 'bg-rose-950 text-rose-300 border border-rose-500/50 font-bold' : 'bg-slate-900 text-slate-400'
            }`}
          >
            {isAr ? 'المحجورة ⚠️' : 'Quarantined ⚠️'} ({files.filter(f => f.verdict === 'QUARANTINED').length})
          </button>
          <button
            onClick={() => setSelectedVerdict('CLEAN')}
            className={`px-2.5 py-1 rounded-lg transition ${
              selectedVerdict === 'CLEAN' ? 'bg-emerald-950 text-emerald-300 border border-emerald-500/50 font-bold' : 'bg-slate-900 text-slate-400'
            }`}
          >
            {isAr ? 'السليمة ✅' : 'Clean ✅'} ({files.filter(f => f.verdict === 'CLEAN').length})
          </button>
        </div>

      </div>

      {/* 4. Stream Cards with Dynamic Visual Badges */}
      <div className="space-y-2.5">
        {filteredFiles.map((file) => {
          const isQuarantined = file.verdict === 'QUARANTINED';
          const isScanning = file.verdict === 'SCANNING';
          const isExpanded = expandedFileId === file.id;

          return (
            <div
              key={file.id}
              className={`rounded-xl border transition p-3.5 space-y-2.5 ${
                isQuarantined
                  ? 'bg-rose-950/20 border-rose-500/40 hover:border-rose-400 shadow-md shadow-rose-950/30'
                  : isScanning
                  ? 'bg-cyan-950/20 border-cyan-500/40 animate-pulse'
                  : 'bg-slate-950 border-slate-800 hover:border-slate-700'
              }`}
            >
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2.5">
                
                {/* File Title & Dynamic Badges */}
                <div className="flex items-center gap-2.5">
                  <div className={`p-2 rounded-lg ${
                    isQuarantined ? 'bg-rose-900/60 text-rose-300' : 'bg-slate-800 text-slate-300'
                  }`}>
                    {isQuarantined ? <FileCode className="w-4 h-4 text-rose-400" /> : <FileText className="w-4 h-4 text-emerald-400" />}
                  </div>

                  <div>
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-xs font-bold text-slate-100 font-mono">{file.filename}</span>
                      
                      {/* DYNAMIC VISUAL STATE INDICATORS */}
                      {isScanning && (
                        <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-cyan-950 text-cyan-300 border border-cyan-500/50 flex items-center gap-1">
                          <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-spin" />
                          Deep Scanning... 🌀
                        </span>
                      )}

                      {isQuarantined && (
                        <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-950 text-rose-300 border border-rose-500/60 flex items-center gap-1 shadow-sm">
                          <AlertTriangle className="w-3 h-3 text-rose-400" />
                          Quarantined ⚠️
                        </span>
                      )}

                      {file.verdict === 'CLEAN' && (
                        <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-950 text-emerald-300 border border-emerald-500/50 flex items-center gap-1">
                          <Check className="w-3 h-3 text-emerald-400" />
                          Clean ✅
                        </span>
                      )}

                      {/* Shannon Entropy Badge */}
                      <span className={`px-1.5 py-0.2 rounded text-[10px] font-mono font-bold border ${
                        file.entropyScore >= 7.20
                          ? 'bg-rose-950 text-rose-300 border-rose-500/50'
                          : file.entropyScore >= 6.0
                          ? 'bg-amber-950 text-amber-300 border-amber-500/50'
                          : 'bg-slate-900 text-slate-300 border-slate-700'
                      }`}>
                        Entropy: {file.entropyScore}/8.00 {file.entropyScore >= 7.20 ? '🔥 Packed' : ''}
                      </span>
                    </div>

                    <div className="flex flex-wrap items-center gap-2 text-[10px] font-mono text-slate-400 mt-1">
                      <span>Source: <strong className="text-cyan-300">{file.sourceIp}</strong></span>
                      <span>→</span>
                      <span>Target: <strong className="text-slate-300">{file.destinationNode}</strong></span>
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
                    className="px-2.5 py-1 bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-700 rounded-lg text-xs font-mono transition flex items-center gap-1"
                  >
                    <span>{isExpanded ? (isAr ? 'إخفاء' : 'Collapse') : (isAr ? 'تفاصيل الساندبوكس' : 'Sandbox Forensics')}</span>
                    {isExpanded ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
                  </button>
                </div>

              </div>

              {/* Threat Description banner if Quarantined */}
              {isQuarantined && file.detectedThreat && (
                <div className="bg-rose-950/50 border border-rose-500/30 rounded-lg p-2 text-xs font-mono text-rose-200 flex items-center justify-between">
                  <span>⚠️ <strong>{isAr ? 'التهديد المرصود:' : 'Intercepted Threat:'}</strong> {file.detectedThreat}</span>
                  {file.matchedRule && (
                    <span className="px-2 py-0.5 rounded bg-rose-900/80 text-[10px] border border-rose-500/40">
                      Rule: {file.matchedRule}
                    </span>
                  )}
                </div>
              )}

              {/* Expanded Sandbox & Forensics Drawer */}
              {isExpanded && (
                <div className="bg-slate-950 rounded-xl p-3 border border-slate-800 space-y-2.5 font-mono text-xs animate-fadeIn">
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-slate-300">
                    <div>
                      <span className="text-[10px] text-slate-400 block">SHA-256 Hash:</span>
                      <div className="flex items-center gap-1.5 mt-0.5">
                        <span className="text-[11px] text-cyan-300 truncate max-w-[280px]">{file.sha256}</span>
                        <button
                          onClick={() => handleCopy(file.sha256)}
                          className="text-slate-400 hover:text-white"
                          title="Copy SHA-256"
                        >
                          {copiedHash === file.sha256 ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                        </button>
                      </div>
                    </div>

                    <div>
                      <span className="text-[10px] text-slate-400 block">{isAr ? 'مسار الحجر بالساندبوكس:' : 'Quarantine Sandbox Path:'}</span>
                      <span className="text-[11px] text-amber-300 truncate block mt-0.5">
                        {file.quarantinePath || (isAr ? 'غير محجور (ملف مسموح به)' : 'Not Quarantined (Approved file)')}
                      </span>
                    </div>
                  </div>

                  {file.sandboxAnalysis && (
                    <div className="p-2.5 rounded-lg bg-slate-900/90 border border-slate-800 space-y-1">
                      <span className="text-[10px] text-slate-400 uppercase tracking-wider block font-bold">
                        {isAr ? 'تقرير بيئة التحليل الرملية (Cyber Threat Sandbox)' : 'Sandbox Behavioral Analysis Report'}
                      </span>
                      <p className="text-xs text-slate-300">
                        {isAr ? file.sandboxAnalysis.detailsAr : file.sandboxAnalysis.threatClassification}
                      </p>
                      <div className="flex flex-wrap items-center gap-3 pt-1 text-[10px] text-slate-400">
                        <span>Binary Packed: <strong className={file.sandboxAnalysis.isPacked ? 'text-rose-400' : 'text-emerald-400'}>{file.sandboxAnalysis.isPacked ? 'YES (Obfuscated)' : 'NO'}</strong></span>
                        <span>•</span>
                        <span>Embedded Executable: <strong className={file.sandboxAnalysis.hasEmbeddedExecutable ? 'text-rose-400' : 'text-emerald-400'}>{file.sandboxAnalysis.hasEmbeddedExecutable ? 'DETECTED' : 'NONE'}</strong></span>
                        <span>•</span>
                        <span>Classification: <strong className="text-cyan-300">{file.sandboxAnalysis.threatClassification}</strong></span>
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
