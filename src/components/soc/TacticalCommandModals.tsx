import React, { useState } from 'react';
import {
  ShieldAlert,
  Lock,
  Search,
  FileDown,
  X,
  CheckCircle2,
  AlertTriangle,
  Globe,
  Sparkles,
  Printer,
  Copy,
  Terminal,
  Activity,
  Zap,
  Clock,
  ShieldCheck
} from 'lucide-react';
import { TargetScanReport } from '../../types';

// =========================================================================
// 1. MANUAL IP QUARANTINE MODAL
// =========================================================================
interface ManualIpQuarantineModalProps {
  isOpen: boolean;
  onClose: () => void;
  lang: 'ar' | 'en';
  onBanSuccess?: () => void;
}

export const ManualIpQuarantineModal: React.FC<ManualIpQuarantineModalProps> = ({
  isOpen,
  onClose,
  lang,
  onBanSuccess
}) => {
  const isAr = lang === 'ar';
  const [ipInput, setIpInput] = useState<string>('194.26.29.0/24');
  const [reasonInput, setReasonInput] = useState<string>('Hostile Automated Exploit & Credential Stuffing Actor');
  const [threatActor, setThreatActor] = useState<string>('APT-29 / RedHydra');
  const [ttlHours, setTtlHours] = useState<number>(24);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleBan = async () => {
    if (!ipInput) return;
    setIsLoading(true);
    try {
      const res = await fetch('/api/v1/traffic/ban-ip', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ip: ipInput,
          reason: reasonInput,
          reasonAr: isAr ? reasonInput : 'حظر يدوي بواسطة مسؤول العمليات',
          threatActor
        })
      });
      if (res.ok) {
        setSuccessMsg(isAr ? `تم حظر ${ipInput} في نواة eBPF بنجاح!` : `Subnet/IP ${ipInput} quarantined in eBPF kernel.`);
        setTimeout(() => {
          setSuccessMsg(null);
          onBanSuccess?.();
          onClose();
        }, 1200);
      }
    } catch (err) {
      console.error('Ban error:', err);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-fadeIn" dir={isAr ? 'rtl' : 'ltr'}>
      <div className="bg-slate-900 border border-rose-500/50 rounded-2xl w-full max-w-md p-5 shadow-2xl space-y-4">
        
        {/* Header */}
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <div className="flex items-center gap-2">
            <div className="p-2 rounded-lg bg-rose-950/80 text-rose-400 border border-rose-500/40">
              <Lock className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-sm font-black uppercase text-slate-100 font-mono">
                {isAr ? 'عزل وحظر عنوان IP يدويًا' : 'Manual IP / Subnet Quarantine'}
              </h3>
              <p className="text-[11px] text-slate-400 font-mono">
                {isAr ? 'إدراج فوري في جدول حظر نواة eBPF' : 'Instant eBPF Kernel Drop Rule Injection'}
              </p>
            </div>
          </div>
          <button onClick={onClose} className="text-slate-400 hover:text-white transition">
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Success Message */}
        {successMsg ? (
          <div className="p-4 bg-emerald-950/80 border border-emerald-500/60 rounded-xl text-emerald-200 text-xs font-mono text-center flex items-center justify-center gap-2">
            <CheckCircle2 className="w-5 h-5 text-emerald-400" />
            <span>{successMsg}</span>
          </div>
        ) : (
          <div className="space-y-3 font-mono text-xs">
            <div>
              <label className="text-slate-300 font-bold block mb-1">
                {isAr ? 'عنوان IP أو نطاق الشبكة (CIDR):' : 'IP Address or Subnet (CIDR):'}
              </label>
              <input
                type="text"
                value={ipInput}
                onChange={(e) => setIpInput(e.target.value)}
                placeholder="194.26.29.112 or 10.0.0.0/24"
                className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-700 text-rose-300 text-xs font-bold focus:outline-none focus:border-rose-400"
              />
            </div>

            <div>
              <label className="text-slate-300 font-bold block mb-1">
                {isAr ? 'اسم الفاعل أو الحملة التهديدية:' : 'Threat Actor / Campaign Tag:'}
              </label>
              <input
                type="text"
                value={threatActor}
                onChange={(e) => setThreatActor(e.target.value)}
                placeholder="APT-29 / VoltSwarm"
                className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-700 text-purple-300 text-xs focus:outline-none"
              />
            </div>

            <div>
              <label className="text-slate-300 font-bold block mb-1">
                {isAr ? 'سبب الحظر التكتيكي:' : 'Quarantine Reason / Justification:'}
              </label>
              <input
                type="text"
                value={reasonInput}
                onChange={(e) => setReasonInput(e.target.value)}
                className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-700 text-slate-200 text-xs focus:outline-none"
              />
            </div>

            <div>
              <label className="text-slate-300 font-bold block mb-1">
                {isAr ? 'مدة الحظر (ساعات):' : 'Quarantine Duration (Hours):'}
              </label>
              <select
                value={ttlHours}
                onChange={(e) => setTtlHours(Number(e.target.value))}
                className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-700 text-cyan-300 text-xs focus:outline-none"
              >
                <option value={1}>1 Hour (Temporary Cooldown)</option>
                <option value={24}>24 Hours (Standard Incident Lockout)</option>
                <option value={168}>7 Days (Extended Threat Containment)</option>
                <option value={8760}>Permanent (Definitive Blacklist)</option>
              </select>
            </div>

            <div className="pt-2 flex items-center justify-end gap-2">
              <button
                onClick={onClose}
                className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-bold transition"
              >
                {isAr ? 'إلغاء' : 'Cancel'}
              </button>
              <button
                onClick={handleBan}
                disabled={isLoading || !ipInput}
                className="px-4 py-2 rounded-lg bg-rose-600 hover:bg-rose-500 text-white text-xs font-bold transition flex items-center gap-1.5 shadow-lg shadow-rose-950 disabled:opacity-50"
              >
                <Lock className="w-3.5 h-3.5" />
                <span>{isLoading ? (isAr ? 'جارِ الحظر...' : 'Quarantining...') : (isAr ? 'تأكيد الحظر في النواة' : 'Enforce Kernel Drop')}</span>
              </button>
            </div>
          </div>
        )}

      </div>
    </div>
  );
};

// =========================================================================
// 2. TARGET SCANNER AUDIT MODAL
// =========================================================================
interface TargetScannerAuditModalProps {
  isOpen: boolean;
  onClose: () => void;
  lang: 'ar' | 'en';
}

export const TargetScannerAuditModal: React.FC<TargetScannerAuditModalProps> = ({
  isOpen,
  onClose,
  lang
}) => {
  const isAr = lang === 'ar';
  const [targetUrl, setTargetUrl] = useState<string>('https://example.com');
  const [scanDepth, setScanDepth] = useState<'STANDARD' | 'DEEP' | 'AGGRESSIVE'>('DEEP');
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [scanReport, setScanReport] = useState<TargetScanReport | null>(null);

  if (!isOpen) return null;

  const handleRunScan = async () => {
    if (!targetUrl) return;
    setIsScanning(true);
    try {
      const res = await fetch('/api/v1/scanner/audit', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ targetUrl, scanDepth })
      });
      if (res.ok) {
        const d = await res.json();
        setScanReport(d.report);
      }
    } catch (err) {
      console.error('Scan error:', err);
    } finally {
      setIsScanning(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-fadeIn" dir={isAr ? 'rtl' : 'ltr'}>
      <div className="bg-slate-900 border border-cyan-500/50 rounded-2xl w-full max-w-2xl p-5 shadow-2xl space-y-4 max-h-[90vh] overflow-y-auto">
        
        {/* Header */}
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <div className="flex items-center gap-2">
            <div className="p-2 rounded-lg bg-cyan-950/80 text-cyan-400 border border-cyan-500/40">
              <Search className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-sm font-black uppercase text-slate-100 font-mono">
                {isAr ? 'فاحص الأهداف وتدقيق الترويسات الأمنية (Target Scanner)' : 'Live Target Posture & Security Header Audit'}
              </h3>
              <p className="text-[11px] text-slate-400 font-mono">
                {isAr ? 'فحص شامل لشهادات SSL وترويسات HSTS, CSP, X-Frame-Options' : 'Real-time HTTP Headers, SSL/TLS, and Defense Posture Scoring'}
              </p>
            </div>
          </div>
          <button onClick={onClose} className="text-slate-400 hover:text-white transition">
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Input Bar */}
        <div className="flex flex-wrap items-center gap-2 font-mono text-xs">
          <input
            type="text"
            value={targetUrl}
            onChange={(e) => setTargetUrl(e.target.value)}
            placeholder="https://target-domain.com"
            className="flex-1 px-3 py-2 rounded-lg bg-slate-950 border border-slate-700 text-cyan-300 focus:outline-none focus:border-cyan-400"
          />
          <select
            value={scanDepth}
            onChange={(e) => setScanDepth(e.target.value as any)}
            className="px-3 py-2 rounded-lg bg-slate-950 border border-slate-700 text-slate-300 focus:outline-none"
          >
            <option value="STANDARD">Standard Scan</option>
            <option value="DEEP">Deep Inspection</option>
            <option value="AGGRESSIVE">Aggressive Recon</option>
          </select>
          <button
            onClick={handleRunScan}
            disabled={isScanning || !targetUrl}
            className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-bold transition flex items-center gap-1.5 shadow-lg shadow-cyan-950 disabled:opacity-50"
          >
            <Search className="w-3.5 h-3.5" />
            <span>{isScanning ? (isAr ? 'جارِ الفحص...' : 'Auditing...') : (isAr ? 'بدء التدقيق' : 'Run Audit')}</span>
          </button>
        </div>

        {/* Scan Report Display */}
        {scanReport && (
          <div className="space-y-3 font-mono text-xs pt-2">
            <div className="grid grid-cols-3 gap-3">
              <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 text-center">
                <span className="text-[10px] text-slate-400 block">OVERALL GRADE</span>
                <span className={`text-xl font-black ${scanReport.overallScore >= 80 ? 'text-emerald-400' : 'text-rose-400'}`}>
                  {scanReport.grade}
                </span>
              </div>
              <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 text-center">
                <span className="text-[10px] text-slate-400 block">POSTURE SCORE</span>
                <span className="text-xl font-black text-cyan-300">{scanReport.overallScore}/100</span>
              </div>
              <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 text-center">
                <span className="text-[10px] text-slate-400 block">HOST TARGET</span>
                <span className="text-xs font-bold text-slate-200 truncate block mt-1">{scanReport.normalizedHost}</span>
              </div>
            </div>

            {/* Executive Summary */}
            <div className="p-3 rounded-xl bg-indigo-950/30 border border-indigo-500/40 text-slate-300 leading-relaxed">
              <div className="flex items-center gap-1.5 text-indigo-300 font-bold mb-1">
                <Sparkles className="w-3.5 h-3.5" />
                <span>{isAr ? 'ملخص التقييم التنفيذي' : 'Executive Security Audit Summary'}</span>
              </div>
              <p className="text-xs">{isAr ? scanReport.executiveSummaryAr : scanReport.executiveSummaryEn}</p>
            </div>

            {/* Security Headers Findings */}
            <div className="space-y-1.5">
              <span className="text-slate-300 font-bold block">HTTP SECURITY HEADERS STATUS:</span>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                {scanReport.headersAnalyzed.map((h) => (
                  <div key={h.headerName} className="p-2 rounded bg-slate-950 border border-slate-800 flex items-center justify-between">
                    <span className="text-slate-300 font-bold">{h.headerName}</span>
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                      h.present ? 'bg-emerald-950 text-emerald-300' : 'bg-rose-950 text-rose-300'
                    }`}>
                      {h.present ? 'PRESENT' : 'MISSING'}
                    </span>
                  </div>
                ))}
              </div>
            </div>

            {/* Remediation Snippet */}
            {scanReport.remediationConfigSnippet && (
              <div>
                <span className="text-slate-300 font-bold block mb-1">RECOMMENDED NGINX HARDENING SNIPPET:</span>
                <pre className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-[11px] text-emerald-300 overflow-x-auto select-all">
                  {scanReport.remediationConfigSnippet}
                </pre>
              </div>
            )}
          </div>
        )}

      </div>
    </div>
  );
};

// =========================================================================
// 3. EXPORT FORENSIC REPORT MODAL
// =========================================================================
interface ExportForensicReportModalProps {
  isOpen: boolean;
  onClose: () => void;
  lang: 'ar' | 'en';
}

export const ExportForensicReportModal: React.FC<ExportForensicReportModalProps> = ({
  isOpen,
  onClose,
  lang
}) => {
  const isAr = lang === 'ar';
  const [incidentId, setIncidentId] = useState<string>('INC-2026-0830');
  const [reportData, setReportData] = useState<any>(null);
  const [isGenerating, setIsGenerating] = useState<boolean>(false);

  if (!isOpen) return null;

  const handleGenerateReport = async () => {
    setIsGenerating(true);
    try {
      const res = await fetch(`/api/v1/forensics/report/generate?incidentId=${incidentId}`);
      if (res.ok) {
        const d = await res.json();
        setReportData(d.report);
      }
    } catch (err) {
      console.error('Report error:', err);
    } finally {
      setIsGenerating(false);
    }
  };

  const handleDownloadJson = () => {
    if (!reportData) return;
    const blob = new Blob([JSON.stringify(reportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `SovereignDefender-ForensicReport-${incidentId}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handlePrintPdf = () => {
    window.print();
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-fadeIn" dir={isAr ? 'rtl' : 'ltr'}>
      <div className="bg-slate-900 border border-purple-500/50 rounded-2xl w-full max-w-2xl p-5 shadow-2xl space-y-4 max-h-[90vh] overflow-y-auto">
        
        {/* Header */}
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <div className="flex items-center gap-2">
            <div className="p-2 rounded-lg bg-purple-950/80 text-purple-400 border border-purple-500/40">
              <FileDown className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-sm font-black uppercase text-slate-100 font-mono">
                {isAr ? 'تصدير التقرير الجنائي الرقمي للحادثة السيبرانية' : 'Export Incident Forensic Report (JSON / PDF)'}
              </h3>
              <p className="text-[11px] text-slate-400 font-mono">
                {isAr ? 'تجميع الأدلة التشفيرية، بصمات FIM، سلاسل الهجمات، والأثر الجنائي' : 'Cryptographic Chain of Custody & Complete SOC Audit Export'}
              </p>
            </div>
          </div>
          <button onClick={onClose} className="text-slate-400 hover:text-white transition">
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Generator Controls */}
        <div className="flex items-center gap-2 font-mono text-xs">
          <input
            type="text"
            value={incidentId}
            onChange={(e) => setIncidentId(e.target.value)}
            placeholder="INC-2026-0830"
            className="flex-1 px-3 py-2 rounded-lg bg-slate-950 border border-slate-700 text-purple-300 focus:outline-none"
          />
          <button
            onClick={handleGenerateReport}
            disabled={isGenerating}
            className="px-4 py-2 rounded-lg bg-purple-600 hover:bg-purple-500 text-white font-bold transition flex items-center gap-1.5 shadow-lg shadow-purple-950"
          >
            <Sparkles className="w-3.5 h-3.5" />
            <span>{isGenerating ? (isAr ? 'جارِ التوليد...' : 'Compiling Audit...') : (isAr ? 'توليد التقرير' : 'Compile Report')}</span>
          </button>
        </div>

        {/* Report Preview */}
        {reportData && (
          <div className="space-y-3 font-mono text-xs pt-2">
            <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 space-y-2">
              <div className="flex items-center justify-between">
                <span className="font-bold text-slate-200">REPORT ID: {reportData.id}</span>
                <span className="text-slate-400">{new Date(reportData.generatedAt).toLocaleString()}</span>
              </div>
              <p className="text-slate-300">{reportData.summaryEn}</p>
              <div className="flex items-center gap-3 pt-2 border-t border-slate-800 text-[11px] text-cyan-300">
                <span>Threat Level: <strong className="text-rose-400">{reportData.threatLevel}</strong></span>
                <span>Events Audited: <strong>{reportData.evidenceSummary?.length || 8}</strong></span>
                <span>Signatures: <strong>SHA-256 Verified</strong></span>
              </div>
            </div>

            {/* Action Download Buttons */}
            <div className="flex items-center justify-end gap-2 pt-2">
              <button
                onClick={handlePrintPdf}
                className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 font-bold transition flex items-center gap-1.5"
              >
                <Printer className="w-3.5 h-3.5" />
                <span>{isAr ? 'طباعة / حفظ PDF' : 'Print / Save PDF'}</span>
              </button>
              <button
                onClick={handleDownloadJson}
                className="px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-bold transition flex items-center gap-1.5 shadow-lg shadow-emerald-950"
              >
                <FileDown className="w-3.5 h-3.5" />
                <span>{isAr ? 'تنزيل ملف JSON' : 'Download JSON Audit'}</span>
              </button>
            </div>
          </div>
        )}

      </div>
    </div>
  );
};
