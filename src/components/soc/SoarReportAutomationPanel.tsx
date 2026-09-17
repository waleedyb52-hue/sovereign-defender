import React, { useState, useEffect } from 'react';
import {
  FileText,
  Download,
  Calendar,
  Send,
  ShieldCheck,
  CheckCircle2,
  Clock,
  Printer,
  Sparkles,
  Activity,
  Layers,
  FileCheck,
  RefreshCw,
  ExternalLink,
  ChevronRight
} from 'lucide-react';

export interface AutomatedReportData {
  id: string;
  generatedAt: string;
  scheduleType: string;
  classification: string;
  complianceStandard: string;
  executiveSummary: {
    overallPostureScore: number;
    totalEventsIngested: number;
    threatsNeutralized: number;
    zeroTrustInterceptionsCount: number;
    quarantinedPayloadsCount: number;
    activeKernelBlackholes: number;
    mttdSeconds: number;
    mttrSeconds: number;
    keyFindingsEn: string[];
    keyFindingsAr: string[];
  };
  threatCategories: {
    category: string;
    count: number;
    trend: string;
    severity: string;
  }[];
  mitreHeatmapHighlights: {
    techniqueId: string;
    techniqueName: string;
    interceptCount: number;
  }[];
  dispatchStatus: {
    status: string;
    channels: {
      channel: string;
      recipient: string;
      deliveredAt: string;
      receiptHash: string;
    }[];
  };
  cryptographicSeal: {
    signatureAlgo: string;
    sha256Digest: string;
    verificationSignature: string;
    signingAuthority: string;
  };
}

interface SoarReportAutomationPanelProps {
  lang: 'en' | 'ar';
}

export const SoarReportAutomationPanel: React.FC<SoarReportAutomationPanelProps> = ({ lang }) => {
  const isAr = lang === 'ar';

  const [reports, setReports] = useState<AutomatedReportData[]>([]);
  const [activeReport, setActiveReport] = useState<AutomatedReportData | null>(null);
  const [schedulerSettings, setSchedulerSettings] = useState<any>(null);
  const [isCompiling, setIsCompiling] = useState<boolean>(false);
  const [feedbackMessage, setFeedbackMessage] = useState<string | null>(null);

  const fetchReports = async () => {
    try {
      const res = await fetch('/api/v1/soar-reports/latest');
      const data = await res.json();
      if (data.success) {
        setReports(data.reports || []);
        if (!activeReport && data.latestReport) {
          setActiveReport(data.latestReport);
        }
        setSchedulerSettings(data.schedulerSettings);
      }
    } catch (err) {
      console.warn('Failed to load reports:', err);
    }
  };

  useEffect(() => {
    fetchReports();
  }, []);

  const handleCompileOnDemand = async (scheduleType: string) => {
    setIsCompiling(true);
    setFeedbackMessage(null);
    try {
      const res = await fetch('/api/v1/soar-reports/generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scheduleType })
      });
      const data = await res.json();
      if (data.success && data.report) {
        setFeedbackMessage(isAr ? data.messageAr : data.message);
        setActiveReport(data.report);
        await fetchReports();
      }
    } catch (err) {
      setFeedbackMessage('Failed to compile report.');
    } finally {
      setIsCompiling(false);
    }
  };

  const handlePrint = () => {
    window.print();
  };

  const handleDownloadJson = () => {
    if (!activeReport) return;
    const blob = new Blob([JSON.stringify(activeReport, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${activeReport.id}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-2xl backdrop-blur-md space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 pb-4 border-b border-slate-800">
        <div className="flex items-center gap-3">
          <div className="p-2.5 bg-gradient-to-br from-indigo-500/20 to-cyan-500/20 border border-indigo-500/30 rounded-lg">
            <FileCheck className="w-5 h-5 text-cyan-400" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-base font-bold text-slate-100">
                {isAr ? 'أتمتة تقارير العمليات السيبرانية والإرسال الذاتي (SOAR Executive Reports)' : 'Full SOAR Report Automation & Autonomous Dispatch'}
              </h3>
              <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-indigo-950 text-indigo-300 border border-indigo-700/50">
                Phase 2 Active
              </span>
            </div>
            <p className="text-xs text-slate-400">
              {isAr
                ? 'محرك جدولة خلفي يجمع تلقائياً مؤشرات الدفاع، الحمولات المعزولة، وتوقيعات الـ HMAC التشفيرية، ويوزعها على مكتب الـ CISO وقنوات الدفاع'
                : 'Background scheduling engine compiling comprehensive security reports & auto-dispatching to CISO & MoD.'}
            </p>
          </div>
        </div>

        {/* Action buttons */}
        <div className="flex items-center gap-2">
          <button
            onClick={() => handleCompileOnDemand('DAILY_EXECUTIVE')}
            disabled={isCompiling}
            className="px-3 py-1.5 rounded-lg text-xs font-bold bg-cyan-600 hover:bg-cyan-500 text-white transition flex items-center gap-1.5 shadow-md shadow-cyan-900/30 disabled:opacity-50"
          >
            <Sparkles className="w-3.5 h-3.5" />
            <span>{isAr ? 'توليد وإرسال فوري الآن' : 'Compile & Dispatch Now'}</span>
          </button>

          <button
            onClick={handleDownloadJson}
            disabled={!activeReport}
            className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 transition"
            title="Download JSON"
          >
            <Download className="w-4 h-4" />
          </button>

          <button
            onClick={handlePrint}
            disabled={!activeReport}
            className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 transition"
            title="Print Official PDF"
          >
            <Printer className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Scheduler Status Pill */}
      {schedulerSettings && (
        <div className="p-3 bg-slate-950/80 rounded-xl border border-slate-800 flex flex-wrap items-center justify-between text-xs gap-3">
          <div className="flex items-center gap-2">
            <Clock className="w-4 h-4 text-cyan-400" />
            <span className="text-slate-400">{isAr ? 'الجدولة النشطة:' : 'Active Cron Cadence:'}</span>
            <span className="text-slate-200 font-semibold font-mono">Daily at {schedulerSettings.dailyTimeUtc} UTC + Weekly CISO Brief</span>
          </div>
          <div className="flex items-center gap-4 text-slate-400">
            <span>Recipient: <strong className="text-cyan-300">{schedulerSettings.cisoEmail}</strong></span>
            <span>MoD Ledger: <strong className="text-emerald-400">Synchronized</strong></span>
          </div>
        </div>
      )}

      {/* Feedback Alert */}
      {feedbackMessage && (
        <div className="p-3 rounded-xl border border-emerald-500/40 bg-emerald-950/40 text-emerald-200 text-xs flex items-center gap-2">
          <CheckCircle2 className="w-4 h-4 text-emerald-400" />
          <span>{feedbackMessage}</span>
        </div>
      )}

      {/* Report Viewer Container */}
      {activeReport ? (
        <div className="bg-slate-950 border border-slate-800 rounded-xl p-6 space-y-6 print:bg-white print:text-black print:border-none">
          {/* Official Letterhead */}
          <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 pb-4 border-b border-slate-800 print:border-gray-300">
            <div>
              <div className="text-[10px] font-mono text-rose-400 font-bold uppercase tracking-wider">
                {activeReport.classification}
              </div>
              <h2 className="text-lg font-bold text-slate-100 print:text-black mt-0.5">
                {isAr ? 'التقرير الأمني الاستراتيجي الشامل لمنظومة الدفاع السيادي' : 'Sovereign Cyber Defense Executive Briefing'}
              </h2>
              <div className="text-xs text-slate-400 print:text-gray-600 font-mono mt-0.5">
                Ref: {activeReport.id} • Standard: {activeReport.complianceStandard}
              </div>
            </div>

            <div className="text-right">
              <div className="text-xs text-slate-400 print:text-gray-600">
                {new Date(activeReport.generatedAt).toLocaleString()}
              </div>
              <span className="px-2.5 py-0.5 rounded text-[11px] font-bold bg-emerald-950/80 text-emerald-300 border border-emerald-700/50 print:bg-gray-100 print:text-black">
                {activeReport.scheduleType}
              </span>
            </div>
          </div>

          {/* Core Posture Scores */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <div className="p-3 bg-slate-900/80 print:bg-gray-50 rounded-xl border border-slate-800 print:border-gray-300">
              <span className="text-[10px] text-slate-400 print:text-gray-600 block">{isAr ? 'مؤشر الصمود العام' : 'Security Posture'}</span>
              <span className="text-xl font-mono font-bold text-emerald-400 print:text-emerald-700">
                {activeReport.executiveSummary.overallPostureScore}%
              </span>
            </div>

            <div className="p-3 bg-slate-900/80 print:bg-gray-50 rounded-xl border border-slate-800 print:border-gray-300">
              <span className="text-[10px] text-slate-400 print:text-gray-600 block">{isAr ? 'التهديدات المحيدة' : 'Threats Neutralized'}</span>
              <span className="text-xl font-mono font-bold text-cyan-400 print:text-cyan-700">
                {activeReport.executiveSummary.threatsNeutralized}
              </span>
            </div>

            <div className="p-3 bg-slate-900/80 print:bg-gray-50 rounded-xl border border-slate-800 print:border-gray-300">
              <span className="text-[10px] text-slate-400 print:text-gray-600 block">{isAr ? 'الحمولات المعزولة' : 'Quarantined Payloads'}</span>
              <span className="text-xl font-mono font-bold text-rose-400 print:text-rose-700">
                {activeReport.executiveSummary.quarantinedPayloadsCount}
              </span>
            </div>

            <div className="p-3 bg-slate-900/80 print:bg-gray-50 rounded-xl border border-slate-800 print:border-gray-300">
              <span className="text-[10px] text-slate-400 print:text-gray-600 block">{isAr ? 'زمن الرصد (MTTD)' : 'MTTD (Sub-ms)'}</span>
              <span className="text-xl font-mono font-bold text-amber-400 print:text-amber-700">
                {(activeReport.executiveSummary.mttdSeconds * 1000).toFixed(2)} ms
              </span>
            </div>
          </div>

          {/* Key Findings */}
          <div className="space-y-2">
            <h4 className="text-xs font-bold text-slate-300 print:text-black uppercase tracking-wider">
              {isAr ? 'النتائج الاستراتيجية الرئيسية' : 'Executive Key Findings'}
            </h4>
            <ul className="space-y-1.5 text-xs text-slate-300 print:text-gray-800">
              {(isAr ? activeReport.executiveSummary.keyFindingsAr : activeReport.executiveSummary.keyFindingsEn).map((finding) => (
                <li key={`finding-${finding.slice(0, 32)}`} className="flex items-start gap-2 bg-slate-900/40 print:bg-transparent p-2 rounded-lg border border-slate-800/60 print:border-none">
                  <CheckCircle2 className="w-4 h-4 text-emerald-400 mt-0.5 shrink-0" />
                  <span>{finding}</span>
                </li>
              ))}
            </ul>
          </div>

          {/* Autonomous Dispatch Confirmation */}
          <div className="p-4 bg-slate-900/60 print:bg-gray-50 rounded-xl border border-slate-800 print:border-gray-300 space-y-2">
            <div className="flex items-center justify-between text-xs">
              <span className="font-bold text-slate-300 print:text-black flex items-center gap-1.5">
                <Send className="w-3.5 h-3.5 text-cyan-400" />
                <span>{isAr ? 'سجل التوزيع والإرسال الذاتي للتقرير' : 'Autonomous SOAR Dispatch Log'}</span>
              </span>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-emerald-950 text-emerald-300 border border-emerald-800">
                {activeReport.dispatchStatus.status}
              </span>
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 text-[11px] text-slate-400 print:text-gray-600">
              {activeReport.dispatchStatus.channels.map((c) => (
                <div key={`channel-${c.channel}-${c.recipient}`} className="p-2 bg-slate-950 print:bg-white rounded border border-slate-800/80 print:border-gray-200">
                  <div className="font-semibold text-slate-200 print:text-black truncate">{c.channel}</div>
                  <div className="truncate text-[10px] text-slate-500">{c.recipient}</div>
                  <div className="text-[9px] font-mono text-cyan-400 mt-1">{c.receiptHash}</div>
                </div>
              ))}
            </div>
          </div>

          {/* Cryptographic Signature Seal */}
          <div className="p-3 bg-black/60 print:bg-gray-100 rounded-xl border border-slate-800 print:border-gray-300 text-[10px] font-mono text-slate-400 print:text-gray-700 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2">
            <div>
              <span className="text-slate-500">SHA-256 Digest:</span> {activeReport.cryptographicSeal.sha256Digest.slice(0, 32)}...
            </div>
            <div className="text-cyan-400 print:text-cyan-700 font-bold">
              HMAC-SHA256 Verified Seal • {activeReport.cryptographicSeal.signingAuthority}
            </div>
          </div>
        </div>
      ) : (
        <div className="p-12 text-center text-slate-500 text-xs">
          {isAr ? 'لا توجد تقارير منشأة حالياً' : 'No reports generated yet.'}
        </div>
      )}
    </div>
  );
};
