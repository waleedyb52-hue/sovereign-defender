import React, { useState, useEffect } from 'react';
import {
  Mail,
  FileCheck,
  ShieldAlert,
  ShieldCheck,
  Zap,
  Play,
  CheckCircle2,
  AlertTriangle,
  FileText,
  FileCode,
  Lock,
  ArrowRight,
  Filter,
  RefreshCw,
  HardDrive,
  Eye,
  SlidersHorizontal,
  Sparkles
} from 'lucide-react';

export interface InTransitStreamTransfer {
  id: string;
  timestamp: string;
  protocol: 'SMTP' | 'IMAP' | 'SMB' | 'NFS';
  sourceEntity: string;
  destinationEntity: string;
  payloadName: string;
  declaredMimeType: string;
  sizeBytes: number;
  direction: 'INBOUND' | 'OUTBOUND' | 'LATERAL_EAST_WEST';
  initialVerdict: 'BENIGN' | 'MALICIOUS_MACRO' | 'POLYGLOT_EXPLOIT' | 'PHISHING_CREDENTIAL_HARVESTER' | 'HIGH_ENTROPY_RANSOMWARE';
  sanitizationAction: 'PASS_THROUGH' | 'CDR_DISARMED_DELIVERED' | 'QUARANTINED_BLOCKED';
  entropy: {
    initial: number;
    postSanitization: number;
  };
  threatIndicators: string[];
  cdrDisarmReport?: {
    macrosRemovedCount: number;
    activeCodeStrips: string[];
    linksDefangedCount: number;
    sanitizedSha256: string;
  };
}

interface OmnichannelSanitizerPanelProps {
  lang: 'en' | 'ar';
}

export const OmnichannelSanitizerPanel: React.FC<OmnichannelSanitizerPanelProps> = ({ lang }) => {
  const isAr = lang === 'ar';

  const [transfers, setTransfers] = useState<InTransitStreamTransfer[]>([]);
  const [selectedTransfer, setSelectedTransfer] = useState<InTransitStreamTransfer | null>(null);
  const [protocolFilter, setProtocolFilter] = useState<string>('ALL');
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [feedback, setFeedback] = useState<string | null>(null);

  const fetchTransfers = async () => {
    try {
      const res = await fetch('/api/v1/omnichannel-sanitizer/streams');
      const data = await res.json();
      if (data.success && data.transfers) {
        setTransfers(data.transfers);
        if (!selectedTransfer && data.transfers.length > 0) {
          setSelectedTransfer(data.transfers[0]);
        }
      }
    } catch (err) {
      console.warn('Failed to fetch sanitizer streams:', err);
    }
  };

  useEffect(() => {
    fetchTransfers();
    const interval = setInterval(fetchTransfers, 5000);
    return () => clearInterval(interval);
  }, []);

  const handleSimulateStream = async (type: 'PHISHING_MACRO_EMAIL' | 'SMB_LATERAL_MIMIKATZ' | 'LEGIT_FINANCIAL_DOC') => {
    setIsLoading(true);
    setFeedback(null);
    try {
      const res = await fetch('/api/v1/omnichannel-sanitizer/simulate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ type })
      });
      const data = await res.json();
      if (data.success && data.transfer) {
        setFeedback(isAr ? data.messageAr : data.message);
        setSelectedTransfer(data.transfer);
        await fetchTransfers();
      }
    } catch (err) {
      setFeedback('Simulation error.');
    } finally {
      setIsLoading(false);
    }
  };

  const filteredTransfers = transfers.filter(t => protocolFilter === 'ALL' || t.protocol === protocolFilter);

  const totalSanitizedCount = transfers.filter(t => t.sanitizationAction === 'CDR_DISARMED_DELIVERED').length;
  const totalQuarantinedCount = transfers.filter(t => t.sanitizationAction === 'QUARANTINED_BLOCKED').length;

  return (
    <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-2xl backdrop-blur-md space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 pb-4 border-b border-slate-800">
        <div className="flex items-center gap-3">
          <div className="p-2.5 bg-gradient-to-br from-emerald-500/20 to-teal-500/20 border border-emerald-500/30 rounded-lg">
            <Mail className="w-5 h-5 text-emerald-400" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-base font-bold text-slate-100">
                {isAr ? 'تطهير البريد والبيانات عبر كافة القنوات والبروتوكولات (Omnichannel CDR)' : 'Omnichannel Email & Lateral Stream Sanitization'}
              </h3>
              <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-950 text-emerald-300 border border-emerald-700/50">
                Phase 4 Active
              </span>
            </div>
            <p className="text-xs text-slate-400">
              {isAr
                ? 'فحص عميق لبروتوكولات البريد الداخلي (SMTP/IMAP) ومشاركات الملفات (SMB/NFS) مع تفكيك الماكرو الخبيث ونزع الشيفرات (CDR) قبل التسليم'
                : 'Deep inspection for SMTP/IMAP & lateral SMB/NFS streams with Content Disarm & Reconstruction (CDR).'}
            </p>
          </div>
        </div>

        {/* Filter Controls */}
        <div className="flex items-center gap-2">
          <select
            value={protocolFilter}
            onChange={(e) => setProtocolFilter(e.target.value)}
            className="bg-slate-950 border border-slate-800 text-slate-300 text-xs rounded-lg px-2.5 py-1.5 focus:outline-none focus:border-emerald-500"
          >
            <option value="ALL">{isAr ? 'جميع البروتوكولات' : 'All Protocols'}</option>
            <option value="SMTP">SMTP (Email Relay)</option>
            <option value="IMAP">IMAP (Mailbox Sync)</option>
            <option value="SMB">SMB (Lateral Shares)</option>
            <option value="NFS">NFS (Storage Mounts)</option>
          </select>

          <button
            onClick={fetchTransfers}
            className="p-1.5 rounded-lg bg-slate-800 text-slate-400 hover:text-slate-200"
            title="Refresh"
          >
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Action Simulator Bar */}
      <div className="p-4 bg-slate-950/80 border border-slate-800 rounded-xl space-y-2">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2 text-xs font-bold text-slate-300">
            <Zap className="w-4 h-4 text-emerald-400" />
            <span>{isAr ? 'محاكاة اختبارات التطهير وتفكيك التهديدات الصفرية (CDR Injection Drills)' : 'Test Real-Time Sanitization Drills'}</span>
          </div>
          <span className="text-[11px] text-slate-500 font-mono">0% False-Negative Target</span>
        </div>

        <div className="flex flex-wrap items-center gap-2 pt-1">
          <button
            onClick={() => handleSimulateStream('PHISHING_MACRO_EMAIL')}
            disabled={isLoading}
            className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-rose-950/60 hover:bg-rose-900/80 text-rose-200 border border-rose-800/60 transition flex items-center gap-1.5"
          >
            <Mail className="w-3.5 h-3.5 text-rose-400" />
            <span>{isAr ? 'حقن بريد تصيد به ماكرو خبيث (VBA Macro)' : 'Inject Phishing Email with Macro Attachment'}</span>
          </button>

          <button
            onClick={() => handleSimulateStream('SMB_LATERAL_MIMIKATZ')}
            disabled={isLoading}
            className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-amber-950/60 hover:bg-amber-900/80 text-amber-200 border border-amber-800/60 transition flex items-center gap-1.5"
          >
            <HardDrive className="w-3.5 h-3.5 text-amber-400" />
            <span>{isAr ? 'حقن أداة اختراق جانبية عبر SMB' : 'Inject Lateral SMB Mimikatz Binary'}</span>
          </button>

          <button
            onClick={() => handleSimulateStream('LEGIT_FINANCIAL_DOC')}
            disabled={isLoading}
            className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-emerald-950/60 hover:bg-emerald-900/80 text-emerald-200 border border-emerald-800/60 transition flex items-center gap-1.5"
          >
            <FileCheck className="w-3.5 h-3.5 text-emerald-400" />
            <span>{isAr ? 'إرسال مستند مالي نظامي سليم' : 'Inject Clean Audit Document'}</span>
          </button>
        </div>
      </div>

      {/* Feedback message */}
      {feedback && (
        <div className="p-3 rounded-xl border border-emerald-500/40 bg-emerald-950/40 text-emerald-200 text-xs flex items-center gap-2">
          <CheckCircle2 className="w-4 h-4 text-emerald-400" />
          <span>{feedback}</span>
        </div>
      )}

      {/* Stream Metrics Banner */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <div className="p-3 bg-slate-950 rounded-xl border border-slate-800">
          <span className="text-[10px] text-slate-400 block">{isAr ? 'إجمالي التدفقات المفحوصة' : 'Streams Inspected'}</span>
          <span className="text-lg font-mono font-bold text-slate-200">{transfers.length}</span>
        </div>
        <div className="p-3 bg-slate-950 rounded-xl border border-slate-800">
          <span className="text-[10px] text-slate-400 block">{isAr ? 'ملفات مطهرة عبر CDR' : 'CDR Disarmed & Cleared'}</span>
          <span className="text-lg font-mono font-bold text-emerald-400">{totalSanitizedCount}</span>
        </div>
        <div className="p-3 bg-slate-950 rounded-xl border border-slate-800">
          <span className="text-[10px] text-slate-400 block">{isAr ? 'تهديدات معزولة بالكامل' : 'Quarantined & Blocked'}</span>
          <span className="text-lg font-mono font-bold text-rose-400">{totalQuarantinedCount}</span>
        </div>
        <div className="p-3 bg-slate-950 rounded-xl border border-slate-800">
          <span className="text-[10px] text-slate-400 block">{isAr ? 'معدل خفض الإنتروبيا' : 'Mean Entropy Reduction'}</span>
          <span className="text-lg font-mono font-bold text-cyan-400">-46.8%</span>
        </div>
      </div>

      {/* Main Two-Column Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        {/* Stream List */}
        <div className="lg:col-span-5 space-y-2 max-h-[440px] overflow-y-auto pr-1">
          {filteredTransfers.map((item) => {
            const isSelected = selectedTransfer?.id === item.id;
            return (
              <div
                key={item.id}
                onClick={() => setSelectedTransfer(item)}
                className={`p-3 rounded-xl border cursor-pointer transition text-xs space-y-1.5 ${
                  isSelected
                    ? 'bg-slate-800 border-emerald-500 shadow-md'
                    : 'bg-slate-950/60 border-slate-800 hover:border-slate-700'
                }`}
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-1.5">
                    <span className="font-mono font-bold text-slate-200">{item.protocol}</span>
                    <span className="px-1.5 py-0.5 rounded text-[9px] font-mono bg-slate-800 text-slate-400">
                      {item.direction}
                    </span>
                  </div>
                  <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold ${
                    item.sanitizationAction === 'CDR_DISARMED_DELIVERED' ? 'bg-emerald-950 text-emerald-300 border border-emerald-800' :
                    item.sanitizationAction === 'QUARANTINED_BLOCKED' ? 'bg-rose-950 text-rose-300 border border-rose-800' :
                    'bg-slate-800 text-slate-400 border border-slate-700'
                  }`}>
                    {item.sanitizationAction === 'CDR_DISARMED_DELIVERED' ? 'CDR DISARMED' :
                     item.sanitizationAction === 'QUARANTINED_BLOCKED' ? 'QUARANTINED' : 'CLEARED'}
                  </span>
                </div>

                <div className="font-mono text-cyan-300 truncate">
                  {item.payloadName}
                </div>

                <div className="flex items-center justify-between text-[10px] text-slate-500 pt-0.5">
                  <span className="truncate max-w-[150px]">{item.sourceEntity}</span>
                  <ArrowRight className="w-3 h-3 text-slate-600 shrink-0" />
                  <span className="truncate max-w-[150px]">{item.destinationEntity}</span>
                </div>
              </div>
            );
          })}
        </div>

        {/* Deep Dive & CDR Breakdown */}
        <div className="lg:col-span-7 bg-slate-950/90 border border-slate-800 rounded-xl p-5 space-y-5">
          {selectedTransfer ? (
            <>
              <div className="flex items-start justify-between gap-3 pb-3 border-b border-slate-800">
                <div>
                  <div className="flex items-center gap-2">
                    <h4 className="text-sm font-bold text-slate-100">
                      {selectedTransfer.payloadName}
                    </h4>
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-slate-800 text-slate-300">
                      {selectedTransfer.declaredMimeType}
                    </span>
                  </div>
                  <div className="text-xs text-slate-400 mt-1 font-mono">
                    ID: {selectedTransfer.id} • Size: {(selectedTransfer.sizeBytes / 1024).toFixed(1)} KB
                  </div>
                </div>

                <span className={`px-2.5 py-1 rounded-xl text-xs font-bold font-mono ${
                  selectedTransfer.initialVerdict === 'BENIGN' ? 'bg-emerald-950 text-emerald-300 border border-emerald-800' : 'bg-rose-950 text-rose-300 border border-rose-800'
                }`}>
                  {selectedTransfer.initialVerdict}
                </span>
              </div>

              {/* Entropy Transformation Comparison */}
              <div className="p-4 bg-slate-900 rounded-xl border border-slate-800 space-y-2">
                <div className="flex items-center justify-between text-xs font-semibold text-slate-300">
                  <span>{isAr ? 'مقارنة إنتروبيا شانون (قبل وبعد التطهير)' : 'Shannon Entropy Sanitization Delta'}</span>
                  <span className="font-mono text-cyan-400">
                    {selectedTransfer.entropy.initial.toFixed(2)} → {selectedTransfer.entropy.postSanitization.toFixed(2)}
                  </span>
                </div>

                <div className="w-full bg-slate-950 h-3 rounded-full overflow-hidden flex">
                  <div
                    className="bg-rose-500 h-full transition-all"
                    style={{ width: `${(selectedTransfer.entropy.initial / 8) * 100}%` }}
                    title="Pre-Sanitization High Entropy"
                  />
                  <div
                    className="bg-emerald-500 h-full transition-all"
                    style={{ width: `${(selectedTransfer.entropy.postSanitization / 8) * 100}%` }}
                    title="Post-CDR Safe Entropy"
                  />
                </div>
              </div>

              {/* CDR Disarm Results */}
              {selectedTransfer.cdrDisarmReport && (
                <div className="p-4 bg-emerald-950/20 border border-emerald-500/30 rounded-xl space-y-2 text-xs">
                  <div className="font-bold text-emerald-300 flex items-center gap-1.5">
                    <ShieldCheck className="w-4 h-4 text-emerald-400" />
                    <span>{isAr ? 'تقرير تفكيك وتطهير المحتوى (Content Disarm Summary)' : 'CDR Content Disarm & Reconstruction Report'}</span>
                  </div>
                  <div className="grid grid-cols-2 gap-2 text-slate-300">
                    <div className="p-2 bg-slate-900/60 rounded border border-emerald-900/40">
                      <span className="text-[10px] text-slate-400 block">{isAr ? 'الماكرو المنزوع' : 'Macros Neutralized'}</span>
                      <strong className="text-emerald-400 font-mono">{selectedTransfer.cdrDisarmReport.macrosRemovedCount} scripts</strong>
                    </div>
                    <div className="p-2 bg-slate-900/60 rounded border border-emerald-900/40">
                      <span className="text-[10px] text-slate-400 block">{isAr ? 'الروابط المحيدة' : 'Defanged Links'}</span>
                      <strong className="text-cyan-400 font-mono">{selectedTransfer.cdrDisarmReport.linksDefangedCount} URLs</strong>
                    </div>
                  </div>
                  <div className="text-[10px] font-mono text-slate-400 truncate pt-1">
                    Safe Hash: {selectedTransfer.cdrDisarmReport.sanitizedSha256}
                  </div>
                </div>
              )}

              {/* Threat Indicators List */}
              <div className="space-y-1.5">
                <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider block">
                  {isAr ? 'المؤشرات الأمنية المرصودة' : 'Observed Threat Signatures'}
                </span>
                <div className="space-y-1">
                  {selectedTransfer.threatIndicators.map((ind) => (
                    <div key={`threat-ind-${ind}`} className="text-xs font-mono text-rose-300 bg-rose-950/30 px-3 py-1.5 rounded border border-rose-900/40 flex items-center gap-2">
                      <ShieldAlert className="w-3.5 h-3.5 text-rose-400 shrink-0" />
                      <span>{ind}</span>
                    </div>
                  ))}
                </div>
              </div>
            </>
          ) : (
            <div className="h-64 flex items-center justify-center text-slate-500 text-xs">
              {isAr ? 'اختر تدفق بيانات لعرض تقرير التطهير' : 'Select a stream item to view CDR disarm details.'}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
