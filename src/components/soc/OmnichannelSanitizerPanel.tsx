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
  initialVerdict:
    | 'BENIGN'
    | 'MALICIOUS_MACRO'
    | 'POLYGLOT_EXPLOIT'
    | 'PHISHING_CREDENTIAL_HARVESTER'
    | 'HIGH_ENTROPY_RANSOMWARE';
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

  const handleSimulateStream = async (
    type: 'PHISHING_MACRO_EMAIL' | 'SMB_LATERAL_MIMIKATZ' | 'LEGIT_FINANCIAL_DOC'
  ) => {
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

  const filteredTransfers = transfers.filter(
    t => protocolFilter === 'ALL' || t.protocol === protocolFilter
  );

  const totalSanitizedCount = transfers.filter(
    t => t.sanitizationAction === 'CDR_DISARMED_DELIVERED'
  ).length;
  const totalQuarantinedCount = transfers.filter(
    t => t.sanitizationAction === 'QUARANTINED_BLOCKED'
  ).length;

  return (
    <div className="space-y-6 rounded-xl border border-slate-800 bg-slate-900/90 p-5 shadow-2xl backdrop-blur-md shadow-[0_0_20px_rgba(0,255,255,0.08)]">
      {/* Header */}
      <div className="flex flex-col items-start justify-between gap-4 border-b border-slate-800 pb-4 md:flex-row md:items-center">
        <div className="flex items-center gap-3">
          <div className="rounded-lg border border-emerald-500/30 bg-gradient-to-br from-emerald-500/20 to-cyan-500/20 p-2.5">
            <Mail className="h-5 w-5 text-emerald-400" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-base font-bold text-slate-100">
                {isAr
                  ? 'تطهير البريد والبيانات عبر كافة القنوات والبروتوكولات (Omnichannel CDR)'
                  : 'Omnichannel Email & Lateral Stream Sanitization'}
              </h3>
              <span className="rounded border border-emerald-700/50 bg-emerald-950 px-2 py-0.5 text-[10px] font-bold text-emerald-300">
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
            onChange={e => setProtocolFilter(e.target.value)}
            className="rounded-lg border border-slate-800 bg-slate-950 px-2.5 py-1.5 text-xs text-slate-300 focus:border-emerald-500 focus:outline-none shadow-[0_0_20px_rgba(0,255,255,0.08)]"
          >
            <option value="ALL">{isAr ? 'جميع البروتوكولات' : 'All Protocols'}</option>
            <option value="SMTP">SMTP (Email Relay)</option>
            <option value="IMAP">IMAP (Mailbox Sync)</option>
            <option value="SMB">SMB (Lateral Shares)</option>
            <option value="NFS">NFS (Storage Mounts)</option>
          </select>

          <button
            onClick={fetchTransfers}
            className="rounded-lg bg-slate-800 p-1.5 text-slate-400 hover:text-slate-200"
            title="Refresh"
          >
            <RefreshCw className="h-4 w-4" />
          </button>
        </div>
      </div>

      {/* Action Simulator Bar */}
      <div className="space-y-2 rounded-xl border border-slate-800 bg-slate-950/80 p-4 shadow-[0_0_20px_rgba(0,255,255,0.08)]">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2 text-xs font-bold text-slate-300">
            <Zap className="h-4 w-4 text-emerald-400" />
            <span>
              {isAr
                ? 'محاكاة اختبارات التطهير وتفكيك التهديدات الصفرية (CDR Injection Drills)'
                : 'Test Real-Time Sanitization Drills'}
            </span>
          </div>
          <span className="font-mono text-[11px] text-slate-500">0% False-Negative Target</span>
        </div>

        <div className="flex flex-wrap items-center gap-2 pt-1">
          <button
            onClick={() => handleSimulateStream('PHISHING_MACRO_EMAIL')}
            disabled={isLoading}
            className="flex items-center gap-1.5 rounded-lg border border-rose-800/60 bg-rose-950/60 px-3 py-1.5 text-xs font-semibold text-rose-200 transition hover:bg-rose-900/80"
          >
            <Mail className="h-3.5 w-3.5 text-rose-400" />
            <span>
              {isAr
                ? 'حقن بريد تصيد به ماكرو خبيث (VBA Macro)'
                : 'Inject Phishing Email with Macro Attachment'}
            </span>
          </button>

          <button
            onClick={() => handleSimulateStream('SMB_LATERAL_MIMIKATZ')}
            disabled={isLoading}
            className="flex items-center gap-1.5 rounded-lg border border-amber-800/60 bg-amber-950/60 px-3 py-1.5 text-xs font-semibold text-amber-200 transition hover:bg-amber-900/80"
          >
            <HardDrive className="h-3.5 w-3.5 text-amber-400" />
            <span>
              {isAr ? 'حقن أداة اختراق جانبية عبر SMB' : 'Inject Lateral SMB Mimikatz Binary'}
            </span>
          </button>

          <button
            onClick={() => handleSimulateStream('LEGIT_FINANCIAL_DOC')}
            disabled={isLoading}
            className="flex items-center gap-1.5 rounded-lg border border-emerald-800/60 bg-emerald-950/60 px-3 py-1.5 text-xs font-semibold text-emerald-200 transition hover:bg-emerald-900/80"
          >
            <FileCheck className="h-3.5 w-3.5 text-emerald-400" />
            <span>{isAr ? 'إرسال مستند مالي نظامي سليم' : 'Inject Clean Audit Document'}</span>
          </button>
        </div>
      </div>

      {/* Feedback message */}
      {feedback && (
        <div className="flex items-center gap-2 rounded-xl border border-emerald-500/40 bg-emerald-950/40 p-3 text-xs text-emerald-200">
          <CheckCircle2 className="h-4 w-4 text-emerald-400" />
          <span>{feedback}</span>
        </div>
      )}

      {/* Stream Metrics Banner */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <div className="rounded-xl border border-slate-800 bg-slate-950 p-3 shadow-[0_0_20px_rgba(0,255,255,0.08)]">
          <span className="block text-[10px] text-slate-400">
            {isAr ? 'إجمالي التدفقات المفحوصة' : 'Streams Inspected'}
          </span>
          <span className="font-mono text-lg font-bold text-slate-200">{transfers.length}</span>
        </div>
        <div className="rounded-xl border border-slate-800 bg-slate-950 p-3 shadow-[0_0_20px_rgba(0,255,255,0.08)]">
          <span className="block text-[10px] text-slate-400">
            {isAr ? 'ملفات مطهرة عبر CDR' : 'CDR Disarmed & Cleared'}
          </span>
          <span className="font-mono text-lg font-bold text-emerald-400">
            {totalSanitizedCount}
          </span>
        </div>
        <div className="rounded-xl border border-slate-800 bg-slate-950 p-3 shadow-[0_0_20px_rgba(0,255,255,0.08)]">
          <span className="block text-[10px] text-slate-400">
            {isAr ? 'تهديدات معزولة بالكامل' : 'Quarantined & Blocked'}
          </span>
          <span className="font-mono text-lg font-bold text-rose-400">{totalQuarantinedCount}</span>
        </div>
        <div className="rounded-xl border border-slate-800 bg-slate-950 p-3 shadow-[0_0_20px_rgba(0,255,255,0.08)]">
          <span className="block text-[10px] text-slate-400">
            {isAr ? 'معدل خفض الإنتروبيا' : 'Mean Entropy Reduction'}
          </span>
          <span className="font-mono text-lg font-bold text-cyan-400">-46.8%</span>
        </div>
      </div>

      {/* Main Two-Column Layout */}
      <div className="grid grid-cols-1 gap-5 lg:grid-cols-12">
        {/* Stream List */}
        <div className="max-h-[440px] space-y-2 overflow-y-auto pr-1 lg:col-span-5">
          {filteredTransfers.map(item => {
            const isSelected = selectedTransfer?.id === item.id;
            return (
              <div
                key={item.id}
                onClick={() => setSelectedTransfer(item)}
                className={`cursor-pointer space-y-1.5 rounded-xl border p-3 text-xs transition ${
                  isSelected
                    ? 'border-emerald-500 bg-slate-800 shadow-md'
                    : 'border-slate-800 bg-slate-950/60 hover:border-slate-700 shadow-[0_0_20px_rgba(0,255,255,0.08)]'
                }`}
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-1.5">
                    <span className="font-mono font-bold text-slate-200">{item.protocol}</span>
                    <span className="rounded bg-slate-800 px-1.5 py-0.5 font-mono text-[9px] text-slate-400">
                      {item.direction}
                    </span>
                  </div>
                  <span
                    className={`rounded-full px-2 py-0.5 text-[10px] font-bold ${
                      item.sanitizationAction === 'CDR_DISARMED_DELIVERED'
                        ? 'border border-emerald-800 bg-emerald-950 text-emerald-300'
                        : item.sanitizationAction === 'QUARANTINED_BLOCKED'
                          ? 'border border-rose-800 bg-rose-950 text-rose-300'
                          : 'border border-slate-700 bg-slate-800 text-slate-400'
                    }`}
                  >
                    {item.sanitizationAction === 'CDR_DISARMED_DELIVERED'
                      ? 'CDR DISARMED'
                      : item.sanitizationAction === 'QUARANTINED_BLOCKED'
                        ? 'QUARANTINED'
                        : 'CLEARED'}
                  </span>
                </div>

                <div className="truncate font-mono text-cyan-300">{item.payloadName}</div>

                <div className="flex items-center justify-between pt-0.5 text-[10px] text-slate-500">
                  <span className="max-w-[150px] truncate">{item.sourceEntity}</span>
                  <ArrowRight className="h-3 w-3 shrink-0 text-slate-600" />
                  <span className="max-w-[150px] truncate">{item.destinationEntity}</span>
                </div>
              </div>
            );
          })}
        </div>

        {/* Deep Dive & CDR Breakdown */}
        <div className="space-y-5 rounded-xl border border-slate-800 bg-slate-950/90 p-5 lg:col-span-7 shadow-[0_0_20px_rgba(0,255,255,0.08)]">
          {selectedTransfer ? (
            <>
              <div className="flex items-start justify-between gap-3 border-b border-slate-800 pb-3">
                <div>
                  <div className="flex items-center gap-2">
                    <h4 className="text-sm font-bold text-slate-100">
                      {selectedTransfer.payloadName}
                    </h4>
                    <span className="rounded bg-slate-800 px-2 py-0.5 font-mono text-[10px] text-slate-300">
                      {selectedTransfer.declaredMimeType}
                    </span>
                  </div>
                  <div className="mt-1 font-mono text-xs text-slate-400">
                    ID: {selectedTransfer.id} • Size:{' '}
                    {(selectedTransfer.sizeBytes / 1024).toFixed(1)} KB
                  </div>
                </div>

                <span
                  className={`rounded-xl px-2.5 py-1 font-mono text-xs font-bold ${
                    selectedTransfer.initialVerdict === 'BENIGN'
                      ? 'border border-emerald-800 bg-emerald-950 text-emerald-300'
                      : 'border border-rose-800 bg-rose-950 text-rose-300'
                  }`}
                >
                  {selectedTransfer.initialVerdict}
                </span>
              </div>

              {/* Entropy Transformation Comparison */}
              <div className="space-y-2 rounded-xl border border-slate-800 bg-slate-900 p-4 shadow-[0_0_20px_rgba(0,255,255,0.08)]">
                <div className="flex items-center justify-between text-xs font-semibold text-slate-300">
                  <span>
                    {isAr
                      ? 'مقارنة إنتروبيا شانون (قبل وبعد التطهير)'
                      : 'Shannon Entropy Sanitization Delta'}
                  </span>
                  <span className="font-mono text-cyan-400">
                    {selectedTransfer.entropy.initial.toFixed(2)} →{' '}
                    {selectedTransfer.entropy.postSanitization.toFixed(2)}
                  </span>
                </div>

                <div className="flex h-3 w-full overflow-hidden rounded-full bg-slate-950">
                  <div
                    className="h-full bg-rose-500 transition-all"
                    style={{ width: `${(selectedTransfer.entropy.initial / 8) * 100}%` }}
                    title="Pre-Sanitization High Entropy"
                  />
                  <div
                    className="h-full bg-emerald-500 transition-all"
                    style={{ width: `${(selectedTransfer.entropy.postSanitization / 8) * 100}%` }}
                    title="Post-CDR Safe Entropy"
                  />
                </div>
              </div>

              {/* CDR Disarm Results */}
              {selectedTransfer.cdrDisarmReport && (
                <div className="space-y-2 rounded-xl border border-emerald-500/30 bg-emerald-950/20 p-4 text-xs">
                  <div className="flex items-center gap-1.5 font-bold text-emerald-300">
                    <ShieldCheck className="h-4 w-4 text-emerald-400" />
                    <span>
                      {isAr
                        ? 'تقرير تفكيك وتطهير المحتوى (Content Disarm Summary)'
                        : 'CDR Content Disarm & Reconstruction Report'}
                    </span>
                  </div>
                  <div className="grid grid-cols-2 gap-2 text-slate-300">
                    <div className="rounded border border-emerald-900/40 bg-slate-900/60 p-2">
                      <span className="block text-[10px] text-slate-400">
                        {isAr ? 'الماكرو المنزوع' : 'Macros Neutralized'}
                      </span>
                      <strong className="font-mono text-emerald-400">
                        {selectedTransfer.cdrDisarmReport.macrosRemovedCount} scripts
                      </strong>
                    </div>
                    <div className="rounded border border-emerald-900/40 bg-slate-900/60 p-2">
                      <span className="block text-[10px] text-slate-400">
                        {isAr ? 'الروابط المحيدة' : 'Defanged Links'}
                      </span>
                      <strong className="font-mono text-cyan-400">
                        {selectedTransfer.cdrDisarmReport.linksDefangedCount} URLs
                      </strong>
                    </div>
                  </div>
                  <div className="truncate pt-1 font-mono text-[10px] text-slate-400">
                    Safe Hash: {selectedTransfer.cdrDisarmReport.sanitizedSha256}
                  </div>
                </div>
              )}

              {/* Threat Indicators List */}
              <div className="space-y-1.5">
                <span className="block text-xs font-semibold tracking-wider text-slate-400 uppercase">
                  {isAr ? 'المؤشرات الأمنية المرصودة' : 'Observed Threat Signatures'}
                </span>
                <div className="space-y-1">
                  {selectedTransfer.threatIndicators.map(ind => (
                    <div
                      key={`threat-ind-${ind}`}
                      className="flex items-center gap-2 rounded border border-rose-900/40 bg-rose-950/30 px-3 py-1.5 font-mono text-xs text-rose-300"
                    >
                      <ShieldAlert className="h-3.5 w-3.5 shrink-0 text-rose-400" />
                      <span>{ind}</span>
                    </div>
                  ))}
                </div>
              </div>
            </>
          ) : (
            <div className="flex h-64 items-center justify-center text-xs text-slate-500">
              {isAr
                ? 'اختر تدفق بيانات لعرض تقرير التطهير'
                : 'Select a stream item to view CDR disarm details.'}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
