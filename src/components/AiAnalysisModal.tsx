import React, { useState, useEffect } from 'react';
import { ModalShell } from './ui/modal';
import { TelemetryPacket } from '../types';
import type { AnalyzeOutcome } from '../lib/aiAnalysis';
import {
  Sparkles,
  X,
  Shield,
  ShieldAlert,
  Cpu,
  Terminal,
  Copy,
  Check,
  Radio,
  CheckCircle2
} from 'lucide-react';

interface AiAnalysisModalProps {
  packet: TelemetryPacket | null;
  onClose: () => void;
  onRunAiAnalyze: (packet: TelemetryPacket) => Promise<AnalyzeOutcome>;
  lang: 'ar' | 'en';
}

export const AiAnalysisModal: React.FC<AiAnalysisModalProps> = ({
  packet,
  onClose,
  onRunAiAnalyze,
  lang
}) => {
  const isAr = lang === 'ar';

  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [outcome, setOutcome] = useState<AnalyzeOutcome | null>(null);
  const aiResult = outcome?.kind === 'ok' ? outcome.result : null;
  const failure = outcome?.kind === 'error' ? outcome : null;
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  // The manual window-level Escape listener was removed: it fired even when
  // another dialog sat on top of this one. Radix scopes Escape to the
  // topmost layer.

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(id);
    setTimeout(() => setCopiedKey(null), 2500);
  };

  /**
   * Null guard, placed AFTER every hook.
   *
   * The original version sat above the useState calls, which made the hook count
   * change between renders as `packet` flipped — the "rendered more hooks than
   * during the previous render" crash. Removing it fixed that and left the body
   * dereferencing a nullable prop, which the project's tsconfig does not check
   * because strictNullChecks is off.
   *
   * Here the hooks have all run, so the order is stable, and nothing below can
   * touch a null packet. The single call site already guards, so this is defence
   * in depth rather than a live bug — but a type that says null while the body
   * assumes otherwise is a trap for the next caller.
   */
  if (!packet) return null;

  const handleTriggerAnalysis = async () => {
    setIsLoading(true);
    try {
      setOutcome(await onRunAiAnalyze(packet));
    } finally {
      setIsLoading(false);
    }
  };

  // Which engine actually produced the verdict. The panel used to say "Gemini" whatever
  // ran; on a sovereign deployment the only engine is the local classifier.
  const engineLabel = aiResult
    ? aiResult.aiGenerated
      ? isAr ? 'نموذج خارجي (Gemini)' : 'External model (Gemini)'
      : isAr ? 'المصنّف المحلي' : 'Local classifier'
    : null;
  const analysisText = aiResult
    ? (isAr ? aiResult.analysisAr || aiResult.analysisEn : aiResult.analysisEn || aiResult.analysisAr)
    : packet.reason;

  const iptablesRule =
    aiResult?.rules?.iptables ||
    packet.generatedRules?.iptables ||
    `iptables -I INPUT -s ${packet.srcIp} -j DROP`;
  const suricataRule =
    aiResult?.rules?.suricata ||
    packet.generatedRules?.suricata ||
    `drop tcp ${packet.srcIp} any -> any ${packet.port} (msg:"SD-AI Threat Block"; sid:901001; rev:1;)`;
  const ebpfRule =
    aiResult?.rules?.ebpf ||
    packet.generatedRules?.ebpf ||
    `SEC("xdp") int xdp_drop_node(struct xdp_md *ctx) { return XDP_DROP; }`;

  return (
    <ModalShell
      open={Boolean(packet)}
      onClose={onClose}
      title={isAr ? 'تحليل الحزمة بالذكاء الاصطناعي' : 'AI packet analysis'}
      dir={isAr ? 'rtl' : 'ltr'}
      overlayClassName="bg-black/80"
      className="w-full max-w-2xl"
    >
      <div className="max-h-[90vh] w-full max-w-2xl space-y-5 overflow-y-auto rounded-2xl border border-cyan-500/40 bg-slate-900 p-6 text-slate-100 shadow-2xl">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <div className="flex items-center gap-3">
            <div className="rounded-xl border border-cyan-500/40 bg-cyan-500/20 p-2.5 text-cyan-300">
              <Sparkles className="h-5 w-5 animate-pulse" />
            </div>
            <div>
              <h3 className="text-base font-bold text-white">
                {isAr ? 'التحليل العميق للحزمة' : 'Deep packet analysis'}
              </h3>
              <p className="font-mono text-xs text-slate-400">
                Target: {packet.srcIp} → {packet.dstIp}:{packet.port} ({packet.vector})
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="rounded-lg bg-slate-800 p-1.5 text-slate-400 transition hover:bg-slate-700 hover:text-white"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Telemetry Summary Cards */}
        <div className="grid grid-cols-2 gap-2.5 font-mono text-xs sm:grid-cols-4">
          <div className="rounded-xl border border-slate-800 bg-slate-950/80 p-2.5 shadow-[0_0_20px_rgba(0,255,255,0.08)]">
            <span className="block text-[10px] text-slate-400">
              {isAr ? 'مؤشر الخطر:' : 'Threat Score:'}
            </span>
            <span className="text-sm font-bold text-rose-400">{packet.threatScore}%</span>
          </div>
          <div className="rounded-xl border border-slate-800 bg-slate-950/80 p-2.5 shadow-[0_0_20px_rgba(0,255,255,0.08)]">
            <span className="block text-[10px] text-slate-400">MITRE Tactic:</span>
            <span className="block truncate text-[11px] font-bold text-cyan-400">
              {packet.mitreTactic}
            </span>
          </div>
          <div className="rounded-xl border border-slate-800 bg-slate-950/80 p-2.5 shadow-[0_0_20px_rgba(0,255,255,0.08)]">
            <span className="block text-[10px] text-slate-400">
              {isAr ? 'معدل الحزم:' : 'Rate:'}
            </span>
            <span className="text-sm font-bold text-amber-300">{packet.reqRate} pps</span>
          </div>
          <div className="rounded-xl border border-slate-800 bg-slate-950/80 p-2.5 shadow-[0_0_20px_rgba(0,255,255,0.08)]">
            <span className="block text-[10px] text-slate-400">
              {isAr ? 'حجم الحزمة:' : 'Packet Size:'}
            </span>
            <span className="text-sm font-bold text-cyan-300">{packet.packetSize} B</span>
          </div>
        </div>

        {/* Payload Snippet */}
        <div className="rounded-xl border border-slate-800 bg-slate-950 p-3 font-mono text-xs shadow-[0_0_20px_rgba(0,255,255,0.08)]">
          <span className="mb-1 block text-[10px] text-slate-400">
            {isAr ? 'الحمولة المفحوصة (Payload):' : 'Raw Incident Payload:'}
          </span>
          <div className="break-all text-emerald-300 select-all">
            {packet.payload || 'No ASCII payload (Network probe)'}
          </div>
        </div>

        {/* Analysis result */}
        <div className="space-y-3 rounded-xl border border-cyan-500/30 bg-gradient-to-br from-cyan-950/40 via-slate-950 to-slate-900 p-4">
          <div className="flex items-center justify-between">
            <span className="flex items-center gap-1.5 text-xs font-bold text-cyan-300">
              <Sparkles className="h-4 w-4" />
              <span>
                {engineLabel
                  ? `${isAr ? 'نتيجة' : 'Result from'}: ${engineLabel}`
                  : isAr ? 'التحليل:' : 'Analysis:'}
              </span>
            </span>

            {!aiResult && (
              <button
                type="button"
                onClick={handleTriggerAnalysis}
                disabled={isLoading}
                className="flex items-center gap-1 rounded-lg bg-cyan-600 px-3 py-1 text-xs font-bold text-white shadow transition hover:bg-cyan-500"
              >
                {isLoading ? (
                  <Cpu className="h-3.5 w-3.5 animate-spin" />
                ) : (
                  <Sparkles className="h-3.5 w-3.5" />
                )}
                <span>
                  {isLoading
                    ? isAr
                      ? 'جاري التحليل...'
                      : 'Analyzing...'
                    : failure
                      ? isAr
                        ? 'إعادة المحاولة'
                        : 'Retry'
                      : isAr
                        ? 'تحليل الآن'
                        : 'Run analysis'}
                </span>
              </button>
            )}
          </div>

          {failure && (
            <div role="alert" className="rounded-lg border border-rose-500/40 bg-rose-950/40 p-3 font-sans text-xs text-rose-200">
              <span className="block font-bold">
                {isAr ? 'تعذّر التحليل — لا يوجد حكم.' : 'Analysis failed — there is no verdict.'}
              </span>
              <span className="block font-mono text-[11px] text-rose-300">
                {failure.status ?? (isAr ? 'لا استجابة' : 'no response')} · {failure.code}
              </span>
              {(isAr ? failure.messageAr || failure.message : failure.message || failure.messageAr) && (
                <span className="mt-1 block">
                  {isAr ? failure.messageAr || failure.message : failure.message || failure.messageAr}
                </span>
              )}
            </div>
          )}

          <p className="font-sans text-xs leading-relaxed text-slate-200">{analysisText}</p>

          {/* What actually fired. This replaces four fixed "XAI attribution" bars (38/32/18/12 %)
              that were drawn the same for every packet — numbers that measured nothing. */}
          <div className="space-y-1.5 border-t border-cyan-500/20 pt-2 text-xs">
            <span className="mb-1 block text-[11px] font-bold text-slate-300">
              {isAr ? 'ما الذي أطلق القرار:' : 'What produced the verdict:'}
            </span>
            {aiResult?.detection ? (
              <div className="space-y-1 font-mono text-[11px] text-slate-300">
                <div>
                  {isAr ? 'الحكم' : 'Verdict'}: <span className="font-bold text-white">{aiResult.verdict}</span>
                  {' · '}
                  {isAr ? 'الصنف' : 'Family'}: <span className="text-cyan-300">{aiResult.detection.family}</span>
                  {' · '}
                  {isAr ? 'الدرجة' : 'Score'}: <span className="text-cyan-300">{aiResult.detection.score}</span>
                  {typeof aiResult.detection.entropy === 'number' && (
                    <>
                      {' · '}
                      {isAr ? 'الإنتروبيا' : 'Entropy'}: <span className="text-cyan-300">{aiResult.detection.entropy}</span>
                    </>
                  )}
                </div>
                {aiResult.detection.signatures.length ? (
                  <ul className="list-inside list-disc text-emerald-300">
                    {aiResult.detection.signatures.map(s => (
                      <li key={s}>{s}</li>
                    ))}
                  </ul>
                ) : (
                  <span className="block text-slate-400">
                    {isAr ? 'لم تُطلق أي قاعدة.' : 'No rule fired.'}
                  </span>
                )}
              </div>
            ) : (
              <span className="block font-sans text-[11px] text-slate-400">
                {aiResult
                  ? isAr
                    ? 'هذا المحرك لا يُرجع تفصيلاً مقاساً للإشارات.'
                    : 'This engine returns no measured signal breakdown.'
                  : isAr
                    ? 'شغّل التحليل لعرض القواعد التي أُطلقت فعلاً.'
                    : 'Run the analysis to see the rules that actually fired.'}
              </span>
            )}
          </div>
        </div>

        {/* Synthesized Kernel Rules Box */}
        <div className="space-y-2.5 font-mono text-xs">
          <span className="flex items-center gap-1.5 text-xs font-bold text-white">
            <Cpu className="h-4 w-4 text-emerald-400" />
            <span>
              {isAr
                ? 'قواعد النواة المولدة تلقائياً للتحييد الفوري:'
                : 'Synthesized Production Defense Rules:'}
            </span>
          </span>

          <div className="space-y-1 rounded-xl border border-slate-800 bg-slate-950 p-3 shadow-[0_0_20px_rgba(0,255,255,0.08)]">
            <div className="flex items-center justify-between">
              <span className="text-[10px] text-slate-400">1. Linux IPTables Drop Command:</span>
              <button
                onClick={() => copyToClipboard(iptablesRule, 'ipt')}
                className="flex items-center gap-1 text-[10px] text-slate-400 hover:text-white"
              >
                {copiedKey === 'ipt' ? (
                  <Check className="h-3.5 w-3.5 text-emerald-400" />
                ) : (
                  <Copy className="h-3.5 w-3.5" />
                )}
                <span>{copiedKey === 'ipt' ? 'Copied' : 'Copy'}</span>
              </button>
            </div>
            <code className="block break-all text-rose-300">{iptablesRule}</code>
          </div>

          <div className="space-y-1 rounded-xl border border-slate-800 bg-slate-950 p-3 shadow-[0_0_20px_rgba(0,255,255,0.08)]">
            <div className="flex items-center justify-between">
              <span className="text-[10px] text-slate-400">
                2. Suricata / Snort Edge Firewall Rule:
              </span>
              <button
                onClick={() => copyToClipboard(suricataRule, 'sur')}
                className="flex items-center gap-1 text-[10px] text-slate-400 hover:text-white"
              >
                {copiedKey === 'sur' ? (
                  <Check className="h-3.5 w-3.5 text-emerald-400" />
                ) : (
                  <Copy className="h-3.5 w-3.5" />
                )}
                <span>{copiedKey === 'sur' ? 'Copied' : 'Copy'}</span>
              </button>
            </div>
            <code className="block break-all text-amber-300">{suricataRule}</code>
          </div>

          <div className="space-y-1 rounded-xl border border-slate-800 bg-slate-950 p-3 shadow-[0_0_20px_rgba(0,255,255,0.08)]">
            <div className="flex items-center justify-between">
              <span className="text-[10px] text-slate-400">3. eBPF XDP Kernel Filter:</span>
              <button
                onClick={() => copyToClipboard(ebpfRule, 'ebpf')}
                className="flex items-center gap-1 text-[10px] text-slate-400 hover:text-white"
              >
                {copiedKey === 'ebpf' ? (
                  <Check className="h-3.5 w-3.5 text-emerald-400" />
                ) : (
                  <Copy className="h-3.5 w-3.5" />
                )}
                <span>{copiedKey === 'ebpf' ? 'Copied' : 'Copy'}</span>
              </button>
            </div>
            <code className="block break-all text-cyan-300">{ebpfRule}</code>
          </div>
        </div>

        {/* Footer */}
        <div className="flex justify-end border-t border-slate-800 pt-3">
          <button
            onClick={onClose}
            className="rounded-xl bg-slate-800 px-5 py-2 text-xs font-bold text-white transition hover:bg-slate-700"
          >
            {isAr ? 'إغلاق الفاحص' : 'Close Inspector'}
          </button>
        </div>
      </div>
    </ModalShell>
  );
};
