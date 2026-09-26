import React, { useState, useEffect } from 'react';
import { ModalShell } from './ui/modal';
import { TelemetryPacket } from '../types';
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
  onRunAiAnalyze: (packet: TelemetryPacket) => Promise<any>;
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
  const [aiResult, setAiResult] = useState<any>(null);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  // The manual window-level Escape listener was removed: it fired even when
  // another dialog sat on top of this one. Radix scopes Escape to the
  // topmost layer.

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(id);
    setTimeout(() => setCopiedKey(null), 2500);
  };

  const handleTriggerAnalysis = async () => {
    setIsLoading(true);
    try {
      const res = await onRunAiAnalyze(packet);
      setAiResult(res);
    } catch (err) {
      console.error('AI Analysis failed:', err);
    } finally {
      setIsLoading(false);
    }
  };

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
      <div className="max-h-[90vh] w-full max-w-2xl space-y-5 overflow-y-auto rounded-2xl border border-purple-500/40 bg-slate-900 p-6 text-slate-100 shadow-2xl">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <div className="flex items-center gap-3">
            <div className="rounded-xl border border-purple-500/40 bg-purple-500/20 p-2.5 text-purple-300">
              <Sparkles className="h-5 w-5 animate-pulse" />
            </div>
            <div>
              <h3 className="text-base font-bold text-white">
                {isAr
                  ? 'الفحص التكتيكي للتهديد بالذكاء الاصطناعي (Gemini AI Inspector)'
                  : 'Deep AI Threat & Kernel Defense Inspector'}
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
          <div className="rounded-xl border border-slate-800 bg-slate-950/80 p-2.5">
            <span className="block text-[10px] text-slate-400">
              {isAr ? 'مؤشر الخطر:' : 'Threat Score:'}
            </span>
            <span className="text-sm font-bold text-rose-400">{packet.threatScore}%</span>
          </div>
          <div className="rounded-xl border border-slate-800 bg-slate-950/80 p-2.5">
            <span className="block text-[10px] text-slate-400">MITRE Tactic:</span>
            <span className="block truncate text-[11px] font-bold text-cyan-400">
              {packet.mitreTactic}
            </span>
          </div>
          <div className="rounded-xl border border-slate-800 bg-slate-950/80 p-2.5">
            <span className="block text-[10px] text-slate-400">
              {isAr ? 'معدل الحزم:' : 'Rate:'}
            </span>
            <span className="text-sm font-bold text-amber-300">{packet.reqRate} pps</span>
          </div>
          <div className="rounded-xl border border-slate-800 bg-slate-950/80 p-2.5">
            <span className="block text-[10px] text-slate-400">
              {isAr ? 'حجم الحزمة:' : 'Packet Size:'}
            </span>
            <span className="text-sm font-bold text-purple-300">{packet.packetSize} B</span>
          </div>
        </div>

        {/* Payload Snippet */}
        <div className="rounded-xl border border-slate-800 bg-slate-950 p-3 font-mono text-xs">
          <span className="mb-1 block text-[10px] text-slate-400">
            {isAr ? 'الحمولة المفحوصة (Payload):' : 'Raw Incident Payload:'}
          </span>
          <div className="break-all text-emerald-300 select-all">
            {packet.payload || 'No ASCII payload (Network probe)'}
          </div>
        </div>

        {/* Gemini AI Deep Reasoning Box */}
        <div className="space-y-3 rounded-xl border border-purple-500/30 bg-gradient-to-br from-purple-950/40 via-slate-950 to-slate-900 p-4">
          <div className="flex items-center justify-between">
            <span className="flex items-center gap-1.5 text-xs font-bold text-purple-300">
              <Sparkles className="h-4 w-4" />
              <span>
                {isAr ? 'تحليل نموذج Gemini 3.7 Flash المتقدم:' : 'Gemini AI Deep Reasoning:'}
              </span>
            </span>

            {!aiResult && (
              <button
                type="button"
                onClick={handleTriggerAnalysis}
                disabled={isLoading}
                className="flex items-center gap-1 rounded-lg bg-purple-600 px-3 py-1 text-xs font-bold text-white shadow transition hover:bg-purple-500"
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
                    : isAr
                      ? 'تحليل الآن'
                      : 'Run Deep Analysis'}
                </span>
              </button>
            )}
          </div>

          <p className="font-sans text-xs leading-relaxed text-slate-200">
            {aiResult?.analysisAr || aiResult?.analysisEn || packet.reason}
          </p>

          {/* Explainable AI (XAI) Feature Attribution Weights */}
          <div className="space-y-1.5 border-t border-purple-500/20 pt-2 text-xs">
            <span className="mb-1 block text-[11px] font-bold text-slate-300">
              {isAr
                ? 'أوزان الميزات المفسرة للقرار (Explainable AI Attribution):'
                : 'Explainable AI (XAI) Attribution Breakdown:'}
            </span>
            <div className="grid grid-cols-2 gap-2 font-mono text-[11px]">
              <div>
                <div className="mb-0.5 flex justify-between text-slate-400">
                  <span>Payload Entropy:</span>
                  <span className="font-bold text-purple-300">38%</span>
                </div>
                <div className="h-1.5 w-full overflow-hidden rounded-full bg-slate-800">
                  <div className="h-full w-[38%] bg-purple-500"></div>
                </div>
              </div>
              <div>
                <div className="mb-0.5 flex justify-between text-slate-400">
                  <span>Signature Match:</span>
                  <span className="font-bold text-cyan-300">32%</span>
                </div>
                <div className="h-1.5 w-full overflow-hidden rounded-full bg-slate-800">
                  <div className="h-full w-[32%] bg-cyan-500"></div>
                </div>
              </div>
              <div>
                <div className="mb-0.5 flex justify-between text-slate-400">
                  <span>Burst Rate Anomaly:</span>
                  <span className="font-bold text-amber-300">18%</span>
                </div>
                <div className="h-1.5 w-full overflow-hidden rounded-full bg-slate-800">
                  <div className="h-full w-[18%] bg-amber-500"></div>
                </div>
              </div>
              <div>
                <div className="mb-0.5 flex justify-between text-slate-400">
                  <span>Packet Size Variance:</span>
                  <span className="font-bold text-rose-300">12%</span>
                </div>
                <div className="h-1.5 w-full overflow-hidden rounded-full bg-slate-800">
                  <div className="h-full w-[12%] bg-rose-500"></div>
                </div>
              </div>
            </div>
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

          <div className="space-y-1 rounded-xl border border-slate-800 bg-slate-950 p-3">
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

          <div className="space-y-1 rounded-xl border border-slate-800 bg-slate-950 p-3">
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

          <div className="space-y-1 rounded-xl border border-slate-800 bg-slate-950 p-3">
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
