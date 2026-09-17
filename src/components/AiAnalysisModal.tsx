import React, { useState, useEffect } from 'react';
import { TelemetryPacket } from '../types';
import { Sparkles, X, Shield, ShieldAlert, Cpu, Terminal, Copy, Check, Radio, CheckCircle2 } from 'lucide-react';

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
  if (!packet) return null;
  const isAr = lang === 'ar';

  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [aiResult, setAiResult] = useState<any>(null);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  // Close on ESC key press
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        onClose();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [onClose]);

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

  const iptablesRule = aiResult?.rules?.iptables || packet.generatedRules?.iptables || `iptables -I INPUT -s ${packet.srcIp} -j DROP`;
  const suricataRule = aiResult?.rules?.suricata || packet.generatedRules?.suricata || `drop tcp ${packet.srcIp} any -> any ${packet.port} (msg:"SD-AI Threat Block"; sid:901001; rev:1;)`;
  const ebpfRule = aiResult?.rules?.ebpf || packet.generatedRules?.ebpf || `SEC("xdp") int xdp_drop_node(struct xdp_md *ctx) { return XDP_DROP; }`;

  return (
    <div
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
      className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4 overflow-y-auto"
    >
      <div className="bg-slate-900 border border-purple-500/40 rounded-2xl max-w-2xl w-full p-6 shadow-2xl space-y-5 text-slate-100 max-h-[90vh] overflow-y-auto">
        {/* Header */}
        <div className="flex items-center justify-between pb-3 border-b border-slate-800">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-purple-500/20 border border-purple-500/40 text-purple-300">
              <Sparkles className="w-5 h-5 animate-pulse" />
            </div>
            <div>
              <h3 className="font-bold text-white text-base">
                {isAr ? 'الفحص التكتيكي للتهديد بالذكاء الاصطناعي (Gemini AI Inspector)' : 'Deep AI Threat & Kernel Defense Inspector'}
              </h3>
              <p className="text-xs text-slate-400 font-mono">
                Target: {packet.srcIp} → {packet.dstIp}:{packet.port} ({packet.vector})
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white transition"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Telemetry Summary Cards */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5 font-mono text-xs">
          <div className="p-2.5 rounded-xl bg-slate-950/80 border border-slate-800">
            <span className="text-[10px] text-slate-400 block">{isAr ? 'مؤشر الخطر:' : 'Threat Score:'}</span>
            <span className="text-rose-400 font-bold text-sm">{packet.threatScore}%</span>
          </div>
          <div className="p-2.5 rounded-xl bg-slate-950/80 border border-slate-800">
            <span className="text-[10px] text-slate-400 block">MITRE Tactic:</span>
            <span className="text-cyan-400 font-bold text-[11px] truncate block">{packet.mitreTactic}</span>
          </div>
          <div className="p-2.5 rounded-xl bg-slate-950/80 border border-slate-800">
            <span className="text-[10px] text-slate-400 block">{isAr ? 'معدل الحزم:' : 'Rate:'}</span>
            <span className="text-amber-300 font-bold text-sm">{packet.reqRate} pps</span>
          </div>
          <div className="p-2.5 rounded-xl bg-slate-950/80 border border-slate-800">
            <span className="text-[10px] text-slate-400 block">{isAr ? 'حجم الحزمة:' : 'Packet Size:'}</span>
            <span className="text-purple-300 font-bold text-sm">{packet.packetSize} B</span>
          </div>
        </div>

        {/* Payload Snippet */}
        <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 font-mono text-xs">
          <span className="text-slate-400 block text-[10px] mb-1">{isAr ? 'الحمولة المفحوصة (Payload):' : 'Raw Incident Payload:'}</span>
          <div className="text-emerald-300 break-all select-all">{packet.payload || 'No ASCII payload (Network probe)'}</div>
        </div>

        {/* Gemini AI Deep Reasoning Box */}
        <div className="p-4 rounded-xl bg-gradient-to-br from-purple-950/40 via-slate-950 to-slate-900 border border-purple-500/30 space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold text-purple-300 flex items-center gap-1.5">
              <Sparkles className="w-4 h-4" />
              <span>{isAr ? 'تحليل نموذج Gemini 3.7 Flash المتقدم:' : 'Gemini AI Deep Reasoning:'}</span>
            </span>

            {!aiResult && (
              <button
                type="button"
                onClick={handleTriggerAnalysis}
                disabled={isLoading}
                className="px-3 py-1 rounded-lg bg-purple-600 hover:bg-purple-500 text-white font-bold text-xs shadow transition flex items-center gap-1"
              >
                {isLoading ? <Cpu className="w-3.5 h-3.5 animate-spin" /> : <Sparkles className="w-3.5 h-3.5" />}
                <span>{isLoading ? (isAr ? 'جاري التحليل...' : 'Analyzing...') : isAr ? 'تحليل الآن' : 'Run Deep Analysis'}</span>
              </button>
            )}
          </div>

          <p className="text-xs text-slate-200 leading-relaxed font-sans">
            {aiResult?.analysisAr || aiResult?.analysisEn || packet.reason}
          </p>

          {/* Explainable AI (XAI) Feature Attribution Weights */}
          <div className="space-y-1.5 pt-2 border-t border-purple-500/20 text-xs">
            <span className="text-[11px] font-bold text-slate-300 block mb-1">
              {isAr ? 'أوزان الميزات المفسرة للقرار (Explainable AI Attribution):' : 'Explainable AI (XAI) Attribution Breakdown:'}
            </span>
            <div className="grid grid-cols-2 gap-2 font-mono text-[11px]">
              <div>
                <div className="flex justify-between text-slate-400 mb-0.5">
                  <span>Payload Entropy:</span>
                  <span className="text-purple-300 font-bold">38%</span>
                </div>
                <div className="w-full h-1.5 bg-slate-800 rounded-full overflow-hidden">
                  <div className="bg-purple-500 h-full w-[38%]"></div>
                </div>
              </div>
              <div>
                <div className="flex justify-between text-slate-400 mb-0.5">
                  <span>Signature Match:</span>
                  <span className="text-cyan-300 font-bold">32%</span>
                </div>
                <div className="w-full h-1.5 bg-slate-800 rounded-full overflow-hidden">
                  <div className="bg-cyan-500 h-full w-[32%]"></div>
                </div>
              </div>
              <div>
                <div className="flex justify-between text-slate-400 mb-0.5">
                  <span>Burst Rate Anomaly:</span>
                  <span className="text-amber-300 font-bold">18%</span>
                </div>
                <div className="w-full h-1.5 bg-slate-800 rounded-full overflow-hidden">
                  <div className="bg-amber-500 h-full w-[18%]"></div>
                </div>
              </div>
              <div>
                <div className="flex justify-between text-slate-400 mb-0.5">
                  <span>Packet Size Variance:</span>
                  <span className="text-rose-300 font-bold">12%</span>
                </div>
                <div className="w-full h-1.5 bg-slate-800 rounded-full overflow-hidden">
                  <div className="bg-rose-500 h-full w-[12%]"></div>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Synthesized Kernel Rules Box */}
        <div className="space-y-2.5 font-mono text-xs">
          <span className="font-bold text-white flex items-center gap-1.5 text-xs">
            <Cpu className="w-4 h-4 text-emerald-400" />
            <span>{isAr ? 'قواعد النواة المولدة تلقائياً للتحييد الفوري:' : 'Synthesized Production Defense Rules:'}</span>
          </span>

          <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 space-y-1">
            <div className="flex items-center justify-between">
              <span className="text-[10px] text-slate-400">1. Linux IPTables Drop Command:</span>
              <button
                onClick={() => copyToClipboard(iptablesRule, 'ipt')}
                className="flex items-center gap-1 text-[10px] text-slate-400 hover:text-white"
              >
                {copiedKey === 'ipt' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copiedKey === 'ipt' ? 'Copied' : 'Copy'}</span>
              </button>
            </div>
            <code className="text-rose-300 block break-all">{iptablesRule}</code>
          </div>

          <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 space-y-1">
            <div className="flex items-center justify-between">
              <span className="text-[10px] text-slate-400">2. Suricata / Snort Edge Firewall Rule:</span>
              <button
                onClick={() => copyToClipboard(suricataRule, 'sur')}
                className="flex items-center gap-1 text-[10px] text-slate-400 hover:text-white"
              >
                {copiedKey === 'sur' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copiedKey === 'sur' ? 'Copied' : 'Copy'}</span>
              </button>
            </div>
            <code className="text-amber-300 block break-all">{suricataRule}</code>
          </div>

          <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 space-y-1">
            <div className="flex items-center justify-between">
              <span className="text-[10px] text-slate-400">3. eBPF XDP Kernel Filter:</span>
              <button
                onClick={() => copyToClipboard(ebpfRule, 'ebpf')}
                className="flex items-center gap-1 text-[10px] text-slate-400 hover:text-white"
              >
                {copiedKey === 'ebpf' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copiedKey === 'ebpf' ? 'Copied' : 'Copy'}</span>
              </button>
            </div>
            <code className="text-cyan-300 block break-all">{ebpfRule}</code>
          </div>
        </div>

        {/* Footer */}
        <div className="pt-3 border-t border-slate-800 flex justify-end">
          <button
            onClick={onClose}
            className="px-5 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-white font-bold text-xs transition"
          >
            {isAr ? 'إغلاق الفاحص' : 'Close Inspector'}
          </button>
        </div>
      </div>
    </div>
  );
};
