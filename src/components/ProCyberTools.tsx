import React, { useState } from 'react';
import { 
  Terminal, 
  Cpu, 
  FileCode, 
  ShieldAlert, 
  Search, 
  Copy, 
  Check, 
  Download, 
  Play, 
  Radio, 
  Zap, 
  Layers, 
  ShieldCheck, 
  Code2, 
  Sliders,
  Sparkles,
  Lock,
  ArrowRight,
  Database
} from 'lucide-react';
import { AttackVectorType } from '../types';
import { ATTACK_VECTORS } from '../data/defaultThreatData';

interface ProCyberToolsProps {
  lang: 'ar' | 'en';
}

export const ProCyberTools: React.FC<ProCyberToolsProps> = ({ lang }) => {
  const isAr = lang === 'ar';
  const [activeTool, setActiveTool] = useState<'PCAP_DISSECT' | 'EBPF_COMPILER' | 'RULE_SYNTHESIZER' | 'WAF_BUILDER' | 'SOAR_PLAYBOOK'>('PCAP_DISSECT');

  // Tool 1 State: PCAP Dissector
  const [pcapInput, setPcapInput] = useState<string>("4500003c1a2b40004006e22c0a0000020a000005d4310050a1b2c3d400000000a00272101a2b0000020405b40402080a000000000000000001030307");
  const [dissectProtocol, setDissectProtocol] = useState<'TCP' | 'UDP' | 'DNS' | 'HTTP'>('TCP');
  const [dissectionResult, setDissectionResult] = useState<any>(null);
  const [isDissecting, setIsDissecting] = useState<boolean>(false);

  // Tool 2 State: eBPF Compiler
  const [ebpfTargetIp, setEbpfTargetIp] = useState<string>('203.0.113.88');
  const [ebpfTargetPort, setEbpfTargetPort] = useState<number>(443);
  const [ebpfHook, setEbpfHook] = useState<'XDP_DROP' | 'TC_INGRESS' | 'KPROBE_EXEC'>('XDP_DROP');
  const [ebpfResult, setEbpfResult] = useState<any>(null);
  const [isCompilingEbpf, setIsCompilingEbpf] = useState<boolean>(false);

  // Tool 3 State: YARA / Sigma / Suricata Synthesizer
  const [selectedVector, setSelectedVector] = useState<AttackVectorType>('SQL_INJECTION');
  const [customRulePayload, setCustomRulePayload] = useState<string>("' UNION SELECT null, username, password_hash, email FROM users-- -");
  const [ruleFormat, setRuleFormat] = useState<'SIGMA' | 'YARA' | 'SURICATA'>('SIGMA');
  const [ruleResults, setRuleResults] = useState<{ sigmaYaml?: string; yaraRule?: string; suricataRule?: string } | null>(null);
  const [isGeneratingRules, setIsGeneratingRules] = useState<boolean>(false);

  // Copy feedback state
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const handleCopyText = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  // Run PCAP Dissection
  const handleRunPcapDissect = async () => {
    setIsDissecting(true);
    try {
      const res = await fetch('/api/v1/tools/pcap-dissect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ rawText: pcapInput, protocol: dissectProtocol })
      });
      const data = await res.json();
      setDissectionResult(data);
    } catch (err) {
      console.warn('Dissect error:', err);
    } finally {
      setIsDissecting(false);
    }
  };

  // Run eBPF Compilation
  const handleCompileEbpf = async () => {
    setIsCompilingEbpf(true);
    try {
      const res = await fetch('/api/v1/tools/ebpf-compile', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ targetIp: ebpfTargetIp, targetPort: ebpfTargetPort, hookType: ebpfHook })
      });
      const data = await res.json();
      setEbpfResult(data);
    } catch (err) {
      console.warn('eBPF compile error:', err);
    } finally {
      setIsCompilingEbpf(false);
    }
  };

  // Run Rule Generation
  const handleGenerateRules = async () => {
    setIsGeneratingRules(true);
    try {
      const res = await fetch('/api/v1/tools/generate-rules', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ vector: selectedVector, payload: customRulePayload })
      });
      const data = await res.json();
      setRuleResults(data);
    } catch (err) {
      console.warn('Rule generation error:', err);
    } finally {
      setIsGeneratingRules(false);
    }
  };

  return (
    <div className="bg-slate-900/90 border border-slate-800 rounded-2xl overflow-hidden shadow-2xl">
      {/* Header */}
      <div className="px-6 py-5 border-b border-slate-800 bg-slate-950/80 flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="p-3 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 shadow-lg shadow-cyan-950/40">
            <Terminal className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="font-bold text-white text-lg">
                {isAr ? 'جناح أدوات الدفاع والتحليل المتقدمة (Professional Cyber Suite)' : 'Professional Cyber Defense & Packet Dissection Suite'}
              </h3>
              <span className="px-2 py-0.5 text-xs font-mono rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/40">
                BLUE TEAM PRO
              </span>
            </div>
            <p className="text-xs text-slate-400">
              {isAr ? 'أدوات احترافية لتحليل وتفكيك الحزم الخام، توليد برامج eBPF، واستنباط قواعد YARA و Sigma و ModSecurity' : 'Autonomous raw packet dissector, eBPF XDP compiler, YARA/Sigma rule synthesizers, and SOAR response engines'}
            </p>
          </div>
        </div>

        {/* Tool Navigation Switcher */}
        <div className="flex items-center gap-1.5 p-1 bg-slate-950 rounded-xl border border-slate-800 text-xs font-medium flex-wrap">
          <button
            onClick={() => setActiveTool('PCAP_DISSECT')}
            className={`flex items-center gap-2 px-3 py-2 rounded-lg transition ${
              activeTool === 'PCAP_DISSECT'
                ? 'bg-cyan-500/20 text-cyan-300 font-bold border border-cyan-500/40'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Code2 className="w-3.5 h-3.5" />
            <span>{isAr ? '1. تفكيك وتحليل الحزم (PCAP)' : '1. PCAP Hex Dissector'}</span>
          </button>

          <button
            onClick={() => setActiveTool('EBPF_COMPILER')}
            className={`flex items-center gap-2 px-3 py-2 rounded-lg transition ${
              activeTool === 'EBPF_COMPILER'
                ? 'bg-emerald-500/20 text-emerald-300 font-bold border border-emerald-500/40'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Cpu className="w-3.5 h-3.5" />
            <span>{isAr ? '2. مترجم eBPF XDP للنواة' : '2. eBPF XDP Compiler'}</span>
          </button>

          <button
            onClick={() => setActiveTool('RULE_SYNTHESIZER')}
            className={`flex items-center gap-2 px-3 py-2 rounded-lg transition ${
              activeTool === 'RULE_SYNTHESIZER'
                ? 'bg-purple-500/20 text-purple-300 font-bold border border-purple-500/40'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <FileCode className="w-3.5 h-3.5" />
            <span>{isAr ? '3. مستنبط YARA و Sigma' : '3. YARA & Sigma Engine'}</span>
          </button>

          <button
            onClick={() => setActiveTool('WAF_BUILDER')}
            className={`flex items-center gap-2 px-3 py-2 rounded-lg transition ${
              activeTool === 'WAF_BUILDER'
                ? 'bg-amber-500/20 text-amber-300 font-bold border border-amber-500/40'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <ShieldCheck className="w-3.5 h-3.5" />
            <span>{isAr ? '4. مخصص Nginx & ModSec WAF' : '4. ModSecurity & WAF'}</span>
          </button>
        </div>
      </div>

      {/* TOOL 1: PCAP & RAW PACKET HEX DISSECTOR */}
      {activeTool === 'PCAP_DISSECT' && (
        <div className="p-6 space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Input & Controls Column */}
            <div className="space-y-4">
              <div>
                <label className="text-xs font-bold text-slate-300 block mb-1.5">
                  {isAr ? 'الحمولة الثنائية / سلسلة Hex المراد تفكيكها:' : 'Raw Hex String / Payload Stream:'}
                </label>
                <textarea
                  value={pcapInput}
                  onChange={e => setPcapInput(e.target.value)}
                  rows={4}
                  className="w-full p-3 rounded-xl bg-slate-950 border border-slate-800 font-mono text-xs text-cyan-300 focus:outline-none focus:border-cyan-500 resize-none leading-relaxed"
                  placeholder="Paste hex bytes e.g. 4500003c..."
                />
              </div>

              <div className="grid grid-cols-2 gap-2">
                <div>
                  <label className="text-xs font-medium text-slate-400 block mb-1">
                    {isAr ? 'بروتوكول النقل:' : 'Transport Protocol:'}
                  </label>
                  <select
                    value={dissectProtocol}
                    onChange={e => setDissectProtocol(e.target.value as any)}
                    className="w-full p-2.5 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono text-white focus:outline-none focus:border-cyan-500"
                  >
                    <option value="TCP">TCP (Port 443/80/22)</option>
                    <option value="UDP">UDP (DNS / NTP)</option>
                    <option value="DNS">DNS (Port 53)</option>
                    <option value="HTTP">HTTP (Layer 7)</option>
                  </select>
                </div>
                <div>
                  <label className="text-xs font-medium text-slate-400 block mb-1">
                    {isAr ? 'العينات الجاهزة:' : 'Sample Preloads:'}
                  </label>
                  <select
                    onChange={e => {
                      if (e.target.value === 'SYN') setPcapInput('4500003c1a2b40004006e22c0a0000020a000005d4310050a1b2c3d400000000a00272101a2b0000');
                      if (e.target.value === 'SQLI') setPcapInput('504f5354202f6170692f76312f6c6f67696e20485454502f312e310d0a486f73743a207461726765740d0a27204f5220313d312d2d');
                      if (e.target.value === 'DNS_TUNNEL') setPcapInput('000101000001000000000000186347467a6333646b58326868633268665a58686d61577706626561636f6e0263630000100001');
                    }}
                    className="w-full p-2.5 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono text-slate-300 focus:outline-none focus:border-cyan-500"
                  >
                    <option value="">{isAr ? 'اختر نموذج...' : 'Select template...'}</option>
                    <option value="SYN">TCP SYN Packet (Port 80)</option>
                    <option value="SQLI">HTTP POST SQLi Exploit</option>
                    <option value="DNS_TUNNEL">DNS Base64 Exfiltration TXT</option>
                  </select>
                </div>
              </div>

              <button
                onClick={handleRunPcapDissect}
                disabled={isDissecting}
                className="w-full py-3 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white font-bold text-xs transition flex items-center justify-center gap-2 shadow-lg shadow-cyan-950/50"
              >
                <Play className="w-4 h-4 fill-current" />
                <span>{isDissecting ? (isAr ? 'جارِ فك التشفير والتحليل...' : 'Dissecting Packet...') : (isAr ? 'تفكيك وتحليل الهيدر والمحتوى' : 'Dissect Packet Headers & Entropy')}</span>
              </button>
            </div>

            {/* Results Column */}
            <div className="lg:col-span-2 space-y-4">
              {dissectionResult ? (
                <div className="space-y-4">
                  {/* Metric Chips */}
                  <div className="grid grid-cols-3 gap-3">
                    <div className="p-3 rounded-xl bg-slate-950 border border-slate-800">
                      <span className="text-slate-400 text-[11px] block">{isAr ? 'حجم الحزمة:' : 'Packet Size:'}</span>
                      <span className="text-base font-bold font-mono text-cyan-300">{dissectionResult.packetLengthBytes} Bytes</span>
                    </div>
                    <div className="p-3 rounded-xl bg-slate-950 border border-slate-800">
                      <span className="text-slate-400 text-[11px] block">{isAr ? 'معامل العشوائية (Shannon Entropy):' : 'Entropy Score:'}</span>
                      <span className="text-base font-bold font-mono text-emerald-400">{dissectionResult.entropy} / 8.0</span>
                    </div>
                    <div className="p-3 rounded-xl bg-slate-950 border border-slate-800">
                      <span className="text-slate-400 text-[11px] block">{isAr ? 'تصنيف الحمولة:' : 'Payload Classification:'}</span>
                      <span className="text-xs font-bold font-mono text-amber-300 truncate block mt-0.5">{dissectionResult.entropyLevel}</span>
                    </div>
                  </div>

                  {/* Header Breakdown */}
                  <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-3 font-mono text-xs">
                    <h5 className="font-bold text-white flex items-center gap-2">
                      <Layers className="w-4 h-4 text-cyan-400" />
                      <span>{isAr ? 'تفكيك ترويسات بروتوكول TCP/IP (Protocol Dissection)' : 'Decoded Protocol Layer Headers'}</span>
                    </h5>
                    
                    <div className="grid grid-cols-2 gap-3 text-[11px]">
                      <div className="p-2.5 rounded-lg bg-slate-900/80 border border-slate-800 space-y-1">
                        <div className="text-slate-400 font-bold border-b border-slate-800 pb-1">Ethernet II Layer:</div>
                        <div>Src MAC: <span className="text-cyan-300">{dissectionResult.headers.ethernet.srcMac}</span></div>
                        <div>Dst MAC: <span className="text-cyan-300">{dissectionResult.headers.ethernet.dstMac}</span></div>
                        <div>Type: <span className="text-slate-300">{dissectionResult.headers.ethernet.etherType}</span></div>
                      </div>

                      <div className="p-2.5 rounded-lg bg-slate-900/80 border border-slate-800 space-y-1">
                        <div className="text-slate-400 font-bold border-b border-slate-800 pb-1">IPv4 Layer (TTL {dissectionResult.headers.ip.ttl}):</div>
                        <div>Source IP: <span className="text-rose-400 font-bold">{dissectionResult.headers.ip.src}</span></div>
                        <div>Dest IP: <span className="text-emerald-400 font-bold">{dissectionResult.headers.ip.dst}</span></div>
                        <div>Checksum: <span className="text-slate-300">{dissectionResult.headers.ip.checksum}</span></div>
                      </div>
                    </div>

                    {/* Flags */}
                    <div className="p-2.5 rounded-lg bg-slate-900/80 border border-slate-800 flex items-center justify-between">
                      <span className="text-slate-400">TCP Control Flags:</span>
                      <div className="flex items-center gap-2">
                        {Object.entries(dissectionResult.headers.transport.flags).map(([flag, active]) => (
                          <span
                            key={flag}
                            className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                              active ? 'bg-rose-500/20 text-rose-300 border border-rose-500/50' : 'bg-slate-950 text-slate-600'
                            }`}
                          >
                            {flag}
                          </span>
                        ))}
                      </div>
                    </div>
                  </div>
                </div>
              ) : (
                <div className="p-12 rounded-xl bg-slate-950 border border-slate-800/80 flex flex-col items-center justify-center text-center text-slate-500 space-y-2">
                  <Terminal className="w-8 h-8 text-slate-600" />
                  <p className="text-xs">
                    {isAr ? 'اضغط على "تفكيك وتحليل" لتشريح الحزمة وفحص ترويسات TCP/IP وحساب الإنتروبيا' : 'Click Dissect Packet to parse binary offsets, analyze TCP control flags, and verify entropy'}
                  </p>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* TOOL 2: AUTONOMOUS eBPF / XDP KERNEL COMPILER */}
      {activeTool === 'EBPF_COMPILER' && (
        <div className="p-6 space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <div className="space-y-4">
              <div>
                <label className="text-xs font-bold text-slate-300 block mb-1">
                  {isAr ? 'عنوان IP المستهدف للحظر بالنواة:' : 'Target IP for Kernel Eviction:'}
                </label>
                <input
                  type="text"
                  value={ebpfTargetIp}
                  onChange={e => setEbpfTargetIp(e.target.value)}
                  className="w-full p-2.5 rounded-lg bg-slate-950 border border-slate-800 font-mono text-xs text-emerald-300 focus:outline-none focus:border-emerald-500"
                />
              </div>

              <div>
                <label className="text-xs font-bold text-slate-300 block mb-1">
                  {isAr ? 'نقطة الخطاف في النواة (Kernel Hook):' : 'eBPF Kernel Hook Point:'}
                </label>
                <select
                  value={ebpfHook}
                  onChange={e => setEbpfHook(e.target.value as any)}
                  className="w-full p-2.5 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono text-white focus:outline-none focus:border-emerald-500"
                >
                  <option value="XDP_DROP">XDP (eXpress Data Path - Earliest Driver Drop)</option>
                  <option value="TC_INGRESS">TC Ingress (Traffic Control Layer)</option>
                  <option value="KPROBE_EXEC">Kprobe sys_execve (Process Spawn Monitor)</option>
                </select>
              </div>

              <button
                onClick={handleCompileEbpf}
                disabled={isCompilingEbpf}
                className="w-full py-3 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-white font-bold text-xs transition flex items-center justify-center gap-2 shadow-lg shadow-emerald-950/50"
              >
                <Cpu className="w-4 h-4" />
                <span>{isCompilingEbpf ? (isAr ? 'جارِ تجميع كود النواة...' : 'Compiling eBPF C...') : (isAr ? 'توليد وتجميع برنامج eBPF' : 'Synthesize & Verify eBPF Program')}</span>
              </button>
            </div>

            <div className="lg:col-span-2 space-y-4">
              {ebpfResult ? (
                <div className="space-y-4">
                  <div className="grid grid-cols-3 gap-3">
                    <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 font-mono">
                      <span className="text-slate-400 text-[10px] block">{isAr ? 'زمن المعالجة بالحزمة:' : 'Packet Processing Latency:'}</span>
                      <span className="text-sm font-bold text-emerald-400">{ebpfResult.nanosecondLatency}</span>
                    </div>
                    <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 font-mono">
                      <span className="text-slate-400 text-[10px] block">{isAr ? 'حجم البايت كود:' : 'Bytecode Size:'}</span>
                      <span className="text-sm font-bold text-cyan-300">{ebpfResult.compiledBytecodeSize} Bytes ({ebpfResult.instructionsCount} insns)</span>
                    </div>
                    <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 font-mono">
                      <span className="text-slate-400 text-[10px] block">{isAr ? 'فاحص النواة (Verifier):' : 'Kernel Verifier:'}</span>
                      <span className="text-xs font-bold text-emerald-300 truncate block mt-0.5">{ebpfResult.verifierStatus}</span>
                    </div>
                  </div>

                  <div className="relative">
                    <div className="flex items-center justify-between px-4 py-2 bg-slate-950 border border-slate-800 rounded-t-xl text-xs font-mono text-slate-400">
                      <span>sovereign_filter.bpf.c (Kernel C Program)</span>
                      <button
                        onClick={() => handleCopyText(ebpfResult.sourceCode, 'ebpf')}
                        className="flex items-center gap-1 text-slate-400 hover:text-white transition"
                      >
                        {copiedId === 'ebpf' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                        <span>{copiedId === 'ebpf' ? 'Copied' : 'Copy C Code'}</span>
                      </button>
                    </div>
                    <pre className="p-4 rounded-b-xl bg-black border-x border-b border-slate-800 text-xs font-mono text-emerald-300/90 overflow-x-auto max-h-72 leading-relaxed">
                      {ebpfResult.sourceCode}
                    </pre>
                  </div>
                </div>
              ) : (
                <div className="p-12 rounded-xl bg-slate-950 border border-slate-800/80 flex flex-col items-center justify-center text-center text-slate-500 space-y-2">
                  <Cpu className="w-8 h-8 text-slate-600" />
                  <p className="text-xs">
                    {isAr ? 'انقر على "توليد وتجميع" لإنشاء برنامج C معتمد في النواة يعمل بسرعة 14.2 نانوثانية' : 'Click Synthesize to generate production-ready eBPF XDP code that drops malicious packets before OS network stack'}
                  </p>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* TOOL 3: YARA, SIGMA & SURICATA SYNTHESIZER */}
      {activeTool === 'RULE_SYNTHESIZER' && (
        <div className="p-6 space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <div className="space-y-4">
              <div>
                <label className="text-xs font-bold text-slate-300 block mb-1">
                  {isAr ? 'نوع الهجوم المستهدف:' : 'Target Attack Vector:'}
                </label>
                <select
                  value={selectedVector}
                  onChange={e => {
                    const vec = e.target.value as AttackVectorType;
                    setSelectedVector(vec);
                    const found = ATTACK_VECTORS.find(v => v.id === vec);
                    if (found && found.samplePayloads.length > 0) {
                      setCustomRulePayload(found.samplePayloads[0]);
                    }
                  }}
                  className="w-full p-2.5 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono text-white focus:outline-none focus:border-purple-500"
                >
                  {ATTACK_VECTORS.map(v => (
                    <option key={v.id} value={v.id}>
                      {isAr ? v.nameAr : v.nameEn} ({v.mitreId})
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label className="text-xs font-bold text-slate-300 block mb-1">
                  {isAr ? 'نمط الحمولة أو البصمة المراد صياغة القاعدة لها:' : 'Signature Payload Pattern:'}
                </label>
                <textarea
                  value={customRulePayload}
                  onChange={e => setCustomRulePayload(e.target.value)}
                  rows={3}
                  className="w-full p-3 rounded-xl bg-slate-950 border border-slate-800 font-mono text-xs text-purple-300 focus:outline-none focus:border-purple-500 resize-none"
                />
              </div>

              <button
                onClick={handleGenerateRules}
                disabled={isGeneratingRules}
                className="w-full py-3 rounded-xl bg-purple-600 hover:bg-purple-500 text-white font-bold text-xs transition flex items-center justify-center gap-2 shadow-lg shadow-purple-950/50"
              >
                <FileCode className="w-4 h-4" />
                <span>{isGeneratingRules ? (isAr ? 'جارِ استنباط القواعد...' : 'Synthesizing Rules...') : (isAr ? 'استنباط قواعد Sigma و YARA و Suricata' : 'Synthesize Detection Rules')}</span>
              </button>
            </div>

            <div className="lg:col-span-2 space-y-4">
              {ruleResults ? (
                <div className="space-y-4">
                  {/* Format Tabs */}
                  <div className="flex items-center gap-2 border-b border-slate-800 pb-2">
                    <button
                      onClick={() => setRuleFormat('SIGMA')}
                      className={`px-3 py-1.5 rounded-lg text-xs font-mono font-bold transition ${
                        ruleFormat === 'SIGMA'
                          ? 'bg-purple-500/20 text-purple-300 border border-purple-500/40'
                          : 'text-slate-400 hover:text-white'
                      }`}
                    >
                      Sigma SIEM (YAML)
                    </button>
                    <button
                      onClick={() => setRuleFormat('YARA')}
                      className={`px-3 py-1.5 rounded-lg text-xs font-mono font-bold transition ${
                        ruleFormat === 'YARA'
                          ? 'bg-purple-500/20 text-purple-300 border border-purple-500/40'
                          : 'text-slate-400 hover:text-white'
                      }`}
                    >
                      YARA Memory Rule (.yar)
                    </button>
                    <button
                      onClick={() => setRuleFormat('SURICATA')}
                      className={`px-3 py-1.5 rounded-lg text-xs font-mono font-bold transition ${
                        ruleFormat === 'SURICATA'
                          ? 'bg-purple-500/20 text-purple-300 border border-purple-500/40'
                          : 'text-slate-400 hover:text-white'
                      }`}
                    >
                      Suricata IDS/IPS (.rules)
                    </button>
                  </div>

                  {/* Code Display */}
                  <div className="relative">
                    <div className="flex items-center justify-between px-4 py-2 bg-slate-950 border border-slate-800 rounded-t-xl text-xs font-mono text-slate-400">
                      <span>{ruleFormat === 'SIGMA' ? 'rule.sigma.yaml' : ruleFormat === 'YARA' ? 'rule.yara.yar' : 'suricata_ids.rules'}</span>
                      <button
                        onClick={() => {
                          const text = ruleFormat === 'SIGMA' ? ruleResults.sigmaYaml : ruleFormat === 'YARA' ? ruleResults.yaraRule : ruleResults.suricataRule;
                          handleCopyText(text || '', 'rules');
                        }}
                        className="flex items-center gap-1 text-slate-400 hover:text-white transition"
                      >
                        {copiedId === 'rules' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                        <span>{copiedId === 'rules' ? 'Copied' : 'Copy Rule'}</span>
                      </button>
                    </div>
                    <pre className="p-4 rounded-b-xl bg-black border-x border-b border-slate-800 text-xs font-mono text-purple-300/90 overflow-x-auto max-h-72 leading-relaxed">
                      {ruleFormat === 'SIGMA' && ruleResults.sigmaYaml}
                      {ruleFormat === 'YARA' && ruleResults.yaraRule}
                      {ruleFormat === 'SURICATA' && ruleResults.suricataRule}
                    </pre>
                  </div>
                </div>
              ) : (
                <div className="p-12 rounded-xl bg-slate-950 border border-slate-800/80 flex flex-col items-center justify-center text-center text-slate-500 space-y-2">
                  <FileCode className="w-8 h-8 text-slate-600" />
                  <p className="text-xs">
                    {isAr ? 'حدد نوع الهجوم لتوليد قواعد استكشاف قابلة للدمج المباشر في أنظمة SIEM و EDR' : 'Select a vector to generate Sigma, YARA, and Suricata signatures for deployment'}
                  </p>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* TOOL 4: MODSECURITY & NGINX WAF CONFIG BUILDER */}
      {activeTool === 'WAF_BUILDER' && (
        <div className="p-6 space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* ModSecurity CRS Rule */}
            <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-3">
              <div className="flex items-center justify-between">
                <h5 className="font-bold text-xs text-white flex items-center gap-2">
                  <ShieldCheck className="w-4 h-4 text-amber-400" />
                  <span>ModSecurity CRS v4 Configuration</span>
                </h5>
                <button
                  onClick={() => handleCopyText(`SecRule REQUEST_URI|ARGS "@rx (?i:(?:select\\s+.*\\s+from|union\\s+select|insert\\s+into))" "id:942100,phase:2,deny,status:403,log,msg:'Sovereign Defender SQLi Block'"`, 'modsec')}
                  className="text-xs text-slate-400 hover:text-white flex items-center gap-1"
                >
                  <Copy className="w-3.5 h-3.5" />
                  <span>Copy</span>
                </button>
              </div>
              <pre className="p-3 rounded-lg bg-black border border-slate-800 text-[11px] font-mono text-amber-300 overflow-x-auto leading-relaxed">
{`# Sovereign Defender v3.0 ModSecurity Core Rule
SecRuleEngine On
SecRequestBodyAccess On
SecRule REQUEST_URI|ARGS "@rx (?i:(?:select\\s+.*\\s+from|union\\s+select|insert\\s+into))" \\
    "id:942100,\\
    phase:2,\\
    deny,\\
    status:403,\\
    log,\\
    msg:'Sovereign Defender SQLi Block',\\
    tag:'OWASP_CRS/WEB_ATTACK/SQLI'"`}
              </pre>
            </div>

            {/* Nginx Lua WAF Direct Filter */}
            <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-3">
              <div className="flex items-center justify-between">
                <h5 className="font-bold text-xs text-white flex items-center gap-2">
                  <Zap className="w-4 h-4 text-cyan-400" />
                  <span>Nginx OpenResty Lua Fast-Path WAF</span>
                </h5>
                <button
                  onClick={() => handleCopyText(`local ip = ngx.var.remote_addr\nlocal res = ngx.location.capture("/api/v1/agent/protect", { method = ngx.HTTP_POST, body = ngx.req.get_body_data() })\nif res.status == 403 then ngx.exit(403) end`, 'lua')}
                  className="text-xs text-slate-400 hover:text-white flex items-center gap-1"
                >
                  <Copy className="w-3.5 h-3.5" />
                  <span>Copy</span>
                </button>
              </div>
              <pre className="p-3 rounded-lg bg-black border border-slate-800 text-[11px] font-mono text-cyan-300 overflow-x-auto leading-relaxed">
{`# Nginx OpenResty Autonomous Filter
access_by_lua_block {
    local http = require "resty.http"
    local client_ip = ngx.var.remote_addr
    local req_body = ngx.req.get_body_data() or ""
    
    -- Query Sovereign Defender v3.0 Agent Subsystem
    local httpc = http.new()
    local res, err = httpc:request_uri("http://127.0.0.1:3000/api/v1/agent/protect", {
        method = "POST",
        body = ngx.encode_json({ clientIp = client_ip, url = ngx.var.uri, body = req_body }),
        headers = { ["Content-Type"] = "application/json" }
    })
    
    if res and res.status == 403 then
        ngx.status = ngx.HTTP_FORBIDDEN
        ngx.say("403 Forbidden - Isolated by Sovereign Defender v3.0")
        ngx.exit(ngx.HTTP_FORBIDDEN)
    end
}`}
              </pre>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
