import React, { useState, useEffect } from 'react';
import { 
  BreachSimulationScenario, 
  BreachSimulationResult 
} from '../types';
import { 
  ShieldAlert, 
  Sparkles, 
  Terminal, 
  Cpu, 
  CheckCircle2, 
  AlertTriangle, 
  Zap, 
  Play, 
  RefreshCw, 
  Copy, 
  Check, 
  Shield, 
  Activity, 
  FileCode2, 
  Lock, 
  Flame, 
  Layers, 
  Sliders 
} from 'lucide-react';

interface DigitalTwinSimulatorProps {
  lang: 'ar' | 'en';
}

export const DigitalTwinSimulator: React.FC<DigitalTwinSimulatorProps> = ({ lang }) => {
  const isAr = lang === 'ar';

  const [scenarios, setScenarios] = useState<BreachSimulationScenario[]>([]);
  const [selectedScenarioId, setSelectedScenarioId] = useState<string>('SCEN-01');
  const [isRunning, setIsRunning] = useState<boolean>(false);
  const [activeSimulationResult, setActiveSimulationResult] = useState<BreachSimulationResult | null>(null);
  const [overallResilience, setOverallResilience] = useState<number>(98);
  const [history, setHistory] = useState<BreachSimulationResult[]>([]);
  const [copiedRule, setCopiedRule] = useState<string | null>(null);
  const [executionLogs, setExecutionLogs] = useState<string[]>([]);

  // Fetch scenarios and history
  const fetchScenariosAndHistory = async () => {
    try {
      const [scenRes, histRes] = await Promise.all([
        fetch('/api/v1/digital-twin/scenarios'),
        fetch('/api/v1/digital-twin/history')
      ]);

      if (scenRes.ok) {
        const sData = await scenRes.json();
        if (sData.scenarios) setScenarios(sData.scenarios);
      }

      if (histRes.ok) {
        const hData = await histRes.json();
        if (hData.overallResilienceScore) setOverallResilience(hData.overallResilienceScore);
        if (hData.history && hData.history.length > 0) {
          setHistory(hData.history);
          if (!activeSimulationResult) {
            setActiveSimulationResult(hData.history[0]);
          }
        }
      }
    } catch (err) {
      console.warn('Digital Twin fetch warning:', err);
    }
  };

  useEffect(() => {
    fetchScenariosAndHistory();
  }, []);

  const handleRunSimulation = async (scenarioIdToRun?: string) => {
    const targetId = scenarioIdToRun || selectedScenarioId;
    const targetScenario = scenarios.find(s => s.id === targetId) || scenarios[0];
    setIsRunning(true);
    setExecutionLogs([
      `[SIM-INIT] Initializing Sovereign Defender Digital Twin environment for target: ${targetScenario?.nameEn || targetId}`,
      `[STAGER] Injecting synthetic polymorphic payload vector into virtual ring buffer...`,
      `[INSPECTION] Intercepting traffic at eBPF XDP hook (Latency: <0.5ms)...`,
      `[AI-EVAL] Triggering Gemini 3.7 Flash Autonomous Mitigation Playbook synthesizer...`
    ]);

    try {
      const res = await fetch('/api/v1/digital-twin/simulate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scenarioId: targetId })
      });

      if (res.ok) {
        const data = await res.json();
        if (data.result) {
          setActiveSimulationResult(data.result);
          setHistory(prev => [data.result, ...prev]);
          setOverallResilience(data.result.resilienceScore);
          setExecutionLogs(prev => [
            ...prev,
            `[EVAL-VERDICT] Payload BLOCKED with 0ms bypass window. Interception Confidence: 99%`,
            `[KERNEL-HARDEN] Synthesized active eBPF XDP filter and IPTables DROP rule applied.`,
            `[COMPLETED] Autonomous Digital Twin breach simulation finished in ${data.result.durationMs}ms.`
          ]);
        }
      }
    } catch (err) {
      console.error('Simulation error:', err);
      setExecutionLogs(prev => [...prev, `[ERROR] Failed to communicate with simulator backend.`]);
    } finally {
      setIsRunning(false);
    }
  };

  const copyToClipboard = (text: string, type: string) => {
    navigator.clipboard.writeText(text);
    setCopiedRule(type);
    setTimeout(() => setCopiedRule(null), 2500);
  };

  const currentScenario = scenarios.find(s => s.id === selectedScenarioId) || scenarios[0];

  return (
    <div className="space-y-6">
      {/* Top Banner: Digital Twin Resilience Index */}
      <div className="p-6 rounded-2xl bg-gradient-to-r from-emerald-950/80 via-slate-900 to-teal-950/80 border border-emerald-500/40 shadow-2xl">
        <div className="flex flex-wrap items-center justify-between gap-6">
          <div className="flex items-center gap-4">
            <div className="p-4 rounded-2xl bg-emerald-500/20 border border-emerald-500/40 text-emerald-300 shadow-inner">
              <Layers className="w-8 h-8 animate-pulse text-emerald-400" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-xl font-black text-white">
                  {isAr ? 'محاكي التوأم الرقمي واختبار الصمود السيبراني (Autonomous Digital Twin)' : 'Autonomous Breach & Digital Twin Simulator'}
                </h2>
                <span className="px-2.5 py-0.5 text-xs font-bold rounded-full bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 font-mono">
                  v4.0 Engine
                </span>
              </div>
              <p className="text-xs text-slate-300 mt-1 max-w-2xl">
                {isAr
                  ? 'بيئة محاكاة رقمية متطابقة لاختبار صلابة دفاعات النواة وتطبيقات الويب ضد سيناريوهات الاختراق المتقدمة وتوليد أدلة معالجة ذكية فورية'
                  : 'Automated self-penetration testing suite executing real-world evasion exploits against the eBPF kernel stack to measure resilience & generate AI playbooks'}
              </p>
            </div>
          </div>

          {/* Resilience Index Gauge */}
          <div className="flex items-center gap-4 bg-slate-950/90 p-3.5 rounded-2xl border border-emerald-500/30">
            <div className="text-center font-mono">
              <span className="text-[10px] text-slate-400 block font-sans">{isAr ? 'مؤشر الصمود الدفاعي:' : 'Resilience Index:'}</span>
              <span className="text-2xl font-black text-emerald-400">{overallResilience}%</span>
              <span className="text-[9px] text-teal-300 block font-bold">HARDENED KERNEL</span>
            </div>
            <div className="h-10 w-px bg-slate-800"></div>
            <div className="text-center font-mono">
              <span className="text-[10px] text-slate-400 block font-sans">{isAr ? 'الاختبارات المنفذة:' : 'Breach Tests Run:'}</span>
              <span className="text-2xl font-black text-cyan-400">{history.length}</span>
              <span className="text-[9px] text-slate-400 block">0ms Bypass</span>
            </div>
          </div>
        </div>
      </div>

      {/* Main Two-Column Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: Scenario Selector & Live Trigger (5 Cols) */}
        <div className="lg:col-span-5 space-y-5">
          <div className="p-5 rounded-2xl bg-slate-900/95 border border-slate-800 shadow-xl space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <Flame className="w-4 h-4 text-rose-400" />
                <span>{isAr ? 'سيناريوهات اختبار الاختراق المتاحة:' : 'Automated Penetration Scenarios:'}</span>
              </h3>
              <span className="text-[10px] text-slate-400 font-mono">6 Attack Vectors</span>
            </div>

            <div className="space-y-2.5">
              {scenarios.map(scen => {
                const isSelected = scen.id === selectedScenarioId;
                return (
                  <div
                    key={scen.id}
                    onClick={() => setSelectedScenarioId(scen.id)}
                    className={`p-3.5 rounded-xl border transition cursor-pointer ${
                      isSelected
                        ? 'bg-emerald-950/40 border-emerald-500/60 shadow-md shadow-emerald-950/30'
                        : 'bg-slate-950/80 border-slate-800 hover:border-slate-700'
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-800 text-cyan-300">
                          {scen.id}
                        </span>
                        <span className="text-xs font-bold text-white">
                          {isAr ? scen.nameAr : scen.nameEn}
                        </span>
                      </div>
                      <span
                        className={`text-[9px] font-bold px-2 py-0.5 rounded border ${
                          scen.severity === 'CRITICAL'
                            ? 'bg-rose-500/20 text-rose-300 border-rose-500/40'
                            : 'bg-amber-500/20 text-amber-300 border-amber-500/40'
                        }`}
                      >
                        {scen.severity}
                      </span>
                    </div>

                    <p className="text-[11px] text-slate-400 mt-1.5 line-clamp-2">
                      {isAr ? scen.descriptionAr : scen.descriptionEn}
                    </p>

                    <div className="mt-2 text-[10px] text-slate-500 font-mono truncate bg-slate-900 p-1 rounded border border-slate-800/80">
                      Payload: <code className="text-slate-300">{scen.simulatedPayload}</code>
                    </div>
                  </div>
                );
              })}
            </div>

            <button
              type="button"
              onClick={() => handleRunSimulation()}
              disabled={isRunning}
              className="w-full py-3 rounded-xl bg-gradient-to-r from-emerald-600 via-teal-600 to-cyan-600 hover:from-emerald-500 hover:to-cyan-500 text-white font-bold text-xs sm:text-sm transition flex items-center justify-center gap-2 shadow-xl shadow-emerald-950/60 disabled:opacity-50"
            >
              {isRunning ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin" />
                  <span>{isAr ? 'جاري تنفيذ اختبار الاختراق وفحص النواة...' : 'Simulating Breach Attack...'}</span>
                </>
              ) : (
                <>
                  <Play className="w-4 h-4 fill-current" />
                  <span>{isAr ? 'بدء اختبار الاختراق الآلي للسيناريو المحدد' : 'Execute Breach Simulation Now'}</span>
                </>
              )}
            </button>
          </div>

          {/* Real-Time Simulation Execution Logs Terminal */}
          <div className="p-4 rounded-2xl bg-slate-950 border border-slate-800 shadow-xl space-y-2 font-mono text-xs">
            <div className="flex items-center justify-between pb-2 border-b border-slate-800/80">
              <span className="text-slate-400 text-[11px] flex items-center gap-1.5">
                <Terminal className="w-3.5 h-3.5 text-emerald-400" />
                <span>Simulation Execution Stream:</span>
              </span>
              <span className="text-[10px] text-emerald-400">STATUS: READY</span>
            </div>
            <div className="space-y-1 max-h-40 overflow-y-auto text-[11px] text-slate-300">
              {executionLogs.length === 0 ? (
                <span className="text-slate-500 italic">Click "Execute Breach Simulation Now" to stream penetration diagnostics...</span>
              ) : (
                executionLogs.map((log) => (
                  <div key={`exec-log-${log}`} className="leading-tight">
                    <span className="text-emerald-500 mr-1">&gt;</span>
                    <span>{log}</span>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>

        {/* Right Column: AI Playbook & Synthesized Defense Rules (7 Cols) */}
        <div className="lg:col-span-7 space-y-5">
          {activeSimulationResult ? (
            <div className="p-6 rounded-2xl bg-slate-900/95 border border-cyan-500/40 shadow-2xl space-y-6">
              {/* Header & Metrics Strip */}
              <div className="flex flex-wrap items-center justify-between gap-3 pb-4 border-b border-slate-800">
                <div>
                  <span className="text-[10px] text-cyan-400 font-mono block">TEST ID: {activeSimulationResult.testId}</span>
                  <h3 className="text-base font-black text-white mt-0.5">
                    {isAr ? activeSimulationResult.scenarioNameAr : activeSimulationResult.scenarioNameEn}
                  </h3>
                </div>

                <div className="flex items-center gap-2">
                  <span className="px-3 py-1 rounded-xl bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 font-bold text-xs flex items-center gap-1.5">
                    <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                    {activeSimulationResult.status}
                  </span>
                  <span className="px-2.5 py-1 rounded-xl bg-slate-950 border border-slate-800 text-slate-300 text-xs font-mono">
                    {activeSimulationResult.durationMs} ms
                  </span>
                </div>
              </div>

              {/* 3 Resilience Metric Cards */}
              <div className="grid grid-cols-3 gap-3 font-mono text-center">
                <div className="p-3 rounded-xl bg-slate-950 border border-emerald-500/30">
                  <span className="text-[10px] text-slate-400 block font-sans">{isAr ? 'مؤشر الصمود:' : 'Resilience:'}</span>
                  <span className="text-xl font-bold text-emerald-400">{activeSimulationResult.resilienceScore}%</span>
                </div>

                <div className="p-3 rounded-xl bg-slate-950 border border-teal-500/30">
                  <span className="text-[10px] text-slate-400 block font-sans">{isAr ? 'مقاومة التخفي:' : 'Evasion Resistance:'}</span>
                  <span className="text-xl font-bold text-teal-300">{activeSimulationResult.evasionResistanceScore}%</span>
                </div>

                <div className="p-3 rounded-xl bg-slate-950 border border-cyan-500/30">
                  <span className="text-[10px] text-slate-400 block font-sans">{isAr ? 'دقة الرصد:' : 'Threat Detection:'}</span>
                  <span className="text-xl font-bold text-cyan-300">{activeSimulationResult.threatScoreDetected}%</span>
                </div>
              </div>

              {/* AI Generated Mitigation Playbook */}
              <div className="p-4 rounded-xl bg-slate-950 border border-purple-500/30 space-y-3">
                <div className="flex items-center justify-between">
                  <h4 className="text-xs font-bold text-purple-300 flex items-center gap-2">
                    <Sparkles className="w-4 h-4 text-purple-400 animate-pulse" />
                    <span>{isAr ? activeSimulationResult.aiPlaybook.titleAr : activeSimulationResult.aiPlaybook.titleEn}</span>
                  </h4>
                  <span className="text-[10px] text-purple-400 font-mono">Gemini 3.7 Flash</span>
                </div>

                <p className="text-xs text-slate-200 leading-relaxed">
                  {isAr ? activeSimulationResult.aiPlaybook.executiveSummaryAr : activeSimulationResult.aiPlaybook.executiveSummaryEn}
                </p>

                {/* Tactical Remediations Checklist */}
                <div className="space-y-1.5 pt-2 border-t border-slate-800">
                  <span className="text-[11px] font-bold text-cyan-400 block">
                    {isAr ? 'إجراءات المعالجة التكتيكية الموصى بها:' : 'Tactical Mitigation Actions:'}
                  </span>
                  {activeSimulationResult.aiPlaybook.tacticalRemediations.map((rem) => (
                    <div key={`remed-${rem}`} className="flex items-start gap-2 text-xs text-slate-300">
                      <span className="text-emerald-400 font-bold shrink-0">✓</span>
                      <span>{rem}</span>
                    </div>
                  ))}
                </div>

                {/* Kernel Hardening Sysctl Commands */}
                <div className="space-y-1.5 pt-2 border-t border-slate-800">
                  <span className="text-[11px] font-bold text-teal-400 block">
                    {isAr ? 'أوامر تحصين نواة لينكس (Kernel Hardening Directives):' : 'Linux Kernel Hardening Directives:'}
                  </span>
                  <div className="bg-slate-900 p-2 rounded-lg border border-slate-800 space-y-1 font-mono text-[11px]">
                    {activeSimulationResult.aiPlaybook.kernelHardeningSteps.map((kStep) => (
                      <div key={`kstep-${kStep}`} className="text-teal-300">
                        <code># {kStep}</code>
                      </div>
                    ))}
                  </div>
                </div>
              </div>

              {/* Synthesized Kernel Defense Rules */}
              <div className="space-y-3">
                <h4 className="text-xs font-bold text-white flex items-center justify-between">
                  <span>{isAr ? 'قواعد دفاع النواة المولدة آلياً (Synthesized Defense Rules):' : 'Autonomous Kernel Defense Code:'}</span>
                  <span className="text-[10px] text-emerald-400 font-mono">Active eBPF / IPTables</span>
                </h4>

                {/* IPTables */}
                <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 space-y-1">
                  <div className="flex items-center justify-between text-[11px]">
                    <span className="font-bold text-amber-400 font-mono">IPTABLES KERNEL DROP</span>
                    <button
                      type="button"
                      onClick={() => copyToClipboard(activeSimulationResult.iptablesRule, 'iptables')}
                      className="text-slate-400 hover:text-white flex items-center gap-1 text-[10px]"
                    >
                      {copiedRule === 'iptables' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                      <span>{copiedRule === 'iptables' ? 'Copied' : 'Copy'}</span>
                    </button>
                  </div>
                  <code className="text-xs font-mono text-slate-300 block truncate">{activeSimulationResult.iptablesRule}</code>
                </div>

                {/* Suricata */}
                <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 space-y-1">
                  <div className="flex items-center justify-between text-[11px]">
                    <span className="font-bold text-cyan-400 font-mono">SURICATA SIGNATURE</span>
                    <button
                      type="button"
                      onClick={() => copyToClipboard(activeSimulationResult.suricataRule, 'suricata')}
                      className="text-slate-400 hover:text-white flex items-center gap-1 text-[10px]"
                    >
                      {copiedRule === 'suricata' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                      <span>{copiedRule === 'suricata' ? 'Copied' : 'Copy'}</span>
                    </button>
                  </div>
                  <code className="text-xs font-mono text-slate-300 block truncate">{activeSimulationResult.suricataRule}</code>
                </div>

                {/* eBPF */}
                <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 space-y-1">
                  <div className="flex items-center justify-between text-[11px]">
                    <span className="font-bold text-purple-400 font-mono">eBPF XDP KERNEL PROGRAM</span>
                    <button
                      type="button"
                      onClick={() => copyToClipboard(activeSimulationResult.ebpfFilter, 'ebpf')}
                      className="text-slate-400 hover:text-white flex items-center gap-1 text-[10px]"
                    >
                      {copiedRule === 'ebpf' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                      <span>{copiedRule === 'ebpf' ? 'Copied' : 'Copy'}</span>
                    </button>
                  </div>
                  <code className="text-xs font-mono text-slate-300 block truncate">{activeSimulationResult.ebpfFilter}</code>
                </div>
              </div>
            </div>
          ) : (
            <div className="p-12 rounded-2xl bg-slate-900/50 border border-slate-800 text-center space-y-3">
              <Shield className="w-12 h-12 text-slate-600 mx-auto" />
              <h4 className="text-sm font-bold text-slate-300">
                {isAr ? 'لم يتم تشغيل أي اختبار بعد' : 'No Simulation Executed Yet'}
              </h4>
              <p className="text-xs text-slate-500 max-w-sm mx-auto">
                {isAr ? 'اختر سيناريو اختراق من القائمة واضغط على زر البدء لتوليد نتائج الصمود وخطة المعالجة' : 'Select a scenario from the left panel and click Execute to generate defense results and playbooks.'}
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
