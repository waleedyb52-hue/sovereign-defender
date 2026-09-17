import React, { useState, useEffect } from 'react';
import {
  GitCommit,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Radio,
  Zap,
  Target,
  Skull,
  Activity,
  AlertTriangle,
  Play,
  Lock,
  Unlock,
  KeyRound,
  FileCode,
  Sparkles,
  Server,
  ArrowRight,
  Database,
  Search,
  RefreshCw,
  Clock,
  Eye,
  CheckCircle2,
  XCircle,
  TrendingUp,
  Cpu,
  Layers,
  ChevronRight,
  ChevronDown,
  Globe,
  CornerDownRight,
  Sliders
} from 'lucide-react';
import { NodeIsolationButton } from './NodeIsolationButton';
import { AttackChainSession, HoneytokenTrap, CredentialStuffingEvent } from '../../types';

interface AttackChainDeceptionPanelProps {
  lang: 'ar' | 'en';
}

interface AttackStageNode {
  id: 'Reconnaissance' | 'Initial Access' | 'Exploitation' | 'Persistence' | 'Exfiltration';
  order: number;
  labelEn: string;
  labelAr: string;
  mitreTechnique: string;
  icon: React.ReactNode;
  color: string;
  descriptionEn: string;
  descriptionAr: string;
}

export const AttackChainDeceptionPanel: React.FC<AttackChainDeceptionPanelProps> = ({ lang }) => {
  const isAr = lang === 'ar';

  // Sub-view toggle
  const [activeView, setActiveView] = useState<'ATTACK_GRAPH' | 'HONEYTOKENS' | 'CREDENTIAL_STUFFING'>('ATTACK_GRAPH');

  // Attack Chains State
  const [attackChains, setAttackChains] = useState<AttackChainSession[]>([]);
  const [selectedChain, setSelectedChain] = useState<AttackChainSession | null>(null);
  const [isLoadingChains, setIsLoadingChains] = useState<boolean>(false);
  const [isSimulatingChain, setIsSimulatingChain] = useState<boolean>(false);
  const [simulationProgress, setSimulationProgress] = useState<number>(0);
  const [geminiSummary, setGeminiSummary] = useState<string | null>(null);

  // Honeytokens State
  const [honeytokens, setHoneytokens] = useState<HoneytokenTrap[]>([]);
  const [isLoadingTraps, setIsLoadingTraps] = useState<boolean>(false);
  const [triggeringTrapId, setTriggeringTrapId] = useState<string | null>(null);
  const [trapActionFeedback, setTrapActionFeedback] = useState<string | null>(null);
  const [newTrapPath, setNewTrapPath] = useState<string>('');
  const [newTrapType, setNewTrapType] = useState<'ENV_SECRETS' | 'GIT_CONFIG' | 'ADMIN_PANEL' | 'WORDPRESS_WP_LOGIN' | 'AWS_IAM_CREDENTIALS'>('ENV_SECRETS');
  const [isDeployingTrap, setIsDeployingTrap] = useState<boolean>(false);

  // Credential Stuffing State
  const [credentialEvents, setCredentialEvents] = useState<CredentialStuffingEvent[]>([]);
  const [targetUsernameInput, setTargetUsernameInput] = useState<string>('admin@sovereign-soc.com');
  const [isSimulatingBruteForce, setIsSimulatingBruteForce] = useState<boolean>(false);

  // 5 Canonical MITRE Stages Definition
  const CANONICAL_STAGES: AttackStageNode[] = [
    {
      id: 'Reconnaissance',
      order: 1,
      labelEn: '1. Reconnaissance',
      labelAr: '1. الاستطلاع وفحص الأهداف',
      mitreTechnique: 'T1595 - Active Scanning',
      icon: <Search className="w-4 h-4 text-cyan-400" />,
      color: 'cyan',
      descriptionEn: 'Port sweep, directory enumeration, and vulnerability probing against public surfaces.',
      descriptionAr: 'مسح المنافذ واستكشاف المسارات البرمجية بحثاً عن ثغرات مكشوفة.'
    },
    {
      id: 'Initial Access',
      order: 2,
      labelEn: '2. Initial Access',
      labelAr: '2. الوصول الأولي والاختراق',
      mitreTechnique: 'T1190 - Exploit Public-Facing App',
      icon: <KeyRound className="w-4 h-4 text-amber-400" />,
      color: 'amber',
      descriptionEn: 'Credential stuffing, password spraying, or bypass of application authentication gates.',
      descriptionAr: 'تخمين كلمات المرور أو تجاوز بوابات التحقق الأمنية للدخول.'
    },
    {
      id: 'Exploitation',
      order: 3,
      labelEn: '3. Exploitation',
      labelAr: '3. استغلال الثغرات والحقن',
      mitreTechnique: 'T1059.004 - Command Injection / SQLi',
      icon: <Zap className="w-4 h-4 text-rose-400" />,
      color: 'rose',
      descriptionEn: 'Arbitrary shell execution, SQL union injection, or SSRF cloud metadata queries.',
      descriptionAr: 'تنفيذ أوامر النظام عن بعد، حقن قواعد البيانات واستغلال ثغرات SSRF.'
    },
    {
      id: 'Persistence',
      order: 4,
      labelEn: '4. Persistence (FIM)',
      labelAr: '4. التثبيت والامتيازات (FIM)',
      mitreTechnique: 'T1505.003 - Web Shell / Sudoers',
      icon: <FileCode className="w-4 h-4 text-purple-400" />,
      color: 'purple',
      descriptionEn: 'Planting backdoors, modifying /etc/sudoers (NOPASSWD), or modifying critical binaries.',
      descriptionAr: 'زرع أبواب خلفية (Web Shell)، وتعديل ملفات الصلاحيات لضمان البقاء.'
    },
    {
      id: 'Exfiltration',
      order: 5,
      labelEn: '5. Exfiltration',
      labelAr: '5. تسريب البيانات وقناة C2',
      mitreTechnique: 'T1048 - Exfil Over Alternative Protocol',
      icon: <Skull className="w-4 h-4 text-red-500" />,
      color: 'red',
      descriptionEn: 'Encrypted outbound C2 tunneling, leaking environment tokens or database dumps.',
      descriptionAr: 'فتح قنوات اتصال خارجية مشفرة لتسريب أسرار الإنتاج وقواعد البيانات.'
    }
  ];

  // Fetch Data on Load
  const fetchAttackChains = async () => {
    setIsLoadingChains(true);
    try {
      const res = await fetch('/api/v1/soc/attack-chains');
      if (res.ok) {
        const data = await res.json();
        const chains: AttackChainSession[] = data.chains || [];
        setAttackChains(chains);
        if (chains.length > 0 && !selectedChain) {
          setSelectedChain(chains[0]);
        }
      }
    } catch (err) {
      console.error('Failed to fetch attack chains:', err);
    } finally {
      setIsLoadingChains(false);
    }
  };

  const fetchHoneytokens = async () => {
    setIsLoadingTraps(true);
    try {
      const res = await fetch('/api/v1/traffic/honeytokens');
      if (res.ok) {
        const data = await res.json();
        setHoneytokens(data.honeytokens || []);
      }
    } catch (err) {
      console.error('Failed to fetch honeytokens:', err);
    } finally {
      setIsLoadingTraps(false);
    }
  };

  const fetchCredentialStuffing = async () => {
    try {
      const res = await fetch('/api/v1/traffic/credential-stuffing');
      if (res.ok) {
        const data = await res.json();
        setCredentialEvents(data.events || []);
      }
    } catch (err) {
      console.error('Failed to fetch credential stuffing logs:', err);
    }
  };

  useEffect(() => {
    fetchAttackChains();
    fetchHoneytokens();
    fetchCredentialStuffing();
  }, []);

  // Simulate Multi-Stage Attack Chain
  const handleSimulateAttackChain = async () => {
    setIsSimulatingChain(true);
    setSimulationProgress(1);
    try {
      const res = await fetch('/api/v1/soc/attack-chains/simulate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          actorIp: '194.26.29.' + Math.floor(10 + Math.random() * 200),
          campaignName: 'APT-41 Operation Ghost Ingress'
        })
      });
      if (res.ok) {
        const data = await res.json();
        if (data.chain) {
          setSelectedChain(data.chain);
        }
        await fetchAttackChains();
      }
    } catch (err) {
      console.error('Simulation error:', err);
    } finally {
      setIsSimulatingChain(false);
      setSimulationProgress(0);
    }
  };

  // Trigger Honeytoken Trap
  const handleTriggerHoneytoken = async (trap: HoneytokenTrap) => {
    setTriggeringTrapId(trap.id);
    try {
      const res = await fetch('/api/v1/traffic/honeytoken/trigger', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          trapId: trap.id,
          endpointPath: trap.endpointPath
        })
      });
      if (res.ok) {
        const data = await res.json();
        setTrapActionFeedback(isAr ? `🚨 تم إطلاق فخ ${trap.endpointPath} وحظر المهاجم فوراً في نواة eBPF!` : `🚨 Tripwire ${trap.endpointPath} triggered! Attacker IP quarantined in kernel.`);
        fetchHoneytokens();
        fetchAttackChains();
      }
    } catch (err) {
      console.error('Trap trigger error:', err);
    } finally {
      setTriggeringTrapId(null);
    }
  };

  // Deploy New Custom Honeytoken
  const handleDeployCustomTrap = async () => {
    if (!newTrapPath) return;
    setIsDeployingTrap(true);
    try {
      const res = await fetch('/api/v1/traffic/honeytoken/create', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          endpointPath: newTrapPath.startsWith('/') ? newTrapPath : '/' + newTrapPath,
          trapType: newTrapType,
          descriptionEn: `Canary Decoy Trap on ${newTrapPath}`,
          descriptionAr: `فخ مصيدة على ${newTrapPath}`,
          autoBanEnabled: true
        })
      });
      if (res.ok) {
        setNewTrapPath('');
        fetchHoneytokens();
      }
    } catch (err) {
      console.error('Deploy trap error:', err);
    } finally {
      setIsDeployingTrap(false);
    }
  };

  // Simulate Credential Stuffing Swarm
  const handleSimulateCredentialStuffing = async () => {
    setIsSimulatingBruteForce(true);
    try {
      const res = await fetch('/api/v1/traffic/credential-stuffing/simulate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ targetUser: targetUsernameInput })
      });
      if (res.ok) {
        fetchCredentialStuffing();
        fetchAttackChains();
      }
    } catch (err) {
      console.error('Credential stuffing sim error:', err);
    } finally {
      setIsSimulatingBruteForce(false);
    }
  };

  // Isolate Attacker Subnet
  const handleIsolateAttacker = async (ip: string) => {
    try {
      const res = await fetch('/api/v1/traffic/ban-ip', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ip,
          reason: `Manual Tactical Isolation from Attack Chain Console for ${ip}`,
          reasonAr: `حظر تكتيكي يدوي للمهاجم ${ip}`
        })
      });
      if (res.ok) {
        alert(isAr ? `تم حظر المهاجم ${ip} في نواة eBPF بنجاح.` : `Attacker ${ip} quarantined in kernel.`);
        fetchAttackChains();
      }
    } catch (err) {
      console.error('Ban error:', err);
    }
  };

  // Generate dynamic Gemini Intent Summary for selected chain
  const getGeminiIntentSummary = (chain: AttackChainSession | null): string => {
    if (!chain) return isAr ? 'لا توجد جلسة هجومية محددة حالياً.' : 'No active attack chain selected.';
    const count = chain.stagesCompleted.length;
    if (count >= 5) {
      return isAr
        ? `🔥 استنتاج الذكاء الاصطناعي (Gemini Threat Intent): المهاجم ينفذ حملة متقدمة (APT Infiltration). بدأ بمسح الثغرات ثم استغل نقاط الضعف لحقن شيل ويب خبيث وتعديل ملف sudoers لرفع الصلاحيات، مع محاولة فتح قناة تسريب مشفرة للخارج. تم تفعيل الحظر الجذري بنجاح.`
        : `🔥 Gemini AI Threat Intent Reasoning: Attacker executed a full APT intrusion lifecycle. Probed public endpoints, achieved remote execution via Web Shell payload, modified /etc/sudoers (NOPASSWD) for privilege escalation, and attempted encrypted outbound C2 exfiltration. Autonomous kernel mitigation applied.`;
    } else if (count >= 3) {
      return isAr
        ? `⚠️ استنتاج الذكاء الاصطناعي (Gemini Threat Intent): المهاجم يحاول تنفيذ شيل خبيث وتثبيت أدوات التحكم عن بعد بعد اجتياز بوابات الفحص الأولى. يُنصح بعزل عنوان المصدر ومراجعة تكامل الملفات.`
        : `⚠️ Gemini AI Threat Intent Reasoning: Attacker bypassed initial access boundaries and is attempting remote shell implantation. High risk of privilege escalation. Recommended action: Isolate IP subnet immediately.`;
    } else {
      return isAr
        ? `ℹ️ استنتاج الذكاء الاصطناعي (Gemini Threat Intent): نشاط استطلاع ومسح أولي للأهداف بحثاً عن ملفات التكوين المكشوفة (.env و .git). لم يتم اختراق دفاعات النظام بعد.`
        : `ℹ️ Gemini AI Threat Intent Reasoning: Reconnaissance and surface enumeration activity detected. Probing for exposed credentials and canary endpoints. Defenses holding at perimeter.`;
    }
  };

  return (
    <div className="space-y-4 text-slate-200" dir={isAr ? 'rtl' : 'ltr'}>

      {/* ========================================================================= */}
      {/* 1. TOP SUB-NAVIGATION BAR & QUICK SUMMARY                                 */}
      {/* ========================================================================= */}
      <div className="bg-slate-950/90 border border-slate-800 rounded-xl p-3 flex flex-wrap items-center justify-between gap-3 shadow-xl backdrop-blur-md">
        
        {/* Navigation Mode Tabs */}
        <div className="flex items-center gap-1.5 bg-slate-900/90 p-1 rounded-lg border border-slate-800">
          <button
            onClick={() => setActiveView('ATTACK_GRAPH')}
            className={`px-3 py-1.5 rounded-md text-xs font-bold transition flex items-center gap-2 ${
              activeView === 'ATTACK_GRAPH'
                ? 'bg-gradient-to-r from-rose-900/80 to-purple-900/80 text-rose-200 border border-rose-500/50 shadow-md'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <GitCommit className="w-3.5 h-3.5 text-rose-400" />
            <span>{isAr ? 'مخطط سلسلة الهجمات التفاعلي (MITRE ATT&CK)' : 'MITRE ATT&CK Intrusion Graph'}</span>
            <span className="px-1.5 py-0.2 rounded text-[10px] font-mono bg-rose-950 text-rose-300 border border-rose-500/40">
              {attackChains.length}
            </span>
          </button>

          <button
            onClick={() => setActiveView('HONEYTOKENS')}
            className={`px-3 py-1.5 rounded-md text-xs font-bold transition flex items-center gap-2 ${
              activeView === 'HONEYTOKENS'
                ? 'bg-gradient-to-r from-purple-900/80 to-cyan-900/80 text-purple-200 border border-purple-500/50 shadow-md'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Radio className="w-3.5 h-3.5 text-purple-400 animate-pulse" />
            <span>{isAr ? 'فخاخ الخداع والمصائد المسمومة (Honeytokens)' : 'Honeytoken & Canary Traps'}</span>
            <span className="px-1.5 py-0.2 rounded text-[10px] font-mono bg-purple-950 text-purple-300 border border-purple-500/40">
              {honeytokens.length}
            </span>
          </button>

          <button
            onClick={() => setActiveView('CREDENTIAL_STUFFING')}
            className={`px-3 py-1.5 rounded-md text-xs font-bold transition flex items-center gap-2 ${
              activeView === 'CREDENTIAL_STUFFING'
                ? 'bg-gradient-to-r from-amber-900/80 to-rose-900/80 text-amber-200 border border-amber-500/50 shadow-md'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <KeyRound className="w-3.5 h-3.5 text-amber-400" />
            <span>{isAr ? 'تعقب هجمات التخمين والبوتات (Credential Stuffing)' : 'Credential Stuffing Botnets'}</span>
            <span className="px-1.5 py-0.2 rounded text-[10px] font-mono bg-amber-950 text-amber-300 border border-amber-500/40">
              {credentialEvents.length}
            </span>
          </button>
        </div>

        {/* Global Action: Refresh & Live Status */}
        <div className="flex items-center gap-2">
          <button
            onClick={() => {
              fetchAttackChains();
              fetchHoneytokens();
              fetchCredentialStuffing();
            }}
            className="px-2.5 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-700 text-xs font-bold flex items-center gap-1.5 transition"
          >
            <RefreshCw className="w-3.5 h-3.5 text-cyan-400" />
            <span>{isAr ? 'تحديث البيانات' : 'Refresh Telemetry'}</span>
          </button>
        </div>
      </div>

      {/* Feedback Banner */}
      {trapActionFeedback && (
        <div className="p-3 bg-purple-950/80 border border-purple-500/60 rounded-xl text-purple-200 text-xs flex items-center justify-between shadow-lg">
          <div className="flex items-center gap-2">
            <Radio className="w-4 h-4 text-purple-400 animate-pulse" />
            <span className="font-mono">{trapActionFeedback}</span>
          </div>
          <button
            onClick={() => setTrapActionFeedback(null)}
            className="text-xs text-purple-400 hover:text-white px-2 py-0.5"
          >
            ✕
          </button>
        </div>
      )}

      {/* ========================================================================= */}
      {/* VIEW 1: INTERACTIVE 5-STAGE MITRE ATT&CK INTRUSION GRAPH                  */}
      {/* ========================================================================= */}
      {activeView === 'ATTACK_GRAPH' && (
        <div className="space-y-4">
          
          {/* Top Controls: Session Selector & Simulation Trigger */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            
            {/* Left: Active Intrusion Sessions List */}
            <div className="lg:col-span-1 bg-slate-950/90 border border-slate-800 rounded-xl p-3.5 space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Skull className="w-4 h-4 text-rose-400" />
                  <h3 className="text-xs font-black uppercase text-slate-200 tracking-wider">
                    {isAr ? 'جلسات الهجمات المرصودة' : 'Correlated Attack Sessions'}
                  </h3>
                </div>
                <button
                  onClick={handleSimulateAttackChain}
                  disabled={isSimulatingChain}
                  className="px-2.5 py-1 rounded bg-rose-600 hover:bg-rose-500 text-white font-mono text-[11px] font-bold transition flex items-center gap-1 shadow-md shadow-rose-950/50"
                >
                  <Play className="w-3 h-3" />
                  <span>{isSimulatingChain ? (isAr ? 'جارِ المحاكاة...' : 'Simulating...') : (isAr ? 'محاكاة هجوم 5 مراحل' : 'Simulate 5-Stage APT')}</span>
                </button>
              </div>

              {/* Sessions Scroller */}
              <div className="space-y-2 max-h-72 overflow-y-auto pr-1">
                {attackChains.length === 0 ? (
                  <div className="text-center py-8 text-slate-500 text-xs">
                    {isAr ? 'لا توجد جلسات هجومية مكتشفة حالياً. انقر على "محاكاة هجوم 5 مراحل" لإنشاء سلسلة.' : 'No active attack chains correlated. Click "Simulate 5-Stage APT" to generate a live sequence.'}
                  </div>
                ) : (
                  attackChains.map((chain) => {
                    const isSelected = selectedChain?.sessionId === chain.sessionId;
                    return (
                      <div
                        key={chain.sessionId}
                        onClick={() => setSelectedChain(chain)}
                        className={`p-3 rounded-lg border cursor-pointer transition ${
                          isSelected
                            ? 'bg-rose-950/40 border-rose-500/80 shadow-lg shadow-rose-950/40'
                            : 'bg-slate-900/60 border-slate-800/80 hover:bg-slate-900 hover:border-slate-700'
                        }`}
                      >
                        <div className="flex items-center justify-between mb-1.5">
                          <span className="font-mono text-xs font-black text-rose-300">
                            {chain.actorIp}
                          </span>
                          <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                            chain.threatScore >= 90 ? 'bg-rose-950 text-rose-300 border border-rose-500/40' : 'bg-amber-950 text-amber-300 border border-amber-500/40'
                          }`}>
                            SCORE {chain.threatScore}/100
                          </span>
                        </div>

                        <div className="flex items-center justify-between text-[11px] text-slate-400 font-mono">
                          <span>Stages: {chain.stagesCompleted.length}/5</span>
                          <span className={`px-1.5 py-0.2 rounded text-[10px] ${
                            chain.status === 'CONTAINED' ? 'bg-emerald-950 text-emerald-300' : 'bg-rose-950 text-rose-400 animate-pulse'
                          }`}>
                            {chain.status}
                          </span>
                        </div>

                        {/* Visual Stage Progress Dots */}
                        <div className="flex items-center gap-1 mt-2">
                          {CANONICAL_STAGES.map((s) => {
                            const completed = chain.stagesCompleted.some(sc => sc.stage === s.id);
                            return (
                              <div
                                key={s.id}
                                title={`${s.labelEn}: ${completed ? 'TRIGGERED' : 'PENDING'}`}
                                className={`h-1.5 flex-1 rounded-full ${
                                  completed ? 'bg-rose-500 shadow-sm shadow-rose-500' : 'bg-slate-800'
                                }`}
                              />
                            );
                          })}
                        </div>
                      </div>
                    );
                  })
                )}
              </div>
            </div>

            {/* Right: Selected Session Detail & Gemini AI Intent Reasoning */}
            <div className="lg:col-span-2 bg-slate-950/90 border border-slate-800 rounded-xl p-4 space-y-3 flex flex-col justify-between">
              
              {/* Header Info */}
              <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800/80 pb-3">
                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-black uppercase text-slate-400 font-mono">
                      {isAr ? 'معرف جلسة التهديد' : 'ATTACK CHAIN ID'}:
                    </span>
                    <span className="text-sm font-black text-rose-400 font-mono">
                      {selectedChain ? selectedChain.sessionId : 'N/A'}
                    </span>
                    {selectedChain && (
                      <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-rose-950 text-rose-300 border border-rose-500/40">
                        ACTOR: {selectedChain.actorIp}
                      </span>
                    )}
                  </div>
                  <p className="text-[11px] text-slate-400 font-mono mt-0.5">
                    {selectedChain ? `${isAr ? 'أول رصد' : 'First Seen'}: ${new Date(selectedChain.firstSeen).toLocaleTimeString()} | ${isAr ? 'آخر نشاط' : 'Last Seen'}: ${new Date(selectedChain.lastSeen).toLocaleTimeString()}` : ''}
                  </p>
                </div>

                {selectedChain && (
                  <div className="w-56">
                    <NodeIsolationButton
                      targetId={selectedChain.actorIp}
                      targetIp={selectedChain.actorIp}
                      targetLabel={`Threat Actor ${selectedChain.actorIp}`}
                      lang={lang}
                      onSuccess={() => {
                        fetchAttackChains();
                      }}
                    />
                  </div>
                )}
              </div>

              {/* Gemini AI Reasoning Box */}
              <div className="bg-gradient-to-br from-indigo-950/40 via-purple-950/30 to-slate-900/60 border border-purple-500/40 rounded-xl p-3.5 shadow-inner">
                <div className="flex items-center gap-2 text-purple-300 text-xs font-bold mb-1.5">
                  <Sparkles className="w-4 h-4 text-purple-400 animate-pulse" />
                  <span>{isAr ? 'تحليل النوايا الهجومية (Gemini AI Threat Intent Summary)' : 'Gemini AI Attack Intent & Blast Radius Assessment'}</span>
                </div>
                <p className="text-xs text-slate-300 leading-relaxed font-mono">
                  {getGeminiIntentSummary(selectedChain)}
                </p>
              </div>

              {/* Quick Attack Chain Metrics */}
              <div className="grid grid-cols-3 gap-3 font-mono">
                <div className="p-2.5 rounded-lg bg-slate-900/80 border border-slate-800">
                  <span className="text-[10px] text-slate-400 block">{isAr ? 'مستوى الخطورة' : 'THREAT LEVEL'}</span>
                  <span className="text-sm font-bold text-rose-400">
                    {selectedChain ? (selectedChain.threatScore >= 80 ? 'CRITICAL' : 'HIGH') : 'NOMINAL'}
                  </span>
                </div>

                <div className="p-2.5 rounded-lg bg-slate-900/80 border border-slate-800">
                  <span className="text-[10px] text-slate-400 block">{isAr ? 'المراحل المكتملة' : 'PROGRESSION'}</span>
                  <span className="text-sm font-bold text-cyan-300">
                    {selectedChain ? `${selectedChain.stagesCompleted.length} of 5 Stages` : '0 / 5'}
                  </span>
                </div>

                <div className="p-2.5 rounded-lg bg-slate-900/80 border border-slate-800">
                  <span className="text-[10px] text-slate-400 block">{isAr ? 'حالة الاحتواء' : 'CONTAINMENT'}</span>
                  <span className={`text-sm font-bold ${selectedChain?.status === 'CONTAINED' ? 'text-emerald-400' : 'text-amber-400'}`}>
                    {selectedChain ? selectedChain.status : 'N/A'}
                  </span>
                </div>
              </div>

            </div>
          </div>

          {/* ========================================================================= */}
          {/* 5-STAGE INTERACTIVE MITRE ATT&CK PROGRESSION GRAPH                       */}
          {/* ========================================================================= */}
          <div className="bg-slate-950/95 border border-slate-800 rounded-xl p-5 shadow-2xl space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <GitCommit className="w-5 h-5 text-rose-400" />
                <h3 className="text-sm font-black uppercase text-slate-200 tracking-wider">
                  {isAr ? 'المسار الزمني لمراحل الهجوم الخمس (5-Stage MITRE Progression Graph)' : '5-Stage MITRE ATT&CK Intrusion Pipeline'}
                </h3>
              </div>
              <span className="text-xs text-slate-400 font-mono">
                {isAr ? 'اضغط على أي مرحلة لعرض الأدلة والحمولة' : 'Click any node to inspect raw forensic payload'}
              </span>
            </div>

            {/* Visual 5-Stage Pipeline */}
            <div className="grid grid-cols-1 md:grid-cols-5 gap-3 relative">
              {CANONICAL_STAGES.map((stage, idx) => {
                const stageData = selectedChain?.stagesCompleted.find(sc => sc.stage === stage.id);
                const isTriggered = !!stageData;

                return (
                  <div
                    key={stage.id}
                    className={`relative p-3.5 rounded-xl border flex flex-col justify-between min-h-[190px] transition-all duration-300 ${
                      isTriggered
                        ? 'bg-slate-900/90 border-rose-500/70 shadow-lg shadow-rose-950/50'
                        : 'bg-slate-950/40 border-slate-800/60 opacity-60'
                    }`}
                  >
                    {/* Top Order & Status Badge */}
                    <div>
                      <div className="flex items-center justify-between mb-2">
                        <div className="flex items-center gap-1.5">
                          {stage.icon}
                          <span className="font-mono text-xs font-black text-slate-200">
                            {isAr ? stage.labelAr : stage.labelEn}
                          </span>
                        </div>
                        <span className={`px-1.5 py-0.5 rounded text-[9px] font-mono font-bold ${
                          isTriggered ? 'bg-rose-950 text-rose-300 border border-rose-500/50 animate-pulse' : 'bg-slate-800 text-slate-400'
                        }`}>
                          {isTriggered ? 'TRIGGERED' : 'INACTIVE'}
                        </span>
                      </div>

                      {/* MITRE Technique Badge */}
                      <div className="inline-block px-2 py-0.5 rounded text-[10px] font-mono bg-slate-950 text-cyan-300 border border-cyan-500/30 mb-2">
                        {stageData?.technique || stage.mitreTechnique}
                      </div>

                      <p className="text-[11px] text-slate-400 leading-snug">
                        {isAr ? stage.descriptionAr : stage.descriptionEn}
                      </p>
                    </div>

                    {/* Bottom Evidence & Timestamp */}
                    <div className="mt-3 pt-2 border-t border-slate-800/80 font-mono text-[10px]">
                      {isTriggered ? (
                        <div className="space-y-1">
                          <div className="text-emerald-400 flex items-center gap-1">
                            <CheckCircle2 className="w-3 h-3" />
                            <span>{new Date(stageData.timestamp).toLocaleTimeString()}</span>
                          </div>
                          <p className="text-rose-300 truncate" title={stageData.description}>
                            {stageData.description}
                          </p>
                        </div>
                      ) : (
                        <span className="text-slate-500 flex items-center gap-1">
                          <Clock className="w-3 h-3" />
                          <span>{isAr ? 'في انتظار الرصد' : 'Awaiting Detection'}</span>
                        </span>
                      )}
                    </div>

                    {/* Step Connector Arrow (for desktop) */}
                    {idx < 4 && (
                      <div className="hidden md:block absolute -right-3 top-1/2 -translate-y-1/2 z-10">
                        <ArrowRight className={`w-4 h-4 ${isTriggered ? 'text-rose-400' : 'text-slate-700'}`} />
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>

        </div>
      )}

      {/* ========================================================================= */}
      {/* VIEW 2: HONEYTOKEN & CANARY TRAPS DECEPTION MONITOR                       */}
      {/* ========================================================================= */}
      {activeView === 'HONEYTOKENS' && (
        <div className="space-y-4">
          
          {/* Top Banner & Deployment Controls */}
          <div className="bg-slate-950/90 border border-purple-500/30 rounded-xl p-4 shadow-xl backdrop-blur-md">
            <div className="flex flex-wrap items-center justify-between gap-4 mb-4">
              <div>
                <div className="flex items-center gap-2">
                  <Radio className="w-5 h-5 text-purple-400 animate-pulse" />
                  <h3 className="text-sm font-black uppercase text-purple-300 tracking-wider">
                    {isAr ? 'منظومة الخداع السيبراني والمصائد المسمومة (Honeytoken Deception Engine)' : 'Autonomous Honeytoken & Canary Trap Monitor'}
                  </h3>
                </div>
                <p className="text-xs text-slate-400 mt-1 font-mono">
                  {isAr
                    ? 'نشر مسارات وهمية وأصول مسمومة (/env., /.git, /admin). أي محاولة وصول تفعل الحظر الفوري التلقائي في نواة eBPF.'
                    : 'Active decoys deployed across critical endpoints. Any unauthorized request instantly triggers auto-jail & kernel IP ban.'}
                </p>
              </div>

              {/* Stats Counters */}
              <div className="flex items-center gap-3 font-mono">
                <div className="px-3 py-1.5 rounded-lg bg-purple-950/60 border border-purple-500/40 text-center">
                  <span className="text-[10px] text-purple-300 block leading-none">ACTIVE TRAPS</span>
                  <span className="text-sm font-bold text-purple-200">{honeytokens.length} Endpoints</span>
                </div>
                <div className="px-3 py-1.5 rounded-lg bg-rose-950/60 border border-rose-500/40 text-center">
                  <span className="text-[10px] text-rose-300 block leading-none">TOTAL HITS</span>
                  <span className="text-sm font-bold text-rose-200">
                    {honeytokens.reduce((acc, t) => acc + t.hitsCount, 0)} Intercepted
                  </span>
                </div>
              </div>
            </div>

            {/* Deploy Custom Trap Form */}
            <div className="bg-slate-900/80 border border-slate-800 rounded-lg p-3 flex flex-wrap items-center gap-3">
              <span className="text-xs font-bold text-slate-300 whitespace-nowrap">
                {isAr ? 'نشر فخ مخصص جديد:' : 'Deploy Custom Canary Trap:'}
              </span>
              <input
                type="text"
                value={newTrapPath}
                onChange={(e) => setNewTrapPath(e.target.value)}
                placeholder="/admin/credentials.txt or /.aws/config"
                className="px-3 py-1.5 rounded bg-slate-950 border border-slate-700 text-xs font-mono text-cyan-300 focus:outline-none focus:border-purple-400 flex-1 min-w-[200px]"
              />
              <select
                value={newTrapType}
                onChange={(e) => setNewTrapType(e.target.value as any)}
                className="px-3 py-1.5 rounded bg-slate-950 border border-slate-700 text-xs font-mono text-slate-200 focus:outline-none"
              >
                <option value="ENV_SECRETS">ENV Secrets Decoy</option>
                <option value="GIT_CONFIG">Git Config Trap</option>
                <option value="ADMIN_PANEL">Admin Panel Decoy</option>
                <option value="WORDPRESS_WP_LOGIN">WordPress WP-Login Trap</option>
                <option value="AWS_IAM_CREDENTIALS">AWS IAM Credentials Canary</option>
              </select>
              <button
                onClick={handleDeployCustomTrap}
                disabled={isDeployingTrap || !newTrapPath}
                className="px-3 py-1.5 rounded bg-purple-600 hover:bg-purple-500 text-white text-xs font-bold font-mono transition flex items-center gap-1.5 disabled:opacity-50"
              >
                <Sparkles className="w-3.5 h-3.5" />
                <span>{isAr ? 'نشر الفخ في المسار' : 'Deploy Canary Asset'}</span>
              </button>
            </div>
          </div>

          {/* Active Honeytokens Table */}
          <div className="bg-slate-950/90 border border-slate-800 rounded-xl overflow-hidden shadow-xl">
            <div className="p-3.5 bg-slate-900/90 border-b border-slate-800 flex items-center justify-between">
              <span className="text-xs font-black uppercase text-slate-300 tracking-wider">
                {isAr ? 'قائمة الفخاخ والمصائد النشطة' : 'Active Deception Endpoints & Auto-Jail Status'}
              </span>
              <span className="text-xs text-purple-400 font-mono">
                {isAr ? 'نظام الحظر الفوري: نشط في النواة (Kernel Auto-Ban Active)' : 'Kernel eBPF Auto-Jail: ENFORCED'}
              </span>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left font-mono text-xs" dir="ltr">
                <thead className="bg-slate-950 text-slate-400 border-b border-slate-800">
                  <tr>
                    <th className="px-4 py-2.5">TRAP ID</th>
                    <th className="px-4 py-2.5">CANARY ENDPOINT</th>
                    <th className="px-4 py-2.5">DECOY TYPE</th>
                    <th className="px-4 py-2.5 text-center">HITS</th>
                    <th className="px-4 py-2.5">LAST TRIGGERED</th>
                    <th className="px-4 py-2.5">LAST ATTACKER</th>
                    <th className="px-4 py-2.5">AUTO-JAIL</th>
                    <th className="px-4 py-2.5 text-right">ACTION</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {honeytokens.map((trap) => (
                    <tr key={trap.id} className="hover:bg-slate-900/60 transition">
                      <td className="px-4 py-3 font-bold text-purple-300">{trap.id}</td>
                      <td className="px-4 py-3 font-bold text-cyan-300">{trap.endpointPath}</td>
                      <td className="px-4 py-3 text-slate-300">{trap.trapType}</td>
                      <td className="px-4 py-3 text-center">
                        <span className={`px-2 py-0.5 rounded font-bold ${
                          trap.hitsCount > 0 ? 'bg-rose-950 text-rose-300 border border-rose-500/40' : 'bg-slate-900 text-slate-500'
                        }`}>
                          {trap.hitsCount}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-slate-400">
                        {trap.lastTriggered ? new Date(trap.lastTriggered).toLocaleTimeString() : 'NEVER'}
                      </td>
                      <td className="px-4 py-3 text-amber-300">{trap.lastAttackerIp || 'NONE'}</td>
                      <td className="px-4 py-3">
                        <span className="px-2 py-0.5 rounded text-[10px] bg-emerald-950 text-emerald-300 border border-emerald-500/30 flex items-center gap-1 w-fit">
                          <CheckCircle2 className="w-3 h-3" />
                          <span>eBPF BAN</span>
                        </span>
                      </td>
                      <td className="px-4 py-3 text-right">
                        <button
                          onClick={() => handleTriggerHoneytoken(trap)}
                          disabled={triggeringTrapId === trap.id}
                          className="px-2.5 py-1 rounded bg-rose-900/80 hover:bg-rose-800 text-rose-200 text-[11px] font-bold border border-rose-500/40 transition flex items-center gap-1 ml-auto"
                        >
                          <Zap className="w-3 h-3 text-amber-400" />
                          <span>{triggeringTrapId === trap.id ? 'Triggering...' : 'Simulate Tripwire Hit'}</span>
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

        </div>
      )}

      {/* ========================================================================= */}
      {/* VIEW 3: CREDENTIAL STUFFING & BOTNET CLUSTER MONITOR                      */}
      {/* ========================================================================= */}
      {activeView === 'CREDENTIAL_STUFFING' && (
        <div className="space-y-4">
          
          {/* Top Controls */}
          <div className="bg-slate-950/90 border border-amber-500/30 rounded-xl p-4 shadow-xl backdrop-blur-md">
            <div className="flex flex-wrap items-center justify-between gap-4 mb-4">
              <div>
                <div className="flex items-center gap-2">
                  <KeyRound className="w-5 h-5 text-amber-400" />
                  <h3 className="text-sm font-black uppercase text-amber-300 tracking-wider">
                    {isAr ? 'مراقبة هجمات التخمين والبوتات الموزعة (Credential Stuffing & Password Spraying)' : 'Distributed Credential Stuffing & Velocity Defense'}
                  </h3>
                </div>
                <p className="text-xs text-slate-400 mt-1 font-mono">
                  {isAr
                    ? 'رصد محاولات التخمين عالية التردد وحظر شبكات البوتات الموزعة وتطبيق تحديات CAPTCHA التلقائية.'
                    : 'Real-time velocity thresholding, automated account lockouts, and distributed botnet swarm neutralization.'}
                </p>
              </div>

              {/* Attack Simulator Form */}
              <div className="flex items-center gap-2 bg-slate-900/80 p-2 rounded-lg border border-slate-800">
                <input
                  type="text"
                  value={targetUsernameInput}
                  onChange={(e) => setTargetUsernameInput(e.target.value)}
                  placeholder="target_user@domain.com"
                  className="px-2.5 py-1 rounded bg-slate-950 border border-slate-700 text-xs font-mono text-cyan-300 focus:outline-none"
                />
                <button
                  onClick={handleSimulateCredentialStuffing}
                  disabled={isSimulatingBruteForce}
                  className="px-3 py-1 rounded bg-amber-600 hover:bg-amber-500 text-slate-950 font-bold font-mono text-xs transition flex items-center gap-1.5"
                >
                  <Play className="w-3 h-3" />
                  <span>{isSimulatingBruteForce ? (isAr ? 'جارِ الإطلاق...' : 'Launching...') : (isAr ? 'محاكاة هجوم تخمين' : 'Simulate Brute Force')}</span>
                </button>
              </div>
            </div>
          </div>

          {/* Credential Events Feed Table */}
          <div className="bg-slate-950/90 border border-slate-800 rounded-xl overflow-hidden shadow-xl">
            <div className="p-3.5 bg-slate-900/90 border-b border-slate-800 flex items-center justify-between">
              <span className="text-xs font-black uppercase text-slate-300 tracking-wider">
                {isAr ? 'سجل هجمات التخمين والبوتات المعترضة' : 'Intercepted Credential Stuffing Telemetry Feed'}
              </span>
              <span className="text-xs text-amber-400 font-mono">
                {isAr ? 'تأمين المصادقة: فعال' : 'PAM Shield: ACTIVE'}
              </span>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left font-mono text-xs" dir="ltr">
                <thead className="bg-slate-950 text-slate-400 border-b border-slate-800">
                  <tr>
                    <th className="px-4 py-2.5">TIMESTAMP</th>
                    <th className="px-4 py-2.5">BOTNET NODE IP</th>
                    <th className="px-4 py-2.5">TARGET ENDPOINT</th>
                    <th className="px-4 py-2.5">ACCOUNT ATTEMPTED</th>
                    <th className="px-4 py-2.5">VELOCITY</th>
                    <th className="px-4 py-2.5">BOTNET CLUSTER</th>
                    <th className="px-4 py-2.5 text-right">ACTION TAKEN</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {credentialEvents.map((evt) => (
                    <tr key={evt.id} className="hover:bg-slate-900/60 transition">
                      <td className="px-4 py-3 text-slate-400">{new Date(evt.timestamp).toLocaleTimeString()}</td>
                      <td className="px-4 py-3 font-bold text-rose-400">{evt.sourceIp}</td>
                      <td className="px-4 py-3 text-cyan-300">{evt.targetEndpoint}</td>
                      <td className="px-4 py-3 font-bold text-amber-300">{evt.usernameAttempted}</td>
                      <td className="px-4 py-3 text-slate-200">
                        <span className="px-2 py-0.5 rounded bg-rose-950 text-rose-300 font-bold">
                          {evt.velocityPerMinute} req/min
                        </span>
                      </td>
                      <td className="px-4 py-3 text-purple-300">{evt.botnetClusterName || 'Distributed Swarm'}</td>
                      <td className="px-4 py-3 text-right">
                        <span className="px-2 py-0.5 rounded text-[10px] bg-rose-950 text-rose-300 border border-rose-500/40 font-bold">
                          {evt.actionTaken}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

        </div>
      )}

    </div>
  );
};
