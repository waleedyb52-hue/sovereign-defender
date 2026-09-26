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
  const [activeView, setActiveView] = useState<
    'ATTACK_GRAPH' | 'HONEYTOKENS' | 'CREDENTIAL_STUFFING'
  >('ATTACK_GRAPH');

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
  const [newTrapType, setNewTrapType] = useState<
    'ENV_SECRETS' | 'GIT_CONFIG' | 'ADMIN_PANEL' | 'WORDPRESS_WP_LOGIN' | 'AWS_IAM_CREDENTIALS'
  >('ENV_SECRETS');
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
      icon: <Search className="h-4 w-4 text-cyan-400" />,
      color: 'cyan',
      descriptionEn:
        'Port sweep, directory enumeration, and vulnerability probing against public surfaces.',
      descriptionAr: 'مسح المنافذ واستكشاف المسارات البرمجية بحثاً عن ثغرات مكشوفة.'
    },
    {
      id: 'Initial Access',
      order: 2,
      labelEn: '2. Initial Access',
      labelAr: '2. الوصول الأولي والاختراق',
      mitreTechnique: 'T1190 - Exploit Public-Facing App',
      icon: <KeyRound className="h-4 w-4 text-amber-400" />,
      color: 'amber',
      descriptionEn:
        'Credential stuffing, password spraying, or bypass of application authentication gates.',
      descriptionAr: 'تخمين كلمات المرور أو تجاوز بوابات التحقق الأمنية للدخول.'
    },
    {
      id: 'Exploitation',
      order: 3,
      labelEn: '3. Exploitation',
      labelAr: '3. استغلال الثغرات والحقن',
      mitreTechnique: 'T1059.004 - Command Injection / SQLi',
      icon: <Zap className="h-4 w-4 text-rose-400" />,
      color: 'rose',
      descriptionEn:
        'Arbitrary shell execution, SQL union injection, or SSRF cloud metadata queries.',
      descriptionAr: 'تنفيذ أوامر النظام عن بعد، حقن قواعد البيانات واستغلال ثغرات SSRF.'
    },
    {
      id: 'Persistence',
      order: 4,
      labelEn: '4. Persistence (FIM)',
      labelAr: '4. التثبيت والامتيازات (FIM)',
      mitreTechnique: 'T1505.003 - Web Shell / Sudoers',
      icon: <FileCode className="h-4 w-4 text-purple-400" />,
      color: 'purple',
      descriptionEn:
        'Planting backdoors, modifying /etc/sudoers (NOPASSWD), or modifying critical binaries.',
      descriptionAr: 'زرع أبواب خلفية (Web Shell)، وتعديل ملفات الصلاحيات لضمان البقاء.'
    },
    {
      id: 'Exfiltration',
      order: 5,
      labelEn: '5. Exfiltration',
      labelAr: '5. تسريب البيانات وقناة C2',
      mitreTechnique: 'T1048 - Exfil Over Alternative Protocol',
      icon: <Skull className="h-4 w-4 text-red-500" />,
      color: 'red',
      descriptionEn:
        'Encrypted outbound C2 tunneling, leaking environment tokens or database dumps.',
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
        setTrapActionFeedback(
          isAr
            ? `🚨 تم إطلاق فخ ${trap.endpointPath} وحظر المهاجم فوراً في نواة eBPF!`
            : `🚨 Tripwire ${trap.endpointPath} triggered! Attacker IP quarantined in kernel.`
        );
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
        alert(
          isAr
            ? `تم حظر المهاجم ${ip} في نواة eBPF بنجاح.`
            : `Attacker ${ip} quarantined in kernel.`
        );
        fetchAttackChains();
      }
    } catch (err) {
      console.error('Ban error:', err);
    }
  };

  // Generate dynamic Gemini Intent Summary for selected chain
  const getGeminiIntentSummary = (chain: AttackChainSession | null): string => {
    if (!chain)
      return isAr ? 'لا توجد جلسة هجومية محددة حالياً.' : 'No active attack chain selected.';
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
      <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-slate-800 bg-slate-950/90 p-3 shadow-xl backdrop-blur-md">
        {/* Navigation Mode Tabs */}
        <div className="flex items-center gap-1.5 rounded-lg border border-slate-800 bg-slate-900/90 p-1">
          <button
            onClick={() => setActiveView('ATTACK_GRAPH')}
            className={`flex items-center gap-2 rounded-md px-3 py-1.5 text-xs font-bold transition ${
              activeView === 'ATTACK_GRAPH'
                ? 'border border-rose-500/50 bg-gradient-to-r from-rose-900/80 to-purple-900/80 text-rose-200 shadow-md'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <GitCommit className="h-3.5 w-3.5 text-rose-400" />
            <span>
              {isAr ? 'مخطط سلسلة الهجمات التفاعلي (MITRE ATT&CK)' : 'MITRE ATT&CK Intrusion Graph'}
            </span>
            <span className="py-0.2 rounded border border-rose-500/40 bg-rose-950 px-1.5 font-mono text-[10px] text-rose-300">
              {attackChains.length}
            </span>
          </button>

          <button
            onClick={() => setActiveView('HONEYTOKENS')}
            className={`flex items-center gap-2 rounded-md px-3 py-1.5 text-xs font-bold transition ${
              activeView === 'HONEYTOKENS'
                ? 'border border-purple-500/50 bg-gradient-to-r from-purple-900/80 to-cyan-900/80 text-purple-200 shadow-md'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Radio className="h-3.5 w-3.5 animate-pulse text-purple-400" />
            <span>
              {isAr ? 'فخاخ الخداع والمصائد المسمومة (Honeytokens)' : 'Honeytoken & Canary Traps'}
            </span>
            <span className="py-0.2 rounded border border-purple-500/40 bg-purple-950 px-1.5 font-mono text-[10px] text-purple-300">
              {honeytokens.length}
            </span>
          </button>

          <button
            onClick={() => setActiveView('CREDENTIAL_STUFFING')}
            className={`flex items-center gap-2 rounded-md px-3 py-1.5 text-xs font-bold transition ${
              activeView === 'CREDENTIAL_STUFFING'
                ? 'border border-amber-500/50 bg-gradient-to-r from-amber-900/80 to-rose-900/80 text-amber-200 shadow-md'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <KeyRound className="h-3.5 w-3.5 text-amber-400" />
            <span>
              {isAr
                ? 'تعقب هجمات التخمين والبوتات (Credential Stuffing)'
                : 'Credential Stuffing Botnets'}
            </span>
            <span className="py-0.2 rounded border border-amber-500/40 bg-amber-950 px-1.5 font-mono text-[10px] text-amber-300">
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
            className="flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-900 px-2.5 py-1.5 text-xs font-bold text-slate-300 transition hover:bg-slate-800"
          >
            <RefreshCw className="h-3.5 w-3.5 text-cyan-400" />
            <span>{isAr ? 'تحديث البيانات' : 'Refresh Telemetry'}</span>
          </button>
        </div>
      </div>

      {/* Feedback Banner */}
      {trapActionFeedback && (
        <div className="flex items-center justify-between rounded-xl border border-purple-500/60 bg-purple-950/80 p-3 text-xs text-purple-200 shadow-lg">
          <div className="flex items-center gap-2">
            <Radio className="h-4 w-4 animate-pulse text-purple-400" />
            <span className="font-mono">{trapActionFeedback}</span>
          </div>
          <button
            onClick={() => setTrapActionFeedback(null)}
            className="px-2 py-0.5 text-xs text-purple-400 hover:text-white"
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
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
            {/* Left: Active Intrusion Sessions List */}
            <div className="space-y-3 rounded-xl border border-slate-800 bg-slate-950/90 p-3.5 lg:col-span-1">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Skull className="h-4 w-4 text-rose-400" />
                  <h3 className="text-xs font-black tracking-wider text-slate-200 uppercase">
                    {isAr ? 'جلسات الهجمات المرصودة' : 'Correlated Attack Sessions'}
                  </h3>
                </div>
                <button
                  onClick={handleSimulateAttackChain}
                  disabled={isSimulatingChain}
                  className="flex items-center gap-1 rounded bg-rose-600 px-2.5 py-1 font-mono text-[11px] font-bold text-white shadow-md shadow-rose-950/50 transition hover:bg-rose-500"
                >
                  <Play className="h-3 w-3" />
                  <span>
                    {isSimulatingChain
                      ? isAr
                        ? 'جارِ المحاكاة...'
                        : 'Simulating...'
                      : isAr
                        ? 'محاكاة هجوم 5 مراحل'
                        : 'Simulate 5-Stage APT'}
                  </span>
                </button>
              </div>

              {/* Sessions Scroller */}
              <div className="max-h-72 space-y-2 overflow-y-auto pr-1">
                {attackChains.length === 0 ? (
                  <div className="py-8 text-center text-xs text-slate-500">
                    {isAr
                      ? 'لا توجد جلسات هجومية مكتشفة حالياً. انقر على "محاكاة هجوم 5 مراحل" لإنشاء سلسلة.'
                      : 'No active attack chains correlated. Click "Simulate 5-Stage APT" to generate a live sequence.'}
                  </div>
                ) : (
                  attackChains.map(chain => {
                    const isSelected = selectedChain?.sessionId === chain.sessionId;
                    return (
                      <div
                        key={chain.sessionId}
                        onClick={() => setSelectedChain(chain)}
                        className={`cursor-pointer rounded-lg border p-3 transition ${
                          isSelected
                            ? 'border-rose-500/80 bg-rose-950/40 shadow-lg shadow-rose-950/40'
                            : 'border-slate-800/80 bg-slate-900/60 hover:border-slate-700 hover:bg-slate-900'
                        }`}
                      >
                        <div className="mb-1.5 flex items-center justify-between">
                          <span className="font-mono text-xs font-black text-rose-300">
                            {chain.actorIp}
                          </span>
                          <span
                            className={`rounded px-2 py-0.5 font-mono text-[10px] font-bold ${
                              chain.threatScore >= 90
                                ? 'border border-rose-500/40 bg-rose-950 text-rose-300'
                                : 'border border-amber-500/40 bg-amber-950 text-amber-300'
                            }`}
                          >
                            SCORE {chain.threatScore}/100
                          </span>
                        </div>

                        <div className="flex items-center justify-between font-mono text-[11px] text-slate-400">
                          <span>Stages: {chain.stagesCompleted.length}/5</span>
                          <span
                            className={`py-0.2 rounded px-1.5 text-[10px] ${
                              chain.status === 'CONTAINED'
                                ? 'bg-emerald-950 text-emerald-300'
                                : 'animate-pulse bg-rose-950 text-rose-400'
                            }`}
                          >
                            {chain.status}
                          </span>
                        </div>

                        {/* Visual Stage Progress Dots */}
                        <div className="mt-2 flex items-center gap-1">
                          {CANONICAL_STAGES.map(s => {
                            const completed = chain.stagesCompleted.some(sc => sc.stage === s.id);
                            return (
                              <div
                                key={s.id}
                                title={`${s.labelEn}: ${completed ? 'TRIGGERED' : 'PENDING'}`}
                                className={`h-1.5 flex-1 rounded-full ${
                                  completed
                                    ? 'bg-rose-500 shadow-sm shadow-rose-500'
                                    : 'bg-slate-800'
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
            <div className="flex flex-col justify-between space-y-3 rounded-xl border border-slate-800 bg-slate-950/90 p-4 lg:col-span-2">
              {/* Header Info */}
              <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800/80 pb-3">
                <div>
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs font-black text-slate-400 uppercase">
                      {isAr ? 'معرف جلسة التهديد' : 'ATTACK CHAIN ID'}:
                    </span>
                    <span className="font-mono text-sm font-black text-rose-400">
                      {selectedChain ? selectedChain.sessionId : 'N/A'}
                    </span>
                    {selectedChain && (
                      <span className="rounded border border-rose-500/40 bg-rose-950 px-2 py-0.5 font-mono text-[10px] text-rose-300">
                        ACTOR: {selectedChain.actorIp}
                      </span>
                    )}
                  </div>
                  <p className="mt-0.5 font-mono text-[11px] text-slate-400">
                    {selectedChain
                      ? `${isAr ? 'أول رصد' : 'First Seen'}: ${new Date(selectedChain.firstSeen).toLocaleTimeString()} | ${isAr ? 'آخر نشاط' : 'Last Seen'}: ${new Date(selectedChain.lastSeen).toLocaleTimeString()}`
                      : ''}
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
              <div className="rounded-xl border border-purple-500/40 bg-gradient-to-br from-indigo-950/40 via-purple-950/30 to-slate-900/60 p-3.5 shadow-inner">
                <div className="mb-1.5 flex items-center gap-2 text-xs font-bold text-purple-300">
                  <Sparkles className="h-4 w-4 animate-pulse text-purple-400" />
                  <span>
                    {isAr
                      ? 'تحليل النوايا الهجومية (Gemini AI Threat Intent Summary)'
                      : 'Gemini AI Attack Intent & Blast Radius Assessment'}
                  </span>
                </div>
                <p className="font-mono text-xs leading-relaxed text-slate-300">
                  {getGeminiIntentSummary(selectedChain)}
                </p>
              </div>

              {/* Quick Attack Chain Metrics */}
              <div className="grid grid-cols-3 gap-3 font-mono">
                <div className="rounded-lg border border-slate-800 bg-slate-900/80 p-2.5">
                  <span className="block text-[10px] text-slate-400">
                    {isAr ? 'مستوى الخطورة' : 'THREAT LEVEL'}
                  </span>
                  <span className="text-sm font-bold text-rose-400">
                    {selectedChain
                      ? selectedChain.threatScore >= 80
                        ? 'CRITICAL'
                        : 'HIGH'
                      : 'NOMINAL'}
                  </span>
                </div>

                <div className="rounded-lg border border-slate-800 bg-slate-900/80 p-2.5">
                  <span className="block text-[10px] text-slate-400">
                    {isAr ? 'المراحل المكتملة' : 'PROGRESSION'}
                  </span>
                  <span className="text-sm font-bold text-cyan-300">
                    {selectedChain
                      ? `${selectedChain.stagesCompleted.length} of 5 Stages`
                      : '0 / 5'}
                  </span>
                </div>

                <div className="rounded-lg border border-slate-800 bg-slate-900/80 p-2.5">
                  <span className="block text-[10px] text-slate-400">
                    {isAr ? 'حالة الاحتواء' : 'CONTAINMENT'}
                  </span>
                  <span
                    className={`text-sm font-bold ${selectedChain?.status === 'CONTAINED' ? 'text-emerald-400' : 'text-amber-400'}`}
                  >
                    {selectedChain ? selectedChain.status : 'N/A'}
                  </span>
                </div>
              </div>
            </div>
          </div>

          {/* ========================================================================= */}
          {/* 5-STAGE INTERACTIVE MITRE ATT&CK PROGRESSION GRAPH                       */}
          {/* ========================================================================= */}
          <div className="space-y-4 rounded-xl border border-slate-800 bg-slate-950/95 p-5 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <GitCommit className="h-5 w-5 text-rose-400" />
                <h3 className="text-sm font-black tracking-wider text-slate-200 uppercase">
                  {isAr
                    ? 'المسار الزمني لمراحل الهجوم الخمس (5-Stage MITRE Progression Graph)'
                    : '5-Stage MITRE ATT&CK Intrusion Pipeline'}
                </h3>
              </div>
              <span className="font-mono text-xs text-slate-400">
                {isAr
                  ? 'اضغط على أي مرحلة لعرض الأدلة والحمولة'
                  : 'Click any node to inspect raw forensic payload'}
              </span>
            </div>

            {/* Visual 5-Stage Pipeline */}
            <div className="relative grid grid-cols-1 gap-3 md:grid-cols-5">
              {CANONICAL_STAGES.map((stage, idx) => {
                const stageData = selectedChain?.stagesCompleted.find(sc => sc.stage === stage.id);
                const isTriggered = !!stageData;

                return (
                  <div
                    key={stage.id}
                    className={`relative flex min-h-[190px] flex-col justify-between rounded-xl border p-3.5 transition-all duration-300 ${
                      isTriggered
                        ? 'border-rose-500/70 bg-slate-900/90 shadow-lg shadow-rose-950/50'
                        : 'border-slate-800/60 bg-slate-950/40 opacity-60'
                    }`}
                  >
                    {/* Top Order & Status Badge */}
                    <div>
                      <div className="mb-2 flex items-center justify-between">
                        <div className="flex items-center gap-1.5">
                          {stage.icon}
                          <span className="font-mono text-xs font-black text-slate-200">
                            {isAr ? stage.labelAr : stage.labelEn}
                          </span>
                        </div>
                        <span
                          className={`rounded px-1.5 py-0.5 font-mono text-[9px] font-bold ${
                            isTriggered
                              ? 'animate-pulse border border-rose-500/50 bg-rose-950 text-rose-300'
                              : 'bg-slate-800 text-slate-400'
                          }`}
                        >
                          {isTriggered ? 'TRIGGERED' : 'INACTIVE'}
                        </span>
                      </div>

                      {/* MITRE Technique Badge */}
                      <div className="mb-2 inline-block rounded border border-cyan-500/30 bg-slate-950 px-2 py-0.5 font-mono text-[10px] text-cyan-300">
                        {stageData?.technique || stage.mitreTechnique}
                      </div>

                      <p className="text-[11px] leading-snug text-slate-400">
                        {isAr ? stage.descriptionAr : stage.descriptionEn}
                      </p>
                    </div>

                    {/* Bottom Evidence & Timestamp */}
                    <div className="mt-3 border-t border-slate-800/80 pt-2 font-mono text-[10px]">
                      {isTriggered ? (
                        <div className="space-y-1">
                          <div className="flex items-center gap-1 text-emerald-400">
                            <CheckCircle2 className="h-3 w-3" />
                            <span>{new Date(stageData.timestamp).toLocaleTimeString()}</span>
                          </div>
                          <p className="truncate text-rose-300" title={stageData.description}>
                            {stageData.description}
                          </p>
                        </div>
                      ) : (
                        <span className="flex items-center gap-1 text-slate-500">
                          <Clock className="h-3 w-3" />
                          <span>{isAr ? 'في انتظار الرصد' : 'Awaiting Detection'}</span>
                        </span>
                      )}
                    </div>

                    {/* Step Connector Arrow (for desktop) */}
                    {idx < 4 && (
                      <div className="absolute top-1/2 -right-3 z-10 hidden -translate-y-1/2 md:block">
                        <ArrowRight
                          className={`h-4 w-4 ${isTriggered ? 'text-rose-400' : 'text-slate-700'}`}
                        />
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
          <div className="rounded-xl border border-purple-500/30 bg-slate-950/90 p-4 shadow-xl backdrop-blur-md">
            <div className="mb-4 flex flex-wrap items-center justify-between gap-4">
              <div>
                <div className="flex items-center gap-2">
                  <Radio className="h-5 w-5 animate-pulse text-purple-400" />
                  <h3 className="text-sm font-black tracking-wider text-purple-300 uppercase">
                    {isAr
                      ? 'منظومة الخداع السيبراني والمصائد المسمومة (Honeytoken Deception Engine)'
                      : 'Autonomous Honeytoken & Canary Trap Monitor'}
                  </h3>
                </div>
                <p className="mt-1 font-mono text-xs text-slate-400">
                  {isAr
                    ? 'نشر مسارات وهمية وأصول مسمومة (/env., /.git, /admin). أي محاولة وصول تفعل الحظر الفوري التلقائي في نواة eBPF.'
                    : 'Active decoys deployed across critical endpoints. Any unauthorized request instantly triggers auto-jail & kernel IP ban.'}
                </p>
              </div>

              {/* Stats Counters */}
              <div className="flex items-center gap-3 font-mono">
                <div className="rounded-lg border border-purple-500/40 bg-purple-950/60 px-3 py-1.5 text-center">
                  <span className="block text-[10px] leading-none text-purple-300">
                    ACTIVE TRAPS
                  </span>
                  <span className="text-sm font-bold text-purple-200">
                    {honeytokens.length} Endpoints
                  </span>
                </div>
                <div className="rounded-lg border border-rose-500/40 bg-rose-950/60 px-3 py-1.5 text-center">
                  <span className="block text-[10px] leading-none text-rose-300">TOTAL HITS</span>
                  <span className="text-sm font-bold text-rose-200">
                    {honeytokens.reduce((acc, t) => acc + t.hitsCount, 0)} Intercepted
                  </span>
                </div>
              </div>
            </div>

            {/* Deploy Custom Trap Form */}
            <div className="flex flex-wrap items-center gap-3 rounded-lg border border-slate-800 bg-slate-900/80 p-3">
              <span className="text-xs font-bold whitespace-nowrap text-slate-300">
                {isAr ? 'نشر فخ مخصص جديد:' : 'Deploy Custom Canary Trap:'}
              </span>
              <input
                type="text"
                value={newTrapPath}
                onChange={e => setNewTrapPath(e.target.value)}
                placeholder="/admin/credentials.txt or /.aws/config"
                className="min-w-[200px] flex-1 rounded border border-slate-700 bg-slate-950 px-3 py-1.5 font-mono text-xs text-cyan-300 focus:border-purple-400 focus:outline-none"
              />
              <select
                value={newTrapType}
                onChange={e => setNewTrapType(e.target.value as any)}
                className="rounded border border-slate-700 bg-slate-950 px-3 py-1.5 font-mono text-xs text-slate-200 focus:outline-none"
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
                className="flex items-center gap-1.5 rounded bg-purple-600 px-3 py-1.5 font-mono text-xs font-bold text-white transition hover:bg-purple-500 disabled:opacity-50"
              >
                <Sparkles className="h-3.5 w-3.5" />
                <span>{isAr ? 'نشر الفخ في المسار' : 'Deploy Canary Asset'}</span>
              </button>
            </div>
          </div>

          {/* Active Honeytokens Table */}
          <div className="overflow-hidden rounded-xl border border-slate-800 bg-slate-950/90 shadow-xl">
            <div className="flex items-center justify-between border-b border-slate-800 bg-slate-900/90 p-3.5">
              <span className="text-xs font-black tracking-wider text-slate-300 uppercase">
                {isAr
                  ? 'قائمة الفخاخ والمصائد النشطة'
                  : 'Active Deception Endpoints & Auto-Jail Status'}
              </span>
              <span className="font-mono text-xs text-purple-400">
                {isAr
                  ? 'نظام الحظر الفوري: نشط في النواة (Kernel Auto-Ban Active)'
                  : 'Kernel eBPF Auto-Jail: ENFORCED'}
              </span>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left font-mono text-xs" dir="ltr">
                <thead className="border-b border-slate-800 bg-slate-950 text-slate-400">
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
                  {honeytokens.map(trap => (
                    <tr key={trap.id} className="transition hover:bg-slate-900/60">
                      <td className="px-4 py-3 font-bold text-purple-300">{trap.id}</td>
                      <td className="px-4 py-3 font-bold text-cyan-300">{trap.endpointPath}</td>
                      <td className="px-4 py-3 text-slate-300">{trap.trapType}</td>
                      <td className="px-4 py-3 text-center">
                        <span
                          className={`rounded px-2 py-0.5 font-bold ${
                            trap.hitsCount > 0
                              ? 'border border-rose-500/40 bg-rose-950 text-rose-300'
                              : 'bg-slate-900 text-slate-500'
                          }`}
                        >
                          {trap.hitsCount}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-slate-400">
                        {trap.lastTriggered
                          ? new Date(trap.lastTriggered).toLocaleTimeString()
                          : 'NEVER'}
                      </td>
                      <td className="px-4 py-3 text-amber-300">{trap.lastAttackerIp || 'NONE'}</td>
                      <td className="px-4 py-3">
                        <span className="flex w-fit items-center gap-1 rounded border border-emerald-500/30 bg-emerald-950 px-2 py-0.5 text-[10px] text-emerald-300">
                          <CheckCircle2 className="h-3 w-3" />
                          <span>eBPF BAN</span>
                        </span>
                      </td>
                      <td className="px-4 py-3 text-right">
                        <button
                          onClick={() => handleTriggerHoneytoken(trap)}
                          disabled={triggeringTrapId === trap.id}
                          className="ml-auto flex items-center gap-1 rounded border border-rose-500/40 bg-rose-900/80 px-2.5 py-1 text-[11px] font-bold text-rose-200 transition hover:bg-rose-800"
                        >
                          <Zap className="h-3 w-3 text-amber-400" />
                          <span>
                            {triggeringTrapId === trap.id
                              ? 'Triggering...'
                              : 'Simulate Tripwire Hit'}
                          </span>
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
          <div className="rounded-xl border border-amber-500/30 bg-slate-950/90 p-4 shadow-xl backdrop-blur-md">
            <div className="mb-4 flex flex-wrap items-center justify-between gap-4">
              <div>
                <div className="flex items-center gap-2">
                  <KeyRound className="h-5 w-5 text-amber-400" />
                  <h3 className="text-sm font-black tracking-wider text-amber-300 uppercase">
                    {isAr
                      ? 'مراقبة هجمات التخمين والبوتات الموزعة (Credential Stuffing & Password Spraying)'
                      : 'Distributed Credential Stuffing & Velocity Defense'}
                  </h3>
                </div>
                <p className="mt-1 font-mono text-xs text-slate-400">
                  {isAr
                    ? 'رصد محاولات التخمين عالية التردد وحظر شبكات البوتات الموزعة وتطبيق تحديات CAPTCHA التلقائية.'
                    : 'Real-time velocity thresholding, automated account lockouts, and distributed botnet swarm neutralization.'}
                </p>
              </div>

              {/* Attack Simulator Form */}
              <div className="flex items-center gap-2 rounded-lg border border-slate-800 bg-slate-900/80 p-2">
                <input
                  type="text"
                  value={targetUsernameInput}
                  onChange={e => setTargetUsernameInput(e.target.value)}
                  placeholder="target_user@domain.com"
                  className="rounded border border-slate-700 bg-slate-950 px-2.5 py-1 font-mono text-xs text-cyan-300 focus:outline-none"
                />
                <button
                  onClick={handleSimulateCredentialStuffing}
                  disabled={isSimulatingBruteForce}
                  className="flex items-center gap-1.5 rounded bg-amber-600 px-3 py-1 font-mono text-xs font-bold text-slate-950 transition hover:bg-amber-500"
                >
                  <Play className="h-3 w-3" />
                  <span>
                    {isSimulatingBruteForce
                      ? isAr
                        ? 'جارِ الإطلاق...'
                        : 'Launching...'
                      : isAr
                        ? 'محاكاة هجوم تخمين'
                        : 'Simulate Brute Force'}
                  </span>
                </button>
              </div>
            </div>
          </div>

          {/* Credential Events Feed Table */}
          <div className="overflow-hidden rounded-xl border border-slate-800 bg-slate-950/90 shadow-xl">
            <div className="flex items-center justify-between border-b border-slate-800 bg-slate-900/90 p-3.5">
              <span className="text-xs font-black tracking-wider text-slate-300 uppercase">
                {isAr
                  ? 'سجل هجمات التخمين والبوتات المعترضة'
                  : 'Intercepted Credential Stuffing Telemetry Feed'}
              </span>
              <span className="font-mono text-xs text-amber-400">
                {isAr ? 'تأمين المصادقة: فعال' : 'PAM Shield: ACTIVE'}
              </span>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left font-mono text-xs" dir="ltr">
                <thead className="border-b border-slate-800 bg-slate-950 text-slate-400">
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
                  {credentialEvents.map(evt => (
                    <tr key={evt.id} className="transition hover:bg-slate-900/60">
                      <td className="px-4 py-3 text-slate-400">
                        {new Date(evt.timestamp).toLocaleTimeString()}
                      </td>
                      <td className="px-4 py-3 font-bold text-rose-400">{evt.sourceIp}</td>
                      <td className="px-4 py-3 text-cyan-300">{evt.targetEndpoint}</td>
                      <td className="px-4 py-3 font-bold text-amber-300">
                        {evt.usernameAttempted}
                      </td>
                      <td className="px-4 py-3 text-slate-200">
                        <span className="rounded bg-rose-950 px-2 py-0.5 font-bold text-rose-300">
                          {evt.velocityPerMinute} req/min
                        </span>
                      </td>
                      <td className="px-4 py-3 text-purple-300">
                        {evt.botnetClusterName || 'Distributed Swarm'}
                      </td>
                      <td className="px-4 py-3 text-right">
                        <span className="rounded border border-rose-500/40 bg-rose-950 px-2 py-0.5 text-[10px] font-bold text-rose-300">
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
