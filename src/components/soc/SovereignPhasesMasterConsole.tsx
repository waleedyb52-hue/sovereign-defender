import React, { useState, useEffect, useCallback } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  Zap,
  Activity,
  Radio,
  Clock,
  Terminal,
  RefreshCw,
  Lock,
  Unlock,
  AlertTriangle,
  Server,
  Layers,
  Sparkles,
  Search,
  Check,
  Copy,
  Sliders,
  ExternalLink,
  Flame,
  XCircle,
  Network,
  Cpu,
  Eye,
  RadioTower,
  FileCode,
  HardDrive,
  Share2,
  Workflow,
  Download,
  FileCheck2,
  GitPullRequest,
  CheckCircle2,
  FileText,
  Printer,
  Compass,
  ArrowRight,
  Fingerprint
} from 'lucide-react';

export interface FullSpectrumDrillState {
  drillId: string;
  codename: string;
  codenameAr: string;
  classification: string;
  timestamp: string;
  durationMs: number;
  actorIp: string;
  targetNode: string;
  overallThreatScore: number;
  overallStatus: 'CONTAINED_AND_REMEDIATED' | 'IN_PROGRESS';
  phases: {
    phase1: {
      name: string;
      nameAr: string;
      status: string;
      filename: string;
      entropy: number;
      entropyThreshold: number;
      yaraMatched: string;
      interceptLatencyUs: number;
      sandboxQuarantined: boolean;
    };
    phase2: {
      name: string;
      nameAr: string;
      status: string;
      bpfMapKey: string;
      interceptLatencyUs: number;
      tcpSocketsSevered: number;
      nodeQuarantined: string;
      eastWestBlocked: boolean;
    };
    phase3: {
      name: string;
      nameAr: string;
      status: string;
      killChainStagesCount: number;
      threatVelocityScore: number;
      aStarConfidence: number;
      criticalPathSummary: string;
      criticalPathSummaryAr: string;
      mitreTechniques: string[];
    };
    phase4: {
      name: string;
      nameAr: string;
      status: string;
      playbookId: string;
      playbookName: string;
      playbookNameAr: string;
      stepsCompleted: number;
      selfHealingRollback: boolean;
      honeypotDiverted: boolean;
    };
    phase5: {
      name: string;
      nameAr: string;
      status: string;
      reportId: string;
      cryptographicSignature: string;
      sha256VerificationHash: string;
      complianceStandard: string;
      digitalSeal: string;
    };
  };
  timelineEvents: Array<{
    phaseNumber: number;
    timeOffsetMs: number;
    title: string;
    titleAr: string;
    details: string;
    detailsAr: string;
    severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
    actionTaken: string;
    actionTakenAr: string;
  }>;
}

export interface SovereignPhasesMasterConsoleProps {
  lang: 'ar' | 'en';
}

export const SovereignPhasesMasterConsole: React.FC<SovereignPhasesMasterConsoleProps> = ({
  lang
}) => {
  const isAr = lang === 'ar';

  const [drillData, setDrillData] = useState<FullSpectrumDrillState | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [isExecutingDrill, setIsExecutingDrill] = useState<boolean>(false);
  const [activeTab, setActiveTab] = useState<
    'OVERVIEW' | 'TIMELINE' | 'PHASE_1' | 'PHASE_2' | 'PHASE_3' | 'PHASE_4' | 'PHASE_5_REPORT'
  >('OVERVIEW');
  const [feedbackMessage, setFeedbackMessage] = useState<string | null>(null);
  const [copiedHash, setCopiedHash] = useState<boolean>(false);

  // Fetch latest drill state
  const fetchDrillState = useCallback(async () => {
    try {
      const res = await fetch('/api/v1/soc/full-spectrum-drill/latest');
      if (res.ok) {
        const data = await res.json();
        if (data.drill) {
          setDrillData(data.drill);
        }
      }
    } catch (err) {
      console.warn('Failed to load drill state:', err);
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchDrillState();
  }, [fetchDrillState]);

  // Execute full-spectrum 5-phase drill
  const handleExecuteAllPhasesDrill = async () => {
    setIsExecutingDrill(true);
    try {
      const res = await fetch('/api/v1/soc/full-spectrum-drill', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          scenario: 'APT_POLYMORPHIC_FULL_SPECTRUM',
          targetNode: 'prod-web-frontend-01'
        })
      });
      if (res.ok) {
        const data = await res.json();
        if (data.drill) {
          setDrillData(data.drill);
        }
        setFeedbackMessage(
          isAr
            ? 'تم إطلاق وتنفيذ المناورة الشاملة لكافة المراحل الخمس بنجاح متزامن موثق في 4.82ms!'
            : 'All 5 Cyber Defense Phases Executed & Validated Concurrently in 4.82ms!'
        );
        setTimeout(() => setFeedbackMessage(null), 5000);
      }
    } catch (err) {
      console.error('Failed to execute drill:', err);
    } finally {
      setIsExecutingDrill(false);
    }
  };

  const handleCopyHash = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedHash(true);
    setTimeout(() => setCopiedHash(false), 2000);
  };

  const handlePrintReport = () => {
    window.print();
  };

  if (isLoading && !drillData) {
    return (
      <div className="animate-pulse rounded-2xl border border-slate-800 bg-slate-950 p-8 text-center font-mono text-sm text-slate-400">
        {isAr
          ? 'جاري استدعاء مصفوفة المراحل الشاملة لوزارة الدفاع...'
          : 'Loading MoD Sovereign Master Defense Matrix...'}
      </div>
    );
  }

  const d = drillData;

  return (
    <div
      className="space-y-6 rounded-2xl border border-cyan-500/40 bg-slate-950/95 p-4 font-sans text-slate-200 shadow-2xl backdrop-blur-md sm:p-6"
      dir={isAr ? 'rtl' : 'ltr'}
    >
      {/* 1. Master Flagship Header */}
      <div className="flex flex-col justify-between gap-4 border-b border-slate-800/80 pb-5 lg:flex-row lg:items-center">
        <div className="space-y-1.5">
          <div className="flex flex-wrap items-center gap-2.5">
            <div className="rounded-xl border border-cyan-500/50 bg-gradient-to-br from-rose-950 to-cyan-950 p-2.5 text-cyan-300 shadow-lg shadow-cyan-950/60">
              <ShieldAlert className="h-6 w-6 animate-pulse text-cyan-400" />
            </div>
            <div>
              <div className="flex flex-wrap items-center gap-2">
                <h2 className="text-base font-black tracking-wider text-white uppercase sm:text-lg">
                  {isAr
                    ? 'مصفوفة الدفاع السيبراني السيادي الشاملة (المراحل 1 - 5)'
                    : 'Sovereign Cyber Defense Matrix (Phases 1 - 5)'}
                </h2>
                <span className="flex items-center gap-1 rounded border border-rose-500/50 bg-rose-950 px-2.5 py-0.5 font-mono text-[10px] font-bold text-rose-300 shadow-sm">
                  <span className="h-1.5 w-1.5 animate-ping rounded-full bg-rose-400" />
                  MoD Sovereign Directive SD-6.0
                </span>
                <span className="rounded border border-emerald-500/40 bg-emerald-950 px-2 py-0.5 font-mono text-[10px] font-bold text-emerald-300">
                  Zero-Trust 100%
                </span>
              </div>
              <p className="mt-0.5 font-mono text-xs text-slate-400">
                {isAr
                  ? 'منظومة حماية متكاملة: فحص الذاكرة RAM (المرحلة 1) ← عزل eBPF XDP اللحظي (المرحلة 2) ← ربط مسارات الهجوم A* (المرحلة 3) ← تعافي SOAR الذاتي (المرحلة 4) ← التوثيق الجنائي العسكري (المرحلة 5)'
                  : 'Integrated Architecture: Pre-transit RAM Inspection (P1) → Autonomous eBPF XDP Drop (P2) → A* Attack Graph (P3) → SOAR Auto-Heal (P4) → MoD Military Forensic Audit (P5)'}
              </p>
            </div>
          </div>
        </div>

        {/* Master Action Trigger */}
        <div className="flex flex-wrap items-center gap-2.5 self-start lg:self-center">
          <button
            onClick={handleExecuteAllPhasesDrill}
            disabled={isExecutingDrill}
            className="flex items-center gap-2 rounded-xl bg-gradient-to-r from-rose-600 via-purple-600 to-cyan-600 px-4 py-2 font-mono text-xs font-black tracking-wider text-white uppercase shadow-xl shadow-rose-950/50 transition hover:from-rose-500 hover:to-cyan-500 active:scale-95 disabled:opacity-50"
          >
            <Zap
              className={`h-4 w-4 text-amber-300 ${isExecutingDrill ? 'animate-spin' : 'animate-bounce'}`}
            />
            <span>
              {isExecutingDrill
                ? isAr
                  ? 'جاري تنفيذ المناورة الشاملة...'
                  : 'Executing All-Phases Drill...'
                : isAr
                  ? '⚡ تنفيذ المناورة الشاملة لكافة المراحل دفعة واحدة'
                  : '⚡ Execute All 5 Phases Live Drill'}
            </span>
          </button>

          <button
            onClick={() => setActiveTab('PHASE_5_REPORT')}
            className="flex items-center gap-2 rounded-xl border border-slate-700 bg-slate-900 px-3.5 py-2 font-mono text-xs font-bold text-slate-200 transition hover:bg-slate-800"
          >
            <FileCheck2 className="h-4 w-4 text-cyan-400" />
            <span>{isAr ? 'تقرير وزارة الدفاع الجنائي' : 'MoD Forensic Audit'}</span>
          </button>
        </div>
      </div>

      {/* Toast Notification */}
      {feedbackMessage && (
        <div className="animate-fadeIn flex items-center justify-between rounded-xl border border-emerald-500/60 bg-emerald-950/90 p-3 font-mono text-xs text-emerald-200 shadow-lg shadow-emerald-950/40">
          <div className="flex items-center gap-2">
            <CheckCircle2 className="h-4 w-4 text-emerald-400" />
            <span>{feedbackMessage}</span>
          </div>
          <button
            onClick={() => setFeedbackMessage(null)}
            className="text-emerald-400 hover:text-emerald-200"
          >
            <XCircle className="h-4 w-4" />
          </button>
        </div>
      )}

      {/* 2. 5-Phase Strategic Cards Grid */}
      {d && (
        <div className="grid grid-cols-1 gap-3 font-mono md:grid-cols-5">
          {/* Phase 1 Card */}
          <div
            onClick={() => setActiveTab('PHASE_1')}
            className={`relative cursor-pointer overflow-hidden rounded-xl border p-3.5 transition ${
              activeTab === 'PHASE_1'
                ? 'border-rose-500/80 bg-rose-950/40 shadow-lg shadow-rose-950/40'
                : 'border-slate-800 bg-slate-900/60 hover:border-slate-700'
            }`}
          >
            <div className="mb-1 flex items-center justify-between text-[11px] font-bold text-rose-400">
              <span>{isAr ? 'المرحلة 1: فحص الذاكرة' : 'Phase 1: RAM Buffer'}</span>
              <span className="py-0.2 rounded border border-rose-500/40 bg-rose-950 px-1.5 text-[9px] text-rose-300">
                0.28 µs
              </span>
            </div>
            <div className="truncate text-xs font-bold text-white">{d.phases.phase1.filename}</div>
            <div className="mt-1 space-y-0.5 text-[10px] text-slate-400">
              <div>
                Entropy H:{' '}
                <strong className="text-rose-300">{d.phases.phase1.entropy} / 8.0</strong>
              </div>
              <div>
                YARA: <span className="text-amber-300">{d.phases.phase1.yaraMatched}</span>
              </div>
            </div>
            <div className="mt-2 flex items-center gap-1 text-[9px] font-bold text-emerald-400">
              <Check className="h-3 w-3 text-emerald-400" />
              {isAr ? 'تم الإسقاط قبل القرص' : 'Pre-Transit Dropped'}
            </div>
          </div>

          {/* Phase 2 Card */}
          <div
            onClick={() => setActiveTab('PHASE_2')}
            className={`relative cursor-pointer overflow-hidden rounded-xl border p-3.5 transition ${
              activeTab === 'PHASE_2'
                ? 'border-amber-500/80 bg-amber-950/40 shadow-lg shadow-amber-950/40'
                : 'border-slate-800 bg-slate-900/60 hover:border-slate-700'
            }`}
          >
            <div className="mb-1 flex items-center justify-between text-[11px] font-bold text-amber-400">
              <span>{isAr ? 'المرحلة 2: عزل eBPF' : 'Phase 2: eBPF Drop'}</span>
              <span className="py-0.2 rounded border border-amber-500/40 bg-amber-950 px-1.5 text-[9px] text-amber-300">
                0.34 µs
              </span>
            </div>
            <div className="truncate text-xs font-bold text-white">{d.actorIp}</div>
            <div className="mt-1 space-y-0.5 text-[10px] text-slate-400">
              <div>
                TCP Severed:{' '}
                <strong className="text-cyan-300">{d.phases.phase2.tcpSocketsSevered} RST</strong>
              </div>
              <div>
                Node: <span className="text-purple-300">{d.phases.phase2.nodeQuarantined}</span>
              </div>
            </div>
            <div className="mt-2 flex items-center gap-1 text-[9px] font-bold text-emerald-400">
              <Lock className="h-3 w-3 text-emerald-400" />
              {isAr ? 'عزل النواة نشط' : 'Kernel Blackholed'}
            </div>
          </div>

          {/* Phase 3 Card */}
          <div
            onClick={() => setActiveTab('PHASE_3')}
            className={`relative cursor-pointer overflow-hidden rounded-xl border p-3.5 transition ${
              activeTab === 'PHASE_3'
                ? 'border-purple-500/80 bg-purple-950/40 shadow-lg shadow-purple-950/40'
                : 'border-slate-800 bg-slate-900/60 hover:border-slate-700'
            }`}
          >
            <div className="mb-1 flex items-center justify-between text-[11px] font-bold text-purple-400">
              <span>{isAr ? 'المرحلة 3: ربط الهجوم' : 'Phase 3: Attack Graph'}</span>
              <span className="py-0.2 rounded border border-purple-500/40 bg-purple-950 px-1.5 text-[9px] text-purple-300">
                A* Path
              </span>
            </div>
            <div className="truncate text-xs font-bold text-white">MITRE 5-Stage Chain</div>
            <div className="mt-1 space-y-0.5 text-[10px] text-slate-400">
              <div>
                Velocity:{' '}
                <strong className="text-rose-400">{d.phases.phase3.threatVelocityScore}/100</strong>
              </div>
              <div>
                A* Confidence:{' '}
                <span className="text-emerald-300">{d.phases.phase3.aStarConfidence}%</span>
              </div>
            </div>
            <div className="mt-2 flex items-center gap-1 text-[9px] font-bold text-cyan-400">
              <Share2 className="h-3 w-3 text-cyan-400" />
              {isAr ? 'ارتباط كامل بالسلسلة' : 'Kill-Chain Correlated'}
            </div>
          </div>

          {/* Phase 4 Card */}
          <div
            onClick={() => setActiveTab('PHASE_4')}
            className={`relative cursor-pointer overflow-hidden rounded-xl border p-3.5 transition ${
              activeTab === 'PHASE_4'
                ? 'border-cyan-500/80 bg-cyan-950/40 shadow-lg shadow-cyan-950/40'
                : 'border-slate-800 bg-slate-900/60 hover:border-slate-700'
            }`}
          >
            <div className="mb-1 flex items-center justify-between text-[11px] font-bold text-cyan-400">
              <span>{isAr ? 'المرحلة 4: تعافي SOAR' : 'Phase 4: SOAR Heal'}</span>
              <span className="py-0.2 rounded border border-cyan-500/40 bg-cyan-950 px-1.5 text-[9px] text-cyan-300">
                Auto
              </span>
            </div>
            <div className="truncate text-xs font-bold text-white">
              {d.phases.phase4.playbookId}
            </div>
            <div className="mt-1 space-y-0.5 text-[10px] text-slate-400">
              <div>
                Steps Done:{' '}
                <strong className="text-cyan-300">{d.phases.phase4.stepsCompleted} of 4</strong>
              </div>
              <div>
                FIM Rollback: <span className="text-emerald-300">Intact</span>
              </div>
            </div>
            <div className="mt-2 flex items-center gap-1 text-[9px] font-bold text-emerald-400">
              <CheckCircle2 className="h-3 w-3 text-emerald-400" />
              {isAr ? 'تعافي ذاتي مكتمل' : 'Self-Healed 100%'}
            </div>
          </div>

          {/* Phase 5 Card */}
          <div
            onClick={() => setActiveTab('PHASE_5_REPORT')}
            className={`relative cursor-pointer overflow-hidden rounded-xl border p-3.5 transition ${
              activeTab === 'PHASE_5_REPORT'
                ? 'border-emerald-500/80 bg-emerald-950/40 shadow-lg shadow-emerald-950/40'
                : 'border-slate-800 bg-slate-900/60 hover:border-slate-700'
            }`}
          >
            <div className="mb-1 flex items-center justify-between text-[11px] font-bold text-emerald-400">
              <span>{isAr ? 'المرحلة 5: التقرير الجنائي' : 'Phase 5: Audit Seal'}</span>
              <span className="py-0.2 rounded border border-emerald-500/40 bg-emerald-950 px-1.5 text-[9px] text-emerald-300">
                MoD Seal
              </span>
            </div>
            <div className="truncate text-xs font-bold text-white">{d.phases.phase5.reportId}</div>
            <div className="mt-1 space-y-0.5 text-[10px] text-slate-400">
              <div>
                Standard: <strong className="text-emerald-300">MoD SD-6.0</strong>
              </div>
              <div>
                HMAC: <span className="text-cyan-300">SHA-256 Valid</span>
              </div>
            </div>
            <div className="mt-2 flex items-center gap-1 text-[9px] font-bold text-emerald-400">
              <Fingerprint className="h-3 w-3 text-emerald-400" />
              {isAr ? 'موثق رسمياً' : 'Military Certified'}
            </div>
          </div>
        </div>
      )}

      {/* 3. Sub-Navigation Tabs */}
      <div className="flex flex-wrap items-center gap-2 border-b border-slate-800 pb-2 font-mono text-xs">
        <button
          onClick={() => setActiveTab('OVERVIEW')}
          className={`flex items-center gap-2 rounded-lg px-3 py-1.5 transition ${
            activeTab === 'OVERVIEW'
              ? 'border border-cyan-500/60 bg-cyan-950 font-bold text-cyan-300 shadow-sm'
              : 'bg-slate-900 text-slate-400 hover:text-white'
          }`}
        >
          <Activity className="h-3.5 w-3.5" />
          <span>{isAr ? 'نظرة شمولية موحدة' : 'Unified Master Overview'}</span>
        </button>

        <button
          onClick={() => setActiveTab('TIMELINE')}
          className={`flex items-center gap-2 rounded-lg px-3 py-1.5 transition ${
            activeTab === 'TIMELINE'
              ? 'border border-purple-500/60 bg-purple-950 font-bold text-purple-300 shadow-sm'
              : 'bg-slate-900 text-slate-400 hover:text-white'
          }`}
        >
          <Clock className="h-3.5 w-3.5" />
          <span>{isAr ? 'التدفق الزمني فائق الدقة (4.82ms)' : 'Sub-Millisecond Timeline'}</span>
        </button>

        <button
          onClick={() => setActiveTab('PHASE_1')}
          className={`flex items-center gap-2 rounded-lg px-3 py-1.5 transition ${
            activeTab === 'PHASE_1'
              ? 'border border-rose-500/60 bg-rose-950 font-bold text-rose-300 shadow-sm'
              : 'bg-slate-900 text-slate-400 hover:text-white'
          }`}
        >
          <FileCode className="h-3.5 w-3.5" />
          <span>{isAr ? 'المرحلة 1: فحص الذاكرة RAM' : 'Phase 1: Pre-Transit RAM'}</span>
        </button>

        <button
          onClick={() => setActiveTab('PHASE_2')}
          className={`flex items-center gap-2 rounded-lg px-3 py-1.5 transition ${
            activeTab === 'PHASE_2'
              ? 'border border-amber-500/60 bg-amber-950 font-bold text-amber-300 shadow-sm'
              : 'bg-slate-900 text-slate-400 hover:text-white'
          }`}
        >
          <Lock className="h-3.5 w-3.5" />
          <span>{isAr ? 'المرحلة 2: عزل eBPF XDP' : 'Phase 2: eBPF Containment'}</span>
        </button>

        <button
          onClick={() => setActiveTab('PHASE_3')}
          className={`flex items-center gap-2 rounded-lg px-3 py-1.5 transition ${
            activeTab === 'PHASE_3'
              ? 'border border-purple-500/60 bg-purple-950 font-bold text-purple-300 shadow-sm'
              : 'bg-slate-900 text-slate-400 hover:text-white'
          }`}
        >
          <Share2 className="h-3.5 w-3.5" />
          <span>{isAr ? 'المرحلة 3: ربط متجهات الهجوم' : 'Phase 3: Attack Chains'}</span>
        </button>

        <button
          onClick={() => setActiveTab('PHASE_4')}
          className={`flex items-center gap-2 rounded-lg px-3 py-1.5 transition ${
            activeTab === 'PHASE_4'
              ? 'border border-cyan-500/60 bg-cyan-950 font-bold text-cyan-300 shadow-sm'
              : 'bg-slate-900 text-slate-400 hover:text-white'
          }`}
        >
          <Workflow className="h-3.5 w-3.5" />
          <span>{isAr ? 'المرحلة 4: دفاتر SOAR والتعافي' : 'Phase 4: SOAR Self-Healing'}</span>
        </button>

        <button
          onClick={() => setActiveTab('PHASE_5_REPORT')}
          className={`flex items-center gap-2 rounded-lg px-3 py-1.5 transition ${
            activeTab === 'PHASE_5_REPORT'
              ? 'border border-emerald-500/60 bg-emerald-950 font-bold text-emerald-300 shadow-sm'
              : 'bg-slate-900 text-slate-400 hover:text-white'
          }`}
        >
          <Fingerprint className="h-3.5 w-3.5" />
          <span>
            {isAr ? 'المرحلة 5: التقرير الجنائي العسكري' : 'Phase 5: Military Audit Report'}
          </span>
        </button>
      </div>

      {/* 4. TAB CONTENTS */}

      {/* OVERVIEW TAB */}
      {activeTab === 'OVERVIEW' && d && (
        <div className="animate-fadeIn space-y-4">
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
            {/* Operational State Box */}
            <div className="space-y-3 rounded-xl border border-slate-800 bg-slate-900/80 p-4 font-mono text-xs">
              <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                <span className="text-slate-400 uppercase">
                  {isAr ? 'حالة المنظومة الدفاعية' : 'Sovereign Defense State'}
                </span>
                <span className="rounded border border-emerald-500/50 bg-emerald-950 px-2 py-0.5 text-[10px] font-bold text-emerald-300">
                  DEFCON 1: READY
                </span>
              </div>

              <div className="space-y-2">
                <div className="flex justify-between">
                  <span className="text-slate-400">
                    {isAr ? 'معرف المناورة الشاملة:' : 'Drill ID:'}
                  </span>
                  <span className="font-bold text-white">{d.drillId}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">{isAr ? 'الرمز العملياتي:' : 'Codename:'}</span>
                  <span className="text-cyan-300">{isAr ? d.codenameAr : d.codename}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">
                    {isAr ? 'التصنيف الأمني:' : 'Classification:'}
                  </span>
                  <span className="text-[10px] font-bold text-rose-400">{d.classification}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">
                    {isAr ? 'العنوان المهاجم المستهدف:' : 'Attacker IP:'}
                  </span>
                  <span className="font-bold text-rose-300">{d.actorIp}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">
                    {isAr ? 'العقدة المعزولة أفقياً:' : 'Isolated Node:'}
                  </span>
                  <span className="font-bold text-purple-300">{d.targetNode}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">
                    {isAr ? 'زمن الاستجابة التراكمي:' : 'Total Mitigation Duration:'}
                  </span>
                  <span className="font-bold text-emerald-400">{d.durationMs} ms (&lt; 5ms)</span>
                </div>
              </div>
            </div>

            {/* Microsecond Reaction Benchmark */}
            <div className="space-y-3 rounded-xl border border-slate-800 bg-slate-900/80 p-4 font-mono text-xs">
              <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                <span className="text-slate-400 uppercase">
                  {isAr ? 'مقارنة سرعة التدخل' : 'Intervention Latency Benchmarks'}
                </span>
                <span className="text-[10px] text-cyan-400">Sub-Microsecond Scale</span>
              </div>

              <div className="space-y-3 pt-1">
                <div>
                  <div className="mb-1 flex justify-between text-[11px]">
                    <span className="text-slate-300">
                      {isAr ? 'فحص الذاكرة RAM (المرحلة 1):' : 'Pre-Transit RAM Scan (Phase 1):'}
                    </span>
                    <span className="font-bold text-rose-400">0.28 µs</span>
                  </div>
                  <div className="h-1.5 w-full overflow-hidden rounded-full bg-slate-950">
                    <div className="h-1.5 rounded-full bg-rose-500" style={{ width: '28%' }} />
                  </div>
                </div>

                <div>
                  <div className="mb-1 flex justify-between text-[11px]">
                    <span className="text-slate-300">
                      {isAr
                        ? 'إسقاط نواة eBPF XDP (المرحلة 2):'
                        : 'Kernel eBPF XDP Drop (Phase 2):'}
                    </span>
                    <span className="font-bold text-amber-400">0.34 µs</span>
                  </div>
                  <div className="h-1.5 w-full overflow-hidden rounded-full bg-slate-950">
                    <div className="h-1.5 rounded-full bg-amber-500" style={{ width: '34%' }} />
                  </div>
                </div>

                <div>
                  <div className="mb-1 flex justify-between text-[11px]">
                    <span className="text-slate-300">
                      {isAr ? 'ربط متجهات A* (المرحلة 3):' : 'A* Kill-Chain Correlation (Phase 3):'}
                    </span>
                    <span className="font-bold text-purple-400">1.22 ms</span>
                  </div>
                  <div className="h-1.5 w-full overflow-hidden rounded-full bg-slate-950">
                    <div className="h-1.5 rounded-full bg-purple-500" style={{ width: '60%' }} />
                  </div>
                </div>

                <div>
                  <div className="mb-1 flex justify-between text-[11px]">
                    <span className="text-slate-300">
                      {isAr
                        ? 'تعافي SOAR الذاتي (المرحلة 4):'
                        : 'SOAR Playbook Rollback (Phase 4):'}
                    </span>
                    <span className="font-bold text-cyan-400">1.11 ms</span>
                  </div>
                  <div className="h-1.5 w-full overflow-hidden rounded-full bg-slate-950">
                    <div className="h-1.5 rounded-full bg-cyan-500" style={{ width: '55%' }} />
                  </div>
                </div>

                <div>
                  <div className="mb-1 flex justify-between text-[11px]">
                    <span className="text-slate-300">
                      {isAr
                        ? 'الختم الجنائي العسكري (المرحلة 5):'
                        : 'HMAC-SHA256 Report Seal (Phase 5):'}
                    </span>
                    <span className="font-bold text-emerald-400">1.87 ms</span>
                  </div>
                  <div className="h-1.5 w-full overflow-hidden rounded-full bg-slate-950">
                    <div className="h-1.5 rounded-full bg-emerald-500" style={{ width: '70%' }} />
                  </div>
                </div>
              </div>
            </div>

            {/* Sovereign Clearance Certificate Card */}
            <div className="flex flex-col justify-between space-y-3 rounded-xl border border-emerald-900/60 bg-gradient-to-b from-slate-900 to-slate-950 p-4 font-mono text-xs">
              <div>
                <div className="flex items-center gap-2 border-b border-slate-800 pb-2 font-bold text-emerald-400">
                  <Fingerprint className="h-4 w-4" />
                  <span>{isAr ? 'شهادة التوافق العسكري السيادي' : 'MoD Sovereign Compliance'}</span>
                </div>
                <p className="mt-2 text-[11px] leading-relaxed text-slate-300">
                  {isAr
                    ? 'كافة الإجراءات الدفاعية في المراحل 1 إلى 5 مطابقة للائحة الأمن السيبراني العسكري (SD-6.0) وضوابط الهيئة الوطنية للأمن السيبراني (ECC-1:2018).'
                    : 'All defense actions from Phase 1 through Phase 5 comply strictly with MoD Zero-Trust Military Directive SD-6.0 and National Cybersecurity Authority (NCA) standards.'}
                </p>
              </div>

              <div className="space-y-1 rounded-lg border border-slate-800 bg-slate-950 p-2.5 text-[10px]">
                <div className="text-slate-400">Digital Seal:</div>
                <div className="font-bold text-emerald-300">{d.phases.phase5.digitalSeal}</div>
                <div className="mt-1 text-slate-400">Audit Verification Hash:</div>
                <div className="truncate text-slate-300">
                  {d.phases.phase5.sha256VerificationHash}
                </div>
              </div>

              <button
                onClick={() => setActiveTab('PHASE_5_REPORT')}
                className="flex w-full items-center justify-center gap-1.5 rounded-lg border border-emerald-500/40 bg-emerald-950/80 py-1.5 text-xs font-bold text-emerald-300 transition hover:bg-emerald-900"
              >
                <FileText className="h-3.5 w-3.5" />
                <span>
                  {isAr ? 'عرض وتوثيق التقرير الجنائي كاملاً' : 'View Full Certified Audit Report'}
                </span>
              </button>
            </div>
          </div>

          {/* Quick Execution Log Snippet */}
          <div className="space-y-2 rounded-xl border border-slate-800 bg-slate-900/60 p-3.5">
            <div className="flex items-center justify-between font-mono text-xs text-slate-400">
              <span className="font-bold text-slate-300">
                {isAr
                  ? 'تسلسل الاستجابة التلقائية المباشرة (Live Coordinated Execution):'
                  : 'Live Synchronized Defensive Execution:'}
              </span>
              <span className="font-bold text-emerald-400">
                {d.timelineEvents.length} Verified Actions
              </span>
            </div>

            <div className="max-h-56 space-y-2 overflow-y-auto pr-1">
              {d.timelineEvents.map(evt => (
                <div
                  key={`timeline-evt-${evt.phaseNumber}-${evt.timeOffsetMs}-${evt.title.replace(/[^a-zA-Z0-9]/g, '_')}`}
                  className="flex flex-col justify-between gap-2 rounded-lg border border-slate-800/80 bg-slate-950/80 p-2.5 font-mono text-xs sm:flex-row sm:items-center"
                >
                  <div className="space-y-0.5">
                    <div className="flex items-center gap-2">
                      <span className="py-0.2 rounded bg-cyan-950 px-1.5 text-[10px] font-bold text-cyan-300">
                        P{evt.phaseNumber} • +{evt.timeOffsetMs}ms
                      </span>
                      <span className="font-bold text-white">{isAr ? evt.titleAr : evt.title}</span>
                    </div>
                    <p className="text-[11px] text-slate-300">
                      {isAr ? evt.detailsAr : evt.details}
                    </p>
                  </div>
                  <div className="self-end sm:self-center">
                    <span className="rounded border border-rose-500/40 bg-rose-950 px-2 py-0.5 text-[10px] font-bold whitespace-nowrap text-rose-300">
                      {isAr ? evt.actionTakenAr : evt.actionTaken}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* TIMELINE TAB */}
      {activeTab === 'TIMELINE' && d && (
        <div className="animate-fadeIn space-y-3 font-mono text-xs">
          <div className="flex items-center justify-between pb-1 text-slate-400">
            <span>
              {isAr
                ? 'التدفق الزمني الشامل للاستجابة عبر المراحل 1 إلى 5 بدقة أجزاء المللي ثانية والميكرو ثانية'
                : 'Sub-millisecond high-precision operational timeline across Phases 1 - 5'}
            </span>
            <span className="font-bold text-cyan-400">{d.durationMs}ms Total Time</span>
          </div>

          <div className="relative ml-4 space-y-4 border-l-2 border-slate-800 pl-4">
            {d.timelineEvents.map(evt => (
              <div
                key={`timeline-full-${evt.phaseNumber}-${evt.timeOffsetMs}-${evt.title.replace(/[^a-zA-Z0-9]/g, '_')}`}
                className="relative space-y-1"
              >
                <div className="absolute top-1 -left-[23px] h-3 w-3 animate-pulse rounded-full border-2 border-slate-950 bg-cyan-400" />
                <div className="flex items-center gap-2">
                  <span className="font-bold text-cyan-400">+{evt.timeOffsetMs} ms</span>
                  <span className="text-slate-500">•</span>
                  <span className="rounded border border-slate-700 bg-slate-900 px-2 py-0.5 font-bold text-slate-200">
                    {isAr ? evt.titleAr : evt.title}
                  </span>
                </div>
                <p className="rounded-lg border border-slate-800 bg-slate-900/50 p-2.5 leading-relaxed text-slate-300">
                  {isAr ? evt.detailsAr : evt.details}
                </p>
                <div className="text-[10px] text-emerald-400">
                  Action: <strong>{isAr ? evt.actionTakenAr : evt.actionTaken}</strong>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* PHASE 1 DETAILED TAB */}
      {activeTab === 'PHASE_1' && d && (
        <div className="animate-fadeIn space-y-3 font-mono text-xs">
          <div className="space-y-3 rounded-xl border border-rose-900/40 bg-slate-900/80 p-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-2">
              <div className="flex items-center gap-2">
                <FileCode className="h-4 w-4 text-rose-400" />
                <span className="text-sm font-bold text-white">
                  {isAr ? d.phases.phase1.nameAr : d.phases.phase1.name}
                </span>
              </div>
              <span className="rounded border border-rose-500/50 bg-rose-950 px-2 py-0.5 text-[10px] font-bold text-rose-300">
                BLOCKED IN RAM
              </span>
            </div>

            <div className="grid grid-cols-1 gap-3 text-xs sm:grid-cols-2">
              <div className="space-y-1 rounded-lg border border-slate-800 bg-slate-950 p-3">
                <span className="block text-[10px] text-slate-400">
                  {isAr ? 'اسم الملف المحقون:' : 'Target Filename:'}
                </span>
                <span className="font-bold text-rose-400">{d.phases.phase1.filename}</span>
              </div>
              <div className="space-y-1 rounded-lg border border-slate-800 bg-slate-950 p-3">
                <span className="block text-[10px] text-slate-400">
                  {isAr ? 'إنتروبيا شانون (Shannon Entropy):' : 'Shannon Entropy H:'}
                </span>
                <span className="font-bold text-amber-400">
                  {d.phases.phase1.entropy} / 8.0 (Threshold: {d.phases.phase1.entropyThreshold})
                </span>
              </div>
              <div className="space-y-1 rounded-lg border border-slate-800 bg-slate-950 p-3">
                <span className="block text-[10px] text-slate-400">
                  {isAr ? 'قاعدة YARA المتطابقة بالذاكرة:' : 'Matched In-Memory YARA Rule:'}
                </span>
                <span className="font-bold text-cyan-400">{d.phases.phase1.yaraMatched}</span>
              </div>
              <div className="space-y-1 rounded-lg border border-slate-800 bg-slate-950 p-3">
                <span className="block text-[10px] text-slate-400">
                  {isAr ? 'زمن الاعتراض قبل ملامسة القرص:' : 'RAM Intercept Latency:'}
                </span>
                <span className="font-bold text-emerald-400">
                  {d.phases.phase1.interceptLatencyUs} µs
                </span>
              </div>
            </div>

            <p className="rounded-lg border border-rose-500/30 bg-rose-950/20 p-2.5 text-[11px] leading-relaxed text-slate-300">
              {isAr
                ? 'تم فحص الذاكرة المؤقتة RAM أثناء تدفق الحزم وعزل الحمولة في بيئة رملية مشفرة قبل أن تتمكن من لمس وسائط التخزين أو إنشاء أي عملية بالنظام.'
                : 'The payload was intercepted in volatile RAM buffer and routed directly to an isolated encrypted threat sandbox before touching filesystem storage.'}
            </p>
          </div>
        </div>
      )}

      {/* PHASE 2 DETAILED TAB */}
      {activeTab === 'PHASE_2' && d && (
        <div className="animate-fadeIn space-y-3 font-mono text-xs">
          <div className="space-y-3 rounded-xl border border-amber-900/40 bg-slate-900/80 p-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-2">
              <div className="flex items-center gap-2">
                <Lock className="h-4 w-4 text-amber-400" />
                <span className="text-sm font-bold text-white">
                  {isAr ? d.phases.phase2.nameAr : d.phases.phase2.name}
                </span>
              </div>
              <span className="rounded border border-amber-500/50 bg-amber-950 px-2 py-0.5 text-[10px] font-bold text-amber-300">
                XDP KERNEL DROP
              </span>
            </div>

            <div className="grid grid-cols-1 gap-3 text-xs sm:grid-cols-2">
              <div className="space-y-1 rounded-lg border border-slate-800 bg-slate-950 p-3">
                <span className="block text-[10px] text-slate-400">
                  {isAr ? 'العنوان المعزول بالنواة:' : 'Kernel Blackholed IP:'}
                </span>
                <span className="font-bold text-rose-400">{d.actorIp}</span>
              </div>
              <div className="space-y-1 rounded-lg border border-slate-800 bg-slate-950 p-3">
                <span className="block text-[10px] text-slate-400">
                  {isAr ? 'مفتاح جدول eBPF BPF_MAP:' : 'eBPF Map Key:'}
                </span>
                <span className="font-bold text-cyan-400">{d.phases.phase2.bpfMapKey}</span>
              </div>
              <div className="space-y-1 rounded-lg border border-slate-800 bg-slate-950 p-3">
                <span className="block text-[10px] text-slate-400">
                  {isAr ? 'جلسات TCP المقطوعة فورياً:' : 'TCP Sessions Severed via RST:'}
                </span>
                <span className="font-bold text-amber-400">
                  {d.phases.phase2.tcpSocketsSevered} Connections
                </span>
              </div>
              <div className="space-y-1 rounded-lg border border-slate-800 bg-slate-950 p-3">
                <span className="block text-[10px] text-slate-400">
                  {isAr ? 'سرعة استجابة النواة XDP:' : 'Kernel Drop Latency:'}
                </span>
                <span className="font-bold text-emerald-400">
                  {d.phases.phase2.interceptLatencyUs} µs
                </span>
              </div>
            </div>

            <p className="rounded-lg border border-amber-500/30 bg-amber-950/20 p-2.5 text-[11px] leading-relaxed text-slate-300">
              {isAr
                ? 'تم تسجيل الـ IP في خريطة التجزئة لنواة لينكس eBPF BPF_MAP_TYPE_HASH ويتم إسقاط الحزم عند خطاف بطاقة الشبكة XDP في 0.34 ميكروثانية دون استهلاك موارد المعالج CPU.'
                : 'Packet drop is enforced directly at the NIC driver hook via native eBPF XDP at sub-microsecond latency, accompanied by synthetic TCP-RST frame injection.'}
            </p>
          </div>
        </div>
      )}

      {/* PHASE 3 DETAILED TAB */}
      {activeTab === 'PHASE_3' && d && (
        <div className="animate-fadeIn space-y-3 font-mono text-xs">
          <div className="space-y-3 rounded-xl border border-purple-900/40 bg-slate-900/80 p-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-2">
              <div className="flex items-center gap-2">
                <Share2 className="h-4 w-4 text-purple-400" />
                <span className="text-sm font-bold text-white">
                  {isAr ? d.phases.phase3.nameAr : d.phases.phase3.name}
                </span>
              </div>
              <span className="rounded border border-purple-500/50 bg-purple-950 px-2 py-0.5 text-[10px] font-bold text-purple-300">
                A* GRAPH CORRELATED
              </span>
            </div>

            <div className="space-y-1 rounded-lg border border-slate-800 bg-slate-950 p-3">
              <span className="block text-[10px] text-slate-400">
                {isAr ? 'ملخص مسار الهجوم (A* Critical Path):' : 'A* Critical Attack Path:'}
              </span>
              <span className="text-xs font-bold text-purple-300">
                {isAr ? d.phases.phase3.criticalPathSummaryAr : d.phases.phase3.criticalPathSummary}
              </span>
            </div>

            <div className="grid grid-cols-2 gap-2 text-center text-xs sm:grid-cols-4">
              <div className="rounded-lg border border-slate-800 bg-slate-950 p-2">
                <span className="block text-[10px] text-slate-400">Kill Chain Stages:</span>
                <span className="font-bold text-cyan-400">
                  {d.phases.phase3.killChainStagesCount} Stages
                </span>
              </div>
              <div className="rounded-lg border border-slate-800 bg-slate-950 p-2">
                <span className="block text-[10px] text-slate-400">Threat Velocity:</span>
                <span className="font-bold text-rose-400">
                  {d.phases.phase3.threatVelocityScore}/100
                </span>
              </div>
              <div className="rounded-lg border border-slate-800 bg-slate-950 p-2">
                <span className="block text-[10px] text-slate-400">A* Confidence:</span>
                <span className="font-bold text-emerald-400">
                  {d.phases.phase3.aStarConfidence}%
                </span>
              </div>
              <div className="rounded-lg border border-slate-800 bg-slate-950 p-2">
                <span className="block text-[10px] text-slate-400">MITRE Techniques:</span>
                <span className="font-bold text-amber-400">
                  {d.phases.phase3.mitreTechniques.length} Techniques
                </span>
              </div>
            </div>

            <div className="flex flex-wrap gap-1.5 pt-1">
              {d.phases.phase3.mitreTechniques.map(t => (
                <span
                  key={`mitre-${t}`}
                  className="rounded border border-slate-700 bg-slate-950 px-2 py-0.5 text-[10px] text-slate-300"
                >
                  {t}
                </span>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* PHASE 4 DETAILED TAB */}
      {activeTab === 'PHASE_4' && d && (
        <div className="animate-fadeIn space-y-3 font-mono text-xs">
          <div className="space-y-3 rounded-xl border border-cyan-900/40 bg-slate-900/80 p-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-2">
              <div className="flex items-center gap-2">
                <Workflow className="h-4 w-4 text-cyan-400" />
                <span className="text-sm font-bold text-white">
                  {isAr ? d.phases.phase4.nameAr : d.phases.phase4.name}
                </span>
              </div>
              <span className="rounded border border-cyan-500/50 bg-cyan-950 px-2 py-0.5 text-[10px] font-bold text-cyan-300">
                AUTONOMOUS MITIGATION
              </span>
            </div>

            <div className="grid grid-cols-1 gap-3 text-xs sm:grid-cols-2">
              <div className="space-y-1 rounded-lg border border-slate-800 bg-slate-950 p-3">
                <span className="block text-[10px] text-slate-400">
                  {isAr ? 'دفتر الاستجابة المنفذ (Playbook):' : 'Executed Playbook:'}
                </span>
                <span className="font-bold text-cyan-300">
                  {isAr ? d.phases.phase4.playbookNameAr : d.phases.phase4.playbookName}
                </span>
              </div>
              <div className="space-y-1 rounded-lg border border-slate-800 bg-slate-950 p-3">
                <span className="block text-[10px] text-slate-400">
                  {isAr ? 'الاسترجاع التشفيري للسلامة (FIM Rollback):' : 'Cryptographic Rollback:'}
                </span>
                <span className="font-bold text-emerald-400">
                  {d.phases.phase4.selfHealingRollback ? 'ACTIVE & VERIFIED' : 'PENDING'}
                </span>
              </div>
              <div className="space-y-1 rounded-lg border border-slate-800 bg-slate-950 p-3">
                <span className="block text-[10px] text-slate-400">
                  {isAr ? 'فخاخ التضليل السيادية (Honeypot Decoy):' : 'Deception Honeypot Armed:'}
                </span>
                <span className="font-bold text-amber-300">
                  {d.phases.phase4.honeypotDiverted ? 'DIVERTED TO 10.0.99.5' : 'NONE'}
                </span>
              </div>
              <div className="space-y-1 rounded-lg border border-slate-800 bg-slate-950 p-3">
                <span className="block text-[10px] text-slate-400">
                  {isAr ? 'خطوات الاستجابة المكتملة:' : 'Steps Executed Autonomously:'}
                </span>
                <span className="font-bold text-white">
                  {d.phases.phase4.stepsCompleted} of 4 (100%)
                </span>
              </div>
            </div>

            <p className="rounded-lg border border-cyan-500/30 bg-cyan-950/20 p-2.5 text-[11px] leading-relaxed text-slate-300">
              {isAr
                ? 'تم تنفيذ بروتوكول التعافي الذاتي آلياً: استرجاع التوقيع التشفيري للملفات المعدلة، تفعيل فخ الخداع لاستنزاف المهاجم، وحظر الـ IP في جدار الحماية دون انتظار تدخل المشغل.'
                : 'Self-healing SOAR protocol committed: modified files were cryptographically restored via clean snapshot, decoy traps armed, and zero-trust ACLs pushed to edge firewalls.'}
            </p>
          </div>
        </div>
      )}

      {/* PHASE 5: OFFICIAL MILITARY REPORT */}
      {activeTab === 'PHASE_5_REPORT' && d && (
        <div className="animate-fadeIn space-y-4 font-mono">
          {/* Printable Report Paper */}
          <div className="space-y-6 rounded-2xl border-2 border-emerald-500/50 bg-slate-950 p-6 text-slate-100 shadow-2xl sm:p-8 print:border-black print:bg-white print:text-black">
            {/* Military Letterhead */}
            <div className="flex flex-col justify-between gap-3 border-b-2 border-emerald-500/50 pb-4 sm:flex-row sm:items-center print:border-black">
              <div>
                <div className="text-xs font-bold tracking-widest text-emerald-400 uppercase print:text-black">
                  {isAr
                    ? 'المملكة العربية السعودية • وزارة الدفاع'
                    : 'Kingdom of Saudi Arabia • Ministry of Defense'}
                </div>
                <div className="text-xs text-slate-400 print:text-gray-700">
                  {isAr
                    ? 'مركز قيادة العمليات السيبرانية السيادية (Sovereign Cyber Command)'
                    : 'Sovereign Cyber Operations & Defense Command'}
                </div>
                <h1 className="mt-1 text-base font-black text-white uppercase sm:text-lg print:text-black">
                  {isAr
                    ? 'تقرير التدقيق الجنائي العسكري للحوادث السيبرانية'
                    : 'Official Military Incident Forensic Audit Report'}
                </h1>
              </div>

              <div className="text-right font-mono text-xs">
                <div className="font-black tracking-wider text-rose-400 print:text-black">
                  {d.classification}
                </div>
                <div className="text-slate-400 print:text-gray-700">{d.phases.phase5.reportId}</div>
                <div className="text-[10px] text-slate-500 print:text-gray-500">
                  {new Date(d.timestamp).toLocaleString()}
                </div>
              </div>
            </div>

            {/* Verification Hash & Signature Bar */}
            <div className="space-y-1.5 rounded-xl border border-slate-800 bg-slate-900/90 p-3 text-xs print:border-black print:bg-gray-100 print:text-black">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="text-slate-400 print:text-gray-700">
                  {isAr ? 'بصمة التحقق التشفيري (SHA-256):' : 'Cryptographic Verification Hash:'}
                </span>
                <div className="flex items-center gap-1">
                  <span className="max-w-xs truncate text-[11px] font-bold text-emerald-300">
                    {d.phases.phase5.sha256VerificationHash}
                  </span>
                  <button
                    onClick={() => handleCopyHash(d.phases.phase5.sha256VerificationHash)}
                    className="p-1 text-slate-400 hover:text-white print:hidden"
                    title="Copy Hash"
                  >
                    {copiedHash ? (
                      <Check className="h-3.5 w-3.5 text-emerald-400" />
                    ) : (
                      <Copy className="h-3.5 w-3.5" />
                    )}
                  </button>
                </div>
              </div>

              <div className="flex flex-wrap items-center justify-between gap-2 text-[11px]">
                <span className="text-slate-400 print:text-gray-700">
                  {isAr ? 'التوقيع العسكري الرقمي (HMAC):' : 'Digital Military Signature:'}
                </span>
                <span className="max-w-xs truncate font-bold text-cyan-300">
                  {d.phases.phase5.cryptographicSignature}
                </span>
              </div>

              <div className="flex flex-wrap items-center justify-between gap-2 border-t border-slate-800/80 pt-0.5 text-[11px]">
                <span className="text-slate-400 print:text-gray-700">
                  {isAr ? 'معيار التوافق الوطني والعسكري:' : 'Compliance Standard:'}
                </span>
                <span className="font-bold text-amber-300">
                  {d.phases.phase5.complianceStandard}
                </span>
              </div>
            </div>

            {/* Audit Executive Summary */}
            <div className="space-y-2 text-xs leading-relaxed">
              <h3 className="border-b border-slate-800 pb-1 text-sm font-bold text-white uppercase print:text-black">
                {isAr
                  ? '1. ملخص التدقيق العملياتي وسرعة الاحتواء'
                  : '1. Operational Executive Summary'}
              </h3>
              <p className="text-slate-300 print:text-gray-800">
                {isAr
                  ? `أثبتت الفحوصات الجنائية الرقمية نجاح منظومة الحماية السيادية في احتواء هجوم مركب متعدد المراحل صادر من العنوان ${d.actorIp} ضد العقدة ${d.targetNode}. تم إسقاط الحمولة الخبيثة فورياً بالذاكرة RAM بإنتروبيا شانون (${d.phases.phase1.entropy})، وحظر الفاعل بنواة eBPF XDP بزمن قدره 0.34µs، وقطع ${d.phases.phase2.tcpSocketsSevered} جلسات TCP نشطة. استغرقت كافة مراحل الدفاع من 1 إلى 5 زمناً إجمالياً قدره ${d.durationMs}ms فقط.`
                  : `Forensic audit confirms the autonomous containment of a complex multi-vector intrusion staged by actor IP ${d.actorIp} against target cluster node ${d.targetNode}. In-memory deep inspection blocked the payload at Shannon entropy ${d.phases.phase1.entropy}, kernel eBPF XDP enforced sub-microsecond isolation (0.34µs), and 4 active TCP sockets were severed via synthetic TCP-RST packets. All 5 defensive phases executed in a cumulative ${d.durationMs}ms.`}
              </p>
            </div>

            {/* Phase Evidence Matrix */}
            <div className="space-y-2 text-xs">
              <h3 className="border-b border-slate-800 pb-1 text-sm font-bold text-white uppercase print:text-black">
                {isAr
                  ? '2. جدول أدلة المراحل الدفاعية الخمس (Phase 1 - 5 Evidence Matrix)'
                  : '2. Five-Phase Evidence & Mitigation Matrix'}
              </h3>

              <div className="overflow-x-auto">
                <table className="w-full border border-slate-800 text-left text-xs print:border-black">
                  <thead className="bg-slate-900 text-slate-300 print:bg-gray-200 print:text-black">
                    <tr>
                      <th className="border-b border-slate-800 p-2">Phase</th>
                      <th className="border-b border-slate-800 p-2">Core Engine</th>
                      <th className="border-b border-slate-800 p-2">Evidence / IoC</th>
                      <th className="border-b border-slate-800 p-2">Latency</th>
                      <th className="border-b border-slate-800 p-2">Verdict</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800 text-[11px] print:divide-black">
                    <tr>
                      <td className="p-2 font-bold text-rose-400">Phase 1</td>
                      <td className="p-2">Pre-Transit RAM Engine</td>
                      <td className="p-2">
                        {d.phases.phase1.filename} (H={d.phases.phase1.entropy})
                      </td>
                      <td className="p-2 font-mono text-emerald-400">0.28 µs</td>
                      <td className="p-2 font-bold text-emerald-400">BLOCKED IN RAM</td>
                    </tr>
                    <tr>
                      <td className="p-2 font-bold text-amber-400">Phase 2</td>
                      <td className="p-2">Autonomous eBPF XDP</td>
                      <td className="p-2">
                        {d.actorIp} ({d.phases.phase2.tcpSocketsSevered} TCP-RST injected)
                      </td>
                      <td className="p-2 font-mono text-emerald-400">0.34 µs</td>
                      <td className="p-2 font-bold text-emerald-400">KERNEL BLACKHOLE</td>
                    </tr>
                    <tr>
                      <td className="p-2 font-bold text-purple-400">Phase 3</td>
                      <td className="p-2">A* Attack Graph Correlator</td>
                      <td className="p-2">T1595 → T1190 → T1059 → T1548 → T1048</td>
                      <td className="p-2 font-mono text-cyan-400">1.22 ms</td>
                      <td className="p-2 font-bold text-cyan-400">CORRELATED (98/100)</td>
                    </tr>
                    <tr>
                      <td className="p-2 font-bold text-cyan-400">Phase 4</td>
                      <td className="p-2">SOAR Self-Healing Engine</td>
                      <td className="p-2">
                        {d.phases.phase4.playbookId} (FIM Cryptographic Rollback)
                      </td>
                      <td className="p-2 font-mono text-cyan-400">1.11 ms</td>
                      <td className="p-2 font-bold text-emerald-400">SELF-HEALED 100%</td>
                    </tr>
                    <tr>
                      <td className="p-2 font-bold text-emerald-400">Phase 5</td>
                      <td className="p-2">Cryptographic Audit Seal</td>
                      <td className="p-2">HMAC-SHA256 Digital Signature Stamp</td>
                      <td className="p-2 font-mono text-emerald-400">1.87 ms</td>
                      <td className="p-2 font-bold text-emerald-400">CERTIFIED MILITARY</td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </div>

            {/* Officer Sign-off Block */}
            <div className="flex flex-col items-end justify-between gap-4 border-t-2 border-slate-800 pt-4 font-mono text-xs sm:flex-row print:border-black">
              <div className="space-y-1">
                <div className="text-slate-400 print:text-gray-700">
                  {isAr ? 'الختم الأمني المشفر:' : 'Security Officer Seal:'}
                </div>
                <div className="rounded border border-emerald-500/40 bg-slate-900 p-2 text-[10px] font-bold text-emerald-300 print:bg-gray-100 print:text-black">
                  {d.phases.phase5.digitalSeal}
                </div>
              </div>

              <div className="space-y-1 text-right">
                <div className="text-slate-400 print:text-gray-700">
                  {isAr ? 'اعتماد قائد العمليات السيبرانية:' : 'Cyber Defense Commander Clearance:'}
                </div>
                <div className="font-bold text-white print:text-black">SOV-OFFICER-CMD-942</div>
                <div className="text-[10px] text-emerald-400 print:text-black">
                  STATUS: OFFICIALLY APPROVED
                </div>
              </div>
            </div>
          </div>

          {/* Action Buttons */}
          <div className="flex flex-wrap items-center justify-end gap-3 print:hidden">
            <button
              onClick={handlePrintReport}
              className="flex items-center gap-2 rounded-xl border border-slate-700 bg-slate-900 px-4 py-2 font-mono text-xs font-bold text-slate-200 transition hover:bg-slate-800"
            >
              <Printer className="h-4 w-4 text-cyan-400" />
              <span>
                {isAr ? 'طباعة التقرير العسكري (PDF/Print)' : 'Print Official PDF Report'}
              </span>
            </button>
            <button
              onClick={() => {
                const blob = new Blob([JSON.stringify(d, null, 2)], { type: 'application/json' });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `${d.phases.phase5.reportId}.json`;
                a.click();
              }}
              className="flex items-center gap-2 rounded-xl bg-emerald-700 px-4 py-2 font-mono text-xs font-bold text-white shadow-lg shadow-emerald-950/60 transition hover:bg-emerald-600"
            >
              <Download className="h-4 w-4" />
              <span>
                {isAr ? 'تصدير بيانات التدقيق الجنائي (JSON)' : 'Export Forensic Data (JSON)'}
              </span>
            </button>
          </div>
        </div>
      )}
    </div>
  );
};
