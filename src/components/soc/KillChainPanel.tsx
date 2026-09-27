import React, { useEffect, useState } from 'react';
import {
  Search,
  KeyRound,
  Terminal,
  Anchor,
  Radio,
  Upload,
  ShieldCheck,
  Ban,
  Eye,
  Cpu,
  FileLock2,
  Bot,
  ChevronRight
} from 'lucide-react';

/**
 * KILL CHAIN / ATTACK LINE PANEL
 *
 * The single view a reviewer should be able to read in five seconds:
 * where an attack got to, and which defensive layer ended it.
 *
 * Layout follows the convention used by SOC consoles for kill-chain
 * progression: a left-to-right (RTL-aware) stage rail, each stage carrying
 * its MITRE technique, its verdict, and the control that produced that
 * verdict. The stage where the attack terminated is marked explicitly so the
 * outcome is never inferred from colour alone.
 */

interface ChainStage {
  stage: string;
  timestamp: string;
  description: string;
  technique: string;
}

interface AttackChain {
  sessionId: string;
  actorIp: string;
  threatScore: number;
  firstSeen: string;
  lastSeen: string;
  status?: string;
  stagesCompleted: ChainStage[];
}

type Verdict = 'DETECTED' | 'CLEAR';

interface StageModel {
  key: string;
  labelAr: string;
  labelEn: string;
  icon: React.ElementType;
  /** The control that owns this stage of the chain. */
  defenceAr: string;
  defenceEn: string;
  defenceIcon: React.ElementType;
}

/** The canonical chain, ordered. Backend stage names map onto these. */
const CHAIN: StageModel[] = [
  {
    key: 'Reconnaissance',
    labelAr: 'الاستطلاع',
    labelEn: 'Reconnaissance',
    icon: Search,
    defenceAr: 'فلترة النواة eBPF/XDP',
    defenceEn: 'eBPF/XDP Kernel Filter',
    defenceIcon: Cpu
  },
  {
    key: 'Initial Access',
    labelAr: 'الوصول الأولي',
    labelEn: 'Initial Access',
    icon: KeyRound,
    defenceAr: 'جدار الحماية WAF',
    defenceEn: 'WAF / Rate Limiting',
    defenceIcon: ShieldCheck
  },
  {
    key: 'Execution',
    labelAr: 'التنفيذ',
    labelEn: 'Execution',
    icon: Terminal,
    defenceAr: 'الفحص العميق للحمولة',
    defenceEn: 'Deep Payload Inspection',
    defenceIcon: Eye
  },
  {
    key: 'Persistence',
    labelAr: 'ترسيخ الوجود',
    labelEn: 'Persistence',
    icon: Anchor,
    defenceAr: 'مراقبة سلامة الملفات FIM',
    defenceEn: 'File Integrity (FIM)',
    defenceIcon: FileLock2
  },
  {
    key: 'Command and Control',
    labelAr: 'القيادة والسيطرة',
    labelEn: 'Command & Control',
    icon: Radio,
    defenceAr: 'صندوق الخداع Honeypot',
    defenceEn: 'Deception / Tarpit',
    defenceIcon: Bot
  },
  {
    key: 'Exfiltration',
    labelAr: 'سحب البيانات',
    labelEn: 'Exfiltration',
    icon: Upload,
    defenceAr: 'منع تسريب البيانات DLP',
    defenceEn: 'DLP / Egress Block',
    defenceIcon: Ban
  }
];

const VERDICT_STYLE: Record<Verdict, { ar: string; en: string; dot: string; text: string }> = {
  DETECTED: { ar: 'رُصد', en: 'Detected', dot: 'bg-amber-500', text: 'text-amber-400' },
  CLEAR: { ar: 'لا نشاط', en: 'No activity', dot: 'bg-slate-600', text: 'text-slate-500' }
};

interface Props {
  lang?: 'ar' | 'en';
}

export const KillChainPanel: React.FC<Props> = ({ lang = 'ar' }) => {
  const isAr = lang === 'ar';
  const [chain, setChain] = useState<AttackChain | null>(null);
  const [loading, setLoading] = useState(false);

  const load = async () => {
    try {
      const res = await fetch('/api/v1/soc/attack-chains');
      if (!res.ok) return;
      const data = await res.json();
      if (data?.success && Array.isArray(data.chains) && data.chains.length > 0) {
        // Show the most severe active chain.
        const top = [...data.chains].sort((a, b) => (b.threatScore || 0) - (a.threatScore || 0))[0];
        setChain(top);
      }
    } catch {
      /* keep last known state */
    }
  };

  const simulate = async () => {
    setLoading(true);
    try {
      const res = await fetch('/api/v1/soc/attack-chains/simulate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({})
      });
      const data = await res.json();
      if (data?.success && data.chain) setChain(data.chain);
    } catch {
      /* non-fatal */
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
    const t = setInterval(load, 6000);
    return () => clearInterval(t);
  }, []);

  const reached = new Set((chain?.stagesCompleted || []).map(s => s.stage));
  const techniqueFor = (key: string) =>
    (chain?.stagesCompleted || []).find(s => s.stage === key)?.technique;

  /** Index of the furthest stage the actor reached — where it is held now. */
  const lastReachedIdx = CHAIN.reduce((acc, s, i) => (reached.has(s.key) ? i : acc), -1);

  /** A stage is either observed for this actor, or it saw no activity. We do
   *  not claim a per-stage "block": containment is a property of the chain,
   *  and the backend reports it explicitly. */
  const verdictFor = (idx: number): Verdict =>
    chain && reached.has(CHAIN[idx].key) ? 'DETECTED' : 'CLEAR';

  const isContained = (chain?.status || '').toUpperCase() === 'CONTAINED';

  return (
    <section className="soc-panel p-5" dir={isAr ? 'rtl' : 'ltr'}>
      {/* Header */}
      <div className="mb-5 flex items-start justify-between gap-4">
        <div>
          <h2 className="text-base font-bold text-slate-100">
            {isAr ? 'خط الهجوم ومسار الاحتواء' : 'Attack Line & Containment Path'}
          </h2>
          <p className="mt-1 text-xs leading-relaxed text-slate-400">
            {isAr
              ? 'تتبّع مراحل الهجوم وفق MITRE ATT&CK مع طبقة الحماية المسؤولة عن كل مرحلة.'
              : 'Attack progression mapped to MITRE ATT&CK, with the control that owns each stage.'}
          </p>
        </div>
        <button
          onClick={simulate}
          disabled={loading}
          className="shrink-0 rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-xs font-semibold text-slate-200 transition-colors hover:bg-slate-700 disabled:opacity-50"
        >
          {loading
            ? isAr
              ? 'جارٍ المحاكاة…'
              : 'Simulating…'
            : isAr
              ? 'محاكاة سلسلة هجوم'
              : 'Simulate chain'}
        </button>
      </div>

      {/* Actor summary */}
      {chain && (
        <div className="mb-5 flex flex-wrap items-center gap-x-6 gap-y-2 border-b border-slate-800 pb-4">
          <div>
            <div className="soc-label">{isAr ? 'المهاجم' : 'Actor'}</div>
            <div className="mt-0.5 font-mono text-sm text-slate-100">{chain.actorIp}</div>
          </div>
          <div>
            <div className="soc-label">{isAr ? 'درجة الخطورة' : 'Severity'}</div>
            <div className="mt-0.5 font-mono text-sm font-bold text-rose-400">
              {chain.threatScore}/100
            </div>
          </div>
          <div>
            <div className="soc-label">{isAr ? 'المراحل المرصودة' : 'Stages observed'}</div>
            <div className="mt-0.5 font-mono text-sm text-slate-100">
              {chain.stagesCompleted.length} / {CHAIN.length}
            </div>
          </div>
          <div
            className={`${isAr ? 'mr-auto' : 'ml-auto'} flex items-center gap-2 rounded-lg border px-3 py-1.5 ${
              isContained
                ? 'border-emerald-500/40 bg-emerald-500/10'
                : 'alert-live border-rose-500/50 bg-rose-500/10'
            }`}
          >
            <ShieldCheck
              className={`h-4 w-4 ${isContained ? 'text-emerald-400' : 'text-rose-400'}`}
            />
            <span
              className={`text-xs font-semibold ${isContained ? 'text-emerald-300' : 'text-rose-300'}`}
            >
              {isContained
                ? isAr
                  ? 'المهاجم محتوى ومحظور'
                  : 'Actor contained & blocked'
                : isAr
                  ? 'سلسلة نشطة — قيد المعالجة'
                  : 'Chain active — responding'}
            </span>
          </div>
        </div>
      )}

      {/* Stage rail */}
      <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
        {CHAIN.map((s, idx) => {
          const verdict = verdictFor(idx);
          const style = VERDICT_STYLE[verdict];
          const StageIcon = s.icon;
          const DefIcon = s.defenceIcon;
          const isFurthest = idx === lastReachedIdx && lastReachedIdx >= 0;
          const tech = techniqueFor(s.key);

          return (
            <div key={s.key} className="relative">
              {/* connector */}
              {idx < CHAIN.length - 1 && (
                <ChevronRight
                  className={`absolute top-1/2 z-10 hidden h-4 w-4 -translate-y-1/2 text-slate-700 xl:block ${isAr ? '-left-3.5 rotate-180' : '-right-3.5'}`}
                />
              )}

              <div
                className={`h-full rounded-xl border p-3 transition-colors ${
                  isFurthest
                    ? 'border-rose-500/50 bg-rose-500/[0.07]'
                    : verdict === 'DETECTED'
                      ? 'border-amber-500/30 bg-amber-500/[0.04]'
                      : 'border-slate-800 bg-slate-900/60 shadow-[0_0_20px_rgba(0,255,255,0.08)]'
                }`}
              >
                {/* stage no + verdict */}
                <div className="mb-2 flex items-center justify-between">
                  <span className="font-mono text-[10px] text-slate-500">
                    {String(idx + 1).padStart(2, '0')}
                  </span>
                  <span className="flex items-center gap-1.5">
                    <span className={`h-1.5 w-1.5 rounded-full ${style.dot}`} />
                    <span className={`text-[10px] font-semibold ${style.text}`}>
                      {isAr ? style.ar : style.en}
                    </span>
                  </span>
                </div>

                {/* stage identity */}
                <div className="mb-1 flex items-center gap-2">
                  <StageIcon
                    className={`h-4 w-4 shrink-0 ${verdict === 'CLEAR' ? 'text-slate-600' : 'text-slate-300'}`}
                  />
                  <span className="text-[13px] leading-tight font-semibold text-slate-100">
                    {isAr ? s.labelAr : s.labelEn}
                  </span>
                </div>

                {/* MITRE technique — only when actually observed */}
                <div
                  className="mb-2.5 h-4 truncate font-mono text-[10px] text-slate-500"
                  title={tech || ''}
                >
                  {tech ? tech.split(' - ')[0] : '—'}
                </div>

                {/* owning control */}
                <div className="border-t border-slate-800 pt-2.5">
                  <div className="soc-label mb-1 text-[9px]">
                    {isAr ? 'طبقة الحماية' : 'Control'}
                  </div>
                  <div className="flex items-start gap-1.5">
                    <DefIcon className="mt-0.5 h-3.5 w-3.5 shrink-0 text-cyan-400" />
                    <span className="text-[11px] leading-snug text-slate-300">
                      {isAr ? s.defenceAr : s.defenceEn}
                    </span>
                  </div>
                </div>

                {isFurthest && (
                  <div
                    className={`mt-2.5 flex items-center gap-1.5 text-[10px] font-semibold ${isContained ? 'text-emerald-300' : 'text-rose-300'}`}
                  >
                    <Ban className="h-3 w-3" />
                    {isContained
                      ? isAr
                        ? 'أقصى مدى بلغه — ثم احتُوي'
                        : 'Furthest reach — then contained'
                      : isAr
                        ? 'أقصى مدى بلغه الآن'
                        : 'Current furthest reach'}
                  </div>
                )}
              </div>
            </div>
          );
        })}
      </div>

      {!chain && (
        <p className="mt-4 text-xs text-slate-500">
          {isAr
            ? 'لا توجد سلسلة هجوم نشطة حالياً — جميع المراحل خالية من النشاط.'
            : 'No active attack chain — all stages clear.'}
        </p>
      )}
    </section>
  );
};
