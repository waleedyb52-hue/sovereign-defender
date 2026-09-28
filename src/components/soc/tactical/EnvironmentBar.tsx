import React from 'react';
import { Activity, Radio, Swords, ShieldCheck } from 'lucide-react';
import { CyberButton } from './CyberButton';

/**
 * ENVIRONMENT BAR — DEFCON, the LIVE/SIM switch, and the resource ticker.
 *
 * DEFCON is DERIVED, and the derivation is disclosed on the badge itself.
 *
 * No endpoint issues a readiness level, so one is computed from measurements that do
 * exist: emergency lockdown, critical alert count, active hard bans, FIM critical
 * alerts and isolated nodes. That is legitimate — a computed indicator over real
 * inputs — but only while the inputs are named, which is why they are listed in the
 * tooltip and the level shows as UNKNOWN rather than 5 when nothing has reported yet.
 * A console that displays a confident DEFCON 5 while every sensor is silent is
 * asserting calm it has not observed, and "all quiet" is the most expensive wrong
 * answer a defence board can give.
 */

export type Environment = 'LIVE' | 'WARGAME';

export interface DefconInputs {
  emergencyLockdown: boolean;
  criticalAlerts: number;
  activeHardBans: number | null;
  fimCritical: number | null;
  isolatedNodes: number;
  anySourceReporting: boolean;
}

export interface DefconResult {
  level: 1 | 2 | 3 | 4 | 5 | null;
  tone: string;
  labelAr: string;
  labelEn: string;
  basis: string[];
}

export function deriveDefcon(i: DefconInputs, isAr: boolean): DefconResult {
  const basis: string[] = [];
  const push = (ar: string, en: string) => basis.push(isAr ? ar : en);

  if (!i.anySourceReporting) {
    return {
      level: null,
      tone: '#64748b',
      labelAr: 'غير معروف',
      labelEn: 'UNKNOWN',
      basis: [isAr ? 'لا مصدر يستجيب — لا حكم على الجاهزية' : 'no source responding — no readiness claim made']
    };
  }

  push(`${i.criticalAlerts} تنبيه حرِج`, `${i.criticalAlerts} critical alerts`);
  if (i.activeHardBans != null) push(`${i.activeHardBans} حجب صارم`, `${i.activeHardBans} active hard bans`);
  if (i.fimCritical != null) push(`${i.fimCritical} تنبيه سلامة ملفات`, `${i.fimCritical} FIM critical`);
  push(`${i.isolatedNodes} عقدة معزولة`, `${i.isolatedNodes} isolated nodes`);
  if (i.emergencyLockdown) push('الإغلاق الطارئ مفعّل', 'emergency lockdown engaged');

  if (i.emergencyLockdown) return { level: 1, tone: '#e11d48', labelAr: 'إغلاق طارئ', labelEn: 'LOCKDOWN', basis };
  if (i.criticalAlerts >= 5 || (i.fimCritical ?? 0) > 0 || i.isolatedNodes >= 2)
    return { level: 2, tone: '#e11d48', labelAr: 'هجوم نشط', labelEn: 'ACTIVE ATTACK', basis };
  if (i.criticalAlerts > 0 || i.isolatedNodes > 0)
    return { level: 3, tone: '#fbbf24', labelAr: 'تحقيق جارٍ', labelEn: 'INVESTIGATING', basis };
  if ((i.activeHardBans ?? 0) > 0) return { level: 4, tone: '#fbbf24', labelAr: 'يقظة مرتفعة', labelEn: 'ELEVATED', basis };
  return { level: 5, tone: '#34d399', labelAr: 'مستقرّ', labelEn: 'NOMINAL', basis };
}

export const DefconBadge: React.FC<{ d: DefconResult; isAr: boolean }> = ({ d, isAr }) => (
  <span
    className="flex shrink-0 items-center gap-1.5 border px-2 py-0.5"
    style={{
      borderColor: `${d.tone}88`,
      background: `${d.tone}14`,
      boxShadow: d.level != null && d.level <= 2 ? `0 0 18px ${d.tone}55` : undefined,
      clipPath: 'polygon(6px 0,100% 0,100% calc(100% - 6px),calc(100% - 6px) 100%,0 100%,0 6px)'
    }}
    title={(isAr ? 'مُشتقّ من: ' : 'derived from: ') + d.basis.join(' · ')}
  >
    <span className="font-mono text-[6px] tracking-widest text-slate-500 uppercase">DEFCON</span>
    <span
      className={`font-mono text-[13px] font-bold ${d.level != null && d.level <= 2 ? 'animate-pulse' : ''}`}
      style={{ color: d.tone, textShadow: `0 0 10px ${d.tone}` }}
    >
      {d.level ?? '—'}
    </span>
    <span className="font-mono text-[6.5px] tracking-widest uppercase" style={{ color: d.tone }}>
      {isAr ? d.labelAr : d.labelEn}
    </span>
  </span>
);

export const EnvironmentToggle: React.FC<{
  env: Environment;
  isAr: boolean;
  /** Set when a drill is running: leaving the sandbox is blocked until it is reset. */
  lockedReason?: string | null;
  onChange: (e: Environment) => void;
}> = ({ env, isAr, lockedReason, onChange }) => (
  <span className="flex shrink-0 items-center gap-1">
    <CyberButton
      tone="cyan"
      size="sm"
      active={env === 'LIVE'}
      disabled={env !== 'LIVE' && Boolean(lockedReason)}
      title={env !== 'LIVE' ? (lockedReason ?? undefined) : undefined}
      onClick={() => onChange('LIVE')}
    >
      <span className="flex items-center gap-1">
        <Radio className="h-2.5 w-2.5" aria-hidden />
        {isAr ? '[ مركز حيّ ]' : '[ LIVE SOC ]'}
      </span>
    </CyberButton>
    <CyberButton tone="amber" size="sm" active={env === 'WARGAME'} onClick={() => onChange('WARGAME')}>
      <span className="flex items-center gap-1">
        <Swords className="h-2.5 w-2.5" aria-hidden />
        {isAr ? '[ محاكاة حربية ]' : '[ WARGAMING ]'}
      </span>
    </CyberButton>
  </span>
);

export const ResourceTicker: React.FC<{
  heapMb: number | null;
  rssMb: number | null;
  uptimeSec: number | null;
  rps: number | null;
  isAr: boolean;
}> = ({ heapMb, rssMb, uptimeSec, rps, isAr }) => {
  const cell = (label: string, v: number | string | null, unit?: string) => (
    <span className="flex items-baseline gap-1">
      <span className="font-mono text-[5.5px] tracking-widest text-slate-600 uppercase">{label}</span>
      {v == null ? (
        <span className="font-mono text-[7px] text-slate-700">—</span>
      ) : (
        <span className="font-mono text-[7.5px] font-bold text-cyan-400 tabular-nums">
          {typeof v === 'number' ? v.toLocaleString('en-US') : v}
          {unit && <span className="text-[5.5px] opacity-60">{unit}</span>}
        </span>
      )}
    </span>
  );

  const hours = uptimeSec != null ? Math.floor(uptimeSec / 3600) : null;
  const mins = uptimeSec != null ? Math.floor((uptimeSec % 3600) / 60) : null;

  return (
    <span className="flex shrink-0 items-center gap-3">
      <Activity className="h-2.5 w-2.5 text-cyan-400/60" aria-hidden />
      {cell(isAr ? 'كومة' : 'HEAP', heapMb != null ? Math.round(heapMb) : null, 'MB')}
      {cell('RSS', rssMb != null ? Math.round(rssMb) : null, 'MB')}
      {cell('RPS', rps)}
      {cell(isAr ? 'تشغيل' : 'UP', hours != null ? `${hours}h${String(mins).padStart(2, '0')}` : null)}
    </span>
  );
};

/** The amber frame and banner that mark the sandbox. Impossible to read as live. */
export const SimulationFrame: React.FC<{ isAr: boolean; drillActive: boolean; detail?: string | null }> = ({
  isAr,
  drillActive,
  detail
}) => (
  <>
    <div
      className="pointer-events-none absolute inset-0 z-30 border-2"
      style={{
        borderColor: 'rgba(245,158,11,0.55)',
        boxShadow: 'inset 0 0 60px rgba(245,158,11,0.09)'
      }}
      aria-hidden
    />
    <div className="pointer-events-none absolute inset-x-0 top-0 z-30 flex justify-center">
      <span
        className={`flex items-center gap-1.5 border border-amber-500/70 bg-amber-950/80 px-3 py-0.5 backdrop-blur-xl ${
          drillActive ? 'animate-pulse' : ''
        }`}
        style={{ clipPath: 'polygon(8px 0,100% 0,100% calc(100% - 8px),calc(100% - 8px) 100%,0 100%,0 8px)' }}
      >
        <ShieldCheck className="h-2.5 w-2.5 text-amber-400" aria-hidden />
        <span
          className="font-mono text-[7.5px] font-bold tracking-widest text-amber-400 uppercase"
          style={{ textShadow: '0 0 10px rgba(251,191,36,0.9)' }}
        >
          {isAr
            ? drillActive ? '⚠ محاكاة نشطة — ليست حادثة حقيقية' : 'بيئة محاكاة معزولة'
            : drillActive ? '⚠ SIMULATION ACTIVE — NOT A REAL INCIDENT' : 'SANDBOXED SIMULATION ENVIRONMENT'}
        </span>
        {detail && <span className="font-mono text-[6.5px] text-amber-300/80">{detail}</span>}
      </span>
    </div>
  </>
);

/**
 * Emergency frame while a host is contained — `.clauderules` §8.
 *
 * Crimson where the simulation frame is amber, and driven by the server's containment
 * records rather than by the click that asked for isolation: the frame appears when the
 * record is ACTIVE and goes when it is RELEASED, so a refused isolation draws nothing.
 *
 * Seeded demo records do not raise it. They are active from boot, and a frame that is
 * always on is a frame the operator learns to stop seeing.
 *
 * Release sits on the frame itself, so it is reachable from any view and any mode.
 */
export const ContainmentFrame: React.FC<{
  isAr: boolean;
  ips: string[];
  busyIp: string | null;
  /** Absent for a VIEWER: the buttons stay visible, disabled, with the reason. */
  onRelease?: (ip: string) => void;
}> = ({ isAr, ips, busyIp, onRelease }) =>
  ips.length === 0 ? null : (
    <>
      <div
        className="pointer-events-none absolute inset-0 z-30 border-2"
        style={{ borderColor: 'rgba(244,63,94,0.6)', boxShadow: 'inset 0 0 70px rgba(244,63,94,0.10)' }}
        aria-hidden
      />
      <div className="pointer-events-none absolute inset-x-0 bottom-9 z-30 flex justify-center">
        <div
          role="status"
          className="pointer-events-auto flex flex-wrap items-center gap-2 border border-rose-500/70 bg-rose-950/85 px-3 py-1 backdrop-blur-xl"
          style={{ clipPath: 'polygon(8px 0,100% 0,100% calc(100% - 8px),calc(100% - 8px) 100%,0 100%,0 8px)' }}
        >
          <span
            className="font-mono text-[10px] font-bold tracking-widest text-rose-300 uppercase"
            style={{ textShadow: '0 0 10px rgba(244,63,94,0.9)' }}
          >
            {isAr ? `${ips.length} مضيف محتوى` : `${ips.length} HOST${ips.length > 1 ? 'S' : ''} CONTAINED`}
          </span>
          {ips.slice(0, 3).map(ip => (
            <CyberButton
              key={ip}
              tone="emerald"
              size="sm"
              disabled={!onRelease || busyIp === ip}
              title={!onRelease ? (isAr ? 'يتطلّب دور محلّل' : 'requires the ANALYST role') : isAr ? `رفع العزل عن ${ip}` : `release ${ip}`}
              onClick={onRelease ? () => onRelease(ip) : undefined}
            >
              {busyIp === ip ? '…' : `${isAr ? 'فك' : 'RELEASE'} ${ip}`}
            </CyberButton>
          ))}
          {ips.length > 3 && <span className="font-mono text-[10px] text-rose-300/80">+{ips.length - 3}</span>}
        </div>
      </div>
    </>
  );
