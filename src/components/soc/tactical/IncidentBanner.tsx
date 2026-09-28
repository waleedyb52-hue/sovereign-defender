import React from 'react';
import { motion, useReducedMotion } from 'motion/react';
import { Siren, CheckCheck, ListFilter } from 'lucide-react';
import { CyberButton } from './CyberButton';
import { IpLink } from './ipDossier';
import type { IncidentMode } from './useIncidentMode';

/**
 * INCIDENT BANNER — the console's "condition red", present only while an incident is.
 *
 * It replaces nothing and adds no panel: it is a strip under the header that exists for
 * the length of the incident. Every figure on it is measured — elapsed time from the
 * first critical event's own timestamp, the count of criticals in the run, the address
 * that sent the most, and time-to-contain only if a containment actually followed.
 *
 * Motion: the siren glyph breathes (opacity, 2 s) and nothing else moves. Under reduced
 * motion it is still. A twelve-hour shift is not the place for strobing.
 */

const clock = (ms: number) => {
  const s = Math.max(0, Math.floor(ms / 1000));
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const sec = s % 60;
  return `${h ? h + ':' : ''}${String(m).padStart(2, '0')}:${String(sec).padStart(2, '0')}`;
};

export const IncidentBanner: React.FC<{
  inc: IncidentMode;
  isAr: boolean;
  canAct: boolean;
  onShowCritical: () => void;
}> = ({ inc, isAr, canAct, onShowCritical }) => {
  const reduce = useReducedMotion() ?? false;
  if (!inc.active || !inc.since) return null;

  const t0 = Date.parse(inc.since);
  const elapsed = clock(inc.now - t0);
  const ttc = inc.containedAt ? clock(Date.parse(inc.containedAt) - t0) : null;

  if (inc.ack) {
    return (
      <div className="relative z-20 flex shrink-0 items-center gap-3 border-b border-rose-500/40 bg-rose-950/40 px-3 py-1 backdrop-blur-2xl" role="status">
        <CheckCheck className="h-3.5 w-3.5 text-rose-300" aria-hidden />
        <span className="text-[11px] text-rose-200">
          {isAr ? 'حادثة نشطة · استلمها ' : 'Active incident · taken by '}
          <span className="font-mono font-semibold">{inc.ack.by}</span>
        </span>
        <span className="font-mono text-[11px] text-rose-300" dir="ltr">T+{elapsed}</span>
        {inc.topIp && <IpLink ip={inc.topIp} className="text-[11px] text-rose-200" />}
        <span className="ms-auto font-mono text-[10px] text-rose-300/80" dir="ltr">
          {inc.criticalCount} CRIT{ttc ? ` · contained T+${ttc}` : ''}
        </span>
      </div>
    );
  }

  return (
    <div
      className="relative z-20 flex shrink-0 flex-wrap items-center gap-x-4 gap-y-1 border-b-2 border-rose-500/80 bg-gradient-to-r from-rose-950/90 via-rose-950/70 to-rose-950/90 px-3 py-1.5 backdrop-blur-2xl"
      role="alert"
      aria-live="assertive"
    >
      <span className="flex items-center gap-2">
        <motion.span
          animate={reduce ? undefined : { opacity: [1, 0.35, 1] }}
          transition={reduce ? undefined : { duration: 2, repeat: Infinity, ease: 'easeInOut' }}
          className="grid h-6 w-6 place-items-center border border-rose-400/70"
          style={{ clipPath: 'polygon(6px 0,100% 0,100% calc(100% - 6px),calc(100% - 6px) 100%,0 100%,0 6px)' }}
        >
          <Siren className="h-3.5 w-3.5 text-rose-300" aria-hidden />
        </motion.span>
        <span className="text-sm font-bold tracking-wide text-rose-100">{isAr ? 'حادثة نشطة' : 'ACTIVE INCIDENT'}</span>
      </span>

      <span className="flex flex-col leading-tight">
        <span className="text-[10px] tracking-widest text-rose-300/80">{isAr ? 'منذ الرصد' : 'SINCE DETECTION'}</span>
        <span className="font-mono text-base font-bold text-white tabular-nums" dir="ltr" style={{ textShadow: '0 0 12px rgba(244,63,94,0.8)' }}>
          T+{elapsed}
        </span>
      </span>

      <span className="flex flex-col leading-tight">
        <span className="text-[10px] tracking-widest text-rose-300/80">{isAr ? 'أحداث حرجة' : 'CRITICAL EVENTS'}</span>
        <span className="font-mono text-base font-bold text-rose-100">{inc.criticalCount || '—'}</span>
      </span>

      {inc.topIp && (
        <span className="flex flex-col leading-tight">
          <span className="text-[10px] tracking-widest text-rose-300/80">{isAr ? 'أبرز مصدر' : 'TOP SOURCE'}</span>
          <IpLink ip={inc.topIp} className="text-sm font-bold text-rose-100" />
        </span>
      )}

      <span className="flex flex-col leading-tight">
        <span className="text-[10px] tracking-widest text-rose-300/80">{isAr ? 'الاحتواء' : 'CONTAINMENT'}</span>
        <span className={`font-mono text-sm font-bold ${ttc ? 'text-emerald-300' : 'text-amber-300'}`} dir="ltr">
          {ttc ? `T+${ttc}` : isAr ? 'لم يُحتوَ' : 'NOT CONTAINED'}
        </span>
      </span>

      {inc.techniques.length > 0 && (
        <span className="flex gap-1">
          {inc.techniques.map(t => (
            <span key={t} className="border border-cyan-500/40 px-1 font-mono text-[10px] text-cyan-300">
              {t}
            </span>
          ))}
        </span>
      )}

      <span className="ms-auto flex items-center gap-1.5">
        <CyberButton size="sm" tone="rose" onClick={onShowCritical}>
          <span className="flex items-center gap-1">
            <ListFilter className="h-3 w-3" aria-hidden />
            {isAr ? 'الأحداث' : 'EVENTS'}
          </span>
        </CyberButton>
        <CyberButton
          size="sm"
          tone="amber"
          disabled={!canAct}
          title={canAct ? undefined : isAr ? 'يتطلّب دور محلّل' : 'requires the ANALYST role'}
          onClick={() => void inc.acknowledge()}
        >
          {isAr ? '[ استلام الحادثة ]' : '[ ACKNOWLEDGE ]'}
        </CyberButton>
      </span>
    </div>
  );
};

export default IncidentBanner;
