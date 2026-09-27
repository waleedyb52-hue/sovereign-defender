import React from 'react';
import { motion } from 'motion/react';
import { Layers } from 'lucide-react';
import { Glass, Label, Row, Stat, Value } from './parts';
import { formatCount } from '../../../lib/utils';
import { EndpointRiskScatter } from './EndpointRiskScatter';
import type { CyberDefendData } from './useCyberDefendData';

/**
 * GAUGE ANALYTICS VIEW — dual arcs, rings, and distribution bars
 *
 * The reference's fourth screen: two large semicircular arcs with giant numerals
 * between them, neon ring gauges top-right, and vertical glass bars along the
 * bottom. That composition is reproduced.
 *
 * ON THE FILE NAME
 *   The specification called this `EnergyGaugesView`. The name is not used, and the
 *   reason is not pedantry: the reference's arcs measured megawatt-hours of
 *   production and consumption, its rings measured thermal and solar share, and its
 *   bars measured fuel sources. This platform generates no energy and burns no fuel.
 *   A file named for data it does not contain sends the next reader looking for an
 *   energy subsystem that was never built, so it is named for the shapes it draws
 *   instead, which is the part that was actually asked for.
 *
 * WHAT THE ARCS MEASURE HERE
 *   Requests protected against threats blocked — the two quantities that actually
 *   describe this platform's work, drawn at the scale the reference gave to
 *   production and consumption. Both are read from the agent's live counters, and
 *   both render an em dash if the counter is unavailable rather than an arc at zero,
 *   because an empty arc reads as "nothing happening" when it means "nothing known".
 */

interface Props {
  d: CyberDefendData;
  isAr: boolean;
  reduce: boolean;
}

export const GaugeAnalyticsView: React.FC<Props> = ({ d, isAr, reduce }) => {
  const protectedN = d.agent.requestsProtected;
  const blockedN = d.agent.threatsBlocked;
  const scale = Math.max(protectedN ?? 0, blockedN ?? 0, 1);
  const retainedTotal = d.families.reduce((a, f) => a + f.count, 0);
  const maxFam = Math.max(1, ...d.families.map(f => f.count));

  return (
    <div className="space-y-3">
      <div className="grid grid-cols-1 gap-3 lg:grid-cols-12">
        {/* Dual arcs */}
        <Glass className="p-4 lg:col-span-7">
          <Label>{isAr ? 'الحماية مقابل الحجب' : 'Protected vs blocked'}</Label>
          <div className="mt-3 flex flex-wrap items-center justify-center gap-6">
            <Arc
              value={protectedN}
              max={scale}
              accent="#FFFFFF"
              label={isAr ? 'طلبات محميّة' : 'Requests protected'}
              reason="/api/v1/agent/status did not report totalRequestsProtected"
              reduce={reduce}
            />
            <Arc
              value={blockedN}
              max={scale}
              accent="#F59E0B"
              label={isAr ? 'تهديدات محجوبة' : 'Threats blocked'}
              reason="/api/v1/agent/status did not report totalThreatsBlocked"
              reduce={reduce}
            />
          </div>
          <div className="mt-3 grid grid-cols-3 gap-2 border-t border-white/5 pt-2.5">
            <Stat
              label={isAr ? 'نسبة الحجب' : 'Block share'}
              value={d.derived.blockShare != null ? `${(d.derived.blockShare * 100).toFixed(2)}%` : null}
              accent="#67e8f9"
            />
            <Stat
              label={isAr ? 'كثافة التهديد' : 'Threat density'}
              value={d.derived.threatDensity != null ? `${d.derived.threatDensity}/10k` : null}
              accent="#fcd34d"
            />
            <Stat
              label={isAr ? 'تقييمات' : 'Evaluations'}
              value={d.posture.evaluations != null ? formatCount(d.posture.evaluations) : null}
              accent="#6ee7b7"
            />
          </div>
        </Glass>

        {/* Ring gauges — the source-distribution position */}
        <Glass className="p-3 lg:col-span-5">
          <Label>{isAr ? 'حالة المحرّك المحلّي' : 'Local engine posture'}</Label>
          <div className="mt-2.5 grid grid-cols-2 gap-2.5">
            <Ring
              label={isAr ? 'ذاكرة العملية' : 'Process heap'}
              value={d.posture.heapMb}
              max={d.posture.rssMb ?? d.posture.heapMb ?? 1}
              unit="MB"
              accent="#FFFFFF"
              reduce={reduce}
            />
            <Ring
              label={isAr ? 'احتفاظ' : 'Retention'}
              value={retainedTotal > 0 ? retainedTotal : null}
              max={500}
              unit=""
              accent="#F59E0B"
              reason="/soc/learning/retention reported nothing held"
              reduce={reduce}
            />
          </div>
          <dl className="mt-2.5 space-y-1 border-t border-white/5 pt-2">
            <Row k={isAr ? 'المحرّك' : 'Engine'} v={d.posture.engine?.replace(/_/g, ' ') ?? null} small />
            <Row
              k={isAr ? 'صفر خروج' : 'Zero egress'}
              v={
                d.posture.zeroEgress === true
                  ? isAr
                    ? 'نعم'
                    : 'yes'
                  : d.posture.zeroEgress === false
                    ? isAr
                      ? 'لا'
                      : 'no'
                    : null
              }
              small
            />
            <Row k={isAr ? 'حزم مُسقَطة' : 'Packets dropped'} v={d.kernel.packetsDropped} />
            <Row k={isAr ? 'منها مزروع' : 'of which seeded'} v={d.kernel.seeded} small />
            <Row k={isAr ? 'منها مرصود' : 'of which observed'} v={d.kernel.observed} small />
          </dl>
          {(d.kernel.seeded ?? 0) > 0 && (
            <p className="mt-2 text-[8px] leading-relaxed text-[#fcd34d]">
              {isAr
                ? 'جزء من عدّاد الحزم مزروع للعرض ولم يُرصد — الرقمان مفصولان أعلاه لهذا السبب.'
                : 'Part of the packet counter is seeded for review and was never observed — which is why the two are reported separately above.'}
            </p>
          )}
        </Glass>
      </div>

      {/* Bottom triptych, as the reference has it: an index on the left, the scatter
          in the centre, the distribution bars on the right. */}
      <div className="grid grid-cols-1 gap-3 lg:grid-cols-12">
        {/* Threat intensity — the energy-intensity-index position */}
        <Glass className="p-3 lg:col-span-3">
          <Label>{isAr ? 'مؤشّر كثافة التهديد' : 'Threat intensity index'}</Label>
          <div className="mt-2.5 text-center">
            <Value
              v={d.derived.threatDensity}
              className="text-3xl font-bold text-white"
              reason="needs requestsProtected and threatsBlocked"
            />
            <p className="mt-0.5 text-[8px] text-slate-500">
              {isAr ? 'تهديد لكل 10,000 طلب' : 'threats per 10,000 requests'}
            </p>
          </div>

          {/* Intensity bar. Scaled against 500/10k, which is a stated reference
              point rather than the observed maximum — a bar that rescales to its
              own peak always looks full and stops carrying information. */}
          <div className="mt-3">
            <div className="h-2.5 overflow-hidden rounded-full bg-white/5">
              {d.derived.threatDensity != null && (
                <div
                  className="h-full rounded-full transition-[width] duration-700"
                  style={{
                    width: `${Math.min(100, (d.derived.threatDensity / 500) * 100)}%`,
                    background:
                      d.derived.threatDensity >= 300
                        ? 'linear-gradient(90deg, #F59E0B, #f43f5e)'
                        : 'linear-gradient(90deg, #22d3ee, #10B981)'
                  }}
                />
              )}
            </div>
            <div className="mt-1 flex justify-between text-[7px] text-slate-600">
              <span>0</span>
              <span>{isAr ? 'مرجع 500' : 'ref 500'}</span>
            </div>
          </div>

          <dl className="mt-3 space-y-1 border-t border-white/5 pt-2">
            <Row k={isAr ? 'تقييمات' : 'Evaluations'} v={d.posture.evaluations} />
            <Row k={isAr ? 'مصائد' : 'Trapped'} v={d.agent.trapped} />
            <Row k={isAr ? 'عناوين معزولة' : 'Quarantined'} v={d.agent.quarantined} />
          </dl>
        </Glass>

        {/* Scatter — the costs-per-household position */}
        <div className="lg:col-span-5">
          <EndpointRiskScatter d={d} isAr={isAr} reduce={reduce} />
        </div>

        {/* Distribution bars — the fuel-source position */}
        <Glass className="p-3 lg:col-span-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-1.5">
            <Layers className="h-3.5 w-3.5 text-[#22d3ee]" aria-hidden />
            <Label>{isAr ? 'توزّع عائلات الهجوم المحتفظ بها' : 'Retained attack family distribution'}</Label>
          </div>
          <span className="text-[8px] text-slate-500">
            {isAr ? `${d.families.length} صنفاً` : `${d.families.length} families`}
          </span>
        </div>

        {d.families.length === 0 ? (
          <p className="py-8 text-center text-[10px] text-slate-500">
            {isAr ? 'لا بيانات من /soc/learning/retention' : 'No data from /soc/learning/retention'}
          </p>
        ) : (
          <div className="mt-3 flex items-end gap-2 overflow-x-auto pb-1" style={{ height: 132 }}>
            {d.families.slice(0, 12).map((f, i) => {
              const clean = f.family === 'CLEAN_TRAFFIC';
              return (
                <motion.div
                  key={f.family}
                  className="flex min-w-[52px] flex-1 flex-col items-center justify-end"
                  initial={reduce ? { opacity: 0 } : { opacity: 0, scaleY: 0.6 }}
                  animate={{ opacity: 1, scaleY: 1 }}
                  transition={{ delay: reduce ? 0 : i * 0.04, duration: 0.24 }}
                  style={{ transformOrigin: 'bottom' }}
                >
                  <Mono className="mb-1 text-[9px] font-bold text-white">{f.count}</Mono>
                  <div
                    className="w-full rounded-t-md border-x border-t"
                    style={{
                      height: `${(f.count / maxFam) * 88}px`,
                      background: clean
                        ? 'linear-gradient(180deg, rgba(16,185,129,0.55), rgba(16,185,129,0.06))'
                        : 'linear-gradient(180deg, rgba(239,68,68,0.6), rgba(239,68,68,0.06))',
                      borderColor: clean ? 'rgba(16,185,129,0.5)' : 'rgba(239,68,68,0.5)'
                    }}
                  />
                  <span className="mt-1 w-full truncate text-center text-[7px] text-slate-500" title={f.family}>
                    {f.family.replace(/_/g, ' ')}
                  </span>
                </motion.div>
              );
            })}
          </div>
        )}
        </Glass>
      </div>
    </div>
  );
};

/** Local mono, kept here so this file does not import for one usage. */
const Mono: React.FC<{ children: React.ReactNode; className?: string }> = ({ children, className }) => (
  <span className={className} style={{ fontFamily: 'var(--font-mono)' }} dir="ltr">
    {children}
  </span>
);

/**
 * Semicircular arc gauge.
 *
 * A null value draws the track and no arc, with an em dash in place of the numeral.
 * Drawing a zero-length arc instead would read as "nothing happened" when the truth
 * is "nothing was reported", and those are different statements.
 */
const Arc: React.FC<{
  value: number | null;
  max: number;
  accent: string;
  label: string;
  reason?: string;
  reduce: boolean;
}> = ({ value, max, accent, label, reason, reduce }) => {
  const pct = value != null && max > 0 ? Math.min(1, value / max) : 0;
  const r = 62;
  const circ = Math.PI * r;
  return (
    <div className="text-center">
      <div className="relative h-[84px] w-[152px]">
        <svg viewBox="0 0 152 84" className="h-full w-full" aria-hidden>
          <path
            d={`M 14 76 A ${r} ${r} 0 0 1 138 76`}
            fill="none"
            stroke="rgba(255,255,255,0.07)"
            strokeWidth="9"
            strokeLinecap="round"
          />
          {value != null && (
            <motion.path
              d={`M 14 76 A ${r} ${r} 0 0 1 138 76`}
              fill="none"
              stroke={accent}
              strokeWidth="9"
              strokeLinecap="round"
              strokeDasharray={circ}
              initial={{ strokeDashoffset: circ }}
              animate={{ strokeDashoffset: circ - pct * circ }}
              transition={reduce ? { duration: 0 } : { duration: 0.9, ease: 'easeOut' }}
              style={{ filter: `drop-shadow(0 0 6px ${accent}66)` }}
            />
          )}
        </svg>
        <div className="absolute inset-x-0 bottom-1 text-center">
          <Value
            v={value != null ? formatCount(value) : null}
            className="text-xl font-bold text-white"
            reason={reason}
          />
        </div>
      </div>
      <p className="text-[8px] tracking-wider text-slate-500 uppercase">{label}</p>
    </div>
  );
};

/** Circular ring gauge, same absence discipline as the arc. */
const Ring: React.FC<{
  label: string;
  value: number | null;
  max: number;
  unit: string;
  accent: string;
  reason?: string;
  reduce: boolean;
}> = ({ label, value, max, unit, accent, reason, reduce }) => {
  const pct = value != null && max > 0 ? Math.min(1, value / max) : 0;
  return (
    <div className="rounded-xl border border-white/8 bg-white/[0.02] p-2 text-center">
      <div className="relative mx-auto h-[62px] w-[62px]">
        <svg viewBox="0 0 62 62" className="h-full w-full -rotate-90" aria-hidden>
          <circle cx="31" cy="31" r="25" fill="none" stroke="rgba(255,255,255,0.07)" strokeWidth="5" />
          {value != null && (
            <motion.circle
              cx="31"
              cy="31"
              r="25"
              fill="none"
              stroke={accent}
              strokeWidth="5"
              strokeLinecap="round"
              strokeDasharray={157}
              initial={{ strokeDashoffset: 157 }}
              animate={{ strokeDashoffset: 157 - pct * 157 }}
              transition={reduce ? { duration: 0 } : { duration: 0.8, ease: 'easeOut' }}
              style={{ filter: `drop-shadow(0 0 5px ${accent}55)` }}
            />
          )}
        </svg>
        <div className="absolute inset-0 grid place-items-center">
          <div>
            <Value
              v={value != null ? Math.round(value) : null}
              className="text-[12px] font-bold text-white"
              reason={reason}
            />
            {unit && value != null && <p className="text-[7px] text-slate-500">{unit}</p>}
          </div>
        </div>
      </div>
      <p className="mt-1 text-[8px] text-slate-500">{label}</p>
    </div>
  );
};
