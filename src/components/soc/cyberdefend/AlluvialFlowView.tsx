import React from 'react';
import { motion } from 'motion/react';
import { ShieldAlert } from 'lucide-react';
import { Glass, Label, Mono, Row } from './parts';
import { formatCount } from '../../../lib/utils';
import type { CyberDefendData } from './useCyberDefendData';

/**
 * ALLUVIAL FLOW VIEW — where traffic goes and what stops it
 *
 * The reference's second screen: source cards down the left, intermediate nodes in
 * the middle, and neon flow fibres curving into destinations. That composition is
 * reproduced.
 *
 * The reference's sources were data centres (North Virginia, Vancouver, Houston)
 * and its nodes were listening stations (Menwith Hill, Fort Meade). Neither exists
 * here, so the same structure carries what does: the endpoints this platform
 * actually sees traffic on, flowing into the three progressive-mitigation tiers it
 * actually applies.
 *
 * On the flow thickness
 *   Each ribbon's width is the product of two real quantities — the endpoint's share
 *   of observed hits, and the tier's share of total mitigations. It is therefore a
 *   readable quantity rather than decoration, which is the whole reason a Sankey is
 *   worth drawing instead of a bar chart. When a tier count is absent its ribbons are
 *   not drawn at all, so an unmeasured path cannot appear as a thin but present flow.
 */

interface Props {
  d: CyberDefendData;
  isAr: boolean;
  reduce: boolean;
}

export const AlluvialFlowView: React.FC<Props> = ({ d, isAr, reduce }) => {
  const tiers = [
    { id: 'tier1', label: isAr ? 'تحديد المعدّل' : 'Rate limited', v: d.mitigation.tier1, color: '#38BDF8' },
    { id: 'tier2', label: isAr ? 'تحدٍّ' : 'Challenged', v: d.mitigation.tier2, color: '#F59E0B' },
    { id: 'tier3', label: isAr ? 'حجب حرج' : 'Critical blocked', v: d.mitigation.tier3, color: '#EF4444' }
  ];
  const totalTier = tiers.reduce((a, t) => a + (t.v ?? 0), 0);
  const maxHits = Math.max(1, ...d.endpoints.map(e => e.hits));
  const shown = d.endpoints.slice(0, 6);

  return (
    <div className="grid grid-cols-1 gap-3 lg:grid-cols-12">
      {/* Sources — the data-centre column position */}
      <Glass className="p-3 lg:col-span-4">
        <Label>{isAr ? 'نقاط النهاية المستهدفة' : 'Targeted endpoints'}</Label>
        <div className="mt-2.5 space-y-2">
          {d.endpoints.length === 0 && (
            <p className="py-6 text-center text-[10px] text-slate-500">
              {isAr ? 'لا بيانات من ' : 'No data from '}
              <Mono className="text-[9px]">/soc/analytics</Mono>
            </p>
          )}
          {d.endpoints.map(e => {
            const threatShare = e.hits > 0 ? e.threatHits / e.hits : 0;
            return (
              <div key={e.endpoint} className="rounded-xl border border-white/8 bg-white/[0.02] p-2.5">
                <div className="flex items-baseline justify-between gap-2">
                  <Mono className="truncate text-[10px] text-slate-200">{e.endpoint}</Mono>
                  <Mono className="shrink-0 text-[11px] font-bold text-white">{formatCount(e.hits)}</Mono>
                </div>
                {/* Hatched bar — the reference's texture, width from real hits. */}
                <div className="mt-1.5 h-2 overflow-hidden rounded-full bg-white/5">
                  <div
                    className="h-full rounded-full"
                    style={{
                      width: `${(e.hits / maxHits) * 100}%`,
                      background: `repeating-linear-gradient(45deg, ${
                        threatShare > 0.3 ? 'rgba(239,68,68,0.85)' : 'rgba(56,189,248,0.8)'
                      } 0 4px, rgba(255,255,255,0.08) 4px 8px)`
                    }}
                  />
                </div>
                <div className="mt-1 flex gap-2.5 text-[8px] text-slate-500">
                  <span>
                    <Mono className="text-[#fca5a5]">{formatCount(e.threatHits)}</Mono>{' '}
                    {isAr ? 'عدائية' : 'hostile'}
                  </span>
                  <span>
                    <Mono className="text-[#6ee7b7]">{formatCount(e.hits - e.threatHits)}</Mono>{' '}
                    {isAr ? 'سليمة' : 'clean'}
                  </span>
                  <span className="ms-auto">
                    <Mono>{(threatShare * 100).toFixed(1)}%</Mono>
                  </span>
                </div>
              </div>
            );
          })}
        </div>
      </Glass>

      {/* Flow */}
      <Glass className="relative overflow-hidden p-3 lg:col-span-5">
        <div className="flex items-center justify-between">
          <Label>{isAr ? 'تدفّق التخفيف التدريجي' : 'Progressive mitigation flow'}</Label>
          <span className="text-[8px] text-slate-500">
            {isAr ? 'المجموع ' : 'total '}
            <Mono>{formatCount(totalTier)}</Mono>
          </span>
        </div>

        {shown.length === 0 || totalTier === 0 ? (
          <p className="py-16 text-center text-[10px] leading-relaxed text-slate-500">
            {isAr
              ? 'لا تدفّق يُرسم: نقاط النهاية أو أعداد التخفيف غير متوفّرة. لا تُرسم مسارات لم تُقَس.'
              : 'Nothing to draw: endpoints or mitigation counts are unavailable. Unmeasured paths are not drawn.'}
          </p>
        ) : (
          <svg
            viewBox="0 0 320 240"
            className="mt-2 w-full"
            role="img"
            aria-label={
              isAr
                ? `تدفّق من ${shown.length} نقطة نهاية إلى ثلاث طبقات تخفيف، المجموع ${totalTier}`
                : `Flow from ${shown.length} endpoints into three mitigation tiers, total ${totalTier}`
            }
          >
            <defs>
              {tiers.map(t => (
                <linearGradient key={t.id} id={`cd-flow-${t.id}`} x1="0" y1="0" x2="1" y2="0">
                  <stop offset="0%" stopColor={t.color} stopOpacity="0.05" />
                  <stop offset="55%" stopColor={t.color} stopOpacity="0.45" />
                  <stop offset="100%" stopColor={t.color} stopOpacity="0.75" />
                </linearGradient>
              ))}
            </defs>

            {/* Source stubs and labels */}
            {shown.map((e, i) => {
              const y = 22 + i * 34;
              return (
                <g key={e.endpoint}>
                  <rect x="4" y={y - 8} width="8" height="16" rx="2" fill="rgba(56,189,248,0.35)" />
                  <text x="18" y={y + 3} fill="#93a1b3" fontSize="7" style={{ fontFamily: 'var(--font-mono)' }}>
                    {e.endpoint.length > 22 ? `${e.endpoint.slice(0, 21)}…` : e.endpoint}
                  </text>
                </g>
              );
            })}

            {/* Ribbons — thickness is endpoint share times tier share, both real */}
            {shown.map((e, i) => {
              const y0 = 22 + i * 34;
              return tiers.map((t, ti) => {
                if (t.v == null || t.v <= 0) return null;
                const share = t.v / totalTier;
                const y1 = 46 + ti * 74;
                const thickness = Math.max(0.8, share * 14 * (e.hits / maxHits) + 0.6);
                return (
                  <path
                    key={`${e.endpoint}-${t.id}`}
                    d={`M 132 ${y0} C 190 ${y0}, 196 ${y1}, 252 ${y1}`}
                    stroke={`url(#cd-flow-${t.id})`}
                    strokeWidth={thickness}
                    fill="none"
                    strokeLinecap="round"
                  />
                );
              });
            })}

            {/* Tier nodes */}
            {tiers.map((t, ti) => {
              const y = 46 + ti * 74;
              return (
                <g key={t.id}>
                  <rect
                    x="252"
                    y={y - 16}
                    width="62"
                    height="32"
                    rx="5"
                    fill="rgba(255,255,255,0.04)"
                    stroke={t.color}
                    strokeOpacity="0.45"
                  />
                  <text
                    x="283"
                    y={y - 3}
                    fill="#e6edf3"
                    fontSize="9"
                    textAnchor="middle"
                    style={{ fontFamily: 'var(--font-mono)', fontWeight: 700 }}
                  >
                    {t.v != null ? formatCount(t.v) : '—'}
                  </text>
                  <text x="283" y={y + 8} fill="#6b7a90" fontSize="6" textAnchor="middle">
                    {t.label}
                  </text>
                </g>
              );
            })}
          </svg>
        )}

        {!reduce && (
          <motion.div
            className="pointer-events-none absolute inset-0"
            style={{ background: 'linear-gradient(90deg, transparent, rgba(56,189,248,0.05), transparent)' }}
            animate={{ x: ['-60%', '160%'] }}
            transition={{ duration: 5, repeat: Infinity, ease: 'linear' }}
            aria-hidden
          />
        )}
      </Glass>

      {/* Anomaly window */}
      <Glass className="p-3 lg:col-span-3">
        <div className="flex items-center gap-1.5">
          <ShieldAlert className="h-3.5 w-3.5 text-[#F59E0B]" aria-hidden />
          <Label>{isAr ? 'كشف الشذوذ' : 'Anomaly detection'}</Label>
        </div>
        <dl className="mt-2.5 space-y-1.5">
          <Row k={isAr ? 'حكم الانحراف' : 'Drift verdict'} v={d.drift.verdict?.replace(/_/g, ' ') ?? null} small />
          <Row k="PSI" v={d.drift.maxPsi} />
          <Row k={isAr ? 'السمة المحرّكة' : 'Driving feature'} v={d.drift.drivingFeature} small />
          <Row k={isAr ? 'حجب نشط' : 'Active blackholes'} v={d.kernel.blackholes} />
          <Row k={isAr ? 'عناوين معزولة' : 'Quarantined IPs'} v={d.agent.quarantined} />
          <Row k={isAr ? 'مصائد' : 'Trapped'} v={d.agent.trapped} />
          <Row k={isAr ? 'بصمات نشطة' : 'Signatures'} v={d.agent.signatures} />
        </dl>
        {d.posture.zeroEgress === true && (
          <div className="mt-2.5 rounded-lg border border-[#10B981]/25 bg-[#10B981]/8 px-2 py-1.5">
            <p className="text-[8px] font-semibold text-[#6ee7b7]">
              {isAr ? 'صفر نداءات خارجية — مقروء من الإعداد' : 'ZERO EXTERNAL CALLS — read from config'}
            </p>
          </div>
        )}
        {d.posture.zeroEgress === false && (
          <div className="mt-2.5 rounded-lg border border-[#F59E0B]/25 bg-[#F59E0B]/8 px-2 py-1.5">
            <p className="text-[8px] font-semibold text-[#fcd34d]">
              {isAr ? 'الخروج ممكن بالإعداد الحالي' : 'EGRESS POSSIBLE IN CURRENT CONFIG'}
            </p>
          </div>
        )}
      </Glass>
    </div>
  );
};
