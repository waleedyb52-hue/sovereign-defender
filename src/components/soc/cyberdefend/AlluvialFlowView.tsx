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
    { id: 'tier1', label: isAr ? 'تحديد المعدّل' : 'Rate limited', v: d.mitigation.tier1, color: '#22d3ee' },
    { id: 'tier2', label: isAr ? 'تحدٍّ' : 'Challenged', v: d.mitigation.tier2, color: '#F59E0B' },
    { id: 'tier3', label: isAr ? 'حجب حرج' : 'Critical blocked', v: d.mitigation.tier3, color: '#f43f5e' }
  ];
  const totalTier = tiers.reduce((a, t) => a + (t.v ?? 0), 0);
  const maxHits = Math.max(1, ...d.endpoints.map(e => e.hits));
  const shown = d.endpoints.slice(0, 6);
  /**
   * The middle column. Real retained families, which is what genuinely sits between
   * a request and the tier that stopped it — the reference's ground stations had no
   * equivalent here, and inventing station names would have been fabricated topology.
   */
  const families = d.families.slice(0, 5);
  const maxFamCount = Math.max(1, ...families.map(f => f.count));
  const midGap = families.length > 1 ? Math.min(44, 190 / (families.length - 1)) : 0;

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
                    <Mono className="text-[#fda4af]">{formatCount(e.threatHits)}</Mono>{' '}
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
            viewBox="0 0 340 250"
            className="mt-2 w-full"
            role="img"
            aria-label={
              isAr
                ? `تدفّق من ${shown.length} نقطة نهاية عبر ${families.length} عائلة إلى ثلاث طبقات تخفيف، المجموع ${totalTier}`
                : `Flow from ${shown.length} endpoints through ${families.length} families into three mitigation tiers, total ${totalTier}`
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
              <linearGradient id="cd-flow-mid" x1="0" y1="0" x2="1" y2="0">
                <stop offset="0%" stopColor="#22d3ee" stopOpacity="0.08" />
                <stop offset="100%" stopColor="#8aa4b8" stopOpacity="0.4" />
              </linearGradient>
            </defs>

            {/* Column headers, so the three stages are named rather than inferred */}
            <text x="4" y="10" fill="#5c7484" fontSize="6" style={{ letterSpacing: '0.08em' }}>
              {isAr ? 'نقاط النهاية' : 'ENDPOINTS'}
            </text>
            <text x="126" y="10" fill="#5c7484" fontSize="6" style={{ letterSpacing: '0.08em' }}>
              {isAr ? 'العائلات' : 'FAMILIES'}
            </text>
            <text x="336" y="10" fill="#5c7484" fontSize="6" textAnchor="end" style={{ letterSpacing: '0.08em' }}>
              {isAr ? 'التخفيف' : 'MITIGATION'}
            </text>

            {/* Column 1 — sources */}
            {shown.map((e, i) => {
              const y = 26 + i * 32;
              return (
                <g key={e.endpoint}>
                  <rect x="4" y={y - 7} width="7" height="14" rx="2" fill="rgba(56,189,248,0.4)" />
                  <text x="15" y={y + 3} fill="#8aa4b8" fontSize="6.5" style={{ fontFamily: 'var(--font-mono)' }}>
                    {e.endpoint.length > 18 ? `${e.endpoint.slice(0, 17)}…` : e.endpoint}
                  </text>
                </g>
              );
            })}

            {/* Sources -> families. Thickness from the endpoint's share of hits. */}
            {shown.map((e, i) => {
              const y0 = 26 + i * 32;
              return families.map((f, fi) => {
                const y1 = 30 + fi * midGap;
                const w = Math.max(0.6, (e.hits / maxHits) * (f.count / maxFamCount) * 6 + 0.4);
                return (
                  <path
                    key={`${e.endpoint}-${f.family}`}
                    d={`M 112 ${y0} C 140 ${y0}, 142 ${y1}, 168 ${y1}`}
                    stroke="url(#cd-flow-mid)"
                    strokeWidth={w}
                    fill="none"
                    strokeLinecap="round"
                  />
                );
              });
            })}

            {/* Column 2 — the middle node column the reference has and this lacked.
                Real attack families with their retained counts, which is what
                actually sits between a request and the tier that stopped it. */}
            {families.map((f, fi) => {
              const y = 30 + fi * midGap;
              const clean = f.family === 'CLEAN_TRAFFIC';
              return (
                <g key={f.family}>
                  <rect
                    x="168"
                    y={y - 9}
                    width="74"
                    height="18"
                    rx="3"
                    fill="rgba(255,255,255,0.035)"
                    stroke={clean ? 'rgba(16,185,129,0.4)' : 'rgba(239,68,68,0.4)'}
                    strokeWidth="0.7"
                  />
                  <text x="173" y={y + 2.5} fill="#c2ccd9" fontSize="5.8">
                    {f.family.replace(/_/g, ' ').slice(0, 15)}
                  </text>
                  <text
                    x="238"
                    y={y + 2.5}
                    fill={clean ? '#6ee7b7' : '#fda4af'}
                    fontSize="6"
                    textAnchor="end"
                    style={{ fontFamily: 'var(--font-mono)', fontWeight: 700 }}
                  >
                    {f.count}
                  </text>
                </g>
              );
            })}

            {/* Families -> tiers */}
            {families.map((f, fi) => {
              const y0 = 30 + fi * midGap;
              return tiers.map((t, ti) => {
                if (t.v == null || t.v <= 0) return null;
                const share = t.v / totalTier;
                const y1 = 48 + ti * 76;
                const w = Math.max(0.7, share * 10 * (f.count / maxFamCount) + 0.5);
                return (
                  <path
                    key={`${f.family}-${t.id}`}
                    d={`M 242 ${y0} C 264 ${y0}, 266 ${y1}, 286 ${y1}`}
                    stroke={`url(#cd-flow-${t.id})`}
                    strokeWidth={w}
                    fill="none"
                    strokeLinecap="round"
                  />
                );
              });
            })}

            {/* Column 3 — destinations */}
            {tiers.map((t, ti) => {
              const y = 48 + ti * 76;
              return (
                <g key={t.id}>
                  <rect
                    x="286"
                    y={y - 16}
                    width="50"
                    height="32"
                    rx="5"
                    fill="rgba(255,255,255,0.04)"
                    stroke={t.color}
                    strokeOpacity="0.45"
                  />
                  <text
                    x="311"
                    y={y - 3}
                    fill="#e6edf3"
                    fontSize="8.5"
                    textAnchor="middle"
                    style={{ fontFamily: 'var(--font-mono)', fontWeight: 700 }}
                  >
                    {t.v != null ? formatCount(t.v) : '—'}
                  </text>
                  <text x="311" y={y + 8} fill="#5c7484" fontSize="5.2" textAnchor="middle">
                    {t.label.length > 14 ? `${t.label.slice(0, 13)}…` : t.label}
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
