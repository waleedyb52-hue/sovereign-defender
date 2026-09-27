import React from 'react';
import { motion } from 'motion/react';
import { Glass, Label, Mono } from './parts';
import { formatCount } from '../../../lib/utils';
import type { CyberDefendData } from './useCyberDefendData';

/**
 * ENDPOINT RISK SCATTER — the reference's scatter plot, with real axes
 *
 * The reference plotted "costs per household" across red, orange and green severity
 * zones. The shape is what was asked for, so the shape is what this reproduces: a
 * two-axis scatter with banded risk regions and a colour per band.
 *
 * The axes are this platform's own, and they were chosen because together they say
 * something an operator cannot read off a bar chart:
 *
 *   x — requests observed on the endpoint (log-scaled, since volume spans orders
 *       of magnitude and a linear axis would collapse everything but the busiest)
 *   y — share of those requests that were hostile
 *
 * The interesting quadrant is top-right: high volume AND high hostile share. That is
 * an endpoint under sustained attack, and it is invisible in either axis alone — a
 * busy endpoint with a low share is normal traffic, and a quiet one with a high
 * share is a probe nobody is pressing. Plotting them together is the whole point.
 *
 * Bands are drawn from stated thresholds rather than tuned to make the data look
 * tidy, and the thresholds are printed in the legend so a viewer can disagree with
 * where the lines fall.
 */

/** Hostile share above which an endpoint is treated as under attack. */
const CRITICAL_SHARE = 0.3;
/** Hostile share above which it warrants attention. */
const WARN_SHARE = 0.1;

interface Props {
  d: CyberDefendData;
  isAr: boolean;
  reduce: boolean;
}

export const EndpointRiskScatter: React.FC<Props> = ({ d, isAr, reduce }) => {
  const [hover, setHover] = React.useState<number | null>(null);

  const points = d.endpoints
    .filter(e => e.hits > 0)
    .map(e => ({
      endpoint: e.endpoint,
      hits: e.hits,
      share: e.threatHits / e.hits,
      threatHits: e.threatHits
    }));

  const maxHits = Math.max(1, ...points.map(p => p.hits));
  // Log scale: volume spans orders of magnitude, and a linear axis would push every
  // endpoint but the busiest into the left margin.
  const xOf = (hits: number) => {
    const t = Math.log10(Math.max(1, hits)) / Math.log10(Math.max(10, maxHits));
    return 42 + t * 236;
  };
  const yOf = (share: number) => 150 - Math.min(1, share) * 128;

  const bandOf = (share: number) =>
    share >= CRITICAL_SHARE ? '#EF4444' : share >= WARN_SHARE ? '#F59E0B' : '#10B981';

  const W = 300;
  const H = 172;

  return (
    <Glass className="p-3">
      <div className="flex items-center justify-between">
        <Label>{isAr ? 'مخطّط خطورة نقاط النهاية' : 'Endpoint risk scatter'}</Label>
        <span className="text-[8px] text-slate-500">
          {isAr ? `${points.length} نقطة` : `${points.length} points`}
        </span>
      </div>

      {points.length === 0 ? (
        <p className="py-12 text-center text-[10px] text-slate-500">
          {isAr ? 'لا بيانات من ' : 'No data from '}
          <Mono className="text-[9px]">/soc/analytics</Mono>
        </p>
      ) : (
        <>
          <svg
            viewBox={`0 0 ${W} ${H}`}
            className="mt-2 w-full"
            role="img"
            aria-label={
              isAr
                ? `مخطّط تشتّت: ${points.length} نقطة نهاية، المحور الأفقي حجم الطلبات والعمودي نسبة الحركة العدائية`
                : `Scatter: ${points.length} endpoints, x is request volume and y is hostile share`
            }
          >
            {/* Risk bands. Drawn behind the data, from stated thresholds. */}
            <rect x="42" y={yOf(1)} width="236" height={yOf(CRITICAL_SHARE) - yOf(1)} fill="rgba(239,68,68,0.07)" />
            <rect
              x="42"
              y={yOf(CRITICAL_SHARE)}
              width="236"
              height={yOf(WARN_SHARE) - yOf(CRITICAL_SHARE)}
              fill="rgba(245,158,11,0.06)"
            />
            <rect x="42" y={yOf(WARN_SHARE)} width="236" height={yOf(0) - yOf(WARN_SHARE)} fill="rgba(16,185,129,0.05)" />

            {/* Threshold rules */}
            {[CRITICAL_SHARE, WARN_SHARE].map(t => (
              <g key={t}>
                <line
                  x1="42"
                  y1={yOf(t)}
                  x2="278"
                  y2={yOf(t)}
                  stroke={t === CRITICAL_SHARE ? 'rgba(239,68,68,0.4)' : 'rgba(245,158,11,0.35)'}
                  strokeWidth="0.7"
                  strokeDasharray="3 3"
                />
                <text x="36" y={yOf(t) + 3} fill="#6b7a90" fontSize="6" textAnchor="end"
                  style={{ fontFamily: 'var(--font-mono)' }}>
                  {(t * 100).toFixed(0)}%
                </text>
              </g>
            ))}

            {/* Axes */}
            <line x1="42" y1="150" x2="278" y2="150" stroke="rgba(255,255,255,0.12)" strokeWidth="0.8" />
            <line x1="42" y1="22" x2="42" y2="150" stroke="rgba(255,255,255,0.12)" strokeWidth="0.8" />
            <text x="160" y="166" fill="#6b7a90" fontSize="6.5" textAnchor="middle">
              {isAr ? 'حجم الطلبات (لوغاريتمي)' : 'request volume (log)'}
            </text>
            <text x="12" y="88" fill="#6b7a90" fontSize="6.5" textAnchor="middle" transform="rotate(-90 12 88)">
              {isAr ? 'نسبة العدائية' : 'hostile share'}
            </text>

            {/* Points */}
            {points.map((p, i) => {
              const cx = xOf(p.hits);
              const cy = yOf(p.share);
              const c = bandOf(p.share);
              const active = hover === i;
              return (
                <g key={p.endpoint}>
                  {/* Halo for the critical band, so the eye lands there first. */}
                  {p.share >= CRITICAL_SHARE && !reduce && (
                    <motion.circle
                      cx={cx}
                      cy={cy}
                      r={7}
                      fill="none"
                      stroke={c}
                      strokeWidth="0.8"
                      animate={{ r: [5, 11], opacity: [0.5, 0] }}
                      transition={{ duration: 1.8, repeat: Infinity, ease: 'easeOut' }}
                    />
                  )}
                  <circle
                    cx={cx}
                    cy={cy}
                    r={active ? 5.5 : 4}
                    fill={c}
                    fillOpacity={active ? 1 : 0.75}
                    stroke="rgba(255,255,255,0.5)"
                    strokeWidth={active ? 1 : 0.5}
                    onMouseEnter={() => setHover(i)}
                    onMouseLeave={() => setHover(null)}
                    style={{ cursor: 'default' }}
                  />
                </g>
              );
            })}
          </svg>

          {/* Readout for the hovered point */}
          <div className="mt-1 min-h-[30px] rounded-lg border border-white/8 bg-white/[0.02] px-2 py-1.5">
            {hover != null && points[hover] ? (
              <>
                <Mono className="block truncate text-[9px] text-slate-200">{points[hover].endpoint}</Mono>
                <div className="mt-0.5 flex gap-3 text-[8px] text-slate-500">
                  <span>
                    <Mono className="text-white">{formatCount(points[hover].hits)}</Mono> {isAr ? 'طلب' : 'requests'}
                  </span>
                  <span>
                    <Mono className="text-[#fca5a5]">{formatCount(points[hover].threatHits)}</Mono>{' '}
                    {isAr ? 'عدائي' : 'hostile'}
                  </span>
                  <span>
                    {/* Inline colour, so the band the point falls in is visible in
                        the readout too — colour here repeats information the y
                        position already carries rather than replacing it. */}
                    <span
                      className="tabular-nums"
                      style={{ fontFamily: 'var(--font-mono)', color: bandOf(points[hover].share) }}
                      dir="ltr"
                    >
                      {(points[hover].share * 100).toFixed(1)}%
                    </span>
                  </span>
                </div>
              </>
            ) : (
              <p className="text-[8px] leading-relaxed text-slate-600">
                {isAr
                  ? `مرّر على نقطة للتفاصيل. الربع الأعلى يميناً هو المهم: حجم عالٍ ونسبة عدائية عالية معاً — وهو غير مرئي في أيّ محور بمفرده. الحدود: ${WARN_SHARE * 100}% و ${CRITICAL_SHARE * 100}%.`
                  : `Hover a point for detail. Top-right is what matters: high volume AND high hostile share together, which neither axis shows alone. Thresholds: ${WARN_SHARE * 100}% and ${CRITICAL_SHARE * 100}%.`}
              </p>
            )}
          </div>
        </>
      )}
    </Glass>
  );
};
