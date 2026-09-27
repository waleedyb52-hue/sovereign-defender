import React from 'react';
import { Mono } from './parts';

/**
 * GLOW SPARKLINE — the reference's smooth luminous trend line
 *
 * The reference's right-hand panel was a soft glowing curve in cyan and white with
 * annotation points marking named locations along it. Bars were standing in for it,
 * which carried the numbers but not the form, so this is the form: a Catmull-Rom
 * smoothed path, a gradient fill beneath, a blur-backed glow stroke, and labelled
 * markers on the points worth naming.
 *
 * Why Catmull-Rom rather than a polyline or a bezier guess
 *   A polyline through fifteen samples reads as jagged telemetry, which is not what
 *   the reference looks like. Catmull-Rom passes exactly through every data point
 *   while producing a continuous curve, so the smoothing is presentational and never
 *   moves a value. A hand-tuned bezier would bend away from the data, which for a
 *   telemetry chart means drawing a reading that was not taken.
 *
 * On the annotations
 *   The reference labelled cities. This labels the peak and the most recent sample,
 *   because those are the two points an operator actually looks for in a trend, and
 *   labelling every point would produce the illusion of more resolution than fifteen
 *   samples carry.
 *
 * An empty or single-point series draws nothing and says so. Two points are the
 * minimum for a trend, and one sample rendered as a flat line is a claim about
 * stability that a single observation cannot support.
 */

export interface SparkPoint {
  label: string;
  value: number;
  /** Secondary series drawn as a fainter line, e.g. the hostile subset. */
  secondary?: number;
}

interface Props {
  points: SparkPoint[];
  isAr: boolean;
  height?: number;
  /** Accent for the primary curve. */
  accent?: string;
  /** Accent for the secondary curve, when the points carry one. */
  secondaryAccent?: string;
  unit?: string;
  ariaLabel?: string;
}

/** Catmull-Rom through every point, emitted as cubic segments. */
function smoothPath(pts: Array<{ x: number; y: number }>): string {
  if (pts.length === 0) return '';
  if (pts.length === 1) return `M ${pts[0].x},${pts[0].y}`;
  let d = `M ${pts[0].x},${pts[0].y}`;
  for (let i = 0; i < pts.length - 1; i++) {
    const p0 = pts[i - 1] ?? pts[i];
    const p1 = pts[i];
    const p2 = pts[i + 1];
    const p3 = pts[i + 2] ?? p2;
    // Tension 1/6 is the standard uniform Catmull-Rom to Bezier conversion.
    const c1x = p1.x + (p2.x - p0.x) / 6;
    const c1y = p1.y + (p2.y - p0.y) / 6;
    const c2x = p2.x - (p3.x - p1.x) / 6;
    const c2y = p2.y - (p3.y - p1.y) / 6;
    d += ` C ${c1x.toFixed(2)},${c1y.toFixed(2)} ${c2x.toFixed(2)},${c2y.toFixed(2)} ${p2.x.toFixed(2)},${p2.y.toFixed(2)}`;
  }
  return d;
}

export const GlowSparkline: React.FC<Props> = ({
  points,
  isAr,
  height = 96,
  accent = '#38BDF8',
  secondaryAccent = '#EF4444',
  unit = '',
  ariaLabel
}) => {
  const uid = React.useId().replace(/:/g, '');
  const W = 300;
  const padX = 10;
  const padTop = 14;
  const padBottom = 20;

  if (points.length < 2) {
    return (
      <p className="py-8 text-center text-[9px] leading-relaxed text-slate-500">
        {isAr
          ? 'نقطتان على الأقل لازمتان لرسم اتجاه. عيّنة واحدة كخطّ مستقيم ادّعاءُ استقرارٍ لا تحمله ملاحظة واحدة.'
          : 'A trend needs at least two points. One sample drawn flat is a claim about stability a single observation cannot support.'}
      </p>
    );
  }

  const values = points.map(p => p.value);
  const secondaries = points.map(p => p.secondary).filter((v): v is number => typeof v === 'number');
  const hasSecondary = secondaries.length === points.length;

  const max = Math.max(1, ...values, ...secondaries);
  const min = Math.min(0, ...values, ...secondaries);
  const span = Math.max(1, max - min);

  const xOf = (i: number) => padX + (i / (points.length - 1)) * (W - padX * 2);
  const yOf = (v: number) => padTop + (1 - (v - min) / span) * (height - padTop - padBottom);

  const main = points.map((p, i) => ({ x: xOf(i), y: yOf(p.value) }));
  const sec = hasSecondary ? points.map((p, i) => ({ x: xOf(i), y: yOf(p.secondary as number) })) : [];

  const mainPath = smoothPath(main);
  const areaPath = `${mainPath} L ${main[main.length - 1].x},${height - padBottom} L ${main[0].x},${height - padBottom} Z`;

  // The two points worth naming: the peak and the latest.
  const peakIdx = values.indexOf(Math.max(...values));
  const lastIdx = points.length - 1;
  const marks = [...new Set([peakIdx, lastIdx])];

  return (
    <div>
      <svg
        viewBox={`0 0 ${W} ${height}`}
        className="w-full"
        role="img"
        aria-label={
          ariaLabel ??
          (isAr
            ? `اتجاه على ${points.length} عيّنة، الذروة ${max}${unit} عند ${points[peakIdx].label}`
            : `Trend over ${points.length} samples, peak ${max}${unit} at ${points[peakIdx].label}`)
        }
      >
        <defs>
          <linearGradient id={`spark-fill-${uid}`} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor={accent} stopOpacity="0.32" />
            <stop offset="70%" stopColor={accent} stopOpacity="0.04" />
            <stop offset="100%" stopColor={accent} stopOpacity="0" />
          </linearGradient>
          <filter id={`spark-glow-${uid}`} x="-20%" y="-40%" width="140%" height="200%">
            <feGaussianBlur stdDeviation="2.4" result="b" />
            <feMerge>
              <feMergeNode in="b" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
        </defs>

        {/* Baseline */}
        <line
          x1={padX}
          y1={height - padBottom}
          x2={W - padX}
          y2={height - padBottom}
          stroke="rgba(255,255,255,0.08)"
          strokeWidth="0.7"
        />

        <path d={areaPath} fill={`url(#spark-fill-${uid})`} />

        {/* Secondary series first, so the primary reads on top. */}
        {hasSecondary && (
          <path
            d={smoothPath(sec)}
            fill="none"
            stroke={secondaryAccent}
            strokeWidth="1.1"
            strokeOpacity="0.65"
            strokeDasharray="3 2"
            strokeLinecap="round"
          />
        )}

        {/* The glow stroke, then a crisp one over it. */}
        <path
          d={mainPath}
          fill="none"
          stroke={accent}
          strokeWidth="2.2"
          strokeLinecap="round"
          strokeOpacity="0.55"
          filter={`url(#spark-glow-${uid})`}
        />
        <path d={mainPath} fill="none" stroke="#FFFFFF" strokeWidth="1" strokeLinecap="round" strokeOpacity="0.9" />

        {/* Annotated markers */}
        {marks.map(i => (
          <g key={i}>
            <circle cx={xOf(i)} cy={yOf(values[i])} r="3.2" fill="#FFFFFF" />
            <circle cx={xOf(i)} cy={yOf(values[i])} r="6" fill="none" stroke={accent} strokeOpacity="0.5" strokeWidth="0.8" />
            <text
              x={Math.min(W - 44, Math.max(4, xOf(i) - 14))}
              y={Math.max(9, yOf(values[i]) - 8)}
              fill="#c2ccd9"
              fontSize="6.5"
              style={{ fontFamily: 'var(--font-mono)' }}
            >
              {values[i]}
              {unit}
            </text>
          </g>
        ))}

        {/* First and last labels only — fifteen samples cannot carry more. */}
        <text x={padX} y={height - 6} fill="#6b7a90" fontSize="6" style={{ fontFamily: 'var(--font-mono)' }}>
          {points[0].label}
        </text>
        <text
          x={W - padX}
          y={height - 6}
          fill="#6b7a90"
          fontSize="6"
          textAnchor="end"
          style={{ fontFamily: 'var(--font-mono)' }}
        >
          {points[lastIdx].label}
        </text>
      </svg>

      <div className="mt-1 flex items-center justify-between text-[8px] text-slate-500">
        <span>
          {isAr ? 'الذروة ' : 'peak '}
          <Mono className="text-white">
            {max}
            {unit}
          </Mono>
          {' · '}
          {points[peakIdx].label}
        </span>
        {hasSecondary && (
          <span className="flex items-center gap-1.5">
            <svg width="14" height="3" aria-hidden>
              <line x1="0" y1="1.5" x2="14" y2="1.5" stroke={secondaryAccent} strokeWidth="1.1" strokeDasharray="3 2" />
            </svg>
            {isAr ? 'العدائية' : 'hostile'}
          </span>
        )}
      </div>
    </div>
  );
};
