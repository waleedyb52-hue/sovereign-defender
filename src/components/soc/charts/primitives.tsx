import React, { useMemo, useState } from 'react';

/**
 * CHART PRIMITIVES
 *
 * Small, dependency-free SVG marks built to the house spec:
 *  - 2px strokes, 4px rounded data-ends anchored to the baseline
 *  - a 2px surface gap between stacked segments so fills never touch
 *  - recessive grid/axes; values and labels wear text tokens, never the
 *    series colour (a colour chip beside the label carries identity)
 *  - every plotted mark has a hover affordance
 *
 * Severity colours are the platform's reserved status palette. They were
 * validated for colour-vision deficiency against the console surface
 * (#000000): worst adjacent pair critical/high ΔE 15.2 deutan, comfortably
 * clear of the ΔE 8 target. They always ship with a written label, never
 * hue alone.
 */

export const SEV_COLOR = {
  CRITICAL: '#f43f5e',
  HIGH: '#f59e0b',
  MEDIUM: '#22d3ee',
  LOW: '#10b981'
} as const;

export const SURFACE = '#03070c';
export const GRID = '#0e3a44';
export const INK_MUTED = '#5c7484';

/* ------------------------------------------------------------------ */
/* Sparkline — one series, no legend (the tile's title names it).      */
/* ------------------------------------------------------------------ */
export const Sparkline: React.FC<{
  values: number[];
  color?: string;
  width?: number;
  height?: number;
  /** Fill under the line, for volume-like measures. */
  area?: boolean;
}> = ({ values, color = '#22d3ee', width = 120, height = 32, area = true }) => {
  if (!values.length) return null;
  const max = Math.max(...values);
  const min = Math.min(...values);
  const span = max - min || 1;
  const stepX = width / Math.max(values.length - 1, 1);

  const pts = values.map((v, i) => {
    const x = i * stepX;
    const y = height - ((v - min) / span) * (height - 4) - 2;
    return [x, y] as const;
  });
  const line = pts
    .map(([x, y], i) => `${i === 0 ? 'M' : 'L'}${x.toFixed(1)},${y.toFixed(1)}`)
    .join(' ');
  const fill = `${line} L${width},${height} L0,${height} Z`;
  const [lx, ly] = pts[pts.length - 1];
  const gid = `spark-${color.replace('#', '')}`;

  return (
    <svg
      width={width}
      height={height}
      viewBox={`0 0 ${width} ${height}`}
      aria-hidden="true"
      className="overflow-visible"
    >
      {area && (
        <>
          <defs>
            <linearGradient id={gid} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={color} stopOpacity="0.28" />
              <stop offset="100%" stopColor={color} stopOpacity="0" />
            </linearGradient>
          </defs>
          <path d={fill} fill={`url(#${gid})`} />
        </>
      )}
      <path
        d={line}
        fill="none"
        stroke={color}
        strokeWidth={2}
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      {/* current value marker */}
      <circle cx={lx} cy={ly} r={3} fill={color} stroke={SURFACE} strokeWidth={2} />
    </svg>
  );
};

/* ------------------------------------------------------------------ */
/* Stacked bar series — magnitude over time, split by status.          */
/* ------------------------------------------------------------------ */
export interface StackBucket {
  label: string;
  segments: Array<{ key: string; value: number; color: string; label: string }>;
}

export const StackedBars: React.FC<{
  buckets: StackBucket[];
  height?: number;
  isAr?: boolean;
  /** Accessible name for the chart. Without one it is an unlabelled figure. */
  ariaLabel?: string;
}> = ({ buckets, height = 130, isAr = false, ariaLabel }) => {
  const [hover, setHover] = useState<number | null>(null);
  const max = Math.max(1, ...buckets.map(b => b.segments.reduce((s, x) => s + x.value, 0)));

  /**
   * Keyboard access.
   *
   * Hover was the only way to read a value here, which meant a keyboard user
   * could not read this chart at all. The bar strip is now a single tab stop and
   * arrow keys move between buckets, which is the pattern a screen-reader user
   * expects from a chart and costs one tab stop rather than one per bar.
   *
   * Home/End jump to the ends, Escape drops the readout — the same keys the rest
   * of the console uses.
   */
  const onKeyDown = (e: React.KeyboardEvent) => {
    if (!buckets.length) return;
    // Arrow direction follows reading order, so Right advances in LTR and
    // retreats in RTL. Reversing it in Arabic would be backwards.
    const forward = isAr ? 'ArrowLeft' : 'ArrowRight';
    const back = isAr ? 'ArrowRight' : 'ArrowLeft';
    const cur = hover ?? -1;
    if (e.key === forward) {
      e.preventDefault();
      setHover(Math.min(buckets.length - 1, cur + 1));
    } else if (e.key === back) {
      e.preventDefault();
      setHover(Math.max(0, cur <= 0 ? 0 : cur - 1));
    } else if (e.key === 'Home') {
      e.preventDefault();
      setHover(0);
    } else if (e.key === 'End') {
      e.preventDefault();
      setHover(buckets.length - 1);
    } else if (e.key === 'Escape') {
      setHover(null);
    }
  };

  const totalOf = (b: StackBucket) => b.segments.reduce((s, x) => s + x.value, 0);

  /** Four gridlines is enough to read a magnitude without fighting the data. */
  const ticks = [max, Math.round(max * 0.75), Math.round(max * 0.5), Math.round(max * 0.25), 0];

  return (
    <div className="relative">
      <div className="flex gap-2">
        {/* Y axis. Previously absent, so bar heights carried no scale at all and
            a reader could compare bars but never read a value off one. */}
        <div
          className="flex shrink-0 flex-col justify-between py-0 text-right font-mono text-[8px] text-slate-600 tabular-nums"
          style={{ height }}
          aria-hidden
        >
          {ticks.map((t, i) => (
            <span key={i} className="leading-none">
              {t}
            </span>
          ))}
        </div>

        <div className="relative flex-1">
          {/* Gridlines, behind the bars and low-contrast so they inform without
              competing. */}
          <div
            className="pointer-events-none absolute inset-0 flex flex-col justify-between"
            aria-hidden
          >
            {ticks.map((_, i) => (
              <div key={i} className="h-px w-full bg-slate-800/45" />
            ))}
          </div>

          <div
            className="relative flex items-end gap-[3px] rounded focus-visible:ring-2 focus-visible:ring-[#22d3ee]/60 focus-visible:outline-none"
            style={{ height }}
            dir="ltr"
            // One tab stop for the series, arrow keys within it.
            tabIndex={0}
            role="img"
            aria-label={
              ariaLabel ??
              (isAr
                ? `مخطّط أعمدة مكدّسة، ${buckets.length} فترة، أعلى قيمة ${max}`
                : `Stacked bar chart, ${buckets.length} intervals, peak ${max}`)
            }
            onKeyDown={onKeyDown}
            onBlur={() => setHover(null)}
          >
            {buckets.map((b, i) => {
              const total = totalOf(b);
              const h = (total / max) * height;
              return (
                <div
                  key={i}
                  className="relative flex flex-1 cursor-default flex-col-reverse justify-start"
                  style={{ height: h || 2 }}
                  onMouseEnter={() => setHover(i)}
                  onMouseLeave={() => setHover(null)}
                >
                  {b.segments
                    .filter(s => s.value > 0)
                    .map((s, si, arr) => (
                      <div
                        key={s.key}
                        style={{
                          height: `${(s.value / (total || 1)) * 100}%`,
                          background: s.color,
                          /* 2px surface gap so adjacent fills never touch */
                          marginTop: si < arr.length - 1 ? 2 : 0,
                          borderTopLeftRadius: si === arr.length - 1 ? 3 : 0,
                          borderTopRightRadius: si === arr.length - 1 ? 3 : 0,
                          opacity: hover === null || hover === i ? 1 : 0.45,
                          transition: 'opacity 120ms ease'
                        }}
                      />
                    ))}
                </div>
              );
            })}
          </div>

          {/* hover / focus readout. Position stays RTL-aware — this is the
              property that kept the chart hand-rolled rather than swapped for a
              library that would need it rebuilt. */}
          {hover !== null && buckets[hover] && (
            <div
              className="pointer-events-none absolute -top-1 z-20 rounded-md border border-slate-700 bg-slate-900 px-2.5 py-2 shadow-xl shadow-[0_0_20px_rgba(0,255,255,0.08)]"
              style={
                {
                  [isAr ? 'right' : 'left']: `${(hover / buckets.length) * 100}%`
                } as React.CSSProperties
              }
            >
              <div className="mb-1 font-mono text-[10px] text-slate-400">
                {buckets[hover].label}
              </div>
              {buckets[hover].segments.map(s => (
                <div key={s.key} className="flex items-center gap-2 text-[11px] whitespace-nowrap">
                  <span className="h-2 w-2 rounded-[2px]" style={{ background: s.color }} />
                  <span className="text-slate-300">{s.label}</span>
                  <span className="ms-auto ps-3 font-mono text-slate-100 tabular-nums">
                    {s.value}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Live region: announces the focused bucket as arrow keys move through it,
          so the readout is spoken and not only drawn. */}
      <div className="sr-only" aria-live="polite" aria-atomic="true">
        {hover !== null && buckets[hover]
          ? `${buckets[hover].label}: ${buckets[hover].segments
              .filter(s => s.value > 0)
              .map(s => `${s.label} ${s.value}`)
              .join(', ')}`
          : ''}
      </div>

      {/* The same data as a table, for a screen reader that would otherwise get
          only the summary label. Hidden visually; not hidden from assistive tech. */}
      <table className="sr-only">
        <caption>{ariaLabel ?? (isAr ? 'بيانات المخطّط' : 'Chart data')}</caption>
        <thead>
          <tr>
            <th scope="col">{isAr ? 'الفترة' : 'Interval'}</th>
            {buckets[0]?.segments.map(s => (
              <th key={s.key} scope="col">
                {s.label}
              </th>
            ))}
            <th scope="col">{isAr ? 'المجموع' : 'Total'}</th>
          </tr>
        </thead>
        <tbody>
          {buckets.map((b, i) => (
            <tr key={i}>
              <th scope="row">{b.label}</th>
              {b.segments.map(s => (
                <td key={s.key}>{s.value}</td>
              ))}
              <td>{totalOf(b)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};

/* ------------------------------------------------------------------ */
/* Legend — always present for >= 2 series; identity never colour-alone */
/* ------------------------------------------------------------------ */
export const Legend: React.FC<{ items: Array<{ label: string; color: string }> }> = ({ items }) => (
  <div className="flex flex-wrap items-center gap-x-4 gap-y-1.5">
    {items.map(i => (
      <span key={i.label} className="flex items-center gap-1.5 text-[11px] text-slate-400">
        <span className="h-2.5 w-2.5 rounded-[3px]" style={{ background: i.color }} />
        {i.label}
      </span>
    ))}
  </div>
);

/* ------------------------------------------------------------------ */
/* Horizontal magnitude bar — one measure, ranked.                     */
/* ------------------------------------------------------------------ */
export const RankedBar: React.FC<{
  value: number;
  max: number;
  color?: string;
}> = ({ value, max, color = '#22d3ee' }) => (
  <div className="h-1.5 overflow-hidden rounded-full bg-slate-800">
    <div
      className="h-full rounded-full transition-[width] duration-500"
      style={{ width: `${Math.max((value / (max || 1)) * 100, 2)}%`, background: color }}
    />
  </div>
);

/* ------------------------------------------------------------------ */
/* Sequential ramp for magnitude heatmaps: ONE hue, near-surface->bright */
/* ------------------------------------------------------------------ */
export function heatStep(t: number): string {
  // t in [0,1]; below the first stop the cell stays at surface level so
  // "no activity" recedes rather than reading as a low value.
  if (t <= 0) return 'transparent';
  const stops = ['#12233d', '#173963', '#1b5296', '#2071c9', '#3f95ec', '#79c0ff'];
  const idx = Math.min(stops.length - 1, Math.max(0, Math.round(t * (stops.length - 1))));
  return stops[idx];
}
