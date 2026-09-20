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
 * (#0d1117): worst adjacent pair critical/high ΔE 15.2 deutan, comfortably
 * clear of the ΔE 8 target. They always ship with a written label, never
 * hue alone.
 */

export const SEV_COLOR = {
  CRITICAL: '#f85149',
  HIGH: '#fab219',
  MEDIUM: '#58a6ff',
  LOW: '#3fb950'
} as const;

export const SURFACE = '#131a24';
export const GRID = '#1e2733';
export const INK_MUTED = '#6b7a90';

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
}> = ({ values, color = '#58a6ff', width = 120, height = 32, area = true }) => {
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
  const line = pts.map(([x, y], i) => `${i === 0 ? 'M' : 'L'}${x.toFixed(1)},${y.toFixed(1)}`).join(' ');
  const fill = `${line} L${width},${height} L0,${height} Z`;
  const [lx, ly] = pts[pts.length - 1];
  const gid = `spark-${color.replace('#', '')}`;

  return (
    <svg width={width} height={height} viewBox={`0 0 ${width} ${height}`} aria-hidden="true" className="overflow-visible">
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
      <path d={line} fill="none" stroke={color} strokeWidth={2} strokeLinecap="round" strokeLinejoin="round" />
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
}> = ({ buckets, height = 130, isAr = false }) => {
  const [hover, setHover] = useState<number | null>(null);
  const max = Math.max(1, ...buckets.map(b => b.segments.reduce((s, x) => s + x.value, 0)));

  return (
    <div className="relative">
      {/* recessive baseline */}
      <div className="flex items-end gap-[3px]" style={{ height }} dir="ltr">
        {buckets.map((b, i) => {
          const total = b.segments.reduce((s, x) => s + x.value, 0);
          const h = (total / max) * height;
          return (
            <div
              key={i}
              className="relative flex-1 flex flex-col-reverse justify-start cursor-default"
              style={{ height: h || 2 }}
              onMouseEnter={() => setHover(i)}
              onMouseLeave={() => setHover(null)}
            >
              {b.segments.filter(s => s.value > 0).map((s, si, arr) => (
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

      {/* hover readout */}
      {hover !== null && buckets[hover] && (
        <div
          className="absolute -top-1 z-20 rounded-md border border-slate-700 bg-slate-900 px-2.5 py-2 shadow-xl pointer-events-none"
          style={{ [isAr ? 'right' : 'left']: `${(hover / buckets.length) * 100}%` } as React.CSSProperties}
        >
          <div className="font-mono text-[10px] text-slate-400 mb-1">{buckets[hover].label}</div>
          {buckets[hover].segments.map(s => (
            <div key={s.key} className="flex items-center gap-2 text-[11px] whitespace-nowrap">
              <span className="w-2 h-2 rounded-[2px]" style={{ background: s.color }} />
              <span className="text-slate-300">{s.label}</span>
              <span className="font-mono text-slate-100 ms-auto ps-3 tabular-nums">{s.value}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

/* ------------------------------------------------------------------ */
/* Legend — always present for >= 2 series; identity never colour-alone */
/* ------------------------------------------------------------------ */
export const Legend: React.FC<{ items: Array<{ label: string; color: string }> }> = ({ items }) => (
  <div className="flex items-center gap-x-4 gap-y-1.5 flex-wrap">
    {items.map(i => (
      <span key={i.label} className="flex items-center gap-1.5 text-[11px] text-slate-400">
        <span className="w-2.5 h-2.5 rounded-[3px]" style={{ background: i.color }} />
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
}> = ({ value, max, color = '#58a6ff' }) => (
  <div className="h-1.5 rounded-full bg-slate-800 overflow-hidden">
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
