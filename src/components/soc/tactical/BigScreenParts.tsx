import React from 'react';
import { Readout, HudValue, toneHex, CYAN, CRIMSON, type Tone } from './TacticalPrimitives';
import { cn } from '../../../lib/utils';

/**
 * BIG-SCREEN PARTS
 *
 * The pieces the reference boards are built from, which the first cockpit attempt
 * did not have: diamond KPI badges down the left edge, section headers whose rule
 * runs to the panel edge, donut breakdowns with leader lines, and dense data tables
 * with a cyan header row.
 *
 * The lesson from comparing the build against the references
 *   The first attempt made the globe a full-bleed background with sparse cards
 *   floating over it. The references do the opposite: the map is a contained element
 *   inside a structured grid, and every surrounding cell is packed. A big-screen
 *   board is read from across a room, so density is the point — empty space reads as
 *   missing instrumentation rather than as calm.
 *
 * Everything here keeps the project's absence discipline: a null value renders an em
 * dash with its reason, never a zero, and never a bar drawn at length zero which
 * would read as "measured, and it was nothing".
 */

/* ── Section header with an extending rule ───────────────────────────────── */

export const SectionHead: React.FC<{
  children: React.ReactNode;
  tone?: Tone;
  right?: React.ReactNode;
}> = ({ children, tone = 'cyan', right }) => {
  const hex = toneHex(tone);
  return (
    <div className="flex items-center gap-2">
      <span
        className="shrink-0 text-[9px] font-semibold tracking-[0.16em] uppercase"
        style={{ color: hex, fontFamily: 'var(--font-mono)', textShadow: `0 0 8px ${hex}55` }}
      >
        {children}
      </span>
      {/* The rule runs to the edge, with a tick at its end — the reference's cap. */}
      <span className="relative flex-1">
        <span className="block h-px w-full" style={{ background: `linear-gradient(90deg, ${hex}66, ${hex}0d)` }} />
        <span className="absolute end-0 top-1/2 h-1.5 w-px -translate-y-1/2" style={{ background: `${hex}88` }} />
      </span>
      {right && <span className="shrink-0">{right}</span>}
    </div>
  );
};

/* ── Diamond KPI badge ───────────────────────────────────────────────────── */

/**
 * The rotated-square badges down the reference's left edge.
 *
 * The frame is a rotated square; the contents are counter-rotated so the number
 * stays upright. Rotating the text with the frame looks striking in a mockup and is
 * unreadable on a wall display.
 */
export const DiamondKpi: React.FC<{
  value: number | string | null;
  label: string;
  tone?: Tone;
  reason?: string;
  icon?: React.ElementType;
}> = ({ value, label, tone = 'cyan', reason, icon: Icon }) => {
  const hex = toneHex(tone);
  return (
    <div className="flex items-center gap-2.5">
      <div className="relative h-[42px] w-[42px] shrink-0">
        <span
          className="absolute inset-[5px] rotate-45 border"
          style={{ borderColor: `${hex}66`, background: `${hex}0a`, boxShadow: `0 0 12px ${hex}22` }}
          aria-hidden
        />
        <span
          className="absolute inset-[11px] rotate-45 border"
          style={{ borderColor: `${hex}33` }}
          aria-hidden
        />
        {Icon && (
          <span className="absolute inset-0 grid place-items-center">
            <Icon className="h-3.5 w-3.5" strokeWidth={1.25} style={{ color: hex }} aria-hidden />
          </span>
        )}
      </div>
      <div className="min-w-0">
        <p
          className="truncate text-[7.5px] tracking-[0.14em] uppercase"
          style={{ color: `${hex}99`, fontFamily: 'var(--font-mono)' }}
        >
          {label}
        </p>
        <p className="leading-tight">
          <HudValue
            v={typeof value === 'number' ? value.toLocaleString('en-US') : value}
            tone={tone}
            glow
            reason={reason}
            className="text-[17px] font-bold"
          />
        </p>
      </div>
    </div>
  );
};

/* ── Donut with leader lines ─────────────────────────────────────────────── */

export interface DonutSlice {
  label: string;
  value: number;
  tone: Tone;
}

/**
 * Proportional breakdown, drawn as the reference's donut with labels on leaders.
 *
 * Slices below two percent are folded into an "other" bucket rather than drawn: a
 * one-pixel wedge with a leader line pointing at it implies a precision the geometry
 * cannot deliver, and it crowds the labels that matter.
 */
export const LeaderDonut: React.FC<{
  slices: DonutSlice[];
  size?: number;
  isAr: boolean;
  centreLabel?: string;
}> = ({ slices, size = 128, isAr, centreLabel }) => {
  const total = slices.reduce((a, s) => a + s.value, 0);

  if (total <= 0) {
    return (
      <p className="py-6 text-center text-[9px] text-slate-600" style={{ fontFamily: 'var(--font-mono)' }}>
        {isAr ? 'لا توزيع لعرضه' : 'no distribution to show'}
      </p>
    );
  }

  const major = slices.filter(s => s.value / total >= 0.02);
  const minorSum = slices.filter(s => s.value / total < 0.02).reduce((a, s) => a + s.value, 0);
  const shown: DonutSlice[] = minorSum > 0
    ? [...major, { label: isAr ? 'أخرى' : 'other', value: minorSum, tone: 'neutral' as Tone }]
    : major;

  const R = size / 2;
  const outer = R - 16;
  const inner = outer * 0.6;
  let acc = -Math.PI / 2;

  return (
    <div className="flex items-center justify-center">
      <svg
        viewBox={`0 0 ${size} ${size}`}
        style={{ width: size, height: size }}
        role="img"
        aria-label={
          isAr
            ? `توزيع على ${shown.length} فئة، المجموع ${total}`
            : `Breakdown across ${shown.length} categories, total ${total}`
        }
      >
        {shown.map(s => {
          const frac = s.value / total;
          const a0 = acc;
          const a1 = acc + frac * Math.PI * 2;
          acc = a1;
          const hex = toneHex(s.tone);
          const large = a1 - a0 > Math.PI ? 1 : 0;
          const p = (r: number, a: number) => `${R + Math.cos(a) * r} ${R + Math.sin(a) * r}`;
          const d = `M ${p(outer, a0)} A ${outer} ${outer} 0 ${large} 1 ${p(outer, a1)} L ${p(inner, a1)} A ${inner} ${inner} 0 ${large} 0 ${p(inner, a0)} Z`;
          const mid = (a0 + a1) / 2;
          const lx = R + Math.cos(mid) * (outer + 4);
          const ly = R + Math.sin(mid) * (outer + 4);
          const ex = R + Math.cos(mid) * (outer + 11);
          const ey = R + Math.sin(mid) * (outer + 11);
          const right = Math.cos(mid) >= 0;
          return (
            <g key={s.label}>
              <path d={d} fill={hex} fillOpacity="0.72" stroke={hex} strokeWidth="0.5" />
              <line x1={lx} y1={ly} x2={ex} y2={ey} stroke={`${hex}88`} strokeWidth="0.6" />
              <text
                x={right ? ex + 2 : ex - 2}
                y={ey + 2}
                fill="#93a1b3"
                fontSize="5.6"
                textAnchor={right ? 'start' : 'end'}
                style={{ fontFamily: 'var(--font-mono)' }}
              >
                {(frac * 100).toFixed(0)}%
              </text>
            </g>
          );
        })}
        {centreLabel && (
          <text
            x={R}
            y={R + 3}
            fill="#e6edf3"
            fontSize="9"
            textAnchor="middle"
            style={{ fontFamily: 'var(--font-mono)', fontWeight: 700 }}
          >
            {centreLabel}
          </text>
        )}
      </svg>

      <ul className="ms-2 space-y-0.5">
        {shown.slice(0, 6).map(s => (
          <li key={s.label} className="flex items-center gap-1.5">
            <span
              className="h-1.5 w-1.5 shrink-0"
              style={{ background: toneHex(s.tone), boxShadow: `0 0 5px ${toneHex(s.tone)}88` }}
              aria-hidden
            />
            <span className="max-w-[92px] truncate text-[7.5px] text-slate-400" title={s.label}>
              {s.label.replace(/_/g, ' ')}
            </span>
            <Readout className="ms-auto text-[7.5px] text-slate-500">{s.value}</Readout>
          </li>
        ))}
      </ul>
    </div>
  );
};

/* ── Dense data table ────────────────────────────────────────────────────── */

export interface TableColumn<T> {
  key: string;
  header: string;
  width?: string;
  tone?: Tone;
  render: (row: T) => React.ReactNode;
}

/**
 * The reference's threat list: a cyan header row over tight monospace rows.
 *
 * Row height is deliberately small. A big-screen board is read at distance and its
 * value is how many rows fit at once; generous padding halves the visible history
 * and buys nothing an operator wanted.
 */
export function DataTable<T>({
  rows,
  columns,
  emptyEndpoint,
  isAr,
  maxHeight = 168,
  onRowClick
}: {
  rows: T[];
  columns: Array<TableColumn<T>>;
  emptyEndpoint?: string;
  isAr: boolean;
  maxHeight?: number;
  onRowClick?: (row: T, i: number) => void;
}) {
  if (rows.length === 0) {
    return (
      <div className="py-6 text-center">
        <p className="text-[9px] text-slate-600">{isAr ? 'لا بيانات' : 'no data'}</p>
        {emptyEndpoint && <Readout className="text-[7.5px] text-slate-700">{emptyEndpoint}</Readout>}
      </div>
    );
  }

  return (
    <div className="mt-1.5">
      <div
        className="flex items-center gap-2 px-1.5 py-1"
        style={{ background: `${CYAN}14`, borderBottom: `1px solid ${CYAN}33` }}
      >
        {columns.map(c => (
          <span
            key={c.key}
            className="shrink-0 text-[7px] tracking-[0.12em] uppercase"
            style={{ width: c.width, color: `${CYAN}cc`, fontFamily: 'var(--font-mono)', flex: c.width ? undefined : 1 }}
          >
            {c.header}
          </span>
        ))}
      </div>
      <div className="overflow-y-auto" style={{ maxHeight }}>
        {rows.map((r, i) => (
          <div
            key={i}
            onClick={onRowClick ? () => onRowClick(r, i) : undefined}
            className={cn(
              'flex items-center gap-2 px-1.5 py-[3px] transition-colors',
              onRowClick && 'cursor-default hover:bg-white/[0.04]'
            )}
            style={{ borderBottom: '1px solid rgba(255,255,255,0.03)' }}
          >
            {columns.map(c => (
              <span
                key={c.key}
                className="shrink-0 truncate text-[8px]"
                style={{ width: c.width, flex: c.width ? undefined : 1, fontFamily: 'var(--font-mono)' }}
              >
                {c.render(r)}
              </span>
            ))}
          </div>
        ))}
      </div>
    </div>
  );
}

/* ── Hexagonal alert callout ─────────────────────────────────────────────── */

/** The red error badge pinned over the reference's globe. */
export const AlertCallout: React.FC<{
  title: string;
  detail: string;
  onClose?: () => void;
}> = ({ title, detail, onClose }) => (
  <div
    className="flex items-center gap-2 border px-2.5 py-1.5"
    style={{
      borderColor: `${CRIMSON}88`,
      background: 'rgba(0,0,0,0.72)',
      boxShadow: `0 0 18px ${CRIMSON}33`,
      clipPath: 'polygon(8px 0,100% 0,100% calc(100% - 8px),calc(100% - 8px) 100%,0 100%,0 8px)'
    }}
  >
    <span
      className="grid h-5 w-5 shrink-0 rotate-45 place-items-center border"
      style={{ borderColor: CRIMSON }}
      aria-hidden
    >
      <span className="-rotate-45 text-[9px] font-bold" style={{ color: CRIMSON }}>
        !
      </span>
    </span>
    <div className="min-w-0">
      <p
        className="text-[8px] font-bold tracking-[0.14em] uppercase"
        style={{ color: CRIMSON, fontFamily: 'var(--font-mono)', textShadow: `0 0 8px ${CRIMSON}66` }}
      >
        {title}
      </p>
      <p className="truncate text-[7.5px] text-slate-400">{detail}</p>
    </div>
    {onClose && (
      <button
        onClick={onClose}
        aria-label="dismiss"
        className="ms-1 shrink-0 text-[10px] leading-none text-slate-500 transition-colors hover:text-white"
      >
        ✕
      </button>
    )}
  </div>
);
