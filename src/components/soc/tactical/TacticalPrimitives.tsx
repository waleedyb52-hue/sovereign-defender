import React from 'react';
import { cn } from '../../../lib/utils';

/**
 * TACTICAL C2 PRIMITIVES
 *
 * The building blocks of the cockpit: chamfered glass panels, corner accents, HUD
 * gauges, tactical switches, and the monospace readout used for every figure.
 *
 * Why chamfered corners need clip-path rather than border-radius
 *   A rounded corner and a cut corner are different geometries; CSS has a property
 *   for the first and none for the second. `clip-path: polygon()` gives the cut, and
 *   the cost is that a clipped element cannot show an outside box-shadow — the glow
 *   would be clipped away with the corner. So the glow is painted by a sibling layer
 *   sitting behind the clipped panel, which is why `TacticalPanel` renders two
 *   stacked divs rather than one.
 *
 * Why the corner accents are separate elements
 *   The specification asks for visible corner brackets. A border on the clipped
 *   element follows the diagonal and reads as a bevel, not a bracket. Absolutely
 *   positioned L-shaped spans give the hard right angle the reference has, and they
 *   sit inside the clip so the diagonal cuts across them exactly as intended.
 *
 * On colour discipline
 *   Cyan is structure and health. Crimson is reserved for threats, eBPF drops and
 *   critical alerts, and nothing else — a console that uses its alarm colour for
 *   decoration teaches the operator to stop seeing it. Every component here that can
 *   take a tone defaults to cyan for that reason.
 */

/* ── Palette ─────────────────────────────────────────────────────────────── */

export const VOID = '#000000';
export const CYAN = '#00f3ff';
/** cyan-400. Technical text, where the brighter neon would fringe on small glyphs. */
export const CYAN_TEXT = '#22d3ee';
/** cyan-500, the border hue. */
export const CYAN_DIM = '#06b6d4';
/** rose-500. Reserved for threats, eBPF drops and critical alerts. */
export const CRIMSON = '#f43f5e';
export const AMBER = '#f59e0b';
export const EMERALD = '#10b981';

export type Tone = 'cyan' | 'crimson' | 'amber' | 'emerald' | 'neutral';

const TONE_HEX: Record<Tone, string> = {
  cyan: CYAN,
  crimson: CRIMSON,
  amber: AMBER,
  emerald: EMERALD,
  neutral: '#64748b'
};

export const toneHex = (t: Tone) => TONE_HEX[t];

/** Chamfer sizes, in pixels of corner cut. */
const CHAMFER = { sm: 8, md: 12, lg: 18 } as const;
type ChamferSize = keyof typeof CHAMFER;

/** Which corners get cut. Most panels cut the diagonal pair, as the reference does. */
export type Corners = 'diagonal' | 'all' | 'top' | 'none';

function clipFor(size: number, corners: Corners): string {
  const s = `${size}px`;
  switch (corners) {
    case 'all':
      return `polygon(${s} 0, calc(100% - ${s}) 0, 100% ${s}, 100% calc(100% - ${s}), calc(100% - ${s}) 100%, ${s} 100%, 0 calc(100% - ${s}), 0 ${s})`;
    case 'top':
      return `polygon(${s} 0, calc(100% - ${s}) 0, 100% ${s}, 100% 100%, 0 100%, 0 ${s})`;
    case 'diagonal':
      // Top-left and bottom-right cut; the other two stay square. This is the
      // asymmetry that makes the reference read as a machined plate rather than a
      // uniformly bevelled box.
      return `polygon(${s} 0, 100% 0, 100% calc(100% - ${s}), calc(100% - ${s}) 100%, 0 100%, 0 ${s})`;
    default:
      return 'none';
  }
}

/* ── Panel ───────────────────────────────────────────────────────────────── */

export interface TacticalPanelProps {
  children: React.ReactNode;
  className?: string;
  tone?: Tone;
  chamfer?: ChamferSize;
  corners?: Corners;
  /** Draw the L-shaped corner brackets. */
  accents?: boolean;
  /** Glow intensity behind the panel. `none` for dense stacks where glow would smear. */
  glow?: 'none' | 'soft' | 'strong';
  style?: React.CSSProperties;
}

export const TacticalPanel: React.FC<TacticalPanelProps> = ({
  children,
  className,
  tone = 'cyan',
  chamfer = 'md',
  corners = 'diagonal',
  accents = true,
  glow = 'soft',
  style
}) => {
  const hex = TONE_HEX[tone];
  const size = CHAMFER[chamfer];
  const clip = clipFor(size, corners);

  return (
    <div className="relative">
      {/* Glow layer. Separate because the panel above is clipped, and a clipped
          element cannot paint an outside shadow. */}
      {glow !== 'none' && (
        <div
          aria-hidden
          className="pointer-events-none absolute inset-0"
          style={{
            clipPath: clip,
            boxShadow:
              glow === 'strong'
                ? `0 0 34px ${hex}33, 0 0 12px ${hex}22`
                : `0 0 20px ${hex}1a`,
            background: glow === 'strong' ? `${hex}08` : 'transparent'
          }}
        />
      )}

      <div
        className={cn('relative border backdrop-blur-xl', className)}
        style={{
          clipPath: clip,
          background: 'rgba(0,0,0,0.40)',
          // 0x66 is 40% — the border strength the reference boards carry.
          borderColor: `${hex}66`,
          ...style
        }}
      >
        {accents && <CornerAccents tone={tone} />}
        {children}
      </div>
    </div>
  );
};

/**
 * L-shaped corner brackets.
 *
 * Separate spans rather than a border, because a border on the clipped element
 * follows the diagonal and reads as a bevel instead of a bracket.
 */
export const CornerAccents: React.FC<{ tone?: Tone; inset?: number }> = ({ tone = 'cyan', inset = 0 }) => {
  const hex = TONE_HEX[tone];
  const L = 14;
  const common = 'pointer-events-none absolute';
  return (
    <>
      <span
        aria-hidden
        className={common}
        style={{ top: inset, left: inset, width: L, height: L, borderTop: `2px solid ${hex}`, borderLeft: `2px solid ${hex}`, opacity: 0.85 }}
      />
      <span
        aria-hidden
        className={common}
        style={{ top: inset, right: inset, width: L, height: L, borderTop: `2px solid ${hex}`, borderRight: `2px solid ${hex}`, opacity: 0.45 }}
      />
      <span
        aria-hidden
        className={common}
        style={{ bottom: inset, left: inset, width: L, height: L, borderBottom: `2px solid ${hex}`, borderLeft: `2px solid ${hex}`, opacity: 0.45 }}
      />
      <span
        aria-hidden
        className={common}
        style={{ bottom: inset, right: inset, width: L, height: L, borderBottom: `2px solid ${hex}`, borderRight: `2px solid ${hex}`, opacity: 0.85 }}
      />
    </>
  );
};

/* ── Readouts ────────────────────────────────────────────────────────────── */

/**
 * Every figure, coordinate, timestamp and log line in the cockpit.
 *
 * Mono is mandatory here for the reason it always is in this project: an operator
 * about to act on an address or a hash must be able to tell 0 from O.
 */
export const Readout: React.FC<{
  children: React.ReactNode;
  className?: string;
  tone?: Tone;
  glow?: boolean;
  title?: string;
}> = ({ children, className, tone, glow, title }) => (
  <span
    className={cn('tabular-nums tracking-tight', className)}
    style={{
      fontFamily: 'var(--font-mono)',
      color: tone ? TONE_HEX[tone] : undefined,
      textShadow: glow && tone ? `0 0 8px ${TONE_HEX[tone]}66` : undefined
    }}
    title={title}
    dir="ltr"
  >
    {children}
  </span>
);

/** Stencil label above a readout. */
export const HudLabel: React.FC<{ children: React.ReactNode; tone?: Tone }> = ({ children, tone = 'neutral' }) => (
  <span
    className="text-[8px] font-medium tracking-[0.18em] uppercase"
    style={{ color: `${TONE_HEX[tone]}99`, fontFamily: 'var(--font-mono)' }}
  >
    {children}
  </span>
);

/**
 * A value that refuses to invent itself. Null renders an em dash with the reason on
 * hover — a zero is a claim about the network, an em dash is an admission about the
 * console, and an operator must be able to tell them apart.
 */
export const HudValue: React.FC<{
  v: number | string | null;
  unit?: string;
  tone?: Tone;
  reason?: string;
  className?: string;
  glow?: boolean;
}> = ({ v, unit, tone = 'cyan', reason, className, glow }) =>
  v == null ? (
    <span className="text-slate-700" style={{ fontFamily: 'var(--font-mono)' }} title={reason}>
      —
    </span>
  ) : (
    <Readout tone={tone} glow={glow} className={className}>
      {v}
      {unit && <span className="ms-0.5 text-[0.62em] opacity-60">{unit}</span>}
    </Readout>
  );

/* ── Gauges ──────────────────────────────────────────────────────────────── */

/** Circular radar gauge. A null value draws the track and no sweep. */
export const RadialGauge: React.FC<{
  value: number | null;
  max: number;
  label: string;
  unit?: string;
  tone?: Tone;
  size?: number;
  reason?: string;
}> = ({ value, max, label, unit, tone = 'cyan', size = 62, reason }) => {
  const hex = TONE_HEX[tone];
  const pct = value != null && max > 0 ? Math.min(1, Math.max(0, value / max)) : 0;
  const r = size / 2 - 6;
  const circ = 2 * Math.PI * r * 0.75; // three-quarter arc, the HUD convention
  const uid = React.useId().replace(/:/g, '');

  return (
    <div className="text-center">
      <div className="relative mx-auto" style={{ width: size, height: size }}>
        <svg viewBox={`0 0 ${size} ${size}`} className="h-full w-full" style={{ transform: 'rotate(135deg)' }} aria-hidden>
          <defs>
            <filter id={`g-${uid}`} x="-50%" y="-50%" width="200%" height="200%">
              <feGaussianBlur stdDeviation="1.6" result="b" />
              <feMerge>
                <feMergeNode in="b" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>
          </defs>
          <circle
            cx={size / 2}
            cy={size / 2}
            r={r}
            fill="none"
            stroke="rgba(255,255,255,0.06)"
            strokeWidth="3"
            strokeDasharray={`${circ} ${circ}`}
            strokeLinecap="round"
          />
          {value != null && (
            <circle
              cx={size / 2}
              cy={size / 2}
              r={r}
              fill="none"
              stroke={hex}
              strokeWidth="3"
              strokeDasharray={`${circ * pct} ${circ * 2}`}
              strokeLinecap="round"
              filter={`url(#g-${uid})`}
              style={{ transition: 'stroke-dasharray 700ms ease-out' }}
            />
          )}
          {/* Tick marks around the arc */}
          {Array.from({ length: 13 }).map((_, i) => {
            const a = (i / 12) * 270 * (Math.PI / 180);
            const x1 = size / 2 + Math.cos(a) * (r + 3);
            const y1 = size / 2 + Math.sin(a) * (r + 3);
            const x2 = size / 2 + Math.cos(a) * (r + 5.5);
            const y2 = size / 2 + Math.sin(a) * (r + 5.5);
            return (
              <line key={i} x1={x1} y1={y1} x2={x2} y2={y2} stroke={`${hex}44`} strokeWidth="0.7" />
            );
          })}
        </svg>
        <div className="absolute inset-0 grid place-items-center">
          <div>
            <HudValue v={value} tone={tone} glow className="text-[13px] font-bold" reason={reason} />
            {unit && value != null && <p className="text-[7px] text-slate-600">{unit}</p>}
          </div>
        </div>
      </div>
      <p className="mt-1">
        <HudLabel tone={tone}>{label}</HudLabel>
      </p>
    </div>
  );
};

/** Horizontal HUD bar with segment ticks. */
export const LinearGauge: React.FC<{
  value: number | null;
  max: number;
  label: string;
  unit?: string;
  tone?: Tone;
  reason?: string;
  /** Segments give the stepped HUD look instead of a smooth fill. */
  segments?: number;
}> = ({ value, max, label, unit, tone = 'cyan', reason, segments = 24 }) => {
  const hex = TONE_HEX[tone];
  const pct = value != null && max > 0 ? Math.min(1, Math.max(0, value / max)) : 0;
  const lit = Math.round(pct * segments);

  return (
    <div>
      <div className="flex items-baseline justify-between">
        <HudLabel tone={tone}>{label}</HudLabel>
        <HudValue v={value} unit={unit} tone={tone} glow reason={reason} className="text-[11px] font-bold" />
      </div>
      <div className="mt-1 flex gap-[2px]" aria-hidden>
        {Array.from({ length: segments }).map((_, i) => (
          <span
            key={i}
            className="h-2 flex-1"
            style={{
              background: i < lit ? hex : 'rgba(255,255,255,0.05)',
              boxShadow: i < lit ? `0 0 6px ${hex}55` : undefined,
              opacity: i < lit ? 0.5 + (i / segments) * 0.5 : 1
            }}
          />
        ))}
      </div>
    </div>
  );
};

/* ── Controls ────────────────────────────────────────────────────────────── */

/** Transparent tactical switch with a glowing border. */
export const TacticalButton: React.FC<
  React.ButtonHTMLAttributes<HTMLButtonElement> & { tone?: Tone; active?: boolean; size?: 'sm' | 'md' }
> = ({ tone = 'cyan', active, size = 'md', className, children, ...rest }) => {
  const hex = TONE_HEX[tone];
  return (
    <button
      {...rest}
      className={cn(
        'relative inline-flex items-center justify-center gap-1.5 border font-medium transition-all',
        'focus-visible:outline-none disabled:opacity-40 disabled:pointer-events-none',
        size === 'sm' ? 'px-2 py-1 text-[9px]' : 'px-3 py-1.5 text-[10px]',
        className
      )}
      style={{
        clipPath: clipFor(6, 'diagonal'),
        borderColor: active ? hex : `${hex}44`,
        color: active ? hex : `${hex}cc`,
        background: active ? `${hex}14` : 'rgba(0,0,0,0.4)',
        textShadow: active ? `0 0 8px ${hex}88` : undefined,
        boxShadow: active ? `inset 0 0 12px ${hex}18` : undefined,
        letterSpacing: '0.06em',
        fontFamily: 'var(--font-mono)'
      }}
    >
      {children}
    </button>
  );
};

/* ── Background ──────────────────────────────────────────────────────────── */

/**
 * Cyber-grid matrix with scanlines.
 *
 * Purely decorative and therefore deliberately faint: it sits behind live data, and
 * texture that competes with a readout is the first thing to go in a console someone
 * watches for a twelve-hour shift. The scanline drift is disabled under
 * prefers-reduced-motion.
 */
export const CyberGridBackdrop: React.FC<{ reduce?: boolean; className?: string }> = ({ reduce, className }) => (
  <div className={cn('pointer-events-none absolute inset-0 overflow-hidden', className)} aria-hidden>
    {/* Fine grid */}
    <div
      className="absolute inset-0"
      style={{
        backgroundImage: `linear-gradient(${CYAN}0a 1px, transparent 1px), linear-gradient(90deg, ${CYAN}0a 1px, transparent 1px)`,
        backgroundSize: '44px 44px'
      }}
    />
    {/* Coarser grid for depth */}
    <div
      className="absolute inset-0"
      style={{
        backgroundImage: `linear-gradient(${CYAN}08 1px, transparent 1px), linear-gradient(90deg, ${CYAN}08 1px, transparent 1px)`,
        backgroundSize: '176px 176px'
      }}
    />
    {/* Vignette, so the centre stage reads brighter than the edges */}
    <div
      className="absolute inset-0"
      style={{ background: 'radial-gradient(ellipse 70% 60% at 50% 45%, transparent 30%, rgba(0,0,0,0.75) 100%)' }}
    />
    {/* Scanlines */}
    <div
      className={cn('absolute inset-0', !reduce && 'tac-scan')}
      style={{
        backgroundImage: 'repeating-linear-gradient(0deg, rgba(0,243,255,0.035) 0px, rgba(0,243,255,0.035) 1px, transparent 1px, transparent 3px)'
      }}
    />
  </div>
);
