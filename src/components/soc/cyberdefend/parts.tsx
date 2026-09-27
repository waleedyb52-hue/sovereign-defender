import React from 'react';
import { cn, formatCount } from '../../../lib/utils';

/**
 * SHARED PARTS FOR THE CYBERDEFEND SURFACE
 *
 * The atoms the three views share, extracted so each view file stays readable and
 * so the honesty behaviour is defined once rather than re-implemented per panel.
 *
 * `Value` and `Row` are the load-bearing ones. Both render an em dash with the
 * reason on hover when their source is absent, which is what keeps this surface
 * compliant with rule 0 of `.clauderules`: a number on screen is real, or it is
 * declared unavailable. Defining that in one place means a new panel cannot
 * accidentally print a zero where it meant "no data".
 */

/** The reference design's card surface. */
export const SURFACE = '#0A0F1D';
/** The near-black field behind everything. */
export const FIELD = '#04070D';

/** Machine data: addresses, counts, digests, latencies. */
export const Mono: React.FC<{ children: React.ReactNode; className?: string; title?: string }> = ({
  children,
  className,
  title
}) => (
  <span
    className={cn('tabular-nums', className)}
    style={{ fontFamily: 'var(--font-mono)' }}
    title={title}
    dir="ltr"
  >
    {children}
  </span>
);

/** Frosted glass card — the surface every panel sits on. */
export const Glass: React.FC<{ children: React.ReactNode; className?: string }> = ({ children, className }) => (
  <div
    className={cn('rounded-2xl border border-white/10 shadow-2xl shadow-black/60 backdrop-blur-2xl', className)}
    style={{ background: `${SURFACE}BF` }}
  >
    {children}
  </div>
);

export const Label: React.FC<{ children: React.ReactNode }> = ({ children }) => (
  <span className="text-[9px] font-medium tracking-[0.12em] text-slate-500 uppercase">{children}</span>
);

/**
 * A figure that refuses to invent itself.
 *
 * Null renders an em dash carrying the reason as a tooltip. Not a zero: a zero is a
 * claim about the network, while an em dash is an admission about the dashboard,
 * and an operator needs to be able to tell those apart.
 */
export const Value: React.FC<{
  v: number | string | null;
  unit?: string;
  reason?: string;
  className?: string;
}> = ({ v, unit, reason, className }) =>
  v == null ? (
    <span className="text-slate-600" title={reason}>
      —
    </span>
  ) : (
    <Mono className={className}>
      {v}
      {unit && <span className="ms-0.5 text-[0.7em] font-normal text-slate-500">{unit}</span>}
    </Mono>
  );

/** Labelled key/value row with the same absence discipline. */
export const Row: React.FC<{
  k: string;
  v: number | string | null;
  small?: boolean;
  reason?: string;
}> = ({ k, v, small, reason }) => (
  <div className="flex items-baseline justify-between gap-2">
    <dt className="text-[9px] text-slate-500">{k}</dt>
    <dd className={cn('text-end', small ? 'text-[9px]' : 'text-[10px]')}>
      {v == null ? (
        <span className="text-slate-600" title={reason}>
          —
        </span>
      ) : (
        <Mono className="text-slate-200">{typeof v === 'number' ? formatCount(v) : v}</Mono>
      )}
    </dd>
  </div>
);

/** Small stat tile used under the gauges. */
export const Stat: React.FC<{ label: string; value: string | null; accent: string }> = ({
  label,
  value,
  accent
}) => (
  <div className="rounded-xl border border-white/8 bg-white/[0.02] px-2 py-1.5">
    <p className="text-[8px] tracking-wider text-slate-500 uppercase">{label}</p>
    <p className="mt-0.5 text-[13px] font-bold" style={{ color: value ? accent : undefined }}>
      {value ?? <span className="text-slate-600">—</span>}
    </p>
  </div>
);

/** Uptime as hours, minutes, seconds. */
export function fmtDur(sec: number): string {
  const h = Math.floor(sec / 3600);
  const m = Math.floor((sec % 3600) / 60);
  const s = sec % 60;
  return `${h}h ${String(m).padStart(2, '0')}m ${String(s).padStart(2, '0')}s`;
}
