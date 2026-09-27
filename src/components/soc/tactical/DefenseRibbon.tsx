import React from 'react';
import { Cpu, ShieldCheck, FileLock2, Gauge, Network, Binary } from 'lucide-react';
import { CYAN, CRIMSON, AMBER, EMERALD, Readout, type Tone } from './TacticalPrimitives';

/**
 * GLOBAL DEFENCE RIBBON
 *
 * One neon counter per live defence stage, in monospace, across the top of the cockpit.
 * These are the phases the platform was built in — kernel XDP, L7 WAF, file integrity,
 * response latency — and the ribbon is where they stop being pages and become state.
 *
 * Each cell states its own provenance. That is not decoration on a status bar: the
 * kernel counters on this host are seeded, not measured, and a ribbon that prints
 * "373,960 dropped" beside a measured RPS with no distinction is teaching an operator
 * to trust both equally. So a cell whose figure is seeded or unavailable says so, in
 * the cell, at the size the figure is shown.
 */

export type Provenance = 'MEASURED' | 'SEEDED' | 'UNAVAILABLE';

const PROV_LABEL: Record<Provenance, { ar: string; en: string; tone: Tone }> = {
  MEASURED: { ar: 'مقيس', en: 'MEASURED', tone: 'emerald' },
  SEEDED: { ar: 'مزروع', en: 'SEEDED', tone: 'amber' },
  UNAVAILABLE: { ar: 'غير متاح', en: 'UNAVAILABLE', tone: 'crimson' }
};

const TONE_HEX: Record<Tone, string> = {
  cyan: CYAN,
  crimson: CRIMSON,
  amber: AMBER,
  emerald: EMERALD,
  neutral: '#5c7484'
};

export const RibbonCell: React.FC<{
  icon: React.ElementType;
  label: string;
  value: number | string | null;
  unit?: string;
  sub?: string;
  tone?: Tone;
  provenance: Provenance;
  reason?: string | null;
  isAr: boolean;
}> = ({ icon: Icon, label, value, unit, sub, tone = 'cyan', provenance, reason, isAr }) => {
  const hex = TONE_HEX[tone];
  const prov = PROV_LABEL[provenance];
  const provHex = TONE_HEX[prov.tone];

  return (
    <div
      className="flex min-w-0 flex-1 items-center gap-2 px-2.5 py-1"
      style={{ borderInlineEnd: '1px solid rgba(6,182,212,0.18)' }}
    >
      <span
        className="grid h-7 w-7 shrink-0 place-items-center"
        style={{
          border: `1px solid ${hex}55`,
          clipPath: 'polygon(6px 0,100% 0,100% calc(100% - 6px),calc(100% - 6px) 100%,0 100%,0 6px)',
          boxShadow: `0 0 14px ${hex}22`
        }}
      >
        <Icon className="h-3.5 w-3.5" strokeWidth={1.25} style={{ color: hex }} aria-hidden />
      </span>

      <div className="min-w-0">
        <p className="truncate text-[6.5px] tracking-[0.18em] uppercase" style={{ color: `${hex}99`, fontFamily: 'var(--font-mono)' }}>
          {label}
        </p>
        <p className="flex items-baseline gap-1 leading-none">
          {value == null ? (
            <span className="text-[14px] text-slate-700" style={{ fontFamily: 'var(--font-mono)' }} title={reason ?? undefined}>
              —
            </span>
          ) : (
            <Readout className="text-[14px] font-bold" tone={tone} glow>
              {typeof value === 'number' ? value.toLocaleString('en-US') : value}
            </Readout>
          )}
          {unit && value != null && (
            <span className="text-[7px] opacity-60" style={{ color: hex, fontFamily: 'var(--font-mono)' }}>
              {unit}
            </span>
          )}
        </p>
        <p className="mt-0.5 flex items-center gap-1">
          <span
            className="text-[5.5px] tracking-[0.14em]"
            style={{ color: provHex, fontFamily: 'var(--font-mono)' }}
            title={reason ?? undefined}
          >
            {isAr ? prov.ar : prov.en}
          </span>
          {sub && <span className="truncate text-[6px] text-slate-600">{sub}</span>}
        </p>
      </div>
    </div>
  );
};

export const RIBBON_ICONS = { Cpu, ShieldCheck, FileLock2, Gauge, Network, Binary };

export default RibbonCell;
