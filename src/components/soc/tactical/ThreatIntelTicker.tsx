import React from 'react';
import { Pause, Play, Database } from 'lucide-react';
import type { useArsenal } from './useArsenal';

type Arsenal = ReturnType<typeof useArsenal>;

/**
 * THREAT INTEL TICKER — the indicator store as a running strip under the header.
 *
 * The brief asked for live STIX/TAXII IOCs and global CVE updates. This platform is
 * zero-egress by construction, and `/soc/threat-intel/stats` reports how many external
 * lookups were made — on a sovereign deployment, none. So the strip runs the LOCAL store
 * and says so in a badge that does not scroll away: a ticker styled as a live global feed
 * would contradict the sovereignty claim the platform makes one panel over. There is no
 * CVE feed to show; nothing here pretends otherwise.
 *
 * Each indicator shows its MITRE technique or `UNMAPPED`, never a guess (§7). Score sets
 * the colour, and the score is printed beside it so colour is never the only signal.
 */

const scoreHex = (s: number | null) => (s == null ? '#94a3b8' : s >= 80 ? '#fb7185' : s >= 50 ? '#fbbf24' : '#22d3ee');

export const ThreatIntelTicker: React.FC<{ a: Arsenal; isAr: boolean }> = ({ a, isAr }) => {
  const [paused, setPaused] = React.useState(false);
  const iocs = a.intel.iocs;
  const lookups = a.intel.totalLookups;
  const silent = a.missing.includes('/forensics/threat-intel/iocs');

  const items = iocs.map(i => (
    <span key={i.id} className="flex shrink-0 items-baseline gap-1.5 pe-6 font-mono text-[10px] whitespace-nowrap">
      <span className="text-slate-400">[{i.type ?? '—'}]</span>
      <span className="font-semibold" style={{ color: scoreHex(i.score) }}>
        {i.value ?? '—'}
      </span>
      <span style={{ color: scoreHex(i.score) }}>{i.score ?? '—'}</span>
      <span className="text-slate-300">{i.actor ?? '—'}</span>
      {i.technique ? (
        <span className="text-cyan-400">{i.technique}</span>
      ) : (
        <span className="text-slate-500">UNMAPPED</span>
      )}
      <span className="text-cyan-500/40" aria-hidden>
        ◆
      </span>
    </span>
  ));

  return (
    <div
      className="tac-ticker-host tac-nonessential relative z-20 flex h-6 shrink-0 items-center gap-2 border-b border-cyan-900/50 bg-[#030712]/70 ps-2 backdrop-blur-2xl"
      role="region"
      aria-label={isAr ? 'مؤشّرات الاختراق' : 'Threat indicators'}
    >
      {/* Provenance: fixed, never scrolls out of view. */}
      <span
        className="flex shrink-0 items-center gap-1 border border-amber-500/40 bg-amber-950/40 px-1.5 py-[1px] font-mono text-[10px] tracking-widest text-amber-300 uppercase"
        title={
          isAr
            ? 'المخزن محلّي؛ المنصّة لا ترسل استعلامات خارجية'
            : 'the store is local; the platform makes no external queries'
        }
      >
        <Database className="h-2.5 w-2.5" aria-hidden />
        {isAr ? 'مخزن IOC محلّي' : 'LOCAL IOC STORE'}
        <span className="text-amber-300/70">
          · {lookups ?? '—'} {isAr ? 'استعلام خارجي' : 'EXT LOOKUPS'}
        </span>
      </span>

      <div className="relative min-w-0 flex-1 overflow-hidden motion-reduce:overflow-x-auto" dir="ltr">
        {iocs.length === 0 ? (
          <span className="font-mono text-[10px] text-slate-400">
            {silent
              ? isAr ? 'مصدر صامت · /forensics/threat-intel/iocs' : 'SOURCE SILENT · /forensics/threat-intel/iocs'
              : isAr ? 'لا مؤشّرات مخزّنة' : 'NO INDICATORS STORED · /forensics/threat-intel/iocs'}
          </span>
        ) : (
          <div
            className="tac-ticker flex w-max"
            data-paused={paused}
            style={{ ['--tac-ticker-dur' as string]: `${Math.max(20, iocs.length * 7)}s` }}
          >
            <span className="flex">{items}</span>
            {/* The loop copy is presentation only; a screen reader hears the list once. */}
            <span className="flex" aria-hidden>
              {items}
            </span>
          </div>
        )}
        <span
          className="pointer-events-none absolute inset-y-0 right-0 w-10 bg-gradient-to-l from-[#030712] to-transparent"
          aria-hidden
        />
      </div>

      {iocs.length > 0 && (
        <button
          type="button"
          onClick={() => setPaused(p => !p)}
          aria-pressed={paused}
          aria-label={paused ? (isAr ? 'استئناف الشريط' : 'resume ticker') : isAr ? 'إيقاف الشريط' : 'pause ticker'}
          className="grid h-6 w-6 shrink-0 place-items-center border-s border-cyan-900/50 text-cyan-400 transition-colors hover:bg-cyan-500/10 focus-visible:ring-1 focus-visible:ring-cyan-400 focus-visible:outline-none motion-reduce:hidden"
        >
          {paused ? <Play className="h-3 w-3" aria-hidden /> : <Pause className="h-3 w-3" aria-hidden />}
        </button>
      )}
    </div>
  );
};

export default ThreatIntelTicker;
