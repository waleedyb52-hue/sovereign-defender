import React from 'react';
import { RadialGauge, type Tone } from './TacticalPrimitives';
import { Sparkline } from '../charts/primitives';
import type { useArsenal } from './useArsenal';

type Arsenal = ReturnType<typeof useArsenal>;

/**
 * TELEMETRY DIALS — four circular readouts framing the theatre.
 *
 * Every dial is a ratio of two things the platform measured or configured. Which four,
 * and which were refused, is the substance of this component:
 *
 *   KERNEL DROP     dropped / received from /ebpf/real-stats. Crimson, because crimson
 *                   means eBPF drops in this palette — unless the driver reports
 *                   emulation, in which case amber and the driver's own words.
 *   AI VERDICT      the confidence the engine issued on its most recent payload, from
 *                   /soc/ai-agent/analyses. The trend beneath it is the engine's own
 *                   history of verdicts, not samples taken by this component.
 *   FIM VERIFIED    files whose hash was verified intact, over files monitored. A file
 *                   with no status yet is counted as unverified, not as intact.
 *   WAF ARMED       enabled rules over configured rules. Configuration, not traffic,
 *                   so it carries no trend.
 *
 * Refused: a WAF block-rate dial. /traffic/waf/metrics starts its request counter at a
 * seeded 192,840 and returns a Math.random() RPS, so any ratio drawn from it would be a
 * well-formatted fiction.
 *
 * A trend is drawn only from samples this component actually took, one per completed
 * poll, and only once there are two of them. A dial with no source draws its track, no
 * sweep, and names the endpoint that is silent.
 */

interface Dial {
  id: string;
  label: string;
  value: number | null;
  tone: Tone;
  caption: string;
  endpoint: string;
  trend: number[] | null;
  trendColor: string;
}

const HEX: Record<Tone, string> = {
  cyan: '#22d3ee',
  crimson: '#f43f5e',
  amber: '#f59e0b',
  emerald: '#10b981',
  neutral: '#64748b'
};

const INTACT = /INTACT|OK|VERIFIED/i;
const HOSTILE = /BLOCK|MALIC|THREAT/i;

const round = (v: number, dp: number) => Number(v.toFixed(dp));

export const TelemetryDials: React.FC<{ a: Arsenal; isAr: boolean }> = ({ a, isAr }) => {
  const [drops, setDrops] = React.useState<number[]>([]);
  const [fim, setFim] = React.useState<number[]>([]);

  const files = a.fim.files;
  const verified = files.filter(f => f.status != null && INTACT.test(f.status)).length;
  const altered = files.filter(f => f.status != null && !INTACT.test(f.status)).length;
  const unverified = files.length - verified - altered;

  const dropPct = a.ebpf.dropRatio != null ? round(a.ebpf.dropRatio * 100, 2) : null;
  const fimPct = files.length ? round((verified / files.length) * 100, 1) : null;

  // One sample per completed poll. Keyed on the poll stamp, not the value, so a steady
  // reading still extends the trend instead of leaving a gap that looks like an outage.
  React.useEffect(() => {
    if (a.loadedAt == null) return;
    if (dropPct != null) setDrops(s => [...s.slice(-29), dropPct]);
    if (fimPct != null) setFim(s => [...s.slice(-29), fimPct]);
  }, [a.loadedAt]);

  const byTime = a.waf.analyses
    .filter(x => x.confidence != null)
    .slice()
    .sort((x, y) => (x.at ?? '').localeCompare(y.at ?? ''));
  const latest = byTime[byTime.length - 1] ?? null;
  const hostile = latest ? HOSTILE.test(latest.verdict ?? '') : false;

  const emu = a.ebpf.emulated;
  const rulesPct =
    a.waf.rulesOn != null && a.waf.rulesTotal ? round((a.waf.rulesOn / a.waf.rulesTotal) * 100, 0) : null;

  const dials: Dial[] = [
    {
      id: 'kernel',
      label: isAr ? 'إسقاط النواة' : 'KERNEL DROP',
      value: dropPct,
      tone: emu ? 'amber' : 'crimson',
      caption: emu
        ? `${isAr ? 'محاكاة' : 'EMULATED'} · ${a.ebpf.driverMode ?? '—'}`
        : a.ebpf.dropped != null && a.ebpf.rxPackets != null
          ? `${a.ebpf.dropped.toLocaleString('en-US')} / ${a.ebpf.rxPackets.toLocaleString('en-US')} PKT`
          : '—',
      endpoint: '/ebpf/real-stats',
      trend: drops,
      trendColor: emu ? HEX.amber : HEX.crimson
    },
    {
      id: 'verdict',
      label: isAr ? 'ثقة الحكم' : 'AI VERDICT',
      value: latest?.confidence ?? null,
      tone: latest ? (hostile ? 'crimson' : 'emerald') : 'neutral',
      caption: latest ? `${(latest.verdict ?? '—').slice(0, 10)} · ${latest.at?.slice(11, 19) ?? '—'}` : '—',
      endpoint: '/soc/ai-agent/analyses',
      trend: byTime.slice(-30).map(x => x.confidence as number),
      trendColor: hostile ? HEX.crimson : HEX.emerald
    },
    {
      id: 'fim',
      label: isAr ? 'سلامة الملفات' : 'FIM VERIFIED',
      value: fimPct,
      tone: altered > 0 ? 'crimson' : unverified > 0 ? 'amber' : 'emerald',
      caption: files.length
        ? `${altered} ${isAr ? 'معدّل' : 'ALTERED'} · ${unverified} ${isAr ? 'غير مُتحقَّق' : 'UNVERIFIED'}`
        : '—',
      endpoint: '/fim/files',
      trend: fim,
      trendColor: altered > 0 ? HEX.crimson : HEX.emerald
    },
    {
      id: 'waf',
      label: isAr ? 'قواعد WAF' : 'WAF ARMED',
      value: rulesPct,
      tone: rulesPct === 100 ? 'emerald' : 'cyan',
      caption: rulesPct != null ? `${a.waf.rulesOn}/${a.waf.rulesTotal} ${isAr ? 'قاعدة' : 'RULES'}` : '—',
      endpoint: '/traffic/waf/metrics',
      trend: null,
      trendColor: HEX.cyan
    }
  ];

  return (
    <div className="grid grid-cols-2 gap-x-1 gap-y-2">
      {dials.map(d => {
        const silent = d.value == null;
        const reason = isAr ? `لا بيانات · ${d.endpoint}` : `no data · ${d.endpoint}`;
        return (
          <div
            key={d.id}
            className="flex min-w-0 flex-col items-center"
            {...(silent
              ? { role: 'group', 'aria-label': `${d.label}: ${reason}` }
              : {
                  role: 'meter',
                  'aria-label': d.label,
                  'aria-valuemin': 0,
                  'aria-valuemax': 100,
                  'aria-valuenow': d.value as number,
                  'aria-valuetext': `${d.value}% · ${d.caption}`
                })}
          >
            <RadialGauge value={d.value} max={100} label={d.label} unit="%" tone={d.tone} size={64} reason={reason} />
            <p
              className="mt-0.5 w-full truncate text-center font-mono text-[10px] text-slate-400"
              title={silent ? reason : d.caption}
              dir="ltr"
            >
              {silent ? d.endpoint : d.caption}
            </p>
            <div className="mt-0.5 h-3.5" aria-hidden>
              {d.trend && d.trend.length >= 2 && (
                <Sparkline values={d.trend} color={d.trendColor} width={72} height={14} />
              )}
            </div>
          </div>
        );
      })}
    </div>
  );
};

export default TelemetryDials;
