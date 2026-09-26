import React, { useEffect, useMemo, useState } from 'react';
import { Grid3x3, ShieldCheck } from 'lucide-react';
import { heatStep } from './charts/primitives';

/**
 * MITRE ATT&CK COVERAGE MATRIX
 *
 * The canonical way a security team shows what it sees: tactics across the
 * top, observed techniques stacked beneath, each cell shaded by how much
 * activity landed there.
 *
 * Encoding: continuous magnitude -> a SINGLE-hue sequential ramp (blue),
 * near-surface for low, bright for high. No rainbow, and "no activity" is
 * left at surface level so an empty cell recedes instead of reading as a
 * low value. Counts are printed in the cells, so magnitude is never carried
 * by colour alone.
 */

interface TelemetryEvent {
  id: string;
  severity: string;
  mitreTactic?: string;
  mitreTechnique?: string;
}

/** The tactic columns we track, in kill-chain order. */
const TACTICS = [
  { key: 'Reconnaissance', ar: 'الاستطلاع', en: 'Recon' },
  { key: 'Initial Access', ar: 'الوصول الأولي', en: 'Initial Access' },
  { key: 'Execution', ar: 'التنفيذ', en: 'Execution' },
  { key: 'Persistence', ar: 'ترسيخ الوجود', en: 'Persistence' },
  { key: 'Privilege Escalation', ar: 'رفع الصلاحيات', en: 'Priv. Esc' },
  { key: 'Defense Evasion', ar: 'تفادي الدفاعات', en: 'Evasion' },
  { key: 'Credential Access', ar: 'سرقة الاعتماد', en: 'Cred. Access' },
  { key: 'Lateral Movement', ar: 'حركة جانبية', en: 'Lateral' },
  { key: 'Command and Control', ar: 'القيادة والسيطرة', en: 'C2' },
  { key: 'Exfiltration', ar: 'سحب البيانات', en: 'Exfiltration' },
  { key: 'Impact', ar: 'الأثر', en: 'Impact' }
];

/** Normalises the various tactic spellings the backend emits. */
function normaliseTactic(raw?: string): string | null {
  if (!raw) return null;
  const t = raw.toLowerCase();
  if (t.includes('recon')) return 'Reconnaissance';
  if (t.includes('initial')) return 'Initial Access';
  if (t.includes('execution')) return 'Execution';
  if (t.includes('persist')) return 'Persistence';
  if (t.includes('privilege')) return 'Privilege Escalation';
  if (t.includes('evasion') || t.includes('defense')) return 'Defense Evasion';
  if (t.includes('credential')) return 'Credential Access';
  if (t.includes('lateral')) return 'Lateral Movement';
  if (t.includes('command') || t.includes('c2')) return 'Command and Control';
  if (t.includes('exfil')) return 'Exfiltration';
  if (t.includes('impact')) return 'Impact';
  return null;
}

interface Props {
  lang?: 'ar' | 'en';
}

export const MitreMatrix: React.FC<Props> = ({ lang = 'ar' }) => {
  const isAr = lang === 'ar';
  const [events, setEvents] = useState<TelemetryEvent[]>([]);
  const [hover, setHover] = useState<{ tactic: string; technique: string; count: number } | null>(
    null
  );

  useEffect(() => {
    const load = async () => {
      try {
        const res = await fetch('/api/v1/soc/unified-telemetry?limit=200');
        if (!res.ok) return;
        const d = await res.json();
        if (Array.isArray(d?.events)) setEvents(d.events);
      } catch {
        /* keep last known */
      }
    };
    load();
    const t = setInterval(load, 8000);
    return () => clearInterval(t);
  }, []);

  /** tactic -> technique -> count */
  const grid = useMemo<Map<string, Map<string, number>>>(() => {
    const m = new Map<string, Map<string, number>>();
    for (const e of events) {
      const tac = normaliseTactic(e.mitreTactic) ?? normaliseTactic(e.mitreTechnique);
      if (!tac) continue;
      const tech = (e.mitreTechnique || 'Unclassified').split(' - ')[0];
      if (!m.has(tac)) m.set(tac, new Map());
      const inner = m.get(tac)!;
      inner.set(tech, (inner.get(tech) ?? 0) + 1);
    }
    return m;
  }, [events]);

  const maxCount = useMemo(() => {
    let mx = 0;
    grid.forEach(inner =>
      inner.forEach(v => {
        if (v > mx) mx = v;
      })
    );
    return mx || 1;
  }, [grid]);

  const observedTactics = TACTICS.filter(t => grid.has(t.key)).length;
  const totalTechniques = useMemo(() => {
    const s = new Set<string>();
    grid.forEach(inner => inner.forEach((_, k) => s.add(k)));
    return s.size;
  }, [grid]);

  const maxRows = Math.max(1, ...TACTICS.map(t => grid.get(t.key)?.size ?? 0));

  return (
    <section className="soc-panel p-5" dir={isAr ? 'rtl' : 'ltr'}>
      <div className="mb-4 flex items-start justify-between gap-4">
        <div>
          <h3 className="flex items-center gap-2 text-sm font-bold text-slate-100">
            <Grid3x3 className="h-4 w-4 text-slate-400" />
            {isAr ? 'مصفوفة تغطية MITRE ATT&CK' : 'MITRE ATT&CK coverage matrix'}
          </h3>
          <p className="mt-0.5 text-[11px] text-slate-500">
            {isAr
              ? 'التكتيكات أفقياً والتقنيات المرصودة تحتها — درجة اللون تعكس كثافة النشاط.'
              : 'Tactics across, observed techniques beneath — shade reflects activity volume.'}
          </p>
        </div>

        <div className="flex shrink-0 items-center gap-4">
          <div className="text-end">
            <div className="font-mono text-lg leading-none font-bold text-slate-100 tabular-nums">
              {observedTactics}
              <span className="text-sm text-slate-500">/{TACTICS.length}</span>
            </div>
            <div className="soc-label mt-1">{isAr ? 'تكتيكات مرصودة' : 'tactics seen'}</div>
          </div>
          <div className="text-end">
            <div className="font-mono text-lg leading-none font-bold text-slate-100 tabular-nums">
              {totalTechniques}
            </div>
            <div className="soc-label mt-1">{isAr ? 'تقنيات' : 'techniques'}</div>
          </div>
        </div>
      </div>

      {/* matrix */}
      <div className="overflow-x-auto pb-1">
        <div className="min-w-[860px]" dir="ltr">
          {/* tactic headers */}
          <div
            className="mb-1.5 grid gap-1.5"
            style={{ gridTemplateColumns: `repeat(${TACTICS.length}, minmax(0, 1fr))` }}
          >
            {TACTICS.map(t => {
              const has = grid.has(t.key);
              return (
                <div
                  key={t.key}
                  className={`truncate rounded px-1 py-1.5 text-center text-[10px] leading-tight font-semibold ${has ? 'bg-slate-800/70 text-slate-200' : 'bg-slate-900/50 text-slate-600'}`}
                  title={isAr ? t.ar : t.en}
                >
                  {isAr ? t.ar : t.en}
                </div>
              );
            })}
          </div>

          {/* technique cells */}
          <div
            className="grid gap-1.5"
            style={{ gridTemplateColumns: `repeat(${TACTICS.length}, minmax(0, 1fr))` }}
          >
            {TACTICS.map(t => {
              const inner = grid.get(t.key);
              const techs: Array<[string, number]> = [];
              inner?.forEach((count, tech) => techs.push([tech, count]));
              techs.sort((a, b) => b[1] - a[1]);
              return (
                <div key={t.key} className="flex flex-col gap-1.5">
                  {Array.from({ length: maxRows }).map((_, r) => {
                    const entry = techs[r];
                    if (!entry) {
                      return (
                        <div
                          key={r}
                          className="h-8 rounded border border-slate-800/60 bg-slate-900/30"
                        />
                      );
                    }
                    const [tech, count] = entry;
                    const t01 = count / maxCount;
                    return (
                      <div
                        key={r}
                        onMouseEnter={() =>
                          setHover({ tactic: isAr ? t.ar : t.en, technique: tech, count })
                        }
                        onMouseLeave={() => setHover(null)}
                        className="flex h-8 cursor-default items-center justify-center rounded border border-slate-700/50 transition-transform hover:scale-[1.04]"
                        style={{ background: heatStep(t01) }}
                        title={`${tech} · ${count}`}
                      >
                        {/* count printed: magnitude never relies on hue alone */}
                        <span className="font-mono text-[10px] font-bold text-white/90 tabular-nums">
                          {count}
                        </span>
                      </div>
                    );
                  })}
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* ramp legend + hover readout */}
      <div className="mt-4 flex flex-wrap items-center justify-between gap-4 border-t border-slate-800 pt-3">
        <div className="flex items-center gap-2">
          <span className="text-[10px] text-slate-500">{isAr ? 'أقل' : 'Low'}</span>
          <div className="flex gap-0.5">
            {[0.2, 0.4, 0.6, 0.8, 1].map(t => (
              <span
                key={t}
                className="h-2.5 w-6 rounded-[2px]"
                style={{ background: heatStep(t) }}
              />
            ))}
          </div>
          <span className="text-[10px] text-slate-500">{isAr ? 'أكثر' : 'High'}</span>
        </div>

        {hover ? (
          <div className="truncate font-mono text-[11px] text-slate-300">
            {hover.tactic} · {hover.technique} ·{' '}
            <span className="font-bold text-slate-100">{hover.count}</span>
          </div>
        ) : (
          <div className="flex items-center gap-1.5 text-[11px] text-emerald-400">
            <ShieldCheck className="h-3.5 w-3.5" />
            {isAr ? 'كل التقنيات المرصودة جرى احتواؤها' : 'All observed techniques contained'}
          </div>
        )}
      </div>
    </section>
  );
};
