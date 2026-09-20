import React, { useEffect, useMemo, useState } from 'react';
import { Activity, Filter, ShieldAlert, Table2 } from 'lucide-react';
import { StackedBars, Legend, RankedBar, SEV_COLOR, type StackBucket } from './charts/primitives';

/**
 * SECURITY ANALYTICS ROW
 *
 * Three questions a reviewer asks in the first ten seconds, answered as
 * charts rather than prose:
 *   1. what is the traffic doing, and how much of it is hostile (over time)
 *   2. where is the hostile traffic coming from (ranked origins)
 *   3. how is it being absorbed (the progressive-mitigation funnel)
 *
 * Every figure is read from /api/v1/soc/analytics — the same numbers the
 * platform runs on, not decorative sample data.
 */

interface FreqPoint {
  time: string;
  timestamp: string;
  reqSec: number;
  cleanSec: number;
  blockedSec: number;
  rateLimitedSec: number;
}
interface GeoRow { country: string; code: string; flag: string; attackCount: number; topVector: string; threatTier: string; }
interface Analytics {
  frequencyGraph: FreqPoint[];
  geoThreatDistribution: GeoRow[];
  progressiveMitigation: {
    tier1RateLimitedCount: number;
    tier2ChallengedCount: number;
    tier3CriticalBlockedCount: number;
    activeTier1Sessions: number;
    activeTier2Challenges: number;
    activeTier3HardBans: number;
  };
}

interface Props { lang?: 'ar' | 'en'; }

export const SecurityAnalyticsRow: React.FC<Props> = ({ lang = 'ar' }) => {
  const isAr = lang === 'ar';
  const [data, setData] = useState<Analytics | null>(null);
  const [showTable, setShowTable] = useState(false);

  useEffect(() => {
    const load = async () => {
      try {
        const res = await fetch('/api/v1/soc/analytics');
        if (!res.ok) return;
        const d = await res.json();
        if (d?.success) setData(d);
      } catch { /* keep last known */ }
    };
    load();
    const t = setInterval(load, 5000);
    return () => clearInterval(t);
  }, []);

  const buckets: StackBucket[] = useMemo(() => {
    if (!data?.frequencyGraph) return [];
    return data.frequencyGraph.map(p => ({
      label: p.time,
      segments: [
        { key: 'blocked', value: p.blockedSec, color: SEV_COLOR.CRITICAL, label: isAr ? 'محظورة' : 'Blocked' },
        { key: 'limited', value: p.rateLimitedSec, color: SEV_COLOR.HIGH, label: isAr ? 'مُقيّدة' : 'Rate-limited' },
        { key: 'clean', value: p.cleanSec, color: SEV_COLOR.LOW, label: isAr ? 'سليمة' : 'Clean' }
      ]
    }));
  }, [data, isAr]);

  const totals = useMemo(() => {
    const g = data?.frequencyGraph ?? [];
    const sum = (k: keyof FreqPoint) => g.reduce((s, p) => s + (Number(p[k]) || 0), 0);
    const blocked = sum('blockedSec'), limited = sum('rateLimitedSec'), clean = sum('cleanSec');
    const all = blocked + limited + clean || 1;
    return {
      blocked, limited, clean, all,
      hostilePct: (((blocked + limited) / all) * 100).toFixed(1)
    };
  }, [data]);

  const geo = (data?.geoThreatDistribution ?? []).slice(0, 5);
  const geoMax = Math.max(1, ...geo.map(g => g.attackCount));

  const funnel = data?.progressiveMitigation;
  const funnelRows = funnel ? [
    { k: 't1', ar: 'المستوى 1 — تقييد المعدل', en: 'Tier 1 — rate limit', v: funnel.tier1RateLimitedCount, live: funnel.activeTier1Sessions, color: SEV_COLOR.LOW },
    { k: 't2', ar: 'المستوى 2 — تحدٍّ تفاعلي', en: 'Tier 2 — challenge',  v: funnel.tier2ChallengedCount,  live: funnel.activeTier2Challenges, color: SEV_COLOR.HIGH },
    { k: 't3', ar: 'المستوى 3 — حظر جذري',    en: 'Tier 3 — hard block', v: funnel.tier3CriticalBlockedCount, live: funnel.activeTier3HardBans, color: SEV_COLOR.CRITICAL }
  ] : [];
  const funnelMax = Math.max(1, ...funnelRows.map(r => r.v));

  const legendItems = [
    { label: isAr ? 'محظورة' : 'Blocked', color: SEV_COLOR.CRITICAL },
    { label: isAr ? 'مُقيّدة' : 'Rate-limited', color: SEV_COLOR.HIGH },
    { label: isAr ? 'سليمة' : 'Clean', color: SEV_COLOR.LOW }
  ];

  return (
    <div className="grid grid-cols-1 xl:grid-cols-[minmax(0,1.6fr)_minmax(0,1fr)_minmax(0,1fr)] gap-5" dir={isAr ? 'rtl' : 'ltr'}>
      {/* ---------- 1. traffic over time ---------- */}
      <section className="soc-panel p-5">
        <div className="flex items-start justify-between gap-3 mb-1">
          <div>
            <h3 className="text-sm font-bold text-slate-100">
              {isAr ? 'حركة المرور والحظر عبر الزمن' : 'Traffic & blocking over time'}
            </h3>
            <p className="text-[11px] text-slate-500 mt-0.5">
              {isAr ? 'طلبات/ثانية — مقسّمة حسب القرار' : 'Requests per second, split by verdict'}
            </p>
          </div>
          <button
            onClick={() => setShowTable(v => !v)}
            title={isAr ? 'عرض كجدول' : 'Table view'}
            className="shrink-0 p-1.5 rounded-md border border-slate-800 text-slate-500 hover:text-slate-200 hover:border-slate-700 transition-colors"
          >
            <Table2 className="w-3.5 h-3.5" />
          </button>
        </div>

        {/* headline: how much of the stream is hostile */}
        <div className="flex items-baseline gap-2 mb-4">
          <span className="font-mono text-2xl font-bold text-slate-100 tabular-nums">{totals.hostilePct}%</span>
          <span className="text-[11px] text-slate-400">{isAr ? 'من الحركة عدائية ومُعالَجة' : 'of traffic hostile & handled'}</span>
        </div>

        {buckets.length === 0 ? (
          <div className="h-[130px] rounded-lg bg-slate-800/40 animate-pulse" />
        ) : showTable ? (
          <div className="max-h-[150px] overflow-y-auto">
            <table className="w-full text-[11px]">
              <thead className="text-slate-500">
                <tr className="text-start">
                  <th className="text-start font-medium py-1">{isAr ? 'الوقت' : 'Time'}</th>
                  <th className="text-end font-medium">{isAr ? 'سليمة' : 'Clean'}</th>
                  <th className="text-end font-medium">{isAr ? 'مُقيّدة' : 'Limited'}</th>
                  <th className="text-end font-medium">{isAr ? 'محظورة' : 'Blocked'}</th>
                </tr>
              </thead>
              <tbody className="font-mono text-slate-300">
                {data!.frequencyGraph.map(p => (
                  <tr key={p.timestamp} className="border-t border-slate-800/60">
                    <td className="py-1 text-slate-500">{p.time}</td>
                    <td className="text-end tabular-nums">{p.cleanSec}</td>
                    <td className="text-end tabular-nums">{p.rateLimitedSec}</td>
                    <td className="text-end tabular-nums">{p.blockedSec}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <StackedBars buckets={buckets} height={130} isAr={isAr} />
        )}

        <div className="mt-3 pt-3 border-t border-slate-800">
          <Legend items={legendItems} />
        </div>
      </section>

      {/* ---------- 2. ranked origins ---------- */}
      <section className="soc-panel p-5">
        <h3 className="text-sm font-bold text-slate-100">
          {isAr ? 'أعلى مصادر الهجوم' : 'Top attack origins'}
        </h3>
        <p className="text-[11px] text-slate-500 mt-0.5 mb-4">
          {isAr ? 'حسب عدد المحاولات المرصودة' : 'By observed attempts'}
        </p>

        {geo.length === 0 ? (
          <div className="space-y-3">
            {[0, 1, 2, 3].map(i => <div key={i} className="h-8 rounded bg-slate-800/40 animate-pulse" />)}
          </div>
        ) : (
          <div className="space-y-3">
            {geo.map(g => (
              <div key={g.code}>
                <div className="flex items-center gap-2 mb-1.5">
                  <span aria-hidden="true">{g.flag}</span>
                  <span className="text-[12px] text-slate-200 truncate">{g.country}</span>
                  <span className="font-mono text-[11px] text-slate-300 ms-auto tabular-nums">{g.attackCount}</span>
                </div>
                <RankedBar
                  value={g.attackCount}
                  max={geoMax}
                  color={g.threatTier === 'CRITICAL' ? SEV_COLOR.CRITICAL : SEV_COLOR.HIGH}
                />
                <div className="font-mono text-[10px] text-slate-600 mt-1 truncate">{g.topVector}</div>
              </div>
            ))}
          </div>
        )}
      </section>

      {/* ---------- 3. progressive mitigation funnel ---------- */}
      <section className="soc-panel p-5">
        <h3 className="text-sm font-bold text-slate-100">
          {isAr ? 'تدرّج الاستجابة' : 'Progressive response'}
        </h3>
        <p className="text-[11px] text-slate-500 mt-0.5 mb-4">
          {isAr ? 'الرد يتصاعد بحسب الخطورة، لا حظر فوري للجميع' : 'Response escalates with severity — not a blanket block'}
        </p>

        {funnelRows.length === 0 ? (
          <div className="space-y-3">
            {[0, 1, 2].map(i => <div key={i} className="h-10 rounded bg-slate-800/40 animate-pulse" />)}
          </div>
        ) : (
          <div className="space-y-4">
            {funnelRows.map(r => (
              <div key={r.k}>
                <div className="flex items-center gap-2 mb-1.5">
                  <span className="w-2.5 h-2.5 rounded-[3px] shrink-0" style={{ background: r.color }} />
                  <span className="text-[12px] text-slate-200">{isAr ? r.ar : r.en}</span>
                  <span className="font-mono text-[11px] text-slate-300 ms-auto tabular-nums">{r.v}</span>
                </div>
                <RankedBar value={r.v} max={funnelMax} color={r.color} />
                <div className="flex items-center gap-1.5 mt-1">
                  <Activity className="w-3 h-3 text-slate-600" />
                  <span className="font-mono text-[10px] text-slate-500">
                    {r.live} {isAr ? 'نشطة الآن' : 'active now'}
                  </span>
                </div>
              </div>
            ))}
          </div>
        )}
      </section>
    </div>
  );
};
