import React, { useEffect, useState } from 'react';
import { ShieldCheck, Radio } from 'lucide-react';
import { Sparkline, SEV_COLOR } from './charts/primitives';

/**
 * POSTURE STRIP
 *
 * The four numbers a reviewer reads first. Each tile pairs the current value
 * with a sparkline of its recent trend, because a bare number says nothing
 * about direction — the trend is what tells an analyst whether the situation
 * is developing or settling.
 *
 * Series come from the live analytics feed; tiles render a skeleton until the
 * first payload lands rather than flashing a zero.
 */

interface FreqPoint { reqSec: number; cleanSec: number; blockedSec: number; rateLimitedSec: number; }

interface Props {
  lang?: 'ar' | 'en';
  flightMode: string;
  threatsBlocked: number;
}

export const PostureStrip: React.FC<Props> = ({ lang = 'ar', flightMode, threatsBlocked }) => {
  const isAr = lang === 'ar';
  const [series, setSeries] = useState<FreqPoint[] | null>(null);

  useEffect(() => {
    const load = async () => {
      try {
        const res = await fetch('/api/v1/soc/analytics');
        if (!res.ok) return;
        const d = await res.json();
        if (Array.isArray(d?.frequencyGraph)) setSeries(d.frequencyGraph);
      } catch { /* keep last known */ }
    };
    load();
    const t = setInterval(load, 5000);
    return () => clearInterval(t);
  }, []);

  const req = series?.map(p => p.reqSec) ?? [];
  const blocked = series?.map(p => p.blockedSec) ?? [];
  const clean = series?.map(p => p.cleanSec) ?? [];
  const last = <T,>(a: T[], f: T): T => (a.length ? a[a.length - 1] : f);

  const blockRate = series && series.length
    ? ((blocked.reduce((s, v) => s + v, 0) / Math.max(1, req.reduce((s, v) => s + v, 0))) * 100)
    : null;

  const Skeleton = () => <div className="h-8 w-[120px] rounded bg-slate-800/50 animate-pulse" />;

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4" dir={isAr ? 'rtl' : 'ltr'}>
      {/* throughput */}
      <div className="soc-panel p-4 flex flex-col justify-between">
        <div className="flex items-start justify-between gap-2">
          <div>
            <div className="soc-label">{isAr ? 'الحركة الواردة' : 'Ingress rate'}</div>
            <div className="mt-2 flex items-baseline gap-1.5 font-mono">
              <span className="text-[26px] leading-none font-bold text-slate-100 tabular-nums">
                {last(req, 0)}
              </span>
              <span className="text-xs text-slate-400">req/s</span>
            </div>
          </div>
          <span className="flex items-center gap-1 text-[10px] text-emerald-400 font-semibold shrink-0">
            <span className="relative flex w-1.5 h-1.5">
              <span className="absolute inline-flex w-full h-full rounded-full bg-emerald-500 opacity-70 animate-ping" />
              <span className="relative inline-flex w-1.5 h-1.5 rounded-full bg-emerald-500" />
            </span>
            {isAr ? 'مباشر' : 'Live'}
          </span>
        </div>
        <div className="mt-3">{series ? <Sparkline values={req} color="#58a6ff" /> : <Skeleton />}</div>
      </div>

      {/* hostile blocked */}
      <div className="soc-panel p-4 sev-critical flex flex-col justify-between">
        <div>
          <div className="soc-label">{isAr ? 'حظر عدائي' : 'Hostile blocked'}</div>
          <div className="mt-2 flex items-baseline gap-1.5 font-mono">
            <span className="text-[26px] leading-none font-bold text-rose-400 tabular-nums">
              {last(blocked, 0)}
            </span>
            <span className="text-xs text-slate-400">req/s</span>
          </div>
          <div className="text-[11px] text-slate-500 mt-1">
            {blockRate === null ? '—' : `${blockRate.toFixed(1)}% ${isAr ? 'من التدفق' : 'of stream'}`}
          </div>
        </div>
        <div className="mt-3">{series ? <Sparkline values={blocked} color={SEV_COLOR.CRITICAL} /> : <Skeleton />}</div>
      </div>

      {/* clean traffic served */}
      <div className="soc-panel p-4 flex flex-col justify-between">
        <div>
          <div className="soc-label">{isAr ? 'حركة سليمة مخدومة' : 'Clean traffic served'}</div>
          <div className="mt-2 flex items-baseline gap-1.5 font-mono">
            <span className="text-[26px] leading-none font-bold text-emerald-400 tabular-nums">
              {last(clean, 0)}
            </span>
            <span className="text-xs text-slate-400">req/s</span>
          </div>
          <div className="text-[11px] text-slate-500 font-mono mt-1">
            {threatsBlocked.toLocaleString()} {isAr ? 'حزمة مُسقطة تراكمياً' : 'dropped total'}
          </div>
        </div>
        <div className="mt-3">{series ? <Sparkline values={clean} color={SEV_COLOR.LOW} /> : <Skeleton />}</div>
      </div>

      {/* posture */}
      <div className="soc-panel p-4 flex flex-col justify-between">
        <div>
          <div className="soc-label">{isAr ? 'وضع الدفاع' : 'Defense posture'}</div>
          <div className="mt-2 flex items-center gap-2">
            <ShieldCheck className="w-5 h-5 text-emerald-400 shrink-0" />
            <span className="text-base font-bold text-slate-100 leading-tight">
              {flightMode === 'AUTOPILOT' ? (isAr ? 'ذاتي التشغيل' : 'Autonomous') : (isAr ? 'إشراف بشري' : 'Supervised')}
            </span>
          </div>
        </div>
        <div className="mt-3 flex flex-wrap gap-1.5">
          {['eBPF/XDP', 'WAF', 'FIM', 'Zero-Trust'].map(t => (
            <span key={t} className="font-mono text-[10px] px-1.5 py-0.5 rounded border border-slate-700 bg-slate-800/60 text-slate-400">
              {t}
            </span>
          ))}
        </div>
      </div>
    </div>
  );
};
