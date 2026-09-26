import React, { useEffect, useMemo, useState } from 'react';
import { Globe2, Shield, Server, Database, FileLock2, Cpu, Ban } from 'lucide-react';

/**
 * ATTACK PATH GRAPH
 *
 * A relationship view rather than a list: the actor, the controls it met, and
 * the assets behind them, drawn as a left-to-right (RTL-aware) path. This is
 * the "how did it connect" question that a flat alert list cannot answer.
 *
 * Each hop states whether it was crossed or held, so the path reads as a
 * story with an outcome — the edge where the chain stopped is drawn solid and
 * labelled, while everything past it stays dashed and dim.
 */

interface Node {
  id: string;
  ar: string;
  en: string;
  sub?: string;
  icon: React.ElementType;
  kind: 'actor' | 'control' | 'asset';
}

const PATH: Node[] = [
  { id: 'actor', ar: 'مصدر خارجي', en: 'External actor', icon: Globe2, kind: 'actor' },
  {
    id: 'xdp',
    ar: 'فلتر النواة',
    en: 'Kernel filter',
    sub: 'eBPF/XDP',
    icon: Cpu,
    kind: 'control'
  },
  {
    id: 'waf',
    ar: 'جدار التطبيقات',
    en: 'App firewall',
    sub: 'WAF/L7',
    icon: Shield,
    kind: 'control'
  },
  {
    id: 'app',
    ar: 'خادم التطبيق',
    en: 'App server',
    sub: '10.0.1.10',
    icon: Server,
    kind: 'asset'
  },
  { id: 'fim', ar: 'حارس الملفات', en: 'File guard', sub: 'FIM', icon: FileLock2, kind: 'control' },
  {
    id: 'db',
    ar: 'قاعدة البيانات',
    en: 'Database',
    sub: '10.0.2.20',
    icon: Database,
    kind: 'asset'
  }
];

interface Props {
  lang?: 'ar' | 'en';
  /** Index of the hop where the chain was stopped. */
  stoppedAt?: number;
  actorIp?: string;
}

export const AttackPathGraph: React.FC<Props> = ({ lang = 'ar', stoppedAt = 1, actorIp }) => {
  const isAr = lang === 'ar';

  return (
    <section className="soc-panel p-5" dir={isAr ? 'rtl' : 'ltr'}>
      <div className="mb-5">
        <h3 className="text-sm font-bold text-slate-100">
          {isAr ? 'مسار الهجوم نحو الأصول' : 'Attack path to assets'}
        </h3>
        <p className="mt-0.5 text-[11px] text-slate-500">
          {isAr
            ? 'العلاقة بين المصدر والضوابط والأصول — وأين انقطع المسار.'
            : 'How the actor, the controls and the assets connect — and where the path broke.'}
        </p>
      </div>

      <div className="overflow-x-auto pb-2">
        <div className="flex min-w-[760px] items-stretch gap-0">
          {PATH.map((n, i) => {
            const Icon = n.icon;
            const blocked = i === stoppedAt;
            const reached = i < stoppedAt;
            const unreached = i > stoppedAt;

            return (
              <React.Fragment key={n.id}>
                {/* node */}
                <div className="flex w-[120px] shrink-0 flex-col items-center gap-2">
                  <div
                    className={`flex h-14 w-14 items-center justify-center rounded-xl border transition-colors ${
                      blocked
                        ? 'border-emerald-500/60 bg-emerald-500/10'
                        : reached
                          ? 'border-rose-500/50 bg-rose-500/10'
                          : 'border-slate-800 bg-slate-900/60'
                    }`}
                  >
                    <Icon
                      className={`h-6 w-6 ${
                        blocked ? 'text-emerald-400' : reached ? 'text-rose-400' : 'text-slate-600'
                      }`}
                    />
                  </div>
                  <div className="text-center">
                    <div
                      className={`text-[12px] leading-tight font-semibold ${unreached ? 'text-slate-500' : 'text-slate-100'}`}
                    >
                      {isAr ? n.ar : n.en}
                    </div>
                    {n.id === 'actor' && actorIp ? (
                      <div className="mt-0.5 font-mono text-[10px] text-slate-400">{actorIp}</div>
                    ) : n.sub ? (
                      <div className="mt-0.5 font-mono text-[10px] text-slate-500">{n.sub}</div>
                    ) : null}
                    {blocked && (
                      <div className="mt-1.5 inline-flex items-center gap-1 text-[10px] font-semibold text-emerald-300">
                        <Ban className="h-3 w-3" />
                        {isAr ? 'توقف هنا' : 'Stopped'}
                      </div>
                    )}
                  </div>
                </div>

                {/* edge */}
                {i < PATH.length - 1 && (
                  <div className="flex min-w-[40px] flex-1 items-start pt-7">
                    <div className="relative w-full">
                      <div
                        className={`h-[2px] w-full rounded ${
                          i < stoppedAt ? 'bg-rose-500/70' : 'bg-slate-800'
                        }`}
                        style={
                          i >= stoppedAt
                            ? {
                                backgroundImage:
                                  'repeating-linear-gradient(90deg,#2d3948 0 6px,transparent 6px 12px)',
                                backgroundColor: 'transparent'
                              }
                            : undefined
                        }
                      />
                      {i === stoppedAt && (
                        <span className="absolute inset-x-0 -top-2 flex justify-center">
                          <span className="bg-[var(--surface-panel)] px-1.5 text-[16px] leading-none text-emerald-400">
                            ×
                          </span>
                        </span>
                      )}
                    </div>
                  </div>
                )}
              </React.Fragment>
            );
          })}
        </div>
      </div>

      {/* legend — identity never by colour alone */}
      <div className="mt-4 flex flex-wrap items-center gap-x-5 gap-y-2 border-t border-slate-800 pt-3">
        <span className="flex items-center gap-1.5 text-[11px] text-slate-400">
          <span className="h-2.5 w-2.5 rounded-[3px] bg-rose-500" />
          {isAr ? 'مسار جرى بلوغه' : 'Path traversed'}
        </span>
        <span className="flex items-center gap-1.5 text-[11px] text-slate-400">
          <span className="h-2.5 w-2.5 rounded-[3px] bg-emerald-500" />
          {isAr ? 'نقطة الإيقاف' : 'Stop point'}
        </span>
        <span className="flex items-center gap-1.5 text-[11px] text-slate-400">
          <span className="h-2.5 w-2.5 rounded-[3px] border border-slate-700 bg-slate-900" />
          {isAr ? 'لم يُبلَغ' : 'Never reached'}
        </span>
      </div>
    </section>
  );
};
