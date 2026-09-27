import React from 'react';
import { motion, AnimatePresence, useReducedMotion } from 'motion/react';
import { Hexagon, Network, Settings, Bell, ShieldAlert } from 'lucide-react';
import { EarthGlobeView } from './EarthGlobeView';
import { AlluvialFlowView } from './AlluvialFlowView';
import { AlertsView } from './AlertsView';
import { GaugeAnalyticsView } from './GaugeAnalyticsView';
import { useCyberDefendData } from './useCyberDefendData';
import { FIELD, Mono } from './parts';
import { cn } from '../../../lib/utils';
import type { ThreatOrigin } from './ThreatGlobeCanvas';

/**
 * CYBERDEFEND — layout wrapper
 *
 * Header, pill tabs, and the three views. Nothing else: this file was a thousand
 * lines with all three screens inlined, and it was split because a file that large
 * is hard to review and — on this host — hard even to write in one pass.
 *
 * The visual language is the reference design's: near-black field, frosted glass,
 * a pill capsule with a spring-animated indicator, neon cyan and crimson.
 *
 * The data is this platform's own. The reference was a satellite and energy console;
 * copying its numbers would mean hardcoding roughly forty invented figures into a
 * security product, which rule 0 of `.clauderules` forbids. The mapping from
 * reference element to real endpoint lives in `useCyberDefendData.ts`.
 *
 * The strip under the header names any endpoint that did not answer, so a view that
 * is quiet is distinguishable from a platform that is idle.
 */

type Tab = 'overview' | 'firewall' | 'alerts' | 'attacks';

interface Props {
  lang?: 'ar' | 'en';
  apiKey?: string;
}

export const CyberDefendPlatform: React.FC<Props> = ({ lang = 'ar', apiKey }) => {
  const isAr = lang === 'ar';
  const reduce = useReducedMotion() ?? false;
  const d = useCyberDefendData(apiKey);
  const [tab, setTab] = React.useState<Tab>('overview');
  const [selectedNode, setSelectedNode] = React.useState(0);
  const [nodeQuery, setNodeQuery] = React.useState('');

  const TABS: Array<{ id: Tab; en: string; ar: string }> = [
    { id: 'overview', en: 'Overview', ar: 'النظرة العامة' },
    { id: 'firewall', en: 'Firewall', ar: 'الجدار الناري' },
    { id: 'alerts', en: 'Alerts', ar: 'التنبيهات' },
    { id: 'attacks', en: 'Attacks', ar: 'الهجمات' }
  ];

  const origins: ThreatOrigin[] = d.geo.map(g => ({ country: g.country, code: g.code, count: g.count }));

  return (
    <div
      className="min-h-screen w-full text-slate-200"
      style={{ background: FIELD, fontFamily: 'var(--font-sans)' }}
      dir={isAr ? 'rtl' : 'ltr'}
    >
      <header
        className="sticky top-0 z-40 border-b border-slate-800/60 backdrop-blur-2xl"
        style={{ background: `${FIELD}D9` }}
      >
        <div className="mx-auto flex max-w-[1680px] items-center justify-between gap-4 px-4 py-2.5">
          {/* Brand */}
          <div className="flex items-center gap-2.5">
            <div className="relative">
              <Hexagon className="h-7 w-7 text-[#38BDF8]" strokeWidth={1.5} aria-hidden />
              <ShieldAlert
                className="absolute inset-0 m-auto h-3.5 w-3.5 text-[#7dd3fc]"
                strokeWidth={2}
                aria-hidden
              />
            </div>
            <span className="text-[15px] font-bold tracking-tight text-white">CYBERDEFEND</span>
            <span className="relative inline-flex items-center gap-1 rounded-full border border-[#10B981]/40 bg-[#10B981]/10 px-2 py-0.5">
              {!reduce && (
                <motion.span
                  className="absolute inset-0 rounded-full bg-[#10B981]/20"
                  animate={{ opacity: [0.35, 0.05, 0.35] }}
                  transition={{ duration: 2.4, repeat: Infinity, ease: 'easeInOut' }}
                  aria-hidden
                />
              )}
              <span className="relative h-1.5 w-1.5 rounded-full bg-[#10B981]" aria-hidden />
              <span className="relative text-[9px] font-semibold tracking-wider text-[#6ee7b7]">ACTIVE</span>
            </span>
          </div>

          {/* Pill tab capsule */}
          <nav
            className="flex items-center gap-1 rounded-full border border-white/10 p-1 backdrop-blur-xl"
            style={{ background: 'rgba(255,255,255,0.04)' }}
            role="tablist"
            aria-label={isAr ? 'شاشات المنصة' : 'Platform views'}
          >
            {TABS.map(t => {
              const active = tab === t.id;
              return (
                <button
                  key={t.id}
                  role="tab"
                  aria-selected={active}
                  onClick={() => setTab(t.id)}
                  className={cn(
                    'relative rounded-full px-3.5 py-1.5 text-[11px] font-medium transition-colors',
                    'focus-visible:ring-2 focus-visible:ring-[#38BDF8]/60 focus-visible:outline-none',
                    active ? 'text-slate-900' : 'text-slate-400 hover:text-slate-200'
                  )}
                >
                  {active && (
                    <motion.span
                      layoutId="cd-pill"
                      className="absolute inset-0 rounded-full bg-white shadow-lg shadow-white/10"
                      transition={reduce ? { duration: 0 } : { type: 'spring', stiffness: 380, damping: 32 }}
                      aria-hidden
                    />
                  )}
                  <span className="relative">{isAr ? t.ar : t.en}</span>
                </button>
              );
            })}
          </nav>

          {/* Quick controls */}
          <div className="flex items-center gap-1.5">
            {[
              { Icon: Network, label: isAr ? 'العقد' : 'Nodes' },
              { Icon: Settings, label: isAr ? 'الإعدادات' : 'Settings' }
            ].map(({ Icon, label }) => (
              <button
                key={label}
                aria-label={label}
                className="rounded-full border border-white/10 bg-white/5 p-1.5 text-slate-400 transition-colors hover:text-slate-100 focus-visible:ring-2 focus-visible:ring-[#38BDF8]/60 focus-visible:outline-none"
              >
                <Icon className="h-3.5 w-3.5" />
              </button>
            ))}
            <button
              aria-label={isAr ? 'التنبيهات' : 'Notifications'}
              className="relative rounded-full border border-white/10 bg-white/5 p-1.5 text-slate-400 transition-colors hover:text-slate-100 focus-visible:ring-2 focus-visible:ring-[#38BDF8]/60 focus-visible:outline-none"
            >
              <Bell className="h-3.5 w-3.5" />
              {d.alerts.some(a => /CRITICAL|HIGH/.test(a.severity)) && (
                <span className="absolute top-0.5 right-0.5 h-1.5 w-1.5 rounded-full bg-[#EF4444]" aria-hidden />
              )}
            </button>
          </div>
        </div>

        {/* Named missing sources. A quiet view must be distinguishable from an idle
            platform, and only the endpoint list can tell them apart. */}
        {d.missing.length > 0 && (
          <div className="border-t border-[#F59E0B]/20 bg-[#F59E0B]/5 px-4 py-1">
            <p className="mx-auto max-w-[1680px] text-[9px] text-[#fcd34d]">
              {isAr ? 'مصادر لم تُجب: ' : 'Sources that did not answer: '}
              <Mono>{d.missing.join(' · ')}</Mono>
              {isAr ? ' — القيم المتعلّقة بها تُعرض شرطة.' : ' — figures from them render as an em dash.'}
            </p>
          </div>
        )}
      </header>

      <main className="mx-auto max-w-[1680px] px-4 py-4">
        <AnimatePresence mode="wait">
          <motion.div
            key={tab}
            initial={reduce ? { opacity: 0 } : { opacity: 0, y: 6 }}
            animate={{ opacity: 1, y: 0 }}
            exit={reduce ? { opacity: 0 } : { opacity: 0, y: -6 }}
            transition={{ duration: 0.22, ease: 'easeOut' }}
            role="tabpanel"
          >
            {tab === 'overview' && (
              <EarthGlobeView
                d={d}
                isAr={isAr}
                reduce={reduce}
                origins={origins}
                selectedNode={selectedNode}
                setSelectedNode={setSelectedNode}
                nodeQuery={nodeQuery}
                setNodeQuery={setNodeQuery}
              />
            )}
            {tab === 'firewall' && <AlluvialFlowView d={d} isAr={isAr} reduce={reduce} />}
            {tab === 'alerts' && <AlertsView d={d} isAr={isAr} reduce={reduce} />}
            {tab === 'attacks' && <GaugeAnalyticsView d={d} isAr={isAr} reduce={reduce} />}
          </motion.div>
        </AnimatePresence>
      </main>
    </div>
  );
};

export default CyberDefendPlatform;
