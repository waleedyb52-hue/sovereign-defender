import React from 'react';
import { motion, AnimatePresence, useReducedMotion } from 'motion/react';
import {
  Hexagon, Network, Settings, Bell, Search, Radar, Satellite, Gauge,
  Activity, ShieldAlert, Cpu, Radio, TrendingUp, Layers, CircleDot
} from 'lucide-react';
import { ThreatGlobeCanvas, type ThreatOrigin } from './ThreatGlobeCanvas';
import { useCyberDefendData } from './useCyberDefendData';
import { cn, formatCount } from '../../../lib/utils';

/**
 * CYBERDEFEND — orbital command surface
 *
 * The reference design's visual language, reproduced: near-black field, frosted
 * glass cards, a pill tab capsule, neon cyan and crimson, a rotating globe with
 * ballistic arcs, an alluvial flow view, and dual-arc gauges.
 *
 * What is NOT reproduced is its data. The reference was a satellite and energy
 * operations console — orbital telemetry, ground stations, megawatt-hours, fuel
 * sources, household costs. This platform has none of those, so copying the numbers
 * would mean hardcoding about forty invented figures into a security console. Rule 0
 * of `.clauderules` forbids exactly that, and this codebase has had to remove five
 * separate instances of it.
 *
 * So every value here is read from a real endpoint, and the mapping lives in
 * `useCyberDefendData.ts` where it can be audited. Where a source is absent the
 * surface shows an em dash and names the missing endpoint — an honest gap rather
 * than a plausible number.
 *
 * On the three tabs
 *   Overview   — the orbital view: real threat origins, a real cluster node under
 *                inspection, real kernel telemetry with its provenance stated.
 *   Firewall   — the alluvial view: real endpoints flowing into real mitigation
 *                tiers, with the drift report as the anomaly window.
 *   Attacks    — the gauge view: threats blocked against requests protected, real
 *                family distribution, real threat density.
 */

type Tab = 'overview' | 'firewall' | 'attacks';

const SURFACE = '#0A0F1D';
const FIELD = '#04070D';

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
    { id: 'attacks', en: 'Attacks', ar: 'الهجمات' }
  ];

  const origins: ThreatOrigin[] = d.geo.map(g => ({ country: g.country, code: g.code, count: g.count }));
  const node = d.nodes[selectedNode] ?? d.nodes[0] ?? null;

  return (
    <div
      className="min-h-screen w-full text-slate-200"
      style={{ background: FIELD, fontFamily: 'var(--font-sans)' }}
      dir={isAr ? 'rtl' : 'ltr'}
    >
      {/* ── Global top navigation ─────────────────────────────────────────── */}
      <header className="sticky top-0 z-40 border-b border-slate-800/60 backdrop-blur-2xl" style={{ background: `${FIELD}D9` }}>
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

          {/* Pill tab capsule, frosted */}
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

          {/* Quick system controls */}
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
              {(d.kernel.blackholes ?? 0) > 0 && (
                <span className="absolute top-0.5 right-0.5 h-1.5 w-1.5 rounded-full bg-[#EF4444]" aria-hidden />
              )}
            </button>
          </div>
        </div>

        {/* Missing-source strip. Named, never silently empty. */}
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
          >
            {tab === 'overview' && (
              <OverviewTab
                d={d}
                isAr={isAr}
                reduce={reduce}
                origins={origins}
                node={node}
                selectedNode={selectedNode}
                setSelectedNode={setSelectedNode}
                nodeQuery={nodeQuery}
                setNodeQuery={setNodeQuery}
              />
            )}
            {tab === 'firewall' && <FirewallTab d={d} isAr={isAr} reduce={reduce} />}
            {tab === 'attacks' && <AttacksTab d={d} isAr={isAr} reduce={reduce} />}
          </motion.div>
        </AnimatePresence>
      </main>
    </div>
  );
};

/* ── Shared atoms ─────────────────────────────────────────────────────────── */

const Mono: React.FC<{ children: React.ReactNode; className?: string }> = ({ children, className }) => (
  <span className={cn('tabular-nums', className)} style={{ fontFamily: 'var(--font-mono)' }} dir="ltr">
    {children}
  </span>
);

/** Frosted glass card, the reference's primary surface. */
const Glass: React.FC<{ children: React.ReactNode; className?: string }> = ({ children, className }) => (
  <div
    className={cn('rounded-2xl border border-white/10 shadow-2xl shadow-black/60 backdrop-blur-2xl', className)}
    style={{ background: `${SURFACE}BF` }}
  >
    {children}
  </div>
);

const Label: React.FC<{ children: React.ReactNode }> = ({ children }) => (
  <span className="text-[9px] font-medium tracking-[0.12em] text-slate-500 uppercase">{children}</span>
);

/** A value that renders an em dash and a reason when its source is absent. */
const Value: React.FC<{ v: number | string | null; unit?: string; reason?: string; className?: string }> = ({
  v,
  unit,
  reason,
  className
}) =>
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

/* ── Tab 1: Overview ─────────────────────────────────────────────────────── */

type D = ReturnType<typeof useCyberDefendData>;

const OverviewTab: React.FC<{
  d: D;
  isAr: boolean;
  reduce: boolean;
  origins: ThreatOrigin[];
  node: D['nodes'][number] | null;
  selectedNode: number;
  setSelectedNode: (n: number) => void;
  nodeQuery: string;
  setNodeQuery: (s: string) => void;
}> = ({ d, isAr, reduce, origins, node, selectedNode, setSelectedNode, nodeQuery, setNodeQuery }) => {
  const filtered = d.nodes.filter(
    n => !nodeQuery || n.name.toLowerCase().includes(nodeQuery.toLowerCase()) || n.ip.includes(nodeQuery)
  );
  const top = d.geo[0] ?? null;

  return (
    <div className="space-y-4">
      {/* Globe theatre with floating cards */}
      <div className="relative overflow-hidden rounded-2xl border border-white/10">
        <ThreatGlobeCanvas
          origins={origins}
          target={{ label: 'SOC', lat: 24.7, lon: 46.7 }}
          height={460}
          reducedMotion={reduce}
          className="block w-full"
        />

        {/* Left: kernel telemetry, in the radar card's position */}
        <Glass className="absolute top-3 start-3 w-[268px] p-3">
          <div className="mb-2 flex items-center gap-1.5">
            <Radar className="h-3.5 w-3.5 text-[#38BDF8]" aria-hidden />
            <Label>{isAr ? 'قياسات النواة' : 'Kernel telemetry'}</Label>
          </div>

          {/* Radar sweep, real only in that the ring count tracks live blackholes. */}
          <div className="relative mx-auto mb-2.5 h-[104px] w-[104px]">
            <div className="absolute inset-0 rounded-full border border-[#38BDF8]/25" />
            <div className="absolute inset-[18%] rounded-full border border-[#38BDF8]/15" />
            <div className="absolute inset-[38%] rounded-full border border-[#38BDF8]/10" />
            {!reduce && (
              <motion.div
                className="absolute inset-0 rounded-full"
                style={{
                  background: 'conic-gradient(from 0deg, rgba(56,189,248,0.30), rgba(56,189,248,0) 28%)'
                }}
                animate={{ rotate: 360 }}
                transition={{ duration: 3.6, repeat: Infinity, ease: 'linear' }}
                aria-hidden
              />
            )}
            <div className="absolute inset-0 grid place-items-center">
              <div className="text-center">
                <Value v={d.kernel.blackholes} className="text-lg font-bold text-[#7dd3fc]" />
                <p className="text-[8px] text-slate-500">{isAr ? 'حجب نشط' : 'active blocks'}</p>
              </div>
            </div>
          </div>

          <dl className="space-y-1">
            <Row k={isAr ? 'الوضع' : 'Mode'} v={d.kernel.mode?.replace(/_/g, ' ') ?? null} small />
            <Row
              k={isAr ? 'زمن النواة' : 'Kernel latency'}
              v={d.kernel.latencyUs != null ? `${d.kernel.latencyUs} µs` : null}
              reason={d.kernel.reason ?? undefined}
            />
            <Row k={isAr ? 'إعادات TCP' : 'TCP resets'} v={d.kernel.tcpResets} />
            <Row k={isAr ? 'شذوذ' : 'Anomalies'} v={d.kernel.anomalies} />
          </dl>

          {d.kernel.countersReadable === false && (
            <p className="mt-2 border-t border-white/5 pt-1.5 text-[8px] leading-relaxed text-[#fcd34d]">
              {isAr
                ? 'عدّادات النواة غير مقروءة على هذا المضيف — الأرقام المتعلّقة بها مزروعة أو محجوبة.'
                : 'Kernel counters unreadable on this host — related figures are seeded or withheld.'}
            </p>
          )}
        </Glass>

        {/* Right: node inspector, in the satellite inspector's position */}
        {node && (
          <Glass className="absolute top-3 end-3 w-[248px] overflow-hidden">
            <div className="flex items-center gap-1.5 px-3 pt-3">
              <Satellite className="h-3.5 w-3.5 text-[#38BDF8]" aria-hidden />
              <Label>{isAr ? 'العقدة قيد الفحص' : 'Node under inspection'}</Label>
            </div>
            <div className="px-3 pt-1.5">
              <p className="truncate text-[13px] font-semibold text-white">{node.name}</p>
              <Mono className="text-[10px] text-slate-500">{node.ip}</Mono>
            </div>

            {/* Node glyph */}
            <div className="relative mx-auto my-2.5 h-[86px] w-[150px]">
              <div className="absolute top-1/2 left-1/2 h-8 w-11 -translate-x-1/2 -translate-y-1/2 rounded border border-[#38BDF8]/40 bg-[#38BDF8]/8" />
              {[-1, 1].map(s => (
                <div
                  key={s}
                  className="absolute top-1/2 h-6 w-[42px] -translate-y-1/2 border border-[#38BDF8]/25"
                  style={{
                    background:
                      'repeating-linear-gradient(90deg, rgba(56,189,248,0.16) 0 3px, transparent 3px 7px)',
                    [s < 0 ? 'left' : 'right']: '4px'
                  } as React.CSSProperties}
                />
              ))}
              {!reduce && (
                <motion.div
                  className="absolute inset-0 rounded-full border border-[#38BDF8]/15"
                  animate={{ scale: [0.9, 1.06, 0.9], opacity: [0.5, 0.15, 0.5] }}
                  transition={{ duration: 3, repeat: Infinity, ease: 'easeInOut' }}
                  aria-hidden
                />
              )}
            </div>

            <div className="space-y-1 px-3">
              <Row k={isAr ? 'الدور' : 'Role'} v={node.role} small />
              <Row k={isAr ? 'درجة الخطر' : 'Threat score'} v={node.threatScore} />
              <Row k={isAr ? 'حزم مُسقَطة' : 'Packets dropped'} v={node.packetsDropped} />
            </div>

            <div
              className={cn(
                'mt-2.5 flex items-center justify-between px-3 py-1.5 text-[9px] font-semibold',
                node.isolated ? 'bg-[#EF4444]/15 text-[#fca5a5]' : 'bg-[#10B981]/12 text-[#6ee7b7]'
              )}
            >
              <span>{node.isolated ? (isAr ? 'معزولة' : 'ISOLATED') : isAr ? 'متصلة' : 'CONNECTED'}</span>
              <span>{isAr ? `${d.nodes.length} عقدة` : `${d.nodes.length} nodes`}</span>
            </div>
          </Glass>
        )}

        {/* Target lock badge */}
        {top && (
          <Glass className="absolute bottom-3 start-1/2 -translate-x-1/2 px-3 py-2">
            <div className="flex items-center gap-3">
              <span className="relative flex h-2 w-2">
                {!reduce && (
                  <motion.span
                    className="absolute inset-0 rounded-full bg-[#EF4444]"
                    animate={{ opacity: [1, 0.2, 1] }}
                    transition={{ duration: 1.1, repeat: Infinity }}
                    aria-hidden
                  />
                )}
                <span className="relative m-auto h-1 w-1 rounded-full bg-white" aria-hidden />
              </span>
              <div>
                <Label>{isAr ? 'أعلى مصدر' : 'Top origin'}</Label>
                <p className="text-[11px] font-semibold text-white">
                  {top.flag ? `${top.flag} ` : ''}
                  {top.country} <Mono className="text-[#fca5a5]">{formatCount(top.count)}</Mono>
                </p>
              </div>
              <div className="border-s border-white/10 ps-3">
                <Label>{isAr ? 'كثافة التهديد' : 'Threat density'}</Label>
                <p className="text-[11px] font-semibold">
                  <Value v={d.derived.threatDensity} unit="/10k" className="text-[#fcd34d]" reason="needs requestsProtected and threatsBlocked" />
                </p>
              </div>
            </div>
          </Glass>
        )}
      </div>

      {/* Bottom telemetry dock */}
      <div className="grid grid-cols-1 gap-3 lg:grid-cols-12">
        {/* Dials */}
        <Glass className="p-3 lg:col-span-3">
          <Label>{isAr ? 'مؤشّرات حيّة' : 'Live dials'}</Label>
          <div className="mt-2.5 grid grid-cols-2 gap-2.5">
            <Dial
              label={isAr ? 'طلب/ث' : 'req/s'}
              value={d.derived.requestRate}
              reason="awaiting a second sample"
              accent="#38BDF8"
              reduce={reduce}
            />
            <Dial
              label={isAr ? 'زمن النواة' : 'kernel µs'}
              value={d.kernel.latencyUs}
              reason={d.kernel.reason ?? undefined}
              accent="#F59E0B"
              reduce={reduce}
            />
          </div>
          <dl className="mt-2.5 space-y-1 border-t border-white/5 pt-2">
            <Row k={isAr ? 'عقد مرصودة' : 'Nodes detected'} v={d.nodes.length} />
            <Row k={isAr ? 'مدّة التشغيل' : 'Uptime'} v={d.posture.uptimeSec != null ? fmtDur(d.posture.uptimeSec) : null} small />
            <Row k={isAr ? 'محرّك الكشف' : 'Engine'} v={d.posture.engine?.replace(/_/g, ' ') ?? null} small />
          </dl>
        </Glass>

        {/* Nodes table */}
        <Glass className="lg:col-span-5">
          <div className="flex items-center justify-between gap-2 px-3 pt-3">
            <div className="flex items-center gap-2">
              <span className="rounded-full bg-white/10 px-2 py-0.5 text-[9px] font-semibold text-white">
                {isAr ? `العقد (${d.nodes.length})` : `NODES (${d.nodes.length})`}
              </span>
              <span className="text-[9px] text-slate-500">
                {isAr ? `معزولة ${d.nodes.filter(n => n.isolated).length}` : `${d.nodes.filter(n => n.isolated).length} isolated`}
              </span>
            </div>
            <div className="flex items-center gap-1 rounded-full border border-white/10 bg-white/5 px-2 py-0.5">
              <Search className="h-3 w-3 text-slate-500" aria-hidden />
              <input
                value={nodeQuery}
                onChange={e => setNodeQuery(e.target.value)}
                placeholder={isAr ? 'بحث' : 'Search'}
                className="w-20 bg-transparent text-[10px] text-slate-200 placeholder:text-slate-600 focus:outline-none"
                aria-label={isAr ? 'بحث في العقد' : 'Search nodes'}
              />
            </div>
          </div>

          <div className="mt-2 max-h-[164px] overflow-y-auto">
            {filtered.length === 0 ? (
              <p className="px-3 py-6 text-center text-[10px] text-slate-500">
                {d.nodes.length === 0
                  ? isAr ? 'لم تُرجِع الخدمة عقداً.' : 'No nodes returned by the service.'
                  : isAr ? 'لا نتائج للبحث.' : 'No matches.'}
              </p>
            ) : (
              filtered.map((n, i) => (
                <button
                  key={n.ip}
                  onClick={() => setSelectedNode(d.nodes.indexOf(n))}
                  className={cn(
                    'flex w-full items-center gap-2 px-3 py-1.5 text-start transition-colors',
                    d.nodes.indexOf(n) === selectedNode ? 'bg-white/[0.06]' : 'hover:bg-white/[0.03]'
                  )}
                >
                  <CircleDot
                    className={cn('h-2.5 w-2.5 shrink-0', n.isolated ? 'text-[#EF4444]' : 'text-[#10B981]')}
                    aria-hidden
                  />
                  <span className="w-[136px] shrink-0 truncate text-[10px] text-slate-200">{n.name}</span>
                  <Mono className="w-[86px] shrink-0 text-[9px] text-slate-500">{n.ip}</Mono>
                  <span className="flex-1 truncate text-[9px] text-slate-600">{n.role ?? '—'}</span>
                  <Mono className="text-[9px] text-[#7dd3fc]">{n.packetsDropped != null ? formatCount(n.packetsDropped) : '—'}</Mono>
                </button>
              ))
            )}
          </div>
        </Glass>

        {/* Drift sparkline, in the "chance of failure" position */}
        <Glass className="p-3 lg:col-span-4">
          <div className="flex items-center justify-between">
            <Label>{isAr ? 'انحراف التوزيع' : 'Distribution drift'}</Label>
            {d.drift.verdict && (
              <span
                className={cn(
                  'rounded-full px-1.5 py-0.5 text-[8px] font-semibold',
                  d.drift.verdict === 'SIGNIFICANT_SHIFT'
                    ? 'bg-[#EF4444]/15 text-[#fca5a5]'
                    : d.drift.verdict === 'MODERATE_SHIFT'
                      ? 'bg-[#F59E0B]/15 text-[#fcd34d]'
                      : d.drift.verdict === 'STABLE'
                        ? 'bg-[#10B981]/15 text-[#6ee7b7]'
                        : 'bg-white/5 text-slate-500'
                )}
              >
                {d.drift.verdict.replace(/_/g, ' ')}
              </span>
            )}
          </div>

          {d.drift.verdict === 'INSUFFICIENT_DATA' ? (
            <p className="mt-2.5 text-[9px] leading-relaxed text-slate-500">{d.drift.insufficientReason}</p>
          ) : (
            <>
              <div className="mt-1.5 flex items-baseline gap-2">
                <Value v={d.drift.maxPsi} className="text-2xl font-bold text-white" />
                <span className="text-[9px] text-slate-500">
                  PSI · {isAr ? 'حدّ' : 'thr'} {d.drift.thresholds?.moderate ?? '—'}/{d.drift.thresholds?.significant ?? '—'}
                </span>
              </div>
              <div className="mt-2 space-y-1">
                {d.drift.features
                  .slice()
                  .sort((a, b) => b.psi - a.psi)
                  .slice(0, 5)
                  .map(f => {
                    const sig = d.drift.thresholds?.significant ?? 0.25;
                    return (
                      <div key={f.feature} className="flex items-center gap-1.5">
                        <span className="w-[86px] shrink-0 truncate text-[8px] text-slate-500">{f.feature}</span>
                        <div className="h-[3px] flex-1 overflow-hidden rounded-full bg-white/5">
                          <div
                            className="h-full rounded-full"
                            style={{
                              width: `${Math.min(100, (f.psi / Math.max(sig * 2, 0.5)) * 100)}%`,
                              background:
                                f.psi >= sig ? '#EF4444' : f.psi >= (d.drift.thresholds?.moderate ?? 0.1) ? '#F59E0B' : '#38BDF8'
                            }}
                          />
                        </div>
                        <Mono className="w-10 shrink-0 text-end text-[8px] text-slate-500">{f.psi}</Mono>
                      </div>
                    );
                  })}
              </div>
              {d.drift.newFamilies.length > 0 && (
                <p className="mt-2 text-[8px] text-[#fcd34d]">
                  {isAr ? 'أصناف جديدة: ' : 'New families: '}
                  <Mono>{d.drift.newFamilies.join(', ')}</Mono>
                </p>
              )}
            </>
          )}
        </Glass>
      </div>
    </div>
  );
};

/* ── Tab 2: Firewall — alluvial flow ─────────────────────────────────────── */

const FirewallTab: React.FC<{ d: D; isAr: boolean; reduce: boolean }> = ({ d, isAr, reduce }) => {
  const tiers = [
    { id: 'tier1', label: isAr ? 'تحديد المعدّل' : 'Rate limited', v: d.mitigation.tier1, color: '#38BDF8' },
    { id: 'tier2', label: isAr ? 'تحدٍّ' : 'Challenged', v: d.mitigation.tier2, color: '#F59E0B' },
    { id: 'tier3', label: isAr ? 'حجب حرج' : 'Critical blocked', v: d.mitigation.tier3, color: '#EF4444' }
  ];
  const totalTier = tiers.reduce((a, t) => a + (t.v ?? 0), 0);
  const maxHits = Math.max(1, ...d.endpoints.map(e => e.hits));

  return (
    <div className="grid grid-cols-1 gap-3 lg:grid-cols-12">
      {/* Endpoints, in the data-centre column's position */}
      <Glass className="p-3 lg:col-span-4">
        <Label>{isAr ? 'نقاط النهاية المستهدفة' : 'Targeted endpoints'}</Label>
        <div className="mt-2.5 space-y-2">
          {d.endpoints.length === 0 && (
            <p className="py-6 text-center text-[10px] text-slate-500">
              {isAr ? 'لا بيانات من /soc/analytics' : 'No data from /soc/analytics'}
            </p>
          )}
          {d.endpoints.map(e => {
            const threatShare = e.hits > 0 ? e.threatHits / e.hits : 0;
            return (
              <div key={e.endpoint} className="rounded-xl border border-white/8 bg-white/[0.02] p-2.5">
                <div className="flex items-baseline justify-between gap-2">
                  <Mono className="truncate text-[10px] text-slate-200">{e.endpoint}</Mono>
                  <Mono className="shrink-0 text-[11px] font-bold text-white">{formatCount(e.hits)}</Mono>
                </div>
                {/* Hatched bar, the reference's texture */}
                <div className="mt-1.5 h-2 overflow-hidden rounded-full bg-white/5">
                  <div
                    className="h-full rounded-full"
                    style={{
                      width: `${(e.hits / maxHits) * 100}%`,
                      background: `repeating-linear-gradient(45deg, ${
                        threatShare > 0.3 ? 'rgba(239,68,68,0.85)' : 'rgba(56,189,248,0.8)'
                      } 0 4px, rgba(255,255,255,0.08) 4px 8px)`
                    }}
                  />
                </div>
                <div className="mt-1 flex gap-2.5 text-[8px] text-slate-500">
                  <span>
                    <Mono className="text-[#fca5a5]">{formatCount(e.threatHits)}</Mono> {isAr ? 'عدائية' : 'hostile'}
                  </span>
                  <span>
                    <Mono className="text-[#6ee7b7]">{formatCount(e.hits - e.threatHits)}</Mono> {isAr ? 'سليمة' : 'clean'}
                  </span>
                  <span className="ms-auto">
                    <Mono>{(threatShare * 100).toFixed(1)}%</Mono>
                  </span>
                </div>
              </div>
            );
          })}
        </div>
      </Glass>

      {/* Alluvial flow */}
      <Glass className="relative overflow-hidden p-3 lg:col-span-5">
        <div className="flex items-center justify-between">
          <Label>{isAr ? 'تدفّق التخفيف التدريجي' : 'Progressive mitigation flow'}</Label>
          <span className="text-[8px] text-slate-500">
            {isAr ? 'المجموع ' : 'total '}
            <Mono>{formatCount(totalTier)}</Mono>
          </span>
        </div>

        <svg viewBox="0 0 320 240" className="mt-2 w-full" role="img"
          aria-label={
            isAr
              ? `تدفّق من ${d.endpoints.length} نقطة نهاية إلى ثلاث طبقات تخفيف`
              : `Flow from ${d.endpoints.length} endpoints into three mitigation tiers`
          }>
          <defs>
            {tiers.map(t => (
              <linearGradient key={t.id} id={`cd-flow-${t.id}`} x1="0" y1="0" x2="1" y2="0">
                <stop offset="0%" stopColor={t.color} stopOpacity="0.05" />
                <stop offset="55%" stopColor={t.color} stopOpacity="0.45" />
                <stop offset="100%" stopColor={t.color} stopOpacity="0.75" />
              </linearGradient>
            ))}
          </defs>

          {/* Sources */}
          {d.endpoints.slice(0, 6).map((e, i) => {
            const y = 22 + i * 34;
            return (
              <g key={e.endpoint}>
                <rect x="4" y={y - 8} width="8" height="16" rx="2" fill="rgba(56,189,248,0.35)" />
                <text x="18" y={y + 3} fill="#93a1b3" fontSize="7" style={{ fontFamily: 'var(--font-mono)' }}>
                  {e.endpoint.length > 22 ? e.endpoint.slice(0, 21) + '…' : e.endpoint}
                </text>
              </g>
            );
          })}

          {/* Flows — thickness proportional to real tier counts */}
          {d.endpoints.slice(0, 6).map((e, i) => {
            const y0 = 22 + i * 34;
            return tiers.map((t, ti) => {
              const share = totalTier > 0 ? (t.v ?? 0) / totalTier : 0;
              if (share <= 0) return null;
              const y1 = 46 + ti * 74;
              const thickness = Math.max(0.8, share * 14 * (e.hits / maxHits) + 0.6);
              return (
                <path
                  key={`${e.endpoint}-${t.id}`}
                  d={`M 132 ${y0} C 190 ${y0}, 196 ${y1}, 252 ${y1}`}
                  stroke={`url(#cd-flow-${t.id})`}
                  strokeWidth={thickness}
                  fill="none"
                  strokeLinecap="round"
                />
              );
            });
          })}

          {/* Tier nodes */}
          {tiers.map((t, ti) => {
            const y = 46 + ti * 74;
            return (
              <g key={t.id}>
                <rect
                  x="252" y={y - 16} width="62" height="32" rx="5"
                  fill="rgba(255,255,255,0.04)" stroke={t.color} strokeOpacity="0.45"
                />
                <text x="283" y={y - 3} fill="#e6edf3" fontSize="9" textAnchor="middle"
                  style={{ fontFamily: 'var(--font-mono)', fontWeight: 700 }}>
                  {t.v != null ? formatCount(t.v) : '—'}
                </text>
                <text x="283" y={y + 8} fill="#6b7a90" fontSize="6" textAnchor="middle">
                  {t.label}
                </text>
              </g>
            );
          })}
        </svg>

        {!reduce && (
          <motion.div
            className="pointer-events-none absolute inset-0"
            style={{ background: 'linear-gradient(90deg, transparent, rgba(56,189,248,0.05), transparent)' }}
            animate={{ x: ['-60%', '160%'] }}
            transition={{ duration: 5, repeat: Infinity, ease: 'linear' }}
            aria-hidden
          />
        )}
      </Glass>

      {/* Anomaly window */}
      <Glass className="p-3 lg:col-span-3">
        <div className="flex items-center gap-1.5">
          <ShieldAlert className="h-3.5 w-3.5 text-[#F59E0B]" aria-hidden />
          <Label>{isAr ? 'كشف الشذوذ' : 'Anomaly detection'}</Label>
        </div>
        <dl className="mt-2.5 space-y-1.5">
          <Row k={isAr ? 'حكم الانحراف' : 'Drift verdict'} v={d.drift.verdict?.replace(/_/g, ' ') ?? null} small />
          <Row k="PSI" v={d.drift.maxPsi} />
          <Row k={isAr ? 'السمة المحرّكة' : 'Driving feature'} v={d.drift.drivingFeature} small />
          <Row k={isAr ? 'حجب نشط' : 'Active blackholes'} v={d.kernel.blackholes} />
          <Row k={isAr ? 'عناوين معزولة' : 'Quarantined IPs'} v={d.agent.quarantined} />
          <Row k={isAr ? 'مصائد' : 'Trapped'} v={d.agent.trapped} />
          <Row k={isAr ? 'بصمات نشطة' : 'Signatures'} v={d.agent.signatures} />
        </dl>
        {d.posture.zeroEgress === true && (
          <div className="mt-2.5 rounded-lg border border-[#10B981]/25 bg-[#10B981]/8 px-2 py-1.5">
            <p className="text-[8px] font-semibold text-[#6ee7b7]">
              {isAr ? 'صفر نداءات خارجية — مقروء من الإعداد' : 'ZERO EXTERNAL CALLS — read from config'}
            </p>
          </div>
        )}
      </Glass>
    </div>
  );
};

/* ── Tab 3: Attacks — dual arcs ──────────────────────────────────────────── */

const AttacksTab: React.FC<{ d: D; isAr: boolean; reduce: boolean }> = ({ d, isAr, reduce }) => {
  const protectedN = d.agent.requestsProtected;
  const blockedN = d.agent.threatsBlocked;
  const maxFam = Math.max(1, ...d.families.map(f => f.count));

  return (
    <div className="space-y-3">
      <div className="grid grid-cols-1 gap-3 lg:grid-cols-12">
        {/* Dual arcs */}
        <Glass className="p-4 lg:col-span-7">
          <Label>{isAr ? 'الحماية مقابل الحجب' : 'Protected vs blocked'}</Label>
          <div className="mt-3 flex items-center justify-center gap-6">
            <Arc
              value={protectedN}
              max={Math.max(protectedN ?? 0, blockedN ?? 0, 1)}
              accent="#FFFFFF"
              label={isAr ? 'طلبات محميّة' : 'Requests protected'}
              reduce={reduce}
            />
            <Arc
              value={blockedN}
              max={Math.max(protectedN ?? 0, blockedN ?? 0, 1)}
              accent="#F59E0B"
              label={isAr ? 'تهديدات محجوبة' : 'Threats blocked'}
              reduce={reduce}
            />
          </div>
          <div className="mt-3 grid grid-cols-3 gap-2 border-t border-white/5 pt-2.5">
            <Stat
              label={isAr ? 'نسبة الحجب' : 'Block share'}
              value={d.derived.blockShare != null ? `${(d.derived.blockShare * 100).toFixed(2)}%` : null}
              accent="#7dd3fc"
            />
            <Stat
              label={isAr ? 'كثافة التهديد' : 'Threat density'}
              value={d.derived.threatDensity != null ? `${d.derived.threatDensity}/10k` : null}
              accent="#fcd34d"
            />
            <Stat
              label={isAr ? 'تقييمات' : 'Evaluations'}
              value={d.posture.evaluations != null ? formatCount(d.posture.evaluations) : null}
              accent="#6ee7b7"
            />
          </div>
        </Glass>

        {/* Engine posture */}
        <Glass className="p-3 lg:col-span-5">
          <Label>{isAr ? 'حالة المحرّك المحلّي' : 'Local engine posture'}</Label>
          <div className="mt-2.5 grid grid-cols-2 gap-2.5">
            <Ring
              label={isAr ? 'ذاكرة العملية' : 'Process heap'}
              value={d.posture.heapMb}
              max={d.posture.rssMb ?? d.posture.heapMb ?? 1}
              unit="MB"
              accent="#FFFFFF"
              reduce={reduce}
            />
            <Ring
              label={isAr ? 'احتفاظ' : 'Retention'}
              value={d.families.reduce((a, f) => a + f.count, 0)}
              max={500}
              unit=""
              accent="#F59E0B"
              reduce={reduce}
            />
          </div>
          <dl className="mt-2.5 space-y-1 border-t border-white/5 pt-2">
            <Row k={isAr ? 'المحرّك' : 'Engine'} v={d.posture.engine?.replace(/_/g, ' ') ?? null} small />
            <Row k={isAr ? 'المسار الوحيد' : 'Sole path'} v={d.posture.zeroEgress === true ? (isAr ? 'نعم' : 'yes') : d.posture.zeroEgress === false ? (isAr ? 'لا' : 'no') : null} small />
            <Row k={isAr ? 'حزم مُسقَطة' : 'Packets dropped'} v={d.kernel.packetsDropped} />
            <Row
              k={isAr ? 'منها مزروع' : 'of which seeded'}
              v={d.kernel.seeded}
              small
            />
          </dl>
        </Glass>
      </div>

      {/* Family distribution */}
      <Glass className="p-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-1.5">
            <Layers className="h-3.5 w-3.5 text-[#38BDF8]" aria-hidden />
            <Label>{isAr ? 'توزّع عائلات الهجوم المحتفظ بها' : 'Retained attack family distribution'}</Label>
          </div>
          <span className="text-[8px] text-slate-500">
            {isAr ? `${d.families.length} صنفاً` : `${d.families.length} families`}
          </span>
        </div>

        {d.families.length === 0 ? (
          <p className="py-8 text-center text-[10px] text-slate-500">
            {isAr ? 'لا بيانات من /soc/learning/retention' : 'No data from /soc/learning/retention'}
          </p>
        ) : (
          <div className="mt-3 flex items-end gap-2 overflow-x-auto pb-1" style={{ height: 132 }}>
            {d.families.slice(0, 12).map((f, i) => (
              <motion.div
                key={f.family}
                className="flex min-w-[52px] flex-1 flex-col items-center justify-end"
                initial={reduce ? { opacity: 0 } : { opacity: 0, scaleY: 0.6 }}
                animate={{ opacity: 1, scaleY: 1 }}
                transition={{ delay: reduce ? 0 : i * 0.04, duration: 0.24 }}
                style={{ transformOrigin: 'bottom' }}
              >
                <Mono className="mb-1 text-[9px] font-bold text-white">{f.count}</Mono>
                <div
                  className="w-full rounded-t-md border-t border-x"
                  style={{
                    height: `${(f.count / maxFam) * 88}px`,
                    background:
                      f.family === 'CLEAN_TRAFFIC'
                        ? 'linear-gradient(180deg, rgba(16,185,129,0.55), rgba(16,185,129,0.06))'
                        : 'linear-gradient(180deg, rgba(239,68,68,0.6), rgba(239,68,68,0.06))',
                    borderColor: f.family === 'CLEAN_TRAFFIC' ? 'rgba(16,185,129,0.5)' : 'rgba(239,68,68,0.5)'
                  }}
                />
                <span className="mt-1 w-full truncate text-center text-[7px] text-slate-500">
                  {f.family.replace(/_/g, ' ')}
                </span>
              </motion.div>
            ))}
          </div>
        )}
      </Glass>
    </div>
  );
};

/* ── Small parts ─────────────────────────────────────────────────────────── */

const Row: React.FC<{ k: string; v: number | string | null; small?: boolean; reason?: string }> = ({
  k,
  v,
  small,
  reason
}) => (
  <div className="flex items-baseline justify-between gap-2">
    <dt className="text-[9px] text-slate-500">{k}</dt>
    <dd className={cn('text-end', small ? 'text-[9px]' : 'text-[10px]')}>
      {v == null ? (
        <span className="text-slate-600" title={reason}>—</span>
      ) : (
        <Mono className="text-slate-200">{typeof v === 'number' ? formatCount(v) : v}</Mono>
      )}
    </dd>
  </div>
);

const Dial: React.FC<{
  label: string; value: number | null; accent: string; reason?: string; reduce: boolean;
}> = ({ label, value, accent, reason, reduce }) => (
  <div className="rounded-xl border border-white/8 bg-white/[0.02] p-2 text-center">
    <div className="relative mx-auto h-[54px] w-[54px]">
      <svg viewBox="0 0 54 54" className="h-full w-full -rotate-90">
        <circle cx="27" cy="27" r="22" fill="none" stroke="rgba(255,255,255,0.07)" strokeWidth="4" />
        {value != null && (
          <motion.circle
            cx="27" cy="27" r="22" fill="none" stroke={accent} strokeWidth="4" strokeLinecap="round"
            strokeDasharray={138}
            initial={{ strokeDashoffset: 138 }}
            animate={{ strokeDashoffset: 138 - Math.min(1, value / 200) * 138 }}
            transition={reduce ? { duration: 0 } : { duration: 0.7, ease: 'easeOut' }}
          />
        )}
      </svg>
      <div className="absolute inset-0 grid place-items-center">
        <Value v={value} className="text-[11px] font-bold text-white" reason={reason} />
      </div>
    </div>
    <p className="mt-1 text-[8px] text-slate-500">{label}</p>
  </div>
);

const Arc: React.FC<{
  value: number | null; max: number; accent: string; label: string; reduce: boolean;
}> = ({ value, max, accent, label, reduce }) => {
  const pct = value != null && max > 0 ? Math.min(1, value / max) : 0;
  const r = 62;
  const circ = Math.PI * r; // semicircle
  return (
    <div className="text-center">
      <div className="relative h-[84px] w-[152px]">
        <svg viewBox="0 0 152 84" className="h-full w-full">
          <path d={`M 14 76 A ${r} ${r} 0 0 1 138 76`} fill="none" stroke="rgba(255,255,255,0.07)" strokeWidth="9" strokeLinecap="round" />
          {value != null && (
            <motion.path
              d={`M 14 76 A ${r} ${r} 0 0 1 138 76`}
              fill="none" stroke={accent} strokeWidth="9" strokeLinecap="round"
              strokeDasharray={circ}
              initial={{ strokeDashoffset: circ }}
              animate={{ strokeDashoffset: circ - pct * circ }}
              transition={reduce ? { duration: 0 } : { duration: 0.9, ease: 'easeOut' }}
              style={{ filter: `drop-shadow(0 0 6px ${accent}66)` }}
            />
          )}
        </svg>
        <div className="absolute inset-x-0 bottom-1 text-center">
          <Value v={value != null ? formatCount(value) : null} className="text-xl font-bold text-white" />
        </div>
      </div>
      <p className="text-[8px] tracking-wider text-slate-500 uppercase">{label}</p>
    </div>
  );
};

const Ring: React.FC<{
  label: string; value: number | null; max: number; unit: string; accent: string; reduce: boolean;
}> = ({ label, value, max, unit, accent, reduce }) => {
  const pct = value != null && max > 0 ? Math.min(1, value / max) : 0;
  return (
    <div className="rounded-xl border border-white/8 bg-white/[0.02] p-2 text-center">
      <div className="relative mx-auto h-[62px] w-[62px]">
        <svg viewBox="0 0 62 62" className="h-full w-full -rotate-90">
          <circle cx="31" cy="31" r="25" fill="none" stroke="rgba(255,255,255,0.07)" strokeWidth="5" />
          {value != null && (
            <motion.circle
              cx="31" cy="31" r="25" fill="none" stroke={accent} strokeWidth="5" strokeLinecap="round"
              strokeDasharray={157}
              initial={{ strokeDashoffset: 157 }}
              animate={{ strokeDashoffset: 157 - pct * 157 }}
              transition={reduce ? { duration: 0 } : { duration: 0.8, ease: 'easeOut' }}
              style={{ filter: `drop-shadow(0 0 5px ${accent}55)` }}
            />
          )}
        </svg>
        <div className="absolute inset-0 grid place-items-center">
          <div>
            <Value v={value != null ? Math.round(value) : null} className="text-[12px] font-bold text-white" />
            {unit && <p className="text-[7px] text-slate-500">{unit}</p>}
          </div>
        </div>
      </div>
      <p className="mt-1 text-[8px] text-slate-500">{label}</p>
    </div>
  );
};

const Stat: React.FC<{ label: string; value: string | null; accent: string }> = ({ label, value, accent }) => (
  <div className="rounded-xl border border-white/8 bg-white/[0.02] px-2 py-1.5">
    <p className="text-[8px] tracking-wider text-slate-500 uppercase">{label}</p>
    <p className="mt-0.5 text-[13px] font-bold" style={{ color: value ? accent : undefined }}>
      {value ?? <span className="text-slate-600">—</span>}
    </p>
  </div>
);

function fmtDur(sec: number): string {
  const h = Math.floor(sec / 3600);
  const m = Math.floor((sec % 3600) / 60);
  const s = sec % 60;
  return `${h}h ${String(m).padStart(2, '0')}m ${String(s).padStart(2, '0')}s`;
}

export default CyberDefendPlatform;
