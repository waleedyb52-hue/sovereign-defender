import React from 'react';
import { motion, AnimatePresence, useReducedMotion } from 'motion/react';
import {
  Globe2, GitBranch, Bell, Gauge, Radar, Crosshair, Cpu,
  ChevronLeft, ChevronRight, Activity, ShieldAlert
} from 'lucide-react';
import { ThreatGlobeCanvas, type ThreatOrigin } from '../cyberdefend/ThreatGlobeCanvas';
import { useCyberDefendData } from '../cyberdefend/useCyberDefendData';
import {
  TacticalPanel, CornerAccents, CyberGridBackdrop, Readout, HudLabel, HudValue,
  RadialGauge, LinearGauge, TacticalButton, CYAN, CRIMSON, type Tone
} from './TacticalPrimitives';
import { cn, formatCount } from '../../../lib/utils';

/**
 * TACTICAL COCKPIT — single-screen multi-pane C2
 *
 * This replaces a tabbed dashboard, and the difference is structural rather than
 * cosmetic. In the previous build each view was a page, so selecting one hid the
 * others and the globe existed on exactly one of them. Here the tactical display is
 * the stage at all times and the panels float over its edges; a rail selects which
 * panels are shown, never whether the map is.
 *
 * That is the whole point of a cockpit: an operator should never have to navigate
 * away from the situation to read something about it.
 *
 * Layout
 *   The globe occupies the full frame as a background layer. Panels are absolutely
 *   positioned over the left and right margins with a clear corridor down the middle,
 *   so the centre of the stage stays legible. Side docks collapse to give the map the
 *   whole frame when an operator wants it.
 *
 * Data
 *   Every figure comes from `useCyberDefendData`, unchanged — no hook, endpoint or
 *   WebSocket path was touched in this restructure. Absent sources render an em dash
 *   with the reason on hover, and the strip along the bottom names any endpoint that
 *   did not answer, so a quiet panel is distinguishable from an idle platform.
 */

type PaneId = 'kernel' | 'flow' | 'alerts' | 'gauges';

interface Props {
  lang?: 'ar' | 'en';
  apiKey?: string;
}

export const TacticalCockpit: React.FC<Props> = ({ lang = 'ar', apiKey }) => {
  const isAr = lang === 'ar';
  const reduce = useReducedMotion() ?? false;
  const d = useCyberDefendData(apiKey);

  const [pane, setPane] = React.useState<PaneId>('kernel');
  const [leftOpen, setLeftOpen] = React.useState(true);
  const [rightOpen, setRightOpen] = React.useState(true);
  const [selectedNode, setSelectedNode] = React.useState(0);
  const [utc, setUtc] = React.useState(() => new Date().toISOString());

  // UTC clock, because a C2 surface is expected to carry one and an operator
  // correlating with another team needs the same reference.
  React.useEffect(() => {
    const t = setInterval(() => setUtc(new Date().toISOString()), 1000);
    return () => clearInterval(t);
  }, []);

  const origins: ThreatOrigin[] = d.geo.map(g => ({ country: g.country, code: g.code, count: g.count }));
  const node = d.nodes[selectedNode] ?? d.nodes[0] ?? null;
  const criticalAlerts = d.alerts.filter(a => /CRITICAL|HIGH/.test(a.severity));

  const RAIL: Array<{ id: PaneId; Icon: React.ElementType; en: string; ar: string; tone: Tone; badge?: number }> = [
    { id: 'kernel', Icon: Cpu, en: 'Kernel', ar: 'النواة', tone: 'cyan' },
    { id: 'flow', Icon: GitBranch, en: 'Flow', ar: 'التدفّق', tone: 'cyan' },
    { id: 'alerts', Icon: Bell, en: 'Alerts', ar: 'التنبيهات', tone: criticalAlerts.length ? 'crimson' : 'cyan', badge: criticalAlerts.length },
    { id: 'gauges', Icon: Gauge, en: 'Gauges', ar: 'المقاييس', tone: 'cyan' }
  ];

  return (
    <div className="relative h-screen w-full overflow-hidden" style={{ background: '#000000' }} dir={isAr ? 'rtl' : 'ltr'}>
      {/* ── Stage: the tactical display, always present ──────────────────── */}
      <div className="absolute inset-0">
        <ThreatGlobeCanvas
          origins={origins}
          target={{ label: 'SOC', lat: 24.7, lon: 46.7 }}
          height={typeof window !== 'undefined' ? window.innerHeight : 900}
          reducedMotion={reduce}
          className="block h-full w-full"
        />
      </div>
      <CyberGridBackdrop reduce={reduce} />

      {/* ── Slim vertical tactical rail ──────────────────────────────────── */}
      <nav
        className="absolute top-1/2 z-30 -translate-y-1/2"
        style={{ [isAr ? 'right' : 'left']: 8 } as React.CSSProperties}
        role="tablist"
        aria-label={isAr ? 'ألواح القُمرة' : 'Cockpit panes'}
      >
        <TacticalPanel chamfer="sm" corners="all" accents={false} glow="soft" className="px-1 py-2">
          <div className="flex flex-col gap-1">
            {RAIL.map(r => {
              const active = pane === r.id;
              return (
                <button
                  key={r.id}
                  role="tab"
                  aria-selected={active}
                  onClick={() => setPane(r.id)}
                  title={isAr ? r.ar : r.en}
                  className="group relative grid h-10 w-10 place-items-center transition-colors focus-visible:outline-none"
                >
                  {/* Vertical glow strip marks the active pane. */}
                  {active && (
                    <motion.span
                      layoutId="rail-strip"
                      className="absolute inset-y-1"
                      style={{
                        [isAr ? 'right' : 'left']: 0,
                        width: 2,
                        background: r.tone === 'crimson' ? CRIMSON : CYAN,
                        boxShadow: `0 0 10px ${r.tone === 'crimson' ? CRIMSON : CYAN}`
                      } as React.CSSProperties}
                      transition={reduce ? { duration: 0 } : { type: 'spring', stiffness: 420, damping: 34 }}
                      aria-hidden
                    />
                  )}
                  <r.Icon
                    className="h-4 w-4 transition-all"
                    strokeWidth={1.25}
                    style={{
                      color: active ? (r.tone === 'crimson' ? CRIMSON : CYAN) : '#475569',
                      filter: active ? `drop-shadow(0 0 6px ${r.tone === 'crimson' ? CRIMSON : CYAN}aa)` : undefined
                    }}
                    aria-hidden
                  />
                  {r.badge ? (
                    <span
                      className="absolute top-1 h-1.5 w-1.5 rounded-full"
                      style={{ [isAr ? 'left' : 'right']: 6, background: CRIMSON, boxShadow: `0 0 6px ${CRIMSON}` } as React.CSSProperties}
                      aria-hidden
                    />
                  ) : null}
                </button>
              );
            })}
          </div>
        </TacticalPanel>
      </nav>

      {/* ── Top status strip ─────────────────────────────────────────────── */}
      <header className="absolute inset-x-0 top-0 z-20 px-3 pt-2">
        <TacticalPanel chamfer="sm" corners="top" glow="none" className="px-3 py-1.5">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center gap-2.5">
              <Crosshair className="h-4 w-4" strokeWidth={1.25} style={{ color: CYAN, filter: `drop-shadow(0 0 6px ${CYAN}88)` }} aria-hidden />
              <span className="text-[11px] font-bold tracking-[0.2em] text-white" style={{ fontFamily: 'var(--font-mono)' }}>
                SOVEREIGN&nbsp;DEFENDER
              </span>
              <span
                className="flex items-center gap-1 border px-1.5 py-0.5"
                style={{ borderColor: `${CYAN}44`, clipPath: 'polygon(4px 0,100% 0,100% calc(100% - 4px),calc(100% - 4px) 100%,0 100%,0 4px)' }}
              >
                {!reduce && (
                  <motion.span
                    className="h-1 w-1 rounded-full"
                    style={{ background: CYAN, boxShadow: `0 0 6px ${CYAN}` }}
                    animate={{ opacity: [1, 0.25, 1] }}
                    transition={{ duration: 2, repeat: Infinity }}
                    aria-hidden
                  />
                )}
                <HudLabel tone="cyan">{isAr ? 'تشغيل' : 'OPERATIONAL'}</HudLabel>
              </span>
            </div>

            <div className="flex flex-wrap items-center gap-4">
              <Meter label={isAr ? 'طلب/ث' : 'RPS'} v={d.derived.requestRate} tone="cyan" reason="awaiting a second sample" />
              <Meter label={isAr ? 'كثافة' : 'DENSITY'} v={d.derived.threatDensity} unit="/10k" tone="amber" reason="needs both counters" />
              <Meter label={isAr ? 'حجب' : 'BLOCKS'} v={d.kernel.blackholes} tone="crimson" />
              <Meter label={isAr ? 'عقد' : 'NODES'} v={d.nodes.length} tone="cyan" />
              <div className="flex items-center gap-1.5">
                <HudLabel>UTC</HudLabel>
                <Readout tone="cyan" className="text-[10px]">
                  {utc.slice(11, 19)}
                </Readout>
              </div>
            </div>
          </div>
        </TacticalPanel>
      </header>

      {/* ── Left dock: kernel telemetry, always visible ──────────────────── */}
      <AnimatePresence>
        {leftOpen && (
          <motion.aside
            initial={reduce ? { opacity: 0 } : { opacity: 0, x: isAr ? 24 : -24 }}
            animate={{ opacity: 1, x: 0 }}
            exit={reduce ? { opacity: 0 } : { opacity: 0, x: isAr ? 24 : -24 }}
            transition={{ duration: 0.22, ease: 'easeOut' }}
            className="absolute top-16 z-20 w-[252px]"
            style={{ [isAr ? 'right' : 'left']: 62 } as React.CSSProperties}
          >
            <TacticalPanel className="p-3" glow="soft">
              <div className="mb-2 flex items-center gap-1.5">
                <Radar className="h-3.5 w-3.5" strokeWidth={1.25} style={{ color: CYAN }} aria-hidden />
                <HudLabel tone="cyan">{isAr ? 'قياسات النواة' : 'Kernel telemetry'}</HudLabel>
              </div>

              <div className="grid grid-cols-2 gap-2">
                <RadialGauge
                  value={d.kernel.blackholes}
                  max={Math.max(8, (d.kernel.blackholes ?? 0) + 2)}
                  label={isAr ? 'حجب' : 'BLOCKS'}
                  tone="crimson"
                  size={58}
                />
                <RadialGauge
                  value={d.kernel.latencyUs}
                  max={2}
                  label={isAr ? 'زمن µs' : 'LATENCY'}
                  unit="µs"
                  tone="cyan"
                  size={58}
                  reason={d.kernel.reason ?? undefined}
                />
              </div>

              <div className="mt-2.5 space-y-2 border-t pt-2" style={{ borderColor: `${CYAN}1a` }}>
                <LinearGauge
                  value={d.kernel.tcpResets}
                  max={Math.max(1000, (d.kernel.tcpResets ?? 0) * 1.2)}
                  label={isAr ? 'إعادات TCP' : 'TCP RESETS'}
                  tone="amber"
                  segments={20}
                />
                <LinearGauge
                  value={d.kernel.anomalies}
                  max={Math.max(10, (d.kernel.anomalies ?? 0) * 1.5)}
                  label={isAr ? 'شذوذ' : 'ANOMALIES'}
                  tone="crimson"
                  segments={20}
                />
              </div>

              <div className="mt-2.5 border-t pt-2" style={{ borderColor: `${CYAN}1a` }}>
                <div className="flex items-baseline justify-between">
                  <HudLabel>{isAr ? 'الوضع' : 'MODE'}</HudLabel>
                  <Readout
                    className="text-[8px]"
                    tone={d.kernel.countersReadable ? 'emerald' : 'amber'}
                  >
                    {d.kernel.mode?.replace(/_/g, ' ') ?? '—'}
                  </Readout>
                </div>
                {d.kernel.countersReadable === false && (
                  <p className="mt-1 text-[7.5px] leading-relaxed" style={{ color: `${CRIMSON}cc` }}>
                    {isAr
                      ? 'عدّادات النواة غير مقروءة — الأرقام مزروعة أو محجوبة، لا مقيسة.'
                      : 'Kernel counters unreadable — figures are seeded or withheld, not measured.'}
                  </p>
                )}
              </div>
            </TacticalPanel>
          </motion.aside>
        )}
      </AnimatePresence>

      {/* ── Right dock: the selected pane ────────────────────────────────── */}
      <AnimatePresence mode="wait">
        {rightOpen && (
          <motion.aside
            key={pane}
            initial={reduce ? { opacity: 0 } : { opacity: 0, x: isAr ? -24 : 24 }}
            animate={{ opacity: 1, x: 0 }}
            exit={reduce ? { opacity: 0 } : { opacity: 0, x: isAr ? -24 : 24 }}
            transition={{ duration: 0.22, ease: 'easeOut' }}
            className="absolute top-16 bottom-14 z-20 w-[330px] overflow-y-auto"
            style={{ [isAr ? 'left' : 'right']: 10 } as React.CSSProperties}
            role="tabpanel"
          >
            <PaneContent pane={pane} d={d} isAr={isAr} reduce={reduce} node={node} setSelectedNode={setSelectedNode} />
          </motion.aside>
        )}
      </AnimatePresence>

      {/* Dock collapse handles — give the stage the whole frame on demand */}
      <DockHandle side={isAr ? 'right' : 'left'} open={leftOpen} onClick={() => setLeftOpen(v => !v)} isAr={isAr} offset={62} />
      <DockHandle side={isAr ? 'left' : 'right'} open={rightOpen} onClick={() => setRightOpen(v => !v)} isAr={isAr} offset={10} />

      {/* ── Bottom strip: target lock and missing sources ────────────────── */}
      <footer className="absolute inset-x-0 bottom-0 z-20 px-3 pb-2">
        <TacticalPanel chamfer="sm" corners="none" accents={false} glow="none" className="px-3 py-1.5">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center gap-3">
              {d.geo[0] ? (
                <>
                  <span className="flex items-center gap-1.5">
                    {!reduce && (
                      <motion.span
                        className="h-1.5 w-1.5 rounded-full"
                        style={{ background: CRIMSON, boxShadow: `0 0 8px ${CRIMSON}` }}
                        animate={{ opacity: [1, 0.2, 1] }}
                        transition={{ duration: 1.1, repeat: Infinity }}
                        aria-hidden
                      />
                    )}
                    <HudLabel tone="crimson">{isAr ? 'أعلى مصدر' : 'TOP ORIGIN'}</HudLabel>
                  </span>
                  <Readout tone="crimson" glow className="text-[10px]">
                    {d.geo[0].code} {formatCount(d.geo[0].count)}
                  </Readout>
                </>
              ) : (
                <HudLabel>{isAr ? 'لا مصادر مُبلَّغة' : 'NO ORIGINS REPORTED'}</HudLabel>
              )}
              {d.emergencyLockdown && (
                <span className="flex items-center gap-1" style={{ color: CRIMSON }}>
                  <ShieldAlert className="h-3 w-3" aria-hidden />
                  <HudLabel tone="crimson">{isAr ? 'إغلاق طارئ' : 'LOCKDOWN'}</HudLabel>
                </span>
              )}
            </div>

            <div className="flex items-center gap-3">
              {d.missing.length > 0 && (
                <span className="text-[8px]" style={{ color: `${CRIMSON}cc`, fontFamily: 'var(--font-mono)' }}>
                  {isAr ? 'مصادر صامتة: ' : 'SILENT: '}
                  {d.missing.join(' · ')}
                </span>
              )}
              <span className="flex items-center gap-1.5">
                <Activity className="h-3 w-3" style={{ color: d.posture.zeroEgress ? CYAN : CRIMSON }} aria-hidden />
                <HudLabel tone={d.posture.zeroEgress ? 'cyan' : 'crimson'}>
                  {d.posture.zeroEgress === true
                    ? isAr ? 'صفر خروج' : 'ZERO EGRESS'
                    : d.posture.zeroEgress === false
                      ? isAr ? 'خروج ممكن' : 'EGRESS POSSIBLE'
                      : '—'}
                </HudLabel>
              </span>
            </div>
          </div>
        </TacticalPanel>
      </footer>
    </div>
  );
};

/* ── Small parts ─────────────────────────────────────────────────────────── */

const Meter: React.FC<{ label: string; v: number | null; unit?: string; tone: Tone; reason?: string }> = ({
  label,
  v,
  unit,
  tone,
  reason
}) => (
  <div className="flex items-center gap-1.5">
    <HudLabel tone={tone}>{label}</HudLabel>
    <HudValue v={v} unit={unit} tone={tone} glow reason={reason} className="text-[11px] font-bold" />
  </div>
);

const DockHandle: React.FC<{
  side: 'left' | 'right';
  open: boolean;
  onClick: () => void;
  isAr: boolean;
  offset: number;
}> = ({ side, open, onClick, isAr, offset }) => {
  const Chevron = (side === 'left') === open ? ChevronLeft : ChevronRight;
  return (
    <button
      onClick={onClick}
      aria-expanded={open}
      aria-label={
        open
          ? isAr ? 'إخفاء اللوح لإظهار المشهد كاملاً' : 'Collapse pane to reveal the full stage'
          : isAr ? 'إظهار اللوح' : 'Expand pane'
      }
      className="absolute top-1/2 z-30 grid h-8 w-4 -translate-y-1/2 place-items-center border transition-colors"
      style={{
        [side]: open ? offset + (side === 'left' ? 254 : 332) : offset,
        borderColor: `${CYAN}33`,
        background: 'rgba(0,0,0,0.6)',
        clipPath: 'polygon(3px 0,100% 0,100% calc(100% - 3px),calc(100% - 3px) 100%,0 100%,0 3px)'
      } as React.CSSProperties}
    >
      <Chevron className="h-3 w-3" style={{ color: `${CYAN}bb` }} aria-hidden />
    </button>
  );
};

/** The right dock's content, switched by the rail. */
const PaneContent: React.FC<{
  pane: PaneId;
  d: ReturnType<typeof useCyberDefendData>;
  isAr: boolean;
  reduce: boolean;
  node: ReturnType<typeof useCyberDefendData>['nodes'][number] | null;
  setSelectedNode: (n: number) => void;
}> = ({ pane, d, isAr, reduce, node, setSelectedNode }) => {
  if (pane === 'kernel') {
    return (
      <TacticalPanel className="p-3">
        <div className="mb-2 flex items-center gap-1.5">
          <Globe2 className="h-3.5 w-3.5" strokeWidth={1.25} style={{ color: CYAN }} aria-hidden />
          <HudLabel tone="cyan">{isAr ? 'عقد العنقود' : 'CLUSTER NODES'}</HudLabel>
        </div>

        {node && (
          <div className="mb-2 border p-2" style={{ borderColor: `${CYAN}22`, background: 'rgba(0,243,255,0.03)' }}>
            <p className="truncate text-[11px] font-semibold text-white">{node.name}</p>
            <Readout className="text-[9px] text-slate-500">{node.ip}</Readout>
            <div className="mt-1.5 grid grid-cols-2 gap-1.5">
              <Field k={isAr ? 'الدور' : 'ROLE'} v={node.role} />
              <Field k={isAr ? 'خطر' : 'THREAT'} v={node.threatScore} />
              <Field k={isAr ? 'مُسقَط' : 'DROPPED'} v={node.packetsDropped} />
              <Field k={isAr ? 'الحال' : 'STATE'} v={node.isolated ? (isAr ? 'معزول' : 'ISOLATED') : isAr ? 'متصل' : 'LINKED'} tone={node.isolated ? 'crimson' : 'emerald'} />
            </div>
          </div>
        )}

        <div className="max-h-[300px] space-y-0.5 overflow-y-auto">
          {d.nodes.length === 0 ? (
            <Empty isAr={isAr} endpoint="/soc/ebpf/cluster-nodes" />
          ) : (
            d.nodes.map((n, i) => (
              <button
                key={n.ip}
                onClick={() => setSelectedNode(i)}
                className="flex w-full items-center gap-2 px-1.5 py-1 text-start transition-colors hover:bg-white/[0.04]"
              >
                <span
                  className="h-1.5 w-1.5 shrink-0"
                  style={{ background: n.isolated ? CRIMSON : CYAN, boxShadow: `0 0 5px ${n.isolated ? CRIMSON : CYAN}` }}
                  aria-hidden
                />
                <span className="flex-1 truncate text-[9px] text-slate-300">{n.name}</span>
                <Readout className="text-[8px] text-slate-600">{n.ip}</Readout>
              </button>
            ))
          )}
        </div>
      </TacticalPanel>
    );
  }

  if (pane === 'flow') {
    const tiers = [
      { label: isAr ? 'معدّل' : 'RATE LIMIT', v: d.mitigation.tier1, tone: 'cyan' as Tone },
      { label: isAr ? 'تحدٍّ' : 'CHALLENGE', v: d.mitigation.tier2, tone: 'amber' as Tone },
      { label: isAr ? 'حجب' : 'HARD BLOCK', v: d.mitigation.tier3, tone: 'crimson' as Tone }
    ];
    const maxHits = Math.max(1, ...d.endpoints.map(e => e.hits));
    return (
      <TacticalPanel className="p-3">
        <div className="mb-2 flex items-center gap-1.5">
          <GitBranch className="h-3.5 w-3.5" strokeWidth={1.25} style={{ color: CYAN }} aria-hidden />
          <HudLabel tone="cyan">{isAr ? 'تدفّق التخفيف' : 'MITIGATION FLOW'}</HudLabel>
        </div>

        <div className="space-y-2">
          {tiers.map(t => (
            <LinearGauge
              key={t.label}
              value={t.v}
              max={Math.max(1, ...tiers.map(x => x.v ?? 0))}
              label={t.label}
              tone={t.tone}
              segments={22}
            />
          ))}
        </div>

        <div className="mt-3 border-t pt-2" style={{ borderColor: `${CYAN}1a` }}>
          <HudLabel tone="cyan">{isAr ? 'نقاط النهاية' : 'ENDPOINTS'}</HudLabel>
          <div className="mt-1.5 space-y-1.5">
            {d.endpoints.length === 0 ? (
              <Empty isAr={isAr} endpoint="/soc/analytics" />
            ) : (
              d.endpoints.map(e => {
                const share = e.hits > 0 ? e.threatHits / e.hits : 0;
                const hot = share > 0.3;
                return (
                  <div key={e.endpoint}>
                    <div className="flex items-baseline justify-between gap-2">
                      <Readout className="truncate text-[8.5px] text-slate-400">{e.endpoint}</Readout>
                      <Readout tone={hot ? 'crimson' : 'cyan'} className="shrink-0 text-[9px]">
                        {formatCount(e.hits)}
                      </Readout>
                    </div>
                    <div className="mt-0.5 h-[3px] bg-white/5">
                      <div
                        className="h-full"
                        style={{
                          width: `${(e.hits / maxHits) * 100}%`,
                          background: hot ? CRIMSON : CYAN,
                          boxShadow: `0 0 6px ${hot ? CRIMSON : CYAN}88`
                        }}
                      />
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>
      </TacticalPanel>
    );
  }

  if (pane === 'alerts') {
    return (
      <TacticalPanel className="p-3" tone={d.alerts.some(a => /CRITICAL|HIGH/.test(a.severity)) ? 'crimson' : 'cyan'}>
        <div className="mb-2 flex items-center justify-between">
          <div className="flex items-center gap-1.5">
            <Bell className="h-3.5 w-3.5" strokeWidth={1.25} style={{ color: CYAN }} aria-hidden />
            <HudLabel tone="cyan">{isAr ? 'تيّار التنبيهات' : 'ALERT STREAM'}</HudLabel>
          </div>
          <Readout className="text-[9px] text-slate-500">{d.alerts.length}</Readout>
        </div>

        <div className="max-h-[420px] space-y-1.5 overflow-y-auto">
          {d.alerts.length === 0 ? (
            <Empty isAr={isAr} endpoint="/soc/unified-telemetry" />
          ) : (
            d.alerts.map(a => {
              const crit = /CRITICAL|HIGH/.test(a.severity);
              return (
                <div
                  key={a.id}
                  className="border-s-2 ps-2"
                  style={{ borderColor: crit ? CRIMSON : a.severity === 'MEDIUM' ? '#f59e0b' : CYAN }}
                >
                  <div className="flex items-baseline gap-2">
                    <Readout tone={crit ? 'crimson' : 'cyan'} className="text-[7.5px] font-bold">
                      {a.severity}
                    </Readout>
                    <Readout className="text-[7.5px] text-slate-600">{a.at.slice(11, 19)}</Readout>
                    {a.mitre ? (
                      <Readout tone="cyan" className="text-[7.5px]">{a.mitre}</Readout>
                    ) : (
                      <span className="text-[7.5px] tracking-wider text-slate-700" style={{ fontFamily: 'var(--font-mono)' }}>
                        UNMAPPED
                      </span>
                    )}
                  </div>
                  <p className="mt-0.5 line-clamp-2 text-[9px] leading-snug text-slate-300">{a.title}</p>
                  {a.action && (
                    <p className="mt-0.5 text-[7.5px] text-slate-600" style={{ fontFamily: 'var(--font-mono)' }}>
                      → {a.action}
                    </p>
                  )}
                </div>
              );
            })
          )}
        </div>
      </TacticalPanel>
    );
  }

  // gauges
  const maxFam = Math.max(1, ...d.families.map(f => f.count));
  return (
    <TacticalPanel className="p-3">
      <div className="mb-2.5 flex items-center gap-1.5">
        <Gauge className="h-3.5 w-3.5" strokeWidth={1.25} style={{ color: CYAN }} aria-hidden />
        <HudLabel tone="cyan">{isAr ? 'مقاييس المنصّة' : 'PLATFORM GAUGES'}</HudLabel>
      </div>

      <div className="grid grid-cols-2 gap-2">
        <RadialGauge
          value={d.agent.requestsProtected}
          max={Math.max(d.agent.requestsProtected ?? 1, d.agent.threatsBlocked ?? 1)}
          label={isAr ? 'محميّة' : 'PROTECTED'}
          tone="cyan"
          size={72}
        />
        <RadialGauge
          value={d.agent.threatsBlocked}
          max={Math.max(d.agent.requestsProtected ?? 1, d.agent.threatsBlocked ?? 1)}
          label={isAr ? 'محجوبة' : 'BLOCKED'}
          tone="crimson"
          size={72}
        />
      </div>

      <div className="mt-3 space-y-2 border-t pt-2" style={{ borderColor: `${CYAN}1a` }}>
        <LinearGauge
          value={d.derived.threatDensity}
          max={500}
          label={isAr ? 'كثافة التهديد /10k' : 'THREAT DENSITY /10k'}
          tone="amber"
          reason="needs requestsProtected and threatsBlocked"
        />
        <LinearGauge
          value={d.posture.heapMb}
          max={d.posture.rssMb ?? 512}
          label={isAr ? 'ذاكرة العملية' : 'PROCESS HEAP'}
          unit="MB"
          tone="cyan"
        />
        <LinearGauge
          value={d.drift.maxPsi}
          max={Math.max(0.5, (d.drift.thresholds?.significant ?? 0.25) * 2)}
          label={isAr ? 'انحراف PSI' : 'DRIFT PSI'}
          tone={
            d.drift.maxPsi != null && d.drift.thresholds && d.drift.maxPsi >= d.drift.thresholds.significant
              ? 'crimson'
              : 'cyan'
          }
          reason={d.drift.insufficientReason ?? undefined}
        />
      </div>

      <div className="mt-3 border-t pt-2" style={{ borderColor: `${CYAN}1a` }}>
        <HudLabel tone="cyan">{isAr ? 'توزّع العائلات' : 'FAMILY DISTRIBUTION'}</HudLabel>
        {d.families.length === 0 ? (
          <div className="mt-1.5">
            <Empty isAr={isAr} endpoint="/soc/learning/retention" />
          </div>
        ) : (
          <div className="mt-1.5 flex items-end gap-1" style={{ height: 68 }}>
            {d.families.slice(0, 8).map(f => {
              const clean = f.family === 'CLEAN_TRAFFIC';
              const c = clean ? CYAN : CRIMSON;
              return (
                <div key={f.family} className="flex flex-1 flex-col items-center justify-end" title={f.family}>
                  <Readout className="mb-0.5 text-[7px] text-slate-500">{f.count}</Readout>
                  <div
                    className="w-full"
                    style={{
                      height: `${(f.count / maxFam) * 46}px`,
                      background: `linear-gradient(180deg, ${c}, ${c}22)`,
                      boxShadow: `0 0 8px ${c}55`
                    }}
                  />
                </div>
              );
            })}
          </div>
        )}
      </div>
    </TacticalPanel>
  );
};

const Field: React.FC<{ k: string; v: number | string | null; tone?: Tone }> = ({ k, v, tone = 'cyan' }) => (
  <div>
    <HudLabel>{k}</HudLabel>
    <p className="text-[9px]">
      <HudValue v={typeof v === 'number' ? formatCount(v) : v} tone={tone} />
    </p>
  </div>
);

const Empty: React.FC<{ isAr: boolean; endpoint: string }> = ({ isAr, endpoint }) => (
  <div className="py-5 text-center">
    <p className="text-[9px] text-slate-600">{isAr ? 'لا بيانات من' : 'No data from'}</p>
    <Readout className="text-[8px] text-slate-700">{endpoint}</Readout>
  </div>
);

export default TacticalCockpit;
