import React from 'react';
import { motion, useReducedMotion } from 'motion/react';
import {
  Crosshair, ShieldAlert, Radio, Waves, LayoutGrid, Cpu, ShieldCheck,
  FileLock2, Gauge, Network, Binary, ArrowUpDown
} from 'lucide-react';
import { GlowSparkline } from '../cyberdefend/GlowSparkline';
import { useCyberDefendData } from '../cyberdefend/useCyberDefendData';
import {
  CornerAccents, Readout, HudLabel, HudValue, RadialGauge, LinearGauge,
  CyberGridBackdrop, CYAN, CRIMSON, type Tone
} from './TacticalPrimitives';
import { SectionHead, LeaderDonut, DataTable, type DonutSlice } from './BigScreenParts';
import { TacticalTheater } from './TacticalTheater';
import { KillChainRail, HudButton } from './KillChainRail';
import { RibbonCell, type Provenance } from './DefenseRibbon';
import { useDefenseRibbon } from './useDefenseRibbon';
import { useLiveAttackStream } from './useLiveAttackStream';
import { formatCount } from '../../../lib/utils';

/**
 * UNIFIED TACTICAL COCKPIT — the platform's single operational surface.
 *
 * Four zones around a deep central theatre, which is what a C2 room is:
 *
 *   ribbon    live counters for every defence stage — kernel XDP, L7 WAF, FIM,
 *             latency — each declaring whether its figure is measured or seeded
 *   left      the MITRE kill chain and the containment pipeline, moved out of its
 *             own page and into the scene
 *   centre    a live radar topology fed by the telemetry socket
 *   bottom    the live attack feed and the traffic curve, full width, with sort
 *             and response controls
 *
 * The panels are glass over the theatre — bg-[#030712]/75, backdrop-blur-xl, a
 * cyan-500/30 edge, a 25px shadow — with the four military corner brackets on each.
 *
 * On data integrity, which this surface makes harder rather than easier:
 *
 *   A single-pane HUD puts measured and seeded figures side by side at the same size,
 *   in the same neon, inside the same glass. That is exactly the arrangement in which
 *   a fabricated number is most convincing, so every cell here carries its provenance
 *   at the size the figure is shown, nulls render as an em dash with the reason on
 *   hover, and the radar's sweep stops dead when the socket drops instead of animating
 *   traffic nobody observed. Stillness is a reading. Motion has to be earned.
 *
 * No endpoint, schema, socket path or hook contract was changed to build this. The
 * cockpit is a second reader of feeds that already existed: `useCyberDefendData` for
 * the seven core endpoints, `useDefenseRibbon` for WAF, FIM, kernel integrity and
 * attack chains, and `useLiveAttackStream` for `/ws/telemetry`.
 */

interface Props {
  lang?: 'ar' | 'en';
  apiKey?: string;
  /** Opens the remaining consoles. Absent, the control is not rendered. */
  onExit?: () => void;
}

/** The brief's glass panel, with the four corner brackets. */
const Glass: React.FC<{
  children: React.ReactNode;
  className?: string;
  tone?: Tone;
  delay?: number;
  reduce: boolean;
}> = ({ children, className = '', tone = 'cyan', delay = 0, reduce }) => (
  <motion.div
    className={`relative border border-cyan-500/30 bg-[#030712]/75 shadow-[0_0_25px_rgba(0,0,0,0.85)] backdrop-blur-xl ${className}`}
    initial={reduce ? false : { opacity: 0, y: 8 }}
    animate={{ opacity: 1, y: 0 }}
    transition={{ duration: 0.35, delay, ease: 'easeOut' }}
  >
    <CornerAccents tone={tone} inset={-1} />
    {children}
  </motion.div>
);

type SortKey = 'TIME' | 'SEVERITY' | 'MITRE';

export const TacticalCockpit: React.FC<Props> = ({ lang = 'ar', apiKey, onExit }) => {
  const isAr = lang === 'ar';
  const reduce = useReducedMotion() ?? false;

  const d = useCyberDefendData(apiKey);
  const r = useDefenseRibbon(apiKey);
  const stream = useLiveAttackStream();

  const [utc, setUtc] = React.useState(() => new Date().toISOString());
  const [sortBy, setSortBy] = React.useState<SortKey>('TIME');
  const [dropsOnly, setDropsOnly] = React.useState(false);
  const [action, setAction] = React.useState<string | null>(null);

  React.useEffect(() => {
    const t = setInterval(() => setUtc(new Date().toISOString()), 1000);
    return () => clearInterval(t);
  }, []);

  /** The console default is a blue-grey; the theatre needs a true black void. */
  React.useEffect(() => {
    document.documentElement.setAttribute('data-surface', 'tactical');
    return () => document.documentElement.removeAttribute('data-surface');
  }, []);

  const critical = d.alerts.filter(a => /CRITICAL|HIGH/.test(a.severity));

  const SEV_RANK: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, UNKNOWN: 4 };
  const feed = React.useMemo(() => {
    const rows = dropsOnly ? d.alerts.filter(a => /CRITICAL|HIGH/.test(a.severity)) : d.alerts;
    const sorted = rows.slice();
    if (sortBy === 'SEVERITY') sorted.sort((a, b) => (SEV_RANK[a.severity] ?? 9) - (SEV_RANK[b.severity] ?? 9));
    else if (sortBy === 'MITRE') sorted.sort((a, b) => (a.mitre ?? 'zzz').localeCompare(b.mitre ?? 'zzz'));
    else sorted.sort((a, b) => b.at.localeCompare(a.at));
    return sorted;
  }, [d.alerts, sortBy, dropsOnly]);

  const familySlices: DonutSlice[] = d.families.map(f => ({
    label: f.family,
    value: f.count,
    tone: f.family === 'CLEAN_TRAFFIC' ? ('cyan' as Tone) : ('crimson' as Tone)
  }));

  /**
   * XDP drop provenance.
   *
   * Live socket counters are measured. Otherwise the cluster statistics distinguish
   * seeded from observed, and on a host without a kernel path the figure is seeded —
   * which the cell must say, because the number is large and looks authoritative.
   */
  const xdpValue = stream.kernel?.droppedPackets ?? r.waf.droppedPackets ?? d.kernel.packetsDropped;
  const xdpProv: Provenance =
    stream.kernel?.droppedPackets != null
      ? 'MEASURED'
      : xdpValue == null
        ? 'UNAVAILABLE'
        : d.kernel.countersReadable === true
          ? 'MEASURED'
          : 'SEEDED';

  const latencyUs = stream.kernel?.avgLatencyNs != null ? stream.kernel.avgLatencyNs / 1000 : d.kernel.latencyUs;
  const latencyProv: Provenance =
    stream.kernel?.avgLatencyNs != null ? 'MEASURED' : latencyUs == null ? 'UNAVAILABLE' : 'SEEDED';

  const allMissing = [...d.missing, ...r.missing];

  const contain = (kind: 'ISOLATE' | 'BLACKHOLE' | 'TARPIT', ip: string) =>
    setAction(`${kind} → ${ip}`);

  return (
    <div className="fixed inset-0 z-0 flex flex-col overflow-hidden bg-black" dir={isAr ? 'rtl' : 'ltr'}>
      {/* ── The theatre. Behind everything, full viewport. ─────────────────── */}
      <div className="absolute inset-0 z-0">
        <CyberGridBackdrop reduce={reduce} />
        <TacticalTheater
          contacts={d.geo.map(g => ({ code: g.code, country: g.country, count: g.count }))}
          nodes={d.nodes.map(n => ({ name: n.name, ip: n.ip, isolated: n.isolated, threatScore: n.threatScore }))}
          tracers={stream.tracers}
          status={stream.status}
          reduce={reduce}
          isAr={isAr}
          className="h-full w-full"
        />
        <div
          className="pointer-events-none absolute inset-0"
          style={{ background: 'radial-gradient(ellipse at center, transparent 38%, rgba(0,0,0,0.86) 100%)' }}
          aria-hidden
        />
      </div>

      {/* ── Identity bar ───────────────────────────────────────────────────── */}
      <div className="relative z-10 flex shrink-0 items-center gap-3 border-b border-cyan-500/20 bg-[#030712]/75 px-4 py-1.5 backdrop-blur-xl">
        <span
          className="grid h-6 w-6 shrink-0 place-items-center border border-cyan-500/40"
          style={{ clipPath: 'polygon(6px 0,100% 0,100% calc(100% - 6px),calc(100% - 6px) 100%,0 100%,0 6px)' }}
        >
          <Crosshair className="h-3 w-3 text-cyan-400" strokeWidth={1.25} aria-hidden />
        </span>
        <p
          className="shrink-0 text-[12px] font-bold tracking-[0.2em] text-white"
          style={{ fontFamily: 'var(--font-mono)', textShadow: `0 0 14px ${CYAN}66` }}
        >
          SOVEREIGN DEFENDER
        </p>
        <span className="text-[6.5px] tracking-[0.3em] text-cyan-400/70" style={{ fontFamily: 'var(--font-mono)' }}>
          UNIFIED TACTICAL C2
        </span>

        <span className="h-px flex-1" style={{ background: `linear-gradient(90deg, ${CYAN}44, transparent)` }} />

        {/* Socket state, stated where it cannot be missed */}
        <span className="flex shrink-0 items-center gap-1.5">
          {!reduce && stream.status === 'LIVE' && (
            <motion.span
              className="h-1.5 w-1.5 rounded-full bg-emerald-400"
              animate={{ opacity: [1, 0.25, 1] }}
              transition={{ duration: 1.4, repeat: Infinity }}
              aria-hidden
            />
          )}
          <span
            className={`text-[7.5px] tracking-[0.16em] ${
              stream.status === 'LIVE' ? 'text-emerald-400' : stream.status === 'CONNECTING' ? 'text-amber-400' : 'text-rose-500'
            }`}
            style={{ fontFamily: 'var(--font-mono)' }}
          >
            {stream.status === 'LIVE'
              ? `${isAr ? 'بثّ حيّ' : 'WS LIVE'} · ${stream.packetsSeen}`
              : stream.status === 'CONNECTING'
                ? isAr ? 'جارٍ الوصل' : 'CONNECTING'
                : isAr ? 'البثّ مقطوع' : 'WS DOWN'}
          </span>
        </span>

        {d.emergencyLockdown && (
          <span className="flex shrink-0 items-center gap-1 text-rose-500">
            <ShieldAlert className="h-3 w-3" aria-hidden />
            <span className="text-[8px] font-bold tracking-[0.16em]" style={{ fontFamily: 'var(--font-mono)' }}>
              {isAr ? 'إغلاق طارئ' : 'LOCKDOWN'}
            </span>
          </span>
        )}

        <Readout className="shrink-0 text-[12px] font-bold text-cyan-400">{utc.slice(11, 19)}</Readout>
        <HudLabel tone="cyan">UTC</HudLabel>

        {onExit && (
          <button
            type="button"
            onClick={onExit}
            className="flex shrink-0 items-center gap-1.5 border border-cyan-500/40 px-2 py-0.5 text-[8px] tracking-[0.14em] text-cyan-400 transition-colors hover:bg-cyan-500/10"
            style={{ fontFamily: 'var(--font-mono)' }}
          >
            <LayoutGrid className="h-2.5 w-2.5" aria-hidden />
            {isAr ? 'الكونسولات' : 'CONSOLES'}
          </button>
        )}
      </div>

      {/* ── Global defence ribbon ──────────────────────────────────────────── */}
      <div className="relative z-10 flex shrink-0 items-stretch border-b border-cyan-500/20 bg-[#030712]/75 backdrop-blur-xl">
        <RibbonCell
          icon={Cpu}
          label={isAr ? 'حجب النواة XDP' : 'KERNEL XDP DROP'}
          value={xdpValue}
          tone={xdpProv === 'MEASURED' ? 'cyan' : 'amber'}
          provenance={xdpProv}
          reason={d.kernel.reason}
          sub={stream.kernel?.driverMode ?? d.kernel.mode?.replace(/_/g, ' ') ?? undefined}
          isAr={isAr}
        />
        <RibbonCell
          icon={ShieldCheck}
          label={isAr ? 'قواعد WAF L7' : 'WAF L7 RULES'}
          value={r.waf.l7Active != null && r.waf.l7Total != null ? `${r.waf.l7Active}/${r.waf.l7Total}` : null}
          tone={r.waf.l7Active != null && r.waf.l7Active === r.waf.l7Total ? 'emerald' : 'amber'}
          provenance={r.waf.l7Active == null ? 'UNAVAILABLE' : 'MEASURED'}
          reason={r.missing.includes('/traffic/waf/metrics') ? '/traffic/waf/metrics unreachable' : null}
          sub={isAr ? 'مفعّلة' : 'ENABLED'}
          isAr={isAr}
        />
        <RibbonCell
          icon={FileLock2}
          label={isAr ? 'سلامة الملفات FIM' : 'FIM INTEGRITY'}
          value={r.fim.files}
          tone={r.fim.critical != null && r.fim.critical > 0 ? 'crimson' : r.fim.active ? 'emerald' : 'amber'}
          provenance={r.fim.files == null ? 'UNAVAILABLE' : 'MEASURED'}
          reason={r.missing.includes('/fim/status') ? '/fim/status unreachable' : null}
          sub={
            r.fim.critical != null
              ? `${r.fim.critical} ${isAr ? 'حرِج' : 'CRIT'}`
              : undefined
          }
          isAr={isAr}
        />
        <RibbonCell
          icon={Gauge}
          label={isAr ? 'زمن الاستجابة' : 'KERNEL LATENCY'}
          value={latencyUs != null ? latencyUs.toFixed(2) : null}
          unit="µs"
          tone={latencyProv === 'MEASURED' ? 'cyan' : 'amber'}
          provenance={latencyProv}
          reason={d.kernel.reason}
          isAr={isAr}
        />
        <RibbonCell
          icon={Network}
          label={isAr ? 'معدّل الطلبات' : 'REQUEST RATE'}
          value={r.waf.rps ?? d.derived.requestRate}
          unit={isAr ? '/ث' : '/s'}
          tone="cyan"
          provenance={r.waf.rps != null || d.derived.requestRate != null ? 'MEASURED' : 'UNAVAILABLE'}
          reason="awaiting a second sample"
          sub={r.waf.blockedSubnets != null ? `${r.waf.blockedSubnets} ${isAr ? 'شبكة محجوبة' : 'SUBNETS'}` : undefined}
          isAr={isAr}
        />
        <RibbonCell
          icon={Binary}
          label={isAr ? 'سلامة النواة' : 'SYSCALL INTEGRITY'}
          value={r.integrity.status === 'UNAVAILABLE' ? null : (r.integrity.status ?? null)}
          tone={r.integrity.status === 'VERIFIED' ? 'emerald' : 'amber'}
          provenance={r.integrity.status === 'UNAVAILABLE' || r.integrity.status == null ? 'UNAVAILABLE' : 'MEASURED'}
          reason={r.integrity.reason}
          sub={r.integrity.mitre ?? undefined}
          isAr={isAr}
        />
      </div>

      {/* ── Main band: rail · theatre · instruments ────────────────────────── */}
      <div className="relative z-10 grid min-h-0 flex-1 grid-cols-12 gap-2 p-2">
        {/* Left: kill chain and containment */}
        <Glass className="col-span-3 flex min-h-0 flex-col px-2.5 py-2 xl:col-span-2" reduce={reduce} delay={0.04}>
          <SectionHead tone={critical.length ? 'crimson' : 'cyan'}>
            {isAr ? 'سلسلة القتل والاحتواء' : 'KILL CHAIN'}
          </SectionHead>
          <div className="mt-1.5 min-h-0 flex-1">
            <KillChainRail
              chains={r.chains}
              isAr={isAr}
              chainsUnavailable={r.missing.includes('/soc/attack-chains')}
              onContain={contain}
            />
          </div>
          {action && (
            <p className="mt-1.5 border-t pt-1.5 text-[7px] text-amber-400" style={{ borderColor: `${CYAN}1a`, fontFamily: 'var(--font-mono)' }}>
              {isAr ? 'طُلب: ' : 'REQUESTED: '}
              {action}
            </p>
          )}
        </Glass>

        {/* Centre: the theatre stays visible; this column only holds its labels */}
        <div className="pointer-events-none col-span-6 flex min-h-0 flex-col justify-between xl:col-span-7">
          <div className="flex justify-center">
            <span
              className="border border-cyan-500/30 bg-[#030712]/75 px-2.5 py-0.5 text-[7.5px] tracking-[0.2em] text-cyan-400 shadow-[0_0_25px_rgba(0,0,0,0.85)] backdrop-blur-xl"
              style={{ fontFamily: 'var(--font-mono)' }}
            >
              {isAr ? 'مسرح التهديد التكتيكي' : 'TACTICAL THREAT THEATRE'}
            </span>
          </div>

          {d.geo[0] && (
            <div className="flex justify-center">
              <span
                className="border border-rose-500/40 bg-[#030712]/75 px-2.5 py-0.5 text-[8px] text-rose-400 shadow-[0_0_25px_rgba(0,0,0,0.85)] backdrop-blur-xl"
                style={{ fontFamily: 'var(--font-mono)' }}
              >
                {isAr ? 'أعلى مصدر' : 'TOP ORIGIN'} · {d.geo[0].code} · {formatCount(d.geo[0].count)}
              </span>
            </div>
          )}
        </div>

        {/* Right: instruments */}
        <div className="col-span-3 flex min-h-0 flex-col gap-2">
          <Glass className="px-2.5 py-2" reduce={reduce} delay={0.08}>
            <SectionHead tone="cyan">{isAr ? 'المقاييس' : 'GAUGES'}</SectionHead>
            <div className="mt-1.5 grid grid-cols-2 gap-1">
              <RadialGauge
                value={r.waf.rps ?? d.derived.requestRate}
                max={200}
                label={isAr ? 'طلب/ث' : 'RPS'}
                tone="cyan"
                size={56}
                reason="awaiting a second sample"
              />
              <RadialGauge
                value={latencyUs}
                max={2}
                label={isAr ? 'نواة' : 'KERNEL'}
                unit="µs"
                tone={latencyProv === 'MEASURED' ? 'cyan' : 'amber'}
                size={56}
                reason={d.kernel.reason ?? undefined}
              />
            </div>
            <div className="mt-1.5 space-y-1.5">
              <LinearGauge
                value={d.derived.threatDensity}
                max={500}
                label={isAr ? 'كثافة /10k' : 'DENSITY /10k'}
                tone="amber"
                segments={16}
                reason="needs both counters"
              />
              <LinearGauge
                value={d.posture.heapMb}
                max={d.posture.rssMb ?? 512}
                label={isAr ? 'ذاكرة' : 'HEAP'}
                unit="MB"
                tone="cyan"
                segments={16}
              />
            </div>
          </Glass>

          <Glass className="px-2.5 py-2" reduce={reduce} delay={0.12}>
            <SectionHead tone="cyan">{isAr ? 'عائلات الهجوم' : 'ATTACK FAMILIES'}</SectionHead>
            <div className="mt-1">
              <LeaderDonut
                slices={familySlices}
                isAr={isAr}
                size={100}
                centreLabel={String(d.families.reduce((a, f) => a + f.count, 0) || '')}
              />
            </div>
          </Glass>

          <Glass className="min-h-0 flex-1 px-2.5 py-2" reduce={reduce} delay={0.16}>
            <SectionHead
              tone={
                d.drift.maxPsi != null && d.drift.thresholds && d.drift.maxPsi >= d.drift.thresholds.significant
                  ? 'crimson'
                  : 'cyan'
              }
            >
              {isAr ? 'انحراف التوزيع' : 'DISTRIBUTION DRIFT'}
            </SectionHead>
            {d.drift.verdict === 'INSUFFICIENT_DATA' ? (
              <p className="mt-1.5 text-[7px] leading-relaxed text-slate-500">{d.drift.insufficientReason}</p>
            ) : (
              <>
                <div className="mt-1.5 flex items-baseline gap-1.5">
                  <HudValue v={d.drift.maxPsi} tone="cyan" glow className="text-[15px] font-bold" />
                  <HudLabel tone="cyan">PSI</HudLabel>
                </div>
                <div className="mt-1.5 space-y-[3px]">
                  {d.drift.features
                    .slice()
                    .sort((a, b) => b.psi - a.psi)
                    .slice(0, 4)
                    .map(f => {
                      const sig = d.drift.thresholds?.significant ?? 0.25;
                      const c = f.psi >= sig ? CRIMSON : CYAN;
                      return (
                        <div key={f.feature} className="flex items-center gap-1.5">
                          <span className="w-[56px] shrink-0 truncate text-[6.5px] text-slate-500">{f.feature}</span>
                          <span className="h-[2px] flex-1 bg-white/5">
                            <span
                              className="block h-full"
                              style={{
                                width: `${Math.min(100, (f.psi / Math.max(sig * 2, 0.5)) * 100)}%`,
                                background: c,
                                boxShadow: `0 0 6px ${c}`
                              }}
                            />
                          </span>
                        </div>
                      );
                    })}
                </div>
              </>
            )}
          </Glass>
        </div>
      </div>

      {/* ── Bottom band: live attack feed and traffic curve ────────────────── */}
      <div className="relative z-10 grid shrink-0 grid-cols-12 gap-2 px-2 pb-2">
        <Glass className="col-span-7 px-2.5 py-2" tone={critical.length ? 'crimson' : 'cyan'} reduce={reduce} delay={0.2}>
          <div className="flex items-center gap-2">
            <SectionHead tone={critical.length ? 'crimson' : 'cyan'}>
              {isAr ? 'تغذية الهجوم الحيّة' : 'LIVE ATTACK FEED'}
            </SectionHead>
            <div className="flex shrink-0 items-center gap-1">
              <ArrowUpDown className="h-2.5 w-2.5 text-cyan-400/60" aria-hidden />
              {(['TIME', 'SEVERITY', 'MITRE'] as const).map(k => (
                <button
                  key={k}
                  type="button"
                  onClick={() => setSortBy(k)}
                  className="px-1.5 py-0.5 text-[6.5px] tracking-[0.12em] transition-colors"
                  style={{
                    fontFamily: 'var(--font-mono)',
                    clipPath: 'polygon(4px 0,100% 0,100% calc(100% - 4px),calc(100% - 4px) 100%,0 100%,0 4px)',
                    border: `1px solid ${sortBy === k ? CYAN + '88' : 'rgba(255,255,255,0.08)'}`,
                    color: sortBy === k ? CYAN : '#5c7484',
                    background: sortBy === k ? `${CYAN}14` : 'transparent'
                  }}
                >
                  {k}
                </button>
              ))}
              <span className="w-16">
                <HudButton tone={dropsOnly ? 'rose' : 'cyan'} onClick={() => setDropsOnly(v => !v)}>
                  {dropsOnly ? (isAr ? 'الحرِج' : 'CRIT') : isAr ? 'الكل' : 'ALL'}
                </HudButton>
              </span>
            </div>
          </div>

          <DataTable
            rows={feed.slice(0, 60)}
            isAr={isAr}
            emptyEndpoint="/soc/unified-telemetry"
            maxHeight={132}
            columns={[
              { key: 'time', header: isAr ? 'الوقت' : 'TIME', width: '50px', render: a => <span className="text-slate-500">{a.at.slice(11, 19)}</span> },
              {
                key: 'sev',
                header: isAr ? 'الخطورة' : 'SEV',
                width: '46px',
                render: a => (
                  <span className={/CRITICAL|HIGH/.test(a.severity) ? 'text-rose-500' : 'text-cyan-400'}>{a.severity.slice(0, 4)}</span>
                )
              },
              {
                key: 'mitre',
                header: 'MITRE',
                width: '54px',
                render: a => (a.mitre ? <span className="text-cyan-400">{a.mitre}</span> : <span className="text-slate-700">UNMAPPED</span>)
              },
              { key: 'src', header: isAr ? 'المصدر' : 'SOURCE', width: '90px', render: a => <span className="text-slate-500">{a.srcIp ?? '—'}</span> },
              { key: 'title', header: isAr ? 'الحدث' : 'EVENT', render: a => <span className="text-slate-300">{a.title}</span> },
              {
                key: 'act',
                header: isAr ? 'الإجراء' : 'ACTION',
                width: '74px',
                render: a => (a.action ? <span className="text-emerald-400">{a.action}</span> : <span className="text-slate-700">—</span>)
              }
            ]}
          />
        </Glass>

        <Glass className="col-span-5 px-2.5 py-2" reduce={reduce} delay={0.24}>
          <SectionHead
            tone="cyan"
            right={
              <Readout className="text-[7px] text-slate-500">
                {d.frequency.length} {isAr ? 'عيّنة' : 'SAMPLES'}
              </Readout>
            }
          >
            {isAr ? 'منحنى حركة الحِزَم' : 'TRAFFIC CURVE'}
          </SectionHead>
          {d.frequency.length >= 2 ? (
            <GlowSparkline
              points={d.frequency.map(f => ({ label: f.label, value: f.value, secondary: f.threats }))}
              isAr={isAr}
              height={118}
              accent={CYAN}
              secondaryAccent={CRIMSON}
              unit={isAr ? '' : '/s'}
            />
          ) : (
            <p className="py-10 text-center text-[8px] text-slate-600" style={{ fontFamily: 'var(--font-mono)' }}>
              {isAr ? 'لا بيانات من /soc/analytics' : 'no data from /soc/analytics'}
            </p>
          )}
        </Glass>
      </div>

      {/* ── Status strip ──────────────────────────────────────────────────── */}
      <div className="relative z-10 flex shrink-0 items-center justify-between gap-3 border-t border-cyan-500/20 bg-[#030712]/75 px-4 py-1 backdrop-blur-xl">
        <div className="flex items-center gap-4">
          <span className="flex items-center gap-1.5">
            <Radio className="h-2.5 w-2.5 text-cyan-400" aria-hidden />
            <HudLabel tone="cyan">{isAr ? 'المحرّك' : 'ENGINE'}</HudLabel>
            <Readout className="text-[8px] text-slate-400">{d.posture.engine?.replace(/_/g, ' ') ?? '—'}</Readout>
          </span>
          <span className="flex items-center gap-1.5">
            <Waves className={`h-2.5 w-2.5 ${d.posture.zeroEgress ? 'text-cyan-400' : 'text-rose-500'}`} aria-hidden />
            <HudLabel tone={d.posture.zeroEgress ? 'cyan' : 'crimson'}>
              {d.posture.zeroEgress === true
                ? isAr ? 'صفر خروج خارجي' : 'ZERO EGRESS'
                : d.posture.zeroEgress === false
                  ? isAr ? 'خروج ممكن' : 'EGRESS POSSIBLE'
                  : '—'}
            </HudLabel>
          </span>
          <span className="flex items-center gap-1.5">
            <HudLabel tone="cyan">{isAr ? 'عقد' : 'NODES'}</HudLabel>
            <Readout className="text-[8px] text-cyan-400">{d.nodes.length}</Readout>
          </span>
        </div>

        {allMissing.length > 0 ? (
          <span className="text-[7px] text-rose-500/90" style={{ fontFamily: 'var(--font-mono)' }}>
            {isAr ? 'مصادر صامتة: ' : 'SILENT: '}
            {allMissing.join(' · ')}
          </span>
        ) : (
          <span className="text-[7px] text-cyan-400/60" style={{ fontFamily: 'var(--font-mono)' }}>
            {isAr ? 'كل المصادر تستجيب' : 'ALL SOURCES RESPONDING'}
          </span>
        )}
      </div>
    </div>
  );
};

export default TacticalCockpit;
