import React from 'react';
import { motion, useReducedMotion } from 'motion/react';
import { Crosshair, LayoutGrid, Radio, Waves, ArrowUpDown } from 'lucide-react';
import { useCyberDefendData } from '../cyberdefend/useCyberDefendData';
import { CornerAccents, Readout, HudLabel, CYAN, CRIMSON, type Tone } from './TacticalPrimitives';
import { SectionHead, DataTable } from './BigScreenParts';
import { TacticalTheater } from './TacticalTheater';
import { KillChainRail } from './KillChainRail';
import { CyberButton } from './CyberButton';
import { EbpfModule, WafModule, FimModule, ScannerModule, IntelModule, ZtnaModule } from './ArsenalModules';
import { TelemetryTimeline } from './TelemetryTimeline';
import { WargamePanel } from './WargamePanel';
import {
  DefconBadge, EnvironmentToggle, ResourceTicker, SimulationFrame, deriveDefcon, type Environment
} from './EnvironmentBar';
import { useDefenseRibbon } from './useDefenseRibbon';
import { useLiveAttackStream } from './useLiveAttackStream';
import { useArsenal } from './useArsenal';
import { useWargames } from './useWargames';

/**
 * UNIFIED TACTICAL COCKPIT — single pane of glass, Z-axis layout.
 *
 *   LAYER 0   pure black, hex grid, CRT scanlines
 *   LAYER 1   the threat theatre: live radar topology, real coordinates, real packets
 *   LAYER 2   floating glass HUDs — header, kill chain left, arsenal right, telemetry
 *             and the live threat table across the bottom
 *
 * ENVIRONMENT SEPARATION is the load-bearing feature here, and it is a safety property
 * rather than a styling one. An operator who cannot tell a drill from an intrusion will
 * either ignore a real one or escalate an exercise; both have happened in real SOCs. So:
 *
 *   LIVE mode renders only real telemetry. The drill launchers are not in the DOM at
 *   all — not disabled, not hidden by CSS, absent. A disabled launcher is one prop away
 *   from firing a synthetic APT at a production board.
 *
 *   WARGAME mode frames the entire surface in amber, banners itself, and blocks the
 *   return to LIVE while the server reports a phase running. The banner follows
 *   `/wargames/status`, not local state, so a reload mid-drill still warns.
 *
 * ON DATA INTEGRITY, which this layout makes harder rather than easier: a single pane
 * puts measured and emulated figures side by side, at the same size, in the same neon,
 * inside the same glass. That is the arrangement in which a fabricated number is most
 * convincing. So the eBPF module labels itself from the driver's own CONTAINER_EMULATION
 * report, the IOC ticker states that its store is local because the platform is
 * zero-egress, DEFCON discloses its inputs and reads UNKNOWN rather than 5 when nothing
 * has reported, the scanner refuses to draw ports nothing scanned for, and the radar's
 * sweep stops dead when the socket drops. Stillness is a reading. Motion is earned.
 *
 * No endpoint, schema, socket path or hook contract was changed. Every module reads a
 * feed the backend already served.
 */

interface Props {
  lang?: 'ar' | 'en';
  apiKey?: string;
  onExit?: () => void;
}

/** LAYER 2 glass: deep transparency, micro-border, corner brackets. */
const Glass: React.FC<{
  children: React.ReactNode;
  className?: string;
  tone?: Tone;
  amber?: boolean;
  delay?: number;
  reduce: boolean;
}> = ({ children, className = '', tone = 'cyan', amber, delay = 0, reduce }) => (
  <motion.div
    className={`relative border bg-[#030712]/60 shadow-[0_0_25px_rgba(0,0,0,0.85)] backdrop-blur-2xl ${className}`}
    style={{ borderColor: amber ? 'rgba(245,158,11,0.5)' : 'rgba(22,78,99,0.5)' }}
    initial={reduce ? false : { opacity: 0, y: 8 }}
    animate={{ opacity: 1, y: 0 }}
    transition={{ duration: 0.35, delay, ease: 'easeOut' }}
  >
    <CornerAccents tone={amber ? 'amber' : tone} inset={-1} />
    {children}
  </motion.div>
);

type SortKey = 'TIME' | 'SEVERITY' | 'MITRE';
const SEV_RANK: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, UNKNOWN: 4 };

export const TacticalCockpit: React.FC<Props> = ({ lang = 'ar', apiKey, onExit }) => {
  const isAr = lang === 'ar';
  const reduce = useReducedMotion() ?? false;

  const d = useCyberDefendData(apiKey);
  const r = useDefenseRibbon(apiKey);
  const a = useArsenal(apiKey);
  const w = useWargames(apiKey);
  const stream = useLiveAttackStream();

  const [env, setEnv] = React.useState<Environment>('LIVE');
  const [utc, setUtc] = React.useState(() => new Date().toISOString());
  const [sortBy, setSortBy] = React.useState<SortKey>('TIME');
  const [critOnly, setCritOnly] = React.useState(false);
  const [isolateBusy, setIsolateBusy] = React.useState(false);
  const [isolateResult, setIsolateResult] = React.useState<string | null>(null);

  React.useEffect(() => {
    const t = setInterval(() => setUtc(new Date().toISOString()), 1000);
    return () => clearInterval(t);
  }, []);

  /** The app paints #0d1117 on the root with !important; the theatre needs black. */
  React.useEffect(() => {
    document.documentElement.setAttribute('data-surface', 'tactical');
    return () => document.documentElement.removeAttribute('data-surface');
  }, []);

  const sim = env === 'WARGAME';
  const critical = d.alerts.filter(x => /CRITICAL|HIGH/.test(x.severity));
  const isolatedNodes = d.nodes.filter(n => n.isolated).length;

  const defcon = deriveDefcon(
    {
      emergencyLockdown: d.emergencyLockdown,
      criticalAlerts: critical.length,
      activeHardBans: a.ztna.activeHardBans,
      fimCritical: r.fim.critical,
      isolatedNodes,
      anySourceReporting: d.missing.length + r.missing.length + a.missing.length < 20 && !d.loading
    },
    isAr
  );

  const feed = React.useMemo(() => {
    const rows = critOnly ? d.alerts.filter(x => /CRITICAL|HIGH/.test(x.severity)) : d.alerts;
    const s = rows.slice();
    if (sortBy === 'SEVERITY') s.sort((x, y) => (SEV_RANK[x.severity] ?? 9) - (SEV_RANK[y.severity] ?? 9));
    else if (sortBy === 'MITRE') s.sort((x, y) => (x.mitre ?? 'zzz').localeCompare(y.mitre ?? 'zzz'));
    else s.sort((x, y) => y.at.localeCompare(x.at));
    return s;
  }, [d.alerts, sortBy, critOnly]);

  /**
   * Real containment, against the real endpoint. The result is reported verbatim —
   * a refused isolation reported as success would leave an operator believing a host
   * was cut off while it is still talking.
   */
  const isolate = async (ip: string) => {
    setIsolateBusy(true);
    setIsolateResult(null);
    try {
      const res = await fetch('/api/v1/soc/ebpf/contain-ip', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...(apiKey ? { 'x-api-key': apiKey } : {}) },
        body: JSON.stringify({ ip, reason: 'Operator isolation from unified cockpit' })
      });
      const body = await res.json().catch(() => null);
      setIsolateResult(res.ok ? (body?.message ?? `${ip} contained`) : `rejected (${res.status})`);
    } catch (err) {
      setIsolateResult(`failed: ${err instanceof Error ? err.message : 'network error'}`);
    } finally {
      setIsolateBusy(false);
      a.refresh();
    }
  };

  const allMissing = [...d.missing, ...r.missing, ...a.missing];
  const accent = sim ? '#fbbf24' : CYAN;

  return (
    <div className="fixed inset-0 z-0 flex h-screen w-screen flex-col overflow-hidden bg-black" dir={isAr ? 'rtl' : 'ltr'}>
      {/* ── LAYER 0: void, hex grid, CRT scanlines ──────────────────────────── */}
      <div className="absolute inset-0 z-0" aria-hidden>
        <div
          className="absolute inset-0"
          style={{
            backgroundImage:
              'linear-gradient(rgba(34,211,238,0.045) 1px, transparent 1px), linear-gradient(90deg, rgba(34,211,238,0.045) 1px, transparent 1px)',
            backgroundSize: '46px 46px'
          }}
        />
        <div
          className="absolute inset-0 opacity-[0.045]"
          style={{ backgroundImage: 'repeating-linear-gradient(0deg, #fff 0 1px, transparent 1px 3px)' }}
        />
      </div>

      {/* ── LAYER 1: the threat theatre ─────────────────────────────────────── */}
      <div className="absolute inset-0 z-0">
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
          style={{ background: 'radial-gradient(ellipse at center, transparent 36%, rgba(0,0,0,0.88) 100%)' }}
          aria-hidden
        />
      </div>

      {sim && <SimulationFrame isAr={isAr} drillActive={w.drillActive} detail={w.activePhase ? `PHASE ${w.activePhase}` : null} />}

      {/* ── LAYER 2 · TOP HEADER ────────────────────────────────────────────── */}
      <header
        className="relative z-20 flex shrink-0 flex-wrap items-center gap-2 border-b bg-[#030712]/60 px-3 py-1.5 backdrop-blur-2xl"
        style={{ borderColor: sim ? 'rgba(245,158,11,0.4)' : 'rgba(22,78,99,0.5)' }}
      >
        <span
          className="grid h-6 w-6 shrink-0 place-items-center border"
          style={{
            borderColor: `${accent}66`,
            clipPath: 'polygon(6px 0,100% 0,100% calc(100% - 6px),calc(100% - 6px) 100%,0 100%,0 6px)'
          }}
        >
          <Crosshair className="h-3 w-3" strokeWidth={1.25} style={{ color: accent }} aria-hidden />
        </span>
        <p
          className="shrink-0 font-mono text-[11px] font-bold tracking-widest text-white uppercase"
          style={{ textShadow: `0 0 12px ${accent}aa` }}
        >
          Sovereign Defender
        </p>

        <DefconBadge d={defcon} isAr={isAr} />

        <EnvironmentToggle
          env={env}
          isAr={isAr}
          lockedReason={
            w.drillActive
              ? isAr
                ? 'محاكاة جارية — صفّر الصندوق قبل العودة إلى الوضع الحيّ'
                : 'a drill is running — reset the sandbox before returning to live'
              : null
          }
          onChange={setEnv}
        />

        <span className="h-px flex-1" style={{ background: `linear-gradient(90deg, ${accent}44, transparent)` }} />

        <ResourceTicker
          heapMb={d.posture.heapMb}
          rssMb={d.posture.rssMb}
          uptimeSec={d.posture.uptimeSec}
          rps={a.waf.rps ?? d.derived.requestRate}
          isAr={isAr}
        />

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
            className={`font-mono text-[7px] tracking-widest uppercase ${
              stream.status === 'LIVE' ? 'text-emerald-400' : stream.status === 'CONNECTING' ? 'text-amber-400' : 'text-rose-500'
            }`}
          >
            {stream.status === 'LIVE'
              ? `WS · ${stream.packetsSeen}`
              : stream.status === 'CONNECTING'
                ? isAr ? 'وصل…' : 'LINKING'
                : isAr ? 'مقطوع' : 'WS DOWN'}
          </span>
        </span>

        <Readout className="shrink-0 font-mono text-[12px] font-bold" tone={sim ? 'amber' : 'cyan'} glow>
          {utc.slice(11, 19)}
        </Readout>
        <HudLabel tone="cyan">UTC</HudLabel>

        {onExit && (
          <CyberButton tone="cyan" size="sm" onClick={onExit}>
            <span className="flex items-center gap-1">
              <LayoutGrid className="h-2.5 w-2.5" aria-hidden />
              {isAr ? '[ الكونسولات ]' : '[ CONSOLES ]'}
            </span>
          </CyberButton>
        )}
      </header>

      {/* ── LAYER 2 · MAIN BAND ─────────────────────────────────────────────── */}
      <div className="relative z-10 grid min-h-0 flex-1 grid-cols-12 gap-2 p-2">
        {/* LEFT: kill chain in live mode, drill control in the sandbox */}
        <Glass
          className="col-span-3 flex min-h-0 flex-col px-2.5 py-2 xl:col-span-2"
          amber={sim}
          reduce={reduce}
          delay={0.04}
        >
          {sim ? (
            <WargamePanel w={w} isAr={isAr} />
          ) : (
            <>
              <SectionHead tone={critical.length ? 'crimson' : 'cyan'}>
                {isAr ? 'سلسلة القتل والاحتواء' : 'KILL CHAIN'}
              </SectionHead>
              <div className="mt-1.5 min-h-0 flex-1">
                <KillChainRail
                  chains={r.chains}
                  isAr={isAr}
                  chainsUnavailable={r.missing.includes('/soc/attack-chains')}
                  onContain={(_kind, ip) => void isolate(ip)}
                />
              </div>
            </>
          )}
        </Glass>

        {/* CENTRE: the theatre shows through; only its labels sit here */}
        <div className="pointer-events-none col-span-6 flex min-h-0 flex-col justify-between xl:col-span-7">
          <div className="flex justify-center pt-4">
            <span
              className="border bg-[#030712]/60 px-3 py-0.5 font-mono text-[7px] tracking-widest uppercase backdrop-blur-2xl"
              style={{ borderColor: `${accent}55`, color: accent, textShadow: `0 0 8px ${accent}cc` }}
            >
              {sim
                ? isAr ? 'مسرح المحاكاة' : 'SIMULATION THEATRE'
                : isAr ? 'مسرح التهديد التكتيكي' : 'TACTICAL THREAT THEATRE'}
            </span>
          </div>

          {d.geo[0] && (
            <div className="flex justify-center pb-1">
              <span
                className="border border-rose-900/60 bg-[#030712]/60 px-3 py-0.5 font-mono text-[7.5px] text-rose-400 backdrop-blur-2xl"
                style={{ textShadow: '0 0 8px rgba(225,29,72,0.8)' }}
              >
                {isAr ? 'أعلى مصدر' : 'TOP ORIGIN'} · {d.geo[0].code} · {d.geo[0].count.toLocaleString('en-US')}
              </span>
            </div>
          )}
        </div>

        {/* RIGHT: the arsenal stack */}
        <div className="col-span-3 flex min-h-0 flex-col gap-1.5 overflow-y-auto pe-0.5">
          <EbpfModule a={a} isAr={isAr} />
          <WafModule a={a} isAr={isAr} />
          <FimModule a={a} isAr={isAr} />
          <ScannerModule a={a} isAr={isAr} />
          <IntelModule a={a} isAr={isAr} />
          <ZtnaModule
            a={a}
            isAr={isAr}
            onIsolate={ip => void isolate(ip)}
            busy={isolateBusy}
            lastAction={isolateResult}
          />
        </div>
      </div>

      {/* ── LAYER 2 · BOTTOM BAND ───────────────────────────────────────────── */}
      <div className="relative z-10 grid shrink-0 grid-cols-12 gap-2 px-2 pb-1.5">
        <Glass
          className="col-span-7 px-2.5 py-1.5"
          tone={critical.length ? 'crimson' : 'cyan'}
          amber={sim}
          reduce={reduce}
          delay={0.16}
        >
          <div className="flex items-center gap-2">
            <SectionHead tone={critical.length ? 'crimson' : 'cyan'}>
              {isAr ? 'تغذية التهديدات الحيّة' : 'LIVE THREAT DATA'}
            </SectionHead>
            <span className="flex shrink-0 items-center gap-1">
              <ArrowUpDown className="h-2.5 w-2.5 text-cyan-400/50" aria-hidden />
              {(['TIME', 'SEVERITY', 'MITRE'] as const).map(k => (
                <CyberButton key={k} tone="cyan" size="sm" active={sortBy === k} onClick={() => setSortBy(k)}>
                  {k}
                </CyberButton>
              ))}
              <CyberButton tone={critOnly ? 'rose' : 'cyan'} size="sm" active={critOnly} onClick={() => setCritOnly(v => !v)}>
                {critOnly ? (isAr ? '[ الحرِج ]' : '[ CRIT ]') : isAr ? '[ الكل ]' : '[ ALL ]'}
              </CyberButton>
            </span>
          </div>

          <DataTable
            rows={feed.slice(0, 60)}
            isAr={isAr}
            emptyEndpoint="/soc/unified-telemetry"
            maxHeight={124}
            columns={[
              { key: 'time', header: isAr ? 'الوقت' : 'TIME', width: '48px', render: x => <span className="text-slate-500">{x.at.slice(11, 19)}</span> },
              {
                key: 'sev',
                header: isAr ? 'الخطورة' : 'SEV',
                width: '44px',
                render: x => (
                  <span className={/CRITICAL|HIGH/.test(x.severity) ? 'text-rose-500' : 'text-cyan-400'}>{x.severity.slice(0, 4)}</span>
                )
              },
              {
                key: 'mitre',
                header: 'MITRE',
                width: '54px',
                render: x => (x.mitre ? <span className="text-cyan-400">{x.mitre}</span> : <span className="text-slate-700">UNMAPPED</span>)
              },
              { key: 'src', header: isAr ? 'المصدر' : 'SOURCE', width: '88px', render: x => <span className="text-slate-500">{x.srcIp ?? '—'}</span> },
              { key: 'title', header: isAr ? 'الحدث' : 'EVENT', render: x => <span className="text-slate-300">{x.title}</span> },
              {
                key: 'act',
                header: isAr ? 'الإجراء' : 'ACTION',
                width: '70px',
                render: x => (x.action ? <span className="text-emerald-400">{x.action}</span> : <span className="text-slate-700">—</span>)
              }
            ]}
          />
        </Glass>

        <Glass className="col-span-5 px-2.5 py-1.5" amber={sim} reduce={reduce} delay={0.2}>
          <SectionHead
            tone="cyan"
            right={
              <Readout className="font-mono text-[7px] text-slate-500">
                {d.frequency.length} {isAr ? 'عيّنة' : 'SAMPLES'}
              </Readout>
            }
          >
            {isAr ? 'الجدول الزمني للقياسات' : 'TELEMETRY TIMELINE'}
          </SectionHead>
          <TelemetryTimeline
            points={d.frequency.map(f => ({ label: f.label, value: f.value, threats: f.threats }))}
            isAr={isAr}
            height={126}
          />
        </Glass>
      </div>

      {/* ── LAYER 2 · STATUS STRIP ──────────────────────────────────────────── */}
      <footer
        className="relative z-20 flex shrink-0 items-center justify-between gap-3 border-t bg-[#030712]/60 px-3 py-1 backdrop-blur-2xl"
        style={{ borderColor: sim ? 'rgba(245,158,11,0.4)' : 'rgba(22,78,99,0.5)' }}
      >
        <div className="flex items-center gap-4">
          <span className="flex items-center gap-1.5">
            <Radio className="h-2.5 w-2.5 text-cyan-400" aria-hidden />
            <HudLabel tone="cyan">{isAr ? 'المحرّك' : 'ENGINE'}</HudLabel>
            <Readout className="font-mono text-[8px] text-slate-400">{d.posture.engine?.replace(/_/g, ' ') ?? '—'}</Readout>
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
            <Readout className="font-mono text-[8px] text-cyan-400">
              {d.nodes.length}
              {isolatedNodes > 0 && <span className="ms-1 text-rose-500">({isolatedNodes})</span>}
            </Readout>
          </span>
          <span className="flex items-center gap-1.5">
            <HudLabel tone="cyan">{isAr ? 'وضع النواة' : 'KERNEL'}</HudLabel>
            <Readout className="font-mono text-[8px]" tone={d.kernel.countersReadable ? 'emerald' : 'amber'}>
              {d.kernel.mode?.replace(/_/g, ' ') ?? '—'}
            </Readout>
          </span>
        </div>

        {allMissing.length > 0 ? (
          <span className="truncate font-mono text-[7px] text-rose-500/90" title={allMissing.join(' · ')}>
            {isAr ? 'مصادر صامتة: ' : 'SILENT: '}
            {allMissing.slice(0, 4).join(' · ')}
            {allMissing.length > 4 && ` +${allMissing.length - 4}`}
          </span>
        ) : (
          <span className="font-mono text-[7px] text-cyan-400/60">
            {isAr ? 'كل المصادر تستجيب' : 'ALL SOURCES RESPONDING'}
          </span>
        )}
      </footer>
    </div>
  );
};

export default TacticalCockpit;
