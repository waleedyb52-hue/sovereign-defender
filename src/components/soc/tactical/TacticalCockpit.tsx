import React from 'react';
import { motion, useReducedMotion } from 'motion/react';
import { Crosshair, LayoutGrid, Radio, Waves, ArrowUpDown } from 'lucide-react';
import { useCyberDefendData } from '../cyberdefend/useCyberDefendData';
import { CornerAccents, Readout, HudLabel, CYAN, CRIMSON, type Tone } from './TacticalPrimitives';
import { SectionHead, DataTable } from './BigScreenParts';
import { TacticalTheater } from './TacticalTheater';
import { KillChainRail, type ContainAction } from './KillChainRail';
import { CyberButton } from './CyberButton';
import { EbpfModule, WafModule, FimModule, ScannerModule, IntelModule, ZtnaModule } from './ArsenalModules';
import { HoneypotSensorGrid } from './HoneypotSensorGrid';
import { TelemetryDials } from './TelemetryDials';
import { ThreatIntelTicker } from './ThreatIntelTicker';
import { IsolationConfirmDialog, type IsolationRequest } from './IsolationConfirmDialog';
import { useContainment } from './useContainment';
import { useLanWatch } from './useLanWatch';
import { useTripwire } from './useTripwire';
import { TripwirePanel } from './TripwirePanel';
import { IpDossierContext, IpLink } from './ipDossier';
import { IpDossierDrawer } from './IpDossierDrawer';
import { OperatorBadge } from './OperatorBadge';
import { AuditTrailPanel } from './AuditTrailPanel';
import { OperatorAdminPanel } from './OperatorAdminPanel';
import { useOperator } from '../../auth/operatorContext';
import { AssetFleetPanel, AssetDrawer } from './AssetFleetPanel';
import { useAssets, type AssetRow } from './useAssets';
import { NetworkTopologyView } from './NetworkTopologyView';
import { NetworkDeviceTable, buildDeviceRows } from './NetworkDeviceTable';
import { ToolWorkspace, TOOL_ICONS, type ToolId, type ToolSpec } from './ToolWorkspace';
import { TelemetryTimeline } from './TelemetryTimeline';
import { WargamePanel } from './WargamePanel';
import {
  ContainmentFrame, DefconBadge, EnvironmentToggle, ResourceTicker, SimulationFrame, deriveDefcon, type Environment
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
  const fleet = useAssets(apiKey);
  const c = useContainment(apiKey);
  const lan = useLanWatch();
  const trip = useTripwire();
  /** The address whose dossier is open. Any IpLink in the cockpit sets it. */
  const [dossierIp, setDossierIp] = React.useState<string | null>(null);
  const dossier = React.useMemo(() => ({ open: (ip: string) => setDossierIp(ip) }), []);
  const { operator, can } = useOperator();
  /** VIEWERs see containment controls disabled, with the reason, rather than refused on click. */
  const canAct = can('ANALYST');

  const [env, setEnv] = React.useState<Environment>('LIVE');
  const [utc, setUtc] = React.useState(() => new Date().toISOString());
  const [sortBy, setSortBy] = React.useState<SortKey>('TIME');
  const [critOnly, setCritOnly] = React.useState(false);
  const [selectedAsset, setSelectedAsset] = React.useState<AssetRow | null>(null);
  /**
   * Which theatre is on stage.
   *
   * Two views rather than one, and never blended. GEO answers "where is this coming
   * from" with position meaning position; NET answers "what is on my network" with
   * position meaning relationship. The previous single canvas mixed the two — bearing
   * from longitude, radius from threat volume — so it could answer neither.
   */
  const [theatre, setTheatre] = React.useState<'GEO' | 'NET'>('NET');
  /**
   * How the network is shown. A graph answers "how is this connected"; a table answers
   * "how many do I have" and "which expose SMB". Those are questions about a set, and a
   * set is read as a list. Shipping only the graph left half the inventory unreadable.
   */
  const [netView, setNetView] = React.useState<'GRAPH' | 'TABLE'>('GRAPH');
  const [workspace, setWorkspace] = React.useState<ToolId | null>(null);
  /** The pending isolation, awaiting the two-step confirmation. */
  const [isoReq, setIsoReq] = React.useState<IsolationRequest | null>(null);

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
   * Containment goes through the two-step confirmation (IsolationConfirmDialog) and
   * then useContainment, which posts the body the route actually reads. No control in
   * this cockpit calls the containment endpoint directly.
   */
  const requestFromChain = (action: ContainAction, ip: string) => {
    const ch = r.chains.find(x => x.actorIp === ip);
    const stage = ch?.stages[ch.stages.length - 1];
    setIsoReq({
      ip,
      origin: `KILL CHAIN · ${action}`,
      context: ch
        ? `${ch.sessionId}${stage ? ` · ${stage.stage}${stage.technique ? ` (${stage.technique})` : ''}` : ''}`
        : null
    });
  };

  /** Real containments only. The service's seeded demo records do not raise the frame. */
  const containedIps = c.active.filter(x => !x.seeded).map(x => x.ip);

  /**
   * Which addresses turn a topology path crimson, and why. Named by a HIGH/CRITICAL
   * alert's source or by an active containment — nothing else colours a path red.
   */
  const hotIps = React.useMemo(() => {
    const m = new Map<string, string>();
    for (const x of d.alerts) {
      if (x.srcIp && /CRITICAL|HIGH/.test(x.severity) && !m.has(x.srcIp)) {
        m.set(x.srcIp, `${x.severity} alert: ${x.title}${x.mitre ? ` (${x.mitre})` : ''}`);
      }
    }
    for (const x of c.active) if (!x.seeded) m.set(x.ip, 'contained');
    return m;
  }, [d.alerts, c.active]);

  /**
   * The tool index. Each badge is a live figure so the list shows state without being
   * opened, and a silent endpoint is named so a quiet panel is never mistaken for a
   * clean result.
   */
  const deviceCount = React.useMemo(() => buildDeviceRows(fleet.assets).length, [fleet.assets]);
  const toolSpecs: ToolSpec[] = [
    {
      id: 'FLEET',
      icon: TOOL_ICONS.FLEET,
      ar: 'أسطول الأصول',
      en: 'ASSET FLEET',
      badge: fleet.summary ? `${fleet.summary.online}/${fleet.summary.hosts}` : null,
      alert: Boolean(fleet.summary && fleet.summary.offline > 0),
      silentEndpoint: fleet.unreachable ? '/api/v1/assets' : null
    },
    {
      id: 'NETWORK',
      icon: TOOL_ICONS.NETWORK,
      ar: 'أجهزة الشبكة',
      en: 'NETWORK DEVICES',
      badge: deviceCount ? String(deviceCount) : null,
      // New devices awaiting review, or a gateway ARP alarm, tint the tool in the index.
      alert: Boolean(lan.status?.newCount) || lan.alarms.length > 0,
      silentEndpoint: lan.error ? '/api/v1/lan-watch' : null
    },
    {
      id: 'EBPF',
      icon: TOOL_ICONS.EBPF,
      ar: 'نواة eBPF / XDP',
      en: 'eBPF / XDP KERNEL',
      badge: a.ebpf.dropped != null ? a.ebpf.dropped.toLocaleString('en-US') : null,
      alert: a.ebpf.emulated,
      silentEndpoint: a.missing.includes('/ebpf/real-stats') ? '/ebpf/real-stats' : null
    },
    {
      id: 'WAF',
      icon: TOOL_ICONS.WAF,
      ar: 'جدار التطبيقات L7',
      en: 'AI WAF · LAYER 7',
      badge: a.waf.rulesOn != null && a.waf.rulesTotal != null ? `${a.waf.rulesOn}/${a.waf.rulesTotal}` : null,
      silentEndpoint: a.missing.includes('/traffic/waf/metrics') ? '/traffic/waf/metrics' : null
    },
    {
      id: 'FIM',
      icon: TOOL_ICONS.FIM,
      ar: 'سلامة الملفات',
      en: 'FILE INTEGRITY',
      badge: a.fim.files.length ? String(a.fim.files.length) : null,
      // A tripwire in the last 24 hours keeps the tool flagged until someone has looked.
      alert:
        a.fim.files.some(f => f.status != null && !/INTACT|OK|VERIFIED/i.test(f.status)) ||
        (trip.status?.incidents ?? []).some(i => Date.now() - Date.parse(i.at) < 86_400_000),
      silentEndpoint: a.missing.includes('/fim/files') ? '/fim/files' : null
    },
    {
      id: 'SCANNER',
      icon: TOOL_ICONS.SCANNER,
      ar: 'تدقيق سطح الويب',
      en: 'WEB SURFACE AUDIT',
      badge: a.scans.count ? String(a.scans.count) : null,
      silentEndpoint: a.missing.includes('/scanner/history') ? '/scanner/history' : null
    },
    {
      id: 'INTEL',
      icon: TOOL_ICONS.INTEL,
      ar: 'استخبارات ومصائد',
      en: 'INTEL · HONEYPOTS',
      // IOC count, not honeypotTrappedCount: the latter starts at a seeded 42.
      badge: a.intel.iocs.length ? String(a.intel.iocs.length) : null,
      silentEndpoint: a.missing.includes('/forensics/threat-intel/iocs') ? '/forensics/threat-intel/iocs' : null
    },
    {
      id: 'ZTNA',
      icon: TOOL_ICONS.ZTNA,
      ar: 'ثقة صفرية وحجر',
      en: 'ZERO TRUST · QUARANTINE',
      badge: a.ztna.activeHardBans != null ? String(a.ztna.activeHardBans) : null,
      alert: Boolean(a.ztna.pendingFrozen) || containedIps.length > 0,
      silentEndpoint: a.missing.includes('/insider-zero-trust/actions') ? '/insider-zero-trust/actions' : null
    },
    ...(canAct
      ? [{ id: 'AUDIT' as const, icon: TOOL_ICONS.AUDIT, ar: 'سجل التدقيق', en: 'AUDIT TRAIL' }]
      : []),
    ...(can('ADMIN')
      ? [{ id: 'OPERATORS' as const, icon: TOOL_ICONS.OPERATORS, ar: 'المشغّلون', en: 'OPERATORS' }]
      : [])
  ];

  const allMissing = [...d.missing, ...r.missing, ...a.missing];
  const accent = sim ? '#fbbf24' : CYAN;

  return (
    <IpDossierContext.Provider value={dossier}>
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
        {theatre === 'NET' ? (
          netView === 'GRAPH' ? (
            <NetworkTopologyView
              assets={fleet.assets}
              isAr={isAr}
              onSelectAsset={setSelectedAsset}
              hot={hotIps}
              className="h-full w-full"
            />
          ) : (
            <div className="h-full w-full px-3 pt-16 pb-24">
              <div className="mx-auto h-full max-w-5xl border border-cyan-500/30 bg-[#030712]/80 p-2.5 backdrop-blur-2xl">
                <NetworkDeviceTable
                  assets={fleet.assets}
                  isAr={isAr}
                  onOpenAsset={setSelectedAsset}
                  lan={lan}
                  canAct={canAct}
                  className="h-full"
                />
              </div>
            </div>
          )
        ) : (
          <TacticalTheater
            contacts={d.geo.map(g => ({ code: g.code, country: g.country, count: g.count }))}
            nodes={d.nodes.map(n => ({ name: n.name, ip: n.ip, isolated: n.isolated, threatScore: n.threatScore }))}
            tracers={stream.tracers}
            status={stream.status}
            reduce={reduce}
            isAr={isAr}
            className="h-full w-full"
          />
        )}
        <div
          className="pointer-events-none absolute inset-0"
          style={{ background: 'radial-gradient(ellipse at center, transparent 36%, rgba(0,0,0,0.88) 100%)' }}
          aria-hidden
        />
      </div>

      {sim && <SimulationFrame isAr={isAr} drillActive={w.drillActive} detail={w.activePhase ? `PHASE ${w.activePhase}` : null} />}
      <ContainmentFrame isAr={isAr} ips={containedIps} busyIp={c.busyIp} onRelease={canAct ? ip => void c.release(ip) : undefined} />

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
          rps={d.derived.requestRate}
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
            className={`font-mono text-[10px] tracking-widest uppercase ${
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

        <OperatorBadge isAr={isAr} />

        {onExit && (
          <CyberButton tone="cyan" size="sm" onClick={onExit}>
            <span className="flex items-center gap-1">
              <LayoutGrid className="h-2.5 w-2.5" aria-hidden />
              {isAr ? '[ الكونسولات ]' : '[ CONSOLES ]'}
            </span>
          </CyberButton>
        )}
      </header>

      <ThreatIntelTicker a={a} isAr={isAr} />

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
              <SectionHead tone="cyan">{isAr ? 'قياسات النواة وL7' : 'KERNEL · L7 DIALS'}</SectionHead>
              <div className="mt-1.5 mb-2 shrink-0 border-b border-cyan-900/40 pb-2">
                <TelemetryDials a={a} isAr={isAr} />
              </div>
              <SectionHead tone={critical.length ? 'crimson' : 'cyan'}>
                {isAr ? 'سلسلة القتل والاحتواء' : 'KILL CHAIN'}
              </SectionHead>
              <div className="mt-1.5 min-h-0 flex-1">
                <KillChainRail
                  chains={r.chains}
                  isAr={isAr}
                  chainsUnavailable={r.missing.includes('/soc/attack-chains')}
                  onContain={canAct ? requestFromChain : undefined}
                />
              </div>
            </>
          )}
        </Glass>

        {/* CENTRE: the theatre shows through; only its labels sit here */}
        <div className="pointer-events-none col-span-6 flex min-h-0 flex-col justify-between xl:col-span-7">
          <div className="pointer-events-auto flex justify-center gap-1 pt-4">
            <CyberButton tone="cyan" size="sm" active={theatre === 'NET'} onClick={() => setTheatre('NET')}>
              {isAr ? '[ شبكتي ]' : '[ MY NETWORK ]'}
            </CyberButton>
            <CyberButton tone="cyan" size="sm" active={theatre === 'GEO'} onClick={() => setTheatre('GEO')}>
              {isAr ? '[ مصادر عالمية ]' : '[ GLOBAL ORIGINS ]'}
            </CyberButton>
            {theatre === 'NET' && (
              <>
                <span className="mx-1 h-4 w-px self-center bg-cyan-500/25" aria-hidden />
                <CyberButton tone="cyan" size="sm" active={netView === 'GRAPH'} onClick={() => setNetView('GRAPH')}>
                  {isAr ? '[ رسم ]' : '[ GRAPH ]'}
                </CyberButton>
                <CyberButton tone="cyan" size="sm" active={netView === 'TABLE'} onClick={() => setNetView('TABLE')}>
                  {isAr ? '[ قائمة الأجهزة ]' : '[ DEVICE LIST ]'}
                </CyberButton>
              </>
            )}
            {sim && (
              <span
                className="border border-amber-500/60 bg-amber-950/70 px-2 py-1 font-mono text-[10px] tracking-widest text-amber-400 uppercase backdrop-blur-2xl"
                style={{ textShadow: '0 0 8px rgba(251,191,36,0.9)' }}
              >
                {isAr ? 'محاكاة' : 'SIMULATION'}
              </span>
            )}
          </div>

          {theatre === 'GEO' && d.geo[0] && (
            <div className="flex justify-center pb-1">
              <span
                className="border border-rose-900/60 bg-[#030712]/60 px-3 py-0.5 font-mono text-[10px] text-rose-400 backdrop-blur-2xl"
                style={{ textShadow: '0 0 8px rgba(225,29,72,0.8)' }}
              >
                {isAr ? 'أعلى مصدر' : 'TOP ORIGIN'} · {d.geo[0].code} · {d.geo[0].count.toLocaleString('en-US')}
              </span>
            </div>
          )}
        </div>

        {/* RIGHT: the arsenal stack. Always-visible status; EXPAND opens the workspace. */}
        <div className="col-span-3 flex min-h-0 flex-col gap-1.5 overflow-y-auto pe-0.5">
          <button
            type="button"
            onClick={() => setWorkspace('FLEET')}
            className="flex shrink-0 items-center justify-center gap-1.5 border border-cyan-500/40 bg-[#030712]/60 py-1 font-mono text-[10px] tracking-widest text-cyan-400 uppercase backdrop-blur-2xl transition-colors hover:bg-cyan-500/12"
          >
            {isAr ? '[ افتح قوائم الأدوات الدفاعية ]' : '[ OPEN DEFENSIVE TOOL LISTS ]'}
          </button>
          <AssetFleetPanel f={fleet} isAr={isAr} onSelect={setSelectedAsset} />
          <EbpfModule a={a} isAr={isAr} />
          <WafModule a={a} isAr={isAr} />
          <FimModule a={a} isAr={isAr} />
          <ScannerModule a={a} isAr={isAr} />
          <IntelModule a={a} isAr={isAr} />
          <HoneypotSensorGrid a={a} isAr={isAr} />
          <ZtnaModule
            a={a}
            isAr={isAr}
            c={c}
            canAct={canAct}
            onRequestIsolate={canAct ? ip => setIsoReq({ ip, origin: 'ZTNA · MANUAL ISOLATION' }) : undefined}
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
                  <span
                    className={
                      /CRITICAL|HIGH/.test(x.severity)
                        ? `text-rose-500 ${x.severity === 'CRITICAL' && Date.now() - Date.parse(x.at) < 120_000 ? 'motion-safe:animate-pulse' : ''}`
                        : 'text-cyan-400'
                    }
                  >
                    {x.severity.slice(0, 4)}
                  </span>
                )
              },
              {
                key: 'mitre',
                header: 'MITRE',
                width: '54px',
                render: x => (x.mitre ? <span className="text-cyan-400">{x.mitre}</span> : <span className="text-slate-500">UNMAPPED</span>)
              },
              { key: 'src', header: isAr ? 'المصدر' : 'SOURCE', width: '88px', render: x => <IpLink ip={x.srcIp} className="text-slate-300" /> },
              { key: 'title', header: isAr ? 'الحدث' : 'EVENT', render: x => <span className="text-slate-300">{x.title}</span> },
              {
                key: 'act',
                header: isAr ? 'الإجراء' : 'ACTION',
                width: '70px',
                render: x => (x.action ? <span className="text-emerald-400">{x.action}</span> : <span className="text-slate-500">—</span>)
              }
            ]}
          />
        </Glass>

        <Glass className="col-span-5 px-2.5 py-1.5" amber={sim} reduce={reduce} delay={0.2}>
          <SectionHead
            tone="cyan"
            right={
              <Readout className="font-mono text-[10px] text-slate-500">
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

      {/* ── LAYER 3 · TOOL WORKSPACE ────────────────────────────────────────── */}
      {/* Each tool gets room to be used, plus an index of every tool. The rail stays for
          noticing; this is for working. */}
      {workspace && (
        <ToolWorkspace
          tools={toolSpecs}
          active={workspace}
          isAr={isAr}
          onSelect={setWorkspace}
          onClose={() => setWorkspace(null)}
        >
          {workspace === 'FLEET' && <AssetFleetPanel f={fleet} isAr={isAr} onSelect={setSelectedAsset} />}
          {workspace === 'NETWORK' && (
            <NetworkDeviceTable
              assets={fleet.assets}
              isAr={isAr}
              onOpenAsset={setSelectedAsset}
              lan={lan}
              canAct={canAct}
              className="h-full min-h-[320px]"
            />
          )}
          {workspace === 'EBPF' && <EbpfModule a={a} isAr={isAr} />}
          {workspace === 'WAF' && <WafModule a={a} isAr={isAr} />}
          {workspace === 'FIM' && (
            <div>
              <FimModule a={a} isAr={isAr} />
              <TripwirePanel t={trip} isAr={isAr} canAdmin={can('ADMIN')} />
            </div>
          )}
          {workspace === 'SCANNER' && <ScannerModule a={a} isAr={isAr} />}
          {workspace === 'INTEL' && (
            <div className="space-y-2">
              <IntelModule a={a} isAr={isAr} />
              <HoneypotSensorGrid a={a} isAr={isAr} />
            </div>
          )}
          {workspace === 'AUDIT' && canAct && <AuditTrailPanel isAr={isAr} />}
          {workspace === 'OPERATORS' && can('ADMIN') && <OperatorAdminPanel isAr={isAr} selfId={operator.id} />}
          {workspace === 'ZTNA' && (
            <ZtnaModule
              a={a}
              isAr={isAr}
              c={c}
              canAct={canAct}
              onRequestIsolate={canAct ? ip => setIsoReq({ ip, origin: 'ZTNA · MANUAL ISOLATION' }) : undefined}
            />
          )}
        </ToolWorkspace>
      )}

      {/* ── LAYER 3 · ENTITY DRAWER ─────────────────────────────────────────── */}
      {/* The drill-down. Every readout in this cockpit used to be a dead end — a number
          an operator could see and not act on — which is most of what "not professional"
          meant. An asset row now opens its full record and its containment controls in
          the same place as the evidence. */}
      {selectedAsset && (
        <AssetDrawer
          asset={fleet.assets.find(x => x.id === selectedAsset.id) ?? selectedAsset}
          f={fleet}
          isAr={isAr}
          onClose={() => setSelectedAsset(null)}
        />
      )}

      {/* ── LAYER 3 · IP DOSSIER ────────────────────────────────────────────── */}
      {dossierIp && (
        <IpDossierDrawer
          ip={dossierIp}
          isAr={isAr}
          alerts={d.alerts}
          a={a}
          c={c}
          lan={lan}
          assets={fleet.assets}
          canAct={canAct}
          onRequestIsolate={canAct ? (ip, context) => setIsoReq({ ip, origin: 'IP DOSSIER', context }) : undefined}
          onClose={() => setDossierIp(null)}
        />
      )}

      {/* ── LAYER 4 · ISOLATION CONFIRMATION ────────────────────────────────── */}
      <IsolationConfirmDialog
        request={isoReq}
        isAr={isAr}
        driverMode={a.ebpf.driverMode}
        emulated={a.ebpf.emulated}
        busy={c.busyIp != null}
        onConfirm={(ip, reason) => c.contain(ip, reason)}
        onClose={() => setIsoReq(null)}
      />

      {/* ── LAYER 2 · STATUS STRIP ──────────────────────────────────────────── */}
      <footer
        className="relative z-20 flex shrink-0 items-center justify-between gap-3 border-t bg-[#030712]/60 px-3 py-1 backdrop-blur-2xl"
        style={{ borderColor: sim ? 'rgba(245,158,11,0.4)' : 'rgba(22,78,99,0.5)' }}
      >
        <div className="flex items-center gap-4">
          <span className="flex items-center gap-1.5">
            <Radio className="h-2.5 w-2.5 text-cyan-400" aria-hidden />
            <HudLabel tone="cyan">{isAr ? 'المحرّك' : 'ENGINE'}</HudLabel>
            <Readout className="font-mono text-[10px] text-slate-400">{d.posture.engine?.replace(/_/g, ' ') ?? '—'}</Readout>
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
            <HudLabel tone="cyan">{isAr ? 'أصول' : 'ASSETS'}</HudLabel>
            <Readout className="font-mono text-[10px] text-cyan-400">
              {fleet.summary ? (
                <>
                  <span className="text-emerald-400">{fleet.summary.online}</span>
                  <span className="text-slate-600">/</span>
                  {fleet.summary.hosts}
                </>
              ) : (
                '—'
              )}
            </Readout>
          </span>
          <span className="flex items-center gap-1.5">
            <HudLabel tone="cyan">{isAr ? 'أجهزة الشبكة' : 'LAN DEVICES'}</HudLabel>
            <Readout className="font-mono text-[10px] text-cyan-400">
              {fleet.summary?.lanDevices ?? '—'}
            </Readout>
          </span>
          <span className="flex items-center gap-1.5">
            <HudLabel tone="cyan">{isAr ? 'عقد' : 'NODES'}</HudLabel>
            <Readout className="font-mono text-[10px] text-cyan-400">
              {d.nodes.length}
              {isolatedNodes > 0 && <span className="ms-1 text-rose-500">({isolatedNodes})</span>}
            </Readout>
          </span>
          <span className="flex items-center gap-1.5">
            <HudLabel tone="cyan">{isAr ? 'وضع النواة' : 'KERNEL'}</HudLabel>
            <Readout className="font-mono text-[10px]" tone={d.kernel.countersReadable ? 'emerald' : 'amber'}>
              {d.kernel.mode?.replace(/_/g, ' ') ?? '—'}
            </Readout>
          </span>
        </div>

        {allMissing.length > 0 ? (
          <span className="truncate font-mono text-[10px] text-rose-500/90" title={allMissing.join(' · ')}>
            {isAr ? 'مصادر صامتة: ' : 'SILENT: '}
            {allMissing.slice(0, 4).join(' · ')}
            {allMissing.length > 4 && ` +${allMissing.length - 4}`}
          </span>
        ) : (
          <span className="font-mono text-[10px] text-cyan-400/60">
            {isAr ? 'كل المصادر تستجيب' : 'ALL SOURCES RESPONDING'}
          </span>
        )}
      </footer>
    </div>
    </IpDossierContext.Provider>
  );
};

export default TacticalCockpit;
