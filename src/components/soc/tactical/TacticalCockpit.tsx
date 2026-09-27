import React from 'react';
import { motion, useReducedMotion } from 'motion/react';
import {
  Crosshair, ShieldAlert, Cpu, Radio, Activity, Layers, Target, Waves, LayoutGrid, X
} from 'lucide-react';
import { ThreatGlobeCanvas, type ThreatOrigin } from '../cyberdefend/ThreatGlobeCanvas';
import { GlowSparkline } from '../cyberdefend/GlowSparkline';
import { useCyberDefendData } from '../cyberdefend/useCyberDefendData';
import {
  TacticalPanel, CyberGridBackdrop, Readout, HudLabel, HudValue,
  RadialGauge, LinearGauge, CYAN, CRIMSON, type Tone
} from './TacticalPrimitives';
import { SectionHead, DiamondKpi, LeaderDonut, DataTable, AlertCallout, type DonutSlice } from './BigScreenParts';
import { formatCount } from '../../../lib/utils';

/**
 * TACTICAL C2 — the platform's primary surface.
 *
 * This is a cinematic Dark SOC HUD, not a dashboard, and the distinction is
 * load-bearing:
 *
 *   A dashboard lays panels in a grid and the grid owns the viewport. A HUD gives the
 *   viewport to the operational scene and floats instrument glass over it. The two
 *   earlier attempts here built the former while being asked for the latter, which is
 *   why they kept reading as "the old design with small edits" — the chrome changed
 *   but the scene was still boxed inside a padded column under a navbar.
 *
 * So: the globe IS the viewport. Every panel is `absolute z-10` glass over it — 40%
 * black, `backdrop-blur-xl`, a cyan-500/40 border, a 20px neon halo. Nothing here
 * participates in page flow, and the surface mounts outside the app's navbar and
 * sidebar so no padding or chrome can box it in.
 *
 * Colour is a grammar, not decoration:
 *   cyan-400   structure, health, measured telemetry
 *   rose-500   threats, eBPF drops, critical alerts — nothing else
 *   black      the void behind the scene
 *
 * Data and logic are untouched. Every figure comes from `useCyberDefendData`; no
 * hook, endpoint, schema or WebSocket path was modified. Absent sources render an em
 * dash with the reason on hover, gauges draw a track and no sweep, and the status
 * strip names any endpoint that went silent, so a quiet panel stays distinguishable
 * from an idle platform. That is `.clauderules` rule 0 and it survives every restyle:
 * glass may look cinematic, but it may not show a number that is not real.
 */

interface Props {
  lang?: 'ar' | 'en';
  apiKey?: string;
  /** Opens the rest of the platform. Absent, the HUD renders without the control. */
  onExit?: () => void;
}

/** Glass shell for a floating HUD dock. The neon halo rides the backing layer. */
const Dock: React.FC<{
  children: React.ReactNode;
  className?: string;
  tone?: Tone;
  delay?: number;
  reduce: boolean;
}> = ({ children, className = '', tone = 'cyan', delay = 0, reduce }) => (
  <motion.div
    className={`absolute z-10 ${className}`}
    initial={reduce ? false : { opacity: 0, y: 10 }}
    animate={{ opacity: 1, y: 0 }}
    transition={{ duration: 0.4, delay, ease: 'easeOut' }}
  >
    <TacticalPanel tone={tone} chamfer="md" glow="strong" className="px-3 py-2">
      {children}
    </TacticalPanel>
  </motion.div>
);

export const TacticalCockpit: React.FC<Props> = ({ lang = 'ar', apiKey, onExit }) => {
  const isAr = lang === 'ar';
  const reduce = useReducedMotion() ?? false;
  const d = useCyberDefendData(apiKey);

  const [utc, setUtc] = React.useState(() => new Date().toISOString());
  const [calloutOpen, setCalloutOpen] = React.useState(true);
  const [selectedNode, setSelectedNode] = React.useState(0);

  React.useEffect(() => {
    const t = setInterval(() => setUtc(new Date().toISOString()), 1000);
    return () => clearInterval(t);
  }, []);

  /**
   * Claim the root background for the duration.
   *
   * The app paints #0d1117 on html/body/#root with `!important`, which is right for
   * the other consoles and wrong here: a blue-grey root reads as haze at every edge
   * this fixed surface does not cover. Cleared on unmount so leaving the HUD restores
   * the console palette instead of leaving the rest of the platform black.
   */
  React.useEffect(() => {
    document.documentElement.setAttribute('data-surface', 'tactical');
    return () => document.documentElement.removeAttribute('data-surface');
  }, []);

  const origins: ThreatOrigin[] = d.geo.map(g => ({ country: g.country, code: g.code, count: g.count }));
  const node = d.nodes[selectedNode] ?? d.nodes[0] ?? null;
  const critical = d.alerts.filter(a => /CRITICAL|HIGH/.test(a.severity));

  const familySlices: DonutSlice[] = d.families.map(f => ({
    label: f.family,
    value: f.count,
    tone: f.family === 'CLEAN_TRAFFIC' ? ('cyan' as Tone) : ('crimson' as Tone)
  }));

  return (
    <div className="fixed inset-0 z-0 overflow-hidden bg-black" dir={isAr ? 'rtl' : 'ltr'}>
      {/* ── The scene. Fills the viewport; everything else floats over it. ── */}
      <div className="absolute inset-0 z-0">
        <CyberGridBackdrop reduce={reduce} />
        <ThreatGlobeCanvas
          origins={origins}
          target={{ label: 'SOC', lat: 24.7, lon: 46.7 }}
          height={1080}
          reducedMotion={reduce}
          className="h-full w-full"
        />
        {/* Vignette, so glass at the edges keeps contrast against a bright limb */}
        <div
          className="pointer-events-none absolute inset-0"
          style={{ background: 'radial-gradient(ellipse at center, transparent 42%, rgba(0,0,0,0.82) 100%)' }}
          aria-hidden
        />
      </div>

      {/* ── Header rail ──────────────────────────────────────────────────── */}
      <div className="absolute inset-x-0 top-0 z-10 flex items-center gap-3 border-b border-cyan-500/20 bg-black/40 px-4 py-2 backdrop-blur-xl">
        <span
          className="grid h-7 w-7 shrink-0 place-items-center border border-cyan-500/40 shadow-[0_0_20px_rgba(0,255,255,0.1)]"
          style={{ clipPath: 'polygon(7px 0,100% 0,100% calc(100% - 7px),calc(100% - 7px) 100%,0 100%,0 7px)' }}
        >
          <Crosshair className="h-3.5 w-3.5 text-cyan-400" strokeWidth={1.25} aria-hidden />
        </span>
        <div className="shrink-0 leading-none">
          <p
            className="text-[13px] font-bold tracking-[0.22em] text-white"
            style={{ fontFamily: 'var(--font-mono)', textShadow: `0 0 14px ${CYAN}66` }}
          >
            SOVEREIGN DEFENDER
          </p>
          <p className="mt-0.5 text-[6.5px] tracking-[0.3em] text-cyan-400/70" style={{ fontFamily: 'var(--font-mono)' }}>
            TACTICAL C2 · ZERO EGRESS
          </p>
        </div>

        <span className="h-px flex-1" style={{ background: `linear-gradient(90deg, ${CYAN}55, transparent)` }} />

        {d.emergencyLockdown && (
          <span className="flex shrink-0 items-center gap-1 text-rose-500">
            <ShieldAlert className="h-3.5 w-3.5" aria-hidden />
            <span className="text-[9px] font-bold tracking-[0.16em]" style={{ fontFamily: 'var(--font-mono)' }}>
              {isAr ? 'إغلاق طارئ' : 'LOCKDOWN'}
            </span>
          </span>
        )}

        <Readout className="shrink-0 text-[10px] text-cyan-400/70">{utc.slice(0, 10)}</Readout>
        <Readout className="shrink-0 text-[13px] font-bold text-cyan-400" title="UTC">
          {utc.slice(11, 19)}
        </Readout>
        <HudLabel tone="cyan">UTC</HudLabel>

        {onExit && (
          <button
            type="button"
            onClick={onExit}
            className="ms-1 flex shrink-0 items-center gap-1.5 border border-cyan-500/40 px-2 py-1 text-[8px] tracking-[0.14em] text-cyan-400 shadow-[0_0_20px_rgba(0,255,255,0.1)] transition-colors hover:bg-cyan-500/10"
            style={{ fontFamily: 'var(--font-mono)' }}
          >
            <LayoutGrid className="h-3 w-3" aria-hidden />
            {isAr ? 'بقيّة المنصّة' : 'ALL CONSOLES'}
          </button>
        )}
      </div>

      {/* ── Left dock: diamond KPI column ────────────────────────────────── */}
      <Dock className="start-3 top-14 w-[186px]" reduce={reduce} delay={0.05}>
        <SectionHead tone="cyan">{isAr ? 'الحالة' : 'POSTURE'}</SectionHead>
        <div className="mt-2 space-y-2.5">
          <DiamondKpi value={d.agent.requestsProtected} label={isAr ? 'طلبات محميّة' : 'PROTECTED'} tone="cyan" icon={Activity} />
          <DiamondKpi value={d.agent.threatsBlocked} label={isAr ? 'تهديدات محجوبة' : 'BLOCKED'} tone="crimson" icon={Target} />
          <DiamondKpi value={d.kernel.blackholes} label={isAr ? 'حجب نشط' : 'ACTIVE BLOCKS'} tone="amber" icon={ShieldAlert} />
          <DiamondKpi value={d.agent.signatures} label={isAr ? 'بصمات' : 'SIGNATURES'} tone="cyan" icon={Layers} />
          <DiamondKpi value={d.nodes.length} label={isAr ? 'عقد العنقود' : 'CLUSTER NODES'} tone="emerald" icon={Cpu} />
        </div>
      </Dock>

      {/* ── Left dock: kernel provenance ─────────────────────────────────── */}
      <Dock
        className="start-3 bottom-32 w-[186px]"
        tone={d.kernel.countersReadable ? 'emerald' : 'amber'}
        reduce={reduce}
        delay={0.1}
      >
        <SectionHead tone={d.kernel.countersReadable ? 'emerald' : 'amber'}>
          {isAr ? 'وضع النواة' : 'KERNEL MODE'}
        </SectionHead>
        <p className="mt-1.5">
          <Readout className="text-[8.5px]" tone={d.kernel.countersReadable ? 'emerald' : 'amber'}>
            {d.kernel.mode?.replace(/_/g, ' ') ?? '—'}
          </Readout>
        </p>
        {d.kernel.countersReadable === false && (
          <p className="mt-1.5 text-[7px] leading-relaxed text-rose-500/80">
            {isAr
              ? 'العدّادات غير مقروءة — أرقام الحِزَم مزروعة وزمن النواة غير متاح.'
              : 'Counters unreadable — packet figures are seeded and kernel latency is unavailable.'}
          </p>
        )}
      </Dock>

      {/* ── Right dock: gauges ───────────────────────────────────────────── */}
      <Dock className="end-3 top-14 w-[210px]" reduce={reduce} delay={0.08}>
        <SectionHead tone="cyan">{isAr ? 'المقاييس' : 'GAUGES'}</SectionHead>
        <div className="mt-2 grid grid-cols-2 gap-1">
          <RadialGauge
            value={d.derived.requestRate}
            max={200}
            label={isAr ? 'طلب/ث' : 'RPS'}
            tone="cyan"
            size={62}
            reason="awaiting a second sample"
          />
          <RadialGauge
            value={d.kernel.latencyUs}
            max={2}
            label={isAr ? 'نواة' : 'KERNEL'}
            unit="µs"
            tone="amber"
            size={62}
            reason={d.kernel.reason ?? undefined}
          />
        </div>
        <div className="mt-2 space-y-2">
          <LinearGauge
            value={d.derived.threatDensity}
            max={500}
            label={isAr ? 'كثافة /10k' : 'DENSITY /10k'}
            tone="amber"
            segments={18}
            reason="needs both counters"
          />
          <LinearGauge
            value={d.posture.heapMb}
            max={d.posture.rssMb ?? 512}
            label={isAr ? 'ذاكرة' : 'HEAP'}
            unit="MB"
            tone="cyan"
            segments={18}
          />
        </div>
      </Dock>

      {/* ── Right dock: drift ────────────────────────────────────────────── */}
      <Dock
        className="end-3 top-[266px] w-[210px]"
        tone={
          d.drift.maxPsi != null && d.drift.thresholds && d.drift.maxPsi >= d.drift.thresholds.significant
            ? 'crimson'
            : 'cyan'
        }
        reduce={reduce}
        delay={0.12}
      >
        <SectionHead tone="cyan">{isAr ? 'انحراف التوزيع' : 'DISTRIBUTION DRIFT'}</SectionHead>
        {d.drift.verdict === 'INSUFFICIENT_DATA' ? (
          <p className="mt-1.5 text-[7.5px] leading-relaxed text-slate-500">{d.drift.insufficientReason}</p>
        ) : (
          <>
            <div className="mt-1.5 flex items-baseline gap-1.5">
              <HudValue v={d.drift.maxPsi} tone="cyan" glow className="text-[16px] font-bold" />
              <HudLabel tone="cyan">PSI</HudLabel>
            </div>
            <div className="mt-1.5 space-y-[3px]">
              {d.drift.features
                .slice()
                .sort((a, b) => b.psi - a.psi)
                .slice(0, 5)
                .map(f => {
                  const sig = d.drift.thresholds?.significant ?? 0.25;
                  const c = f.psi >= sig ? CRIMSON : CYAN;
                  return (
                    <div key={f.feature} className="flex items-center gap-1.5">
                      <span className="w-[60px] shrink-0 truncate text-[6.5px] text-slate-500">{f.feature}</span>
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
      </Dock>

      {/* ── Right dock: family breakdown ─────────────────────────────────── */}
      <Dock className="end-3 bottom-32 w-[210px]" reduce={reduce} delay={0.16}>
        <SectionHead tone="cyan">{isAr ? 'عائلات الهجوم' : 'ATTACK FAMILIES'}</SectionHead>
        <div className="mt-1">
          <LeaderDonut
            slices={familySlices}
            isAr={isAr}
            size={104}
            centreLabel={String(d.families.reduce((a, f) => a + f.count, 0) || '')}
          />
        </div>
      </Dock>

      {/* ── Centre-left dock: the threat feed ────────────────────────────── */}
      <Dock
        className="start-[204px] top-14 w-[330px]"
        tone={critical.length ? 'crimson' : 'cyan'}
        reduce={reduce}
        delay={0.2}
      >
        <SectionHead
          tone={critical.length ? 'crimson' : 'cyan'}
          right={<Readout className="text-[7.5px] text-slate-500">{d.alerts.length}</Readout>}
        >
          {isAr ? 'تغذية التهديدات' : 'THREAT FEED'}
        </SectionHead>
        <DataTable
          rows={d.alerts.slice(0, 40)}
          isAr={isAr}
          emptyEndpoint="/soc/unified-telemetry"
          maxHeight={168}
          columns={[
            {
              key: 'time',
              header: isAr ? 'الوقت' : 'TIME',
              width: '50px',
              render: a => <span className="text-slate-500">{a.at.slice(11, 19)}</span>
            },
            {
              key: 'sev',
              header: isAr ? 'الخطورة' : 'SEV',
              width: '46px',
              render: a => (
                <span className={/CRITICAL|HIGH/.test(a.severity) ? 'text-rose-500' : 'text-cyan-400'}>
                  {a.severity.slice(0, 4)}
                </span>
              )
            },
            {
              key: 'mitre',
              header: 'MITRE',
              width: '56px',
              render: a =>
                a.mitre ? (
                  <span className="text-cyan-400">{a.mitre}</span>
                ) : (
                  <span className="text-slate-700">UNMAPPED</span>
                )
            },
            {
              key: 'title',
              header: isAr ? 'الحدث' : 'EVENT',
              render: a => <span className="text-slate-300">{a.title}</span>
            }
          ]}
        />
      </Dock>

      {/* ── Alert callout, pinned over the scene ─────────────────────────── */}
      {calloutOpen && critical.length > 0 && (
        <div className="absolute start-[204px] top-[268px] z-10 max-w-[300px]">
          <AlertCallout
            title={isAr ? 'حالة حرجة' : 'CRITICAL STATE'}
            detail={critical[0].title || (isAr ? 'تنبيه بلا عنوان' : 'untitled alert')}
            onClose={() => setCalloutOpen(false)}
          />
        </div>
      )}

      {/* ── Scene labels: top origin, selected node ──────────────────────── */}
      {d.geo[0] && (
        <div className="absolute start-1/2 top-16 z-10 flex -translate-x-1/2 items-center gap-2 border border-rose-500/40 bg-black/40 px-2.5 py-1 shadow-[0_0_20px_rgba(244,63,94,0.12)] backdrop-blur-xl">
          {!reduce && (
            <motion.span
              className="h-1.5 w-1.5 rounded-full bg-rose-500"
              style={{ boxShadow: `0 0 8px ${CRIMSON}` }}
              animate={{ opacity: [1, 0.2, 1] }}
              transition={{ duration: 1.1, repeat: Infinity }}
              aria-hidden
            />
          )}
          <span className="text-[7.5px] tracking-[0.16em] text-rose-500/80" style={{ fontFamily: 'var(--font-mono)' }}>
            {isAr ? 'أعلى مصدر' : 'TOP ORIGIN'}
          </span>
          <Readout className="text-[10px] font-bold text-rose-500">
            {d.geo[0].code} · {formatCount(d.geo[0].count)}
          </Readout>
        </div>
      )}

      {node && (
        <button
          type="button"
          onClick={() => setSelectedNode(i => (i + 1) % Math.max(1, d.nodes.length))}
          className="absolute start-1/2 bottom-[168px] z-10 -translate-x-1/2 border border-cyan-500/40 bg-black/40 px-3 py-1.5 text-center shadow-[0_0_20px_rgba(0,255,255,0.1)] backdrop-blur-xl transition-colors hover:bg-cyan-500/10"
          aria-label={
            isAr
              ? `العقدة ${selectedNode + 1} من ${d.nodes.length}، اضغط للعقدة التالية`
              : `Node ${selectedNode + 1} of ${d.nodes.length}, press for the next node`
          }
        >
          <span className="text-[7px] tracking-[0.16em] text-cyan-400/70" style={{ fontFamily: 'var(--font-mono)' }}>
            {isAr ? 'العقدة' : 'NODE'} {selectedNode + 1}/{d.nodes.length}
          </span>
          <p className="text-[10px] text-slate-200">{node.name}</p>
          <Readout className="text-[8px] text-slate-500">{node.ip}</Readout>
          <p className={`text-[7px] ${node.isolated ? 'text-rose-500' : 'text-cyan-400/80'}`}>
            {node.isolated ? (isAr ? 'معزولة' : 'ISOLATED') : isAr ? 'متصلة' : 'ATTACHED'}
          </p>
        </button>
      )}

      {/* ── Bottom dock: tendency chart, spanning the scene ──────────────── */}
      <div className="absolute inset-x-3 bottom-8 z-10">
        <TacticalPanel chamfer="md" glow="strong" className="px-3 py-2">
          <SectionHead
            tone="cyan"
            right={
              <Readout className="text-[7.5px] text-slate-500">
                {d.frequency.length} {isAr ? 'عيّنة' : 'SAMPLES'}
              </Readout>
            }
          >
            {isAr ? 'منحنى حركة المرور' : 'TRAFFIC TENDENCY'}
          </SectionHead>
          {d.frequency.length >= 2 ? (
            <GlowSparkline
              points={d.frequency.map(f => ({ label: f.label, value: f.value, secondary: f.threats }))}
              isAr={isAr}
              height={82}
              accent={CYAN}
              secondaryAccent={CRIMSON}
              unit={isAr ? '' : '/s'}
            />
          ) : (
            <p className="py-6 text-center text-[8px] text-slate-600" style={{ fontFamily: 'var(--font-mono)' }}>
              {isAr ? 'لا بيانات من /soc/analytics' : 'no data from /soc/analytics'}
            </p>
          )}
        </TacticalPanel>
      </div>

      {/* ── Status strip ─────────────────────────────────────────────────── */}
      <div className="absolute inset-x-0 bottom-0 z-10 flex items-center justify-between gap-3 border-t border-cyan-500/20 bg-black/40 px-4 py-1 backdrop-blur-xl">
        <div className="flex items-center gap-4">
          <span className="flex items-center gap-1.5">
            <Radio className="h-3 w-3 text-cyan-400" aria-hidden />
            <HudLabel tone="cyan">{isAr ? 'المحرّك' : 'ENGINE'}</HudLabel>
            <Readout className="text-[8px] text-slate-400">{d.posture.engine?.replace(/_/g, ' ') ?? '—'}</Readout>
          </span>
          <span className="flex items-center gap-1.5">
            <Waves className={`h-3 w-3 ${d.posture.zeroEgress ? 'text-cyan-400' : 'text-rose-500'}`} aria-hidden />
            <HudLabel tone={d.posture.zeroEgress ? 'cyan' : 'crimson'}>
              {d.posture.zeroEgress === true
                ? isAr ? 'صفر خروج خارجي' : 'ZERO EGRESS'
                : d.posture.zeroEgress === false
                  ? isAr ? 'خروج ممكن' : 'EGRESS POSSIBLE'
                  : '—'}
            </HudLabel>
          </span>
          <span className="flex items-center gap-1.5">
            <HudLabel tone="cyan">{isAr ? 'مصادر' : 'ORIGINS'}</HudLabel>
            <Readout className="text-[8px] text-cyan-400">{d.geo.length}</Readout>
          </span>
        </div>

        {d.missing.length > 0 ? (
          <span className="flex items-center gap-1.5 text-[7.5px] text-rose-500/90" style={{ fontFamily: 'var(--font-mono)' }}>
            <X className="h-2.5 w-2.5" aria-hidden />
            {isAr ? 'مصادر صامتة: ' : 'SILENT: '}
            {d.missing.join(' · ')}
          </span>
        ) : (
          <span className="text-[7.5px] text-cyan-400/60" style={{ fontFamily: 'var(--font-mono)' }}>
            {isAr ? 'كل المصادر تستجيب' : 'ALL SOURCES RESPONDING'}
          </span>
        )}
      </div>
    </div>
  );
};

export default TacticalCockpit;
