import React from 'react';
import { motion, useReducedMotion } from 'motion/react';
import {
  Crosshair, ShieldAlert, Cpu, Radio, Activity, Layers, Target, Waves
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
 * TACTICAL COCKPIT — big-screen command board
 *
 * Rebuilt against the reference images rather than a description of them, and the
 * difference that mattered was structural.
 *
 * The first attempt made the globe a full-bleed background with sparse cards
 * floating over it. The references do the opposite: the tactical display is a
 * CONTAINED element inside a structured grid, and every surrounding cell is packed
 * with instrumentation. A board like this is read from across a room, so density is
 * the point — empty space reads as missing instruments, not as calm.
 *
 * The grid, following 360 SKYEYE:
 *
 *   ┌ header: brand, angular rule, UTC ─────────────────────────────────────┐
 *   │ ◆ KPI │        GLOBE         │ breakdown + │ gauges    │
 *   │ ◆ KPI │      (contained)     │ threat list │ drift     │
 *   │ ◆ KPI │                      │             │ families  │
 *   ├ tendency chart, full width ───────────────────────────────────────────┤
 *   └ status strip ─────────────────────────────────────────────────────────┘
 *
 * Data and logic are untouched. Every figure still comes from `useCyberDefendData`;
 * no hook, endpoint, schema or socket path was modified by this restructure. Absent
 * sources render an em dash with the reason on hover, gauges draw a track and no
 * sweep, and the status strip names any endpoint that went silent so a quiet panel
 * stays distinguishable from an idle platform.
 */

interface Props {
  lang?: 'ar' | 'en';
  apiKey?: string;
}

export const TacticalCockpit: React.FC<Props> = ({ lang = 'ar', apiKey }) => {
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

  const origins: ThreatOrigin[] = d.geo.map(g => ({ country: g.country, code: g.code, count: g.count }));
  const node = d.nodes[selectedNode] ?? d.nodes[0] ?? null;
  const critical = d.alerts.filter(a => /CRITICAL|HIGH/.test(a.severity));

  const familySlices: DonutSlice[] = d.families.map(f => ({
    label: f.family,
    value: f.count,
    tone: f.family === 'CLEAN_TRAFFIC' ? ('cyan' as Tone) : ('crimson' as Tone)
  }));

  return (
    <div
      className="relative flex h-screen w-full flex-col overflow-hidden"
      style={{ background: '#000000' }}
      dir={isAr ? 'rtl' : 'ltr'}
    >
      <CyberGridBackdrop reduce={reduce} />

      {/* ── Header ────────────────────────────────────────────────────────── */}
      <header className="relative z-10 flex shrink-0 items-center gap-3 px-4 pt-2.5 pb-1.5">
        <div className="flex shrink-0 items-center gap-2">
          <span
            className="grid h-7 w-7 place-items-center border"
            style={{
              borderColor: `${CYAN}77`,
              clipPath: 'polygon(7px 0,100% 0,100% calc(100% - 7px),calc(100% - 7px) 100%,0 100%,0 7px)',
              boxShadow: `0 0 14px ${CYAN}33`
            }}
          >
            <Crosshair className="h-3.5 w-3.5" strokeWidth={1.25} style={{ color: CYAN }} aria-hidden />
          </span>
          <div className="leading-none">
            <p
              className="text-[13px] font-bold tracking-[0.22em] text-white"
              style={{ fontFamily: 'var(--font-mono)', textShadow: `0 0 12px ${CYAN}55` }}
            >
              SOVEREIGN
            </p>
            <p className="mt-0.5 text-[6.5px] tracking-[0.3em]" style={{ color: `${CYAN}88`, fontFamily: 'var(--font-mono)' }}>
              DEFENDER · TACTICAL C2
            </p>
          </div>
        </div>

        {/* Angular rule, as the reference caps its header line */}
        <span className="relative flex-1">
          <span className="block h-px w-full" style={{ background: `linear-gradient(90deg, ${CYAN}55, ${CYAN}11 60%, transparent)` }} />
        </span>

        <div className="flex shrink-0 items-center gap-3">
          {d.emergencyLockdown && (
            <span className="flex items-center gap-1" style={{ color: CRIMSON }}>
              <ShieldAlert className="h-3 w-3" aria-hidden />
              <HudLabel tone="crimson">{isAr ? 'إغلاق طارئ' : 'LOCKDOWN'}</HudLabel>
            </span>
          )}
          <Readout tone="cyan" className="text-[10px]">
            {utc.slice(0, 10)}
          </Readout>
          <Readout tone="cyan" glow className="text-[12px] font-bold">
            {utc.slice(11, 19)}
          </Readout>
          <HudLabel>UTC</HudLabel>
        </div>
      </header>

      {/* ── Main grid ─────────────────────────────────────────────────────── */}
      <div className="relative z-10 grid min-h-0 flex-1 grid-cols-12 gap-2 px-3">
        {/* Left: diamond KPI column */}
        <aside className="col-span-2 flex flex-col justify-center gap-3">
          <DiamondKpi
            value={d.agent.requestsProtected}
            label={isAr ? 'طلبات محميّة' : 'PROTECTED'}
            tone="cyan"
            icon={Activity}
          />
          <DiamondKpi
            value={d.agent.threatsBlocked}
            label={isAr ? 'تهديدات محجوبة' : 'BLOCKED'}
            tone="crimson"
            icon={Target}
          />
          <DiamondKpi
            value={d.kernel.blackholes}
            label={isAr ? 'حجب نشط' : 'ACTIVE BLOCKS'}
            tone="amber"
            icon={ShieldAlert}
          />
          <DiamondKpi
            value={d.agent.signatures}
            label={isAr ? 'بصمات' : 'SIGNATURES'}
            tone="cyan"
            icon={Layers}
          />
          <DiamondKpi
            value={d.nodes.length}
            label={isAr ? 'عقد العنقود' : 'CLUSTER NODES'}
            tone="emerald"
            icon={Cpu}
          />

          {/* Kernel mode, stated plainly under the badges */}
          <div className="mt-1 border-t pt-2" style={{ borderColor: `${CYAN}1a` }}>
            <HudLabel>{isAr ? 'وضع النواة' : 'KERNEL MODE'}</HudLabel>
            <p className="mt-0.5">
              <Readout className="text-[8px]" tone={d.kernel.countersReadable ? 'emerald' : 'amber'}>
                {d.kernel.mode?.replace(/_/g, ' ') ?? '—'}
              </Readout>
            </p>
            {d.kernel.countersReadable === false && (
              <p className="mt-1 text-[7px] leading-relaxed" style={{ color: `${CRIMSON}bb` }}>
                {isAr
                  ? 'العدّادات غير مقروءة — الأرقام مزروعة أو محجوبة، لا مقيسة.'
                  : 'Counters unreadable — figures are seeded or withheld, not measured.'}
              </p>
            )}
          </div>
        </aside>

        {/* Centre: the contained tactical display */}
        <section className="relative col-span-5 min-h-0">
          <TacticalPanel className="h-full" glow="strong" chamfer="lg">
            <div className="absolute inset-x-3 top-2 z-10">
              <SectionHead
                tone="cyan"
                right={
                  <Readout className="text-[7.5px] text-slate-500">
                    {d.geo.length} {isAr ? 'مصدر' : 'ORIGINS'}
                  </Readout>
                }
              >
                {isAr ? 'المشهد التكتيكي' : 'TACTICAL DISPLAY'}
              </SectionHead>
            </div>

            <div className="h-full w-full">
              <ThreatGlobeCanvas
                origins={origins}
                target={{ label: 'SOC', lat: 24.7, lon: 46.7 }}
                height={520}
                reducedMotion={reduce}
                className="block h-full w-full"
              />
            </div>

            {/* Alert callout pinned over the display, as the reference has */}
            {calloutOpen && critical.length > 0 && (
              <div className="absolute bottom-16 start-4 z-10 max-w-[260px]">
                <AlertCallout
                  title={isAr ? 'حالة حرجة' : 'CRITICAL STATE'}
                  detail={critical[0].title || (isAr ? 'تنبيه بلا عنوان' : 'untitled alert')}
                  onClose={() => setCalloutOpen(false)}
                />
              </div>
            )}

            {/* Top origin, bottom-left of the stage */}
            {d.geo[0] && (
              <div className="absolute bottom-3 start-4 z-10 flex items-center gap-2">
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
                <Readout tone="crimson" glow className="text-[10px]">
                  {d.geo[0].code} · {formatCount(d.geo[0].count)}
                </Readout>
              </div>
            )}

            {/* Selected node, bottom-right */}
            {node && (
              <button
                type="button"
                onClick={() => setSelectedNode(i => (i + 1) % Math.max(1, d.nodes.length))}
                className="absolute end-4 bottom-3 z-10 text-end transition-colors hover:bg-white/[0.04]"
                aria-label={
                  isAr
                    ? `العقدة ${selectedNode + 1} من ${d.nodes.length}، اضغط للعقدة التالية`
                    : `Node ${selectedNode + 1} of ${d.nodes.length}, press for the next node`
                }
              >
                <HudLabel tone="cyan">
                  {isAr ? 'العقدة' : 'NODE'} {selectedNode + 1}/{d.nodes.length}
                </HudLabel>
                <p className="text-[9px] text-slate-300">{node.name}</p>
                <Readout className="text-[8px] text-slate-600">{node.ip}</Readout>
                <p className="text-[7px]" style={{ color: node.isolated ? CRIMSON : `${CYAN}99` }}>
                  {node.isolated
                    ? isAr ? 'معزولة' : 'ISOLATED'
                    : isAr ? 'متصلة' : 'ATTACHED'}
                </p>
              </button>
            )}
          </TacticalPanel>
        </section>

        {/* Centre-right: breakdown and the threat list */}
        <section className="col-span-3 flex min-h-0 flex-col gap-2">
          <TacticalPanel className="px-2.5 py-2" chamfer="sm">
            <SectionHead tone="cyan">{isAr ? 'تحليل العائلات' : 'FAMILY ANALYSIS'}</SectionHead>
            <div className="mt-1.5">
              <LeaderDonut
                slices={familySlices}
                isAr={isAr}
                size={116}
                centreLabel={String(d.families.reduce((a, f) => a + f.count, 0) || '')}
              />
            </div>
          </TacticalPanel>

          <TacticalPanel className="flex min-h-0 flex-1 flex-col px-2.5 py-2" chamfer="sm">
            <SectionHead
              tone={critical.length ? 'crimson' : 'cyan'}
              right={<Readout className="text-[7.5px] text-slate-500">{d.alerts.length}</Readout>}
            >
              {isAr ? 'قائمة التهديدات' : 'THREATS LIST'}
            </SectionHead>
            <div className="min-h-0 flex-1">
              <DataTable
                rows={d.alerts.slice(0, 40)}
                isAr={isAr}
                emptyEndpoint="/soc/unified-telemetry"
                maxHeight={220}
                columns={[
                  {
                    key: 'time',
                    header: isAr ? 'الوقت' : 'TIME',
                    width: '52px',
                    render: a => <span className="text-slate-500">{a.at.slice(11, 19)}</span>
                  },
                  {
                    key: 'sev',
                    header: isAr ? 'الخطورة' : 'SEV',
                    width: '52px',
                    render: a => (
                      <span style={{ color: /CRITICAL|HIGH/.test(a.severity) ? CRIMSON : `${CYAN}cc` }}>
                        {a.severity.slice(0, 4)}
                      </span>
                    )
                  },
                  {
                    key: 'mitre',
                    header: 'MITRE',
                    width: '58px',
                    render: a =>
                      a.mitre ? (
                        <span style={{ color: `${CYAN}cc` }}>{a.mitre}</span>
                      ) : (
                        <span className="text-slate-700">UNMAPPED</span>
                      )
                  },
                  {
                    key: 'title',
                    header: isAr ? 'الحدث' : 'EVENT',
                    render: a => <span className="text-slate-400">{a.title}</span>
                  }
                ]}
              />
            </div>
          </TacticalPanel>
        </section>

        {/* Right: gauge stack */}
        <aside className="col-span-2 flex min-h-0 flex-col gap-2">
          <TacticalPanel className="px-2.5 py-2" chamfer="sm">
            <SectionHead tone="cyan">{isAr ? 'المقاييس' : 'GAUGES'}</SectionHead>
            <div className="mt-2 grid grid-cols-2 gap-1">
              <RadialGauge
                value={d.derived.requestRate}
                max={200}
                label={isAr ? 'طلب/ث' : 'RPS'}
                tone="cyan"
                size={54}
                reason="awaiting a second sample"
              />
              <RadialGauge
                value={d.kernel.latencyUs}
                max={2}
                label={isAr ? 'نواة' : 'KERNEL'}
                unit="µs"
                tone="amber"
                size={54}
                reason={d.kernel.reason ?? undefined}
              />
            </div>
            <div className="mt-2 space-y-1.5">
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
          </TacticalPanel>

          <TacticalPanel className="px-2.5 py-2" chamfer="sm">
            <SectionHead
              tone={
                d.drift.maxPsi != null && d.drift.thresholds && d.drift.maxPsi >= d.drift.thresholds.significant
                  ? 'crimson'
                  : 'cyan'
              }
            >
              {isAr ? 'الانحراف' : 'DRIFT'}
            </SectionHead>
            {d.drift.verdict === 'INSUFFICIENT_DATA' ? (
              <p className="mt-1.5 text-[7.5px] leading-relaxed text-slate-600">{d.drift.insufficientReason}</p>
            ) : (
              <>
                <div className="mt-1.5 flex items-baseline gap-1.5">
                  <HudValue v={d.drift.maxPsi} tone="cyan" glow className="text-[15px] font-bold" />
                  <HudLabel>PSI</HudLabel>
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
                          <span className="w-[54px] shrink-0 truncate text-[6.5px] text-slate-600">{f.feature}</span>
                          <span className="h-[2px] flex-1 bg-white/5">
                            <span
                              className="block h-full"
                              style={{
                                width: `${Math.min(100, (f.psi / Math.max(sig * 2, 0.5)) * 100)}%`,
                                background: c,
                                boxShadow: `0 0 5px ${c}88`
                              }}
                            />
                          </span>
                        </div>
                      );
                    })}
                </div>
              </>
            )}
          </TacticalPanel>

          <TacticalPanel className="min-h-0 flex-1 px-2.5 py-2" chamfer="sm">
            <SectionHead tone="cyan">{isAr ? 'نقاط النهاية' : 'ENDPOINTS'}</SectionHead>
            <DataTable
              rows={d.endpoints}
              isAr={isAr}
              emptyEndpoint="/soc/analytics"
              maxHeight={124}
              columns={[
                {
                  key: 'ep',
                  header: isAr ? 'المسار' : 'PATH',
                  render: e => <span className="text-slate-400">{e.endpoint}</span>
                },
                {
                  key: 'hits',
                  header: isAr ? 'زيارات' : 'HITS',
                  width: '42px',
                  render: e => {
                    const hot = e.hits > 0 && e.threatHits / e.hits > 0.3;
                    return <span style={{ color: hot ? CRIMSON : `${CYAN}cc` }}>{formatCount(e.hits)}</span>;
                  }
                }
              ]}
            />
          </TacticalPanel>
        </aside>
      </div>

      {/* ── Tendency chart, full width ────────────────────────────────────── */}
      <section className="relative z-10 shrink-0 px-3 pt-2">
        <TacticalPanel className="px-3 py-2" chamfer="sm" glow="none">
          <SectionHead
            tone="cyan"
            right={
              <Readout className="text-[7.5px] text-slate-500">
                {d.frequency.length} {isAr ? 'عيّنة' : 'SAMPLES'}
              </Readout>
            }
          >
            {isAr ? 'منحنى حركة المرور' : 'TENDENCY CHART'}
          </SectionHead>
          {d.frequency.length >= 2 ? (
            <GlowSparkline
              points={d.frequency.map(f => ({ label: f.label, value: f.value, secondary: f.threats }))}
              isAr={isAr}
              height={86}
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
      </section>

      {/* ── Status strip ──────────────────────────────────────────────────── */}
      <footer className="relative z-10 flex shrink-0 items-center justify-between gap-3 px-4 py-1.5">
        <div className="flex items-center gap-3">
          <span className="flex items-center gap-1.5">
            <Radio className="h-3 w-3" style={{ color: CYAN }} aria-hidden />
            <HudLabel tone="cyan">{isAr ? 'المحرّك' : 'ENGINE'}</HudLabel>
            <Readout className="text-[8px] text-slate-400">{d.posture.engine?.replace(/_/g, ' ') ?? '—'}</Readout>
          </span>
          <span className="flex items-center gap-1.5">
            <Waves className="h-3 w-3" style={{ color: d.posture.zeroEgress ? CYAN : CRIMSON }} aria-hidden />
            <HudLabel tone={d.posture.zeroEgress ? 'cyan' : 'crimson'}>
              {d.posture.zeroEgress === true
                ? isAr ? 'صفر خروج' : 'ZERO EGRESS'
                : d.posture.zeroEgress === false
                  ? isAr ? 'خروج ممكن' : 'EGRESS POSSIBLE'
                  : '—'}
            </HudLabel>
          </span>
        </div>

        {d.missing.length > 0 && (
          <span className="text-[7.5px]" style={{ color: `${CRIMSON}cc`, fontFamily: 'var(--font-mono)' }}>
            {isAr ? 'مصادر صامتة: ' : 'SILENT: '}
            {d.missing.join(' · ')}
          </span>
        )}
      </footer>
    </div>
  );
};

export default TacticalCockpit;
