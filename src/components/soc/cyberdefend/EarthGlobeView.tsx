import React from 'react';
import { motion } from 'motion/react';
import { Radar, Satellite, Search, CircleDot } from 'lucide-react';
import { ThreatGlobeCanvas, type ThreatOrigin } from './ThreatGlobeCanvas';
import { GlowSparkline } from './GlowSparkline';
import { Glass, Label, Mono, Row, Value } from './parts';
import { cn, formatCount } from '../../../lib/utils';
import type { CyberDefendData } from './useCyberDefendData';

/**
 * EARTH GLOBE VIEW — the orbital command theatre
 *
 * The reference's first screen: a rotating globe with ballistic arcs, a radar card
 * on the left, an inspector card on the right, and a telemetry dock along the
 * bottom. That composition is reproduced exactly.
 *
 * What sits inside it is this platform's own data. The reference showed satellite
 * telemetry — `SAT-Error: ST 25854-54 | Rx 74/100 | Tx 96%`, `Starlink-17524`,
 * speed dials in km/h. None of that exists here, so the same card positions carry
 * the real equivalents: kernel telemetry with its provenance, a selectable eBPF
 * cluster node, request rate derived from counter deltas.
 *
 * The kernel card is the one to look at first. When counters are unreadable it says
 * so under the figures rather than showing a latency it never measured — which is
 * the state this host is in, and the honest version of the reference's confident
 * `SAT-Error` readout.
 */

interface Props {
  d: CyberDefendData;
  isAr: boolean;
  reduce: boolean;
  origins: ThreatOrigin[];
  selectedNode: number;
  setSelectedNode: (n: number) => void;
  nodeQuery: string;
  setNodeQuery: (s: string) => void;
}

export const EarthGlobeView: React.FC<Props> = ({
  d,
  isAr,
  reduce,
  origins,
  selectedNode,
  setSelectedNode,
  nodeQuery,
  setNodeQuery
}) => {
  /**
   * Layer visibility. Display-only: hiding a layer never drops a measurement, and
   * each row shows its real count so a viewer can see exactly what is hidden.
   */
  const [layerState, setLayerState] = React.useState<Record<string, boolean>>({
    origins: true,
    arcs: true,
    grid: true,
    station: true
  });
  const toggleLayer = (id: string) => setLayerState(prev => ({ ...prev, [id]: !prev[id] }));

  /** Manual rotation from the compass. Null keeps the globe auto-spinning. */
  const [spinOffset, setSpinOffset] = React.useState<number | null>(null);

  const node = d.nodes[selectedNode] ?? d.nodes[0] ?? null;

  const layers = [
    { id: 'origins', en: 'Threat origins', ar: 'مصادر التهديد', on: layerState.origins, count: d.geo.length },
    { id: 'arcs', en: 'Attack arcs', ar: 'أقواس الهجوم', on: layerState.arcs, count: d.geo.length },
    { id: 'grid', en: 'Orbital grid', ar: 'الشبكة المدارية', on: layerState.grid, count: null },
    { id: 'station', en: 'Receiving station', ar: 'محطة الاستقبال', on: layerState.station, count: 1 }
  ];
  const top = d.geo[0] ?? null;
  const filtered = d.nodes.filter(
    n => !nodeQuery || n.name.toLowerCase().includes(nodeQuery.toLowerCase()) || n.ip.includes(nodeQuery)
  );

  return (
    <div className="space-y-4">
      {/* Globe theatre with floating cards */}
      <div className="relative overflow-hidden rounded-2xl border border-white/10">
        <ThreatGlobeCanvas
          origins={layerState.origins ? origins : []}
          target={layerState.station ? { label: 'SOC', lat: 24.7, lon: 46.7 } : null}
          showArcs={layerState.arcs}
          showGrid={layerState.grid}
          rotationOverride={spinOffset}
          height={460}
          reducedMotion={reduce}
          className="block w-full"
        />

        {/* Left card — the radar position, carrying kernel telemetry */}
        <Glass className="absolute top-3 start-3 w-[268px] p-3">
          <div className="mb-2 flex items-center gap-1.5">
            <Radar className="h-3.5 w-3.5 text-[#38BDF8]" aria-hidden />
            <Label>{isAr ? 'قياسات النواة' : 'Kernel telemetry'}</Label>
          </div>

          {/* Radar sweep. The centre figure is the live blackhole count. */}
          <div className="relative mx-auto mb-2.5 h-[104px] w-[104px]">
            <div className="absolute inset-0 rounded-full border border-[#38BDF8]/25" />
            <div className="absolute inset-[18%] rounded-full border border-[#38BDF8]/15" />
            <div className="absolute inset-[38%] rounded-full border border-[#38BDF8]/10" />
            {!reduce && (
              <motion.div
                className="absolute inset-0 rounded-full"
                style={{ background: 'conic-gradient(from 0deg, rgba(56,189,248,0.30), rgba(56,189,248,0) 28%)' }}
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

          {/* Layer filters, in the reference's side-list position. These change what
              the globe draws, not what was measured — so a hidden layer is a display
              choice and never a missing reading. Each row prints its real count. */}
          <div className="mt-2 border-t border-white/5 pt-2">
            <Label>{isAr ? 'الطبقات' : 'Layers'}</Label>
            <div className="mt-1 space-y-0.5">
              {layers.map(l => (
                <button
                  key={l.id}
                  onClick={() => toggleLayer(l.id)}
                  aria-pressed={l.on}
                  className="flex w-full items-center gap-1.5 rounded px-1 py-0.5 text-start transition-colors hover:bg-white/[0.04] focus-visible:ring-1 focus-visible:ring-[#38BDF8]/60 focus-visible:outline-none"
                >
                  <span
                    className={cn(
                      'grid h-2.5 w-2.5 shrink-0 place-items-center rounded-[3px] border',
                      l.on ? 'border-[#38BDF8]/70 bg-[#38BDF8]/30' : 'border-white/20'
                    )}
                    aria-hidden
                  >
                    {l.on && <span className="h-1 w-1 rounded-[1px] bg-[#7dd3fc]" />}
                  </span>
                  <span className={cn('flex-1 text-[8px]', l.on ? 'text-slate-300' : 'text-slate-600')}>
                    {isAr ? l.ar : l.en}
                  </span>
                  <Mono className="text-[8px] text-slate-600">{l.count ?? '-'}</Mono>
                </button>
              ))}
            </div>
          </div>

          {d.kernel.countersReadable === false && (
            <p className="mt-2 border-t border-white/5 pt-1.5 text-[8px] leading-relaxed text-[#fcd34d]">
              {isAr
                ? 'عدّادات النواة غير مقروءة على هذا المضيف — الأرقام المتعلّقة بها مزروعة أو محجوبة.'
                : 'Kernel counters unreadable on this host — related figures are seeded or withheld.'}
            </p>
          )}
        </Glass>

        {/* Right card — the inspector position, carrying a real cluster node */}
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

            <div className="relative mx-auto my-2.5 h-[86px] w-[150px]">
              <div className="absolute top-1/2 left-1/2 h-8 w-11 -translate-x-1/2 -translate-y-1/2 rounded border border-[#38BDF8]/40 bg-[#38BDF8]/8" />
              {[-1, 1].map(s => (
                <div
                  key={s}
                  className="absolute top-1/2 h-6 w-[42px] -translate-y-1/2 border border-[#38BDF8]/25"
                  style={
                    {
                      background: 'repeating-linear-gradient(90deg, rgba(56,189,248,0.16) 0 3px, transparent 3px 7px)',
                      [s < 0 ? 'left' : 'right']: '4px'
                    } as React.CSSProperties
                  }
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
                  <Value
                    v={d.derived.threatDensity}
                    unit="/10k"
                    className="text-[#fcd34d]"
                    reason="needs requestsProtected and threatsBlocked"
                  />
                </p>
              </div>
            </div>
          </Glass>
        )}
      </div>

      {/* Bottom telemetry dock */}
      <div className="grid grid-cols-1 gap-3 lg:grid-cols-12">
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
          {/* Compass. Camera control, as in the reference — it carries no units and
              does not pretend to report a bearing, because it measures nothing. */}
          <div className="mt-2.5 border-t border-white/5 pt-2">
            <div className="flex items-center justify-between">
              <Label>{isAr ? 'زاوية العرض' : 'View angle'}</Label>
              {spinOffset != null && (
                <button
                  onClick={() => setSpinOffset(null)}
                  className="text-[8px] text-[#7dd3fc] transition-colors hover:text-white"
                >
                  {isAr ? 'استئناف الدوران' : 'resume spin'}
                </button>
              )}
            </div>
            <div className="mt-1.5 flex items-center gap-2">
              <div className="relative h-[44px] w-[44px] shrink-0">
                <svg viewBox="0 0 44 44" className="h-full w-full" aria-hidden>
                  <circle cx="22" cy="22" r="18" fill="none" stroke="rgba(255,255,255,0.1)" strokeWidth="1" />
                  {[0, 90, 180, 270].map(a => (
                    <line
                      key={a}
                      x1="22"
                      y1="6"
                      x2="22"
                      y2="10"
                      stroke="rgba(56,189,248,0.45)"
                      strokeWidth="1"
                      transform={`rotate(${a} 22 22)`}
                    />
                  ))}
                  <g transform={`rotate(${spinOffset ?? 0} 22 22)`}>
                    <path d="M 22 9 L 25 22 L 22 19 L 19 22 Z" fill="#7dd3fc" />
                  </g>
                </svg>
              </div>
              <input
                type="range"
                min={0}
                max={359}
                value={spinOffset ?? 0}
                onChange={e => setSpinOffset(Number(e.target.value))}
                aria-label={isAr ? 'زاوية دوران الكرة' : 'Globe rotation angle'}
                className="h-1 flex-1 cursor-pointer appearance-none rounded-full bg-white/10 accent-[#38BDF8]"
              />
            </div>
          </div>

          <dl className="mt-2.5 space-y-1 border-t border-white/5 pt-2">
            <Row k={isAr ? 'عقد مرصودة' : 'Nodes detected'} v={d.nodes.length} />
            <Row k={isAr ? 'محرّك الكشف' : 'Engine'} v={d.posture.engine?.replace(/_/g, ' ') ?? null} small />
          </dl>
        </Glass>

        {/* Nodes table — the towers table position */}
        <Glass className="lg:col-span-5">
          <div className="flex items-center justify-between gap-2 px-3 pt-3">
            <div className="flex items-center gap-2">
              <span className="rounded-full bg-white/10 px-2 py-0.5 text-[9px] font-semibold text-white">
                {isAr ? `العقد (${d.nodes.length})` : `NODES (${d.nodes.length})`}
              </span>
              <span className="text-[9px] text-slate-500">
                {isAr
                  ? `معزولة ${d.nodes.filter(n => n.isolated).length}`
                  : `${d.nodes.filter(n => n.isolated).length} isolated`}
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
                  ? isAr
                    ? 'لم تُرجِع الخدمة عقداً.'
                    : 'No nodes returned by the service.'
                  : isAr
                    ? 'لا نتائج للبحث.'
                    : 'No matches.'}
              </p>
            ) : (
              filtered.map(n => (
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
                  <Mono className="text-[9px] text-[#7dd3fc]">
                    {n.packetsDropped != null ? formatCount(n.packetsDropped) : '—'}
                  </Mono>
                </button>
              ))
            )}
          </div>
        </Glass>

        {/* Drift bars — the "chance of failure" sparkline position */}
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

          {/* The reference's smooth luminous trend, from the real request series. */}
          {d.frequency.length >= 2 && (
            <div className="mt-1.5 border-b border-white/5 pb-2">
              <GlowSparkline
                points={d.frequency.map(f => ({ label: f.label, value: f.value, secondary: f.threats }))}
                isAr={isAr}
                height={88}
                unit={isAr ? '' : '/s'}
                ariaLabel={
                  isAr
                    ? `معدّل الطلبات على ${d.frequency.length} عيّنة، والخطّ المتقطّع للحركة العدائية`
                    : `Request rate over ${d.frequency.length} samples, dashed line is hostile traffic`
                }
              />
            </div>
          )}

          {d.drift.verdict === 'INSUFFICIENT_DATA' ? (
            <p className="mt-2.5 text-[9px] leading-relaxed text-slate-500">{d.drift.insufficientReason}</p>
          ) : (
            <>
              <div className="mt-1.5 flex items-baseline gap-2">
                <Value v={d.drift.maxPsi} className="text-2xl font-bold text-white" />
                <span className="text-[9px] text-slate-500">
                  PSI · {isAr ? 'حدّ' : 'thr'} {d.drift.thresholds?.moderate ?? '—'}/
                  {d.drift.thresholds?.significant ?? '—'}
                </span>
              </div>
              <div className="mt-2 space-y-1">
                {d.drift.features
                  .slice()
                  .sort((a, b) => b.psi - a.psi)
                  .slice(0, 5)
                  .map(f => {
                    const sig = d.drift.thresholds?.significant ?? 0.25;
                    const mod = d.drift.thresholds?.moderate ?? 0.1;
                    return (
                      <div key={f.feature} className="flex items-center gap-1.5">
                        <span className="w-[86px] shrink-0 truncate text-[8px] text-slate-500">{f.feature}</span>
                        <div className="h-[3px] flex-1 overflow-hidden rounded-full bg-white/5">
                          <div
                            className="h-full rounded-full"
                            style={{
                              width: `${Math.min(100, (f.psi / Math.max(sig * 2, 0.5)) * 100)}%`,
                              background: f.psi >= sig ? '#EF4444' : f.psi >= mod ? '#F59E0B' : '#38BDF8'
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

/** Circular dial. Null value shows an em dash inside the ring rather than a zero arc. */
const Dial: React.FC<{
  label: string;
  value: number | null;
  accent: string;
  reason?: string;
  reduce: boolean;
}> = ({ label, value, accent, reason, reduce }) => (
  <div className="rounded-xl border border-white/8 bg-white/[0.02] p-2 text-center">
    <div className="relative mx-auto h-[54px] w-[54px]">
      <svg viewBox="0 0 54 54" className="h-full w-full -rotate-90">
        <circle cx="27" cy="27" r="22" fill="none" stroke="rgba(255,255,255,0.07)" strokeWidth="4" />
        {value != null && (
          <motion.circle
            cx="27"
            cy="27"
            r="22"
            fill="none"
            stroke={accent}
            strokeWidth="4"
            strokeLinecap="round"
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
