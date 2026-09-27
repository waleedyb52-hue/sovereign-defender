import React from 'react';
import { motion, useMotionValue, useSpring, useTransform, useReducedMotion } from 'motion/react';
import { Cpu, FileLock2, Magnet, BrainCircuit, ShieldOff, AlertTriangle } from 'lucide-react';
import { Card, Badge, Mono } from '../ui/primitives';
import type { BadgeTone } from '../ui/primitives';
import { cn, formatCount } from '../../lib/utils';
import type { TelemetryState } from '../../hooks/useTelemetry';

/**
 * TELEMETRY HUD — four micro-metric cards
 *
 * Every figure here is fetched, never seeded. Where a source is absent the card
 * shows an em dash and names the reason; it does not render a zero, because a
 * zero is a claim about the network and an em dash is an admission about the
 * dashboard.
 *
 * On the sparklines
 *   These plot deltas between successive polls, so each point is an observed
 *   rate rather than a re-drawing of a cumulative total. The honest consequence
 *   is that there is no history at mount: until two samples exist the card says
 *   COLLECTING instead of drawing a line. Seeding the series to make the first
 *   paint look complete would invent a past the operator never observed, which
 *   is the exact failure mode rule 0 exists to stop.
 *
 * On the fourth card
 *   The specification asked for "local vLLM RAM usage". There is no vLLM in this
 *   deployment — detection runs on a deterministic payload classifier, which is
 *   the *only* path when no external model is configured. So the card reports
 *   what is real: the active signature count, the process heap, and whether
 *   egress is actually possible. The ZERO EGRESS badge is rendered from
 *   `zeroExternalApiCalls`, so it appears only when the running configuration
 *   earns it. A sovereignty badge printed unconditionally would be the most
 *   damaging false statement this console could make.
 */

interface Props {
  telemetry: TelemetryState;
  lang?: 'ar' | 'en';
}

/* ── Count-up numeral ────────────────────────────────────────────────────── */

const CountUp: React.FC<{ value: number | null; format?: (n: number) => string }> = ({
  value,
  format = formatCount
}) => {
  const reduce = useReducedMotion();
  const mv = useMotionValue(value ?? 0);
  const spring = useSpring(mv, { stiffness: 90, damping: 20, mass: 0.6 });
  const text = useTransform(spring, latest => format(Math.round(latest)));
  const seeded = React.useRef(false);

  React.useEffect(() => {
    if (value == null) return;
    // First real value is set without animating. Springing up from zero on mount
    // would render a climb that never happened.
    if (!seeded.current) {
      mv.jump(value);
      seeded.current = true;
      return;
    }
    mv.set(value);
  }, [value, mv]);

  if (value == null) return <span className="text-slate-600">—</span>;
  if (reduce) return <>{format(value)}</>;
  return <motion.span>{text}</motion.span>;
};

/* ── Sparkline ───────────────────────────────────────────────────────────── */

const Spark: React.FC<{ points: number[]; color: string; height?: number }> = ({
  points,
  color,
  height = 26
}) => {
  if (points.length < 2) return null;
  const w = 88;
  const max = Math.max(...points, 1);
  const step = w / (points.length - 1);
  const d = points
    .map(
      (p, i) =>
        `${i === 0 ? 'M' : 'L'}${(i * step).toFixed(1)},${(height - (p / max) * height).toFixed(1)}`
    )
    .join(' ');
  const area = `${d} L${w},${height} L0,${height} Z`;
  const id = React.useId();

  return (
    <svg
      width={w}
      height={height}
      viewBox={`0 0 ${w} ${height}`}
      className="overflow-visible"
      aria-hidden
    >
      <defs>
        <linearGradient id={id} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor={color} stopOpacity="0.28" />
          <stop offset="100%" stopColor={color} stopOpacity="0" />
        </linearGradient>
      </defs>
      <path d={area} fill={`url(#${id})`} />
      <path
        d={d}
        fill="none"
        stroke={color}
        strokeWidth="1.4"
        strokeLinejoin="round"
        strokeLinecap="round"
      />
    </svg>
  );
};

/* ── Card ────────────────────────────────────────────────────────────────── */

interface MetricCardProps {
  icon: React.ElementType;
  label: string;
  value: number | null;
  unit?: string;
  accent: string;
  series?: number[];
  collecting?: boolean;
  footer?: React.ReactNode;
  index: number;
  unavailableNote?: string;
  lang: 'ar' | 'en';
  /** Origin label rendered beside the figure. Absent when the service does not say. */
  provenanceTag?: { tone: BadgeTone; label: string };
}

const MetricCard: React.FC<MetricCardProps> = ({
  icon: Icon,
  label,
  value,
  unit,
  accent,
  series = [],
  collecting,
  footer,
  index,
  unavailableNote,
  lang,
  provenanceTag
}) => {
  const reduce = useReducedMotion();
  const isAr = lang === 'ar';

  return (
    <motion.div
      initial={reduce ? { opacity: 0 } : { opacity: 0, y: 4 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.22, delay: reduce ? 0 : index * 0.05, ease: 'easeOut' }}
    >
      <Card className="relative overflow-hidden p-3.5">
        {/* Accent hairline. Decorative only — never the sole carrier of meaning. */}
        <div
          className="absolute inset-x-0 top-0 h-px"
          style={{ background: accent, opacity: 0.5 }}
        />

        <div className="mb-2 flex items-start justify-between gap-2">
          <div className="flex items-center gap-1.5">
            <Icon className="h-3.5 w-3.5 shrink-0" style={{ color: accent }} aria-hidden />
            <span
              className="text-[10px] font-medium tracking-wider text-slate-400 uppercase"
              style={{ fontFamily: 'var(--font-sans)' }}
            >
              {label}
            </span>
          </div>
          <div className="flex shrink-0 items-center gap-1">
            {provenanceTag && <Badge tone={provenanceTag.tone} label={provenanceTag.label} />}
            {collecting && series.length < 2 && (
              <span className="text-[9px] tracking-wider text-slate-600">
                {isAr ? 'يجمع' : 'COLLECTING'}
              </span>
            )}
          </div>
        </div>

        <div className="flex items-end justify-between gap-2">
          <div className="min-w-0">
            <div
              className="text-2xl leading-none font-semibold text-slate-100 tabular-nums"
              style={{ fontFamily: 'var(--font-mono)' }}
            >
              <CountUp value={value} />
              {unit && value != null && (
                <span className="ml-1 text-[11px] font-normal text-slate-500">{unit}</span>
              )}
            </div>
            {value == null && unavailableNote && (
              <p className="mt-1 text-[9px] leading-tight text-slate-600">{unavailableNote}</p>
            )}
          </div>
          <div className="shrink-0">
            <Spark points={series} color={accent} />
          </div>
        </div>

        {footer && <div className="mt-2.5 border-t border-slate-800/60 pt-2">{footer}</div>}
      </Card>
    </motion.div>
  );
};

/* ── HUD ─────────────────────────────────────────────────────────────────── */

export const TelemetryHud: React.FC<Props> = ({ telemetry: t, lang = 'ar' }) => {
  const isAr = lang === 'ar';
  const noSource = isAr ? 'لا يوجد مصدر بيانات متصل' : 'no connected data source';

  /**
   * Provenance of the packet counter, taken from the service rather than assumed.
   * MIXED is called out separately because a blended figure is the easiest kind
   * to misread — part of it is real and part of it is not.
   */
  const packetsField = t.ebpf.provenance?.fields?.totalPacketsDropped;
  const packetsTag =
    packetsField === 'SEEDED'
      ? { tone: 'tarpit' as const, label: isAr ? 'مزروع' : 'SEEDED' }
      : packetsField === 'MIXED_SEEDED_AND_MEASURED'
        ? { tone: 'tarpit' as const, label: isAr ? 'مزروع + مرصود' : 'SEEDED + MEASURED' }
        : packetsField === 'MEASURED'
          ? { tone: 'secure' as const, label: isAr ? 'مقيس' : 'MEASURED' }
          : undefined;

  const kernelSimulated = t.ebpf.provenance && !t.ebpf.provenance.kernelNative;

  return (
    <div dir={isAr ? 'rtl' : 'ltr'}>
      {t.error && (
        <div className="mb-3 flex items-start gap-2 rounded border border-[#f43f5e]/30 bg-[#f43f5e]/5 px-3 py-2">
          <ShieldOff className="mt-px h-4 w-4 shrink-0 text-[#f43f5e]" aria-hidden />
          <div className="text-[11px] text-[#fda4af]">
            <p className="font-medium">{isAr ? 'تعذّر قراءة القياسات' : 'Telemetry unavailable'}</p>
            <Mono className="text-[10px] text-slate-500">{t.error}</Mono>
          </div>
        </div>
      )}
      {t.stale && !t.error && (
        <div className="mb-3 flex items-center gap-2 rounded border border-[#F59E0B]/30 bg-[#F59E0B]/5 px-3 py-1.5 text-[10px] text-[#fcd34d]">
          <AlertTriangle className="h-3.5 w-3.5 shrink-0" aria-hidden />
          {isAr
            ? 'بعض المصادر لم تُجب في آخر استعلام — المعروض قد يكون قديماً.'
            : 'Some sources did not answer the last poll — values shown may be stale.'}
        </div>
      )}

      {kernelSimulated && (
        <div className="mb-3 flex items-start gap-2 rounded border border-[#F59E0B]/30 bg-[#F59E0B]/5 px-3 py-2">
          <Cpu className="mt-px h-4 w-4 shrink-0 text-[#F59E0B]" aria-hidden />
          <div className="text-[10px] leading-relaxed text-[#fcd34d]">
            <p className="font-medium">
              {isAr
                ? 'طبقة eBPF تعمل بالمحاكاة على هذا المضيف'
                : 'eBPF layer is simulated on this host'}
            </p>
            <p className="text-slate-500">{t.ebpf.provenance?.reason}</p>
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <MetricCard
          index={0}
          lang={lang}
          icon={Cpu}
          label={isAr ? 'حزم مُسقَطة (eBPF)' : 'Packets dropped (eBPF)'}
          value={t.ebpf.packetsDropped}
          accent="#22d3ee"
          series={t.series.packetsDropped ?? []}
          collecting={t.collecting}
          unavailableNote={noSource}
          /* The badge is the whole point of this card. Without it the figure
             reads as a kernel measurement, and on a host with no kernel path
             every one of those packets is a literal shipped for review. */
          provenanceTag={packetsTag}
          footer={
            <div className="space-y-1">
              <div className="flex items-center justify-between text-[10px]">
                <span className="text-slate-500">{isAr ? 'زمن النواة' : 'kernel latency'}</span>
                {t.ebpf.kernelLatencyUs != null ? (
                  <Mono className="text-[#67e8f9]">{t.ebpf.kernelLatencyUs.toFixed(2)} µs</Mono>
                ) : (
                  <span
                    className="text-[9px] text-slate-600"
                    title={t.ebpf.provenance?.reason ?? undefined}
                  >
                    {isAr ? 'غير متوفّر — لا مسار نواة' : 'unavailable — no kernel path'}
                  </span>
                )}
              </div>
              {t.ebpf.seededPacketsDropped != null && t.ebpf.seededPacketsDropped > 0 && (
                <div className="flex items-center justify-between text-[9px]">
                  <span className="text-slate-600">
                    {isAr ? 'منها مزروع للعرض' : 'of which seeded'}
                  </span>
                  <Mono className="text-slate-500">{formatCount(t.ebpf.seededPacketsDropped)}</Mono>
                </div>
              )}
            </div>
          }
        />

        <MetricCard
          index={1}
          lang={lang}
          icon={FileLock2}
          label={isAr ? 'ملفات محمية (FIM)' : 'Files protected (FIM)'}
          value={t.fim.monitoredFiles}
          accent="#10B981"
          series={t.series.fimAlerts ?? []}
          collecting={t.collecting}
          unavailableNote={noSource}
          footer={
            <div className="flex items-center justify-between text-[10px]">
              <span className="text-slate-500">{isAr ? 'تنبيهات حرجة' : 'critical alerts'}</span>
              {t.fim.criticalAlerts != null ? (
                <Badge
                  tone={t.fim.criticalAlerts > 0 ? 'quarantine' : 'secure'}
                  label={String(t.fim.criticalAlerts)}
                  mono
                />
              ) : (
                <span className="text-slate-600">—</span>
              )}
            </div>
          }
        />

        <MetricCard
          index={2}
          lang={lang}
          icon={Magnet}
          label={isAr ? 'اتصالات المصيدة' : 'Tarpit connections'}
          value={t.tarpit.trapped}
          accent="#F59E0B"
          series={t.series.tarpit ?? []}
          collecting={t.collecting}
          unavailableNote={noSource}
          footer={
            <div className="flex items-center justify-between text-[10px]">
              <span className="text-slate-500">{isAr ? 'عناوين معزولة' : 'quarantined IPs'}</span>
              {t.tarpit.quarantinedIps != null ? (
                <Mono className="text-[#fcd34d]">{t.tarpit.quarantinedIps}</Mono>
              ) : (
                <span className="text-slate-600">—</span>
              )}
            </div>
          }
        />

        {/* Local inference posture. Reports the engine that exists, not one that
            would look more impressive. */}
        <MetricCard
          index={3}
          lang={lang}
          icon={BrainCircuit}
          label={isAr ? 'المحرّك المحلّي' : 'Local inference'}
          value={t.inference.signatures}
          unit={isAr ? 'بصمة' : 'sigs'}
          accent="#a78bfa"
          collecting={false}
          unavailableNote={noSource}
          footer={
            <div className="space-y-1.5">
              <div className="flex items-center justify-between text-[10px]">
                <span className="text-slate-500">{isAr ? 'ذاكرة العملية' : 'process heap'}</span>
                {t.inference.heapMb != null ? (
                  <Mono className="text-slate-300">
                    {t.inference.heapMb.toFixed(0)} / {t.inference.rssMb?.toFixed(0) ?? '—'} MB
                  </Mono>
                ) : (
                  <span className="text-slate-600">—</span>
                )}
              </div>
              <div className="flex flex-wrap items-center gap-1">
                {t.inference.zeroExternalApiCalls === true && (
                  <Badge
                    tone="secure"
                    label={isAr ? 'صفر نداءات خارجية' : 'ZERO EXTERNAL API CALLS'}
                  />
                )}
                {t.inference.zeroExternalApiCalls === false && (
                  <Badge
                    tone="tarpit"
                    label={
                      isAr
                        ? `خروج ممكن: ${t.inference.externalProvider ?? 'مزوّد خارجي'}`
                        : `EGRESS POSSIBLE: ${t.inference.externalProvider ?? 'external'}`
                    }
                  />
                )}
                {t.inference.isSoleDetectionPath && (
                  <Badge tone="ebpf" label={isAr ? 'مسار الكشف الوحيد' : 'SOLE DETECTION PATH'} />
                )}
              </div>
            </div>
          }
        />
      </div>

      {t.collecting && !t.error && (
        <p className="mt-2 text-[10px] text-slate-600">
          {isAr
            ? 'الرسوم البيانية تُبنى من فروق القياسات المتتالية، فتظهر بعد أول عيّنتين. لا تُعرض سلسلة لم تُرصد.'
            : 'Series are built from deltas between successive polls, so they appear after the first two samples. No series is drawn that was not observed.'}
        </p>
      )}
    </div>
  );
};
