import React from 'react';
import { motion, useReducedMotion } from 'motion/react';
import {
  Database,
  GitBranch,
  ShieldAlert,
  Activity,
  TrendingUp,
  Timer,
  AlertTriangle,
  CheckCircle2,
  Layers,
  Gauge
} from 'lucide-react';
import { Card, CardHeader, CardTitle, Badge, Mono } from '../ui/primitives';
import type { BadgeTone } from '../ui/primitives';
import { StackedBars, Legend, SEV_COLOR, type StackBucket } from './charts/primitives';
import { cn, formatCount } from '../../lib/utils';

/**
 * CORPUS & LEARNING PANEL
 *
 * The adjudicated corpus, the temporal folds, drift on the live stream, and what
 * the promotion gate decided — on one surface, because they are one story: what
 * the platform has been told, how it is allowed to learn from it, and whether the
 * traffic has moved since.
 *
 * The design decision that shapes this panel
 *   The headline is not the corpus size. It is `operatorGrounded`, because that one
 *   boolean determines whether any figure derived from this data may be presented
 *   as a measurement of the detector. A panel that led with "80 labels" and left
 *   the provenance in a tooltip would let a viewer draw exactly the conclusion the
 *   data does not support.
 *
 *   So the provenance banner sits above the numbers, and when the corpus is not
 *   operator-grounded every derived figure below it is rendered muted with the word
 *   PIPELINE rather than in the colour of a result. The numbers are still shown —
 *   hiding them would be its own dishonesty — but they are visibly not load-bearing.
 *
 * On the fold strip
 *   The newest fold is drawn in a different colour and labelled TEST ONLY, because
 *   the guarantee that no rule was tuned against it is the platform's most
 *   load-bearing methodological claim and an operator should be able to see which
 *   slice it protects.
 */

const API = '/api/v1/soc';

interface CorpusStats {
  totalLabels: number;
  malicious: number;
  benign: number;
  agreementRate: number | null;
  machineFalsePositives: number;
  machineFalseNegatives: number;
  revisions: number;
  distinctAdjudicators: number;
  pendingCount: number;
  sufficient: boolean;
  shortfall?: string;
  minLabelsForStableFigure: number;
  operatorGrounded: boolean;
  bySource: Record<string, number>;
  byActorKind: Record<string, number>;
}

interface Fold {
  index: number;
  n: number;
  from: string;
  to: string;
  role: 'TUNING' | 'TEST';
}

interface DriftFeature {
  feature: string;
  psi: number;
  jsd: number;
  verdict: string;
}

interface DriftReport {
  verdict: 'STABLE' | 'MODERATE_SHIFT' | 'SIGNIFICANT_SHIFT' | 'INSUFFICIENT_DATA';
  maxPsi: number;
  drivingFeature: string | null;
  features: DriftFeature[];
  familyDistributionShift: { psi: number; newFamilies: string[]; vanishedFamilies: string[] };
  referenceSize: number;
  currentSize: number;
  thresholds: { moderate: number; significant: number; minSamples: number };
  insufficientReason?: string;
}

interface RetentionStats {
  capacity: number;
  held: number;
  byFamily: Record<string, number>;
  admitted: number;
  evicted: number;
  perFamilyFloor: number;
}

interface Props {
  lang?: 'ar' | 'en';
  apiKey?: string;
}

export const CorpusIntelPanel: React.FC<Props> = ({ lang = 'ar', apiKey }) => {
  const isAr = lang === 'ar';
  const reduce = useReducedMotion();

  const [stats, setStats] = React.useState<CorpusStats | null>(null);
  const [folds, setFolds] = React.useState<{
    sufficient: boolean;
    folds: Fold[];
    shortfall?: string;
  } | null>(null);
  const [drift, setDrift] = React.useState<DriftReport | null>(null);
  const [retention, setRetention] = React.useState<RetentionStats | null>(null);
  const [reasonBreakdown, setReasonBreakdown] = React.useState<Record<string, number>>({});
  const [error, setError] = React.useState<string | null>(null);

  const headers = React.useCallback((): Record<string, string> => {
    const h: Record<string, string> = { 'Content-Type': 'application/json' };
    if (apiKey) h['x-api-key'] = apiKey;
    return h;
  }, [apiKey]);

  React.useEffect(() => {
    let cancelled = false;
    const load = async () => {
      try {
        const [s, f, d, r] = await Promise.allSettled([
          fetch(`${API}/adjudication/stats`, { headers: headers() }).then(x => x.json()),
          fetch(`${API}/adjudication/folds`, { headers: headers() }).then(x => x.json()),
          fetch(`${API}/learning/drift`, { headers: headers() }).then(x => x.json()),
          fetch(`${API}/learning/retention`, { headers: headers() }).then(x => x.json())
        ]);
        if (cancelled) return;
        if (s.status === 'fulfilled' && s.value?.success) setStats(s.value);
        if (f.status === 'fulfilled') setFolds(f.value);
        if (d.status === 'fulfilled' && d.value?.success) setDrift(d.value.report);
        if (r.status === 'fulfilled' && r.value?.success) {
          setRetention(r.value.statistics);
          setReasonBreakdown(r.value.reasonBreakdown ?? {});
        }
        setError(null);
      } catch {
        if (!cancelled)
          setError(isAr ? 'تعذّر قراءة بيانات الكوربوس.' : 'Could not read corpus data.');
      }
    };
    load();
    const t = setInterval(load, 12000);
    return () => {
      cancelled = true;
      clearInterval(t);
    };
  }, [headers, isAr]);

  /** When the corpus is not operator-grounded, derived figures are not results. */
  const grounded = stats?.operatorGrounded ?? false;
  const muted = stats && stats.totalLabels > 0 && !grounded;

  const driftTone = (v?: string): BadgeTone =>
    v === 'SIGNIFICANT_SHIFT'
      ? 'quarantine'
      : v === 'MODERATE_SHIFT'
        ? 'tarpit'
        : v === 'STABLE'
          ? 'secure'
          : 'neutral';

  /** Retention by family, as a stacked bar. Reuses the accessible chart primitive. */
  const retentionBuckets: StackBucket[] = React.useMemo(() => {
    if (!retention) return [];
    const entries = Object.entries(retention.byFamily)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 8);
    return entries.map(([family, count]) => ({
      label: family.replace(/_/g, ' ').slice(0, 14),
      segments: [
        {
          key: family,
          value: count,
          // Benign retention reads as settled, hostile as needing attention.
          color: family === 'CLEAN_TRAFFIC' ? SEV_COLOR.LOW : SEV_COLOR.CRITICAL,
          label: family
        }
      ]
    }));
  }, [retention]);

  return (
    <Card dir={isAr ? 'rtl' : 'ltr'}>
      <CardHeader>
        <div className="flex items-center gap-2">
          <Database className="h-4 w-4 text-[#38BDF8]" aria-hidden />
          <CardTitle>
            {isAr ? 'الكوربوس والتعلّم المستمر' : 'CORPUS & CONTINUAL LEARNING'}
          </CardTitle>
        </div>
        {stats && (
          <Badge
            tone={grounded ? 'secure' : 'tarpit'}
            label={
              grounded
                ? isAr
                  ? 'مُحكَّم بشرياً'
                  : 'OPERATOR-GROUNDED'
                : isAr
                  ? 'غير مُحكَّم بشرياً'
                  : 'NOT OPERATOR-GROUNDED'
            }
          />
        )}
      </CardHeader>

      {error && (
        <div className="mx-4 mb-3 rounded border border-[#EF4444]/30 bg-[#EF4444]/5 px-3 py-2 text-[11px] text-[#fca5a5]">
          {error}
        </div>
      )}

      {/* Provenance banner. Above the numbers, deliberately. */}
      {muted && stats && (
        <div className="mx-4 mb-3 flex items-start gap-2 rounded border border-[#F59E0B]/30 bg-[#F59E0B]/5 px-3 py-2">
          <ShieldAlert className="mt-px h-4 w-4 shrink-0 text-[#F59E0B]" aria-hidden />
          <div className="text-[10px] leading-relaxed text-[#fcd34d]">
            <p className="font-medium">
              {isAr
                ? 'الأحكام لم تصدر عن محلّل بشري — فكل رقم مُشتقّ منها يقيس المسار لا المحرّك.'
                : 'These labels did not come from a human analyst, so every figure derived from them measures the pipeline, not the detector.'}
            </p>
            <p className="mt-0.5 text-slate-500">
              {isAr ? 'المصادر: ' : 'Origins: '}
              <Mono className="text-[9px]">{JSON.stringify(stats.bySource)}</Mono>
              {' · '}
              {isAr
                ? 'بوّابة الترقية سترفض، وهذا صواب.'
                : 'The promotion gate will refuse, correctly.'}
            </p>
          </div>
        </div>
      )}

      {/* Corpus metrics */}
      {stats && (
        <div className="grid grid-cols-2 gap-2 px-4 pb-3 sm:grid-cols-4">
          <Metric
            icon={Database}
            label={isAr ? 'أحكام' : 'Labels'}
            value={formatCount(stats.totalLabels)}
            sub={`${stats.malicious} ${isAr ? 'خطر' : 'mal'} / ${stats.benign} ${isAr ? 'سليم' : 'ben'}`}
            muted={muted}
          />
          <Metric
            icon={Timer}
            label={isAr ? 'في الانتظار' : 'Pending'}
            value={formatCount(stats.pendingCount)}
            sub={isAr ? 'تنتظر حُكماً' : 'awaiting a ruling'}
          />
          <Metric
            icon={AlertTriangle}
            label={isAr ? 'أخطاء المحرّك' : 'Machine errors'}
            value={`${stats.machineFalsePositives} FP / ${stats.machineFalseNegatives} FN`}
            sub={isAr ? 'وجدها الحُكم' : 'found by adjudication'}
            muted={muted}
          />
          <Metric
            icon={Gauge}
            label={isAr ? 'كفاية العيّنة' : 'Sample sufficiency'}
            value={
              stats.sufficient
                ? `${stats.totalLabels}/${stats.minLabelsForStableFigure}`
                : `${stats.totalLabels}/${stats.minLabelsForStableFigure}`
            }
            sub={
              stats.sufficient
                ? isAr
                  ? 'كافية'
                  : 'sufficient'
                : isAr
                  ? 'غير كافية'
                  : 'below threshold'
            }
            muted={!stats.sufficient}
          />
        </div>
      )}

      {/* Temporal folds */}
      <div className="border-t border-slate-800/80 px-4 py-3">
        <div className="mb-2 flex items-center gap-1.5">
          <Layers className="h-3.5 w-3.5 text-cyan-500/70" aria-hidden />
          <span className="text-[10px] tracking-wider text-cyan-400/70 uppercase">
            {isAr
              ? 'الطبقات الزمنية — التدريب يسبق الاختبار'
              : 'TEMPORAL FOLDS — TRAINING PRECEDES TEST'}
          </span>
        </div>
        {folds?.sufficient ? (
          <>
            <div className="flex gap-1.5" role="list">
              {folds.folds.map((f, i) => (
                <motion.div
                  key={f.index}
                  role="listitem"
                  initial={reduce ? { opacity: 0 } : { opacity: 0, scaleY: 0.85 }}
                  animate={{ opacity: 1, scaleY: 1 }}
                  transition={{ delay: reduce ? 0 : i * 0.05, duration: 0.2 }}
                  className={cn(
                    'flex-1 rounded border px-2 py-1.5 text-center',
                    f.role === 'TEST'
                      ? 'border-fuchsia-500/40 bg-fuchsia-500/8'
                      : 'border-slate-700/40 bg-black/25'
                  )}
                >
                  <Mono
                    className={cn(
                      'block text-[11px] font-bold',
                      f.role === 'TEST' ? 'text-fuchsia-300' : 'text-slate-300'
                    )}
                  >
                    {f.n}
                  </Mono>
                  <span
                    className={cn(
                      'text-[8px] tracking-wider',
                      f.role === 'TEST' ? 'text-fuchsia-400/80' : 'text-slate-600'
                    )}
                  >
                    {f.role === 'TEST'
                      ? isAr
                        ? 'اختبار فقط'
                        : 'TEST ONLY'
                      : `${isAr ? 'طبقة' : 'fold'} ${f.index}`}
                  </span>
                </motion.div>
              ))}
            </div>
            <p className="mt-1.5 text-[9px] leading-relaxed text-slate-600">
              {isAr
                ? 'الطبقة الأرجوانية محجوزة للاختبار: لا قاعدة كُتبت استناداً إليها، ولا معامل في واجهة التصدير يُعيدها للتدريب.'
                : 'The fuchsia fold is test-only: no rule was written against it, and no parameter in the tuning export can return it.'}
            </p>
          </>
        ) : (
          <p className="text-[10px] text-slate-500">
            {folds?.shortfall ?? (isAr ? 'جارٍ التحميل…' : 'Loading…')}
          </p>
        )}
      </div>

      {/* Drift */}
      <div className="border-t border-slate-800/80 px-4 py-3">
        <div className="mb-2 flex items-center justify-between gap-2">
          <div className="flex items-center gap-1.5">
            <TrendingUp className="h-3.5 w-3.5 text-cyan-500/70" aria-hidden />
            <span className="text-[10px] tracking-wider text-cyan-400/70 uppercase">
              {isAr ? 'انحراف التوزيع الوارد' : 'INCOMING DISTRIBUTION DRIFT'}
            </span>
          </div>
          {drift && (
            <Badge
              tone={driftTone(drift.verdict)}
              label={
                drift.verdict === 'INSUFFICIENT_DATA'
                  ? isAr
                    ? 'بيانات غير كافية'
                    : 'INSUFFICIENT DATA'
                  : drift.verdict
              }
            />
          )}
        </div>

        {drift?.verdict === 'INSUFFICIENT_DATA' ? (
          <p className="text-[10px] leading-relaxed text-slate-500">{drift.insufficientReason}</p>
        ) : drift ? (
          <>
            <div className="mb-2 flex items-baseline gap-3">
              <div>
                <span className="text-[9px] text-slate-500">PSI </span>
                <Mono className="text-sm font-bold text-slate-200">{drift.maxPsi}</Mono>
              </div>
              <span className="text-[9px] text-slate-600">
                {isAr ? 'حدّ التنبيه' : 'thresholds'} {drift.thresholds.moderate} /{' '}
                {drift.thresholds.significant}
              </span>
              {drift.drivingFeature && (
                <span className="text-[9px] text-slate-500">
                  {isAr ? 'المحرّك: ' : 'driven by '}
                  <Mono className="text-[#7dd3fc]">{drift.drivingFeature}</Mono>
                </span>
              )}
            </div>
            <div className="space-y-1">
              {drift.features
                .slice()
                .sort((a, b) => b.psi - a.psi)
                .slice(0, 4)
                .map(f => (
                  <div key={f.feature} className="flex items-center gap-2">
                    <span className="w-28 shrink-0 truncate text-[9px] text-slate-500">
                      {f.feature}
                    </span>
                    <div className="h-1 flex-1 overflow-hidden rounded bg-slate-800">
                      <div
                        className="h-full rounded"
                        style={{
                          width: `${Math.min(100, (f.psi / Math.max(drift.thresholds.significant * 2, 0.5)) * 100)}%`,
                          background:
                            f.psi >= drift.thresholds.significant
                              ? '#EF4444'
                              : f.psi >= drift.thresholds.moderate
                                ? '#F59E0B'
                                : '#10B981'
                        }}
                      />
                    </div>
                    <Mono className="w-14 shrink-0 text-right text-[9px] text-slate-500">
                      {f.psi}
                    </Mono>
                  </div>
                ))}
            </div>
            {drift.familyDistributionShift.newFamilies.length > 0 && (
              <p className="mt-2 text-[9px] text-[#fcd34d]">
                {isAr ? 'أصناف جديدة ظهرت: ' : 'New families appeared: '}
                <Mono>{drift.familyDistributionShift.newFamilies.join(', ')}</Mono>
                {' — '}
                {isAr
                  ? 'وهي أقوى إشارة يحتاجها كاشف تواقيع: شكل صنف لم تُكتب له قاعدة.'
                  : 'the strongest signal a signature detector gets — the shape of a class nobody wrote a rule for.'}
              </p>
            )}
          </>
        ) : (
          <p className="text-[10px] text-slate-500">{isAr ? 'جارٍ التحميل…' : 'Loading…'}</p>
        )}
      </div>

      {/* Retention */}
      {retention && (
        <div className="border-t border-slate-800/80 px-4 py-3">
          <div className="mb-2 flex items-center justify-between gap-2">
            <div className="flex items-center gap-1.5">
              <GitBranch className="h-3.5 w-3.5 text-cyan-500/70" aria-hidden />
              <span className="text-[10px] tracking-wider text-cyan-400/70 uppercase">
                {isAr ? 'الاحتفاظ الاستراتيجي' : 'STRATEGIC RETENTION'}
              </span>
            </div>
            <span className="text-[9px] text-slate-500">
              <Mono>{retention.held}</Mono>/{retention.capacity}
              {' · '}
              {isAr ? 'أُسقط' : 'evicted'} <Mono>{retention.evicted}</Mono>
            </span>
          </div>

          {retentionBuckets.length > 0 && (
            <StackedBars
              buckets={retentionBuckets}
              height={70}
              isAr={isAr}
              ariaLabel={
                isAr
                  ? `توزّع العيّنات المحتفظ بها على ${retentionBuckets.length} صنفاً`
                  : `Retained samples across ${retentionBuckets.length} families`
              }
            />
          )}

          <div className="mt-2 flex flex-wrap gap-1">
            {Object.entries(reasonBreakdown)
              .sort((a, b) => b[1] - a[1])
              .map(([reason, n]) => (
                <span
                  key={reason}
                  className="rounded border border-slate-700/40 bg-black/25 px-1.5 py-0.5 text-[9px] text-slate-400"
                >
                  {reason.replace(/_/g, ' ').toLowerCase()}{' '}
                  <Mono className="text-slate-300">{n}</Mono>
                </span>
              ))}
          </div>
          <p className="mt-1.5 text-[9px] leading-relaxed text-slate-600">
            {isAr
              ? `لكل صنف أرضية ${retention.perFamilyFloor} عيّنات لا تُسقَط: بلا ذلك يمحو تيّار يغلب عليه صنف واحد كل أمثلة الأصناف النادرة، فينسى التدريب وجودها.`
              : `Each family keeps a floor of ${retention.perFamilyFloor} samples. Without it, a stream dominated by one family erases every example of the rare ones and a retrain has no idea they exist.`}
          </p>
        </div>
      )}
    </Card>
  );
};

const Metric: React.FC<{
  icon: React.ElementType;
  label: string;
  value: string;
  sub?: string;
  muted?: boolean;
}> = ({ icon: Icon, label, value, sub, muted }) => (
  <div
    className={cn(
      'rounded border px-2.5 py-2',
      muted ? 'border-slate-800/50 bg-black/15' : 'border-slate-700/40 bg-black/25'
    )}
  >
    <div className="mb-1 flex items-center gap-1.5">
      <Icon className="h-3 w-3 shrink-0 text-slate-500" aria-hidden />
      <span className="text-[9px] tracking-wider text-slate-500 uppercase">{label}</span>
    </div>
    <p
      className={cn('text-sm leading-none font-bold', muted ? 'text-slate-500' : 'text-cyan-200')}
      style={{ fontFamily: 'var(--font-mono)' }}
    >
      {value}
    </p>
    {sub && <p className="mt-0.5 text-[8px] leading-tight text-slate-600">{sub}</p>}
    {muted && (
      <span className="mt-1 inline-block text-[8px] tracking-wider text-[#fcd34d]/70">
        PIPELINE
      </span>
    )}
  </div>
);
