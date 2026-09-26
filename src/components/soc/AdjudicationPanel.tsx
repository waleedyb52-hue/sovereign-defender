import React, { useCallback, useEffect, useState } from 'react';
import { Gavel, ShieldAlert, ShieldCheck, Clock, UserCheck, AlertTriangle, Database, Layers } from 'lucide-react';

/**
 * OPERATOR ADJUDICATION PANEL
 *
 * The surface where an analyst turns a machine verdict into ground truth. Two
 * design decisions carry the weight here, and both are about not flattering the
 * platform.
 *
 * The machine's call is shown, not hidden.
 *   An analyst who cannot see what the classifier decided cannot meaningfully
 *   overturn it. So the verdict, the score and the signatures that fired are all
 *   on the card. The risk is anchoring — the analyst just agrees with whatever is
 *   displayed — which is why OVERTURN is styled as a first-class action rather
 *   than a small link, and why the panel counts overturns prominently. A corpus
 *   with no overturns in it is a warning sign, not a success.
 *
 * The corpus header reports its own inadequacy.
 *   While the label count is below the threshold, the panel says so in place of
 *   an agreement percentage. It does not show a progress-bar-shaped number that
 *   reads as a score. Phase 1's first principle, on the screen.
 */

interface QueueItem {
  id: string;
  payloadSample: string;
  machineVerdict: 'BLOCK' | 'ALLOW' | 'UNKNOWN';
  machineScore: number;
  machineFamily: string;
  machineSignatures: string[];
  srcIp: string;
  detectedAt: string;
  seenCount: number;
}

interface Stats {
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
  durable: boolean;
}

interface Fold {
  index: number; n: number; from: string; to: string; role: 'TUNING' | 'TEST';
}

interface Props { lang?: 'ar' | 'en'; apiKey?: string; }

const API = '/api/v1/soc/adjudication';

export const AdjudicationPanel: React.FC<Props> = ({ lang = 'ar', apiKey }) => {
  const isAr = lang === 'ar';
  const [queue, setQueue] = useState<QueueItem[]>([]);
  const [stats, setStats] = useState<Stats | null>(null);
  const [folds, setFolds] = useState<{ sufficient: boolean; folds: Fold[]; shortfall?: string } | null>(null);
  const [analyst, setAnalyst] = useState('');
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const headers = useCallback((): Record<string, string> => {
    const h: Record<string, string> = { 'Content-Type': 'application/json' };
    if (apiKey) h['x-api-key'] = apiKey;
    return h;
  }, [apiKey]);

  const refresh = useCallback(async () => {
    try {
      const [q, s, f] = await Promise.all([
        fetch(`${API}/queue?limit=25`, { headers: headers() }).then(r => r.json()),
        fetch(`${API}/stats`, { headers: headers() }).then(r => r.json()),
        fetch(`${API}/folds`, { headers: headers() }).then(r => r.json())
      ]);
      if (q?.success) setQueue(q.items ?? []);
      if (s?.success) setStats(s);
      if (f?.success !== undefined) setFolds(f);
      setError(null);
    } catch {
      setError(isAr ? 'تعذّر الوصول إلى مخزن الأحكام.' : 'Could not reach the adjudication store.');
    }
  }, [headers, isAr]);

  useEffect(() => {
    refresh();
    const t = setInterval(refresh, 15000);
    return () => clearInterval(t);
  }, [refresh]);

  const rule = async (id: string, label: 'MALICIOUS' | 'BENIGN') => {
    if (!analyst.trim()) {
      setError(isAr
        ? 'اسم المُحكِّم مطلوب — الحُكم بلا هوية مجرد ادّعاء لا قياس.'
        : 'Adjudicator identity is required — a label without provenance is an assertion, not a measurement.');
      return;
    }
    setBusy(id);
    try {
      const res = await fetch(`${API}/adjudicate`, {
        method: 'POST',
        headers: headers(),
        body: JSON.stringify({ detectionId: id, analystLabel: label, adjudicatedBy: analyst.trim() })
      });
      const d = await res.json();
      if (!d.success) setError(d.error ?? 'ADJUDICATION_FAILED');
      else { setError(null); setQueue(prev => prev.filter(x => x.id !== id)); }
      refresh();
    } catch {
      setError(isAr ? 'فشل تسجيل الحُكم.' : 'Failed to record the ruling.');
    } finally {
      setBusy(null);
    }
  };

  const machineChip = (v: string) =>
    v === 'BLOCK'
      ? 'bg-red-500/10 text-red-300 border-red-500/30'
      : 'bg-emerald-500/10 text-emerald-300 border-emerald-500/30';

  return (
    <div className="bg-[#0a0f16] border border-cyan-500/20 rounded-lg p-5 font-mono" dir={isAr ? 'rtl' : 'ltr'}>
      <div className="flex items-center justify-between mb-4 flex-wrap gap-2">
        <div className="flex items-center gap-2">
          <Gavel className="w-5 h-5 text-cyan-400" />
          <h3 className="text-cyan-300 text-sm font-bold tracking-wide">
            {isAr ? 'حُكم المحلّل — إنتاج بيانات مُسمّاة' : 'OPERATOR ADJUDICATION — GROUND TRUTH'}
          </h3>
        </div>
        {stats && !stats.durable && (
          <span className="text-[10px] text-amber-300 border border-amber-500/30 bg-amber-500/10 px-2 py-0.5 rounded">
            {isAr ? 'مخزن مؤقت في الذاكرة — غير محفوظ' : 'IN-MEMORY STORE — NOT PERSISTED'}
          </span>
        )}
      </div>

      {/* Corpus header. States its own inadequacy rather than showing a score-shaped number. */}
      {stats && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-4">
          <Metric icon={Database} label={isAr ? 'أحكام مسجّلة' : 'Labels'} value={String(stats.totalLabels)}
            sub={`${stats.malicious} ${isAr ? 'خطر' : 'mal'} / ${stats.benign} ${isAr ? 'سليم' : 'ben'}`} />
          <Metric icon={Clock} label={isAr ? 'في الانتظار' : 'Pending'} value={String(stats.pendingCount)} />
          <Metric icon={UserCheck} label={isAr ? 'أخطاء كشفها المحلّل' : 'Machine errors found'}
            value={`${stats.machineFalsePositives} FP / ${stats.machineFalseNegatives} FN`} />
          <Metric icon={ShieldCheck} label={isAr ? 'اتفاق مع المحرّك' : 'Agreement'}
            value={stats.agreementRate === null ? (isAr ? 'محجوب' : 'withheld') : `${(stats.agreementRate * 100).toFixed(1)}%`}
            sub={stats.agreementRate === null ? (isAr ? 'العيّنة أصغر من أن تعني شيئاً' : 'sample too small to mean anything') : undefined}
            muted={stats.agreementRate === null} />
        </div>
      )}

      {stats && !stats.sufficient && (
        <div className="mb-4 text-[11px] text-amber-200/90 bg-amber-500/5 border border-amber-500/25 rounded px-3 py-2 flex gap-2">
          <AlertTriangle className="w-4 h-4 shrink-0 text-amber-400" />
          <span>
            {isAr
              ? `لا يُعلَن رقم بعد: ${stats.totalLabels} من ${stats.minLabelsForStableFigure} حُكماً. المنصّة تذكر النقص بدلاً من تقدير رقم.`
              : stats.shortfall}
          </span>
        </div>
      )}

      {stats && stats.totalLabels > 0 && !stats.operatorGrounded && (
        <div className="mb-4 text-[11px] text-red-200/90 bg-red-500/5 border border-red-500/30 rounded px-3 py-2 flex gap-2">
          <ShieldAlert className="w-4 h-4 shrink-0 text-red-400" />
          <span>
            {isAr
              ? `ليست بيانات مُحكَّمة بشرياً بالكامل (${JSON.stringify(stats.bySource)}). أي رقم مبني عليها يختبر المسار لا المحرّك.`
              : `Not fully human-adjudicated (${JSON.stringify(stats.bySource)}). Any figure from this tests the pipeline, not the detector.`}
          </span>
        </div>
      )}

      {/* Temporal folds — TESSERACT ordering, recomputed from timestamps. */}
      {folds && (
        <div className="mb-4">
          <div className="flex items-center gap-2 mb-2">
            <Layers className="w-3.5 h-3.5 text-cyan-500/70" />
            <span className="text-[10px] text-cyan-400/70 tracking-wider">
              {isAr ? 'الطبقات الزمنية — التدريب يسبق الاختبار دائماً' : 'TEMPORAL FOLDS — TRAINING ALWAYS PRECEDES TEST'}
            </span>
          </div>
          {folds.sufficient ? (
            <div className="flex gap-2 flex-wrap">
              {folds.folds.map(f => (
                <div key={f.index}
                  className={`text-[10px] px-2 py-1 rounded border ${f.role === 'TEST'
                    ? 'bg-fuchsia-500/10 text-fuchsia-300 border-fuchsia-500/30'
                    : 'bg-slate-500/10 text-slate-300 border-slate-500/25'}`}>
                  {isAr ? 'طبقة' : 'fold'} {f.index} · n={f.n} · {f.role === 'TEST' ? (isAr ? 'اختبار فقط' : 'TEST ONLY') : (isAr ? 'تدريب' : 'TUNING')}
                </div>
              ))}
            </div>
          ) : (
            <p className="text-[10px] text-slate-500">{folds.shortfall}</p>
          )}
        </div>
      )}

      {/* Provenance input. The panel refuses to submit without it. */}
      <div className="mb-4">
        <label className="block text-[10px] text-cyan-400/70 mb-1 tracking-wider">
          {isAr ? 'هوية المُحكِّم (تُسجَّل مع كل حُكم)' : 'ADJUDICATOR IDENTITY (recorded with every label)'}
        </label>
        <input
          value={analyst}
          onChange={e => setAnalyst(e.target.value)}
          placeholder={isAr ? 'مثال: waleed@soc' : 'e.g. analyst@soc'}
          className="w-full bg-black/40 border border-cyan-500/20 rounded px-3 py-1.5 text-xs text-cyan-100
                     placeholder:text-slate-600 focus:outline-none focus:border-cyan-400/50"
        />
      </div>

      {error && (
        <div className="mb-3 text-[11px] text-red-300 bg-red-500/5 border border-red-500/25 rounded px-3 py-2">
          {error}
        </div>
      )}

      {/* The queue. */}
      <div className="space-y-2 max-h-[420px] overflow-y-auto pr-1">
        {queue.length === 0 && (
          <p className="text-[11px] text-slate-500 py-4 text-center">
            {isAr ? 'لا كشوف في الانتظار. البيانات المُسمّاة تنمو مع حركة المرور الحقيقية.'
                  : 'Nothing awaiting a ruling. The labelled corpus grows with live traffic.'}
          </p>
        )}
        {queue.map(item => (
          <div key={item.id} className="border border-slate-700/40 rounded bg-black/30 p-3">
            <div className="flex items-start justify-between gap-3 flex-wrap">
              <div className="min-w-0 flex-1">
                <code className="block text-[11px] text-slate-200 break-all leading-relaxed">
                  {item.payloadSample.slice(0, 220)}{item.payloadSample.length > 220 ? '…' : ''}
                </code>
                <div className="flex items-center gap-2 mt-2 flex-wrap text-[10px]">
                  <span className={`px-1.5 py-0.5 rounded border ${machineChip(item.machineVerdict)}`}>
                    {isAr ? 'المحرّك:' : 'machine:'} {item.machineVerdict}
                  </span>
                  <span className="text-slate-500">{item.machineFamily}</span>
                  <span className="text-slate-500">score {item.machineScore}</span>
                  {item.seenCount > 1 && (
                    <span className="text-amber-400/80">×{item.seenCount} {isAr ? 'مشاهدة' : 'seen'}</span>
                  )}
                  <span className="text-slate-600">{item.srcIp}</span>
                </div>
                {item.machineSignatures.length > 0 && (
                  <p className="text-[10px] text-slate-600 mt-1 truncate">
                    {item.machineSignatures.slice(0, 3).join(' · ')}
                  </p>
                )}
              </div>

              {/* Both actions are equally weighted. Overturning must not feel like the exception. */}
              <div className="flex gap-2 shrink-0">
                <button
                  disabled={busy === item.id}
                  onClick={() => rule(item.id, 'MALICIOUS')}
                  className="text-[10px] px-2.5 py-1.5 rounded border border-red-500/40 bg-red-500/10
                             text-red-300 hover:bg-red-500/20 disabled:opacity-40 transition">
                  {isAr ? 'خطر' : 'MALICIOUS'}
                </button>
                <button
                  disabled={busy === item.id}
                  onClick={() => rule(item.id, 'BENIGN')}
                  className="text-[10px] px-2.5 py-1.5 rounded border border-emerald-500/40 bg-emerald-500/10
                             text-emerald-300 hover:bg-emerald-500/20 disabled:opacity-40 transition">
                  {isAr ? 'سليم' : 'BENIGN'}
                </button>
              </div>
            </div>
          </div>
        ))}
      </div>

      <p className="text-[10px] text-slate-600 mt-4 leading-relaxed border-t border-slate-800 pt-3">
        {isAr
          ? 'كل حُكم يُضاف ولا يُعدَّل: المراجعة تُنشئ سجلاً جديداً يُبطل القديم، والقديم يبقى قابلاً للتدقيق. الطبقة الأحدث محجوزة للاختبار ولا يجوز كتابة أي قاعدة استناداً إليها.'
          : 'Labels are appended, never edited: a revision writes a new row superseding the old, and the old stays auditable. The newest fold is test-only — no rule may be written against it.'}
      </p>
    </div>
  );
};

const Metric: React.FC<{
  icon: React.ElementType; label: string; value: string; sub?: string; muted?: boolean;
}> = ({ icon: Icon, label, value, sub, muted }) => (
  <div className="bg-black/30 border border-slate-700/40 rounded px-3 py-2">
    <div className="flex items-center gap-1.5 mb-1">
      <Icon className="w-3 h-3 text-cyan-500/60" />
      <span className="text-[9px] text-slate-500 tracking-wider uppercase">{label}</span>
    </div>
    <p className={`text-sm font-bold ${muted ? 'text-slate-500' : 'text-cyan-200'}`}>{value}</p>
    {sub && <p className="text-[9px] text-slate-600 mt-0.5">{sub}</p>}
  </div>
);
