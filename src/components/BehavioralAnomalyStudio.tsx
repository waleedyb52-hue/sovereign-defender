import React, { useState, useEffect } from 'react';
import { BehavioralBaseline } from '../types';
import {
  Activity,
  Sliders,
  Sparkles,
  AlertTriangle,
  CheckCircle2,
  Zap,
  RotateCcw,
  TrendingUp,
  Cpu,
  Radio,
  ShieldCheck,
  BarChart3
} from 'lucide-react';

interface BehavioralAnomalyStudioProps {
  lang: 'ar' | 'en';
}

export const BehavioralAnomalyStudio: React.FC<BehavioralAnomalyStudioProps> = ({ lang }) => {
  const isAr = lang === 'ar';

  const [baseline, setBaseline] = useState<BehavioralBaseline | null>(null);
  const [zThreshold, setZThreshold] = useState<number>(3.0);
  const [testReqRate, setTestReqRate] = useState<number>(18.5);
  const [testEntropy, setTestEntropy] = useState<number>(5.8);
  const [testPacketSize, setTestPacketSize] = useState<number>(1840);
  const [evalResult, setEvalResult] = useState<any>(null);
  const [isEvaluating, setIsEvaluating] = useState<boolean>(false);
  const [tuneMessage, setTuneMessage] = useState<string | null>(null);

  const fetchBaseline = async () => {
    try {
      const res = await fetch('/api/v1/behavioral/baseline');
      if (res.ok) {
        const data = await res.json();
        if (data.baseline) {
          setBaseline(data.baseline);
          setZThreshold(data.baseline.anomalyThresholdZScore || 3.0);
        }
      }
    } catch (err) {
      console.warn('Baseline fetch warning:', err);
    }
  };

  useEffect(() => {
    fetchBaseline();
    const interval = setInterval(fetchBaseline, 8000);
    return () => clearInterval(interval);
  }, []);

  const handleTuneThreshold = async (newVal: number) => {
    setZThreshold(newVal);
    try {
      const res = await fetch('/api/v1/behavioral/tune', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ anomalyThresholdZScore: newVal })
      });
      if (res.ok) {
        const data = await res.json();
        setBaseline(data.baseline);
      }
    } catch (err) {
      console.error('Tune error:', err);
    }
  };

  const handleRecalibrateBaseline = async () => {
    try {
      const res = await fetch('/api/v1/behavioral/tune', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ resetBaseline: true, anomalyThresholdZScore: 3.0 })
      });
      if (res.ok) {
        const data = await res.json();
        setBaseline(data.baseline);
        setZThreshold(3.0);
        setTuneMessage(
          isAr
            ? 'تمت إعادة ضبط وتدريب النموذج السلوكي بنجاح'
            : 'Behavioral baseline recalibrated with 20,000 samples.'
        );
        setTimeout(() => setTuneMessage(null), 5000);
      }
    } catch (err) {
      console.error('Recalibrate error:', err);
    }
  };

  const handleEvaluateTelemetry = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsEvaluating(true);
    try {
      const res = await fetch('/api/v1/behavioral/evaluate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          reqRate: Number(testReqRate),
          entropy: Number(testEntropy),
          packetSize: Number(testPacketSize)
        })
      });
      if (res.ok) {
        const data = await res.json();
        setEvalResult(data);
        fetchBaseline();
      }
    } catch (err) {
      console.error('Evaluate error:', err);
    } finally {
      setIsEvaluating(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Banner: Behavioral Anomaly Header */}
      <div className="rounded-2xl border border-cyan-500/40 bg-gradient-to-r from-cyan-950/80 via-slate-900 to-cyan-950/80 p-6 shadow-2xl">
        <div className="flex flex-wrap items-center justify-between gap-6">
          <div className="flex items-center gap-4">
            <div className="rounded-2xl border border-cyan-500/40 bg-cyan-500/20 p-4 text-cyan-300 shadow-inner">
              <Activity className="h-8 w-8 animate-pulse text-cyan-400" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-xl font-black text-white">
                  {isAr
                    ? 'محرك كشف الشذوذ السلوكي وضبط الحساسية (Behavioral Anomaly & Baseline Tuning)'
                    : 'Behavioral Anomaly & Gaussian Baseline Engine'}
                </h2>
                <span className="rounded-full border border-cyan-500/40 bg-cyan-500/20 px-2.5 py-0.5 font-mono text-xs font-bold text-cyan-300">
                  Z-Score Heuristics
                </span>
              </div>
              <p className="mt-1 max-w-2xl text-xs text-slate-300">
                {isAr
                  ? 'بناء نموذج سلوكي مستمر لحركة المرور الطبيعية (Gaussian Distribution) ورصد التسلل الخفي عبر الانحراف المعياري لإنتروبيا البيانات وتوزيع الحزم'
                  : 'Real-time statistical anomaly detection mapping traffic against learned Gaussian baselines using multi-variable Z-score deviation'}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-4 rounded-2xl border border-cyan-500/30 bg-slate-950/90 p-3.5 text-center font-mono">
            <div>
              <span className="block font-sans text-[10px] text-slate-400">
                {isAr ? 'العينات المتعلمة:' : 'Learned Samples:'}
              </span>
              <span className="text-2xl font-black text-cyan-400">
                {baseline?.sampleCount.toLocaleString() || '20,000'}
              </span>
              <span className="block text-[9px] font-bold text-emerald-400">ONLINE LEARNING</span>
            </div>
            <div className="h-10 w-px bg-slate-800"></div>
            <div>
              <span className="block font-sans text-[10px] text-slate-400">
                {isAr ? 'حد الانحراف المعياري:' : 'Anomaly Cutoff:'}
              </span>
              <span className="text-2xl font-black text-cyan-400">{zThreshold.toFixed(1)}σ</span>
              <span className="block text-[9px] text-slate-400">Z-Score Deviation</span>
            </div>
          </div>
        </div>
      </div>

      {tuneMessage && (
        <div className="flex items-center gap-2 rounded-xl border border-emerald-500/60 bg-emerald-950/80 p-3.5 text-xs font-bold text-emerald-300 shadow-lg">
          <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-400" />
          <span>{tuneMessage}</span>
        </div>
      )}

      {/* Main Grid: Baseline & Tuning (Left) + Live Evaluator & Drift Flags (Right) */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
        {/* Left Column: Baseline Statistical Profile & Threshold Tuner (6 Cols) */}
        <div className="space-y-5 lg:col-span-6">
          {/* Baseline Metric Cards */}
          <div className="space-y-4 rounded-2xl border border-slate-800 bg-slate-900/95 p-5 shadow-xl shadow-[0_0_20px_rgba(0,255,255,0.08)]">
            <div className="flex items-center justify-between">
              <h3 className="flex items-center gap-2 text-sm font-bold text-white">
                <BarChart3 className="h-4 w-4 text-cyan-400" />
                <span>
                  {isAr
                    ? 'المؤشرات الإحصائية للمرور الطبيعي (Gaussian Baseline):'
                    : 'Baseline Statistical Profile:'}
                </span>
              </h3>
              <button
                type="button"
                onClick={handleRecalibrateBaseline}
                className="flex items-center gap-1 rounded-lg border border-slate-700 bg-slate-800 px-2.5 py-1 text-xs font-bold text-slate-300 transition hover:bg-slate-700"
              >
                <RotateCcw className="h-3 w-3" />
                <span>{isAr ? 'إعادة ضبط النموذج' : 'Recalibrate'}</span>
              </button>
            </div>

            <div className="grid grid-cols-3 gap-3 text-center font-mono">
              <div className="rounded-xl border border-slate-800 bg-slate-950 p-3 shadow-[0_0_20px_rgba(0,255,255,0.08)]">
                <span className="block font-sans text-[10px] text-slate-400">
                  {isAr ? 'معدل الطلبات/ث:' : 'Mean Req Rate (μ):'}
                </span>
                <span className="text-lg font-bold text-cyan-300">
                  {baseline?.meanReqRate || 5.0} pkts/s
                </span>
                <span className="block text-[9px] text-slate-500">
                  σ = ±{baseline?.stdDevReqRate || 1.2}
                </span>
              </div>

              <div className="rounded-xl border border-slate-800 bg-slate-950 p-3 shadow-[0_0_20px_rgba(0,255,255,0.08)]">
                <span className="block font-sans text-[10px] text-slate-400">
                  {isAr ? 'إنتروبيا شانون:' : 'Mean Entropy (μ):'}
                </span>
                <span className="text-lg font-bold text-cyan-300">
                  {baseline?.meanEntropy || 3.8} bits
                </span>
                <span className="block text-[9px] text-slate-500">
                  σ = ±{baseline?.stdDevEntropy || 0.4}
                </span>
              </div>

              <div className="rounded-xl border border-slate-800 bg-slate-950 p-3 shadow-[0_0_20px_rgba(0,255,255,0.08)]">
                <span className="block font-sans text-[10px] text-slate-400">
                  {isAr ? 'حجم الحزم الطبيعي:' : 'Mean Pkt Size (μ):'}
                </span>
                <span className="text-lg font-bold text-emerald-300">
                  {baseline?.meanPacketSize || 640} B
                </span>
                <span className="block text-[9px] text-slate-500">
                  σ = ±{baseline?.stdDevPacketSize || 120}
                </span>
              </div>
            </div>

            {/* Threshold Slider */}
            <div className="space-y-3 rounded-xl border border-cyan-500/30 bg-slate-950 p-4">
              <div className="flex items-center justify-between">
                <label className="flex items-center gap-1.5 text-xs font-bold text-slate-200">
                  <Sliders className="h-3.5 w-3.5 text-cyan-400" />
                  <span>
                    {isAr
                      ? 'حساسية كشف الشذوذ (Anomaly Z-Score Threshold):'
                      : 'Anomaly Threshold (Z-Score):'}
                  </span>
                </label>
                <span className="rounded border border-cyan-500/40 bg-cyan-950 px-2.5 py-0.5 font-mono text-xs font-bold text-cyan-300">
                  {zThreshold.toFixed(1)} σ
                </span>
              </div>

              <input
                type="range"
                min="1.5"
                max="5.0"
                step="0.1"
                value={zThreshold}
                onChange={e => handleTuneThreshold(parseFloat(e.target.value))}
                className="h-2 w-full cursor-pointer appearance-none rounded-lg bg-slate-800 accent-cyan-500"
              />

              <div className="flex items-center justify-between font-mono text-[10px] text-slate-400">
                <span>1.5σ ({isAr ? 'حساسية فائقة / تنبيهات أكثر' : 'Ultra Sensitive'})</span>
                <span>3.0σ ({isAr ? 'المستوى الإنتاجي المثالي' : 'Recommended'})</span>
                <span>5.0σ ({isAr ? 'تسامح عالي / للهجمات الكبرى' : 'High Tolerance'})</span>
              </div>
            </div>
          </div>

          {/* Active Drift Flags Log */}
          <div className="space-y-3 rounded-2xl border border-slate-800 bg-slate-900/95 p-5 shadow-xl shadow-[0_0_20px_rgba(0,255,255,0.08)]">
            <div className="flex items-center justify-between">
              <h3 className="flex items-center gap-2 text-sm font-bold text-white">
                <AlertTriangle className="h-4 w-4 text-amber-400" />
                <span>
                  {isAr
                    ? 'سجل انحرافات حركة المرور الحية (Active Drift Flags):'
                    : 'Active Behavioral Drift Flags:'}
                </span>
              </h3>
              <span className="font-mono text-[10px] text-slate-400">
                {baseline?.activeDriftFlags?.length || 0} Events
              </span>
            </div>

            <div className="max-h-52 space-y-2 overflow-y-auto pr-1">
              {(baseline?.activeDriftFlags || []).map((flag: any) => (
                <div
                  key={flag.id}
                  className="flex items-center justify-between rounded-xl border border-slate-800 bg-slate-950 p-3 font-mono text-xs shadow-[0_0_20px_rgba(0,255,255,0.08)]"
                >
                  <div>
                    <div className="flex items-center gap-2 font-bold text-white">
                      <span className="rounded border border-amber-500/40 bg-amber-950 px-1.5 py-0.5 text-[10px] text-amber-300">
                        {flag.flag}
                      </span>
                      <span className="text-[11px] text-slate-300">
                        {isAr ? flag.flagAr : flag.flag}
                      </span>
                    </div>
                    <div className="mt-1 text-[10px] text-slate-400">{flag.sampleMetric}</div>
                  </div>

                  <div className="text-right">
                    <span className="text-xs font-bold text-rose-400">{flag.deviationZScore}σ</span>
                    <span className="block text-[9px] text-slate-500">
                      {new Date(flag.triggeredAt).toLocaleTimeString()}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Right Column: Live Telemetry Anomaly Evaluator (6 Cols) */}
        <div className="space-y-5 lg:col-span-6">
          <form
            onSubmit={handleEvaluateTelemetry}
            className="space-y-4 rounded-2xl border border-cyan-500/40 bg-slate-900/95 p-5 shadow-2xl"
          >
            <h3 className="flex items-center gap-2 text-sm font-bold text-white">
              <Sparkles className="h-4 w-4 text-cyan-400" />
              <span>
                {isAr
                  ? 'اختبار وتقييم بيانات حية فوراً (Live Telemetry Evaluator):'
                  : 'Live Telemetry Deviation Evaluator:'}
              </span>
            </h3>

            <div className="space-y-3">
              <div>
                <label className="mb-1 block text-xs font-semibold text-slate-300">
                  {isAr
                    ? 'معدل الطلبات اللحظي (Requests / Sec):'
                    : 'Incoming Request Rate (pkts/s):'}
                </label>
                <input
                  type="number"
                  step="0.1"
                  value={testReqRate}
                  onChange={e => setTestReqRate(parseFloat(e.target.value))}
                  className="w-full rounded-lg border border-slate-800 bg-slate-950 px-3 py-2 font-mono text-xs text-white focus:border-cyan-500 focus:outline-none shadow-[0_0_20px_rgba(0,255,255,0.08)]"
                />
              </div>

              <div>
                <label className="mb-1 block text-xs font-semibold text-slate-300">
                  {isAr
                    ? 'إنتروبيا الحمولة (Shannon Payload Entropy: 0-8 bits):'
                    : 'Payload Shannon Entropy (0-8 bits):'}
                </label>
                <input
                  type="number"
                  step="0.01"
                  value={testEntropy}
                  onChange={e => setTestEntropy(parseFloat(e.target.value))}
                  className="w-full rounded-lg border border-slate-800 bg-slate-950 px-3 py-2 font-mono text-xs text-white focus:border-cyan-500 focus:outline-none shadow-[0_0_20px_rgba(0,255,255,0.08)]"
                />
              </div>

              <div>
                <label className="mb-1 block text-xs font-semibold text-slate-300">
                  {isAr ? 'حجم الحزمة (Packet Size in Bytes):' : 'Packet Size (Bytes):'}
                </label>
                <input
                  type="number"
                  value={testPacketSize}
                  onChange={e => setTestPacketSize(parseInt(e.target.value))}
                  className="w-full rounded-lg border border-slate-800 bg-slate-950 px-3 py-2 font-mono text-xs text-white focus:border-cyan-500 focus:outline-none shadow-[0_0_20px_rgba(0,255,255,0.08)]"
                />
              </div>
            </div>

            <button
              type="submit"
              disabled={isEvaluating}
              className="flex w-full items-center justify-center gap-2 rounded-xl bg-gradient-to-r from-cyan-600 to-cyan-600 py-2.5 text-xs font-bold text-white shadow-lg shadow-cyan-950/50 transition hover:from-cyan-500 hover:to-cyan-500"
            >
              <Zap className="h-3.5 w-3.5" />
              <span>
                {isEvaluating
                  ? 'Evaluating...'
                  : isAr
                    ? 'حساب الانحراف المعياري ورصد الشذوذ (Calculate Z-Score)'
                    : 'Calculate Multi-Variable Deviation'}
              </span>
            </button>
          </form>

          {/* Evaluator Live Verdict */}
          {evalResult && (
            <div
              className={`space-y-3 rounded-2xl border p-5 shadow-xl ${
                evalResult.isAnomalous
                  ? 'border-rose-500/60 bg-rose-950/40 text-rose-200'
                  : 'border-emerald-500/60 bg-emerald-950/40 text-emerald-200'
              }`}
            >
              <div className="flex items-center justify-between">
                <span className="flex items-center gap-2 text-xs font-bold">
                  {evalResult.isAnomalous ? (
                    <AlertTriangle className="h-4 w-4 text-rose-400" />
                  ) : (
                    <CheckCircle2 className="h-4 w-4 text-emerald-400" />
                  )}
                  <span>
                    {evalResult.isAnomalous
                      ? isAr
                        ? 'تم رصد شذوذ سلوكي حاد (ANOMALOUS)'
                        : 'ANOMALY DETECTED'
                      : isAr
                        ? 'المرور ضمن المعدل الطبيعي (BENIGN)'
                        : 'TRAFFIC WITHIN NORMAL GAUSSIAN BOUNDS'}
                  </span>
                </span>
                <span className="font-mono text-xs font-black">
                  Max Z: {evalResult.maxZScore}σ (Cutoff: {evalResult.thresholdZScore}σ)
                </span>
              </div>

              <div className="grid grid-cols-3 gap-2 border-t border-slate-800 pt-2 font-mono text-[11px]">
                <div className="rounded bg-slate-950/80 p-2">
                  <span className="block text-[10px] text-slate-400">Δ Z(ReqRate):</span>
                  <span className="font-bold text-cyan-300">{evalResult.deviations.zReqRate}σ</span>
                </div>
                <div className="rounded bg-slate-950/80 p-2">
                  <span className="block text-[10px] text-slate-400">Δ Z(Entropy):</span>
                  <span className="font-bold text-cyan-300">
                    {evalResult.deviations.zEntropy}σ
                  </span>
                </div>
                <div className="rounded bg-slate-950/80 p-2">
                  <span className="block text-[10px] text-slate-400">Δ Z(Size):</span>
                  <span className="font-bold text-emerald-300">
                    {evalResult.deviations.zPacketSize}σ
                  </span>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
