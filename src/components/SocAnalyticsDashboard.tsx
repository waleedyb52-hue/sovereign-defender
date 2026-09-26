import React, { useState, useEffect } from 'react';
import {
  BarChart3,
  Globe,
  Activity,
  ShieldCheck,
  ShieldAlert,
  TrendingUp,
  Layers,
  AlertTriangle,
  Sliders,
  RefreshCw,
  Zap,
  Cpu,
  Radio
} from 'lucide-react';
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  BarChart,
  Bar,
  Cell,
  PieChart,
  Pie,
  Legend
} from 'recharts';

interface SocAnalyticsDashboardProps {
  lang: 'ar' | 'en';
}

export const SocAnalyticsDashboard: React.FC<SocAnalyticsDashboardProps> = ({ lang }) => {
  const isAr = lang === 'ar';
  const [analyticsData, setAnalyticsData] = useState<any>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [autoRefresh, setAutoRefresh] = useState<boolean>(true);

  const fetchAnalytics = async () => {
    try {
      const res = await fetch('/api/v1/soc/analytics');
      if (res.ok) {
        const data = await res.json();
        setAnalyticsData(data);
      }
    } catch (err) {
      console.warn('Failed to load SOC analytics:', err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchAnalytics();
    if (autoRefresh) {
      const interval = setInterval(fetchAnalytics, 6000);
      return () => clearInterval(interval);
    }
  }, [autoRefresh]);

  const frequencyGraph = analyticsData?.frequencyGraph || [];
  const endpointDistribution = analyticsData?.endpointDistribution || [];
  const geoThreatDistribution = analyticsData?.geoThreatDistribution || [];
  const progressive = analyticsData?.progressiveMitigation || {
    tier1RateLimitedCount: 14,
    tier2ChallengedCount: 8,
    tier3CriticalBlockedCount: 39,
    activeTier1Sessions: 3,
    activeTier2Challenges: 1,
    activeTier3HardBans: 12
  };

  const COLORS = ['#6366f1', '#f43f5e', '#f59e0b', '#06b6d4', '#10b981', '#a855f7'];

  return (
    <div className="space-y-6">
      {/* Header Panel */}
      <div className="flex flex-col gap-4 rounded-2xl border border-slate-800 bg-gradient-to-r from-slate-900 via-slate-900 to-indigo-950/40 p-6 shadow-xl md:flex-row md:items-center md:justify-between">
        <div>
          <div className="mb-2 flex items-center gap-3">
            <div className="rounded-xl border border-cyan-500/30 bg-cyan-500/20 p-2.5 text-cyan-400">
              <BarChart3 className="h-6 w-6" />
            </div>
            <h2 className="text-xl font-black text-white sm:text-2xl">
              {isAr
                ? 'لوحة تحليلات الـ SOC وخريطة التهديدات الجغرافية'
                : 'Enterprise SOC Analytics & Geo-Threat Hub'}
            </h2>
            <span className="rounded-full border border-cyan-500/30 bg-cyan-500/20 px-2.5 py-0.5 text-xs font-bold text-cyan-300">
              REAL-TIME
            </span>
          </div>
          <p className="max-w-3xl text-sm leading-relaxed text-slate-300">
            {isAr
              ? 'مراقبة حركة المرور المباشرة، وتوزيع الهجمات على مسارات النظام والـ Endpoints، ورصد التهديدات الجغرافية وتوزيع الحظر التدريجي الذكي (3-Tier Progressive Mitigation).'
              : 'Real-time telemetry analytics: In-flight attack frequency graphs, targeted endpoint vulnerability breakdown, GeoIP threat origin clusters, and 3-Tier progressive defense rate-limiting.'}
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => setAutoRefresh(!autoRefresh)}
            className={`flex items-center gap-2 rounded-xl border px-3.5 py-2 text-xs font-bold transition ${
              autoRefresh
                ? 'border-emerald-500/40 bg-emerald-950/30 text-emerald-300'
                : 'border-slate-700 bg-slate-800 text-slate-400'
            }`}
          >
            <Radio
              className={`h-3.5 w-3.5 ${autoRefresh ? 'animate-pulse text-emerald-400' : ''}`}
            />
            <span>
              {isAr
                ? autoRefresh
                  ? 'بث مباشر نشط'
                  : 'البث متوقف'
                : autoRefresh
                  ? 'Live Stream Active'
                  : 'Paused'}
            </span>
          </button>

          <button
            onClick={fetchAnalytics}
            className="flex items-center gap-2 rounded-xl border border-slate-700 bg-slate-800/80 px-4 py-2 text-xs font-bold text-slate-200 transition hover:bg-slate-700"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${isLoading ? 'animate-spin' : ''}`} />
            <span>{isAr ? 'تحديث' : 'Refresh'}</span>
          </button>
        </div>
      </div>

      {/* 3-Tier Progressive Mitigation Status Cards */}
      <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
        {/* Tier 1 */}
        <div className="relative overflow-hidden rounded-2xl border border-amber-500/30 bg-slate-900 p-5 text-left shadow-lg">
          <div className="mb-3 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="rounded-xl border border-amber-500/30 bg-amber-500/20 p-2 text-amber-400">
                <Activity className="h-4 w-4" />
              </span>
              <div>
                <span className="block text-xs font-black tracking-wider text-amber-300 uppercase">
                  {isAr ? 'المستوى 1: التقييد التدريجي' : 'Tier 1: Progressive Rate-Limit'}
                </span>
                <span className="text-[10px] text-slate-400">HTTP 429 Adaptive Throttling</span>
              </div>
            </div>
            <span className="rounded bg-amber-500/20 px-2 py-0.5 font-mono text-xs font-bold text-amber-300">
              LOW-MED
            </span>
          </div>

          <div className="flex items-baseline justify-between border-t border-slate-800 pt-2">
            <div>
              <span className="font-mono text-2xl font-black text-white">
                {progressive.tier1RateLimitedCount}
              </span>
              <span className="block text-[11px] text-slate-400">
                {isAr ? 'إجمالي الطلبات المقيدة' : 'Total Throttled'}
              </span>
            </div>
            <div className="text-right">
              <span className="font-mono text-xs font-bold text-amber-400">
                {progressive.activeTier1Sessions} active
              </span>
              <span className="block text-[10px] text-slate-500">
                {isAr ? 'جلسات نشطة الآن' : 'In-Flight Sessions'}
              </span>
            </div>
          </div>
        </div>

        {/* Tier 2 */}
        <div className="relative overflow-hidden rounded-2xl border border-purple-500/30 bg-slate-900 p-5 text-left shadow-lg">
          <div className="mb-3 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="rounded-xl border border-purple-500/30 bg-purple-500/20 p-2 text-purple-400">
                <Sliders className="h-4 w-4" />
              </span>
              <div>
                <span className="block text-xs font-black tracking-wider text-purple-300 uppercase">
                  {isAr ? 'المستوى 2: التحدي الأمني التفاعلي' : 'Tier 2: Interactive Challenge'}
                </span>
                <span className="text-[10px] text-slate-400">CAPTCHA & Proof-of-Work</span>
              </div>
            </div>
            <span className="rounded bg-purple-500/20 px-2 py-0.5 font-mono text-xs font-bold text-purple-300">
              HIGH RISK
            </span>
          </div>

          <div className="flex items-baseline justify-between border-t border-slate-800 pt-2">
            <div>
              <span className="font-mono text-2xl font-black text-white">
                {progressive.tier2ChallengedCount}
              </span>
              <span className="block text-[11px] text-slate-400">
                {isAr ? 'التحديات الصادرة' : 'Issued Challenges'}
              </span>
            </div>
            <div className="text-right">
              <span className="font-mono text-xs font-bold text-purple-400">
                {progressive.activeTier2Challenges} active
              </span>
              <span className="block text-[10px] text-slate-500">
                {isAr ? 'جلسات قيد التحقق' : 'Verifying Now'}
              </span>
            </div>
          </div>
        </div>

        {/* Tier 3 */}
        <div className="relative overflow-hidden rounded-2xl border border-rose-500/30 bg-slate-900 p-5 text-left shadow-lg">
          <div className="mb-3 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="rounded-xl border border-rose-500/30 bg-rose-500/20 p-2 text-rose-400">
                <ShieldAlert className="h-4 w-4" />
              </span>
              <div>
                <span className="block text-xs font-black tracking-wider text-rose-300 uppercase">
                  {isAr ? 'المستوى 3: الحظر الفوري بالنواة' : 'Tier 3: Critical Kernel Drop'}
                </span>
                <span className="text-[10px] text-slate-400">IPTables / eBPF XDP Eviction</span>
              </div>
            </div>
            <span className="rounded bg-rose-500/20 px-2 py-0.5 font-mono text-xs font-bold text-rose-300">
              CRITICAL
            </span>
          </div>

          <div className="flex items-baseline justify-between border-t border-slate-800 pt-2">
            <div>
              <span className="font-mono text-2xl font-black text-white">
                {progressive.tier3CriticalBlockedCount}
              </span>
              <span className="block text-[11px] text-slate-400">
                {isAr ? 'إسقاط مباشر بالحظر' : 'Hard Bans Enforced'}
              </span>
            </div>
            <div className="text-right">
              <span className="font-mono text-xs font-bold text-rose-400">
                {progressive.activeTier3HardBans} active
              </span>
              <span className="block text-[10px] text-slate-500">
                {isAr ? 'قواعد جدار الحماية' : 'Kernel Rules Active'}
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Main Charts Grid */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
        {/* Traffic Velocity & Threat Ingress Stream (7 cols) */}
        <div className="space-y-4 rounded-2xl border border-slate-800 bg-slate-900 p-6 text-left shadow-xl lg:col-span-7">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2.5">
              <TrendingUp className="h-5 w-5 text-indigo-400" />
              <div>
                <h3 className="text-sm font-black text-white">
                  {isAr
                    ? 'معدل تدفق الحزم والهجمات اللحظية (Traffic Ingress & Attack Volume)'
                    : 'Real-Time Ingress Velocity & Defense Mitigations'}
                </h3>
                <span className="text-xs text-slate-400">Packets/Sec across edge gateways</span>
              </div>
            </div>
          </div>

          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart
                data={frequencyGraph}
                margin={{ top: 10, right: 10, left: -20, bottom: 0 }}
              >
                <defs>
                  <linearGradient id="cleanColor" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#10b981" stopOpacity={0.4} />
                    <stop offset="95%" stopColor="#10b981" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="blockedColor" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#f43f5e" stopOpacity={0.5} />
                    <stop offset="95%" stopColor="#f43f5e" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <XAxis dataKey="time" stroke="#64748b" fontSize={10} tickLine={false} />
                <YAxis stroke="#64748b" fontSize={10} tickLine={false} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#0f172a',
                    borderColor: '#334155',
                    borderRadius: '0.75rem',
                    fontSize: '12px'
                  }}
                  itemStyle={{ color: '#e2e8f0' }}
                />
                <Area
                  type="monotone"
                  dataKey="cleanSec"
                  name={isAr ? 'حركة سليمة (Clean)' : 'Clean Traffic'}
                  stroke="#10b981"
                  fillOpacity={1}
                  fill="url(#cleanColor)"
                />
                <Area
                  type="monotone"
                  dataKey="blockedSec"
                  name={isAr ? 'هجمات محظورة (Blocked)' : 'Threats Blocked'}
                  stroke="#f43f5e"
                  fillOpacity={1}
                  fill="url(#blockedColor)"
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>

          <div className="flex items-center justify-center gap-6 border-t border-slate-800 pt-2 text-xs font-medium">
            <div className="flex items-center gap-2">
              <span className="h-3 w-3 rounded-full bg-emerald-500"></span>
              <span className="text-slate-300">
                {isAr ? 'حركة المرور السليمة' : 'Clean Forwarded'}
              </span>
            </div>
            <div className="flex items-center gap-2">
              <span className="h-3 w-3 rounded-full bg-rose-500"></span>
              <span className="text-slate-300">
                {isAr ? 'هجمات محظورة فورياً' : 'Hard Blocked (eBPF/IPTables)'}
              </span>
            </div>
            <div className="flex items-center gap-2">
              <span className="h-3 w-3 rounded-full bg-amber-500"></span>
              <span className="text-slate-300">
                {isAr ? 'تقييد تدريجي 429' : 'Rate-Limited (429)'}
              </span>
            </div>
          </div>
        </div>

        {/* Targeted Endpoints & Vulnerability Surface (5 cols) */}
        <div className="space-y-4 rounded-2xl border border-slate-800 bg-slate-900 p-6 text-left shadow-xl lg:col-span-5">
          <div className="flex items-center gap-2.5">
            <Layers className="h-5 w-5 text-purple-400" />
            <div>
              <h3 className="text-sm font-black text-white">
                {isAr
                  ? 'توزيع الاستهداف على المسارات والـ Endpoints'
                  : 'Targeted Endpoint Attack Distribution'}
              </h3>
              <span className="text-xs text-slate-400">Exposed application attack surface</span>
            </div>
          </div>

          <div className="space-y-3">
            {endpointDistribution.map((ep: any) => {
              const percentage = Math.round((ep.threatHits / ep.hits) * 100);
              const isCrit = ep.risk === 'CRITICAL';
              return (
                <div
                  key={ep.id || `ep-${ep.endpoint}-${ep.primaryVector}`}
                  className="space-y-1.5 rounded-xl border border-slate-800/80 bg-slate-950 p-3"
                >
                  <div className="flex items-center justify-between text-xs">
                    <span className="max-w-[200px] truncate font-mono font-bold text-slate-200">
                      {ep.endpoint}
                    </span>
                    <span
                      className={`rounded px-2 py-0.5 text-[10px] font-bold ${
                        isCrit ? 'bg-rose-500/20 text-rose-300' : 'bg-amber-500/20 text-amber-300'
                      }`}
                    >
                      {ep.threatHits} {isAr ? 'هجوم' : 'threats'} ({percentage}%)
                    </span>
                  </div>

                  <div className="h-1.5 w-full overflow-hidden rounded-full bg-slate-800">
                    <div
                      className={`h-full rounded-full ${isCrit ? 'bg-rose-500' : 'bg-amber-500'}`}
                      style={{ width: `${Math.min(100, percentage)}%` }}
                    />
                  </div>

                  <div className="flex items-center justify-between font-mono text-[10px] text-slate-500">
                    <span>{ep.primaryVector}</span>
                    <span>Total Hits: {ep.hits}</span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* Geo-Threat Origin Map & Clusters */}
      <div className="space-y-4 rounded-2xl border border-slate-800 bg-slate-900 p-6 text-left shadow-xl">
        <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex items-center gap-2.5">
            <Globe className="h-5 w-5 text-cyan-400" />
            <div>
              <h3 className="text-sm font-black text-white">
                {isAr
                  ? 'خريطة التهديدات الجغرافية وتوزيع مصادر الهجمات (GeoIP Threat Clusters)'
                  : 'Global Geo-Threat Distribution & Origin Clusters'}
              </h3>
              <span className="text-xs text-slate-400">
                Origin countries and automated botnet clusters
              </span>
            </div>
          </div>
        </div>

        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 md:grid-cols-4">
          {geoThreatDistribution.map((geo: any) => {
            const isCrit = geo.threatTier === 'CRITICAL';
            const isHigh = geo.threatTier === 'HIGH';
            return (
              <div
                key={geo.id || `geo-${geo.country || geo.countryCode}-${geo.threatTier}`}
                className="space-y-2 rounded-xl border border-slate-800 bg-slate-950 p-4 transition hover:border-slate-700"
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="text-xl">{geo.flag}</span>
                    <span className="text-xs font-bold text-slate-200">{geo.country}</span>
                  </div>
                  <span
                    className={`rounded-full px-2 py-0.5 text-[10px] font-bold ${
                      isCrit
                        ? 'bg-rose-500/20 text-rose-300'
                        : isHigh
                          ? 'bg-amber-500/20 text-amber-300'
                          : 'bg-slate-800 text-slate-300'
                    }`}
                  >
                    {geo.threatTier}
                  </span>
                </div>

                <div className="flex items-baseline justify-between border-t border-slate-900 pt-1 text-xs">
                  <span className="font-mono text-lg font-black text-white">{geo.attackCount}</span>
                  <span className="max-w-[110px] truncate font-mono text-[11px] text-indigo-400">
                    {geo.topVector}
                  </span>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};
