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
      <div className="p-6 rounded-2xl bg-gradient-to-r from-slate-900 via-slate-900 to-indigo-950/40 border border-slate-800 shadow-xl flex flex-col md:flex-row md:items-center md:justify-between gap-4">
        <div>
          <div className="flex items-center gap-3 mb-2">
            <div className="p-2.5 rounded-xl bg-cyan-500/20 text-cyan-400 border border-cyan-500/30">
              <BarChart3 className="w-6 h-6" />
            </div>
            <h2 className="text-xl sm:text-2xl font-black text-white">
              {isAr ? 'لوحة تحليلات الـ SOC وخريطة التهديدات الجغرافية' : 'Enterprise SOC Analytics & Geo-Threat Hub'}
            </h2>
            <span className="px-2.5 py-0.5 rounded-full text-xs font-bold bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">
              REAL-TIME
            </span>
          </div>
          <p className="text-sm text-slate-300 max-w-3xl leading-relaxed">
            {isAr
              ? 'مراقبة حركة المرور المباشرة، وتوزيع الهجمات على مسارات النظام والـ Endpoints، ورصد التهديدات الجغرافية وتوزيع الحظر التدريجي الذكي (3-Tier Progressive Mitigation).'
              : 'Real-time telemetry analytics: In-flight attack frequency graphs, targeted endpoint vulnerability breakdown, GeoIP threat origin clusters, and 3-Tier progressive defense rate-limiting.'}
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => setAutoRefresh(!autoRefresh)}
            className={`flex items-center gap-2 px-3.5 py-2 rounded-xl text-xs font-bold border transition ${
              autoRefresh
                ? 'bg-emerald-950/30 border-emerald-500/40 text-emerald-300'
                : 'bg-slate-800 border-slate-700 text-slate-400'
            }`}
          >
            <Radio className={`w-3.5 h-3.5 ${autoRefresh ? 'text-emerald-400 animate-pulse' : ''}`} />
            <span>{isAr ? (autoRefresh ? 'بث مباشر نشط' : 'البث متوقف') : (autoRefresh ? 'Live Stream Active' : 'Paused')}</span>
          </button>

          <button
            onClick={fetchAnalytics}
            className="flex items-center gap-2 px-4 py-2 rounded-xl bg-slate-800/80 hover:bg-slate-700 text-slate-200 text-xs font-bold border border-slate-700 transition"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin' : ''}`} />
            <span>{isAr ? 'تحديث' : 'Refresh'}</span>
          </button>
        </div>
      </div>

      {/* 3-Tier Progressive Mitigation Status Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        
        {/* Tier 1 */}
        <div className="p-5 rounded-2xl bg-slate-900 border border-amber-500/30 shadow-lg relative overflow-hidden text-left">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2">
              <span className="p-2 rounded-xl bg-amber-500/20 text-amber-400 border border-amber-500/30">
                <Activity className="w-4 h-4" />
              </span>
              <div>
                <span className="text-xs font-black text-amber-300 uppercase tracking-wider block">
                  {isAr ? 'المستوى 1: التقييد التدريجي' : 'Tier 1: Progressive Rate-Limit'}
                </span>
                <span className="text-[10px] text-slate-400">HTTP 429 Adaptive Throttling</span>
              </div>
            </div>
            <span className="text-xs font-bold px-2 py-0.5 rounded bg-amber-500/20 text-amber-300 font-mono">
              LOW-MED
            </span>
          </div>

          <div className="flex items-baseline justify-between pt-2 border-t border-slate-800">
            <div>
              <span className="text-2xl font-black text-white font-mono">
                {progressive.tier1RateLimitedCount}
              </span>
              <span className="text-[11px] text-slate-400 block">{isAr ? 'إجمالي الطلبات المقيدة' : 'Total Throttled'}</span>
            </div>
            <div className="text-right">
              <span className="text-xs font-bold text-amber-400 font-mono">
                {progressive.activeTier1Sessions} active
              </span>
              <span className="text-[10px] text-slate-500 block">{isAr ? 'جلسات نشطة الآن' : 'In-Flight Sessions'}</span>
            </div>
          </div>
        </div>

        {/* Tier 2 */}
        <div className="p-5 rounded-2xl bg-slate-900 border border-purple-500/30 shadow-lg relative overflow-hidden text-left">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2">
              <span className="p-2 rounded-xl bg-purple-500/20 text-purple-400 border border-purple-500/30">
                <Sliders className="w-4 h-4" />
              </span>
              <div>
                <span className="text-xs font-black text-purple-300 uppercase tracking-wider block">
                  {isAr ? 'المستوى 2: التحدي الأمني التفاعلي' : 'Tier 2: Interactive Challenge'}
                </span>
                <span className="text-[10px] text-slate-400">CAPTCHA & Proof-of-Work</span>
              </div>
            </div>
            <span className="text-xs font-bold px-2 py-0.5 rounded bg-purple-500/20 text-purple-300 font-mono">
              HIGH RISK
            </span>
          </div>

          <div className="flex items-baseline justify-between pt-2 border-t border-slate-800">
            <div>
              <span className="text-2xl font-black text-white font-mono">
                {progressive.tier2ChallengedCount}
              </span>
              <span className="text-[11px] text-slate-400 block">{isAr ? 'التحديات الصادرة' : 'Issued Challenges'}</span>
            </div>
            <div className="text-right">
              <span className="text-xs font-bold text-purple-400 font-mono">
                {progressive.activeTier2Challenges} active
              </span>
              <span className="text-[10px] text-slate-500 block">{isAr ? 'جلسات قيد التحقق' : 'Verifying Now'}</span>
            </div>
          </div>
        </div>

        {/* Tier 3 */}
        <div className="p-5 rounded-2xl bg-slate-900 border border-rose-500/30 shadow-lg relative overflow-hidden text-left">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2">
              <span className="p-2 rounded-xl bg-rose-500/20 text-rose-400 border border-rose-500/30">
                <ShieldAlert className="w-4 h-4" />
              </span>
              <div>
                <span className="text-xs font-black text-rose-300 uppercase tracking-wider block">
                  {isAr ? 'المستوى 3: الحظر الفوري بالنواة' : 'Tier 3: Critical Kernel Drop'}
                </span>
                <span className="text-[10px] text-slate-400">IPTables / eBPF XDP Eviction</span>
              </div>
            </div>
            <span className="text-xs font-bold px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 font-mono">
              CRITICAL
            </span>
          </div>

          <div className="flex items-baseline justify-between pt-2 border-t border-slate-800">
            <div>
              <span className="text-2xl font-black text-white font-mono">
                {progressive.tier3CriticalBlockedCount}
              </span>
              <span className="text-[11px] text-slate-400 block">{isAr ? 'إسقاط مباشر بالحظر' : 'Hard Bans Enforced'}</span>
            </div>
            <div className="text-right">
              <span className="text-xs font-bold text-rose-400 font-mono">
                {progressive.activeTier3HardBans} active
              </span>
              <span className="text-[10px] text-slate-500 block">{isAr ? 'قواعد جدار الحماية' : 'Kernel Rules Active'}</span>
            </div>
          </div>
        </div>

      </div>

      {/* Main Charts Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        
        {/* Traffic Velocity & Threat Ingress Stream (7 cols) */}
        <div className="lg:col-span-7 p-6 rounded-2xl bg-slate-900 border border-slate-800 shadow-xl space-y-4 text-left">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2.5">
              <TrendingUp className="w-5 h-5 text-indigo-400" />
              <div>
                <h3 className="text-sm font-black text-white">
                  {isAr ? 'معدل تدفق الحزم والهجمات اللحظية (Traffic Ingress & Attack Volume)' : 'Real-Time Ingress Velocity & Defense Mitigations'}
                </h3>
                <span className="text-xs text-slate-400">Packets/Sec across edge gateways</span>
              </div>
            </div>
          </div>

          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={frequencyGraph} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="cleanColor" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#10b981" stopOpacity={0.4}/>
                    <stop offset="95%" stopColor="#10b981" stopOpacity={0}/>
                  </linearGradient>
                  <linearGradient id="blockedColor" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#f43f5e" stopOpacity={0.5}/>
                    <stop offset="95%" stopColor="#f43f5e" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <XAxis dataKey="time" stroke="#64748b" fontSize={10} tickLine={false} />
                <YAxis stroke="#64748b" fontSize={10} tickLine={false} />
                <Tooltip 
                  contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '0.75rem', fontSize: '12px' }}
                  itemStyle={{ color: '#e2e8f0' }}
                />
                <Area type="monotone" dataKey="cleanSec" name={isAr ? 'حركة سليمة (Clean)' : 'Clean Traffic'} stroke="#10b981" fillOpacity={1} fill="url(#cleanColor)" />
                <Area type="monotone" dataKey="blockedSec" name={isAr ? 'هجمات محظورة (Blocked)' : 'Threats Blocked'} stroke="#f43f5e" fillOpacity={1} fill="url(#blockedColor)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>

          <div className="flex items-center justify-center gap-6 pt-2 border-t border-slate-800 text-xs font-medium">
            <div className="flex items-center gap-2">
              <span className="w-3 h-3 rounded-full bg-emerald-500"></span>
              <span className="text-slate-300">{isAr ? 'حركة المرور السليمة' : 'Clean Forwarded'}</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="w-3 h-3 rounded-full bg-rose-500"></span>
              <span className="text-slate-300">{isAr ? 'هجمات محظورة فورياً' : 'Hard Blocked (eBPF/IPTables)'}</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="w-3 h-3 rounded-full bg-amber-500"></span>
              <span className="text-slate-300">{isAr ? 'تقييد تدريجي 429' : 'Rate-Limited (429)'}</span>
            </div>
          </div>
        </div>

        {/* Targeted Endpoints & Vulnerability Surface (5 cols) */}
        <div className="lg:col-span-5 p-6 rounded-2xl bg-slate-900 border border-slate-800 shadow-xl space-y-4 text-left">
          <div className="flex items-center gap-2.5">
            <Layers className="w-5 h-5 text-purple-400" />
            <div>
              <h3 className="text-sm font-black text-white">
                {isAr ? 'توزيع الاستهداف على المسارات والـ Endpoints' : 'Targeted Endpoint Attack Distribution'}
              </h3>
              <span className="text-xs text-slate-400">Exposed application attack surface</span>
            </div>
          </div>

          <div className="space-y-3">
            {endpointDistribution.map((ep: any) => {
              const percentage = Math.round((ep.threatHits / ep.hits) * 100);
              const isCrit = ep.risk === 'CRITICAL';
              return (
                <div key={ep.id || `ep-${ep.endpoint}-${ep.primaryVector}`} className="p-3 rounded-xl bg-slate-950 border border-slate-800/80 space-y-1.5">
                  <div className="flex items-center justify-between text-xs">
                    <span className="font-mono font-bold text-slate-200 truncate max-w-[200px]">{ep.endpoint}</span>
                    <span className={`text-[10px] font-bold px-2 py-0.5 rounded ${
                      isCrit ? 'bg-rose-500/20 text-rose-300' : 'bg-amber-500/20 text-amber-300'
                    }`}>
                      {ep.threatHits} {isAr ? 'هجوم' : 'threats'} ({percentage}%)
                    </span>
                  </div>

                  <div className="w-full h-1.5 rounded-full bg-slate-800 overflow-hidden">
                    <div 
                      className={`h-full rounded-full ${isCrit ? 'bg-rose-500' : 'bg-amber-500'}`}
                      style={{ width: `${Math.min(100, percentage)}%` }}
                    />
                  </div>

                  <div className="flex items-center justify-between text-[10px] text-slate-500 font-mono">
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
      <div className="p-6 rounded-2xl bg-slate-900 border border-slate-800 shadow-xl space-y-4 text-left">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
          <div className="flex items-center gap-2.5">
            <Globe className="w-5 h-5 text-cyan-400" />
            <div>
              <h3 className="text-sm font-black text-white">
                {isAr ? 'خريطة التهديدات الجغرافية وتوزيع مصادر الهجمات (GeoIP Threat Clusters)' : 'Global Geo-Threat Distribution & Origin Clusters'}
              </h3>
              <span className="text-xs text-slate-400">Origin countries and automated botnet clusters</span>
            </div>
          </div>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-3">
          {geoThreatDistribution.map((geo: any) => {
            const isCrit = geo.threatTier === 'CRITICAL';
            const isHigh = geo.threatTier === 'HIGH';
            return (
              <div 
                key={geo.id || `geo-${geo.country || geo.countryCode}-${geo.threatTier}`} 
                className="p-4 rounded-xl bg-slate-950 border border-slate-800 hover:border-slate-700 transition space-y-2"
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="text-xl">{geo.flag}</span>
                    <span className="text-xs font-bold text-slate-200">{geo.country}</span>
                  </div>
                  <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full ${
                    isCrit ? 'bg-rose-500/20 text-rose-300' : isHigh ? 'bg-amber-500/20 text-amber-300' : 'bg-slate-800 text-slate-300'
                  }`}>
                    {geo.threatTier}
                  </span>
                </div>

                <div className="flex items-baseline justify-between text-xs pt-1 border-t border-slate-900">
                  <span className="text-lg font-black text-white font-mono">{geo.attackCount}</span>
                  <span className="text-[11px] font-mono text-indigo-400 truncate max-w-[110px]">{geo.topVector}</span>
                </div>
              </div>
            );
          })}
        </div>
      </div>

    </div>
  );
};
