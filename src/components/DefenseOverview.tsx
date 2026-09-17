import React, { useState, useEffect } from 'react';
import { QuarantinedHost } from '../types';
import { Shield, ShieldAlert, Lock, Unlock, Clock, Radio, Cpu, RefreshCw, CheckCircle, AlertOctagon, Terminal } from 'lucide-react';

interface DefenseOverviewProps {
  quarantinedHosts: QuarantinedHost[];
  onUnbanHost: (ip: string) => Promise<void>;
  lang: 'ar' | 'en';
}

export const DefenseOverview: React.FC<DefenseOverviewProps> = ({
  quarantinedHosts,
  onUnbanHost,
  lang
}) => {
  const isAr = lang === 'ar';
  const [unbanningIp, setUnbanningIp] = useState<string | null>(null);

  const formatTtl = (seconds: number) => {
    const m = Math.floor(seconds / 60);
    const s = seconds % 60;
    return `${m}m ${s < 10 ? '0' : ''}${s}s`;
  };

  const handleUnban = async (ip: string) => {
    setUnbanningIp(ip);
    try {
      await onUnbanHost(ip);
    } finally {
      setUnbanningIp(null);
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Banner: Blue Team Tactical Status */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="p-4 rounded-2xl bg-slate-900/90 border border-slate-800 shadow-lg">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-400">{isAr ? 'عناوين IP في العزل النشط:' : 'Quarantined Attackers:'}</span>
            <Lock className="w-4 h-4 text-rose-400" />
          </div>
          <div className="text-2xl font-black text-white mt-2">{quarantinedHosts.length}</div>
          <span className="text-[10px] text-rose-400 font-mono mt-1 block">{isAr ? 'حظر فوري عبر IPTables' : 'IPTables Kernel Blocked'}</span>
        </div>

        <div className="p-4 rounded-2xl bg-slate-900/90 border border-slate-800 shadow-lg">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-400">{isAr ? 'الأصول المحمية (Whitelist):' : 'Whitelisted Core Assets:'}</span>
            <Shield className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-black text-white mt-2">6 Nodes</div>
          <span className="text-[10px] text-emerald-400 font-mono mt-1 block">{isAr ? 'حماية من حجب الخدمة الذاتي' : 'Self-DoS Immunity Active'}</span>
        </div>

        <div className="p-4 rounded-2xl bg-slate-900/90 border border-slate-800 shadow-lg">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-400">{isAr ? 'مصائد الخداع السيبراني:' : 'Deception Honeypots:'}</span>
            <Radio className="w-4 h-4 text-purple-400" />
          </div>
          <div className="text-2xl font-black text-white mt-2">10.0.99.5</div>
          <span className="text-[10px] text-purple-400 font-mono mt-1 block">{isAr ? 'عزل وإيقاع تلقائي بالمهاجمين' : 'Active Cowrie SSH/HTTP Trap'}</span>
        </div>

        <div className="p-4 rounded-2xl bg-slate-900/90 border border-slate-800 shadow-lg">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-400">{isAr ? 'طبقة ترشيح النواة (eBPF):' : 'Kernel eBPF XDP Filter:'}</span>
            <Cpu className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-2xl font-black text-white mt-2">v6.8 Active</div>
          <span className="text-[10px] text-cyan-400 font-mono mt-1 block">Zero CPU Copy Packet Drop</span>
        </div>
      </div>

      {/* Active Quarantine Table with Live TTL */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-5 shadow-xl">
        <div className="flex flex-wrap items-center justify-between gap-3 pb-3 border-b border-slate-800 mb-4">
          <div className="flex items-center gap-2">
            <Lock className="w-4 h-4 text-rose-400" />
            <h3 className="font-bold text-white text-base">
              {isAr ? 'جدول العزل التكتيكي وفك الحظر التلقائي (Dynamic Quarantine & Auto-Rollback Table)' : 'Tactical Quarantine & Dynamic TTL Rollback Table'}
            </h3>
          </div>
          <span className="text-xs font-mono text-slate-400">
            {isAr ? 'تدرج فترات الحظر (5m → 10m → 20m)' : 'Exponential Backoff TTL'}
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left font-mono text-xs">
            <thead>
              <tr className="text-slate-400 border-b border-slate-800">
                <th className="pb-2.5 font-bold">IP Address</th>
                <th className="pb-2.5 font-bold">{isAr ? 'الناقل المرصود' : 'Attack Vector'}</th>
                <th className="pb-2.5 font-bold">{isAr ? 'مؤشر التهديد' : 'Threat Score'}</th>
                <th className="pb-2.5 font-bold">{isAr ? 'المستوى (Tier)' : 'Tier'}</th>
                <th className="pb-2.5 font-bold">{isAr ? 'الوقت المتبقي (TTL)' : 'TTL Remaining'}</th>
                <th className="pb-2.5 font-bold">{isAr ? 'الإجراء المتخذ' : 'Action Taken'}</th>
                <th className="pb-2.5 font-bold text-right">{isAr ? 'فك الحظر' : 'Rollback'}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {quarantinedHosts.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-8 text-center text-slate-500 font-sans text-xs">
                    {isAr ? 'لا توجد عناوين IP محظورة حالياً. جميع التهديدات تم تحييدها أو انقضت مدة عزلها.' : 'No hosts currently in quarantine.'}
                  </td>
                </tr>
              ) : (
                quarantinedHosts.map(host => (
                  <tr key={host.ip} className="hover:bg-slate-800/40 transition">
                    <td className="py-3 font-bold text-white flex items-center gap-2">
                      <span className="w-2 h-2 rounded-full bg-rose-500 animate-pulse"></span>
                      <span>{host.ip}</span>
                    </td>
                    <td className="py-3 text-cyan-300">{host.attackVector}</td>
                    <td className="py-3">
                      <span className="text-rose-400 font-bold">{host.threatScore}%</span>
                    </td>
                    <td className="py-3">
                      <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                        Tier {host.tier}
                      </span>
                    </td>
                    <td className="py-3">
                      <span className="flex items-center gap-1 text-amber-300 font-bold">
                        <Clock className="w-3.5 h-3.5 text-amber-400" />
                        <span>{formatTtl(host.remainingSeconds)}</span>
                      </span>
                    </td>
                    <td className="py-3 text-[11px] text-slate-300 max-w-xs truncate">{host.actionTaken}</td>
                    <td className="py-3 text-right">
                      <button
                        onClick={() => handleUnban(host.ip)}
                        disabled={unbanningIp === host.ip}
                        className="px-2.5 py-1 rounded bg-slate-800 hover:bg-emerald-950/60 hover:text-emerald-300 text-slate-300 border border-slate-700 text-[11px] font-sans font-bold transition flex items-center gap-1 ml-auto"
                      >
                        {unbanningIp === host.ip ? (
                          <RefreshCw className="w-3 h-3 animate-spin" />
                        ) : (
                          <Unlock className="w-3 h-3 text-emerald-400" />
                        )}
                        <span>{isAr ? 'فك الحظر' : 'Unban'}</span>
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Critical Infrastructure Whitelist Manager */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-5 shadow-xl">
        <div className="flex items-center gap-2 pb-3 border-b border-slate-800 mb-3">
          <Shield className="w-4 h-4 text-emerald-400" />
          <h3 className="font-bold text-white text-base">
            {isAr ? 'القوائم البيضاء المحمية للأصول الحيوية (Critical Asset Whitelist Shield)' : 'Critical Infrastructure & Whitelist Manager'}
          </h3>
        </div>
        <p className="text-xs text-slate-400 mb-4">
          {isAr
            ? 'تضمن هذه القوائم عدم حظر موجهات الشبكة الأساسية، خوادم DNS الحيوية، أو عناوين الإدارة الداخلية حتى تحت ضغط الهجمات المزيفة لمنع سيناريوهات حجب الخدمة الذاتي (Self-DoS).'
            : 'Protects core infrastructure, authoritative DNS resolvers, and default gateways from eviction to prevent Self-DoS under spoofed volumetric floods.'}
        </p>

        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3 font-mono text-xs">
          {[
            { ip: '127.0.0.0/8', name: 'Loopback / Localhost Daemon' },
            { ip: '10.0.0.1/32', name: 'Core Edge Ingress Gateway' },
            { ip: '10.0.0.2/32', name: 'Sovereign Defender Agent Node' },
            { ip: '192.168.1.1/32', name: 'Internal Network Core Switch' },
            { ip: '1.1.1.1/32', name: 'Enterprise Cloudflare DNS' },
            { ip: '8.8.8.8/32', name: 'Google DNS Root Resolver' }
          ].map(asset => (
            <div key={asset.ip} className="p-3 rounded-xl bg-slate-950/80 border border-emerald-500/30 flex items-center justify-between gap-2">
              <div>
                <div className="font-bold text-emerald-300">{asset.ip}</div>
                <div className="text-[10px] text-slate-400 font-sans mt-0.5">{asset.name}</div>
              </div>
              <span className="text-[9px] font-bold px-1.5 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/40">
                IMMUNE
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
