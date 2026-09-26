import React, { useState, useEffect } from 'react';
import { QuarantinedHost } from '../types';
import {
  Shield,
  ShieldAlert,
  Lock,
  Unlock,
  Clock,
  Radio,
  Cpu,
  RefreshCw,
  CheckCircle,
  AlertOctagon,
  Terminal
} from 'lucide-react';

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
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <div className="rounded-2xl border border-slate-800 bg-slate-900/90 p-4 shadow-lg">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-400">
              {isAr ? 'عناوين IP في العزل النشط:' : 'Quarantined Attackers:'}
            </span>
            <Lock className="h-4 w-4 text-rose-400" />
          </div>
          <div className="mt-2 text-2xl font-black text-white">{quarantinedHosts.length}</div>
          <span className="mt-1 block font-mono text-[10px] text-rose-400">
            {isAr ? 'حظر فوري عبر IPTables' : 'IPTables Kernel Blocked'}
          </span>
        </div>

        <div className="rounded-2xl border border-slate-800 bg-slate-900/90 p-4 shadow-lg">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-400">
              {isAr ? 'الأصول المحمية (Whitelist):' : 'Whitelisted Core Assets:'}
            </span>
            <Shield className="h-4 w-4 text-emerald-400" />
          </div>
          <div className="mt-2 text-2xl font-black text-white">6 Nodes</div>
          <span className="mt-1 block font-mono text-[10px] text-emerald-400">
            {isAr ? 'حماية من حجب الخدمة الذاتي' : 'Self-DoS Immunity Active'}
          </span>
        </div>

        <div className="rounded-2xl border border-slate-800 bg-slate-900/90 p-4 shadow-lg">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-400">
              {isAr ? 'مصائد الخداع السيبراني:' : 'Deception Honeypots:'}
            </span>
            <Radio className="h-4 w-4 text-purple-400" />
          </div>
          <div className="mt-2 text-2xl font-black text-white">10.0.99.5</div>
          <span className="mt-1 block font-mono text-[10px] text-purple-400">
            {isAr ? 'عزل وإيقاع تلقائي بالمهاجمين' : 'Active Cowrie SSH/HTTP Trap'}
          </span>
        </div>

        <div className="rounded-2xl border border-slate-800 bg-slate-900/90 p-4 shadow-lg">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-400">
              {isAr ? 'طبقة ترشيح النواة (eBPF):' : 'Kernel eBPF XDP Filter:'}
            </span>
            <Cpu className="h-4 w-4 text-cyan-400" />
          </div>
          <div className="mt-2 text-2xl font-black text-white">v6.8 Active</div>
          <span className="mt-1 block font-mono text-[10px] text-cyan-400">
            Zero CPU Copy Packet Drop
          </span>
        </div>
      </div>

      {/* Active Quarantine Table with Live TTL */}
      <div className="rounded-2xl border border-slate-800 bg-slate-900/90 p-5 shadow-xl">
        <div className="mb-4 flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 pb-3">
          <div className="flex items-center gap-2">
            <Lock className="h-4 w-4 text-rose-400" />
            <h3 className="text-base font-bold text-white">
              {isAr
                ? 'جدول العزل التكتيكي وفك الحظر التلقائي (Dynamic Quarantine & Auto-Rollback Table)'
                : 'Tactical Quarantine & Dynamic TTL Rollback Table'}
            </h3>
          </div>
          <span className="font-mono text-xs text-slate-400">
            {isAr ? 'تدرج فترات الحظر (5m → 10m → 20m)' : 'Exponential Backoff TTL'}
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left font-mono text-xs">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400">
                <th className="pb-2.5 font-bold">IP Address</th>
                <th className="pb-2.5 font-bold">{isAr ? 'الناقل المرصود' : 'Attack Vector'}</th>
                <th className="pb-2.5 font-bold">{isAr ? 'مؤشر التهديد' : 'Threat Score'}</th>
                <th className="pb-2.5 font-bold">{isAr ? 'المستوى (Tier)' : 'Tier'}</th>
                <th className="pb-2.5 font-bold">
                  {isAr ? 'الوقت المتبقي (TTL)' : 'TTL Remaining'}
                </th>
                <th className="pb-2.5 font-bold">{isAr ? 'الإجراء المتخذ' : 'Action Taken'}</th>
                <th className="pb-2.5 text-right font-bold">{isAr ? 'فك الحظر' : 'Rollback'}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {quarantinedHosts.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-8 text-center font-sans text-xs text-slate-500">
                    {isAr
                      ? 'لا توجد عناوين IP محظورة حالياً. جميع التهديدات تم تحييدها أو انقضت مدة عزلها.'
                      : 'No hosts currently in quarantine.'}
                  </td>
                </tr>
              ) : (
                quarantinedHosts.map(host => (
                  <tr key={host.ip} className="transition hover:bg-slate-800/40">
                    <td className="flex items-center gap-2 py-3 font-bold text-white">
                      <span className="h-2 w-2 animate-pulse rounded-full bg-rose-500"></span>
                      <span>{host.ip}</span>
                    </td>
                    <td className="py-3 text-cyan-300">{host.attackVector}</td>
                    <td className="py-3">
                      <span className="font-bold text-rose-400">{host.threatScore}%</span>
                    </td>
                    <td className="py-3">
                      <span className="rounded border border-slate-700 bg-slate-800 px-2 py-0.5 text-slate-300">
                        Tier {host.tier}
                      </span>
                    </td>
                    <td className="py-3">
                      <span className="flex items-center gap-1 font-bold text-amber-300">
                        <Clock className="h-3.5 w-3.5 text-amber-400" />
                        <span>{formatTtl(host.remainingSeconds)}</span>
                      </span>
                    </td>
                    <td className="max-w-xs truncate py-3 text-[11px] text-slate-300">
                      {host.actionTaken}
                    </td>
                    <td className="py-3 text-right">
                      <button
                        onClick={() => handleUnban(host.ip)}
                        disabled={unbanningIp === host.ip}
                        className="ml-auto flex items-center gap-1 rounded border border-slate-700 bg-slate-800 px-2.5 py-1 font-sans text-[11px] font-bold text-slate-300 transition hover:bg-emerald-950/60 hover:text-emerald-300"
                      >
                        {unbanningIp === host.ip ? (
                          <RefreshCw className="h-3 w-3 animate-spin" />
                        ) : (
                          <Unlock className="h-3 w-3 text-emerald-400" />
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
      <div className="rounded-2xl border border-slate-800 bg-slate-900/90 p-5 shadow-xl">
        <div className="mb-3 flex items-center gap-2 border-b border-slate-800 pb-3">
          <Shield className="h-4 w-4 text-emerald-400" />
          <h3 className="text-base font-bold text-white">
            {isAr
              ? 'القوائم البيضاء المحمية للأصول الحيوية (Critical Asset Whitelist Shield)'
              : 'Critical Infrastructure & Whitelist Manager'}
          </h3>
        </div>
        <p className="mb-4 text-xs text-slate-400">
          {isAr
            ? 'تضمن هذه القوائم عدم حظر موجهات الشبكة الأساسية، خوادم DNS الحيوية، أو عناوين الإدارة الداخلية حتى تحت ضغط الهجمات المزيفة لمنع سيناريوهات حجب الخدمة الذاتي (Self-DoS).'
            : 'Protects core infrastructure, authoritative DNS resolvers, and default gateways from eviction to prevent Self-DoS under spoofed volumetric floods.'}
        </p>

        <div className="grid grid-cols-1 gap-3 font-mono text-xs sm:grid-cols-2 md:grid-cols-3">
          {[
            { ip: '127.0.0.0/8', name: 'Loopback / Localhost Daemon' },
            { ip: '10.0.0.1/32', name: 'Core Edge Ingress Gateway' },
            { ip: '10.0.0.2/32', name: 'Sovereign Defender Agent Node' },
            { ip: '192.168.1.1/32', name: 'Internal Network Core Switch' },
            { ip: '1.1.1.1/32', name: 'Enterprise Cloudflare DNS' },
            { ip: '8.8.8.8/32', name: 'Google DNS Root Resolver' }
          ].map(asset => (
            <div
              key={asset.ip}
              className="flex items-center justify-between gap-2 rounded-xl border border-emerald-500/30 bg-slate-950/80 p-3"
            >
              <div>
                <div className="font-bold text-emerald-300">{asset.ip}</div>
                <div className="mt-0.5 font-sans text-[10px] text-slate-400">{asset.name}</div>
              </div>
              <span className="rounded border border-emerald-500/40 bg-emerald-500/20 px-1.5 py-0.5 text-[9px] font-bold text-emerald-300">
                IMMUNE
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
