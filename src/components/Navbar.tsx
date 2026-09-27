import React, { useState, useEffect } from 'react';
import {
  Shield,
  RefreshCw,
  Waves,
  Pause,
  Bell,
  UserCheck,
  Zap,
  Globe,
  Maximize2,
  Clock,
  Flame
} from 'lucide-react';
import { DefenseFlightMode, AppTab } from '../types';
import { usePrefersCalm, setCalmMode } from '../hooks/useLiveData';
export type { AppTab };

interface NavbarProps {
  activeTab: AppTab;
  setActiveTab: (tab: AppTab) => void;
  lang: 'ar' | 'en';
  setLang: (lang: 'ar' | 'en') => void;
  systemStatus: {
    totalRequestsProtected: number;
    totalThreatsBlocked: number;
    activeIptablesRules: number;
    honeypotTrappedCount: number;
  };
  flightMode: DefenseFlightMode;
  onToggleFlightMode: (mode: DefenseFlightMode) => void;
  pendingApprovalsCount: number;
  onOpenApprovalModal: () => void;
  onOpenAlertModal: () => void;
  onRefresh: () => void;
  onResetTelemetry?: () => void;
  onLaunchKiosk?: () => void;
  onLaunchWarGames?: () => void;
}

export const Navbar: React.FC<NavbarProps> = ({
  lang,
  setLang,
  flightMode,
  onToggleFlightMode,
  pendingApprovalsCount,
  onOpenApprovalModal,
  onOpenAlertModal,
  onRefresh,
  onLaunchKiosk,
  onLaunchWarGames
}) => {
  const isAr = lang === 'ar';
  const calm = usePrefersCalm();
  const [currentTime, setCurrentTime] = useState<string>('');

  useEffect(() => {
    const updateTime = () => {
      const now = new Date();
      setCurrentTime(now.toTimeString().slice(0, 8) + ' UTC');
    };
    updateTime();
    const timer = setInterval(updateTime, 1000);
    return () => clearInterval(timer);
  }, []);

  return (
    <header className="sticky top-0 z-30 flex h-12 items-center border-b border-[#0e3a44] bg-[#000000] font-mono select-none">
      <div className="flex w-full items-center justify-between px-4">
        {/* Brand & System Identity */}
        <div className="flex items-center gap-3">
          <div className="relative">
            <div className="flex h-7 w-7 items-center justify-center rounded border border-[#0e3a44] bg-[#03070c]">
              <Shield className="h-4 w-4 text-[#10b981]" />
            </div>
            <span className="absolute -top-0.5 -right-0.5 flex h-2 w-2">
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-[#10b981] opacity-75"></span>
              <span className="relative inline-flex h-2 w-2 rounded-full bg-[#10b981]"></span>
            </span>
          </div>

          <div className="flex items-center gap-2">
            <span className="text-xs font-bold tracking-wider text-[#e6edf3]">
              SOVEREIGN DEFENDER
            </span>
            <span className="py-0.2 rounded border border-[#0e3a44] bg-[#03070c] px-1.5 text-[9px] font-bold text-[#8aa4b8]">
              v7.0 eBPF
            </span>
          </div>
        </div>

        {/* Center: Discreet Sovereign Node Coordinates & Live Heartbeat */}
        <div className="hidden items-center gap-2 text-[11px] text-[#5c7484] md:flex">
          <span className="h-1.5 w-1.5 rounded-full bg-[#10b981]" />
          <span>RIYADH CORE NODE (24.71°N, 46.67°E)</span>
          <span className="text-[#0e3a44]">•</span>
          <div className="flex items-center gap-1 text-[#8aa4b8]">
            <Clock className="h-3 w-3 text-[#5c7484]" />
            <span className="font-mono">{currentTime}</span>
          </div>
        </div>

        {/* Right Controls: Minimalist Flight Mode, Alerts, Kiosk & Lang */}
        <div className="flex items-center gap-2 sm:gap-2.5">
          {/* Flight Mode Pill */}
          <div className="flex items-center rounded-md border border-[#0e3a44] bg-[#03070c] p-0.5 text-[11px]">
            <button
              type="button"
              onClick={() => onToggleFlightMode('AUTOPILOT')}
              title={isAr ? 'الوضع الذاتي التلقائي' : 'Auto-Pilot Mode'}
              className={`flex items-center gap-1 rounded px-2 py-0.5 text-[11px] font-bold transition ${
                flightMode === 'AUTOPILOT'
                  ? 'bg-[#1A1A1A] text-[#10b981] shadow-[0_0_8px_rgba(57,255,20,0.15)]'
                  : 'text-[#5c7484] hover:text-[#AAAAAA]'
              }`}
            >
              <Zap className="h-3 w-3" />
              <span className="hidden sm:inline">{isAr ? 'طيار آلي' : 'Auto'}</span>
            </button>

            <button
              type="button"
              onClick={() => onToggleFlightMode('MANUAL_APPROVAL')}
              title={isAr ? 'وضع الموافقة اليدوية' : 'Manual Approval Mode'}
              className={`flex items-center gap-1 rounded px-2 py-0.5 text-[11px] font-bold transition ${
                flightMode === 'MANUAL_APPROVAL'
                  ? 'bg-[#1A1A1A] text-[#f59e0b]'
                  : 'text-[#5c7484] hover:text-[#AAAAAA]'
              }`}
            >
              <UserCheck className="h-3 w-3" />
              <span className="hidden sm:inline">{isAr ? 'يدوي' : 'Manual'}</span>
            </button>
          </div>

          {/* Pending Approvals Badge (Only shows when in Manual mode and > 0) */}
          {flightMode === 'MANUAL_APPROVAL' && pendingApprovalsCount > 0 && (
            <button
              onClick={onOpenApprovalModal}
              className="flex items-center gap-1 rounded border border-[#f59e0b]/35 bg-[#061019] px-2 py-1 text-[11px] font-bold text-[#f59e0b] transition hover:border-[#f59e0b]/60"
            >
              <UserCheck className="h-3 w-3" />
              <span>{pendingApprovalsCount}</span>
            </button>
          )}

          {/* Multi-Channel Alerts Button */}
          <button
            onClick={onOpenAlertModal}
            title={isAr ? 'إعدادات التنبيهات' : 'Alert Configuration'}
            className="rounded-md border border-[#0e3a44] bg-[#03070c] p-1.5 text-[#8aa4b8] transition hover:bg-[#061019] hover:text-[#e6edf3]"
          >
            <Bell className="h-3.5 w-3.5" />
          </button>

          {/* Motion toggle — a console watched for hours needs a real way to
              stop things moving, without changing OS settings. */}
          <button
            onClick={() => setCalmMode(!calm)}
            title={
              calm
                ? isAr
                  ? 'استئناف الحركة والرسوم المتحركة'
                  : 'Resume motion'
                : isAr
                  ? 'وضع السكون — إيقاف كل الحركة'
                  : 'Calm mode — stop all motion'
            }
            aria-pressed={calm}
            className={`rounded-md border p-1.5 transition ${
              calm
                ? 'border-[#22d3ee]/40 bg-[#061019] text-[#22d3ee]'
                : 'border-[#0e3a44] bg-[#03070c] text-[#8aa4b8] hover:bg-[#061019] hover:text-[#e6edf3]'
            }`}
          >
            {calm ? <Pause className="h-3.5 w-3.5" /> : <Waves className="h-3.5 w-3.5" />}
          </button>

          {/* SOC Wall Kiosk Launcher Button */}
          {onLaunchKiosk && (
            <button
              onClick={onLaunchKiosk}
              title={isAr ? 'عرض الشاشة الجدارية (SOC Wall Display)' : 'SOC Wall Kiosk Display'}
              className="flex items-center gap-1.5 rounded-md border border-[#10b981]/35 bg-[#061019] px-2.5 py-1 text-[11px] font-bold text-[#10b981] transition hover:border-[#10b981]/60 hover:bg-[#22303f]"
            >
              <Maximize2 className="h-3 w-3" />
              <span className="hidden sm:inline">{isAr ? 'شاشة الجدار' : 'SOC Wall'}</span>
            </button>
          )}

          {/* MoD War Games Simulation Launcher Button */}
          {onLaunchWarGames && (
            <button
              onClick={onLaunchWarGames}
              title={
                isAr
                  ? 'إطلاق مناورات الحرب السيبرانية (VIP MoD Simulation)'
                  : 'Launch MoD War Games Simulation'
              }
              className="flex items-center gap-1.5 rounded-md border border-[#f43f5e]/40 bg-[#061019] px-2.5 py-1 text-[11px] font-bold text-[#f43f5e] transition hover:border-[#f43f5e]/70 hover:bg-[#22303f]"
            >
              <Flame className="h-3 w-3 animate-pulse text-[#f43f5e]" />
              <span className="hidden sm:inline">{isAr ? 'مناورات الدفاع' : 'MoD War Games'}</span>
            </button>
          )}

          {/* Language Toggle */}
          <button
            onClick={() => setLang(isAr ? 'en' : 'ar')}
            className="flex items-center gap-1 rounded-md border border-[#0e3a44] bg-[#03070c] px-2 py-1 text-[11px] text-[#8aa4b8] transition hover:bg-[#061019] hover:text-[#e6edf3]"
          >
            <Globe className="h-3 w-3 text-[#5c7484]" />
            <span>{isAr ? 'EN' : 'عربي'}</span>
          </button>

          {/* Refresh State */}
          <button
            onClick={onRefresh}
            title={isAr ? 'تحديث الحالة' : 'Sync Telemetry'}
            className="rounded-md border border-[#0e3a44] bg-[#03070c] p-1.5 text-[#5c7484] transition hover:bg-[#061019] hover:text-[#e6edf3]"
          >
            <RefreshCw className="h-3 w-3" />
          </button>
        </div>
      </div>
    </header>
  );
};
