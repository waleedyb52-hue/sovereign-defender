import React, { useState, useEffect } from 'react';
import { 
  Shield, 
  RefreshCw,
  Bell,
  UserCheck,
  Zap,
  Globe,
  Maximize2,
  Clock,
  Flame
} from 'lucide-react';
import { DefenseFlightMode, AppTab } from '../types';
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
    <header className="border-b border-[#1e2733] bg-[#0d1117] sticky top-0 z-30 h-12 flex items-center select-none font-mono">
      <div className="w-full px-4 flex items-center justify-between">
        
        {/* Brand & System Identity */}
        <div className="flex items-center gap-3">
          <div className="relative">
            <div className="w-7 h-7 rounded bg-[#131a24] flex items-center justify-center border border-[#1e2733]">
              <Shield className="w-4 h-4 text-[#3fb950]" />
            </div>
            <span className="absolute -top-0.5 -right-0.5 flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-[#3fb950] opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2 w-2 bg-[#3fb950]"></span>
            </span>
          </div>

          <div className="flex items-center gap-2">
            <span className="font-bold text-xs text-[#e6edf3] tracking-wider">SOVEREIGN DEFENDER</span>
            <span className="px-1.5 py-0.2 text-[9px] font-bold rounded bg-[#141414] text-[#93a1b3] border border-[#262626]">
              v7.0 eBPF
            </span>
          </div>
        </div>

        {/* Center: Discreet Sovereign Node Coordinates & Live Heartbeat */}
        <div className="hidden md:flex items-center gap-2 text-[11px] text-[#7d8590]">
          <span className="w-1.5 h-1.5 rounded-full bg-[#3fb950]" />
          <span>RIYADH CORE NODE (24.71°N, 46.67°E)</span>
          <span className="text-[#333333]">•</span>
          <div className="flex items-center gap-1 text-[#93a1b3]">
            <Clock className="w-3 h-3 text-[#555555]" />
            <span className="font-mono">{currentTime}</span>
          </div>
        </div>

        {/* Right Controls: Minimalist Flight Mode, Alerts, Kiosk & Lang */}
        <div className="flex items-center gap-2 sm:gap-2.5">
          
          {/* Flight Mode Pill */}
          <div className="flex items-center p-0.5 rounded-md bg-[#131a24] border border-[#222222] text-[11px]">
            <button
              type="button"
              onClick={() => onToggleFlightMode('AUTOPILOT')}
              title={isAr ? 'الوضع الذاتي التلقائي' : 'Auto-Pilot Mode'}
              className={`flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-bold transition ${
                flightMode === 'AUTOPILOT'
                  ? 'bg-[#1A1A1A] text-[#3fb950] shadow-[0_0_8px_rgba(57,255,20,0.15)]'
                  : 'text-[#7d8590] hover:text-[#AAAAAA]'
              }`}
            >
              <Zap className="w-3 h-3" />
              <span className="hidden sm:inline">{isAr ? 'طيار آلي' : 'Auto'}</span>
            </button>

            <button
              type="button"
              onClick={() => onToggleFlightMode('MANUAL_APPROVAL')}
              title={isAr ? 'وضع الموافقة اليدوية' : 'Manual Approval Mode'}
              className={`flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-bold transition ${
                flightMode === 'MANUAL_APPROVAL'
                  ? 'bg-[#1A1A1A] text-[#d29922]'
                  : 'text-[#7d8590] hover:text-[#AAAAAA]'
              }`}
            >
              <UserCheck className="w-3 h-3" />
              <span className="hidden sm:inline">{isAr ? 'يدوي' : 'Manual'}</span>
            </button>
          </div>

          {/* Pending Approvals Badge (Only shows when in Manual mode and > 0) */}
          {flightMode === 'MANUAL_APPROVAL' && pendingApprovalsCount > 0 && (
            <button
              onClick={onOpenApprovalModal}
              className="flex items-center gap-1 px-2 py-1 rounded bg-[#1A1505] text-[#d29922] text-[11px] font-bold border border-[#d29922]/40 transition animate-pulse"
            >
              <UserCheck className="w-3 h-3" />
              <span>{pendingApprovalsCount}</span>
            </button>
          )}

          {/* Multi-Channel Alerts Button */}
          <button
            onClick={onOpenAlertModal}
            title={isAr ? 'إعدادات التنبيهات' : 'Alert Configuration'}
            className="p-1.5 rounded-md bg-[#131a24] hover:bg-[#181818] text-[#93a1b3] hover:text-[#e6edf3] border border-[#222222] transition"
          >
            <Bell className="w-3.5 h-3.5" />
          </button>

          {/* SOC Wall Kiosk Launcher Button */}
          {onLaunchKiosk && (
            <button
              onClick={onLaunchKiosk}
              title={isAr ? 'عرض الشاشة الجدارية (SOC Wall Display)' : 'SOC Wall Kiosk Display'}
              className="flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-[#131a24] hover:bg-[#181818] text-[#3fb950] text-[11px] font-bold border border-[#3fb950]/40 hover:border-[#3fb950] transition"
            >
              <Maximize2 className="w-3 h-3" />
              <span className="hidden sm:inline">{isAr ? 'شاشة الجدار' : 'SOC Wall'}</span>
            </button>
          )}

          {/* MoD War Games Simulation Launcher Button */}
          {onLaunchWarGames && (
            <button
              onClick={onLaunchWarGames}
              title={isAr ? 'إطلاق مناورات الحرب السيبرانية (VIP MoD Simulation)' : 'Launch MoD War Games Simulation'}
              className="flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-[#180508] hover:bg-[#25070C] text-[#f85149] text-[11px] font-bold border border-[#f85149]/60 hover:border-[#f85149] shadow-[0_0_12px_rgba(255,0,60,0.25)] transition"
            >
              <Flame className="w-3 h-3 text-[#f85149] animate-pulse" />
              <span className="hidden sm:inline">{isAr ? 'مناورات الدفاع' : 'MoD War Games'}</span>
            </button>
          )}

          {/* Language Toggle */}
          <button
            onClick={() => setLang(isAr ? 'en' : 'ar')}
            className="flex items-center gap-1 px-2 py-1 rounded-md bg-[#131a24] hover:bg-[#181818] text-[11px] text-[#93a1b3] hover:text-[#e6edf3] border border-[#222222] transition"
          >
            <Globe className="w-3 h-3 text-[#7d8590]" />
            <span>{isAr ? 'EN' : 'عربي'}</span>
          </button>

          {/* Refresh State */}
          <button
            onClick={onRefresh}
            title={isAr ? 'تحديث الحالة' : 'Sync Telemetry'}
            className="p-1.5 rounded-md bg-[#131a24] hover:bg-[#181818] text-[#7d8590] hover:text-[#e6edf3] border border-[#222222] transition"
          >
            <RefreshCw className="w-3 h-3" />
          </button>
        </div>
      </div>
    </header>
  );
};
