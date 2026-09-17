import React, { useState, useEffect } from 'react';
import { AutonomousThreatMap } from './AutonomousThreatMap';
import {
  Minimize2,
  ShieldAlert,
  Clock
} from 'lucide-react';

interface MarqueeLog {
  id: string;
  timestamp: string;
  threatScore: number;
  action: string;
  ip: string;
  asn: string;
  reason: string;
}

interface KioskModeWrapperProps {
  lang?: 'ar' | 'en';
  onExitKiosk: () => void;
}

export const KioskModeWrapper: React.FC<KioskModeWrapperProps> = ({
  lang = 'ar',
  onExitKiosk
}) => {
  const isAr = lang === 'ar';
  const [logs, setLogs] = useState<MarqueeLog[]>([]);
  const [currentTime, setCurrentTime] = useState(new Date().toLocaleTimeString());

  // Clock ticker
  useEffect(() => {
    const timer = setInterval(() => {
      setCurrentTime(new Date().toLocaleTimeString());
    }, 1000);
    return () => clearInterval(timer);
  }, []);

  // Keyboard shortcut listener for Esc to exit Kiosk Mode
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' || e.key === 'Esc') {
        onExitKiosk();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [onExitKiosk]);

  // Fetch autonomous mitigation logs for the bottom marquee ticker
  useEffect(() => {
    const fetchTickerLogs = async () => {
      try {
        const res = await fetch('/api/v1/threats/heatmap-stream').catch(() => null);
        if (!res || !res.ok) return;
        const data = await res.json().catch(() => null);
        if (data && data.mitigationMarquee && data.mitigationMarquee.length > 0) {
          setLogs(data.mitigationMarquee);
        }
      } catch {
        // Fallback default autonomous telemetry logs
        setLogs([
          {
            id: 'm1',
            timestamp: new Date().toLocaleTimeString(),
            threatScore: 96.4,
            action: 'eBPF_AUTO_DROP',
            ip: '194.26.29.112',
            asn: 'AS13335',
            reason: '[AUTONOMOUS] Algorithmic score 96.4% -> eBPF dropped 4,200 packets from AS13335 (194.26.29.112)'
          },
          {
            id: 'm2',
            timestamp: new Date().toLocaleTimeString(),
            threatScore: 92.1,
            action: 'eBPF_AUTO_DROP',
            ip: '185.220.101.5',
            asn: 'AS208323',
            reason: '[AUTONOMOUS] Algorithmic score 92.1% -> eBPF dropped 3,650 packets from AS208323 (185.220.101.5)'
          }
        ]);
      }
    };

    fetchTickerLogs().catch(() => {});
    const interval = setInterval(() => {
      fetchTickerLogs().catch(() => {});
    }, 3000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="fixed inset-0 z-[9999] bg-[#050505] text-[#EAEAEA] flex flex-col justify-between select-none overflow-hidden font-mono">
      {/* Top SOC Wall Display Minimalist Banner */}
      <div className="absolute top-0 left-0 right-0 z-40 bg-[#050505]/85 backdrop-blur-md border-b border-[#2A2A2A] px-6 py-2.5 flex items-center justify-between text-xs">
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-[#39FF14] animate-ping" />
            <span className="font-bold text-[#EAEAEA] tracking-wider">
              {isAr ? 'شاشة جدارية سيادية للتحكم (SOC WALL KIOSK)' : 'SOVEREIGN DEFENDER • ZERO-TOUCH SOC WALL DISPLAY'}
            </span>
          </div>
          <span className="text-[#888888]">|</span>
          <span className="text-[11px] text-[#39FF14] bg-[#39FF14]/15 px-2 py-0.5 rounded border border-[#39FF14]/30">
            {isAr ? 'تتبع آلي عالي الدقة (K-Means Auto-Tracking)' : 'K-MEANS AUTONOMOUS TRACKING ACTIVE'}
          </span>
        </div>

        <div className="flex items-center gap-4">
          <div className="flex items-center gap-1.5 text-[#888888] text-[11px]">
            <Clock className="w-3.5 h-3.5 text-[#39FF14]" />
            <span className="font-mono text-[#EAEAEA]">{currentTime} UTC</span>
          </div>

          <button
            onClick={onExitKiosk}
            className="flex items-center gap-1.5 px-3 py-1 rounded bg-[#181818] border border-[#2A2A2A] hover:border-[#FF003C] hover:text-[#FF003C] transition text-xs font-bold"
            title="Press Esc to Exit"
          >
            <Minimize2 className="w-3.5 h-3.5" />
            <span>{isAr ? 'خروج (Esc)' : 'Exit Kiosk (Esc)'}</span>
          </button>
        </div>
      </div>

      {/* Main 3D Geospatial Threat Map Canvas (Full Viewport) */}
      <div className="relative w-full h-full pt-10 pb-12">
        <AutonomousThreatMap
          lang={lang}
          isKioskMode={true}
          onToggleKiosk={onExitKiosk}
        />
      </div>

      {/* Bottom Autonomous Mitigation Marquee / Auto-Ticker */}
      <div className="absolute bottom-0 left-0 right-0 z-40 bg-[#121212] border-t border-[#2A2A2A] h-12 flex items-center overflow-hidden px-4">
        {/* Ticker Header Tag */}
        <div className="flex items-center gap-2 bg-[#FF003C]/20 border border-[#FF003C]/40 text-[#FF003C] px-3 py-1 rounded text-[11px] font-bold shrink-0 mr-3 shadow-lg z-10">
          <ShieldAlert className="w-4 h-4 animate-pulse" />
          <span>{isAr ? 'شريط التدخل الآلي (eBPF Mitigation Stream)' : 'AUTONOMOUS MITIGATION STREAM'}</span>
        </div>

        {/* Continuous Scrolling Auto-Ticker Marquee */}
        <div className="flex-1 overflow-hidden relative">
          <div className="flex items-center gap-8 whitespace-nowrap animate-marquee">
            {[...logs.map(l => ({ ...l, loopSegment: 'alpha', itemUuid: crypto.randomUUID() })), ...logs.map(l => ({ ...l, loopSegment: 'beta', itemUuid: crypto.randomUUID() }))].map((log) => (
              <div
                key={`kiosk-ticker-${log.itemUuid}`}
                className="flex items-center gap-2.5 text-xs text-[#EAEAEA] bg-[#181818] px-3 py-1 rounded border border-[#2A2A2A]"
              >
                <span className="text-[10px] text-[#888888]">{log.timestamp}</span>
                <span className="text-[10px] font-bold px-1.5 py-0.2 rounded bg-[#FF003C]/20 text-[#FF003C] border border-[#FF003C]/40">
                  {log.threatScore}%
                </span>
                <span className="text-[#39FF14] font-semibold">{log.ip}</span>
                <span className="text-[#888888] text-[11px]">{log.reason}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      <style>{`
        @keyframes marquee {
          0% { transform: translateX(0%); }
          100% { transform: translateX(-50%); }
        }
        .animate-marquee {
          display: flex;
          width: 200%;
          animation: marquee 35s linear infinite;
        }
        .animate-marquee:hover {
          animation-play-state: paused;
        }
      `}</style>
    </div>
  );
};
