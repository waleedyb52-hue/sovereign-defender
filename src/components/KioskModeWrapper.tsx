import React, { useState, useEffect } from 'react';
import { AutonomousThreatMap } from './AutonomousThreatMap';
import { Minimize2, ShieldAlert, Clock } from 'lucide-react';

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

export const KioskModeWrapper: React.FC<KioskModeWrapperProps> = ({ lang = 'ar', onExitKiosk }) => {
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
            reason:
              '[AUTONOMOUS] Algorithmic score 96.4% -> eBPF dropped 4,200 packets from AS13335 (194.26.29.112)'
          },
          {
            id: 'm2',
            timestamp: new Date().toLocaleTimeString(),
            threatScore: 92.1,
            action: 'eBPF_AUTO_DROP',
            ip: '185.220.101.5',
            asn: 'AS208323',
            reason:
              '[AUTONOMOUS] Algorithmic score 92.1% -> eBPF dropped 3,650 packets from AS208323 (185.220.101.5)'
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
    <div className="fixed inset-0 z-[9999] flex flex-col justify-between overflow-hidden bg-[#000000] font-mono text-[#e6edf3] select-none">
      {/* Top SOC Wall Display Minimalist Banner */}
      <div className="absolute top-0 right-0 left-0 z-40 flex items-center justify-between border-b border-[#0e3a44] bg-[#000000]/85 px-6 py-2.5 text-xs backdrop-blur-md">
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2">
            <span className="h-2.5 w-2.5 animate-ping rounded-full bg-[#10b981]" />
            <span className="font-bold tracking-wider text-[#e6edf3]">
              {isAr
                ? 'شاشة جدارية سيادية للتحكم (SOC WALL KIOSK)'
                : 'SOVEREIGN DEFENDER • ZERO-TOUCH SOC WALL DISPLAY'}
            </span>
          </div>
          <span className="text-[#8aa4b8]">|</span>
          <span className="rounded border border-[#10b981]/30 bg-[#10b981]/15 px-2 py-0.5 text-[11px] text-[#10b981]">
            {isAr
              ? 'تتبع آلي عالي الدقة (K-Means Auto-Tracking)'
              : 'K-MEANS AUTONOMOUS TRACKING ACTIVE'}
          </span>
        </div>

        <div className="flex items-center gap-4">
          <div className="flex items-center gap-1.5 text-[11px] text-[#8aa4b8]">
            <Clock className="h-3.5 w-3.5 text-[#10b981]" />
            <span className="font-mono text-[#e6edf3]">{currentTime} UTC</span>
          </div>

          <button
            onClick={onExitKiosk}
            className="flex items-center gap-1.5 rounded border border-[#0e3a44] bg-[#061019] px-3 py-1 text-xs font-bold transition hover:border-[#f43f5e] hover:text-[#f43f5e]"
            title="Press Esc to Exit"
          >
            <Minimize2 className="h-3.5 w-3.5" />
            <span>{isAr ? 'خروج (Esc)' : 'Exit Kiosk (Esc)'}</span>
          </button>
        </div>
      </div>

      {/* Main 3D Geospatial Threat Map Canvas (Full Viewport) */}
      <div className="relative h-full w-full pt-10 pb-12">
        <AutonomousThreatMap lang={lang} isKioskMode={true} onToggleKiosk={onExitKiosk} />
      </div>

      {/* Bottom Autonomous Mitigation Marquee / Auto-Ticker */}
      <div className="absolute right-0 bottom-0 left-0 z-40 flex h-12 items-center overflow-hidden border-t border-[#0e3a44] bg-[#03070c] px-4">
        {/* Ticker Header Tag */}
        <div className="z-10 mr-3 flex shrink-0 items-center gap-2 rounded border border-[#f43f5e]/40 bg-[#f43f5e]/20 px-3 py-1 text-[11px] font-bold text-[#f43f5e] shadow-lg">
          <ShieldAlert className="h-4 w-4 animate-pulse" />
          <span>
            {isAr ? 'شريط التدخل الآلي (eBPF Mitigation Stream)' : 'AUTONOMOUS MITIGATION STREAM'}
          </span>
        </div>

        {/* Continuous Scrolling Auto-Ticker Marquee */}
        <div className="relative flex-1 overflow-hidden">
          <div className="animate-marquee flex items-center gap-8 whitespace-nowrap">
            {[
              ...logs.map(l => ({ ...l, loopSegment: 'alpha', itemUuid: crypto.randomUUID() })),
              ...logs.map(l => ({ ...l, loopSegment: 'beta', itemUuid: crypto.randomUUID() }))
            ].map(log => (
              <div
                key={`kiosk-ticker-${log.itemUuid}`}
                className="flex items-center gap-2.5 rounded border border-[#0e3a44] bg-[#061019] px-3 py-1 text-xs text-[#e6edf3]"
              >
                <span className="text-[10px] text-[#8aa4b8]">{log.timestamp}</span>
                <span className="py-0.2 rounded border border-[#f43f5e]/40 bg-[#f43f5e]/20 px-1.5 text-[10px] font-bold text-[#f43f5e]">
                  {log.threatScore}%
                </span>
                <span className="font-semibold text-[#10b981]">{log.ip}</span>
                <span className="text-[11px] text-[#8aa4b8]">{log.reason}</span>
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
