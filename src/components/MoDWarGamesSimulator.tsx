import React, { useState, useEffect, useRef } from 'react';
import {
  ShieldCheck,
  Zap,
  Lock,
  Unlock,
  Radio,
  AlertTriangle,
  FileText,
  Clock,
  CheckCircle2,
  XCircle,
  Download,
  RotateCcw,
  UserX,
  Key,
  Flame,
  Activity,
  Sparkles,
  Play
} from 'lucide-react';

export type WarGamePhase = 
  | 'STANDBY' 
  | 'PHASE_1_DDOS' 
  | 'PHASE_2_APT' 
  | 'PHASE_3_EBPF_KILLCHAIN' 
  | 'PHASE_4_INSIDER' 
  | 'REPORT_READY';

interface MoDWarGamesSimulatorProps {
  isOpen: boolean;
  onClose: () => void;
  lang: 'ar' | 'en';
  onForceHeatmapTab?: () => void;
}

// Sound effects synthesizer via Web Audio API (Zero external assets, guaranteed reliability)
class CyberAudioSynthesizer {
  private ctx: AudioContext | null = null;

  private init() {
    if (!this.ctx && typeof window !== 'undefined') {
      const AudioCtx = window.AudioContext || (window as any).webkitAudioContext;
      if (AudioCtx) {
        this.ctx = new AudioCtx();
      }
    }
    if (this.ctx && this.ctx.state === 'suspended') {
      this.ctx.resume().catch(() => {});
    }
  }

  public playRadarPing() {
    try {
      this.init();
      if (!this.ctx) return;
      const osc = this.ctx.createOscillator();
      const gain = this.ctx.createGain();
      osc.type = 'sine';
      osc.frequency.setValueAtTime(880, this.ctx.currentTime);
      osc.frequency.exponentialRampToValueAtTime(440, this.ctx.currentTime + 0.35);
      gain.gain.setValueAtTime(0.15, this.ctx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.001, this.ctx.currentTime + 0.35);
      osc.connect(gain);
      gain.connect(this.ctx.destination);
      osc.start();
      osc.stop(this.ctx.currentTime + 0.35);
    } catch {
      // Audio not permitted or supported
    }
  }

  public playCriticalAlarm() {
    try {
      this.init();
      if (!this.ctx) return;
      const now = this.ctx.currentTime;
      const osc = this.ctx.createOscillator();
      const gain = this.ctx.createGain();
      osc.type = 'sawtooth';
      osc.frequency.setValueAtTime(520, now);
      osc.frequency.linearRampToValueAtTime(820, now + 0.15);
      osc.frequency.linearRampToValueAtTime(520, now + 0.3);
      gain.gain.setValueAtTime(0.22, now);
      gain.gain.exponentialRampToValueAtTime(0.01, now + 0.45);
      osc.connect(gain);
      gain.connect(this.ctx.destination);
      osc.start(now);
      osc.stop(now + 0.45);
    } catch {
      // Ignore
    }
  }

  public playEbpfShatter() {
    try {
      this.init();
      if (!this.ctx) return;
      const now = this.ctx.currentTime;
      // White noise blast + descending sweep
      const bufferSize = this.ctx.sampleRate * 0.25;
      const buffer = this.ctx.createBuffer(1, bufferSize, this.ctx.sampleRate);
      const data = buffer.getChannelData(0);
      for (let i = 0; i < bufferSize; i++) {
        data[i] = (Math.random() * 2 - 1) * Math.exp(-i / (bufferSize * 0.3));
      }
      const noise = this.ctx.createBufferSource();
      noise.buffer = buffer;
      const filter = this.ctx.createBiquadFilter();
      filter.type = 'bandpass';
      filter.frequency.setValueAtTime(1400, now);
      filter.Q.setValueAtTime(3, now);
      const gain = this.ctx.createGain();
      gain.gain.setValueAtTime(0.25, now);
      gain.gain.exponentialRampToValueAtTime(0.01, now + 0.3);
      noise.connect(filter);
      filter.connect(gain);
      gain.connect(this.ctx.destination);
      noise.start(now);
    } catch {
      // Ignore
    }
  }

  public playZeroTrustLock() {
    try {
      this.init();
      if (!this.ctx) return;
      const now = this.ctx.currentTime;
      const osc = this.ctx.createOscillator();
      const gain = this.ctx.createGain();
      osc.type = 'square';
      osc.frequency.setValueAtTime(300, now);
      osc.frequency.setValueAtTime(150, now + 0.1);
      gain.gain.setValueAtTime(0.2, now);
      gain.gain.exponentialRampToValueAtTime(0.01, now + 0.25);
      osc.connect(gain);
      gain.connect(this.ctx.destination);
      osc.start(now);
      osc.stop(now + 0.25);
    } catch {
      // Ignore
    }
  }

  public playSuccessChime() {
    try {
      this.init();
      if (!this.ctx) return;
      const notes = [523.25, 659.25, 783.99, 1046.5]; // C5, E5, G5, C6
      notes.forEach((freq, idx) => {
        const osc = this.ctx!.createOscillator();
        const gain = this.ctx!.createGain();
        const start = this.ctx!.currentTime + idx * 0.08;
        osc.type = 'sine';
        osc.frequency.setValueAtTime(freq, start);
        gain.gain.setValueAtTime(0.12, start);
        gain.gain.exponentialRampToValueAtTime(0.001, start + 0.4);
        osc.connect(gain);
        gain.connect(this.ctx!.destination);
        osc.start(start);
        osc.stop(start + 0.4);
      });
    } catch {
      // Ignore
    }
  }
}

const audioSynth = new CyberAudioSynthesizer();

export const MoDWarGamesSimulator: React.FC<MoDWarGamesSimulatorProps> = ({
  isOpen,
  onClose,
  lang,
  onForceHeatmapTab
}) => {
  const isAr = lang === 'ar';

  // VIP Authentication Gate State
  const [isAuthenticated, setIsAuthenticated] = useState<boolean>(false);
  const [vipPasswordInput, setVipPasswordInput] = useState<string>('');
  const [authError, setAuthError] = useState<string | null>(null);

  // Simulation State Machine
  const [phase, setPhase] = useState<WarGamePhase>('STANDBY');
  const [elapsedMs, setElapsedMs] = useState<number>(0);
  const [simRunning, setSimRunning] = useState<boolean>(false);

  // Phase 4 Zero-Trust OTP State
  const [showOtpModal, setShowOtpModal] = useState<boolean>(false);
  const [otpInput, setOtpInput] = useState<string>('');
  const [otpApproving, setOtpApproving] = useState<boolean>(false);

  // Post-Action Report State
  const [soarReport, setSoarReport] = useState<any | null>(null);
  const [reportCopied, setReportCopied] = useState<boolean>(false);

  // Live Simulation Metrics
  const [liveThroughputGbps, setLiveThroughputGbps] = useState<number>(48.2);
  const [liveEntropy, setLiveEntropy] = useState<number>(4.12);
  const [liveDroppedPkts, setLiveDroppedPkts] = useState<number>(0);
  const [activeVectorCount, setActiveVectorCount] = useState<number>(14);

  const timerRef = useRef<NodeJS.Timeout | null>(null);
  const startTimeRef = useRef<number>(0);

  // Handle VIP Password Auth
  const handleVipSubmit = (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    const cleanKey = vipPasswordInput.trim().toUpperCase();
    if (cleanKey === 'MOD-DEFENSE-2026' || cleanKey === 'MOD' || cleanKey === 'VIP-CYBER-WAR' || cleanKey === '1234') {
      setIsAuthenticated(true);
      setAuthError(null);
      audioSynth.playRadarPing();
    } else {
      setAuthError(isAr ? 'رمز التفويض غير صحيح. يرجى إدخال المفتاح الرئاسي المعتمد.' : 'Invalid VIP Authorization Key.');
    }
  };

  const handleQuickVipAutoFill = () => {
    setVipPasswordInput('MOD-DEFENSE-2026');
    setIsAuthenticated(true);
    setAuthError(null);
    audioSynth.playRadarPing();
  };

  // Timer loop when simulation is running
  useEffect(() => {
    if (!simRunning) {
      if (timerRef.current) clearInterval(timerRef.current);
      return;
    }

    startTimeRef.current = Date.now() - elapsedMs;
    timerRef.current = setInterval(() => {
      const now = Date.now();
      const currentElapsed = now - startTimeRef.current;
      setElapsedMs(currentElapsed);

      // Automated Narrative Transition Engine
      // Phase 1: T+0s to T+5000ms
      // Phase 2: T+5000ms to T+8000ms
      // Phase 3: T+8000ms to T+12000ms
      // Phase 4: T+12000ms (Freezes UI with Zero-Trust OTP modal)
      if (currentElapsed >= 12000 && phase === 'PHASE_3_EBPF_KILLCHAIN') {
        triggerPhase4Insider();
      } else if (currentElapsed >= 8000 && phase === 'PHASE_2_APT') {
        triggerPhase3Ebpf();
      } else if (currentElapsed >= 5000 && phase === 'PHASE_1_DDOS') {
        triggerPhase2Apt();
      }
    }, 100);

    return () => {
      if (timerRef.current) clearInterval(timerRef.current);
    };
  }, [simRunning, phase, elapsedMs]);

  // Start War Games Simulation Sequence
  const handleStartWarGames = async () => {
    if (onForceHeatmapTab) {
      onForceHeatmapTab();
    }

    setElapsedMs(0);
    setPhase('PHASE_1_DDOS');
    setSimRunning(true);
    setShowOtpModal(false);
    setSoarReport(null);
    setLiveThroughputGbps(184.6);
    setLiveEntropy(4.85);
    setLiveDroppedPkts(0);
    setActiveVectorCount(54);

    audioSynth.playRadarPing();

    try {
      await fetch('/api/v1/wargames/phase1-ddos', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
      }).catch(() => null);
    } catch {
      // Graceful fallback
    }
  };

  // Step 2: Trigger Phase 2 (Concentrated APT Payload)
  const triggerPhase2Apt = async () => {
    setPhase('PHASE_2_APT');
    setLiveThroughputGbps(412.0);
    setLiveEntropy(7.99); // Critical Shannon Entropy
    audioSynth.playCriticalAlarm();

    try {
      await fetch('/api/v1/wargames/phase2-apt', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
      }).catch(() => null);
    } catch {
      // Graceful fallback
    }
  };

  // Step 3: Trigger Phase 3 (Autonomous eBPF Killchain)
  const triggerPhase3Ebpf = async () => {
    setPhase('PHASE_3_EBPF_KILLCHAIN');
    setLiveEntropy(1.42);
    setLiveDroppedPkts(48200);
    audioSynth.playEbpfShatter();

    try {
      await fetch('/api/v1/wargames/phase3-ebpf', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
      }).catch(() => null);
    } catch {
      // Graceful fallback
    }
  };

  // Step 4: Trigger Phase 4 (Insider Threat Rogue Admin)
  const triggerPhase4Insider = async () => {
    setSimRunning(false); // Freeze timer
    setPhase('PHASE_4_INSIDER');
    setShowOtpModal(true);
    audioSynth.playZeroTrustLock();

    try {
      await fetch('/api/v1/wargames/phase4-insider', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
      }).catch(() => null);
    } catch {
      // Graceful fallback
    }
  };

  // Handle Dual-Key OTP Verification
  const handleAuthorizeOtp = async (overrideValue?: string) => {
    setOtpApproving(true);
    const code = overrideValue || otpInput || '992814';

    try {
      const res = await fetch('/api/v1/wargames/phase4-authorize', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ otp: code, approver: 'MoD Executive General' })
      }).catch(() => null);

      if (res && res.ok) {
        const data = await res.json().catch(() => null);
        if (data && data.soarReport) {
          setSoarReport(data.soarReport);
          setShowOtpModal(false);
          setPhase('REPORT_READY');
          audioSynth.playSuccessChime();
        }
      }
    } catch {
      // Graceful error handling
    } finally {
      setOtpApproving(false);
    }
  };

  // Clean Reset
  const handleResetSimulation = async () => {
    setSimRunning(false);
    setPhase('STANDBY');
    setElapsedMs(0);
    setShowOtpModal(false);
    setSoarReport(null);
    setLiveThroughputGbps(48.2);
    setLiveEntropy(4.12);
    setLiveDroppedPkts(0);
    setActiveVectorCount(14);

    try {
      await fetch('/api/v1/wargames/reset', { method: 'POST' }).catch(() => null);
    } catch {
      // Graceful fallback
    }
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/85 backdrop-blur-md font-mono select-none p-4 overflow-y-auto">
      
      {/* 1. VIP LOGIN AUTHENTICATION GATE */}
      {!isAuthenticated && (
        <div className="relative w-full max-w-lg bg-[#0A0A0A] border-2 border-[#FFB000]/60 rounded-2xl shadow-[0_0_60px_rgba(255,176,0,0.25)] p-6 sm:p-8 text-center">
          <div className="mx-auto w-14 h-14 rounded-2xl bg-[#FFB000]/10 border border-[#FFB000]/40 flex items-center justify-center mb-4">
            <Lock className="w-7 h-7 text-[#FFB000] animate-pulse" />
          </div>

          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-[#FFB000]/10 border border-[#FFB000]/30 text-[#FFB000] text-[11px] font-bold uppercase tracking-widest mb-2">
            <span>{isAr ? 'وزارة الدفاع • بوابة المحاكاة السرية' : 'MINISTRY OF DEFENSE • VIP WAR GAMES PORTAL'}</span>
          </div>

          <h2 className="text-xl sm:text-2xl font-black text-white tracking-wide mt-1">
            {isAr ? 'محاكي مناورات الحرب السيبرانية' : 'Red Team War Games Simulator'}
          </h2>
          <p className="text-xs text-[#888888] mt-2 max-w-sm mx-auto">
            {isAr 
              ? 'مخصص للعروض الحية والتنفيذية أمام قيادات وزارة الدفاع. يتطلب إدخال مفتاح التفويض السيادي للبدء.'
              : 'Authorized executive presentation mode for high-stakes MoD demonstrations.'}
          </p>

          <form onSubmit={handleVipSubmit} className="mt-6 space-y-4">
            <div>
              <input
                type="password"
                value={vipPasswordInput}
                onChange={(e) => setVipPasswordInput(e.target.value)}
                placeholder="ENTER VIP PASSCODE"
                className="w-full text-center bg-[#141414] border border-[#333333] focus:border-[#FFB000] rounded-xl px-4 py-3 text-sm text-white tracking-widest uppercase outline-none transition"
              />
              {authError && (
                <div className="text-[11px] text-[#FF003C] mt-2 font-bold">{authError}</div>
              )}
            </div>

            <div className="flex flex-col sm:flex-row gap-2">
              <button
                type="submit"
                className="flex-1 bg-[#FFB000] hover:bg-[#FFB000]/90 text-black font-black py-2.5 px-4 rounded-xl text-xs uppercase tracking-wider transition flex items-center justify-center gap-2 shadow-lg shadow-[#FFB000]/20"
              >
                <Unlock className="w-4 h-4" />
                <span>{isAr ? 'تحقق وبدء المحاكاة' : 'Authenticate & Unlock'}</span>
              </button>

              <button
                type="button"
                onClick={handleQuickVipAutoFill}
                className="bg-[#181818] hover:bg-[#222222] border border-[#333333] text-[#FFB000] font-bold py-2.5 px-4 rounded-xl text-xs transition flex items-center justify-center gap-1.5"
                title="Auto-fill default presentation passcode"
              >
                <Sparkles className="w-3.5 h-3.5" />
                <span>{isAr ? 'تعبئة سريعة (VIP Demo)' : '1-Click Demo Auth'}</span>
              </button>
            </div>
          </form>

          <div className="mt-6 pt-4 border-t border-[#1E1E1E] flex items-center justify-between text-[10px] text-[#666666]">
            <span>CLEARANCE: TOP SECRET // SCDS-V9</span>
            <button
              onClick={onClose}
              className="text-[#888888] hover:text-white transition"
            >
              {isAr ? 'إلغاء والعودة' : 'Cancel'}
            </button>
          </div>
        </div>
      )}

      {/* 2. AUTHENTICATED WAR GAMES STAGE CONTROLLER */}
      {isAuthenticated && (
        <div className="relative w-full max-w-5xl bg-[#0A0A0A] border-2 border-[#FF003C]/50 rounded-2xl shadow-[0_0_80px_rgba(255,0,60,0.3)] overflow-hidden flex flex-col max-h-[92vh]">
          
          {/* Header Bar */}
          <div className="px-6 py-4 bg-[#101010] border-b border-[#222222] flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="w-9 h-9 rounded-xl bg-[#FF003C]/20 border border-[#FF003C]/60 flex items-center justify-center">
                <Flame className="w-5 h-5 text-[#FF003C] animate-pulse" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <h3 className="font-black text-white text-base tracking-wide">
                    {isAr ? 'مناورات الحرب السيبرانية • القيادة العامة' : 'MoD WAR GAMES • RED TEAM EMULATOR'}
                  </h3>
                  <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-[#FF003C]/20 text-[#FF003C] border border-[#FF003C]/40">
                    EXECUTIVE VIP
                  </span>
                </div>
                <div className="text-xs text-[#888888]">
                  {isAr 
                    ? 'محاكاة هجوم سيبراني متعدد المحاور (DDoS + APT + eBPF Killchain + Insider)'
                    : 'Real-time multi-vector red team scenario demonstrating autonomous zero-trust containment.'}
                </div>
              </div>
            </div>

            {/* Close / Abort Button */}
            <div className="flex items-center gap-2">
              <button
                onClick={handleResetSimulation}
                title="Reset simulation state"
                className="p-2 rounded-lg bg-[#181818] hover:bg-[#222222] text-[#888888] hover:text-white border border-[#333333] transition"
              >
                <RotateCcw className="w-4 h-4" />
              </button>
              <button
                onClick={onClose}
                className="p-2 rounded-lg bg-[#181818] hover:bg-[#FF003C]/20 text-[#888888] hover:text-[#FF003C] border border-[#333333] transition"
              >
                <XCircle className="w-4 h-4" />
              </button>
            </div>
          </div>

          {/* Tactical HUD Breadcrumbs Timeline */}
          <div className="px-6 py-3 bg-[#0E0E0E] border-b border-[#1E1E1E] grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs">
            {/* Step 1 */}
            <div className={`p-2.5 rounded-lg border flex flex-col justify-between transition ${
              phase === 'PHASE_1_DDOS' 
                ? 'bg-[#FFB000]/20 border-[#FFB000] text-white shadow-[0_0_15px_rgba(255,176,0,0.3)] animate-pulse' 
                : phase !== 'STANDBY' 
                  ? 'bg-[#121212] border-emerald-500/40 text-emerald-400' 
                  : 'bg-[#121212] border-[#222222] text-[#666666]'
            }`}>
              <div className="flex items-center justify-between text-[10px] font-bold">
                <span>T+0s • PHASE 1</span>
                {phase !== 'STANDBY' && phase !== 'PHASE_1_DDOS' && <CheckCircle2 className="w-3 h-3 text-emerald-400" />}
              </div>
              <div className="font-bold mt-1 text-[11px] truncate">
                {isAr ? 'مسح حجب الخدمة (DDoS)' : 'Global DDoS Scan'}
              </div>
              <div className="text-[9px] opacity-75 mt-0.5">54 Botnet Vectors</div>
            </div>

            {/* Step 2 */}
            <div className={`p-2.5 rounded-lg border flex flex-col justify-between transition ${
              phase === 'PHASE_2_APT' 
                ? 'bg-[#FF003C]/20 border-[#FF003C] text-white shadow-[0_0_15px_rgba(255,0,60,0.3)] animate-pulse' 
                : (phase === 'PHASE_3_EBPF_KILLCHAIN' || phase === 'PHASE_4_INSIDER' || phase === 'REPORT_READY') 
                  ? 'bg-[#121212] border-emerald-500/40 text-emerald-400' 
                  : 'bg-[#121212] border-[#222222] text-[#666666]'
            }`}>
              <div className="flex items-center justify-between text-[10px] font-bold">
                <span>T+5s • PHASE 2</span>
                {(phase === 'PHASE_3_EBPF_KILLCHAIN' || phase === 'PHASE_4_INSIDER' || phase === 'REPORT_READY') && (
                  <CheckCircle2 className="w-3 h-3 text-emerald-400" />
                )}
              </div>
              <div className="font-bold mt-1 text-[11px] truncate">
                {isAr ? 'حمولة APT مركزة' : 'Targeted APT Payload'}
              </div>
              <div className="text-[9px] opacity-75 mt-0.5">Entropy: 7.99 bits</div>
            </div>

            {/* Step 3 */}
            <div className={`p-2.5 rounded-lg border flex flex-col justify-between transition ${
              phase === 'PHASE_3_EBPF_KILLCHAIN' 
                ? 'bg-cyan-500/20 border-cyan-500 text-white shadow-[0_0_15px_rgba(6,182,212,0.3)] animate-pulse' 
                : (phase === 'PHASE_4_INSIDER' || phase === 'REPORT_READY') 
                  ? 'bg-[#121212] border-emerald-500/40 text-emerald-400' 
                  : 'bg-[#121212] border-[#222222] text-[#666666]'
            }`}>
              <div className="flex items-center justify-between text-[10px] font-bold">
                <span>T+8s • PHASE 3</span>
                {(phase === 'PHASE_4_INSIDER' || phase === 'REPORT_READY') && (
                  <CheckCircle2 className="w-3 h-3 text-emerald-400" />
                )}
              </div>
              <div className="font-bold mt-1 text-[11px] truncate">
                {isAr ? 'إسقاط eBPF بالنواة' : 'Autonomous eBPF Drop'}
              </div>
              <div className="text-[9px] opacity-75 mt-0.5">0.31µs Zero-Copy</div>
            </div>

            {/* Step 4 */}
            <div className={`p-2.5 rounded-lg border flex flex-col justify-between transition ${
              phase === 'PHASE_4_INSIDER' 
                ? 'bg-[#FF003C]/30 border-[#FF003C] text-white shadow-[0_0_15px_rgba(255,0,60,0.4)] animate-pulse' 
                : phase === 'REPORT_READY' 
                  ? 'bg-[#121212] border-emerald-500/40 text-emerald-400' 
                  : 'bg-[#121212] border-[#222222] text-[#666666]'
            }`}>
              <div className="flex items-center justify-between text-[10px] font-bold">
                <span>T+12s • PHASE 4</span>
                {phase === 'REPORT_READY' && <CheckCircle2 className="w-3 h-3 text-emerald-400" />}
              </div>
              <div className="font-bold mt-1 text-[11px] truncate">
                {isAr ? 'اعتراض التهديد الداخلي' : 'Insider Log Purge'}
              </div>
              <div className="text-[9px] opacity-75 mt-0.5">Zero-Trust OTP Lock</div>
            </div>
          </div>

          {/* Main Stage Viewport */}
          <div className="p-6 overflow-y-auto space-y-6">

            {/* Standby Launch Hero Banner */}
            {phase === 'STANDBY' && (
              <div className="rounded-2xl bg-gradient-to-b from-[#141414] to-[#0A0A0A] border border-[#222222] p-6 sm:p-8 text-center space-y-5">
                <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-[#FF003C]/10 border border-[#FF003C]/30 text-[#FF003C] text-xs font-bold">
                  <Radio className="w-3.5 h-3.5 animate-pulse" />
                  <span>{isAr ? 'جاهز للإطلاق المباشر في العرض' : 'ARMED & READY FOR LIVE VIP PRESENTATION'}</span>
                </div>

                <div className="max-w-2xl mx-auto">
                  <h4 className="text-xl sm:text-2xl font-black text-white">
                    {isAr ? 'محاكاة سيناريو الهجوم المعقد ضد النواة السيادية' : 'Sovereign Core Live Red Team Cyber Engagement'}
                  </h4>
                  <p className="text-xs text-[#888888] mt-2 leading-relaxed">
                    {isAr 
                      ? 'سيناريو تدريبي متكامل مدته 16 ثانية يحاكي هجوماً منسقاً: مسح استطلاعي بـ 54 روبوت، يليه استهداف مركز بحمولة تشفيرية APT، وتفعيل الإسقاط الذاتي في نواة لينكس (eBPF XDP)، ثم تجميد محاولة مستخدم داخلي لحذف السجلات عبر مصادقة انعدام الثقة.'
                      : 'A cinematic 16-second narrative: Injects 54 botnet scanners, fires a concentrated high-entropy APT laser, autonomously engages Linux eBPF zero-copy drop, and traps a rogue admin attempting log deletion.'}
                  </p>
                </div>

                <div className="pt-2">
                  <button
                    onClick={handleStartWarGames}
                    className="inline-flex items-center gap-3 px-8 py-4 rounded-xl bg-gradient-to-r from-[#FF003C] to-[#E60033] hover:from-[#FF1A4D] hover:to-[#FF003C] text-white font-black text-sm uppercase tracking-wider shadow-[0_0_30px_rgba(255,0,60,0.4)] transition transform hover:scale-[1.02] active:scale-[0.98]"
                  >
                    <Play className="w-5 h-5 fill-current" />
                    <span>{isAr ? 'إطلاق مناورات الحرب السيبرانية (START SIMULATION)' : 'Launch MoD War Games Simulation'}</span>
                  </button>
                </div>
              </div>
            )}

            {/* Active Simulation Visual HUD */}
            {phase !== 'STANDBY' && phase !== 'REPORT_READY' && (
              <div className="space-y-4">
                
                {/* Real-time Telemetry Dashboard Strip */}
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                  <div className="bg-[#121212] border border-[#222222] rounded-xl p-3.5">
                    <div className="text-[10px] text-[#888888] uppercase font-bold">{isAr ? 'زمن المحاكاة' : 'Scenario Clock'}</div>
                    <div className="text-xl font-black text-[#FFB000] font-mono mt-0.5">
                      T+{(elapsedMs / 1000).toFixed(2)}s
                    </div>
                  </div>

                  <div className="bg-[#121212] border border-[#222222] rounded-xl p-3.5">
                    <div className="text-[10px] text-[#888888] uppercase font-bold">{isAr ? 'معدل تدفق الحزم' : 'Live Ingress Load'}</div>
                    <div className="text-xl font-black text-white font-mono mt-0.5">
                      {liveThroughputGbps.toFixed(1)} <span className="text-xs text-[#888888]">Gbps</span>
                    </div>
                  </div>

                  <div className={`bg-[#121212] border rounded-xl p-3.5 transition ${
                    liveEntropy > 7.0 ? 'border-[#FF003C]/60 bg-[#FF003C]/10' : 'border-[#222222]'
                  }`}>
                    <div className="text-[10px] text-[#888888] uppercase font-bold">{isAr ? 'إنتروبيا شانون' : 'Shannon Entropy'}</div>
                    <div className={`text-xl font-black font-mono mt-0.5 ${
                      liveEntropy > 7.0 ? 'text-[#FF003C] animate-pulse' : 'text-emerald-400'
                    }`}>
                      {liveEntropy.toFixed(2)} <span className="text-xs">bits/byte</span>
                    </div>
                  </div>

                  <div className="bg-[#121212] border border-cyan-500/40 bg-cyan-950/10 rounded-xl p-3.5">
                    <div className="text-[10px] text-cyan-400 uppercase font-bold">{isAr ? 'إسقاط eBPF بالنواة' : 'Kernel XDP Drops'}</div>
                    <div className="text-xl font-black text-cyan-400 font-mono mt-0.5">
                      {liveDroppedPkts.toLocaleString()} <span className="text-xs">pkts</span>
                    </div>
                  </div>
                </div>

                {/* Phase 1 Live Callout */}
                {phase === 'PHASE_1_DDOS' && (
                  <div className="bg-[#141414] border-2 border-[#FFB000]/60 rounded-xl p-5 shadow-[0_0_30px_rgba(255,176,0,0.15)] space-y-2">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2 text-[#FFB000] font-bold text-sm">
                        <Activity className="w-4 h-4 animate-spin" />
                        <span>{isAr ? 'المرحلة 1: مسح حجب الخدمة الموزع (54 روبوت)' : 'PHASE 1: GLOBAL DISTRIBUTED DDOS SCAN (54 BOTS)'}</span>
                      </div>
                      <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-[#FFB000]/20 text-[#FFB000]">
                        AI NOISE FILTER: MONITORING
                      </span>
                    </div>
                    <p className="text-xs text-[#CCCCCC] leading-relaxed">
                      {isAr 
                        ? 'المنظومة ترصد تذبذب الحزم وتتعرف على الـ 54 متجهاً هجومياً، مع تفعيل مرشح الضوضاء الذكي لتفادي الإسقاط العشوائي المبكر للحفاظ على سلاسة الخدمة.'
                        : 'Autonomous AI engine evaluates volumetric dispersion across Europe, Asia, and Americas. Vectors remain monitored under noise threshold without premature drops.'}
                    </p>
                  </div>
                )}

                {/* Phase 2 Live Callout */}
                {phase === 'PHASE_2_APT' && (
                  <div className="bg-[#160507] border-2 border-[#FF003C] rounded-xl p-5 shadow-[0_0_40px_rgba(255,0,60,0.3)] space-y-2 animate-pulse">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2 text-[#FF003C] font-black text-sm">
                        <AlertTriangle className="w-4 h-4 animate-bounce" />
                        <span>{isAr ? 'المرحلة 2: شعاع ليزري مركز بحمولة APT نحو العقدة السيادية' : 'PHASE 2: CONCENTRATED APT ZERO-DAY LASER TARGETING RIYADH NODE'}</span>
                      </div>
                      <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-[#FF003C] text-white font-bold">
                        THREAT SCORE: 98% CRITICAL
                      </span>
                    </div>
                    <p className="text-xs text-[#FF8099] leading-relaxed">
                      {isAr 
                        ? 'ارتفاع إنتروبيا شانون إلى 7.99 بت/بايت يشير إلى حمولة برمجية خبيثة متعددة الأشكال تحاول تجاوز الجدار الناري والتسرب إلى العقدة المركزية!'
                        : 'Shannon entropy spikes to 7.99 bits/byte. High cryptographic obfuscation detected. Laser vector focusing energy on Riyadh Central Datacenter!'}
                    </p>
                  </div>
                )}

                {/* Phase 3 Live Callout */}
                {phase === 'PHASE_3_EBPF_KILLCHAIN' && (
                  <div className="bg-cyan-950/20 border-2 border-cyan-400 rounded-xl p-5 shadow-[0_0_40px_rgba(6,182,212,0.3)] space-y-2">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2 text-cyan-400 font-black text-sm">
                        <Zap className="w-4 h-4 animate-pulse" />
                        <span>{isAr ? 'المرحلة 3: تفعيل الإسقاط العتادي الفوري بنواة لينكس (eBPF XDP)' : 'PHASE 3: KERNEL XDP ISOLATION ENGAGED (0.31µs ZERO-COPY)'}</span>
                      </div>
                      <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-cyan-400 text-black font-black">
                        BPF_MAP_TYPE_HASH: XDP_DROP
                      </span>
                    </div>
                    <p className="text-xs text-cyan-200 leading-relaxed">
                      {isAr 
                        ? 'قامت نواة لينكس فورياً بإدراج عنوان المهاجم في جدول BPF_MAP المشترك وإسقاط الحزم في طبقة تعريف الشبكة قبل استهلاك أي موارد معالجة. تفتت الأشعة الهجومية إلى دروع زرقاء آمنة.'
                        : 'Linux Kernel XDP driver pinned IP 185.190.240.101 into in-kernel drop table. Attack packets shattered at wire speed with 0 context switches!'}
                    </p>
                  </div>
                )}
              </div>
            )}

            {/* 3. PHASE 4: FULL-SCREEN ZERO-TRUST OVERRIDE MODAL */}
            {showOtpModal && (
              <div className="bg-gradient-to-b from-[#1C0507] to-[#0A0A0A] border-2 border-[#FF003C] rounded-2xl p-6 sm:p-8 shadow-[0_0_60px_rgba(255,0,60,0.5)] space-y-5 text-center">
                <div className="mx-auto w-16 h-16 rounded-2xl bg-[#FF003C]/20 border border-[#FF003C] flex items-center justify-center">
                  <UserX className="w-8 h-8 text-[#FF003C] animate-pulse" />
                </div>

                <div>
                  <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-[#FF003C]/20 border border-[#FF003C]/40 text-[#FF003C] text-xs font-bold uppercase tracking-widest">
                    <span>{isAr ? 'تحذير أمني: تجميد جلسة مستخدم مشبوه' : 'ZERO-TRUST OVERRIDE: PRIVILEGED INTERCEPTION'}</span>
                  </div>
                  <h3 className="text-xl sm:text-2xl font-black text-white mt-2">
                    {isAr ? 'تم اعتراض محاولة حذف سجلات التدقيق بنجاح' : 'Rogue Admin Intrusion Log Purge Intercepted'}
                  </h3>
                  <p className="text-xs text-[#CCCCCC] max-w-lg mx-auto mt-2">
                    {isAr 
                      ? 'رصد محرك انعدام الثقة قيام الحساب الممتاز admin_svc_rogue@mod.gov.sa بمحاولة إتلاف سجلات النواة لتغطية آثار الاختراق. تم تجميد الجلسة فورياً ويتطلب فك الحظر تصريح قائد الفريق المزدوج.'
                      : 'Privileged user admin_svc_rogue@mod.gov.sa executed unauthorized log wipe (rm -rf /var/log/audit.log). Session instantly frozen pending Team Lead OTP.'}
                  </p>
                </div>

                <div className="max-w-md mx-auto bg-[#141414] border border-[#2A2A2A] rounded-xl p-4 text-left font-mono text-xs space-y-1.5 text-[#888888]">
                  <div>Target Actor: <span className="text-white font-bold">admin_svc_rogue@mod.gov.sa</span></div>
                  <div>Origin IP: <span className="text-[#FF003C] font-bold">10.0.99.14 (Internal DMZ Subnet)</span></div>
                  <div>Intercepted Command: <span className="text-[#FFB000]">rm -rf /var/log/audit.log && DELETE FROM security_events;</span></div>
                  <div>Kernel Verdict: <span className="text-emerald-400 font-bold">BLOCKED [ZERO-TRUST PRIVILEGED ISOLATION]</span></div>
                </div>

                <div className="max-w-sm mx-auto space-y-3">
                  <div className="flex gap-2">
                    <input
                      type="text"
                      value={otpInput}
                      onChange={(e) => setOtpInput(e.target.value)}
                      placeholder="ENTER DUAL-KEY OTP (e.g. 992814)"
                      className="flex-1 text-center bg-[#181818] border border-[#333333] focus:border-[#39FF14] rounded-xl px-3 py-2.5 text-sm text-white font-mono tracking-widest outline-none"
                    />
                    <button
                      onClick={() => handleAuthorizeOtp()}
                      disabled={otpApproving}
                      className="bg-emerald-500 hover:bg-emerald-400 text-black font-black px-5 py-2.5 rounded-xl text-xs uppercase tracking-wider transition flex items-center justify-center gap-1.5"
                    >
                      <Key className="w-3.5 h-3.5" />
                      <span>{otpApproving ? '...' : isAr ? 'تحقق واعتماد' : 'Verify'}</span>
                    </button>
                  </div>

                  <button
                    onClick={() => handleAuthorizeOtp('992814')}
                    disabled={otpApproving}
                    className="w-full bg-[#181818] hover:bg-[#222222] border border-[#333333] text-[#FFB000] font-bold py-2.5 px-4 rounded-xl text-xs transition flex items-center justify-center gap-2"
                  >
                    <ShieldCheck className="w-4 h-4" />
                    <span>{isAr ? 'المصادقة السريعة لقائد العرض (1-Click VIP Override)' : '1-Click Executive Dual-Key Override'}</span>
                  </button>
                </div>
              </div>
            )}

            {/* 4. PHASE 5: MoD POST-ACTION REPORT (SOAR INTEGRATION) */}
            {phase === 'REPORT_READY' && soarReport && (
              <div className="bg-[#0E0E0E] border-2 border-emerald-500/60 rounded-2xl p-6 sm:p-8 space-y-6 shadow-[0_0_60px_rgba(57,255,20,0.2)]">
                {/* Header Banner */}
                <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 pb-4 border-b border-[#222222]">
                  <div className="flex items-center gap-3">
                    <div className="w-12 h-12 rounded-2xl bg-emerald-500/10 border border-emerald-500/40 flex items-center justify-center">
                      <ShieldCheck className="w-6 h-6 text-emerald-400" />
                    </div>
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
                          {soarReport.classification}
                        </span>
                        <span className="text-xs text-[#888888]">INCIDENT POST-ACTION REPORT</span>
                      </div>
                      <h3 className="text-lg sm:text-xl font-black text-white mt-0.5">
                        {isAr ? 'تقرير ما بعد الواقعة السيبرانية • وزارة الدفاع' : 'Ministry of Defense • Incident Post-Action Report'}
                      </h3>
                    </div>
                  </div>

                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => {
                        const blob = new Blob([JSON.stringify(soarReport, null, 2)], { type: 'application/json' });
                        const url = URL.createObjectURL(blob);
                        const a = document.createElement('a');
                        a.href = url;
                        a.download = `MoD_Cyber_PostAction_Report_${Date.now()}.json`;
                        a.click();
                        setReportCopied(true);
                        setTimeout(() => setReportCopied(false), 2000);
                      }}
                      className="flex items-center gap-1.5 px-3 py-2 rounded-xl bg-[#181818] hover:bg-[#222222] text-xs text-white border border-[#333333] transition"
                    >
                      <Download className="w-3.5 h-3.5" />
                      <span>{reportCopied ? (isAr ? 'تم التحميل!' : 'Downloaded!') : (isAr ? 'تصدير التقرير' : 'Export JSON')}</span>
                    </button>

                    <button
                      onClick={handleStartWarGames}
                      className="flex items-center gap-1.5 px-4 py-2 rounded-xl bg-emerald-500 hover:bg-emerald-400 text-black font-bold text-xs uppercase tracking-wider transition"
                    >
                      <RotateCcw className="w-3.5 h-3.5" />
                      <span>{isAr ? 'إعادة تشغيل المحاكاة' : 'Replay Demo'}</span>
                    </button>
                  </div>
                </div>

                {/* Core Incident Metrics Grid */}
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                  <div className="bg-[#141414] border border-[#222222] rounded-xl p-4">
                    <div className="text-[10px] text-[#888888] uppercase font-bold">Mean Time to Detect (MTTD)</div>
                    <div className="text-2xl font-black text-emerald-400 mt-1">
                      {(soarReport.executiveSummary?.mttdSeconds * 1000).toFixed(1)} <span className="text-xs">ms</span>
                    </div>
                    <div className="text-[10px] text-[#666666] mt-0.5">Bayesian Confidence: 99.8%</div>
                  </div>

                  <div className="bg-[#141414] border border-[#222222] rounded-xl p-4">
                    <div className="text-[10px] text-[#888888] uppercase font-bold">Mean Time to Respond (MTTR)</div>
                    <div className="text-2xl font-black text-cyan-400 mt-1">
                      310 <span className="text-xs">ns</span>
                    </div>
                    <div className="text-[10px] text-[#666666] mt-0.5">Linux eBPF XDP Zero-Copy</div>
                  </div>

                  <div className="bg-[#141414] border border-[#222222] rounded-xl p-4">
                    <div className="text-[10px] text-[#888888] uppercase font-bold">Data Exfiltrated / Loss</div>
                    <div className="text-2xl font-black text-emerald-400 mt-1">
                      0.00 <span className="text-xs">Bytes</span>
                    </div>
                    <div className="text-[10px] text-[#666666] mt-0.5">Zero Data Compromise</div>
                  </div>

                  <div className="bg-[#141414] border border-[#222222] rounded-xl p-4">
                    <div className="text-[10px] text-[#888888] uppercase font-bold">Zero-Trust Compliance</div>
                    <div className="text-2xl font-black text-emerald-400 mt-1">
                      100%
                    </div>
                    <div className="text-[10px] text-[#666666] mt-0.5">Sovereign Standard SCDS-V9</div>
                  </div>
                </div>

                {/* Key Findings List */}
                <div className="bg-[#121212] border border-[#222222] rounded-xl p-5 space-y-3">
                  <h4 className="font-bold text-white text-xs uppercase tracking-wider flex items-center gap-2">
                    <FileText className="w-4 h-4 text-emerald-400" />
                    <span>{isAr ? 'النتائج والاستنتاجات التنفيذية' : 'Executive Postmortem Findings'}</span>
                  </h4>

                  <ul className="space-y-2 text-xs text-[#CCCCCC]">
                    {(isAr ? soarReport.executiveSummary?.keyFindingsAr : soarReport.executiveSummary?.keyFindingsEn)?.map((finding: string) => {
                      const findingKey = `mod-finding-${finding.slice(0, 48).replace(/[^a-zA-Z0-9]/g, '-').toLowerCase()}`;
                      return (
                        <li key={findingKey} className="flex items-start gap-2.5">
                          <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0 mt-0.5" />
                          <span>{finding}</span>
                        </li>
                      );
                    })}
                  </ul>
                </div>

                {/* Mitigated MITRE TTPs Matrix */}
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs">
                  <div className="p-3 rounded-xl bg-[#121212] border border-[#222222]">
                    <div className="text-[#888888] font-bold">T1498 • Volumetric DDoS</div>
                    <div className="text-white font-bold mt-1">54 Botnet Ingress Nodes</div>
                    <div className="text-[11px] text-emerald-400 mt-0.5">Neutralized at Edge Filter</div>
                  </div>

                  <div className="p-3 rounded-xl bg-[#121212] border border-[#222222]">
                    <div className="text-[#888888] font-bold">T1190 • Exploit Public-Facing App</div>
                    <div className="text-white font-bold mt-1">APT-41 Zero-Day Laser</div>
                    <div className="text-[11px] text-cyan-400 mt-0.5">eBPF Kernel Drop (0.31µs)</div>
                  </div>

                  <div className="p-3 rounded-xl bg-[#121212] border border-[#222222]">
                    <div className="text-[#888888] font-bold">T1070.002 • Clear Linux Logs</div>
                    <div className="text-white font-bold mt-1">Rogue Admin Interception</div>
                    <div className="text-[11px] text-[#FFB000] mt-0.5">Dual-Key Step-Up Intercepted</div>
                  </div>
                </div>

                {/* Cryptographic Digital Signature Footer */}
                <div className="pt-4 border-t border-[#222222] flex flex-col sm:flex-row items-center justify-between text-[11px] text-[#888888] gap-2 font-mono">
                  <div>
                    SHA-256 Seal: <span className="text-emerald-400 font-bold">{soarReport.cryptographicSeal?.sha256Digest?.substring(0, 24)}...</span>
                  </div>
                  <div>
                    Authority: <span className="text-white">SOVEREIGN_CYBER_COMMAND_AUTONOMOUS_ORCHESTRATOR</span>
                  </div>
                </div>
              </div>
            )}

          </div>

          {/* Footer Bar */}
          <div className="px-6 py-3 bg-[#0C0C0C] border-t border-[#1E1E1E] flex items-center justify-between text-xs text-[#666666]">
            <span>SOVEREIGN DEFENDER 6.0 • MoD RED TEAM SIMULATOR</span>
            <div className="flex items-center gap-3">
              <button
                onClick={onClose}
                className="text-[#888888] hover:text-white transition text-xs"
              >
                {isAr ? 'إغلاق المحاكي' : 'Dismiss'}
              </button>
            </div>
          </div>

        </div>
      )}

    </div>
  );
};
