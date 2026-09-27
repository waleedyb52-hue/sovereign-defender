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
    if (
      cleanKey === 'MOD-DEFENSE-2026' ||
      cleanKey === 'MOD' ||
      cleanKey === 'VIP-CYBER-WAR' ||
      cleanKey === '1234'
    ) {
      setIsAuthenticated(true);
      setAuthError(null);
      audioSynth.playRadarPing();
    } else {
      setAuthError(
        isAr
          ? 'رمز التفويض غير صحيح. يرجى إدخال المفتاح الرئاسي المعتمد.'
          : 'Invalid VIP Authorization Key.'
      );
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
    <div className="fixed inset-0 z-50 flex items-center justify-center overflow-y-auto bg-black/85 p-4 font-mono backdrop-blur-md select-none">
      {/* 1. VIP LOGIN AUTHENTICATION GATE */}
      {!isAuthenticated && (
        <div className="relative w-full max-w-lg rounded-2xl border-2 border-[#f59e0b]/60 bg-[#000000] p-6 text-center shadow-[0_0_60px_rgba(255,176,0,0.25)] sm:p-8">
          <div className="mx-auto mb-4 flex h-14 w-14 items-center justify-center rounded-2xl border border-[#f59e0b]/40 bg-[#f59e0b]/10">
            <Lock className="h-7 w-7 animate-pulse text-[#f59e0b]" />
          </div>

          <div className="mb-2 inline-flex items-center gap-2 rounded-full border border-[#f59e0b]/30 bg-[#f59e0b]/10 px-3 py-1 text-[11px] font-bold tracking-widest text-[#f59e0b] uppercase">
            <span>
              {isAr
                ? 'وزارة الدفاع • بوابة المحاكاة السرية'
                : 'MINISTRY OF DEFENSE • VIP WAR GAMES PORTAL'}
            </span>
          </div>

          <h2 className="mt-1 text-xl font-black tracking-wide text-white sm:text-2xl">
            {isAr ? 'محاكي مناورات الحرب السيبرانية' : 'Red Team War Games Simulator'}
          </h2>
          <p className="mx-auto mt-2 max-w-sm text-xs text-[#8aa4b8]">
            {isAr
              ? 'مخصص للعروض الحية والتنفيذية أمام قيادات وزارة الدفاع. يتطلب إدخال مفتاح التفويض السيادي للبدء.'
              : 'Authorized executive presentation mode for high-stakes MoD demonstrations.'}
          </p>

          <form onSubmit={handleVipSubmit} className="mt-6 space-y-4">
            <div>
              <input
                type="password"
                value={vipPasswordInput}
                onChange={e => setVipPasswordInput(e.target.value)}
                placeholder="ENTER VIP PASSCODE"
                className="w-full rounded-xl border border-[#0e3a44] bg-[#03070c] px-4 py-3 text-center text-sm tracking-widest text-white uppercase transition outline-none focus:border-[#f59e0b]"
              />
              {authError && (
                <div className="mt-2 text-[11px] font-bold text-[#f43f5e]">{authError}</div>
              )}
            </div>

            <div className="flex flex-col gap-2 sm:flex-row">
              <button
                type="submit"
                className="flex flex-1 items-center justify-center gap-2 rounded-xl bg-[#f59e0b] px-4 py-2.5 text-xs font-black tracking-wider text-black uppercase shadow-lg shadow-[#f59e0b]/20 transition hover:bg-[#f59e0b]/90"
              >
                <Unlock className="h-4 w-4" />
                <span>{isAr ? 'تحقق وبدء المحاكاة' : 'Authenticate & Unlock'}</span>
              </button>

              <button
                type="button"
                onClick={handleQuickVipAutoFill}
                className="flex items-center justify-center gap-1.5 rounded-xl border border-[#0e3a44] bg-[#061019] px-4 py-2.5 text-xs font-bold text-[#f59e0b] transition hover:bg-[#0e3a44]"
                title="Auto-fill default presentation passcode"
              >
                <Sparkles className="h-3.5 w-3.5" />
                <span>{isAr ? 'تعبئة سريعة (VIP Demo)' : '1-Click Demo Auth'}</span>
              </button>
            </div>
          </form>

          <div className="mt-6 flex items-center justify-between border-t border-[#0e3a44] pt-4 text-[10px] text-[#5c7484]">
            <span>CLEARANCE: TOP SECRET // SCDS-V9</span>
            <button onClick={onClose} className="text-[#8aa4b8] transition hover:text-white">
              {isAr ? 'إلغاء والعودة' : 'Cancel'}
            </button>
          </div>
        </div>
      )}

      {/* 2. AUTHENTICATED WAR GAMES STAGE CONTROLLER */}
      {isAuthenticated && (
        <div className="relative flex max-h-[92vh] w-full max-w-5xl flex-col overflow-hidden rounded-2xl border-2 border-[#f43f5e]/50 bg-[#000000] shadow-[0_0_80px_rgba(255,0,60,0.3)]">
          {/* Header Bar */}
          <div className="flex items-center justify-between border-b border-[#0e3a44] bg-[#101010] px-6 py-4">
            <div className="flex items-center gap-3">
              <div className="flex h-9 w-9 items-center justify-center rounded-xl border border-[#f43f5e]/60 bg-[#f43f5e]/20">
                <Flame className="h-5 w-5 animate-pulse text-[#f43f5e]" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <h3 className="text-base font-black tracking-wide text-white">
                    {isAr
                      ? 'مناورات الحرب السيبرانية • القيادة العامة'
                      : 'MoD WAR GAMES • RED TEAM EMULATOR'}
                  </h3>
                  <span className="rounded border border-[#f43f5e]/40 bg-[#f43f5e]/20 px-2 py-0.5 text-[10px] font-bold text-[#f43f5e]">
                    EXECUTIVE VIP
                  </span>
                </div>
                <div className="text-xs text-[#8aa4b8]">
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
                className="rounded-lg border border-[#0e3a44] bg-[#061019] p-2 text-[#8aa4b8] transition hover:bg-[#0e3a44] hover:text-white"
              >
                <RotateCcw className="h-4 w-4" />
              </button>
              <button
                onClick={onClose}
                className="rounded-lg border border-[#0e3a44] bg-[#061019] p-2 text-[#8aa4b8] transition hover:bg-[#f43f5e]/20 hover:text-[#f43f5e]"
              >
                <XCircle className="h-4 w-4" />
              </button>
            </div>
          </div>

          {/* Tactical HUD Breadcrumbs Timeline */}
          <div className="grid grid-cols-2 gap-2 border-b border-[#0e3a44] bg-[#0E0E0E] px-6 py-3 text-xs sm:grid-cols-4">
            {/* Step 1 */}
            <div
              className={`flex flex-col justify-between rounded-lg border p-2.5 transition ${
                phase === 'PHASE_1_DDOS'
                  ? 'animate-pulse border-[#f59e0b] bg-[#f59e0b]/20 text-white shadow-[0_0_15px_rgba(255,176,0,0.3)]'
                  : phase !== 'STANDBY'
                    ? 'border-emerald-500/40 bg-[#03070c] text-emerald-400'
                    : 'border-[#0e3a44] bg-[#03070c] text-[#5c7484]'
              }`}
            >
              <div className="flex items-center justify-between text-[10px] font-bold">
                <span>T+0s • PHASE 1</span>
                {phase !== 'STANDBY' && phase !== 'PHASE_1_DDOS' && (
                  <CheckCircle2 className="h-3 w-3 text-emerald-400" />
                )}
              </div>
              <div className="mt-1 truncate text-[11px] font-bold">
                {isAr ? 'مسح حجب الخدمة (DDoS)' : 'Global DDoS Scan'}
              </div>
              <div className="mt-0.5 text-[9px] opacity-75">54 Botnet Vectors</div>
            </div>

            {/* Step 2 */}
            <div
              className={`flex flex-col justify-between rounded-lg border p-2.5 transition ${
                phase === 'PHASE_2_APT'
                  ? 'animate-pulse border-[#f43f5e] bg-[#f43f5e]/20 text-white shadow-[0_0_15px_rgba(255,0,60,0.3)]'
                  : phase === 'PHASE_3_EBPF_KILLCHAIN' ||
                      phase === 'PHASE_4_INSIDER' ||
                      phase === 'REPORT_READY'
                    ? 'border-emerald-500/40 bg-[#03070c] text-emerald-400'
                    : 'border-[#0e3a44] bg-[#03070c] text-[#5c7484]'
              }`}
            >
              <div className="flex items-center justify-between text-[10px] font-bold">
                <span>T+5s • PHASE 2</span>
                {(phase === 'PHASE_3_EBPF_KILLCHAIN' ||
                  phase === 'PHASE_4_INSIDER' ||
                  phase === 'REPORT_READY') && (
                  <CheckCircle2 className="h-3 w-3 text-emerald-400" />
                )}
              </div>
              <div className="mt-1 truncate text-[11px] font-bold">
                {isAr ? 'حمولة APT مركزة' : 'Targeted APT Payload'}
              </div>
              <div className="mt-0.5 text-[9px] opacity-75">Entropy: 7.99 bits</div>
            </div>

            {/* Step 3 */}
            <div
              className={`flex flex-col justify-between rounded-lg border p-2.5 transition ${
                phase === 'PHASE_3_EBPF_KILLCHAIN'
                  ? 'animate-pulse border-cyan-500 bg-cyan-500/20 text-white shadow-[0_0_15px_rgba(6,182,212,0.3)]'
                  : phase === 'PHASE_4_INSIDER' || phase === 'REPORT_READY'
                    ? 'border-emerald-500/40 bg-[#03070c] text-emerald-400'
                    : 'border-[#0e3a44] bg-[#03070c] text-[#5c7484]'
              }`}
            >
              <div className="flex items-center justify-between text-[10px] font-bold">
                <span>T+8s • PHASE 3</span>
                {(phase === 'PHASE_4_INSIDER' || phase === 'REPORT_READY') && (
                  <CheckCircle2 className="h-3 w-3 text-emerald-400" />
                )}
              </div>
              <div className="mt-1 truncate text-[11px] font-bold">
                {isAr ? 'إسقاط eBPF بالنواة' : 'Autonomous eBPF Drop'}
              </div>
              <div className="mt-0.5 text-[9px] opacity-75">0.31µs Zero-Copy</div>
            </div>

            {/* Step 4 */}
            <div
              className={`flex flex-col justify-between rounded-lg border p-2.5 transition ${
                phase === 'PHASE_4_INSIDER'
                  ? 'animate-pulse border-[#f43f5e] bg-[#f43f5e]/30 text-white shadow-[0_0_15px_rgba(255,0,60,0.4)]'
                  : phase === 'REPORT_READY'
                    ? 'border-emerald-500/40 bg-[#03070c] text-emerald-400'
                    : 'border-[#0e3a44] bg-[#03070c] text-[#5c7484]'
              }`}
            >
              <div className="flex items-center justify-between text-[10px] font-bold">
                <span>T+12s • PHASE 4</span>
                {phase === 'REPORT_READY' && <CheckCircle2 className="h-3 w-3 text-emerald-400" />}
              </div>
              <div className="mt-1 truncate text-[11px] font-bold">
                {isAr ? 'اعتراض التهديد الداخلي' : 'Insider Log Purge'}
              </div>
              <div className="mt-0.5 text-[9px] opacity-75">Zero-Trust OTP Lock</div>
            </div>
          </div>

          {/* Main Stage Viewport */}
          <div className="space-y-6 overflow-y-auto p-6">
            {/* Standby Launch Hero Banner */}
            {phase === 'STANDBY' && (
              <div className="space-y-5 rounded-2xl border border-[#0e3a44] bg-gradient-to-b from-[#03070c] to-[#000000] p-6 text-center sm:p-8">
                <div className="inline-flex items-center gap-2 rounded-full border border-[#f43f5e]/30 bg-[#f43f5e]/10 px-3 py-1 text-xs font-bold text-[#f43f5e]">
                  <Radio className="h-3.5 w-3.5 animate-pulse" />
                  <span>
                    {isAr
                      ? 'جاهز للإطلاق المباشر في العرض'
                      : 'ARMED & READY FOR LIVE VIP PRESENTATION'}
                  </span>
                </div>

                <div className="mx-auto max-w-2xl">
                  <h4 className="text-xl font-black text-white sm:text-2xl">
                    {isAr
                      ? 'محاكاة سيناريو الهجوم المعقد ضد النواة السيادية'
                      : 'Sovereign Core Live Red Team Cyber Engagement'}
                  </h4>
                  <p className="mt-2 text-xs leading-relaxed text-[#8aa4b8]">
                    {isAr
                      ? 'سيناريو تدريبي متكامل مدته 16 ثانية يحاكي هجوماً منسقاً: مسح استطلاعي بـ 54 روبوت، يليه استهداف مركز بحمولة تشفيرية APT، وتفعيل الإسقاط الذاتي في نواة لينكس (eBPF XDP)، ثم تجميد محاولة مستخدم داخلي لحذف السجلات عبر مصادقة انعدام الثقة.'
                      : 'A cinematic 16-second narrative: Injects 54 botnet scanners, fires a concentrated high-entropy APT laser, autonomously engages Linux eBPF zero-copy drop, and traps a rogue admin attempting log deletion.'}
                  </p>
                </div>

                <div className="pt-2">
                  <button
                    onClick={handleStartWarGames}
                    className="inline-flex transform items-center gap-3 rounded-xl bg-gradient-to-r from-[#f43f5e] to-[#E60033] px-8 py-4 text-sm font-black tracking-wider text-white uppercase shadow-[0_0_30px_rgba(255,0,60,0.4)] transition hover:scale-[1.02] hover:from-[#FF1A4D] hover:to-[#f43f5e] active:scale-[0.98]"
                  >
                    <Play className="h-5 w-5 fill-current" />
                    <span>
                      {isAr
                        ? 'إطلاق مناورات الحرب السيبرانية (START SIMULATION)'
                        : 'Launch MoD War Games Simulation'}
                    </span>
                  </button>
                </div>
              </div>
            )}

            {/* Active Simulation Visual HUD */}
            {phase !== 'STANDBY' && phase !== 'REPORT_READY' && (
              <div className="space-y-4">
                {/* Real-time Telemetry Dashboard Strip */}
                <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
                  <div className="rounded-xl border border-[#0e3a44] bg-[#03070c] p-3.5">
                    <div className="text-[10px] font-bold text-[#8aa4b8] uppercase">
                      {isAr ? 'زمن المحاكاة' : 'Scenario Clock'}
                    </div>
                    <div className="mt-0.5 font-mono text-xl font-black text-[#f59e0b]">
                      T+{(elapsedMs / 1000).toFixed(2)}s
                    </div>
                  </div>

                  <div className="rounded-xl border border-[#0e3a44] bg-[#03070c] p-3.5">
                    <div className="text-[10px] font-bold text-[#8aa4b8] uppercase">
                      {isAr ? 'معدل تدفق الحزم' : 'Live Ingress Load'}
                    </div>
                    <div className="mt-0.5 font-mono text-xl font-black text-white">
                      {liveThroughputGbps.toFixed(1)}{' '}
                      <span className="text-xs text-[#8aa4b8]">Gbps</span>
                    </div>
                  </div>

                  <div
                    className={`rounded-xl border bg-[#03070c] p-3.5 transition ${
                      liveEntropy > 7.0 ? 'border-[#f43f5e]/60 bg-[#f43f5e]/10' : 'border-[#0e3a44]'
                    }`}
                  >
                    <div className="text-[10px] font-bold text-[#8aa4b8] uppercase">
                      {isAr ? 'إنتروبيا شانون' : 'Shannon Entropy'}
                    </div>
                    <div
                      className={`mt-0.5 font-mono text-xl font-black ${
                        liveEntropy > 7.0 ? 'animate-pulse text-[#f43f5e]' : 'text-emerald-400'
                      }`}
                    >
                      {liveEntropy.toFixed(2)} <span className="text-xs">bits/byte</span>
                    </div>
                  </div>

                  <div className="rounded-xl border border-cyan-500/40 bg-[#03070c] bg-cyan-950/10 p-3.5">
                    <div className="text-[10px] font-bold text-cyan-400 uppercase">
                      {isAr ? 'إسقاط eBPF بالنواة' : 'Kernel XDP Drops'}
                    </div>
                    <div className="mt-0.5 font-mono text-xl font-black text-cyan-400">
                      {liveDroppedPkts.toLocaleString()} <span className="text-xs">pkts</span>
                    </div>
                  </div>
                </div>

                {/* Phase 1 Live Callout */}
                {phase === 'PHASE_1_DDOS' && (
                  <div className="space-y-2 rounded-xl border-2 border-[#f59e0b]/60 bg-[#03070c] p-5 shadow-[0_0_30px_rgba(255,176,0,0.15)]">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2 text-sm font-bold text-[#f59e0b]">
                        <Activity className="h-4 w-4 animate-spin" />
                        <span>
                          {isAr
                            ? 'المرحلة 1: مسح حجب الخدمة الموزع (54 روبوت)'
                            : 'PHASE 1: GLOBAL DISTRIBUTED DDOS SCAN (54 BOTS)'}
                        </span>
                      </div>
                      <span className="rounded bg-[#f59e0b]/20 px-2 py-0.5 font-mono text-[11px] text-[#f59e0b]">
                        AI NOISE FILTER: MONITORING
                      </span>
                    </div>
                    <p className="text-xs leading-relaxed text-[#CCCCCC]">
                      {isAr
                        ? 'المنظومة ترصد تذبذب الحزم وتتعرف على الـ 54 متجهاً هجومياً، مع تفعيل مرشح الضوضاء الذكي لتفادي الإسقاط العشوائي المبكر للحفاظ على سلاسة الخدمة.'
                        : 'Autonomous AI engine evaluates volumetric dispersion across Europe, Asia, and Americas. Vectors remain monitored under noise threshold without premature drops.'}
                    </p>
                  </div>
                )}

                {/* Phase 2 Live Callout */}
                {phase === 'PHASE_2_APT' && (
                  <div className="animate-pulse space-y-2 rounded-xl border-2 border-[#f43f5e] bg-[#160507] p-5 shadow-[0_0_40px_rgba(255,0,60,0.3)]">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2 text-sm font-black text-[#f43f5e]">
                        <AlertTriangle className="h-4 w-4 animate-bounce" />
                        <span>
                          {isAr
                            ? 'المرحلة 2: شعاع ليزري مركز بحمولة APT نحو العقدة السيادية'
                            : 'PHASE 2: CONCENTRATED APT ZERO-DAY LASER TARGETING RIYADH NODE'}
                        </span>
                      </div>
                      <span className="rounded bg-[#f43f5e] px-2 py-0.5 font-mono text-[11px] font-bold text-white">
                        THREAT SCORE: 98% CRITICAL
                      </span>
                    </div>
                    <p className="text-xs leading-relaxed text-[#FF8099]">
                      {isAr
                        ? 'ارتفاع إنتروبيا شانون إلى 7.99 بت/بايت يشير إلى حمولة برمجية خبيثة متعددة الأشكال تحاول تجاوز الجدار الناري والتسرب إلى العقدة المركزية!'
                        : 'Shannon entropy spikes to 7.99 bits/byte. High cryptographic obfuscation detected. Laser vector focusing energy on Riyadh Central Datacenter!'}
                    </p>
                  </div>
                )}

                {/* Phase 3 Live Callout */}
                {phase === 'PHASE_3_EBPF_KILLCHAIN' && (
                  <div className="space-y-2 rounded-xl border-2 border-cyan-400 bg-cyan-950/20 p-5 shadow-[0_0_40px_rgba(6,182,212,0.3)]">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2 text-sm font-black text-cyan-400">
                        <Zap className="h-4 w-4 animate-pulse" />
                        <span>
                          {isAr
                            ? 'المرحلة 3: تفعيل الإسقاط العتادي الفوري بنواة لينكس (eBPF XDP)'
                            : 'PHASE 3: KERNEL XDP ISOLATION ENGAGED (0.31µs ZERO-COPY)'}
                        </span>
                      </div>
                      <span className="rounded bg-cyan-400 px-2 py-0.5 font-mono text-[11px] font-black text-black">
                        BPF_MAP_TYPE_HASH: XDP_DROP
                      </span>
                    </div>
                    <p className="text-xs leading-relaxed text-cyan-200">
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
              <div className="space-y-5 rounded-2xl border-2 border-[#f43f5e] bg-gradient-to-b from-[#1C0507] to-[#000000] p-6 text-center shadow-[0_0_60px_rgba(255,0,60,0.5)] sm:p-8">
                <div className="mx-auto flex h-16 w-16 items-center justify-center rounded-2xl border border-[#f43f5e] bg-[#f43f5e]/20">
                  <UserX className="h-8 w-8 animate-pulse text-[#f43f5e]" />
                </div>

                <div>
                  <div className="inline-flex items-center gap-2 rounded-full border border-[#f43f5e]/40 bg-[#f43f5e]/20 px-3 py-1 text-xs font-bold tracking-widest text-[#f43f5e] uppercase">
                    <span>
                      {isAr
                        ? 'تحذير أمني: تجميد جلسة مستخدم مشبوه'
                        : 'ZERO-TRUST OVERRIDE: PRIVILEGED INTERCEPTION'}
                    </span>
                  </div>
                  <h3 className="mt-2 text-xl font-black text-white sm:text-2xl">
                    {isAr
                      ? 'تم اعتراض محاولة حذف سجلات التدقيق بنجاح'
                      : 'Rogue Admin Intrusion Log Purge Intercepted'}
                  </h3>
                  <p className="mx-auto mt-2 max-w-lg text-xs text-[#CCCCCC]">
                    {isAr
                      ? 'رصد محرك انعدام الثقة قيام الحساب الممتاز admin_svc_rogue@mod.gov.sa بمحاولة إتلاف سجلات النواة لتغطية آثار الاختراق. تم تجميد الجلسة فورياً ويتطلب فك الحظر تصريح قائد الفريق المزدوج.'
                      : 'Privileged user admin_svc_rogue@mod.gov.sa executed unauthorized log wipe (rm -rf /var/log/audit.log). Session instantly frozen pending Team Lead OTP.'}
                  </p>
                </div>

                <div className="mx-auto max-w-md space-y-1.5 rounded-xl border border-[#0e3a44] bg-[#03070c] p-4 text-left font-mono text-xs text-[#8aa4b8]">
                  <div>
                    Target Actor:{' '}
                    <span className="font-bold text-white">admin_svc_rogue@mod.gov.sa</span>
                  </div>
                  <div>
                    Origin IP:{' '}
                    <span className="font-bold text-[#f43f5e]">
                      10.0.99.14 (Internal DMZ Subnet)
                    </span>
                  </div>
                  <div>
                    Intercepted Command:{' '}
                    <span className="text-[#f59e0b]">
                      rm -rf /var/log/audit.log && DELETE FROM security_events;
                    </span>
                  </div>
                  <div>
                    Kernel Verdict:{' '}
                    <span className="font-bold text-emerald-400">
                      BLOCKED [ZERO-TRUST PRIVILEGED ISOLATION]
                    </span>
                  </div>
                </div>

                <div className="mx-auto max-w-sm space-y-3">
                  <div className="flex gap-2">
                    <input
                      type="text"
                      value={otpInput}
                      onChange={e => setOtpInput(e.target.value)}
                      placeholder="ENTER DUAL-KEY OTP (e.g. 992814)"
                      className="flex-1 rounded-xl border border-[#0e3a44] bg-[#061019] px-3 py-2.5 text-center font-mono text-sm tracking-widest text-white outline-none focus:border-[#10b981]"
                    />
                    <button
                      onClick={() => handleAuthorizeOtp()}
                      disabled={otpApproving}
                      className="flex items-center justify-center gap-1.5 rounded-xl bg-emerald-500 px-5 py-2.5 text-xs font-black tracking-wider text-black uppercase transition hover:bg-emerald-400"
                    >
                      <Key className="h-3.5 w-3.5" />
                      <span>{otpApproving ? '...' : isAr ? 'تحقق واعتماد' : 'Verify'}</span>
                    </button>
                  </div>

                  <button
                    onClick={() => handleAuthorizeOtp('992814')}
                    disabled={otpApproving}
                    className="flex w-full items-center justify-center gap-2 rounded-xl border border-[#0e3a44] bg-[#061019] px-4 py-2.5 text-xs font-bold text-[#f59e0b] transition hover:bg-[#0e3a44]"
                  >
                    <ShieldCheck className="h-4 w-4" />
                    <span>
                      {isAr
                        ? 'المصادقة السريعة لقائد العرض (1-Click VIP Override)'
                        : '1-Click Executive Dual-Key Override'}
                    </span>
                  </button>
                </div>
              </div>
            )}

            {/* 4. PHASE 5: MoD POST-ACTION REPORT (SOAR INTEGRATION) */}
            {phase === 'REPORT_READY' && soarReport && (
              <div className="space-y-6 rounded-2xl border-2 border-emerald-500/60 bg-[#0E0E0E] p-6 shadow-[0_0_60px_rgba(57,255,20,0.2)] sm:p-8">
                {/* Header Banner */}
                <div className="flex flex-col items-start justify-between gap-4 border-b border-[#0e3a44] pb-4 sm:flex-row sm:items-center">
                  <div className="flex items-center gap-3">
                    <div className="flex h-12 w-12 items-center justify-center rounded-2xl border border-emerald-500/40 bg-emerald-500/10">
                      <ShieldCheck className="h-6 w-6 text-emerald-400" />
                    </div>
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="rounded border border-emerald-500/30 bg-emerald-500/20 px-2 py-0.5 text-[10px] font-bold text-emerald-400">
                          {soarReport.classification}
                        </span>
                        <span className="text-xs text-[#8aa4b8]">INCIDENT POST-ACTION REPORT</span>
                      </div>
                      <h3 className="mt-0.5 text-lg font-black text-white sm:text-xl">
                        {isAr
                          ? 'تقرير ما بعد الواقعة السيبرانية • وزارة الدفاع'
                          : 'Ministry of Defense • Incident Post-Action Report'}
                      </h3>
                    </div>
                  </div>

                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => {
                        const blob = new Blob([JSON.stringify(soarReport, null, 2)], {
                          type: 'application/json'
                        });
                        const url = URL.createObjectURL(blob);
                        const a = document.createElement('a');
                        a.href = url;
                        a.download = `MoD_Cyber_PostAction_Report_${Date.now()}.json`;
                        a.click();
                        setReportCopied(true);
                        setTimeout(() => setReportCopied(false), 2000);
                      }}
                      className="flex items-center gap-1.5 rounded-xl border border-[#0e3a44] bg-[#061019] px-3 py-2 text-xs text-white transition hover:bg-[#0e3a44]"
                    >
                      <Download className="h-3.5 w-3.5" />
                      <span>
                        {reportCopied
                          ? isAr
                            ? 'تم التحميل!'
                            : 'Downloaded!'
                          : isAr
                            ? 'تصدير التقرير'
                            : 'Export JSON'}
                      </span>
                    </button>

                    <button
                      onClick={handleStartWarGames}
                      className="flex items-center gap-1.5 rounded-xl bg-emerald-500 px-4 py-2 text-xs font-bold tracking-wider text-black uppercase transition hover:bg-emerald-400"
                    >
                      <RotateCcw className="h-3.5 w-3.5" />
                      <span>{isAr ? 'إعادة تشغيل المحاكاة' : 'Replay Demo'}</span>
                    </button>
                  </div>
                </div>

                {/* Core Incident Metrics Grid */}
                <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
                  <div className="rounded-xl border border-[#0e3a44] bg-[#03070c] p-4">
                    <div className="text-[10px] font-bold text-[#8aa4b8] uppercase">
                      Mean Time to Detect (MTTD)
                    </div>
                    <div className="mt-1 text-2xl font-black text-emerald-400">
                      {(soarReport.executiveSummary?.mttdSeconds * 1000).toFixed(1)}{' '}
                      <span className="text-xs">ms</span>
                    </div>
                    <div className="mt-0.5 text-[10px] text-[#5c7484]">
                      Bayesian Confidence: 99.8%
                    </div>
                  </div>

                  <div className="rounded-xl border border-[#0e3a44] bg-[#03070c] p-4">
                    <div className="text-[10px] font-bold text-[#8aa4b8] uppercase">
                      Mean Time to Respond (MTTR)
                    </div>
                    <div className="mt-1 text-2xl font-black text-cyan-400">
                      310 <span className="text-xs">ns</span>
                    </div>
                    <div className="mt-0.5 text-[10px] text-[#5c7484]">
                      Linux eBPF XDP Zero-Copy
                    </div>
                  </div>

                  <div className="rounded-xl border border-[#0e3a44] bg-[#03070c] p-4">
                    <div className="text-[10px] font-bold text-[#8aa4b8] uppercase">
                      Data Exfiltrated / Loss
                    </div>
                    <div className="mt-1 text-2xl font-black text-emerald-400">
                      0.00 <span className="text-xs">Bytes</span>
                    </div>
                    <div className="mt-0.5 text-[10px] text-[#5c7484]">Zero Data Compromise</div>
                  </div>

                  <div className="rounded-xl border border-[#0e3a44] bg-[#03070c] p-4">
                    <div className="text-[10px] font-bold text-[#8aa4b8] uppercase">
                      Zero-Trust Compliance
                    </div>
                    <div className="mt-1 text-2xl font-black text-emerald-400">100%</div>
                    <div className="mt-0.5 text-[10px] text-[#5c7484]">
                      Sovereign Standard SCDS-V9
                    </div>
                  </div>
                </div>

                {/* Key Findings List */}
                <div className="space-y-3 rounded-xl border border-[#0e3a44] bg-[#03070c] p-5">
                  <h4 className="flex items-center gap-2 text-xs font-bold tracking-wider text-white uppercase">
                    <FileText className="h-4 w-4 text-emerald-400" />
                    <span>
                      {isAr ? 'النتائج والاستنتاجات التنفيذية' : 'Executive Postmortem Findings'}
                    </span>
                  </h4>

                  <ul className="space-y-2 text-xs text-[#CCCCCC]">
                    {(isAr
                      ? soarReport.executiveSummary?.keyFindingsAr
                      : soarReport.executiveSummary?.keyFindingsEn
                    )?.map((finding: string) => {
                      const findingKey = `mod-finding-${finding
                        .slice(0, 48)
                        .replace(/[^a-zA-Z0-9]/g, '-')
                        .toLowerCase()}`;
                      return (
                        <li key={findingKey} className="flex items-start gap-2.5">
                          <CheckCircle2 className="mt-0.5 h-4 w-4 flex-shrink-0 text-emerald-400" />
                          <span>{finding}</span>
                        </li>
                      );
                    })}
                  </ul>
                </div>

                {/* Mitigated MITRE TTPs Matrix */}
                <div className="grid grid-cols-1 gap-3 text-xs sm:grid-cols-3">
                  <div className="rounded-xl border border-[#0e3a44] bg-[#03070c] p-3">
                    <div className="font-bold text-[#8aa4b8]">T1498 • Volumetric DDoS</div>
                    <div className="mt-1 font-bold text-white">54 Botnet Ingress Nodes</div>
                    <div className="mt-0.5 text-[11px] text-emerald-400">
                      Neutralized at Edge Filter
                    </div>
                  </div>

                  <div className="rounded-xl border border-[#0e3a44] bg-[#03070c] p-3">
                    <div className="font-bold text-[#8aa4b8]">
                      T1190 • Exploit Public-Facing App
                    </div>
                    <div className="mt-1 font-bold text-white">APT-41 Zero-Day Laser</div>
                    <div className="mt-0.5 text-[11px] text-cyan-400">
                      eBPF Kernel Drop (0.31µs)
                    </div>
                  </div>

                  <div className="rounded-xl border border-[#0e3a44] bg-[#03070c] p-3">
                    <div className="font-bold text-[#8aa4b8]">T1070.002 • Clear Linux Logs</div>
                    <div className="mt-1 font-bold text-white">Rogue Admin Interception</div>
                    <div className="mt-0.5 text-[11px] text-[#f59e0b]">
                      Dual-Key Step-Up Intercepted
                    </div>
                  </div>
                </div>

                {/* Cryptographic Digital Signature Footer */}
                <div className="flex flex-col items-center justify-between gap-2 border-t border-[#0e3a44] pt-4 font-mono text-[11px] text-[#8aa4b8] sm:flex-row">
                  <div>
                    SHA-256 Seal:{' '}
                    <span className="font-bold text-emerald-400">
                      {soarReport.cryptographicSeal?.sha256Digest?.substring(0, 24)}...
                    </span>
                  </div>
                  <div>
                    Authority:{' '}
                    <span className="text-white">
                      SOVEREIGN_CYBER_COMMAND_AUTONOMOUS_ORCHESTRATOR
                    </span>
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* Footer Bar */}
          <div className="flex items-center justify-between border-t border-[#0e3a44] bg-[#0C0C0C] px-6 py-3 text-xs text-[#5c7484]">
            <span>SOVEREIGN DEFENDER 6.0 • MoD RED TEAM SIMULATOR</span>
            <div className="flex items-center gap-3">
              <button
                onClick={onClose}
                className="text-xs text-[#8aa4b8] transition hover:text-white"
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
