import React, { useState } from 'react';
import { ATTACK_VECTORS } from '../data/defaultThreatData';
import { AttackVectorType, SimulatorControls, TelemetryPacket } from '../types';
import {
  Play,
  Flame,
  StopCircle,
  RefreshCw,
  Zap,
  Shield,
  ShieldAlert,
  Sliders,
  Terminal,
  Crosshair,
  HelpCircle
} from 'lucide-react';

interface AttackSimulatorProps {
  onInjectPacket: (packetConfig: SimulatorControls) => Promise<any> | void;
  isStreaming: boolean;
  onToggleContinuousStream: (controls: SimulatorControls) => void;
  lang: 'ar' | 'en';
  latestGeneratedRules?: {
    iptables?: string;
    suricata?: string;
    ebpf?: string;
    analysisAr?: string;
    analysisEn?: string;
  } | null;
}

export const AttackSimulator: React.FC<AttackSimulatorProps> = ({
  onInjectPacket,
  isStreaming,
  onToggleContinuousStream,
  lang,
  latestGeneratedRules
}) => {
  const isAr = lang === 'ar';

  const [selectedVectorId, setSelectedVectorId] = useState<AttackVectorType>('SQL_INJECTION');
  const [spoofedIp, setSpoofedIp] = useState<string>('203.0.113.88');
  const [targetPort, setTargetPort] = useState<number>(443);
  const [packetSize, setPacketSize] = useState<number>(840);
  const [packetsPerSec, setPacketsPerSec] = useState<number>(120);
  const [durationSec, setDurationSec] = useState<number>(15);
  const [customPayload, setCustomPayload] = useState<string>(
    "' UNION SELECT null, username, password_hash, email FROM users-- -"
  );
  const [isInjecting, setIsInjecting] = useState<boolean>(false);

  const currentVector = ATTACK_VECTORS.find(v => v.id === selectedVectorId) || ATTACK_VECTORS[0];

  const handleVectorChange = (vectorId: AttackVectorType) => {
    setSelectedVectorId(vectorId);
    const vec = ATTACK_VECTORS.find(v => v.id === vectorId);
    if (vec) {
      setTargetPort(vec.defaultPort);
      setCustomPayload(vec.samplePayloads[0] || '');
      if (vectorId === 'SSH_BRUTE_FORCE') {
        setPacketSize(1850);
        setPacketsPerSec(260);
      } else if (vectorId === 'DDOS_AMPLIFICATION') {
        setPacketSize(4096);
        setPacketsPerSec(2500);
      } else if (vectorId === 'DNS_EXFILTRATION') {
        setPacketSize(512);
        setPacketsPerSec(45);
      } else {
        setPacketSize(840);
        setPacketsPerSec(120);
      }
    }
  };

  const getControlsState = (): SimulatorControls => ({
    selectedVector: selectedVectorId,
    spoofedSrcIp: spoofedIp,
    targetNodeId: selectedVectorId === 'LATERAL_MOVEMENT' ? 'node-db' : 'node-web',
    targetPort,
    packetSize,
    packetsPerSec,
    durationSec,
    customPayload,
    isContinuous: isStreaming
  });

  const handleSingleShot = async () => {
    setIsInjecting(true);
    try {
      await onInjectPacket(getControlsState());
    } finally {
      setIsInjecting(false);
    }
  };

  const handleBurst = async () => {
    setIsInjecting(true);
    try {
      for (let i = 0; i < 5; i++) {
        setTimeout(() => {
          onInjectPacket({
            ...getControlsState(),
            packetsPerSec: packetsPerSec * 2
          });
        }, i * 150);
      }
    } finally {
      setTimeout(() => setIsInjecting(false), 800);
    }
  };

  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900/90 p-5 shadow-xl shadow-[0_0_20px_rgba(0,255,255,0.08)]">
      {/* Title & Badge */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 pb-4">
        <div className="flex items-center gap-2.5">
          <div className="rounded-lg border border-rose-500/30 bg-rose-500/10 p-2 text-rose-400">
            <Flame className="h-5 w-5 animate-pulse" />
          </div>
          <div>
            <h2 className="text-lg font-bold text-white">
              {isAr
                ? 'محاكي الهجمات المتقدم وحاقن الحزم (Attack Simulator)'
                : 'Advanced Cyber Attack Simulator & Injector'}
            </h2>
            <p className="text-xs text-slate-400">
              {isAr
                ? 'محاكاة حية لمختلف ناقلات الهجوم، تزييف عناوين IP، وضبط معدل الحزم بالثانية'
                : 'Inject real-time cyber payloads, spoof source IPs, and test autonomous kernel response'}
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <span className="rounded border border-slate-700 bg-slate-800 px-2.5 py-1 font-mono text-xs text-slate-300">
            MITRE ATT&CK: <strong className="text-emerald-400">{currentVector.mitreId}</strong>
          </span>
          <span
            className={`rounded border px-2.5 py-1 text-xs font-bold ${
              currentVector.severity === 'CRITICAL'
                ? 'border-rose-500/40 bg-rose-500/20 text-rose-300'
                : currentVector.severity === 'HIGH'
                  ? 'border-amber-500/40 bg-amber-500/20 text-amber-300'
                  : 'border-cyan-500/40 bg-cyan-500/20 text-cyan-300'
            }`}
          >
            {currentVector.severity}
          </span>
        </div>
      </div>

      {/* Attack Vectors Grid Selector */}
      <div className="mt-4">
        <label className="mb-2 block text-xs font-bold text-slate-300">
          {isAr
            ? 'اختر ناقل الهجوم السيبراني (Cyber Attack Vector):'
            : 'Select Cyber Attack Vector:'}
        </label>
        <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
          {ATTACK_VECTORS.map(vector => {
            const isSelected = vector.id === selectedVectorId;
            return (
              <button
                key={vector.id}
                type="button"
                onClick={() => handleVectorChange(vector.id)}
                className={`rounded-xl border p-3 text-left transition-all ${
                  isSelected
                    ? 'border-rose-500/60 bg-rose-500/15 text-white shadow-md ring-1 shadow-rose-950/40 ring-rose-400/40'
                    : 'border-slate-800/80 bg-slate-950/60 text-slate-400 hover:bg-slate-800/60 hover:text-slate-200 shadow-[0_0_20px_rgba(0,255,255,0.08)]'
                }`}
              >
                <div className="mb-1 flex items-center justify-between">
                  <span className="rounded border border-slate-700 bg-slate-800 px-1.5 py-0.5 font-mono text-[10px] text-slate-300">
                    Port {vector.defaultPort}
                  </span>
                  <span className="text-[9px] font-bold text-rose-400">
                    {vector.mitreId.split(' ')[0]}
                  </span>
                </div>
                <div className="truncate text-xs font-bold text-slate-100">
                  {isAr ? vector.nameAr : vector.nameEn}
                </div>
              </button>
            );
          })}
        </div>
      </div>

      {/* Vector Description Callout */}
      <div className="mt-3.5 flex items-start gap-2.5 rounded-xl border border-slate-800 bg-slate-950/80 p-3 text-xs text-slate-300 shadow-[0_0_20px_rgba(0,255,255,0.08)]">
        <Crosshair className="mt-0.5 h-4 w-4 shrink-0 text-cyan-400" />
        <div>
          <strong className="text-white">
            {isAr ? currentVector.nameAr : currentVector.nameEn}:{' '}
          </strong>
          <span className="text-slate-400">
            {isAr ? currentVector.descriptionAr : currentVector.descriptionEn}
          </span>
        </div>
      </div>

      {/* Granular Sliders & Injection Controls Grid */}
      <div className="mt-5 grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-3">
        {/* 1. Source IP Spoofing */}
        <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-3.5 shadow-[0_0_20px_rgba(0,255,255,0.08)]">
          <label className="mb-1.5 block flex items-center justify-between text-xs font-bold text-slate-300">
            <span>{isAr ? 'عنوان IP المصدر المزيف (Spoofed IP):' : 'Spoofed Source IP:'}</span>
            <span className="font-mono text-[10px] text-cyan-400">IPv4 Spoof</span>
          </label>
          <input
            type="text"
            value={spoofedIp}
            onChange={e => setSpoofedIp(e.target.value)}
            className="w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 font-mono text-xs text-white focus:border-rose-500 focus:outline-none shadow-[0_0_20px_rgba(0,255,255,0.08)]"
            placeholder="e.g. 203.0.113.88"
          />
          {/* Quick presets */}
          <div className="mt-2 flex flex-wrap gap-1">
            <button
              onClick={() => setSpoofedIp('203.0.113.88')}
              className="rounded bg-slate-800 px-1.5 py-0.5 text-[10px] text-slate-300 hover:bg-slate-700"
            >
              Botnet C2
            </button>
            <button
              onClick={() => setSpoofedIp('185.220.101.5')}
              className="rounded bg-slate-800 px-1.5 py-0.5 text-[10px] text-slate-300 hover:bg-slate-700"
            >
              Tor Exit
            </button>
            <button
              onClick={() => setSpoofedIp('10.0.0.15')}
              className="rounded bg-slate-800 px-1.5 py-0.5 text-[10px] text-slate-300 hover:bg-slate-700"
            >
              Internal Pivot
            </button>
            <button
              onClick={() => setSpoofedIp('10.0.0.1')}
              className="rounded bg-emerald-900/60 px-1.5 py-0.5 text-[10px] text-emerald-300 hover:bg-emerald-800"
              title={isAr ? 'أصل محمي بالقائمة البيضاء (لن يتم طرده)' : 'Whitelisted Core Asset'}
            >
              Whitelisted (10.0.0.1)
            </button>
          </div>
        </div>

        {/* 2. Target Port & Protocol */}
        <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-3.5 shadow-[0_0_20px_rgba(0,255,255,0.08)]">
          <label className="mb-1.5 block flex items-center justify-between text-xs font-bold text-slate-300">
            <span>
              {isAr ? 'المنفذ والخدمة المستهدفة (Target Port):' : 'Target Port & Service:'}
            </span>
            <span className="font-mono text-[10px] text-cyan-400">Port {targetPort}</span>
          </label>
          <div className="flex gap-2">
            <input
              type="number"
              value={targetPort}
              onChange={e => setTargetPort(Number(e.target.value))}
              className="w-24 rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 font-mono text-xs text-white focus:border-rose-500 focus:outline-none shadow-[0_0_20px_rgba(0,255,255,0.08)]"
            />
            <div className="flex flex-1 flex-wrap gap-1">
              {[22, 80, 443, 53, 445, 3389, 5432].map(port => (
                <button
                  key={port}
                  onClick={() => setTargetPort(port)}
                  className={`rounded px-2 py-1 font-mono text-[10px] ${
                    targetPort === port
                      ? 'bg-rose-500 text-white'
                      : 'bg-slate-800 text-slate-300 hover:bg-slate-700'
                  }`}
                >
                  {port}
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* 3. Packet Size Slider */}
        <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-3.5 shadow-[0_0_20px_rgba(0,255,255,0.08)]">
          <div className="mb-1 flex items-center justify-between text-xs font-bold text-slate-300">
            <span>{isAr ? 'حجم الحزمة (Packet Size):' : 'Packet Size (Bytes):'}</span>
            <span className="font-mono text-cyan-400">{packetSize.toLocaleString()} B</span>
          </div>
          <input
            type="range"
            min="64"
            max="65535"
            step="128"
            value={packetSize}
            onChange={e => setPacketSize(Number(e.target.value))}
            className="h-1.5 w-full cursor-pointer appearance-none rounded-lg bg-slate-800 accent-rose-500"
          />
          <div className="mt-1 flex justify-between font-mono text-[10px] text-slate-500">
            <span>64 B</span>
            <span>1500 B (MTU)</span>
            <span>65 KB (Jumbo)</span>
          </div>
        </div>

        {/* 4. Injection Rate Slider (Packets/Sec) */}
        <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-3.5 shadow-[0_0_20px_rgba(0,255,255,0.08)]">
          <div className="mb-1 flex items-center justify-between text-xs font-bold text-slate-300">
            <span>{isAr ? 'معدل الحزم بالثانية (Rate):' : 'Payload Rate (Packets/Sec):'}</span>
            <span className="font-mono text-rose-400">{packetsPerSec.toLocaleString()} pps</span>
          </div>
          <input
            type="range"
            min="1"
            max="5000"
            step="50"
            value={packetsPerSec}
            onChange={e => setPacketsPerSec(Number(e.target.value))}
            className="h-1.5 w-full cursor-pointer appearance-none rounded-lg bg-slate-800 accent-rose-500"
          />
          <div className="mt-1 flex justify-between font-mono text-[10px] text-slate-500">
            <span>1 pps (Stealth)</span>
            <span>500 pps</span>
            <span>5,000 pps (Flood)</span>
          </div>
        </div>

        {/* 5. Connection Duration Slider */}
        <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-3.5 shadow-[0_0_20px_rgba(0,255,255,0.08)]">
          <div className="mb-1 flex items-center justify-between text-xs font-bold text-slate-300">
            <span>{isAr ? 'مدة الاتصال (Duration):' : 'Connection Duration (Sec):'}</span>
            <span className="font-mono text-amber-400">{durationSec}s</span>
          </div>
          <input
            type="range"
            min="1"
            max="120"
            step="1"
            value={durationSec}
            onChange={e => setDurationSec(Number(e.target.value))}
            className="h-1.5 w-full cursor-pointer appearance-none rounded-lg bg-slate-800 accent-amber-500"
          />
          <div className="mt-1 flex justify-between font-mono text-[10px] text-slate-500">
            <span>1s (Burst)</span>
            <span>30s</span>
            <span>120s (Sustained)</span>
          </div>
        </div>

        {/* 6. Target Infrastructure Node */}
        <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-3.5 shadow-[0_0_20px_rgba(0,255,255,0.08)]">
          <label className="mb-1.5 block text-xs font-bold text-slate-300">
            {isAr ? 'الهدف المستهدف في الشبكة:' : 'Target Network Node:'}
          </label>
          <div className="flex items-center justify-between rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 font-mono text-xs text-white shadow-[0_0_20px_rgba(0,255,255,0.08)]">
            <span>
              {selectedVectorId === 'LATERAL_MOVEMENT'
                ? '10.0.0.8 (Database Tier)'
                : selectedVectorId === 'DNS_EXFILTRATION'
                  ? '10.0.0.1 (Gateway DNS)'
                  : '10.0.0.5 (Target Web App)'}
            </span>
            <span className="text-[10px] text-emerald-400">● In-Range</span>
          </div>
        </div>
      </div>

      {/* Custom Exploit Payload Input */}
      <div className="mt-4">
        <label className="mb-1.5 block flex items-center justify-between text-xs font-bold text-slate-300">
          <span>
            {isAr ? 'حمولة الهجوم الخام (Raw Exploit Payload):' : 'Raw Exploit / Test Payload:'}
          </span>
          <span className="text-[10px] text-slate-400">
            {isAr ? 'يمكنك تعديل الحمولة يدوياً' : 'Editable Payload'}
          </span>
        </label>
        <textarea
          rows={2}
          value={customPayload}
          onChange={e => setCustomPayload(e.target.value)}
          className="w-full rounded-xl border border-slate-800 bg-slate-950 px-3.5 py-2 font-mono text-xs text-emerald-300 focus:border-rose-500 focus:outline-none shadow-[0_0_20px_rgba(0,255,255,0.08)]"
          placeholder="Enter exploit payload string or command..."
        />
      </div>

      {/* Action Buttons Bar */}
      <div className="mt-5 flex flex-wrap items-center justify-between gap-3 border-t border-slate-800 pt-4">
        <div className="flex items-center gap-2">
          {/* 1. Single Shot Injection */}
          <button
            type="button"
            onClick={handleSingleShot}
            className="flex items-center gap-2 rounded-xl bg-gradient-to-r from-rose-600 to-rose-600 px-5 py-2.5 text-xs font-bold text-white shadow-lg shadow-rose-950/50 transition hover:from-rose-500 hover:to-rose-500 active:scale-95 sm:text-sm"
          >
            <Play className="h-4 w-4 fill-white" />
            <span>{isAr ? 'حقن حزمة منفردة (Inject Packet)' : 'Inject Single Packet'}</span>
          </button>

          {/* 2. Burst 10x */}
          <button
            type="button"
            onClick={handleBurst}
            className="flex items-center gap-2 rounded-xl border border-slate-700 bg-slate-800 px-4 py-2.5 text-xs font-bold text-slate-200 transition hover:bg-slate-700 active:scale-95 sm:text-sm"
          >
            <Zap className="h-4 w-4 text-amber-400" />
            <span>{isAr ? 'دفعة مكثفة (Burst 5x)' : 'Burst Attack (5x)'}</span>
          </button>
        </div>

        {/* 3. Continuous Injection Stream Toggle */}
        <button
          type="button"
          onClick={() => onToggleContinuousStream(getControlsState())}
          className={`flex items-center gap-2 rounded-xl px-5 py-2.5 text-xs font-bold shadow-md transition sm:text-sm ${
            isStreaming
              ? 'animate-pulse bg-rose-500 text-white hover:bg-rose-600'
              : 'bg-emerald-600/90 text-white hover:bg-emerald-500'
          }`}
        >
          {isStreaming ? (
            <>
              <StopCircle className="h-4 w-4" />
              <span>{isAr ? 'إيقاف التدفق الحي (Stop Stream)' : 'Stop Live Stream'}</span>
            </>
          ) : (
            <>
              <Play className="h-4 w-4" />
              <span>
                {isAr ? 'تشغيل تدفق مستمر (Continuous Stream)' : 'Start Continuous Stream'}
              </span>
            </>
          )}
        </button>
      </div>

      {/* Live Gemini-Generated Kernel Rules Card */}
      {latestGeneratedRules && (
        <div className="animate-fadeIn mt-5 space-y-3 rounded-xl border border-slate-800 bg-slate-950 p-4 font-mono text-xs shadow-[0_0_20px_rgba(0,255,255,0.08)]">
          <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800 pb-2">
            <div className="flex items-center gap-2 font-sans font-bold text-cyan-400">
              <Shield className="h-4 w-4" />
              <span>
                {isAr
                  ? 'قواعد الدفاع الفورية المولدة عبر الذكاء الاصطناعي (Live Synthesized Rules):'
                  : 'Live Autonomous Defense Rules Synthesized:'}
              </span>
            </div>
            <span className="font-mono text-[10px] text-emerald-400">
              POST /api/generate-rules ● Active
            </span>
          </div>

          {(latestGeneratedRules.analysisAr || latestGeneratedRules.analysisEn) && (
            <p className="font-sans text-xs text-slate-300">
              {isAr ? latestGeneratedRules.analysisAr : latestGeneratedRules.analysisEn}
            </p>
          )}

          <div className="grid grid-cols-1 gap-2 text-[11px] md:grid-cols-3">
            {latestGeneratedRules.iptables && (
              <div className="rounded-lg border border-slate-800 bg-slate-900 p-2.5 shadow-[0_0_20px_rgba(0,255,255,0.08)]">
                <span className="mb-0.5 block text-[9px] text-slate-400">
                  1. Linux IPTables Drop:
                </span>
                <code className="block truncate text-rose-300">
                  {latestGeneratedRules.iptables}
                </code>
              </div>
            )}
            {latestGeneratedRules.suricata && (
              <div className="rounded-lg border border-slate-800 bg-slate-900 p-2.5 shadow-[0_0_20px_rgba(0,255,255,0.08)]">
                <span className="mb-0.5 block text-[9px] text-slate-400">
                  2. Suricata / Snort Signature:
                </span>
                <code className="block truncate text-amber-300">
                  {latestGeneratedRules.suricata}
                </code>
              </div>
            )}
            {latestGeneratedRules.ebpf && (
              <div className="rounded-lg border border-slate-800 bg-slate-900 p-2.5 shadow-[0_0_20px_rgba(0,255,255,0.08)]">
                <span className="mb-0.5 block text-[9px] text-slate-400">3. eBPF XDP Filter:</span>
                <code className="block truncate text-cyan-300">{latestGeneratedRules.ebpf}</code>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
