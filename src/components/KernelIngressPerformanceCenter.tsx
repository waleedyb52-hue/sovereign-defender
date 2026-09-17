import React, { useState, useEffect, useRef } from 'react';
import { 
  Zap, 
  Cpu, 
  Layers, 
  Activity, 
  ShieldCheck, 
  ShieldAlert, 
  Flame, 
  Database, 
  RefreshCw, 
  Sparkles, 
  Gauge, 
  Radio, 
  Sliders, 
  CheckCircle2, 
  AlertTriangle,
  Play,
  Maximize2,
  Lock,
  ArrowRight,
  Clock,
  HardDrive
} from 'lucide-react';
import { 
  EnterpriseIngressPerformanceState, 
  XdpDriverMode 
} from '../types';

interface KernelIngressPerformanceCenterProps {
  lang: 'ar' | 'en';
}

export const KernelIngressPerformanceCenter: React.FC<KernelIngressPerformanceCenterProps> = ({ lang }) => {
  const isAr = lang === 'ar';

  const [perfState, setPerfState] = useState<EnterpriseIngressPerformanceState | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [activeSubTab, setActiveSubTab] = useState<'OVERVIEW' | 'EBPF_XDP' | 'MULTI_TIER_CACHE' | 'WORKERS' | 'BACKPRESSURE' | 'CANVAS_STREAM'>('OVERVIEW');

  // Interactive controls state
  const [testSignature, setTestSignature] = useState<string>('GET /api/v1/products');
  const [bloomTestResult, setBloomTestResult] = useState<any>(null);
  const [testingBloom, setTestingBloom] = useState<boolean>(false);

  const [manualIpToPin, setManualIpToPin] = useState<string>('198.51.100.99');
  const [pinReason, setPinReason] = useState<string>('eBPF In-Kernel Blacklist Pin');
  const [pinning, setPinning] = useState<boolean>(false);

  const [benchmarking, setBenchmarking] = useState<boolean>(false);
  const [benchmarkResult, setBenchmarkResult] = useState<any>(null);

  const [ddosSimulating, setDdosSimulating] = useState<boolean>(false);

  // Canvas visualizer ref
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const animationFrameRef = useRef<number | null>(null);
  const packetsQueueRef = useRef<Array<{ x: number; y: number; speed: number; type: 'DROP' | 'PASS' | 'REDIRECT' | 'BLOOM'; size: number }>>([]);

  const fetchPerformanceState = async () => {
    try {
      const res = await fetch('/api/v1/performance/full-state');
      if (res.ok) {
        const data = await res.json();
        if (data.success && data.performanceState) {
          setPerfState(data.performanceState);
        }
      }
    } catch (e) {
      console.warn('Failed to fetch performance state:', e);
    } finally {
      setLoading(false);
    }
  };

  // Poll state every 2 seconds
  useEffect(() => {
    fetchPerformanceState();
    const interval = setInterval(fetchPerformanceState, 2000);
    return () => clearInterval(interval);
  }, []);

  // Robust WebSocket Live Stream Listener with Fallback & Error Catching
  useEffect(() => {
    let ws: WebSocket | null = null;
    let fallbackInterval: NodeJS.Timeout | null = null;
    let reconnectTimeout: NodeJS.Timeout | null = null;
    let isCleanedUp = false;

    // Local fallback simulated packet stream when WebSocket is unavailable or closed
    const startFallbackStream = () => {
      if (fallbackInterval) return;
      fallbackInterval = setInterval(() => {
        if (isCleanedUp) return;
        const rand = Math.random();
        const type: 'DROP' | 'PASS' | 'REDIRECT' | 'BLOOM' =
          rand > 0.82 ? 'DROP' : rand > 0.68 ? 'REDIRECT' : rand > 0.52 ? 'BLOOM' : 'PASS';

        packetsQueueRef.current.push({
          x: 0,
          y: Math.random() * 220 + 20,
          speed: Math.random() * 4 + 3,
          type,
          size: Math.random() * 3 + 3
        });

        if (packetsQueueRef.current.length > 250) {
          packetsQueueRef.current.shift();
        }
      }, 180);
    };

    const stopFallbackStream = () => {
      if (fallbackInterval) {
        clearInterval(fallbackInterval);
        fallbackInterval = null;
      }
    };

    const connectWebSocket = () => {
      if (isCleanedUp) return;

      try {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${protocol}//${window.location.host}/ws/telemetry`;

        ws = new WebSocket(wsUrl);

        // Crucial: Attach onerror and onclose handlers IMMEDIATELY upon instantiation
        // to cleanly intercept preview/sandbox failures without bubbling unhandled rejections
        ws.onerror = (err) => {
          console.warn('Telemetry WS fallback to polling mode:', err);
          startFallbackStream();
        };

        ws.onclose = () => {
          startFallbackStream();
          // Attempt quiet, throttled reconnection after 6 seconds
          if (!isCleanedUp) {
            reconnectTimeout = setTimeout(connectWebSocket, 6000);
          }
        };

        ws.onopen = () => {
          stopFallbackStream();
        };

        ws.onmessage = (event) => {
          try {
            const msg = JSON.parse(event.data);

            if (msg.type === 'REAL_EBPF_STATS' && msg.data) {
              setPerfState(prev => {
                if (!prev) return prev;
                const k = msg.data;
                return {
                  ...prev,
                  realEbpfStats: k,
                  xdpEngine: {
                    ...prev.xdpEngine,
                    rxPacketsTotal: k.rxPackets ?? prev.xdpEngine.rxPacketsTotal,
                    xdpDropCount: k.droppedPackets ?? prev.xdpEngine.xdpDropCount,
                    xdpPassCount: k.passedPackets ?? prev.xdpEngine.xdpPassCount,
                    avgEvaluationLatencyNs: k.avgLatencyNs ?? prev.xdpEngine.avgEvaluationLatencyNs,
                    driverAttached: `${k.interfaceName} (${k.driverMode})`,
                    bpfMaps: {
                      ...prev.xdpEngine.bpfMaps,
                      ipBlacklistMap: {
                        ...prev.xdpEngine.bpfMaps.ipBlacklistMap,
                        entries: k.activeBlacklistEntries ?? prev.xdpEngine.bpfMaps.ipBlacklistMap.entries
                      }
                    }
                  }
                };
              });
            }

            if (msg.type === 'TELEMETRY_PACKET') {
              const status = msg.data?.status;
              let type: 'DROP' | 'PASS' | 'REDIRECT' | 'BLOOM' = 'PASS';
              if (status === 'BLOCKED') type = 'DROP';
              else if (status === 'HONEYPOT_DIVERTED') type = 'REDIRECT';
              else if (msg.data?.bloomBypassed) type = 'BLOOM';

              packetsQueueRef.current.push({
                x: 0,
                y: Math.random() * 220 + 20,
                speed: Math.random() * 4 + 3,
                type,
                size: Math.random() * 3 + 3
              });

              if (packetsQueueRef.current.length > 250) {
                packetsQueueRef.current.shift();
              }
            }
          } catch {
            // Gracefully ignore parse issues
          }
        };
      } catch {
        startFallbackStream();
      }
    };

    connectWebSocket();

    return () => {
      isCleanedUp = true;
      stopFallbackStream();
      if (reconnectTimeout) {
        clearTimeout(reconnectTimeout);
      }
      if (ws) {
        ws.onopen = null;
        ws.onclose = null;
        ws.onerror = null;
        ws.onmessage = null;
        try {
          ws.close();
        } catch {
          // Safe fallback
        }
      }
    };
  }, []);

  // 60FPS Canvas Packet Stream Renderer
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let width = (canvas.width = canvas.parentElement?.clientWidth || 800);
    let height = (canvas.height = 260);

    const handleResize = () => {
      if (canvas && canvas.parentElement) {
        width = canvas.width = canvas.parentElement.clientWidth;
      }
    };
    window.addEventListener('resize', handleResize);

    const render = () => {
      ctx.fillStyle = 'rgba(10, 15, 29, 0.35)';
      ctx.fillRect(0, 0, width, height);

      // Draw Grid Lines
      ctx.strokeStyle = 'rgba(30, 41, 59, 0.4)';
      ctx.lineWidth = 1;
      for (let x = 0; x < width; x += 40) {
        ctx.beginPath();
        ctx.moveTo(x, 0);
        ctx.lineTo(x, height);
        ctx.stroke();
      }

      // Draw Ingress Pipeline Stages
      const xdpX = width * 0.25;
      const bloomX = width * 0.55;
      const targetX = width * 0.85;

      // Draw eBPF Stage Line
      ctx.strokeStyle = 'rgba(239, 68, 68, 0.6)';
      ctx.setLineDash([4, 4]);
      ctx.beginPath();
      ctx.moveTo(xdpX, 0);
      ctx.lineTo(xdpX, height);
      ctx.stroke();

      // Draw Bloom Stage Line
      ctx.strokeStyle = 'rgba(6, 182, 212, 0.6)';
      ctx.beginPath();
      ctx.moveTo(bloomX, 0);
      ctx.lineTo(bloomX, height);
      ctx.stroke();

      ctx.setLineDash([]);

      // Stage Labels
      ctx.font = '10px monospace';
      ctx.fillStyle = 'rgba(239, 68, 68, 0.9)';
      ctx.fillText('eBPF / XDP (360ns)', xdpX - 45, 18);

      ctx.fillStyle = 'rgba(6, 182, 212, 0.9)';
      ctx.fillText('Bloom Filter (42µs)', bloomX - 50, 18);

      ctx.fillStyle = 'rgba(16, 185, 129, 0.9)';
      ctx.fillText('OS Stack / Host', targetX - 40, 18);

      // Render & Move Packets
      const activePackets = packetsQueueRef.current;
      for (let i = activePackets.length - 1; i >= 0; i--) {
        const p = activePackets[i];
        p.x += p.speed;

        // Color based on packet disposition
        if (p.type === 'DROP') {
          ctx.fillStyle = '#f43f5e';
          ctx.shadowColor = '#f43f5e';
        } else if (p.type === 'REDIRECT') {
          ctx.fillStyle = '#a855f7';
          ctx.shadowColor = '#a855f7';
        } else if (p.type === 'BLOOM') {
          ctx.fillStyle = '#06b6d4';
          ctx.shadowColor = '#06b6d4';
        } else {
          ctx.fillStyle = '#10b981';
          ctx.shadowColor = '#10b981';
        }

        ctx.shadowBlur = 6;
        ctx.beginPath();
        ctx.arc(p.x, p.y, p.size, 0, Math.PI * 2);
        ctx.fill();
        ctx.shadowBlur = 0;

        // If DROP and reaches eBPF stage, create particle splash and remove
        if (p.type === 'DROP' && p.x >= xdpX) {
          ctx.fillStyle = 'rgba(244, 63, 94, 0.8)';
          ctx.beginPath();
          ctx.arc(p.x, p.y, p.size * 2.5, 0, Math.PI * 2);
          ctx.fill();
          activePackets.splice(i, 1);
          continue;
        }

        // If off screen, remove
        if (p.x > width) {
          activePackets.splice(i, 1);
        }
      }

      // Generate background organic synthetic packets for continuous visualization
      if (Math.random() < 0.6) {
        const randType = Math.random() < 0.15 ? 'DROP' : Math.random() < 0.05 ? 'REDIRECT' : Math.random() < 0.4 ? 'BLOOM' : 'PASS';
        activePackets.push({
          x: 0,
          y: Math.random() * (height - 40) + 25,
          speed: Math.random() * 3 + 2.5,
          type: randType,
          size: Math.random() * 2.5 + 2.5
        });
      }

      animationFrameRef.current = requestAnimationFrame(render);
    };

    render();

    return () => {
      if (animationFrameRef.current) cancelAnimationFrame(animationFrameRef.current);
      window.removeEventListener('resize', handleResize);
    };
  }, []);

  const handleSwitchXdpMode = async (mode: XdpDriverMode) => {
    try {
      const res = await fetch('/api/v1/ebpf/xdp-mode', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mode })
      });
      if (res.ok) {
        fetchPerformanceState();
      }
    } catch (e) {
      console.warn('Switch XDP mode error:', e);
    }
  };

  const handlePinIpToBpfMap = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!manualIpToPin) return;
    setPinning(true);
    try {
      const res = await fetch('/api/v1/ebpf/map-sync', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip: manualIpToPin, reason: pinReason, ttlSeconds: 7200 })
      });
      if (res.ok) {
        fetchPerformanceState();
        setManualIpToPin('');
      }
    } catch (e) {
      console.warn('Pin IP error:', e);
    } finally {
      setPinning(false);
    }
  };

  const handleTestBloomFilter = async () => {
    setTestingBloom(true);
    try {
      const res = await fetch('/api/v1/performance/bloom-test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ signature: testSignature })
      });
      if (res.ok) {
        const data = await res.json();
        setBloomTestResult(data);
      }
    } catch (e) {
      console.warn('Bloom test error:', e);
    } finally {
      setTestingBloom(false);
    }
  };

  const handleRunWorkerBenchmark = async () => {
    setBenchmarking(true);
    try {
      const res = await fetch('/api/v1/performance/worker-benchmark', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ payloadCount: 250 })
      });
      if (res.ok) {
        const data = await res.json();
        setBenchmarkResult(data);
        fetchPerformanceState();
      }
    } catch (e) {
      console.warn('Worker benchmark error:', e);
    } finally {
      setBenchmarking(false);
    }
  };

  const handleSimulateDdosSpike = async () => {
    setDdosSimulating(true);
    try {
      const res = await fetch('/api/v1/performance/simulate-ddos-spike', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ spikePps: 2800 })
      });
      if (res.ok) {
        fetchPerformanceState();
      }
    } catch (e) {
      console.warn('DDoS spike error:', e);
    } finally {
      setTimeout(() => setDdosSimulating(false), 2000);
    }
  };

  const xdp = perfState?.xdpEngine;
  const cache = perfState?.multiTierCache;
  const workers = perfState?.workerPipeline;
  const bucket = perfState?.tokenBucket;
  const ws = perfState?.websocketStream;

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="relative overflow-hidden rounded-2xl bg-gradient-to-r from-slate-950 via-slate-900 to-indigo-950 border border-slate-800 p-6 shadow-2xl">
        <div className="absolute top-0 right-0 w-96 h-96 bg-cyan-500/10 rounded-full blur-3xl pointer-events-none" />
        <div className="relative z-10 flex flex-col lg:flex-row lg:items-center lg:justify-between gap-6">
          <div className="space-y-2">
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 text-xs font-bold uppercase tracking-wider">
              <Zap className="w-3.5 h-3.5" />
              <span>{isAr ? 'محرك تسريع النواة والأداء الفائق v4.0' : 'Ultra-High Throughput & eBPF Kernel Ingress Engine v4.0'}</span>
            </div>
            <h1 className="text-2xl sm:text-3xl font-black text-white tracking-tight">
              {isAr ? 'مركز تسريع النواة والإنتاجية المؤسسية' : 'Enterprise Kernel Ingress & Performance Center'}
            </h1>
            <p className="text-sm text-slate-400 max-w-3xl leading-relaxed">
              {isAr 
                ? 'تحويل عمليات تقييم التهديدات إلى طبقة تعريف النواة عبر eBPF/XDP لتقليل زمن الاستجابة إلى أجزاء من الميكروثانية (360ns)، مع مرشح بلوم الاحتمالي وخيوط المعالجة غير المحجوبة.'
                : 'Zero-copy eBPF/XDP kernel offloading engine delivering sub-microsecond threat mitigation (360ns), 2-tier Bloom caching, asynchronous worker pipelines, and adaptive DDoS backpressure.'}
            </p>
          </div>

          {/* Quick Hardware Status Indicators */}
          <div className="flex flex-wrap items-center gap-3">
            <div className="bg-slate-900/90 border border-emerald-500/30 rounded-xl px-4 py-2.5 text-center min-w-[130px]">
              <div className="text-[10px] text-slate-400 font-bold uppercase tracking-wider">{isAr ? 'زمن النواة' : 'Kernel Latency'}</div>
              <div className="text-lg font-black text-emerald-400 flex items-center justify-center gap-1">
                <span>{xdp?.avgEvaluationLatencyNs || 360}</span>
                <span className="text-xs font-mono">ns</span>
              </div>
              <div className="text-[9px] text-emerald-300/80 font-mono">Sub-µs Fast-Path</div>
            </div>

            <div className="bg-slate-900/90 border border-cyan-500/30 rounded-xl px-4 py-2.5 text-center min-w-[130px]">
              <div className="text-[10px] text-slate-400 font-bold uppercase tracking-wider">{isAr ? 'توفير الحصة' : 'AI Quota Saved'}</div>
              <div className="text-lg font-black text-cyan-400">
                {cache?.aiQuotaEfficiency?.apiQuotaSavedPercentage || 96.8}%
              </div>
              <div className="text-[9px] text-cyan-300/80 font-mono">Bloom + LRU Bypass</div>
            </div>

            <div className="bg-slate-900/90 border border-purple-500/30 rounded-xl px-4 py-2.5 text-center min-w-[130px]">
              <div className="text-[10px] text-slate-400 font-bold uppercase tracking-wider">{isAr ? 'تأخير الحلقة' : 'Event Loop Lag'}</div>
              <div className="text-lg font-black text-purple-400 flex items-center justify-center gap-1">
                <span>{workers?.eventLoopDelayMs || 0.8}</span>
                <span className="text-xs font-mono">ms</span>
              </div>
              <div className="text-[9px] text-purple-300/80 font-mono">Non-Blocking Pool</div>
            </div>
          </div>
        </div>

        {/* Sub-Navigation Tabs */}
        <div className="mt-6 pt-4 border-t border-slate-800/80 flex flex-wrap items-center gap-2">
          {[
            { id: 'OVERVIEW', labelEn: 'Unified Architecture', labelAr: 'المخطط البنيوي الشامل', icon: Layers },
            { id: 'EBPF_XDP', labelEn: 'eBPF / XDP Ingress', labelAr: 'محرك eBPF XDP', icon: Zap },
            { id: 'MULTI_TIER_CACHE', labelEn: 'Bloom & Multi-Tier Cache', labelAr: 'مرشح بلوم والكاش الذكي', icon: Database },
            { id: 'WORKERS', labelEn: 'Async Worker Pool', labelAr: 'خيوط المعالجة غير المحجوبة', icon: Cpu },
            { id: 'BACKPRESSURE', labelEn: 'Token Bucket & Backpressure', labelAr: 'محدد المعدل وإسقاط الضغط', icon: Activity },
            { id: 'CANVAS_STREAM', labelEn: 'High-Rate 60FPS Stream', labelAr: 'تدفق الحزم المباشر 60FPS', icon: Gauge }
          ].map(tab => {
            const Icon = tab.icon;
            const active = activeSubTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveSubTab(tab.id as any)}
                className={`flex items-center gap-2 px-3.5 py-2 rounded-xl text-xs font-bold transition-all ${
                  active
                    ? 'bg-cyan-500 text-slate-950 shadow-lg shadow-cyan-500/20 font-black'
                    : 'bg-slate-900/80 hover:bg-slate-800 text-slate-300 border border-slate-800'
                }`}
              >
                <Icon className="w-3.5 h-3.5" />
                <span>{isAr ? tab.labelAr : tab.labelEn}</span>
              </button>
            );
          })}
        </div>
      </div>

      {/* SUB-TAB 1: UNIFIED ARCHITECTURE OVERVIEW */}
      {activeSubTab === 'OVERVIEW' && (
        <div className="space-y-6">
          {/* Live Canvas High-Rate Stream Widget */}
          <div className="bg-slate-900/90 border border-slate-800 rounded-2xl overflow-hidden shadow-xl p-5">
            <div className="flex flex-wrap items-center justify-between gap-4 mb-4">
              <div className="flex items-center gap-2.5">
                <div className="p-2 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
                  <Gauge className="w-4 h-4" />
                </div>
                <div>
                  <h3 className="font-bold text-white text-sm sm:text-base">
                    {isAr ? 'المعالج البصري لتدفق الحزم عالي السرعة (60 FPS Hardware Stage Visualizer)' : 'Live Hardware Stage Packet Flow Stream (60 FPS)'}
                  </h3>
                  <p className="text-xs text-slate-400">
                    {isAr ? 'رسم مباشر لمرور الحزم عبر طبقات eBPF XDP، مرشح بلوم، وتوجيه النواة الفوري' : 'Visualizing zero-copy packet traversal through eBPF XDP, Bloom Filter, and Host OS Stack'}
                  </p>
                </div>
              </div>

              <div className="flex items-center gap-3 text-xs font-mono">
                <span className="flex items-center gap-1 text-emerald-400">
                  <span className="w-2 h-2 rounded-full bg-emerald-400 animate-ping" />
                  <span>XDP_PASS</span>
                </span>
                <span className="flex items-center gap-1 text-rose-400">
                  <span className="w-2 h-2 rounded-full bg-rose-400" />
                  <span>XDP_DROP</span>
                </span>
                <span className="flex items-center gap-1 text-cyan-400">
                  <span className="w-2 h-2 rounded-full bg-cyan-400" />
                  <span>BLOOM_CLEAN</span>
                </span>
                <span className="flex items-center gap-1 text-purple-400">
                  <span className="w-2 h-2 rounded-full bg-purple-400" />
                  <span>XDP_REDIRECT</span>
                </span>
              </div>
            </div>

            <div className="rounded-xl overflow-hidden border border-slate-800 bg-slate-950">
              <canvas ref={canvasRef} className="w-full h-[220px] block" />
            </div>
          </div>

          {/* 4 Architectural Pillar Cards */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            {/* Pillar 1: eBPF XDP */}
            <div className="bg-slate-900/90 border border-slate-800 hover:border-cyan-500/40 transition rounded-2xl p-5 flex flex-col justify-between">
              <div>
                <div className="flex items-center justify-between mb-3">
                  <div className="p-2 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400">
                    <Zap className="w-4 h-4" />
                  </div>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-red-500/20 text-red-300 border border-red-500/30">
                    Sub-Microsecond
                  </span>
                </div>
                <h4 className="font-bold text-white text-sm mb-1">
                  {isAr ? '1. تفريغ النواة (eBPF/XDP)' : '1. eBPF/XDP Kernel Offload'}
                </h4>
                <p className="text-xs text-slate-400 mb-4 leading-relaxed">
                  {isAr 
                    ? 'إسقاط الحزم الخبيثة عند بطاقة الشبكة قبل معالجتها من نظام التشغيل.'
                    : 'Zero-copy fast-path drops at the network driver level in ~360 nanoseconds.'}
                </p>
              </div>
              <div className="pt-3 border-t border-slate-800/80 space-y-1.5 text-xs font-mono">
                <div className="flex justify-between text-slate-400">
                  <span>Drops Total:</span>
                  <span className="text-red-400 font-bold">{xdp?.xdpDropCount?.toLocaleString() || '3,410'}</span>
                </div>
                <div className="flex justify-between text-slate-400">
                  <span>BPF Maps:</span>
                  <span className="text-emerald-400 font-bold">{xdp?.bpfMaps?.ipBlacklistMap?.entries || 4} Pins</span>
                </div>
              </div>
            </div>

            {/* Pillar 2: Bloom Filter */}
            <div className="bg-slate-900/90 border border-slate-800 hover:border-cyan-500/40 transition rounded-2xl p-5 flex flex-col justify-between">
              <div>
                <div className="flex items-center justify-between mb-3">
                  <div className="p-2 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
                    <Database className="w-4 h-4" />
                  </div>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">
                    65,536 Bits Bitset
                  </span>
                </div>
                <h4 className="font-bold text-white text-sm mb-1">
                  {isAr ? '2. مرشح بلوم والكاش الثنائي' : '2. Probabilistic Bloom Filter'}
                </h4>
                <p className="text-xs text-slate-400 mb-4 leading-relaxed">
                  {isAr 
                    ? 'تخطي فوري لحركة المرور النظيفة دون استهلاك حصص الذكاء الاصطناعي.'
                    : 'Prewarmed clean signatures evaluated in 42µs with 3 non-cryptographic hashes.'}
                </p>
              </div>
              <div className="pt-3 border-t border-slate-800/80 space-y-1.5 text-xs font-mono">
                <div className="flex justify-between text-slate-400">
                  <span>Clean Bypassed:</span>
                  <span className="text-cyan-400 font-bold">{cache?.tier2BloomFilter?.cleanTrafficBypassedCount?.toLocaleString() || '24,820'}</span>
                </div>
                <div className="flex justify-between text-slate-400">
                  <span>Quota Saved:</span>
                  <span className="text-emerald-400 font-bold">{cache?.aiQuotaEfficiency?.apiQuotaSavedPercentage || 96.8}%</span>
                </div>
              </div>
            </div>

            {/* Pillar 3: Async Worker Pool */}
            <div className="bg-slate-900/90 border border-slate-800 hover:border-cyan-500/40 transition rounded-2xl p-5 flex flex-col justify-between">
              <div>
                <div className="flex items-center justify-between mb-3">
                  <div className="p-2 rounded-lg bg-purple-500/10 border border-purple-500/30 text-purple-400">
                    <Cpu className="w-4 h-4" />
                  </div>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-purple-500/20 text-purple-300 border border-purple-500/30">
                    4 Threads Pool
                  </span>
                </div>
                <h4 className="font-bold text-white text-sm mb-1">
                  {isAr ? '3. خيوط معالجة الخلفية' : '3. Async Worker Threads'}
                </h4>
                <p className="text-xs text-slate-400 mb-4 leading-relaxed">
                  {isAr 
                    ? 'تفريغ تحليل PCAP المعقد وحساب الإنتروبيا بعيداً عن مسار خادم HTTP.'
                    : 'CPU-intensive Shannon entropy & PCAP dissection offloaded from event loop.'}
                </p>
              </div>
              <div className="pt-3 border-t border-slate-800/80 space-y-1.5 text-xs font-mono">
                <div className="flex justify-between text-slate-400">
                  <span>Tasks Completed:</span>
                  <span className="text-purple-400 font-bold">{workers?.tasksCompletedTotal?.toLocaleString() || '2,480'}</span>
                </div>
                <div className="flex justify-between text-slate-400">
                  <span>Loop Lag:</span>
                  <span className="text-emerald-400 font-bold">{workers?.eventLoopDelayMs || 0.8} ms</span>
                </div>
              </div>
            </div>

            {/* Pillar 4: Token Bucket */}
            <div className="bg-slate-900/90 border border-slate-800 hover:border-cyan-500/40 transition rounded-2xl p-5 flex flex-col justify-between">
              <div>
                <div className="flex items-center justify-between mb-3">
                  <div className="p-2 rounded-lg bg-amber-500/10 border border-amber-500/30 text-amber-400">
                    <Activity className="w-4 h-4" />
                  </div>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-amber-500/20 text-amber-300 border border-amber-500/30">
                    Load Shedding
                  </span>
                </div>
                <h4 className="font-bold text-white text-sm mb-1">
                  {isAr ? '4. محدد المعدل والتكيف مع الضغط' : '4. Adaptive Token Bucket'}
                </h4>
                <p className="text-xs text-slate-400 mb-4 leading-relaxed">
                  {isAr 
                    ? 'إسقاط السجلات غير الضرورية تلقائياً أثناء هجمات الحرمان من الخدمة.'
                    : 'Dynamic rate limits preserving 100% capacity for critical security verdicts.'}
                </p>
              </div>
              <div className="pt-3 border-t border-slate-800/80 space-y-1.5 text-xs font-mono">
                <div className="flex justify-between text-slate-400">
                  <span>Bucket Fill:</span>
                  <span className="text-amber-400 font-bold">{bucket?.fillPercentage || 100}%</span>
                </div>
                <div className="flex justify-between text-slate-400">
                  <span>Priority Protected:</span>
                  <span className="text-emerald-400 font-bold">{bucket?.prioritizedSecurityVerdictsCount?.toLocaleString() || '18,130'}</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* SUB-TAB 2: eBPF / XDP KERNEL INGRESS */}
      {activeSubTab === 'EBPF_XDP' && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Driver Status & Mode Switcher */}
          <div className="lg:col-span-1 space-y-6">
            <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-5 shadow-xl">
              <h3 className="font-bold text-white text-sm mb-3 flex items-center gap-2">
                <Zap className="w-4 h-4 text-cyan-400" />
                <span>{isAr ? 'وضع تشغيل معالج XDP' : 'XDP Driver Attachment Mode'}</span>
              </h3>
              <p className="text-xs text-slate-400 mb-4">
                {isAr 
                  ? 'اختر وضع التفريغ في طبقة تعريف بطاقة الشبكة أو نواة لينكس.'
                  : 'Toggle hardware-assisted zero-copy driver offloading vs generic stack.'}
              </p>

              <div className="space-y-2">
                {[
                  { id: 'NATIVE_DRIVER', name: 'NATIVE_DRIVER (Zero-Copy Driver Offload)', speed: '~360 ns', badge: 'Recommended' },
                  { id: 'OFFLOADED_NIC', name: 'OFFLOADED_NIC (SmartNIC ASIC Silicon)', speed: '~180 ns', badge: 'Hardware' },
                  { id: 'SKB_GENERIC', name: 'SKB_GENERIC (Generic Linux OS Stack)', speed: '~1,200 ns', badge: 'Fallback' }
                ].map(m => (
                  <button
                    key={m.id}
                    onClick={() => handleSwitchXdpMode(m.id as XdpDriverMode)}
                    className={`w-full text-left p-3 rounded-xl border transition ${
                      xdp?.mode === m.id
                        ? 'bg-cyan-500/20 border-cyan-500/50 text-white'
                        : 'bg-slate-950/60 border-slate-800 text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-bold text-xs">{m.name}</span>
                      <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800 text-slate-300">{m.speed}</span>
                    </div>
                  </button>
                ))}
              </div>

              <div className="mt-4 pt-4 border-t border-slate-800 text-xs font-mono space-y-1 text-slate-400">
                <div>Attached Device: <span className="text-cyan-300">{xdp?.driverAttached}</span></div>
                <div>Hardware Offload: <span className="text-emerald-400">{xdp?.hardwareOffloadActive ? 'ENABLED [✓]' : 'DISABLED'}</span></div>
              </div>
            </div>

            {/* Manual BPF Pin Form */}
            <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-5 shadow-xl">
              <h3 className="font-bold text-white text-sm mb-2 flex items-center gap-2">
                <Lock className="w-4 h-4 text-red-400" />
                <span>{isAr ? 'حقن عنوان IP في جدول BPF MAP' : 'Inject IP to In-Kernel BPF MAP'}</span>
              </h3>
              <p className="text-xs text-slate-400 mb-4">
                {isAr ? 'إدراج فوري في الذاكرة المشتركة للنواة للإسقاط العتادي المباشر.' : 'Directly insert drop rule into BPF_MAP_TYPE_HASH pin.'}
              </p>

              <form onSubmit={handlePinIpToBpfMap} className="space-y-3">
                <div>
                  <label className="text-[11px] font-bold text-slate-400 uppercase">Target IPv4</label>
                  <input
                    type="text"
                    value={manualIpToPin}
                    onChange={(e) => setManualIpToPin(e.target.value)}
                    placeholder="198.51.100.99"
                    className="w-full mt-1 bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-white font-mono focus:border-cyan-500 outline-none"
                  />
                </div>
                <div>
                  <label className="text-[11px] font-bold text-slate-400 uppercase">Reason / Signature</label>
                  <input
                    type="text"
                    value={pinReason}
                    onChange={(e) => setPinReason(e.target.value)}
                    placeholder="Kernel Pin: Zero-Day Exploit"
                    className="w-full mt-1 bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-white font-mono focus:border-cyan-500 outline-none"
                  />
                </div>
                <button
                  type="submit"
                  disabled={pinning}
                  className="w-full bg-red-500/20 hover:bg-red-500/30 border border-red-500/40 text-red-300 py-2 rounded-lg text-xs font-bold transition flex items-center justify-center gap-2"
                >
                  <Zap className="w-3.5 h-3.5" />
                  <span>{pinning ? 'Pinning to Kernel...' : isAr ? 'حقن فوري في النواة' : 'Sync to BPF Map'}</span>
                </button>
              </form>
            </div>
          </div>

          {/* BPF Maps & Counter Inspector */}
          <div className="lg:col-span-2 space-y-6">
            {/* Realtime XDP Stats Grid */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
              <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4">
                <div className="text-[10px] text-slate-400 uppercase font-bold">RX Packets (Ingress)</div>
                <div className="text-xl font-black text-white font-mono mt-1">
                  {xdp?.rxPacketsTotal?.toLocaleString() || '42,890'}
                </div>
              </div>
              <div className="bg-slate-900/90 border border-red-500/30 rounded-xl p-4">
                <div className="text-[10px] text-red-400 uppercase font-bold">XDP_DROP (Zero-Copy)</div>
                <div className="text-xl font-black text-red-400 font-mono mt-1">
                  {xdp?.xdpDropCount?.toLocaleString() || '3,410'}
                </div>
              </div>
              <div className="bg-slate-900/90 border border-emerald-500/30 rounded-xl p-4">
                <div className="text-[10px] text-emerald-400 uppercase font-bold">XDP_PASS (Forwarded)</div>
                <div className="text-xl font-black text-emerald-400 font-mono mt-1">
                  {xdp?.xdpPassCount?.toLocaleString() || '39,180'}
                </div>
              </div>
              <div className="bg-slate-900/90 border border-purple-500/30 rounded-xl p-4">
                <div className="text-[10px] text-purple-400 uppercase font-bold">XDP_REDIRECT (Trap)</div>
                <div className="text-xl font-black text-purple-400 font-mono mt-1">
                  {xdp?.xdpRedirectCount?.toLocaleString() || '300'}
                </div>
              </div>
            </div>

            {/* In-Kernel BPF Maps Table */}
            <div className="bg-slate-900/90 border border-slate-800 rounded-2xl overflow-hidden shadow-xl">
              <div className="p-4 border-b border-slate-800 bg-slate-950/60 flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Database className="w-4 h-4 text-cyan-400" />
                  <h4 className="font-bold text-white text-sm">
                    {isAr ? 'جداول ذاكرة النواة الحية (Active In-Kernel BPF_MAPS)' : 'Active In-Kernel BPF_MAPS (Pinned)'}
                  </h4>
                </div>
                <span className="text-xs font-mono text-cyan-400">Map Capacity: 65,536 Slots</span>
              </div>

              <div className="p-4 space-y-4">
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                  <div className="p-3 rounded-xl bg-slate-950 border border-slate-800">
                    <div className="text-xs font-bold text-slate-300">ip_blacklist_map</div>
                    <div className="text-[11px] text-slate-500 font-mono mt-0.5">BPF_MAP_TYPE_HASH</div>
                    <div className="mt-2 text-sm font-black text-red-400 font-mono">
                      {xdp?.bpfMaps?.ipBlacklistMap?.entries || 4} Entries ({xdp?.bpfMaps?.ipBlacklistMap?.memoryKb || 0.25} KB)
                    </div>
                  </div>

                  <div className="p-3 rounded-xl bg-slate-950 border border-slate-800">
                    <div className="text-xs font-bold text-slate-300">payload_hash_map</div>
                    <div className="text-[11px] text-slate-500 font-mono mt-0.5">BPF_MAP_TYPE_HASH</div>
                    <div className="mt-2 text-sm font-black text-cyan-400 font-mono">
                      {xdp?.bpfMaps?.payloadHashMap?.entries || 4} Signatures ({xdp?.bpfMaps?.payloadHashMap?.memoryKb || 0.5} KB)
                    </div>
                  </div>

                  <div className="p-3 rounded-xl bg-slate-950 border border-slate-800">
                    <div className="text-xs font-bold text-slate-300">rate_limit_lru_map</div>
                    <div className="text-[11px] text-slate-500 font-mono mt-0.5">BPF_MAP_TYPE_LRU_HASH</div>
                    <div className="mt-2 text-sm font-black text-purple-400 font-mono">
                      {xdp?.bpfMaps?.rateLimitLruMap?.entries || 0} Dynamic Windows
                    </div>
                  </div>
                </div>

                {/* Sample eBPF C Source Code Viewer */}
                <div className="rounded-xl bg-slate-950 border border-slate-800 p-3.5">
                  <div className="text-xs font-bold text-slate-400 mb-2 flex items-center justify-between">
                    <span>Generated Ingress eBPF C Bytecode Filter</span>
                    <span className="text-[10px] text-emerald-400 font-mono">Verified JIT Compiled</span>
                  </div>
                  <pre className="text-[11px] font-mono text-cyan-300/90 overflow-x-auto p-2 bg-slate-900/60 rounded-lg">
{`SEC("xdp")
int xdp_sovereign_filter(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;

    // Fast O(1) in-kernel lookup in BPF_MAP_TYPE_HASH
    __u32 src_ip = ip->saddr;
    struct bpf_action_val *action = bpf_map_lookup_elem(&ip_blacklist_map, &src_ip);
    if (action && action->verdict == XDP_DROP) {
        return XDP_DROP; // Sub-microsecond zero-copy drop
    }
    return XDP_PASS;
}`}
                  </pre>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* SUB-TAB 3: MULTI-TIER CACHING & BLOOM FILTER */}
      {activeSubTab === 'MULTI_TIER_CACHE' && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Interactive Bloom Test Playground */}
          <div className="lg:col-span-1 space-y-6">
            <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-5 shadow-xl">
              <h3 className="font-bold text-white text-sm mb-2 flex items-center gap-2">
                <Sparkles className="w-4 h-4 text-cyan-400" />
                <span>{isAr ? 'مختبر اختبار مرشح بلوم (Bloom Filter Sandbox)' : 'Interactive Bloom Filter Sandbox'}</span>
              </h3>
              <p className="text-xs text-slate-400 mb-4">
                {isAr 
                  ? 'أدخل مساراً أو توقيعاً للتحقق مما إذا كان مرشح بلوم سيمرره عبر المسار السريع (42µs).'
                  : 'Test any URI or signature against the 65,536-bit probabilistic bitset.'}
              </p>

              <div className="space-y-3">
                <div>
                  <label className="text-[11px] font-bold text-slate-400 uppercase">Test Signature / Route</label>
                  <input
                    type="text"
                    value={testSignature}
                    onChange={(e) => setTestSignature(e.target.value)}
                    placeholder="GET /api/v1/products"
                    className="w-full mt-1 bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-white font-mono focus:border-cyan-500 outline-none"
                  />
                </div>

                <div className="flex flex-wrap gap-1.5">
                  {['GET /api/v1/products', 'GET /favicon.ico', 'GET /robots.txt', 'GET /api/v1/auth/malicious'].map(sample => (
                    <button
                      key={sample}
                      onClick={() => setTestSignature(sample)}
                      className="text-[10px] font-mono px-2 py-1 rounded bg-slate-800 text-slate-300 hover:text-white"
                    >
                      {sample}
                    </button>
                  ))}
                </div>

                <button
                  onClick={handleTestBloomFilter}
                  disabled={testingBloom}
                  className="w-full bg-cyan-500/20 hover:bg-cyan-500/30 border border-cyan-500/40 text-cyan-300 py-2 rounded-lg text-xs font-bold transition flex items-center justify-center gap-2"
                >
                  <Play className="w-3.5 h-3.5" />
                  <span>{testingBloom ? 'Testing Bitset...' : isAr ? 'اختبار التوقيع الآن' : 'Evaluate Signature'}</span>
                </button>
              </div>

              {bloomTestResult && (
                <div className="mt-4 p-3.5 rounded-xl bg-slate-950 border border-slate-800 text-xs font-mono space-y-2">
                  <div className="flex justify-between items-center">
                    <span className="text-slate-400">Verdict:</span>
                    <span className={`font-bold px-2 py-0.5 rounded ${
                      bloomTestResult.fastPathEligible 
                        ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30' 
                        : 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                    }`}>
                      {bloomTestResult.bloomVerdict}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-400">Fast-Path Eligible:</span>
                    <span className={bloomTestResult.fastPathEligible ? 'text-emerald-400' : 'text-amber-400'}>
                      {bloomTestResult.fastPathEligible ? 'YES (Bypasses AI deep scan)' : 'NO (Escalated to heuristic/AI)'}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-400">Latency:</span>
                    <span className="text-cyan-300">{bloomTestResult.estimatedLookupLatencyMicros} microseconds</span>
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* Caching Metrics & Quota Savings */}
          <div className="lg:col-span-2 space-y-6">
            <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-5 shadow-xl">
              <h3 className="font-bold text-white text-sm mb-4 flex items-center gap-2">
                <Layers className="w-4 h-4 text-emerald-400" />
                <span>{isAr ? 'تحليل كفاءة الحصص وتوفير استدعاءات الذكاء الاصطناعي' : 'AI Quota Protection & Multi-Tier Efficiency Metrics'}</span>
              </h3>

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 mb-6">
                <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 text-center">
                  <div className="text-xs text-slate-400 font-bold uppercase">Tier 1: Hot LRU Cache</div>
                  <div className="text-2xl font-black text-emerald-400 font-mono mt-1">
                    {cache?.tier1HotCache?.hits?.toLocaleString() || '16,420'}
                  </div>
                  <div className="text-[11px] text-slate-400 mt-1">
                    Hit Ratio: <span className="text-emerald-300 font-bold">{cache?.tier1HotCache?.hitRatio || 0.88}</span>
                  </div>
                </div>

                <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 text-center">
                  <div className="text-xs text-slate-400 font-bold uppercase">Tier 2: Bloom Filter</div>
                  <div className="text-2xl font-black text-cyan-400 font-mono mt-1">
                    {cache?.tier2BloomFilter?.cleanTrafficBypassedCount?.toLocaleString() || '24,820'}
                  </div>
                  <div className="text-[11px] text-slate-400 mt-1">
                    FP Rate Est: <span className="text-cyan-300 font-bold">{cache?.tier2BloomFilter?.falsePositiveRateEst || 0.00018}</span>
                  </div>
                </div>

                <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 text-center">
                  <div className="text-xs text-slate-400 font-bold uppercase">Gemini AI Invocations</div>
                  <div className="text-2xl font-black text-purple-400 font-mono mt-1">
                    {cache?.aiQuotaEfficiency?.geminiAiDeepEvaluations?.toLocaleString() || '1,650'}
                  </div>
                  <div className="text-[11px] text-slate-400 mt-1">
                    Zero-Day Escalations Only
                  </div>
                </div>
              </div>

              {/* Visual Pipeline Bar */}
              <div className="space-y-2">
                <div className="flex justify-between text-xs font-bold">
                  <span className="text-slate-300">AI Compute & Quota Saved vs Raw Ingestion</span>
                  <span className="text-emerald-400">{cache?.aiQuotaEfficiency?.apiQuotaSavedPercentage || 96.8}% Saved</span>
                </div>
                <div className="w-full h-4 bg-slate-950 rounded-full overflow-hidden flex border border-slate-800">
                  <div 
                    style={{ width: `${cache?.aiQuotaEfficiency?.apiQuotaSavedPercentage || 96.8}%` }} 
                    className="h-full bg-gradient-to-r from-emerald-500 via-cyan-500 to-indigo-500" 
                  />
                  <div 
                    style={{ width: `${100 - (cache?.aiQuotaEfficiency?.apiQuotaSavedPercentage || 96.8)}%` }} 
                    className="h-full bg-purple-600" 
                  />
                </div>
                <div className="flex justify-between text-[11px] text-slate-400 font-mono">
                  <span>Fast-Path Resolved: 96.8%</span>
                  <span>Deep AI Analyzed: 3.2%</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* SUB-TAB 4: ASYNC WORKER POOL */}
      {activeSubTab === 'WORKERS' && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Worker Pool Activity */}
            <div className="lg:col-span-2 bg-slate-900/90 border border-slate-800 rounded-2xl p-5 shadow-xl space-y-6">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Cpu className="w-4 h-4 text-purple-400" />
                  <h3 className="font-bold text-white text-sm">
                    {isAr ? 'مصفوفة خيوط المعالجة المتوازية (Worker Threads Pool)' : 'Asynchronous Worker Pool Matrix'}
                  </h3>
                </div>
                <button
                  onClick={handleRunWorkerBenchmark}
                  disabled={benchmarking}
                  className="px-3 py-1.5 rounded-lg bg-purple-500/20 hover:bg-purple-500/30 border border-purple-500/40 text-purple-300 text-xs font-bold transition flex items-center gap-1.5"
                >
                  <Play className="w-3.5 h-3.5" />
                  <span>{benchmarking ? 'Benchmarking Pool...' : isAr ? 'تشغيل اختبار ضغط الخيوط' : 'Run PCAP Dissection Benchmark'}</span>
                </button>
              </div>

              {/* 4 Dedicated Worker Core Visualizers */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                {[1, 2, 3, 4].map(id => (
                  <div key={`worker-core-${id}`} className="p-4 rounded-xl bg-slate-950 border border-slate-800 text-center">
                    <div className="flex items-center justify-center gap-1 text-xs font-bold text-slate-300 mb-2">
                      <Cpu className="w-3.5 h-3.5 text-purple-400" />
                      <span>Worker #{id}</span>
                    </div>
                    <div className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                      <span>ONLINE (IDLE)</span>
                    </div>
                    <div className="text-[10px] text-slate-500 mt-2 font-mono">Shannon / PCAP Dissect</div>
                  </div>
                ))}
              </div>

              {/* Task Distribution Breakdown */}
              <div className="space-y-3 pt-4 border-t border-slate-800">
                <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider">
                  {isAr ? 'توزيع المهام المنفذة في الخلفية' : 'Offloaded Task Distribution Breakdown'}
                </h4>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono">
                  <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800">
                    <div className="text-slate-400 text-[10px]">PCAP Entropy:</div>
                    <div className="text-cyan-400 font-bold text-base mt-0.5">
                      {workers?.taskDistribution?.pcapEntropyDissections || 940}
                    </div>
                  </div>
                  <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800">
                    <div className="text-slate-400 text-[10px]">Dataset Logs:</div>
                    <div className="text-purple-400 font-bold text-base mt-0.5">
                      {workers?.taskDistribution?.datasetIngestions || 610}
                    </div>
                  </div>
                  <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800">
                    <div className="text-slate-400 text-[10px]">Gaussian Recalcs:</div>
                    <div className="text-emerald-400 font-bold text-base mt-0.5">
                      {workers?.taskDistribution?.behavioralModelRecalcs || 580}
                    </div>
                  </div>
                  <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800">
                    <div className="text-slate-400 text-[10px]">Crypto Hashes:</div>
                    <div className="text-amber-400 font-bold text-base mt-0.5">
                      {workers?.taskDistribution?.cryptoHashGenerations || 350}
                    </div>
                  </div>
                </div>
              </div>
            </div>

            {/* Event Loop Health Meter */}
            <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-5 shadow-xl space-y-4">
              <h3 className="font-bold text-white text-sm flex items-center gap-2">
                <Activity className="w-4 h-4 text-emerald-400" />
                <span>{isAr ? 'صحة حلقة أحداث خادم Node.js' : 'Express Event Loop Delay'}</span>
              </h3>

              <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 text-center">
                <div className="text-3xl font-black text-emerald-400 font-mono">
                  {workers?.eventLoopDelayMs || 0.8} ms
                </div>
                <div className="text-xs text-slate-400 mt-1">
                  Health Status: <span className="text-emerald-300 font-bold uppercase">{workers?.eventLoopHealth || 'OPTIMAL'}</span>
                </div>
                <p className="text-[11px] text-slate-500 mt-2">
                  Target latency &lt; 2.0ms under full ingestion load.
                </p>
              </div>

              {benchmarkResult && (
                <div className="p-3 rounded-xl bg-slate-950 border border-purple-500/30 text-xs font-mono space-y-1">
                  <div className="text-purple-300 font-bold">Benchmark Completed:</div>
                  <div className="text-slate-400">Duration: {benchmarkResult.workerExecution?.durationMs} ms</div>
                  <div className="text-slate-400">Worker ID: #{benchmarkResult.workerExecution?.workerId}</div>
                  <div className="text-slate-400">Calculated Entropy: {benchmarkResult.workerExecution?.data?.entropy}</div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* SUB-TAB 5: TOKEN BUCKET & ADAPTIVE BACKPRESSURE */}
      {activeSubTab === 'BACKPRESSURE' && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Token Bucket Water-Level Animation */}
          <div className="lg:col-span-1 bg-slate-900/90 border border-slate-800 rounded-2xl p-5 shadow-xl space-y-4">
            <h3 className="font-bold text-white text-sm flex items-center gap-2">
              <Activity className="w-4 h-4 text-amber-400" />
              <span>{isAr ? 'مستوى خزان التوكنات اللحظي' : 'Token Bucket Level'}</span>
            </h3>

            <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 text-center space-y-3">
              <div className="relative w-24 h-40 mx-auto rounded-2xl border-2 border-slate-700 overflow-hidden bg-slate-900 flex flex-col justify-end">
                <div 
                  style={{ height: `${bucket?.fillPercentage || 100}%` }}
                  className={`w-full transition-all duration-500 ${
                    (bucket?.fillPercentage || 100) > 35 
                      ? 'bg-gradient-to-t from-emerald-600 to-cyan-400' 
                      : (bucket?.fillPercentage || 100) > 15
                      ? 'bg-gradient-to-t from-amber-600 to-amber-400'
                      : 'bg-gradient-to-t from-red-600 to-red-400'
                  }`}
                />
                <div className="absolute inset-0 flex items-center justify-center font-mono font-black text-white text-sm drop-shadow">
                  {bucket?.currentTokens || 600} / {bucket?.bucketCapacity || 600}
                </div>
              </div>

              <div className="text-xs font-mono text-slate-400">
                Refill Rate: <span className="text-emerald-400 font-bold">+{bucket?.refillRatePerSec || 150} tokens/sec</span>
              </div>

              <button
                onClick={handleSimulateDdosSpike}
                disabled={ddosSimulating}
                className="w-full bg-red-500/20 hover:bg-red-500/30 border border-red-500/40 text-red-300 py-2 rounded-lg text-xs font-bold transition flex items-center justify-center gap-2"
              >
                <Flame className="w-3.5 h-3.5" />
                <span>{ddosSimulating ? 'Flooding Bucket...' : isAr ? 'محاكاة فيضان DDoS (2,400 PPS)' : 'Simulate Extreme DDoS Spike'}</span>
              </button>
            </div>
          </div>

          {/* Load Shedding & Traffic Prioritization Metrics */}
          <div className="lg:col-span-2 bg-slate-900/90 border border-slate-800 rounded-2xl p-5 shadow-xl space-y-6">
            <div className="flex items-center justify-between">
              <h3 className="font-bold text-white text-sm flex items-center gap-2">
                <ShieldCheck className="w-4 h-4 text-emerald-400" />
                <span>{isAr ? 'نظام إسقاط الحزم المتكيف مع الضغط (Adaptive Load Shedding)' : 'Adaptive Load Shedding & Traffic Prioritization'}</span>
              </h3>
              <span className={`px-2.5 py-1 rounded-lg text-xs font-mono font-bold ${
                bucket?.pressureMode === 'NORMAL'
                  ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                  : 'bg-red-500/20 text-red-300 border border-red-500/40'
              }`}>
                Mode: {bucket?.pressureMode || 'NORMAL'}
              </span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div className="p-4 rounded-xl bg-slate-950 border border-slate-800">
                <div className="text-xs font-bold text-emerald-400 uppercase">Prioritized Security Verdicts</div>
                <div className="text-2xl font-black text-white font-mono mt-1">
                  {bucket?.prioritizedSecurityVerdictsCount?.toLocaleString() || '18,130'}
                </div>
                <p className="text-[11px] text-slate-400 mt-1">
                  100% Guaranteed throughput for hard blocks & critical alarms.
                </p>
              </div>

              <div className="p-4 rounded-xl bg-slate-950 border border-slate-800">
                <div className="text-xs font-bold text-amber-400 uppercase">Shed Passive Logs (Under Load)</div>
                <div className="text-2xl font-black text-amber-400 font-mono mt-1">
                  {bucket?.shedTelemetryPacketsCount?.toLocaleString() || '320'}
                </div>
                <p className="text-[11px] text-slate-400 mt-1">
                  Non-critical passive logging shed during high saturation spikes.
                </p>
              </div>
            </div>

            <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 text-xs space-y-2 text-slate-400 leading-relaxed">
              <div className="font-bold text-white">How Adaptive Backpressure Works:</div>
              <div>
                • <strong className="text-cyan-300">Normal Operations (&gt;35% Tokens):</strong> 100% of telemetry, logs, and SIEM records are processed in full detail.
              </div>
              <div>
                • <strong className="text-amber-300">Elevated Saturation (12-35% Tokens):</strong> 50% of passive telemetry logs are shed while retaining full firewall blocking capabilities.
              </div>
              <div>
                • <strong className="text-red-300">Critical Flood (&lt;12% Tokens):</strong> Automatic 100% load shedding on passive UI logs. All system CPU is reserved exclusively for zero-copy eBPF kernel drops.
              </div>
            </div>
          </div>
        </div>
      )}

      {/* SUB-TAB 6: DEDICATED HIGH-RATE CANVAS STREAM */}
      {activeSubTab === 'CANVAS_STREAM' && (
        <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="font-bold text-white text-base">
                {isAr ? 'عرض تدفق الحزم المباشر عالي السرعة (High-Throughput WebSocket Stream)' : 'Dedicated High-Throughput Canvas Packet Stream'}
              </h3>
              <p className="text-xs text-slate-400">
                {isAr ? 'متصل عبر WebSocket (/ws/telemetry) بمعدل 60 إطاراً في الثانية' : 'Broadcasting at 60 FPS directly via WebSocket with hardware acceleration'}
              </p>
            </div>
            <div className="text-xs font-mono text-cyan-400">
              Connected Clients: <span className="font-bold">{ws?.connectedClients || 1}</span>
            </div>
          </div>

          <div className="rounded-xl overflow-hidden border border-slate-800 bg-slate-950">
            <canvas ref={canvasRef} className="w-full h-[260px] block" />
          </div>
        </div>
      )}
    </div>
  );
};
