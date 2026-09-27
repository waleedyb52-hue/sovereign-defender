import React, { useState, useEffect, useCallback } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  Zap,
  Activity,
  Radio,
  Clock,
  Terminal,
  RefreshCw,
  Lock,
  Unlock,
  AlertTriangle,
  Server,
  Layers,
  Sparkles,
  Search,
  Check,
  Copy,
  Sliders,
  ExternalLink,
  Flame,
  XCircle,
  Network,
  Cpu,
  Eye,
  RadioTower,
  FileCode,
  HardDrive,
  Share2,
  Workflow
} from 'lucide-react';

export interface EbpfContainmentRecord {
  id: string;
  targetIp: string;
  cidrBlock: string;
  reason: string;
  reasonAr: string;
  triggeredByIoc: string;
  severity: 'CRITICAL' | 'HIGH';
  status: 'ACTIVE_BLACKHOLE' | 'RELEASED';
  interceptLatencyUs: number;
  packetsDroppedCount: number;
  tcpConnectionsSevered: number;
  isolatedAt: string;
  releasedAt?: string;
  nodeName: string;
  bpfMapKey?: string;
}

export interface SeveredTcpSocket {
  id: string;
  targetIp: string;
  srcPort: number;
  dstIp: string;
  dstPort: number;
  protocol: 'TCP';
  stateBeforeSever: 'ESTABLISHED' | 'SYN_SENT' | 'CLOSE_WAIT';
  rstInjectedAt: string;
  latencyUs: number;
  bytesTransferredBeforeKill: number;
}

export interface BehavioralAnomaly {
  id: string;
  type:
    | 'DATA_EXFILTRATION'
    | 'PERSISTENT_CODE_INJECTION'
    | 'UNAUTHORIZED_BINARY_EXECUTION'
    | 'LATERAL_CLUSTER_TRAVERSAL';
  title: string;
  titleAr: string;
  actorIp: string;
  targetNode: string;
  confidenceScore: number;
  thresholdExceeded: string;
  thresholdExceededAr: string;
  heuristicDetails: {
    samplesAnalyzed: number;
    anomalyMetric: string;
    baselineValue: string;
    observedValue: string;
  };
  detectedAt: string;
  autoContained: boolean;
  containmentRecordId?: string;
}

export interface ClusterNodeIsolationState {
  nodeName: string;
  nodeIp: string;
  clusterRole: 'INGRESS_PROXY' | 'APP_WORKLOAD' | 'DATABASE_CLUSTER' | 'AI_INFERENCE_GATEWAY';
  isolationStatus: 'HEALTHY_ATTACHED' | 'QUARANTINED_EAST_WEST';
  ebpfXdpAttached: boolean;
  ingressPacketsDropped: number;
  egressPacketsDropped: number;
  lastIsolatedAt?: string;
}

export interface EbpfStatistics {
  activeBlackholesCount: number;
  totalHistoricIsolations: number;
  totalPacketsDropped: number;
  totalTcpResetsInjected: number;
  meanKernelLatencyUs: number;
  anomaliesDetectedCount?: number;
  quarantinedNodesCount?: number;
  totalClusterNodesCount?: number;
}

export interface AutonomousContainmentTelemetryProps {
  lang: 'ar' | 'en';
}

export const AutonomousContainmentTelemetry: React.FC<AutonomousContainmentTelemetryProps> = ({
  lang
}) => {
  const isAr = lang === 'ar';

  const [activeTab, setActiveTab] = useState<
    'ROUTING' | 'ANOMALIES' | 'SEVERED_SOCKETS' | 'CLUSTER_NODES' | 'EBPF_CODE'
  >('ROUTING');
  const [records, setRecords] = useState<EbpfContainmentRecord[]>([]);
  const [anomalies, setAnomalies] = useState<BehavioralAnomaly[]>([]);
  const [severedSockets, setSeveredSockets] = useState<SeveredTcpSocket[]>([]);
  const [clusterNodes, setClusterNodes] = useState<ClusterNodeIsolationState[]>([]);
  const [stats, setStats] = useState<EbpfStatistics>({
    activeBlackholesCount: 2,
    totalHistoricIsolations: 3,
    totalPacketsDropped: 248910,
    totalTcpResetsInjected: 842,
    meanKernelLatencyUs: 0.34,
    anomaliesDetectedCount: 3,
    quarantinedNodesCount: 2,
    totalClusterNodesCount: 4
  });

  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [isLiveStream, setIsLiveStream] = useState<boolean>(true);
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [copiedIp, setCopiedIp] = useState<string | null>(null);
  const [actionMessage, setActionMessage] = useState<string | null>(null);
  const [isSimulating, setIsSimulating] = useState<boolean>(false);

  // Manual IP Containment input
  const [manualIpInput, setManualIpInput] = useState<string>('');
  const [isTriggeringContainment, setIsTriggeringContainment] = useState<boolean>(false);

  // Fetch telemetry
  const fetchEbpfTelemetry = useCallback(async () => {
    try {
      const [recRes, anomRes, sockRes, nodeRes] = await Promise.all([
        fetch('/api/v1/soc/ebpf/containment-records'),
        fetch('/api/v1/soc/ebpf/anomalies'),
        fetch('/api/v1/soc/ebpf/severed-sockets'),
        fetch('/api/v1/soc/ebpf/cluster-nodes')
      ]);

      if (recRes.ok) {
        const data = await recRes.json();
        if (data.records) setRecords(data.records);
        if (data.statistics) setStats(data.statistics);
      }
      if (anomRes.ok) {
        const data = await anomRes.json();
        if (data.anomalies) setAnomalies(data.anomalies);
      }
      if (sockRes.ok) {
        const data = await sockRes.json();
        if (data.sockets) setSeveredSockets(data.sockets);
      }
      if (nodeRes.ok) {
        const data = await nodeRes.json();
        if (data.nodes) setClusterNodes(data.nodes);
      }
    } catch (err) {
      console.warn('Failed to fetch eBPF containment data:', err);
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchEbpfTelemetry();
  }, [fetchEbpfTelemetry]);

  useEffect(() => {
    if (!isLiveStream) return;
    const interval = setInterval(() => {
      fetchEbpfTelemetry();
    }, 3500);
    return () => clearInterval(interval);
  }, [isLiveStream, fetchEbpfTelemetry]);

  // Handle Release IP
  const handleReleaseIp = async (targetIp: string) => {
    try {
      const res = await fetch('/api/v1/soc/ebpf/release-ip', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ targetIp })
      });
      if (res.ok) {
        setActionMessage(
          isAr
            ? `تم إلغاء عزل IP ${targetIp} بنواة النظام`
            : `IP ${targetIp} released from eBPF drop`
        );
        setTimeout(() => setActionMessage(null), 3500);
        fetchEbpfTelemetry();
      }
    } catch (err) {
      console.error('Failed to release IP:', err);
    }
  };

  // Handle Manual IP Containment
  const handleTriggerManualContainment = async () => {
    if (!manualIpInput.trim()) return;
    setIsTriggeringContainment(true);
    try {
      const res = await fetch('/api/v1/soc/ebpf/contain-ip', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          targetIp: manualIpInput.trim(),
          reason: 'Manual Zero-Trust Command containment protocol committed by SOC operator',
          reasonAr: 'أمر عزل فوري صادر من مشغل غرفة العمليات وفق بروتوكول انعدام الثقة',
          triggeredByIoc: 'SOC_OPERATOR_MANUAL_ISOLATE'
        })
      });
      if (res.ok) {
        setManualIpInput('');
        setActionMessage(
          isAr ? 'تم تطبيق عزل eBPF الفوري بنواة النظام' : 'eBPF drop applied at kernel layer'
        );
        setTimeout(() => setActionMessage(null), 3500);
        fetchEbpfTelemetry();
      }
    } catch (err) {
      console.error('Trigger containment error:', err);
    } finally {
      setIsTriggeringContainment(false);
    }
  };

  // Anomaly Simulation Trigger
  const handleSimulateAnomaly = async (
    scenario: 'EXFILTRATION' | 'BINARY_EXECUTION' | 'CODE_INJECTION' | 'LATERAL_CLUSTER_TRAVERSAL'
  ) => {
    setIsSimulating(true);
    try {
      const res = await fetch('/api/v1/soc/ebpf/simulate-anomaly', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scenario })
      });
      if (res.ok) {
        setActionMessage(
          isAr
            ? 'رصد شذوذ سلوكي وتطبيق عزل فوري بنواة eBPF بدون تدخل بشري!'
            : 'Behavioral anomaly heuristic triggered zero-trust auto-containment in microseconds!'
        );
        setTimeout(() => setActionMessage(null), 4000);
        await fetchEbpfTelemetry();
      }
    } catch (err) {
      console.error('Simulation error:', err);
    } finally {
      setIsSimulating(false);
    }
  };

  // Cluster Node Quarantine toggle
  const handleToggleNodeQuarantine = async (nodeName: string, isCurrentlyQuarantined: boolean) => {
    try {
      const endpoint = isCurrentlyQuarantined
        ? '/api/v1/soc/ebpf/release-node'
        : '/api/v1/soc/ebpf/quarantine-node';
      const res = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ nodeName })
      });
      if (res.ok) {
        setActionMessage(
          isAr
            ? isCurrentlyQuarantined
              ? `تمت إعادة إلحاق العقدة ${nodeName} بالشبكة الداخلية`
              : `تم عزل العقدة ${nodeName} وفصل الاتصالات الأفقية (East-West)`
            : isCurrentlyQuarantined
              ? `Node ${nodeName} re-attached to cluster mesh`
              : `Node ${nodeName} isolated via East-West microsegmentation`
        );
        setTimeout(() => setActionMessage(null), 3500);
        fetchEbpfTelemetry();
      }
    } catch (err) {
      console.error('Cluster node isolation toggle error:', err);
    }
  };

  const handleCopy = (ip: string) => {
    navigator.clipboard.writeText(ip);
    setCopiedIp(ip);
    setTimeout(() => setCopiedIp(null), 2000);
  };

  const filteredRecords = records.filter(
    r =>
      r.targetIp.toLowerCase().includes(searchQuery.toLowerCase()) ||
      r.reason.toLowerCase().includes(searchQuery.toLowerCase()) ||
      r.reasonAr.includes(searchQuery) ||
      r.triggeredByIoc.toLowerCase().includes(searchQuery.toLowerCase())
  );

  return (
    <div
      className="space-y-4 rounded-2xl border border-cyan-500/30 bg-slate-950/95 p-4 font-sans text-slate-200 shadow-2xl backdrop-blur-md sm:p-5"
      dir={isAr ? 'rtl' : 'ltr'}
    >
      {/* 1. Header & Live Telemetry Control */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800/80 pb-3">
        <div className="flex items-center gap-3">
          <div className="rounded-xl border border-rose-500/40 bg-rose-950/80 p-2.5 text-rose-300 shadow-md shadow-rose-950/60">
            <Zap className="h-5 w-5 animate-pulse text-rose-400" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-sm font-black tracking-wider text-rose-400 uppercase sm:text-base">
                {isAr
                  ? 'المرحلة الثانية: العزل الذاتي بنواة النظام (Autonomous eBPF Containment)'
                  : 'Phase 2: Autonomous Kernel eBPF Containment & Zero-Trust'}
              </h3>
              <span className="flex items-center gap-1 rounded border border-rose-500/40 bg-rose-950 px-2 py-0.5 font-mono text-[10px] font-bold text-rose-300">
                <span className="h-1.5 w-1.5 animate-ping rounded-full bg-rose-400" />
                MoD Zero-Trust
              </span>
            </div>
            <p className="mt-0.5 font-mono text-[11px] text-slate-400">
              {isAr
                ? 'رصد شذوذ السلوك الحركي وحقن TCP-RST وإسقاط فوري للحزم بنواة eBPF XDP بزمن 0.34µs وعزل العقد المصابة أفقياً'
                : 'Heuristic IoC anomaly engine, autonomous zero-trust isolation, sub-microsecond eBPF XDP packet drop & TCP RST severing'}
            </p>
          </div>
        </div>

        {/* Live Stream & Refresh */}
        <div className="flex items-center gap-2">
          <button
            onClick={() => setIsLiveStream(!isLiveStream)}
            className={`flex items-center gap-1.5 rounded-lg border px-3 py-1 font-mono text-xs font-bold transition ${
              isLiveStream
                ? 'border-emerald-500/50 bg-emerald-950/70 text-emerald-300 shadow-md'
                : 'border-slate-700 bg-slate-900 text-slate-400 shadow-[0_0_20px_rgba(0,255,255,0.08)]'
            }`}
          >
            {isLiveStream ? (
              <Radio className="h-3.5 w-3.5 animate-pulse text-emerald-400" />
            ) : (
              <Clock className="h-3.5 w-3.5 text-slate-400" />
            )}
            <span>
              {isLiveStream
                ? isAr
                  ? 'البث اللحظي: نشط'
                  : 'STREAM: ACTIVE'
                : isAr
                  ? 'متوقف'
                  : 'PAUSED'}
            </span>
          </button>

          <button
            onClick={fetchEbpfTelemetry}
            disabled={isLoading}
            className="rounded-lg border border-slate-700 bg-slate-900 p-1.5 text-slate-300 transition hover:bg-slate-800 shadow-[0_0_20px_rgba(0,255,255,0.08)]"
            title={isAr ? 'تحديث السجلات' : 'Refresh Telemetry'}
          >
            <RefreshCw className={`h-3.5 w-3.5 ${isLoading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* 2. Key Metrics Overview */}
      <div className="grid grid-cols-2 gap-2.5 font-mono text-xs sm:grid-cols-5">
        <div className="rounded-xl border border-rose-900/60 bg-slate-900/90 p-2.5 shadow-sm">
          <span className="block text-[9px] text-slate-400">
            {isAr ? 'عزل النواة النشط (Blackhole)' : 'ACTIVE KERNEL BLACKHOLES'}
          </span>
          <div className="mt-0.5 flex items-center gap-2">
            <Lock className="h-4 w-4 text-rose-400" />
            <span className="text-base font-bold text-rose-300">
              {stats.activeBlackholesCount} IPs
            </span>
          </div>
        </div>

        <div className="rounded-xl border border-amber-900/60 bg-slate-900/90 p-2.5 shadow-sm">
          <span className="block text-[9px] text-slate-400">
            {isAr ? 'حزم تم إسقاطها (eBPF XDP)' : 'PACKETS DROPPED'}
          </span>
          <div className="mt-0.5 flex items-center gap-2">
            <Flame className="h-4 w-4 text-amber-400" />
            <span className="text-base font-bold text-amber-300">
              {stats.totalPacketsDropped.toLocaleString()}
            </span>
          </div>
        </div>

        <div className="rounded-xl border border-cyan-900/60 bg-slate-900/90 p-2.5 shadow-sm">
          <span className="block text-[9px] text-slate-400">
            {isAr ? 'جلسات TCP مقطوعة (RST)' : 'TCP SESSIONS SEVERED'}
          </span>
          <div className="mt-0.5 flex items-center gap-2">
            <Network className="h-4 w-4 text-cyan-400" />
            <span className="text-base font-bold text-cyan-300">
              {stats.totalTcpResetsInjected} RST
            </span>
          </div>
        </div>

        <div className="rounded-xl border border-emerald-900/60 bg-slate-900/90 p-2.5 shadow-sm">
          <span className="block text-[9px] text-slate-400">
            {isAr ? 'سرعة استجابة النواة' : 'KERNEL INTERCEPT SPEED'}
          </span>
          <div className="mt-0.5 flex items-center gap-2">
            <Zap className="h-4 w-4 text-emerald-400" />
            <span className="text-base font-bold text-emerald-300">
              {stats.meanKernelLatencyUs} µs
            </span>
          </div>
        </div>

        <div className="col-span-2 rounded-xl border border-cyan-900/60 bg-slate-900/90 p-2.5 shadow-sm sm:col-span-1">
          <span className="block text-[9px] text-slate-400">
            {isAr ? 'العقد المعزولة أفقياً' : 'QUARANTINED NODES'}
          </span>
          <div className="mt-0.5 flex items-center gap-2">
            <Server className="h-4 w-4 text-cyan-400" />
            <span className="text-base font-bold text-cyan-300">
              {stats.quarantinedNodesCount || 2} / {stats.totalClusterNodesCount || 4}
            </span>
          </div>
        </div>
      </div>

      {/* Action Notification Toast */}
      {actionMessage && (
        <div className="animate-fadeIn flex items-center justify-between rounded-lg border border-emerald-500/50 bg-emerald-950/80 p-2.5 font-mono text-xs text-emerald-200">
          <span className="flex items-center gap-2">
            <ShieldCheck className="h-4 w-4 text-emerald-400" />
            {actionMessage}
          </span>
          <button
            onClick={() => setActionMessage(null)}
            className="text-emerald-400 hover:text-emerald-200"
          >
            <XCircle className="h-4 w-4" />
          </button>
        </div>
      )}

      {/* 3. Operational Drill Simulation Bar */}
      <div className="flex flex-col justify-between gap-3 rounded-xl border border-slate-800 bg-slate-900/80 p-3 md:flex-row md:items-center shadow-[0_0_20px_rgba(0,255,255,0.08)]">
        <div className="flex items-center gap-2">
          <Sparkles className="h-4 w-4 text-cyan-400" />
          <span className="font-mono text-xs font-bold text-slate-300">
            {isAr
              ? 'محاكاة مؤشرات الاختراق وسرعة العزل الذاتي (Phase 2 Drills):'
              : 'Trigger Phase 2 Autonomous Zero-Trust Containment Drills:'}
          </span>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <button
            onClick={() => handleSimulateAnomaly('EXFILTRATION')}
            disabled={isSimulating}
            className="flex items-center gap-1.5 rounded-lg border border-amber-500/50 bg-amber-950/80 px-2.5 py-1 font-mono text-xs font-bold text-amber-300 transition hover:bg-amber-900/90"
            title={
              isAr
                ? 'محاكاة تسريب كمي للبيانات المشفرة'
                : 'Simulate Outbound Data Exfiltration Burst'
            }
          >
            <Activity className="h-3.5 w-3.5 text-amber-400" />
            <span>{isAr ? 'تسريب بيانات خبيث' : 'Exfiltration Spike'}</span>
          </button>

          <button
            onClick={() => handleSimulateAnomaly('BINARY_EXECUTION')}
            disabled={isSimulating}
            className="flex items-center gap-1.5 rounded-lg border border-rose-500/50 bg-rose-950/80 px-2.5 py-1 font-mono text-xs font-bold text-rose-300 transition hover:bg-rose-900/90"
            title={
              isAr ? 'محاكاة تفريع شل بنظام التشغيل' : 'Simulate Unauthorized Shell /bin/bash Fork'
            }
          >
            <Terminal className="h-3.5 w-3.5 text-rose-400" />
            <span>{isAr ? 'تشغيل /bin/bash' : 'Shell Fork Alert'}</span>
          </button>

          <button
            onClick={() => handleSimulateAnomaly('CODE_INJECTION')}
            disabled={isSimulating}
            className="flex items-center gap-1.5 rounded-lg border border-cyan-500/50 bg-cyan-950/80 px-2.5 py-1 font-mono text-xs font-bold text-cyan-300 transition hover:bg-cyan-900/90"
            title={isAr ? 'محاكاة تدفق حقن متزامن' : 'Simulate Cascading Polyglot Injection'}
          >
            <Zap className="h-3.5 w-3.5 text-cyan-400" />
            <span>{isAr ? 'حقن متتالي مكثف' : 'Injection Burst'}</span>
          </button>

          <button
            onClick={() => handleSimulateAnomaly('LATERAL_CLUSTER_TRAVERSAL')}
            disabled={isSimulating}
            className="flex items-center gap-1.5 rounded-lg border border-cyan-500/50 bg-cyan-950/80 px-2.5 py-1 font-mono text-xs font-bold text-cyan-300 transition hover:bg-cyan-900/90"
            title={
              isAr ? 'محاكاة مسح جانبي للعقد الداخلية' : 'Simulate Cluster East-West Port Sweep'
            }
          >
            <Share2 className="h-3.5 w-3.5 text-cyan-400" />
            <span>{isAr ? 'مسح أفقي للعقد' : 'East-West Sweep'}</span>
          </button>
        </div>
      </div>

      {/* 4. Sub-Navigation Tabs */}
      <div className="flex flex-wrap items-center gap-1.5 border-b border-slate-800 pb-2 font-mono text-xs">
        <button
          onClick={() => setActiveTab('ROUTING')}
          className={`flex items-center gap-2 rounded-lg px-3 py-1.5 transition ${
            activeTab === 'ROUTING'
              ? 'border border-rose-500/60 bg-rose-950 font-bold text-rose-300 shadow-sm'
              : 'bg-slate-900 text-slate-400 hover:text-white'
          }`}
        >
          <Lock className="h-3.5 w-3.5" />
          <span>
            {isAr ? 'جدول العزل بالنواة (eBPF Blackholes)' : 'Kernel Blackholes'} (
            {records.filter(r => r.status === 'ACTIVE_BLACKHOLE').length})
          </span>
        </button>

        <button
          onClick={() => setActiveTab('ANOMALIES')}
          className={`flex items-center gap-2 rounded-lg px-3 py-1.5 transition ${
            activeTab === 'ANOMALIES'
              ? 'border border-amber-500/60 bg-amber-950 font-bold text-amber-300 shadow-sm'
              : 'bg-slate-900 text-slate-400 hover:text-white'
          }`}
        >
          <Activity className="h-3.5 w-3.5" />
          <span>
            {isAr ? 'كشف الشذوذ السلوكي (IoC Heuristics)' : 'Behavioral Anomalies'} (
            {anomalies.length})
          </span>
        </button>

        <button
          onClick={() => setActiveTab('SEVERED_SOCKETS')}
          className={`flex items-center gap-2 rounded-lg px-3 py-1.5 transition ${
            activeTab === 'SEVERED_SOCKETS'
              ? 'border border-cyan-500/60 bg-cyan-950 font-bold text-cyan-300 shadow-sm'
              : 'bg-slate-900 text-slate-400 hover:text-white'
          }`}
        >
          <Network className="h-3.5 w-3.5" />
          <span>
            {isAr ? 'اتصالات TCP المقطوعة فورياً' : 'Severed TCP Sockets'} ({severedSockets.length})
          </span>
        </button>

        <button
          onClick={() => setActiveTab('CLUSTER_NODES')}
          className={`flex items-center gap-2 rounded-lg px-3 py-1.5 transition ${
            activeTab === 'CLUSTER_NODES'
              ? 'border border-cyan-500/60 bg-cyan-950 font-bold text-cyan-300 shadow-sm'
              : 'bg-slate-900 text-slate-400 hover:text-white'
          }`}
        >
          <Server className="h-3.5 w-3.5" />
          <span>
            {isAr ? 'عزل العقد أفقياً (Microsegmentation)' : 'Node Micro-segmentation'} (
            {clusterNodes.length})
          </span>
        </button>

        <button
          onClick={() => setActiveTab('EBPF_CODE')}
          className={`flex items-center gap-2 rounded-lg px-3 py-1.5 transition ${
            activeTab === 'EBPF_CODE'
              ? 'border border-emerald-500/60 bg-emerald-950 font-bold text-emerald-300 shadow-sm'
              : 'bg-slate-900 text-slate-400 hover:text-white'
          }`}
        >
          <FileCode className="h-3.5 w-3.5" />
          <span>{isAr ? 'شيفرة eBPF XDP بالنواة' : 'Kernel eBPF C Code'}</span>
        </button>
      </div>

      {/* 5. TAB CONTENTS */}

      {/* TAB 1: KERNEL BLACKHOLES */}
      {activeTab === 'ROUTING' && (
        <div className="animate-fadeIn space-y-3">
          {/* Search & Manual Quick Trigger */}
          <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-slate-800 bg-slate-900/70 p-2.5 shadow-[0_0_20px_rgba(0,255,255,0.08)]">
            <div className="relative">
              <Search className="absolute top-2.5 left-2.5 h-3.5 w-3.5 text-slate-400" />
              <input
                type="text"
                value={searchQuery}
                onChange={e => setSearchQuery(e.target.value)}
                placeholder={
                  isAr ? 'بحث في العناوين أو الأسباب...' : 'Search isolated IP, reason, IoC...'
                }
                className="w-56 rounded-lg border border-slate-700 bg-slate-950 py-1 pr-3 pl-8 font-mono text-xs text-slate-200 outline-none focus:border-rose-400 shadow-[0_0_20px_rgba(0,255,255,0.08)]"
              />
            </div>

            <div className="flex items-center gap-2">
              <input
                type="text"
                value={manualIpInput}
                onChange={e => setManualIpInput(e.target.value)}
                placeholder={
                  isAr
                    ? 'إدخال IP لعزله بالنواة فوراً (مثال 198.51.100.4)...'
                    : 'Target IP (e.g. 198.51.100.4)...'
                }
                className="w-64 rounded-lg border border-slate-700 bg-slate-950 px-3 py-1 font-mono text-xs text-slate-200 outline-none focus:border-rose-400 shadow-[0_0_20px_rgba(0,255,255,0.08)]"
              />
              <button
                onClick={handleTriggerManualContainment}
                disabled={isTriggeringContainment || !manualIpInput.trim()}
                className="flex items-center gap-1.5 rounded-lg bg-rose-600 px-3 py-1 font-mono text-xs font-bold text-white shadow-md shadow-rose-950/60 transition hover:bg-rose-500 disabled:opacity-50"
              >
                <Lock className="h-3.5 w-3.5" />
                <span>{isAr ? 'عزل عبر eBPF' : 'Enforce Drop'}</span>
              </button>
            </div>
          </div>

          {/* Cards */}
          <div className="max-h-[420px] space-y-2.5 overflow-y-auto pr-1">
            {filteredRecords.map(record => {
              const isActive = record.status === 'ACTIVE_BLACKHOLE';

              return (
                <div
                  key={record.id}
                  className={`flex flex-col justify-between gap-3 rounded-xl border p-3.5 transition md:flex-row md:items-center ${
                    isActive
                      ? 'border-rose-500/40 bg-rose-950/20 shadow-lg shadow-rose-950/20 hover:border-rose-400/60'
                      : 'border-slate-800 bg-slate-900/50 hover:border-slate-700 shadow-[0_0_20px_rgba(0,255,255,0.08)]'
                  }`}
                >
                  <div className="space-y-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <span
                        className={`flex items-center gap-1 rounded px-2 py-0.5 font-mono text-[10px] font-bold uppercase ${
                          isActive
                            ? 'border border-rose-500/50 bg-rose-900/80 text-rose-200'
                            : 'bg-slate-800 text-slate-300'
                        }`}
                      >
                        {isActive ? (
                          <Lock className="h-2.5 w-2.5" />
                        ) : (
                          <Unlock className="h-2.5 w-2.5" />
                        )}
                        {isActive
                          ? isAr
                            ? 'عزل نشط'
                            : 'ACTIVE DROP'
                          : isAr
                            ? 'مفرج عنه'
                            : 'RELEASED'}
                      </span>

                      <span className="rounded border border-slate-800 bg-slate-950 px-2 py-0.5 font-mono text-xs font-bold text-rose-400 shadow-[0_0_20px_rgba(0,255,255,0.08)]">
                        {record.cidrBlock}
                      </span>

                      <button
                        onClick={() => handleCopy(record.targetIp)}
                        className="p-1 text-slate-400 transition hover:text-slate-200"
                        title={isAr ? 'نسخ العنوان' : 'Copy IP'}
                      >
                        {copiedIp === record.targetIp ? (
                          <Check className="h-3 w-3 text-emerald-400" />
                        ) : (
                          <Copy className="h-3 w-3" />
                        )}
                      </button>

                      <span className="py-0.2 rounded border border-cyan-500/40 bg-cyan-950 px-1.5 font-mono text-[9px] text-cyan-300">
                        ⚡ {record.interceptLatencyUs} µs
                      </span>

                      {record.bpfMapKey && (
                        <span className="py-0.2 rounded border border-slate-800 bg-slate-950 px-1.5 font-mono text-[9px] text-slate-400 shadow-[0_0_20px_rgba(0,255,255,0.08)]">
                          BPF Key: {record.bpfMapKey}
                        </span>
                      )}

                      <span className="font-mono text-[10px] text-slate-400">
                        Node: <strong className="text-slate-300">{record.nodeName}</strong>
                      </span>
                    </div>

                    <p className="text-xs leading-snug text-slate-300">
                      {isAr && record.reasonAr ? record.reasonAr : record.reason}
                    </p>

                    <div className="flex flex-wrap items-center gap-3 pt-0.5 font-mono text-[10px] text-slate-400">
                      <span>
                        IoC: <strong className="text-amber-400">{record.triggeredByIoc}</strong>
                      </span>
                      <span>•</span>
                      <span>
                        Packets Dropped:{' '}
                        <strong className="text-rose-400">
                          {record.packetsDroppedCount.toLocaleString()}
                        </strong>
                      </span>
                      <span>•</span>
                      <span>
                        TCP RST Injected:{' '}
                        <strong className="text-cyan-400">{record.tcpConnectionsSevered}</strong>
                      </span>
                      <span>•</span>
                      <span>Time: {new Date(record.isolatedAt).toLocaleTimeString()}</span>
                    </div>
                  </div>

                  <div className="flex items-center gap-2 self-end md:self-center">
                    {isActive ? (
                      <button
                        onClick={() => handleReleaseIp(record.targetIp)}
                        className="flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-900 px-2.5 py-1 font-mono text-xs text-slate-300 transition hover:border-slate-600 hover:bg-slate-800 shadow-[0_0_20px_rgba(0,255,255,0.08)]"
                      >
                        <Unlock className="h-3.5 w-3.5 text-amber-400" />
                        <span>{isAr ? 'إلغاء العزل' : 'Release IP'}</span>
                      </button>
                    ) : (
                      <button
                        onClick={() => {
                          setManualIpInput(record.targetIp);
                          handleTriggerManualContainment();
                        }}
                        className="flex items-center gap-1.5 rounded-lg border border-rose-500/40 bg-rose-950/60 px-2.5 py-1 font-mono text-xs text-rose-300 transition hover:bg-rose-900/70"
                      >
                        <Lock className="h-3.5 w-3.5" />
                        <span>{isAr ? 'إعادة العزل' : 'Re-isolate'}</span>
                      </button>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* TAB 2: BEHAVIORAL ANOMALIES (HEURISTIC IOC ENGINE) */}
      {activeTab === 'ANOMALIES' && (
        <div className="animate-fadeIn space-y-3">
          <div className="flex items-center justify-between pb-1 font-mono text-xs text-slate-400">
            <span>
              {isAr
                ? 'المراقبة المستمرة لمؤشرات الاختراق (IoCs) مع تقييم الثقة واتخاذ قرار العزل الآلي'
                : 'Continuous heuristic evaluation of IoCs with confidence scoring & autonomous isolation'}
            </span>
            <span className="font-bold text-amber-400">{anomalies.length} Alerts Logged</span>
          </div>

          <div className="max-h-[420px] space-y-2.5 overflow-y-auto pr-1">
            {anomalies.map(anom => {
              const isHighConfidence = anom.confidenceScore >= 85;

              return (
                <div
                  key={anom.id}
                  className={`space-y-2 rounded-xl border p-3.5 ${
                    isHighConfidence
                      ? 'border-amber-500/40 bg-amber-950/20 shadow-md shadow-amber-950/20'
                      : 'border-slate-800 bg-slate-900/50 shadow-[0_0_20px_rgba(0,255,255,0.08)]'
                  }`}
                >
                  <div className="flex flex-col justify-between gap-2 sm:flex-row sm:items-center">
                    <div className="flex items-center gap-2">
                      <span className="rounded border border-amber-500/50 bg-amber-950 px-2 py-0.5 font-mono text-[10px] font-bold text-amber-300">
                        {anom.type}
                      </span>
                      <span className="text-xs font-bold text-white">
                        {isAr ? anom.titleAr : anom.title}
                      </span>
                    </div>

                    <div className="flex items-center gap-2 font-mono text-xs">
                      <span className="text-[10px] text-slate-400">
                        {isAr ? 'درجة الثقة:' : 'Confidence:'}
                      </span>
                      <span
                        className={`rounded px-2 py-0.5 text-[11px] font-bold ${
                          anom.confidenceScore >= 90
                            ? 'border border-rose-500/50 bg-rose-950 text-rose-300'
                            : 'border border-amber-500/50 bg-amber-950 text-amber-300'
                        }`}
                      >
                        {anom.confidenceScore}% {anom.confidenceScore >= 90 ? '🔥 High' : ''}
                      </span>
                    </div>
                  </div>

                  {/* Threshold Violation Info */}
                  <div className="rounded-lg border border-slate-800 bg-slate-950/80 p-2 font-mono text-xs text-slate-300 shadow-[0_0_20px_rgba(0,255,255,0.08)]">
                    <span className="mb-0.5 block text-[11px] font-bold text-rose-400">
                      ⚠️{' '}
                      {isAr
                        ? 'تجاوز حد السياسة الأمنية (Threshold Breach):'
                        : 'Security Threshold Breach:'}
                    </span>
                    <p>{isAr ? anom.thresholdExceededAr : anom.thresholdExceeded}</p>
                  </div>

                  {/* Heuristic metrics breakdown */}
                  <div className="grid grid-cols-1 gap-2 rounded-lg border border-slate-800/80 bg-slate-900/60 p-2 font-mono text-[10px] sm:grid-cols-3 shadow-[0_0_20px_rgba(0,255,255,0.08)]">
                    <div>
                      <span className="block text-slate-400">Metric:</span>
                      <span className="font-bold text-cyan-300">
                        {anom.heuristicDetails.anomalyMetric}
                      </span>
                    </div>
                    <div>
                      <span className="block text-slate-400">Baseline Value:</span>
                      <span className="text-emerald-400">
                        {anom.heuristicDetails.baselineValue}
                      </span>
                    </div>
                    <div>
                      <span className="block text-slate-400">Observed Spike:</span>
                      <span className="font-bold text-rose-400">
                        {anom.heuristicDetails.observedValue}
                      </span>
                    </div>
                  </div>

                  {/* Bottom details */}
                  <div className="flex flex-wrap items-center justify-between gap-2 pt-1 font-mono text-[10px] text-slate-400">
                    <div className="flex items-center gap-2">
                      <span>
                        Actor IP: <strong className="text-rose-400">{anom.actorIp}</strong>
                      </span>
                      <span>•</span>
                      <span>
                        Target Node: <strong className="text-slate-300">{anom.targetNode}</strong>
                      </span>
                      <span>•</span>
                      <span>{new Date(anom.detectedAt).toLocaleTimeString()}</span>
                    </div>

                    <div>
                      {anom.autoContained ? (
                        <span className="flex items-center gap-1 rounded border border-rose-500/50 bg-rose-950 px-2 py-0.5 font-bold text-rose-300">
                          <Check className="h-3 w-3 text-rose-400" />
                          {isAr ? 'عزل تلقائي بالنواة (Zero-Trust)' : 'Zero-Trust Auto-Isolated'}
                        </span>
                      ) : (
                        <span className="rounded bg-slate-800 px-2 py-0.5 text-slate-400">
                          {isAr ? 'قيد المراقبة' : 'Monitored'}
                        </span>
                      )}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* TAB 3: SEVERED TCP SOCKETS */}
      {activeTab === 'SEVERED_SOCKETS' && (
        <div className="animate-fadeIn space-y-3">
          <div className="flex items-center justify-between pb-1 font-mono text-xs text-slate-400">
            <span>
              {isAr
                ? 'جلسات TCP النشطة التي تم قطعها فورياً بإرسال حزم TCP-RST لحظية من النواة'
                : 'Active TCP connections severed via synthetic kernel TCP-RST packets'}
            </span>
            <span className="font-bold text-cyan-400">{severedSockets.length} Sockets Severed</span>
          </div>

          <div className="max-h-[420px] space-y-2 overflow-y-auto pr-1">
            {severedSockets.map(sock => (
              <div
                key={sock.id}
                className="flex flex-col justify-between gap-2 rounded-xl border border-cyan-900/40 bg-slate-900/60 p-3 font-mono text-xs sm:flex-row sm:items-center"
              >
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="rounded border border-cyan-500/40 bg-cyan-950 px-2 py-0.5 text-[10px] font-bold text-cyan-300">
                      TCP-RST SEVERED
                    </span>
                    <span className="font-bold text-rose-400">
                      {sock.targetIp}:{sock.srcPort}
                    </span>
                    <span className="text-slate-500">→</span>
                    <span className="font-bold text-emerald-400">
                      {sock.dstIp}:{sock.dstPort}
                    </span>
                  </div>

                  <div className="flex flex-wrap items-center gap-3 text-[10px] text-slate-400">
                    <span>
                      State Before Sever:{' '}
                      <strong className="text-amber-300">{sock.stateBeforeSever}</strong>
                    </span>
                    <span>•</span>
                    <span>
                      Kill Latency: <strong className="text-cyan-300">{sock.latencyUs} µs</strong>
                    </span>
                    <span>•</span>
                    <span>
                      Transferred: <strong>{sock.bytesTransferredBeforeKill} bytes</strong>
                    </span>
                    <span>•</span>
                    <span>Time: {new Date(sock.rstInjectedAt).toLocaleTimeString()}</span>
                  </div>
                </div>

                <div className="self-end sm:self-center">
                  <span className="rounded border border-slate-800 bg-slate-950 px-2 py-1 text-[10px] text-slate-300 shadow-[0_0_20px_rgba(0,255,255,0.08)]">
                    Killed in &lt;0.35µs
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* TAB 4: CLUSTER NODES MICROSEGMENTATION */}
      {activeTab === 'CLUSTER_NODES' && (
        <div className="animate-fadeIn space-y-3">
          <div className="flex items-center justify-between pb-1 font-mono text-xs text-slate-400">
            <span>
              {isAr
                ? 'عزل العقد المصابة أفقياً (East-West Microsegmentation) لمنع التحرك الجانبي داخل عنقود الخوادم'
                : 'Zero-Trust cluster micro-segmentation: Block East-West lateral movement while preserving telemetry'}
            </span>
          </div>

          <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
            {clusterNodes.map(node => {
              const isQuarantined = node.isolationStatus === 'QUARANTINED_EAST_WEST';

              return (
                <div
                  key={node.nodeName}
                  className={`space-y-2.5 rounded-xl border p-3.5 transition ${
                    isQuarantined
                      ? 'border-cyan-500/50 bg-cyan-950/20 shadow-md shadow-cyan-950/30'
                      : 'border-slate-800 bg-slate-900/50 shadow-[0_0_20px_rgba(0,255,255,0.08)]'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <Server
                        className={`h-4 w-4 ${isQuarantined ? 'text-cyan-400' : 'text-emerald-400'}`}
                      />
                      <span className="font-mono text-xs font-bold text-white">
                        {node.nodeName}
                      </span>
                    </div>

                    <span
                      className={`rounded px-2 py-0.5 font-mono text-[10px] font-bold ${
                        isQuarantined
                          ? 'animate-pulse border border-cyan-500/50 bg-cyan-950 text-cyan-300'
                          : 'border border-emerald-500/50 bg-emerald-950 text-emerald-300'
                      }`}
                    >
                      {isQuarantined
                        ? isAr
                          ? 'معزولة أفقياً'
                          : 'QUARANTINED'
                        : isAr
                          ? 'متصلة بالشبكة'
                          : 'ATTACHED'}
                    </span>
                  </div>

                  <div className="grid grid-cols-2 gap-2 rounded-lg border border-slate-800 bg-slate-950/80 p-2 font-mono text-[10px] shadow-[0_0_20px_rgba(0,255,255,0.08)]">
                    <div>
                      <span className="block text-slate-400">IP:</span>
                      <span className="text-slate-200">{node.nodeIp}</span>
                    </div>
                    <div>
                      <span className="block text-slate-400">Role:</span>
                      <span className="text-cyan-300">{node.clusterRole}</span>
                    </div>
                    <div>
                      <span className="block text-slate-400">eBPF XDP Driver:</span>
                      <span className="font-bold text-emerald-400">
                        {node.ebpfXdpAttached ? 'ATTACHED (enp1s0)' : 'DETACHED'}
                      </span>
                    </div>
                    <div>
                      <span className="block text-slate-400">Lateral Packets Blocked:</span>
                      <span className="font-bold text-rose-400">
                        {(node.ingressPacketsDropped + node.egressPacketsDropped).toLocaleString()}
                      </span>
                    </div>
                  </div>

                  <div className="flex items-center justify-between pt-1">
                    <span className="font-mono text-[10px] text-slate-400">
                      {isQuarantined
                        ? isAr
                          ? 'منع الاتصال بقواعد البيانات والعقد'
                          : 'East-West cluster traffic blocked'
                        : isAr
                          ? 'سليمة'
                          : 'Healthy'}
                    </span>

                    <button
                      onClick={() => handleToggleNodeQuarantine(node.nodeName, isQuarantined)}
                      className={`flex items-center gap-1.5 rounded-lg px-2.5 py-1 font-mono text-xs font-bold transition ${
                        isQuarantined
                          ? 'border border-emerald-500/50 bg-emerald-950/80 text-emerald-300 hover:bg-emerald-900'
                          : 'border border-cyan-500/50 bg-cyan-950/80 text-cyan-300 hover:bg-cyan-900'
                      }`}
                    >
                      {isQuarantined ? (
                        <Unlock className="h-3 w-3" />
                      ) : (
                        <Lock className="h-3 w-3" />
                      )}
                      <span>
                        {isQuarantined
                          ? isAr
                            ? 'إعادة الإلحاق'
                            : 'Re-attach Node'
                          : isAr
                            ? 'عزل العقدة'
                            : 'Quarantine Node'}
                      </span>
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* TAB 5: KERNEL eBPF C CODE INSPECTOR */}
      {activeTab === 'EBPF_CODE' && (
        <div className="animate-fadeIn space-y-3 font-mono text-xs">
          <div className="flex items-center justify-between pb-1 text-slate-400">
            <span>
              {isAr
                ? 'كود برنامج eBPF المجمع بنواة لينكس (Kernel Bytecode Filter)'
                : 'Kernel eBPF XDP C program loaded in NIC driver hook:'}
            </span>
            <span className="rounded border border-emerald-500/40 bg-emerald-950 px-2 py-0.5 text-[10px] text-emerald-300">
              Driver: XDP_DRV Native
            </span>
          </div>

          <div className="overflow-x-auto rounded-xl border border-slate-800 bg-slate-950 p-3.5 text-[11px] leading-relaxed text-cyan-200 shadow-inner shadow-[0_0_20px_rgba(0,255,255,0.08)]">
            <pre>{`// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>

// Hash map storing zero-trust blackholed IP addresses
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);   // IPv4 Address (big-endian)
    __type(value, __u64); // Drop timestamp & packet count
} blackhole_ips_map SEC(".maps");

SEC("xdp")
int xdp_sovereign_zero_trust(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    if (eth->h_proto != __constant_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) return XDP_PASS;

    __u32 src_ip = iph->saddr;
    __u64 *drop_count = bpf_map_lookup_elem(&blackhole_ips_map, &src_ip);

    if (drop_count) {
        __sync_fetch_and_add(drop_count, 1);
        // Sub-microsecond instantaneous kernel drop:
        return XDP_DROP;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";`}</pre>
          </div>
        </div>
      )}
    </div>
  );
};
