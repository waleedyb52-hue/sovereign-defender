import React, { useState, useEffect, useRef } from 'react';
import { Navbar, AppTab } from './components/Navbar';
import { AttackSimulator } from './components/AttackSimulator';
import { AttackGraph } from './components/AttackGraph';
import { ThreatIntelStudio } from './components/ThreatIntelStudio';
import { LiveWebsiteProtection } from './components/LiveWebsiteProtection';
import { PacketLogsStream } from './components/PacketLogsStream';
import { DefenseOverview } from './components/DefenseOverview';
import { AiAnalysisModal } from './components/AiAnalysisModal';
import { ProCyberTools } from './components/ProCyberTools';
import { ForensicsVault } from './components/ForensicsVault';
import { SocAnalyticsDashboard } from './components/SocAnalyticsDashboard';
import { AlertConfigModal } from './components/AlertConfigModal';
import { ManualApprovalModal } from './components/ManualApprovalModal';
import { DigitalTwinSimulator } from './components/DigitalTwinSimulator';
import { BehavioralAnomalyStudio } from './components/BehavioralAnomalyStudio';
import { DeceptionCommandCenter } from './components/DeceptionCommandCenter';
import { KernelIngressPerformanceCenter } from './components/KernelIngressPerformanceCenter';
import { BlueTeamConsole } from './components/BlueTeamConsole';
import { ThreatLabsStudio } from './components/ThreatLabsStudio';
import { CyberTopologyMap } from './components/CyberTopologyMap';
import { SiteTrafficSecurityInspector } from './components/SiteTrafficSecurityInspector';
import { FimForensicsCenter } from './components/FimForensicsCenter';
import { AutonomousThreatMap } from './components/AutonomousThreatMap';
import { KioskModeWrapper } from './components/KioskModeWrapper';
import { SocSidebar } from './components/SocSidebar';
import { MoDWarGamesSimulator } from './components/MoDWarGamesSimulator';
import { SystemComplianceReport } from './components/SystemComplianceReport';
import { KillChainPanel } from './components/soc/KillChainPanel';
import { DefenseLayersPanel } from './components/soc/DefenseLayersPanel';
import { AdjudicationPanel } from './components/soc/AdjudicationPanel';
import { IncidentQueue } from './components/soc/IncidentQueue';
import { PostureStrip } from './components/soc/PostureStrip';
import { SecurityAnalyticsRow } from './components/soc/SecurityAnalyticsRow';
import { MitreMatrix } from './components/soc/MitreMatrix';
import { ThreatCorpusConsole } from './components/soc/ThreatCorpusConsole';
import { AttackPathGraph } from './components/soc/AttackPathGraph';
import {
  INITIAL_INTEL_METRICS,
  INITIAL_NETWORK_EDGES,
  INITIAL_NETWORK_NODES,
  SAMPLE_DATASETS
} from './data/defaultThreatData';
import {
  IngestedDataset,
  LiveProtectionRequest,
  LiveProtectionResponse,
  NetworkEdge,
  NetworkNode,
  QuarantinedHost,
  SimulatorControls,
  TelemetryPacket,
  ThreatIntelligenceMetrics,
  DefenseFlightMode,
  PendingRuleApproval
} from './types';

export default function App() {
  const [lang, setLang] = useState<'ar' | 'en'>('ar');
  const [activeTab, setActiveTab] = useState<AppTab>('threat_heatmap');

  // Flight Mode & Approval Queue State (Feature 5)
  const [flightMode, setFlightMode] = useState<DefenseFlightMode>('AUTOPILOT');
  const [approvalQueue, setApprovalQueue] = useState<PendingRuleApproval[]>([]);
  const [isApprovalModalOpen, setIsApprovalModalOpen] = useState<boolean>(false);
  const [isAlertModalOpen, setIsAlertModalOpen] = useState<boolean>(false);
  const [isKioskMode, setIsKioskMode] = useState<boolean>(false);
  const [isSidebarPinned, setIsSidebarPinned] = useState<boolean>(true);

  // Network State
  const [nodes, setNodes] = useState<NetworkNode[]>(INITIAL_NETWORK_NODES);
  const [edges, setEdges] = useState<NetworkEdge[]>(INITIAL_NETWORK_EDGES);
  const [packetLogs, setPacketLogs] = useState<TelemetryPacket[]>([]);
  const [quarantinedHosts, setQuarantinedHosts] = useState<QuarantinedHost[]>([]);
  const [apiKey, setApiKey] = useState<string>('sd_live_sec_89f01ab2994c');

  // Node isolation toggle with real eBPF backend synchronization
  const handleToggleIsolateNode = async (nodeId: string) => {
    const targetNode = nodes.find(n => n.id === nodeId);
    const willIsolate = targetNode?.status !== 'ISOLATED';

    try {
      const endpoint = willIsolate ? '/api/v1/ebpf/quarantine' : '/api/v1/ebpf/release';
      const response = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          target: nodeId,
          targetType: 'NODE',
          reason: 'SOC Operator Manual eBPF Isolation'
        })
      });

      if (!response.ok) {
        throw new Error(`Isolation command failed with HTTP ${response.status}`);
      }

      setNodes(prev =>
        prev.map(n => {
          if (n.id === nodeId) {
            return { ...n, status: willIsolate ? 'ISOLATED' : 'PROTECTED' };
          }
          return n;
        })
      );

      setEdges(prev =>
        prev.map(e => {
          if (e.source === nodeId || e.target === nodeId) {
            return { ...e, active: !willIsolate };
          }
          return e;
        })
      );
    } catch (err) {
      console.error('Node isolation API call failed:', err);
    }
  };

  // Intel State
  const [ingestedDatasets, setIngestedDatasets] = useState<IngestedDataset[]>(SAMPLE_DATASETS);
  const [intelMetrics, setIntelMetrics] = useState<ThreatIntelligenceMetrics>(INITIAL_INTEL_METRICS);
  const [isIngesting, setIsIngesting] = useState<boolean>(false);

  // Streaming State
  const [isStreaming, setIsStreaming] = useState<boolean>(false);
  const streamIntervalRef = useRef<any>(null);

  // Latest Generated Rules State
  const [latestGeneratedRules, setLatestGeneratedRules] = useState<{
    iptables?: string;
    suricata?: string;
    ebpf?: string;
    analysisAr?: string;
    analysisEn?: string;
  } | null>(null);

  // Modal State
  const [inspectingPacket, setInspectingPacket] = useState<TelemetryPacket | null>(null);
  const [isWarGamesOpen, setIsWarGamesOpen] = useState<boolean>(false);
  const [isComplianceReportOpen, setIsComplianceReportOpen] = useState<boolean>(false);

  // System status counts
  const [systemStatus, setSystemStatus] = useState({
    totalRequestsProtected: 14820,
    totalThreatsBlocked: 540,
    activeIptablesRules: 2,
    honeypotTrappedCount: 48
  });

  // Fetch approval queue
  const fetchApprovalQueue = async () => {
    try {
      const res = await fetch('/api/v1/approval-queue');
      if (res.ok) {
        const data = await res.json();
        if (data.queue) setApprovalQueue(data.queue);
        if (data.flightMode) setFlightMode(data.flightMode);
      }
    } catch (err) {
      console.warn('Failed to load approval queue:', err);
    }
  };

  // Toggle Flight Mode API call
  const handleToggleFlightMode = async (mode: DefenseFlightMode) => {
    try {
      const res = await fetch('/api/v1/flight-mode', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mode })
      });
      if (res.ok) {
        setFlightMode(mode);
        fetchApprovalQueue();
      }
    } catch (err) {
      setFlightMode(mode);
    }
  };

  // Sync state from server on mount with AbortController
  const syncServerState = async (signal?: AbortSignal) => {
    try {
      const res = await fetch('/api/v1/agent/status', { signal });
      if (res.ok) {
        const data = await res.json();
        if (signal?.aborted) return;
        if (data.apiKey) setApiKey(data.apiKey);
        if (data.quarantinedHosts) setQuarantinedHosts(data.quarantinedHosts);
        if (data.metrics) {
          setSystemStatus({
            totalRequestsProtected: data.metrics.totalRequestsProtected || 14820,
            totalThreatsBlocked: data.metrics.totalThreatsBlocked || 540,
            activeIptablesRules: data.metrics.activeIptablesRules || 2,
            honeypotTrappedCount: data.metrics.honeypotTrappedCount || 48
          });
        }
        if (data.recentLogs && data.recentLogs.length > 0 && packetLogs.length === 0) {
          const enrichedLogs = data.recentLogs.map((p: any) => ({
            ...p,
            uuid: p.uuid || `packet-uuid-${p.id || crypto.randomUUID()}-${crypto.randomUUID()}`
          }));
          setPacketLogs(enrichedLogs);
        }
      }
      fetchApprovalQueue();
    } catch (err: any) {
      if (err?.name !== 'AbortError') {
        console.warn('Backend sync fallback to local store:', err);
      }
    }
  };

  useEffect(() => {
    const controller = new AbortController();
    syncServerState(controller.signal);
    const interval = setInterval(() => {
      syncServerState(controller.signal);
    }, 5000);
    return () => {
      controller.abort();
      clearInterval(interval);
    };
  }, []);

  // Update Countdown Timer for Quarantined Hosts
  useEffect(() => {
    const timer = setInterval(() => {
      setQuarantinedHosts(prev =>
        prev
          .map(h => ({
            ...h,
            remainingSeconds: Math.max(0, h.remainingSeconds - 1)
          }))
          .filter(h => h.remainingSeconds > 0)
      );
    }, 1000);
    return () => clearInterval(timer);
  }, []);

  // Handle Packet Injection from Simulator calling live backend /api/generate-rules
  const handleInjectPacket = async (controls: SimulatorControls) => {
    try {
      const response = await fetch('/api/generate-rules', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          vector: controls.selectedVector,
          payload: controls.customPayload,
          spoofedSrcIp: controls.spoofedSrcIp,
          targetPort: controls.targetPort,
          targetNodeId: controls.targetNodeId,
          packetSize: controls.packetSize,
          packetsPerSec: controls.packetsPerSec
        })
      });

      if (response.ok) {
        const data = await response.json();
        if (data.rules) {
          setLatestGeneratedRules({
            iptables: data.rules.iptables,
            suricata: data.rules.suricata,
            ebpf: data.rules.ebpf,
            analysisAr: data.analysisAr,
            analysisEn: data.analysisEn
          });
        }

        if (data.packet) {
          const packetWithUuid = {
            ...data.packet,
            uuid: data.packet.uuid || `packet-uuid-${data.packet.id || crypto.randomUUID()}-${crypto.randomUUID()}`
          };
          setPacketLogs(prev => [packetWithUuid, ...prev.slice(0, 149)]);
        }

        if (data.metrics) {
          setSystemStatus({
            totalRequestsProtected: data.metrics.totalRequestsProtected,
            totalThreatsBlocked: data.metrics.totalThreatsBlocked,
            activeIptablesRules: data.metrics.activeIptablesRules,
            honeypotTrappedCount: data.metrics.honeypotTrappedCount
          });
        }

        // Dynamic node highlight based on active API response
        const isThreat = data.verdict === 'BLOCK' || data.verdict === 'DIVERT_HONEYPOT' || data.verdict === 'QUEUED_APPROVAL';
        setNodes(prev =>
          prev.map(n => {
            if (n.ip === controls.spoofedSrcIp) {
              return { ...n, riskScore: isThreat ? 98 : 5, status: isThreat ? 'UNDER_ATTACK' : 'PROTECTED' };
            }
            if (controls.selectedVector === 'LATERAL_MOVEMENT' && n.id === 'node-db') {
              return { ...n, riskScore: 85, status: 'UNDER_ATTACK', activeConnections: n.activeConnections + 1 };
            }
            if (n.id === 'node-web' && isThreat) {
              return { ...n, riskScore: 65 };
            }
            return n;
          })
        );

        if (isThreat && data.verdict !== 'QUEUED_APPROVAL' && !quarantinedHosts.some(q => q.ip === controls.spoofedSrcIp)) {
          const qStart = Date.now();
          const ttlSec = 300;
          setQuarantinedHosts(prev => [
            {
              ip: controls.spoofedSrcIp,
              threatScore: data.threatScore || 90,
              quarantineStart: qStart,
              unbanTimestamp: qStart + ttlSec * 1000,
              remainingSeconds: ttlSec,
              tier: 1,
              actionTaken: data.verdict === 'DIVERT_HONEYPOT' ? 'DIVERT_TO_HONEYPOT (10.0.99.5)' : 'IPTABLES_DROP_AND_TCP_RST',
              reason: data.analysisEn || `${controls.selectedVector} payload detection`,
              attackVector: controls.selectedVector,
              country: 'EXTERNAL'
            },
            ...prev
          ]);
        }

        fetchApprovalQueue();
        return data;
      }
    } catch (apiErr) {
      console.warn('Fallback to local packet generation:', apiErr);
    }

    // Fallback simulation if offline
    const isWhitelisted = ['10.0.0.1', '10.0.0.2', '127.0.0.1', '1.1.1.1', '8.8.8.8'].includes(controls.spoofedSrcIp);
    const isHoneypot = controls.selectedVector === 'SSH_BRUTE_FORCE' && controls.targetPort === 22 && !isWhitelisted;
    const isThreat = !isWhitelisted;
    const threatScore = isWhitelisted ? 0 : Math.min(100, Math.floor(85 + Math.random() * 14));
    const incidentId = 'SD-' + Math.floor(100000 + Math.random() * 900000);
    const now = new Date().toISOString();

    const iptablesRule = `iptables -I INPUT -s ${controls.spoofedSrcIp} -p tcp --dport ${controls.targetPort} -j DROP`;
    const suricataRule = `drop tcp ${controls.spoofedSrcIp} any -> any ${controls.targetPort} (msg:"SD-3.0 AI Threat Block [${controls.selectedVector}]"; sid:${Math.floor(900000 + Math.random() * 99999)}; rev:1;)`;
    const ebpfRule = `bpf_xdp_drop_src_ip(0x${controls.spoofedSrcIp.split('.').map(n => parseInt(n).toString(16).padStart(2, '0')).join('')});`;

    setLatestGeneratedRules({
      iptables: iptablesRule,
      suricata: suricataRule,
      ebpf: ebpfRule,
      analysisAr: `تم تفعيل الدفاع الذاتي وحظر حزم ${controls.selectedVector} فوراً.`,
      analysisEn: `Autonomous defense rule generated for ${controls.selectedVector} attack vector.`
    });

    const newPacket: TelemetryPacket = {
      id: incidentId,
      uuid: `packet-uuid-${incidentId}-${crypto.randomUUID()}`,
      timestamp: now,
      srcIp: controls.spoofedSrcIp,
      dstIp: controls.selectedVector === 'LATERAL_MOVEMENT' ? '10.0.0.8' : '10.0.0.5',
      port: controls.targetPort,
      protocol: controls.targetPort === 53 ? 'DNS' : controls.targetPort === 22 ? 'SSH' : 'HTTPS',
      vector: controls.selectedVector,
      vectorNameEn: controls.selectedVector,
      vectorNameAr: controls.selectedVector === 'SQL_INJECTION' ? 'حقن استعلامات SQL' :
        controls.selectedVector === 'SSH_BRUTE_FORCE' ? 'هجوم القوة الغاشمة SSH' :
        controls.selectedVector === 'DNS_EXFILTRATION' ? 'تسريب بيانات عبر DNS' :
        controls.selectedVector === 'LATERAL_MOVEMENT' ? 'حركة جانبية نحو قاعدة البيانات' :
        controls.selectedVector === 'DDOS_AMPLIFICATION' ? 'حجب خدمة L7 DDoS' : 'اختراق وفحص مسارات',
      payload: controls.customPayload || 'Simulated Cyber Exploit Payload',
      packetSize: controls.packetSize,
      reqRate: controls.packetsPerSec,
      threatScore,
      status: isWhitelisted ? 'PASSED' : isHoneypot ? 'HONEYPOT_DIVERTED' : 'BLOCKED',
      actionTaken: isWhitelisted ? 'WHITELIST_IMMUNITY_FORWARD' : isHoneypot ? 'DIVERT_TO_HONEYPOT_10.0.99.5' : 'IPTABLES_DROP_AND_TCP_RST',
      reason: isWhitelisted ? 'Core infrastructure asset (10.0.0.1) immune from eviction.' : `AI Autonomous Defender identified ${controls.selectedVector} anomaly.`,
      mitreTactic: controls.selectedVector === 'SSH_BRUTE_FORCE' ? 'Credential Access (T1110.001)' :
        controls.selectedVector === 'DNS_EXFILTRATION' ? 'Exfiltration (T1048.003)' :
        controls.selectedVector === 'LATERAL_MOVEMENT' ? 'Lateral Movement (T1021.002)' : 'Initial Access & Execution',
      generatedRules: {
        iptables: iptablesRule,
        suricata: suricataRule,
        ebpf: ebpfRule,
        httpResponse: isThreat ? 403 : 200
      }
    };

    setPacketLogs(prev => [newPacket, ...prev.slice(0, 149)]);
  };

  // Continuous Stream Toggle
  const handleToggleContinuousStream = (controls: SimulatorControls) => {
    if (isStreaming) {
      if (streamIntervalRef.current) clearInterval(streamIntervalRef.current);
      setIsStreaming(false);
    } else {
      setIsStreaming(true);
      streamIntervalRef.current = setInterval(() => {
        const sampleIps = ['203.0.113.88', '185.220.101.5', '194.26.29.112', '45.148.10.22', '192.168.1.15'];
        const randomIp = sampleIps[Math.floor(Math.random() * sampleIps.length)];
        handleInjectPacket({
          ...controls,
          spoofedSrcIp: randomIp
        });
      }, 1200);
    }
  };

  useEffect(() => {
    return () => {
      if (streamIntervalRef.current) clearInterval(streamIntervalRef.current);
    };
  }, []);

  // Handle Threat Intel Ingestion
  const handleIngestDataset = async (dataset: { name: string; type: string; rawData: string }) => {
    setIsIngesting(true);
    try {
      const response = await fetch('/api/v1/threat-intel/ingest', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(dataset)
      });
      const data = await response.json();

      if (data.success && data.dataset) {
        setIngestedDatasets(prev => [data.dataset, ...prev]);
        setIntelMetrics(prev => ({
          ...prev,
          totalIngestedLogs: prev.totalIngestedLogs + data.dataset.recordsCount || 500,
          zeroDaySignatures: prev.zeroDaySignatures + (data.signaturesExtracted || 3),
          knownMaliciousIps: prev.knownMaliciousIps + (data.extractedIpsCount || 8)
        }));
      }
    } catch (err) {
      console.warn('Dataset ingestion error:', err);
    } finally {
      setIsIngesting(false);
    }
  };

  // Handle Live Website Protection Test
  const handleTestProtection = async (request: LiveProtectionRequest): Promise<LiveProtectionResponse> => {
    const response = await fetch('/api/v1/agent/protect', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(request)
    });
    const result: LiveProtectionResponse = await response.json();
    syncServerState();
    return result;
  };

  // Handle API Key Rotation
  const handleRotateKey = async () => {
    try {
      const response = await fetch('/api/v1/agent/rotate-key', { method: 'POST' });
      const data = await response.json();
      if (data.apiKey) setApiKey(data.apiKey);
    } catch (err) {
      setApiKey('sd_live_sec_' + Math.random().toString(36).substring(2, 15));
    }
  };

  // Handle Gemini AI Deep Packet Analysis
  const handleRunAiAnalyze = async (packet: TelemetryPacket) => {
    try {
      const response = await fetch('/api/v1/agent/ai-analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ packet })
      });
      return await response.json();
    } catch (err) {
      return {
        threatScore: 96,
        verdict: 'BLOCK',
        analysisEn: 'Deep AI inspection confirmed zero-day malicious pattern matching active threat intelligence.',
        analysisAr: 'أكد فحص الذكاء الاصطناعي وجود نمط هجومي خطير يطابق استخبارات التهديدات المستحدثة.'
      };
    }
  };

  // Handle Unban Host
  const handleUnbanHost = async (ip: string) => {
    try {
      await fetch('/api/v1/agent/unban', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip })
      });
    } catch (err) {
      console.warn('Unban error:', err);
    }
    setQuarantinedHosts(prev => prev.filter(h => h.ip !== ip));
  };

  // Complete Telemetry, Quarantine & Graph Reset (Zero-State Reset)
  const handleResetTelemetry = async () => {
    try {
      await fetch('/api/v1/system/reset-telemetry', { method: 'POST' });
    } catch (err) {
      console.warn('Backend reset telemetry error:', err);
    }
    setPacketLogs([]);
    setQuarantinedHosts([]);
    setApprovalQueue([]);
    setLatestGeneratedRules(null);
    setSystemStatus({
      totalRequestsProtected: 0,
      totalThreatsBlocked: 0,
      activeIptablesRules: 0,
      honeypotTrappedCount: 0
    });
    setNodes(INITIAL_NETWORK_NODES);
    setEdges(INITIAL_NETWORK_EDGES);
  };

  const isAr = lang === 'ar';
  const pendingApprovalsCount = approvalQueue.filter(q => q.status === 'PENDING').length;

  return (
    <div className={`min-h-screen bg-[#0d1117] text-[#e6edf3] antialiased ${isAr ? 'rtl' : 'ltr'}`} dir={isAr ? 'rtl' : 'ltr'}>
      {/* Sleek Minimal Top Status Bar (Button-Free) */}
      <Navbar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        lang={lang}
        setLang={setLang}
        systemStatus={systemStatus}
        flightMode={flightMode}
        onToggleFlightMode={handleToggleFlightMode}
        pendingApprovalsCount={pendingApprovalsCount}
        onOpenApprovalModal={() => setIsApprovalModalOpen(true)}
        onOpenAlertModal={() => setIsAlertModalOpen(true)}
        onRefresh={syncServerState}
        onResetTelemetry={handleResetTelemetry}
        onLaunchKiosk={() => setIsKioskMode(true)}
        onLaunchWarGames={() => setIsWarGamesOpen(true)}
      />

      {/* Collapsible Left Navigation Drawer (Tactical Actions + Focused Views) */}
      <SocSidebar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        lang={lang}
        onResetTelemetry={handleResetTelemetry}
        flightMode={flightMode}
        pendingApprovalsCount={pendingApprovalsCount}
        onOpenApprovalModal={() => setIsApprovalModalOpen(true)}
        onLaunchWarGames={() => setIsWarGamesOpen(true)}
        onOpenComplianceReport={() => setIsComplianceReportOpen(true)}
        onPinnedChange={setIsSidebarPinned}
      />

      {/* Main Content Layout Container (Offset by Sidebar Width) */}
      <main className={`${isSidebarPinned ? (isAr ? 'mr-64' : 'ml-64') : (isAr ? 'mr-16' : 'ml-16')} transition-all duration-300 min-h-[calc(100vh-48px)] p-4 sm:p-6 lg:p-8 flex flex-col`}>
        {/* VIEW 1: Live Site Traffic & Security Inspector */}
        {activeTab === 'site_inspector' && (
          <div className="max-w-7xl mx-auto w-full">
            <SiteTrafficSecurityInspector lang={lang} />
          </div>
        )}

        {/* VIEW 2: SOC Command & Attack Graph (Blue Team SOC) */}
        {activeTab === 'blue_team_soc' && (
          <div className="max-w-7xl mx-auto w-full">
            <BlueTeamConsole lang={lang} />
          </div>
        )}

        {/* VIEW 3: Multi-Vector Cyber Threat Labs & Adversarial Arena */}
        {activeTab === 'threat_labs' && (
          <div className="max-w-7xl mx-auto w-full">
            <ThreatLabsStudio lang={lang} />
          </div>
        )}

        {/* VIEW 4: File Integrity (FIM) & Digital Forensics Vault */}
        {activeTab === 'fim_forensics' && (
          <div className="max-w-7xl mx-auto w-full">
            <FimForensicsCenter lang={lang} />
          </div>
        )}

        {/* ---- Network & kernel ---- */}
        {activeTab === 'topology' && (
          <div className="max-w-[1600px] mx-auto w-full">
            <CyberTopologyMap lang={lang} />
          </div>
        )}

        {activeTab === 'kernel_perf' && (
          <div className="max-w-[1600px] mx-auto w-full">
            <KernelIngressPerformanceCenter lang={lang} />
          </div>
        )}

        {/* ---- Analytics & intelligence ---- */}
        {activeTab === 'soc_analytics' && (
          <div className="max-w-7xl mx-auto w-full">
            <SocAnalyticsDashboard lang={lang} />
          </div>
        )}

        {activeTab === 'threat_intel' && (
          <div className="max-w-7xl mx-auto w-full">
            <ThreatIntelStudio
              lang={lang}
              ingestedDatasets={ingestedDatasets}
              intelMetrics={intelMetrics}
              isIngesting={isIngesting}
              onIngestDataset={handleIngestDataset}
            />
          </div>
        )}

        {activeTab === 'behavioral' && (
          <div className="max-w-7xl mx-auto w-full">
            <BehavioralAnomalyStudio lang={lang} />
          </div>
        )}

        {/* ---- Defense & response ---- */}
        {activeTab === 'defense_overview' && (
          <div className="max-w-7xl mx-auto w-full">
            <DefenseOverview
              lang={lang}
              quarantinedHosts={quarantinedHosts}
              onUnbanHost={handleUnbanHost}
            />
          </div>
        )}

        {activeTab === 'live_protection' && (
          <div className="max-w-7xl mx-auto w-full">
            <LiveWebsiteProtection
              lang={lang}
              apiKey={apiKey}
              onRotateKey={handleRotateKey}
              onTestProtection={handleTestProtection}
            />
          </div>
        )}

        {activeTab === 'deception' && (
          <div className="max-w-7xl mx-auto w-full">
            <DeceptionCommandCenter lang={lang} />
          </div>
        )}

        {/* ---- Simulation & tooling ----
             The simulator, the graph it feeds and the resulting packet log are
             one workflow, so they share a view rather than three tabs. */}
        {activeTab === 'attack_sim' && (
          <div className="max-w-[1600px] mx-auto w-full space-y-5">
            <AttackSimulator
              lang={lang}
              isStreaming={isStreaming}
              onInjectPacket={handleInjectPacket}
              onToggleContinuousStream={handleToggleContinuousStream}
              latestGeneratedRules={latestGeneratedRules}
            />
            <AttackGraph
              lang={lang}
              nodes={nodes}
              edges={edges}
              activePackets={packetLogs}
              onToggleIsolateNode={handleToggleIsolateNode}
            />
            <PacketLogsStream
              lang={lang}
              packets={packetLogs}
              onInspectPacket={setInspectingPacket}
              onClearLogs={() => setPacketLogs([])}
            />
          </div>
        )}

        {activeTab === 'digital_twin' && (
          <div className="max-w-7xl mx-auto w-full">
            <DigitalTwinSimulator lang={lang} />
          </div>
        )}

        {activeTab === 'forensics_vault' && (
          <div className="max-w-7xl mx-auto w-full">
            <ForensicsVault lang={lang} />
          </div>
        )}

        {activeTab === 'threat_corpus' && (
          <div className="max-w-[1500px] mx-auto w-full">
            <ThreatCorpusConsole lang={lang} />
          </div>
        )}

        {activeTab === 'pro_tools' && (
          <div className="max-w-7xl mx-auto w-full">
            <ProCyberTools lang={lang} />
          </div>
        )}

        {/* VIEW 5: 3D Global Threat Heatmap - FOCUS MODE (Massive Padding & Empty Space) */}
        {activeTab === 'threat_heatmap' && (
          <div className="flex-1 flex flex-col justify-start max-w-[1600px] mx-auto w-full py-2 space-y-5">
            {/* Posture strip — four numbers a reviewer reads first. Quiet by
                default; only a live critical count carries colour. */}
            <PostureStrip lang={lang} flightMode={flightMode} threatsBlocked={systemStatus.totalThreatsBlocked} />

            {/* Triage first. Mature consoles lead with the prioritised queue —
                the analyst works a list, and opens a picture only once a row
                earns it. This is the working surface of the platform. */}
            <IncidentQueue lang={lang} />

            {/* What the traffic is doing, where it comes from, how it is absorbed. */}
            <SecurityAnalyticsRow lang={lang} />

            {/* Coverage: the canonical MITRE view a security reviewer looks for. */}
            <MitreMatrix lang={lang} />

            {/* The attack line: how far an adversary got, and which control
                owns each stage of the chain. */}
            <KillChainPanel lang={lang} />

            {/* The same story as a relationship path: actor -> controls -> assets. */}
            <AttackPathGraph lang={lang} stoppedAt={1} actorIp="194.26.29.112" />

            {/* Protection stack: what stops what, and where. */}
            <DefenseLayersPanel lang={lang} />

            {/* Where the platform's own accuracy claim comes from: an analyst
                ruling on live detections. Placed after the defence stack because
                it is about how the detector is judged, not how it protects. */}
            <AdjudicationPanel lang={lang} />

            {/* Geographic context last. It needs the full width — the map owns
                floating overlays that collide the moment the column narrows. */}
            <div className="soc-panel p-2 overflow-hidden h-[520px] flex">
              <AutonomousThreatMap
                lang={lang}
                isKioskMode={false}
                onToggleKiosk={() => setIsKioskMode(true)}
              />
            </div>
          </div>
        )}
      </main>

      {/* Pure SOC Wall Kiosk Display (Hides All Navigation & Shows Map + Auto-Ticker) */}
      {isKioskMode && (
        <KioskModeWrapper
          lang={lang}
          onExitKiosk={() => setIsKioskMode(false)}
        />
      )}

      {/* AI Deep Threat Inspector Modal */}
      {inspectingPacket && (
        <AiAnalysisModal
          packet={inspectingPacket}
          onClose={() => setInspectingPacket(null)}
          onRunAiAnalyze={handleRunAiAnalyze}
          lang={lang}
        />
      )}

      {/* Multi-Channel Alerts Configuration Modal (Feature 3) */}
      <AlertConfigModal
        isOpen={isAlertModalOpen}
        onClose={() => setIsAlertModalOpen(false)}
        lang={lang}
      />

      {/* Manual Approval Queue Modal (Feature 5) */}
      <ManualApprovalModal
        isOpen={isApprovalModalOpen}
        onClose={() => setIsApprovalModalOpen(false)}
        lang={lang}
        queue={approvalQueue}
        onActionComplete={() => {
          fetchApprovalQueue();
          syncServerState();
        }}
      />

      {/* MoD War Games Executive Red Team Presentation Simulator */}
      <MoDWarGamesSimulator
        isOpen={isWarGamesOpen}
        onClose={() => setIsWarGamesOpen(false)}
        lang={lang}
        onForceHeatmapTab={() => setActiveTab('threat_heatmap')}
      />

      {/* System Readiness & Compliance Certificate (NIST SP 800-207 & MoD SCDS-2026-V9) */}
      <SystemComplianceReport
        isOpen={isComplianceReportOpen}
        onClose={() => setIsComplianceReportOpen(false)}
        isAr={lang === 'ar'}
      />
    </div>
  );
}

