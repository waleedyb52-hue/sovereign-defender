import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  Activity,
  Radio,
  FileCheck,
  FileWarning,
  RotateCcw,
  Ban,
  Search,
  RefreshCw,
  Zap,
  Lock,
  Unlock,
  AlertTriangle,
  Play,
  Clock,
  Crosshair,
  Server,
  Layers,
  ChevronRight,
  ChevronDown,
  Terminal,
  Filter,
  CheckCircle2,
  XCircle,
  Cpu,
  Sliders,
  Download,
  Trash2,
  Code,
  Shield,
  Eye,
  Check,
  FileText,
  Sparkles,
  ExternalLink,
  Flame,
  Globe,
  Database,
  Key,
  HardDrive,
  Copy,
  Printer,
  FileCode,
  Share2,
  Wifi,
  CornerDownRight,
  Maximize2,
  FileDown,
  Mail,
  ShieldOff,
  Drama
} from 'lucide-react';
import { WebTrafficWafPanel } from './soc/WebTrafficWafPanel';
import { DeceptionSandboxPanel } from './soc/DeceptionSandboxPanel';
import { AttackChainDeceptionPanel } from './soc/AttackChainDeceptionPanel';
import { FileIntegrityProcessPanel } from './soc/FileIntegrityProcessPanel';
import { InterceptionMatrixPanel } from './soc/InterceptionMatrixPanel';
import { DeceptionGridPanel } from './soc/DeceptionGridPanel';
import { ThreatIncidentTimeline } from './soc/ThreatIncidentTimeline';
import { AutonomousContainmentTelemetry } from './soc/AutonomousContainmentTelemetry';
import { SovereignPhasesMasterConsole } from './soc/SovereignPhasesMasterConsole';
import { InteractiveNetworkTopologyMap } from './soc/InteractiveNetworkTopologyMap';
import { InsiderZeroTrustPanel } from './soc/InsiderZeroTrustPanel';
import { SoarReportAutomationPanel } from './soc/SoarReportAutomationPanel';
import { OmnichannelSanitizerPanel } from './soc/OmnichannelSanitizerPanel';
import {
  ManualIpQuarantineModal,
  TargetScannerAuditModal,
  ExportForensicReportModal
} from './soc/TacticalCommandModals';

export interface BlueTeamConsoleProps {
  lang: 'ar' | 'en';
}

// Data Interfaces
export interface UnifiedEvent {
  id: string;
  timestamp: string;
  source: 'WAF_EBPF' | 'FIM' | 'TARGET_SCANNER' | 'AI_DEFENSE' | 'SYSTEM_LOCKDOWN' | 'HONEYPOT';
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  title: string;
  titleAr: string;
  details: string;
  detailsAr?: string;
  actorIp?: string;
  sessionId?: string;
  mitreTactic?: string;
  mitreTechnique?: string;
  actionTaken: string;
  actionTakenAr: string;
  metadata?: Record<string, any>;
}

export interface FimFile {
  relativePath: string;
  fileName: string;
  originalHash: string;
  currentHash: string;
  isModified: boolean;
  isQuarantined: boolean;
  status: 'SECURE' | 'MODIFIED' | 'QUARANTINED' | 'INTACT' | 'TAMPERED' | 'DELETED';
  lastChecked?: string;
  lastModified?: string;
  sizeBytes: number;
  category?: string;
}

export interface FimAlert {
  id: string;
  timestamp: string;
  filePath: string;
  fileName: string;
  changeType: 'CREATE' | 'MODIFY' | 'DELETE' | 'PERMISSION_CHANGE' | string;
  previousHash?: string;
  originalHash?: string;
  currentHash: string;
  diffSnippet?: string;
  threatCategory: string;
  intentClassification: string;
  threatScore: number;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  mitreTechnique: string;
  analysisEn: string;
  analysisAr: string;
  status: 'DETECTED' | 'QUARANTINED' | 'ROLLEDBACK' | 'DISMISSED' | 'ALERTED' | 'IGNORED';
  aiAnalyzed?: boolean;
}

export interface HeaderAuditItem {
  name?: string;
  header?: string;
  present: boolean;
  value?: string | null;
  status: 'PASS' | 'FAIL' | 'WARN';
  recommendation: string;
  weight?: number;
}

export interface TargetScanReport {
  id: string;
  targetUrl: string;
  normalizedHost: string;
  ipAddress?: string;
  timestamp: string;
  responseTimeMs?: number;
  latencyMs?: number;
  httpStatus?: number;
  overallScore: number;
  grade: 'A+' | 'A' | 'B' | 'C' | 'D' | 'F';
  executiveSummaryEn: string;
  executiveSummaryAr: string;
  mitreMapping?: string[];
  headersAudit: HeaderAuditItem[];
  vulnerabilitiesFound?: string[];
  remediationDirectives?: string[];
  actionableMitigations?: string[];
  tlsStatus?: {
    isHttps: boolean;
    hstsEnforced: boolean;
    validTls: boolean;
    details: string;
  };
}

export interface AttackChainSession {
  sessionId: string;
  actorIp: string;
  firstSeen: string;
  lastSeen: string;
  threatScore: number;
  stagesCompleted: Array<{
    stage: 'Reconnaissance' | 'Initial Access' | 'Execution' | 'Persistence' | 'Exfiltration';
    timestamp: string;
    description: string;
    technique: string;
  }>;
  status: 'ACTIVE_TRACKING' | 'CONTAINED' | 'NEUTRALIZED';
}

export interface ForensicProcess {
  pid: number;
  ppid: number;
  name: string;
  user: string;
  cpuPercent: number;
  memoryMb: number;
  command: string;
  sha256: string;
  startTime: string;
  status: 'RUNNING' | 'SUSPICIOUS' | 'INJECTED' | 'TERMINATED';
  loadedModules: string[];
  injectionEvidence?: string;
  threatScore: number;
}

export interface YaraRule {
  id: string;
  name: string;
  tags: string[];
  description: string;
  author: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  strings: string[];
  condition: string;
  rawRule: string;
  matchesCount: number;
  lastMatched?: string;
}

export interface SigmaRule {
  id: string;
  title: string;
  status: 'experimental' | 'test' | 'stable';
  description: string;
  logsource: {
    category?: string;
    product?: string;
    service?: string;
  };
  detection: Record<string, any>;
  level: 'critical' | 'high' | 'medium' | 'low';
  tags: string[];
  rawYaml: string;
  matchesCount: number;
}

export interface NetworkSocket {
  id: string;
  protocol: 'TCP' | 'UDP';
  localAddress: string;
  remoteAddress: string;
  state: 'ESTABLISHED' | 'LISTEN' | 'SYN_SENT' | 'TIME_WAIT' | 'CLOSE_WAIT';
  pid: number;
  processName: string;
  bytesSent: number;
  bytesRecv: number;
  threatFlag: 'MALICIOUS_C2' | 'SUSPICIOUS' | 'NORMAL';
  geoCountry?: string;
  geoCity?: string;
  asn?: string;
}

export interface PcapPacket {
  id: string;
  frameNo: number;
  timestamp: string;
  srcIp: string;
  srcPort: number;
  dstIp: string;
  dstPort: number;
  protocol: 'TCP' | 'UDP' | 'HTTP' | 'DNS' | 'TLS';
  lengthBytes: number;
  info: string;
  hexDump: string;
  asciiDump: string;
  isThreat: boolean;
  threatSignature?: string;
}

export interface IocItem {
  id: string;
  type: 'IP' | 'HASH_SHA256' | 'DOMAIN';
  value: string;
  threatActor: string;
  malwareFamily: string;
  threatScore: number;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  firstSeen: string;
  lastSeen: string;
  mitreTactic: string;
  mitreTechnique: string;
  description: string;
  descriptionAr: string;
  status: 'ACTIVE_BLOCK' | 'MONITORING' | 'RESOLVED';
}

export interface PlaybookStep {
  id: string;
  order: number;
  title: string;
  titleAr: string;
  description: string;
  descriptionAr: string;
  actionCode: string;
  status: 'PENDING' | 'RUNNING' | 'COMPLETED' | 'FAILED';
  executedAt?: string;
  outputLog?: string;
}

export interface IncidentPlaybook {
  id: string;
  name: string;
  nameAr: string;
  category: 'RANSOMWARE' | 'WEBSHELL' | 'CREDENTIAL_STUFFING' | 'C2_EXFILTRATION';
  severity: 'CRITICAL' | 'HIGH';
  description: string;
  descriptionAr: string;
  mitreTechniques: string[];
  targetIncidentId?: string;
  status: 'READY' | 'IN_PROGRESS' | 'CONTAINED';
  steps: PlaybookStep[];
  startedAt?: string;
  completedAt?: string;
}

export const BlueTeamConsole: React.FC<BlueTeamConsoleProps> = ({ lang }) => {
  const isAr = lang === 'ar';
  
  // Navigation SubTab state (17 SOC Pillars v6.0 Sovereign Matrix)
  const [subTab, setSubTab] = useState<
    'topology_map' | 'insider_zero_trust' | 'soar_reports' | 'omnichannel_sanitizer' | 'sovereign_phases' | 'traffic_waf' | 'ebpf_containment' | 'threat_timeline' | 'deception_sandbox' | 'telemetry' | 'fim' | 'scanner' | 'processes' | 'rules_engine' | 'network_pcap' | 'threat_intel' | 'playbooks_reports' | 'interception' | 'deception_grid'
  >('topology_map');

  // Emergency Lockdown State
  const [isLockdownActive, setIsLockdownActive] = useState<boolean>(false);
  const [isLockdownLoading, setIsLockdownLoading] = useState<boolean>(false);

  // Tactical Command Bar Modals State
  const [isQuarantineModalOpen, setIsQuarantineModalOpen] = useState<boolean>(false);
  const [isScannerModalOpen, setIsScannerModalOpen] = useState<boolean>(false);
  const [isReportModalOpen, setIsReportModalOpen] = useState<boolean>(false);

  // 1. Unified Telemetry State
  const [telemetryEvents, setTelemetryEvents] = useState<UnifiedEvent[]>([]);
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [sourceFilter, setSourceFilter] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [isLoadingTelemetry, setIsLoadingTelemetry] = useState<boolean>(false);
  const [selectedTelemetryEvent, setSelectedTelemetryEvent] = useState<UnifiedEvent | null>(null);

  // 2. FIM State
  const [fimFiles, setFimFiles] = useState<FimFile[]>([]);
  const [fimAlerts, setFimAlerts] = useState<FimAlert[]>([]);
  const [fimWatcherActive, setFimWatcherActive] = useState<boolean>(true);
  const [isFimLoading, setIsFimLoading] = useState<boolean>(false);
  const [fimActionMessage, setFimActionMessage] = useState<string | null>(null);
  const [viewingDiffAlertId, setViewingDiffAlertId] = useState<string | null>(null);

  // 3. Scanner State
  const [targetUrlInput, setTargetUrlInput] = useState<string>('https://example.com');
  const [currentScanReport, setCurrentScanReport] = useState<TargetScanReport | null>(null);
  const [scanHistory, setScanHistory] = useState<TargetScanReport[]>([]);
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [scanDepth, setScanDepth] = useState<'STANDARD' | 'DEEP' | 'AGGRESSIVE'>('DEEP');
  const [cronActive, setCronActive] = useState<boolean>(false);
  const [selectedRemediationHeader, setSelectedRemediationHeader] = useState<string | null>(null);

  // 4. Memory & Process Forensics State
  const [processes, setProcesses] = useState<ForensicProcess[]>([]);
  const [selectedProcess, setSelectedProcess] = useState<ForensicProcess | null>(null);
  const [memoryDumpData, setMemoryDumpData] = useState<{ dumpSizeKb: number; hexSnippet: string; stringsExtracted: string[]; dumpTimestamp: string } | null>(null);
  const [isProcLoading, setIsProcLoading] = useState<boolean>(false);
  const [hashScanResult, setHashScanResult] = useState<any>(null);
  const [isHashScanning, setIsHashScanning] = useState<boolean>(false);

  // 5. YARA & Sigma State
  const [yaraRules, setYaraRules] = useState<YaraRule[]>([]);
  const [sigmaRules, setSigmaRules] = useState<SigmaRule[]>([]);
  const [activeRuleType, setActiveRuleType] = useState<'YARA' | 'SIGMA'>('YARA');
  const [selectedYaraRule, setSelectedYaraRule] = useState<YaraRule | null>(null);
  const [ruleEditorCode, setRuleEditorCode] = useState<string>('');
  const [ruleTestPayload, setRuleTestPayload] = useState<string>('POST /api/upload.php HTTP/1.1\ncmd=eval(base64_decode("c3lzdGVtKCdpZCcpOw=="));');
  const [ruleTestResult, setRuleTestResult] = useState<any>(null);
  const [isTestingRule, setIsTestingRule] = useState<boolean>(false);

  // 6. Network Sockets & PCAP State
  const [sockets, setSockets] = useState<NetworkSocket[]>([]);
  const [pcapPackets, setPcapPackets] = useState<PcapPacket[]>([]);
  const [selectedPacket, setSelectedPacket] = useState<PcapPacket | null>(null);
  const [isSocketsLoading, setIsSocketsLoading] = useState<boolean>(false);

  // 7. Threat Intel & IOC State
  const [iocList, setIocList] = useState<IocItem[]>([]);
  const [iocQueryInput, setIocQueryInput] = useState<string>('194.26.29.112');
  const [iocQueryResult, setIocQueryResult] = useState<any>(null);
  const [isQueryingIoc, setIsQueryingIoc] = useState<boolean>(false);

  // 8. Incident Response Playbooks & Reports State
  const [playbooks, setPlaybooks] = useState<IncidentPlaybook[]>([]);
  const [selectedPlaybook, setSelectedPlaybook] = useState<IncidentPlaybook | null>(null);
  const [isPlaybookExecuting, setIsPlaybookExecuting] = useState<boolean>(false);
  const [forensicReport, setForensicReport] = useState<any>(null);
  const [isGeneratingReport, setIsGeneratingReport] = useState<boolean>(false);

  // Dynamic Ticker Metrics
  const [tickerThroughput, setTickerThroughput] = useState<number>(248.4);
  const [tickerLatencyUs, setTickerLatencyUs] = useState<number>(0.42);

  // Periodic Ticker Animation
  useEffect(() => {
    const timer = setInterval(() => {
      setTickerThroughput(Number((240 + Math.random() * 25).toFixed(1)));
      setTickerLatencyUs(Number((0.35 + Math.random() * 0.15).toFixed(2)));
    }, 3500);
    return () => clearInterval(timer);
  }, []);

  // Fetch Lockdown Status
  const fetchLockdownStatus = async () => {
    try {
      const res = await fetch('/api/v1/soc/lockdown/status');
      if (res.ok) {
        const data = await res.json();
        setIsLockdownActive(!!data.emergencyLockdownActive);
      }
    } catch (err) {
      console.warn('Lockdown status fetch error:', err);
    }
  };

  const handleToggleLockdown = async () => {
    setIsLockdownLoading(true);
    try {
      const res = await fetch('/api/v1/soc/lockdown/toggle', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ active: !isLockdownActive })
      });
      if (res.ok) {
        const data = await res.json();
        setIsLockdownActive(!!data.emergencyLockdownActive);
        fetchTelemetry();
      }
    } catch (err) {
      console.error('Lockdown toggle error:', err);
    } finally {
      setIsLockdownLoading(false);
    }
  };

  // 1. Fetch Unified Telemetry
  const fetchTelemetry = async () => {
    setIsLoadingTelemetry(true);
    try {
      const params = new URLSearchParams();
      if (severityFilter !== 'ALL') params.append('severity', severityFilter);
      if (sourceFilter !== 'ALL') params.append('source', sourceFilter);
      if (searchQuery) params.append('search', searchQuery);

      const res = await fetch(`/api/v1/soc/unified-telemetry?${params.toString()}`);
      if (res.ok) {
        const data = await res.json();
        setTelemetryEvents(data.events || []);
        if (data.emergencyLockdown !== undefined) {
          setIsLockdownActive(!!data.emergencyLockdown);
        }
        if (!selectedTelemetryEvent && data.events && data.events.length > 0) {
          setSelectedTelemetryEvent(data.events[0]);
        }
      }
    } catch (err) {
      console.warn('Telemetry fetch error:', err);
    } finally {
      setIsLoadingTelemetry(false);
    }
  };

  // 2. Fetch FIM
  const fetchFimData = async () => {
    setIsFimLoading(true);
    try {
      const [statusRes, filesRes, alertsRes] = await Promise.all([
        fetch('/api/v1/fim/status'),
        fetch('/api/v1/fim/files'),
        fetch('/api/v1/fim/alerts')
      ]);

      if (statusRes.ok) {
        const s = await statusRes.json();
        setFimWatcherActive(s.activeWatcher !== false);
      }
      if (filesRes.ok) {
        const f = await filesRes.json();
        setFimFiles(f.files || []);
      }
      if (alertsRes.ok) {
        const a = await alertsRes.json();
        setFimAlerts(a.alerts || []);
      }
    } catch (err) {
      console.warn('FIM fetch error:', err);
    } finally {
      setIsFimLoading(false);
    }
  };

  // 3. Fetch Scanner History
  const fetchScannerHistory = async () => {
    try {
      const [histRes, cronRes] = await Promise.all([
        fetch('/api/v1/scanner/history'),
        fetch('/api/v1/scanner/cron/status')
      ]);
      if (histRes.ok) {
        const h = await histRes.json();
        setScanHistory(h.history || []);
        if (!currentScanReport && h.history?.length > 0) {
          setCurrentScanReport(h.history[0]);
        }
      }
      if (cronRes.ok) {
        const c = await cronRes.json();
        setCronActive(!!c.active);
      }
    } catch (err) {
      console.warn('Scanner history fetch error:', err);
    }
  };

  // 4. Fetch Processes
  const fetchProcesses = async () => {
    setIsProcLoading(true);
    try {
      const res = await fetch('/api/v1/forensics/processes');
      if (res.ok) {
        const data = await res.json();
        setProcesses(data.processes || []);
        if (!selectedProcess && data.processes?.length > 0) {
          setSelectedProcess(data.processes.find((p: ForensicProcess) => p.status === 'INJECTED') || data.processes[0]);
        }
      }
    } catch (err) {
      console.warn('Process fetch error:', err);
    } finally {
      setIsProcLoading(false);
    }
  };

  // 5. Fetch Rules
  const fetchRules = async () => {
    try {
      const [yaraRes, sigmaRes] = await Promise.all([
        fetch('/api/v1/forensics/rules/yara'),
        fetch('/api/v1/forensics/rules/sigma')
      ]);
      if (yaraRes.ok) {
        const y = await yaraRes.json();
        setYaraRules(y.rules || []);
        if (!selectedYaraRule && y.rules?.length > 0) {
          setSelectedYaraRule(y.rules[0]);
          setRuleEditorCode(y.rules[0].rawRule);
        }
      }
      if (sigmaRes.ok) {
        const s = await sigmaRes.json();
        setSigmaRules(s.rules || []);
      }
    } catch (err) {
      console.warn('Rules fetch error:', err);
    }
  };

  // 6. Fetch Sockets & PCAP
  const fetchSocketsAndPcap = async () => {
    setIsSocketsLoading(true);
    try {
      const [sockRes, pcapRes] = await Promise.all([
        fetch('/api/v1/forensics/network/sockets'),
        fetch('/api/v1/forensics/network/pcap')
      ]);
      if (sockRes.ok) {
        const s = await sockRes.json();
        setSockets(s.sockets || []);
      }
      if (pcapRes.ok) {
        const p = await pcapRes.json();
        setPcapPackets(p.packets || []);
        if (!selectedPacket && p.packets?.length > 0) {
          setSelectedPacket(p.packets[0]);
        }
      }
    } catch (err) {
      console.warn('Sockets fetch error:', err);
    } finally {
      setIsSocketsLoading(false);
    }
  };

  // 7. Fetch IOCs
  const fetchIocs = async () => {
    try {
      const res = await fetch('/api/v1/forensics/threat-intel/iocs');
      if (res.ok) {
        const data = await res.json();
        setIocList(data.iocs || []);
      }
    } catch (err) {
      console.warn('IOC fetch error:', err);
    }
  };

  // 8. Fetch Playbooks
  const fetchPlaybooks = async () => {
    try {
      const res = await fetch('/api/v1/forensics/playbooks');
      if (res.ok) {
        const data = await res.json();
        setPlaybooks(data.playbooks || []);
        if (!selectedPlaybook && data.playbooks?.length > 0) {
          setSelectedPlaybook(data.playbooks[0]);
        }
      }
    } catch (err) {
      console.warn('Playbooks fetch error:', err);
    }
  };

  // Initial Load & polling
  useEffect(() => {
    fetchLockdownStatus();
    fetchTelemetry();
    fetchFimData();
    fetchScannerHistory();
    fetchProcesses();
    fetchRules();
    fetchSocketsAndPcap();
    fetchIocs();
    fetchPlaybooks();

    const interval = setInterval(() => {
      if (subTab === 'telemetry') fetchTelemetry();
      if (subTab === 'fim') fetchFimData();
      if (subTab === 'network_pcap') fetchSocketsAndPcap();
      if (subTab === 'processes') fetchProcesses();
    }, 6000);

    return () => clearInterval(interval);
  }, [subTab]);

  // Action: Kill Process
  const handleKillProcess = async (pid: number) => {
    try {
      const res = await fetch('/api/v1/forensics/process/kill', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ pid })
      });
      if (res.ok) {
        fetchProcesses();
        fetchTelemetry();
      }
    } catch (err) {
      console.error('Kill process error:', err);
    }
  };

  // Action: Dump Memory
  const handleDumpMemory = async (pid: number) => {
    try {
      const res = await fetch('/api/v1/forensics/process/dump-memory', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ pid })
      });
      if (res.ok) {
        const data = await res.json();
        setMemoryDumpData(data);
      }
    } catch (err) {
      console.error('Dump memory error:', err);
    }
  };

  // Action: Scan Hash
  const handleScanHash = async (hash: string, name?: string) => {
    setIsHashScanning(true);
    try {
      const res = await fetch('/api/v1/forensics/hash/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ hash, procName: name })
      });
      if (res.ok) {
        const data = await res.json();
        setHashScanResult(data.result);
      }
    } catch (err) {
      console.error('Hash scan error:', err);
    } finally {
      setIsHashScanning(false);
    }
  };

  // Action: Test YARA Rule
  const handleTestYaraRule = async () => {
    setIsTestingRule(true);
    try {
      const res = await fetch('/api/v1/forensics/rules/yara/test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ruleContent: ruleEditorCode,
          targetPayload: ruleTestPayload
        })
      });
      if (res.ok) {
        const data = await res.json();
        setRuleTestResult(data.result);
      }
    } catch (err) {
      console.error('Test rule error:', err);
    } finally {
      setIsTestingRule(false);
    }
  };

  // Action: Reset Socket
  const handleResetSocket = async (socketId: string) => {
    try {
      const res = await fetch('/api/v1/forensics/network/socket/reset', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ socketId })
      });
      if (res.ok) {
        fetchSocketsAndPcap();
        fetchTelemetry();
      }
    } catch (err) {
      console.error('Reset socket error:', err);
    }
  };

  // Action: Query IOC
  const handleQueryIoc = async () => {
    if (!iocQueryInput) return;
    setIsQueryingIoc(true);
    try {
      const res = await fetch('/api/v1/forensics/threat-intel/query', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query: iocQueryInput })
      });
      if (res.ok) {
        const data = await res.json();
        setIocQueryResult(data.result);
      }
    } catch (err) {
      console.error('Query IOC error:', err);
    } finally {
      setIsQueryingIoc(false);
    }
  };

  // Action: Execute Playbook Step
  const handleExecutePlaybookStep = async (playbookId: string, stepId: string) => {
    setIsPlaybookExecuting(true);
    try {
      const res = await fetch('/api/v1/forensics/playbook/step/execute', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ playbookId, stepId })
      });
      if (res.ok) {
        const data = await res.json();
        setSelectedPlaybook(data.playbook);
        fetchPlaybooks();
        fetchTelemetry();
      }
    } catch (err) {
      console.error('Playbook step execution error:', err);
    } finally {
      setIsPlaybookExecuting(false);
    }
  };

  // Action: Execute All Playbook Steps
  const handleExecuteEntirePlaybook = async (playbookId: string) => {
    setIsPlaybookExecuting(true);
    try {
      const res = await fetch('/api/v1/forensics/playbook/execute-all', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ playbookId })
      });
      if (res.ok) {
        const data = await res.json();
        setSelectedPlaybook(data.playbook);
        fetchPlaybooks();
        fetchTelemetry();
      }
    } catch (err) {
      console.error('Playbook full execution error:', err);
    } finally {
      setIsPlaybookExecuting(false);
    }
  };

  // Action: Generate Forensic Report
  const handleGenerateReport = async () => {
    setIsGeneratingReport(true);
    try {
      const res = await fetch('/api/v1/forensics/report/generate');
      if (res.ok) {
        const data = await res.json();
        setForensicReport(data.report);
      }
    } catch (err) {
      console.error('Generate report error:', err);
    } finally {
      setIsGeneratingReport(false);
    }
  };

  // Action: Run Target Scan
  const handleRunScan = async () => {
    if (!targetUrlInput) return;
    setIsScanning(true);
    try {
      const res = await fetch('/api/v1/scanner/audit', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ targetUrl: targetUrlInput })
      });
      if (res.ok) {
        const data = await res.json();
        setCurrentScanReport(data.report);
        fetchScannerHistory();
        fetchTelemetry();
      }
    } catch (err) {
      console.error('Target scan error:', err);
    } finally {
      setIsScanning(false);
    }
  };

  // Action: Simulate FIM Tamper
  const handleSimulateFimTamper = async (type: string) => {
    try {
      const res = await fetch('/api/v1/fim/simulate-tamper', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ type })
      });
      if (res.ok) {
        const data = await res.json();
        setFimActionMessage(`Injected tamper test: ${data.alert?.threatCategory || type}`);
        fetchFimData();
        fetchTelemetry();
      }
    } catch (err) {
      console.error('FIM simulate error:', err);
    }
  };

  // Action: Rollback FIM
  const handleFimRollback = async (alertId: string) => {
    try {
      const res = await fetch('/api/v1/fim/rollback', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ alertId })
      });
      if (res.ok) {
        setFimActionMessage('Cryptographic snapshot restored successfully.');
        fetchFimData();
        fetchTelemetry();
      }
    } catch (err) {
      console.error('FIM rollback error:', err);
    }
  };

  // Calculations for Summary
  const criticalThreats = telemetryEvents.filter(e => e.severity === 'CRITICAL').length;
  const activeQuarantined = fimAlerts.filter(a => a.status === 'DETECTED' || a.status === 'ALERTED').length;

  return (
    <div className="space-y-4 text-slate-200 font-sans" dir={isAr ? 'rtl' : 'ltr'}>
      
      {/* ========================================================================= */}
      {/* 1. MILITARY-GRADE LIVE TICKER BAR & SYSTEM CONTROLS                        */}
      {/* ========================================================================= */}
      <div className="bg-slate-950/90 border border-cyan-500/30 rounded-xl p-3.5 shadow-2xl backdrop-blur-md">
        <div className="flex flex-wrap items-center justify-between gap-4">
          
          {/* Status & Identity */}
          <div className="flex items-center gap-3">
            <div className="p-2 bg-cyan-950/60 border border-cyan-400/40 rounded-lg text-cyan-400 shadow-md shadow-cyan-950/50">
              <ShieldAlert className="w-5 h-5 animate-pulse text-cyan-300" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-xs font-black uppercase tracking-widest text-cyan-400">
                  {isAr ? 'منظومة الدفاع السيبراني v5.5 نخبة' : 'SOVEREIGN SOC COMMAND v5.5 ELITE'}
                </span>
                <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-950/70 text-emerald-300 border border-emerald-500/40 flex items-center gap-1">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-ping" />
                  DEFCON 2 // ARMORED
                </span>
              </div>
              <p className="text-[11px] text-slate-400 font-mono">
                {isAr ? 'مركز عمليات الأمن الأزرق، الأدلة الجنائية، والتحكم بالتهديدات' : 'Blue Team Operations, Digital Forensics & Threat Ingress Defense'}
              </p>
            </div>
          </div>

          {/* Live Telemetry Ticker Readouts */}
          <div className="flex items-center gap-3 overflow-x-auto py-1">
            <div className="px-2.5 py-1 rounded-lg bg-slate-900/80 border border-slate-800 flex items-center gap-2">
              <Activity className="w-3.5 h-3.5 text-cyan-400" />
              <div className="text-left font-mono">
                <span className="text-[9px] block text-slate-400 leading-none">THROUGHPUT</span>
                <span className="text-xs font-bold text-cyan-300">{tickerThroughput} Mbps</span>
              </div>
            </div>

            <div className="px-2.5 py-1 rounded-lg bg-slate-900/80 border border-slate-800 flex items-center gap-2">
              <Zap className="w-3.5 h-3.5 text-amber-400" />
              <div className="text-left font-mono">
                <span className="text-[9px] block text-slate-400 leading-none">eBPF FILTER</span>
                <span className="text-xs font-bold text-amber-300">{tickerLatencyUs} µs</span>
              </div>
            </div>

            <div className="px-2.5 py-1 rounded-lg bg-slate-900/80 border border-slate-800 flex items-center gap-2">
              <FileCheck className="w-3.5 h-3.5 text-emerald-400" />
              <div className="text-left font-mono">
                <span className="text-[9px] block text-slate-400 leading-none">FIM INTEGRITY</span>
                <span className="text-xs font-bold text-emerald-300">{fimFiles.length} Monitored</span>
              </div>
            </div>

            <div className="px-2.5 py-1 rounded-lg bg-slate-900/80 border border-slate-800 flex items-center gap-2">
              <Flame className="w-3.5 h-3.5 text-rose-400" />
              <div className="text-left font-mono">
                <span className="text-[9px] block text-slate-400 leading-none">ACTIVE THREATS</span>
                <span className="text-xs font-bold text-rose-400">{criticalThreats + activeQuarantined} Intercepted</span>
              </div>
            </div>
          </div>

          {/* Persistent Tactical Action Bar */}
          <div className="flex items-center gap-2 flex-wrap">
            {/* 1. Emergency Zero-Trust Lockdown Button */}
            <button
              onClick={handleToggleLockdown}
              disabled={isLockdownLoading}
              className={`px-3 py-1.5 rounded-lg text-xs font-black transition flex items-center gap-1.5 shadow-lg ${
                isLockdownActive
                  ? 'bg-rose-600 hover:bg-rose-500 text-white border border-rose-400 animate-pulse shadow-rose-900/60'
                  : 'bg-slate-900 hover:bg-rose-950/60 text-rose-300 border border-rose-500/40 hover:border-rose-400'
              }`}
            >
              {isLockdownActive ? <Lock className="w-3.5 h-3.5 text-white" /> : <Unlock className="w-3.5 h-3.5 text-rose-400" />}
              <span>
                {isLockdownActive
                  ? (isAr ? '🚨 إغلاق شامل (ZERO-TRUST)' : '🚨 ZERO-TRUST ACTIVE')
                  : (isAr ? 'إغلاق شامل للطوارئ' : 'EMERGENCY LOCKDOWN')}
              </span>
            </button>

            {/* 2. Manual IP Quarantine */}
            <button
              onClick={() => setIsQuarantineModalOpen(true)}
              className="px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-rose-900/50 text-rose-300 border border-rose-500/40 hover:border-rose-400 text-xs font-bold font-mono transition flex items-center gap-1.5 shadow-md"
            >
              <Ban className="w-3.5 h-3.5 text-rose-400" />
              <span>{isAr ? 'حظر IP يدوي' : 'Quarantine IP'}</span>
            </button>

            {/* 3. Target Scanner Audit */}
            <button
              onClick={() => setIsScannerModalOpen(true)}
              className="px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-cyan-900/50 text-cyan-300 border border-cyan-500/40 hover:border-cyan-400 text-xs font-bold font-mono transition flex items-center gap-1.5 shadow-md"
            >
              <Search className="w-3.5 h-3.5 text-cyan-400" />
              <span>{isAr ? 'فاحص الأهداف' : 'Target Audit'}</span>
            </button>

            {/* 4. Export Incident Forensic Report */}
            <button
              onClick={() => setIsReportModalOpen(true)}
              className="px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-purple-900/50 text-purple-300 border border-purple-500/40 hover:border-purple-400 text-xs font-bold font-mono transition flex items-center gap-1.5 shadow-md"
            >
              <FileDown className="w-3.5 h-3.5 text-purple-400" />
              <span>{isAr ? 'تصدير تقرير جنائي' : 'Export Forensic Audit'}</span>
            </button>
          </div>

        </div>
      </div>

      {/* ========================================================================= */}
      {/* 2. HIGH-DENSITY 10-PILLAR NAVIGATION TABS (v6.0 SOC SUITE)                */}
      {/* ========================================================================= */}
      <div className="flex items-center gap-1.5 overflow-x-auto pb-1 border-b border-slate-800">
        
        {/* Phase 1 Upgrade: Interactive Topology Map */}
        <button
          onClick={() => setSubTab('topology_map')}
          className={`px-3 py-1.5 rounded-t-lg text-xs font-bold transition whitespace-nowrap flex items-center gap-1.5 ${
            subTab === 'topology_map'
              ? 'bg-cyan-950/90 text-cyan-200 border-t-2 border-cyan-400 border-x border-slate-800 shadow-md'
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/50'
          }`}
        >
          <Radio className="w-3.5 h-3.5 text-cyan-400 animate-pulse" />
          <span>{isAr ? 'خريطة طبولوجيا الشبكة (D3)' : '1. Network Topology (D3)'}</span>
          <span className="px-1.5 py-0.2 rounded text-[10px] font-mono bg-cyan-900/40 text-cyan-300">Phase 1</span>
        </button>

        {/* Phase 3 Upgrade: Dynamic Zero-Trust Insider Prevention */}
        <button
          onClick={() => setSubTab('insider_zero_trust')}
          className={`px-3 py-1.5 rounded-t-lg text-xs font-bold transition whitespace-nowrap flex items-center gap-1.5 ${
            subTab === 'insider_zero_trust'
              ? 'bg-rose-950/90 text-rose-200 border-t-2 border-rose-400 border-x border-slate-800 shadow-md'
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/50'
          }`}
        >
          <Lock className="w-3.5 h-3.5 text-rose-400 animate-pulse" />
          <span>{isAr ? 'منع التهديدات الداخلية (Zero-Trust OTP)' : '3. Insider Zero-Trust (OTP)'}</span>
          <span className="px-1.5 py-0.2 rounded text-[10px] font-mono bg-rose-900/40 text-rose-300">Phase 3</span>
        </button>

        {/* Phase 2 Upgrade: SOAR Report Automation */}
        <button
          onClick={() => setSubTab('soar_reports')}
          className={`px-3 py-1.5 rounded-t-lg text-xs font-bold transition whitespace-nowrap flex items-center gap-1.5 ${
            subTab === 'soar_reports'
              ? 'bg-indigo-950/90 text-indigo-200 border-t-2 border-indigo-400 border-x border-slate-800 shadow-md'
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/50'
          }`}
        >
          <FileCheck className="w-3.5 h-3.5 text-indigo-400" />
          <span>{isAr ? 'أتمتة تقارير SOAR' : '2. SOAR Reports & Dispatch'}</span>
          <span className="px-1.5 py-0.2 rounded text-[10px] font-mono bg-indigo-900/40 text-indigo-300">Phase 2</span>
        </button>

        {/* Phase 4 Upgrade: Omnichannel Sanitizer & CDR */}
        <button
          onClick={() => setSubTab('omnichannel_sanitizer')}
          className={`px-3 py-1.5 rounded-t-lg text-xs font-bold transition whitespace-nowrap flex items-center gap-1.5 ${
            subTab === 'omnichannel_sanitizer'
              ? 'bg-emerald-950/90 text-emerald-200 border-t-2 border-emerald-400 border-x border-slate-800 shadow-md'
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/50'
          }`}
        >
          <Mail className="w-3.5 h-3.5 text-emerald-400" />
          <span>{isAr ? 'تطهير البريد والبيانات (CDR)' : '4. Omnichannel CDR Sanitizer'}</span>
          <span className="px-1.5 py-0.2 rounded text-[10px] font-mono bg-emerald-900/40 text-emerald-300">Phase 4</span>
        </button>

        {/* Master Pillar: Sovereign Cyber Defense Matrix (Phases 1 - 5) */}
        <button
          onClick={() => setSubTab('sovereign_phases')}
          className={`px-3 py-1.5 rounded-t-lg text-xs font-mono font-bold transition whitespace-nowrap flex items-center gap-1.5 ${
            subTab === 'sovereign_phases'
              ? 'bg-[#181818] text-[#e6edf3] border-t-2 border-[#3fb950] border-x border-[#1e2733]'
              : 'text-[#93a1b3] hover:text-[#e6edf3] hover:bg-[#141414] bg-[#0D0D0D] border-t border-x border-[#1e2733]'
          }`}
        >
          <ShieldAlert className={`w-3.5 h-3.5 ${subTab === 'sovereign_phases' ? 'text-[#3fb950]' : 'text-[#93a1b3]'}`} />
          <span>{isAr ? 'المصفوفة السيادية (1 - 5)' : 'Sovereign Matrix (Phases 1 - 5)'}</span>
          <span className="px-1.5 py-0.2 rounded text-[10px] font-mono bg-[#1e2733] text-[#93a1b3]">MoD</span>
        </button>

        {/* Pillar 1: Web Traffic & WAF */}
        <button
          onClick={() => setSubTab('traffic_waf')}
          className={`px-3 py-1.5 rounded-t-lg text-xs font-mono font-bold transition whitespace-nowrap flex items-center gap-1.5 ${
            subTab === 'traffic_waf'
              ? 'bg-[#181818] text-[#e6edf3] border-t-2 border-[#3fb950] border-x border-[#1e2733]'
              : 'text-[#93a1b3] hover:text-[#e6edf3] hover:bg-[#141414] bg-[#0D0D0D] border-t border-x border-[#1e2733]'
          }`}
        >
          <Activity className={`w-3.5 h-3.5 ${subTab === 'traffic_waf' ? 'text-[#3fb950]' : 'text-[#93a1b3]'}`} />
          <span>{isAr ? '1. حركة المرور و WAF' : '1. Live Traffic & WAF'}</span>
          <span className="px-1.5 py-0.2 rounded text-[10px] font-mono bg-[#1e2733] text-[#93a1b3]">LIVE</span>
        </button>

        {/* Pillar: Autonomous Containment Telemetry (eBPF Kernel) */}
        <button
          onClick={() => setSubTab('ebpf_containment')}
          className={`px-3 py-1.5 rounded-t-lg text-xs font-mono font-bold transition whitespace-nowrap flex items-center gap-1.5 ${
            subTab === 'ebpf_containment'
              ? 'bg-[#181818] text-[#e6edf3] border-t-2 border-[#3fb950] border-x border-[#1e2733]'
              : 'text-[#93a1b3] hover:text-[#e6edf3] hover:bg-[#141414] bg-[#0D0D0D] border-t border-x border-[#1e2733]'
          }`}
        >
          <Zap className={`w-3.5 h-3.5 ${subTab === 'ebpf_containment' ? 'text-[#3fb950]' : 'text-[#93a1b3]'}`} />
          <span>{isAr ? 'عزل النواة (eBPF)' : 'eBPF Containment'}</span>
          <span className="px-1.5 py-0.2 rounded text-[10px] font-mono bg-[#1e2733] text-[#93a1b3]">Zero-Trust</span>
        </button>

        {/* Pillar 2: Attack Chain & Honeytoken Deception */}
        <button
          onClick={() => setSubTab('deception_sandbox')}
          className={`px-3 py-1.5 rounded-t-lg text-xs font-mono font-bold transition whitespace-nowrap flex items-center gap-1.5 ${
            subTab === 'deception_sandbox'
              ? 'bg-[#181818] text-[#e6edf3] border-t-2 border-[#3fb950] border-x border-[#1e2733]'
              : 'text-[#93a1b3] hover:text-[#e6edf3] hover:bg-[#141414] bg-[#0D0D0D] border-t border-x border-[#1e2733]'
          }`}
        >
          <Flame className={`w-3.5 h-3.5 ${subTab === 'deception_sandbox' ? 'text-[#3fb950]' : 'text-[#93a1b3]'}`} />
          <span>{isAr ? '2. سلسلة الهجوم والخداع' : '2. Attack Graph & Deception'}</span>
          <span className="px-1.5 py-0.2 rounded text-[10px] font-mono bg-[#1e2733] text-[#93a1b3]">AUTO</span>
        </button>

        {/* Pillar 3: FIM & Process Forensics */}
        <button
          onClick={() => setSubTab('fim')}
          className={`px-3 py-1.5 rounded-t-lg text-xs font-mono font-bold transition whitespace-nowrap flex items-center gap-1.5 ${
            subTab === 'fim'
              ? 'bg-[#181818] text-[#e6edf3] border-t-2 border-[#3fb950] border-x border-[#1e2733]'
              : 'text-[#93a1b3] hover:text-[#e6edf3] hover:bg-[#141414] bg-[#0D0D0D] border-t border-x border-[#1e2733]'
          }`}
        >
          <FileCheck className={`w-3.5 h-3.5 ${subTab === 'fim' ? 'text-[#3fb950]' : 'text-[#93a1b3]'}`} />
          <span>{isAr ? '3. تكامل الملفات والعمليات' : '3. File Integrity & Processes'}</span>
          {activeQuarantined > 0 && (
            <span className="px-1.5 py-0.2 rounded text-[10px] font-mono bg-[#2A0E12] text-[#f85149] border border-[#f85149]/30">{activeQuarantined}</span>
          )}
        </button>

        {/* Pillar: Active In-Line Interception & DLP */}
        <button
          onClick={() => setSubTab('interception')}
          className={`px-3 py-1.5 rounded-t-lg text-xs font-mono font-bold transition whitespace-nowrap flex items-center gap-1.5 ${
            subTab === 'interception'
              ? 'bg-[#181818] text-[#e6edf3] border-t-2 border-[#DC143C] border-x border-[#1e2733]'
              : 'text-[#93a1b3] hover:text-[#e6edf3] hover:bg-[#141414] bg-[#0D0D0D] border-t border-x border-[#1e2733]'
          }`}
        >
          <ShieldOff className={`w-3.5 h-3.5 ${subTab === 'interception' ? 'text-[#DC143C]' : 'text-[#93a1b3]'}`} />
          <span>{isAr ? 'الاعتراض النشط ومنع التسريب' : 'Active Interception & DLP'}</span>
          <span className="px-1.5 py-0.2 rounded text-[10px] font-mono bg-[#2A0D14] text-[#FF5C7A]">LIVE</span>
        </button>

        {/* Pillar: Adaptive Deception Grid & Shadow Routing */}
        <button
          onClick={() => setSubTab('deception_grid')}
          className={`px-3 py-1.5 rounded-t-lg text-xs font-mono font-bold transition whitespace-nowrap flex items-center gap-1.5 ${
            subTab === 'deception_grid'
              ? 'bg-[#181818] text-[#e6edf3] border-t-2 border-[#8A2BE2] border-x border-[#1e2733]'
              : 'text-[#93a1b3] hover:text-[#e6edf3] hover:bg-[#141414] bg-[#0D0D0D] border-t border-x border-[#1e2733]'
          }`}
        >
          <Drama className={`w-3.5 h-3.5 ${subTab === 'deception_grid' ? 'text-[#8A2BE2]' : 'text-[#93a1b3]'}`} />
          <span>{isAr ? 'شبكة الخداع التكيفية' : 'Adaptive Deception Grid'}</span>
          <span className="px-1.5 py-0.2 rounded text-[10px] font-mono bg-[#1A0D2A] text-[#C89BFF]">TRAP</span>
        </button>

        {/* Pillar 4: Telemetry Stream */}
        <button
          onClick={() => setSubTab('telemetry')}
          className={`px-3 py-1.5 rounded-t-lg text-xs font-mono font-bold transition whitespace-nowrap flex items-center gap-1.5 ${
            subTab === 'telemetry'
              ? 'bg-[#181818] text-[#e6edf3] border-t-2 border-[#3fb950] border-x border-[#1e2733]'
              : 'text-[#93a1b3] hover:text-[#e6edf3] hover:bg-[#141414] bg-[#0D0D0D] border-t border-x border-[#1e2733]'
          }`}
        >
          <Radio className={`w-3.5 h-3.5 ${subTab === 'telemetry' ? 'text-[#3fb950]' : 'text-[#93a1b3]'}`} />
          <span>{isAr ? '4. سجلات MITRE والتتبع' : '4. Telemetry & MITRE'}</span>
          <span className="px-1.5 py-0.2 rounded text-[10px] font-mono bg-[#1e2733] text-[#93a1b3]">{telemetryEvents.length}</span>
        </button>

        {/* Pillar: Threat Incident Timeline (D3.js) */}
        <button
          onClick={() => setSubTab('threat_timeline')}
          className={`px-3 py-1.5 rounded-t-lg text-xs font-mono font-bold transition whitespace-nowrap flex items-center gap-1.5 ${
            subTab === 'threat_timeline'
              ? 'bg-[#181818] text-[#e6edf3] border-t-2 border-[#3fb950] border-x border-[#1e2733]'
              : 'text-[#93a1b3] hover:text-[#e6edf3] hover:bg-[#141414] bg-[#0D0D0D] border-t border-x border-[#1e2733]'
          }`}
        >
          <Clock className={`w-3.5 h-3.5 ${subTab === 'threat_timeline' ? 'text-[#3fb950]' : 'text-[#93a1b3]'}`} />
          <span>{isAr ? 'المخطط الزمني (D3)' : 'Threat Timeline (D3)'}</span>
          <span className="px-1.5 py-0.2 rounded text-[10px] font-mono bg-[#1e2733] text-[#93a1b3]">D3</span>
        </button>

        {/* Pillar 5: Target Scanner */}
        <button
          onClick={() => setSubTab('scanner')}
          className={`px-3 py-1.5 rounded-t-lg text-xs font-mono font-bold transition whitespace-nowrap flex items-center gap-1.5 ${
            subTab === 'scanner'
              ? 'bg-[#181818] text-[#e6edf3] border-t-2 border-[#3fb950] border-x border-[#1e2733]'
              : 'text-[#93a1b3] hover:text-[#e6edf3] hover:bg-[#141414] bg-[#0D0D0D] border-t border-x border-[#1e2733]'
          }`}
        >
          <Crosshair className={`w-3.5 h-3.5 ${subTab === 'scanner' ? 'text-[#3fb950]' : 'text-[#93a1b3]'}`} />
          <span>{isAr ? 'ماسح الأهداف والثغرات' : '5. Target Scanner'}</span>
        </button>

        {/* Pillar 6: Memory & Process Forensics */}
        <button
          onClick={() => setSubTab('processes')}
          className={`px-3 py-1.5 rounded-t-lg text-xs font-mono font-bold transition whitespace-nowrap flex items-center gap-1.5 ${
            subTab === 'processes'
              ? 'bg-[#181818] text-[#e6edf3] border-t-2 border-[#3fb950] border-x border-[#1e2733]'
              : 'text-[#93a1b3] hover:text-[#e6edf3] hover:bg-[#141414] bg-[#0D0D0D] border-t border-x border-[#1e2733]'
          }`}
        >
          <Cpu className={`w-3.5 h-3.5 ${subTab === 'processes' ? 'text-[#3fb950]' : 'text-[#93a1b3]'}`} />
          <span>{isAr ? 'معالجات الذاكرة' : '6. Processes'}</span>
          <span className="px-1.5 py-0.2 rounded text-[10px] font-mono bg-[#1e2733] text-[#93a1b3]">{processes.length}</span>
        </button>

        {/* Pillar 7: YARA & Sigma Rules */}
        <button
          onClick={() => setSubTab('rules_engine')}
          className={`px-3 py-1.5 rounded-t-lg text-xs font-mono font-bold transition whitespace-nowrap flex items-center gap-1.5 ${
            subTab === 'rules_engine'
              ? 'bg-[#181818] text-[#e6edf3] border-t-2 border-[#3fb950] border-x border-[#1e2733]'
              : 'text-[#93a1b3] hover:text-[#e6edf3] hover:bg-[#141414] bg-[#0D0D0D] border-t border-x border-[#1e2733]'
          }`}
        >
          <FileCode className={`w-3.5 h-3.5 ${subTab === 'rules_engine' ? 'text-[#3fb950]' : 'text-[#93a1b3]'}`} />
          <span>{isAr ? 'قواعد YARA و Sigma' : '7. YARA & Sigma'}</span>
        </button>

        {/* Pillar 8: Network & PCAP Inspector */}
        <button
          onClick={() => setSubTab('network_pcap')}
          className={`px-3 py-1.5 rounded-t-lg text-xs font-mono font-bold transition whitespace-nowrap flex items-center gap-1.5 ${
            subTab === 'network_pcap'
              ? 'bg-[#181818] text-[#e6edf3] border-t-2 border-[#3fb950] border-x border-[#1e2733]'
              : 'text-[#93a1b3] hover:text-[#e6edf3] hover:bg-[#141414] bg-[#0D0D0D] border-t border-x border-[#1e2733]'
          }`}
        >
          <Wifi className={`w-3.5 h-3.5 ${subTab === 'network_pcap' ? 'text-[#3fb950]' : 'text-[#93a1b3]'}`} />
          <span>{isAr ? 'حزم PCAP' : '8. PCAP Inspector'}</span>
        </button>

        {/* Pillar 9: Threat Intel & IOC Lookup */}
        <button
          onClick={() => setSubTab('threat_intel')}
          className={`px-3 py-1.5 rounded-t-lg text-xs font-mono font-bold transition whitespace-nowrap flex items-center gap-1.5 ${
            subTab === 'threat_intel'
              ? 'bg-[#181818] text-[#e6edf3] border-t-2 border-[#3fb950] border-x border-[#1e2733]'
              : 'text-[#93a1b3] hover:text-[#e6edf3] hover:bg-[#141414] bg-[#0D0D0D] border-t border-x border-[#1e2733]'
          }`}
        >
          <Globe className={`w-3.5 h-3.5 ${subTab === 'threat_intel' ? 'text-[#3fb950]' : 'text-[#93a1b3]'}`} />
          <span>{isAr ? 'استخبارات IOC' : '9. Threat Intel'}</span>
          <span className="px-1.5 py-0.2 rounded text-[10px] font-mono bg-[#1e2733] text-[#93a1b3]">{iocList.length}</span>
        </button>

        {/* Pillar 10: Incident Playbooks & Audit Reports */}
        <button
          onClick={() => setSubTab('playbooks_reports')}
          className={`px-3 py-1.5 rounded-t-lg text-xs font-mono font-bold transition whitespace-nowrap flex items-center gap-1.5 ${
            subTab === 'playbooks_reports'
              ? 'bg-[#181818] text-[#e6edf3] border-t-2 border-[#3fb950] border-x border-[#1e2733]'
              : 'text-[#93a1b3] hover:text-[#e6edf3] hover:bg-[#141414] bg-[#0D0D0D] border-t border-x border-[#1e2733]'
          }`}
        >
          <FileText className={`w-3.5 h-3.5 ${subTab === 'playbooks_reports' ? 'text-[#3fb950]' : 'text-[#93a1b3]'}`} />
          <span>{isAr ? 'التقارير' : '10. Reports'}</span>
        </button>

      </div>

      {/* ========================================================================= */}
      {/* PHASE 1 UPGRADE: INTERACTIVE D3 NETWORK TOPOLOGY MAP & MINIMALIST UX       */}
      {/* ========================================================================= */}
      {subTab === 'topology_map' && (
        <InteractiveNetworkTopologyMap lang={lang} />
      )}

      {/* ========================================================================= */}
      {/* PHASE 3 UPGRADE: DYNAMIC ZERO-TRUST INSIDER THREAT & TEAM LEAD OTP         */}
      {/* ========================================================================= */}
      {subTab === 'insider_zero_trust' && (
        <InsiderZeroTrustPanel lang={lang} />
      )}

      {/* ========================================================================= */}
      {/* PHASE 2 UPGRADE: FULL SOAR REPORT AUTOMATION & AUTONOMOUS DISPATCH         */}
      {/* ========================================================================= */}
      {subTab === 'soar_reports' && (
        <SoarReportAutomationPanel lang={lang} />
      )}

      {/* ========================================================================= */}
      {/* PHASE 4 UPGRADE: OMNICHANNEL CDR EMAIL & LATERAL STREAM SANITIZER          */}
      {/* ========================================================================= */}
      {subTab === 'omnichannel_sanitizer' && (
        <OmnichannelSanitizerPanel lang={lang} />
      )}

      {/* ========================================================================= */}
      {/* MASTER FLAGSHIP: SOVEREIGN CYBER DEFENSE MATRIX (PHASES 1 - 5)             */}
      {/* ========================================================================= */}
      {subTab === 'sovereign_phases' && (
        <SovereignPhasesMasterConsole lang={lang} />
      )}

      {/* ========================================================================= */}
      {/* TAB 1: WEB TRAFFIC & WAF TELEMETRY (v6.0)                                  */}
      {/* ========================================================================= */}
      {subTab === 'traffic_waf' && (
        <WebTrafficWafPanel lang={lang} onRefreshTelemetry={fetchTelemetry} />
      )}

      {/* ========================================================================= */}
      {/* TAB: AUTONOMOUS eBPF KERNEL CONTAINMENT TELEMETRY                           */}
      {/* ========================================================================= */}
      {subTab === 'ebpf_containment' && (
        <AutonomousContainmentTelemetry lang={lang} />
      )}

      {/* ========================================================================= */}
      {/* TAB 2: DECEPTION, ATTACK GRAPH & HONEYTOKEN TRAPS (v6.0)                   */}
      {/* ========================================================================= */}
      {subTab === 'deception_sandbox' && (
        <AttackChainDeceptionPanel lang={lang} />
      )}

      {/* ========================================================================= */}
      {/* TAB 4: CRYPTOGRAPHIC FILE INTEGRITY & PROCESS FORENSICS (v6.0)             */}
      {/* ========================================================================= */}
      {subTab === 'fim' && (
        <FileIntegrityProcessPanel lang={lang} />
      )}

      {/* ========================================================================= */}
      {/* TAB: ACTIVE IN-LINE INTERCEPTION & DATA LOSS PREVENTION                    */}
      {/* ========================================================================= */}
      {subTab === 'interception' && (
        <InterceptionMatrixPanel lang={lang} />
      )}

      {/* ========================================================================= */}
      {/* TAB: ADAPTIVE DECEPTION GRID, SHADOW ROUTING & INTENT PROFILING            */}
      {/* ========================================================================= */}
      {subTab === 'deception_grid' && (
        <DeceptionGridPanel lang={lang} />
      )}

      {/* ========================================================================= */}
      {/* TAB: THREAT INCIDENT TIMELINE (D3.js VERTICAL ENGINE)                      */}
      {/* ========================================================================= */}
      {subTab === 'threat_timeline' && (
        <ThreatIncidentTimeline lang={lang} />
      )}

      {/* ========================================================================= */}
      {/* TAB 1: UNIFIED SOC TELEMETRY & MITRE ATT&CK MATRIX (SPLIT SCREEN VIEW)      */}
      {/* ========================================================================= */}
      {subTab === 'telemetry' && (
        <div className="space-y-4">
          
          {/* Filter Bar */}
          <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-3 flex flex-wrap items-center justify-between gap-3">
            <div className="flex flex-wrap items-center gap-2">
              <div className="relative">
                <Search className="w-3.5 h-3.5 text-slate-400 absolute top-2.5 left-2.5" />
                <input
                  type="text"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  placeholder={isAr ? 'بحث في السجلات والـ IPs...' : 'Search logs, tactics, IPs...'}
                  className="pl-8 pr-3 py-1 bg-slate-950 border border-slate-700 rounded-lg text-xs text-slate-200 w-52 focus:border-cyan-400 outline-none"
                />
              </div>

              <select
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value)}
                className="bg-slate-950 border border-slate-700 rounded-lg px-2.5 py-1 text-xs text-slate-300 outline-none"
              >
                <option value="ALL">Severity: ALL</option>
                <option value="CRITICAL">CRITICAL</option>
                <option value="HIGH">HIGH</option>
                <option value="MEDIUM">MEDIUM</option>
                <option value="LOW">LOW</option>
              </select>

              <select
                value={sourceFilter}
                onChange={(e) => setSourceFilter(e.target.value)}
                className="bg-slate-950 border border-slate-700 rounded-lg px-2.5 py-1 text-xs text-slate-300 outline-none"
              >
                <option value="ALL">Source: ALL</option>
                <option value="WAF_EBPF">WAF / eBPF Kernel</option>
                <option value="FIM">File Integrity (FIM)</option>
                <option value="AI_DEFENSE">AI Defense Guardrails</option>
                <option value="SYSTEM_LOCKDOWN">System Lockdown</option>
              </select>
            </div>

            <div className="flex items-center gap-2">
              <button
                onClick={() => setSubTab('threat_timeline')}
                className="px-2.5 py-1 bg-rose-950/70 hover:bg-rose-900/80 text-rose-300 border border-rose-500/40 rounded-lg text-xs font-mono flex items-center gap-1.5 transition"
              >
                <Clock className="w-3.5 h-3.5 text-rose-400" />
                <span>{isAr ? 'المخطط الزمني (D3)' : 'D3 Threat Timeline'}</span>
              </button>

              <button
                onClick={fetchTelemetry}
                disabled={isLoadingTelemetry}
                className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 rounded-lg text-xs font-mono flex items-center gap-1.5 transition"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${isLoadingTelemetry ? 'animate-spin' : ''}`} />
                <span>{isAr ? 'تحديث' : 'Refresh'}</span>
              </button>
            </div>
          </div>

          {/* Split Screen Telemetry View */}
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
            
            {/* Left Column: Live Event Stream (7 Cols) */}
            <div className="lg:col-span-7 bg-slate-950 border border-slate-800 rounded-xl p-3 space-y-2 max-h-[580px] overflow-y-auto font-mono text-xs">
              <div className="text-[11px] font-bold text-slate-400 uppercase tracking-wider flex items-center justify-between pb-1 border-b border-slate-800">
                <span>{isAr ? 'سجل الأحداث الأمنية الموحد' : 'Unified Security Event Ingress'}</span>
                <span>{telemetryEvents.length} Events Logged</span>
              </div>

              {telemetryEvents.length === 0 ? (
                <div className="text-center py-12 text-slate-500">
                  <Activity className="w-8 h-8 mx-auto mb-2 opacity-40 animate-pulse" />
                  <p>{isAr ? 'لا توجد سجلات تطابق الفلتر الحالي' : 'No telemetry events matching current criteria.'}</p>
                </div>
              ) : (
                telemetryEvents.map((evt) => {
                  const isSelected = selectedTelemetryEvent?.id === evt.id;
                  const sevColor =
                    evt.severity === 'CRITICAL' ? 'border-rose-500/80 bg-rose-950/30 text-rose-300' :
                    evt.severity === 'HIGH' ? 'border-amber-500/60 bg-amber-950/20 text-amber-300' :
                    evt.severity === 'MEDIUM' ? 'border-cyan-500/50 bg-cyan-950/20 text-cyan-300' :
                    'border-slate-700 bg-slate-900/40 text-slate-300';

                  return (
                    <div
                      key={evt.uuid || `telemetry-evt-${evt.id}-${evt.timestamp}`}
                      onClick={() => setSelectedTelemetryEvent(evt)}
                      className={`p-2.5 rounded-lg border transition cursor-pointer ${sevColor} ${
                        isSelected ? 'ring-2 ring-cyan-400 bg-slate-900/90' : 'hover:bg-slate-900/60'
                      }`}
                    >
                      <div className="flex items-center justify-between gap-2">
                        <div className="flex items-center gap-2">
                          <span className={`px-1.5 py-0.2 rounded text-[10px] font-bold uppercase ${
                            evt.severity === 'CRITICAL' ? 'bg-rose-900 text-rose-200' :
                            evt.severity === 'HIGH' ? 'bg-amber-900 text-amber-200' :
                            'bg-slate-800 text-slate-300'
                          }`}>
                            {evt.severity}
                          </span>
                          <span className="text-[10px] text-slate-400">{evt.source}</span>
                          {evt.actorIp && (
                            <span className="text-[10px] text-cyan-400 font-bold bg-cyan-950/80 px-1 rounded">{evt.actorIp}</span>
                          )}
                        </div>
                        <span className="text-[10px] text-slate-500">{new Date(evt.timestamp).toLocaleTimeString()}</span>
                      </div>

                      <div className="font-bold text-xs mt-1 text-slate-100">
                        {isAr && evt.titleAr ? evt.titleAr : evt.title}
                      </div>

                      <div className="text-[11px] text-slate-400 line-clamp-1 mt-0.5">
                        {isAr && evt.detailsAr ? evt.detailsAr : evt.details}
                      </div>

                      <div className="flex items-center justify-between text-[10px] text-slate-500 mt-1.5 pt-1 border-t border-slate-800/80">
                        <span>MITRE: {evt.mitreTechnique || evt.mitreTactic || 'N/A'}</span>
                        <span className="text-emerald-400 font-bold">{isAr && evt.actionTakenAr ? evt.actionTakenAr : evt.actionTaken}</span>
                      </div>
                    </div>
                  );
                })
              )}
            </div>

            {/* Right Column: Deep Forensic Packet & Tactic Inspector (5 Cols) */}
            <div className="lg:col-span-5 bg-slate-950 border border-slate-800 rounded-xl p-4 space-y-4">
              <div className="flex items-center justify-between pb-2 border-b border-slate-800">
                <div className="flex items-center gap-2">
                  <Terminal className="w-4 h-4 text-cyan-400" />
                  <h4 className="text-xs font-bold text-cyan-300 uppercase tracking-wider">
                    {isAr ? 'فاحص الأدلة وتفاصيل التهديد' : 'Deep Threat & Payload Inspector'}
                  </h4>
                </div>
                {selectedTelemetryEvent && (
                  <span className="text-[10px] font-mono text-slate-400">{selectedTelemetryEvent.id}</span>
                )}
              </div>

              {selectedTelemetryEvent ? (
                <div className="space-y-3 text-xs font-mono">
                  <div className="bg-slate-900/90 border border-slate-800 rounded-lg p-3 space-y-2">
                    <div className="flex justify-between">
                      <span className="text-slate-400">Timestamp:</span>
                      <span className="text-slate-200">{selectedTelemetryEvent.timestamp}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-400">Source:</span>
                      <span className="text-cyan-300 font-bold">{selectedTelemetryEvent.source}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-400">Attacker IP:</span>
                      <span className="text-rose-400 font-bold">{selectedTelemetryEvent.actorIp || 'Internal Bus'}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-400">MITRE Tactic:</span>
                      <span className="text-amber-300">{selectedTelemetryEvent.mitreTactic || 'Defense Evasion'}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-400">MITRE Technique:</span>
                      <span className="text-amber-300">{selectedTelemetryEvent.mitreTechnique || 'T1059'}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-400">Enforced Action:</span>
                      <span className="text-emerald-400 font-bold">{selectedTelemetryEvent.actionTaken}</span>
                    </div>
                  </div>

                  <div className="space-y-1">
                    <span className="text-[11px] font-bold text-slate-400 uppercase">Analysis Summary:</span>
                    <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800 text-slate-200 leading-relaxed font-sans text-xs">
                      {isAr && selectedTelemetryEvent.detailsAr ? selectedTelemetryEvent.detailsAr : selectedTelemetryEvent.details}
                    </div>
                  </div>

                  {selectedTelemetryEvent.actorIp && (
                    <div className="pt-2 border-t border-slate-800 flex items-center gap-2">
                      <button
                        onClick={() => {
                          setIocQueryInput(selectedTelemetryEvent.actorIp!);
                          setSubTab('threat_intel');
                        }}
                        className="px-3 py-1.5 bg-rose-950/60 hover:bg-rose-900 border border-rose-500/50 rounded-lg text-rose-200 text-xs font-bold transition flex items-center gap-1.5"
                      >
                        <Globe className="w-3.5 h-3.5" />
                        <span>Query IP in Threat Intel</span>
                      </button>
                    </div>
                  )}
                </div>
              ) : (
                <div className="text-center py-16 text-slate-500 text-xs">
                  <Eye className="w-8 h-8 mx-auto mb-2 opacity-30" />
                  <p>{isAr ? 'حدد أي حدث من القائمة اليسرى لمعاينته' : 'Select any telemetry record on the left to inspect raw payloads and forensic details.'}</p>
                </div>
              )}
            </div>

          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* TAB 2: CRYPTOGRAPHIC FILE INTEGRITY MONITORING (FIM)                       */}
      {/* ========================================================================= */}
      {subTab === 'fim' && (
        <div className="space-y-4">
          <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 flex flex-wrap items-center justify-between gap-3">
            <div>
              <h3 className="text-sm font-bold text-emerald-400 flex items-center gap-2">
                <FileCheck className="w-4 h-4" />
                <span>{isAr ? 'مراقبة سلامة وتكامل الملفات (FIM Realtime Watcher)' : 'Cryptographic File Integrity Monitoring (FIM)'}</span>
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">
                {isAr ? 'مطابقة البصمات التشفيرية SHA-256 للملفات الحيوية لمنع حقن الشيل وتشفير برمجيات الفدية.' : 'Continuous SHA-256 baseline hashing against critical server paths to detect unauthorized tampering.'}
              </p>
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <button
                onClick={() => handleSimulateFimTamper('WEBSHELL')}
                className="px-3 py-1.5 bg-rose-950/70 hover:bg-rose-900 border border-rose-500/50 rounded-lg text-rose-300 text-xs font-bold transition flex items-center gap-1.5"
              >
                <Zap className="w-3.5 h-3.5" />
                <span>{isAr ? 'حقن تجربة WebShell' : 'Simulate WebShell Tamper'}</span>
              </button>

              <button
                onClick={() => handleSimulateFimTamper('RANSOMWARE')}
                className="px-3 py-1.5 bg-amber-950/70 hover:bg-amber-900 border border-amber-500/50 rounded-lg text-amber-300 text-xs font-bold transition flex items-center gap-1.5"
              >
                <Lock className="w-3.5 h-3.5" />
                <span>{isAr ? 'حقن تجربة Ransomware' : 'Simulate Ransomware Encrypt'}</span>
              </button>

              <button
                onClick={fetchFimData}
                className="px-2.5 py-1.5 bg-slate-800 hover:bg-slate-700 rounded-lg text-xs font-mono"
              >
                <RefreshCw className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>

          {fimActionMessage && (
            <div className="p-2.5 rounded-lg bg-emerald-950/60 border border-emerald-500/50 text-emerald-300 text-xs flex items-center justify-between">
              <span>{fimActionMessage}</span>
              <button onClick={() => setFimActionMessage(null)} className="text-slate-400 hover:text-white">&times;</button>
            </div>
          )}

          {/* FIM Alerts & Files Grid */}
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
            
            {/* Active FIM Alerts (7 Cols) */}
            <div className="lg:col-span-7 bg-slate-950 border border-slate-800 rounded-xl p-3 space-y-3">
              <div className="text-xs font-bold text-slate-300 uppercase tracking-wider pb-1 border-b border-slate-800 flex justify-between">
                <span>{isAr ? 'تنبيهات التلاعب المكتشفة' : 'Tamper Detections & Quarantined Files'}</span>
                <span className="text-rose-400">{fimAlerts.length} Alerts</span>
              </div>

              {fimAlerts.length === 0 ? (
                <div className="text-center py-12 text-slate-500 text-xs">
                  <FileCheck className="w-8 h-8 mx-auto mb-2 opacity-30" />
                  <p>{isAr ? 'كافة الملفات المراقبة سليمة ومطابقة للبصمة الأصلية' : 'All monitored file baselines are intact and verified.'}</p>
                </div>
              ) : (
                fimAlerts.map((alt) => (
                  <div key={alt.id} className="p-3 bg-slate-900/90 border border-rose-500/40 rounded-lg space-y-2">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span className="px-1.5 py-0.2 rounded text-[10px] font-bold bg-rose-900 text-rose-200">{alt.severity}</span>
                        <span className="font-mono text-xs font-bold text-slate-100">{alt.fileName}</span>
                      </div>
                      <span className="text-[10px] text-slate-400">{alt.changeType}</span>
                    </div>

                    <div className="text-[11px] text-slate-300">
                      {isAr && alt.analysisAr ? alt.analysisAr : alt.analysisEn}
                    </div>

                    <div className="font-mono text-[10px] text-slate-400 bg-slate-950 p-1.5 rounded truncate">
                      Hash: {alt.currentHash}
                    </div>

                    <div className="flex items-center justify-between pt-1 border-t border-slate-800">
                      <span className="text-[10px] text-amber-400">Status: {alt.status}</span>
                      <div className="flex items-center gap-2">
                        <button
                          onClick={() => handleFimRollback(alt.id)}
                          className="px-2 py-1 bg-emerald-950 hover:bg-emerald-900 border border-emerald-500/50 rounded text-emerald-200 text-[11px] font-bold flex items-center gap-1"
                        >
                          <RotateCcw className="w-3 h-3" />
                          <span>{isAr ? 'استرجاع النسخة السليمة' : 'Restore Baseline'}</span>
                        </button>
                      </div>
                    </div>
                  </div>
                ))
              )}
            </div>

            {/* Monitored File Directory (5 Cols) */}
            <div className="lg:col-span-5 bg-slate-950 border border-slate-800 rounded-xl p-3 space-y-2 max-h-[500px] overflow-y-auto">
              <div className="text-xs font-bold text-slate-300 uppercase tracking-wider pb-1 border-b border-slate-800">
                {isAr ? 'دليل الملفات المراقبة تشفيرياً' : 'Cryptographically Monitored Inventory'}
              </div>

              {fimFiles.map((file) => (
                <div key={`fim-file-${file.relativePath}`} className="p-2 bg-slate-900/60 border border-slate-800/80 rounded-lg text-xs font-mono flex items-center justify-between">
                  <div className="truncate mr-2">
                    <span className="text-slate-200 block truncate">{file.fileName}</span>
                    <span className="text-[10px] text-slate-500 truncate block">{file.relativePath}</span>
                  </div>
                  <span className={`px-1.5 py-0.2 rounded text-[10px] font-bold ${
                    file.isModified ? 'bg-rose-900 text-rose-200' : 'bg-emerald-950 text-emerald-300'
                  }`}>
                    {file.isModified ? 'MODIFIED' : 'INTACT'}
                  </span>
                </div>
              ))}
            </div>

          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* TAB 3: TARGET SECURITY SCANNER & MITIGATION TEMPLATES                     */}
      {/* ========================================================================= */}
      {subTab === 'scanner' && (
        <div className="space-y-4">
          <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 space-y-3">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <h3 className="text-sm font-bold text-amber-400 flex items-center gap-2">
                  <Crosshair className="w-4 h-4" />
                  <span>{isAr ? 'ماسح الأهداف وفحص الثغرات الحية' : 'Tactical Target Security & Posture Scanner'}</span>
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  {isAr ? 'فحص ترويسات الأمان، إعدادات TLS/HSTS، وشهادات الأمان مع توليد قوالب معالجة فورية.' : 'Audit HTTP Security Headers, TLS posture, and active misconfigurations with 1-click remediation scripts.'}
                </p>
              </div>

              <div className="flex items-center gap-2">
                <input
                  type="text"
                  value={targetUrlInput}
                  onChange={(e) => setTargetUrlInput(e.target.value)}
                  placeholder="https://your-domain.com"
                  className="px-3 py-1.5 bg-slate-950 border border-slate-700 rounded-lg text-xs text-slate-200 w-64 focus:border-amber-400 outline-none font-mono"
                />
                <button
                  onClick={handleRunScan}
                  disabled={isScanning}
                  className="px-3.5 py-1.5 bg-amber-600 hover:bg-amber-500 text-slate-950 font-bold rounded-lg text-xs transition flex items-center gap-1.5"
                >
                  <Play className={`w-3.5 h-3.5 ${isScanning ? 'animate-spin' : ''}`} />
                  <span>{isScanning ? (isAr ? 'جاري الفحص...' : 'Auditing...') : (isAr ? 'بدء الفحص' : 'Audit Target')}</span>
                </button>
              </div>
            </div>
          </div>

          {currentScanReport && (
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
              {/* Score & Executive Summary (4 Cols) */}
              <div className="lg:col-span-4 bg-slate-950 border border-slate-800 rounded-xl p-4 space-y-4">
                <div className="flex items-center justify-between pb-2 border-b border-slate-800">
                  <span className="text-xs text-slate-400 font-mono">TARGET AUDIT</span>
                  <span className="text-xs font-mono text-cyan-400">{currentScanReport.normalizedHost}</span>
                </div>

                <div className="text-center py-4 bg-slate-900/60 rounded-xl border border-slate-800">
                  <div className="text-4xl font-black font-mono text-amber-400">{currentScanReport.overallScore}/100</div>
                  <div className="text-xs font-bold text-slate-300 mt-1">GRADE: {currentScanReport.grade}</div>
                </div>

                <div className="space-y-1">
                  <span className="text-[11px] font-bold text-slate-400 uppercase">Executive Assessment:</span>
                  <p className="text-xs text-slate-300 leading-relaxed font-sans bg-slate-900/40 p-2.5 rounded-lg border border-slate-800/80">
                    {isAr && currentScanReport.executiveSummaryAr ? currentScanReport.executiveSummaryAr : currentScanReport.executiveSummaryEn}
                  </p>
                </div>
              </div>

              {/* Headers Audit & Remediation (8 Cols) */}
              <div className="lg:col-span-8 bg-slate-950 border border-slate-800 rounded-xl p-4 space-y-3">
                <div className="text-xs font-bold text-slate-300 uppercase tracking-wider pb-1 border-b border-slate-800">
                  {isAr ? 'تدقيق ترويسات الأمان والتوصيات' : 'HTTP Security Headers Compliance Matrix'}
                </div>

                <div className="space-y-2 max-h-[420px] overflow-y-auto">
                  {currentScanReport.headersAudit.map((h) => (
                    <div key={`header-${h.header || h.name}`} className="p-2.5 rounded-lg bg-slate-900 border border-slate-800 space-y-1 text-xs font-mono">
                      <div className="flex items-center justify-between">
                        <span className="font-bold text-slate-200">{h.header || h.name}</span>
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          h.status === 'PASS' ? 'bg-emerald-950 text-emerald-300 border border-emerald-500/40' :
                          h.status === 'FAIL' ? 'bg-rose-950 text-rose-300 border border-rose-500/40' :
                          'bg-amber-950 text-amber-300 border border-amber-500/40'
                        }`}>
                          {h.status}
                        </span>
                      </div>
                      <p className="text-[11px] text-slate-400 font-sans">{h.recommendation}</p>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* ========================================================================= */}
      {/* TAB 4: MEMORY & PROCESS FORENSICS INSPECTOR (NEW V5.5)                     */}
      {/* ========================================================================= */}
      {subTab === 'processes' && (
        <div className="space-y-4">
          <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 flex flex-wrap items-center justify-between gap-3">
            <div>
              <h3 className="text-sm font-bold text-purple-400 flex items-center gap-2">
                <Cpu className="w-4 h-4" />
                <span>{isAr ? 'فاحص معالجات الذاكرة وحقن المكتبات (Process & Memory Forensics)' : 'Live Process Tree, Memory & Hook Injection Inspector'}</span>
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">
                {isAr ? 'رصد العمليات النشطة، اكتشاف حقن DLL والـ Hooks غير المصرحة، تفريغ صفحات الذاكرة وفحص البصمات بالذكاء الاصطناعي.' : 'Inspect running process trees, detect dynamic ptrace hooks and memory injections, dump memory pages, and scan binary hashes.'}
              </p>
            </div>

            <button
              onClick={fetchProcesses}
              className="px-2.5 py-1.5 bg-slate-800 hover:bg-slate-700 rounded-lg text-xs font-mono flex items-center gap-1"
            >
              <RefreshCw className="w-3.5 h-3.5" />
              <span>Refresh Procs</span>
            </button>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
            
            {/* Process Table (7 Cols) */}
            <div className="lg:col-span-7 bg-slate-950 border border-slate-800 rounded-xl p-3 space-y-2 max-h-[580px] overflow-y-auto font-mono text-xs">
              <div className="text-xs font-bold text-slate-300 uppercase tracking-wider pb-1 border-b border-slate-800 flex justify-between">
                <span>{isAr ? 'شجرة العمليات النشطة' : 'Live System Process Hierarchy'}</span>
                <span>{processes.length} Processes</span>
              </div>

              {processes.map((proc) => {
                const isSelected = selectedProcess?.pid === proc.pid;
                const statusColor =
                  proc.status === 'INJECTED' ? 'border-rose-500/70 bg-rose-950/30' :
                  proc.status === 'SUSPICIOUS' ? 'border-amber-500/60 bg-amber-950/20' :
                  proc.status === 'TERMINATED' ? 'border-slate-800 bg-slate-950 opacity-50' :
                  'border-slate-800 bg-slate-900/40';

                return (
                  <div
                    key={proc.pid}
                    onClick={() => {
                      setSelectedProcess(proc);
                      setMemoryDumpData(null);
                      setHashScanResult(null);
                    }}
                    className={`p-2.5 rounded-lg border cursor-pointer transition ${statusColor} ${
                      isSelected ? 'ring-2 ring-purple-400 bg-slate-900/90' : 'hover:bg-slate-900/60'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span className="font-bold text-purple-300">PID: {proc.pid}</span>
                        <span className="text-slate-400 text-[10px]">PPID: {proc.ppid}</span>
                        <span className="text-slate-200 font-bold">{proc.name}</span>
                      </div>
                      <span className={`px-1.5 py-0.2 rounded text-[10px] font-bold ${
                        proc.status === 'INJECTED' ? 'bg-rose-900 text-rose-200 animate-pulse' :
                        proc.status === 'SUSPICIOUS' ? 'bg-amber-900 text-amber-200' :
                        proc.status === 'TERMINATED' ? 'bg-slate-800 text-slate-400' :
                        'bg-emerald-950 text-emerald-300'
                      }`}>
                        {proc.status}
                      </span>
                    </div>

                    <div className="text-[11px] text-slate-400 truncate mt-1">
                      User: {proc.user} | CPU: {proc.cpuPercent}% | RAM: {proc.memoryMb}MB
                    </div>

                    <div className="text-[10px] text-slate-500 font-mono truncate mt-0.5 bg-slate-950/80 p-1 rounded">
                      CMD: {proc.command}
                    </div>

                    {proc.injectionEvidence && (
                      <div className="mt-1.5 text-[10px] text-rose-300 bg-rose-950/40 p-1.5 rounded border border-rose-500/30 flex items-center gap-1.5">
                        <AlertTriangle className="w-3 h-3 text-rose-400 shrink-0" />
                        <span>{proc.injectionEvidence}</span>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>

            {/* Deep Process Controls & Memory Dump (5 Cols) */}
            <div className="lg:col-span-5 bg-slate-950 border border-slate-800 rounded-xl p-4 space-y-4">
              {selectedProcess ? (
                <div className="space-y-3 font-mono text-xs">
                  <div className="flex items-center justify-between pb-2 border-b border-slate-800">
                    <h4 className="font-bold text-purple-300">PROCESS FORENSICS // PID {selectedProcess.pid}</h4>
                    <span className="text-slate-400 text-[10px]">{selectedProcess.name}</span>
                  </div>

                  <div className="bg-slate-900/90 border border-slate-800 rounded-lg p-3 space-y-1.5 text-[11px]">
                    <div className="flex justify-between">
                      <span className="text-slate-400">Binary Hash:</span>
                      <span className="text-slate-300 truncate max-w-[200px]">{selectedProcess.sha256}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-400">Loaded Modules:</span>
                      <span className="text-cyan-300">{selectedProcess.loadedModules.length} Modules</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-400">Threat Score:</span>
                      <span className="text-rose-400 font-bold">{selectedProcess.threatScore}/100</span>
                    </div>
                  </div>

                  {/* Actions */}
                  <div className="grid grid-cols-2 gap-2 pt-2">
                    <button
                      onClick={() => handleDumpMemory(selectedProcess.pid)}
                      className="px-3 py-1.5 bg-purple-950/60 hover:bg-purple-900 border border-purple-500/40 rounded-lg text-purple-200 text-xs font-bold transition flex items-center justify-center gap-1.5"
                    >
                      <HardDrive className="w-3.5 h-3.5" />
                      <span>Dump Memory</span>
                    </button>

                    <button
                      onClick={() => handleScanHash(selectedProcess.sha256, selectedProcess.name)}
                      disabled={isHashScanning}
                      className="px-3 py-1.5 bg-cyan-950/60 hover:bg-cyan-900 border border-cyan-500/40 rounded-lg text-cyan-200 text-xs font-bold transition flex items-center justify-center gap-1.5"
                    >
                      <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
                      <span>{isHashScanning ? 'Scanning...' : 'Scan via AI'}</span>
                    </button>
                  </div>

                  {selectedProcess.status !== 'TERMINATED' && (
                    <button
                      onClick={() => handleKillProcess(selectedProcess.pid)}
                      className="w-full px-3 py-2 bg-rose-600 hover:bg-rose-500 text-white font-bold rounded-lg text-xs transition flex items-center justify-center gap-2 shadow-lg shadow-rose-950/50"
                    >
                      <Ban className="w-4 h-4" />
                      <span>{isAr ? 'إنهاء العملية فوراً (SIGKILL)' : 'Terminate Process (Kill PID)'}</span>
                    </button>
                  )}

                  {/* Memory Dump Output */}
                  {memoryDumpData && (
                    <div className="space-y-2 pt-2 border-t border-slate-800">
                      <span className="text-[11px] font-bold text-purple-300 uppercase">Memory Hex Inspection:</span>
                      <pre className="p-2.5 rounded-lg bg-slate-900 border border-slate-800 text-[10px] text-emerald-400 overflow-x-auto max-h-40 leading-snug">
                        {memoryDumpData.hexSnippet}
                      </pre>
                      <div className="text-[10px] text-slate-400">
                        Strings Extracted: {memoryDumpData.stringsExtracted.join(', ')}
                      </div>
                    </div>
                  )}

                  {/* Hash Scan AI Intelligence Output */}
                  {hashScanResult && (
                    <div className="p-3 bg-slate-900/90 border border-cyan-500/40 rounded-lg space-y-2 text-xs">
                      <div className="flex items-center justify-between">
                        <span className="font-bold text-cyan-300">VirusTotal / Gemini Attribution</span>
                        <span className="text-rose-400 font-bold">{hashScanResult.detectionsRatio}</span>
                      </div>
                      <p className="text-[11px] text-slate-300 font-sans">
                        {isAr && hashScanResult.behaviorSummaryAr ? hashScanResult.behaviorSummaryAr : hashScanResult.behaviorSummaryEn}
                      </p>
                      <div className="flex flex-wrap gap-1">
                        {hashScanResult.sandboxTags?.map((tag: string) => (
                          <span key={`sandbox-tag-${tag}`} className="px-1.5 py-0.2 rounded text-[9px] bg-slate-800 text-cyan-300">{tag}</span>
                        ))}
                      </div>
                    </div>
                  )}

                </div>
              ) : (
                <div className="text-center py-20 text-slate-500 text-xs">
                  <Cpu className="w-8 h-8 mx-auto mb-2 opacity-30" />
                  <p>{isAr ? 'اختر عملية من القائمة اليسرى لتشريح صفحات الذاكرة' : 'Select a process from the hierarchy to inspect memory segments and execute forensic termination.'}</p>
                </div>
              )}
            </div>

          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* TAB 5: YARA & SIGMA DETECTION RULES ENGINE (NEW V5.5)                      */}
      {/* ========================================================================= */}
      {subTab === 'rules_engine' && (
        <div className="space-y-4">
          <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 flex flex-wrap items-center justify-between gap-3">
            <div>
              <h3 className="text-sm font-bold text-pink-400 flex items-center gap-2">
                <FileCode className="w-4 h-4" />
                <span>{isAr ? 'محرك ومحرر قواعد YARA و Sigma للكشف المتقدم' : 'Live YARA & Sigma Rule Engineering Engine'}</span>
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">
                {isAr ? 'إنشاء وتعديل قواعد بصمات الملفات (YARA) وقواعد ارتباط سجلات الأمان (Sigma) واختبارها فورياً ضد الحمولات المشبوهة.' : 'Author and test live YARA binary signature patterns and Sigma SIEM correlation queries against live memory & payloads.'}
              </p>
            </div>

            <div className="flex items-center gap-2">
              <button
                onClick={() => setActiveRuleType('YARA')}
                className={`px-3 py-1 rounded-lg text-xs font-bold transition ${
                  activeRuleType === 'YARA' ? 'bg-pink-600 text-white' : 'bg-slate-800 text-slate-300'
                }`}
              >
                YARA Rules ({yaraRules.length})
              </button>
              <button
                onClick={() => setActiveRuleType('SIGMA')}
                className={`px-3 py-1 rounded-lg text-xs font-bold transition ${
                  activeRuleType === 'SIGMA' ? 'bg-pink-600 text-white' : 'bg-slate-800 text-slate-300'
                }`}
              >
                Sigma Rules ({sigmaRules.length})
              </button>
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
            
            {/* Rule List (4 Cols) */}
            <div className="lg:col-span-4 bg-slate-950 border border-slate-800 rounded-xl p-3 space-y-2 max-h-[580px] overflow-y-auto font-mono text-xs">
              <div className="text-xs font-bold text-slate-300 uppercase tracking-wider pb-1 border-b border-slate-800">
                {activeRuleType === 'YARA' ? 'YARA Signature Catalog' : 'Sigma Log Correlation Catalog'}
              </div>

              {activeRuleType === 'YARA' ? (
                yaraRules.map((r) => (
                  <div
                    key={r.id}
                    onClick={() => {
                      setSelectedYaraRule(r);
                      setRuleEditorCode(r.rawRule);
                      setRuleTestResult(null);
                    }}
                    className={`p-2.5 rounded-lg border cursor-pointer transition ${
                      selectedYaraRule?.id === r.id ? 'border-pink-500 bg-pink-950/40 text-pink-200' : 'border-slate-800 bg-slate-900/40 hover:bg-slate-900/80 text-slate-300'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-bold text-slate-100 truncate">{r.name}</span>
                      <span className="text-[10px] text-pink-400 font-bold">{r.severity}</span>
                    </div>
                    <p className="text-[11px] text-slate-400 line-clamp-2 mt-1 font-sans">{r.description}</p>
                    <div className="flex items-center justify-between text-[10px] text-slate-500 mt-1.5">
                      <span>Matches: {r.matchesCount}</span>
                      <span>Tags: {r.tags.slice(0, 2).join(', ')}</span>
                    </div>
                  </div>
                ))
              ) : (
                sigmaRules.map((s) => (
                  <div
                    key={s.id}
                    onClick={() => {
                      setRuleEditorCode(s.rawYaml);
                      setRuleTestResult(null);
                    }}
                    className="p-2.5 rounded-lg border border-slate-800 bg-slate-900/40 hover:bg-slate-900/80 cursor-pointer space-y-1 text-slate-300"
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-bold text-slate-100 truncate">{s.title}</span>
                      <span className="text-[10px] text-amber-400 font-bold">{s.level}</span>
                    </div>
                    <p className="text-[11px] text-slate-400 line-clamp-2 font-sans">{s.description}</p>
                  </div>
                ))
              )}
            </div>

            {/* Code Editor & Realtime Matcher (8 Cols) */}
            <div className="lg:col-span-8 bg-slate-950 border border-slate-800 rounded-xl p-4 space-y-4">
              <div className="flex items-center justify-between pb-2 border-b border-slate-800">
                <div className="flex items-center gap-2">
                  <Code className="w-4 h-4 text-pink-400" />
                  <span className="text-xs font-bold text-pink-300 uppercase">Live Rule Code Editor</span>
                </div>
                <button
                  onClick={handleTestYaraRule}
                  disabled={isTestingRule}
                  className="px-3 py-1 bg-pink-600 hover:bg-pink-500 text-white font-bold rounded-lg text-xs transition flex items-center gap-1.5"
                >
                  <Play className="w-3.5 h-3.5" />
                  <span>{isTestingRule ? 'Testing...' : 'Test Rule vs Payload'}</span>
                </button>
              </div>

              {/* Editor TextArea */}
              <textarea
                value={ruleEditorCode}
                onChange={(e) => setRuleEditorCode(e.target.value)}
                rows={10}
                className="w-full p-3 bg-slate-900 border border-slate-800 rounded-lg text-xs font-mono text-pink-200 outline-none focus:border-pink-500 leading-relaxed resize-none"
              />

              {/* Test Payload Input & Output */}
              <div className="space-y-2">
                <span className="text-xs font-bold text-slate-400 uppercase">Test Payload / Sample String Buffer:</span>
                <textarea
                  value={ruleTestPayload}
                  onChange={(e) => setRuleTestPayload(e.target.value)}
                  rows={3}
                  className="w-full p-2.5 bg-slate-900 border border-slate-800 rounded-lg text-xs font-mono text-slate-200 outline-none focus:border-cyan-400 resize-none"
                />
              </div>

              {ruleTestResult && (
                <div className={`p-3 rounded-lg border text-xs font-mono ${
                  ruleTestResult.matched ? 'bg-rose-950/60 border-rose-500 text-rose-200' : 'bg-emerald-950/60 border-emerald-500 text-emerald-200'
                }`}>
                  <div className="flex items-center justify-between font-bold">
                    <span>{ruleTestResult.matched ? '🚨 RULE MATCH CONFIRMED (POSITIVE)' : '✅ NO MATCH (CLEAN SAMPLE)'}</span>
                    <span>Latency: {ruleTestResult.executionTimeMs}ms</span>
                  </div>
                  <p className="mt-1 font-sans text-[11px]">
                    {isAr && ruleTestResult.matchDetailsAr ? ruleTestResult.matchDetailsAr : ruleTestResult.matchDetailsEn}
                  </p>
                  {ruleTestResult.matchedStrings?.length > 0 && (
                    <div className="mt-1 text-[10px] text-amber-300">
                      Matched Patterns: {ruleTestResult.matchedStrings.join(' , ')}
                    </div>
                  )}
                </div>
              )}
            </div>

          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* TAB 6: ACTIVE NETWORK CONNECTIONS & PCAP PACKET INSPECTOR (NEW V5.5)       */}
      {/* ========================================================================= */}
      {subTab === 'network_pcap' && (
        <div className="space-y-4">
          <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 flex flex-wrap items-center justify-between gap-3">
            <div>
              <h3 className="text-sm font-bold text-blue-400 flex items-center gap-2">
                <Wifi className="w-4 h-4" />
                <span>{isAr ? 'المقابس الشبكية النشطة وفاحص حزم PCAP الثنائي (Hex / ASCII)' : 'Active Network Sockets & Deep Packet Inspection (DPI)'}</span>
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">
                {isAr ? 'مراقبة الاتصالات الخارجية المشبوهة، إسقاط الجلسات عبر TCP RST، ومعاينة تدفق البايتات الخام بدقة الميكروثانية.' : 'Monitor TCP/UDP sockets, terminate adversarial C2 sessions via TCP RST injection, and inspect raw packet hex dumps.'}
              </p>
            </div>

            <button
              onClick={fetchSocketsAndPcap}
              className="px-2.5 py-1.5 bg-slate-800 hover:bg-slate-700 rounded-lg text-xs font-mono flex items-center gap-1"
            >
              <RefreshCw className="w-3.5 h-3.5" />
              <span>Refresh Sockets</span>
            </button>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
            
            {/* Active Sockets Table (6 Cols) */}
            <div className="lg:col-span-6 bg-slate-950 border border-slate-800 rounded-xl p-3 space-y-2 max-h-[580px] overflow-y-auto font-mono text-xs">
              <div className="text-xs font-bold text-slate-300 uppercase tracking-wider pb-1 border-b border-slate-800 flex justify-between">
                <span>Active Sockets</span>
                <span>{sockets.length} Connections</span>
              </div>

              {sockets.map((sock) => {
                const isC2 = sock.threatFlag === 'MALICIOUS_C2';
                return (
                  <div
                    key={sock.id}
                    className={`p-2.5 rounded-lg border space-y-1.5 ${
                      isC2 ? 'border-rose-500/80 bg-rose-950/30' : 'border-slate-800 bg-slate-900/40'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-bold text-slate-100">{sock.localAddress} &rarr; {sock.remoteAddress}</span>
                      <span className={`px-1.5 py-0.2 rounded text-[10px] font-bold ${
                        isC2 ? 'bg-rose-900 text-rose-200 animate-pulse' : 'bg-slate-800 text-slate-300'
                      }`}>
                        {sock.state}
                      </span>
                    </div>

                    <div className="flex items-center justify-between text-[11px] text-slate-400">
                      <span>Process: {sock.processName} (PID {sock.pid})</span>
                      <span>{sock.protocol} | Tx: {(sock.bytesSent / 1024).toFixed(1)}KB</span>
                    </div>

                    {sock.geoCountry && (
                      <div className="text-[10px] text-amber-300">
                        Geo: {sock.geoCountry} - {sock.geoCity} ({sock.asn})
                      </div>
                    )}

                    {isC2 && sock.state !== 'CLOSE_WAIT' && (
                      <div className="pt-1 flex justify-end">
                        <button
                          onClick={() => handleResetSocket(sock.id)}
                          className="px-2 py-1 bg-rose-600 hover:bg-rose-500 text-white font-bold rounded text-[10px] flex items-center gap-1"
                        >
                          <Ban className="w-3 h-3" />
                          <span>Reset TCP Socket</span>
                        </button>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>

            {/* PCAP Packet Stream & Hex Dump (6 Cols) */}
            <div className="lg:col-span-6 bg-slate-950 border border-slate-800 rounded-xl p-3 space-y-3 font-mono text-xs">
              <div className="text-xs font-bold text-slate-300 uppercase tracking-wider pb-1 border-b border-slate-800 flex justify-between">
                <span>Live PCAP Packet Frames</span>
                <span>{pcapPackets.length} Frames</span>
              </div>

              <div className="space-y-2 max-h-48 overflow-y-auto">
                {pcapPackets.map((pkt) => (
                  <div
                    key={pkt.uuid || `pcap-${pkt.id}-${pkt.frameNo}`}
                    onClick={() => setSelectedPacket(pkt)}
                    className={`p-2 rounded border cursor-pointer text-[11px] ${
                      selectedPacket?.id === pkt.id ? 'border-blue-400 bg-blue-950/40 text-blue-200' : 'border-slate-800 bg-slate-900/40 text-slate-300 hover:bg-slate-900'
                    }`}
                  >
                    <div className="flex justify-between font-bold">
                      <span>Frame #{pkt.frameNo} [{pkt.protocol}]</span>
                      <span className="text-slate-400">{pkt.srcIp}:{pkt.srcPort} &rarr; {pkt.dstIp}:{pkt.dstPort}</span>
                    </div>
                    <div className="text-[10px] text-slate-400 truncate mt-0.5">{pkt.info}</div>
                  </div>
                ))}
              </div>

              {selectedPacket && (
                <div className="space-y-2 pt-2 border-t border-slate-800">
                  <div className="flex justify-between text-[11px] text-slate-300">
                    <span className="font-bold text-blue-300">Raw Frame #{selectedPacket.frameNo} Hex Dissection:</span>
                    <span>{selectedPacket.lengthBytes} Bytes</span>
                  </div>
                  <pre className="p-2.5 rounded-lg bg-slate-900 border border-slate-800 text-[10px] text-cyan-300 overflow-x-auto leading-snug max-h-48">
                    {selectedPacket.hexDump}
                  </pre>
                  <div className="text-[10px] text-slate-400 bg-slate-900/80 p-2 rounded truncate">
                    ASCII: {selectedPacket.asciiDump}
                  </div>
                </div>
              )}
            </div>

          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* TAB 7: THREAT INTELLIGENCE & IOC LOOKUP (NEW V5.5)                         */}
      {/* ========================================================================= */}
      {subTab === 'threat_intel' && (
        <div className="space-y-4">
          <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 space-y-3">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <h3 className="text-sm font-bold text-rose-400 flex items-center gap-2">
                  <Globe className="w-4 h-4" />
                  <span>{isAr ? 'استخبارات التهديدات والبحث الجنائي عن المؤشرات (IOCs)' : 'Threat Intelligence Feeds & Deep IOC Attribution Query'}</span>
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  {isAr ? 'الاستعلام عن عناوين IP، البصمات التشفيرية، والنطاقات الخبيثة وربطها بمجموعات التهديد المتقدمة (APT).' : 'Query suspicious IPs, SHA-256 binary hashes, or C2 domains against Gemini Threat Intelligence for instant risk scoring.'}
                </p>
              </div>

              <div className="flex items-center gap-2">
                <input
                  type="text"
                  value={iocQueryInput}
                  onChange={(e) => setIocQueryInput(e.target.value)}
                  placeholder="IP, SHA-256, or Domain..."
                  className="px-3 py-1.5 bg-slate-950 border border-slate-700 rounded-lg text-xs text-slate-200 w-64 focus:border-rose-400 outline-none font-mono"
                />
                <button
                  onClick={handleQueryIoc}
                  disabled={isQueryingIoc}
                  className="px-3.5 py-1.5 bg-rose-600 hover:bg-rose-500 text-white font-bold rounded-lg text-xs transition flex items-center gap-1.5"
                >
                  <Sparkles className="w-3.5 h-3.5" />
                  <span>{isQueryingIoc ? 'Querying AI...' : 'Query Intel'}</span>
                </button>
              </div>
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
            
            {/* Active IOC Database (6 Cols) */}
            <div className="lg:col-span-6 bg-slate-950 border border-slate-800 rounded-xl p-3 space-y-2 max-h-[580px] overflow-y-auto font-mono text-xs">
              <div className="text-xs font-bold text-slate-300 uppercase tracking-wider pb-1 border-b border-slate-800 flex justify-between">
                <span>Active Threat IOC Feeds</span>
                <span>{iocList.length} Indicators</span>
              </div>

              {iocList.map((ioc) => (
                <div
                  key={ioc.id}
                  onClick={() => {
                    setIocQueryInput(ioc.value);
                    handleQueryIoc();
                  }}
                  className="p-2.5 rounded-lg border border-slate-800 bg-slate-900/40 hover:bg-slate-900/80 cursor-pointer space-y-1.5"
                >
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-rose-300 truncate">{ioc.value}</span>
                    <span className="px-1.5 py-0.2 rounded text-[10px] font-bold bg-rose-900 text-rose-200">{ioc.type}</span>
                  </div>
                  <div className="text-[11px] text-slate-300 font-sans font-bold">
                    Attribution: {ioc.threatActor} ({ioc.malwareFamily})
                  </div>
                  <p className="text-[10px] text-slate-400 font-sans">
                    {isAr && ioc.descriptionAr ? ioc.descriptionAr : ioc.description}
                  </p>
                </div>
              ))}
            </div>

            {/* AI Threat Intel Dossier (6 Cols) */}
            <div className="lg:col-span-6 bg-slate-950 border border-slate-800 rounded-xl p-4 space-y-3 font-mono text-xs">
              <div className="text-xs font-bold text-rose-300 uppercase tracking-wider pb-1 border-b border-slate-800">
                Threat Intelligence Dossier
              </div>

              {iocQueryResult ? (
                <div className="space-y-3">
                  <div className="p-3 rounded-lg bg-slate-900 border border-rose-500/40 space-y-2">
                    <div className="flex justify-between">
                      <span className="text-slate-400">Indicator:</span>
                      <span className="text-slate-100 font-bold">{iocQueryResult.query}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-400">Threat Actor:</span>
                      <span className="text-rose-400 font-bold">{iocQueryResult.threatActor}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-400">Malware Family:</span>
                      <span className="text-amber-300">{iocQueryResult.malwareFamily}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-400">Threat Score:</span>
                      <span className="text-rose-400 font-black">{iocQueryResult.threatScore}/100 ({iocQueryResult.threatLevel})</span>
                    </div>
                  </div>

                  <div className="space-y-1 font-sans">
                    <span className="text-[11px] font-bold text-slate-400 uppercase">AI Threat Rationale:</span>
                    <p className="p-2.5 rounded-lg bg-slate-900 border border-slate-800 text-slate-200 text-xs leading-relaxed">
                      {isAr && iocQueryResult.aiRationaleAr ? iocQueryResult.aiRationaleAr : iocQueryResult.aiRationaleEn}
                    </p>
                  </div>

                  <div className="space-y-1">
                    <span className="text-[11px] font-bold text-slate-400 uppercase">Recommended Firewall & eBPF Rules:</span>
                    <pre className="p-2.5 rounded-lg bg-slate-900 border border-slate-800 text-[10px] text-emerald-400 overflow-x-auto leading-snug">
                      {iocQueryResult.recommendedRules?.join('\n')}
                    </pre>
                  </div>
                </div>
              ) : (
                <div className="text-center py-20 text-slate-500">
                  <Globe className="w-8 h-8 mx-auto mb-2 opacity-30" />
                  <p>{isAr ? 'أدخل أي عنوان IP أو بصمة للاستعلام عن استخبارات التهديد' : 'Enter an IP or hash to query threat intelligence attribution.'}</p>
                </div>
              )}
            </div>

          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* TAB 8: INCIDENT RESPONSE PLAYBOOKS & AUDIT REPORTS (NEW V5.5)              */}
      {/* ========================================================================= */}
      {subTab === 'playbooks_reports' && (
        <div className="space-y-4">
          <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 flex flex-wrap items-center justify-between gap-3">
            <div>
              <h3 className="text-sm font-bold text-indigo-400 flex items-center gap-2">
                <FileText className="w-4 h-4" />
                <span>{isAr ? 'خطط الاستجابة التلقائية للحوادث وتوليد التقارير الجنائية' : 'Automated Incident Response Playbooks & Compliance Reports'}</span>
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">
                {isAr ? 'تنفيذ خطط الاحتواء المتتالية خطوة بخطوة وتصدير تقارير الامتثال المعتمدة (ISO 27035 / NIST SP 800-61).' : 'Execute step-by-step containment workflows and generate ISO 27035 / NIST-compliant forensic reports.'}
              </p>
            </div>

            <button
              onClick={handleGenerateReport}
              disabled={isGeneratingReport}
              className="px-3.5 py-1.5 bg-indigo-600 hover:bg-indigo-500 text-white font-bold rounded-lg text-xs transition flex items-center gap-1.5"
            >
              <Download className="w-3.5 h-3.5" />
              <span>{isGeneratingReport ? 'Compiling Report...' : 'Generate Forensic Report'}</span>
            </button>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
            
            {/* Playbooks List & Execution Engine (7 Cols) */}
            <div className="lg:col-span-7 bg-slate-950 border border-slate-800 rounded-xl p-4 space-y-4">
              <div className="text-xs font-bold text-slate-300 uppercase tracking-wider pb-1 border-b border-slate-800">
                Active Incident Response Playbooks
              </div>

              {playbooks.map((pb) => (
                <div key={pb.id} className="p-3 bg-slate-900/90 border border-indigo-500/40 rounded-xl space-y-3">
                  <div className="flex items-center justify-between">
                    <div>
                      <h4 className="text-xs font-bold text-indigo-300">{isAr ? pb.nameAr : pb.name}</h4>
                      <p className="text-[11px] text-slate-400 mt-0.5 font-sans">{isAr ? pb.descriptionAr : pb.description}</p>
                    </div>
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                      pb.status === 'CONTAINED' ? 'bg-emerald-950 text-emerald-300 border border-emerald-500/40' : 'bg-amber-950 text-amber-300 border border-amber-500/40'
                    }`}>
                      {pb.status}
                    </span>
                  </div>

                  {/* Playbook Steps */}
                  <div className="space-y-2 font-mono text-xs">
                    {pb.steps.map((step) => (
                      <div key={step.id} className="p-2 rounded bg-slate-950 border border-slate-800 flex items-center justify-between gap-2">
                        <div className="flex items-center gap-2 truncate">
                          <span className="text-indigo-400 font-bold">#{step.order}</span>
                          <span className="text-slate-200 truncate">{isAr ? step.titleAr : step.title}</span>
                        </div>

                        <div className="flex items-center gap-2 shrink-0">
                          <span className={`text-[10px] ${step.status === 'COMPLETED' ? 'text-emerald-400 font-bold' : 'text-slate-500'}`}>
                            {step.status}
                          </span>
                          {step.status !== 'COMPLETED' && (
                            <button
                              onClick={() => handleExecutePlaybookStep(pb.id, step.id)}
                              disabled={isPlaybookExecuting}
                              className="px-2 py-0.5 bg-indigo-950 hover:bg-indigo-900 border border-indigo-500/40 rounded text-[10px] text-indigo-200 font-bold"
                            >
                              Run Step
                            </button>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>

                  {pb.status !== 'CONTAINED' && (
                    <div className="pt-2 flex justify-end">
                      <button
                        onClick={() => handleExecuteEntirePlaybook(pb.id)}
                        disabled={isPlaybookExecuting}
                        className="px-3 py-1.5 bg-emerald-600 hover:bg-emerald-500 text-white font-bold rounded-lg text-xs transition flex items-center gap-1.5 shadow-md"
                      >
                        <Play className="w-3.5 h-3.5" />
                        <span>{isAr ? 'تنفيذ كامل الخطة التلقائية' : 'Execute All Containment Steps'}</span>
                      </button>
                    </div>
                  )}
                </div>
              ))}
            </div>

            {/* Compliance Forensic Report Viewer (5 Cols) */}
            <div className="lg:col-span-5 bg-slate-950 border border-slate-800 rounded-xl p-4 space-y-3 font-mono text-xs">
              <div className="text-xs font-bold text-indigo-300 uppercase tracking-wider pb-1 border-b border-slate-800 flex justify-between">
                <span>Forensic Incident Report</span>
                {forensicReport && <span>{forensicReport.reportId}</span>}
              </div>

              {forensicReport ? (
                <div className="space-y-3 max-h-[540px] overflow-y-auto">
                  <div className="p-2.5 rounded bg-slate-900 border border-indigo-500/40 space-y-1">
                    <span className="text-[10px] text-amber-400 font-bold">{forensicReport.classification}</span>
                    <div className="text-[10px] text-slate-400 truncate">Chain of Custody Hash: {forensicReport.chainOfCustodyHash}</div>
                  </div>

                  <div className="space-y-1 font-sans">
                    <span className="text-[11px] font-bold text-slate-400 uppercase">Executive Summary:</span>
                    <p className="p-2 rounded bg-slate-900 border border-slate-800 text-[11px] text-slate-300 leading-relaxed">
                      {isAr && forensicReport.executiveSummaryAr ? forensicReport.executiveSummaryAr : forensicReport.executiveSummaryEn}
                    </p>
                  </div>

                  <div className="space-y-1">
                    <span className="text-[11px] font-bold text-slate-400 uppercase">Forensic Timeline:</span>
                    {forensicReport.forensicTimeline.map((t: any) => (
                      <div key={`timeline-${t.id || t.time + '-' + t.event}`} className="p-1.5 rounded bg-slate-900 border border-slate-800 text-[10px] space-y-0.5">
                        <div className="flex justify-between text-cyan-300 font-bold">
                          <span>{t.time}</span>
                          <span>{t.actor}</span>
                        </div>
                        <div className="text-slate-300">{t.event}</div>
                      </div>
                    ))}
                  </div>

                  <div className="space-y-1 font-sans">
                    <span className="text-[11px] font-bold text-slate-400 uppercase">Compliance Alignment:</span>
                    <ul className="text-[10px] text-emerald-400 list-disc list-inside space-y-0.5">
                      {forensicReport.complianceAlignment.map((c: string) => (
                        <li key={`compliance-${c}`}>{c}</li>
                      ))}
                    </ul>
                  </div>
                </div>
              ) : (
                <div className="text-center py-24 text-slate-500">
                  <FileText className="w-8 h-8 mx-auto mb-2 opacity-30" />
                  <p>{isAr ? 'اضغط "Generate Forensic Report" لتجميع تقرير الحادث' : 'Click "Generate Forensic Report" above to compile audit trail.'}</p>
                </div>
              )}
            </div>

          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* PERSISTENT TACTICAL COMMAND BAR MODALS                                    */}
      {/* ========================================================================= */}
      <ManualIpQuarantineModal
        isOpen={isQuarantineModalOpen}
        onClose={() => setIsQuarantineModalOpen(false)}
        lang={lang}
        onBanSuccess={fetchTelemetry}
      />

      <TargetScannerAuditModal
        isOpen={isScannerModalOpen}
        onClose={() => setIsScannerModalOpen(false)}
        lang={lang}
      />

      <ExportForensicReportModal
        isOpen={isReportModalOpen}
        onClose={() => setIsReportModalOpen(false)}
        lang={lang}
      />

    </div>
  );
};
