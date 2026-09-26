import React, { useState, useEffect, useRef, useMemo } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  Activity,
  Globe,
  Radio,
  Server,
  Cpu,
  Layers,
  Zap,
  Lock,
  Unlock,
  AlertTriangle,
  Play,
  Crosshair,
  Ban,
  CheckCircle2,
  RefreshCw,
  Terminal,
  Filter,
  Eye,
  Sliders,
  ExternalLink,
  Flame,
  Wifi,
  Database,
  HardDrive,
  Network,
  Binary,
  ArrowRight,
  Download,
  Search,
  AlertOctagon,
  X,
  Copy,
  Check,
  Route,
  Key,
  FolderTree,
  Code,
  Info,
  ChevronDown,
  ChevronUp,
  Maximize2,
  Minimize2,
  ArrowDownLeft,
  ArrowUpRight,
  ArrowLeftRight,
  Share2,
  Gauge,
  TrendingUp,
  TrendingDown,
  Cable,
  SlidersHorizontal,
  RadioTower,
  PanelRightClose,
  PanelRightOpen,
  Sparkles,
  RefreshCcw
} from 'lucide-react';

export interface TopologyNode {
  id: string;
  label: string;
  labelAr: string;
  type: 'GATEWAY' | 'AI_LAYER' | 'APP_SERVER' | 'STORAGE_VAULT' | 'DATABASE' | 'HONEYPOT';
  ipAddress: string;
  status: 'HEALTHY' | 'UNDER_ATTACK' | 'ISOLATED' | 'DEGRADED';
  activeLoadPercent: number;
  blockedConnectionsCount: number;
  threatsMitigatedCount: number;
  lastPingMs: number;
  vlan: string;
}

export interface AttackArcVector {
  id: string;
  timestamp: string;
  sourceIp: string;
  sourceCountry: string;
  sourceCountryName: string;
  sourceCoords: [number, number]; // [lat, lng]
  targetNodeId: string;
  targetCoords: [number, number]; // [lat, lng]
  attackType: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  ratePps: number;
  status: 'DROPPED_AT_BORDER' | 'HONEYPOT_CAPTURED' | 'CONTAINED';
}

export interface SocketConnection {
  id: string;
  srcIp: string;
  srcPort: number;
  dstIp: string;
  dstPort: number;
  protocol: 'TCP' | 'UDP' | 'ICMP';
  state: 'ESTABLISHED' | 'SYN_SENT' | 'LISTEN' | 'TIME_WAIT' | 'FIN_WAIT' | 'DROPPED';
  latencyMs: number;
  bytesTransferred: number;
  threatLevel: 'BENIGN' | 'SUSPICIOUS' | 'MALICIOUS';
  processName: string;
  pid: number;
  targetNodeId: string;
  tcpFlags: string[];
  hexDump: string;
  asciiPayload: string;
  timestamp: string;
  isEbpfFiltered?: boolean;
}

export interface TracerouteHop {
  hop: number;
  ip: string;
  rttMs: number;
  hostname: string;
  asn: string;
  country: string;
}

export interface SiteRouteNode {
  id: string;
  path: string;
  label: string;
  labelAr: string;
  status: 'SECURE' | 'EXPOSED' | 'UNDER_ATTACK';
  rps: number;
  errorRatePercent: number;
  activePayloads: string[];
  lastInspected: string;
  children?: SiteRouteNode[];
}

export interface DeceptionTrapMonitor {
  id: string;
  path: string;
  descriptionEn: string;
  descriptionAr: string;
  hitsCount: number;
  lastTriggered?: string;
  lastAttackerIp?: string;
  autoQuarantine: boolean;
  active: boolean;
}

export interface SegmentDensityMetric {
  nodeId: string;
  label: string;
  labelAr: string;
  vlan: string;
  ipAddress: string;
  densityScore: number;
  threatCount: number;
  activeSockets: number;
  maliciousPct: number;
  activeLoad: number;
  latencyMs: number;
  status: string;
  thermalStatus: 'CRITICAL_OVERHEAT' | 'ELEVATED_HEAT' | 'TEMPERATE' | 'QUARANTINE_COLD';
}

export interface ConnectedEdgeDetail {
  id: string;
  sourceNodeId: string;
  targetNodeId: string;
  neighborNodeId: string;
  neighborLabel: string;
  neighborLabelAr: string;
  neighborIp: string;
  neighborVlan: string;
  neighborType: string;
  direction: 'INGRESS' | 'EGRESS' | 'BIDIRECTIONAL';
  capacityGbps: number;
  currentThroughputMbps: number;
  utilizationPercent: number;
  latencyMs: number;
  jitterMs: number;
  packetLossPercent: number;
  protocol: string;
  securityEncap: string;
  status: 'OPERATIONAL' | 'CONGESTED' | 'QUARANTINED' | 'DEGRADED';
}

export interface NodeThroughputProfile {
  nodeId: string;
  // Ingress Telemetry (RX)
  ingressBandwidthMbps: number;
  ingressPeakMbps: number;
  ingressPps: number;
  ingressBytesTotal: number;
  ingressDropRatePercent: number;
  ingressBufferSaturationPercent: number;
  ingressProtocols: { protocol: string; percent: number; color: string }[];
  /** Transport-level split, derived from the protocol mix above. */
  protocolBreakdown: {
    tcpPercent: number;
    udpPercent: number;
    icmpPercent: number;
    tlsEncryptedPercent: number;
  };
  // Egress Telemetry (TX)
  egressBandwidthMbps: number;
  egressPeakMbps: number;
  egressPps: number;
  egressBytesTotal: number;
  egressRetransmitRatePercent: number;
  egressQueueDepthPercent: number;
  mtuBytes: number;
  egressEncryption: string;
  // Hardware & NIC Telemetry
  nicInterface: string;
  macAddress: string;
  driverMode: string;
  irqRatePerSec: number;
  connectedEdges: ConnectedEdgeDetail[];
  // Time-Series Throughput Sparkline Data (16 points)
  history: { time: string; ingressMbps: number; egressMbps: number }[];
}

export const calculateNodeThroughputProfile = (
  nodeId: string,
  nodes: TopologyNode[],
  sockets: SocketConnection[],
  attackArcs: AttackArcVector[],
  densityMetric?: SegmentDensityMetric
): NodeThroughputProfile => {
  const node = nodes.find(n => n.id === nodeId) ||
    nodes[0] || {
      id: nodeId,
      label: 'Node',
      labelAr: 'عقدة',
      type: 'APP_SERVER',
      ipAddress: '10.0.0.1',
      status: 'HEALTHY',
      activeLoadPercent: 40,
      blockedConnectionsCount: 10,
      threatsMitigatedCount: 10,
      lastPingMs: 1.0,
      vlan: 'VLAN-10'
    };

  const isUnderAttack = node.status === 'UNDER_ATTACK' || (densityMetric?.densityScore || 0) >= 0.7;
  const isIsolated = node.status === 'ISOLATED';
  const density = densityMetric?.densityScore || node.activeLoadPercent / 100;

  // Sockets matching this node
  const nodeSockets = sockets.filter(
    s => s.targetNodeId === nodeId || s.dstIp === node.ipAddress || s.srcIp === node.ipAddress
  );
  const totalSocketBytes = nodeSockets.reduce((acc, s) => acc + s.bytesTransferred, 0);

  // Ingress Calculation
  const baseIngressMbps =
    nodeId === 'node-ingress-waf'
      ? 1420
      : nodeId === 'node-ai-filter'
        ? 920
        : nodeId === 'node-app-core'
          ? 1150
          : nodeId === 'node-database'
            ? 780
            : nodeId === 'node-storage-fim'
              ? 640
              : 120;
  const attackMultiplier = isUnderAttack ? 2.8 : 1.0;
  const isolationMultiplier = isIsolated ? 0.02 : 1.0;

  const ingressBandwidthMbps =
    Math.round(
      baseIngressMbps * (0.6 + density * 0.8) * attackMultiplier * isolationMultiplier * 10
    ) / 10;
  const ingressPeakMbps =
    Math.round(ingressBandwidthMbps * (isUnderAttack ? 1.65 : 1.28) * 10) / 10;
  const ingressPps = Math.round(ingressBandwidthMbps * 1420 * (isUnderAttack ? 1.8 : 1.0));
  const ingressBytesTotal = Math.max(
    1024 * 1024 * 50,
    totalSocketBytes * 45 + Math.round(ingressBandwidthMbps * 1024 * 1024 * 1.5)
  );
  const ingressDropRatePercent = isIsolated
    ? 100
    : isUnderAttack
      ? 14.8
      : Math.round((0.02 + density * 0.15) * 100) / 100;
  const ingressBufferSaturationPercent = isIsolated
    ? 0
    : Math.min(99, Math.round(node.activeLoadPercent * (isUnderAttack ? 1.4 : 0.85)));

  // Egress Calculation
  const baseEgressMbps =
    nodeId === 'node-ingress-waf'
      ? 1180
      : nodeId === 'node-ai-filter'
        ? 840
        : nodeId === 'node-app-core'
          ? 980
          : nodeId === 'node-database'
            ? 920
            : nodeId === 'node-storage-fim'
              ? 510
              : 85;
  const egressBandwidthMbps =
    Math.round(baseEgressMbps * (0.55 + density * 0.75) * isolationMultiplier * 10) / 10;
  const egressPeakMbps = Math.round(egressBandwidthMbps * 1.25 * 10) / 10;
  const egressPps = Math.round(egressBandwidthMbps * 1210);
  const egressBytesTotal = Math.max(
    1024 * 1024 * 35,
    totalSocketBytes * 32 + Math.round(egressBandwidthMbps * 1024 * 1024 * 1.1)
  );
  const egressRetransmitRatePercent = isIsolated ? 0 : isUnderAttack ? 2.4 : 0.04;
  const egressQueueDepthPercent = isIsolated
    ? 0
    : Math.min(95, Math.round(node.activeLoadPercent * 0.7 + (isUnderAttack ? 25 : 0)));

  // Protocols Breakdown
  const ingressProtocols =
    nodeId === 'node-ingress-waf'
      ? [
          { protocol: 'HTTPS / TLS 1.3', percent: 64, color: '#06b6d4' },
          { protocol: 'HTTP/2 (gRPC Ingress)', percent: 22, color: '#8b5cf6' },
          { protocol: 'WSS (WebSocket Stream)', percent: 10, color: '#10b981' },
          { protocol: 'Raw TCP / eBPF Pass', percent: 4, color: '#f59e0b' }
        ]
      : nodeId === 'node-ai-filter'
        ? [
            { protocol: 'mTLS Internal gRPC', percent: 58, color: '#8b5cf6' },
            { protocol: 'REST / JSON Ingress', percent: 26, color: '#06b6d4' },
            { protocol: 'LLM Vector Stream', percent: 16, color: '#ec4899' }
          ]
        : nodeId === 'node-database'
          ? [
              { protocol: 'PostgreSQL / TLS Wire', percent: 74, color: '#10b981' },
              { protocol: 'Distributed Spanner RPC', percent: 18, color: '#3b82f6' },
              { protocol: 'WAL Replication Sync', percent: 8, color: '#f59e0b' }
            ]
          : nodeId === 'node-honeypot'
            ? [
                { protocol: 'Decoy SMBv2 / SMBv3', percent: 44, color: '#ef4444' },
                { protocol: 'SSH Decoy Probe', percent: 32, color: '#f97316' },
                { protocol: 'Decoy HTTP Admin', percent: 24, color: '#eab308' }
              ]
            : [
                { protocol: 'HTTP/2 Microservices', percent: 60, color: '#3b82f6' },
                { protocol: 'Internal gRPC / Protobuf', percent: 28, color: '#8b5cf6' },
                { protocol: 'Health & IPC Signals', percent: 12, color: '#10b981' }
              ];

  // Connected Edges definitions for all nodes
  const edgeMappings: Record<
    string,
    Array<{
      neighborId: string;
      direction: 'INGRESS' | 'EGRESS' | 'BIDIRECTIONAL';
      capacityGbps: number;
      protocol: string;
      securityEncap: string;
    }>
  > = {
    'node-ingress-waf': [
      {
        neighborId: 'node-ai-filter',
        direction: 'BIDIRECTIONAL',
        capacityGbps: 40,
        protocol: 'mTLS 1.3 / gRPC',
        securityEncap: 'Hardware WireGuard eBPF'
      },
      {
        neighborId: 'node-app-core',
        direction: 'BIDIRECTIONAL',
        capacityGbps: 40,
        protocol: 'HTTP/2 over TLS',
        securityEncap: 'Direct Kernel Socket'
      },
      {
        neighborId: 'node-honeypot',
        direction: 'EGRESS',
        capacityGbps: 10,
        protocol: 'Raw TCP Mirror',
        securityEncap: 'Isolated Deception Quarantine'
      }
    ],
    'node-ai-filter': [
      {
        neighborId: 'node-ingress-waf',
        direction: 'INGRESS',
        capacityGbps: 40,
        protocol: 'mTLS 1.3 / gRPC',
        securityEncap: 'Hardware WireGuard eBPF'
      },
      {
        neighborId: 'node-app-core',
        direction: 'EGRESS',
        capacityGbps: 40,
        protocol: 'Internal gRPC',
        securityEncap: 'Zero-Trust IPSec Mesh'
      },
      {
        neighborId: 'node-storage-fim',
        direction: 'BIDIRECTIONAL',
        capacityGbps: 25,
        protocol: 'RoCE v2 RDMA',
        securityEncap: 'Encrypted NVMe-oF Tunnel'
      }
    ],
    'node-app-core': [
      {
        neighborId: 'node-ingress-waf',
        direction: 'INGRESS',
        capacityGbps: 40,
        protocol: 'HTTP/2 over TLS',
        securityEncap: 'Direct Kernel Socket'
      },
      {
        neighborId: 'node-ai-filter',
        direction: 'INGRESS',
        capacityGbps: 40,
        protocol: 'Internal gRPC',
        securityEncap: 'Zero-Trust IPSec Mesh'
      },
      {
        neighborId: 'node-database',
        direction: 'BIDIRECTIONAL',
        capacityGbps: 100,
        protocol: 'PostgreSQL TLS 1.3',
        securityEncap: 'PCIe Gen4 Direct Crypt'
      }
    ],
    'node-storage-fim': [
      {
        neighborId: 'node-ai-filter',
        direction: 'INGRESS',
        capacityGbps: 25,
        protocol: 'RoCE v2 RDMA',
        securityEncap: 'Encrypted NVMe-oF Tunnel'
      },
      {
        neighborId: 'node-database',
        direction: 'BIDIRECTIONAL',
        capacityGbps: 40,
        protocol: 'Encrypted gRPC Sync',
        securityEncap: 'AES-256-GCM Hardware Tunnel'
      }
    ],
    'node-database': [
      {
        neighborId: 'node-app-core',
        direction: 'INGRESS',
        capacityGbps: 100,
        protocol: 'PostgreSQL TLS 1.3',
        securityEncap: 'PCIe Gen4 Direct Crypt'
      },
      {
        neighborId: 'node-storage-fim',
        direction: 'BIDIRECTIONAL',
        capacityGbps: 40,
        protocol: 'Encrypted gRPC Sync',
        securityEncap: 'AES-256-GCM Hardware Tunnel'
      }
    ],
    'node-honeypot': [
      {
        neighborId: 'node-ingress-waf',
        direction: 'INGRESS',
        capacityGbps: 10,
        protocol: 'Raw TCP Mirror',
        securityEncap: 'Isolated Deception Quarantine'
      }
    ]
  };

  const rawEdges = edgeMappings[nodeId] || [];
  // Transport split, classified from the protocol mix this node actually
  // carries — the panel previously read a field nothing ever produced, so it
  // rendered "undefined%".
  const classify = (name: string) => {
    const n = name.toLowerCase();
    if (n.includes('icmp') || n.includes('ping')) return 'icmp';
    if (n.includes('udp') || n.includes('quic') || n.includes('dns')) return 'udp';
    return 'tcp';
  };
  const isEncrypted = (name: string) => {
    const n = name.toLowerCase();
    return (
      n.includes('tls') ||
      n.includes('https') ||
      n.includes('wss') ||
      n.includes('ssl') ||
      n.includes('mtls')
    );
  };
  const protoTotal = ingressProtocols.reduce((sum, p) => sum + p.percent, 0) || 1;
  const bucket = (kind: string) =>
    Math.round(
      (ingressProtocols
        .filter(p => classify(p.protocol) === kind)
        .reduce((sum, p) => sum + p.percent, 0) /
        protoTotal) *
        1000
    ) / 10;
  const protocolBreakdown = {
    tcpPercent: bucket('tcp'),
    udpPercent: bucket('udp'),
    icmpPercent: bucket('icmp'),
    tlsEncryptedPercent:
      Math.round(
        (ingressProtocols
          .filter(p => isEncrypted(p.protocol))
          .reduce((sum, p) => sum + p.percent, 0) /
          protoTotal) *
          1000
      ) / 10
  };

  const connectedEdges: ConnectedEdgeDetail[] = rawEdges.map((re, index) => {
    const neighborNode = nodes.find(n => n.id === re.neighborId) || {
      id: re.neighborId,
      label: re.neighborId.replace('node-', '').toUpperCase(),
      labelAr: re.neighborId,
      type: 'APP_SERVER',
      ipAddress: '10.0.0.x',
      vlan: 'VLAN-XX',
      status: 'HEALTHY',
      lastPingMs: 0.5
    };

    const edgeThroughputMbps =
      Math.round(
        (ingressBandwidthMbps / Math.max(1, rawEdges.length)) * (0.8 + index * 0.15) * 10
      ) / 10;
    const capacityMbps = re.capacityGbps * 1000;
    const utilizationPercent = Math.min(
      100,
      Math.round((edgeThroughputMbps / capacityMbps) * 1000) / 10
    );
    const isEdgeCongested = utilizationPercent > 65 || isUnderAttack;
    const isEdgeQuarantined = isIsolated || neighborNode.status === 'ISOLATED';

    return {
      id: `edge-${nodeId}-${re.neighborId}`,
      sourceNodeId: nodeId,
      targetNodeId: re.neighborId,
      neighborNodeId: re.neighborId,
      neighborLabel: neighborNode.label,
      neighborLabelAr: neighborNode.labelAr,
      neighborIp: neighborNode.ipAddress,
      neighborVlan: neighborNode.vlan,
      neighborType: neighborNode.type,
      direction: re.direction,
      capacityGbps: re.capacityGbps,
      currentThroughputMbps: isEdgeQuarantined ? 0 : edgeThroughputMbps,
      utilizationPercent: isEdgeQuarantined ? 0 : utilizationPercent,
      latencyMs: isEdgeQuarantined
        ? 999
        : Math.round((neighborNode.lastPingMs + (isUnderAttack ? 1.4 : 0.2)) * 100) / 100,
      jitterMs: isEdgeQuarantined ? 0 : Math.round((0.02 + (index + 1) * 0.015) * 100) / 100,
      packetLossPercent: isEdgeQuarantined ? 100 : isUnderAttack ? 1.2 : 0.0,
      protocol: re.protocol,
      securityEncap: re.securityEncap,
      status: isEdgeQuarantined ? 'QUARANTINED' : isEdgeCongested ? 'CONGESTED' : 'OPERATIONAL'
    };
  });

  // Time-Series Sparkline History
  const history = Array.from({ length: 16 }).map((_, i) => {
    const tOffset = (15 - i) * 4;
    const timeLabel = `-${tOffset}s`;
    const variance = Math.sin(i * 0.6) * 0.12;
    const histIngress = Math.max(
      10,
      Math.round(ingressBandwidthMbps * (0.88 + variance + i * 0.008) * 10) / 10
    );
    const histEgress = Math.max(
      8,
      Math.round(egressBandwidthMbps * (0.85 - variance + i * 0.008) * 10) / 10
    );
    return {
      time: timeLabel,
      ingressMbps: isIsolated ? 0 : histIngress,
      egressMbps: isIsolated ? 0 : histEgress
    };
  });

  return {
    nodeId,
    ingressBandwidthMbps,
    ingressPeakMbps,
    ingressPps,
    ingressBytesTotal,
    ingressDropRatePercent,
    ingressBufferSaturationPercent,
    ingressProtocols,
    protocolBreakdown,
    egressBandwidthMbps,
    egressPeakMbps,
    egressPps,
    egressBytesTotal,
    egressRetransmitRatePercent,
    egressQueueDepthPercent,
    mtuBytes: 9000,
    egressEncryption: 'AES-256-GCM / WireGuard TLS 1.3',
    nicInterface:
      nodeId === 'node-ingress-waf'
        ? 'eth0 (eBPF XDP_DRV)'
        : nodeId === 'node-database'
          ? 'bond0 (100GbE QSFP28)'
          : 'eth0 (VirtIO 40GbE)',
    macAddress: `02:42:0a:00:00:${nodeId === 'node-ingress-waf' ? '01' : nodeId === 'node-ai-filter' ? '02' : nodeId === 'node-app-core' ? '05' : nodeId === 'node-storage-fim' ? '07' : nodeId === 'node-database' ? '08' : '99'}`,
    driverMode: 'mlx5_core (Native eBPF Hook)',
    irqRatePerSec: Math.round(ingressPps * 0.08),
    connectedEdges,
    history
  };
};

export interface CyberTopologyMapProps {
  lang: 'ar' | 'en';
}

export const CyberTopologyMap: React.FC<CyberTopologyMapProps> = ({ lang }) => {
  const isAr = lang === 'ar';
  const canvasRef = useRef<HTMLCanvasElement | null>(null);

  // Socket Matrix & DPI
  const [sockets, setSockets] = useState<SocketConnection[]>([]);
  const [selectedSocket, setSelectedSocket] = useState<SocketConnection | null>(null);
  const [socketFilter, setSocketFilter] = useState<string>('');
  const [protocolFilter, setProtocolFilter] = useState<'ALL' | 'TCP' | 'UDP' | 'ICMP'>('ALL');
  const [threatFilter, setThreatFilter] = useState<'ALL' | 'MALICIOUS' | 'SUSPICIOUS' | 'BENIGN'>(
    'ALL'
  );

  // Core Topology State
  const [nodes, setNodes] = useState<TopologyNode[]>([]);
  const [attackArcs, setAttackArcs] = useState<AttackArcVector[]>([]);
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>('node-ingress-waf');
  const [viewMode, setViewMode] = useState<'INFRASTRUCTURE_MESH' | 'GLOBAL_GEOGRAPHIC'>(
    'INFRASTRUCTURE_MESH'
  );
  const [activeSubTab, setActiveSubTab] = useState<
    'SOCKET_MATRIX' | 'TOPOLOGY_OVERVIEW' | 'SITE_SURVEILLANCE_TREE' | 'HONEYTOKEN_TRAPS'
  >('SOCKET_MATRIX');

  // Traceroute State
  const [activeTraceroute, setActiveTraceroute] = useState<{
    targetIp: string;
    hops: TracerouteHop[];
  } | null>(null);
  const [isTracingRoute, setIsTracingRoute] = useState<boolean>(false);

  // Site Route Tree & Deception Traps
  const [siteTree, setSiteTree] = useState<SiteRouteNode | null>(null);
  const [expandedRoutes, setExpandedRoutes] = useState<Record<string, boolean>>({
    'route-root': true,
    'route-api-v1': true
  });
  const [deceptionTraps, setDeceptionTraps] = useState<DeceptionTrapMonitor[]>([]);

  // Interactive Intensity Heatmap Overlay State
  const [heatmapEnabled, setHeatmapEnabled] = useState<boolean>(true);
  const [heatmapMetric, setHeatmapMetric] = useState<
    'THREAT_SEVERITY' | 'TRAFFIC_VOLUME' | 'LATENCY_CONGESTION' | 'ANOMALY_INDEX'
  >('THREAT_SEVERITY');
  const [heatmapPalette, setHeatmapPalette] = useState<'PLASMA' | 'INFERNO' | 'TOXIC_RADAR'>(
    'PLASMA'
  );
  const [heatmapRadius, setHeatmapRadius] = useState<number>(75);
  const [heatmapIntensity, setHeatmapIntensity] = useState<number>(0.85);
  const [heatmapBlur, setHeatmapBlur] = useState<number>(30);
  const [showHeatmapSettings, setShowHeatmapSettings] = useState<boolean>(false);
  const [showHeatmapLegend, setShowHeatmapLegend] = useState<boolean>(true);
  const [legendExpanded, setLegendExpanded] = useState<boolean>(false);
  const [canvasMousePos, setCanvasMousePos] = useState<{ x: number; y: number } | null>(null);
  /**
   * What actually gets stored here is a SegmentDensityMetric plus the cursor
   * position. The shape was previously re-typed by hand and had drifted from
   * it — it declared `id` where the metric carries `nodeId`, and omitted
   * `thermalStatus` — so the reads below were silently undefined. Deriving
   * from the source type keeps the two from separating again.
   */
  const [hoveredHeatPoint, setHoveredHeatPoint] = useState<
    (SegmentDensityMetric & { x: number; y: number }) | null
  >(null);

  // Emergency & Combat Controls
  const [emergencyLockdown, setEmergencyLockdown] = useState<boolean>(false);
  const [subnetQuarantineInput, setSubnetQuarantineInput] = useState<string>('194.26.29.0/24');
  const [showSubnetModal, setShowSubnetModal] = useState<boolean>(false);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [actionMessage, setActionMessage] = useState<string | null>(null);
  const [copiedCode, setCopiedCode] = useState<boolean>(false);

  // Expanded Node Deep Inspection Side-Panel State
  const [isNodeExpanded, setIsNodeExpanded] = useState<boolean>(false);
  const [expandedNodeSubTab, setExpandedNodeSubTab] = useState<
    'THROUGHPUT' | 'EDGES' | 'SOCKETS' | 'TACTICAL'
  >('THROUGHPUT');
  const [pingTestingEdgeId, setPingTestingEdgeId] = useState<string | null>(null);
  const [edgePingResults, setEdgePingResults] = useState<
    Record<string, { rttMs: number; jitterMs: number; timestamp: number; simulated?: boolean }>
  >({});
  const [edgeQoSThrottled, setEdgeQoSThrottled] = useState<Record<string, boolean>>({});
  const [edgeQuarantined, setEdgeQuarantined] = useState<Record<string, boolean>>({});
  const [quickLockedNodes, setQuickLockedNodes] = useState<Record<string, boolean>>({});

  // Memory buffer cap (200 items)
  const MAX_BUFFER_CAP = 200;

  // Fetch Topology State
  const fetchTopology = async () => {
    try {
      const res = await fetch('/api/v1/topology/state');
      if (res.ok) {
        const data = await res.json();
        setNodes(data.nodes || []);
        setAttackArcs(prev => {
          const combined = data.attackArcs || [];
          return combined.slice(0, MAX_BUFFER_CAP);
        });
      }
    } catch (err) {
      console.warn('Failed to load topology state:', err);
    }
  };

  // Fetch Socket Connections
  const fetchSockets = async () => {
    try {
      const res = await fetch('/api/v1/topology/sockets');
      if (res.ok) {
        const data = await res.json();
        setSockets((data.sockets || []).slice(0, MAX_BUFFER_CAP));
      }
    } catch (err) {
      console.warn('Failed to load socket stream:', err);
    }
  };

  // Fetch Site Route Tree
  const fetchSiteTree = async () => {
    try {
      const res = await fetch('/api/v1/topology/site-tree');
      if (res.ok) {
        const data = await res.json();
        setSiteTree(data.tree || null);
      }
    } catch (err) {
      console.warn('Failed to load site route tree:', err);
    }
  };

  // Fetch Deception Traps
  const fetchDeceptionTraps = async () => {
    try {
      const res = await fetch('/api/v1/topology/deception-traps');
      if (res.ok) {
        const data = await res.json();
        setDeceptionTraps(data.traps || []);
      }
    } catch (err) {
      console.warn('Failed to load deception traps:', err);
    }
  };

  // Fetch Lockdown Status
  const fetchLockdownStatus = async () => {
    try {
      const res = await fetch('/api/v1/soc/lockdown/status').catch(() => null);
      if (res && res.ok && res.headers.get('content-type')?.includes('application/json')) {
        const data = await res.json().catch(() => null);
        if (data) {
          setEmergencyLockdown(!!data.emergencyLockdownActive);
        }
      }
    } catch {
      // Safe fallback
    }
  };

  // Initial Load and Polling
  useEffect(() => {
    fetchTopology();
    fetchSockets();
    fetchSiteTree();
    fetchDeceptionTraps();
    fetchLockdownStatus();

    const interval = setInterval(() => {
      fetchTopology();
      fetchSockets();
    }, 4000);

    return () => clearInterval(interval);
  }, []);

  // Segment Threat Density Metrics Computation
  const segmentDensityMetrics = useMemo<Record<string, SegmentDensityMetric>>(() => {
    const metrics: Record<string, SegmentDensityMetric> = {};

    for (const node of nodes) {
      const nodeSockets = sockets.filter(
        s => s.targetNodeId === node.id || (node.id === 'node-ingress-waf' && s.isEbpfFiltered)
      );
      const maliciousCount = nodeSockets.filter(s => s.threatLevel === 'MALICIOUS').length;
      const suspiciousCount = nodeSockets.filter(s => s.threatLevel === 'SUSPICIOUS').length;
      const benignCount = nodeSockets.filter(s => s.threatLevel === 'BENIGN').length;
      const totalSockets = nodeSockets.length;
      const maliciousPct =
        totalSockets > 0
          ? Math.round(((maliciousCount + suspiciousCount) / totalSockets) * 100)
          : 0;

      const nodeArcs = attackArcs.filter(a => a.targetNodeId === node.id);
      const critArcs = nodeArcs.filter(a => a.severity === 'CRITICAL').length;
      const highArcs = nodeArcs.filter(a => a.severity === 'HIGH').length;
      const totalThreats = maliciousCount + suspiciousCount + critArcs + highArcs;

      let score = 0.1;
      if (heatmapMetric === 'THREAT_SEVERITY') {
        score = Math.min(
          1.0,
          maliciousCount * 0.22 +
            suspiciousCount * 0.1 +
            critArcs * 0.28 +
            highArcs * 0.14 +
            (node.status === 'UNDER_ATTACK' ? 0.35 : 0.05)
        );
      } else if (heatmapMetric === 'TRAFFIC_VOLUME') {
        score = Math.min(1.0, (node.activeLoadPercent / 100) * 0.6 + (totalSockets / 15) * 0.4);
      } else if (heatmapMetric === 'LATENCY_CONGESTION') {
        const avgLat =
          totalSockets > 0
            ? nodeSockets.reduce((acc, s) => acc + s.latencyMs, 0) / totalSockets
            : 1;
        score = Math.min(1.0, (node.lastPingMs / 5) * 0.5 + (avgLat / 80) * 0.5);
      } else if (heatmapMetric === 'ANOMALY_INDEX') {
        score = Math.min(
          1.0,
          maliciousCount * 0.2 +
            (node.blockedConnectionsCount / 1200) * 0.4 +
            (node.status === 'UNDER_ATTACK' ? 0.4 : 0.05)
        );
      }

      if (node.status === 'ISOLATED') {
        score = 0.02; // Isolated nodes are cooled down
      }

      let thermalStatus: 'CRITICAL_OVERHEAT' | 'ELEVATED_HEAT' | 'TEMPERATE' | 'QUARANTINE_COLD' =
        'TEMPERATE';
      if (node.status === 'ISOLATED') {
        thermalStatus = 'QUARANTINE_COLD';
      } else if (score >= 0.7) {
        thermalStatus = 'CRITICAL_OVERHEAT';
      } else if (score >= 0.4) {
        thermalStatus = 'ELEVATED_HEAT';
      }

      metrics[node.id] = {
        nodeId: node.id,
        label: node.label,
        labelAr: node.labelAr,
        vlan: node.vlan,
        ipAddress: node.ipAddress,
        densityScore: Math.max(0.05, Math.min(1.0, score)),
        threatCount: totalThreats,
        activeSockets: totalSockets,
        maliciousPct,
        activeLoad: node.activeLoadPercent,
        latencyMs: node.lastPingMs,
        status: node.status,
        thermalStatus
      };
    }

    return metrics;
  }, [nodes, sockets, attackArcs, heatmapMetric]);

  // Heatmap Palette Configuration
  const getPaletteConfig = (palette: 'PLASMA' | 'INFERNO' | 'TOXIC_RADAR') => {
    switch (palette) {
      case 'INFERNO':
        return {
          name: 'Inferno Neon',
          nameAr: 'جحيم نيون',
          gradientCss: 'from-purple-600 via-pink-500 via-orange-500 to-yellow-300',
          getColorStops: (alpha: number = 1.0) => [
            { stop: 0.0, color: `rgba(20, 5, 45, 0)` },
            { stop: 0.2, color: `rgba(139, 92, 246, ${0.4 * alpha})` },
            { stop: 0.45, color: `rgba(236, 72, 153, ${0.65 * alpha})` },
            { stop: 0.7, color: `rgba(249, 115, 22, ${0.85 * alpha})` },
            { stop: 0.9, color: `rgba(225, 29, 72, ${0.95 * alpha})` },
            { stop: 1.0, color: `rgba(254, 240, 138, ${1.0 * alpha})` }
          ],
          contourColor: '#f97316',
          conduitColor: 'rgba(236, 72, 153, 0.45)'
        };
      case 'TOXIC_RADAR':
        return {
          name: 'Toxic FLIR Radar',
          nameAr: 'رادار الأشعة التكتيكي',
          gradientCss: 'from-emerald-600 via-lime-500 via-yellow-400 to-rose-600',
          getColorStops: (alpha: number = 1.0) => [
            { stop: 0.0, color: `rgba(2, 44, 34, 0)` },
            { stop: 0.2, color: `rgba(16, 185, 129, ${0.4 * alpha})` },
            { stop: 0.45, color: `rgba(132, 204, 22, ${0.65 * alpha})` },
            { stop: 0.7, color: `rgba(234, 179, 8, ${0.85 * alpha})` },
            { stop: 0.9, color: `rgba(239, 68, 68, ${0.95 * alpha})` },
            { stop: 1.0, color: `rgba(255, 241, 242, ${1.0 * alpha})` }
          ],
          contourColor: '#84cc16',
          conduitColor: 'rgba(132, 204, 22, 0.45)'
        };
      case 'PLASMA':
      default:
        return {
          name: 'Plasma Thermal',
          nameAr: 'بلازما حرارية',
          gradientCss: 'from-cyan-500 via-blue-500 via-amber-400 to-rose-500',
          getColorStops: (alpha: number = 1.0) => [
            { stop: 0.0, color: `rgba(0, 20, 60, 0)` },
            { stop: 0.2, color: `rgba(6, 182, 212, ${0.4 * alpha})` },
            { stop: 0.45, color: `rgba(59, 130, 246, ${0.65 * alpha})` },
            { stop: 0.7, color: `rgba(245, 158, 11, ${0.85 * alpha})` },
            { stop: 0.9, color: `rgba(239, 68, 68, ${0.95 * alpha})` },
            { stop: 1.0, color: `rgba(255, 255, 255, ${1.0 * alpha})` }
          ],
          contourColor: '#f59e0b',
          conduitColor: 'rgba(6, 182, 212, 0.45)'
        };
    }
  };

  // Canvas Mouse Move Handler for Interactive Tooltip
  const handleCanvasMouseMove = (e: React.MouseEvent<HTMLCanvasElement>) => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const rect = canvas.getBoundingClientRect();
    const scaleX = canvas.width / rect.width;
    const scaleY = canvas.height / rect.height;
    const mouseX = (e.clientX - rect.left) * scaleX;
    const mouseY = (e.clientY - rect.top) * scaleY;

    setCanvasMousePos({ x: mouseX, y: mouseY });

    if (viewMode === 'INFRASTRUCTURE_MESH') {
      const nodePositions: Record<string, { x: number; y: number }> = {
        'node-ingress-waf': { x: canvas.width * 0.18, y: canvas.height * 0.5 },
        'node-ai-filter': { x: canvas.width * 0.42, y: canvas.height * 0.28 },
        'node-app-core': { x: canvas.width * 0.42, y: canvas.height * 0.72 },
        'node-storage-fim': { x: canvas.width * 0.68, y: canvas.height * 0.28 },
        'node-database': { x: canvas.width * 0.68, y: canvas.height * 0.72 },
        'node-honeypot': { x: canvas.width * 0.88, y: canvas.height * 0.5 }
      };

      let closest: { id: string; dist: number } | null = null;
      for (const [id, pos] of Object.entries(nodePositions)) {
        const dx = mouseX - pos.x;
        const dy = mouseY - pos.y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < 65 && (!closest || dist < closest.dist)) {
          closest = { id, dist };
        }
      }

      if (closest) {
        const metric = segmentDensityMetrics[closest.id];
        if (metric) {
          setHoveredHeatPoint({
            ...metric,
            x: e.clientX - rect.left,
            y: e.clientY - rect.top
          });
          return;
        }
      }
    }
    setHoveredHeatPoint(null);
  };

  const handleCanvasMouseLeave = () => {
    setCanvasMousePos(null);
    setHoveredHeatPoint(null);
  };

  const handleCanvasClick = () => {
    if (hoveredHeatPoint) {
      setSelectedNodeId(hoveredHeatPoint.nodeId);
      setIsNodeExpanded(true);
    }
  };

  /**
   * Edge ping.
   *
   * This is a model, not a measurement — a browser cannot send ICMP, and nothing
   * here touches the wire. The internal names already said `simulatedRtt` and
   * `simulatedJitter`, but the sentence shown to the operator read "Link RTT
   * measured", which is the part that mattered and the part that was wrong.
   *
   * The simulation stays; the claim about it does not. Results are tagged
   * `simulated` so any surface rendering them can label them, rather than each
   * one having to remember.
   */
  const handleTestEdgePing = (edgeId: string, baseLatency: number) => {
    setPingTestingEdgeId(edgeId);
    setTimeout(() => {
      const simulatedRtt = Math.max(
        0.12,
        Math.round((baseLatency + (Math.random() * 0.4 - 0.2)) * 100) / 100
      );
      const simulatedJitter = Math.round((0.01 + Math.random() * 0.04) * 100) / 100;
      setEdgePingResults(prev => ({
        ...prev,
        [edgeId]: {
          rttMs: simulatedRtt,
          jitterMs: simulatedJitter,
          timestamp: Date.now(),
          simulated: true
        }
      }));
      setPingTestingEdgeId(null);
      setActionMessage(
        isAr
          ? `⚡ زمن استجابة محاكى للرابط ${edgeId}: ${simulatedRtt}ms (تذبذب: ±${simulatedJitter}ms) — نموذج لا قياس`
          : `⚡ Simulated RTT for ${edgeId}: ${simulatedRtt} ms (jitter ±${simulatedJitter} ms) — modelled, not measured`
      );
      setTimeout(() => setActionMessage(null), 4000);
    }, 600);
  };

  const handleToggleEdgeQoS = (edgeId: string) => {
    setEdgeQoSThrottled(prev => {
      const next = !prev[edgeId];
      setActionMessage(
        isAr
          ? next
            ? `🛡️ تم تفعيل تحديد النطاق وخنق الحركة (QoS Rate Limit) على الرابط ${edgeId}`
            : `⚡ تم إلغاء خنق الحركة على الرابط ${edgeId}`
          : next
            ? `🛡️ QoS Bandwidth Cap & Token Throttling applied to ${edgeId}`
            : `⚡ QoS Throttling lifted on ${edgeId}`
      );
      setTimeout(() => setActionMessage(null), 4000);
      return { ...prev, [edgeId]: next };
    });
  };

  const handleToggleEdgeQuarantine = (edgeId: string) => {
    setEdgeQuarantined(prev => {
      const next = !prev[edgeId];
      setActionMessage(
        isAr
          ? next
            ? `🚫 تم عزل الرابط الشبكي ${edgeId} فوراً وقطع المسار`
            : `✅ تم فك عزل الرابط الشبكي ${edgeId} واستعادة التوجيه`
          : next
            ? `🚫 Edge Link ${edgeId} quarantined immediately. Traffic severed.`
            : `✅ Edge Link ${edgeId} unquarantined and restored.`
      );
      setTimeout(() => setActionMessage(null), 4000);
      return { ...prev, [edgeId]: next };
    });
  };

  // Drop Specific Socket
  const handleDropSocket = async (socketId: string) => {
    try {
      const res = await fetch('/api/v1/topology/socket/drop', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ socketId })
      });
      if (res.ok) {
        const data = await res.json();
        setActionMessage(
          isAr ? `⚡ تم إسقاط الاتصال الشبكي ${socketId} وتطبيق حظر النواة` : data.message
        );
        fetchSockets();
        if (selectedSocket?.id === socketId) {
          setSelectedSocket(data.socket || null);
        }
        setTimeout(() => setActionMessage(null), 4000);
      }
    } catch (err) {
      console.warn('Drop socket failed:', err);
    }
  };

  // Flush All Active Sockets
  const handleFlushSockets = async () => {
    try {
      const res = await fetch('/api/v1/topology/sockets/flush', { method: 'POST' });
      if (res.ok) {
        const data = await res.json();
        setActionMessage(
          isAr ? `⚡ تم تفريغ ${data.flushedCount} اتصال خارجي بنجاح` : data.message
        );
        fetchSockets();
        setTimeout(() => setActionMessage(null), 4000);
      }
    } catch (err) {
      console.warn('Flush sockets failed:', err);
    }
  };

  // Push eBPF Drop Rule
  const handlePushEbpfRule = async (target: string) => {
    try {
      const res = await fetch('/api/v1/topology/socket/ebpf-rule', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ipOrSocketId: target })
      });
      if (res.ok) {
        const data = await res.json();
        setActionMessage(
          isAr
            ? `🛡️ تم تطبيق مرشح eBPF XDP بنجاح لعنوان IP: ${data.ip}`
            : `🛡️ eBPF XDP Driver Rule Activated for ${data.ip}`
        );
        fetchSockets();
        setTimeout(() => setActionMessage(null), 4000);
      }
    } catch (err) {
      console.warn('Push eBPF rule failed:', err);
    }
  };

  // Toggle Security Quick-Lock for a Node Segment (eBPF Kernel Drop)
  const handleToggleQuickLock = async (node: TopologyNode) => {
    const isCurrentlyLocked = !!quickLockedNodes[node.id];
    setIsLoading(true);
    try {
      if (!isCurrentlyLocked) {
        // Apply eBPF Drop Rule
        const res = await fetch('/api/v1/topology/socket/ebpf-rule', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ ipOrSocketId: node.ipAddress })
        });
        if (res.ok) {
          const data = await res.json();
          setQuickLockedNodes(prev => ({ ...prev, [node.id]: true }));
          setActionMessage(
            isAr
              ? `🔒 تم تفعيل القفل الأمني السريع (Security Quick-Lock) للعقدة ${node.labelAr || node.label} (${node.ipAddress}): تم تطبيق مرشح إسقاط فوري eBPF/XDP لجميع حزم النطاق.`
              : `🔒 Security Quick-Lock ENGAGED: Kernel eBPF/XDP drop-rule applied to all traffic originating from ${node.label} (${node.ipAddress} / ${node.vlan}).`
          );
          fetchSockets();
          fetchTopology();
          setTimeout(() => setActionMessage(null), 5000);
        }
      } else {
        // Disengage Quick-Lock
        const res = await fetch('/api/v1/agent/unban', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ ip: node.ipAddress })
        });
        setQuickLockedNodes(prev => ({ ...prev, [node.id]: false }));
        setActionMessage(
          isAr
            ? `🔓 تم إلغاء القفل الأمني السريع للعقدة ${node.labelAr || node.label} (${node.ipAddress}). تم استئناف التوجيه عبر النواة.`
            : `🔓 Security Quick-Lock DISENGAGED for ${node.label} (${node.ipAddress}). eBPF filter cleared.`
        );
        fetchSockets();
        fetchTopology();
        setTimeout(() => setActionMessage(null), 5000);
      }
    } catch (err) {
      console.warn('Quick-Lock toggle failed:', err);
    } finally {
      setIsLoading(false);
    }
  };

  // Execute Traceroute
  const handleTraceRoute = async (targetIp: string) => {
    setIsTracingRoute(true);
    try {
      const res = await fetch('/api/v1/topology/traceroute', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ targetIp })
      });
      if (res.ok) {
        const data = await res.json();
        setActiveTraceroute(data);
      }
    } catch (err) {
      console.warn('Traceroute failed:', err);
    } finally {
      setIsTracingRoute(false);
    }
  };

  // Toggle Emergency Lockdown
  const handleToggleEmergencyLockdown = async () => {
    setIsLoading(true);
    try {
      const res = await fetch('/api/v1/soc/lockdown/toggle', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ active: !emergencyLockdown })
      });
      if (res.ok) {
        const data = await res.json();
        setEmergencyLockdown(data.emergencyLockdownActive);
        setActionMessage(
          data.emergencyLockdownActive
            ? isAr
              ? '🚨 تم تفعيل الإغلاق التام للشبكة (Zero-Trust Lockdown)'
              : '🚨 Emergency Zero-Trust Network Lockdown Activated'
            : isAr
              ? '✅ تم استئناف التوجيه الطبيعي للشبكة'
              : '✅ Emergency Lockdown Deactivated'
        );
        setTimeout(() => setActionMessage(null), 5000);
      }
    } catch (err) {
      console.warn('Lockdown toggle failed:', err);
    } finally {
      setIsLoading(false);
    }
  };

  // Quarantine Subnet
  const handleQuarantineSubnet = async () => {
    if (!subnetQuarantineInput) return;
    try {
      const res = await fetch('/api/v1/topology/subnet/quarantine', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          subnet: subnetQuarantineInput,
          reason: 'Operator CIDR Lockdown from Topology Map'
        })
      });
      if (res.ok) {
        setActionMessage(
          isAr
            ? `🛡️ تم حظر النطاق الشبكي ${subnetQuarantineInput} فوراً`
            : `🛡️ Subnet ${subnetQuarantineInput} Quarantined at Kernel Border`
        );
        setShowSubnetModal(false);
        setTimeout(() => setActionMessage(null), 4000);
      }
    } catch (err) {
      console.warn('Subnet quarantine failed:', err);
    }
  };

  // Trigger Honeytoken Tripwire Simulator
  const handleTriggerHoneytoken = async (path: string) => {
    try {
      const fakeIp = `194.26.29.${Math.floor(10 + Math.random() * 200)}`;
      const res = await fetch('/api/v1/topology/deception-trap/trigger', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ path, attackerIp: fakeIp })
      });
      if (res.ok) {
        setActionMessage(
          isAr
            ? `🪤 تم تفجير الفخ على المسار ${path} وحظر المهاجم ${fakeIp} فوراً!`
            : `🪤 Honeytoken Trap Triggered on ${path}! Attacker ${fakeIp} quarantined.`
        );
        fetchDeceptionTraps();
        setTimeout(() => setActionMessage(null), 4000);
      }
    } catch (err) {
      console.warn('Honeytoken trigger failed:', err);
    }
  };

  // Export PCAP / Audit Log
  const handleExportPcap = async () => {
    try {
      const res = await fetch('/api/v1/topology/pcap/export');
      if (res.ok) {
        const data = await res.json();
        const jsonBlob = new Blob([JSON.stringify(data.data, null, 2)], {
          type: 'application/json'
        });
        const url = URL.createObjectURL(jsonBlob);
        const a = document.createElement('a');
        a.href = url;
        a.download = data.filename || 'sovereign_soc_audit_pcap.json';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        setActionMessage(
          isAr ? '💾 تم تنزيل تقرير PCAP الجنائي بنجاح' : '💾 Forensic PCAP / Audit Stream Exported'
        );
        setTimeout(() => setActionMessage(null), 4000);
      }
    } catch (err) {
      console.warn('PCAP export failed:', err);
    }
  };

  // Isolate Node
  const handleIsolateNode = async (nodeId: string) => {
    setIsLoading(true);
    try {
      const res = await fetch('/api/v1/topology/node/isolate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ nodeId, reason: 'Operator Emergency Topology Quarantine' })
      });
      if (res.ok) {
        const data = await res.json();
        setActionMessage(isAr ? `تم عزل العقدة ${nodeId} بنجاح عن شبكة التوجيه` : data.message);
        fetchTopology();
        setTimeout(() => setActionMessage(null), 4000);
      }
    } catch (err) {
      console.warn('Isolate node failed:', err);
    } finally {
      setIsLoading(false);
    }
  };

  // Restore Node
  const handleRestoreNode = async (nodeId: string) => {
    setIsLoading(true);
    try {
      const res = await fetch('/api/v1/topology/node/restore', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ nodeId })
      });
      if (res.ok) {
        const data = await res.json();
        setActionMessage(isAr ? `تمت إعادة إدخال العقدة ${nodeId} للشبكة الإنتاجية` : data.message);
        fetchTopology();
        setTimeout(() => setActionMessage(null), 4000);
      }
    } catch (err) {
      console.warn('Restore node failed:', err);
    } finally {
      setIsLoading(false);
    }
  };

  // Trigger Instant Attack Simulation
  const handleSimulateAttackVector = async (
    targetNodeId: string,
    attackType: string,
    severity: 'CRITICAL' | 'HIGH'
  ) => {
    try {
      const res = await fetch('/api/v1/topology/vector/simulate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          sourceIp: `${Math.floor(100 + Math.random() * 100)}.${Math.floor(10 + Math.random() * 200)}.${Math.floor(1 + Math.random() * 254)}.${Math.floor(1 + Math.random() * 254)}`,
          sourceCountry: 'RU',
          sourceCountryName: 'Threat Swarm Node',
          sourceCoords: [55.75, 37.61],
          targetNodeId,
          attackType,
          severity,
          ratePps: Math.floor(45000 + Math.random() * 120000),
          status: 'DROPPED_AT_BORDER'
        })
      });
      if (res.ok) {
        setActionMessage(
          isAr
            ? `⚡ تم إطلاق مسار هجوم محاكى نحو ${targetNodeId}`
            : `⚡ Injected attack vector against ${targetNodeId}`
        );
        fetchTopology();
        setTimeout(() => setActionMessage(null), 4000);
      }
    } catch (err) {
      console.warn('Simulate vector failed:', err);
    }
  };

  // Canvas Visualizer Engine with Intensity Heatmap Overlay
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let animationFrameId: number;
    let particleOffset = 0;

    const render = () => {
      particleOffset = (particleOffset + 0.015) % 1;
      const width = canvas.width;
      const height = canvas.height;

      // Tactical navy-blue background with clearly visible grid
      ctx.fillStyle = '#0d1117';
      ctx.fillRect(0, 0, width, height);

      // Draw Grid Matrix Lines
      ctx.strokeStyle = 'rgba(34, 211, 238, 0.16)';
      ctx.lineWidth = 1;
      const gridSize = 40;
      for (let x = 0; x < width; x += gridSize) {
        ctx.beginPath();
        ctx.moveTo(x, 0);
        ctx.lineTo(x, height);
        ctx.stroke();
      }
      for (let y = 0; y < height; y += gridSize) {
        ctx.beginPath();
        ctx.moveTo(0, y);
        ctx.lineTo(width, y);
        ctx.stroke();
      }

      const paletteCfg = getPaletteConfig(heatmapPalette);
      const colorStops = paletteCfg.getColorStops(heatmapIntensity);

      if (viewMode === 'INFRASTRUCTURE_MESH') {
        const nodePositions: Record<string, { x: number; y: number; color: string }> = {
          'node-ingress-waf': { x: width * 0.18, y: height * 0.5, color: '#06b6d4' },
          'node-ai-filter': { x: width * 0.42, y: height * 0.28, color: '#8b5cf6' },
          'node-app-core': { x: width * 0.42, y: height * 0.72, color: '#3b82f6' },
          'node-storage-fim': { x: width * 0.68, y: height * 0.28, color: '#f59e0b' },
          'node-database': { x: width * 0.68, y: height * 0.72, color: '#10b981' },
          'node-honeypot': { x: width * 0.88, y: height * 0.5, color: '#ef4444' }
        };

        const connections = [
          ['node-ingress-waf', 'node-ai-filter'],
          ['node-ingress-waf', 'node-app-core'],
          ['node-ai-filter', 'node-storage-fim'],
          ['node-app-core', 'node-database'],
          ['node-ai-filter', 'node-app-core'],
          ['node-ingress-waf', 'node-honeypot'],
          ['node-storage-fim', 'node-database']
        ];

        // 1. RENDER HEATMAP OVERLAY LAYER (Behind Hardware Nodes)
        if (heatmapEnabled) {
          ctx.save();
          ctx.globalCompositeOperation = 'screen';

          // A. Thermal Conduits along mesh links
          for (const [fromId, toId] of connections) {
            const from = nodePositions[fromId];
            const to = nodePositions[toId];
            if (!from || !to) continue;

            const fromMetric = segmentDensityMetrics[fromId]?.densityScore || 0.2;
            const toMetric = segmentDensityMetrics[toId]?.densityScore || 0.2;
            const avgDensity = (fromMetric + toMetric) / 2;

            const conduitWidth = 8 + avgDensity * 22;
            const grad = ctx.createLinearGradient(from.x, from.y, to.x, to.y);

            // Interpolate conduit gradient
            grad.addColorStop(0, avgDensity > 0.6 ? colorStops[4].color : colorStops[2].color);
            grad.addColorStop(0.5, avgDensity > 0.6 ? colorStops[3].color : colorStops[1].color);
            grad.addColorStop(1, avgDensity > 0.6 ? colorStops[4].color : colorStops[2].color);

            ctx.strokeStyle = grad;
            ctx.lineWidth = conduitWidth;
            ctx.beginPath();
            ctx.moveTo(from.x, from.y);
            ctx.lineTo(to.x, to.y);
            ctx.stroke();
          }

          // B. Multi-Stop Radial Heat Blooms for each segment node
          for (const node of nodes) {
            const pos = nodePositions[node.id];
            if (!pos) continue;

            const metric = segmentDensityMetrics[node.id];
            const density = metric ? metric.densityScore : 0.2;
            const dynamicRadius =
              heatmapRadius * (0.65 + density * 0.7) + Math.sin(particleOffset * Math.PI * 2) * 3;

            const heatGrad = ctx.createRadialGradient(pos.x, pos.y, 2, pos.x, pos.y, dynamicRadius);

            // Map color stops dynamically based on density
            if (density >= 0.7) {
              // Extreme Heat: Core to Crit to High
              heatGrad.addColorStop(0.0, colorStops[5].color);
              heatGrad.addColorStop(0.2, colorStops[4].color);
              heatGrad.addColorStop(0.45, colorStops[3].color);
              heatGrad.addColorStop(0.7, colorStops[2].color);
              heatGrad.addColorStop(1.0, colorStops[0].color);
            } else if (density >= 0.4) {
              // Moderate Heat: High to Mid to Low
              heatGrad.addColorStop(0.0, colorStops[3].color);
              heatGrad.addColorStop(0.3, colorStops[2].color);
              heatGrad.addColorStop(0.65, colorStops[1].color);
              heatGrad.addColorStop(1.0, colorStops[0].color);
            } else {
              // Low Heat / Cool Zone
              heatGrad.addColorStop(0.0, colorStops[2].color);
              heatGrad.addColorStop(0.4, colorStops[1].color);
              heatGrad.addColorStop(1.0, colorStops[0].color);
            }

            ctx.fillStyle = heatGrad;
            ctx.beginPath();
            ctx.arc(pos.x, pos.y, dynamicRadius, 0, Math.PI * 2);
            ctx.fill();

            // C. Thermal Iso-Density Contour Rings for Hotspots (Density > 0.45)
            if (density > 0.45) {
              ctx.strokeStyle = paletteCfg.contourColor;
              ctx.lineWidth = 1.2;
              ctx.setLineDash([4, 6]);
              ctx.beginPath();
              ctx.arc(pos.x, pos.y, dynamicRadius * 0.68, 0, Math.PI * 2);
              ctx.stroke();

              if (density >= 0.7) {
                ctx.beginPath();
                ctx.arc(pos.x, pos.y, dynamicRadius * 0.42, 0, Math.PI * 2);
                ctx.stroke();
              }
              ctx.setLineDash([]);
            }
          }

          ctx.restore();
        }

        // 2. RENDER TOPOLOGY CONNECTION LINKS & PACKET PARTICLES
        ctx.lineWidth = 2;
        for (const [fromId, toId] of connections) {
          const from = nodePositions[fromId];
          const to = nodePositions[toId];
          if (!from || !to) continue;

          ctx.strokeStyle = 'rgba(122, 155, 209, 0.5)';
          ctx.beginPath();
          ctx.moveTo(from.x, from.y);
          ctx.lineTo(to.x, to.y);
          ctx.stroke();

          const curX = from.x + (to.x - from.x) * particleOffset;
          const curY = from.y + (to.y - from.y) * particleOffset;

          const grad = ctx.createRadialGradient(curX, curY, 0, curX, curY, 8);
          grad.addColorStop(0, '#00f0ff');
          grad.addColorStop(1, 'rgba(0, 240, 255, 0)');
          ctx.fillStyle = grad;
          ctx.beginPath();
          ctx.arc(curX, curY, 6, 0, Math.PI * 2);
          ctx.fill();
        }

        // 3. RENDER INBOUND ATTACK ARCS
        for (let i = 0; i < attackArcs.length; i++) {
          const arc = attackArcs[i];
          const target = nodePositions[arc.targetNodeId] || nodePositions['node-ingress-waf'];
          const startX = 20;
          const startY = height * 0.15 + ((i * 70) % (height * 0.7));

          ctx.strokeStyle =
            arc.severity === 'CRITICAL' ? 'rgba(239, 68, 68, 0.7)' : 'rgba(245, 158, 11, 0.7)';
          ctx.lineWidth = 2;
          ctx.setLineDash([4, 4]);
          ctx.beginPath();
          ctx.moveTo(startX, startY);
          ctx.bezierCurveTo(startX + 80, startY, target.x - 80, target.y, target.x, target.y);
          ctx.stroke();
          ctx.setLineDash([]);

          const threatT = (particleOffset + i * 0.25) % 1;
          const px = startX * (1 - threatT) + target.x * threatT;
          const py = startY * (1 - threatT) + target.y * threatT;
          ctx.fillStyle = '#ff0055';
          ctx.beginPath();
          ctx.arc(px, py, 4, 0, Math.PI * 2);
          ctx.fill();
        }

        // 4. RENDER SHARP HARDWARE NODES & LABELS
        for (const node of nodes) {
          const pos = nodePositions[node.id];
          if (!pos) continue;

          const isSelected = selectedNodeId === node.id;
          const isUnderAttack = node.status === 'UNDER_ATTACK';
          const isIsolated = node.status === 'ISOLATED';
          const isHovered = hoveredHeatPoint?.nodeId === node.id;

          const glowColor = isIsolated
            ? 'rgba(239, 68, 68, 0.25)'
            : isUnderAttack
              ? 'rgba(245, 158, 11, 0.35)'
              : 'rgba(6, 182, 212, 0.25)';
          ctx.fillStyle = glowColor;
          ctx.beginPath();
          ctx.arc(pos.x, pos.y, isSelected || isHovered ? 38 : 28, 0, Math.PI * 2);
          ctx.fill();

          ctx.strokeStyle = isIsolated
            ? '#ef4444'
            : isUnderAttack
              ? '#f59e0b'
              : isSelected
                ? '#00f0ff'
                : isHovered
                  ? '#38bdf8'
                  : '#4d6fa0';
          ctx.lineWidth = isSelected ? 3.5 : isHovered ? 3 : 2;
          ctx.beginPath();
          ctx.arc(pos.x, pos.y, 22, 0, Math.PI * 2);
          ctx.stroke();

          ctx.fillStyle = isIsolated ? '#7f1d1d' : isUnderAttack ? '#78350f' : '#131a24';
          ctx.beginPath();
          ctx.arc(pos.x, pos.y, 16, 0, Math.PI * 2);
          ctx.fill();

          ctx.font = 'bold 11px monospace';
          ctx.fillStyle = isSelected ? '#00f0ff' : '#e2e8f0';
          ctx.textAlign = 'center';
          ctx.fillText(node.label.split(' ')[0], pos.x, pos.y + 36);

          ctx.font = '10px monospace';
          ctx.fillStyle = isIsolated ? '#f87171' : isUnderAttack ? '#fbbf24' : '#94a3b8';
          ctx.fillText(node.ipAddress, pos.x, pos.y + 48);

          // Thermal Density Badge above node
          if (heatmapEnabled) {
            const density = segmentDensityMetrics[node.id]?.densityScore || 0.2;
            const pct = Math.round(density * 100);
            ctx.font = 'bold 9px monospace';
            ctx.fillStyle = density >= 0.7 ? '#fca5a5' : density >= 0.4 ? '#fde047' : '#67e8f9';
            ctx.fillText(`🔥 ${pct}%`, pos.x, pos.y - 30);
          }
        }
      } else {
        // GLOBAL GEOGRAPHIC VIEW
        ctx.strokeStyle = 'rgba(30, 41, 59, 0.8)';
        ctx.lineWidth = 1.5;

        const centerX = width * 0.5;
        const centerY = height * 0.5;
        const radius = Math.min(width, height) * 0.42;

        ctx.beginPath();
        ctx.arc(centerX, centerY, radius, 0, Math.PI * 2);
        ctx.stroke();

        for (let i = 1; i <= 3; i++) {
          ctx.beginPath();
          ctx.ellipse(centerX, centerY, radius * (i / 4), radius, 0, 0, Math.PI * 2);
          ctx.stroke();

          ctx.beginPath();
          ctx.ellipse(centerX, centerY, radius, radius * (i / 4), 0, 0, Math.PI * 2);
          ctx.stroke();
        }

        const targetX = centerX + radius * 0.1;
        const targetY = centerY - radius * 0.35;

        const origins = [
          {
            name: 'RU Threat Cluster (Moscow)',
            x: centerX + radius * 0.45,
            y: centerY - radius * 0.4,
            threatIntensity: 0.9
          },
          {
            name: 'DE Proxy Relay (Frankfurt)',
            x: centerX + radius * 0.22,
            y: centerY - radius * 0.28,
            threatIntensity: 0.6
          },
          {
            name: 'US Botnet Hive (California)',
            x: centerX - radius * 0.65,
            y: centerY - radius * 0.15,
            threatIntensity: 0.85
          },
          {
            name: 'NL Tor Gateway (Amsterdam)',
            x: centerX + radius * 0.15,
            y: centerY - radius * 0.32,
            threatIntensity: 0.75
          }
        ];

        // Heatmap Overlays for Global Threat Origins
        if (heatmapEnabled) {
          ctx.save();
          ctx.globalCompositeOperation = 'screen';

          for (const org of origins) {
            const bloomRadius = 40 + org.threatIntensity * 35;
            const orgGrad = ctx.createRadialGradient(org.x, org.y, 2, org.x, org.y, bloomRadius);
            orgGrad.addColorStop(0.0, colorStops[5].color);
            orgGrad.addColorStop(0.3, colorStops[4].color);
            orgGrad.addColorStop(0.6, colorStops[3].color);
            orgGrad.addColorStop(1.0, colorStops[0].color);

            ctx.fillStyle = orgGrad;
            ctx.beginPath();
            ctx.arc(org.x, org.y, bloomRadius, 0, Math.PI * 2);
            ctx.fill();
          }

          // Central Sovereign Target Thermal Bloom
          const hubGrad = ctx.createRadialGradient(targetX, targetY, 2, targetX, targetY, 55);
          hubGrad.addColorStop(0.0, colorStops[2].color);
          hubGrad.addColorStop(0.5, colorStops[1].color);
          hubGrad.addColorStop(1.0, colorStops[0].color);
          ctx.fillStyle = hubGrad;
          ctx.beginPath();
          ctx.arc(targetX, targetY, 55, 0, Math.PI * 2);
          ctx.fill();

          ctx.restore();
        }

        ctx.fillStyle = '#00f0ff';
        ctx.beginPath();
        ctx.arc(targetX, targetY, 7, 0, Math.PI * 2);
        ctx.fill();

        ctx.font = 'bold 11px monospace';
        ctx.fillStyle = '#00f0ff';
        ctx.textAlign = 'left';
        ctx.fillText('⚡ SOVEREIGN HUB (London DC)', targetX + 12, targetY + 4);

        for (let i = 0; i < origins.length; i++) {
          const org = origins[i];
          ctx.fillStyle = '#ff0055';
          ctx.beginPath();
          ctx.arc(org.x, org.y, 5, 0, Math.PI * 2);
          ctx.fill();

          ctx.font = '10px monospace';
          ctx.fillStyle = '#fca5a5';
          ctx.textAlign = 'right';
          ctx.fillText(org.name, org.x - 8, org.y + 3);

          ctx.strokeStyle = 'rgba(239, 68, 68, 0.6)';
          ctx.lineWidth = 1.5;
          ctx.beginPath();
          ctx.moveTo(org.x, org.y);
          ctx.quadraticCurveTo(centerX, centerY - radius * 0.65, targetX, targetY);
          ctx.stroke();

          const missileT = (particleOffset + i * 0.22) % 1;
          const mx =
            (1 - missileT) * (1 - missileT) * org.x +
            2 * (1 - missileT) * missileT * centerX +
            missileT * missileT * targetX;
          const my =
            (1 - missileT) * (1 - missileT) * org.y +
            2 * (1 - missileT) * missileT * (centerY - radius * 0.65) +
            missileT * missileT * targetY;

          ctx.fillStyle = '#ff0055';
          ctx.beginPath();
          ctx.arc(mx, my, 4, 0, Math.PI * 2);
          ctx.fill();
        }
      }

      animationFrameId = requestAnimationFrame(render);
    };

    render();
    return () => cancelAnimationFrame(animationFrameId);
  }, [
    nodes,
    attackArcs,
    selectedNodeId,
    viewMode,
    heatmapEnabled,
    heatmapMetric,
    heatmapPalette,
    heatmapRadius,
    heatmapIntensity,
    segmentDensityMetrics
  ]);

  // Filtered Sockets List
  const filteredSockets = useMemo(() => {
    return sockets.filter(s => {
      if (protocolFilter !== 'ALL' && s.protocol !== protocolFilter) return false;
      if (threatFilter !== 'ALL' && s.threatLevel !== threatFilter) return false;
      if (socketFilter.trim()) {
        const query = socketFilter.toLowerCase();
        const match =
          s.srcIp.toLowerCase().includes(query) ||
          s.dstIp.toLowerCase().includes(query) ||
          s.processName.toLowerCase().includes(query) ||
          s.asciiPayload.toLowerCase().includes(query) ||
          s.id.toLowerCase().includes(query);
        if (!match) return false;
      }
      return true;
    });
  }, [sockets, protocolFilter, threatFilter, socketFilter]);

  const selectedNode = nodes.find(n => n.id === selectedNodeId) || nodes[0];
  const selectedNodeMetric = selectedNode ? segmentDensityMetrics[selectedNode.id] : undefined;

  const selectedNodeThroughput = useMemo(() => {
    if (!selectedNode) return null;
    return calculateNodeThroughputProfile(
      selectedNode.id,
      nodes,
      sockets,
      attackArcs,
      selectedNodeMetric
    );
  }, [selectedNode, nodes, sockets, attackArcs, selectedNodeMetric]);

  // Helper to toggle tree route expansion
  const toggleRouteExpand = (routeId: string) => {
    setExpandedRoutes(prev => ({
      ...prev,
      [routeId]: !prev[routeId]
    }));
  };

  // Render Recursive Route Tree Node
  const renderRouteTreeNode = (node: SiteRouteNode, level: number = 0) => {
    const isExpanded = !!expandedRoutes[node.id];
    const hasChildren = node.children && node.children.length > 0;

    const statusBadge =
      node.status === 'UNDER_ATTACK'
        ? 'bg-rose-500/20 text-rose-300 border-rose-500/50'
        : node.status === 'EXPOSED'
          ? 'bg-amber-500/20 text-amber-300 border-amber-500/50'
          : 'bg-emerald-500/20 text-emerald-300 border-emerald-500/50';

    return (
      <div key={node.id} className="space-y-2">
        <div
          className={`flex flex-col items-start justify-between gap-3 rounded-xl border p-3.5 transition md:flex-row md:items-center ${
            node.status === 'UNDER_ATTACK'
              ? 'border-rose-900/60 bg-rose-950/20'
              : node.status === 'EXPOSED'
                ? 'border-amber-900/60 bg-amber-950/20'
                : 'border-slate-800 bg-slate-900/80'
          }`}
          style={{ marginLeft: `${level * 20}px` }}
        >
          <div className="flex items-center gap-3">
            {hasChildren ? (
              <button
                onClick={() => toggleRouteExpand(node.id)}
                className="flex h-6 w-6 items-center justify-center rounded bg-slate-800 text-xs font-bold text-slate-300 hover:bg-slate-700"
              >
                {isExpanded ? '−' : '+'}
              </button>
            ) : (
              <div className="flex h-6 w-6 items-center justify-center text-slate-600">•</div>
            )}

            <div>
              <div className="flex flex-wrap items-center gap-2">
                <code className="rounded border border-slate-800 bg-slate-950 px-2 py-0.5 font-mono text-xs font-bold text-cyan-300">
                  {node.path}
                </code>
                <span className="text-xs font-bold text-slate-200">
                  {isAr ? node.labelAr : node.label}
                </span>
                <span
                  className={`rounded border px-2 py-0.5 font-mono text-[10px] font-bold uppercase ${statusBadge}`}
                >
                  {node.status}
                </span>
              </div>

              {node.activePayloads && node.activePayloads.length > 0 && (
                <div className="mt-1 flex items-center gap-1.5 font-mono text-[11px] text-slate-400">
                  <span className="font-bold text-rose-400">Latest Ingress:</span>
                  <span className="max-w-md truncate text-slate-300">{node.activePayloads[0]}</span>
                </div>
              )}
            </div>
          </div>

          <div className="flex shrink-0 items-center gap-4 font-mono text-xs">
            <div className="text-right">
              <span className="block text-[10px] text-slate-500">RPS</span>
              <span className="font-bold text-slate-200">{node.rps}</span>
            </div>
            <div className="text-right">
              <span className="block text-[10px] text-slate-500">Error Rate</span>
              <span
                className={`font-bold ${node.errorRatePercent > 5 ? 'text-rose-400' : 'text-emerald-400'}`}
              >
                {node.errorRatePercent}%
              </span>
            </div>

            <button
              onClick={() =>
                handleSimulateAttackVector('node-app-core', `Exploit on ${node.path}`, 'HIGH')
              }
              className="flex items-center gap-1 rounded-lg border border-slate-700 bg-slate-950 px-2.5 py-1 text-[11px] font-bold text-slate-300 hover:bg-slate-800 hover:text-white"
              title="Simulate Ingress Attack"
            >
              <Zap className="h-3 w-3 text-amber-400" />
              <span>Probe</span>
            </button>
          </div>
        </div>

        {hasChildren && isExpanded && (
          <div className="ml-4 space-y-2 border-l-2 border-slate-800 pl-2">
            {node.children!.map(child => renderRouteTreeNode(child, level + 1))}
          </div>
        )}
      </div>
    );
  };

  return (
    <div className="space-y-6">
      {/* 1. TOP-LEVEL COMBAT ACTION & INCIDENT CONTROL BAR */}
      <div className="space-y-4 rounded-2xl border border-slate-800 bg-gradient-to-r from-slate-900 via-slate-900/95 to-slate-950 p-5 shadow-2xl">
        <div className="flex flex-col items-start justify-between gap-4 lg:flex-row lg:items-center">
          <div className="flex items-center gap-3.5">
            <div className="flex h-12 w-12 items-center justify-center rounded-xl border border-cyan-500/40 bg-cyan-950/80 p-1 shadow-lg shadow-cyan-950/50">
              <Network className="h-6 w-6 animate-pulse text-cyan-400" />
            </div>
            <div>
              <div className="flex flex-wrap items-center gap-2">
                <h2 className="text-lg font-black tracking-wide text-white">
                  {isAr
                    ? 'منظومة مراقبة الشبكة وتوبولوجيا المقابس الحية (V6.0 Combat Network)'
                    : 'Real-Time Network Topology & Full Site Telemetry'}
                </h2>
                <span className="rounded-full border border-cyan-500/40 bg-cyan-500/20 px-2 py-0.5 font-mono text-xs font-bold text-cyan-300">
                  V6.0 PRODUCTION SOC
                </span>
                {emergencyLockdown && (
                  <span className="animate-pulse rounded-full bg-rose-500 px-2 py-0.5 font-mono text-xs font-bold text-white">
                    ZERO-TRUST LOCKDOWN ACTIVE
                  </span>
                )}
              </div>
              <p className="text-xs font-medium text-slate-400">
                {isAr
                  ? 'مصفوفة المقابس اللحظية، فحص الإطارات العميقة (DPI & Hex Parser)، شجرة مسارات التطبيق وفخاخ الخداع الرقمي'
                  : 'Live socket connection matrix, deep packet hex inspection, hierarchical application surveillance, and honeytoken tripwires'}
              </p>
            </div>
          </div>

          {/* Action Directives Bar */}
          <div className="flex flex-wrap items-center gap-2">
            <button
              onClick={handleToggleEmergencyLockdown}
              disabled={isLoading}
              className={`flex items-center gap-2 rounded-xl px-3.5 py-2 text-xs font-bold shadow-lg transition ${
                emergencyLockdown
                  ? 'bg-emerald-600 text-white ring-2 shadow-emerald-950/50 ring-emerald-400 hover:bg-emerald-500'
                  : 'bg-rose-600 text-white shadow-rose-950/50 hover:bg-rose-500'
              }`}
            >
              <AlertOctagon className="h-4 w-4" />
              <span>
                {emergencyLockdown
                  ? isAr
                    ? 'تعطيل وضع الإغلاق التام'
                    : 'Deactivate Zero-Trust Lockdown'
                  : isAr
                    ? '🚨 إغلاق تام فوري (Zero-Trust)'
                    : '🚨 Zero-Trust Lockdown'}
              </span>
            </button>

            <button
              onClick={() => setShowSubnetModal(true)}
              className="flex items-center gap-2 rounded-xl border border-amber-500/40 bg-slate-950 px-3.5 py-2 text-xs font-bold text-amber-300 transition hover:bg-slate-800"
            >
              <Ban className="h-4 w-4" />
              <span>{isAr ? 'عزل نطاق CIDR' : 'Quarantine CIDR'}</span>
            </button>

            <button
              onClick={handleFlushSockets}
              className="flex items-center gap-2 rounded-xl border border-slate-800 bg-slate-950 px-3.5 py-2 text-xs font-bold text-slate-300 transition hover:bg-slate-800 hover:text-white"
              title="Flush Active Sockets"
            >
              <Zap className="h-4 w-4 text-cyan-400" />
              <span>{isAr ? 'تفريغ المقابس' : 'Flush Sockets'}</span>
            </button>

            <button
              onClick={handleExportPcap}
              className="flex items-center gap-2 rounded-xl border border-cyan-500/40 bg-cyan-950/60 px-3.5 py-2 text-xs font-bold text-cyan-300 transition hover:bg-cyan-900"
              title="Export PCAP / Forensic Audit Log"
            >
              <Download className="h-4 w-4" />
              <span>{isAr ? 'تصدير PCAP' : 'Export PCAP'}</span>
            </button>

            <button
              onClick={() => {
                fetchTopology();
                fetchSockets();
                fetchSiteTree();
                fetchDeceptionTraps();
              }}
              className="rounded-xl border border-slate-800 bg-slate-950 p-2 text-slate-300 transition hover:bg-slate-800"
              title="Refresh All Telemetry"
            >
              <RefreshCw className="h-4 w-4" />
            </button>
          </div>
        </div>

        {/* Sub-Tab Navigation Bar */}
        <div className="flex scrollbar-none items-center space-x-2 overflow-x-auto border-t border-slate-800/80 pt-3">
          <button
            onClick={() => setActiveSubTab('TOPOLOGY_OVERVIEW')}
            className={`flex items-center gap-2 rounded-lg px-3 py-1.5 text-xs font-bold whitespace-nowrap transition ${
              activeSubTab === 'TOPOLOGY_OVERVIEW'
                ? 'border border-cyan-500/50 bg-cyan-500/20 text-cyan-300 shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Globe className="h-3.5 w-3.5" />
            <span>
              {isAr ? 'خريطة التوبولوجيا والمشهد ثلاثي الأبعاد' : 'Topology Graph & Attack Vectors'}
            </span>
          </button>

          <button
            onClick={() => setActiveSubTab('SOCKET_MATRIX')}
            className={`flex items-center gap-2 rounded-lg px-3 py-1.5 text-xs font-bold whitespace-nowrap transition ${
              activeSubTab === 'SOCKET_MATRIX'
                ? 'border border-cyan-500/50 bg-cyan-500/20 text-cyan-300 shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Binary className="h-3.5 w-3.5" />
            <span>
              {isAr
                ? 'مصفوفة المقابس وفحص الإطارات (DPI & Hex)'
                : 'Socket Matrix & Deep Packet Inspection'}
            </span>
            <span className="py-0.2 rounded bg-cyan-950 px-1.5 font-mono text-[10px] text-cyan-400">
              {sockets.length}
            </span>
          </button>

          <button
            onClick={() => setActiveSubTab('SITE_SURVEILLANCE_TREE')}
            className={`flex items-center gap-2 rounded-lg px-3 py-1.5 text-xs font-bold whitespace-nowrap transition ${
              activeSubTab === 'SITE_SURVEILLANCE_TREE'
                ? 'border border-cyan-500/50 bg-cyan-500/20 text-cyan-300 shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <FolderTree className="h-3.5 w-3.5" />
            <span>
              {isAr
                ? 'شجرة مسارات التطبيق والمراقبة اللحظية'
                : 'Hierarchical Site Surveillance Tree'}
            </span>
          </button>

          <button
            onClick={() => setActiveSubTab('HONEYTOKEN_TRAPS')}
            className={`flex items-center gap-2 rounded-lg px-3 py-1.5 text-xs font-bold whitespace-nowrap transition ${
              activeSubTab === 'HONEYTOKEN_TRAPS'
                ? 'border border-cyan-500/50 bg-cyan-500/20 text-cyan-300 shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <ShieldAlert className="h-3.5 w-3.5 text-amber-400" />
            <span>
              {isAr ? 'فخاخ الخداع الرقمي (Honeytokens)' : 'Deception Traps & Honeytokens'}
            </span>
            <span className="py-0.2 rounded bg-amber-950 px-1.5 font-mono text-[10px] text-amber-400">
              {deceptionTraps.length}
            </span>
          </button>
        </div>
      </div>

      {/* ACTION FLASH ALERT */}
      {actionMessage && (
        <div className="animate-fadeIn flex items-center gap-2.5 rounded-xl border border-emerald-500/40 bg-emerald-500/20 p-3.5 text-xs font-bold text-emerald-300">
          <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-400" />
          <span>{actionMessage}</span>
        </div>
      )}

      {/* DEDICATED CSS KEYFRAMES FOR CYBER TOPOLOGY ALERT PULSES */}
      <style>{`
        @keyframes cyberAlertSonarRing {
          0% {
            transform: scale(0.65);
            opacity: 0.95;
            box-shadow: 0 0 0 0 rgba(244, 63, 94, 0.9);
          }
          40% {
            opacity: 0.7;
            box-shadow: 0 0 22px 8px rgba(239, 68, 68, 0.55);
          }
          100% {
            transform: scale(2.9);
            opacity: 0;
            box-shadow: 0 0 50px 18px rgba(239, 68, 68, 0);
          }
        }

        @keyframes cyberElevatedSonarRing {
          0% {
            transform: scale(0.7);
            opacity: 0.85;
            box-shadow: 0 0 0 0 rgba(245, 158, 11, 0.8);
          }
          50% {
            opacity: 0.5;
            box-shadow: 0 0 18px 6px rgba(245, 158, 11, 0.45);
          }
          100% {
            transform: scale(2.4);
            opacity: 0;
            box-shadow: 0 0 38px 14px rgba(245, 158, 11, 0);
          }
        }

        @keyframes cyberAlertAuraGlow {
          0%, 100% {
            transform: scale(1);
            opacity: 0.45;
            filter: drop-shadow(0 0 10px rgba(239, 68, 68, 0.8));
          }
          50% {
            transform: scale(1.28);
            opacity: 0.9;
            filter: drop-shadow(0 0 28px rgba(244, 63, 94, 1));
          }
        }

        @keyframes cyberAlertBeaconPulse {
          0%, 100% {
            transform: scale(1);
            box-shadow: 0 0 12px rgba(239, 68, 68, 0.6);
          }
          50% {
            transform: scale(1.08);
            box-shadow: 0 0 24px rgba(244, 63, 94, 0.95);
          }
        }

        @keyframes cyberThreatRadarSweep {
          0% {
            transform: rotate(0deg);
          }
          100% {
            transform: rotate(360deg);
          }
        }
      `}</style>

      {/* 2. TAB 1: VISUAL TOPOLOGY GRAPH & ATTACK VECTORS */}
      {activeSubTab === 'TOPOLOGY_OVERVIEW' && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
            {/* Visual Canvas Stage (2 cols) */}
            <div className="relative flex flex-col justify-between overflow-hidden rounded-2xl border border-slate-800 bg-slate-950 p-4 shadow-2xl lg:col-span-2">
              <div className="mb-3 flex flex-wrap items-center justify-between gap-2 border-b border-slate-800/80 pb-3">
                <div className="flex items-center gap-2">
                  <span className="h-2.5 w-2.5 animate-pulse rounded-full bg-emerald-400" />
                  <span className="font-mono text-xs font-bold text-slate-300 uppercase">
                    {viewMode === 'INFRASTRUCTURE_MESH'
                      ? 'Real-Time Dynamic Mesh (eBPF / Zero-Copy)'
                      : 'Global Attack Arcs & Ingress Vectors'}
                  </span>
                </div>

                <div className="flex items-center gap-2">
                  <button
                    onClick={() => setViewMode('INFRASTRUCTURE_MESH')}
                    className={`rounded-lg px-2.5 py-1 text-xs font-bold transition ${
                      viewMode === 'INFRASTRUCTURE_MESH'
                        ? 'border border-cyan-500/50 bg-cyan-500/20 text-cyan-300 shadow-sm'
                        : 'text-slate-400 hover:text-white'
                    }`}
                  >
                    Mesh
                  </button>
                  <button
                    onClick={() => setViewMode('GLOBAL_GEOGRAPHIC')}
                    className={`rounded-lg px-2.5 py-1 text-xs font-bold transition ${
                      viewMode === 'GLOBAL_GEOGRAPHIC'
                        ? 'border border-rose-500/50 bg-rose-500/20 text-rose-300 shadow-sm'
                        : 'text-slate-400 hover:text-white'
                    }`}
                  >
                    Globe
                  </button>
                </div>
              </div>

              {/* HEATMAP INTERACTIVE CONTROL TOOLBAR */}
              <div className="mb-3 flex flex-wrap items-center justify-between gap-2.5 rounded-xl border border-slate-800/90 bg-slate-900/90 p-2.5 font-mono text-xs">
                {/* Master Heatmap Switch */}
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => setHeatmapEnabled(!heatmapEnabled)}
                    className={`flex items-center gap-1.5 rounded-lg px-3 py-1.5 font-bold transition ${
                      heatmapEnabled
                        ? 'bg-gradient-to-r from-orange-600 to-rose-600 text-white shadow-lg ring-1 shadow-orange-950/50 ring-orange-400'
                        : 'border border-slate-800 bg-slate-950 text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    <Flame
                      className={`h-3.5 w-3.5 ${heatmapEnabled ? 'animate-pulse text-amber-200' : 'text-slate-500'}`}
                    />
                    <span>
                      {heatmapEnabled
                        ? isAr
                          ? 'الخريطة الحرارية: نشطة'
                          : 'Heatmap: ACTIVE'
                        : isAr
                          ? 'الخريطة الحرارية: معطلة'
                          : 'Heatmap: OFF'}
                    </span>
                  </button>
                </div>

                {heatmapEnabled && (
                  <div className="flex flex-wrap items-center gap-2">
                    {/* Metric Selector */}
                    <div className="flex items-center gap-1 rounded-lg border border-slate-800 bg-slate-950 p-1">
                      <span className="px-1 font-sans text-[10px] text-slate-500">
                        {isAr ? 'المعيار:' : 'Metric:'}
                      </span>
                      <button
                        onClick={() => setHeatmapMetric('THREAT_SEVERITY')}
                        className={`rounded px-2 py-0.5 text-[11px] font-bold ${
                          heatmapMetric === 'THREAT_SEVERITY'
                            ? 'border border-rose-500/50 bg-rose-500/20 text-rose-300'
                            : 'text-slate-400 hover:text-white'
                        }`}
                      >
                        ⚡ {isAr ? 'خطورة التهديد' : 'Threat'}
                      </button>
                      <button
                        onClick={() => setHeatmapMetric('TRAFFIC_VOLUME')}
                        className={`rounded px-2 py-0.5 text-[11px] font-bold ${
                          heatmapMetric === 'TRAFFIC_VOLUME'
                            ? 'border border-cyan-500/50 bg-cyan-500/20 text-cyan-300'
                            : 'text-slate-400 hover:text-white'
                        }`}
                      >
                        📊 {isAr ? 'حجم المرور' : 'Traffic'}
                      </button>
                      <button
                        onClick={() => setHeatmapMetric('LATENCY_CONGESTION')}
                        className={`rounded px-2 py-0.5 text-[11px] font-bold ${
                          heatmapMetric === 'LATENCY_CONGESTION'
                            ? 'border border-amber-500/50 bg-amber-500/20 text-amber-300'
                            : 'text-slate-400 hover:text-white'
                        }`}
                      >
                        ⏱️ {isAr ? 'الاستجابة' : 'Latency'}
                      </button>
                      <button
                        onClick={() => setHeatmapMetric('ANOMALY_INDEX')}
                        className={`rounded px-2 py-0.5 text-[11px] font-bold ${
                          heatmapMetric === 'ANOMALY_INDEX'
                            ? 'border border-purple-500/50 bg-purple-500/20 text-purple-300'
                            : 'text-slate-400 hover:text-white'
                        }`}
                      >
                        🛡️ {isAr ? 'الشذوذ' : 'Anomaly'}
                      </button>
                    </div>

                    {/* Palette Selector */}
                    <div className="flex items-center gap-1 rounded-lg border border-slate-800 bg-slate-950 p-1">
                      <span className="px-1 font-sans text-[10px] text-slate-500">
                        {isAr ? 'النمط:' : 'Palette:'}
                      </span>
                      <button
                        onClick={() => setHeatmapPalette('PLASMA')}
                        className={`rounded px-2 py-0.5 text-[11px] font-bold ${
                          heatmapPalette === 'PLASMA'
                            ? 'border border-cyan-400 bg-cyan-500/30 text-cyan-200'
                            : 'text-slate-400 hover:text-white'
                        }`}
                      >
                        Plasma
                      </button>
                      <button
                        onClick={() => setHeatmapPalette('INFERNO')}
                        className={`rounded px-2 py-0.5 text-[11px] font-bold ${
                          heatmapPalette === 'INFERNO'
                            ? 'border border-orange-400 bg-orange-500/30 text-orange-200'
                            : 'text-slate-400 hover:text-white'
                        }`}
                      >
                        Inferno
                      </button>
                      <button
                        onClick={() => setHeatmapPalette('TOXIC_RADAR')}
                        className={`rounded px-2 py-0.5 text-[11px] font-bold ${
                          heatmapPalette === 'TOXIC_RADAR'
                            ? 'border border-lime-400 bg-lime-500/30 text-lime-200'
                            : 'text-slate-400 hover:text-white'
                        }`}
                      >
                        FLIR
                      </button>
                    </div>

                    {/* Settings / Tuners toggle */}
                    <button
                      onClick={() => setShowHeatmapSettings(!showHeatmapSettings)}
                      className={`rounded-lg border p-1.5 transition ${
                        showHeatmapSettings
                          ? 'border-cyan-500 bg-slate-800 text-cyan-300'
                          : 'border-slate-800 bg-slate-950 text-slate-400 hover:text-white'
                      }`}
                      title="Adjust Heatmap Calibration"
                    >
                      <Sliders className="h-3.5 w-3.5" />
                    </button>

                    {/* Heatmap Legend Toggle */}
                    <button
                      onClick={() => setShowHeatmapLegend(!showHeatmapLegend)}
                      className={`flex items-center gap-1.5 rounded-lg border px-2 py-1 text-[11px] font-bold transition ${
                        showHeatmapLegend
                          ? 'border-orange-500/50 bg-orange-500/20 text-orange-300 shadow-sm'
                          : 'border-slate-800 bg-slate-950 text-slate-400 hover:text-white'
                      }`}
                      title={isAr ? 'تبديل دليل الشدة الحرارية' : 'Toggle Heatmap Intensity Legend'}
                    >
                      <Info className="h-3.5 w-3.5 text-orange-400" />
                      <span className="hidden sm:inline">{isAr ? 'دليل الشدة' : 'Legend'}</span>
                    </button>
                  </div>
                )}
              </div>

              {/* CALIBRATION SLIDERS PANEL (Collapsible) */}
              {heatmapEnabled && showHeatmapSettings && (
                <div className="animate-fadeIn mb-3 grid grid-cols-1 gap-4 rounded-xl border border-cyan-500/30 bg-slate-900/95 p-3 font-mono text-xs sm:grid-cols-3">
                  <div>
                    <div className="mb-1 flex justify-between text-[11px] text-slate-400">
                      <span>{isAr ? 'نصف القطر الحراري:' : 'Thermal Radius:'}</span>
                      <span className="font-bold text-cyan-300">{heatmapRadius}px</span>
                    </div>
                    <input
                      type="range"
                      min={30}
                      max={120}
                      value={heatmapRadius}
                      onChange={e => setHeatmapRadius(Number(e.target.value))}
                      className="h-1.5 w-full cursor-pointer appearance-none rounded-lg bg-slate-950 accent-cyan-400"
                    />
                  </div>

                  <div>
                    <div className="mb-1 flex justify-between text-[11px] text-slate-400">
                      <span>{isAr ? 'كثافة الإشعاع:' : 'Heat Intensity:'}</span>
                      <span className="font-bold text-orange-300">
                        {Math.round(heatmapIntensity * 100)}%
                      </span>
                    </div>
                    <input
                      type="range"
                      min={0.3}
                      max={1.0}
                      step={0.05}
                      value={heatmapIntensity}
                      onChange={e => setHeatmapIntensity(Number(e.target.value))}
                      className="h-1.5 w-full cursor-pointer appearance-none rounded-lg bg-slate-950 accent-orange-400"
                    />
                  </div>

                  <div>
                    <div className="mb-1 flex justify-between text-[11px] text-slate-400">
                      <span>{isAr ? 'نعومة التلاشي:' : 'Blur Gradient:'}</span>
                      <span className="font-bold text-emerald-300">{heatmapBlur}px</span>
                    </div>
                    <input
                      type="range"
                      min={10}
                      max={50}
                      value={heatmapBlur}
                      onChange={e => setHeatmapBlur(Number(e.target.value))}
                      className="h-1.5 w-full cursor-pointer appearance-none rounded-lg bg-slate-950 accent-emerald-400"
                    />
                  </div>
                </div>
              )}

              <div className="relative flex h-[440px] w-full cursor-crosshair items-center justify-center overflow-hidden rounded-xl border border-slate-900 bg-slate-950">
                <canvas
                  ref={canvasRef}
                  width={800}
                  height={440}
                  onMouseMove={handleCanvasMouseMove}
                  onMouseLeave={handleCanvasMouseLeave}
                  onClick={handleCanvasClick}
                  className="h-full w-full object-cover"
                />

                {/* CSS-DRIVEN PULSE ANIMATION & ACTIVE THREAT ALERT ZONES OVERLAY */}
                <div className="pointer-events-none absolute inset-0 z-10 overflow-hidden">
                  {viewMode === 'INFRASTRUCTURE_MESH' &&
                    nodes.map(node => {
                      const posRatioMap: Record<string, { left: string; top: string }> = {
                        'node-ingress-waf': { left: '18%', top: '50%' },
                        'node-ai-filter': { left: '42%', top: '28%' },
                        'node-app-core': { left: '42%', top: '72%' },
                        'node-storage-fim': { left: '68%', top: '28%' },
                        'node-database': { left: '68%', top: '72%' },
                        'node-honeypot': { left: '88%', top: '50%' }
                      };

                      const pos = posRatioMap[node.id] || { left: '50%', top: '50%' };
                      const metric = segmentDensityMetrics[node.id];
                      const isOverheat =
                        metric?.thermalStatus === 'CRITICAL_OVERHEAT' ||
                        node.status === 'UNDER_ATTACK' ||
                        (metric?.densityScore || 0) >= 0.7;
                      const isElevated =
                        metric?.thermalStatus === 'ELEVATED_HEAT' ||
                        ((metric?.densityScore || 0) >= 0.4 && !isOverheat);
                      const isHighThreat = isOverheat || isElevated;

                      if (!isHighThreat) return null;

                      return (
                        <div
                          key={`threat-pulse-${node.id}`}
                          className="pointer-events-none absolute flex -translate-x-1/2 -translate-y-1/2 items-center justify-center"
                          style={{ left: pos.left, top: pos.top }}
                        >
                          {/* CRITICAL OVERHEAT ZONE: Triple Sonar Pulse Shockwaves & Radial Flame Aura */}
                          {isOverheat && (
                            <>
                              {/* Ambient Danger Glow Breathing Aura */}
                              <div
                                className="pointer-events-none absolute h-32 w-32 rounded-full bg-rose-600/35 blur-xl"
                                style={{ animation: 'cyberAlertAuraGlow 2s ease-in-out infinite' }}
                              />

                              {/* Concentric Sonar Pulse Rings */}
                              <div
                                className="pointer-events-none absolute h-16 w-16 rounded-full border-2 border-rose-500"
                                style={{
                                  animation:
                                    'cyberAlertSonarRing 2.4s cubic-bezier(0, 0.2, 0.8, 1) infinite'
                                }}
                              />
                              <div
                                className="pointer-events-none absolute h-16 w-16 rounded-full border-2 border-rose-400"
                                style={{
                                  animation:
                                    'cyberAlertSonarRing 2.4s cubic-bezier(0, 0.2, 0.8, 1) infinite 0.8s'
                                }}
                              />
                              <div
                                className="pointer-events-none absolute h-16 w-16 rounded-full border border-orange-400"
                                style={{
                                  animation:
                                    'cyberAlertSonarRing 2.4s cubic-bezier(0, 0.2, 0.8, 1) infinite 1.6s'
                                }}
                              />

                              {/* Floating Alert Beacon Pill Badge */}
                              <button
                                onClick={e => {
                                  e.stopPropagation();
                                  setSelectedNodeId(node.id);
                                }}
                                className="pointer-events-auto absolute -top-11 z-30 flex cursor-pointer items-center gap-1 rounded-full border border-rose-500 bg-rose-950/95 px-2 py-0.5 font-mono text-[9px] font-bold tracking-wider text-rose-200 uppercase shadow-xl shadow-rose-950/90 transition-transform hover:scale-105"
                                style={{
                                  animation: 'cyberAlertBeaconPulse 1.4s ease-in-out infinite'
                                }}
                                title={
                                  isAr
                                    ? 'انقر للتركيز على بؤرة الإنذار'
                                    : 'Click to lock onto Alert Zone'
                                }
                              >
                                <span className="relative flex h-2 w-2">
                                  <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-rose-400 opacity-80"></span>
                                  <span className="relative inline-flex h-2 w-2 rounded-full bg-rose-500"></span>
                                </span>
                                <span>{isAr ? 'بؤرة إنذار حرجة' : 'CRITICAL ALERT'}</span>
                                <span className="py-0.2 rounded border border-rose-600/50 bg-rose-900/80 px-1 font-bold text-white">
                                  {Math.round((metric?.densityScore || 0.85) * 100)}%
                                </span>
                              </button>
                            </>
                          )}

                          {/* ELEVATED SURGE ZONE: Dual Sonar Pulse Shockwaves */}
                          {isElevated && !isOverheat && (
                            <>
                              {/* Ambient Amber Glow */}
                              <div
                                className="pointer-events-none absolute h-24 w-24 rounded-full bg-amber-500/25 blur-lg"
                                style={{
                                  animation: 'cyberAlertAuraGlow 2.5s ease-in-out infinite'
                                }}
                              />

                              {/* Dual Concentric Elevated Pulse Rings */}
                              <div
                                className="pointer-events-none absolute h-14 w-14 rounded-full border-2 border-amber-500"
                                style={{
                                  animation:
                                    'cyberElevatedSonarRing 2.6s cubic-bezier(0, 0.2, 0.8, 1) infinite'
                                }}
                              />
                              <div
                                className="pointer-events-none absolute h-14 w-14 rounded-full border border-yellow-400"
                                style={{
                                  animation:
                                    'cyberElevatedSonarRing 2.6s cubic-bezier(0, 0.2, 0.8, 1) infinite 1.3s'
                                }}
                              />

                              {/* Floating Surge Pill Badge */}
                              <button
                                onClick={e => {
                                  e.stopPropagation();
                                  setSelectedNodeId(node.id);
                                }}
                                className="pointer-events-auto absolute -top-11 z-30 flex cursor-pointer items-center gap-1 rounded-full border border-amber-500 bg-amber-950/90 px-2 py-0.5 font-mono text-[9px] font-bold tracking-wider text-amber-200 uppercase shadow-lg shadow-amber-950/70 transition-transform hover:scale-105"
                                style={{
                                  animation: 'cyberAlertBeaconPulse 2s ease-in-out infinite'
                                }}
                                title={
                                  isAr
                                    ? 'انقر للتركيز على تدفق التهديد'
                                    : 'Click to inspect elevated surge'
                                }
                              >
                                <span className="relative flex h-2 w-2">
                                  <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-amber-400 opacity-80"></span>
                                  <span className="relative inline-flex h-2 w-2 rounded-full bg-amber-500"></span>
                                </span>
                                <span>{isAr ? 'تدفق مرتفع' : 'ELEVATED SURGE'}</span>
                                <span className="py-0.2 rounded border border-amber-600/50 bg-amber-900/80 px-1 font-bold text-amber-100">
                                  {Math.round((metric?.densityScore || 0.5) * 100)}%
                                </span>
                              </button>
                            </>
                          )}
                        </div>
                      );
                    })}

                  {/* GLOBAL GEOGRAPHIC VIEW ALERT PULSES */}
                  {viewMode === 'GLOBAL_GEOGRAPHIC' && (
                    <>
                      {/* Moscow Threat Cluster */}
                      <div
                        className="pointer-events-none absolute -translate-x-1/2 -translate-y-1/2"
                        style={{ left: '72.5%', top: '33.2%' }}
                      >
                        <div
                          className="h-12 w-12 rounded-full border-2 border-rose-500"
                          style={{
                            animation:
                              'cyberAlertSonarRing 2.2s cubic-bezier(0, 0.2, 0.8, 1) infinite'
                          }}
                        />
                      </div>
                      {/* California Botnet Hive */}
                      <div
                        className="pointer-events-none absolute -translate-x-1/2 -translate-y-1/2"
                        style={{ left: '17.5%', top: '43.7%' }}
                      >
                        <div
                          className="h-12 w-12 rounded-full border-2 border-rose-500"
                          style={{
                            animation:
                              'cyberAlertSonarRing 2.2s cubic-bezier(0, 0.2, 0.8, 1) infinite 0.7s'
                          }}
                        />
                      </div>
                    </>
                  )}
                </div>

                {/* INTERACTIVE FLOATING HUD TOOLTIP ON HOVER */}
                {hoveredHeatPoint && (
                  <div
                    className="pointer-events-none absolute -top-3 z-20 min-w-[220px] -translate-x-1/2 -translate-y-full transform rounded-xl border border-cyan-500/50 bg-slate-950/95 p-3 font-mono text-xs shadow-2xl backdrop-blur-md transition-all"
                    style={{
                      left: `${hoveredHeatPoint.x}px`,
                      top: `${hoveredHeatPoint.y - 12}px`
                    }}
                  >
                    <div className="mb-2 flex items-center justify-between border-b border-slate-800 pb-1.5">
                      <div className="flex items-center gap-1.5 font-bold text-white">
                        <Flame className="h-3.5 w-3.5 animate-pulse text-orange-400" />
                        <span>{isAr ? hoveredHeatPoint.labelAr : hoveredHeatPoint.label}</span>
                      </div>
                      <span className="rounded border border-cyan-500/40 bg-cyan-950 px-1.5 py-0.5 text-[10px] font-bold text-cyan-300">
                        {hoveredHeatPoint.vlan}
                      </span>
                    </div>

                    <div className="space-y-1 text-[11px]">
                      <div className="flex justify-between">
                        <span className="text-slate-400">
                          {isAr ? 'كثافة التهديد:' : 'Thermal Density:'}
                        </span>
                        <span
                          className={`font-bold ${hoveredHeatPoint.densityScore > 0.6 ? 'text-rose-400' : hoveredHeatPoint.densityScore > 0.3 ? 'text-amber-400' : 'text-emerald-400'}`}
                        >
                          {Math.round(hoveredHeatPoint.densityScore * 100)}% (
                          {hoveredHeatPoint.thermalStatus})
                        </span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-slate-400">
                          {isAr ? 'المقابس النشطة:' : 'Active Sockets:'}
                        </span>
                        <span className="text-slate-200">
                          {hoveredHeatPoint.activeSockets} ({hoveredHeatPoint.maliciousPct}% bad)
                        </span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-slate-400">
                          {isAr ? 'الحمل اللحظي:' : 'Active Load:'}
                        </span>
                        <span className="font-bold text-cyan-300">
                          {hoveredHeatPoint.activeLoad}%
                        </span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-slate-400">
                          {isAr ? 'زمن الاستجابة:' : 'Ping / Latency:'}
                        </span>
                        <span className="text-slate-300">{hoveredHeatPoint.latencyMs}ms</span>
                      </div>
                    </div>

                    <div className="mt-2 border-t border-slate-800/80 pt-1.5 text-center text-[10px] text-cyan-400">
                      {isAr
                        ? 'انقر للقفل على العقدة في لوحة التحكم'
                        : 'Click to inspect & control node'}
                    </div>
                  </div>
                )}

                {/* FLOATING HEATMAP INTENSITY & PACKET DENSITY CORRELATION LEGEND */}
                {heatmapEnabled && showHeatmapLegend && (
                  <div
                    className={`absolute bottom-3 ${isAr ? 'right-3' : 'left-3'} z-20 max-w-[340px] overflow-hidden rounded-xl border border-slate-700/80 bg-slate-950/95 font-mono text-xs shadow-2xl backdrop-blur-md transition-all duration-300 select-none sm:max-w-[385px]`}
                  >
                    {/* Legend Header */}
                    <div className="flex items-center justify-between gap-2 border-b border-slate-800 bg-slate-900/90 p-2.5">
                      <div className="flex items-center gap-2">
                        <div className="flex h-5 w-5 shrink-0 items-center justify-center rounded-lg border border-orange-500/40 bg-orange-500/20 text-orange-300">
                          <Flame className="h-3.5 w-3.5 animate-pulse" />
                        </div>
                        <div>
                          <div className="flex items-center gap-1.5 text-[11px] leading-tight font-bold text-white">
                            <span>
                              {isAr
                                ? 'مقياس الشدة والتشبع الحراري'
                                : 'Threat Heatmap Intensity Scale'}
                            </span>
                          </div>
                          <div className="text-[9px] text-slate-400">
                            {isAr
                              ? 'علاقة كثافة الحزم/التهديدات بدرجة تشبع اللون'
                              : 'Packet & Threat Density vs. Saturation'}
                          </div>
                        </div>
                      </div>

                      <div className="flex items-center gap-1">
                        <button
                          onClick={e => {
                            e.stopPropagation();
                            setLegendExpanded(!legendExpanded);
                          }}
                          className="rounded-md border border-slate-700 bg-slate-800 p-1 text-slate-300 transition hover:text-white"
                          title={
                            legendExpanded
                              ? isAr
                                ? 'طي التفاصيل'
                                : 'Collapse details'
                              : isAr
                                ? 'توسيع التفاصيل'
                                : 'Expand details'
                          }
                        >
                          {legendExpanded ? (
                            <ChevronUp className="h-3.5 w-3.5" />
                          ) : (
                            <ChevronDown className="h-3.5 w-3.5" />
                          )}
                        </button>
                        <button
                          onClick={e => {
                            e.stopPropagation();
                            setShowHeatmapLegend(false);
                          }}
                          className="rounded-md border border-slate-700 bg-slate-800/60 p-1 text-slate-400 transition hover:text-rose-300"
                          title={isAr ? 'إخفاء الدليل' : 'Hide Legend'}
                        >
                          <X className="h-3.5 w-3.5" />
                        </button>
                      </div>
                    </div>

                    {/* Continuous Color Gradient Bar */}
                    <div className="space-y-2.5 p-3">
                      {/* Palette info tag */}
                      <div className="flex items-center justify-between text-[10px]">
                        <span className="font-sans text-slate-400">
                          {isAr ? 'النمط اللوني الفعال:' : 'Active Thermal Palette:'}
                        </span>
                        <span className="rounded border border-slate-800 bg-slate-900 px-1.5 py-0.5 font-bold text-cyan-300">
                          {isAr
                            ? getPaletteConfig(heatmapPalette).nameAr
                            : getPaletteConfig(heatmapPalette).name}
                        </span>
                      </div>

                      {/* Gradient Bar with Ticks */}
                      <div className="space-y-1">
                        <div
                          className={`h-3.5 w-full rounded-md bg-gradient-to-r ${getPaletteConfig(heatmapPalette).gradientCss} relative overflow-hidden border border-slate-700/60 shadow-inner`}
                        >
                          {/* Subtle Scanline Overlay */}
                          <div className="absolute inset-0 animate-pulse bg-[linear-gradient(90deg,transparent_0%,rgba(255,255,255,0.2)_50%,transparent_100%)] opacity-40" />
                        </div>
                        {/* Scale Percentage Markers */}
                        <div className="flex justify-between px-0.5 font-mono text-[9px] text-slate-400">
                          <span>0% (Cold)</span>
                          <span>25%</span>
                          <span>50%</span>
                          <span>75%</span>
                          <span className="font-bold text-rose-400">100% (Crit)</span>
                        </div>
                      </div>

                      {/* 4-Tier Qualitative Range Spectrum */}
                      <div className="grid grid-cols-4 gap-1 pt-0.5 text-center text-[9px]">
                        <div className="flex flex-col rounded border border-slate-800 bg-slate-900/80 p-1">
                          <span className="font-bold text-cyan-300">
                            {isAr ? 'طبيعي' : 'Nominal'}
                          </span>
                          <span className="mt-0.5 text-[8px] text-slate-400">&lt;25% Sat</span>
                        </div>
                        <div className="flex flex-col rounded border border-slate-800 bg-slate-900/80 p-1">
                          <span className="font-bold text-amber-300">
                            {isAr ? 'مرتفع' : 'Elevated'}
                          </span>
                          <span className="mt-0.5 text-[8px] text-slate-400">25-50% Sat</span>
                        </div>
                        <div className="flex flex-col rounded border border-slate-800 bg-slate-900/80 p-1">
                          <span className="font-bold text-orange-400">
                            {isAr ? 'شديد' : 'Surge'}
                          </span>
                          <span className="mt-0.5 text-[8px] text-slate-400">50-75% Sat</span>
                        </div>
                        <div className="flex flex-col rounded border border-rose-500/40 bg-rose-950/20 bg-slate-900/80 p-1">
                          <span className="animate-pulse font-bold text-rose-400">
                            {isAr ? 'حرج' : 'Critical'}
                          </span>
                          <span className="mt-0.5 text-[8px] text-rose-300">75-100% Sat</span>
                        </div>
                      </div>

                      {/* Expanded Detailed Breakdown */}
                      {legendExpanded && (
                        <div className="animate-fadeIn mt-2 space-y-2 border-t border-slate-800/80 pt-2.5 text-[10px]">
                          <div className="flex items-center gap-1.5 font-semibold text-slate-300">
                            <Activity className="h-3 w-3 text-cyan-400" />
                            <span>
                              {isAr
                                ? 'تفسير الارتباط الرياضي والفيزيائي:'
                                : 'Correlation Matrix & Physics:'}
                            </span>
                          </div>

                          <div className="space-y-1.5 text-[10px] leading-relaxed text-slate-400">
                            <div className="space-y-1 rounded-lg border border-slate-800 bg-slate-900/90 p-2">
                              <div className="flex items-center justify-between font-bold text-slate-200">
                                <span className="flex items-center gap-1">
                                  <span className="h-2 w-2 rounded-full bg-cyan-400" />
                                  {isAr
                                    ? 'درجة تشبع اللون (Saturation / α):'
                                    : 'Color Saturation (α Opacity):'}
                                </span>
                                <span className="text-cyan-300">0.0 → 1.0</span>
                              </div>
                              <p className="text-[9px] text-slate-400">
                                {isAr
                                  ? 'يتناسب تشبع اللون طردياً مع تدفق الحزم الخبيثة ومعدل الاستغلال. تزداد الشدة من الشفافية التامة عند الاستقرار إلى التوهج النيوني الصريح عند ذروة الهجوم.'
                                  : 'Directly proportional to malicious packet velocity and exploit payloads. Transitions from cold transparency at idle to intense neon saturation at attack peak.'}
                              </p>
                            </div>

                            <div className="space-y-1 rounded-lg border border-slate-800 bg-slate-900/90 p-2">
                              <div className="flex items-center justify-between font-bold text-slate-200">
                                <span className="flex items-center gap-1">
                                  <span className="h-2 w-2 rounded-full bg-orange-400" />
                                  {isAr
                                    ? 'نصف القطر الحراري والتشتت:'
                                    : 'Thermal Radius & Dissipation:'}
                                </span>
                                <span className="text-orange-300">30px → 120px</span>
                              </div>
                              <p className="text-[9px] text-slate-400">
                                {isAr
                                  ? 'تتسع هالة التوهج الدائرية حول العقدة المصابة مع ارتفاع عدد المقابس المخترقة أو انتشار هجمات الحرمان من الخدمة (DDoS).'
                                  : 'Radial bloom expands outward based on concurrent infected socket connections and lateral movement attempts.'}
                              </p>
                            </div>

                            <div className="space-y-1 rounded-lg border border-slate-800 bg-slate-900/90 p-2">
                              <div className="flex items-center justify-between font-bold text-slate-200">
                                <span className="flex items-center gap-1">
                                  <span className="h-2 w-2 animate-ping rounded-full bg-rose-500" />
                                  {isAr
                                    ? 'النواة البيضاء الساخنة (Hot Core):'
                                    : 'White-Hot Saturation Core:'}
                                </span>
                                <span className="text-rose-300">100% Saturation</span>
                              </div>
                              <p className="text-[9px] text-slate-400">
                                {isAr
                                  ? 'تدل على مركز بؤرة الهجوم اللحظي، مثل محاولات حقن SQLi أو RCE النشطة أو تسريب البيانات الحرج.'
                                  : 'Indicates the absolute ground zero of active zero-day exploitation, command execution, or mass exfiltration.'}
                              </p>
                            </div>
                          </div>

                          <div className="flex items-center justify-between border-t border-slate-800/60 pt-1 font-sans text-[9px] text-slate-500">
                            <span>{isAr ? 'المعيار المقاس اللحظي:' : 'Current Live Metric:'}</span>
                            <span className="font-mono font-bold text-cyan-400">
                              {heatmapMetric.replace('_', ' ')}
                            </span>
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                )}

                {/* Minimized / Collapsed Floating Pill Indicator */}
                {heatmapEnabled && !showHeatmapLegend && (
                  <button
                    onClick={() => setShowHeatmapLegend(true)}
                    className={`absolute bottom-3 ${isAr ? 'right-3' : 'left-3'} z-20 flex items-center gap-1.5 rounded-lg border border-slate-700/80 bg-slate-950/90 px-2.5 py-1.5 font-mono text-xs text-slate-300 shadow-lg backdrop-blur-md transition hover:text-white`}
                  >
                    <Flame className="h-3.5 w-3.5 text-orange-400" />
                    <span>{isAr ? 'إظهار دليل الشدة' : 'Show Intensity Legend'}</span>
                  </button>
                )}
              </div>

              {/* Fast Node Switcher Bar */}
              <div className="mt-4 grid grid-cols-3 gap-2 border-t border-slate-800/80 pt-3 sm:grid-cols-6">
                {nodes.map(n => {
                  const isSelected = selectedNodeId === n.id;
                  const isIso = n.status === 'ISOLATED';
                  const isAtk = n.status === 'UNDER_ATTACK';
                  const metric = segmentDensityMetrics[n.id];
                  const isOverheat = metric?.thermalStatus === 'CRITICAL_OVERHEAT' || isAtk;
                  const isElevated = metric?.thermalStatus === 'ELEVATED_HEAT';

                  return (
                    <button
                      key={n.id}
                      onClick={() => setSelectedNodeId(n.id)}
                      className={`relative overflow-hidden rounded-xl border p-2 text-left font-mono text-xs transition ${
                        isSelected
                          ? 'border-cyan-500 bg-cyan-500/20 text-cyan-300 shadow-sm'
                          : isOverheat
                            ? 'animate-pulse border-rose-500/80 bg-rose-950/50 text-rose-200 shadow-lg ring-1 shadow-rose-950/50 ring-rose-500/60'
                            : isElevated
                              ? 'border-amber-500/60 bg-amber-950/40 text-amber-300 shadow-sm'
                              : isIso
                                ? 'border-rose-800 bg-rose-950/30 text-rose-300'
                                : 'border-slate-800 bg-slate-900/80 text-slate-400 hover:text-slate-200'
                      }`}
                    >
                      {/* Active Alert Zone Ping Dot on High Threat */}
                      {isOverheat && (
                        <span className="absolute top-1.5 right-1.5 flex h-2 w-2">
                          <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-rose-400 opacity-80"></span>
                          <span className="relative inline-flex h-2 w-2 rounded-full bg-rose-500"></span>
                        </span>
                      )}
                      <div className="flex items-center justify-between pr-2">
                        <span className="truncate text-[10px] font-bold">
                          {n.id.replace('node-', '')}
                        </span>
                        {!isOverheat && (
                          <span
                            className={`h-1.5 w-1.5 rounded-full ${isIso ? 'bg-rose-500' : isElevated ? 'bg-amber-400' : 'bg-emerald-400'}`}
                          />
                        )}
                      </div>
                      <div className="mt-1 flex items-center justify-between truncate text-[9px] text-slate-500">
                        <span>{n.ipAddress}</span>
                        {metric && (
                          <span
                            className={`text-[8px] font-bold ${isOverheat ? 'text-rose-400' : isElevated ? 'text-amber-400' : 'text-slate-500'}`}
                          >
                            {Math.round(metric.densityScore * 100)}%
                          </span>
                        )}
                      </div>
                    </button>
                  );
                })}
              </div>
            </div>

            {/* Node Telemetry & Defensive Controller Sidebar (1 col) */}
            <div className="flex flex-col justify-between space-y-4 rounded-2xl border border-slate-800 bg-slate-900/90 p-5 shadow-2xl">
              <div className="space-y-4">
                <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                  <div className="flex items-center gap-2">
                    <Server className="h-5 w-5 text-cyan-400" />
                    <h3 className="text-sm font-bold text-white">
                      {isAr ? 'تفاصيل وتحكم العقدة المحددة' : 'Selected Node Telemetry'}
                    </h3>
                  </div>
                  <div className="flex items-center gap-2">
                    <span
                      className={`rounded-full px-2.5 py-0.5 font-mono text-[10px] font-bold uppercase ${
                        selectedNode?.status === 'ISOLATED'
                          ? 'bg-rose-500 text-white'
                          : selectedNode?.status === 'UNDER_ATTACK'
                            ? 'animate-pulse bg-amber-500 text-slate-950'
                            : 'border border-emerald-500/40 bg-emerald-500/20 text-emerald-300'
                      }`}
                    >
                      {selectedNode?.status || 'UNKNOWN'}
                    </span>
                    <button
                      onClick={() => {
                        setIsNodeExpanded(true);
                        setExpandedNodeSubTab('THROUGHPUT');
                      }}
                      className="flex items-center gap-1 rounded-lg border border-cyan-500/50 bg-cyan-950/80 p-1.5 font-mono text-xs font-bold text-cyan-300 shadow-md shadow-cyan-950/40 transition hover:scale-105 hover:bg-cyan-900"
                      title={isAr ? 'توسيع الفحص العميق للعقدة' : 'Expand Deep Inspector'}
                    >
                      <Maximize2 className="h-3.5 w-3.5" />
                      <span className="hidden sm:inline">{isAr ? 'توسيع' : 'Expand'}</span>
                    </button>
                  </div>
                </div>

                {/* HIGH INTENSITY ALERT ZONE WARNING BANNER (CSS PULSE DRIVEN) */}
                {selectedNode &&
                  segmentDensityMetrics[selectedNode.id] &&
                  (segmentDensityMetrics[selectedNode.id].thermalStatus === 'CRITICAL_OVERHEAT' ||
                    selectedNode.status === 'UNDER_ATTACK') && (
                    <div
                      className="flex items-center justify-between gap-2 rounded-xl border border-rose-500/80 bg-rose-950/80 p-3 font-mono text-xs text-rose-200 shadow-xl shadow-rose-950/70"
                      style={{ animation: 'cyberAlertBeaconPulse 1.8s ease-in-out infinite' }}
                    >
                      <div className="flex items-center gap-2">
                        <span className="relative flex h-3 w-3 shrink-0">
                          <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-rose-400 opacity-80"></span>
                          <span className="relative inline-flex h-3 w-3 rounded-full bg-rose-500"></span>
                        </span>
                        <div>
                          <div className="text-[11px] leading-tight font-bold text-white">
                            {isAr
                              ? '🚨 بؤرة هجوم نشطة عالية الكثافة'
                              : '🚨 ACTIVE THREAT ALERT ZONE'}
                          </div>
                          <div className="text-[9px] text-rose-300">
                            {isAr
                              ? 'تجاوزت كثافة الحزم الخبيثة عتبة الخطر'
                              : 'Malicious packet velocity exceeds critical threshold'}
                          </div>
                        </div>
                      </div>
                      <span className="shrink-0 rounded bg-rose-600 px-2 py-0.5 text-[10px] font-bold text-white">
                        {Math.round(segmentDensityMetrics[selectedNode.id].densityScore * 100)}%
                        HEAT
                      </span>
                    </div>
                  )}

                {selectedNode && (
                  <div className="space-y-3 font-mono text-xs">
                    <div className="flex items-center justify-between">
                      <div>
                        <span className="block text-[10px] text-slate-400">Node Name:</span>
                        <span className="text-sm font-bold text-slate-100">
                          {isAr ? selectedNode.labelAr : selectedNode.label}
                        </span>
                      </div>
                      <span className="rounded border border-slate-800 bg-slate-950 px-2 py-0.5 font-mono text-[10px] text-cyan-400">
                        {selectedNode.id}
                      </span>
                    </div>

                    <div className="grid grid-cols-2 gap-2.5 rounded-xl border border-slate-800 bg-slate-950 p-2.5">
                      <div>
                        <span className="block text-[10px] text-slate-500">Internal IP:</span>
                        <span className="font-bold text-slate-200">{selectedNode.ipAddress}</span>
                      </div>
                      <div>
                        <span className="block text-[10px] text-slate-500">VLAN Zone:</span>
                        <span className="font-bold text-cyan-400">{selectedNode.vlan}</span>
                      </div>
                      <div>
                        <span className="block text-[10px] text-slate-500">Active Load:</span>
                        <span className="font-bold text-amber-400">
                          {selectedNode.activeLoadPercent}%
                        </span>
                      </div>
                      <div>
                        <span className="block text-[10px] text-slate-500">Kernel Latency:</span>
                        <span className="font-bold text-emerald-400">
                          {selectedNode.lastPingMs}ms
                        </span>
                      </div>
                    </div>

                    {/* Real-time Ingress & Egress Throughput Snapshot */}
                    {selectedNodeThroughput && (
                      <div className="grid grid-cols-2 gap-2 rounded-xl border border-slate-800 bg-slate-950/90 p-2.5">
                        <div className="space-y-1">
                          <div className="flex items-center gap-1 text-[10px] font-bold text-cyan-400">
                            <ArrowDownLeft className="h-3.5 w-3.5" />
                            <span>Ingress RX</span>
                          </div>
                          <div className="text-sm font-black text-white">
                            {selectedNodeThroughput.ingressBandwidthMbps}{' '}
                            <span className="text-[9px] font-normal text-slate-400">Mbps</span>
                          </div>
                          <div className="flex items-center justify-between text-[9px] text-slate-400">
                            <span>Peak: {selectedNodeThroughput.ingressPeakMbps}M</span>
                            <span className="text-cyan-400">
                              {selectedNodeThroughput.ingressPps.toLocaleString()} pps
                            </span>
                          </div>
                        </div>
                        <div className="space-y-1">
                          <div className="flex items-center gap-1 text-[10px] font-bold text-emerald-400">
                            <ArrowUpRight className="h-3.5 w-3.5" />
                            <span>Egress TX</span>
                          </div>
                          <div className="text-sm font-black text-white">
                            {selectedNodeThroughput.egressBandwidthMbps}{' '}
                            <span className="text-[9px] font-normal text-slate-400">Mbps</span>
                          </div>
                          <div className="flex items-center justify-between text-[9px] text-slate-400">
                            <span>Peak: {selectedNodeThroughput.egressPeakMbps}M</span>
                            <span className="text-emerald-400">
                              {selectedNodeThroughput.egressPps.toLocaleString()} pps
                            </span>
                          </div>
                        </div>
                      </div>
                    )}

                    {/* Connected Edges Quick Summary */}
                    {selectedNodeThroughput && selectedNodeThroughput.connectedEdges.length > 0 && (
                      <div className="space-y-1.5 rounded-xl border border-slate-800 bg-slate-950/70 p-2.5">
                        <div className="flex items-center justify-between text-[10px]">
                          <span className="flex items-center gap-1 font-bold tracking-wider text-slate-400 uppercase">
                            <Cable className="h-3 w-3 text-cyan-400" />
                            <span>
                              {isAr ? 'الروابط الشبكية المتصلة:' : 'Connected Mesh Edges:'}
                            </span>
                          </span>
                          <span className="rounded border border-cyan-500/30 bg-cyan-950 px-1.5 py-0.5 font-mono font-bold text-cyan-400">
                            {selectedNodeThroughput.connectedEdges.length} Links
                          </span>
                        </div>
                        <div className="flex flex-wrap gap-1">
                          {selectedNodeThroughput.connectedEdges.map(edge => (
                            <button
                              key={edge.id}
                              onClick={() => {
                                setIsNodeExpanded(true);
                                setExpandedNodeSubTab('EDGES');
                              }}
                              className="flex items-center gap-1.5 rounded border border-slate-700/80 bg-slate-900 px-2 py-0.5 font-mono text-[10px] text-slate-300 transition hover:bg-slate-800"
                            >
                              <span
                                className={`h-1.5 w-1.5 rounded-full ${edgeQuarantined[edge.id] ? 'bg-rose-400' : edge.status === 'CONGESTED' ? 'bg-amber-400' : 'bg-emerald-400'}`}
                              />
                              <span className="max-w-[90px] truncate">
                                {isAr ? edge.neighborLabelAr : edge.neighborLabel}
                              </span>
                              <span className="text-[9px] text-slate-500">
                                ({edge.capacityGbps}G)
                              </span>
                            </button>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Load Progress Bar */}
                    <div className="space-y-1">
                      <div className="flex justify-between text-[10px] text-slate-400">
                        <span>CPU / Ingress Buffer Load</span>
                        <span>{selectedNode.activeLoadPercent}%</span>
                      </div>
                      <div className="h-1.5 w-full overflow-hidden rounded-full bg-slate-800">
                        <div
                          className={`h-full rounded-full transition-all duration-300 ${
                            selectedNode.activeLoadPercent > 80
                              ? 'bg-rose-500'
                              : selectedNode.activeLoadPercent > 50
                                ? 'bg-amber-400'
                                : 'bg-cyan-400'
                          }`}
                          style={{ width: `${selectedNode.activeLoadPercent}%` }}
                        />
                      </div>
                    </div>
                  </div>
                )}
              </div>

              {/* Tactical Directives and Expand Side-Panel Trigger */}
              <div className="space-y-2.5 border-t border-slate-800 pt-3">
                <button
                  onClick={() => {
                    setIsNodeExpanded(true);
                    setExpandedNodeSubTab('THROUGHPUT');
                  }}
                  className="flex w-full items-center justify-center gap-2 rounded-xl bg-gradient-to-r from-cyan-600/90 to-blue-600/90 px-3 py-2 text-xs font-bold text-slate-950 shadow-lg shadow-cyan-950/60 transition hover:scale-[1.01] hover:from-cyan-500 hover:to-blue-500"
                >
                  <Maximize2 className="h-4 w-4" />
                  <span>
                    {isAr
                      ? 'فتح لوحة الفحص الشاملة للعقدة والروابط'
                      : 'Expand Node Metrics & Connected Edges'}
                  </span>
                </button>

                <div className="space-y-2">
                  {selectedNode?.status === 'ISOLATED' ? (
                    <button
                      onClick={() => handleRestoreNode(selectedNode.id)}
                      disabled={isLoading}
                      className="flex w-full items-center justify-center gap-2 rounded-xl bg-emerald-600 px-3 py-2 text-xs font-bold text-white shadow-lg shadow-emerald-950/50 transition hover:bg-emerald-500"
                    >
                      <Unlock className="h-4 w-4" />
                      <span>{isAr ? 'إعادة العقدة للشبكة' : 'Restore Node to Production'}</span>
                    </button>
                  ) : (
                    <button
                      onClick={() => handleIsolateNode(selectedNode.id)}
                      disabled={isLoading}
                      className="flex w-full items-center justify-center gap-2 rounded-xl bg-rose-600/90 px-3 py-2 text-xs font-bold text-white shadow-lg shadow-rose-950/50 transition hover:bg-rose-600"
                    >
                      <Ban className="h-4 w-4" />
                      <span>{isAr ? 'عزل العقدة فوراً' : 'Isolate Subnet (Quarantine)'}</span>
                    </button>
                  )}

                  {/* Simulation buttons */}
                  <div className="grid grid-cols-2 gap-2">
                    <button
                      onClick={() =>
                        handleSimulateAttackVector(
                          selectedNode.id,
                          'SYN Flood / L4 Amp',
                          'CRITICAL'
                        )
                      }
                      className="flex items-center justify-center gap-1.5 rounded-xl border border-slate-700 bg-slate-950 px-2 py-1.5 text-[11px] font-bold text-slate-200 transition hover:bg-slate-800"
                    >
                      <Flame className="h-3.5 w-3.5 text-rose-400" />
                      <span>Simulate DDoS</span>
                    </button>

                    <button
                      onClick={() =>
                        handleSimulateAttackVector(
                          selectedNode.id,
                          'Prompt Injection / SQLi',
                          'HIGH'
                        )
                      }
                      className="flex items-center justify-center gap-1.5 rounded-xl border border-slate-700 bg-slate-950 px-2 py-1.5 text-[11px] font-bold text-slate-200 transition hover:bg-slate-800"
                    >
                      <Zap className="h-3.5 w-3.5 text-amber-400" />
                      <span>Inject Exploit</span>
                    </button>
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* 3. SEGMENT THREAT DENSITY & THERMAL TELEMETRY MATRIX */}
          <div className="space-y-4 rounded-2xl border border-slate-800 bg-slate-900/90 p-5 shadow-2xl">
            <div className="flex flex-col items-start justify-between gap-3 border-b border-slate-800 pb-3 sm:flex-row sm:items-center">
              <div className="flex items-center gap-2.5">
                <Flame className="h-5 w-5 animate-pulse text-orange-400" />
                <div>
                  <h3 className="flex items-center gap-2 text-sm font-bold text-white">
                    <span>
                      {isAr
                        ? 'مصفوفة كثافة التهديدات الحرارية عبر قطاعات الشبكة'
                        : 'Real-Time Threat Traffic Density Matrix Across Network Segments'}
                    </span>
                    <span className="rounded border border-orange-500/40 bg-orange-500/20 px-2 py-0.5 font-mono text-[10px] text-orange-300">
                      LIVE RADAR
                    </span>
                  </h3>
                  <p className="text-xs text-slate-400">
                    {isAr
                      ? 'تحليل حراري لحظي يربط بين خطورة التهديدات، حمولة المقابس النشطة، وزمن استجابة النواة عبر القطاعات المعزولة'
                      : 'Thermal telemetry correlating MITRE ATT&CK severity, active socket payload ratios, and kernel latencies'}
                  </p>
                </div>
              </div>

              <div className="flex items-center gap-2 font-mono text-xs">
                <span className="text-slate-500">
                  {isAr ? 'مقياس الخريطة:' : 'Active Heat Metric:'}
                </span>
                <span className="rounded-lg border border-cyan-500/40 bg-slate-950 px-2.5 py-1 font-bold text-cyan-300">
                  {heatmapMetric.replace('_', ' ')}
                </span>
              </div>
            </div>

            <div className="grid grid-cols-1 gap-3.5 md:grid-cols-2 lg:grid-cols-3">
              {(Object.values(segmentDensityMetrics) as SegmentDensityMetric[]).map(metric => {
                const isOverheat = metric.thermalStatus === 'CRITICAL_OVERHEAT';
                const isElevated = metric.thermalStatus === 'ELEVATED_HEAT';
                const isCold = metric.thermalStatus === 'QUARANTINE_COLD';

                return (
                  <div
                    key={metric.nodeId}
                    onClick={() => setSelectedNodeId(metric.nodeId)}
                    className={`relative flex cursor-pointer flex-col justify-between overflow-hidden rounded-xl border p-4 transition ${
                      selectedNodeId === metric.nodeId
                        ? 'border-cyan-400 bg-slate-950 shadow-lg ring-1 shadow-cyan-950/40 ring-cyan-400/50'
                        : isOverheat
                          ? 'border-rose-500/60 bg-rose-950/30 shadow-lg ring-1 shadow-rose-950/40 ring-rose-500/40 hover:border-rose-400'
                          : isElevated
                            ? 'border-amber-500/40 bg-amber-950/20 hover:border-amber-400'
                            : isCold
                              ? 'border-slate-800 bg-slate-950/80 opacity-60'
                              : 'border-slate-800 bg-slate-950/60 hover:border-slate-700'
                    }`}
                  >
                    {/* Thermal background glow indicator with CSS pulse for Overheat */}
                    <div
                      className={`pointer-events-none absolute top-0 right-0 h-28 w-28 rounded-full blur-2xl ${
                        isOverheat
                          ? 'animate-pulse bg-rose-500 opacity-30'
                          : isElevated
                            ? 'bg-orange-500 opacity-20'
                            : 'bg-cyan-500 opacity-20'
                      }`}
                    />

                    <div className="relative z-10 space-y-3">
                      <div className="flex items-start justify-between gap-2">
                        <div>
                          <div className="flex items-center gap-1.5 text-xs font-bold text-white">
                            {isOverheat && (
                              <span className="relative flex h-2 w-2">
                                <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-rose-400 opacity-75"></span>
                                <span className="relative inline-flex h-2 w-2 rounded-full bg-rose-500"></span>
                              </span>
                            )}
                            <span>{isAr ? metric.labelAr : metric.label}</span>
                          </div>
                          <div className="mt-0.5 font-mono text-[10px] text-slate-400">
                            {metric.ipAddress} • {metric.vlan}
                          </div>
                        </div>
                        <span
                          className={`shrink-0 rounded px-2 py-0.5 font-mono text-[9px] font-bold uppercase ${
                            isOverheat
                              ? 'animate-pulse border border-rose-500 bg-rose-500/30 text-rose-300 shadow-sm shadow-rose-950'
                              : isElevated
                                ? 'border border-amber-500 bg-amber-500/30 text-amber-300'
                                : isCold
                                  ? 'bg-slate-800 text-slate-400'
                                  : 'border border-emerald-500/40 bg-emerald-500/20 text-emerald-300'
                          }`}
                        >
                          {metric.thermalStatus.replace('_', ' ')}
                        </span>
                      </div>

                      {/* Density Progress Bar */}
                      <div>
                        <div className="mb-1 flex justify-between font-mono text-[10px]">
                          <span className="text-slate-400">
                            {isAr ? 'كثافة التهديد:' : 'Threat Density:'}
                          </span>
                          <span
                            className={`font-bold ${isOverheat ? 'text-rose-400' : isElevated ? 'text-amber-400' : 'text-cyan-400'}`}
                          >
                            {Math.round(metric.densityScore * 100)}%
                          </span>
                        </div>
                        <div className="h-1.5 w-full overflow-hidden rounded-full border border-slate-800 bg-slate-900">
                          <div
                            className={`h-full transition-all duration-500 ${
                              isOverheat
                                ? 'bg-gradient-to-r from-orange-500 to-rose-600'
                                : isElevated
                                  ? 'bg-gradient-to-r from-yellow-400 to-amber-500'
                                  : 'bg-gradient-to-r from-cyan-400 to-blue-500'
                            }`}
                            style={{ width: `${Math.round(metric.densityScore * 100)}%` }}
                          />
                        </div>
                      </div>

                      {/* Stats Grid */}
                      <div className="grid grid-cols-3 gap-1.5 pt-1 text-center font-mono text-[10px]">
                        <div className="rounded-lg border border-slate-800 bg-slate-900 p-1.5">
                          <div className="text-slate-500">{isAr ? 'المقابس' : 'Sockets'}</div>
                          <div className="mt-0.5 font-bold text-white">{metric.activeSockets}</div>
                        </div>
                        <div className="rounded-lg border border-slate-800 bg-slate-900 p-1.5">
                          <div className="text-slate-500">{isAr ? 'التهديدات' : 'Threats'}</div>
                          <div
                            className={`mt-0.5 font-bold ${metric.threatCount > 0 ? 'text-rose-400' : 'text-slate-300'}`}
                          >
                            {metric.threatCount}
                          </div>
                        </div>
                        <div className="rounded-lg border border-slate-800 bg-slate-900 p-1.5">
                          <div className="text-slate-500">{isAr ? 'الاستجابة' : 'Latency'}</div>
                          <div className="mt-0.5 font-bold text-emerald-400">
                            {metric.latencyMs}ms
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      )}

      {/* 3. TAB 2: DYNAMIC SOCKET & CONNECTION MATRIX + DPI & HEX PARSER */}
      {activeSubTab === 'SOCKET_MATRIX' && (
        <div className="space-y-5">
          {/* Controls Bar */}
          <div className="flex flex-col items-start justify-between gap-4 rounded-2xl border border-slate-800 bg-slate-900 p-4 md:flex-row md:items-center">
            <div className="flex w-full items-center gap-3 md:w-auto">
              <div className="relative flex-1 md:w-72">
                <Search className="absolute top-2.5 left-3 h-4 w-4 text-slate-500" />
                <input
                  type="text"
                  placeholder={
                    isAr
                      ? 'بحث بالعنوان IP، المنفذ، العملية أو الحمولة...'
                      : 'Search IP, port, process, payload...'
                  }
                  value={socketFilter}
                  onChange={e => setSocketFilter(e.target.value)}
                  className="w-full rounded-xl border border-slate-800 bg-slate-950 py-2 pr-3 pl-9 text-xs text-white placeholder-slate-500 focus:border-cyan-500 focus:outline-none"
                />
              </div>

              {/* Protocol Filter */}
              <div className="flex items-center gap-1 rounded-xl border border-slate-800 bg-slate-950 p-1 text-xs">
                {(['ALL', 'TCP', 'UDP', 'ICMP'] as const).map(p => (
                  <button
                    key={p}
                    onClick={() => setProtocolFilter(p)}
                    className={`rounded-lg px-2.5 py-1 font-bold transition ${
                      protocolFilter === p
                        ? 'bg-cyan-500 text-slate-950'
                        : 'text-slate-400 hover:text-white'
                    }`}
                  >
                    {p}
                  </button>
                ))}
              </div>
            </div>

            <div className="flex items-center gap-2">
              <span className="font-mono text-xs text-slate-400">Threat Verdict:</span>
              <div className="flex items-center gap-1 rounded-xl border border-slate-800 bg-slate-950 p-1 text-xs">
                {(['ALL', 'MALICIOUS', 'SUSPICIOUS', 'BENIGN'] as const).map(t => (
                  <button
                    key={t}
                    onClick={() => setThreatFilter(t)}
                    className={`rounded-lg px-2.5 py-1 font-bold transition ${
                      threatFilter === t
                        ? t === 'MALICIOUS'
                          ? 'bg-rose-600 text-white'
                          : t === 'SUSPICIOUS'
                            ? 'bg-amber-500 text-slate-950'
                            : t === 'BENIGN'
                              ? 'bg-emerald-500 text-slate-950'
                              : 'bg-cyan-500 text-slate-950'
                        : 'text-slate-400 hover:text-white'
                    }`}
                  >
                    {t}
                  </button>
                ))}
              </div>
            </div>
          </div>

          {/* Socket Matrix Table */}
          <div className="overflow-hidden rounded-2xl border border-slate-800 bg-slate-950 shadow-2xl">
            <div className="overflow-x-auto">
              <table className="w-full text-left font-mono text-xs">
                <thead className="border-b border-slate-800 bg-slate-900/90 text-[11px] text-slate-400 uppercase">
                  <tr>
                    <th className="p-3.5">Socket ID & Protocol</th>
                    <th className="p-3.5">Source IP : Port</th>
                    <th className="p-3.5">Destination IP : Port</th>
                    <th className="p-3.5">State & Flags</th>
                    <th className="p-3.5">Latency / Bytes</th>
                    <th className="p-3.5">Threat Verdict</th>
                    <th className="p-3.5 text-right">DPI & Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {filteredSockets.length === 0 ? (
                    <tr>
                      <td colSpan={7} className="p-8 text-center text-slate-500">
                        {isAr
                          ? 'لا توجد مقابس شبكية تطابق معايير الفلترة الحالية'
                          : 'No active socket streams match current filter'}
                      </td>
                    </tr>
                  ) : (
                    filteredSockets.map(s => {
                      const isMal = s.threatLevel === 'MALICIOUS';
                      const isSusp = s.threatLevel === 'SUSPICIOUS';
                      const isDropped = s.state === 'DROPPED';

                      return (
                        <tr
                          key={s.id}
                          className={`cursor-pointer transition hover:bg-slate-900/50 ${
                            isDropped ? 'bg-slate-950 opacity-50' : isMal ? 'bg-rose-950/10' : ''
                          }`}
                          onClick={() => setSelectedSocket(s)}
                        >
                          <td className="p-3.5 font-bold">
                            <div className="flex items-center gap-2">
                              <span className="text-cyan-400">{s.id}</span>
                              <span className="rounded bg-slate-800 px-1.5 py-0.5 text-[10px] text-slate-300">
                                {s.protocol}
                              </span>
                            </div>
                            <span className="block text-[10px] text-slate-500">
                              {s.processName} (PID: {s.pid})
                            </span>
                          </td>

                          <td className="p-3.5">
                            <span className="font-bold text-slate-200">{s.srcIp}</span>
                            <span className="text-cyan-400">:{s.srcPort}</span>
                          </td>

                          <td className="p-3.5">
                            <span className="font-bold text-slate-200">{s.dstIp}</span>
                            <span className="text-emerald-400">:{s.dstPort}</span>
                          </td>

                          <td className="p-3.5">
                            <div className="flex items-center gap-1.5">
                              <span
                                className={`rounded px-2 py-0.5 text-[10px] font-bold ${
                                  isDropped
                                    ? 'bg-slate-800 text-slate-400 line-through'
                                    : s.state === 'ESTABLISHED'
                                      ? 'bg-emerald-500/20 text-emerald-300'
                                      : 'bg-amber-500/20 text-amber-300'
                                }`}
                              >
                                {s.state}
                              </span>
                            </div>
                            <div className="mt-0.5 flex gap-1 text-[10px] text-slate-500">
                              {s.tcpFlags.map(f => (
                                <span key={f} className="font-bold text-cyan-400">
                                  [{f}]
                                </span>
                              ))}
                            </div>
                          </td>

                          <td className="p-3.5 text-slate-300">
                            <div>{s.latencyMs} ms</div>
                            <div className="text-[10px] text-slate-500">
                              {(s.bytesTransferred / 1024).toFixed(1)} KB
                            </div>
                          </td>

                          <td className="p-3.5">
                            <span
                              className={`rounded-full px-2.5 py-1 text-[10px] font-bold uppercase ${
                                isMal
                                  ? 'border border-rose-500/40 bg-rose-500/20 text-rose-300'
                                  : isSusp
                                    ? 'border border-amber-500/40 bg-amber-500/20 text-amber-300'
                                    : 'border border-emerald-500/40 bg-emerald-500/20 text-emerald-300'
                              }`}
                            >
                              {s.threatLevel}
                            </span>
                          </td>

                          <td className="p-3.5 text-right">
                            <div
                              className="flex flex-wrap items-center justify-end gap-1.5"
                              onClick={e => e.stopPropagation()}
                            >
                              <button
                                onClick={() => setSelectedSocket(s)}
                                className="flex items-center gap-1 rounded-lg border border-cyan-500/40 bg-cyan-950/70 px-2 py-1 text-[11px] font-bold text-cyan-300 transition hover:bg-cyan-900"
                                title="Deep Packet Inspection & Hex Dump"
                              >
                                <Binary className="h-3 w-3 text-cyan-400" />
                                <span>DPI</span>
                              </button>

                              <button
                                onClick={() => handleTraceRoute(s.srcIp)}
                                disabled={isTracingRoute}
                                className="flex items-center gap-1 rounded-lg border border-slate-700 bg-slate-900 px-2 py-1 text-[11px] font-bold text-slate-300 transition hover:bg-slate-800 hover:text-white"
                                title="Trace Hop-by-Hop Route"
                              >
                                <Route className="h-3 w-3 text-cyan-400" />
                                <span>Trace</span>
                              </button>

                              <button
                                onClick={() => handlePushEbpfRule(s.id)}
                                className="flex items-center gap-1 rounded-lg border border-amber-500/40 bg-amber-950/60 px-2 py-1 text-[11px] font-bold text-amber-300 transition hover:bg-amber-900"
                                title="Push eBPF XDP Drop Rule to Kernel"
                              >
                                <ShieldCheck className="h-3 w-3 text-amber-400" />
                                <span>eBPF</span>
                              </button>

                              {!isDropped ? (
                                <button
                                  onClick={() => handleDropSocket(s.id)}
                                  className="flex items-center gap-1 rounded-lg border border-rose-600/50 bg-rose-950/70 px-2 py-1 text-[11px] font-bold text-rose-300 shadow-sm transition hover:bg-rose-900"
                                  title="Reset Socket (TCP RST / Instant Drop)"
                                >
                                  <Zap className="h-3 w-3 text-rose-400" />
                                  <span>TCP RST</span>
                                </button>
                              ) : (
                                <span className="rounded bg-slate-900 px-2 py-1 font-mono text-[10px] text-slate-500">
                                  DROPPED
                                </span>
                              )}
                            </div>
                          </td>
                        </tr>
                      );
                    })
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* 4. TAB 3: HIERARCHICAL SITE SURVEILLANCE TREE */}
      {activeSubTab === 'SITE_SURVEILLANCE_TREE' && (
        <div className="space-y-5">
          <div className="flex flex-col items-start justify-between gap-4 rounded-2xl border border-slate-800 bg-slate-900 p-4 md:flex-row md:items-center">
            <div>
              <h3 className="flex items-center gap-2 text-sm font-bold text-white">
                <FolderTree className="h-4 w-4 text-cyan-400" />
                <span>
                  {isAr
                    ? 'شجرة التوجيه الحية ومراقبة ثغرات المسارات'
                    : 'Application Route Security & Ingress Flow Hierarchy'}
                </span>
              </h3>
              <p className="text-xs text-slate-400">
                {isAr
                  ? 'مراقبة فورية لمعدل الطلبات ونسبة الأخطاء ومحاولات الاستغلال النشطة لكل مسار في التطبيق'
                  : 'Real-time throughput, error rates, and active OWASP exploitation payloads per route endpoint'}
              </p>
            </div>

            <div className="flex items-center gap-2">
              <button
                onClick={fetchSiteTree}
                className="flex items-center gap-1.5 rounded-xl border border-slate-800 bg-slate-950 px-3 py-1.5 text-xs font-bold text-slate-300 hover:bg-slate-800"
              >
                <RefreshCw className="h-3.5 w-3.5" />
                <span>Refresh Map</span>
              </button>
            </div>
          </div>

          {/* Tree View Container */}
          <div className="space-y-3 rounded-2xl border border-slate-800 bg-slate-950 p-5 shadow-2xl">
            {siteTree ? (
              renderRouteTreeNode(siteTree)
            ) : (
              <div className="p-8 text-center font-mono text-xs text-slate-500">
                {isAr ? 'جاري جلب خريطة مسارات التطبيق...' : 'Loading site route tree...'}
              </div>
            )}
          </div>
        </div>
      )}

      {/* 5. TAB 4: DECEPTION TRAPS & HONEYTOKEN MATRIX */}
      {activeSubTab === 'HONEYTOKEN_TRAPS' && (
        <div className="space-y-5">
          <div className="flex flex-col items-start justify-between gap-4 rounded-2xl border border-slate-800 bg-slate-900 p-4 md:flex-row md:items-center">
            <div>
              <h3 className="flex items-center gap-2 text-sm font-bold text-white">
                <ShieldAlert className="h-4 w-4 text-amber-400" />
                <span>
                  {isAr
                    ? 'مصفوفة فخاخ الخداع الرقمي (Honeytoken Tripwire Matrix)'
                    : 'Deception Honeytokens & Active Tripwire Monitors'}
                </span>
              </h3>
              <p className="text-xs text-slate-400">
                {isAr
                  ? 'مسارات وهمية حساسة تقوم بعزل وحظر أي مهاجم أو بوت مسح آلي فور لمسها على مستوى النواة'
                  : 'Decoy sensitive endpoints that trigger instant kernel-level quarantine and packet capture upon touch'}
              </p>
            </div>

            <button
              onClick={fetchDeceptionTraps}
              className="flex items-center gap-1.5 rounded-xl border border-slate-800 bg-slate-950 px-3 py-1.5 text-xs font-bold text-slate-300 hover:bg-slate-800"
            >
              <RefreshCw className="h-3.5 w-3.5" />
              <span>Refresh Traps</span>
            </button>
          </div>

          <div className="grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-3">
            {deceptionTraps.map(trap => (
              <div
                key={trap.id}
                className="space-y-4 rounded-2xl border border-slate-800 bg-slate-950 p-5 shadow-xl transition hover:border-amber-500/40"
              >
                <div className="flex items-center justify-between">
                  <span className="rounded border border-amber-500/40 bg-amber-950/60 px-2 py-0.5 font-mono text-xs font-bold text-amber-400">
                    {trap.id}
                  </span>
                  <span
                    className="h-2.5 w-2.5 animate-pulse rounded-full bg-emerald-400"
                    title="Trap Armed"
                  />
                </div>

                <div>
                  <code className="block truncate font-mono text-sm font-bold text-cyan-300">
                    {trap.path}
                  </code>
                  <p className="mt-1 text-xs text-slate-400">
                    {isAr ? trap.descriptionAr : trap.descriptionEn}
                  </p>
                </div>

                <div className="grid grid-cols-2 gap-2 rounded-xl border border-slate-800 bg-slate-900/80 p-3 font-mono text-xs">
                  <div>
                    <span className="block text-[10px] text-slate-500">Tripwire Hits:</span>
                    <span className="text-sm font-black text-rose-400">{trap.hitsCount}</span>
                  </div>
                  <div>
                    <span className="block text-[10px] text-slate-500">Auto Quarantine:</span>
                    <span className="font-bold text-emerald-400">KERNEL ACTIVE</span>
                  </div>
                  {trap.lastAttackerIp && (
                    <div className="col-span-2 mt-1">
                      <span className="block text-[10px] text-slate-500">Last Attacker:</span>
                      <span className="block truncate font-bold text-slate-300">
                        {trap.lastAttackerIp}
                      </span>
                    </div>
                  )}
                </div>

                <button
                  onClick={() => handleTriggerHoneytoken(trap.path)}
                  className="flex w-full items-center justify-center gap-2 rounded-xl bg-amber-600/90 px-3 py-2 text-xs font-bold text-slate-950 shadow-lg shadow-amber-950/40 transition hover:bg-amber-600"
                >
                  <Zap className="h-4 w-4" />
                  <span>{isAr ? 'محاكاة تفجير الفخ' : 'Trigger Tripwire Simulator'}</span>
                </button>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* 6. MODAL: DEEP PACKET INSPECTION (DPI) & HEX PARSER */}
      {selectedSocket && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/80 p-4 backdrop-blur-md">
          <div className="max-h-[90vh] w-full max-w-4xl space-y-6 overflow-y-auto rounded-2xl border border-slate-800 bg-slate-900 p-6 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-4">
              <div className="flex items-center gap-3">
                <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-cyan-500/40 bg-cyan-950">
                  <Binary className="h-5 w-5 text-cyan-400" />
                </div>
                <div>
                  <h3 className="text-base font-black text-white">
                    {isAr
                      ? 'فحص الإطار العميق ومحلل الـ Hex (DPI & Hex Parser)'
                      : 'Deep Packet Inspection & Hex Frame Parser'}
                  </h3>
                  <p className="font-mono text-xs text-slate-400">
                    Stream ID: {selectedSocket.id} • Protocol: {selectedSocket.protocol} • Process:{' '}
                    {selectedSocket.processName}
                  </p>
                </div>
              </div>

              <button
                onClick={() => setSelectedSocket(null)}
                className="rounded-xl bg-slate-800 p-2 text-slate-300 transition hover:bg-slate-700"
              >
                <X className="h-5 w-5" />
              </button>
            </div>

            {/* Socket Header Metadata */}
            <div className="grid grid-cols-2 gap-3 rounded-xl border border-slate-800 bg-slate-950 p-4 font-mono text-xs sm:grid-cols-4">
              <div>
                <span className="block text-[10px] text-slate-500">Source IP:Port</span>
                <span className="font-bold text-cyan-400">
                  {selectedSocket.srcIp}:{selectedSocket.srcPort}
                </span>
              </div>
              <div>
                <span className="block text-[10px] text-slate-500">Destination IP:Port</span>
                <span className="font-bold text-emerald-400">
                  {selectedSocket.dstIp}:{selectedSocket.dstPort}
                </span>
              </div>
              <div>
                <span className="block text-[10px] text-slate-500">TCP Flags</span>
                <span className="font-bold text-slate-200">
                  {selectedSocket.tcpFlags.join(', ')}
                </span>
              </div>
              <div>
                <span className="block text-[10px] text-slate-500">Threat Level</span>
                <span
                  className={`font-bold ${selectedSocket.threatLevel === 'MALICIOUS' ? 'text-rose-400' : 'text-emerald-400'}`}
                >
                  {selectedSocket.threatLevel}
                </span>
              </div>
            </div>

            {/* Detected Attack Signatures Alert Banner */}
            {(() => {
              const detectedSignatures: Array<{
                type: string;
                name: string;
                nameAr: string;
                pattern: string;
                severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
                mitre: string;
              }> = [];
              const pLower = (selectedSocket.asciiPayload || '').toLowerCase();

              if (
                pLower.includes('union select') ||
                pLower.includes('or 1=1') ||
                pLower.includes('information_schema') ||
                pLower.includes('sqlmap')
              ) {
                detectedSignatures.push({
                  type: 'SQLI',
                  name: 'SQL Injection Signature Trigger',
                  nameAr: 'اكتشاف توقيع هجوم حقن قواعد البيانات (SQLi)',
                  pattern: pLower.includes('union select')
                    ? 'UNION SELECT'
                    : pLower.includes('or 1=1')
                      ? "' OR 1=1--"
                      : 'SQL Injection Heuristic',
                  severity: 'CRITICAL',
                  mitre: 'MITRE ATT&CK: T1190 - Exploit Public-Facing Application'
                });
              }

              if (
                pLower.includes('<script>') ||
                pLower.includes('document.cookie') ||
                pLower.includes('onerror=')
              ) {
                detectedSignatures.push({
                  type: 'XSS',
                  name: 'Cross-Site Scripting (XSS) Trigger',
                  nameAr: 'توقيع هجوم البرمجة عبر المواقع (XSS)',
                  pattern: '<script> / DOM Exfiltration',
                  severity: 'HIGH',
                  mitre: 'MITRE ATT&CK: T1059.007 - JavaScript Execution'
                });
              }

              if (
                pLower.includes('etc/passwd') ||
                pLower.includes('../') ||
                pLower.includes('..\\')
              ) {
                detectedSignatures.push({
                  type: 'PATH_TRAVERSAL',
                  name: 'Path Traversal / Local File Inclusion (LFI)',
                  nameAr: 'توقيع هجوم اختراق مسارات الملفات الحساسة (LFI)',
                  pattern: '../../../../etc/passwd',
                  severity: 'CRITICAL',
                  mitre: 'MITRE ATT&CK: T1083 - File and Directory Discovery'
                });
              }

              if (
                pLower.includes('ignore safety') ||
                pLower.includes('reveal root') ||
                pLower.includes('dan mode') ||
                pLower.includes('prompt injection')
              ) {
                detectedSignatures.push({
                  type: 'PROMPT_INJECTION',
                  name: 'LLM Prompt Injection / Jailbreak Attack',
                  nameAr: 'توقيع هجوم كسر حماية وتجاوز نموذج الذكاء الاصطناعي',
                  pattern: 'Adversarial Prompt Override String',
                  severity: 'CRITICAL',
                  mitre: 'ATLAS MITRE: AML.T0054 - LLM Jailbreak'
                });
              }

              if (
                pLower.includes('db_backup.sql') ||
                pLower.includes('.env') ||
                pLower.includes('.git') ||
                pLower.includes('smb2')
              ) {
                detectedSignatures.push({
                  type: 'HONEYTOKEN',
                  name: 'Deception Honeytoken Touch Trigger',
                  nameAr: 'توقيع لمس فخ الخداع الرقمي والأصول الوهمية',
                  pattern: 'Decoy Credential Extraction',
                  severity: 'HIGH',
                  mitre: 'MITRE ATT&CK: T1552 - Unsecured Credentials'
                });
              }

              if (detectedSignatures.length === 0) return null;

              return (
                <div className="space-y-3 rounded-xl border border-rose-500/50 bg-rose-950/40 p-4 shadow-lg shadow-rose-950/30">
                  <div className="flex items-center justify-between">
                    <span className="flex items-center gap-2 font-mono text-xs font-bold tracking-wide text-rose-300 uppercase">
                      <ShieldAlert className="h-4 w-4 animate-pulse text-rose-400" />
                      <span>
                        {isAr
                          ? 'تنبيه مطابقة التواقيع الهجومية (Active Signature Triggers):'
                          : 'Active Signature Triggers Detected in Frame:'}
                      </span>
                    </span>
                    <span className="rounded bg-rose-500 px-2 py-0.5 font-mono text-[10px] font-bold text-white">
                      {detectedSignatures.length} MATCH{detectedSignatures.length > 1 ? 'ES' : ''}
                    </span>
                  </div>

                  <div className="grid grid-cols-1 gap-2 md:grid-cols-2">
                    {detectedSignatures.map(sig => (
                      <div
                        key={`sig-${sig.name.replace(/[^a-zA-Z0-9]/g, '_')}-${sig.severity}-${sig.mitre}`}
                        className="rounded-lg border border-rose-900/60 bg-slate-950/80 p-2.5 font-mono text-xs"
                      >
                        <div className="flex items-center justify-between text-[11px] font-bold text-rose-300">
                          <span>{isAr ? sig.nameAr : sig.name}</span>
                          <span className="rounded border border-rose-800 bg-rose-950 px-1.5 py-0.5 text-[9px] text-rose-400 uppercase">
                            {sig.severity}
                          </span>
                        </div>
                        <div className="mt-1 text-[10px] text-amber-300">
                          <span className="text-slate-500">Pattern: </span>
                          <code className="rounded bg-slate-900 px-1 py-0.5 text-amber-200">
                            {sig.pattern}
                          </code>
                        </div>
                        <div className="mt-0.5 text-[10px] text-slate-400">{sig.mitre}</div>
                      </div>
                    ))}
                  </div>
                </div>
              );
            })()}

            {/* Hex Dump Parser View */}
            <div className="space-y-2">
              <div className="flex items-center justify-between font-mono text-xs">
                <div className="flex items-center gap-2">
                  <span className="font-bold text-slate-400 uppercase">
                    Raw Packet Frame Hex Dump:
                  </span>
                  <span className="rounded border border-cyan-500/30 bg-cyan-950 px-2 py-0.5 text-[10px] text-cyan-400">
                    16-Byte Offset Matrix
                  </span>
                </div>
                <button
                  onClick={() => {
                    navigator.clipboard.writeText(selectedSocket.hexDump);
                    setCopiedCode(true);
                    setTimeout(() => setCopiedCode(false), 2000);
                  }}
                  className="flex items-center gap-1 rounded bg-slate-800 px-2.5 py-1 font-mono text-xs text-slate-300 hover:bg-slate-700"
                >
                  {copiedCode ? (
                    <Check className="h-3.5 w-3.5 text-emerald-400" />
                  ) : (
                    <Copy className="h-3.5 w-3.5" />
                  )}
                  <span>{copiedCode ? 'Copied' : 'Copy Hex Matrix'}</span>
                </button>
              </div>

              <div className="overflow-x-auto rounded-xl border border-slate-800 bg-slate-950 p-4 font-mono text-[11px] leading-relaxed whitespace-pre text-cyan-300 shadow-inner">
                {selectedSocket.hexDump}
              </div>
            </div>

            {/* ASCII Payload Translation */}
            <div className="space-y-2">
              <div className="flex items-center justify-between font-mono text-xs">
                <span className="font-bold text-slate-400 uppercase">
                  ASCII Decoded Ingress Payload:
                </span>
                <span className="text-[10px] text-slate-500">UTF-8 / ISO-8859-1 Sanitized</span>
              </div>
              <div className="overflow-x-auto rounded-xl border border-slate-800 bg-slate-950 p-3.5 font-mono text-xs leading-relaxed whitespace-pre-wrap text-slate-200">
                {selectedSocket.asciiPayload}
              </div>
            </div>

            {/* Tactical Action Directives */}
            <div className="flex flex-wrap items-center justify-between gap-3 border-t border-slate-800 pt-4">
              <div className="flex items-center gap-2">
                <button
                  onClick={() => handleTraceRoute(selectedSocket.srcIp)}
                  disabled={isTracingRoute}
                  className="flex items-center gap-2 rounded-xl bg-cyan-600 px-4 py-2 text-xs font-bold text-slate-950 shadow-lg shadow-cyan-950/50 transition hover:bg-cyan-500"
                >
                  <Route className="h-4 w-4" />
                  <span>{isTracingRoute ? 'Tracing Route...' : 'Trace Route'}</span>
                </button>

                <button
                  onClick={() => handlePushEbpfRule(selectedSocket.id)}
                  className="flex items-center gap-2 rounded-xl border border-cyan-500/40 bg-slate-950 px-4 py-2 text-xs font-bold text-cyan-300 transition hover:bg-slate-800"
                >
                  <ShieldCheck className="h-4 w-4" />
                  <span>Push eBPF Rule</span>
                </button>
              </div>

              {selectedSocket.state !== 'DROPPED' && (
                <button
                  onClick={() => handleDropSocket(selectedSocket.id)}
                  className="flex items-center gap-2 rounded-xl bg-rose-600 px-4 py-2 text-xs font-bold text-white shadow-lg shadow-rose-950/50 transition hover:bg-rose-500"
                >
                  <Ban className="h-4 w-4" />
                  <span>Drop Socket Connection</span>
                </button>
              )}
            </div>
          </div>
        </div>
      )}

      {/* 7. MODAL: TRACEROUTE HOP-BY-HOP VISUALIZER */}
      {activeTraceroute && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/80 p-4 backdrop-blur-md">
          <div className="w-full max-w-2xl space-y-5 rounded-2xl border border-slate-800 bg-slate-900 p-6 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-3">
                <Route className="h-5 w-5 text-cyan-400" />
                <h3 className="text-base font-bold text-white">
                  {isAr
                    ? 'مسار التوجيه الشبكي (Traceroute)'
                    : `Traceroute Path to ${activeTraceroute.targetIp}`}
                </h3>
              </div>
              <button
                onClick={() => setActiveTraceroute(null)}
                className="rounded-xl bg-slate-800 p-2 text-slate-300 hover:bg-slate-700"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            <div className="space-y-2 font-mono text-xs">
              {activeTraceroute.hops.map(hop => (
                <div
                  key={hop.hop}
                  className="flex items-center justify-between gap-3 rounded-xl border border-slate-800 bg-slate-950 p-3"
                >
                  <div className="flex items-center gap-3">
                    <span className="flex h-6 w-6 items-center justify-center rounded border border-cyan-500/40 bg-cyan-950 font-bold text-cyan-400">
                      {hop.hop}
                    </span>
                    <div>
                      <span className="font-bold text-slate-100">{hop.ip}</span>
                      <span className="block text-[11px] text-slate-500">
                        {hop.hostname} ({hop.asn})
                      </span>
                    </div>
                  </div>

                  <div className="text-right">
                    <span className="font-bold text-emerald-400">{hop.rttMs} ms</span>
                    <span className="block text-[10px] text-slate-500">{hop.country}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* 8. MODAL: SUBNECT / CIDR QUARANTINE */}
      {showSubnetModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/80 p-4 backdrop-blur-md">
          <div className="w-full max-w-md space-y-4 rounded-2xl border border-slate-800 bg-slate-900 p-6 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="flex items-center gap-2 text-base font-bold text-white">
                <Ban className="h-4 w-4 text-rose-400" />
                <span>{isAr ? 'حظر وعزل نطاق CIDR' : 'Quarantine Subnet / CIDR'}</span>
              </h3>
              <button
                onClick={() => setShowSubnetModal(false)}
                className="text-slate-400 hover:text-white"
              >
                <X className="h-5 w-5" />
              </button>
            </div>

            <div className="space-y-2">
              <label className="block font-mono text-xs text-slate-400">CIDR Subnet Range:</label>
              <input
                type="text"
                value={subnetQuarantineInput}
                onChange={e => setSubnetQuarantineInput(e.target.value)}
                placeholder="e.g. 194.26.29.0/24"
                className="w-full rounded-xl border border-slate-800 bg-slate-950 p-2.5 font-mono text-xs text-white focus:border-rose-500 focus:outline-none"
              />
            </div>

            <div className="flex items-center justify-end gap-2 border-t border-slate-800 pt-3">
              <button
                onClick={() => setShowSubnetModal(false)}
                className="rounded-xl bg-slate-800 px-3.5 py-2 text-xs font-bold text-slate-300"
              >
                Cancel
              </button>
              <button
                onClick={handleQuarantineSubnet}
                className="rounded-xl bg-rose-600 px-4 py-2 text-xs font-bold text-white shadow-lg shadow-rose-950/50 hover:bg-rose-500"
              >
                Enforce Subnet Quarantine
              </button>
            </div>
          </div>
        </div>
      )}

      {/* 9. MODAL: EXPANDED NODE THROUGHPUT, TELEMETRY & CONNECTED EDGES INSPECTOR */}
      {isNodeExpanded && selectedNode && selectedNodeThroughput && (
        <div className="fixed inset-0 z-50 flex items-center justify-center overflow-hidden bg-slate-950/85 p-2 backdrop-blur-md sm:p-4 md:p-6">
          <div className="animate-in fade-in zoom-in-95 flex max-h-[94vh] w-full max-w-6xl flex-col overflow-hidden rounded-3xl border border-cyan-500/40 bg-slate-900/95 shadow-2xl shadow-cyan-950/60 duration-200">
            {/* Header with Node Metadata, Switcher, and Controls */}
            <div className="flex flex-col gap-4 border-b border-slate-800 bg-slate-950/90 p-5">
              <div className="flex flex-col items-start justify-between gap-3 sm:flex-row sm:items-center">
                <div className="flex items-center gap-3">
                  <div className="flex h-11 w-11 items-center justify-center rounded-2xl border border-cyan-500/50 bg-cyan-950 shadow-lg shadow-cyan-950/50">
                    <Server className="h-6 w-6 text-cyan-400" />
                  </div>
                  <div>
                    <div className="flex flex-wrap items-center gap-2">
                      <h2 className="text-base font-black text-white sm:text-lg">
                        {isAr ? selectedNode.labelAr : selectedNode.label}
                      </h2>
                      <span className="rounded border border-slate-700 bg-slate-900 px-2 py-0.5 font-mono text-[11px] font-bold text-cyan-300">
                        {selectedNode.id}
                      </span>
                      <span
                        className={`rounded-full px-2.5 py-0.5 font-mono text-[10px] font-bold uppercase ${
                          selectedNode.status === 'ISOLATED'
                            ? 'bg-rose-500 text-white'
                            : selectedNode.status === 'UNDER_ATTACK'
                              ? 'animate-pulse bg-amber-500 text-slate-950'
                              : 'border border-emerald-500/40 bg-emerald-500/20 text-emerald-300'
                        }`}
                      >
                        {selectedNode.status}
                      </span>
                    </div>
                    <p className="mt-0.5 flex flex-wrap items-center gap-3 font-mono text-xs text-slate-400">
                      <span>
                        IP: <strong className="text-slate-200">{selectedNode.ipAddress}</strong>
                      </span>
                      <span>•</span>
                      <span>
                        VLAN: <strong className="text-cyan-300">{selectedNode.vlan}</strong>
                      </span>
                      <span>•</span>
                      <span>
                        Kernel Latency:{' '}
                        <strong className="text-emerald-400">{selectedNode.lastPingMs} ms</strong>
                      </span>
                      <span>•</span>
                      <span>
                        NIC:{' '}
                        <strong className="text-slate-300">
                          {selectedNodeThroughput.nicInterface}
                        </strong>
                      </span>
                    </p>
                  </div>
                </div>

                <div className="flex items-center gap-2 self-end sm:self-center">
                  <button
                    onClick={() => handleToggleQuickLock(selectedNode)}
                    disabled={isLoading}
                    className={`flex items-center gap-1.5 rounded-xl border px-3 py-1.5 font-mono text-xs font-bold transition ${
                      quickLockedNodes[selectedNode.id]
                        ? 'animate-pulse border-rose-400 bg-rose-600 text-white shadow-lg shadow-rose-950/60 hover:bg-rose-500'
                        : 'border-rose-500/40 bg-slate-950 text-rose-300 hover:border-rose-400 hover:bg-rose-950/40'
                    }`}
                    title={
                      quickLockedNodes[selectedNode.id]
                        ? 'Quick-Lock Active: eBPF drop-rule enforced for segment'
                        : 'Instantly apply eBPF drop-rule for this segment'
                    }
                  >
                    {quickLockedNodes[selectedNode.id] ? (
                      <Lock className="h-3.5 w-3.5 text-white" />
                    ) : (
                      <ShieldAlert className="h-3.5 w-3.5 text-rose-400" />
                    )}
                    <span className="font-bold">
                      {quickLockedNodes[selectedNode.id]
                        ? isAr
                          ? 'القفل الأمني نشط (eBPF)'
                          : 'Quick-Lock: LOCKED'
                        : isAr
                          ? 'قفل أمني سريع (Quick-Lock)'
                          : 'Security Quick-Lock'}
                    </span>
                  </button>
                  <button
                    onClick={() => handleTraceRoute(selectedNode.ipAddress)}
                    className="flex items-center gap-1.5 rounded-xl border border-slate-700 bg-slate-950 px-3 py-1.5 font-mono text-xs font-bold text-cyan-300 transition hover:bg-slate-800"
                  >
                    <Route className="h-3.5 w-3.5" />
                    <span className="hidden sm:inline">Trace Route</span>
                  </button>
                  <button
                    onClick={() => setIsNodeExpanded(false)}
                    className="rounded-xl bg-slate-800 p-2 text-slate-300 transition hover:bg-slate-700"
                    title="Close Inspector"
                  >
                    <X className="h-5 w-5" />
                  </button>
                </div>
              </div>

              {/* Node Switcher Pills */}
              <div className="flex scrollbar-thin items-center gap-2 overflow-x-auto pb-1">
                <span className="mr-1 shrink-0 font-mono text-[10px] tracking-wider text-slate-500 uppercase">
                  {isAr ? 'تبديل العقدة:' : 'Inspect Node:'}
                </span>
                {nodes.map(n => {
                  const isActive = n.id === selectedNode.id;
                  const isThreat = n.status === 'UNDER_ATTACK';
                  const isIso = n.status === 'ISOLATED';
                  return (
                    <button
                      key={n.id}
                      onClick={() => setSelectedNodeId(n.id)}
                      className={`flex shrink-0 items-center gap-2 rounded-xl px-3 py-1 font-mono text-xs font-bold transition ${
                        isActive
                          ? 'bg-cyan-500 text-slate-950 shadow-md shadow-cyan-500/30'
                          : 'border border-slate-800 bg-slate-950 text-slate-400 hover:border-slate-700 hover:text-slate-200'
                      }`}
                    >
                      <span
                        className={`h-2 w-2 rounded-full ${
                          isThreat
                            ? isActive
                              ? 'animate-ping bg-slate-950'
                              : 'animate-pulse bg-amber-400'
                            : isIso
                              ? 'bg-rose-400'
                              : isActive
                                ? 'bg-slate-950'
                                : 'bg-emerald-400'
                        }`}
                      />
                      <span>{isAr ? n.labelAr : n.label}</span>
                    </button>
                  );
                })}
              </div>

              {/* Sub-Navigation Tabs */}
              <div className="flex items-center gap-2 border-t border-slate-800/80 pt-3">
                <button
                  onClick={() => setExpandedNodeSubTab('THROUGHPUT')}
                  className={`flex items-center gap-2 rounded-xl px-3.5 py-1.5 text-xs font-bold transition ${
                    expandedNodeSubTab === 'THROUGHPUT'
                      ? 'border border-cyan-500 bg-cyan-950 text-cyan-300 shadow-lg shadow-cyan-950/60'
                      : 'border border-slate-800 bg-slate-950 text-slate-400 hover:text-slate-200'
                  }`}
                >
                  <Activity className="h-3.5 w-3.5" />
                  <span>
                    {isAr ? 'حركة المرور والتدفق (Throughput)' : 'Ingress & Egress Throughput'}
                  </span>
                </button>

                <button
                  onClick={() => setExpandedNodeSubTab('EDGES')}
                  className={`flex items-center gap-2 rounded-xl px-3.5 py-1.5 text-xs font-bold transition ${
                    expandedNodeSubTab === 'EDGES'
                      ? 'border border-cyan-500 bg-cyan-950 text-cyan-300 shadow-lg shadow-cyan-950/60'
                      : 'border border-slate-800 bg-slate-950 text-slate-400 hover:text-slate-200'
                  }`}
                >
                  <Cable className="h-3.5 w-3.5" />
                  <span>
                    {isAr
                      ? `الروابط المتصلة (${selectedNodeThroughput.connectedEdges.length})`
                      : `Connected Edges (${selectedNodeThroughput.connectedEdges.length})`}
                  </span>
                </button>

                <button
                  onClick={() => setExpandedNodeSubTab('SOCKETS')}
                  className={`flex items-center gap-2 rounded-xl px-3.5 py-1.5 text-xs font-bold transition ${
                    expandedNodeSubTab === 'SOCKETS'
                      ? 'border border-cyan-500 bg-cyan-950 text-cyan-300 shadow-lg shadow-cyan-950/60'
                      : 'border border-slate-800 bg-slate-950 text-slate-400 hover:text-slate-200'
                  }`}
                >
                  <Binary className="h-3.5 w-3.5" />
                  <span>
                    {isAr
                      ? `المقابس النشطة (${sockets.filter(s => s.srcIp === selectedNode.ipAddress || s.dstIp === selectedNode.ipAddress).length})`
                      : `Node Sockets (${sockets.filter(s => s.srcIp === selectedNode.ipAddress || s.dstIp === selectedNode.ipAddress).length})`}
                  </span>
                </button>

                <button
                  onClick={() => setExpandedNodeSubTab('TACTICAL')}
                  className={`flex items-center gap-2 rounded-xl px-3.5 py-1.5 text-xs font-bold transition ${
                    expandedNodeSubTab === 'TACTICAL'
                      ? 'border border-cyan-500 bg-cyan-950 text-cyan-300 shadow-lg shadow-cyan-950/60'
                      : 'border border-slate-800 bg-slate-950 text-slate-400 hover:text-slate-200'
                  }`}
                >
                  <ShieldAlert className="h-3.5 w-3.5" />
                  <span>{isAr ? 'التحكم الدفاعي والنواة' : 'Kernel Defense & Actions'}</span>
                </button>
              </div>
            </div>

            {/* Scrollable Content Body */}
            <div className="flex-1 space-y-6 overflow-y-auto p-5 sm:p-6">
              {/* TAB 1: THROUGHPUT METRICS & WAVEFORM */}
              {expandedNodeSubTab === 'THROUGHPUT' && (
                <div className="space-y-6">
                  {/* Hero Metric Cards */}
                  <div className="grid grid-cols-1 gap-4 font-mono sm:grid-cols-2 lg:grid-cols-4">
                    {/* Ingress RX */}
                    <div className="space-y-3 rounded-2xl border border-cyan-500/30 bg-slate-950 p-4 shadow-xl">
                      <div className="flex items-center justify-between">
                        <span className="flex items-center gap-1.5 text-xs font-bold text-cyan-400">
                          <ArrowDownLeft className="h-4 w-4" />
                          <span>INGRESS THROUGHPUT (RX)</span>
                        </span>
                        <span className="rounded border border-cyan-500/30 bg-cyan-950 px-2 py-0.5 text-[10px] text-cyan-300">
                          LIVE RX
                        </span>
                      </div>
                      <div>
                        <div className="text-2xl font-black text-white sm:text-3xl">
                          {selectedNodeThroughput.ingressBandwidthMbps}{' '}
                          <span className="text-xs font-normal text-cyan-400">Mbps</span>
                        </div>
                        <div className="mt-1 flex items-center justify-between text-xs text-slate-400">
                          <span>
                            Peak:{' '}
                            <strong className="text-slate-200">
                              {selectedNodeThroughput.ingressPeakMbps} Mbps
                            </strong>
                          </span>
                          <span>{selectedNodeThroughput.ingressPps.toLocaleString()} pps</span>
                        </div>
                      </div>
                      <div className="space-y-1 pt-1">
                        <div className="flex justify-between text-[10px] text-slate-400">
                          <span>Buffer Saturation</span>
                          <span
                            className={
                              selectedNodeThroughput.ingressBufferSaturationPercent > 75
                                ? 'font-bold text-rose-400'
                                : 'text-cyan-400'
                            }
                          >
                            {selectedNodeThroughput.ingressBufferSaturationPercent}%
                          </span>
                        </div>
                        <div className="h-1.5 w-full overflow-hidden rounded-full bg-slate-800">
                          <div
                            className={`h-full rounded-full ${
                              selectedNodeThroughput.ingressBufferSaturationPercent > 75
                                ? 'bg-rose-500'
                                : selectedNodeThroughput.ingressBufferSaturationPercent > 50
                                  ? 'bg-amber-400'
                                  : 'bg-cyan-400'
                            }`}
                            style={{
                              width: `${selectedNodeThroughput.ingressBufferSaturationPercent}%`
                            }}
                          />
                        </div>
                      </div>
                    </div>

                    {/* Egress TX */}
                    <div className="space-y-3 rounded-2xl border border-emerald-500/30 bg-slate-950 p-4 shadow-xl">
                      <div className="flex items-center justify-between">
                        <span className="flex items-center gap-1.5 text-xs font-bold text-emerald-400">
                          <ArrowUpRight className="h-4 w-4" />
                          <span>EGRESS THROUGHPUT (TX)</span>
                        </span>
                        <span className="rounded border border-emerald-500/30 bg-emerald-950 px-2 py-0.5 text-[10px] text-emerald-300">
                          LIVE TX
                        </span>
                      </div>
                      <div>
                        <div className="text-2xl font-black text-white sm:text-3xl">
                          {selectedNodeThroughput.egressBandwidthMbps}{' '}
                          <span className="text-xs font-normal text-emerald-400">Mbps</span>
                        </div>
                        <div className="mt-1 flex items-center justify-between text-xs text-slate-400">
                          <span>
                            Peak:{' '}
                            <strong className="text-slate-200">
                              {selectedNodeThroughput.egressPeakMbps} Mbps
                            </strong>
                          </span>
                          <span>{selectedNodeThroughput.egressPps.toLocaleString()} pps</span>
                        </div>
                      </div>
                      <div className="space-y-1 pt-1">
                        <div className="flex justify-between text-[10px] text-slate-400">
                          <span>Queue Depth Saturation</span>
                          <span
                            className={
                              selectedNodeThroughput.egressQueueDepthPercent > 70
                                ? 'font-bold text-amber-400'
                                : 'text-emerald-400'
                            }
                          >
                            {selectedNodeThroughput.egressQueueDepthPercent}%
                          </span>
                        </div>
                        <div className="h-1.5 w-full overflow-hidden rounded-full bg-slate-800">
                          <div
                            className={`h-full rounded-full ${
                              selectedNodeThroughput.egressQueueDepthPercent > 70
                                ? 'bg-amber-400'
                                : 'bg-emerald-400'
                            }`}
                            style={{ width: `${selectedNodeThroughput.egressQueueDepthPercent}%` }}
                          />
                        </div>
                      </div>
                    </div>

                    {/* Cumulative Volume */}
                    <div className="space-y-3 rounded-2xl border border-slate-800 bg-slate-950 p-4 shadow-xl">
                      <div className="flex items-center justify-between">
                        <span className="flex items-center gap-1.5 text-xs font-bold text-indigo-400">
                          <HardDrive className="h-4 w-4" />
                          <span>DATA TRANSFERRED</span>
                        </span>
                        <span className="rounded border border-indigo-500/30 bg-indigo-950 px-2 py-0.5 text-[10px] text-indigo-300">
                          TOTAL
                        </span>
                      </div>
                      <div className="space-y-1.5 text-xs">
                        <div className="flex justify-between">
                          <span className="text-slate-400">RX Total:</span>
                          <span className="font-bold text-white">
                            {selectedNodeThroughput.ingressBytesTotal}
                          </span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-slate-400">TX Total:</span>
                          <span className="font-bold text-white">
                            {selectedNodeThroughput.egressBytesTotal}
                          </span>
                        </div>
                        <div className="flex justify-between border-t border-slate-800 pt-1 text-[11px]">
                          <span className="text-slate-400">RX Drops:</span>
                          <span
                            className={
                              selectedNodeThroughput.ingressDropRatePercent > 1
                                ? 'font-bold text-rose-400'
                                : 'text-emerald-400'
                            }
                          >
                            {selectedNodeThroughput.ingressDropRatePercent}%
                          </span>
                        </div>
                        <div className="flex justify-between text-[11px]">
                          <span className="text-slate-400">TX Retransmit:</span>
                          <span
                            className={
                              selectedNodeThroughput.egressRetransmitRatePercent > 1
                                ? 'font-bold text-amber-400'
                                : 'text-emerald-400'
                            }
                          >
                            {selectedNodeThroughput.egressRetransmitRatePercent}%
                          </span>
                        </div>
                      </div>
                    </div>

                    {/* Hardware NIC & eBPF Telemetry */}
                    <div className="space-y-3 rounded-2xl border border-slate-800 bg-slate-950 p-4 shadow-xl">
                      <div className="flex items-center justify-between">
                        <span className="flex items-center gap-1.5 text-xs font-bold text-amber-400">
                          <Cpu className="h-4 w-4" />
                          <span>NIC & HARDWARE HOOK</span>
                        </span>
                        <span className="rounded border border-amber-500/30 bg-amber-950 px-2 py-0.5 text-[10px] text-amber-300">
                          eBPF XDP
                        </span>
                      </div>
                      <div className="space-y-1 text-xs">
                        <div>
                          <span className="block text-[10px] text-slate-500">Driver Hook:</span>
                          <span className="block truncate font-bold text-slate-200">
                            {selectedNodeThroughput.driverMode}
                          </span>
                        </div>
                        <div>
                          <span className="block text-[10px] text-slate-500">MAC Address:</span>
                          <span className="font-bold text-cyan-300">
                            {selectedNodeThroughput.macAddress}
                          </span>
                        </div>
                        <div className="flex justify-between border-t border-slate-800 pt-1 text-[11px]">
                          <span className="text-slate-400">Jumbo MTU:</span>
                          <span className="font-bold text-emerald-400">
                            {selectedNodeThroughput.mtuBytes} B
                          </span>
                        </div>
                        <div className="flex justify-between text-[11px]">
                          <span className="text-slate-400">IRQ Interrupts:</span>
                          <span className="font-bold text-cyan-400">
                            {selectedNodeThroughput.irqRatePerSec} /sec
                          </span>
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Dynamic Throughput Waveform (SVG Sparkline & Chart) */}
                  <div className="space-y-4 rounded-2xl border border-slate-800 bg-slate-950 p-5 shadow-2xl">
                    <div className="flex flex-col items-start justify-between gap-2 border-b border-slate-800 pb-3 sm:flex-row sm:items-center">
                      <div>
                        <h3 className="flex items-center gap-2 text-sm font-bold text-white">
                          <Activity className="h-4 w-4 text-cyan-400" />
                          <span>
                            {isAr
                              ? 'مخطط تدفق البيانات الحي (Throughput Timeline Waveform)'
                              : 'Real-Time Ingress vs Egress Waveform'}
                          </span>
                        </h3>
                        <p className="text-xs text-slate-400">
                          {isAr
                            ? 'مقارنة مستمرة بين معدل الاستقبال (Ingress RX) ومعدل الإرسال (Egress TX) عبر الزمن'
                            : 'Continuous comparison of RX vs TX bandwidth saturation (Mbps) sampled every 500ms'}
                        </p>
                      </div>
                      <div className="flex items-center gap-4 font-mono text-xs">
                        <div className="flex items-center gap-1.5">
                          <span className="h-3 w-3 rounded bg-cyan-400 shadow-sm shadow-cyan-400" />
                          <span className="text-slate-300">Ingress (RX)</span>
                        </div>
                        <div className="flex items-center gap-1.5">
                          <span className="h-3 w-3 rounded bg-emerald-400 shadow-sm shadow-emerald-400" />
                          <span className="text-slate-300">Egress (TX)</span>
                        </div>
                      </div>
                    </div>

                    {/* SVG Waveform Visualizer */}
                    <div className="relative flex h-44 w-full flex-col justify-end overflow-hidden rounded-xl border border-slate-800/80 bg-slate-900/60 p-3 sm:h-52">
                      {/* Grid guidelines */}
                      <div className="pointer-events-none absolute inset-0 flex flex-col justify-between p-3 opacity-20">
                        <div className="w-full border-b border-dashed border-slate-400" />
                        <div className="w-full border-b border-dashed border-slate-400" />
                        <div className="w-full border-b border-dashed border-slate-400" />
                        <div className="w-full border-b border-slate-400" />
                      </div>

                      {/* SVG Curves */}
                      {(() => {
                        const history = selectedNodeThroughput.history;
                        const maxVal = Math.max(
                          ...history.map(h => Math.max(h.ingressMbps, h.egressMbps)),
                          100
                        );
                        const svgWidth = 800;
                        const svgHeight = 150;

                        const getX = (idx: number) => (idx / (history.length - 1)) * svgWidth;
                        const getY = (val: number) =>
                          svgHeight - (val / maxVal) * (svgHeight - 20) - 10;

                        const ingressPoints = history
                          .map((h, i) => `${getX(i)},${getY(h.ingressMbps)}`)
                          .join(' ');
                        const egressPoints = history
                          .map((h, i) => `${getX(i)},${getY(h.egressMbps)}`)
                          .join(' ');

                        const ingressArea = `${getX(0)},${svgHeight} ${ingressPoints} ${getX(history.length - 1)},${svgHeight}`;
                        const egressArea = `${getX(0)},${svgHeight} ${egressPoints} ${getX(history.length - 1)},${svgHeight}`;

                        return (
                          <svg
                            viewBox={`0 0 ${svgWidth} ${svgHeight}`}
                            className="z-10 h-full w-full overflow-visible"
                            preserveAspectRatio="none"
                          >
                            <defs>
                              <linearGradient id="ingressGrad" x1="0" y1="0" x2="0" y2="1">
                                <stop offset="0%" stopColor="#00f0ff" stopOpacity="0.4" />
                                <stop offset="100%" stopColor="#00f0ff" stopOpacity="0.0" />
                              </linearGradient>
                              <linearGradient id="egressGrad" x1="0" y1="0" x2="0" y2="1">
                                <stop offset="0%" stopColor="#10b981" stopOpacity="0.35" />
                                <stop offset="100%" stopColor="#10b981" stopOpacity="0.0" />
                              </linearGradient>
                            </defs>

                            {/* Ingress Area & Line */}
                            <polygon points={ingressArea} fill="url(#ingressGrad)" />
                            <polyline
                              fill="none"
                              stroke="#00f0ff"
                              strokeWidth="2.5"
                              strokeLinecap="round"
                              strokeLinejoin="round"
                              points={ingressPoints}
                            />

                            {/* Egress Area & Line */}
                            <polygon points={egressArea} fill="url(#egressGrad)" />
                            <polyline
                              fill="none"
                              stroke="#10b981"
                              strokeWidth="2.5"
                              strokeLinecap="round"
                              strokeLinejoin="round"
                              points={egressPoints}
                            />

                            {/* Data points */}
                            {history.map((h, i) => (
                              <g key={`sparkline-point-${h.time}`}>
                                <circle
                                  cx={getX(i)}
                                  cy={getY(h.ingressMbps)}
                                  r="3"
                                  fill="#00f0ff"
                                  stroke="#0d1117"
                                  strokeWidth="1.5"
                                />
                                <circle
                                  cx={getX(i)}
                                  cy={getY(h.egressMbps)}
                                  r="3"
                                  fill="#10b981"
                                  stroke="#0d1117"
                                  strokeWidth="1.5"
                                />
                              </g>
                            ))}
                          </svg>
                        );
                      })()}

                      {/* Time labels below chart */}
                      <div className="z-10 mt-2 flex justify-between font-mono text-[9px] text-slate-500">
                        <span>-12s</span>
                        <span>-9s</span>
                        <span>-6s</span>
                        <span>-3s</span>
                        <span className="font-bold text-cyan-400">LIVE (NOW)</span>
                      </div>
                    </div>
                  </div>

                  {/* Protocol Breakdown and Encryption Matrix */}
                  <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
                    {/* Protocol Breakdown */}
                    <div className="space-y-3 rounded-2xl border border-slate-800 bg-slate-950 p-4">
                      <h4 className="flex items-center gap-2 text-xs font-bold tracking-wider text-white uppercase">
                        <Binary className="h-4 w-4 text-cyan-400" />
                        <span>
                          {isAr
                            ? 'توزيع البروتوكولات عبر حركة العقدة'
                            : 'Ingress Protocol Distribution'}
                        </span>
                      </h4>
                      <div className="space-y-2 font-mono text-xs">
                        <div>
                          <div className="mb-1 flex justify-between text-[11px]">
                            <span className="text-cyan-300">TCP (HTTP/2 / TLS 1.3 / gRPC)</span>
                            <span className="font-bold text-white">
                              {selectedNodeThroughput.protocolBreakdown.tcpPercent}%
                            </span>
                          </div>
                          <div className="h-2 w-full overflow-hidden rounded-full bg-slate-800">
                            <div
                              className="h-full bg-cyan-400"
                              style={{
                                width: `${selectedNodeThroughput.protocolBreakdown.tcpPercent}%`
                              }}
                            />
                          </div>
                        </div>

                        <div>
                          <div className="mb-1 flex justify-between text-[11px]">
                            <span className="text-indigo-300">UDP (QUIC / DNS / RoCE)</span>
                            <span className="font-bold text-white">
                              {selectedNodeThroughput.protocolBreakdown.udpPercent}%
                            </span>
                          </div>
                          <div className="h-2 w-full overflow-hidden rounded-full bg-slate-800">
                            <div
                              className="h-full bg-indigo-400"
                              style={{
                                width: `${selectedNodeThroughput.protocolBreakdown.udpPercent}%`
                              }}
                            />
                          </div>
                        </div>

                        <div>
                          <div className="mb-1 flex justify-between text-[11px]">
                            <span className="text-amber-300">ICMP / Diagnostic Radar</span>
                            <span className="font-bold text-white">
                              {selectedNodeThroughput.protocolBreakdown.icmpPercent}%
                            </span>
                          </div>
                          <div className="h-2 w-full overflow-hidden rounded-full bg-slate-800">
                            <div
                              className="h-full bg-amber-400"
                              style={{
                                width: `${selectedNodeThroughput.protocolBreakdown.icmpPercent}%`
                              }}
                            />
                          </div>
                        </div>

                        <div>
                          <div className="mb-1 flex justify-between text-[11px]">
                            <span className="text-emerald-300">Encrypted Payload Ratio</span>
                            <span className="font-bold text-white">
                              {selectedNodeThroughput.protocolBreakdown.tlsEncryptedPercent}%
                            </span>
                          </div>
                          <div className="h-2 w-full overflow-hidden rounded-full bg-slate-800">
                            <div
                              className="h-full bg-emerald-400"
                              style={{
                                width: `${selectedNodeThroughput.protocolBreakdown.tlsEncryptedPercent}%`
                              }}
                            />
                          </div>
                        </div>
                      </div>
                    </div>

                    {/* Encryption & Security Pipeline */}
                    <div className="space-y-3 rounded-2xl border border-slate-800 bg-slate-950 p-4 font-mono text-xs">
                      <h4 className="flex items-center gap-2 text-xs font-bold tracking-wider text-white uppercase">
                        <Lock className="h-4 w-4 text-emerald-400" />
                        <span>
                          {isAr
                            ? 'تشفير وحماية القنوات الخارجة'
                            : 'Egress Security & Cryptographic Tunnel'}
                        </span>
                      </h4>
                      <div className="space-y-2.5">
                        <div className="rounded-xl border border-slate-800 bg-slate-900 p-2.5">
                          <span className="block text-[10px] text-slate-500">
                            Cryptographic Standard:
                          </span>
                          <span className="font-bold text-emerald-300">
                            {selectedNodeThroughput.egressEncryption}
                          </span>
                        </div>
                        <div className="grid grid-cols-2 gap-2">
                          <div className="rounded-xl border border-slate-800 bg-slate-900 p-2.5">
                            <span className="block text-[10px] text-slate-500">MTU Size:</span>
                            <span className="font-bold text-white">
                              {selectedNodeThroughput.mtuBytes} Bytes
                            </span>
                          </div>
                          <div className="rounded-xl border border-slate-800 bg-slate-900 p-2.5">
                            <span className="block text-[10px] text-slate-500">
                              Packet Retransmit:
                            </span>
                            <span className="font-bold text-cyan-400">
                              {selectedNodeThroughput.egressRetransmitRatePercent}%
                            </span>
                          </div>
                        </div>
                        <div className="flex items-center justify-between rounded-xl border border-slate-800 bg-slate-900 p-2.5">
                          <span className="text-slate-400">Zero-Copy Direct Socket:</span>
                          <span className="rounded border border-emerald-500/40 bg-emerald-950 px-2 py-0.5 text-[10px] font-bold text-emerald-300">
                            ENABLED (vmsplice)
                          </span>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {/* TAB 2: CONNECTED EDGES & NEIGHBOR LINKS */}
              {expandedNodeSubTab === 'EDGES' && (
                <div className="space-y-5">
                  <div className="flex flex-col items-start justify-between gap-3 rounded-2xl border border-slate-800 bg-slate-950 p-4 sm:flex-row sm:items-center">
                    <div>
                      <h3 className="flex items-center gap-2 text-sm font-bold text-white">
                        <Cable className="h-4 w-4 text-cyan-400" />
                        <span>
                          {isAr
                            ? `روابط الشبكة المباشرة للعقدة (${selectedNodeThroughput.connectedEdges.length} روابط)`
                            : `Direct Mesh Edges & Peer Topologies (${selectedNodeThroughput.connectedEdges.length} Connected Links)`}
                        </span>
                      </h3>
                      <p className="text-xs text-slate-400">
                        {isAr
                          ? 'عرض تفصيلي لكل مسار شبكي متصل: السعة، معدل التدفق، زمن الاستجابة، ونوع التشفير مع أدوات الاختبار والتحكم'
                          : 'Granular telemetry for every connected edge: bandwidth capacity, live throughput, RTT latency, and dynamic QoS controls'}
                      </p>
                    </div>

                    <div className="flex items-center gap-2">
                      <span className="rounded-xl border border-cyan-500/40 bg-cyan-950 px-3 py-1 font-mono text-xs font-bold text-cyan-300">
                        Aggregate Capacity:{' '}
                        {selectedNodeThroughput.connectedEdges.reduce(
                          (acc, e) => acc + e.capacityGbps,
                          0
                        )}{' '}
                        Gbps
                      </span>
                    </div>
                  </div>

                  {/* Connected Edges Grid */}
                  <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
                    {selectedNodeThroughput.connectedEdges.map(edge => {
                      const isQuarantined =
                        edgeQuarantined[edge.id] || edge.status === 'QUARANTINED';
                      const isQoSLimited = edgeQoSThrottled[edge.id];
                      const pingResult = edgePingResults[edge.id];
                      const isPingTesting = pingTestingEdgeId === edge.id;

                      const saturationPercent = Math.min(
                        100,
                        Math.round(
                          (edge.currentThroughputMbps / (edge.capacityGbps * 1000)) * 100 * 12
                        )
                      );

                      return (
                        <div
                          key={edge.id}
                          className={`space-y-4 rounded-2xl border p-5 shadow-xl transition ${
                            isQuarantined
                              ? 'border-rose-600/70 bg-rose-950/30 shadow-rose-950/40'
                              : isQoSLimited
                                ? 'border-amber-500/60 bg-amber-950/30 shadow-amber-950/30'
                                : 'border-slate-800 bg-slate-950 hover:border-cyan-500/50'
                          }`}
                        >
                          {/* Edge Header */}
                          <div className="flex items-center justify-between">
                            <div className="flex items-center gap-2.5">
                              <div
                                className={`flex h-8 w-8 items-center justify-center rounded-xl font-mono text-xs font-bold ${
                                  isQuarantined
                                    ? 'border border-rose-500/40 bg-rose-950 text-rose-300'
                                    : 'border border-cyan-500/40 bg-cyan-950 text-cyan-300'
                                }`}
                              >
                                {edge.direction === 'INGRESS'
                                  ? '←'
                                  : edge.direction === 'EGRESS'
                                    ? '→'
                                    : '⇄'}
                              </div>
                              <div>
                                <h4 className="flex items-center gap-2 text-sm font-bold text-white">
                                  <span>{isAr ? edge.neighborLabelAr : edge.neighborLabel}</span>
                                </h4>
                                <span className="block font-mono text-[11px] text-slate-400">
                                  {edge.neighborIp} • {edge.neighborVlan}
                                </span>
                              </div>
                            </div>

                            <span
                              className={`rounded-full border px-2.5 py-0.5 font-mono text-[10px] font-bold uppercase ${
                                isQuarantined
                                  ? 'border-rose-500/50 bg-rose-500/20 text-rose-300'
                                  : edge.status === 'CONGESTED'
                                    ? 'border-amber-500/50 bg-amber-500/20 text-amber-300'
                                    : 'border-emerald-500/40 bg-emerald-500/20 text-emerald-300'
                              }`}
                            >
                              {isQuarantined
                                ? 'QUARANTINED'
                                : isQoSLimited
                                  ? 'QoS THROTTLED'
                                  : edge.status}
                            </span>
                          </div>

                          {/* Edge Stats Matrix */}
                          <div className="grid grid-cols-2 gap-2.5 rounded-xl border border-slate-800/80 bg-slate-900/80 p-3 font-mono text-xs">
                            <div>
                              <span className="block text-[10px] text-slate-500">
                                Link Capacity:
                              </span>
                              <span className="font-bold text-cyan-300">
                                {edge.capacityGbps} Gbps
                              </span>
                            </div>
                            <div>
                              <span className="block text-[10px] text-slate-500">
                                Live Throughput:
                              </span>
                              <span className="font-bold text-white">
                                {edge.currentThroughputMbps} Mbps
                              </span>
                            </div>
                            <div>
                              <span className="block text-[10px] text-slate-500">Latency RTT:</span>
                              <span className="font-bold text-emerald-400">
                                {pingResult
                                  ? `${pingResult.rttMs} ms (±${pingResult.jitterMs}ms)`
                                  : `${edge.latencyMs} ms`}
                              </span>
                            </div>
                            <div>
                              <span className="block text-[10px] text-slate-500">Packet Loss:</span>
                              <span
                                className={
                                  edge.packetLossPercent > 0.5
                                    ? 'font-bold text-rose-400'
                                    : 'text-slate-300'
                                }
                              >
                                {edge.packetLossPercent}%
                              </span>
                            </div>
                          </div>

                          {/* Saturation Bar */}
                          <div className="space-y-1">
                            <div className="flex justify-between font-mono text-[10px] text-slate-400">
                              <span>Link Load & Saturation</span>
                              <span>{saturationPercent}%</span>
                            </div>
                            <div className="h-1.5 w-full overflow-hidden rounded-full bg-slate-800">
                              <div
                                className={`h-full rounded-full ${
                                  saturationPercent > 80
                                    ? 'bg-rose-500'
                                    : saturationPercent > 50
                                      ? 'bg-amber-400'
                                      : 'bg-cyan-400'
                                }`}
                                style={{ width: `${saturationPercent}%` }}
                              />
                            </div>
                          </div>

                          {/* Encapsulation and Security Protocol */}
                          <div className="flex items-center justify-between rounded-xl border border-slate-800 bg-slate-900/50 p-2.5 font-mono text-[11px] text-slate-300">
                            <span className="text-slate-500">Protocol & Encap:</span>
                            <span className="max-w-[200px] truncate font-bold text-cyan-300">
                              {edge.protocol}
                            </span>
                          </div>

                          {/* Action Directives per Edge */}
                          <div className="grid grid-cols-3 gap-2 border-t border-slate-800/80 pt-1">
                            <button
                              onClick={() => handleTestEdgePing(edge.id, edge.latencyMs)}
                              disabled={isPingTesting}
                              className="flex items-center justify-center gap-1 rounded-xl border border-slate-700 bg-slate-900 px-2 py-1.5 font-mono text-[11px] font-bold text-slate-200 transition hover:bg-slate-800"
                            >
                              <Activity
                                className={`h-3.5 w-3.5 ${isPingTesting ? 'animate-spin text-cyan-400' : 'text-cyan-400'}`}
                              />
                              <span>{isPingTesting ? 'Pinging...' : 'Ping RTT'}</span>
                            </button>

                            <button
                              onClick={() => handleToggleEdgeQoS(edge.id)}
                              className={`flex items-center justify-center gap-1 rounded-xl border px-2 py-1.5 font-mono text-[11px] font-bold transition ${
                                isQoSLimited
                                  ? 'border-amber-500 bg-amber-950 text-amber-300'
                                  : 'border-slate-700 bg-slate-900 text-slate-300 hover:bg-slate-800'
                              }`}
                            >
                              <SlidersHorizontal className="h-3.5 w-3.5 text-amber-400" />
                              <span>{isQoSLimited ? 'QoS Active' : 'Throttle QoS'}</span>
                            </button>

                            <button
                              onClick={() => handleToggleEdgeQuarantine(edge.id)}
                              className={`flex items-center justify-center gap-1 rounded-xl border px-2 py-1.5 font-mono text-[11px] font-bold transition ${
                                isQuarantined
                                  ? 'border-emerald-500 bg-emerald-950 text-emerald-300'
                                  : 'border-rose-600/80 bg-rose-950/80 text-rose-200 hover:bg-rose-900'
                              }`}
                            >
                              <Ban className="h-3.5 w-3.5" />
                              <span>{isQuarantined ? 'Restore Link' : 'Quarantine'}</span>
                            </button>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}

              {/* TAB 3: ACTIVE NODE SOCKETS */}
              {expandedNodeSubTab === 'SOCKETS' && (
                <div className="space-y-4">
                  <div className="flex items-center justify-between rounded-2xl border border-slate-800 bg-slate-950 p-4">
                    <div>
                      <h3 className="flex items-center gap-2 text-sm font-bold text-white">
                        <Binary className="h-4 w-4 text-cyan-400" />
                        <span>
                          {isAr
                            ? `المقابس الشبكية النشطة المتصلة بالعقدة (${selectedNode.ipAddress})`
                            : `Active Socket Connections Linked to ${selectedNode.label} (${selectedNode.ipAddress})`}
                        </span>
                      </h3>
                      <p className="text-xs text-slate-400">
                        {isAr
                          ? 'فحص جميع الاتصالات المباشرة والموجهة عبر هذه العقدة مع إمكانية فحص الإطارات وتحليل الـ Hex'
                          : 'Live socket streams terminating or routing through this node with Deep Packet Inspection'}
                      </p>
                    </div>

                    <span className="rounded-xl border border-cyan-500/40 bg-cyan-950 px-3 py-1 font-mono text-xs font-bold text-cyan-300">
                      {
                        sockets.filter(
                          s =>
                            s.srcIp === selectedNode.ipAddress || s.dstIp === selectedNode.ipAddress
                        ).length
                      }{' '}
                      Active Streams
                    </span>
                  </div>

                  <div className="overflow-x-auto rounded-2xl border border-slate-800 bg-slate-950">
                    <table className="w-full text-left font-mono text-xs">
                      <thead className="border-b border-slate-800 bg-slate-900/90 text-slate-400">
                        <tr>
                          <th className="p-3">Stream ID</th>
                          <th className="p-3">Process</th>
                          <th className="p-3">Source → Dest</th>
                          <th className="p-3">Protocol</th>
                          <th className="p-3">State</th>
                          <th className="p-3">Threat</th>
                          <th className="p-3 text-right">Action</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800/80">
                        {sockets
                          .filter(
                            s =>
                              s.srcIp === selectedNode.ipAddress ||
                              s.dstIp === selectedNode.ipAddress
                          )
                          .map(s => (
                            <tr key={s.id} className="transition hover:bg-slate-900/60">
                              <td className="p-3 font-bold text-cyan-400">{s.id}</td>
                              <td className="p-3 text-slate-200">
                                {s.processName} <span className="text-slate-500">({s.pid})</span>
                              </td>
                              <td className="p-3 text-slate-300">
                                {s.srcIp}:{s.srcPort} → {s.dstIp}:{s.dstPort}
                              </td>
                              <td className="p-3 text-indigo-300">{s.protocol}</td>
                              <td className="p-3">
                                <span className="rounded border border-slate-700 bg-slate-900 px-2 py-0.5 text-[10px] text-slate-200">
                                  {s.state}
                                </span>
                              </td>
                              <td className="p-3">
                                <span
                                  className={`rounded px-2 py-0.5 text-[10px] font-bold ${
                                    s.threatLevel === 'MALICIOUS'
                                      ? 'border border-rose-800 bg-rose-950 text-rose-400'
                                      : s.threatLevel === 'SUSPICIOUS'
                                        ? 'border border-amber-800 bg-amber-950 text-amber-400'
                                        : 'border border-emerald-800 bg-emerald-950 text-emerald-400'
                                  }`}
                                >
                                  {s.threatLevel}
                                </span>
                              </td>
                              <td className="p-3 text-right">
                                <button
                                  onClick={() => setSelectedSocket(s)}
                                  className="rounded-lg border border-cyan-500/40 bg-cyan-950 px-2.5 py-1 text-[11px] font-bold text-cyan-300 transition hover:bg-cyan-900"
                                >
                                  DPI Hex
                                </button>
                              </td>
                            </tr>
                          ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

              {/* TAB 4: TACTICAL DEFENSE & ACTIONS */}
              {expandedNodeSubTab === 'TACTICAL' && (
                <div className="space-y-6">
                  {/* Security Quick-Lock Feature Card */}
                  <div
                    className={`rounded-2xl border p-5 transition-all ${
                      quickLockedNodes[selectedNode.id]
                        ? 'border-rose-500/60 bg-rose-950/30 shadow-xl shadow-rose-950/40'
                        : 'border-slate-800 bg-slate-950'
                    }`}
                  >
                    <div className="flex flex-col items-start justify-between gap-4 sm:flex-row sm:items-center">
                      <div className="space-y-1">
                        <div className="flex items-center gap-2">
                          <div
                            className={`flex h-8 w-8 items-center justify-center rounded-lg ${
                              quickLockedNodes[selectedNode.id]
                                ? 'animate-pulse bg-rose-600 text-white'
                                : 'border border-rose-500/30 bg-rose-950/50 text-rose-400'
                            }`}
                          >
                            <Lock className="h-4 w-4" />
                          </div>
                          <h4 className="flex items-center gap-2 text-sm font-bold text-white">
                            <span>
                              {isAr
                                ? 'القفل الأمني السريع لنطاق العقدة (eBPF Quick-Lock)'
                                : 'Security Quick-Lock (Kernel eBPF/XDP Drop)'}
                            </span>
                            {quickLockedNodes[selectedNode.id] && (
                              <span className="animate-pulse rounded-full bg-rose-500 px-2 py-0.5 font-mono text-[10px] font-black text-white">
                                DROP ENFORCED
                              </span>
                            )}
                          </h4>
                        </div>
                        <p className="max-w-2xl text-xs text-slate-400">
                          {isAr
                            ? `تطبيق قاعدة إسقاط فورية عبر تعريف النواة eBPF XDP لجميع حزم البيانات الصادرة أو الواردة من نطاق العقدة (${selectedNode.ipAddress} / ${selectedNode.vlan}) لتجميد التهديدات في طبقة كرت الشبكة.`
                            : `Instantly apply a sub-microsecond eBPF/XDP drop-rule for all traffic originating from or targeting this node segment (${selectedNode.ipAddress} / ${selectedNode.vlan}) directly in the NIC kernel hook.`}
                        </p>
                      </div>

                      <button
                        onClick={() => handleToggleQuickLock(selectedNode)}
                        disabled={isLoading}
                        className={`flex shrink-0 items-center gap-2 rounded-xl px-5 py-2.5 text-xs font-bold shadow-lg transition ${
                          quickLockedNodes[selectedNode.id]
                            ? 'border border-rose-400 bg-rose-600 text-white shadow-rose-950/70 hover:bg-rose-500'
                            : 'border border-rose-500/40 bg-slate-900 text-rose-300 shadow-slate-950 hover:border-rose-500 hover:bg-rose-950/60 hover:text-white'
                        }`}
                      >
                        {quickLockedNodes[selectedNode.id] ? (
                          <>
                            <Unlock className="h-4 w-4" />
                            <span>
                              {isAr ? 'إلغاء القفل السريع (Disengage)' : 'Disengage Quick-Lock'}
                            </span>
                          </>
                        ) : (
                          <>
                            <Lock className="h-4 w-4 text-rose-400" />
                            <span>
                              {isAr
                                ? 'تفعيل القفل السريع (Quick-Lock)'
                                : 'Engage Security Quick-Lock'}
                            </span>
                          </>
                        )}
                      </button>
                    </div>
                  </div>

                  <div className="space-y-4 rounded-2xl border border-slate-800 bg-slate-950 p-5">
                    <h3 className="flex items-center gap-2 text-sm font-bold text-white">
                      <ShieldCheck className="h-4 w-4 text-cyan-400" />
                      <span>
                        {isAr
                          ? 'أوامر التحكم التكتيكية للعقدة'
                          : 'Node Defensive Directives & Attack Simulation'}
                      </span>
                    </h3>

                    <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 md:grid-cols-3">
                      {selectedNode.status === 'ISOLATED' ? (
                        <button
                          onClick={() => handleRestoreNode(selectedNode.id)}
                          disabled={isLoading}
                          className="flex flex-col items-center justify-center gap-2 rounded-xl bg-emerald-600 p-4 text-xs font-bold text-white shadow-lg shadow-emerald-950/50 transition hover:bg-emerald-500"
                        >
                          <Unlock className="h-5 w-5" />
                          <span>Restore Node to Mesh</span>
                        </button>
                      ) : (
                        <button
                          onClick={() => handleIsolateNode(selectedNode.id)}
                          disabled={isLoading}
                          className="flex flex-col items-center justify-center gap-2 rounded-xl bg-rose-600 p-4 text-xs font-bold text-white shadow-lg shadow-rose-950/50 transition hover:bg-rose-500"
                        >
                          <Ban className="h-5 w-5" />
                          <span>Isolate Subnet Immediately</span>
                        </button>
                      )}

                      <button
                        onClick={() =>
                          handleSimulateAttackVector(
                            selectedNode.id,
                            'SYN Flood / L4 Amp',
                            'CRITICAL'
                          )
                        }
                        className="flex flex-col items-center justify-center gap-2 rounded-xl border border-slate-700 bg-slate-900 p-4 text-xs font-bold text-slate-200 transition hover:bg-slate-800"
                      >
                        <Flame className="h-5 w-5 text-rose-400" />
                        <span>Simulate L4 SYN Flood</span>
                      </button>

                      <button
                        onClick={() =>
                          handleSimulateAttackVector(
                            selectedNode.id,
                            'Prompt Injection / SQLi',
                            'HIGH'
                          )
                        }
                        className="flex flex-col items-center justify-center gap-2 rounded-xl border border-slate-700 bg-slate-900 p-4 text-xs font-bold text-slate-200 transition hover:bg-slate-800"
                      >
                        <Zap className="h-5 w-5 text-amber-400" />
                        <span>Simulate L7 Prompt Injection</span>
                      </button>
                    </div>
                  </div>
                </div>
              )}
            </div>

            {/* Footer with close trigger */}
            <div className="flex items-center justify-between border-t border-slate-800 bg-slate-950 p-4 font-mono text-xs text-slate-400">
              <span>Node Inspector Stream: Active • eBPF XDP Hooked</span>
              <button
                onClick={() => setIsNodeExpanded(false)}
                className="rounded-xl bg-slate-800 px-4 py-2 font-bold text-white transition hover:bg-slate-700"
              >
                {isAr ? 'إغلاق اللوحة' : 'Close Deep Inspector'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
