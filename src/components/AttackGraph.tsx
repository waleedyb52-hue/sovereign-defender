import React, { useState, useEffect } from 'react';
import {
  NetworkNode,
  NetworkEdge,
  TelemetryPacket,
  TopologyViewMode,
  GeoThreatNode,
  KillChainStage
} from '../types';
import { INITIAL_GEO_THREATS, INITIAL_KILL_CHAIN_STAGES } from '../data/defaultThreatData';
import {
  Shield,
  ShieldAlert,
  Server,
  Database,
  Router,
  Skull,
  Radio,
  Lock,
  Globe,
  Layers,
  Activity,
  Compass,
  Crosshair,
  Power,
  CheckCircle2,
  AlertTriangle,
  Sliders,
  Maximize2,
  Terminal,
  Zap
} from 'lucide-react';

interface AttackGraphProps {
  nodes: NetworkNode[];
  edges: NetworkEdge[];
  activePackets: TelemetryPacket[];
  lang: 'ar' | 'en';
  onSelectNode?: (node: NetworkNode) => void;
  onToggleIsolateNode?: (nodeId: string) => void;
}

export const AttackGraph: React.FC<AttackGraphProps> = ({
  nodes,
  edges,
  activePackets,
  lang,
  onSelectNode,
  onToggleIsolateNode
}) => {
  const isAr = lang === 'ar';
  const [activeViewMode, setActiveViewMode] = useState<TopologyViewMode>('ARCHITECTURE');
  const [selectedNode, setSelectedNode] = useState<NetworkNode | null>(
    nodes.find(n => n.id === 'node-defender') || null
  );
  const [animatedParticles, setAnimatedParticles] = useState<
    { id: string; edgeId: string; progress: number; color: string }[]
  >([]);
  const [geoThreats] = useState<GeoThreatNode[]>(INITIAL_GEO_THREATS);
  const [killChainStages] = useState<KillChainStage[]>(INITIAL_KILL_CHAIN_STAGES);
  const [filterStatus, setFilterStatus] = useState<'ALL' | 'ATTACK' | 'PROTECTED' | 'HONEYPOT'>(
    'ALL'
  );
  const [simulatedBlastRadius, setSimulatedBlastRadius] = useState<string | null>('node-web');

  // Periodically generate visual packet flow particles based on recent telemetry
  useEffect(() => {
    const interval = setInterval(() => {
      setAnimatedParticles(prev => {
        const updated = prev
          .map(p => ({ ...p, progress: p.progress + 0.08 }))
          .filter(p => p.progress < 1);

        // Add new particles along active edges
        if (edges.length > 0 && updated.length < 14) {
          const randomEdge = edges[Math.floor(Math.random() * edges.length)];
          const particleColor =
            randomEdge.target === 'node-honeypot'
              ? '#c084fc'
              : randomEdge.threatLevel === 'HIGH' || randomEdge.threatLevel === 'CRITICAL'
                ? '#f43f5e'
                : '#10b981';

          updated.push({
            id: crypto.randomUUID(),
            edgeId: randomEdge.id,
            progress: 0,
            color: particleColor
          });
        }
        return updated;
      });
    }, 90);

    return () => clearInterval(interval);
  }, [edges]);

  const getNodeIcon = (type: NetworkNode['type']) => {
    switch (type) {
      case 'ATTACKER':
        return <Skull className="h-4 w-4 text-rose-400" />;
      case 'DEFENDER':
        return <Shield className="h-4 w-4 text-emerald-400" />;
      case 'GATEWAY':
        return <Router className="h-4 w-4 text-cyan-400" />;
      case 'WEB_SERVER':
        return <Server className="h-4 w-4 text-cyan-400" />;
      case 'DATABASE':
        return <Database className="h-4 w-4 text-amber-400" />;
      case 'HONEYPOT':
        return <Radio className="h-4 w-4 text-cyan-400" />;
      case 'BASTION':
        return <Lock className="h-4 w-4 text-cyan-400" />;
      default:
        return <Server className="h-4 w-4 text-slate-400" />;
    }
  };

  const getNodeColorClass = (
    type: NetworkNode['type'],
    isSelected: boolean,
    isIsolated: boolean
  ) => {
    if (isIsolated)
      return 'bg-rose-950/80 border-rose-500 text-rose-300 ring-2 ring-rose-500/50 opacity-70';
    if (isSelected)
      return 'ring-2 ring-emerald-400 bg-slate-900 border-emerald-400 shadow-lg shadow-emerald-500/20';
    switch (type) {
      case 'ATTACKER':
        return 'bg-rose-950/70 border-rose-600/60 hover:border-rose-400 text-rose-300';
      case 'DEFENDER':
        return 'bg-emerald-950/70 border-emerald-500/80 hover:border-emerald-400 text-emerald-300 ring-1 ring-emerald-500/30';
      case 'HONEYPOT':
        return 'bg-cyan-950/70 border-cyan-500/70 hover:border-cyan-400 text-cyan-300';
      case 'DATABASE':
        return 'bg-amber-950/60 border-amber-500/70 hover:border-amber-400 text-amber-300';
      case 'GATEWAY':
        return 'bg-cyan-950/60 border-cyan-500/70 hover:border-cyan-400 text-cyan-300';
      default:
        return 'bg-slate-900/80 border-slate-700 hover:border-slate-500 text-slate-300 shadow-[0_0_20px_rgba(0,255,255,0.08)]';
    }
  };

  const nodeMap = new Map<string, NetworkNode>(nodes.map(n => [n.id, n]));

  // Filtered nodes
  const filteredNodes = nodes.filter(n => {
    if (filterStatus === 'ATTACK') return n.type === 'ATTACKER' || n.status === 'UNDER_ATTACK';
    if (filterStatus === 'PROTECTED') return n.status === 'PROTECTED';
    if (filterStatus === 'HONEYPOT') return n.type === 'HONEYPOT';
    return true;
  });

  return (
    <div className="overflow-hidden rounded-2xl border border-slate-800 bg-slate-900/90 shadow-xl shadow-[0_0_20px_rgba(0,255,255,0.08)]">
      {/* Top Header with Multi-View Topology Switcher */}
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-800 bg-slate-950/80 px-5 py-4 shadow-[0_0_20px_rgba(0,255,255,0.08)]">
        <div className="flex items-center gap-3">
          <div className="rounded-xl border border-emerald-500/30 bg-emerald-500/10 p-2.5 text-emerald-400">
            <Layers className="h-5 w-5 animate-pulse" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-base font-bold text-white">
                {isAr
                  ? 'خريطة الطوبولوجيا السيبرانية المتعددة (Multi-Vector Topology)'
                  : 'Advanced Multi-Vector Network Topology'}
              </h3>
              <span className="rounded border border-cyan-500/40 bg-cyan-500/20 px-2 py-0.5 font-mono text-[10px] text-cyan-300">
                LIVE SOC
              </span>
            </div>
            <p className="text-xs text-slate-400">
              {isAr
                ? 'خرائط حية لمسارات الهجوم، سلسلة القتل MITRE، التوزيع الجغرافي، ونطاق انتشار التهديد'
                : 'Real-time interactive architectural graph, MITRE ATT&CK kill chain, geo origins, & blast radius'}
            </p>
          </div>
        </div>

        {/* View Mode Tabs */}
        <div className="flex items-center gap-1.5 rounded-xl border border-slate-800 bg-slate-950 p-1 text-xs font-medium shadow-[0_0_20px_rgba(0,255,255,0.08)]">
          <button
            onClick={() => setActiveViewMode('ARCHITECTURE')}
            className={`flex items-center gap-1.5 rounded-lg px-3 py-1.5 transition ${
              activeViewMode === 'ARCHITECTURE'
                ? 'border border-emerald-500/40 bg-emerald-500/20 font-bold text-emerald-300'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Layers className="h-3.5 w-3.5" />
            <span>{isAr ? 'الهيكلية والصفر-ثقة' : 'Zero-Trust Architecture'}</span>
          </button>

          <button
            onClick={() => setActiveViewMode('MITRE_KILL_CHAIN')}
            className={`flex items-center gap-1.5 rounded-lg px-3 py-1.5 transition ${
              activeViewMode === 'MITRE_KILL_CHAIN'
                ? 'border border-rose-500/40 bg-rose-500/20 font-bold text-rose-300'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Crosshair className="h-3.5 w-3.5" />
            <span>{isAr ? 'سلسلة القتل MITRE' : 'MITRE Kill Chain'}</span>
          </button>

          <button
            onClick={() => setActiveViewMode('GEO_THREAT_MAP')}
            className={`flex items-center gap-1.5 rounded-lg px-3 py-1.5 transition ${
              activeViewMode === 'GEO_THREAT_MAP'
                ? 'border border-cyan-500/40 bg-cyan-500/20 font-bold text-cyan-300'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Globe className="h-3.5 w-3.5" />
            <span>{isAr ? 'الخريطة الجغرافية C2' : 'Geo Threat Map'}</span>
          </button>

          <button
            onClick={() => setActiveViewMode('BLAST_RADIUS_RADAR')}
            className={`flex items-center gap-1.5 rounded-lg px-3 py-1.5 transition ${
              activeViewMode === 'BLAST_RADIUS_RADAR'
                ? 'border border-cyan-500/40 bg-cyan-500/20 font-bold text-cyan-300'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Radio className="h-3.5 w-3.5" />
            <span>{isAr ? 'رادار نطاق الأثر' : 'Blast Radius Radar'}</span>
          </button>
        </div>
      </div>

      {/* Sub-toolbar with filtering and quick metrics */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 bg-slate-950/40 px-5 py-2.5 text-xs shadow-[0_0_20px_rgba(0,255,255,0.08)]">
        <div className="flex items-center gap-2">
          <span className="text-slate-400">{isAr ? 'تصفية العقد:' : 'Filter Nodes:'}</span>
          <div className="flex items-center gap-1">
            {(['ALL', 'ATTACK', 'PROTECTED', 'HONEYPOT'] as const).map(mode => (
              <button
                key={mode}
                onClick={() => setFilterStatus(mode)}
                className={`rounded px-2.5 py-1 font-mono text-[11px] transition ${
                  filterStatus === mode
                    ? 'border border-slate-700 bg-slate-800 font-bold text-white'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {mode}
              </button>
            ))}
          </div>
        </div>

        <div className="flex items-center gap-4 font-mono text-xs">
          <span className="flex items-center gap-1.5 text-emerald-400">
            <span className="h-2 w-2 animate-pulse rounded-full bg-emerald-500"></span>
            {isAr ? 'وكيل eBPF: نشط (0ns Overhead)' : 'eBPF Shield: Active'}
          </span>
          <span className="flex items-center gap-1.5 text-cyan-400">
            <span className="h-2 w-2 rounded-full bg-cyan-500"></span>
            {isAr ? 'المصيدة: 10.0.99.5 جاهزة' : 'Honeypot: Armed'}
          </span>
          <span className="flex items-center gap-1.5 text-rose-400">
            <span className="h-2 w-2 rounded-full bg-rose-500"></span>
            {isAr ? 'حظر فوري: 100%' : 'Auto-Eviction: 100%'}
          </span>
        </div>
      </div>

      {/* VIEW 1: ZERO-TRUST ARCHITECTURE TOPOLOGY */}
      {activeViewMode === 'ARCHITECTURE' && (
        <div className="relative h-[410px] w-full overflow-hidden bg-slate-950/95 select-none">
          {/* Subtle Grid and Zone Dividers */}
          <div className="absolute inset-0 bg-[radial-gradient(#1e293b_1px,transparent_1px)] [background-size:24px_24px] opacity-35"></div>

          {/* Zone Watermarks */}
          <div className="pointer-events-none absolute top-4 left-6 font-mono text-[10px] tracking-widest text-slate-700 uppercase">
            [ External Perimeter / Ingress ]
          </div>
          <div className="pointer-events-none absolute top-4 left-[38%] font-mono text-[10px] tracking-widest text-slate-700 uppercase">
            [ Autonomous eBPF Kernel Zone ]
          </div>
          <div className="pointer-events-none absolute top-4 right-8 font-mono text-[10px] tracking-widest text-slate-700 uppercase">
            [ Core Vault & Deception Tier ]
          </div>

          {/* SVG Edges and Particle Animations */}
          <svg
            className="absolute inset-0 h-full w-full"
            viewBox="0 0 1020 410"
            preserveAspectRatio="xMidYMid meet"
          >
            <defs>
              <filter id="glowArch" x="-20%" y="-20%" width="140%" height="140%">
                <feGaussianBlur stdDeviation="3" result="blur" />
                <feComposite in="SourceGraphic" in2="blur" operator="over" />
              </filter>
            </defs>

            {/* Render Network Edges */}
            {edges.map(edge => {
              const src = nodeMap.get(edge.source);
              const dst = nodeMap.get(edge.target);
              if (!src || !dst) return null;

              const isRed = edge.threatLevel === 'HIGH' || edge.threatLevel === 'CRITICAL';
              const isPurple = edge.target === 'node-honeypot';
              const strokeColor = isPurple ? '#a855f7' : isRed ? '#f43f5e' : '#334155';
              const strokeWidth = edge.active ? 2 : 1;

              return (
                <g key={edge.id}>
                  <line
                    x1={src.x + 36}
                    y1={src.y + 36}
                    x2={dst.x + 36}
                    y2={dst.y + 36}
                    stroke={strokeColor}
                    strokeWidth={strokeWidth}
                    strokeDasharray={isRed ? '4 4' : undefined}
                    opacity={edge.active ? 0.75 : 0.2}
                  />
                </g>
              );
            })}

            {/* Render Animated Packets */}
            {animatedParticles.map(p => {
              const edge = edges.find(e => e.id === p.edgeId);
              if (!edge) return null;
              const src = nodeMap.get(edge.source);
              const dst = nodeMap.get(edge.target);
              if (!src || !dst) return null;

              const cx = src.x + 36 + (dst.x + 36 - (src.x + 36)) * p.progress;
              const cy = src.y + 36 + (dst.y + 36 - (src.y + 36)) * p.progress;

              return (
                <circle
                  key={p.id || crypto.randomUUID()}
                  cx={cx}
                  cy={cy}
                  r="4"
                  fill={p.color}
                  filter="url(#glowArch)"
                />
              );
            })}
          </svg>

          {/* Render Interactive Nodes */}
          {filteredNodes.map(node => {
            const isSelected = selectedNode?.id === node.id;
            const isUnderAttack = node.status === 'UNDER_ATTACK' || node.riskScore > 75;
            const isIsolated = node.status === 'ISOLATED';

            return (
              <div
                key={node.id || `node-${crypto.randomUUID()}`}
                onClick={() => {
                  setSelectedNode(node);
                  onSelectNode?.(node);
                }}
                style={{
                  left: `${(node.x / 1020) * 100}%`,
                  top: `${(node.y / 410) * 100}%`,
                  transform: 'translate(-50%, -50%)'
                }}
                className="group absolute z-10 flex cursor-pointer flex-col items-center transition-all duration-300"
              >
                {/* Ping ring if under attack */}
                {isUnderAttack && (
                  <span className="pointer-events-none absolute -inset-2 animate-ping rounded-2xl bg-rose-500/20"></span>
                )}

                {/* Node Card */}
                <div
                  className={`flex items-center gap-2.5 rounded-xl border px-3 py-2.5 shadow-md transition-all ${getNodeColorClass(
                    node.type,
                    isSelected,
                    isIsolated
                  )}`}
                >
                  <div className="rounded-lg border border-white/10 bg-black/50 p-1.5">
                    {getNodeIcon(node.type)}
                  </div>
                  <div className="text-left">
                    <div className="flex items-center gap-1.5 text-xs font-bold whitespace-nowrap text-white">
                      <span>{isAr ? node.labelAr : node.labelEn}</span>
                      {isIsolated && (
                        <span className="py-0.2 rounded border border-rose-500 bg-rose-500/30 px-1 text-[9px] text-rose-300">
                          ISOLATED
                        </span>
                      )}
                    </div>
                    <div className="flex items-center gap-1.5 font-mono text-[10px] text-slate-400">
                      <span>{node.ip}</span>
                      <span className="text-slate-600">|</span>
                      <span
                        className={
                          node.riskScore > 50
                            ? 'font-semibold text-rose-400'
                            : 'font-semibold text-emerald-400'
                        }
                      >
                        Risk: {node.riskScore}%
                      </span>
                    </div>
                  </div>
                </div>

                {/* Sub-badge */}
                <div className="mt-1 flex items-center gap-1">
                  <span
                    className={`rounded-full border px-2 py-0.5 font-mono text-[9px] ${
                      node.type === 'DEFENDER'
                        ? 'border-emerald-500/40 bg-emerald-500/20 text-emerald-300'
                        : node.type === 'HONEYPOT'
                          ? 'border-cyan-500/40 bg-cyan-500/20 text-cyan-300'
                          : node.type === 'ATTACKER'
                            ? 'border-rose-500/40 bg-rose-500/20 text-rose-300'
                            : 'border-slate-700 bg-slate-800 text-slate-300'
                    }`}
                  >
                    {node.type}
                  </span>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* VIEW 2: MITRE ATT&CK KILL CHAIN VECTOR VIEW */}
      {activeViewMode === 'MITRE_KILL_CHAIN' && (
        <div className="min-h-[410px] space-y-4 bg-slate-950/95 p-6">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Crosshair className="h-5 w-5 text-rose-400" />
              <h4 className="text-sm font-bold text-white">
                {isAr
                  ? 'مسار سلسلة القتل السيبراني ونقاط الاعتراض الذاتي (MITRE ATT&CK Execution Chain)'
                  : 'MITRE ATT&CK Kill-Chain Interception Trajectory'}
              </h4>
            </div>
            <span className="flex items-center gap-1 font-mono text-xs text-emerald-400">
              <CheckCircle2 className="h-3.5 w-3.5" />
              {isAr ? 'سلسلة الهجوم مقطوعة في 3 طبقات' : 'Kill Chain Severed at 3 Defense Layers'}
            </span>
          </div>

          <div className="grid grid-cols-1 gap-3 pt-2 md:grid-cols-5">
            {killChainStages.map((stage, idx) => {
              const isSevered =
                stage.status === 'SEVERED_BY_DEFENDER' || stage.status === 'BLOCKED_KERNEL';
              const isHoneypot = stage.status === 'DIVERTED_HONEYPOT';

              return (
                <div
                  key={stage.id}
                  className={`relative rounded-xl border p-4 transition-all ${
                    isSevered
                      ? 'border-emerald-500/50 bg-emerald-950/30'
                      : isHoneypot
                        ? 'border-cyan-500/50 bg-cyan-950/30'
                        : 'border-slate-800 bg-slate-900/60 shadow-[0_0_20px_rgba(0,255,255,0.08)]'
                  }`}
                >
                  <div className="mb-2 flex items-center justify-between">
                    <span className="font-mono text-xs font-bold text-slate-400">
                      STEP 0{stage.stepNumber}
                    </span>
                    <span
                      className={`rounded-full border px-2 py-0.5 font-mono text-[10px] ${
                        isSevered
                          ? 'border-emerald-500/40 bg-emerald-500/20 text-emerald-300'
                          : isHoneypot
                            ? 'border-cyan-500/40 bg-cyan-500/20 text-cyan-300'
                            : 'animate-pulse border-rose-500/40 bg-rose-500/20 text-rose-300'
                      }`}
                    >
                      {stage.status}
                    </span>
                  </div>

                  <h5 className="mb-1 text-xs font-bold text-white">
                    {isAr ? stage.titleAr : stage.titleEn}
                  </h5>
                  <div className="mb-2 font-mono text-[10px] text-cyan-400">
                    {stage.mitreTactic} ({stage.techniqueId})
                  </div>
                  <p className="mb-3 text-[11px] leading-relaxed text-slate-400">
                    {isAr ? stage.descriptionAr : stage.descriptionEn}
                  </p>

                  <div className="rounded border border-white/5 bg-black/40 p-2 font-mono text-[10px] text-slate-300">
                    <span className="font-bold text-emerald-400">
                      {isAr ? 'إجراء الوكيل: ' : 'Agent Action: '}
                    </span>
                    {stage.mitigationRule}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* VIEW 3: GEO THREAT ORIGIN MAP */}
      {activeViewMode === 'GEO_THREAT_MAP' && (
        <div className="relative h-[410px] w-full overflow-hidden bg-slate-950/95 p-5">
          <div className="mb-3 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Globe className="h-5 w-5 text-cyan-400" />
              <h4 className="text-sm font-bold text-white">
                {isAr
                  ? 'مصادر التهديدات الدولية وعقد الـ C2 المستهدفة'
                  : 'Global Cyber Threat Vectors & C2 Origin Autonomous Systems'}
              </h4>
            </div>
            <div className="font-mono text-xs text-slate-400">
              {isAr
                ? '5 بؤر هجوم نشطة تحت الرصد والمحاصرة'
                : '5 Active Threat Clusters Geographically Mapped'}
            </div>
          </div>

          <div className="grid grid-cols-1 gap-3 pt-2 md:grid-cols-3">
            {geoThreats.map(geo => (
              <div
                key={geo.id || `geo-${crypto.randomUUID()}`}
                className="rounded-xl border border-slate-800 bg-slate-900/80 p-3.5 transition hover:border-slate-700 shadow-[0_0_20px_rgba(0,255,255,0.08)]"
              >
                <div className="mb-2 flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="text-lg">{geo.flag}</span>
                    <div>
                      <span className="text-xs font-bold text-white">{geo.country}</span>
                      <span className="block font-mono text-[10px] text-slate-400">{geo.city}</span>
                    </div>
                  </div>
                  <span
                    className={`rounded border px-2 py-0.5 font-mono text-[10px] ${
                      geo.threatLevel === 'CRITICAL'
                        ? 'border-rose-500/40 bg-rose-500/20 text-rose-300'
                        : 'border-amber-500/40 bg-amber-500/20 text-amber-300'
                    }`}
                  >
                    {geo.threatLevel}
                  </span>
                </div>

                <div className="space-y-1.5 font-mono text-xs">
                  <div className="flex items-center justify-between text-slate-300">
                    <span className="text-slate-500">IP:</span>
                    <span className="text-cyan-300">{geo.ip}</span>
                  </div>
                  <div className="flex items-center justify-between text-slate-300">
                    <span className="text-slate-500">ASN:</span>
                    <span className="max-w-[160px] truncate text-slate-400">{geo.asn}</span>
                  </div>
                  <div className="flex items-center justify-between text-slate-300">
                    <span className="text-slate-500">Vector:</span>
                    <span className="text-rose-400">{geo.attackType}</span>
                  </div>
                  <div className="flex items-center justify-between text-slate-300">
                    <span className="text-slate-500">Decoy:</span>
                    <span
                      className={
                        geo.divertedToHoneypot ? 'font-bold text-cyan-400' : 'text-slate-400'
                      }
                    >
                      {geo.divertedToHoneypot ? 'Diverted to Honeypot' : 'Direct eBPF Block'}
                    </span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* VIEW 4: BLAST RADIUS & MICROSEGMENTATION RADAR */}
      {activeViewMode === 'BLAST_RADIUS_RADAR' && (
        <div className="min-h-[410px] space-y-4 bg-slate-950/95 p-6">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Radio className="h-5 w-5 text-cyan-400" />
              <h4 className="text-sm font-bold text-white">
                {isAr
                  ? 'رادار محاكاة نطاق الأثر وعزل التجزئة الميكروية (Blast Radius & Microsegmentation)'
                  : 'Blast Radius Exposure & Zero-Trust Microsegmentation Radar'}
              </h4>
            </div>
            <span className="font-mono text-xs text-slate-400">
              {isAr
                ? 'محاكاة انتشار العدوى عند سقوط عقدة معينة'
                : 'Contagion Propagation & Containment Engine'}
            </span>
          </div>

          <div className="grid grid-cols-1 gap-4 pt-2 lg:grid-cols-3">
            {/* Target Node Selector */}
            <div className="space-y-3 rounded-xl border border-slate-800 bg-slate-900/80 p-4 shadow-[0_0_20px_rgba(0,255,255,0.08)]">
              <label className="block text-xs font-bold text-slate-300">
                {isAr ? 'اختر العقدة لمحاكاة نطاق الخطر:' : 'Select Node to Simulate Blast Radius:'}
              </label>
              <div className="space-y-1.5">
                {nodes
                  .filter(n => n.type !== 'ATTACKER')
                  .map(node => (
                    <button
                      key={node.id}
                      onClick={() => setSimulatedBlastRadius(node.id)}
                      className={`flex w-full items-center justify-between rounded-lg p-2 text-left font-mono text-xs transition ${
                        simulatedBlastRadius === node.id
                          ? 'border border-cyan-500 bg-cyan-950/70 font-bold text-cyan-200'
                          : 'border border-slate-800 bg-slate-950 text-slate-400 hover:text-white shadow-[0_0_20px_rgba(0,255,255,0.08)]'
                      }`}
                    >
                      <div className="flex items-center gap-2">
                        {getNodeIcon(node.type)}
                        <span>{isAr ? node.labelAr : node.labelEn}</span>
                      </div>
                      <span>{node.ip}</span>
                    </button>
                  ))}
              </div>
            </div>

            {/* Assessment Panel */}
            <div className="space-y-3 rounded-xl border border-slate-800 bg-slate-900/80 p-4 lg:col-span-2 shadow-[0_0_20px_rgba(0,255,255,0.08)]">
              <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                <div>
                  <h5 className="text-sm font-bold text-white">
                    {isAr
                      ? 'تقييم نطاق الانتشار (Blast Radius Assessment)'
                      : 'Active Blast Radius Simulation Results'}
                  </h5>
                  <p className="font-mono text-xs text-slate-400">
                    Target: {nodeMap.get(simulatedBlastRadius || '')?.ip} (
                    {nodeMap.get(simulatedBlastRadius || '')?.labelEn})
                  </p>
                </div>
                <div className="rounded-lg border border-rose-500/40 bg-rose-500/20 px-3 py-1 font-mono text-xs font-bold text-rose-300">
                  {simulatedBlastRadius === 'node-db'
                    ? 'CRITICAL ASSET EXPOSURE (89%)'
                    : 'CONTROLLED SPREAD (22%)'}
                </div>
              </div>

              <div className="grid grid-cols-3 gap-2 text-center font-mono text-xs">
                <div className="rounded-lg border border-slate-800 bg-slate-950 p-2.5 shadow-[0_0_20px_rgba(0,255,255,0.08)]">
                  <span className="block text-[10px] text-slate-400">
                    {isAr ? 'احتمالية الاختراق:' : 'Lateral Probability:'}
                  </span>
                  <span className="text-sm font-bold text-rose-400">
                    {simulatedBlastRadius === 'node-db'
                      ? '89%'
                      : simulatedBlastRadius === 'node-web'
                        ? '45%'
                        : '12%'}
                  </span>
                </div>
                <div className="rounded-lg border border-slate-800 bg-slate-950 p-2.5 shadow-[0_0_20px_rgba(0,255,255,0.08)]">
                  <span className="block text-[10px] text-slate-400">
                    {isAr ? 'العقد المهددة مباشرة:' : 'Adjacent Assets at Risk:'}
                  </span>
                  <span className="text-sm font-bold text-amber-400">
                    {simulatedBlastRadius === 'node-web'
                      ? '2 Nodes (DB, Bastion)'
                      : '1 Node (eBPF Shield)'}
                  </span>
                </div>
                <div className="rounded-lg border border-slate-800 bg-slate-950 p-2.5 shadow-[0_0_20px_rgba(0,255,255,0.08)]">
                  <span className="block text-[10px] text-slate-400">
                    {isAr ? 'زمن الاستجابة التلقائية:' : 'SOAR Playbook TTL:'}
                  </span>
                  <span className="text-sm font-bold text-emerald-400">0.04 ms (eBPF)</span>
                </div>
              </div>

              {/* Automated Playbook Steps */}
              <div className="space-y-1.5 rounded-lg border border-slate-800 bg-slate-950 p-3 font-mono text-xs shadow-[0_0_20px_rgba(0,255,255,0.08)]">
                <div className="flex items-center gap-1.5 font-bold text-slate-300">
                  <Zap className="h-3.5 w-3.5 text-emerald-400" />
                  <span>
                    {isAr
                      ? 'خطة الاحتواء المؤتمتة المنفذة من الوكيل:'
                      : 'Autonomous Agent Containment Playbook:'}
                  </span>
                </div>
                <p className="text-[11px] text-slate-400">
                  1.{' '}
                  {isAr
                    ? 'تطبيق قاعدة eBPF XDP لعزل المنفذ 5432/3389 فوراً عن العقد المشبوهة.'
                    : 'Apply instant eBPF XDP drop rule for ports 5432/3389 from unverified IP.'}
                </p>
                <p className="text-[11px] text-slate-400">
                  2.{' '}
                  {isAr
                    ? 'توليد مسار وهمي وتحويل محاولات الاستكشاف إلى المصيدة 10.0.99.5.'
                    : 'Divert active reconnaissance scans transparently to honeypot decoy cluster.'}
                </p>
                <p className="text-[11px] text-slate-400">
                  3.{' '}
                  {isAr
                    ? 'تجديد الرموز السرية ومفاتيح الـ JWT تلقائياً للحد من توسع الصلاحيات.'
                    : 'Issue zero-trust token invalidation for compromised session boundaries.'}
                </p>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Selected Node Details Drawer */}
      {selectedNode && (
        <div className="flex flex-wrap items-center justify-between gap-4 border-t border-slate-800/80 bg-slate-950 px-5 py-3.5 font-mono text-xs shadow-[0_0_20px_rgba(0,255,255,0.08)]">
          <div className="flex items-center gap-3">
            <div className="rounded-lg border border-slate-700 bg-slate-800 p-2 text-white">
              {getNodeIcon(selectedNode.type)}
            </div>
            <div>
              <div className="flex items-center gap-2 font-bold text-white">
                <span>{isAr ? selectedNode.labelAr : selectedNode.labelEn}</span>
                <span className="text-slate-400">({selectedNode.ip})</span>
                <span className="rounded border border-cyan-500/30 bg-slate-800 px-2 py-0.5 text-[10px] text-cyan-300">
                  {selectedNode.os}
                </span>
                {selectedNode.status === 'ISOLATED' && (
                  <span className="rounded border border-rose-500 bg-rose-950 px-2 py-0.5 text-[10px] font-bold text-rose-300">
                    {isAr ? 'معزولة تماماً' : 'FULLY ISOLATED'}
                  </span>
                )}
              </div>
              <p className="mt-0.5 text-[11px] text-slate-400">
                {isAr ? 'المنافذ المفتوحة:' : 'Listening Ports:'} [{selectedNode.ports.join(', ')}]
                • {isAr ? 'الاتصالات النشطة:' : 'Connections:'} {selectedNode.activeConnections} •{' '}
                {isAr ? 'قواعد جدار الحماية:' : 'Firewall Rules:'} {selectedNode.firewallRulesCount}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => onToggleIsolateNode?.(selectedNode.id)}
              className={`flex items-center gap-1.5 rounded-lg border px-3 py-1.5 text-xs font-bold transition ${
                selectedNode.status === 'ISOLATED'
                  ? 'border-emerald-500 bg-emerald-950/60 text-emerald-300 hover:bg-emerald-900/60'
                  : 'border-rose-500 bg-rose-950/60 text-rose-300 hover:bg-rose-900/60'
              }`}
            >
              <Power className="h-3.5 w-3.5" />
              <span>
                {selectedNode.status === 'ISOLATED'
                  ? isAr
                    ? 'إلغاء العزل واستعادة الاتصال'
                    : 'Restore Connectivity'
                  : isAr
                    ? 'عزل العقدة فوراً (Isolate)'
                    : 'Isolate Node (eBPF Cut)'}
              </span>
            </button>

            <div className="flex items-center gap-2 rounded-lg border border-slate-800 bg-slate-900 px-3 py-1.5 shadow-[0_0_20px_rgba(0,255,255,0.08)]">
              <span className="text-slate-400">{isAr ? 'مؤشر الخطر:' : 'Risk Level:'}</span>
              <span
                className={`font-bold ${selectedNode.riskScore > 50 ? 'text-rose-400' : 'text-emerald-400'}`}
              >
                {selectedNode.riskScore}%
              </span>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
