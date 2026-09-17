import React, { useState, useEffect } from 'react';
import { NetworkNode, NetworkEdge, TelemetryPacket, TopologyViewMode, GeoThreatNode, KillChainStage } from '../types';
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
  const [selectedNode, setSelectedNode] = useState<NetworkNode | null>(nodes.find(n => n.id === 'node-defender') || null);
  const [animatedParticles, setAnimatedParticles] = useState<{ id: string; edgeId: string; progress: number; color: string }[]>([]);
  const [geoThreats] = useState<GeoThreatNode[]>(INITIAL_GEO_THREATS);
  const [killChainStages] = useState<KillChainStage[]>(INITIAL_KILL_CHAIN_STAGES);
  const [filterStatus, setFilterStatus] = useState<'ALL' | 'ATTACK' | 'PROTECTED' | 'HONEYPOT'>('ALL');
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
          const particleColor = randomEdge.target === 'node-honeypot' 
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
        return <Skull className="w-4 h-4 text-rose-400" />;
      case 'DEFENDER':
        return <Shield className="w-4 h-4 text-emerald-400" />;
      case 'GATEWAY':
        return <Router className="w-4 h-4 text-cyan-400" />;
      case 'WEB_SERVER':
        return <Server className="w-4 h-4 text-sky-400" />;
      case 'DATABASE':
        return <Database className="w-4 h-4 text-amber-400" />;
      case 'HONEYPOT':
        return <Radio className="w-4 h-4 text-purple-400" />;
      case 'BASTION':
        return <Lock className="w-4 h-4 text-indigo-400" />;
      default:
        return <Server className="w-4 h-4 text-slate-400" />;
    }
  };

  const getNodeColorClass = (type: NetworkNode['type'], isSelected: boolean, isIsolated: boolean) => {
    if (isIsolated) return 'bg-rose-950/80 border-rose-500 text-rose-300 ring-2 ring-rose-500/50 opacity-70';
    if (isSelected) return 'ring-2 ring-emerald-400 bg-slate-900 border-emerald-400 shadow-lg shadow-emerald-500/20';
    switch (type) {
      case 'ATTACKER':
        return 'bg-rose-950/70 border-rose-600/60 hover:border-rose-400 text-rose-300';
      case 'DEFENDER':
        return 'bg-emerald-950/70 border-emerald-500/80 hover:border-emerald-400 text-emerald-300 ring-1 ring-emerald-500/30';
      case 'HONEYPOT':
        return 'bg-purple-950/70 border-purple-500/70 hover:border-purple-400 text-purple-300';
      case 'DATABASE':
        return 'bg-amber-950/60 border-amber-500/70 hover:border-amber-400 text-amber-300';
      case 'GATEWAY':
        return 'bg-cyan-950/60 border-cyan-500/70 hover:border-cyan-400 text-cyan-300';
      default:
        return 'bg-slate-900/80 border-slate-700 hover:border-slate-500 text-slate-300';
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
    <div className="bg-slate-900/90 border border-slate-800 rounded-2xl overflow-hidden shadow-xl">
      {/* Top Header with Multi-View Topology Switcher */}
      <div className="px-5 py-4 border-b border-slate-800 flex flex-wrap items-center justify-between gap-4 bg-slate-950/80">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-400">
            <Layers className="w-5 h-5 animate-pulse" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="font-bold text-white text-base">
                {isAr ? 'خريطة الطوبولوجيا السيبرانية المتعددة (Multi-Vector Topology)' : 'Advanced Multi-Vector Network Topology'}
              </h3>
              <span className="px-2 py-0.5 text-[10px] font-mono rounded bg-cyan-500/20 text-cyan-300 border border-cyan-500/40">
                LIVE SOC
              </span>
            </div>
            <p className="text-xs text-slate-400">
              {isAr ? 'خرائط حية لمسارات الهجوم، سلسلة القتل MITRE، التوزيع الجغرافي، ونطاق انتشار التهديد' : 'Real-time interactive architectural graph, MITRE ATT&CK kill chain, geo origins, & blast radius'}
            </p>
          </div>
        </div>

        {/* View Mode Tabs */}
        <div className="flex items-center gap-1.5 p-1 bg-slate-950 rounded-xl border border-slate-800 text-xs font-medium">
          <button
            onClick={() => setActiveViewMode('ARCHITECTURE')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg transition ${
              activeViewMode === 'ARCHITECTURE'
                ? 'bg-emerald-500/20 text-emerald-300 font-bold border border-emerald-500/40'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Layers className="w-3.5 h-3.5" />
            <span>{isAr ? 'الهيكلية والصفر-ثقة' : 'Zero-Trust Architecture'}</span>
          </button>

          <button
            onClick={() => setActiveViewMode('MITRE_KILL_CHAIN')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg transition ${
              activeViewMode === 'MITRE_KILL_CHAIN'
                ? 'bg-rose-500/20 text-rose-300 font-bold border border-rose-500/40'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Crosshair className="w-3.5 h-3.5" />
            <span>{isAr ? 'سلسلة القتل MITRE' : 'MITRE Kill Chain'}</span>
          </button>

          <button
            onClick={() => setActiveViewMode('GEO_THREAT_MAP')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg transition ${
              activeViewMode === 'GEO_THREAT_MAP'
                ? 'bg-cyan-500/20 text-cyan-300 font-bold border border-cyan-500/40'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Globe className="w-3.5 h-3.5" />
            <span>{isAr ? 'الخريطة الجغرافية C2' : 'Geo Threat Map'}</span>
          </button>

          <button
            onClick={() => setActiveViewMode('BLAST_RADIUS_RADAR')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg transition ${
              activeViewMode === 'BLAST_RADIUS_RADAR'
                ? 'bg-purple-500/20 text-purple-300 font-bold border border-purple-500/40'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Radio className="w-3.5 h-3.5" />
            <span>{isAr ? 'رادار نطاق الأثر' : 'Blast Radius Radar'}</span>
          </button>
        </div>
      </div>

      {/* Sub-toolbar with filtering and quick metrics */}
      <div className="px-5 py-2.5 bg-slate-950/40 border-b border-slate-800 flex flex-wrap items-center justify-between gap-3 text-xs">
        <div className="flex items-center gap-2">
          <span className="text-slate-400">{isAr ? 'تصفية العقد:' : 'Filter Nodes:'}</span>
          <div className="flex items-center gap-1">
            {(['ALL', 'ATTACK', 'PROTECTED', 'HONEYPOT'] as const).map(mode => (
              <button
                key={mode}
                onClick={() => setFilterStatus(mode)}
                className={`px-2.5 py-1 rounded text-[11px] font-mono transition ${
                  filterStatus === mode
                    ? 'bg-slate-800 text-white font-bold border border-slate-700'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {mode}
              </button>
            ))}
          </div>
        </div>

        <div className="flex items-center gap-4 text-xs font-mono">
          <span className="flex items-center gap-1.5 text-emerald-400">
            <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
            {isAr ? 'وكيل eBPF: نشط (0ns Overhead)' : 'eBPF Shield: Active'}
          </span>
          <span className="flex items-center gap-1.5 text-purple-400">
            <span className="w-2 h-2 rounded-full bg-purple-500"></span>
            {isAr ? 'المصيدة: 10.0.99.5 جاهزة' : 'Honeypot: Armed'}
          </span>
          <span className="flex items-center gap-1.5 text-rose-400">
            <span className="w-2 h-2 rounded-full bg-rose-500"></span>
            {isAr ? 'حظر فوري: 100%' : 'Auto-Eviction: 100%'}
          </span>
        </div>
      </div>

      {/* VIEW 1: ZERO-TRUST ARCHITECTURE TOPOLOGY */}
      {activeViewMode === 'ARCHITECTURE' && (
        <div className="relative w-full h-[410px] bg-slate-950/95 overflow-hidden select-none">
          {/* Subtle Grid and Zone Dividers */}
          <div className="absolute inset-0 bg-[radial-gradient(#1e293b_1px,transparent_1px)] [background-size:24px_24px] opacity-35"></div>

          {/* Zone Watermarks */}
          <div className="absolute left-6 top-4 text-[10px] font-mono text-slate-700 uppercase tracking-widest pointer-events-none">
            [ External Perimeter / Ingress ]
          </div>
          <div className="absolute left-[38%] top-4 text-[10px] font-mono text-slate-700 uppercase tracking-widest pointer-events-none">
            [ Autonomous eBPF Kernel Zone ]
          </div>
          <div className="absolute right-8 top-4 text-[10px] font-mono text-slate-700 uppercase tracking-widest pointer-events-none">
            [ Core Vault & Deception Tier ]
          </div>

          {/* SVG Edges and Particle Animations */}
          <svg className="absolute inset-0 w-full h-full" viewBox="0 0 1020 410" preserveAspectRatio="xMidYMid meet">
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

              const cx = (src.x + 36) + ((dst.x + 36) - (src.x + 36)) * p.progress;
              const cy = (src.y + 36) + ((dst.y + 36) - (src.y + 36)) * p.progress;

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
                className="absolute cursor-pointer transition-all duration-300 flex flex-col items-center group z-10"
              >
                {/* Ping ring if under attack */}
                {isUnderAttack && (
                  <span className="absolute -inset-2 rounded-2xl bg-rose-500/20 animate-ping pointer-events-none"></span>
                )}

                {/* Node Card */}
                <div
                  className={`px-3 py-2.5 rounded-xl border flex items-center gap-2.5 transition-all shadow-md ${getNodeColorClass(
                    node.type,
                    isSelected,
                    isIsolated
                  )}`}
                >
                  <div className="p-1.5 rounded-lg bg-black/50 border border-white/10">
                    {getNodeIcon(node.type)}
                  </div>
                  <div className="text-left">
                    <div className="text-xs font-bold text-white whitespace-nowrap flex items-center gap-1.5">
                      <span>{isAr ? node.labelAr : node.labelEn}</span>
                      {isIsolated && (
                        <span className="text-[9px] px-1 py-0.2 bg-rose-500/30 text-rose-300 border border-rose-500 rounded">
                          ISOLATED
                        </span>
                      )}
                    </div>
                    <div className="text-[10px] font-mono text-slate-400 flex items-center gap-1.5">
                      <span>{node.ip}</span>
                      <span className="text-slate-600">|</span>
                      <span className={node.riskScore > 50 ? 'text-rose-400 font-semibold' : 'text-emerald-400 font-semibold'}>
                        Risk: {node.riskScore}%
                      </span>
                    </div>
                  </div>
                </div>

                {/* Sub-badge */}
                <div className="mt-1 flex items-center gap-1">
                  <span
                    className={`text-[9px] font-mono px-2 py-0.5 rounded-full border ${
                      node.type === 'DEFENDER'
                        ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40'
                        : node.type === 'HONEYPOT'
                        ? 'bg-purple-500/20 text-purple-300 border-purple-500/40'
                        : node.type === 'ATTACKER'
                        ? 'bg-rose-500/20 text-rose-300 border-rose-500/40'
                        : 'bg-slate-800 text-slate-300 border-slate-700'
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
        <div className="p-6 bg-slate-950/95 min-h-[410px] space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Crosshair className="w-5 h-5 text-rose-400" />
              <h4 className="font-bold text-sm text-white">
                {isAr ? 'مسار سلسلة القتل السيبراني ونقاط الاعتراض الذاتي (MITRE ATT&CK Execution Chain)' : 'MITRE ATT&CK Kill-Chain Interception Trajectory'}
              </h4>
            </div>
            <span className="text-xs font-mono text-emerald-400 flex items-center gap-1">
              <CheckCircle2 className="w-3.5 h-3.5" />
              {isAr ? 'سلسلة الهجوم مقطوعة في 3 طبقات' : 'Kill Chain Severed at 3 Defense Layers'}
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-5 gap-3 pt-2">
            {killChainStages.map((stage, idx) => {
              const isSevered = stage.status === 'SEVERED_BY_DEFENDER' || stage.status === 'BLOCKED_KERNEL';
              const isHoneypot = stage.status === 'DIVERTED_HONEYPOT';

              return (
                <div
                  key={stage.id}
                  className={`p-4 rounded-xl border relative transition-all ${
                    isSevered
                      ? 'bg-emerald-950/30 border-emerald-500/50'
                      : isHoneypot
                      ? 'bg-purple-950/30 border-purple-500/50'
                      : 'bg-slate-900/60 border-slate-800'
                  }`}
                >
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-xs font-mono font-bold text-slate-400">
                      STEP 0{stage.stepNumber}
                    </span>
                    <span
                      className={`text-[10px] font-mono px-2 py-0.5 rounded-full border ${
                        isSevered
                          ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40'
                          : isHoneypot
                          ? 'bg-purple-500/20 text-purple-300 border-purple-500/40'
                          : 'bg-rose-500/20 text-rose-300 border-rose-500/40 animate-pulse'
                      }`}
                    >
                      {stage.status}
                    </span>
                  </div>

                  <h5 className="font-bold text-xs text-white mb-1">
                    {isAr ? stage.titleAr : stage.titleEn}
                  </h5>
                  <div className="text-[10px] font-mono text-cyan-400 mb-2">
                    {stage.mitreTactic} ({stage.techniqueId})
                  </div>
                  <p className="text-[11px] text-slate-400 leading-relaxed mb-3">
                    {isAr ? stage.descriptionAr : stage.descriptionEn}
                  </p>

                  <div className="p-2 rounded bg-black/40 border border-white/5 text-[10px] font-mono text-slate-300">
                    <span className="text-emerald-400 font-bold">{isAr ? 'إجراء الوكيل: ' : 'Agent Action: '}</span>
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
        <div className="relative w-full h-[410px] bg-slate-950/95 overflow-hidden p-5">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2">
              <Globe className="w-5 h-5 text-cyan-400" />
              <h4 className="font-bold text-sm text-white">
                {isAr ? 'مصادر التهديدات الدولية وعقد الـ C2 المستهدفة' : 'Global Cyber Threat Vectors & C2 Origin Autonomous Systems'}
              </h4>
            </div>
            <div className="text-xs font-mono text-slate-400">
              {isAr ? '5 بؤر هجوم نشطة تحت الرصد والمحاصرة' : '5 Active Threat Clusters Geographically Mapped'}
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-3 pt-2">
            {geoThreats.map(geo => (
              <div
                key={geo.id || `geo-${crypto.randomUUID()}`}
                className="p-3.5 rounded-xl bg-slate-900/80 border border-slate-800 hover:border-slate-700 transition"
              >
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-2">
                    <span className="text-lg">{geo.flag}</span>
                    <div>
                      <span className="font-bold text-xs text-white">{geo.country}</span>
                      <span className="text-[10px] text-slate-400 block font-mono">{geo.city}</span>
                    </div>
                  </div>
                  <span
                    className={`text-[10px] font-mono px-2 py-0.5 rounded border ${
                      geo.threatLevel === 'CRITICAL'
                        ? 'bg-rose-500/20 text-rose-300 border-rose-500/40'
                        : 'bg-amber-500/20 text-amber-300 border-amber-500/40'
                    }`}
                  >
                    {geo.threatLevel}
                  </span>
                </div>

                <div className="space-y-1.5 text-xs font-mono">
                  <div className="flex items-center justify-between text-slate-300">
                    <span className="text-slate-500">IP:</span>
                    <span className="text-cyan-300">{geo.ip}</span>
                  </div>
                  <div className="flex items-center justify-between text-slate-300">
                    <span className="text-slate-500">ASN:</span>
                    <span className="text-slate-400 truncate max-w-[160px]">{geo.asn}</span>
                  </div>
                  <div className="flex items-center justify-between text-slate-300">
                    <span className="text-slate-500">Vector:</span>
                    <span className="text-rose-400">{geo.attackType}</span>
                  </div>
                  <div className="flex items-center justify-between text-slate-300">
                    <span className="text-slate-500">Decoy:</span>
                    <span className={geo.divertedToHoneypot ? 'text-purple-400 font-bold' : 'text-slate-400'}>
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
        <div className="p-6 bg-slate-950/95 min-h-[410px] space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Radio className="w-5 h-5 text-purple-400" />
              <h4 className="font-bold text-sm text-white">
                {isAr ? 'رادار محاكاة نطاق الأثر وعزل التجزئة الميكروية (Blast Radius & Microsegmentation)' : 'Blast Radius Exposure & Zero-Trust Microsegmentation Radar'}
              </h4>
            </div>
            <span className="text-xs font-mono text-slate-400">
              {isAr ? 'محاكاة انتشار العدوى عند سقوط عقدة معينة' : 'Contagion Propagation & Containment Engine'}
            </span>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 pt-2">
            {/* Target Node Selector */}
            <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 space-y-3">
              <label className="text-xs font-bold text-slate-300 block">
                {isAr ? 'اختر العقدة لمحاكاة نطاق الخطر:' : 'Select Node to Simulate Blast Radius:'}
              </label>
              <div className="space-y-1.5">
                {nodes.filter(n => n.type !== 'ATTACKER').map(node => (
                  <button
                    key={node.id}
                    onClick={() => setSimulatedBlastRadius(node.id)}
                    className={`w-full p-2 rounded-lg text-left text-xs font-mono flex items-center justify-between transition ${
                      simulatedBlastRadius === node.id
                        ? 'bg-purple-950/70 border border-purple-500 text-purple-200 font-bold'
                        : 'bg-slate-950 border border-slate-800 text-slate-400 hover:text-white'
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
            <div className="lg:col-span-2 p-4 rounded-xl bg-slate-900/80 border border-slate-800 space-y-3">
              <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                <div>
                  <h5 className="font-bold text-white text-sm">
                    {isAr ? 'تقييم نطاق الانتشار (Blast Radius Assessment)' : 'Active Blast Radius Simulation Results'}
                  </h5>
                  <p className="text-xs text-slate-400 font-mono">
                    Target: {nodeMap.get(simulatedBlastRadius || '')?.ip} ({nodeMap.get(simulatedBlastRadius || '')?.labelEn})
                  </p>
                </div>
                <div className="px-3 py-1 rounded-lg bg-rose-500/20 border border-rose-500/40 text-rose-300 text-xs font-mono font-bold">
                  {simulatedBlastRadius === 'node-db' ? 'CRITICAL ASSET EXPOSURE (89%)' : 'CONTROLLED SPREAD (22%)'}
                </div>
              </div>

              <div className="grid grid-cols-3 gap-2 text-xs font-mono text-center">
                <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800">
                  <span className="text-slate-400 block text-[10px]">{isAr ? 'احتمالية الاختراق:' : 'Lateral Probability:'}</span>
                  <span className="text-sm font-bold text-rose-400">
                    {simulatedBlastRadius === 'node-db' ? '89%' : simulatedBlastRadius === 'node-web' ? '45%' : '12%'}
                  </span>
                </div>
                <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800">
                  <span className="text-slate-400 block text-[10px]">{isAr ? 'العقد المهددة مباشرة:' : 'Adjacent Assets at Risk:'}</span>
                  <span className="text-sm font-bold text-amber-400">
                    {simulatedBlastRadius === 'node-web' ? '2 Nodes (DB, Bastion)' : '1 Node (eBPF Shield)'}
                  </span>
                </div>
                <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800">
                  <span className="text-slate-400 block text-[10px]">{isAr ? 'زمن الاستجابة التلقائية:' : 'SOAR Playbook TTL:'}</span>
                  <span className="text-sm font-bold text-emerald-400">0.04 ms (eBPF)</span>
                </div>
              </div>

              {/* Automated Playbook Steps */}
              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-1.5 text-xs font-mono">
                <div className="font-bold text-slate-300 flex items-center gap-1.5">
                  <Zap className="w-3.5 h-3.5 text-emerald-400" />
                  <span>{isAr ? 'خطة الاحتواء المؤتمتة المنفذة من الوكيل:' : 'Autonomous Agent Containment Playbook:'}</span>
                </div>
                <p className="text-slate-400 text-[11px]">
                  1. {isAr ? 'تطبيق قاعدة eBPF XDP لعزل المنفذ 5432/3389 فوراً عن العقد المشبوهة.' : 'Apply instant eBPF XDP drop rule for ports 5432/3389 from unverified IP.'}
                </p>
                <p className="text-slate-400 text-[11px]">
                  2. {isAr ? 'توليد مسار وهمي وتحويل محاولات الاستكشاف إلى المصيدة 10.0.99.5.' : 'Divert active reconnaissance scans transparently to honeypot decoy cluster.'}
                </p>
                <p className="text-slate-400 text-[11px]">
                  3. {isAr ? 'تجديد الرموز السرية ومفاتيح الـ JWT تلقائياً للحد من توسع الصلاحيات.' : 'Issue zero-trust token invalidation for compromised session boundaries.'}
                </p>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Selected Node Details Drawer */}
      {selectedNode && (
        <div className="px-5 py-3.5 bg-slate-950 border-t border-slate-800/80 flex flex-wrap items-center justify-between gap-4 text-xs font-mono">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-slate-800 border border-slate-700 text-white">
              {getNodeIcon(selectedNode.type)}
            </div>
            <div>
              <div className="font-bold text-white flex items-center gap-2">
                <span>{isAr ? selectedNode.labelAr : selectedNode.labelEn}</span>
                <span className="text-slate-400">({selectedNode.ip})</span>
                <span className="text-[10px] px-2 py-0.5 rounded bg-slate-800 text-cyan-300 border border-cyan-500/30">
                  {selectedNode.os}
                </span>
                {selectedNode.status === 'ISOLATED' && (
                  <span className="text-[10px] px-2 py-0.5 rounded bg-rose-950 text-rose-300 border border-rose-500 font-bold">
                    {isAr ? 'معزولة تماماً' : 'FULLY ISOLATED'}
                  </span>
                )}
              </div>
              <p className="text-[11px] text-slate-400 mt-0.5">
                {isAr ? 'المنافذ المفتوحة:' : 'Listening Ports:'} [{selectedNode.ports.join(', ')}] • {isAr ? 'الاتصالات النشطة:' : 'Connections:'} {selectedNode.activeConnections} • {isAr ? 'قواعد جدار الحماية:' : 'Firewall Rules:'} {selectedNode.firewallRulesCount}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => onToggleIsolateNode?.(selectedNode.id)}
              className={`px-3 py-1.5 rounded-lg border text-xs font-bold transition flex items-center gap-1.5 ${
                selectedNode.status === 'ISOLATED'
                  ? 'bg-emerald-950/60 border-emerald-500 text-emerald-300 hover:bg-emerald-900/60'
                  : 'bg-rose-950/60 border-rose-500 text-rose-300 hover:bg-rose-900/60'
              }`}
            >
              <Power className="w-3.5 h-3.5" />
              <span>
                {selectedNode.status === 'ISOLATED' 
                  ? (isAr ? 'إلغاء العزل واستعادة الاتصال' : 'Restore Connectivity') 
                  : (isAr ? 'عزل العقدة فوراً (Isolate)' : 'Isolate Node (eBPF Cut)')
                }
              </span>
            </button>

            <div className="px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 flex items-center gap-2">
              <span className="text-slate-400">{isAr ? 'مؤشر الخطر:' : 'Risk Level:'}</span>
              <span className={`font-bold ${selectedNode.riskScore > 50 ? 'text-rose-400' : 'text-emerald-400'}`}>
                {selectedNode.riskScore}%
              </span>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
