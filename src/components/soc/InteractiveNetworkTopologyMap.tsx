import React, { useState, useEffect, useRef } from 'react';
import * as d3 from 'd3';
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  Server,
  Database,
  Globe,
  Radio,
  HardDrive,
  Cpu,
  Lock,
  Unlock,
  AlertTriangle,
  Zap,
  Activity,
  Maximize2,
  RefreshCw,
  Eye,
  SlidersHorizontal,
  X,
  ArrowRight,
  Sparkles,
  Layers,
  Terminal,
  FileText
} from 'lucide-react';
import { NodeIsolationButton } from './NodeIsolationButton';

export interface TopologyNodeData {
  id: string;
  label: string;
  labelAr: string;
  type: 'GATEWAY' | 'AI_LAYER' | 'APP_SERVER' | 'DATABASE' | 'STORAGE_VAULT' | 'HONEYPOT';
  ip: string;
  status: 'PROTECTED' | 'UNDER_ATTACK' | 'ISOLATED' | 'SUSPICIOUS';
  threatScore: number;
  cpuLoad: number;
  activeSockets: number;
  vlan: string;
  x?: number;
  y?: number;
}

export interface TopologyLinkData {
  source: string;
  target: string;
  type: 'AUTHORIZED' | 'LATERAL_ATTACK' | 'ISOLATED_DROP' | 'HONEYPOT_SINK';
  active: boolean;
  bandwidthMbps: number;
}

interface InteractiveNetworkTopologyMapProps {
  lang: 'en' | 'ar';
}

export const InteractiveNetworkTopologyMap: React.FC<InteractiveNetworkTopologyMapProps> = ({ lang }) => {
  const isAr = lang === 'ar';
  const svgRef = useRef<SVGSVGElement | null>(null);

  // Minimalist View Mode (Eliminates cognitive overload / alert fatigue)
  const [isMinimalistMode, setIsMinimalistMode] = useState<boolean>(true);
  const [selectedNode, setSelectedNode] = useState<TopologyNodeData | null>(null);
  const [isDrillDownOpen, setIsDrillDownOpen] = useState<boolean>(false);
  const [filterType, setFilterType] = useState<string>('ALL');

  // Network State
  const [nodes, setNodes] = useState<TopologyNodeData[]>([
    { id: 'gw-ingress-01', label: 'Edge Gateway (eBPF XDP)', labelAr: 'بوابة الحافة (eBPF XDP)', type: 'GATEWAY', ip: '10.0.0.1', status: 'PROTECTED', threatScore: 12, cpuLoad: 28, activeSockets: 412, vlan: 'VLAN-10-WAN' },
    { id: 'ai-infer-01', label: 'Gemini AI Defense Mesh', labelAr: 'شبكة دفاع الذكاء الاصطناعي', type: 'AI_LAYER', ip: '10.0.1.5', status: 'PROTECTED', threatScore: 8, cpuLoad: 44, activeSockets: 88, vlan: 'VLAN-20-AI' },
    { id: 'web-prod-01', label: 'Core Web Workload 01', labelAr: 'خادم الويب الرئيسي 01', type: 'APP_SERVER', ip: '10.0.1.10', status: 'UNDER_ATTACK', threatScore: 94, cpuLoad: 89, activeSockets: 640, vlan: 'VLAN-30-APP' },
    { id: 'web-prod-02', label: 'Secondary Workload 02', labelAr: 'خادم الويب الثانوي 02', type: 'APP_SERVER', ip: '10.0.1.11', status: 'PROTECTED', threatScore: 14, cpuLoad: 31, activeSockets: 210, vlan: 'VLAN-30-APP' },
    { id: 'db-master-01', label: 'Sovereign DB (Classified)', labelAr: 'قاعدة البيانات السيادية (سرية)', type: 'DATABASE', ip: '10.0.2.20', status: 'SUSPICIOUS', threatScore: 78, cpuLoad: 72, activeSockets: 145, vlan: 'VLAN-40-DB' },
    { id: 'vault-keys-01', label: 'HSM Cryptographic Vault', labelAr: 'خزينة المفاتيح التشفيرية HSM', type: 'STORAGE_VAULT', ip: '10.0.2.99', status: 'PROTECTED', threatScore: 5, cpuLoad: 18, activeSockets: 32, vlan: 'VLAN-50-VAULT' },
    { id: 'decoy-honeypot', label: 'Deception Honeypot Asset', labelAr: 'مصيدة التضليل والاستدراج', type: 'HONEYPOT', ip: '10.0.9.88', status: 'PROTECTED', threatScore: 99, cpuLoad: 12, activeSockets: 6, vlan: 'VLAN-99-TRAP' }
  ]);

  const [links, setLinks] = useState<TopologyLinkData[]>([
    { source: 'gw-ingress-01', target: 'ai-infer-01', type: 'AUTHORIZED', active: true, bandwidthMbps: 450 },
    { source: 'gw-ingress-01', target: 'web-prod-01', type: 'AUTHORIZED', active: true, bandwidthMbps: 820 },
    { source: 'gw-ingress-01', target: 'web-prod-02', type: 'AUTHORIZED', active: true, bandwidthMbps: 240 },
    { source: 'web-prod-01', target: 'db-master-01', type: 'LATERAL_ATTACK', active: true, bandwidthMbps: 120 },
    { source: 'web-prod-02', target: 'db-master-01', type: 'AUTHORIZED', active: true, bandwidthMbps: 85 },
    { source: 'db-master-01', target: 'vault-keys-01', type: 'AUTHORIZED', active: true, bandwidthMbps: 40 },
    { source: 'gw-ingress-01', target: 'decoy-honeypot', type: 'HONEYPOT_SINK', active: true, bandwidthMbps: 15 }
  ]);

  // Isolate node toggle via eBPF
  const handleToggleIsolate = (nodeId: string) => {
    setNodes(prev =>
      prev.map(n => {
        if (n.id === nodeId) {
          const newStatus = n.status === 'ISOLATED' ? 'PROTECTED' : 'ISOLATED';
          return { ...n, status: newStatus };
        }
        return n;
      })
    );

    setLinks(prev =>
      prev.map(l => {
        if (l.source === nodeId || l.target === nodeId) {
          return { ...l, type: l.type === 'ISOLATED_DROP' ? 'AUTHORIZED' : 'ISOLATED_DROP' };
        }
        return l;
      })
    );

    if (selectedNode && selectedNode.id === nodeId) {
      setSelectedNode(prev => prev ? { ...prev, status: prev.status === 'ISOLATED' ? 'PROTECTED' : 'ISOLATED' } : null);
    }
  };

  // D3 Rendering
  useEffect(() => {
    if (!svgRef.current) return;

    const width = 860;
    const height = 480;

    const svg = d3.select(svgRef.current);
    svg.selectAll('*').remove();

    // Defs for glowing drop filters
    const defs = svg.append('defs');

    // Glow filter for attack nodes
    const glowFilter = defs.append('filter')
      .attr('id', 'threat-glow')
      .attr('x', '-50%').attr('y', '-50%').attr('width', '200%').attr('height', '200%');
    glowFilter.append('feGaussianBlur').attr('stdDeviation', '6').attr('result', 'coloredBlur');
    const feMerge = glowFilter.append('feMerge');
    feMerge.append('feMergeNode').attr('in', 'coloredBlur');
    feMerge.append('feMergeNode').attr('in', 'SourceGraphic');

    // Filter nodes for Minimalist Mode if enabled
    const visibleNodes = isMinimalistMode
      ? nodes.filter(n => n.status === 'UNDER_ATTACK' || n.status === 'SUSPICIOUS' || n.status === 'ISOLATED' || n.type === 'GATEWAY' || n.type === 'DATABASE')
      : nodes.filter(n => filterType === 'ALL' || n.type === filterType);

    const visibleNodeIds = new Set(visibleNodes.map(n => n.id));
    const visibleLinks = links.filter(l => visibleNodeIds.has(l.source as string) && visibleNodeIds.has(l.target as string));

    // Force simulation
    const simulationNodes = visibleNodes.map(d => ({ ...d }));
    const simulationLinks = visibleLinks.map(d => ({ ...d }));

    const simulation = d3.forceSimulation(simulationNodes as any)
      .force('link', d3.forceLink(simulationLinks as any).id((d: any) => d.id).distance(140))
      .force('charge', d3.forceManyBody().strength(-420))
      .force('center', d3.forceCenter(width / 2, height / 2))
      .force('collision', d3.forceCollide().radius(50));

    const g = svg.append('g').attr('class', 'topology-mesh');

    // Draw Links
    const linkGroup = g.append('g').attr('class', 'links');
    const link = linkGroup.selectAll('line')
      .data(simulationLinks)
      .enter()
      .append('line')
      .attr('stroke', (d: any) => {
        if (d.type === 'LATERAL_ATTACK') return '#f43f5e'; // Crimson
        if (d.type === 'ISOLATED_DROP') return '#64748b'; // Slate gray
        if (d.type === 'HONEYPOT_SINK') return '#eab308'; // Amber
        return '#06b6d4'; // Cyan
      })
      .attr('stroke-width', (d: any) => d.type === 'LATERAL_ATTACK' ? 3.5 : 2)
      .attr('stroke-dasharray', (d: any) => d.type === 'LATERAL_ATTACK' ? '6,4' : d.type === 'ISOLATED_DROP' ? '3,3' : 'none')
      .attr('stroke-opacity', 0.75);

    // Draw Nodes
    const nodeGroup = g.append('g').attr('class', 'nodes');
    const node = nodeGroup.selectAll('g')
      .data(simulationNodes)
      .enter()
      .append('g')
      .attr('class', 'cursor-pointer select-none')
      .call(
        d3.drag<any, any>()
          .on('start', (event, d) => {
            if (!event.active) simulation.alphaTarget(0.3).restart();
            d.fx = d.x;
            d.fy = d.y;
          })
          .on('drag', (event, d) => {
            d.fx = event.x;
            d.fy = event.y;
          })
          .on('end', (event, d) => {
            if (!event.active) simulation.alphaTarget(0);
            d.fx = null;
            d.fy = null;
          })
      )
      .on('click', (_, d: any) => {
        setSelectedNode(d);
        setIsDrillDownOpen(true);
      });

    // Outer Halo for Under Attack
    node.filter((d: any) => d.status === 'UNDER_ATTACK')
      .append('circle')
      .attr('r', 32)
      .attr('fill', 'none')
      .attr('stroke', '#f43f5e')
      .attr('stroke-width', 2)
      .attr('opacity', 0.8)
      .attr('filter', 'url(#threat-glow)');

    // Main Circle
    node.append('circle')
      .attr('r', 24)
      .attr('fill', (d: any) => {
        if (d.status === 'UNDER_ATTACK') return '#881337'; // Rose 900
        if (d.status === 'SUSPICIOUS') return '#78350f'; // Amber 900
        if (d.status === 'ISOLATED') return '#334155'; // Slate 700
        return '#082f49'; // Sky 950
      })
      .attr('stroke', (d: any) => {
        if (d.status === 'UNDER_ATTACK') return '#f43f5e';
        if (d.status === 'SUSPICIOUS') return '#f59e0b';
        if (d.status === 'ISOLATED') return '#94a3b8';
        return '#38bdf8';
      })
      .attr('stroke-width', 2.5);

    // Node Type Initials or Icon Glyph
    node.append('text')
      .attr('text-anchor', 'middle')
      .attr('dy', '0.35em')
      .attr('fill', '#ffffff')
      .attr('font-size', '11px')
      .attr('font-weight', 'bold')
      .attr('font-family', 'monospace')
      .text((d: any) => {
        if (d.type === 'GATEWAY') return 'GW';
        if (d.type === 'AI_LAYER') return 'AI';
        if (d.type === 'APP_SERVER') return 'APP';
        if (d.type === 'DATABASE') return 'DB';
        if (d.type === 'STORAGE_VAULT') return 'HSM';
        return 'TRAP';
      });

    // Labels beneath nodes
    node.append('text')
      .attr('text-anchor', 'middle')
      .attr('dy', 38)
      .attr('fill', '#cbd5e1')
      .attr('font-size', '11px')
      .attr('font-weight', '600')
      .text((d: any) => isAr ? d.labelAr : d.label);

    // IP Address beneath label
    node.append('text')
      .attr('text-anchor', 'middle')
      .attr('dy', 50)
      .attr('fill', '#64748b')
      .attr('font-size', '9px')
      .attr('font-family', 'monospace')
      .text((d: any) => d.ip);

    // Simulation Tick
    simulation.on('tick', () => {
      link
        .attr('x1', (d: any) => d.source.x)
        .attr('y1', (d: any) => d.source.y)
        .attr('x2', (d: any) => d.target.x)
        .attr('y2', (d: any) => d.target.y);

      node.attr('transform', (d: any) => `translate(${d.x},${d.y})`);
    });

    return () => { simulation.stop(); };
  }, [nodes, links, isMinimalistMode, filterType, isAr]);

  const underAttackCount = nodes.filter(n => n.status === 'UNDER_ATTACK').length;
  const suspiciousCount = nodes.filter(n => n.status === 'SUSPICIOUS').length;
  const isolatedCount = nodes.filter(n => n.status === 'ISOLATED').length;

  return (
    <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-2xl backdrop-blur-md">
      {/* Header & Controls */}
      <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 pb-4 border-b border-slate-800">
        <div className="flex items-center gap-3">
          <div className="p-2.5 bg-gradient-to-br from-cyan-500/20 to-indigo-500/20 border border-cyan-500/30 rounded-lg">
            <Radio className="w-5 h-5 text-cyan-400 animate-pulse" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-base font-bold text-slate-100">
                {isAr ? 'خريطة طبولوجيا الشبكة التفاعلية والتحركات الجانبية' : 'Interactive Zero-Trust Network Topology Map'}
              </h3>
              <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-cyan-950/80 text-cyan-300 border border-cyan-700/50">
                D3.js Live Graph
              </span>
            </div>
            <p className="text-xs text-slate-400">
              {isAr
                ? 'استبدال الجداول المعقدة برسم بياني بديهي للحد من الإجهاد الذهني وإرهاق التنبيهات (Alert Fatigue)'
                : 'Overhauled visual threat intelligence to eliminate analyst cognitive overload & alert fatigue.'}
            </p>
          </div>
        </div>

        {/* Minimalist Mode & Filter Toggle */}
        <div className="flex items-center gap-2">
          <button
            onClick={() => setIsMinimalistMode(prev => !prev)}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 border transition ${
              isMinimalistMode
                ? 'bg-cyan-500/20 text-cyan-200 border-cyan-500/50 shadow-sm'
                : 'bg-slate-800 text-slate-400 border-slate-700 hover:text-slate-200'
            }`}
          >
            <Eye className="w-3.5 h-3.5" />
            <span>{isAr ? 'الوضع المبسط (منع التشتت الذهني)' : 'Minimalist Focus (Anti-Fatigue)'}</span>
          </button>

          <select
            value={filterType}
            onChange={(e) => setFilterType(e.target.value)}
            className="bg-slate-950 border border-slate-800 text-slate-300 text-xs rounded-lg px-2.5 py-1.5 focus:outline-none focus:border-cyan-500"
          >
            <option value="ALL">{isAr ? 'جميع العقد' : 'All Nodes'}</option>
            <option value="GATEWAY">{isAr ? 'بوابات eBPF' : 'Gateways'}</option>
            <option value="APP_SERVER">{isAr ? 'خوادم الويب' : 'App Servers'}</option>
            <option value="DATABASE">{isAr ? 'قواعد البيانات' : 'Databases'}</option>
            <option value="HONEYPOT">{isAr ? 'فخاخ التضليل' : 'Honeypots'}</option>
          </select>
        </div>
      </div>

      {/* Quick Status Bar */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 my-4">
        <div className="p-3 bg-slate-950/60 border border-slate-800 rounded-lg flex items-center justify-between">
          <div>
            <span className="text-[11px] text-slate-400">{isAr ? 'العقد الخاضعة للهجوم' : 'Under Attack'}</span>
            <div className="text-lg font-mono font-bold text-rose-400">{underAttackCount}</div>
          </div>
          <ShieldAlert className="w-5 h-5 text-rose-400" />
        </div>

        <div className="p-3 bg-slate-950/60 border border-slate-800 rounded-lg flex items-center justify-between">
          <div>
            <span className="text-[11px] text-slate-400">{isAr ? 'نشاط جانبي مشبوه' : 'Suspicious Movement'}</span>
            <div className="text-lg font-mono font-bold text-amber-400">{suspiciousCount}</div>
          </div>
          <AlertTriangle className="w-5 h-5 text-amber-400" />
        </div>

        <div className="p-3 bg-slate-950/60 border border-slate-800 rounded-lg flex items-center justify-between">
          <div>
            <span className="text-[11px] text-slate-400">{isAr ? 'العقد المعزولة' : 'Isolated Nodes'}</span>
            <div className="text-lg font-mono font-bold text-slate-400">{isolatedCount}</div>
          </div>
          <Lock className="w-5 h-5 text-slate-400" />
        </div>

        <div className="p-3 bg-slate-950/60 border border-slate-800 rounded-lg flex items-center justify-between">
          <div>
            <span className="text-[11px] text-slate-400">{isAr ? 'سلامة الشبكة السيادية' : 'Network Posture'}</span>
            <div className="text-lg font-mono font-bold text-emerald-400">98.4%</div>
          </div>
          <ShieldCheck className="w-5 h-5 text-emerald-400" />
        </div>
      </div>

      {/* SVG Canvas Map Area */}
      <div className="relative bg-slate-950/80 border border-slate-800/80 rounded-xl overflow-hidden min-h-[480px] flex items-center justify-center">
        {/* Subtle grid background */}
        <div className="absolute inset-0 bg-[radial-gradient(#1e293b_1px,transparent_1px)] [background-size:20px_20px] opacity-40 pointer-events-none" />

        <svg
          ref={svgRef}
          viewBox="0 0 860 480"
          className="w-full h-auto max-h-[520px] select-none"
        />

        {/* Legend Overlay */}
        <div className="absolute bottom-3 left-3 bg-slate-900/90 border border-slate-800 rounded-lg p-2.5 text-[11px] text-slate-400 space-y-1 backdrop-blur-md">
          <div className="font-semibold text-slate-200 mb-1">{isAr ? 'دلالات الرموز' : 'Legend'}</div>
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-rose-500 shadow-sm shadow-rose-500" />
            <span>{isAr ? 'عقدة مستهدفة بهجوم نشط' : 'Node Under Active Attack'}</span>
          </div>
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-amber-500 shadow-sm shadow-amber-500" />
            <span>{isAr ? 'سلوك جانبي شاذ' : 'Suspicious Lateral Activity'}</span>
          </div>
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-cyan-400 shadow-sm shadow-cyan-400" />
            <span>{isAr ? 'مسار مشفر ومحمي' : 'Zero-Trust Secure Pathway'}</span>
          </div>
          <div className="flex items-center gap-2">
            <span className="w-4 h-0.5 border-t-2 border-dashed border-rose-500" />
            <span>{isAr ? 'محاولة تحرك جانبي (Lateral Jump)' : 'Lateral Movement Vector'}</span>
          </div>
        </div>
      </div>

      {/* Slide-out Drill-Down Drawer for Node Telemetry (Pitch-Black Cyber-Ops Surface) */}
      {isDrillDownOpen && selectedNode && (
        <div className="fixed inset-0 bg-[#0d1117]/85 backdrop-blur-sm z-50 flex items-center justify-end p-4 animate-in fade-in">
          <div className="bg-[#131a24] border border-[#1e2733] rounded-xl w-full max-w-md p-5 shadow-2xl space-y-4 text-[#e6edf3] animate-in slide-in-from-right font-mono">
            <div className="flex items-center justify-between pb-3 border-b border-[#1e2733]">
              <div className="flex items-center gap-2.5">
                <div className={`p-2 rounded border ${
                  selectedNode.status === 'UNDER_ATTACK' ? 'bg-[#0d1117] text-[#f85149] border-[#f85149]' :
                  selectedNode.status === 'SUSPICIOUS' ? 'bg-[#0d1117] text-[#fab219] border-[#fab219]' :
                  selectedNode.status === 'ISOLATED' ? 'bg-[#0d1117] text-[#93a1b3] border-[#93a1b3]' :
                  'bg-[#0d1117] text-[#3fb950] border-[#3fb950]'
                }`}>
                  <Server className="w-5 h-5" />
                </div>
                <div>
                  <h4 className="text-sm font-bold text-[#e6edf3]">
                    {isAr ? selectedNode.labelAr : selectedNode.label}
                  </h4>
                  <span className="text-xs text-[#93a1b3]">{selectedNode.ip} • {selectedNode.vlan}</span>
                </div>
              </div>
              <button
                onClick={() => setIsDrillDownOpen(false)}
                className="p-1 rounded text-[#93a1b3] hover:text-[#e6edf3] hover:bg-[#1a2230]"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Drill-down telemetry metrics */}
            <div className="grid grid-cols-3 gap-3">
              <div className="p-3 bg-[#0d1117] rounded border border-[#1e2733]">
                <span className="text-[10px] text-[#93a1b3]">{isAr ? 'درجة الخطورة' : 'Threat Score'}</span>
                <div className={`text-base font-bold ${selectedNode.threatScore > 70 ? 'text-[#f85149]' : 'text-[#3fb950]'}`}>
                  {selectedNode.threatScore}/100
                </div>
              </div>
              <div className="p-3 bg-[#0d1117] rounded border border-[#1e2733]">
                <span className="text-[10px] text-[#93a1b3]">{isAr ? 'ضغط المعالج' : 'CPU Load'}</span>
                <div className="text-base font-bold text-[#e6edf3]">{selectedNode.cpuLoad}%</div>
              </div>
              <div className="p-3 bg-[#0d1117] rounded border border-[#1e2733]">
                <span className="text-[10px] text-[#93a1b3]">{isAr ? 'جلسات TCP' : 'Sockets'}</span>
                <div className="text-base font-bold text-[#3fb950]">{selectedNode.activeSockets}</div>
              </div>
            </div>

            {/* Security Diagnosis */}
            <div className="p-3.5 bg-[#0d1117] rounded border border-[#1e2733] space-y-2 text-xs">
              <div className="font-semibold text-[#e6edf3] flex items-center gap-2">
                <Activity className="w-4 h-4 text-[#3fb950]" />
                <span>{isAr ? 'التشخيص الأمني بنواة eBPF' : 'eBPF Kernel Security Diagnostics'}</span>
              </div>
              <p className="text-[#93a1b3] leading-relaxed">
                {selectedNode.status === 'UNDER_ATTACK'
                  ? (isAr ? 'تم رصد محاولات استغلال واستدعاء غير مصرح به للشل. تم تطبيق إسقاط الحزم عند خطاف XDP.' : 'Exploitation and unauthorized subshell spawn detected. XDP hook drop rules actively enforced.')
                  : selectedNode.status === 'SUSPICIOUS'
                  ? (isAr ? 'رصد تدفق بيانات غير طبيعي باتجاه خادم قاعدة البيانات. تم تفعيل المراقبة الدقيقة.' : 'Abnormal lateral egress detected toward database. Microsegmentation active.')
                  : selectedNode.status === 'ISOLATED'
                  ? (isAr ? 'العقدة معزولة تشغيلياً وشبكياً في النواة (XDP Drop).' : 'Node isolated via eBPF XDP hook. East-west lateral traffic blocked.')
                  : (isAr ? 'العقدة مستقرة وتعمل تحت مظلة الحماية السيادية المشفرة.' : 'Node operating normally under sovereign zero-trust cryptographic perimeter.')}
              </p>
            </div>

            {/* Real Asynchronous Node Isolation Action */}
            <div className="pt-2">
              <NodeIsolationButton
                targetId={selectedNode.id}
                targetIp={selectedNode.ip}
                targetLabel={`${selectedNode.label || selectedNode.id} (${selectedNode.ip})`}
                isAlreadyIsolated={selectedNode.status === 'ISOLATED'}
                lang={lang}
                onSuccess={(targetId, newStatus) => {
                  const nodeStatus: TopologyNodeData['status'] =
                    newStatus === 'ISOLATED' ? 'ISOLATED' : 'PROTECTED';
                  setNodes(prev =>
                    prev.map(n => {
                      if (n.id === targetId) {
                        return { ...n, status: nodeStatus };
                      }
                      return n;
                    })
                  );
                  setLinks(prev =>
                    prev.map(l => {
                      if (l.source === targetId || l.target === targetId) {
                        return { ...l, type: newStatus === 'ISOLATED' ? 'ISOLATED_DROP' : 'AUTHORIZED' };
                      }
                      return l;
                    })
                  );
                  setSelectedNode(prev => prev ? { ...prev, status: nodeStatus } : null);
                }}
              />
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
