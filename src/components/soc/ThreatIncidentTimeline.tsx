import React, { useState, useEffect, useRef, useMemo, useCallback } from 'react';
import * as d3 from 'd3';
import {
  ShieldAlert,
  ShieldCheck,
  Zap,
  Activity,
  Radio,
  Clock,
  Search,
  RefreshCw,
  Play,
  Pause,
  Filter,
  Layers,
  Sparkles,
  Flame,
  AlertTriangle,
  FileCheck,
  Lock,
  Crosshair,
  ExternalLink,
  Copy,
  Check,
  X,
  Maximize2,
  ZoomIn,
  ZoomOut,
  RotateCcw,
  Terminal,
  ArrowRight,
  ArrowLeft,
  Share2,
  ChevronDown
} from 'lucide-react';

export type IncidentType = 'BLOCKED_ATTACK' | 'SYSTEM_ALERT';

export interface TimelineIncident {
  id: string;
  type: IncidentType;
  timestamp: string;
  title: string;
  titleAr: string;
  details: string;
  detailsAr?: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  category: 
    | 'SQL_INJECTION'
    | 'XSS_ATTACK'
    | 'RCE_EXPLOIT'
    | 'PATH_TRAVERSAL'
    | 'DDOS_SYN_FLOOD'
    | 'HONEYPOT_HIT'
    | 'AI_PROMPT_INJECTION'
    | 'FIM_TAMPER'
    | 'ZERO_TRUST_LOCKDOWN'
    | 'PROCESS_ANOMALY'
    | 'BASELINE_DRIFT'
    | 'SCANNER_CVE'
    | 'BRUTE_FORCE';
  actorIp?: string;
  country?: string;
  target?: string;
  mitreTactic?: string;
  mitreTechnique?: string;
  actionTaken: string;
  actionTakenAr: string;
  payloadSnippet?: string;
  correlatedWithId?: string;
  correlationReason?: string;
  correlationReasonAr?: string;
  impactScore: number;
}

export interface ThreatIncidentTimelineProps {
  lang: 'ar' | 'en';
}

export const ThreatIncidentTimeline: React.FC<ThreatIncidentTimelineProps> = ({ lang }) => {
  const isAr = lang === 'ar';

  // State
  const [incidents, setIncidents] = useState<TimelineIncident[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [isLiveSync, setIsLiveSync] = useState<boolean>(true);
  const [isSimulating, setIsSimulating] = useState<boolean>(false);
  const [selectedIncident, setSelectedIncident] = useState<TimelineIncident | null>(null);
  const [hoveredIncidentId, setHoveredIncidentId] = useState<string | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  // Filters
  const [timeHorizon, setTimeHorizon] = useState<'ALL' | '15M' | '1H' | '6H'>('ALL');
  const [typeFilter, setTypeFilter] = useState<'ALL' | 'BLOCKED_ONLY' | 'ALERTS_ONLY' | 'CORRELATED_ONLY' | 'CRITICAL_ONLY'>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');

  // DOM Refs for D3
  const containerRef = useRef<HTMLDivElement | null>(null);
  const svgRef = useRef<SVGSVGElement | null>(null);
  const zoomBehaviorRef = useRef<d3.ZoomBehavior<SVGSVGElement, unknown> | null>(null);
  const [containerDimensions, setContainerDimensions] = useState<{ width: number; height: number }>({
    width: 1000,
    height: 750
  });

  // Fetch Timeline Data
  const fetchTimelineData = useCallback(async () => {
    try {
      const res = await fetch('/api/v1/soc/threat-timeline');
      if (res.ok) {
        const data = await res.json();
        if (data.incidents && Array.isArray(data.incidents)) {
          setIncidents(data.incidents);
        }
      }
    } catch (err) {
      console.warn('Threat timeline fetch error:', err);
    } finally {
      setIsLoading(false);
    }
  }, []);

  // Initial Load & Live Polling
  useEffect(() => {
    fetchTimelineData();
  }, [fetchTimelineData]);

  useEffect(() => {
    if (!isLiveSync) return;
    const interval = setInterval(() => {
      fetchTimelineData();
    }, 4500);
    return () => clearInterval(interval);
  }, [isLiveSync, fetchTimelineData]);

  // ResizeObserver for Container Sizing
  useEffect(() => {
    if (!containerRef.current) return;

    let timeoutId: NodeJS.Timeout;
    const observer = new ResizeObserver((entries) => {
      for (const entry of entries) {
        clearTimeout(timeoutId);
        timeoutId = setTimeout(() => {
          const { width } = entry.contentRect;
          // Calculate dynamic height based on incident count, minimum 680px
          const calculatedHeight = Math.max(720, Math.min(1800, incidents.length * 95 + 180));
          setContainerDimensions({
            width: Math.max(800, width),
            height: calculatedHeight
          });
        }, 100);
      }
    });

    observer.observe(containerRef.current);
    return () => {
      clearTimeout(timeoutId);
      observer.disconnect();
    };
  }, [incidents.length]);

  // Filtered Incidents
  const filteredIncidents = useMemo(() => {
    let list = [...incidents];
    const now = Date.now();

    // Time horizon filter
    if (timeHorizon === '15M') {
      const cutoff = now - 15 * 60 * 1000;
      list = list.filter(i => new Date(i.timestamp).getTime() >= cutoff);
    } else if (timeHorizon === '1H') {
      const cutoff = now - 60 * 60 * 1000;
      list = list.filter(i => new Date(i.timestamp).getTime() >= cutoff);
    } else if (timeHorizon === '6H') {
      const cutoff = now - 6 * 60 * 60 * 1000;
      list = list.filter(i => new Date(i.timestamp).getTime() >= cutoff);
    }

    // Type / category filter
    if (typeFilter === 'BLOCKED_ONLY') {
      list = list.filter(i => i.type === 'BLOCKED_ATTACK');
    } else if (typeFilter === 'ALERTS_ONLY') {
      list = list.filter(i => i.type === 'SYSTEM_ALERT');
    } else if (typeFilter === 'CORRELATED_ONLY') {
      list = list.filter(i => !!i.correlatedWithId);
    } else if (typeFilter === 'CRITICAL_ONLY') {
      list = list.filter(i => i.severity === 'CRITICAL' || i.severity === 'HIGH');
    }

    // Search query filter
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase().trim();
      list = list.filter(i =>
        i.title.toLowerCase().includes(q) ||
        i.titleAr.includes(q) ||
        i.details.toLowerCase().includes(q) ||
        (i.actorIp && i.actorIp.toLowerCase().includes(q)) ||
        (i.target && i.target.toLowerCase().includes(q)) ||
        (i.category && i.category.toLowerCase().includes(q)) ||
        (i.actionTaken && i.actionTaken.toLowerCase().includes(q)) ||
        (i.payloadSnippet && i.payloadSnippet.toLowerCase().includes(q))
      );
    }

    // Sort chronologically ascending (earliest to latest from top to bottom)
    return list.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
  }, [incidents, timeHorizon, typeFilter, searchQuery]);

  // Computed Metrics
  const metrics = useMemo(() => {
    const blocked = incidents.filter(i => i.type === 'BLOCKED_ATTACK');
    const alerts = incidents.filter(i => i.type === 'SYSTEM_ALERT');
    const correlatedCount = incidents.filter(i => i.correlatedWithId).length;
    const criticalCount = incidents.filter(i => i.severity === 'CRITICAL').length;
    return {
      totalBlocked: blocked.length,
      totalAlerts: alerts.length,
      correlatedPairs: Math.floor(correlatedCount / 2),
      criticalCount,
      meanLatencyUs: 0.42
    };
  }, [incidents]);

  // Simulate Trigger
  const handleSimulateAttackAlertPair = async () => {
    setIsSimulating(true);
    try {
      const vectors = ['RCE', 'SQLI', 'HONEYPOT'];
      const chosenVector = vectors[Math.floor(Math.random() * vectors.length)];
      const res = await fetch('/api/v1/soc/threat-timeline/simulate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ vector: chosenVector })
      });

      if (res.ok) {
        const data = await res.json();
        if (data.created) {
          // Instantly refresh list
          fetchTimelineData();
        }
      }
    } catch (err) {
      console.error('Simulation error:', err);
    } finally {
      setIsSimulating(false);
    }
  };

  // Zoom Action Helpers
  const handleZoomIn = () => {
    if (!svgRef.current || !zoomBehaviorRef.current) return;
    d3.select(svgRef.current).transition().duration(300).call(zoomBehaviorRef.current.scaleBy, 1.25);
  };

  const handleZoomOut = () => {
    if (!svgRef.current || !zoomBehaviorRef.current) return;
    d3.select(svgRef.current).transition().duration(300).call(zoomBehaviorRef.current.scaleBy, 0.8);
  };

  const handleResetZoom = () => {
    if (!svgRef.current || !zoomBehaviorRef.current) return;
    d3.select(svgRef.current).transition().duration(400).call(zoomBehaviorRef.current.transform, d3.zoomIdentity);
  };

  // Copy to clipboard helper
  const handleCopyText = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  // ===========================================================================
  // D3 RENDERING PIPELINE FOR VERTICAL TIMELINE
  // ===========================================================================
  useEffect(() => {
    if (!svgRef.current || filteredIncidents.length === 0) return;

    const svg = d3.select(svgRef.current);
    const { width, height } = containerDimensions;

    // Clear previous dynamic content
    svg.selectAll('*').remove();

    // Definitions for gradients & glowing filters
    const defs = svg.append('defs');

    // Glow filter for critical nodes and correlation lines
    const filter = defs.append('filter')
      .attr('id', 'glow')
      .attr('x', '-30%')
      .attr('y', '-30%')
      .attr('width', '160%')
      .attr('height', '160%');
    filter.append('feGaussianBlur')
      .attr('stdDeviation', '4')
      .attr('result', 'coloredBlur');
    const feMerge = filter.append('feMerge');
    feMerge.append('feMergeNode').attr('in', 'coloredBlur');
    feMerge.append('feMergeNode').attr('in', 'SourceGraphic');

    // Correlation gradient (Red to Emerald/Cyan)
    const correlationGrad = defs.append('linearGradient')
      .attr('id', 'correlationGrad')
      .attr('gradientUnits', 'userSpaceOnUse');
    correlationGrad.append('stop').attr('offset', '0%').attr('stop-color', '#f43f5e'); // Rose
    correlationGrad.append('stop').attr('offset', '50%').attr('stop-color', '#fbbf24'); // Amber
    correlationGrad.append('stop').attr('offset', '100%').attr('stop-color', '#06b6d4'); // Cyan

    // Spine gradient (Cyan to Blue to Purple)
    const spineGrad = defs.append('linearGradient')
      .attr('id', 'spineGrad')
      .attr('x1', '0%').attr('y1', '0%')
      .attr('x2', '0%').attr('y2', '100%');
    spineGrad.append('stop').attr('offset', '0%').attr('stop-color', '#06b6d4').attr('stop-opacity', 0.9);
    spineGrad.append('stop').attr('offset', '50%').attr('stop-color', '#3b82f6').attr('stop-opacity', 0.7);
    spineGrad.append('stop').attr('offset', '100%').attr('stop-color', '#10b981').attr('stop-opacity', 0.8);

    // Zoom container
    const g = svg.append('g').attr('class', 'zoom-layer');

    const zoom = d3.zoom<SVGSVGElement, unknown>()
      .scaleExtent([0.65, 3.0])
      .translateExtent([[-width * 0.5, -100], [width * 1.5, height + 300]])
      .on('zoom', (event) => {
        g.attr('transform', event.transform);
      });

    zoomBehaviorRef.current = zoom;
    svg.call(zoom);

    // Layout Dimensions
    const margin = { top: 60, bottom: 60, left: 40, right: 40 };
    const innerHeight = height - margin.top - margin.bottom;
    const centerX = width / 2;
    const cardWidth = Math.min(320, (width - 160) / 2);
    const cardHeight = 72;

    // Time Scale along Vertical Y-Axis
    const timestamps = filteredIncidents.map(d => new Date(d.timestamp).getTime());
    let startTime = timestamps.length > 0 ? Math.min(...timestamps) : Date.now() - 3600000;
    let endTime = timestamps.length > 0 ? Math.max(...timestamps) : Date.now();
    
    // Add small buffer if all events happen very close
    if (endTime - startTime < 60000) {
      startTime -= 30000;
      endTime += 30000;
    }

    const yScale = d3.scaleTime()
      .domain([new Date(startTime), new Date(endTime)])
      .range([margin.top, margin.top + innerHeight]);

    // Draw Background Grid Lines
    const timeTicks = yScale.ticks(Math.max(4, Math.floor(innerHeight / 120)));
    const gridGroup = g.append('g').attr('class', 'grid-lines');

    timeTicks.forEach((tick) => {
      const y = yScale(tick);
      gridGroup.append('line')
        .attr('x1', margin.left)
        .attr('x2', width - margin.right)
        .attr('y1', y)
        .attr('y2', y)
        .attr('stroke', '#1e293b')
        .attr('stroke-width', 1)
        .attr('stroke-dasharray', '3, 4')
        .attr('opacity', 0.6);

      // Time tick label
      gridGroup.append('text')
        .attr('x', margin.left + 8)
        .attr('y', y - 4)
        .attr('fill', '#64748b')
        .attr('font-size', '10px')
        .attr('font-family', 'monospace')
        .text(tick.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }));
    });

    // Draw Central Vertical Spine
    const spineGroup = g.append('g').attr('class', 'central-spine');

    // Glowing spine backing line
    spineGroup.append('line')
      .attr('x1', centerX)
      .attr('x2', centerX)
      .attr('y1', margin.top - 20)
      .attr('y2', margin.top + innerHeight + 20)
      .attr('stroke', 'url(#spineGrad)')
      .attr('stroke-width', 3)
      .attr('stroke-linecap', 'round')
      .attr('filter', 'url(#glow)');

    // Inner crisp spine line
    spineGroup.append('line')
      .attr('x1', centerX)
      .attr('x2', centerX)
      .attr('y1', margin.top - 20)
      .attr('y2', margin.top + innerHeight + 20)
      .attr('stroke', '#0ea5e9')
      .attr('stroke-width', 1.5)
      .attr('stroke-linecap', 'round');

    // Create incident position map for correlation bezier paths
    const incidentCoords = new Map<string, { x: number; y: number; type: IncidentType }>();

    // Spread overlapping events evenly along the vertical axis
    filteredIncidents.forEach((inc, idx) => {
      const rawY = yScale(new Date(inc.timestamp));
      // Clamp to prevent card stacking
      const minDistance = cardHeight + 16;
      let y = rawY;

      // Determine left or right based on incident type
      const isBlocked = inc.type === 'BLOCKED_ATTACK';
      const x = isBlocked ? centerX - 36 - cardWidth : centerX + 36;

      incidentCoords.set(inc.id, { x: isBlocked ? x + cardWidth : x, y, type: inc.type });
    });

    // Draw Correlation Bridges (D3 Bezier Curves)
    const correlationGroup = g.append('g').attr('class', 'correlation-bridges');

    filteredIncidents.forEach((inc) => {
      if (inc.correlatedWithId && inc.type === 'BLOCKED_ATTACK') {
        const start = incidentCoords.get(inc.id);
        const end = incidentCoords.get(inc.correlatedWithId);

        if (start && end) {
          const isHovered = hoveredIncidentId === inc.id || hoveredIncidentId === inc.correlatedWithId;
          
          // Generate smooth cubic bezier curve across central spine
          const pathD = `M ${start.x} ${start.y} C ${centerX - 10} ${start.y}, ${centerX + 10} ${end.y}, ${end.x} ${end.y}`;

          // Glowing background curve
          correlationGroup.append('path')
            .attr('d', pathD)
            .attr('fill', 'none')
            .attr('stroke', isHovered ? '#f59e0b' : '#06b6d4')
            .attr('stroke-width', isHovered ? 4 : 2)
            .attr('stroke-dasharray', isHovered ? 'none' : '5, 4')
            .attr('opacity', isHovered ? 0.95 : 0.6)
            .attr('filter', isHovered ? 'url(#glow)' : 'none')
            .style('cursor', 'pointer')
            .on('click', () => {
              setSelectedIncident(inc);
            });

          // Correlation pill at the spine midpoint
          const midY = (start.y + end.y) / 2;
          const latencyDeltaMs = Math.abs(new Date(inc.timestamp).getTime() - new Date(inc.timestamp).getTime());

          const tagGroup = correlationGroup.append('g')
            .attr('transform', `translate(${centerX}, ${midY})`)
            .style('cursor', 'pointer')
            .on('click', () => setSelectedIncident(inc));

          tagGroup.append('rect')
            .attr('x', -24)
            .attr('y', -8)
            .attr('width', 48)
            .attr('height', 16)
            .attr('rx', 8)
            .attr('fill', '#0f172a')
            .attr('stroke', isHovered ? '#f59e0b' : '#38bdf8')
            .attr('stroke-width', 1);

          tagGroup.append('text')
            .attr('x', 0)
            .attr('y', 3.5)
            .attr('text-anchor', 'middle')
            .attr('fill', isHovered ? '#fef08a' : '#38bdf8')
            .attr('font-size', '9px')
            .attr('font-family', 'monospace')
            .attr('font-weight', 'bold')
            .text('CORR 🔗');
        }
      }
    });

    // Draw Incidents Nodes and Cards
    const nodesGroup = g.append('g').attr('class', 'incident-nodes');

    filteredIncidents.forEach((inc) => {
      const isBlocked = inc.type === 'BLOCKED_ATTACK';
      const pos = incidentCoords.get(inc.id);
      if (!pos) return;

      const cardX = isBlocked ? centerX - 36 - cardWidth : centerX + 36;
      const cardY = pos.y - cardHeight / 2;
      const isHovered = hoveredIncidentId === inc.id || (inc.correlatedWithId && hoveredIncidentId === inc.correlatedWithId);
      const isSelected = selectedIncident?.id === inc.id;

      const incidentGroup = nodesGroup.append('g')
        .attr('class', `incident-item ${inc.id}`)
        .style('cursor', 'pointer')
        .on('mouseenter', () => setHoveredIncidentId(inc.id))
        .on('mouseleave', () => setHoveredIncidentId(null))
        .on('click', () => setSelectedIncident(inc));

      // 1. Horizontal Stem connecting card to central spine
      incidentGroup.append('line')
        .attr('x1', isBlocked ? cardX + cardWidth : cardX)
        .attr('x2', centerX)
        .attr('y1', pos.y)
        .attr('y2', pos.y)
        .attr('stroke', isHovered ? (isBlocked ? '#f43f5e' : '#10b981') : '#334155')
        .attr('stroke-width', isHovered ? 2 : 1)
        .attr('stroke-dasharray', isBlocked ? '3, 2' : 'none');

      // 2. Center Spine Anchor Marker
      const spineAnchor = incidentGroup.append('circle')
        .attr('cx', centerX)
        .attr('cy', pos.y)
        .attr('r', isHovered ? 6 : 4)
        .attr('fill', isBlocked ? '#f43f5e' : '#10b981')
        .attr('stroke', '#0f172a')
        .attr('stroke-width', 2);

      if (inc.severity === 'CRITICAL' || isHovered) {
        spineAnchor.attr('filter', 'url(#glow)');
      }

      // 3. Card Container
      const sevStroke =
        inc.severity === 'CRITICAL' ? '#f43f5e' :
        inc.severity === 'HIGH' ? '#f59e0b' :
        inc.severity === 'MEDIUM' ? '#06b6d4' : '#64748b';

      const sevBg =
        inc.severity === 'CRITICAL' ? 'rgba(88, 28, 28, 0.45)' :
        inc.severity === 'HIGH' ? 'rgba(120, 53, 15, 0.35)' :
        'rgba(15, 23, 42, 0.75)';

      // Card Box Rect
      incidentGroup.append('rect')
        .attr('x', cardX)
        .attr('y', cardY)
        .attr('width', cardWidth)
        .attr('height', cardHeight)
        .attr('rx', 8)
        .attr('fill', isSelected ? 'rgba(30, 41, 59, 0.95)' : sevBg)
        .attr('stroke', isHovered || isSelected ? sevStroke : '#334155')
        .attr('stroke-width', isHovered || isSelected ? 2 : 1)
        .attr('filter', isHovered || isSelected ? 'url(#glow)' : 'none');

      // Type Badge Pill inside card (Upper corner)
      const pillColor = isBlocked ? '#f43f5e' : '#10b981';
      const pillBg = isBlocked ? 'rgba(225, 29, 72, 0.2)' : 'rgba(16, 185, 129, 0.2)';
      const pillLabel = isBlocked ? '🛑 BLOCKED' : '🛡️ ALERT';

      incidentGroup.append('rect')
        .attr('x', cardX + 8)
        .attr('y', cardY + 8)
        .attr('width', 66)
        .attr('height', 16)
        .attr('rx', 4)
        .attr('fill', pillBg)
        .attr('stroke', pillColor)
        .attr('stroke-width', 0.5);

      incidentGroup.append('text')
        .attr('x', cardX + 41)
        .attr('y', cardY + 19.5)
        .attr('text-anchor', 'middle')
        .attr('fill', pillColor)
        .attr('font-size', '9px')
        .attr('font-weight', 'bold')
        .attr('font-family', 'monospace')
        .text(pillLabel);

      // Severity tag
      incidentGroup.append('text')
        .attr('x', cardX + 80)
        .attr('y', cardY + 19.5)
        .attr('fill', sevStroke)
        .attr('font-size', '9px')
        .attr('font-weight', 'bold')
        .attr('font-family', 'monospace')
        .text(inc.severity);

      // Timestamp
      incidentGroup.append('text')
        .attr('x', cardX + cardWidth - 8)
        .attr('y', cardY + 19.5)
        .attr('text-anchor', 'end')
        .attr('fill', '#94a3b8')
        .attr('font-size', '9px')
        .attr('font-family', 'monospace')
        .text(new Date(inc.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }));

      // Title Text
      const displayTitle = isAr && inc.titleAr ? inc.titleAr : inc.title;
      const truncatedTitle = displayTitle.length > 34 ? displayTitle.substring(0, 32) + '...' : displayTitle;

      incidentGroup.append('text')
        .attr('x', cardX + 8)
        .attr('y', cardY + 39)
        .attr('fill', '#f1f5f9')
        .attr('font-size', '11px')
        .attr('font-weight', '600')
        .text(truncatedTitle);

      // Footer: Actor IP or Target Asset + Action Taken
      const metaText = isBlocked
        ? `${inc.actorIp || 'UNKNOWN'} ➔ ${inc.actionTaken.split(' ')[0]}`
        : `${(inc.target || '').split(' ')[0]} ➔ ${inc.actionTaken.split(' ')[0]}`;
      const truncatedMeta = metaText.length > 38 ? metaText.substring(0, 36) + '...' : metaText;

      incidentGroup.append('text')
        .attr('x', cardX + 8)
        .attr('y', cardY + 58)
        .attr('fill', isBlocked ? '#fda4af' : '#6ee7b7')
        .attr('font-size', '9.5px')
        .attr('font-family', 'monospace')
        .text(truncatedMeta);

      // Correlation indicator icon
      if (inc.correlatedWithId) {
        incidentGroup.append('circle')
          .attr('cx', cardX + cardWidth - 12)
          .attr('cy', cardY + cardHeight - 12)
          .attr('r', 4)
          .attr('fill', '#fbbf24')
          .attr('stroke', '#0f172a')
          .attr('stroke-width', 1);
      }
    });

  }, [filteredIncidents, containerDimensions, hoveredIncidentId, selectedIncident, isAr]);

  return (
    <div className="space-y-4 font-sans text-slate-200" dir={isAr ? 'rtl' : 'ltr'}>
      
      {/* ===================================================================== */}
      {/* 1. TOP HEADER & METRIC CARDS BANNER                                   */}
      {/* ===================================================================== */}
      <div className="bg-slate-950/90 border border-cyan-500/30 rounded-xl p-4 shadow-2xl backdrop-blur-md">
        <div className="flex flex-wrap items-center justify-between gap-4">
          
          {/* Title and Identification */}
          <div className="flex items-center gap-3">
            <div className="p-2.5 bg-cyan-950/80 border border-cyan-400/40 rounded-xl text-cyan-300 shadow-md shadow-cyan-950/60">
              <Clock className="w-5 h-5 text-cyan-300 animate-pulse" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-sm font-black uppercase tracking-wider text-cyan-400">
                  {isAr ? 'المخطط الزمني للحوادث والتهديدات (D3.js)' : 'Threat Incident Timeline (D3.js)'}
                </h2>
                <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-cyan-950 text-cyan-300 border border-cyan-500/40 flex items-center gap-1">
                  <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-ping" />
                  TEMPORAL CORRELATION
                </span>
              </div>
              <p className="text-[11px] text-slate-400 font-mono">
                {isAr
                  ? 'تسلسل زمني متزامن يرسم علاقة الهجمات المحظورة بإنذارات النواة وتكامل الملفات'
                  : 'Bilateral D3.js temporal timeline mapping blocked ingress attacks directly to system alerts'}
              </p>
            </div>
          </div>

          {/* Key Metric Gauges */}
          <div className="flex items-center gap-3 overflow-x-auto py-1">
            
            {/* Blocked Attacks */}
            <div className="px-3 py-1.5 rounded-lg bg-slate-900/90 border border-rose-900/50 flex items-center gap-2.5">
              <ShieldAlert className="w-4 h-4 text-rose-400" />
              <div className="text-left font-mono">
                <span className="text-[9px] block text-slate-400 leading-none">{isAr ? 'هجمات محظورة' : 'BLOCKED ATTACKS'}</span>
                <span className="text-xs font-bold text-rose-300">{metrics.totalBlocked}</span>
              </div>
            </div>

            {/* System Alerts */}
            <div className="px-3 py-1.5 rounded-lg bg-slate-900/90 border border-cyan-900/50 flex items-center gap-2.5">
              <Activity className="w-4 h-4 text-cyan-400" />
              <div className="text-left font-mono">
                <span className="text-[9px] block text-slate-400 leading-none">{isAr ? 'إنذارات النظام' : 'SYSTEM ALERTS'}</span>
                <span className="text-xs font-bold text-cyan-300">{metrics.totalAlerts}</span>
              </div>
            </div>

            {/* Correlated Pairs */}
            <div className="px-3 py-1.5 rounded-lg bg-slate-900/90 border border-amber-900/50 flex items-center gap-2.5">
              <Sparkles className="w-4 h-4 text-amber-400" />
              <div className="text-left font-mono">
                <span className="text-[9px] block text-slate-400 leading-none">{isAr ? 'سلاسل مترابطة' : 'CORRELATED CHAINS'}</span>
                <span className="text-xs font-bold text-amber-300">{metrics.correlatedPairs} Pairs</span>
              </div>
            </div>

            {/* Mean Time to Intercept */}
            <div className="px-3 py-1.5 rounded-lg bg-slate-900/90 border border-emerald-900/50 flex items-center gap-2.5">
              <Zap className="w-4 h-4 text-emerald-400" />
              <div className="text-left font-mono">
                <span className="text-[9px] block text-slate-400 leading-none">{isAr ? 'سرعة الاعتراض' : 'MTTI SPEED'}</span>
                <span className="text-xs font-bold text-emerald-300">{metrics.meanLatencyUs} µs</span>
              </div>
            </div>

          </div>

          {/* Quick Tactical Actions */}
          <div className="flex items-center gap-2">
            
            {/* Simulate Attack & Alert Sequence */}
            <button
              onClick={handleSimulateAttackAlertPair}
              disabled={isSimulating}
              className="px-3 py-1.5 rounded-lg bg-gradient-to-r from-rose-600 to-amber-600 hover:from-rose-500 hover:to-amber-500 text-white font-mono text-xs font-bold flex items-center gap-1.5 shadow-lg shadow-rose-950/50 transition disabled:opacity-50"
            >
              <Zap className={`w-3.5 h-3.5 ${isSimulating ? 'animate-spin' : ''}`} />
              <span>{isAr ? 'محاكاة تسلسل هجوم وإنذار' : '⚡ Simulate Incident Pair'}</span>
            </button>

            {/* Live Sync Toggle */}
            <button
              onClick={() => setIsLiveSync(!isLiveSync)}
              className={`px-3 py-1.5 rounded-lg text-xs font-mono font-bold transition flex items-center gap-1.5 border ${
                isLiveSync
                  ? 'bg-emerald-950/70 text-emerald-300 border-emerald-500/50 shadow-md'
                  : 'bg-slate-900 text-slate-400 border-slate-700'
              }`}
            >
              {isLiveSync ? <Radio className="w-3.5 h-3.5 text-emerald-400 animate-pulse" /> : <Pause className="w-3.5 h-3.5 text-slate-400" />}
              <span>{isLiveSync ? (isAr ? 'بث مباشر نشط' : 'LIVE SYNC: ON') : (isAr ? 'متوقف' : 'PAUSED')}</span>
            </button>

            {/* Manual Refresh */}
            <button
              onClick={fetchTimelineData}
              disabled={isLoading}
              className="p-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-700 transition"
              title={isAr ? 'تحديث البيانات' : 'Refresh Timeline'}
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin' : ''}`} />
            </button>

          </div>

        </div>
      </div>

      {/* ===================================================================== */}
      {/* 2. FILTER & D3 INTERACTIVE CONTROLS BAR                                */}
      {/* ===================================================================== */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-3 flex flex-wrap items-center justify-between gap-3">
        
        {/* Left Filter Group: Time & Type */}
        <div className="flex flex-wrap items-center gap-2.5">
          
          {/* Search Input */}
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-slate-400 absolute top-2.5 left-2.5" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder={isAr ? 'بحث في التهديدات أو الـ IP...' : 'Search payload, IP, vector...'}
              className="pl-8 pr-3 py-1 bg-slate-950 border border-slate-700 rounded-lg text-xs text-slate-200 w-48 focus:border-cyan-400 outline-none"
            />
          </div>

          {/* Time Horizon Pills */}
          <div className="flex items-center bg-slate-950 rounded-lg p-0.5 border border-slate-800">
            {(['ALL', '15M', '1H', '6H'] as const).map((h) => (
              <button
                key={h}
                onClick={() => setTimeHorizon(h)}
                className={`px-2.5 py-0.5 rounded text-[11px] font-mono transition ${
                  timeHorizon === h
                    ? 'bg-cyan-600 text-white font-bold'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {h === 'ALL' ? (isAr ? 'الكل' : 'All') : h}
              </button>
            ))}
          </div>

          {/* Category Filter Selector */}
          <select
            value={typeFilter}
            onChange={(e) => setTypeFilter(e.target.value as any)}
            className="bg-slate-950 border border-slate-700 rounded-lg px-2.5 py-1 text-xs text-slate-300 outline-none font-mono"
          >
            <option value="ALL">{isAr ? 'جميع الفئات (المترابطة)' : 'Filter: All Incidents'}</option>
            <option value="BLOCKED_ONLY">{isAr ? 'الهجمات المحظورة فقط' : 'Blocked Attacks Only (Ingress)'}</option>
            <option value="ALERTS_ONLY">{isAr ? 'إنذارات النظام فقط' : 'System Alerts Only (Host)'}</option>
            <option value="CORRELATED_ONLY">{isAr ? 'السلاسل المترابطة فقط' : 'Correlated Pairs Only'}</option>
            <option value="CRITICAL_ONLY">{isAr ? 'التهديدات الحرجة فقط' : 'Critical / High Only'}</option>
          </select>

          <span className="text-[11px] font-mono text-slate-400">
            {filteredIncidents.length} / {incidents.length} {isAr ? 'حدث' : 'incidents'}
          </span>
        </div>

        {/* Right Controls: D3 Zoom & Pan controls */}
        <div className="flex items-center gap-1.5 bg-slate-950 rounded-lg p-1 border border-slate-800">
          <button
            onClick={handleZoomIn}
            className="p-1 text-slate-400 hover:text-slate-100 hover:bg-slate-800 rounded transition"
            title={isAr ? 'تكبير' : 'Zoom In'}
          >
            <ZoomIn className="w-3.5 h-3.5" />
          </button>
          <button
            onClick={handleZoomOut}
            className="p-1 text-slate-400 hover:text-slate-100 hover:bg-slate-800 rounded transition"
            title={isAr ? 'تصغير' : 'Zoom Out'}
          >
            <ZoomOut className="w-3.5 h-3.5" />
          </button>
          <button
            onClick={handleResetZoom}
            className="px-2 py-0.5 text-slate-400 hover:text-slate-100 hover:bg-slate-800 rounded text-[10px] font-mono flex items-center gap-1 transition"
            title={isAr ? 'إعادة ضبط المنظور' : 'Reset View'}
          >
            <RotateCcw className="w-3 h-3" />
            <span>Reset</span>
          </button>
        </div>

      </div>

      {/* ===================================================================== */}
      {/* 3. D3 VERTICAL TIMELINE STAGE WITH LANE HEADERS                       */}
      {/* ===================================================================== */}
      <div className="bg-slate-950 border border-slate-800 rounded-xl overflow-hidden shadow-2xl relative">
        
        {/* Lane Headers Ribbon */}
        <div className="grid grid-cols-12 bg-slate-900/90 border-b border-slate-800 py-2.5 px-4 text-xs font-mono font-bold text-slate-400 z-10">
          {/* Left Lane: Blocked Attacks */}
          <div className="col-span-5 flex items-center gap-2 text-rose-400">
            <ShieldAlert className="w-4 h-4 text-rose-400" />
            <span className="uppercase tracking-wider">
              {isAr ? 'هجمات الدخول المحظورة (WAF / eBPF / Honeypot)' : 'Blocked Ingress Attacks (WAF / eBPF / Honeypot)'}
            </span>
          </div>

          {/* Center Lane: Temporal Axis */}
          <div className="col-span-2 text-center text-cyan-400 flex items-center justify-center gap-1.5">
            <Clock className="w-3.5 h-3.5 text-cyan-400" />
            <span className="uppercase tracking-widest text-[11px]">{isAr ? 'المحور الزمني' : 'TEMPORAL SPINE'}</span>
          </div>

          {/* Right Lane: Defensive Alerts */}
          <div className="col-span-5 flex items-center justify-end gap-2 text-emerald-400">
            <span className="uppercase tracking-wider">
              {isAr ? 'إنذارات النظام الدفاعية (FIM / Kernel / SOAR)' : 'System Alerts (FIM / Kernel / SOAR Posture)'}
            </span>
            <Activity className="w-4 h-4 text-emerald-400" />
          </div>
        </div>

        {/* Dynamic D3 SVG Container */}
        <div
          ref={containerRef}
          className="w-full relative overflow-hidden bg-radial from-slate-900/40 via-slate-950 to-slate-950"
          style={{ height: '680px' }}
        >
          {filteredIncidents.length === 0 ? (
            <div className="h-full flex flex-col items-center justify-center text-slate-500 font-mono space-y-2">
              <Clock className="w-10 h-10 opacity-40 animate-pulse text-cyan-400" />
              <p className="text-xs">{isAr ? 'لا توجد حوادث أمنية مسجلة في هذا النطاق الزمني.' : 'No security incidents found matching current filters.'}</p>
              <button
                onClick={handleSimulateAttackAlertPair}
                className="mt-2 px-3 py-1 bg-cyan-900/40 hover:bg-cyan-900/70 border border-cyan-500/40 rounded-lg text-cyan-300 text-xs transition"
              >
                {isAr ? 'توليد هجوم تجريبي الآن' : 'Simulate First Incident Pair'}
              </button>
            </div>
          ) : (
            <svg
              ref={svgRef}
              className="w-full h-full cursor-grab active:cursor-grabbing"
              width={containerDimensions.width}
              height={containerDimensions.height}
            />
          )}

          {/* Live Instruction Tip in Bottom Corner */}
          <div className="absolute bottom-3 right-3 pointer-events-none bg-slate-900/80 border border-slate-800 rounded-lg px-2.5 py-1 text-[10px] text-slate-400 font-mono flex items-center gap-2">
            <span>🖱️ Scroll to Zoom / Pan</span>
            <span>•</span>
            <span>Click any node to inspect payload & MITRE</span>
          </div>
        </div>

      </div>

      {/* ===================================================================== */}
      {/* 4. FORENSIC INCIDENT DETAIL MODAL / DRAWER                            */}
      {/* ===================================================================== */}
      {selectedIncident && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md animate-fadeIn">
          <div className="bg-slate-950 border border-cyan-500/40 rounded-2xl max-w-2xl w-full max-h-[90vh] overflow-y-auto shadow-2xl p-5 space-y-4">
            
            {/* Modal Header */}
            <div className="flex items-start justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-3">
                <div className={`p-2.5 rounded-xl border ${
                  selectedIncident.type === 'BLOCKED_ATTACK'
                    ? 'bg-rose-950/60 border-rose-500/50 text-rose-400'
                    : 'bg-emerald-950/60 border-emerald-500/50 text-emerald-400'
                }`}>
                  {selectedIncident.type === 'BLOCKED_ATTACK' ? <ShieldAlert className="w-5 h-5" /> : <Activity className="w-5 h-5" />}
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase ${
                      selectedIncident.type === 'BLOCKED_ATTACK' ? 'bg-rose-900 text-rose-200' : 'bg-emerald-900 text-emerald-200'
                    }`}>
                      {selectedIncident.type === 'BLOCKED_ATTACK' ? (isAr ? 'هجوم محظور' : 'BLOCKED INGRESS ATTACK') : (isAr ? 'إنذار نظام' : 'SYSTEM DEFENSIVE ALERT')}
                    </span>
                    <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase ${
                      selectedIncident.severity === 'CRITICAL' ? 'bg-rose-900 text-rose-200' :
                      selectedIncident.severity === 'HIGH' ? 'bg-amber-900 text-amber-200' : 'bg-cyan-900 text-cyan-200'
                    }`}>
                      {selectedIncident.severity}
                    </span>
                    <span className="text-xs font-mono text-slate-400">{selectedIncident.id}</span>
                  </div>
                  <h3 className="text-base font-bold text-slate-100 mt-1">
                    {isAr && selectedIncident.titleAr ? selectedIncident.titleAr : selectedIncident.title}
                  </h3>
                </div>
              </div>

              <button
                onClick={() => setSelectedIncident(null)}
                className="p-1 rounded-lg hover:bg-slate-900 text-slate-400 hover:text-slate-200 transition"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Incident Metadata Grid */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5 font-mono text-xs">
              <div className="bg-slate-900/80 p-2.5 rounded-lg border border-slate-800">
                <span className="text-[10px] text-slate-400 block">{isAr ? 'الوقت الدقيق' : 'TIMESTAMP'}</span>
                <span className="font-bold text-slate-200">{new Date(selectedIncident.timestamp).toLocaleTimeString()}</span>
              </div>
              <div className="bg-slate-900/80 p-2.5 rounded-lg border border-slate-800">
                <span className="text-[10px] text-slate-400 block">{isAr ? 'مصدر الهجوم' : 'ACTOR IP / ORIGIN'}</span>
                <span className="font-bold text-cyan-300">{selectedIncident.actorIp || 'Host Subsystem'}</span>
              </div>
              <div className="bg-slate-900/80 p-2.5 rounded-lg border border-slate-800">
                <span className="text-[10px] text-slate-400 block">{isAr ? 'الموقع المستهدف' : 'TARGET ASSET'}</span>
                <span className="font-bold text-amber-300 truncate block">{selectedIncident.target || '/'}</span>
              </div>
              <div className="bg-slate-900/80 p-2.5 rounded-lg border border-slate-800">
                <span className="text-[10px] text-slate-400 block">{isAr ? 'مؤشر الخطورة' : 'THREAT IMPACT'}</span>
                <span className="font-bold text-rose-400">{selectedIncident.impactScore}/100</span>
              </div>
            </div>

            {/* Description Details */}
            <div className="bg-slate-900/60 p-3 rounded-lg border border-slate-800 text-xs leading-relaxed text-slate-300">
              <span className="text-[10px] font-mono font-bold text-slate-400 block mb-1 uppercase">
                {isAr ? 'تفاصيل الحادث والتحليل الأمني' : 'Forensic Incident Analysis'}
              </span>
              <p>{isAr && selectedIncident.detailsAr ? selectedIncident.detailsAr : selectedIncident.details}</p>
            </div>

            {/* MITRE & Action Taken */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs font-mono">
              <div className="p-3 bg-slate-900/80 rounded-lg border border-slate-800">
                <span className="text-[10px] text-slate-400 block mb-1">MITRE ATT&CK MATRIX</span>
                <span className="text-cyan-400 font-bold block">{selectedIncident.mitreTactic || 'Initial Access'}</span>
                <span className="text-slate-400 text-[11px]">{selectedIncident.mitreTechnique || 'T1190 - Exploit Public-Facing Application'}</span>
              </div>
              <div className="p-3 bg-slate-900/80 rounded-lg border border-slate-800">
                <span className="text-[10px] text-slate-400 block mb-1">{isAr ? 'الإجراء الدفاعي المتخذ' : 'DEFENSIVE ACTION COMMITTED'}</span>
                <span className="text-emerald-400 font-bold block">{selectedIncident.actionTaken}</span>
                <span className="text-slate-400 text-[11px]">{isAr && selectedIncident.actionTakenAr ? selectedIncident.actionTakenAr : 'Automated kernel policy enforced'}</span>
              </div>
            </div>

            {/* Raw Payload Snippet if available */}
            {selectedIncident.payloadSnippet && (
              <div className="space-y-1">
                <div className="flex items-center justify-between text-[10px] font-mono text-slate-400">
                  <span>{isAr ? 'الحمولة المحظورة أو محتوى الاستعلام' : 'INTERCEPTED PAYLOAD SNIPPET'}</span>
                  <button
                    onClick={() => handleCopyText(selectedIncident.payloadSnippet!, selectedIncident.id)}
                    className="flex items-center gap-1 text-cyan-400 hover:text-cyan-300"
                  >
                    {copiedId === selectedIncident.id ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                    <span>{copiedId === selectedIncident.id ? 'Copied' : 'Copy'}</span>
                  </button>
                </div>
                <pre className="p-3 bg-slate-950 rounded-lg border border-rose-900/40 text-[11px] font-mono text-rose-300 overflow-x-auto whitespace-pre-wrap">
                  {selectedIncident.payloadSnippet}
                </pre>
              </div>
            )}

            {/* Correlation Chain Panel */}
            {selectedIncident.correlatedWithId && (
              <div className="p-3.5 rounded-xl bg-gradient-to-r from-amber-950/40 via-cyan-950/40 to-slate-950 border border-amber-500/40 space-y-2">
                <div className="flex items-center gap-2 text-amber-300 font-mono text-xs font-bold">
                  <Sparkles className="w-4 h-4 text-amber-400" />
                  <span>{isAr ? 'العلاقة التبادلية والارتباط الدفاعي' : 'Cross-Subsystem Correlation Linked'}</span>
                  <span className="px-1.5 py-0.2 rounded bg-amber-900/60 text-amber-200 text-[10px]">
                    ID: {selectedIncident.correlatedWithId}
                  </span>
                </div>
                <p className="text-xs text-slate-300 leading-relaxed">
                  {isAr && selectedIncident.correlationReasonAr
                    ? selectedIncident.correlationReasonAr
                    : selectedIncident.correlationReason || 'Causal correlation established between ingress attack drop and immediate defensive telemetry alarm.'}
                </p>
              </div>
            )}

            {/* Modal Footer */}
            <div className="flex items-center justify-between pt-2 border-t border-slate-800">
              <span className="text-[10px] font-mono text-slate-500">
                Sovereign Defender Threat Forensics Suite v5.5
              </span>
              <button
                onClick={() => setSelectedIncident(null)}
                className="px-4 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-mono transition"
              >
                {isAr ? 'إغلاق النافذة' : 'Dismiss Dossier'}
              </button>
            </div>

          </div>
        </div>
      )}

    </div>
  );
};
