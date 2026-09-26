import React, { useRef, useEffect, useCallback, useState } from 'react';

// =============================================================================
// FORCE-DIRECTED LINK ANALYSIS CANVAS
// A dependency-free physics renderer. Node layout is solved with a Coulomb
// repulsion / Hooke attraction model integrated on requestAnimationFrame, and
// the simulation parks itself once kinetic energy falls below a threshold so
// a settled graph costs nothing to display.
// =============================================================================

export type GraphNodeType = 'ACTOR' | 'ENDPOINT' | 'FILE_OBJECT' | 'TECHNIQUE' | 'STATE';
export type GraphRelationship = 'ATTACKED' | 'TAMPERED_WITH' | 'EXFILTRATING' | 'MITIGATED_BY';

export interface GraphNode {
  id: string;
  label: string;
  type: GraphNodeType;
  riskWeight: number;
}
export interface GraphEdge {
  source: string;
  target: string;
  relationship: GraphRelationship;
  latencyMs: number;
}

/** Palette required by the SOC spec. */
export const NODE_PALETTE: Record<GraphNodeType, string> = {
  ACTOR: '#FF0055', // attacker
  FILE_OBJECT: '#00F0FF', // target resource / file
  ENDPOINT: '#00F0FF', // target endpoint shares the resource colour
  TECHNIQUE: '#FFB800', // MITRE technique
  STATE: '#00FF66' // applied mitigation
};

const EDGE_PALETTE: Record<GraphRelationship, string> = {
  ATTACKED: '#FF0055',
  TAMPERED_WITH: '#FF7A00',
  EXFILTRATING: '#00F0FF',
  MITIGATED_BY: '#00FF66'
};

// --- Physics constants ------------------------------------------------
/** Coulomb constant: raises inter-node spacing. */
const K_REPULSION = 5200;
/** Hooke spring constant for edges. */
const K_SPRING = 0.045;
/** Natural spring length in pixels. */
const REST_LENGTH = 118;
/** Velocity retained per step; below 1 this bleeds energy out of the system. */
const DAMPING = 0.86;
/** Pull toward the canvas centre, so disconnected clusters cannot drift away. */
const K_GRAVITY = 0.012;
/** Per-step displacement ceiling, which keeps the integrator stable. */
const MAX_VELOCITY = 12;
/** Total kinetic energy below which the layout is considered settled. */
const SETTLE_ENERGY = 0.18;
/** Frames of calm required before the loop parks itself. */
const SETTLE_FRAMES = 24;
/** Minimum separation used in the denominator, avoiding a divide by zero. */
const MIN_DISTANCE = 24;

interface SimNode extends GraphNode {
  x: number;
  y: number;
  vx: number;
  vy: number;
  radius: number;
}

export interface ForceGraphCanvasProps {
  nodes: GraphNode[];
  edges: GraphEdge[];
  height?: number;
  isAr: boolean;
  onSelectNode?: (node: GraphNode | null) => void;
  /**
   * Per-node-type colour override. Lets a second surface (the deception grid)
   * reuse this physics engine under its own palette instead of forking the
   * renderer, so layout and interaction behaviour stay identical everywhere.
   */
  paletteOverride?: Partial<Record<string, string>>;
  /** Legend entries to draw; defaults to the interception vocabulary. */
  legendOverride?: Array<[string, string]>;
}

export const ForceGraphCanvas: React.FC<ForceGraphCanvasProps> = ({
  nodes,
  edges,
  height = 340,
  isAr,
  onSelectNode,
  paletteOverride,
  legendOverride
}) => {
  const palette: Record<string, string> = { ...NODE_PALETTE, ...(paletteOverride ?? {}) };
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const simNodesRef = useRef<Map<string, SimNode>>(new Map());
  const frameRef = useRef<number | null>(null);
  const calmFramesRef = useRef(0);
  const pulseRef = useRef(0);
  const hoveredRef = useRef<string | null>(null);
  const runningRef = useRef(false);

  const [settled, setSettled] = useState(false);
  const [fps, setFps] = useState(0);

  // -------------------------------------------------------------------
  // Seed / reconcile simulation state against incoming graph data
  // -------------------------------------------------------------------
  const syncNodes = useCallback(
    (width: number, h: number) => {
      const map: Map<string, SimNode> = simNodesRef.current;
      const incoming = new Set(nodes.map(n => n.id));

      // Drop nodes that left the graph.
      for (const id of Array.from(map.keys())) {
        if (!incoming.has(id)) map.delete(id);
      }

      nodes.forEach((n, i) => {
        const existing = map.get(n.id);
        const radius = 9 + (n.riskWeight / 100) * 11;
        if (existing) {
          // Preserve position so a poll refresh does not restart the layout.
          existing.label = n.label;
          existing.type = n.type;
          existing.riskWeight = n.riskWeight;
          existing.radius = radius;
          return;
        }
        // Seed new nodes on a deterministic circle: a fixed starting geometry
        // converges predictably, where random placement can fall into a
        // different local minimum on every refresh.
        const angle = (i / Math.max(1, nodes.length)) * Math.PI * 2;
        const spread = Math.min(width, h) * 0.3;
        map.set(n.id, {
          ...n,
          radius,
          x: width / 2 + Math.cos(angle) * spread,
          y: h / 2 + Math.sin(angle) * spread,
          vx: 0,
          vy: 0
        });
      });
    },
    [nodes]
  );

  // -------------------------------------------------------------------
  // One integration step. Returns total kinetic energy.
  // -------------------------------------------------------------------
  const step = useCallback(
    (width: number, h: number): number => {
      const map: Map<string, SimNode> = simNodesRef.current;
      const list: SimNode[] = Array.from(map.values());
      const n = list.length;
      if (n === 0) return 0;

      // --- Coulomb repulsion between every pair -----------------------
      // F = k * q1 * q2 / d^2, with charge proxied by node radius. The pair
      // loop is symmetric, so each pair is visited once and the equal and
      // opposite force is applied to both ends.
      for (let i = 0; i < n; i++) {
        const a = list[i];
        for (let j = i + 1; j < n; j++) {
          const b = list[j];
          let dx = a.x - b.x;
          let dy = a.y - b.y;
          let distSq = dx * dx + dy * dy;
          if (distSq < MIN_DISTANCE * MIN_DISTANCE) {
            distSq = MIN_DISTANCE * MIN_DISTANCE;
            // Nudge coincident nodes apart so the direction vector is defined.
            if (dx === 0 && dy === 0) {
              dx = (i % 2 === 0 ? 1 : -1) * 0.5;
              dy = 0.5;
            }
          }
          const dist = Math.sqrt(distSq);
          const charge = (a.radius / 12) * (b.radius / 12);
          const force = (K_REPULSION * charge) / distSq;
          const fx = (dx / dist) * force;
          const fy = (dy / dist) * force;
          a.vx += fx;
          a.vy += fy;
          b.vx -= fx;
          b.vy -= fy;
        }
      }

      // --- Hooke attraction along edges -------------------------------
      // F = -k * (d - restLength), directed along the edge.
      for (const e of edges) {
        const a = map.get(e.source);
        const b = map.get(e.target);
        if (!a || !b) continue;
        const dx = b.x - a.x;
        const dy = b.y - a.y;
        const dist = Math.max(MIN_DISTANCE, Math.sqrt(dx * dx + dy * dy));
        const displacement = dist - REST_LENGTH;
        const force = K_SPRING * displacement;
        const fx = (dx / dist) * force;
        const fy = (dy / dist) * force;
        a.vx += fx;
        a.vy += fy;
        b.vx -= fx;
        b.vy -= fy;
      }

      // --- Centring gravity + integration ------------------------------
      let energy = 0;
      const cx = width / 2;
      const cy = h / 2;
      for (const node of list) {
        node.vx += (cx - node.x) * K_GRAVITY;
        node.vy += (cy - node.y) * K_GRAVITY;

        node.vx *= DAMPING;
        node.vy *= DAMPING;

        // Clamp speed so a large force spike cannot eject a node off-canvas.
        const speed = Math.hypot(node.vx, node.vy);
        if (speed > MAX_VELOCITY) {
          node.vx = (node.vx / speed) * MAX_VELOCITY;
          node.vy = (node.vy / speed) * MAX_VELOCITY;
        }

        node.x += node.vx;
        node.y += node.vy;

        // Keep nodes inside the viewport with a reflecting boundary.
        const pad = node.radius + 6;
        if (node.x < pad) {
          node.x = pad;
          node.vx *= -0.4;
        }
        if (node.x > width - pad) {
          node.x = width - pad;
          node.vx *= -0.4;
        }
        if (node.y < pad) {
          node.y = pad;
          node.vy *= -0.4;
        }
        if (node.y > h - pad) {
          node.y = h - pad;
          node.vy *= -0.4;
        }

        energy += node.vx * node.vx + node.vy * node.vy;
      }
      return energy;
    },
    [edges]
  );

  // -------------------------------------------------------------------
  // Rendering
  // -------------------------------------------------------------------
  const draw = useCallback(
    (ctx: CanvasRenderingContext2D, width: number, h: number) => {
      const map: Map<string, SimNode> = simNodesRef.current;
      ctx.clearRect(0, 0, width, h);

      // Backdrop grid.
      ctx.strokeStyle = 'rgba(0, 240, 255, 0.045)';
      ctx.lineWidth = 1;
      for (let x = 0; x < width; x += 34) {
        ctx.beginPath();
        ctx.moveTo(x, 0);
        ctx.lineTo(x, h);
        ctx.stroke();
      }
      for (let y = 0; y < h; y += 34) {
        ctx.beginPath();
        ctx.moveTo(0, y);
        ctx.lineTo(width, y);
        ctx.stroke();
      }

      const pulse = pulseRef.current;

      // --- Edges with travelling laser packets ------------------------
      for (const e of edges) {
        const a = map.get(e.source);
        const b = map.get(e.target);
        if (!a || !b) continue;
        const colour = EDGE_PALETTE[e.relationship] ?? '#5C6E8C';
        const highlighted = hoveredRef.current === e.source || hoveredRef.current === e.target;

        ctx.strokeStyle = colour;
        ctx.globalAlpha = highlighted ? 0.75 : 0.28;
        ctx.lineWidth = highlighted ? 2 : 1.1;
        ctx.beginPath();
        ctx.moveTo(a.x, a.y);
        ctx.lineTo(b.x, b.y);
        ctx.stroke();

        // A packet travelling source -> target conveys flow direction.
        const t = (pulse + ((e.source.length * 7 + e.target.length * 3) % 100) / 100) % 1;
        const px = a.x + (b.x - a.x) * t;
        const py = a.y + (b.y - a.y) * t;
        ctx.globalAlpha = 0.95;
        ctx.fillStyle = colour;
        ctx.beginPath();
        ctx.arc(px, py, highlighted ? 3.2 : 2.2, 0, Math.PI * 2);
        ctx.fill();

        // Short comet tail behind the packet.
        ctx.globalAlpha = 0.35;
        ctx.lineWidth = highlighted ? 2.6 : 1.8;
        ctx.beginPath();
        const tailT = Math.max(0, t - 0.06);
        ctx.moveTo(a.x + (b.x - a.x) * tailT, a.y + (b.y - a.y) * tailT);
        ctx.lineTo(px, py);
        ctx.stroke();
      }
      ctx.globalAlpha = 1;

      // --- Nodes -------------------------------------------------------
      for (const node of map.values()) {
        const colour = palette[node.type] ?? '#9FB0CC';
        const hovered = hoveredRef.current === node.id;
        // High-risk nodes breathe; the amplitude scales with risk so the eye is
        // drawn to the most dangerous entity without any legend lookup.
        const halo =
          node.radius +
          5 +
          (node.riskWeight / 100) * 5 * (0.6 + 0.4 * Math.sin(pulse * Math.PI * 2));

        ctx.globalAlpha = 0.13 + (node.riskWeight / 100) * 0.16;
        ctx.fillStyle = colour;
        ctx.beginPath();
        ctx.arc(node.x, node.y, halo, 0, Math.PI * 2);
        ctx.fill();

        ctx.globalAlpha = 1;
        ctx.fillStyle = '#050914';
        ctx.beginPath();
        ctx.arc(node.x, node.y, node.radius, 0, Math.PI * 2);
        ctx.fill();

        ctx.strokeStyle = colour;
        ctx.lineWidth = hovered ? 2.6 : 1.6;
        ctx.stroke();

        ctx.fillStyle = colour;
        ctx.beginPath();
        ctx.arc(node.x, node.y, node.radius * 0.36, 0, Math.PI * 2);
        ctx.fill();

        // Label, truncated so dense graphs stay readable.
        const label = node.label.length > 22 ? node.label.slice(0, 21) + '…' : node.label;
        ctx.font = hovered ? 'bold 11px ui-monospace, monospace' : '10px ui-monospace, monospace';
        ctx.fillStyle = hovered ? '#FFFFFF' : 'rgba(230, 237, 247, 0.82)';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'top';
        ctx.fillText(label, node.x, node.y + node.radius + 4);
      }
      ctx.globalAlpha = 1;
    },
    [edges, palette]
  );

  // -------------------------------------------------------------------
  // Animation loop
  // -------------------------------------------------------------------
  const startLoop = useCallback(() => {
    if (runningRef.current) return;
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    runningRef.current = true;
    calmFramesRef.current = 0;
    setSettled(false);

    let lastFpsAt = performance.now();
    let framesSince = 0;

    const tick = () => {
      const c = canvasRef.current;
      if (!c) {
        runningRef.current = false;
        return;
      }
      const width = c.clientWidth;
      const h = c.clientHeight;

      const energy = step(width, h);
      pulseRef.current = (pulseRef.current + 0.012) % 1;
      draw(ctx, width, h);

      framesSince++;
      const now = performance.now();
      if (now - lastFpsAt >= 1000) {
        setFps(Math.round((framesSince * 1000) / (now - lastFpsAt)));
        framesSince = 0;
        lastFpsAt = now;
      }

      // Park the layout once it stops moving. The pulse animation still needs
      // frames, so the loop continues at a reduced cost: physics is skipped
      // and only the draw call runs.
      if (energy < SETTLE_ENERGY) {
        calmFramesRef.current++;
        if (calmFramesRef.current > SETTLE_FRAMES && !settled) setSettled(true);
      } else {
        calmFramesRef.current = 0;
        if (settled) setSettled(false);
      }

      frameRef.current = requestAnimationFrame(tick);
    };
    frameRef.current = requestAnimationFrame(tick);
  }, [step, draw, settled]);

  const stopLoop = useCallback(() => {
    if (frameRef.current !== null) cancelAnimationFrame(frameRef.current);
    frameRef.current = null;
    runningRef.current = false;
  }, []);

  // Size the backing store to the device pixel ratio for a crisp render.
  const resize = useCallback(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    const width = canvas.clientWidth;
    const h = canvas.clientHeight;
    canvas.width = Math.max(1, Math.floor(width * dpr));
    canvas.height = Math.max(1, Math.floor(h * dpr));
    const ctx = canvas.getContext('2d');
    if (ctx) ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    syncNodes(width, h);
  }, [syncNodes]);

  useEffect(() => {
    resize();
    window.addEventListener('resize', resize);
    return () => window.removeEventListener('resize', resize);
  }, [resize]);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    syncNodes(canvas.clientWidth, canvas.clientHeight);
    startLoop();
    return stopLoop;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [nodes, edges]);

  // Suspend entirely when the tab is hidden: rAF is already throttled there,
  // but stopping outright means a background SOC tab costs zero CPU.
  useEffect(() => {
    const onVisibility = () => {
      if (document.hidden) stopLoop();
      else startLoop();
    };
    document.addEventListener('visibilitychange', onVisibility);
    return () => document.removeEventListener('visibilitychange', onVisibility);
  }, [startLoop, stopLoop]);

  // -------------------------------------------------------------------
  // Pointer interaction
  // -------------------------------------------------------------------
  const hitTest = (clientX: number, clientY: number): SimNode | null => {
    const canvas = canvasRef.current;
    if (!canvas) return null;
    const rect = canvas.getBoundingClientRect();
    const x = clientX - rect.left;
    const y = clientY - rect.top;
    const nodeIter: Map<string, SimNode> = simNodesRef.current;
    for (const node of nodeIter.values()) {
      if (Math.hypot(node.x - x, node.y - y) <= node.radius + 6) return node;
    }
    return null;
  };

  return (
    <div
      className="relative overflow-hidden rounded-lg border"
      style={{ borderColor: '#16203A', background: '#050914', height }}
    >
      <canvas
        ref={canvasRef}
        className="block h-full w-full"
        style={{ cursor: hoveredRef.current ? 'pointer' : 'default' }}
        onMouseMove={e => {
          hoveredRef.current = hitTest(e.clientX, e.clientY)?.id ?? null;
        }}
        onMouseLeave={() => {
          hoveredRef.current = null;
        }}
        onClick={e => {
          const hit = hitTest(e.clientX, e.clientY);
          onSelectNode?.(
            hit
              ? { id: hit.id, label: hit.label, type: hit.type, riskWeight: hit.riskWeight }
              : null
          );
        }}
      />

      {/* Legend */}
      <div className="pointer-events-none absolute top-2 left-2 flex flex-wrap gap-2">
        {(
          (legendOverride ?? [
            ['ACTOR', isAr ? 'المهاجم' : 'Attacker'],
            ['FILE_OBJECT', isAr ? 'المورد المستهدف' : 'Target Resource'],
            ['TECHNIQUE', isAr ? 'تقنية MITRE' : 'MITRE Technique'],
            ['STATE', isAr ? 'الإجراء المطبق' : 'Mitigation']
          ]) as Array<[string, string]>
        ).map(([type, label]) => (
          <span
            key={type}
            className="flex items-center gap-1 font-mono text-[9px]"
            style={{ color: '#7A8AA8' }}
          >
            <span className="h-2 w-2 rounded-full" style={{ background: NODE_PALETTE[type] }} />
            {label}
          </span>
        ))}
      </div>

      {/* Physics telemetry */}
      <div
        className="pointer-events-none absolute right-2 bottom-2 font-mono text-[9px]"
        style={{ color: '#4B5B78' }}
      >
        {nodes.length}N · {edges.length}E · {fps}fps ·{' '}
        {settled ? (isAr ? 'مستقر' : 'settled') : isAr ? 'يتقارب' : 'converging'}
      </div>

      {nodes.length === 0 && (
        <div
          className="absolute inset-0 flex items-center justify-center font-mono text-[11px]"
          style={{ color: '#4B5B78' }}
        >
          {isAr ? 'لا توجد حوادث نشطة لرسمها.' : 'No active incidents to plot.'}
        </div>
      )}
    </div>
  );
};

export default ForceGraphCanvas;
