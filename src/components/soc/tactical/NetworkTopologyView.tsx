import React from 'react';
import {
  Router, Smartphone, Server as ServerIcon, HelpCircle, Monitor, Network,
  Maximize2, Plus, Minus, Move, ShieldOff
} from 'lucide-react';
import type { AssetRow } from './useAssets';
import type { TwinState } from './digitalTwin';

/**
 * NETWORK TOPOLOGY — your network as relationships, pannable and zoomable.
 *
 * WHAT THIS REPLACES, twice over.
 *
 * First, the radar it succeeded encoded bearing from longitude and radius from threat
 * volume, so spatial position carried two incompatible meanings: neither a map, since
 * position was not geography, nor a radar, since radius was not range. Latitude went
 * unused entirely, putting devices in opposite hemispheres on the same bearing.
 *
 * Second, the first version of THIS component zoomed with a CSS `transform: scale()` on
 * the whole SVG and had no pan at all. That is why nothing could be moved or explored.
 * Scaling an SVG in CSS also scales stroke widths and glyphs, so lines thicken and text
 * blurs as you zoom, and the content clips at the container edge instead of extending
 * past it. Navigation is now driven by the viewBox: strokes and labels keep their
 * rendered size at every zoom level, and the canvas extends beyond the frame the way a
 * map is expected to.
 *
 * NAVIGATION: drag to pan, wheel to zoom toward the cursor, +/− buttons, and a fit
 * control that frames every node with margin. Arrow keys pan and +/− zoom for anyone not
 * using a mouse, because a graph reachable only by dragging is a graph some operators
 * cannot read at all.
 *
 * WHAT POSITION MEANS: concentric relationship tiers, not distance.
 *   centre  the enrolled host doing the observing — the vantage point
 *   ring 1  its local segments, one plate per CIDR it reported
 *   ring 2  LAN neighbours, each attached to the segment its address falls in
 *
 * Every node is a device something actually observed. An ARP entry means a device
 * answered on the wire, which is stronger evidence than a ping reply and was obtained
 * without sending a packet. Nothing is invented to fill the canvas: an empty graph means
 * nothing was seen, and it says so.
 */

export interface TopoNeighbour {
  ip: string;
  mac: string;
  vendor: string | null;
  openPorts?: number[];
  lastSweptAt?: string;
  sweepState?: 'NOT_IN_RANGE' | 'RESPONDED' | 'NO_RESPONSE' | null;
  viaInterface: string | null;
}

type NodeKind = 'VANTAGE' | 'SEGMENT' | 'DEVICE';

interface Node {
  id: string;
  kind: NodeKind;
  label: string;
  sub: string | null;
  x: number;
  y: number;
  tone: string;
  icon: React.ElementType;
  typeLabel: string;
  neighbour?: TopoNeighbour;
  asset?: AssetRow;
  openPorts: number[];
  isolated: boolean;
  /** Why this node is on a crimson path, when it is. */
  hot?: string;
  /** Digital-twin projection for this device, in the wargame environment only. */
  twin?: TwinState;
}

interface Edge {
  from: string;
  to: string;
  tone: string;
  width: number;
  dashed: boolean;
  hot?: boolean;
  /** A projected attack path to an EXPOSED device (simulation only). */
  projected?: boolean;
}

const TONE = {
  vantage: '#22d3ee',
  vantageIsolated: '#e11d48',
  vantageStale: '#fbbf24',
  segment: '#0891b2',
  open: '#fbbf24',
  filtering: '#0e7490',
  unswept: '#475569',
  hot: '#f43f5e'
} as const;

const SERVICE: Record<number, string> = {
  22: 'SSH', 23: 'TELNET', 53: 'DNS', 80: 'HTTP', 135: 'RPC', 139: 'NBT',
  443: 'HTTPS', 445: 'SMB', 1433: 'MSSQL', 3306: 'MYSQL', 3389: 'RDP',
  5432: 'PGSQL', 5900: 'VNC', 5985: 'WINRM', 6379: 'REDIS', 8080: 'HTTP-ALT'
};

/**
 * Device class from evidence, never from a guess.
 *
 * A .1 or .254 address serving 80/443 is a gateway: that is a conventional reading of two
 * observed facts. A randomised MAC with no open ports is probably a phone, but "probably"
 * is not a claim this makes — it reports that the address is randomised, which is a fact
 * about the address, and leaves the device type unclassified. Guessing device types is how
 * an inventory fills with confident fiction.
 */
function classify(n: TopoNeighbour): { icon: React.ElementType; en: string; ar: string } {
  const last = Number(n.ip.split('.')[3]);
  const ports = n.openPorts ?? [];
  if ((last === 1 || last === 254) && (ports.includes(80) || ports.includes(443) || ports.length === 0))
    return { icon: Router, en: 'GATEWAY', ar: 'بوّابة' };
  if (ports.some(p => [445, 3389, 5985, 135, 139].includes(p)))
    return { icon: Monitor, en: 'WINDOWS HOST', ar: 'مضيف ويندوز' };
  if (ports.includes(22)) return { icon: ServerIcon, en: 'SSH HOST', ar: 'مضيف SSH' };
  if (/^.[26ae]:/i.test(n.mac)) return { icon: Smartphone, en: 'RANDOMISED MAC', ar: 'عنوان معشّى' };
  return { icon: HelpCircle, en: 'UNCLASSIFIED', ar: 'غير مصنّف' };
}

export function inCidr(ip: string, cidr: string): boolean {
  const m = /^((?:\d{1,3}\.){3}\d{1,3})\/(\d{1,2})$/.exec(cidr);
  if (!m) return false;
  const bits = Number(m[2]);
  const toInt = (v: string) => v.split('.').map(Number).reduce((a, o) => (a << 8) | o, 0) >>> 0;
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return ((toInt(ip) & mask) >>> 0) === ((toInt(m[1]) & mask) >>> 0);
}

interface ViewBox {
  x: number;
  y: number;
  w: number;
  h: number;
}

const BASE: ViewBox = { x: 0, y: 0, w: 1200, h: 760 };

export const NetworkTopologyView: React.FC<{
  assets: AssetRow[];
  isAr: boolean;
  onSelectAsset: (a: AssetRow) => void;
  /**
   * Addresses that put a path in crimson, with the reason: the source IP of a HIGH or
   * CRITICAL alert, or an address under active containment. Crimson is never ambient
   * here — a path turns red only when an address on it is named by one of those.
   */
  hot?: ReadonlyMap<string, string>;
  /**
   * Digital-twin states by address. Supplied only in the wargame environment, and drawn
   * in amber and dashes so a projection can never be read as a live condition.
   */
  twin?: ReadonlyMap<string, TwinState>;
  className?: string;
}> = ({ assets, isAr, onSelectAsset, hot, twin, className }) => {
  const svgRef = React.useRef<SVGSVGElement>(null);
  const [vb, setVb] = React.useState<ViewBox>(BASE);
  const [selected, setSelected] = React.useState<Node | null>(null);
  const [hovered, setHovered] = React.useState<string | null>(null);
  const drag = React.useRef<{ x: number; y: number; vb: ViewBox } | null>(null);
  const [panning, setPanning] = React.useState(false);

  const hosts = assets.filter(a => a.kind === 'HOST');

  /* ── Layout ──────────────────────────────────────────────────────────────── */

  const { nodes, edges } = React.useMemo(() => {
    const ns: Node[] = [];
    const es: Edge[] = [];
    const cx = BASE.w / 2;
    const cy = BASE.h / 2;

    hosts.forEach((h, hi) => {
      const va = hosts.length === 1 ? 0 : (hi / hosts.length) * Math.PI * 2 - Math.PI / 2;
      const vr = hosts.length === 1 ? 0 : 84;
      const vid = `v:${h.id}`;

      ns.push({
        id: vid,
        kind: 'VANTAGE',
        label: h.label,
        sub: h.primaryIp,
        x: cx + Math.cos(va) * vr,
        y: cy + Math.sin(va) * vr,
        tone: h.isolated ? TONE.vantageIsolated : h.liveness === 'ONLINE' ? TONE.vantage : TONE.vantageStale,
        icon: Monitor,
        typeLabel: isAr ? 'مضيف مسجّل' : 'ENROLLED HOST',
        asset: h,
        openPorts: [],
        isolated: h.isolated,
        hot: h.primaryIp ? hot?.get(h.primaryIp) : undefined,
        twin: h.primaryIp ? twin?.get(h.primaryIp) : undefined
      });

      const segments = h.posture?.segments ?? [];
      const neighbours = (h.posture?.neighbours ?? []) as TopoNeighbour[];

      // Only segments with a neighbour in them are drawn. A host-only virtual adapter
      // with nothing behind it is real but uninformative, and six empty spokes crowd out
      // the segment that matters.
      const populated = segments.filter(s => neighbours.some(n => inCidr(n.ip, s.cidr)));
      const segs = populated.length > 0 ? populated : segments.slice(0, 3);

      segs.forEach((seg, si) => {
        const mine = neighbours.filter(n => inCidr(n.ip, seg.cidr));
        // Angular budget proportional to device count, so a busy segment gets the room it
        // needs instead of every segment getting an equal slice and the dense one piling up.
        const totalDevices = Math.max(1, segs.reduce((s, x) => s + neighbours.filter(n => inCidr(n.ip, x.cidr)).length, 0));
        const before = segs.slice(0, si).reduce((s, x) => s + Math.max(1, neighbours.filter(n => inCidr(n.ip, x.cidr)).length), 0);
        const own = Math.max(1, mine.length);
        const span = (own / (totalDevices + segs.length)) * Math.PI * 2;
        const start = (before / (totalDevices + segs.length)) * Math.PI * 2 - Math.PI / 2 + hi * 0.4;
        const mid = start + span / 2;

        const sid = `s:${h.id}:${seg.cidr}`;
        const sr = 208;
        ns.push({
          id: sid,
          kind: 'SEGMENT',
          label: seg.cidr,
          sub: seg.interface,
          x: cx + Math.cos(mid) * sr,
          y: cy + Math.sin(mid) * sr,
          tone: TONE.segment,
          icon: Network,
          typeLabel: isAr ? 'قطاع شبكي' : 'NETWORK SEGMENT',
          openPorts: [],
          isolated: false
        });
        const segHot = mine.some(n => hot?.has(n.ip));
        es.push({
          from: vid,
          to: sid,
          tone: segHot ? TONE.hot : TONE.vantage,
          width: 2,
          dashed: false,
          hot: segHot
        });

        mine.forEach((n, ni) => {
          const t = mine.length === 1 ? 0.5 : ni / (mine.length - 1);
          const a = start + span * (0.12 + 0.76 * t);
          // Alternate radius so adjacent labels cannot collide even on a dense segment.
          const dr = 168 + (ni % 2) * 62;
          const cls = classify(n);
          const nid = `n:${n.ip}`;
          if (ns.some(x => x.id === nid)) return;

          const ports = n.openPorts ?? [];
          const tone =
            ports.length > 0 ? TONE.open : n.sweepState === 'NO_RESPONSE' ? TONE.filtering : TONE.unswept;

          ns.push({
            id: nid,
            kind: 'DEVICE',
            label: n.ip,
            sub: n.vendor ?? (isAr ? cls.ar : cls.en),
            x: cx + Math.cos(a) * (sr + dr),
            y: cy + Math.sin(a) * (sr + dr),
            tone,
            icon: cls.icon,
            typeLabel: isAr ? cls.ar : cls.en,
            neighbour: n,
            openPorts: ports,
            isolated: false,
            hot: hot?.get(n.ip),
            twin: twin?.get(n.ip)
          });
          const devHot = hot?.has(n.ip) ?? false;
          es.push({
            from: sid,
            to: nid,
            tone: devHot ? TONE.hot : tone,
            width: devHot ? 2 : ports.length > 0 ? 1.4 : 1,
            // Dashed where the ports are unknown, so an unexamined link reads as
            // provisional rather than as a confirmed clean path.
            dashed: !devHot && (!n.sweepState || n.sweepState === 'NOT_IN_RANGE'),
            hot: devHot,
            projected: twin?.get(n.ip) === 'EXPOSED'
          });
        });
      });
    });

    // Crimson paths last, so they are never painted under a quiet one.
    es.sort((x, y) => Number(Boolean(x.hot)) - Number(Boolean(y.hot)));
    return { nodes: ns, edges: es };
  }, [hosts, isAr, hot, twin]);

  const byId = React.useMemo(() => new Map(nodes.map(n => [n.id, n])), [nodes]);

  /* ── Navigation ──────────────────────────────────────────────────────────── */

  const fit = React.useCallback(() => {
    if (nodes.length === 0) return setVb(BASE);
    const pad = 130;
    const xs = nodes.map(n => n.x);
    const ys = nodes.map(n => n.y);
    const minX = Math.min(...xs) - pad;
    const minY = Math.min(...ys) - pad;
    const w = Math.max(360, Math.max(...xs) + pad - minX);
    const h = Math.max(240, Math.max(...ys) + pad - minY);
    // Match the frame's aspect so fit does not squash the graph.
    const ar = BASE.w / BASE.h;
    const fitted = w / h > ar ? { w, h: w / ar } : { w: h * ar, h };
    setVb({ x: minX - (fitted.w - w) / 2, y: minY - (fitted.h - h) / 2, w: fitted.w, h: fitted.h });
  }, [nodes]);

  // Frame the graph whenever its shape changes, but never while the operator is reading:
  // re-fitting under someone who has zoomed in on a device yanks the view away from them.
  const lastCount = React.useRef(-1);
  React.useEffect(() => {
    if (nodes.length !== lastCount.current) {
      lastCount.current = nodes.length;
      fit();
    }
  }, [nodes.length, fit]);

  /** Convert a client point to viewBox coordinates, so zoom can anchor on the cursor. */
  const toLocal = (clientX: number, clientY: number) => {
    const r = svgRef.current?.getBoundingClientRect();
    if (!r) return { x: vb.x + vb.w / 2, y: vb.y + vb.h / 2 };
    return { x: vb.x + ((clientX - r.left) / r.width) * vb.w, y: vb.y + ((clientY - r.top) / r.height) * vb.h };
  };

  const zoomAt = (factor: number, anchor?: { x: number; y: number }) => {
    setVb(cur => {
      const w = Math.min(BASE.w * 4, Math.max(BASE.w * 0.12, cur.w * factor));
      const h = w * (cur.h / cur.w);
      const a = anchor ?? { x: cur.x + cur.w / 2, y: cur.y + cur.h / 2 };
      // Keep the anchor point stationary: the pixel under the cursor stays put.
      return { x: a.x - ((a.x - cur.x) * w) / cur.w, y: a.y - ((a.y - cur.y) * h) / cur.h, w, h };
    });
  };

  const onWheel = (e: React.WheelEvent) => {
    e.preventDefault();
    zoomAt(e.deltaY > 0 ? 1.13 : 1 / 1.13, toLocal(e.clientX, e.clientY));
  };

  const onPointerDown = (e: React.PointerEvent) => {
    // Left button only, and never on a node: dragging a node should select it.
    if (e.button !== 0) return;
    drag.current = { x: e.clientX, y: e.clientY, vb };
    setPanning(true);
    (e.currentTarget as Element).setPointerCapture(e.pointerId);
  };

  const onPointerMove = (e: React.PointerEvent) => {
    const d = drag.current;
    if (!d) return;
    const r = svgRef.current?.getBoundingClientRect();
    if (!r) return;
    const dx = ((e.clientX - d.x) / r.width) * d.vb.w;
    const dy = ((e.clientY - d.y) / r.height) * d.vb.h;
    setVb({ ...d.vb, x: d.vb.x - dx, y: d.vb.y - dy });
  };

  const endPan = () => {
    drag.current = null;
    setPanning(false);
  };

  const onKeyDown = (e: React.KeyboardEvent) => {
    const step = vb.w * 0.12;
    if (e.key === 'ArrowLeft') setVb(v => ({ ...v, x: v.x - step }));
    else if (e.key === 'ArrowRight') setVb(v => ({ ...v, x: v.x + step }));
    else if (e.key === 'ArrowUp') setVb(v => ({ ...v, y: v.y - step }));
    else if (e.key === 'ArrowDown') setVb(v => ({ ...v, y: v.y + step }));
    else if (e.key === '+' || e.key === '=') zoomAt(1 / 1.2);
    else if (e.key === '-' || e.key === '_') zoomAt(1.2);
    else if (e.key === '0') fit();
    else return;
    e.preventDefault();
  };

  /* ── Empty state ─────────────────────────────────────────────────────────── */

  if (hosts.length === 0) {
    return (
      <div className={`grid place-items-center ${className ?? ''}`}>
        <div className="max-w-md px-6 text-center">
          <Network className="mx-auto h-7 w-7 text-cyan-500/40" strokeWidth={1.25} aria-hidden />
          <p className="mt-2 font-mono text-[10px] leading-relaxed text-slate-300">
            {isAr
              ? 'لا مضيف مسجّل، فلا شبكة لرسمها.'
              : 'No host enrolled, so there is no network to draw.'}
          </p>
          <p className="mt-1.5 font-mono text-[8px] leading-relaxed text-slate-500">
            {isAr
              ? 'افتح «أسطول الأصول» في العمود الأيمن، اصدر رمز تسجيل، وشغّل الأمر على الجهاز الذي تريد مراقبته. سيُبلّغ عن قطاعاته وجيرانه فورًا.'
              : 'Open ASSET FLEET on the right, mint an enrolment token, and run the command on the machine you want watched. It reports its segments and neighbours immediately.'}
          </p>
          <p className="mt-2 font-mono text-[10px] text-slate-700">
            {isAr
              ? 'لن تُرسم أجهزة نموذجية — رسمٌ فارغ يعني أن شيئًا لم يُرصَد.'
              : 'no sample devices are drawn — an empty graph means nothing was observed.'}
          </p>
        </div>
      </div>
    );
  }

  const devices = nodes.filter(n => n.kind === 'DEVICE');
  const anySwept = devices.some(n => n.openPorts.length > 0 || n.neighbour?.sweepState === 'NO_RESPONSE');
  const zoomPct = Math.round((BASE.w / vb.w) * 100);

  /* ── Render ──────────────────────────────────────────────────────────────── */

  return (
    <div className={`relative overflow-hidden ${className ?? ''}`}>
      <svg
        ref={svgRef}
        viewBox={`${vb.x} ${vb.y} ${vb.w} ${vb.h}`}
        className="h-full w-full touch-none outline-none"
        style={{ cursor: panning ? 'grabbing' : 'grab' }}
        onWheel={onWheel}
        onPointerDown={onPointerDown}
        onPointerMove={onPointerMove}
        onPointerUp={endPan}
        onPointerCancel={endPan}
        onKeyDown={onKeyDown}
        tabIndex={0}
        role="application"
        aria-label={
          isAr
            ? `طوبولوجيا الشبكة: ${hosts.length} مضيف مسجّل و${devices.length} جهاز مرصود. الأسهم للتحريك، + و− للتكبير، 0 للملاءمة.`
            : `Network topology: ${hosts.length} enrolled hosts, ${devices.length} observed devices. Arrow keys pan, + and − zoom, 0 fits.`
        }
      >
        <defs>
          <radialGradient id="nt-core" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor="#22d3ee" stopOpacity="0.16" />
            <stop offset="100%" stopColor="#22d3ee" stopOpacity="0" />
          </radialGradient>
          <filter id="nt-glow" x="-60%" y="-60%" width="220%" height="220%">
            <feGaussianBlur stdDeviation="4" result="b" />
            <feMerge>
              <feMergeNode in="b" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
          <pattern id="nt-grid" width="52" height="52" patternUnits="userSpaceOnUse">
            <path d="M52 0H0v52" fill="none" stroke="rgba(34,211,238,0.055)" strokeWidth="1" />
          </pattern>
        </defs>

        {/* Grid, drawn far larger than the frame so panning never reaches its edge. */}
        <rect x={BASE.x - 4000} y={BASE.y - 4000} width={BASE.w + 8000} height={BASE.h + 8000} fill="url(#nt-grid)" />

        {/* Relationship tiers, faint, so they read as structure rather than as range. */}
        {[208, 376, 438].map(r => (
          <circle
            key={r}
            cx={BASE.w / 2}
            cy={BASE.h / 2}
            r={r}
            fill="none"
            stroke="rgba(34,211,238,0.07)"
            strokeWidth="1"
            strokeDasharray="2 8"
          />
        ))}
        <circle cx={BASE.w / 2} cy={BASE.h / 2} r={300} fill="url(#nt-core)" />

        {/* Edges. Curved, because a bundle of straight radial lines reads as a starburst
            and its crossings become unreadable the moment two segments overlap. */}
        {edges.map((e, i) => {
          const a = byId.get(e.from);
          const b = byId.get(e.to);
          if (!a || !b) return null;
          const live = hovered === e.from || hovered === e.to || selected?.id === e.from || selected?.id === e.to;
          const mx = (a.x + b.x) / 2;
          const my = (a.y + b.y) / 2;
          // Bow the curve away from the centre so siblings fan out instead of overlapping.
          const nx = -(b.y - a.y);
          const ny = b.x - a.x;
          const len = Math.hypot(nx, ny) || 1;
          const bow = 26;
          const d = `M ${a.x} ${a.y} Q ${mx + (nx / len) * bow} ${my + (ny / len) * bow} ${b.x} ${b.y}`;
          return (
            <g key={i}>
              {e.hot && (
                <path d={d} fill="none" stroke={TONE.hot} strokeWidth={7} filter="url(#nt-glow)" className="tac-hot-path" />
              )}
              {e.projected && (
                <path d={d} fill="none" stroke="#fbbf24" strokeWidth={2.5} strokeDasharray="8 6" opacity={0.9} />
              )}
              <path
                d={d}
                fill="none"
                stroke={e.tone}
                strokeWidth={live ? e.width + 1 : e.width}
                strokeDasharray={e.dashed ? '4 5' : undefined}
                opacity={e.hot ? 0.95 : live ? 0.95 : 0.38}
              />
            </g>
          );
        })}

        {/* Nodes as plates. A labelled plate is legible at a glance and at a distance;
            a bare dot with text beside it is not, and this board is read from across a
            room. */}
        {nodes.map(n => {
          const isSel = selected?.id === n.id;
          const isHov = hovered === n.id;
          const w = n.kind === 'VANTAGE' ? 188 : n.kind === 'SEGMENT' ? 150 : 138;
          const h = n.kind === 'VANTAGE' ? 54 : 42;
          const cut = 9;

          return (
            <g
              key={n.id}
              transform={`translate(${n.x - w / 2},${n.y - h / 2})`}
              onPointerDown={ev => {
                // Stop the pan gesture so a click on a plate selects rather than drags.
                ev.stopPropagation();
                setSelected(n);
              }}
              onMouseEnter={() => setHovered(n.id)}
              onMouseLeave={() => setHovered(null)}
              style={{ cursor: 'pointer' }}
              role="button"
              tabIndex={0}
              aria-label={`${n.label} — ${n.typeLabel}${n.openPorts.length ? `, ports ${n.openPorts.join(' ')}` : ''}${n.hot ? ` — ${n.hot}` : ''}`}
              onKeyDown={ev => {
                if (ev.key === 'Enter' || ev.key === ' ') {
                  ev.preventDefault();
                  setSelected(n);
                }
              }}
            >
              {(isSel || isHov) && (
                <path
                  d={`M ${cut} -3 H ${w + 3} V ${h - cut} L ${w - cut + 3} ${h + 3} H -3 V ${cut}Z`}
                  fill="none"
                  stroke={n.tone}
                  strokeWidth="1.2"
                  opacity={isSel ? 0.9 : 0.5}
                  filter="url(#nt-glow)"
                />
              )}

              {/* Twin projection: an amber (exposed) or slate (unknown) dashed outline around
                  the plate, plus a tag. Dashes keep it visibly a projection, never a state. */}
              {n.twin && n.twin !== 'CLEAR' && (
                <>
                  <path
                    d={`M ${cut - 1} -6 H ${w + 6} V ${h - cut + 1} L ${w - cut + 1} ${h + 6} H -6 V ${cut - 1}Z`}
                    fill="none"
                    stroke={n.twin === 'EXPOSED' ? '#fbbf24' : '#94a3b8'}
                    strokeWidth={1.4}
                    strokeDasharray="5 4"
                  />
                  <text x={w} y={-10} textAnchor="end" fontFamily="var(--font-mono)" fontSize="10" fontWeight="bold" fill={n.twin === 'EXPOSED' ? '#fbbf24' : '#94a3b8'}>
                    {n.twin === 'EXPOSED' ? (isAr ? 'مكشوف · محاكاة' : 'EXPOSED · SIM') : isAr ? 'مجهول' : 'UNKNOWN'}
                  </text>
                </>
              )}

              {/* Chamfered plate, which is this platform's panel language. */}
              <path
                d={`M ${cut} 0 H ${w} V ${h - cut} L ${w - cut} ${h} H 0 V ${cut}Z`}
                fill="rgba(3,7,18,0.93)"
                stroke={n.hot ? TONE.hot : n.tone}
                strokeWidth={n.kind === 'VANTAGE' ? 1.7 : 1.1}
                strokeOpacity={isSel || isHov ? 1 : 0.62}
              />
              {/* Accent spine: the tone strip that makes class readable without reading. */}
              <rect x={0} y={cut} width={3} height={h - cut * 2} fill={n.tone} opacity="0.95" />

              <foreignObject x={10} y={4} width={w - 16} height={h - 8}>
                <div
                  // @ts-expect-error xmlns is valid inside foreignObject
                  xmlns="http://www.w3.org/1999/xhtml"
                  style={{ display: 'flex', alignItems: 'center', gap: 6, height: '100%', overflow: 'hidden' }}
                >
                  <n.icon
                    style={{ width: n.kind === 'VANTAGE' ? 16 : 13, height: n.kind === 'VANTAGE' ? 16 : 13, color: n.tone, flexShrink: 0 }}
                    strokeWidth={1.5}
                  />
                  <div style={{ minWidth: 0, lineHeight: 1.25 }}>
                    <div
                      style={{
                        fontFamily: 'var(--font-mono)',
                        fontSize: n.kind === 'VANTAGE' ? 13 : 11,
                        fontWeight: 700,
                        color: '#e6edf3',
                        whiteSpace: 'nowrap',
                        overflow: 'hidden',
                        textOverflow: 'ellipsis',
                        textShadow: `0 0 8px ${n.tone}66`
                      }}
                    >
                      {n.label}
                    </div>
                    <div
                      style={{
                        fontFamily: 'var(--font-mono)',
                        fontSize: 8,
                        letterSpacing: '0.08em',
                        color: '#8aa4b8',
                        whiteSpace: 'nowrap',
                        overflow: 'hidden',
                        textOverflow: 'ellipsis'
                      }}
                    >
                      {n.sub ?? n.typeLabel}
                    </div>
                    {n.openPorts.length > 0 && (
                      <div
                        style={{
                          fontFamily: 'var(--font-mono)',
                          fontSize: 8,
                          color: TONE.open,
                          whiteSpace: 'nowrap',
                          overflow: 'hidden',
                          textOverflow: 'ellipsis'
                        }}
                      >
                        {n.openPorts.slice(0, 4).map(p => SERVICE[p] ?? p).join(' · ')}
                      </div>
                    )}
                  </div>
                  {n.isolated && <ShieldOff style={{ width: 12, height: 12, color: '#e11d48', flexShrink: 0, marginInlineStart: 'auto' }} />}
                </div>
              </foreignObject>
            </g>
          );
        })}
      </svg>

      {/* ── Legend ─────────────────────────────────────────────────────────── */}
      <div className="pointer-events-none absolute start-2 top-2 border border-cyan-500/25 bg-[#030712]/80 px-2 py-1.5 backdrop-blur-xl">
        <p className="font-mono text-[10px] tracking-widest text-cyan-400 uppercase">
          {isAr ? 'الموضع = العلاقة، لا الجغرافيا' : 'POSITION = RELATIONSHIP, NOT GEOGRAPHY'}
        </p>
        <div className="mt-1 space-y-[2px]">
          {(
            [
              [TONE.vantage, isAr ? 'مضيف مسجّل — نقطة الرصد' : 'enrolled host — vantage point'],
              [TONE.segment, isAr ? 'قطاع شبكي' : 'network segment'],
              [TONE.open, isAr ? 'جهاز بمنافذ مفتوحة' : 'device with open ports'],
              [TONE.filtering, isAr ? 'يُرشِّح — فُحص ولم يُجب' : 'filtering — probed, no response'],
              [TONE.unswept, isAr ? 'مرصود، لم يُمسح' : 'observed, not swept'],
              [TONE.hot, isAr ? 'مسار أحمر — مصدر تنبيه حرِج أو محتوى' : 'crimson path — HIGH/CRITICAL alert source or contained']
            ] as const
          ).map(([tone, label]) => (
            <p key={label} className="flex items-center gap-1.5 font-mono text-[10px] text-slate-300">
              <span className="h-2 w-[3px]" style={{ background: tone }} aria-hidden />
              {label}
            </p>
          ))}
        </div>
        {!anySwept && devices.length > 0 && (
          <p className="mt-1 max-w-[260px] font-mono text-[10px] leading-relaxed text-slate-500">
            {isAr
              ? 'الوصلات المتقطّعة: المنافذ غير معروفة، لم يُشغَّل مسح. الرصد سلبي من ذاكرة ARP.'
              : 'dashed links: ports unknown, no sweep has run. discovery is passive, from the ARP cache.'}
          </p>
        )}
      </div>

      {/* ── Navigation controls ────────────────────────────────────────────── */}
      <div className="absolute end-2 top-2 flex items-center gap-1">
        <span className="flex items-center gap-1 border border-cyan-500/25 bg-[#030712]/80 px-1.5 py-0.5 font-mono text-[10px] text-slate-400 backdrop-blur-xl">
          <Move className="h-2.5 w-2.5 text-cyan-400/70" aria-hidden />
          {isAr ? 'اسحب · عجلة · ٠ ملاءمة' : 'DRAG · WHEEL · 0 FIT'}
          <span className="ms-1 text-cyan-400 tabular-nums">{zoomPct}%</span>
        </span>
        {(
          [
            [Plus, () => zoomAt(1 / 1.25), isAr ? 'تكبير' : 'zoom in'],
            [Minus, () => zoomAt(1.25), isAr ? 'تصغير' : 'zoom out'],
            [Maximize2, fit, isAr ? 'ملاءمة الكل' : 'fit all']
          ] as const
        ).map(([Icon, fn, label], i) => (
          <button
            key={i}
            type="button"
            onClick={fn}
            aria-label={label}
            title={label}
            className="grid h-6 w-6 place-items-center border border-cyan-500/30 bg-[#030712]/80 text-cyan-400 backdrop-blur-xl transition-colors hover:bg-cyan-500/15"
          >
            <Icon className="h-3 w-3" aria-hidden />
          </button>
        ))}
      </div>

      {/* ── Selection inspector ────────────────────────────────────────────── */}
      {selected && (
        <div className="absolute end-2 bottom-2 w-[272px] border border-cyan-500/40 bg-[#030712]/95 p-2.5 shadow-[0_0_30px_rgba(0,0,0,0.9)] backdrop-blur-2xl">
          <div className="flex items-start justify-between gap-2">
            <div className="min-w-0">
              <p className="truncate font-mono text-[11px] font-bold text-white" style={{ textShadow: `0 0 10px ${selected.tone}88` }}>
                {selected.label}
              </p>
              <p className="font-mono text-[10px] tracking-widest uppercase" style={{ color: selected.tone }}>
                {selected.typeLabel}
              </p>
            </div>
            <button
              type="button"
              onClick={() => setSelected(null)}
              aria-label={isAr ? 'إغلاق' : 'close'}
              className="shrink-0 font-mono text-[11px] leading-none text-slate-500 hover:text-white"
            >
              ✕
            </button>
          </div>

          {selected.neighbour && (
            <div className="mt-1.5 space-y-[2px] border-t border-cyan-900/40 pt-1.5">
              {(
                [
                  ['MAC', selected.neighbour.mac],
                  [isAr ? 'المُصنِّع' : 'VENDOR', selected.neighbour.vendor ?? (isAr ? 'مجهول' : 'unknown')],
                  [isAr ? 'عبر الواجهة' : 'VIA', selected.neighbour.viaInterface ?? '—']
                ] as const
              ).map(([k, v]) => (
                <p key={k} className="flex justify-between gap-2 font-mono text-[10px]">
                  <span className="text-slate-600">{k}</span>
                  <span className="truncate text-slate-300">{v}</span>
                </p>
              ))}

              {!selected.neighbour.vendor && (
                <p className="font-mono text-[10px] leading-relaxed text-amber-400/80">
                  {isAr
                    ? 'مجهول لأن البادئة غير مُدرَجة أو العنوان معشّى — لا يُخمَّن مُصنِّع.'
                    : 'unknown because the prefix is unlisted or the MAC is randomised — no vendor is guessed.'}
                </p>
              )}

              <p className="flex justify-between gap-2 font-mono text-[10px]">
                <span className="text-slate-600">{isAr ? 'المنافذ' : 'PORTS'}</span>
                <span className="truncate" style={{ color: selected.openPorts.length ? TONE.open : '#5c7484' }}>
                  {selected.openPorts.length
                    ? selected.openPorts.map(p => `${p}${SERVICE[p] ? `/${SERVICE[p]}` : ''}`).join(', ')
                    : selected.neighbour.sweepState === 'NO_RESPONSE'
                      ? isAr ? 'فُحص ولم يُجب' : 'probed, no response'
                      : selected.neighbour.sweepState === 'RESPONDED'
                        ? isAr ? 'لا شيء مفتوح مما فُحص' : 'none open among probed'
                        : isAr ? 'لم يُمسح' : 'not swept'}
                </span>
              </p>

              {selected.neighbour.sweepState === 'NO_RESPONSE' && (
                <p className="font-mono text-[10px] leading-relaxed text-amber-400/80">
                  {isAr
                    ? 'يردّ على ARP ولا يردّ على TCP — جهاز يُرشِّح أو محميّ بجدار، لا جهاز متوقّف.'
                    : 'answers ARP but not TCP: a filtering or firewalled device, not one that is down.'}
                </p>
              )}

              <p className="pt-0.5 font-mono text-[10px] text-slate-600">
                {isAr ? 'الدليل: ردّ على الشبكة (ذاكرة ARP)' : 'evidence: answered on the wire (ARP cache)'}
              </p>
            </div>
          )}

          {selected.asset && (
            <button
              type="button"
              onClick={() => onSelectAsset(selected.asset!)}
              className="mt-2 w-full border border-cyan-500/40 px-2 py-1 font-mono text-[10px] tracking-widest text-cyan-400 uppercase transition-colors hover:bg-cyan-500/15"
            >
              {isAr ? '[ فتح سجلّ الأصل ]' : '[ OPEN ASSET RECORD ]'}
            </button>
          )}
        </div>
      )}
    </div>
  );
};

export default NetworkTopologyView;
