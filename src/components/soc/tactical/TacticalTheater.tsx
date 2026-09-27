import React from 'react';
import { CYAN, CRIMSON, AMBER, EMERALD } from './TacticalPrimitives';
import type { Tracer, StreamStatus } from './useLiveAttackStream';

/**
 * TACTICAL THREAT THEATRE
 *
 * A live radar topology, replacing the wireframe globe. The brief was explicit that
 * hollow wireframe graphics are out, and the reason holds up technically: a graticule
 * sphere spends most of its pixels on lines that encode nothing, and the contacts —
 * the only part carrying information — end up as small dots competing with the mesh.
 * Here the geometry is solid and every mark is a reading:
 *
 *   range rings      concentric bands, labelled by threat volume, not decoration
 *   contacts         one filled plate per real origin country, radius from volume,
 *                    bearing from its real longitude so the layout is geographic
 *   cluster plates   the actual eBPF cluster nodes, ringed when isolated
 *   tracers          one streak per TELEMETRY_PACKET off the live socket, coloured
 *                    by the verdict the engine reached — drop, pass or redirect
 *   sweep            a bearing line whose only job is to show the surface is live;
 *                    it stops dead when the socket drops, so stillness is a signal
 *
 * Drawn on canvas rather than SVG because tracers arrive per request and a per-frame
 * DOM diff of a hundred nodes will not hold 60 FPS under load — which is the one
 * condition a defence console has to look good under.
 *
 * Nothing is drawn that was not measured. With no origins the field renders empty and
 * names the endpoint; with the socket down the sweep freezes and the caller is
 * expected to say so. A radar that animates fabricated contacts is the most dangerous
 * possible version of a fabricated number, because it reads as proof of watching.
 */

export interface TheaterNode {
  name: string;
  ip: string;
  isolated: boolean;
  threatScore: number | null;
}

export interface TheaterContact {
  code: string;
  country: string;
  count: number;
  lon?: number;
}

interface Props {
  contacts: TheaterContact[];
  nodes: TheaterNode[];
  tracers: Tracer[];
  status: StreamStatus;
  reduce?: boolean;
  isAr: boolean;
  className?: string;
  /** Named in the empty state so an operator knows which feed is silent. */
  emptyEndpoint?: string;
}

/** Longitudes for the codes the geo feed emits, so bearing is geographic. */
const LON: Record<string, number> = {
  US: -98.6, CN: 104.2, RU: 105.3, DE: 10.4, NL: 5.3, GB: -2.0, FR: 2.2, BR: -51.9,
  IN: 78.9, IR: 53.7, KP: 127.5, UA: 31.2, SA: 45.1, AE: 53.8, EG: 30.8, TR: 35.2,
  JP: 138.3, KR: 127.8, SG: 103.8, AU: 133.8, CA: -106.3, MX: -102.5, ZA: 22.9,
  NG: 8.7, VN: 108.3, ID: 113.9, PK: 69.3, RO: 25.0, PL: 19.1, SE: 18.6, CH: 8.2,
  IT: 12.6, ES: -3.7, KZ: 66.9, BY: 27.95
};

const VERDICT_COLOUR: Record<Tracer['verdict'], string> = {
  DROP: CRIMSON,
  PASS: EMERALD,
  REDIRECT: AMBER
};

export const TacticalTheater: React.FC<Props> = ({
  contacts,
  nodes,
  tracers,
  status,
  reduce = false,
  isAr,
  className,
  emptyEndpoint = '/soc/analytics'
}) => {
  const canvasRef = React.useRef<HTMLCanvasElement>(null);
  const raf = React.useRef<number | null>(null);

  // Live values held in refs: the draw loop reads them without being torn down and
  // rebuilt on every poll, which would restart the sweep several times a second.
  const contactsRef = React.useRef(contacts);
  contactsRef.current = contacts;
  const nodesRef = React.useRef(nodes);
  nodesRef.current = nodes;
  const tracersRef = React.useRef(tracers);
  tracersRef.current = tracers;
  const statusRef = React.useRef(status);
  statusRef.current = status;

  React.useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let w = 0;
    let h = 0;
    const dpr = Math.min(window.devicePixelRatio || 1, 2);

    const resize = () => {
      const r = canvas.getBoundingClientRect();
      w = r.width;
      h = r.height;
      canvas.width = Math.max(1, Math.floor(w * dpr));
      canvas.height = Math.max(1, Math.floor(h * dpr));
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    };
    resize();

    const ro = new ResizeObserver(resize);
    ro.observe(canvas);

    let sweep = 0;
    let frame = 0;

    const draw = () => {
      frame++;
      const cs = contactsRef.current;
      const ns = nodesRef.current;
      const ts = tracersRef.current;
      const live = statusRef.current === 'LIVE';

      const cx = w / 2;
      const cy = h / 2;
      const R = Math.min(w, h) * 0.42;

      ctx.clearRect(0, 0, w, h);

      // ── Range rings. Solid bands, not a wireframe mesh. ──────────────────
      for (let i = 4; i >= 1; i--) {
        const r = (R * i) / 4;
        ctx.beginPath();
        ctx.arc(cx, cy, r, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(6, 182, 212, ${0.022 * (5 - i)})`;
        ctx.fill();
        ctx.strokeStyle = `rgba(34, 211, 238, ${i === 4 ? 0.3 : 0.13})`;
        ctx.lineWidth = i === 4 ? 1.2 : 0.7;
        ctx.stroke();
      }

      // Bearing ticks every 30 degrees, short marks on the outer ring only.
      ctx.strokeStyle = 'rgba(34, 211, 238, 0.22)';
      ctx.lineWidth = 1;
      for (let a = 0; a < 360; a += 30) {
        const rad = (a * Math.PI) / 180;
        ctx.beginPath();
        ctx.moveTo(cx + Math.cos(rad) * (R - 7), cy + Math.sin(rad) * (R - 7));
        ctx.lineTo(cx + Math.cos(rad) * R, cy + Math.sin(rad) * R);
        ctx.stroke();
      }

      // ── Sweep. Frozen when the socket is down, and that stillness is the point. ──
      if (live && !reduce) {
        sweep = (sweep + 0.011) % (Math.PI * 2);
        ctx.save();
        ctx.beginPath();
        ctx.moveTo(cx, cy);
        ctx.arc(cx, cy, R, sweep - 0.5, sweep);
        ctx.closePath();
        const g = ctx.createRadialGradient(cx, cy, 0, cx, cy, R);
        g.addColorStop(0, 'rgba(34, 211, 238, 0.14)');
        g.addColorStop(1, 'rgba(34, 211, 238, 0)');
        ctx.fillStyle = g;
        ctx.fill();
        ctx.restore();

        ctx.beginPath();
        ctx.moveTo(cx, cy);
        ctx.lineTo(cx + Math.cos(sweep) * R, cy + Math.sin(sweep) * R);
        ctx.strokeStyle = 'rgba(34, 211, 238, 0.5)';
        ctx.lineWidth = 1.2;
        ctx.stroke();
      }

      // ── Contacts: one solid plate per real origin. ───────────────────────
      const maxCount = Math.max(1, ...cs.map(c => c.count));
      cs.forEach((c, i) => {
        const lon = c.lon ?? LON[c.code];
        // A code without a centroid still gets a stable slot rather than being
        // dropped: it is a real origin, and hiding it would understate the picture.
        const bearing =
          lon != null ? ((lon + 180) / 360) * Math.PI * 2 - Math.PI / 2 : (i / Math.max(1, cs.length)) * Math.PI * 2;

        const share = c.count / maxCount;
        // Louder origins sit further out, so the ring an operator scans first is
        // the one carrying the most volume.
        const rr = R * (0.32 + 0.6 * share);
        const x = cx + Math.cos(bearing) * rr;
        const y = cy + Math.sin(bearing) * rr;
        const size = 4 + share * 7;

        // Link to centre: the path the traffic takes.
        ctx.beginPath();
        ctx.moveTo(cx, cy);
        ctx.lineTo(x, y);
        ctx.strokeStyle = `rgba(244, 63, 94, ${0.1 + share * 0.3})`;
        ctx.lineWidth = 0.6 + share * 1.4;
        ctx.stroke();

        ctx.beginPath();
        ctx.arc(x, y, size + 5, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(244, 63, 94, ${0.07 + share * 0.1})`;
        ctx.fill();

        // Solid diamond plate, the reference's contact mark.
        ctx.save();
        ctx.translate(x, y);
        ctx.rotate(Math.PI / 4);
        ctx.fillStyle = CRIMSON;
        ctx.globalAlpha = 0.85;
        ctx.fillRect(-size / 2, -size / 2, size, size);
        ctx.globalAlpha = 1;
        ctx.strokeStyle = 'rgba(253, 164, 175, 0.9)';
        ctx.lineWidth = 0.8;
        ctx.strokeRect(-size / 2, -size / 2, size, size);
        ctx.restore();

        ctx.font = '8px ui-monospace, monospace';
        ctx.fillStyle = 'rgba(253, 164, 175, 0.92)';
        ctx.textAlign = Math.cos(bearing) >= 0 ? 'left' : 'right';
        ctx.fillText(`${c.code} ${c.count}`, x + (Math.cos(bearing) >= 0 ? size + 4 : -size - 4), y + 3);
      });

      // ── Cluster plates on the inner ring. ───────────────────────────────
      ns.forEach((n, i) => {
        const a = (i / Math.max(1, ns.length)) * Math.PI * 2 - Math.PI / 2;
        const rr = R * 0.17;
        const x = cx + Math.cos(a) * rr;
        const y = cy + Math.sin(a) * rr;
        const col = n.isolated ? CRIMSON : CYAN;

        ctx.fillStyle = col;
        ctx.globalAlpha = 0.9;
        ctx.fillRect(x - 4, y - 4, 8, 8);
        ctx.globalAlpha = 1;

        if (n.isolated) {
          // Containment ring, pulsing so an isolated node is findable at a glance.
          const pulse = reduce ? 9 : 9 + Math.sin(frame / 14) * 2.5;
          ctx.beginPath();
          ctx.arc(x, y, pulse, 0, Math.PI * 2);
          ctx.strokeStyle = 'rgba(244, 63, 94, 0.75)';
          ctx.lineWidth = 1.2;
          ctx.stroke();
        }

        ctx.font = '7px ui-monospace, monospace';
        ctx.fillStyle = n.isolated ? 'rgba(253,164,175,0.9)' : 'rgba(103, 232, 249, 0.8)';
        ctx.textAlign = 'center';
        ctx.fillText(n.name.slice(0, 12), x, y + 15);
      });

      // ── Centre plate: the defended asset. ───────────────────────────────
      ctx.beginPath();
      ctx.arc(cx, cy, 16, 0, Math.PI * 2);
      ctx.fillStyle = 'rgba(0, 0, 0, 0.85)';
      ctx.fill();
      ctx.strokeStyle = CYAN;
      ctx.lineWidth = 1.4;
      ctx.stroke();
      ctx.font = 'bold 8px ui-monospace, monospace';
      ctx.fillStyle = CYAN;
      ctx.textAlign = 'center';
      ctx.fillText('SOC', cx, cy + 3);

      // ── Tracers: one streak per packet the socket actually delivered. ────
      const now = Date.now();
      ts.forEach(t => {
        const age = (now - t.at) / 2600;
        if (age > 1) return;
        // Bearing from the tracer id so a given packet keeps its lane for its life.
        const a = ((t.id * 137.508) % 360) * (Math.PI / 180);
        const from = R * 1.02;
        const to = 18;
        const rr = from + (to - from) * age;
        const x = cx + Math.cos(a) * rr;
        const y = cy + Math.sin(a) * rr;
        const col = VERDICT_COLOUR[t.verdict];
        const fade = 1 - age;

        ctx.beginPath();
        ctx.moveTo(cx + Math.cos(a) * (rr + 16), cy + Math.sin(a) * (rr + 16));
        ctx.lineTo(x, y);
        ctx.strokeStyle = col;
        ctx.globalAlpha = fade * 0.75;
        ctx.lineWidth = t.verdict === 'DROP' ? 1.9 : 1.1;
        ctx.stroke();

        ctx.beginPath();
        ctx.arc(x, y, t.verdict === 'DROP' ? 2.4 : 1.7, 0, Math.PI * 2);
        ctx.fillStyle = col;
        ctx.globalAlpha = fade;
        ctx.fill();
        ctx.globalAlpha = 1;
      });

      raf.current = requestAnimationFrame(draw);
    };

    raf.current = requestAnimationFrame(draw);

    return () => {
      ro.disconnect();
      if (raf.current) cancelAnimationFrame(raf.current);
    };
  }, [reduce]);

  const silent = contacts.length === 0 && nodes.length === 0;

  return (
    <div className={`relative ${className ?? ''}`}>
      <canvas
        ref={canvasRef}
        className="block h-full w-full"
        role="img"
        aria-label={
          isAr
            ? `رادار تكتيكي: ${contacts.length} مصدر، ${nodes.length} عقدة، البثّ ${status}`
            : `Tactical radar: ${contacts.length} origins, ${nodes.length} nodes, stream ${status}`
        }
      />

      {silent && (
        <div className="absolute inset-0 grid place-items-center">
          <div className="text-center">
            <p className="text-[10px] text-slate-500" style={{ fontFamily: 'var(--font-mono)' }}>
              {isAr ? 'لا مصادر ولا عقد لعرضها' : 'no origins or nodes to plot'}
            </p>
            <p className="mt-1 text-[8px] text-slate-700" style={{ fontFamily: 'var(--font-mono)' }}>
              {emptyEndpoint}
            </p>
          </div>
        </div>
      )}

      {/* The socket's state, on the face of the radar. A frozen sweep must be
          explained, or it reads as a rendering bug instead of a dead feed. */}
      {status !== 'LIVE' && (
        <div className="absolute bottom-2 left-1/2 -translate-x-1/2">
          <p
            className={`text-[8px] tracking-[0.16em] ${status === 'CONNECTING' ? 'text-amber-400' : 'text-rose-500'}`}
            style={{ fontFamily: 'var(--font-mono)' }}
          >
            {status === 'CONNECTING'
              ? isAr ? 'جارٍ وصل البثّ…' : 'STREAM CONNECTING…'
              : isAr
                ? 'البثّ مقطوع — المسح متوقّف، لا حِزَم مُفترضة'
                : 'STREAM DOWN — SWEEP HELD, NO PACKETS ASSUMED'}
          </p>
        </div>
      )}
    </div>
  );
};

export default TacticalTheater;
