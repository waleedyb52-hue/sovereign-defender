import React from 'react';

/**
 * THREAT GLOBE — orbital command view
 *
 * A rotating globe with atmospheric rim glow, orbital grid lines, pulsing threat
 * rings and ballistic attack arcs. The visual language of the reference design,
 * drawn from this platform's own geographic threat distribution.
 *
 * Why 2D canvas rather than three.js
 *   three.js is already a dependency, so the choice is not about adding one. An
 *   orthographic globe with graticules, glow and arcs is a few hundred lines of
 *   canvas and costs a fraction of the memory of a WebGL context plus geometry —
 *   which matters on the host this runs on. It also gives exact control over the
 *   rim gradient and the arc easing, which is most of what makes the reference
 *   read the way it does.
 *
 * Every marker is a real country from `/api/v1/soc/analytics`
 *   Coordinates come from a small lookup of country centroids, and the ring size
 *   scales with the observed threat count. Where the feed returns nothing the globe
 *   still turns and no markers are drawn — an empty globe is honest, and inventing
 *   attack origins to fill it would put fabricated geography in front of an
 *   operator.
 */

export interface ThreatOrigin {
  country: string;
  code: string;
  count: number;
  /** Optional explicit position; otherwise resolved from the code. */
  lat?: number;
  lon?: number;
}

/** Country centroids for the codes this platform's geo feed emits. */
const CENTROIDS: Record<string, [number, number]> = {
  US: [39.8, -98.6], CN: [35.9, 104.2], RU: [61.5, 105.3], DE: [51.2, 10.4],
  NL: [52.1, 5.3], GB: [54.0, -2.0], FR: [46.2, 2.2], BR: [-14.2, -51.9],
  IN: [20.6, 78.9], IR: [32.4, 53.7], KP: [40.3, 127.5], UA: [48.4, 31.2],
  SA: [23.9, 45.1], AE: [23.4, 53.8], EG: [26.8, 30.8], TR: [38.9, 35.2],
  JP: [36.2, 138.3], KR: [35.9, 127.8], SG: [1.35, 103.8], AU: [-25.3, 133.8],
  CA: [56.1, -106.3], MX: [23.6, -102.5], ZA: [-30.6, 22.9], NG: [9.1, 8.7],
  VN: [14.1, 108.3], ID: [-0.8, 113.9], PK: [30.4, 69.3], RO: [45.9, 25.0],
  PL: [51.9, 19.1], SE: [60.1, 18.6], CH: [46.8, 8.2], IT: [41.9, 12.6],
  ES: [40.5, -3.7], KZ: [48.0, 66.9], BY: [53.7, 27.95]
};

interface Props {
  origins: ThreatOrigin[];
  /** Target the command view is locked on, drawn as the receiving station. */
  target?: { label: string; lat: number; lon: number } | null;
  height?: number;
  className?: string;
  /** Honour prefers-reduced-motion: the globe holds still instead of spinning. */
  reducedMotion?: boolean;
  /** Draw the ballistic arcs. Display-only — hiding them drops no measurement. */
  showArcs?: boolean;
  /** Draw the orbital graticule. */
  showGrid?: boolean;
  /**
   * Fix the rotation at this bearing instead of spinning.
   *
   * Null resumes the automatic spin. This exists so the compass control can hold
   * the globe still on a region an operator is reading, which is what the
   * reference's camera dial did.
   */
  rotationOverride?: number | null;
}

export const ThreatGlobeCanvas: React.FC<Props> = ({
  origins,
  target = null,
  height = 420,
  className,
  reducedMotion = false,
  showArcs = true,
  showGrid = true,
  rotationOverride = null
}) => {
  const ref = React.useRef<HTMLCanvasElement>(null);
  const raf = React.useRef<number | null>(null);
  const originsRef = React.useRef(origins);
  originsRef.current = origins;

  /**
   * Live flags held in refs.
   *
   * The draw loop is created once; putting these in its dependency list would tear
   * down and rebuild the animation on every toggle, which shows as a visible stutter
   * and resets the spin. Refs let the running loop read the current value instead.
   */
  const flags = React.useRef({ showArcs, showGrid, rotationOverride, target });
  flags.current = { showArcs, showGrid, rotationOverride, target };

  React.useEffect(() => {
    const canvas = ref.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const dpr = Math.min(2, window.devicePixelRatio || 1);
    let w = 0;
    let h = 0;

    const resize = () => {
      const rect = canvas.parentElement?.getBoundingClientRect();
      w = Math.max(320, rect?.width ?? 640);
      h = height;
      canvas.width = w * dpr;
      canvas.height = h * dpr;
      canvas.style.width = `${w}px`;
      canvas.style.height = `${h}px`;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    };
    resize();
    const ro = new ResizeObserver(resize);
    if (canvas.parentElement) ro.observe(canvas.parentElement);

    let spin = 0;
    const started = performance.now();

    /** Orthographic projection. Returns null for points on the far hemisphere. */
    const project = (lat: number, lon: number, cx: number, cy: number, r: number, rot: number) => {
      const phi = (lat * Math.PI) / 180;
      const lambda = ((lon + rot) * Math.PI) / 180;
      const x = Math.cos(phi) * Math.sin(lambda);
      const y = Math.sin(phi);
      const z = Math.cos(phi) * Math.cos(lambda);
      if (z < 0) return null; // behind the globe
      return { x: cx + x * r, y: cy - y * r, z };
    };

    const draw = (now: number) => {
      const t = (now - started) / 1000;
      const override = flags.current.rotationOverride;
      if (override != null) spin = override;
      else if (!reducedMotion) spin = (t * 6) % 360;

      const cx = w / 2;
      const cy = h / 2;
      const r = Math.min(w, h) * 0.34;

      ctx.clearRect(0, 0, w, h);

      // Deep space. The reference's near-black field.
      ctx.fillStyle = '#030509';
      ctx.fillRect(0, 0, w, h);

      // Sparse starfield, deterministic so it does not shimmer between frames.
      ctx.save();
      for (let i = 0; i < 90; i++) {
        const sx = ((i * 9301 + 49297) % 233280) / 233280;
        const sy = ((i * 4021 + 18913) % 199017) / 199017;
        const a = 0.12 + (((i * 7919) % 100) / 100) * 0.3;
        ctx.fillStyle = `rgba(200,225,255,${a})`;
        ctx.fillRect(sx * w, sy * h, 1, 1);
      }
      ctx.restore();

      // Atmospheric rim glow — the halo that makes the planet read as lit.
      const glow = ctx.createRadialGradient(cx, cy, r * 0.92, cx, cy, r * 1.42);
      glow.addColorStop(0, 'rgba(56,189,248,0.22)');
      glow.addColorStop(0.45, 'rgba(56,189,248,0.07)');
      glow.addColorStop(1, 'rgba(56,189,248,0)');
      ctx.fillStyle = glow;
      ctx.beginPath();
      ctx.arc(cx, cy, r * 1.42, 0, Math.PI * 2);
      ctx.fill();

      // The sphere, lit from upper left.
      const body = ctx.createRadialGradient(cx - r * 0.35, cy - r * 0.4, r * 0.1, cx, cy, r);
      body.addColorStop(0, '#0d1b2e');
      body.addColorStop(0.55, '#081221');
      body.addColorStop(1, '#040810');
      ctx.fillStyle = body;
      ctx.beginPath();
      ctx.arc(cx, cy, r, 0, Math.PI * 2);
      ctx.fill();

      // Terminator edge.
      ctx.strokeStyle = 'rgba(56,189,248,0.4)';
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.arc(cx, cy, r, 0, Math.PI * 2);
      ctx.stroke();

      // Orbital grid: parallels and meridians, clipped to the near hemisphere.
      if (flags.current.showGrid) {
      ctx.save();
      ctx.beginPath();
      ctx.arc(cx, cy, r - 0.5, 0, Math.PI * 2);
      ctx.clip();
      ctx.strokeStyle = 'rgba(56,189,248,0.13)';
      ctx.lineWidth = 0.7;

      for (let lat = -60; lat <= 60; lat += 30) {
        ctx.beginPath();
        let first = true;
        for (let lon = -180; lon <= 180; lon += 4) {
          const p = project(lat, lon, cx, cy, r, spin);
          if (!p) { first = true; continue; }
          if (first) { ctx.moveTo(p.x, p.y); first = false; } else ctx.lineTo(p.x, p.y);
        }
        ctx.stroke();
      }
      for (let lon = -180; lon < 180; lon += 30) {
        ctx.beginPath();
        let first = true;
        for (let lat = -90; lat <= 90; lat += 3) {
          const p = project(lat, lon, cx, cy, r, spin);
          if (!p) { first = true; continue; }
          if (first) { ctx.moveTo(p.x, p.y); first = false; } else ctx.lineTo(p.x, p.y);
        }
        ctx.stroke();
      }
      ctx.restore();
      }

      const list = originsRef.current ?? [];
      const maxCount = Math.max(1, ...list.map(o => o.count));

      // Receiving station, if the view is locked on one.
      const liveTarget = flags.current.target;
      const tgt = liveTarget ? project(liveTarget.lat, liveTarget.lon, cx, cy, r, spin) : null;
      if (tgt) {
        ctx.strokeStyle = 'rgba(255,255,255,0.85)';
        ctx.lineWidth = 1.2;
        ctx.beginPath();
        ctx.arc(tgt.x, tgt.y, 4.5, 0, Math.PI * 2);
        ctx.stroke();
        ctx.beginPath();
        ctx.moveTo(tgt.x - 9, tgt.y);
        ctx.lineTo(tgt.x + 9, tgt.y);
        ctx.moveTo(tgt.x, tgt.y - 9);
        ctx.lineTo(tgt.x, tgt.y + 9);
        ctx.stroke();
      }

      // Threat origins: pulsing radar rings plus a ballistic arc to the station.
      for (let i = 0; i < list.length; i++) {
        const o = list[i];
        const c = CENTROIDS[o.code] ?? (o.lat != null && o.lon != null ? [o.lat, o.lon] : null);
        if (!c) continue;
        const p = project(c[0], c[1], cx, cy, r, spin);
        if (!p) continue;

        const weight = 0.35 + (o.count / maxCount) * 0.65;
        const phase = reducedMotion ? 0.5 : (t * 0.9 + i * 0.37) % 1;

        // Expanding rings, fading as they grow.
        for (let k = 0; k < 2; k++) {
          const ph = (phase + k * 0.5) % 1;
          const rad = 3 + ph * (12 + weight * 16);
          ctx.strokeStyle = `rgba(239,68,68,${(1 - ph) * 0.55 * weight})`;
          ctx.lineWidth = 1.1;
          ctx.beginPath();
          ctx.arc(p.x, p.y, rad, 0, Math.PI * 2);
          ctx.stroke();
        }

        // The source itself.
        ctx.fillStyle = `rgba(239,68,68,${0.65 + weight * 0.35})`;
        ctx.beginPath();
        ctx.arc(p.x, p.y, 2 + weight * 2, 0, Math.PI * 2);
        ctx.fill();

        // Ballistic arc toward the station, bowed outward from the surface.
        if (tgt && flags.current.showArcs) {
          const mx = (p.x + tgt.x) / 2;
          const my = (p.y + tgt.y) / 2;
          const dx = mx - cx;
          const dy = my - cy;
          const d = Math.max(1, Math.hypot(dx, dy));
          const lift = 26 + weight * 34;
          const ax = mx + (dx / d) * lift;
          const ay = my + (dy / d) * lift;

          const grad = ctx.createLinearGradient(p.x, p.y, tgt.x, tgt.y);
          grad.addColorStop(0, `rgba(239,68,68,${0.5 * weight})`);
          grad.addColorStop(0.75, 'rgba(255,255,255,0.32)');
          grad.addColorStop(1, 'rgba(255,255,255,0.08)');
          ctx.strokeStyle = grad;
          ctx.lineWidth = 0.9 + weight;
          ctx.beginPath();
          ctx.moveTo(p.x, p.y);
          ctx.quadraticCurveTo(ax, ay, tgt.x, tgt.y);
          ctx.stroke();

          // A travelling pulse along the arc, so the direction of attack reads.
          if (!reducedMotion) {
            const u = (t * 0.45 + i * 0.29) % 1;
            const qx = (1 - u) * (1 - u) * p.x + 2 * (1 - u) * u * ax + u * u * tgt.x;
            const qy = (1 - u) * (1 - u) * p.y + 2 * (1 - u) * u * ay + u * u * tgt.y;
            ctx.fillStyle = 'rgba(255,255,255,0.9)';
            ctx.beginPath();
            ctx.arc(qx, qy, 1.6, 0, Math.PI * 2);
            ctx.fill();
          }
        }
      }

      raf.current = requestAnimationFrame(draw);
    };

    raf.current = requestAnimationFrame(draw);
    return () => {
      if (raf.current) cancelAnimationFrame(raf.current);
      ro.disconnect();
    };
    // `target` and the display flags are read through `flags`, so they are absent
    // here on purpose: including them would rebuild the loop on every toggle.
  }, [height, reducedMotion]);

  return (
    <canvas
      ref={ref}
      className={className}
      role="img"
      aria-label={
        origins.length
          ? `Orbital threat view: ${origins.length} origin countries, highest volume ${origins[0]?.country ?? ''}`
          : 'Orbital threat view: no threat origins reported'
      }
    />
  );
};
