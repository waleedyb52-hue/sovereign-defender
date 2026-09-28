import React from 'react';
import * as THREE from 'three';
import { OrbitControls } from 'three/addons/controls/OrbitControls.js';
import { CSS2DRenderer, CSS2DObject } from 'three/addons/renderers/CSS2DRenderer.js';
import { useReducedMotion } from 'motion/react';
import type { AssetRow } from './useAssets';
import { inCidr } from './NetworkTopologyView';

/**
 * HOLOGRAPHIC TOPOLOGY — the same network as the 2D graph, in three tiers of depth.
 *
 *   top      enrolled hosts: the vantage points doing the observing
 *   middle   their local segments
 *   bottom   devices seen on each segment (ARP, sweep)
 *
 * Position is relationship, as in 2D; height only separates the tiers so they can be
 * read at an angle. Nothing is placed that no sensor reported.
 *
 * PARTICLES ARE MEASUREMENTS, not decoration, and that is why most paths have none:
 *   crimson  on the path of a device that sent HIGH/CRITICAL alerts in the last ten
 *            minutes, one particle per alert (capped at eight), flowing inward;
 *   cyan     on a host's segment spokes, scaled to the established connections its
 *            sensor measured (log scale). A host whose sensor could not count sends none.
 * Per-device traffic is not measured, so device links carry no flow; the legend says so.
 *
 * Under reduced motion the camera stops turning and particles hold still where they are.
 * The render loop sleeps while the tab is hidden. WebGL failure falls back to a message.
 */

export interface Topology3DProps {
  assets: AssetRow[];
  /** ip → reason, the same map that turns 2D paths crimson. */
  hot: ReadonlyMap<string, string>;
  /** ip → HIGH/CRITICAL alerts from it in the last ten minutes. */
  alertCounts: ReadonlyMap<string, number>;
  /** mac → LAN-watch state. */
  lanStates?: ReadonlyMap<string, 'NEW' | 'BASELINE' | 'APPROVED'>;
  isAr: boolean;
  onSelectIp?: (ip: string) => void;
  /**
   * Where the legend sits. In the cockpit the theatre runs under the HUD columns, so the
   * default corner is hidden; the cockpit places it in the visible centre instead.
   */
  legendClassName?: string;
  className?: string;
}

const C = {
  vantage: 0x22d3ee,
  stale: 0xfbbf24,
  hot: 0xf43f5e,
  segment: 0x0891b2,
  open: 0xfbbf24,
  fresh: 0xfbbf24,
  filtering: 0x0e7490,
  unswept: 0x64748b
};

interface NodeSpec {
  id: string;
  kind: 'VANTAGE' | 'SEGMENT' | 'DEVICE';
  pos: THREE.Vector3;
  color: number;
  label: string;
  sub: string | null;
  ip: string | null;
  hot: boolean;
  isNew: boolean;
  alwaysLabel: boolean;
}

interface EdgeSpec {
  from: string;
  to: string;
  color: number;
  hot: boolean;
  /** Particles and their direction: 'in' toward the vantage, 'both' for host traffic. */
  flow: { count: number; color: number; dir: 'in' | 'both' } | null;
}

function buildGraph(p: Topology3DProps): { nodes: NodeSpec[]; edges: EdgeSpec[] } {
  const nodes: NodeSpec[] = [];
  const edges: EdgeSpec[] = [];
  const hosts = p.assets.filter(a => a.kind === 'HOST');

  hosts.forEach((h, hi) => {
    const va = hosts.length === 1 ? 0 : (hi / hosts.length) * Math.PI * 2;
    const vr = hosts.length === 1 ? 0 : 36;
    const vid = `v:${h.id}`;
    const hostHot = Boolean(h.primaryIp && p.hot.has(h.primaryIp)) || h.isolated;
    nodes.push({
      id: vid,
      kind: 'VANTAGE',
      pos: new THREE.Vector3(Math.cos(va) * vr, 46, Math.sin(va) * vr),
      color: hostHot ? C.hot : h.liveness === 'ONLINE' ? C.vantage : C.stale,
      label: h.label,
      sub: h.primaryIp,
      ip: h.primaryIp,
      hot: hostHot,
      isNew: false,
      alwaysLabel: true
    });

    const segments = h.posture?.segments ?? [];
    const neighbours = h.posture?.neighbours ?? [];
    const populated = segments.filter(s => neighbours.some(n => inCidr(n.ip, s.cidr)));
    const segs = populated.length > 0 ? populated : segments.slice(0, 3);
    const established = h.posture?.establishedConnections;
    // Host activity, log-scaled: 1 conn -> 1, 7 -> 3, 63 -> 6. Unknown -> none.
    const hostParticles = established == null ? 0 : Math.min(6, Math.round(Math.log2(established + 1)));
    const perSpoke = segs.length ? Math.ceil(hostParticles / segs.length) : 0;

    const total = Math.max(1, segs.reduce((s, x) => s + Math.max(1, neighbours.filter(n => inCidr(n.ip, x.cidr)).length), 0));
    let before = 0;
    segs.forEach(seg => {
      const mine = neighbours.filter(n => inCidr(n.ip, seg.cidr));
      const share = Math.max(1, mine.length);
      const span = (share / total) * Math.PI * 2;
      const start = (before / total) * Math.PI * 2 + hi * 0.4;
      before += share;
      const mid = start + span / 2;
      const sid = `s:${h.id}:${seg.cidr}`;
      const segHot = mine.some(n => p.hot.has(n.ip));
      nodes.push({
        id: sid,
        kind: 'SEGMENT',
        pos: new THREE.Vector3(Math.cos(mid) * 118, 8, Math.sin(mid) * 118),
        color: segHot ? C.hot : C.segment,
        label: seg.cidr,
        sub: seg.interface,
        ip: null,
        hot: segHot,
        isNew: false,
        alwaysLabel: true
      });
      edges.push({
        from: sid,
        to: vid,
        color: segHot ? C.hot : C.vantage,
        hot: segHot,
        flow: perSpoke > 0 ? { count: perSpoke, color: C.vantage, dir: 'both' } : null
      });

      mine.forEach((n, ni) => {
        const nid = `n:${n.ip}`;
        if (nodes.some(x => x.id === nid)) return;
        const t = mine.length === 1 ? 0.5 : ni / (mine.length - 1);
        const a = start + span * (0.12 + 0.76 * t);
        const r = 210 + (ni % 2) * 42;
        const ports = n.openPorts ?? [];
        const isHot = p.hot.has(n.ip);
        const isNew = p.lanStates?.get(n.mac.toLowerCase()) === 'NEW';
        const color = isHot ? C.hot : isNew ? C.fresh : ports.length ? C.open : n.sweepState === 'NO_RESPONSE' ? C.filtering : C.unswept;
        nodes.push({
          id: nid,
          kind: 'DEVICE',
          pos: new THREE.Vector3(Math.cos(a) * r, -30 - (ni % 3) * 6, Math.sin(a) * r),
          color,
          label: n.ip,
          sub: n.vendor ?? null,
          ip: n.ip,
          hot: isHot,
          isNew,
          alwaysLabel: isHot || isNew
        });
        const alerts = p.alertCounts.get(n.ip) ?? 0;
        edges.push({
          from: nid,
          to: sid,
          color: isHot ? C.hot : color,
          hot: isHot,
          flow: isHot && alerts > 0 ? { count: Math.min(8, alerts), color: C.hot, dir: 'in' } : null
        });
      });
    });
  });
  return { nodes, edges };
}

/** A soft round glow, drawn once and shared by every sprite. */
function glowTexture(): THREE.Texture {
  const c = document.createElement('canvas');
  c.width = c.height = 64;
  const g = c.getContext('2d')!;
  const grad = g.createRadialGradient(32, 32, 0, 32, 32, 32);
  grad.addColorStop(0, 'rgba(255,255,255,1)');
  grad.addColorStop(0.25, 'rgba(255,255,255,0.55)');
  grad.addColorStop(1, 'rgba(255,255,255,0)');
  g.fillStyle = grad;
  g.fillRect(0, 0, 64, 64);
  const tex = new THREE.CanvasTexture(c);
  tex.colorSpace = THREE.SRGBColorSpace;
  return tex;
}

interface Particle {
  sprite: THREE.Sprite;
  curve: THREE.QuadraticBezierCurve3;
  t: number;
  speed: number;
  reverse: boolean;
}

export const NetworkTopology3D: React.FC<Topology3DProps> = props => {
  const { isAr, className, legendClassName = 'start-2 bottom-2' } = props;
  const reduce = useReducedMotion() ?? false;
  const mountRef = React.useRef<HTMLDivElement>(null);
  const propsRef = React.useRef(props);
  propsRef.current = props;
  const [failed, setFailed] = React.useState<string | null>(null);
  const [hover, setHover] = React.useState<{ label: string; sub: string | null; x: number; y: number } | null>(null);

  const world = React.useRef<{
    renderer: THREE.WebGLRenderer;
    labels: CSS2DRenderer;
    scene: THREE.Scene;
    camera: THREE.PerspectiveCamera;
    controls: OrbitControls;
    graph: THREE.Group;
    glow: THREE.Texture;
    particles: Particle[];
    pickables: THREE.Object3D[];
  } | null>(null);

  const graph = React.useMemo(() => buildGraph(props), [props.assets, props.hot, props.alertCounts, props.lanStates]);
  // Rebuild the scene only when the structure or its colours change, not on every poll.
  const signature = React.useMemo(
    () => JSON.stringify([graph.nodes.map(n => [n.id, n.color, n.alwaysLabel]), graph.edges.map(e => [e.from, e.to, e.color, e.flow?.count ?? 0])]),
    [graph]
  );

  /* ── One-time world ────────────────────────────────────────────────────── */
  React.useEffect(() => {
    const mount = mountRef.current;
    if (!mount) return;
    let renderer: THREE.WebGLRenderer;
    try {
      renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true, powerPreference: 'high-performance' });
    } catch (err) {
      setFailed(err instanceof Error ? err.message : 'WebGL unavailable');
      return;
    }
    renderer.setPixelRatio(Math.min(2, window.devicePixelRatio || 1));
    renderer.setClearColor(0x000000, 0);
    mount.appendChild(renderer.domElement);

    const labels = new CSS2DRenderer();
    labels.domElement.style.position = 'absolute';
    labels.domElement.style.inset = '0';
    labels.domElement.style.pointerEvents = 'none';
    mount.appendChild(labels.domElement);

    const scene = new THREE.Scene();
    scene.fog = new THREE.Fog(0x000000, 420, 900);
    const camera = new THREE.PerspectiveCamera(42, 1, 1, 2000);
    camera.position.set(0, 260, 420);

    const controls = new OrbitControls(camera, renderer.domElement);
    controls.enableDamping = true;
    controls.dampingFactor = 0.08;
    controls.minDistance = 160;
    controls.maxDistance = 820;
    controls.maxPolarAngle = Math.PI * 0.49;
    controls.autoRotate = !reduce;
    controls.autoRotateSpeed = 0.35;
    // Stop turning once the operator takes the camera; they are looking at something.
    controls.addEventListener('start', () => (controls.autoRotate = false));

    // Floor: polar grid and tier rings, faint.
    const floor = new THREE.PolarGridHelper(320, 12, 6, 64, 0x0e7490, 0x0b3440);
    (floor.material as THREE.Material).transparent = true;
    (floor.material as THREE.Material).opacity = 0.35;
    floor.position.y = -60;
    scene.add(floor);

    const graphGroup = new THREE.Group();
    scene.add(graphGroup);

    world.current = { renderer, labels, scene, camera, controls, graph: graphGroup, glow: glowTexture(), particles: [], pickables: [] };

    const resize = () => {
      const w = mount.clientWidth || 1;
      const h = mount.clientHeight || 1;
      renderer.setSize(w, h, false);
      renderer.domElement.style.width = '100%';
      renderer.domElement.style.height = '100%';
      labels.setSize(w, h);
      camera.aspect = w / h;
      camera.updateProjectionMatrix();
    };
    const ro = new ResizeObserver(resize);
    ro.observe(mount);
    resize();

    // Picking: a click (not a drag) on a device or host opens its dossier.
    const ray = new THREE.Raycaster();
    const ndc = new THREE.Vector2();
    let down: { x: number; y: number } | null = null;
    const toNdc = (e: PointerEvent) => {
      const r = renderer.domElement.getBoundingClientRect();
      ndc.set(((e.clientX - r.left) / r.width) * 2 - 1, -((e.clientY - r.top) / r.height) * 2 + 1);
      return r;
    };
    const onDown = (e: PointerEvent) => (down = { x: e.clientX, y: e.clientY });
    const onUp = (e: PointerEvent) => {
      if (!down || Math.hypot(e.clientX - down.x, e.clientY - down.y) > 5) return;
      toNdc(e);
      ray.setFromCamera(ndc, camera);
      const hit = ray.intersectObjects(world.current?.pickables ?? [], false)[0];
      const ip = hit?.object.userData.ip as string | undefined;
      if (ip) propsRef.current.onSelectIp?.(ip);
    };
    const onMove = (e: PointerEvent) => {
      const r = toNdc(e);
      ray.setFromCamera(ndc, camera);
      const hit = ray.intersectObjects(world.current?.pickables ?? [], false)[0];
      if (hit) {
        const d = hit.object.userData as { label: string; sub: string | null };
        setHover({ label: d.label, sub: d.sub, x: e.clientX - r.left, y: e.clientY - r.top });
        renderer.domElement.style.cursor = 'pointer';
      } else {
        setHover(null);
        renderer.domElement.style.cursor = 'grab';
      }
    };
    renderer.domElement.addEventListener('pointerdown', onDown);
    renderer.domElement.addEventListener('pointerup', onUp);
    renderer.domElement.addEventListener('pointermove', onMove);

    let raf = 0;
    let last = performance.now();
    const loop = (now: number) => {
      raf = requestAnimationFrame(loop);
      if (document.hidden) return;
      const dt = Math.min(0.05, (now - last) / 1000);
      last = now;
      const w = world.current;
      if (!w) return;
      w.controls.update();
      if (!reduce) {
        for (const p of w.particles) {
          p.t = (p.t + p.speed * dt) % 1;
          p.sprite.position.copy(p.curve.getPoint(p.reverse ? 1 - p.t : p.t));
        }
      }
      w.renderer.render(w.scene, w.camera);
      w.labels.render(w.scene, w.camera);
    };
    raf = requestAnimationFrame(loop);

    return () => {
      cancelAnimationFrame(raf);
      ro.disconnect();
      renderer.domElement.removeEventListener('pointerdown', onDown);
      renderer.domElement.removeEventListener('pointerup', onUp);
      renderer.domElement.removeEventListener('pointermove', onMove);
      controls.dispose();
      scene.traverse(o => {
        const m = o as THREE.Mesh;
        m.geometry?.dispose?.();
        const mat = m.material as THREE.Material | THREE.Material[] | undefined;
        if (Array.isArray(mat)) mat.forEach(x => x.dispose());
        else mat?.dispose?.();
      });
      world.current?.glow.dispose();
      renderer.dispose();
      mount.innerHTML = '';
      world.current = null;
    };
    // Created once per mount; `reduce` is read here and applies from the next mount.
  }, []);

  /* ── Graph content, rebuilt when the structure changes ─────────────────── */
  React.useEffect(() => {
    const w = world.current;
    if (!w) return;

    // Clear the previous graph, releasing GPU memory and label elements.
    for (const child of [...w.graph.children]) {
      child.traverse(o => {
        if (o instanceof CSS2DObject) o.element.remove();
        const m = o as THREE.Mesh;
        m.geometry?.dispose?.();
        // Disposing a material leaves its map alone, so the shared glow texture survives.
        (m.material as THREE.Material | undefined)?.dispose?.();
      });
      w.graph.remove(child);
    }
    w.particles = [];
    w.pickables = [];

    const byId = new Map(graph.nodes.map(n => [n.id, n]));

    const glowSprite = (color: number, size: number, opacity = 0.85) => {
      const s = new THREE.Sprite(new THREE.SpriteMaterial({ map: w.glow, color, transparent: true, opacity, depthWrite: false, blending: THREE.AdditiveBlending }));
      s.scale.set(size, size, 1);
      return s;
    };

    for (const n of graph.nodes) {
      const g = new THREE.Group();
      g.position.copy(n.pos);
      let core: THREE.Mesh;
      if (n.kind === 'VANTAGE') {
        core = new THREE.Mesh(new THREE.OctahedronGeometry(9, 0), new THREE.MeshBasicMaterial({ color: n.color, wireframe: true }));
        g.add(glowSprite(n.color, 64, 0.7));
        const ring = new THREE.Mesh(new THREE.RingGeometry(16, 17, 48), new THREE.MeshBasicMaterial({ color: n.color, transparent: true, opacity: 0.5, side: THREE.DoubleSide }));
        ring.rotation.x = -Math.PI / 2;
        g.add(ring);
      } else if (n.kind === 'SEGMENT') {
        core = new THREE.Mesh(new THREE.TorusGeometry(7, 1.3, 8, 32), new THREE.MeshBasicMaterial({ color: n.color }));
        core.rotation.x = -Math.PI / 2;
        g.add(glowSprite(n.color, 34, 0.55));
      } else {
        core = new THREE.Mesh(new THREE.SphereGeometry(n.hot ? 5.5 : 4.2, 16, 12), new THREE.MeshBasicMaterial({ color: n.color }));
        g.add(glowSprite(n.color, n.hot ? 40 : 22, n.hot ? 0.9 : 0.55));
        if (n.isNew) {
          const ring = new THREE.Mesh(new THREE.RingGeometry(8, 9, 32), new THREE.MeshBasicMaterial({ color: C.fresh, transparent: true, opacity: 0.8, side: THREE.DoubleSide }));
          ring.rotation.x = -Math.PI / 2;
          g.add(ring);
        }
      }
      core.userData = { ip: n.ip, label: n.label, sub: n.sub };
      g.add(core);
      if (n.ip) w.pickables.push(core);

      if (n.alwaysLabel) {
        const el = document.createElement('div');
        el.className = 'sd-3d-label';
        el.style.cssText = `font-family: var(--font-mono); font-size: ${n.kind === 'VANTAGE' ? 12 : 10}px; color: ${n.hot ? '#fecdd3' : '#cffafe'}; text-shadow: 0 0 8px ${n.hot ? 'rgba(244,63,94,.9)' : 'rgba(34,211,238,.8)'}; white-space: nowrap; transform: translateY(-18px); pointer-events: none;`;
        el.textContent = n.label + (n.isNew ? '  · NEW' : '');
        const lbl = new CSS2DObject(el);
        g.add(lbl);
      }
      w.graph.add(g);
    }

    for (const e of graph.edges) {
      const a = byId.get(e.from);
      const b = byId.get(e.to);
      if (!a || !b) continue;
      const mid = a.pos.clone().lerp(b.pos, 0.5);
      mid.y += 22;
      const curve = new THREE.QuadraticBezierCurve3(a.pos.clone(), mid, b.pos.clone());
      const line = new THREE.Line(
        new THREE.BufferGeometry().setFromPoints(curve.getPoints(28)),
        new THREE.LineBasicMaterial({ color: e.color, transparent: true, opacity: e.hot ? 0.95 : 0.35 })
      );
      w.graph.add(line);

      if (e.flow) {
        for (let i = 0; i < e.flow.count; i++) {
          const s = glowSprite(e.flow.color, e.flow.color === C.hot ? 9 : 7, 0.95);
          const t = i / e.flow.count;
          const reverse = e.flow.dir === 'both' && i % 2 === 1;
          s.position.copy(curve.getPoint(reverse ? 1 - t : t));
          w.graph.add(s);
          w.particles.push({ sprite: s, curve, t, speed: e.flow.color === C.hot ? 0.45 : 0.28, reverse });
        }
      }
    }
    // Keyed on the structural signature, not on `graph`, which is new on every poll.
  }, [signature]);

  const hosts = props.assets.filter(a => a.kind === 'HOST');

  return (
    <div className={`relative ${className ?? ''}`} dir="ltr">
      <div ref={mountRef} className="absolute inset-0" style={{ cursor: 'grab' }} />

      {failed && (
        <div className="absolute inset-0 grid place-items-center">
          <p className="border border-amber-500/40 bg-black/70 px-4 py-2 text-sm text-amber-200">
            {isAr ? 'العرض ثلاثي الأبعاد غير متاح في هذا المتصفح (WebGL). استخدم الرسم ثنائي الأبعاد.' : '3D view unavailable in this browser (WebGL). Use the 2D graph.'}
            <span className="mt-1 block font-mono text-[10px] text-amber-300/80">{failed}</span>
          </p>
        </div>
      )}

      {!failed && hosts.length === 0 && (
        <div className="absolute inset-0 grid place-items-center">
          <p className="text-sm text-slate-400">{isAr ? 'لا مضيف مسجّل بعد — شغّل الحسّاس على جهاز.' : 'No enrolled host yet — run the sensor on a machine.'}</p>
        </div>
      )}

      {hover && (
        <div
          className="pointer-events-none absolute z-10 border border-cyan-500/50 bg-[#030712]/90 px-2 py-1 font-mono text-[11px] text-cyan-100"
          style={{ left: hover.x + 14, top: hover.y + 10 }}
        >
          {hover.label}
          {hover.sub && <span className="block text-[10px] text-slate-400">{hover.sub}</span>}
          {props.onSelectIp && <span className="block text-[10px] text-cyan-400">{isAr ? 'انقر لفتح الملف' : 'click for dossier'}</span>}
        </div>
      )}

      {/* Legend: what the particles are, and what they are not. */}
      <div className={`pointer-events-none absolute max-w-[330px] border border-cyan-500/25 bg-[#030712]/80 px-2.5 py-2 backdrop-blur-xl ${legendClassName}`} dir={isAr ? 'rtl' : 'ltr'}>
        <p className="font-mono text-[10px] tracking-widest text-cyan-300">
          {isAr ? 'ثلاثي الأبعاد · الموضع = العلاقة' : '3D · POSITION = RELATIONSHIP'}
        </p>
        <p className="mt-1 text-[11px] leading-snug text-slate-300">
          <span className="text-rose-300">●</span>{' '}
          {isAr ? 'جسيمات حمراء: تنبيهات حرجة من الجهاز (آخر ١٠ دقائق)، واحدة لكل تنبيه.' : 'crimson particles: HIGH/CRITICAL alerts from the device (last 10 min), one per alert.'}
        </p>
        <p className="text-[11px] leading-snug text-slate-300">
          <span className="text-cyan-300">●</span>{' '}
          {isAr ? 'جسيمات سماوية: اتصالات المضيف القائمة كما قاسها حسّاسه.' : "cyan particles: the host's established connections, as its sensor measured."}
        </p>
        <p className="mt-0.5 text-[10px] leading-snug text-slate-400">
          {isAr
            ? 'حركة كل جهاز على حدة غير مُقاسة، فلا جسيمات على روابط الأجهزة. اسحب للتدوير، العجلة للتقريب.'
            : 'Per-device traffic is not measured, so device links carry none. Drag to orbit, wheel to zoom.'}
        </p>
      </div>
    </div>
  );
};

export default NetworkTopology3D;
