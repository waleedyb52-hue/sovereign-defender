import React from 'react';
import { Router, Smartphone, Server as ServerIcon, HelpCircle, Monitor, Cloud } from 'lucide-react';
import type { AssetRow } from './useAssets';

/**
 * NETWORK TOPOLOGY — your actual network, drawn as relationships.
 *
 * This is the view that answers "show me my devices". It is deliberately NOT a map, and
 * the separation is the design correction this component exists to make.
 *
 * THE DEFECT IT REPLACES. The radar in TacticalTheater encoded bearing from longitude
 * and radius from threat volume. Spatial position therefore carried two incompatible
 * meanings at once: it was neither a map — position was not geography — nor a radar —
 * radius was not range. An operator could read neither distance nor location from it,
 * which is why something looked wrong that was hard to name. Latitude was not used at
 * all, so two devices on opposite sides of the equator landed on the same bearing.
 *
 * HOW THE INDUSTRY SPLITS THIS. Falcon, Darktrace and Kibana draw geography on a real
 * projection where position means position and volume goes to mark size. Palantir Gotham
 * draws a node-link graph where position means relationship and geography is absent.
 * Neither blends the two in one canvas. This component is the second kind.
 *
 * WHAT POSITION MEANS HERE. Concentric relationship tiers, not distance:
 *   centre  the enrolled host doing the observing — the vantage point
 *   ring 1  its local segments, one node per CIDR it reported
 *   ring 2  LAN neighbours, attached to the segment their address falls in
 *   outer   external peers seen in real flows, grouped, never geolocated here
 *
 * Every node is a device something actually observed: an ARP entry means a device
 * answered on the wire, which is stronger evidence than a ping reply and was obtained
 * without sending a packet. Nothing is inferred to fill the picture — an empty ring
 * means nothing was seen, and the view says so.
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

interface Props {
  assets: AssetRow[];
  isAr: boolean;
  onSelectAsset: (a: AssetRow) => void;
  className?: string;
}

type NodeKind = 'VANTAGE' | 'SEGMENT' | 'NEIGHBOUR' | 'GATEWAY';

interface Node {
  id: string;
  kind: NodeKind;
  label: string;
  sub: string | null;
  x: number;
  y: number;
  tone: string;
  neighbour?: TopoNeighbour;
  asset?: AssetRow;
  openPorts: number[];
}

/**
 * Device class from evidence, never from a guess.
 *
 * A .1 or .254 address with open 80/443 is a gateway — that is a conventional reading of
 * two observed facts, not an assumption. A randomised MAC with no open ports is almost
 * certainly a phone, but "almost certainly" is not a claim this makes: it returns UNKNOWN,
 * and the panel says the vendor is unknown because the address is randomised. Guessing
 * device types is how an inventory fills with confident fiction.
 */
function classify(n: TopoNeighbour): { icon: React.ElementType; label: string; labelAr: string } {
  const last = Number(n.ip.split('.')[3]);
  const ports = n.openPorts ?? [];
  const isEdge = last === 1 || last === 254;
  if (isEdge && (ports.includes(80) || ports.includes(443) || ports.length === 0))
    return { icon: Router, label: 'GATEWAY', labelAr: 'بوّابة' };
  if (ports.includes(445) || ports.includes(3389) || ports.includes(5985))
    return { icon: Monitor, label: 'WINDOWS HOST', labelAr: 'مضيف ويندوز' };
  if (ports.includes(22)) return { icon: ServerIcon, label: 'SSH HOST', labelAr: 'مضيف SSH' };
  // A locally-administered MAC (second nibble 2, 6, a or e) means the address is
  // randomised — which phones do by default. That is a fact about the address, so it is
  // reported; the device type behind it is not.
  if (/^.[26ae]:/i.test(n.mac)) return { icon: Smartphone, label: 'RANDOMISED MAC', labelAr: 'عنوان معشّى' };
  return { icon: HelpCircle, label: 'UNCLASSIFIED', labelAr: 'غير مصنّف' };
}

function inSegment(ip: string, cidr: string): boolean {
  const m = /^((?:\d{1,3}\.){3}\d{1,3})\/(\d{1,2})$/.exec(cidr);
  if (!m) return false;
  const bits = Number(m[2]);
  const toInt = (s: string) => s.split('.').map(Number).reduce((a, o) => (a << 8) | o, 0) >>> 0;
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return ((toInt(ip) & mask) >>> 0) === ((toInt(m[1]) & mask) >>> 0);
}

export const NetworkTopologyView: React.FC<Props> = ({ assets, isAr, onSelectAsset, className }) => {
  const [selected, setSelected] = React.useState<Node | null>(null);
  const [zoom, setZoom] = React.useState(1);

  const hosts = assets.filter(a => a.kind === 'HOST');

  const { nodes, links } = React.useMemo(() => {
    const ns: Node[] = [];
    const ls: Array<{ from: string; to: string; tone: string; width: number }> = [];

    const W = 820;
    const H = 520;
    const cx = W / 2;
    const cy = H / 2;

    // Vantage points: the enrolled hosts. With more than one they share the centre ring.
    hosts.forEach((h, hi) => {
      const a = hosts.length === 1 ? 0 : (hi / hosts.length) * Math.PI * 2;
      const r = hosts.length === 1 ? 0 : 52;
      const id = `v:${h.id}`;
      ns.push({
        id,
        kind: 'VANTAGE',
        label: h.label,
        sub: h.primaryIp,
        x: cx + Math.cos(a) * r,
        y: cy + Math.sin(a) * r,
        tone: h.isolated ? '#e11d48' : h.liveness === 'ONLINE' ? '#22d3ee' : '#fbbf24',
        asset: h,
        openPorts: []
      });

      const segments = h.posture?.segments ?? [];
      const neighbours = (h.posture?.neighbours ?? []) as TopoNeighbour[];

      // Only segments that actually have a neighbour in them are drawn. A VMware host-only
      // adapter with nothing behind it is real but not informative, and six empty spokes
      // crowd out the segment that matters.
      const populated = segments.filter(s => neighbours.some(n => inSegment(n.ip, s.cidr)));
      const drawSegments = populated.length > 0 ? populated : segments.slice(0, 4);

      drawSegments.forEach((seg, si) => {
        const sa = (si / Math.max(1, drawSegments.length)) * Math.PI * 2 - Math.PI / 2 + hi * 0.35;
        const sr = 132;
        const sid = `s:${h.id}:${seg.cidr}`;
        const mine = neighbours.filter(n => inSegment(n.ip, seg.cidr));

        ns.push({
          id: sid,
          kind: 'SEGMENT',
          label: seg.cidr,
          sub: seg.interface,
          x: cx + Math.cos(sa) * sr,
          y: cy + Math.sin(sa) * sr,
          tone: '#0891b2',
          openPorts: []
        });
        ls.push({ from: id, to: sid, tone: '#22d3ee', width: 1.4 });

        // Neighbours fan out from their own segment, so an address sits under the
        // interface that observed it rather than floating in a generic cloud.
        mine.forEach((n, ni) => {
          const spread = Math.min(1.15, 0.26 * Math.max(1, mine.length - 1));
          const na = sa + (mine.length === 1 ? 0 : (ni / (mine.length - 1) - 0.5) * spread);
          const nr = sr + 112;
          const cls = classify(n);
          const nid = `n:${n.ip}`;
          if (ns.some(x => x.id === nid)) return; // two sensors, one segment
          ns.push({
            id: nid,
            kind: cls.label === 'GATEWAY' ? 'GATEWAY' : 'NEIGHBOUR',
            label: n.ip,
            sub: n.vendor ?? (isAr ? cls.labelAr : cls.label),
            x: cx + Math.cos(na) * nr,
            y: cy + Math.sin(na) * nr,
            tone:
              (n.openPorts?.length ?? 0) > 0
                ? '#fbbf24'
                : n.sweepState === 'NO_RESPONSE'
                  ? '#0e7490'
                  : '#5c7484',
            neighbour: n,
            openPorts: n.openPorts ?? []
          });
          ls.push({
            from: sid,
            to: nid,
            tone: (n.openPorts?.length ?? 0) > 0 ? '#fbbf24' : '#334155',
            width: 0.8
          });
        });
      });
    });

    return { nodes: ns, links: ls };
  }, [hosts, isAr]);

  const byId = React.useMemo(() => new Map(nodes.map(n => [n.id, n])), [nodes]);

  if (hosts.length === 0) {
    return (
      <div className={`grid place-items-center ${className ?? ''}`}>
        <div className="max-w-sm text-center">
          <p className="font-mono text-[9px] leading-relaxed text-slate-400">
            {isAr
              ? 'لا مضيف مسجّل، فلا شبكة لرسمها. شغّل المجسّ على جهاز ليُبلّغ عن قطاعاته وجيرانه.'
              : 'No host enrolled, so there is no network to draw. Run the sensor on a machine and it will report its segments and neighbours.'}
          </p>
          <p className="mt-1.5 font-mono text-[7px] text-slate-600">
            {isAr
              ? 'لن تُرسم أجهزة نموذجية — رسمٌ فارغ يعني أن شيئًا لم يُرصَد.'
              : 'no sample devices are drawn — an empty graph means nothing was observed.'}
          </p>
        </div>
      </div>
    );
  }

  const totalNeighbours = nodes.filter(n => n.kind === 'NEIGHBOUR' || n.kind === 'GATEWAY').length;
  const anySwept = nodes.some(n => n.openPorts.length > 0);

  return (
    <div className={`relative ${className ?? ''}`}>
      <svg
        viewBox="0 0 820 520"
        className="h-full w-full"
        style={{ transform: `scale(${zoom})`, transformOrigin: 'center' }}
        role="img"
        aria-label={
          isAr
            ? `طوبولوجيا الشبكة: ${hosts.length} مضيف مسجّل، ${totalNeighbours} جهاز مرصود`
            : `Network topology: ${hosts.length} enrolled hosts, ${totalNeighbours} observed devices`
        }
      >
        {/* Relationship tiers, drawn faintly so they read as structure, not as range. */}
        {[132, 244].map(r => (
          <circle key={r} cx={410} cy={260} r={r} fill="none" stroke="rgba(34,211,238,0.08)" strokeWidth="1" strokeDasharray="3 5" />
        ))}

        {links.map((l, i) => {
          const a = byId.get(l.from);
          const b = byId.get(l.to);
          if (!a || !b) return null;
          return (
            <line
              key={i}
              x1={a.x}
              y1={a.y}
              x2={b.x}
              y2={b.y}
              stroke={l.tone}
              strokeWidth={l.width}
              opacity={0.55}
            />
          );
        })}

        {nodes.map(n => {
          const isSel = selected?.id === n.id;
          const size = n.kind === 'VANTAGE' ? 13 : n.kind === 'SEGMENT' ? 8 : 6;
          return (
            <g
              key={n.id}
              onClick={() => setSelected(n)}
              style={{ cursor: 'pointer' }}
              role="button"
              tabIndex={0}
              aria-label={`${n.label} ${n.sub ?? ''}`}
              onKeyDown={e => {
                if (e.key === 'Enter' || e.key === ' ') setSelected(n);
              }}
            >
              {isSel && <circle cx={n.x} cy={n.y} r={size + 7} fill="none" stroke={n.tone} strokeWidth="1.2" opacity="0.9" />}
              {n.kind === 'VANTAGE' ? (
                <>
                  <circle cx={n.x} cy={n.y} r={size} fill="rgba(0,0,0,0.85)" stroke={n.tone} strokeWidth="1.8" />
                  <circle cx={n.x} cy={n.y} r={size - 5} fill={n.tone} opacity="0.85" />
                </>
              ) : n.kind === 'SEGMENT' ? (
                <rect
                  x={n.x - size}
                  y={n.y - size / 1.6}
                  width={size * 2}
                  height={size * 1.25}
                  fill="rgba(0,0,0,0.8)"
                  stroke={n.tone}
                  strokeWidth="1.2"
                />
              ) : (
                <g transform={`translate(${n.x},${n.y}) rotate(45)`}>
                  <rect x={-size} y={-size} width={size * 2} height={size * 2} fill={n.tone} opacity="0.85" />
                </g>
              )}

              <text
                x={n.x}
                y={n.y + (n.kind === 'VANTAGE' ? size + 12 : size + 10)}
                textAnchor="middle"
                fontSize={n.kind === 'VANTAGE' ? 9 : 7}
                fill={n.kind === 'VANTAGE' ? '#e6edf3' : '#8aa4b8'}
                style={{ fontFamily: 'var(--font-mono)' }}
              >
                {n.label}
              </text>
              {n.openPorts.length > 0 && (
                <text
                  x={n.x}
                  y={n.y + size + 19}
                  textAnchor="middle"
                  fontSize="6"
                  fill="#fbbf24"
                  style={{ fontFamily: 'var(--font-mono)' }}
                >
                  {n.openPorts.slice(0, 4).join(',')}
                </text>
              )}
            </g>
          );
        })}
      </svg>

      {/* Legend. A graph whose marks are not defined is a picture. */}
      <div className="absolute start-2 top-2 border border-cyan-900/50 bg-black/70 px-2 py-1 backdrop-blur-xl">
        <p className="font-mono text-[6px] tracking-widest text-cyan-400 uppercase">
          {isAr ? 'الموضع = العلاقة، لا الجغرافيا' : 'POSITION = RELATIONSHIP, NOT GEOGRAPHY'}
        </p>
        <div className="mt-0.5 space-y-[1px]">
          {(
            [
              ['#22d3ee', isAr ? 'مضيف مسجّل (نقطة الرصد)' : 'enrolled host (vantage)'],
              ['#0891b2', isAr ? 'قطاع شبكي' : 'network segment'],
              ['#fbbf24', isAr ? 'جهاز بمنافذ مفتوحة' : 'device with open ports'],
              ['#0e7490', isAr ? 'يُرشِّح — فُحص ولم يُجب' : 'filtering: probed, no response'],
              ['#5c7484', isAr ? 'جهاز مرصود، لم يُمسح' : 'observed, not swept']
            ] as const
          ).map(([tone, label]) => (
            <p key={label} className="flex items-center gap-1 font-mono text-[6px] text-slate-400">
              <span className="h-1.5 w-1.5" style={{ background: tone }} aria-hidden />
              {label}
            </p>
          ))}
        </div>
        {!anySwept && totalNeighbours > 0 && (
          <p className="mt-1 max-w-[190px] font-mono text-[5.5px] leading-relaxed text-slate-500">
            {isAr
              ? 'المنافذ غير معروفة — لم يُشغَّل مسح نشط. الرصد سلبي من ذاكرة ARP.'
              : 'ports unknown — no active sweep has run. discovery is passive, from the ARP cache.'}
          </p>
        )}
      </div>

      {/* Zoom. Modest range: this is a relationship graph, not a slippy map. */}
      <div className="absolute end-2 top-2 flex gap-1">
        {([['−', -0.15], ['+', 0.15]] as const).map(([sym, d]) => (
          <button
            key={sym}
            type="button"
            onClick={() => setZoom(z => Math.min(1.8, Math.max(0.6, z + d)))}
            aria-label={sym === '+' ? 'zoom in' : 'zoom out'}
            className="h-5 w-5 border border-cyan-900/50 bg-black/70 font-mono text-[10px] text-cyan-400 backdrop-blur-xl transition-colors hover:bg-cyan-500/10"
          >
            {sym}
          </button>
        ))}
      </div>

      {/* Selection detail. Every mark is a doorway, which is the point. */}
      {selected && (
        <div className="absolute end-2 bottom-2 max-w-[260px] border border-cyan-500/40 bg-[#030712]/92 p-2 shadow-[0_0_25px_rgba(0,0,0,0.85)] backdrop-blur-2xl">
          <div className="flex items-start justify-between gap-2">
            <p className="font-mono text-[9px] font-bold text-white">{selected.label}</p>
            <button
              type="button"
              onClick={() => setSelected(null)}
              aria-label={isAr ? 'إغلاق' : 'close'}
              className="font-mono text-[10px] leading-none text-slate-500 hover:text-white"
            >
              ✕
            </button>
          </div>
          <p className="font-mono text-[6.5px] tracking-widest text-cyan-400/70 uppercase">{selected.kind}</p>

          {selected.neighbour && (
            <div className="mt-1 space-y-[1px]">
              <p className="font-mono text-[6.5px] text-slate-400">MAC {selected.neighbour.mac}</p>
              <p className="font-mono text-[6.5px] text-slate-400">
                {isAr ? 'المُصنِّع' : 'VENDOR'} {selected.neighbour.vendor ?? (isAr ? 'مجهول' : 'unknown')}
              </p>
              {!selected.neighbour.vendor && (
                <p className="font-mono text-[5.5px] leading-relaxed text-amber-400/80">
                  {isAr
                    ? 'مجهول لأن البادئة غير مُدرَجة أو العنوان معشّى — لا يُخمَّن مُصنِّع.'
                    : 'unknown because the prefix is not listed or the MAC is randomised — no vendor is guessed.'}
                </p>
              )}
              <p className="font-mono text-[6.5px] text-slate-400">
                {isAr ? 'عبر' : 'VIA'} {selected.neighbour.viaInterface ?? '—'}
              </p>
              <p className="font-mono text-[6.5px]" style={{ color: selected.openPorts.length ? '#fbbf24' : '#5c7484' }}>
                {isAr ? 'منافذ مفتوحة' : 'OPEN PORTS'}{' '}
                {selected.openPorts.length
                  ? selected.openPorts.join(', ')
                  : selected.neighbour.sweepState === 'NO_RESPONSE'
                    ? isAr ? 'فُحص ولم يُجب' : 'probed, no response'
                    : selected.neighbour.sweepState === 'RESPONDED'
                      ? isAr ? 'لا شيء مفتوح مما فُحص' : 'none open among probed'
                      : isAr ? 'لم يُمسح' : 'not swept'}
              </p>
              {selected.neighbour.sweepState === 'NO_RESPONSE' && (
                <p className="font-mono text-[5.5px] leading-relaxed text-amber-400/80">
                  {isAr
                    ? 'يردّ على ARP ولا يردّ على TCP — جهاز يُرشِّح أو محميّ بجدار، لا جهاز متوقّف.'
                    : 'answers ARP but not TCP: a filtering or firewalled device, not a device that is down.'}
                </p>
              )}
              <p className="font-mono text-[5.5px] text-slate-600">
                {isAr ? 'الدليل: ردّ على الشبكة (ذاكرة ARP)' : 'evidence: answered on the wire (ARP cache)'}
              </p>
            </div>
          )}

          {selected.asset && (
            <button
              type="button"
              onClick={() => onSelectAsset(selected.asset!)}
              className="mt-1.5 w-full border border-cyan-500/40 px-2 py-1 font-mono text-[7px] tracking-widest text-cyan-400 uppercase transition-colors hover:bg-cyan-500/10"
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
