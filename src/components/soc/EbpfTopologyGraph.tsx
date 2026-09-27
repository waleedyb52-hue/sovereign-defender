import React from 'react';
import {
  ReactFlow,
  Background,
  Controls,
  BackgroundVariant,
  type Node,
  type Edge,
  type NodeProps,
  Handle,
  Position
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { Server, Crosshair, ShieldAlert, X, ArrowDownToLine, ArrowUpFromLine } from 'lucide-react';
import { Card, CardHeader, CardTitle, Badge, Button, Mono } from '../ui/primitives';
import { cn, formatBytes } from '../../lib/utils';
import type { ClusterNode } from '../../hooks/useTelemetry';

/**
 * eBPF SERVICE TOPOLOGY
 *
 * Nodes are the cluster members the server reports, and threat nodes are derived
 * from quarantined hosts. The layout is computed from the node list rather than
 * hardcoded, so the graph reflects the cluster instead of a picture of one.
 *
 * Where the honesty rule bites here
 *   Ingress/egress byte counters are only shown for nodes whose response
 *   actually carried them. `/api/v1/soc/ebpf/cluster-nodes` does not always
 *   include per-node byte counts, and inventing plausible traffic volumes for a
 *   network diagram would be among the more misleading things this console could
 *   do — an operator reads those numbers as evidence. Absent counters render as
 *   "not reported by this node", with the endpoint named.
 *
 * Edge semantics follow the spec: animated dashes for live traffic, solid
 * crimson for an installed XDP_DROP route. The distinction is also stated in
 * text on the side panel, because an animation is not an accessible signal.
 */

interface ThreatHost {
  ip: string;
  threatScore?: number | null;
  isolated?: boolean;
}

interface Props {
  nodes: ClusterNode[];
  threats?: ThreatHost[];
  lang?: 'ar' | 'en';
  onIsolate?: (ip: string) => void;
}

type SdNodeData = {
  label: string;
  ip: string;
  role?: string | null;
  kind: 'internal' | 'threat';
  isolated: boolean;
  threatScore?: number | null;
  ingressBytes?: number | null;
  egressBytes?: number | null;
  packetsDropped?: number | null;
};

/* ── Custom node ─────────────────────────────────────────────────────────── */

const SdNode: React.FC<NodeProps> = ({ data, selected }) => {
  const d = data as unknown as SdNodeData;
  const threat = d.kind === 'threat';

  return (
    <div
      className={cn(
        'min-w-[136px] rounded-md border px-2.5 py-2 backdrop-blur-sm transition-shadow',
        threat
          ? 'border-[#f43f5e]/55 bg-[#f43f5e]/8'
          : d.isolated
            ? 'border-[#F59E0B]/55 bg-[#F59E0B]/8'
            : 'border-[#22d3ee]/40 bg-[#0F1420]/90',
        selected && 'ring-2 ring-white/25'
      )}
      style={{
        boxShadow: threat
          ? '0 0 18px rgba(239,68,68,0.28)'
          : d.isolated
            ? '0 0 16px rgba(245,158,11,0.22)'
            : '0 0 16px rgba(56,189,248,0.16)'
      }}
    >
      <Handle
        type="target"
        position={Position.Left}
        className="!h-1.5 !w-1.5 !border-0 !bg-slate-600"
      />
      <Handle
        type="source"
        position={Position.Right}
        className="!h-1.5 !w-1.5 !border-0 !bg-slate-600"
      />

      <div className="mb-1 flex items-center gap-1.5">
        {threat ? (
          <Crosshair className="h-3 w-3 shrink-0 text-[#fda4af]" aria-hidden />
        ) : (
          <Server className="h-3 w-3 shrink-0 text-[#67e8f9]" aria-hidden />
        )}
        <span
          className="truncate text-[10px] font-medium text-slate-200"
          style={{ fontFamily: 'var(--font-sans)' }}
          title={d.label}
        >
          {d.label}
        </span>
      </div>
      <Mono className="block text-[9px] text-slate-500">{d.ip}</Mono>
      {d.isolated && (
        <span className="mt-1 inline-block text-[8px] tracking-wider text-[#fcd34d]">XDP_DROP</span>
      )}
    </div>
  );
};

const nodeTypes = { sd: SdNode };

/* ── Graph ───────────────────────────────────────────────────────────────── */

export const EbpfTopologyGraph: React.FC<Props> = ({
  nodes,
  threats = [],
  lang = 'ar',
  onIsolate
}) => {
  const isAr = lang === 'ar';
  const [selected, setSelected] = React.useState<SdNodeData | null>(null);

  const { rfNodes, rfEdges } = React.useMemo(() => {
    const isIsolated = (s?: string | null) =>
      Boolean(s && /ISOLAT|QUARANT|CONTAIN|BLACKHOL/i.test(s));

    // Internal nodes in a column; threats in a column facing them. Positions are
    // derived from the counts so the graph grows with the cluster.
    const internal: Node[] = nodes.map((n, i) => ({
      id: `int-${n.nodeIp}`,
      type: 'sd',
      position: { x: 300, y: i * 92 },
      data: {
        label: n.nodeName,
        ip: n.nodeIp,
        role: n.clusterRole,
        kind: 'internal',
        isolated: isIsolated(n.isolationStatus),
        ingressBytes: n.ingressBytes ?? null,
        egressBytes: n.egressBytes ?? null,
        packetsDropped: n.packetsDropped ?? null,
        threatScore: n.threatScore ?? null
      } satisfies SdNodeData as unknown as Record<string, unknown>
    }));

    const threatNodes: Node[] = threats.map((t, i) => ({
      id: `thr-${t.ip}`,
      type: 'sd',
      position: { x: 0, y: i * 92 + 20 },
      data: {
        label: isAr ? 'مصدر خارجي' : 'External source',
        ip: t.ip,
        kind: 'threat',
        isolated: Boolean(t.isolated),
        threatScore: t.threatScore ?? null
      } satisfies SdNodeData as unknown as Record<string, unknown>
    }));

    // Every threat is drawn against the ingress node when one is identifiable,
    // otherwise the first node. No edge is invented between internal nodes,
    // because the server does not report an internal service graph.
    const ingress =
      internal.find(n => /INGRESS|PROXY|EDGE/i.test(String((n.data as any).role ?? ''))) ??
      internal[0];

    const edges: Edge[] = [];
    if (ingress) {
      for (const t of threatNodes) {
        const blocked = (t.data as any).isolated as boolean;
        edges.push({
          id: `e-${t.id}`,
          source: t.id,
          target: ingress.id,
          animated: !blocked,
          style: blocked
            ? { stroke: '#f43f5e', strokeWidth: 1.8 }
            : { stroke: '#F59E0B', strokeWidth: 1.2, strokeDasharray: '4 3' },
          label: blocked ? 'XDP_DROP' : undefined,
          labelStyle: { fill: '#fda4af', fontSize: 9, fontFamily: 'var(--font-mono)' },
          labelBgStyle: { fill: '#0F1420', fillOpacity: 0.85 }
        });
      }
    }

    return { rfNodes: [...threatNodes, ...internal], rfEdges: edges };
  }, [nodes, threats, isAr]);

  const empty = rfNodes.length === 0;

  return (
    <Card className="overflow-hidden">
      <CardHeader>
        <CardTitle>{isAr ? 'خرائط مسارات النواة eBPF' : 'eBPF SERVICE TOPOLOGY'}</CardTitle>
        <div className="flex items-center gap-1.5">
          <Badge tone="ebpf" label={isAr ? `${nodes.length} عقدة` : `${nodes.length} nodes`} />
          {threats.length > 0 && (
            <Badge
              tone="quarantine"
              label={isAr ? `${threats.length} تهديد` : `${threats.length} threats`}
            />
          )}
        </div>
      </CardHeader>

      <div className="relative h-[380px] border-t border-slate-800/80" dir="ltr">
        {empty ? (
          <div className="flex h-full flex-col items-center justify-center gap-1.5 px-6 text-center">
            <ShieldAlert className="h-5 w-5 text-slate-700" aria-hidden />
            <p className="text-[11px] text-slate-500">
              {isAr ? 'لم تُرجِع الخدمة أي عقد.' : 'No nodes returned by the service.'}
            </p>
            <Mono className="text-[9px] text-slate-600">/api/v1/soc/ebpf/cluster-nodes</Mono>
          </div>
        ) : (
          <ReactFlow
            nodes={rfNodes}
            edges={rfEdges}
            nodeTypes={nodeTypes}
            fitView
            fitViewOptions={{ padding: 0.25 }}
            proOptions={{ hideAttribution: true }}
            onNodeClick={(_e, n) => setSelected(n.data as unknown as SdNodeData)}
            className="bg-[#080B11]"
          >
            <Background variant={BackgroundVariant.Dots} gap={18} size={1} color="#0e3a44" />
            <Controls
              showInteractive={false}
              className="!border !border-slate-800 !bg-[#0F1420]/90 [&>button]:!border-slate-800 [&>button]:!bg-transparent [&>button]:!fill-slate-400"
            />
          </ReactFlow>
        )}

        {/* Side panel: ingress/egress detail for the selected node. */}
        {selected && (
          <div
            className="absolute inset-y-0 right-0 w-64 border-l border-slate-800 bg-[#0F1420]/95 p-3 backdrop-blur-md"
            dir={isAr ? 'rtl' : 'ltr'}
          >
            <div className="mb-2.5 flex items-start justify-between gap-2">
              <div className="min-w-0">
                <p className="truncate text-[12px] font-semibold text-slate-200">
                  {selected.label}
                </p>
                <Mono className="text-[10px] text-slate-500">{selected.ip}</Mono>
              </div>
              <button
                onClick={() => setSelected(null)}
                aria-label={isAr ? 'إغلاق' : 'Close'}
                className="text-slate-500 transition-colors hover:text-slate-200"
              >
                <X className="h-3.5 w-3.5" />
              </button>
            </div>

            <div className="mb-3 flex flex-wrap gap-1">
              {selected.role && <Badge tone="neutral" label={selected.role} />}
              <Badge
                tone={selected.kind === 'threat' ? 'quarantine' : 'ebpf'}
                label={
                  selected.kind === 'threat'
                    ? isAr
                      ? 'مصدر خارجي'
                      : 'EXTERNAL'
                    : isAr
                      ? 'داخلي'
                      : 'INTERNAL'
                }
              />
              {selected.isolated && <Badge tone="tarpit" label="XDP_DROP" />}
            </div>

            <dl className="space-y-1.5">
              <Row
                icon={ArrowDownToLine}
                label={isAr ? 'بايتات واردة' : 'Ingress bytes'}
                value={selected.ingressBytes != null ? formatBytes(selected.ingressBytes) : null}
              />
              <Row
                icon={ArrowUpFromLine}
                label={isAr ? 'بايتات صادرة' : 'Egress bytes'}
                value={selected.egressBytes != null ? formatBytes(selected.egressBytes) : null}
              />
              <Row
                label={isAr ? 'حزم مُسقَطة' : 'Packets dropped'}
                value={selected.packetsDropped != null ? String(selected.packetsDropped) : null}
              />
              <Row
                label={isAr ? 'درجة الخطر' : 'Threat score'}
                value={selected.threatScore != null ? String(selected.threatScore) : null}
              />
            </dl>

            {(selected.ingressBytes == null || selected.egressBytes == null) && (
              <p className="mt-2 text-[9px] leading-relaxed text-slate-600">
                {isAr
                  ? 'الحقول الفارغة لم تُرد في استجابة الخدمة لهذه العقدة. لا تُعرض أرقام مُقدَّرة.'
                  : 'Empty fields were not returned for this node by the service. No estimated figures are shown.'}
              </p>
            )}

            {selected.kind === 'threat' && !selected.isolated && onIsolate && (
              <Button
                variant="danger"
                size="sm"
                className="mt-3 w-full"
                onClick={() => onIsolate(selected.ip)}
              >
                {isAr ? 'عزل هذا المصدر' : 'Isolate this source'}
              </Button>
            )}
          </div>
        )}
      </div>

      {/* Legend — the edge semantics in words, since animation is not accessible. */}
      <div className="flex flex-wrap items-center gap-3 border-t border-slate-800/80 px-4 py-2 text-[9px] text-slate-500">
        <span className="flex items-center gap-1.5">
          <svg width="18" height="4" aria-hidden>
            <line
              x1="0"
              y1="2"
              x2="18"
              y2="2"
              stroke="#F59E0B"
              strokeWidth="1.4"
              strokeDasharray="4 3"
            />
          </svg>
          {isAr ? 'مرور حيّ' : 'live traffic'}
        </span>
        <span className="flex items-center gap-1.5">
          <svg width="18" height="4" aria-hidden>
            <line x1="0" y1="2" x2="18" y2="2" stroke="#f43f5e" strokeWidth="2" />
          </svg>
          {isAr ? 'مسار محجوب في النواة (XDP_DROP)' : 'kernel-blocked route (XDP_DROP)'}
        </span>
        <span className="ms-auto">
          {isAr ? 'انقر عقدة لعرض التفاصيل' : 'click a node for detail'}
        </span>
      </div>
    </Card>
  );
};

const Row: React.FC<{ icon?: React.ElementType; label: string; value: string | null }> = ({
  icon: Icon,
  label,
  value
}) => (
  <div className="flex items-center justify-between gap-2">
    <dt className="flex items-center gap-1.5 text-[10px] text-slate-500">
      {Icon && <Icon className="h-3 w-3 shrink-0" aria-hidden />}
      {label}
    </dt>
    <dd className="text-[10px]">
      {value ? (
        <Mono className="text-slate-300">{value}</Mono>
      ) : (
        <span className="text-slate-600">—</span>
      )}
    </dd>
  </div>
);
