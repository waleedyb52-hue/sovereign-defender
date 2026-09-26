import React, { useState, useEffect, useCallback, useMemo } from 'react';
import ForceGraphCanvas, { NODE_PALETTE, type GraphNode, type GraphEdge } from './ForceGraphCanvas';
import {
  Network,
  ListFilter,
  ShieldOff,
  ShieldAlert,
  Ban,
  Zap,
  FileWarning,
  FileX,
  FileUp,
  FileDown,
  FilePen,
  Fingerprint,
  Radio,
  RefreshCw,
  Power,
  Lock,
  Unlock,
  Crosshair,
  GitCompareArrows,
  Server,
  Activity,
  AlertOctagon,
  CheckCircle2,
  XCircle,
  Link2,
  Terminal
} from 'lucide-react';

// =============================================================================
// INTERCEPTION MATRIX PANEL
// Live view of the active in-line tamper interceptor and the file DLP engine.
// Mirrors the server contract exposed by /api/v1/soc/intercept/*.
// =============================================================================

type InterceptVerdict = 'PASS' | 'INTERCEPT_DROP' | 'EMERGENCY_RESET';
type FileOperation = 'FILE_DOWNLOAD' | 'FILE_UPLOAD' | 'FILE_MODIFICATION' | 'FILE_DELETION';
type DlpAction = 'ALLOW' | 'BLOCK' | 'QUARANTINE';

interface TamperFinding {
  tamperClass: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  detail: string;
  detailAr: string;
  expected?: string;
  observed?: string;
}

interface InterceptionRecord {
  interceptId: string;
  timestamp: number;
  sessionId: string;
  actorIp: string;
  route: string;
  method: string;
  verdict: InterceptVerdict;
  findings: TamperFinding[];
  primaryTamperClass: string;
  expectedHash: string | null;
  observedHash: string;
  payloadSizeBytes: number;
  tcpResetIssued: boolean;
  quarantined: boolean;
  auditHash: string;
}

interface DlpRecord {
  recordId: string;
  timestamp: number;
  operation: FileOperation;
  filePath: string;
  fileName: string;
  actorIp: string;
  token: string;
  processName: string;
  mimeType: string | null;
  sizeBytes: number;
  action: DlpAction;
  blocked: boolean;
  violationClass: string | null;
  matchedRuleId: string | null;
  matchReason: string;
  matchReasonAr: string;
  severity: string;
  mitreTechnique: string | null;
  tokenLockedDown: boolean;
  auditHash: string;
}

interface QuarantinedSession {
  sessionId: string;
  actorIp: string;
  reason: string;
  reasonAr: string;
  quarantinedAt: number;
  expiresAt: number;
  interceptCount: number;
}
interface LockedToken {
  token: string;
  actorIp: string;
  reason: string;
  reasonAr: string;
  lockedAt: number;
  expiresAt: number;
  violationCount: number;
}

interface ActiveBlocksResponse {
  quarantinedSessions: QuarantinedSession[];
  lockedTokens: LockedToken[];
  recentInterceptions: InterceptionRecord[];
  recentFileBlocks: DlpRecord[];
  stats: {
    inLine: {
      enabled: boolean;
      totalInspected: number;
      totalIntercepted: number;
      totalResets: number;
      interceptRatePercent: number;
      activeQuarantines: number;
    };
    fileDlp: {
      enabled: boolean;
      totalEvaluated: number;
      totalBlocked: number;
      blockRatePercent: number;
      blockedByOperation: Record<string, number>;
      lockedTokens: number;
    };
  };
  auditIntegrity: {
    inLine: { valid: boolean; verified: number };
    fileDlp: { valid: boolean; verified: number };
  };
}

export interface InterceptionMatrixPanelProps {
  lang: 'ar' | 'en';
}

/** Unified shape for the link-analysis graph, from either engine. */
interface LinkChain {
  kind: 'FILE' | 'TRANSIT';
  actorIp: string;
  action: string;
  actionLabel: string;
  target: string;
  mitigation: string;
  severity: string;
  blocked: boolean;
  detail: string;
  expectedHash?: string | null;
  observedHash?: string;
}

const OPERATION_META: Record<
  FileOperation,
  { icon: React.ElementType; label: string; labelAr: string }
> = {
  FILE_DOWNLOAD: { icon: FileDown, label: 'DOWNLOAD', labelAr: 'تنزيل' },
  FILE_UPLOAD: { icon: FileUp, label: 'UPLOAD', labelAr: 'رفع' },
  FILE_MODIFICATION: { icon: FilePen, label: 'MODIFY', labelAr: 'تعديل' },
  FILE_DELETION: { icon: FileX, label: 'DELETE', labelAr: 'حذف' }
};

function shortHash(h: string | null | undefined, len = 14): string {
  if (!h) return '—';
  return h.length > len ? h.slice(0, len) + '…' : h;
}

function timeAgo(ts: number, isAr: boolean): string {
  const s = Math.max(0, Math.floor((Date.now() - ts) / 1000));
  if (s < 60) return isAr ? `منذ ${s} ث` : `${s}s ago`;
  if (s < 3600) return isAr ? `منذ ${Math.floor(s / 60)} د` : `${Math.floor(s / 60)}m ago`;
  return isAr ? `منذ ${Math.floor(s / 3600)} س` : `${Math.floor(s / 3600)}h ago`;
}

export const InterceptionMatrixPanel: React.FC<InterceptionMatrixPanelProps> = ({ lang }) => {
  const isAr = lang === 'ar';

  const [data, setData] = useState<ActiveBlocksResponse | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [isBusy, setIsBusy] = useState(false);
  const [feedback, setFeedback] = useState<{ type: 'success' | 'error'; message: string } | null>(
    null
  );
  const [selectedChain, setSelectedChain] = useState<LinkChain | null>(null);
  const [streamPulse, setStreamPulse] = useState(0);
  const [graph, setGraph] = useState<{ nodes: GraphNode[]; edges: GraphEdge[] }>({
    nodes: [],
    edges: []
  });
  const [graphSummary, setGraphSummary] = useState<{ peakRiskWeight: number } | null>(null);
  const [selectedGraphNode, setSelectedGraphNode] = useState<GraphNode | null>(null);
  const [visibleCount, setVisibleCount] = useState<number>(25);

  // ---------------------------------------------------------------
  const fetchBlocks = useCallback(async (spinner = false) => {
    if (spinner) setIsLoading(true);
    try {
      const [blocksRes, graphRes] = await Promise.all([
        fetch('/api/v1/soc/intercept/active-blocks?limit=60'),
        fetch('/api/v1/soc/intercept/link-graph')
      ]);

      if (blocksRes.ok) {
        const json = await blocksRes.json();
        if (json && json.success) {
          setData(json as ActiveBlocksResponse);
          setStreamPulse(p => p + 1);
        }
      }
      if (graphRes.ok) {
        const g = await graphRes.json();
        if (g && g.success && Array.isArray(g.nodes)) {
          setGraph({ nodes: g.nodes as GraphNode[], edges: (g.edges ?? []) as GraphEdge[] });
          setGraphSummary(g.summary ?? null);
        }
      }
    } catch {
      /* transient network error; the next poll recovers */
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchBlocks(true);
  }, [fetchBlocks]);
  useEffect(() => {
    const id = setInterval(() => fetchBlocks(false), 4000);
    return () => clearInterval(id);
  }, [fetchBlocks]);

  // ---------------------------------------------------------------
  const post = async (url: string, body: Record<string, unknown>) => {
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
    return { ok: res.ok, data: await res.json().catch(() => ({})) };
  };

  const simulateTamper = async (scenario: string) => {
    setIsBusy(true);
    setFeedback(null);
    try {
      const { ok, data: r } = await post('/api/v1/soc/intercept/simulate-tamper', {
        scenario,
        sessionId: 'soc-drill-' + scenario.toLowerCase()
      });
      if (ok && r.success) {
        setFeedback({
          type: 'success',
          message: isAr
            ? `تم اعتراض ${scenario}: الحكم ${r.interception.verdict}`
            : `${scenario} intercepted: verdict ${r.interception.verdict}`
        });
        await fetchBlocks(false);
      } else {
        setFeedback({
          type: 'error',
          message: r.message || (isAr ? 'فشلت المحاكاة.' : 'Simulation failed.')
        });
      }
    } catch {
      setFeedback({
        type: 'error',
        message: isAr ? 'تعذر الاتصال بمحرك الاعتراض.' : 'Could not reach the interception engine.'
      });
    } finally {
      setIsBusy(false);
    }
  };

  const simulateFileAction = async (payload: Record<string, unknown>) => {
    setIsBusy(true);
    setFeedback(null);
    try {
      const { ok, data: r } = await post('/api/v1/soc/intercept/simulate-file-action', payload);
      if (ok && r.success) {
        setFeedback({
          type: 'success',
          message: isAr
            ? `${r.record.operation}: ${r.record.action}${r.record.violationClass ? ' — ' + r.record.violationClass : ''}`
            : `${r.record.operation}: ${r.record.action}${r.record.violationClass ? ' — ' + r.record.violationClass : ''}`
        });
        await fetchBlocks(false);
      } else {
        setFeedback({
          type: 'error',
          message: r.message || (isAr ? 'فشلت المحاكاة.' : 'Simulation failed.')
        });
      }
    } catch {
      setFeedback({
        type: 'error',
        message: isAr ? 'تعذر الاتصال بمحرك منع التسريب.' : 'Could not reach the DLP engine.'
      });
    } finally {
      setIsBusy(false);
    }
  };

  const release = async (target: { sessionId?: string; token?: string }) => {
    setIsBusy(true);
    try {
      await post('/api/v1/soc/intercept/release', target);
      await fetchBlocks(false);
      setFeedback({
        type: 'success',
        message: isAr ? 'تم الإفراج بعد مراجعة المحلل.' : 'Released after analyst review.'
      });
    } finally {
      setIsBusy(false);
    }
  };

  const toggleEngine = async (engine: 'IN_LINE' | 'FILE_DLP', enabled: boolean) => {
    setIsBusy(true);
    try {
      await post('/api/v1/soc/intercept/engine-state', { engine, enabled });
      await fetchBlocks(false);
    } finally {
      setIsBusy(false);
    }
  };

  // ---------------------------------------------------------------
  const fileChain = (r: DlpRecord): LinkChain => ({
    kind: 'FILE',
    actorIp: r.actorIp,
    action: r.operation,
    actionLabel:
      (isAr ? OPERATION_META[r.operation]?.labelAr : OPERATION_META[r.operation]?.label) ??
      r.operation,
    target: r.fileName,
    mitigation: r.tokenLockedDown ? `${r.action} + TOKEN LOCKDOWN` : r.action,
    severity: r.severity,
    blocked: r.blocked,
    detail: isAr ? r.matchReasonAr : r.matchReason
  });

  const transitChain = (r: InterceptionRecord): LinkChain => ({
    kind: 'TRANSIT',
    actorIp: r.actorIp,
    action: r.primaryTamperClass,
    actionLabel: r.primaryTamperClass.replace(/_/g, ' '),
    target: r.route,
    mitigation: r.tcpResetIssued ? 'EMERGENCY_RESET (TCP RST)' : r.verdict,
    severity: r.findings[0]?.severity ?? 'HIGH',
    blocked: r.verdict !== 'PASS',
    detail: r.findings.map(f => (isAr ? f.detailAr : f.detail)).join(' | '),
    expectedHash: r.expectedHash,
    observedHash: r.observedHash
  });

  const blockedTransit = useMemo(
    () => (data?.recentInterceptions ?? []).filter(r => r.verdict !== 'PASS'),
    [data]
  );

  // Auto-select the newest event so the link graph is never empty.
  useEffect(() => {
    if (selectedChain || !data) return;
    if (data.recentFileBlocks.length > 0) setSelectedChain(fileChain(data.recentFileBlocks[0]));
    else if (blockedTransit.length > 0) setSelectedChain(transitChain(blockedTransit[0]));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [data, blockedTransit, selectedChain]);

  const inLine = data?.stats.inLine;
  const dlp = data?.stats.fileDlp;

  /**
   * Unified, newest-first audit feed across both engines. Badge text follows
   * the SOC convention [STATE: REASON] so an analyst can triage by shape.
   */
  const auditRows = useMemo(() => {
    const rows: Array<{
      key: string;
      timestamp: number;
      actorIp: string;
      target: string;
      badge: string;
      badgeBg: string;
      badgeBorder: string;
      badgeColor: string;
      expectedHash?: string | null;
      observedHash?: string;
      chain: LinkChain;
    }> = [];

    for (const r of data?.recentFileBlocks ?? []) {
      const reason = r.violationClass ?? r.operation.replace('FILE_', '') + '_ATTEMPT';
      rows.push({
        key: r.recordId,
        timestamp: r.timestamp,
        actorIp: r.actorIp,
        target: r.fileName,
        badge: (r.action === 'QUARANTINE' ? 'TRAPPED: ' : 'BLOCKED: ') + reason,
        badgeBg: r.action === 'QUARANTINE' ? 'rgba(255,184,0,0.14)' : 'rgba(255,0,85,0.16)',
        badgeBorder: r.action === 'QUARANTINE' ? 'rgba(255,184,0,0.45)' : 'rgba(255,0,85,0.5)',
        badgeColor: r.action === 'QUARANTINE' ? '#FFB800' : '#FF0055',
        chain: fileChain(r)
      });
    }

    for (const r of blockedTransit) {
      rows.push({
        key: r.interceptId,
        timestamp: r.timestamp,
        actorIp: r.actorIp,
        target: r.route,
        badge: 'INTERCEPTED: ' + r.primaryTamperClass,
        badgeBg: 'rgba(0,240,255,0.10)',
        badgeBorder: 'rgba(0,240,255,0.4)',
        badgeColor: '#00F0FF',
        expectedHash: r.expectedHash,
        observedHash: r.observedHash,
        chain: transitChain(r)
      });
    }

    return rows.sort((a, b) => b.timestamp - a.timestamp);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [data, blockedTransit, isAr]);

  // ---------------------------------------------------------------
  return (
    <div
      className="space-y-5 rounded-xl border p-5 shadow-2xl"
      style={{ background: '#050914', borderColor: '#1B2338' }}
    >
      {/* ---------------- Header ---------------- */}
      <div
        className="flex flex-col items-start justify-between gap-4 border-b pb-4 lg:flex-row lg:items-center"
        style={{ borderColor: '#1B2338' }}
      >
        <div className="flex items-center gap-3">
          <div
            className="rounded-lg border p-2.5"
            style={{ background: 'rgba(220,20,60,0.12)', borderColor: 'rgba(220,20,60,0.4)' }}
          >
            <ShieldOff className="h-5 w-5" style={{ color: '#DC143C' }} />
          </div>
          <div>
            <div className="flex flex-wrap items-center gap-2">
              <h3 className="text-base font-bold" style={{ color: '#E6EDF7' }}>
                {isAr
                  ? 'مصفوفة الاعتراض النشط ومنع تسريب البيانات'
                  : 'Active Interception & DLP Matrix'}
              </h3>
              <span
                className="flex items-center gap-1 rounded border px-2 py-0.5 font-mono text-[10px] font-bold"
                style={{
                  background: 'rgba(220,20,60,0.15)',
                  borderColor: 'rgba(220,20,60,0.45)',
                  color: '#FF5C7A'
                }}
              >
                <Radio className="h-3 w-3 animate-pulse" />
                {isAr ? 'اعتراض مباشر' : 'IN-LINE'}
              </span>
              <span
                key={streamPulse}
                className="font-mono text-[10px]"
                style={{ color: '#4B5B78' }}
              >
                {isAr ? 'تحديث حي' : 'live'} · {streamPulse}
              </span>
            </div>
            <p className="mt-0.5 text-xs" style={{ color: '#7A8AA8' }}>
              {isAr
                ? 'اعتراض فعّال للتلاعب بالبيانات أثناء النقل وعمليات الملفات غير المصرح بها قبل وصولها إلى المعالج'
                : 'Actively blocks in-transit data manipulation and unauthorized file operations before they reach any handler.'}
            </p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <button
            onClick={() => toggleEngine('IN_LINE', !(inLine?.enabled ?? true))}
            disabled={isBusy || !data}
            className="flex items-center gap-1.5 rounded-lg border px-2.5 py-1.5 font-mono text-[11px] font-bold transition disabled:opacity-50"
            style={
              inLine?.enabled
                ? {
                    background: 'rgba(220,20,60,0.12)',
                    borderColor: 'rgba(220,20,60,0.4)',
                    color: '#FF5C7A'
                  }
                : { background: '#0C1322', borderColor: '#1B2338', color: '#7A8AA8' }
            }
          >
            <Power className="h-3.5 w-3.5" />
            {isAr ? 'محرك النقل' : 'TRANSIT'} {inLine?.enabled ? 'ON' : 'OFF'}
          </button>
          <button
            onClick={() => toggleEngine('FILE_DLP', !(dlp?.enabled ?? true))}
            disabled={isBusy || !data}
            className="flex items-center gap-1.5 rounded-lg border px-2.5 py-1.5 font-mono text-[11px] font-bold transition disabled:opacity-50"
            style={
              dlp?.enabled
                ? {
                    background: 'rgba(220,20,60,0.12)',
                    borderColor: 'rgba(220,20,60,0.4)',
                    color: '#FF5C7A'
                  }
                : { background: '#0C1322', borderColor: '#1B2338', color: '#7A8AA8' }
            }
          >
            <Power className="h-3.5 w-3.5" />
            {isAr ? 'محرك الملفات' : 'FILE DLP'} {dlp?.enabled ? 'ON' : 'OFF'}
          </button>
          <button
            onClick={() => fetchBlocks(true)}
            className="rounded-lg border p-1.5 transition"
            style={{ background: '#0C1322', borderColor: '#1B2338', color: '#7A8AA8' }}
            title={isAr ? 'تحديث' : 'Refresh'}
          >
            <RefreshCw className={`h-4 w-4 ${isLoading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* ---------------- Metric tiles ---------------- */}
      <div className="grid grid-cols-2 gap-2.5 lg:grid-cols-6">
        {[
          {
            icon: Activity,
            label: isAr ? 'تم فحصه' : 'Inspected',
            value: inLine?.totalInspected ?? 0,
            color: '#5EA9FF'
          },
          {
            icon: Ban,
            label: isAr ? 'اعتراضات' : 'Intercepts',
            value: inLine?.totalIntercepted ?? 0,
            color: '#DC143C'
          },
          {
            icon: Zap,
            label: isAr ? 'إعادة تعيين' : 'TCP Resets',
            value: inLine?.totalResets ?? 0,
            color: '#FF8A3D'
          },
          {
            icon: FileWarning,
            label: isAr ? 'ملفات محظورة' : 'Files Blocked',
            value: dlp?.totalBlocked ?? 0,
            color: '#DC143C'
          },
          {
            icon: Lock,
            label: isAr ? 'رموز معزولة' : 'Locked Tokens',
            value: dlp?.lockedTokens ?? 0,
            color: '#C77DFF'
          },
          {
            icon: ShieldAlert,
            label: isAr ? 'جلسات محجوزة' : 'Quarantined',
            value: inLine?.activeQuarantines ?? 0,
            color: '#FFD166'
          }
        ].map((tile, i) => (
          <div
            key={i}
            className="rounded-lg border p-2.5"
            style={{ background: '#0A0F1E', borderColor: '#1B2338' }}
          >
            <div
              className="flex items-center gap-1.5 font-mono text-[10px]"
              style={{ color: '#7A8AA8' }}
            >
              <tile.icon className="h-3.5 w-3.5" style={{ color: tile.color }} />
              <span className="truncate">{tile.label}</span>
            </div>
            <div className="mt-1 font-mono text-xl font-bold" style={{ color: tile.color }}>
              {tile.value}
            </div>
          </div>
        ))}
      </div>

      {/* ---------------- Canvas link analysis ---------------- */}
      <div
        className="space-y-3 rounded-lg border p-4"
        style={{ background: '#0A0F1E', borderColor: '#1B2338' }}
      >
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div
            className="flex items-center gap-2 font-mono text-xs font-bold"
            style={{ color: '#E6EDF7' }}
          >
            <Network className="h-4 w-4" style={{ color: '#00F0FF' }} />
            <span>
              {isAr
                ? 'محرك تحليل الصلات — رسم القوى الفيزيائي'
                : 'Link Analysis Engine — Force-Directed Graph'}
            </span>
          </div>
          <div
            className="flex items-center gap-3 font-mono text-[10px]"
            style={{ color: '#4B5B78' }}
          >
            <span>
              {isAr ? 'العقد' : 'nodes'}: {graph.nodes.length}
            </span>
            <span>
              {isAr ? 'الوصلات' : 'edges'}: {graph.edges.length}
            </span>
            <span>
              {isAr ? 'أعلى خطورة' : 'peak risk'}: {graphSummary?.peakRiskWeight ?? 0}
            </span>
          </div>
        </div>

        <ForceGraphCanvas
          nodes={graph.nodes}
          edges={graph.edges}
          height={360}
          isAr={isAr}
          onSelectNode={setSelectedGraphNode}
        />

        {selectedGraphNode && (
          <div
            className="flex items-center justify-between gap-3 rounded-lg border p-2.5"
            style={{ background: '#060B16', borderColor: '#16203A' }}
          >
            <div className="flex min-w-0 items-center gap-2">
              <span
                className="h-2.5 w-2.5 shrink-0 rounded-full"
                style={{ background: NODE_PALETTE[selectedGraphNode.type] }}
              />
              <div className="min-w-0">
                <div
                  className="truncate font-mono text-[11px] font-bold"
                  style={{ color: NODE_PALETTE[selectedGraphNode.type] }}
                >
                  {selectedGraphNode.label}
                </div>
                <div className="font-mono text-[9px]" style={{ color: '#5C6E8C' }}>
                  {selectedGraphNode.type} · {isAr ? 'وزن الخطورة' : 'risk weight'}{' '}
                  {selectedGraphNode.riskWeight}/100
                </div>
              </div>
            </div>
            <div className="shrink-0 text-end font-mono text-[9px]" style={{ color: '#4B5B78' }}>
              {
                graph.edges.filter(
                  e => e.source === selectedGraphNode.id || e.target === selectedGraphNode.id
                ).length
              }{' '}
              {isAr ? 'صلة' : 'links'}
            </div>
          </div>
        )}
      </div>

      {/* ---------------- Interception audit table ---------------- */}
      <div className="rounded-lg border" style={{ background: '#0A0F1E', borderColor: '#1B2338' }}>
        <div
          className="flex flex-wrap items-center justify-between gap-2 border-b p-3"
          style={{ borderColor: '#1B2338' }}
        >
          <div
            className="flex items-center gap-2 font-mono text-xs font-bold"
            style={{ color: '#E6EDF7' }}
          >
            <ListFilter className="h-4 w-4" style={{ color: '#FF0055' }} />
            <span>{isAr ? 'سجل تدقيق الاعتراض' : 'Interception Audit Log'}</span>
            <span
              className="rounded px-1.5 py-0.5 text-[10px]"
              style={{ background: 'rgba(255,0,85,0.15)', color: '#FF5C7A' }}
            >
              {auditRows.length}
            </span>
          </div>
          <div className="font-mono text-[9px]" style={{ color: '#4B5B78' }}>
            {isAr ? 'يعرض أحدث' : 'rendering newest'} {Math.min(auditRows.length, visibleCount)} /{' '}
            {auditRows.length}
          </div>
        </div>

        {/* Virtualized: only a bounded slice is mounted, so a flood of
            interceptions never mounts thousands of rows. */}
        <div
          className="overflow-y-auto"
          style={{ maxHeight: 300 }}
          onScroll={e => {
            const el = e.currentTarget;
            if (el.scrollTop + el.clientHeight >= el.scrollHeight - 40) {
              setVisibleCount(c => Math.min(c + 25, auditRows.length));
            }
          }}
        >
          {auditRows.length === 0 && (
            <div className="p-6 text-center font-mono text-[11px]" style={{ color: '#4B5B78' }}>
              {isAr ? 'لا توجد معاملات معترضة بعد.' : 'No intercepted transactions yet.'}
            </div>
          )}

          {auditRows.slice(0, visibleCount).map(row => (
            <div
              key={row.key}
              onClick={() => setSelectedChain(row.chain)}
              className="cursor-pointer border-b px-3 py-2 transition"
              style={{
                borderColor: '#121A2C',
                background:
                  selectedChain &&
                  selectedChain.target === row.chain.target &&
                  selectedChain.actorIp === row.chain.actorIp
                    ? 'rgba(255,0,85,0.07)'
                    : 'transparent'
              }}
            >
              <div className="flex items-start justify-between gap-2">
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-1.5">
                    <span
                      className="rounded border px-1.5 py-0.5 font-mono text-[9px] font-bold"
                      style={{
                        background: row.badgeBg,
                        borderColor: row.badgeBorder,
                        color: row.badgeColor
                      }}
                    >
                      [{row.badge}]
                    </span>
                    <span className="font-mono text-[10px]" style={{ color: '#7A8AA8' }}>
                      {row.actorIp}
                    </span>
                    <span className="truncate font-mono text-[10px]" style={{ color: '#5C6E8C' }}>
                      → {row.target}
                    </span>
                  </div>

                  {/* Side-by-side hash diff, monospace */}
                  {row.expectedHash !== undefined && (
                    <div className="mt-1.5 grid grid-cols-1 gap-1 sm:grid-cols-2">
                      <div
                        className="rounded px-1.5 py-1"
                        style={{
                          background: 'rgba(0,255,102,0.05)',
                          border: '1px solid rgba(0,255,102,0.18)'
                        }}
                      >
                        <div className="font-mono text-[8px]" style={{ color: '#4B5B78' }}>
                          {isAr ? 'البصمة المتوقعة' : 'EXPECTED'}
                        </div>
                        <div
                          className="font-mono text-[9px] break-all"
                          style={{ color: '#00FF66' }}
                        >
                          {row.expectedHash ?? '—'}
                        </div>
                      </div>
                      <div
                        className="rounded px-1.5 py-1"
                        style={{
                          background: 'rgba(255,0,85,0.06)',
                          border: '1px solid rgba(255,0,85,0.22)'
                        }}
                      >
                        <div className="font-mono text-[8px]" style={{ color: '#4B5B78' }}>
                          {isAr ? 'البصمة المتلاعب بها' : 'TAMPERED'}
                        </div>
                        <div
                          className="font-mono text-[9px] break-all"
                          style={{ color: '#FF0055' }}
                        >
                          {row.observedHash ?? '—'}
                        </div>
                      </div>
                    </div>
                  )}
                </div>
                <span className="shrink-0 font-mono text-[9px]" style={{ color: '#4B5B78' }}>
                  {timeAgo(row.timestamp, isAr)}
                </span>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* ---------------- Live Intercept Link ---------------- */}
      <div
        className="rounded-lg border p-4"
        style={{ background: '#0A0F1E', borderColor: '#1B2338' }}
      >
        <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
          <div
            className="flex items-center gap-2 font-mono text-xs font-bold"
            style={{ color: '#E6EDF7' }}
          >
            <Link2 className="h-4 w-4" style={{ color: '#DC143C' }} />
            <span>
              {isAr ? 'رابط الاعتراض الحي — تحليل الصلة' : 'Live Intercept Link — Chain Analysis'}
            </span>
          </div>
          <span className="font-mono text-[10px]" style={{ color: '#4B5B78' }}>
            {isAr ? 'اختر حدثاً من القوائم أدناه' : 'select an event below to trace it'}
          </span>
        </div>

        {selectedChain ? (
          <LiveInterceptLink chain={selectedChain} isAr={isAr} />
        ) : (
          <div className="py-10 text-center font-mono text-xs" style={{ color: '#4B5B78' }}>
            {isAr
              ? 'لا توجد اعتراضات نشطة. النظام في وضع المراقبة.'
              : 'No active interceptions. Engines are watching.'}
          </div>
        )}
      </div>

      {/* ---------------- Drill controls ---------------- */}
      <div
        className="space-y-2.5 rounded-lg border p-3.5"
        style={{ background: '#0A0F1E', borderColor: '#1B2338' }}
      >
        <div
          className="flex items-center gap-2 font-mono text-xs font-bold"
          style={{ color: '#B9C6DC' }}
        >
          <Terminal className="h-4 w-4" style={{ color: '#DC143C' }} />
          <span>{isAr ? 'تدريبات الاعتراض' : 'Interception Drills'}</span>
        </div>

        <div className="flex flex-wrap gap-1.5">
          {[
            { s: 'PAYLOAD_MUTATION', l: isAr ? 'تلاعب بالحمولة الموقعة' : 'Signed Payload Tamper' },
            { s: 'PARAMETER_POLLUTION', l: isAr ? 'تلويث المعاملات' : 'Param Pollution' },
            { s: 'PROTOTYPE_POLLUTION', l: isAr ? 'تلويث النموذج الأولي' : 'Prototype Pollution' },
            { s: 'CONTENT_LENGTH_MISMATCH', l: isAr ? 'تعارض طول المحتوى' : 'Length Mismatch' },
            { s: 'FORGED_INTEGRITY_HEADER', l: isAr ? 'تزوير ترويسة التكامل' : 'Forged Signature' }
          ].map(b => (
            <button
              key={b.s}
              onClick={() => simulateTamper(b.s)}
              disabled={isBusy}
              className="rounded-lg border px-2.5 py-1.5 font-mono text-[11px] font-semibold transition disabled:opacity-50"
              style={{
                background: 'rgba(220,20,60,0.10)',
                borderColor: 'rgba(220,20,60,0.35)',
                color: '#FF8FA6'
              }}
            >
              {b.l}
            </button>
          ))}
        </div>

        <div className="flex flex-wrap gap-1.5">
          {[
            {
              l: isAr ? 'تنزيل ملف أسرار' : 'Exfil .env',
              p: {
                operation: 'FILE_DOWNLOAD',
                filePath: '/srv/app/production.env',
                token: 'drill-exfil'
              }
            },
            {
              l: isAr ? 'رفع قذيفة ويب' : 'Upload WebShell',
              p: {
                operation: 'FILE_UPLOAD',
                filePath: '/var/www/html/shell.php',
                token: 'drill-shell'
              }
            },
            {
              l: isAr ? 'تعديل sudoers' : 'Modify sudoers',
              p: { operation: 'FILE_MODIFICATION', filePath: '/etc/sudoers', token: 'drill-mod' }
            },
            {
              l: isAr ? 'حذف سجل التدقيق' : 'Delete audit log',
              p: {
                operation: 'FILE_DELETION',
                filePath: '/var/log/audit/audit.log',
                token: 'drill-del'
              }
            }
          ].map((b, i) => (
            <button
              key={i}
              onClick={() => simulateFileAction(b.p)}
              disabled={isBusy}
              className="rounded-lg border px-2.5 py-1.5 font-mono text-[11px] font-semibold transition disabled:opacity-50"
              style={{ background: '#0C1322', borderColor: '#26304A', color: '#9FB0CC' }}
            >
              {b.l}
            </button>
          ))}
        </div>
      </div>

      {feedback && (
        <div
          className="flex items-start gap-2 rounded-lg border p-2.5 font-mono text-[11px]"
          style={
            feedback.type === 'success'
              ? {
                  background: 'rgba(34,197,94,0.08)',
                  borderColor: 'rgba(34,197,94,0.35)',
                  color: '#7EE2A8'
                }
              : {
                  background: 'rgba(220,20,60,0.10)',
                  borderColor: 'rgba(220,20,60,0.4)',
                  color: '#FF8FA6'
                }
          }
        >
          {feedback.type === 'success' ? (
            <CheckCircle2 className="mt-0.5 h-3.5 w-3.5 shrink-0" />
          ) : (
            <XCircle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
          )}
          <span className="flex-1">{feedback.message}</span>
          <button onClick={() => setFeedback(null)}>
            <XCircle className="h-3 w-3" />
          </button>
        </div>
      )}

      {/* ---------------- Two-column event matrix ---------------- */}
      <div className="grid grid-cols-1 gap-3 xl:grid-cols-2">
        {/* File interceptions */}
        <div className="space-y-2">
          <div
            className="flex items-center gap-2 font-mono text-xs font-bold"
            style={{ color: '#B9C6DC' }}
          >
            <FileWarning className="h-4 w-4" style={{ color: '#DC143C' }} />
            <span>{isAr ? 'عمليات الملفات المعترضة' : 'Intercepted File Operations'}</span>
            <span
              className="rounded px-1.5 py-0.5 text-[10px]"
              style={{ background: 'rgba(220,20,60,0.15)', color: '#FF5C7A' }}
            >
              {data?.recentFileBlocks.length ?? 0}
            </span>
          </div>

          <div className="max-h-[360px] space-y-1.5 overflow-y-auto pe-1">
            {(data?.recentFileBlocks ?? []).length === 0 && (
              <EmptyRow
                text={isAr ? 'لا توجد عمليات ملفات محظورة.' : 'No blocked file operations.'}
              />
            )}
            {(data?.recentFileBlocks ?? []).map(r => {
              const meta = OPERATION_META[r.operation];
              const Icon = meta?.icon ?? FileWarning;
              const selected =
                selectedChain?.kind === 'FILE' &&
                selectedChain.target === r.fileName &&
                selectedChain.actorIp === r.actorIp;
              return (
                <button
                  key={r.recordId}
                  onClick={() => setSelectedChain(fileChain(r))}
                  className="w-full rounded-lg border p-2.5 text-start transition"
                  style={{
                    background: selected ? 'rgba(220,20,60,0.10)' : '#0A0F1E',
                    borderColor: selected ? 'rgba(220,20,60,0.5)' : '#1B2338'
                  }}
                >
                  <div className="flex items-start justify-between gap-2">
                    <div className="flex min-w-0 items-start gap-2">
                      <Icon
                        className="mt-0.5 h-4 w-4 shrink-0"
                        style={{ color: r.blocked ? '#DC143C' : '#7A8AA8' }}
                      />
                      <div className="min-w-0">
                        <StatusBadge
                          action={r.action}
                          violation={r.violationClass}
                          operation={r.operation}
                        />
                        <div
                          className="mt-1 truncate font-mono text-[11px] font-bold"
                          style={{ color: '#E6EDF7' }}
                        >
                          {r.fileName}
                        </div>
                        <div
                          className="truncate font-mono text-[10px]"
                          style={{ color: '#5C6E8C' }}
                          title={r.filePath}
                        >
                          {r.filePath}
                        </div>
                        <div className="mt-0.5 font-mono text-[10px]" style={{ color: '#7A8AA8' }}>
                          {r.actorIp} · {r.matchedRuleId ?? '—'}
                          {r.tokenLockedDown && (
                            <span style={{ color: '#C77DFF' }}>
                              {' '}
                              · {isAr ? 'الرمز معزول' : 'token locked'}
                            </span>
                          )}
                        </div>
                      </div>
                    </div>
                    <span className="shrink-0 font-mono text-[9px]" style={{ color: '#4B5B78' }}>
                      {timeAgo(r.timestamp, isAr)}
                    </span>
                  </div>
                </button>
              );
            })}
          </div>
        </div>

        {/* In-transit tampering */}
        <div className="space-y-2">
          <div
            className="flex items-center gap-2 font-mono text-xs font-bold"
            style={{ color: '#B9C6DC' }}
          >
            <GitCompareArrows className="h-4 w-4" style={{ color: '#FF8A3D' }} />
            <span>{isAr ? 'تلاعب بالبيانات أثناء النقل' : 'Data-in-Transit Tampering'}</span>
            <span
              className="rounded px-1.5 py-0.5 text-[10px]"
              style={{ background: 'rgba(255,138,61,0.15)', color: '#FF8A3D' }}
            >
              {blockedTransit.length}
            </span>
          </div>

          <div className="max-h-[360px] space-y-1.5 overflow-y-auto pe-1">
            {blockedTransit.length === 0 && (
              <EmptyRow
                text={
                  isAr ? 'لا يوجد تلاعب مرصود أثناء النقل.' : 'No in-transit tampering detected.'
                }
              />
            )}
            {blockedTransit.map(r => {
              const selected =
                selectedChain?.kind === 'TRANSIT' &&
                selectedChain.target === r.route &&
                selectedChain.actorIp === r.actorIp;
              return (
                <button
                  key={r.interceptId}
                  onClick={() => setSelectedChain(transitChain(r))}
                  className="w-full rounded-lg border p-2.5 text-start transition"
                  style={{
                    background: selected ? 'rgba(255,138,61,0.08)' : '#0A0F1E',
                    borderColor: selected ? 'rgba(255,138,61,0.5)' : '#1B2338'
                  }}
                >
                  <div className="flex items-start justify-between gap-2">
                    <div className="min-w-0 flex-1">
                      <div className="flex flex-wrap items-center gap-1.5">
                        <span
                          className="rounded border px-1.5 py-0.5 font-mono text-[9px] font-bold"
                          style={
                            r.verdict === 'EMERGENCY_RESET'
                              ? {
                                  background: 'rgba(220,20,60,0.18)',
                                  borderColor: 'rgba(220,20,60,0.5)',
                                  color: '#FF5C7A'
                                }
                              : {
                                  background: 'rgba(255,138,61,0.15)',
                                  borderColor: 'rgba(255,138,61,0.45)',
                                  color: '#FF8A3D'
                                }
                          }
                        >
                          {r.verdict}
                        </span>
                        <span className="font-mono text-[9px]" style={{ color: '#FFD166' }}>
                          {r.primaryTamperClass}
                        </span>
                        {r.tcpResetIssued && (
                          <span
                            className="flex items-center gap-0.5 font-mono text-[9px]"
                            style={{ color: '#DC143C' }}
                          >
                            <Zap className="h-2.5 w-2.5" /> TCP RST
                          </span>
                        )}
                      </div>
                      <div
                        className="mt-1 truncate font-mono text-[11px] font-bold"
                        style={{ color: '#E6EDF7' }}
                      >
                        {r.method} {r.route}
                      </div>
                      <div className="font-mono text-[10px]" style={{ color: '#7A8AA8' }}>
                        {r.actorIp}
                      </div>

                      {/* Hash diff */}
                      <div
                        className="mt-1.5 space-y-0.5 rounded p-1.5"
                        style={{ background: '#060B16', border: '1px solid #16203A' }}
                      >
                        <div className="flex items-center gap-1.5 font-mono text-[9px]">
                          <span className="w-14 shrink-0" style={{ color: '#4B5B78' }}>
                            {isAr ? 'متوقع' : 'expected'}
                          </span>
                          <span style={{ color: '#7EE2A8' }}>{shortHash(r.expectedHash)}</span>
                        </div>
                        <div className="flex items-center gap-1.5 font-mono text-[9px]">
                          <span className="w-14 shrink-0" style={{ color: '#4B5B78' }}>
                            {isAr ? 'مرصود' : 'observed'}
                          </span>
                          <span style={{ color: '#FF5C7A' }}>{shortHash(r.observedHash)}</span>
                        </div>
                      </div>
                    </div>
                    <span className="shrink-0 font-mono text-[9px]" style={{ color: '#4B5B78' }}>
                      {timeAgo(r.timestamp, isAr)}
                    </span>
                  </div>
                </button>
              );
            })}
          </div>
        </div>
      </div>

      {/* ---------------- Active containment ---------------- */}
      <div className="grid grid-cols-1 gap-3 xl:grid-cols-2">
        <ContainmentList
          title={isAr ? 'الجلسات المحجوزة' : 'Quarantined Sessions'}
          icon={ShieldAlert}
          accent="#FFD166"
          isAr={isAr}
          empty={isAr ? 'لا توجد جلسات محجوزة.' : 'No quarantined sessions.'}
          rows={(data?.quarantinedSessions ?? []).map(q => ({
            id: q.sessionId,
            primary: q.sessionId,
            secondary: `${q.actorIp} · ${isAr ? q.reasonAr : q.reason}`,
            count: q.interceptCount,
            onRelease: () => release({ sessionId: q.sessionId })
          }))}
          disabled={isBusy}
        />
        <ContainmentList
          title={isAr ? 'الرموز المعزولة' : 'Locked Tokens'}
          icon={Lock}
          accent="#C77DFF"
          isAr={isAr}
          empty={isAr ? 'لا توجد رموز معزولة.' : 'No locked tokens.'}
          rows={(data?.lockedTokens ?? []).map(t => ({
            id: t.token,
            primary: t.token,
            secondary: `${t.actorIp} · ${isAr ? t.reasonAr : t.reason}`,
            count: t.violationCount,
            onRelease: () => release({ token: t.token })
          }))}
          disabled={isBusy}
        />
      </div>

      {/* ---------------- Audit chain integrity ---------------- */}
      {data && (
        <div
          className="flex flex-wrap items-center gap-3 border-t pt-3 font-mono text-[10px]"
          style={{ borderColor: '#1B2338', color: '#5C6E8C' }}
        >
          <Fingerprint className="h-3.5 w-3.5" style={{ color: '#5EA9FF' }} />
          <span>{isAr ? 'سلسلة التدقيق المقاومة للعبث:' : 'Tamper-evident audit chain:'}</span>
          <ChainBadge
            label={isAr ? 'النقل' : 'transit'}
            valid={data.auditIntegrity.inLine.valid}
            verified={data.auditIntegrity.inLine.verified}
          />
          <ChainBadge
            label={isAr ? 'الملفات' : 'file dlp'}
            valid={data.auditIntegrity.fileDlp.valid}
            verified={data.auditIntegrity.fileDlp.verified}
          />
        </div>
      )}
    </div>
  );
};

// =============================================================================
// Sub-components
// =============================================================================

const EmptyRow: React.FC<{ text: string }> = ({ text }) => (
  <div
    className="rounded-lg border p-5 text-center font-mono text-[11px]"
    style={{ background: '#0A0F1E', borderColor: '#1B2338', color: '#4B5B78' }}
  >
    {text}
  </div>
);

const ChainBadge: React.FC<{ label: string; valid: boolean; verified: number }> = ({
  label,
  valid,
  verified
}) => (
  <span
    className="flex items-center gap-1 rounded border px-1.5 py-0.5"
    style={
      valid
        ? {
            background: 'rgba(34,197,94,0.08)',
            borderColor: 'rgba(34,197,94,0.3)',
            color: '#7EE2A8'
          }
        : {
            background: 'rgba(220,20,60,0.12)',
            borderColor: 'rgba(220,20,60,0.45)',
            color: '#FF5C7A'
          }
    }
  >
    {valid ? <CheckCircle2 className="h-2.5 w-2.5" /> : <AlertOctagon className="h-2.5 w-2.5" />}
    {label}: {valid ? 'INTACT' : 'BROKEN'} ({verified})
  </span>
);

/** `BLOCKED: DELETE_ATTEMPT` / `QUARANTINED: EXFILTRATION_DETECTED` style badge. */
const StatusBadge: React.FC<{
  action: DlpAction;
  violation: string | null;
  operation: FileOperation;
}> = ({ action, violation, operation }) => {
  const label = violation ?? operation.replace('FILE_', '') + '_ATTEMPT';
  const style =
    action === 'BLOCK'
      ? { background: 'rgba(220,20,60,0.18)', borderColor: 'rgba(220,20,60,0.5)', color: '#FF5C7A' }
      : action === 'QUARANTINE'
        ? {
            background: 'rgba(255,209,102,0.14)',
            borderColor: 'rgba(255,209,102,0.45)',
            color: '#FFD166'
          }
        : {
            background: 'rgba(34,197,94,0.10)',
            borderColor: 'rgba(34,197,94,0.3)',
            color: '#7EE2A8'
          };

  return (
    <span
      className="inline-block rounded border px-1.5 py-0.5 font-mono text-[9px] font-bold"
      style={style}
    >
      {action === 'BLOCK' ? 'BLOCKED' : action === 'QUARANTINE' ? 'QUARANTINED' : 'ALLOWED'}:{' '}
      {label}
    </span>
  );
};

interface ContainmentRow {
  id: string;
  primary: string;
  secondary: string;
  count: number;
  onRelease: () => void;
}

const ContainmentList: React.FC<{
  title: string;
  icon: React.ElementType;
  accent: string;
  isAr: boolean;
  empty: string;
  rows: ContainmentRow[];
  disabled: boolean;
}> = ({ title, icon: Icon, accent, isAr, empty, rows, disabled }) => (
  <div className="space-y-2">
    <div
      className="flex items-center gap-2 font-mono text-xs font-bold"
      style={{ color: '#B9C6DC' }}
    >
      <Icon className="h-4 w-4" style={{ color: accent }} />
      <span>{title}</span>
      <span
        className="rounded px-1.5 py-0.5 text-[10px]"
        style={{ background: `${accent}22`, color: accent }}
      >
        {rows.length}
      </span>
    </div>
    <div className="max-h-[190px] space-y-1.5 overflow-y-auto pe-1">
      {rows.length === 0 && <EmptyRow text={empty} />}
      {rows.map(r => (
        <div
          key={r.id}
          className="flex items-center justify-between gap-2 rounded-lg border p-2"
          style={{ background: '#0A0F1E', borderColor: '#1B2338' }}
        >
          <div className="min-w-0">
            <div className="truncate font-mono text-[11px] font-bold" style={{ color: '#E6EDF7' }}>
              {r.primary}
            </div>
            <div className="truncate font-mono text-[10px]" style={{ color: '#5C6E8C' }}>
              {r.secondary}
            </div>
          </div>
          <div className="flex shrink-0 items-center gap-1.5">
            <span
              className="rounded px-1.5 py-0.5 font-mono text-[9px]"
              style={{ background: `${accent}22`, color: accent }}
            >
              ×{r.count}
            </span>
            <button
              onClick={r.onRelease}
              disabled={disabled}
              className="flex items-center gap-1 rounded border px-1.5 py-1 font-mono text-[10px] transition disabled:opacity-50"
              style={{ background: '#0C1322', borderColor: '#26304A', color: '#9FB0CC' }}
              title={isAr ? 'إفراج' : 'Release'}
            >
              <Unlock className="h-3 w-3" />
            </button>
          </div>
        </div>
      ))}
    </div>
  </div>
);

/**
 * Link-analysis graph: Actor IP -> Intercepted Action -> Target -> Mitigation.
 * Rendered as inline SVG so the connector paths can animate without pulling in
 * a charting dependency.
 */
const LiveInterceptLink: React.FC<{ chain: LinkChain; isAr: boolean }> = ({ chain, isAr }) => {
  const accent = chain.blocked ? '#DC143C' : '#7EE2A8';
  const nodes = [
    {
      icon: Crosshair,
      label: isAr ? 'المصدر المهاجم' : 'ACTOR',
      value: chain.actorIp,
      color: '#FF5C7A'
    },
    {
      icon: chain.kind === 'FILE' ? FileWarning : GitCompareArrows,
      label: isAr ? 'الإجراء المعترض' : 'ACTION',
      value: chain.actionLabel,
      color: '#FF8A3D'
    },
    { icon: Server, label: isAr ? 'الهدف' : 'TARGET', value: chain.target, color: '#5EA9FF' },
    {
      icon: ShieldOff,
      label: isAr ? 'الإجراء المطبق' : 'MITIGATION',
      value: chain.mitigation,
      color: accent
    }
  ];

  return (
    <div className="space-y-3">
      {/* Node chain */}
      <div className="grid grid-cols-1 items-stretch gap-1.5 md:grid-cols-7">
        {nodes.map((n, i) => (
          <React.Fragment key={i}>
            <div
              className="flex min-w-0 flex-col justify-center rounded-lg border p-2.5 md:col-span-1"
              style={{ background: '#060B16', borderColor: i === 3 ? `${accent}88` : '#1B2338' }}
            >
              <div
                className="mb-1 flex items-center gap-1 font-mono text-[9px]"
                style={{ color: '#4B5B78' }}
              >
                <n.icon className="h-3 w-3" style={{ color: n.color }} />
                <span className="truncate">{n.label}</span>
              </div>
              <div
                className="font-mono text-[11px] leading-tight font-bold break-all"
                style={{ color: n.color }}
                title={n.value}
              >
                {n.value}
              </div>
            </div>

            {i < 3 && (
              <div className="hidden items-center justify-center md:col-span-1 md:flex">
                <svg width="100%" height="24" viewBox="0 0 100 24" preserveAspectRatio="none">
                  <defs>
                    <linearGradient id={`lnk-${i}`} x1="0" x2="1">
                      <stop offset="0%" stopColor={nodes[i].color} stopOpacity="0.7" />
                      <stop offset="100%" stopColor={nodes[i + 1].color} stopOpacity="0.7" />
                    </linearGradient>
                  </defs>
                  <line
                    x1="0"
                    y1="12"
                    x2="92"
                    y2="12"
                    stroke={`url(#lnk-${i})`}
                    strokeWidth="1.5"
                    strokeDasharray="5 4"
                  >
                    <animate
                      attributeName="stroke-dashoffset"
                      from="18"
                      to="0"
                      dur="0.9s"
                      repeatCount="indefinite"
                    />
                  </line>
                  <polygon points="92,7 100,12 92,17" fill={nodes[i + 1].color} opacity="0.85" />
                </svg>
              </div>
            )}
          </React.Fragment>
        ))}
      </div>

      {/* Detail strip */}
      <div
        className="rounded-lg border p-2.5"
        style={{ background: '#060B16', borderColor: '#16203A' }}
      >
        <div className="font-mono text-[10px] leading-relaxed" style={{ color: '#9FB0CC' }}>
          {chain.detail}
        </div>
        {chain.kind === 'TRANSIT' && chain.observedHash && (
          <div className="mt-2 grid grid-cols-1 gap-1.5 font-mono text-[9px] sm:grid-cols-2">
            <div
              className="rounded p-1.5"
              style={{
                background: 'rgba(34,197,94,0.06)',
                border: '1px solid rgba(34,197,94,0.2)'
              }}
            >
              <span style={{ color: '#4B5B78' }}>
                {isAr ? 'البصمة المتوقعة' : 'expected digest'}
              </span>
              <div className="mt-0.5 break-all" style={{ color: '#7EE2A8' }}>
                {chain.expectedHash ?? '—'}
              </div>
            </div>
            <div
              className="rounded p-1.5"
              style={{
                background: 'rgba(220,20,60,0.07)',
                border: '1px solid rgba(220,20,60,0.25)'
              }}
            >
              <span style={{ color: '#4B5B78' }}>
                {isAr ? 'البصمة المرصودة' : 'observed digest'}
              </span>
              <div className="mt-0.5 break-all" style={{ color: '#FF5C7A' }}>
                {chain.observedHash}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default InterceptionMatrixPanel;
