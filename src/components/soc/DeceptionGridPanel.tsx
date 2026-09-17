import React, { useState, useEffect, useCallback, useMemo, useRef } from 'react';
import ForceGraphCanvas, { type GraphNode, type GraphEdge } from './ForceGraphCanvas';
import {
  Ghost,
  Drama,
  TerminalSquare,
  Network,
  KeyRound,
  Fingerprint,
  RefreshCw,
  Radio,
  Unlock,
  Gauge,
  Crosshair,
  ShieldQuestion,
  Timer,
  FlaskConical,
  CheckCircle2,
  XCircle,
  Play,
  Layers
} from 'lucide-react';

// =============================================================================
// DECEPTION GRID COMMAND CENTER
// Live view of the shadow decoy grid: who is trapped, what they are running
// inside the sandbox, which canaries they have swallowed, and how their
// behaviour maps onto ATT&CK.
// =============================================================================

/** Deception palette: neon violet for the grid, emerald for trapped canaries. */
const DECEPTION_PALETTE: Record<string, string> = {
  ACTOR: '#FF0055',
  DECOY_ASSET: '#8A2BE2',
  TECHNIQUE: '#FFB800',
  CANARY: '#00FF66'
};

const VIOLET = '#8A2BE2';
const EMERALD = '#00FF66';

interface ClonedContext {
  sessionId: string; actorIp: string; username: string; displayName: string;
  avatarUrl: string; roles: string[]; permissions: string[]; tenantId: string;
  presentedToken: string | null; clonedAt: number; lastSeenAt: number;
}

interface CanarySummary {
  canaryId: string; kind: string; plantedPath: string; redeemed: boolean;
}

interface EntrappedActor {
  sessionId: string; actorIp: string; divertedAt: number; lastInteractionAt: number;
  interactions: number; intentScoreAtDiversion: number;
  clonedContext: ClonedContext; canaries: CanarySummary[];
  syntheticFileCount: number;
  sophisticationIndex: number;
  sophisticationBand: 'SCRIPT_KIDDIE' | 'COMMODITY_TOOLING' | 'COMPETENT_OPERATOR' | 'ADVANCED_PERSISTENT';
  killChain: string[]; techniques: string[];
}

interface TranscriptEntry {
  actionId: string; timestamp: number; sessionId: string; actorIp: string;
  method: string; path: string; rawPayload: string; decodedPayload: string;
  obfuscationDepth: number; intentScore: number; decoyResponseKind: string;
  decoyStatusCode: number; appliedLatencyMs: number; mitreTechniques: string[];
  tactic: string; canariesTouched: string[];
}

interface GridStats {
  router: {
    activeSessions: number; totalDiverted: number; totalInteractions: number;
    canariesMinted: number; canariesRedeemed: number;
    latencyProfile: Record<string, { samples: number; p50: number; p95: number }>;
  };
  profiler: { trackedProfiles: number; totalActions: number; peakSophistication: number; bands: Record<string, number> };
  intent: { totalAnalyzed: number; totalDiverted: number; totalMonitored: number; diversionThreshold: number };
}

export interface DeceptionGridPanelProps { lang: 'ar' | 'en'; }

const BAND_STYLE: Record<string, { bg: string; border: string; color: string; labelAr: string }> = {
  SCRIPT_KIDDIE: { bg: 'rgba(122,138,168,0.12)', border: 'rgba(122,138,168,0.4)', color: '#9FB0CC', labelAr: 'مبتدئ' },
  COMMODITY_TOOLING: { bg: 'rgba(255,184,0,0.12)', border: 'rgba(255,184,0,0.4)', color: '#FFB800', labelAr: 'أدوات جاهزة' },
  COMPETENT_OPERATOR: { bg: 'rgba(255,122,0,0.14)', border: 'rgba(255,122,0,0.45)', color: '#FF7A00', labelAr: 'مشغّل كفء' },
  ADVANCED_PERSISTENT: { bg: 'rgba(255,0,85,0.16)', border: 'rgba(255,0,85,0.5)', color: '#FF0055', labelAr: 'تهديد متقدم مستمر' }
};

function timeAgo(ts: number, isAr: boolean): string {
  const s = Math.max(0, Math.floor((Date.now() - ts) / 1000));
  if (s < 60) return isAr ? `منذ ${s} ث` : `${s}s`;
  if (s < 3600) return isAr ? `منذ ${Math.floor(s / 60)} د` : `${Math.floor(s / 60)}m`;
  return isAr ? `منذ ${Math.floor(s / 3600)} س` : `${Math.floor(s / 3600)}h`;
}

export const DeceptionGridPanel: React.FC<DeceptionGridPanelProps> = ({ lang }) => {
  const isAr = lang === 'ar';

  const [actors, setActors] = useState<EntrappedActor[]>([]);
  const [transcript, setTranscript] = useState<TranscriptEntry[]>([]);
  const [graph, setGraph] = useState<{ nodes: GraphNode[]; edges: GraphEdge[] }>({ nodes: [], edges: [] });
  const [stats, setStats] = useState<GridStats | null>(null);
  const [selectedSession, setSelectedSession] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [isBusy, setIsBusy] = useState(false);
  const [feedback, setFeedback] = useState<{ type: 'success' | 'error'; message: string } | null>(null);
  const [autoScroll, setAutoScroll] = useState(true);
  const terminalRef = useRef<HTMLDivElement | null>(null);

  // -----------------------------------------------------------------
  const fetchGrid = useCallback(async (spinner = false) => {
    if (spinner) setIsLoading(true);
    try {
      const qs = selectedSession ? '?sessionId=' + encodeURIComponent(selectedSession) : '';
      const [eRes, tRes, gRes] = await Promise.all([
        fetch('/api/v1/soc/deception/entrapped'),
        fetch('/api/v1/soc/deception/transcript' + qs),
        fetch('/api/v1/soc/deception/flow-graph')
      ]);
      if (eRes.ok) {
        const j = await eRes.json();
        if (j?.success) { setActors(j.entrapped ?? []); setStats(j.stats ?? null); }
      }
      if (tRes.ok) {
        const j = await tRes.json();
        if (j?.success) setTranscript(j.entries ?? []);
      }
      if (gRes.ok) {
        const j = await gRes.json();
        if (j?.success) setGraph({ nodes: j.nodes ?? [], edges: j.edges ?? [] });
      }
    } catch {
      /* transient; next poll recovers */
    } finally { setIsLoading(false); }
  }, [selectedSession]);

  useEffect(() => { fetchGrid(true); }, [fetchGrid]);
  useEffect(() => {
    const id = setInterval(() => fetchGrid(false), 4000);
    return () => clearInterval(id);
  }, [fetchGrid]);

  useEffect(() => {
    if (autoScroll && terminalRef.current) terminalRef.current.scrollTop = 0;
  }, [transcript, autoScroll]);

  // -----------------------------------------------------------------
  const runProbe = async (label: string, payload: string, path: string) => {
    setIsBusy(true); setFeedback(null);
    try {
      const res = await fetch('/api/v1/soc/deception/test/deception-probe', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ payload, path, sessionId: 'soc-drill-' + Date.now().toString(36) })
      });
      const j = await res.json();
      if (j?.success) {
        const s = j.stage1_intent;
        setFeedback({
          type: 'success',
          message: isAr
            ? `${label}: النية ${s.adversaryIntentScore}/100 — ${j.stage2_diversion.diverted ? 'حُوّل إلى الشبكة' : 'لم يُحوّل'}`
            : `${label}: intent ${s.adversaryIntentScore}/100 — ${j.stage2_diversion.diverted ? 'diverted into the grid' : 'not diverted'}`
        });
        await fetchGrid(false);
      } else {
        setFeedback({ type: 'error', message: j?.message || (isAr ? 'فشل الفحص.' : 'Probe failed.') });
      }
    } catch {
      setFeedback({ type: 'error', message: isAr ? 'تعذر الاتصال بشبكة الخداع.' : 'Could not reach the deception grid.' });
    } finally { setIsBusy(false); }
  };

  const release = async (sessionId: string) => {
    setIsBusy(true);
    try {
      await fetch('/api/v1/soc/deception/release', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ sessionId })
      });
      if (selectedSession === sessionId) setSelectedSession(null);
      await fetchGrid(false);
      setFeedback({ type: 'success', message: isAr ? 'أُطلقت الجلسة بعد المراجعة.' : 'Session released after review.' });
    } finally { setIsBusy(false); }
  };

  const canariesRedeemed = useMemo(
    () => actors.reduce((n, a) => n + a.canaries.filter(c => c.redeemed).length, 0),
    [actors]
  );

  const visibleTranscript = useMemo(
    () => (selectedSession ? transcript.filter(t => t.sessionId === selectedSession) : transcript),
    [transcript, selectedSession]
  );

  // -----------------------------------------------------------------
  return (
    <div className="rounded-xl p-5 space-y-5 border shadow-2xl" style={{ background: '#050914', borderColor: '#1B2338' }}>
      {/* Header */}
      <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-4 pb-4 border-b" style={{ borderColor: '#1B2338' }}>
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-lg border" style={{ background: 'rgba(138,43,226,0.14)', borderColor: 'rgba(138,43,226,0.45)' }}>
            <Drama className="w-5 h-5" style={{ color: VIOLET }} />
          </div>
          <div>
            <div className="flex items-center gap-2 flex-wrap">
              <h3 className="text-base font-bold" style={{ color: '#E6EDF7' }}>
                {isAr ? 'شبكة الخداع التكيفية والتوجيه الظلي' : 'Adaptive Deception Grid & Shadow Routing'}
              </h3>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold border flex items-center gap-1"
                style={{ background: 'rgba(138,43,226,0.16)', borderColor: 'rgba(138,43,226,0.5)', color: '#C89BFF' }}>
                <Radio className="w-3 h-3 animate-pulse" />
                {isAr ? 'فخ نشط' : 'TRAP ACTIVE'}
              </span>
            </div>
            <p className="text-xs mt-0.5" style={{ color: '#7A8AA8' }}>
              {isAr
                ? 'يرصد الاستطلاع المموه ويشعب المهاجم بصمت إلى بيئة وهمية مطابقة مع الحفاظ على جلسته'
                : 'Detects obfuscated recon and silently forks the attacker into an identical decoy, session intact.'}
            </p>
          </div>
        </div>
        <button onClick={() => fetchGrid(true)} className="p-1.5 rounded-lg border transition"
          style={{ background: '#0C1322', borderColor: '#1B2338', color: '#7A8AA8' }} title={isAr ? 'تحديث' : 'Refresh'}>
          <RefreshCw className={`w-4 h-4 ${isLoading ? 'animate-spin' : ''}`} />
        </button>
      </div>

      {/* Metric tiles */}
      <div className="grid grid-cols-2 lg:grid-cols-6 gap-2.5">
        {[
          { icon: Ghost, label: isAr ? 'محتجزون' : 'Entrapped', value: actors.length, color: VIOLET },
          { icon: Crosshair, label: isAr ? 'تم تحويلهم' : 'Diverted', value: stats?.router.totalDiverted ?? 0, color: '#FF0055' },
          { icon: Layers, label: isAr ? 'تفاعلات' : 'Interactions', value: stats?.router.totalInteractions ?? 0, color: '#00F0FF' },
          { icon: KeyRound, label: isAr ? 'طُعوم مزروعة' : 'Canaries', value: stats?.router.canariesMinted ?? 0, color: EMERALD },
          { icon: Fingerprint, label: isAr ? 'طُعوم استُخدمت' : 'Redeemed', value: canariesRedeemed, color: EMERALD },
          { icon: Gauge, label: isAr ? 'أعلى تطور' : 'Peak Soph.', value: stats?.profiler.peakSophistication ?? 0, color: '#FFB800' }
        ].map((t, i) => (
          <div key={i} className="p-2.5 rounded-lg border" style={{ background: '#0A0F1E', borderColor: '#1B2338' }}>
            <div className="flex items-center gap-1.5 text-[10px] font-mono" style={{ color: '#7A8AA8' }}>
              <t.icon className="w-3.5 h-3.5" style={{ color: t.color }} />
              <span className="truncate">{t.label}</span>
            </div>
            <div className="text-xl font-bold font-mono mt-1" style={{ color: t.color }}>{t.value}</div>
          </div>
        ))}
      </div>

      {/* Latency-matching profile: the anti-fingerprinting control */}
      {stats?.router.latencyProfile && (
        <div className="rounded-lg border p-3" style={{ background: '#0A0F1E', borderColor: '#1B2338' }}>
          <div className="flex items-center gap-2 text-[11px] font-bold font-mono mb-2" style={{ color: '#B9C6DC' }}>
            <Timer className="w-3.5 h-3.5" style={{ color: '#00F0FF' }} />
            <span>{isAr ? 'مطابقة زمن الاستجابة (دفاع ضد البصمة الزمنية)' : 'Latency Matching (timing side-channel defense)'}</span>
          </div>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
            {(Object.entries(stats.router.latencyProfile) as Array<[string, { samples: number; p50: number; p95: number }]>).map(([bucket, p]) => (
              <div key={bucket} className="rounded px-2 py-1.5" style={{ background: '#060B16', border: '1px solid #16203A' }}>
                <div className="text-[9px] font-mono" style={{ color: '#4B5B78' }}>{bucket}</div>
                <div className="text-[11px] font-mono" style={{ color: '#00F0FF' }}>
                  p50 {p.p50}ms · p95 {p.p95}ms
                </div>
                <div className="text-[9px] font-mono" style={{ color: '#4B5B78' }}>
                  {p.samples} {isAr ? 'عينة حقيقية' : 'real samples'}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Drill bar */}
      <div className="rounded-lg border p-3 space-y-2" style={{ background: '#0A0F1E', borderColor: '#1B2338' }}>
        <div className="flex items-center gap-2 text-xs font-bold font-mono" style={{ color: '#B9C6DC' }}>
          <FlaskConical className="w-4 h-4" style={{ color: VIOLET }} />
          <span>{isAr ? 'تدريبات الاستطلاع المموه' : 'Obfuscated Recon Drills'}</span>
          {isBusy && <Play className="w-3.5 h-3.5 animate-pulse" style={{ color: VIOLET }} />}
        </div>
        <div className="flex flex-wrap gap-1.5">
          {[
            { l: isAr ? 'اجتياز مزدوج الترميز' : 'Double-encoded traversal', p: '%252e%252e%252f%252e%252e%252fetc%252fpasswd', path: '/api/v1/files' },
            { l: isAr ? 'استطلاع .env' : '.env recon', p: 'x', path: '/.env' },
            { l: isAr ? 'استطلاع .git' : '.git recon', p: 'x', path: '/.git/config' },
            { l: isAr ? 'حقن SQL أعمى' : 'Blind SQLi', p: "1' AND sleep(5)--", path: '/api/v1/items' },
            { l: isAr ? 'حقن أوامر' : 'Command injection', p: ';cat /etc/passwd', path: '/api/v1/ping' },
            { l: isAr ? 'مفتاح SSH' : 'SSH key probe', p: 'x', path: '/home/deploy/id_rsa' }
          ].map((b, i) => (
            <button key={i} onClick={() => runProbe(b.l, b.p, b.path)} disabled={isBusy}
              className="px-2.5 py-1.5 rounded-lg text-[11px] font-mono font-semibold border transition disabled:opacity-50"
              style={{ background: 'rgba(138,43,226,0.10)', borderColor: 'rgba(138,43,226,0.35)', color: '#C89BFF' }}>
              {b.l}
            </button>
          ))}
        </div>
      </div>

      {feedback && (
        <div className="p-2.5 rounded-lg border text-[11px] font-mono flex items-start gap-2"
          style={feedback.type === 'success'
            ? { background: 'rgba(0,255,102,0.07)', borderColor: 'rgba(0,255,102,0.3)', color: '#7EE2A8' }
            : { background: 'rgba(255,0,85,0.09)', borderColor: 'rgba(255,0,85,0.4)', color: '#FF8FA6' }}>
          {feedback.type === 'success' ? <CheckCircle2 className="w-3.5 h-3.5 mt-0.5 shrink-0" /> : <XCircle className="w-3.5 h-3.5 mt-0.5 shrink-0" />}
          <span className="flex-1">{feedback.message}</span>
          <button onClick={() => setFeedback(null)}><XCircle className="w-3 h-3" /></button>
        </div>
      )}

      {/* Deception flow graph */}
      <div className="rounded-lg border p-4 space-y-2" style={{ background: '#0A0F1E', borderColor: '#1B2338' }}>
        <div className="flex items-center justify-between gap-2 flex-wrap">
          <div className="flex items-center gap-2 text-xs font-bold font-mono" style={{ color: '#E6EDF7' }}>
            <Network className="w-4 h-4" style={{ color: VIOLET }} />
            <span>{isAr ? 'رسم تدفق الخداع' : 'Deception Flow Graph'}</span>
          </div>
          <span className="text-[10px] font-mono" style={{ color: '#4B5B78' }}>
            {isAr ? 'المهاجم ← الأصل الوهمي ← الطُعم ← تقنية MITRE' : 'Actor → Decoy Asset → Canary → MITRE Technique'}
          </span>
        </div>
        <ForceGraphCanvas
          nodes={graph.nodes}
          edges={graph.edges}
          height={320}
          isAr={isAr}
          paletteOverride={DECEPTION_PALETTE}
          legendOverride={[
            ['ACTOR', isAr ? 'المهاجم' : 'Attacker'],
            ['DECOY_ASSET', isAr ? 'أصل وهمي' : 'Decoy Asset'],
            ['CANARY', isAr ? 'طُعم' : 'Canary'],
            ['TECHNIQUE', isAr ? 'تقنية MITRE' : 'MITRE Technique']
          ]}
        />
      </div>

      {/* Entrapped actors + shadow terminal */}
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-3">
        {/* Actors matrix */}
        <div className="space-y-2">
          <div className="flex items-center gap-2 text-xs font-bold font-mono" style={{ color: '#B9C6DC' }}>
            <Ghost className="w-4 h-4" style={{ color: VIOLET }} />
            <span>{isAr ? 'مصفوفة الفاعلين المحتجزين' : 'Entrapped Actors Matrix'}</span>
            <span className="px-1.5 py-0.5 rounded text-[10px]" style={{ background: 'rgba(138,43,226,0.16)', color: '#C89BFF' }}>
              {actors.length}
            </span>
          </div>

          <div className="space-y-1.5 max-h-[420px] overflow-y-auto pe-1">
            {actors.length === 0 && (
              <div className="p-6 text-center text-[11px] font-mono rounded-lg border"
                style={{ background: '#0A0F1E', borderColor: '#1B2338', color: '#4B5B78' }}>
                {isAr ? 'لا يوجد فاعلون محتجزون حالياً. الشبكة في وضع الترقب.' : 'No entrapped actors. The grid is waiting.'}
              </div>
            )}

            {actors.map(a => {
              const band = BAND_STYLE[a.sophisticationBand] ?? BAND_STYLE.SCRIPT_KIDDIE;
              const selected = selectedSession === a.sessionId;
              const swallowed = a.canaries.filter(c => c.redeemed).length;
              return (
                <div key={a.sessionId}
                  onClick={() => setSelectedSession(selected ? null : a.sessionId)}
                  className="p-2.5 rounded-lg border cursor-pointer transition"
                  style={{
                    background: selected ? 'rgba(138,43,226,0.09)' : '#0A0F1E',
                    borderColor: selected ? 'rgba(138,43,226,0.5)' : '#1B2338'
                  }}>
                  <div className="flex items-start justify-between gap-2">
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-1.5 flex-wrap">
                        <span className="px-1.5 py-0.5 rounded text-[9px] font-mono font-bold border"
                          style={{ background: band.bg, borderColor: band.border, color: band.color }}>
                          {isAr ? band.labelAr : a.sophisticationBand.replace(/_/g, ' ')} {a.sophisticationIndex}
                        </span>
                        <span className="text-[11px] font-mono font-bold" style={{ color: '#FF0055' }}>{a.actorIp}</span>
                        <span className="text-[9px] font-mono" style={{ color: '#4B5B78' }}>{timeAgo(a.lastInteractionAt, isAr)}</span>
                      </div>

                      {/* Cloned identity - the session-bleed-safe fake */}
                      <div className="mt-1.5 rounded px-2 py-1.5" style={{ background: '#060B16', border: '1px solid #16203A' }}>
                        <div className="text-[9px] font-mono" style={{ color: '#4B5B78' }}>
                          {isAr ? 'الهوية المستنسخة (حالة تركيبية معزولة)' : 'Cloned identity (isolated synthetic state)'}
                        </div>
                        <div className="text-[10px] font-mono" style={{ color: '#C89BFF' }}>
                          {a.clonedContext.username} · {a.clonedContext.tenantId} · [{a.clonedContext.roles.join(', ')}]
                        </div>
                      </div>

                      <div className="flex items-center gap-2.5 mt-1.5 text-[9px] font-mono flex-wrap" style={{ color: '#7A8AA8' }}>
                        <span>{isAr ? 'تفاعلات' : 'probes'}: {a.interactions}</span>
                        <span>{isAr ? 'نية' : 'intent'}: {a.intentScoreAtDiversion}</span>
                        <span style={{ color: EMERALD }}>
                          {isAr ? 'طُعوم' : 'canaries'}: {a.canaries.length}{swallowed > 0 ? ` (${swallowed} ${isAr ? 'استُخدم' : 'redeemed'})` : ''}
                        </span>
                        {a.syntheticFileCount > 0 && <span>{isAr ? 'ملفات وهمية' : 'synthetic files'}: {a.syntheticFileCount}</span>}
                      </div>

                      {a.killChain.length > 0 && (
                        <div className="flex items-center gap-1 mt-1.5 flex-wrap">
                          {a.killChain.map((t, i) => (
                            <React.Fragment key={t}>
                              {i > 0 && <span className="text-[9px]" style={{ color: '#33415C' }}>→</span>}
                              <span className="px-1.5 py-0.5 rounded text-[9px] font-mono"
                                style={{ background: 'rgba(255,184,0,0.10)', color: '#FFB800' }}>{t}</span>
                            </React.Fragment>
                          ))}
                        </div>
                      )}
                    </div>

                    <button onClick={e => { e.stopPropagation(); release(a.sessionId); }} disabled={isBusy}
                      className="px-1.5 py-1 rounded border text-[10px] font-mono transition disabled:opacity-50 shrink-0"
                      style={{ background: '#0C1322', borderColor: '#26304A', color: '#9FB0CC' }}
                      title={isAr ? 'إطلاق' : 'Release'}>
                      <Unlock className="w-3 h-3" />
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Shadow terminal */}
        <div className="space-y-2">
          <div className="flex items-center justify-between gap-2 flex-wrap">
            <div className="flex items-center gap-2 text-xs font-bold font-mono" style={{ color: '#B9C6DC' }}>
              <TerminalSquare className="w-4 h-4" style={{ color: EMERALD }} />
              <span>{isAr ? 'طرفية الظل' : 'Shadow Terminal'}</span>
              {selectedSession && (
                <span className="px-1.5 py-0.5 rounded text-[9px] font-mono"
                  style={{ background: 'rgba(138,43,226,0.16)', color: '#C89BFF' }}>
                  {selectedSession.slice(0, 22)}
                </span>
              )}
            </div>
            <label className="flex items-center gap-1 text-[9px] font-mono cursor-pointer" style={{ color: '#4B5B78' }}>
              <input type="checkbox" checked={autoScroll} onChange={e => setAutoScroll(e.target.checked)} />
              {isAr ? 'تتبع تلقائي' : 'follow'}
            </label>
          </div>

          <div ref={terminalRef} className="rounded-lg border p-2.5 max-h-[420px] overflow-y-auto font-mono text-[10px] space-y-2"
            style={{ background: '#060B16', borderColor: '#16203A' }}>
            {visibleTranscript.length === 0 && (
              <div className="py-8 text-center" style={{ color: '#4B5B78' }}>
                {isAr ? 'لا توجد أوامر مرصودة داخل الصندوق الوهمي بعد.' : 'No commands observed inside the sandbox yet.'}
              </div>
            )}

            {visibleTranscript.map(e => (
              <div key={e.actionId} className="pb-2 border-b" style={{ borderColor: '#101828' }}>
                <div className="flex items-center gap-1.5 flex-wrap">
                  <span style={{ color: EMERALD }}>
                    {e.actorIp}<span style={{ color: '#33415C' }}>@</span>decoy
                  </span>
                  <span style={{ color: '#33415C' }}>:~$</span>
                  <span style={{ color: '#FFB800' }}>{e.method}</span>
                  <span className="break-all" style={{ color: '#E6EDF7' }}>{e.path.slice(0, 80)}</span>
                </div>

                {e.decodedPayload && e.decodedPayload !== e.rawPayload && (
                  <div className="mt-1 ps-3 break-all" style={{ color: '#C89BFF' }}>
                    <span style={{ color: '#4B5B78' }}>{isAr ? 'بعد فك التمويه: ' : 'deobfuscated: '}</span>
                    {e.decodedPayload.slice(0, 150)}
                  </div>
                )}

                <div className="mt-1 ps-3 flex items-center gap-2 flex-wrap" style={{ color: '#4B5B78' }}>
                  <span style={{ color: '#00F0FF' }}>{e.decoyResponseKind}</span>
                  <span>{e.decoyStatusCode}</span>
                  <span>{e.appliedLatencyMs}ms</span>
                  {e.obfuscationDepth > 0 && <span style={{ color: '#FF7A00' }}>obf×{e.obfuscationDepth}</span>}
                  <span style={{ color: '#FFB800' }}>{e.tactic}</span>
                  {e.canariesTouched.length > 0 && (
                    <span style={{ color: EMERALD }}>
                      <KeyRound className="w-2.5 h-2.5 inline" /> {e.canariesTouched.length} {isAr ? 'طُعم' : 'canary'}
                    </span>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Footer: mitigation posture */}
      <div className="flex flex-wrap items-center gap-3 pt-3 border-t text-[10px] font-mono" style={{ borderColor: '#1B2338', color: '#5C6E8C' }}>
        <ShieldQuestion className="w-3.5 h-3.5" style={{ color: VIOLET }} />
        <span>{isAr ? 'دفاعات مقاومة كشف المصيدة:' : 'Anti-fingerprinting posture:'}</span>
        {[
          isAr ? 'مطابقة زمنية' : 'latency matched',
          isAr ? 'عزل الحالة' : 'state isolated',
          isAr ? 'رموز تبدو صالحة' : 'tokens appear valid',
          isAr ? 'محتوى حتمي' : 'deterministic content',
          isAr ? 'بلا تنفيذ فعلي' : 'no real execution'
        ].map(x => (
          <span key={x} className="px-1.5 py-0.5 rounded border"
            style={{ background: 'rgba(0,255,102,0.06)', borderColor: 'rgba(0,255,102,0.25)', color: '#7EE2A8' }}>
            {x}
          </span>
        ))}
      </div>
    </div>
  );
};

export default DeceptionGridPanel;
