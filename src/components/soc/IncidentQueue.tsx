import React, { useEffect, useMemo, useRef, useState } from 'react';
import {
  ShieldCheck,
  Cpu,
  FileLock2,
  Bot,
  Eye,
  Ban,
  Activity,
  ChevronLeft,
  ChevronRight,
  Filter,
  Clock,
  Download,
  ShieldAlert
} from 'lucide-react';

/**
 * INCIDENT QUEUE — the triage surface.
 *
 * Every mature security console is built around a prioritised queue, not a
 * visualisation: the analyst's job is to work a list top-down, and the graph
 * is what they open once a row matters. This component is that list.
 *
 * Design rules taken from production consoles:
 *  - severity is a rail + word, never colour alone
 *  - one row = one decision; the response already taken is a column, so the
 *    analyst can see what the platform did without opening anything
 *  - selecting a row opens detail beside the list rather than navigating away
 *  - the queue is filterable by severity, because triage starts by cutting noise
 */

export interface TelemetryEvent {
  id: string;
  timestamp: string;
  source: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | string;
  title: string;
  titleAr?: string;
  details?: string;
  detailsAr?: string;
  actorIp?: string;
  mitreTactic?: string;
  mitreTechnique?: string;
  actionTaken?: string;
  actionTakenAr?: string;
}

interface Props {
  lang?: 'ar' | 'en';
}

const SEVERITY = {
  CRITICAL: {
    ar: 'حرجة',
    en: 'Critical',
    rail: 'bg-rose-500',
    text: 'text-rose-400',
    chip: 'bg-rose-500/10 border-rose-500/30',
    rank: 0
  },
  HIGH: {
    ar: 'عالية',
    en: 'High',
    rail: 'bg-amber-500',
    text: 'text-amber-400',
    chip: 'bg-amber-500/10 border-amber-500/30',
    rank: 1
  },
  MEDIUM: {
    ar: 'متوسطة',
    en: 'Medium',
    rail: 'bg-cyan-500',
    text: 'text-cyan-400',
    chip: 'bg-cyan-500/10 border-cyan-500/30',
    rank: 2
  },
  LOW: {
    ar: 'منخفضة',
    en: 'Low',
    rail: 'bg-slate-600',
    text: 'text-slate-400',
    chip: 'bg-slate-700/40 border-slate-700',
    rank: 3
  }
} as const;

const sevOf = (s: string) =>
  SEVERITY[(s || 'LOW').toUpperCase() as keyof typeof SEVERITY] ?? SEVERITY.LOW;

/** Maps the emitting subsystem onto the control that produced the verdict. */
const SOURCE_META: Record<string, { ar: string; en: string; icon: React.ElementType }> = {
  WAF_EBPF: { ar: 'نواة eBPF / WAF', en: 'eBPF / WAF', icon: Cpu },
  AI_DEFENSE: { ar: 'محرك الذكاء', en: 'AI engine', icon: Bot },
  FIM: { ar: 'سلامة الملفات', en: 'File integrity', icon: FileLock2 },
  SYSTEM_LOCKDOWN: { ar: 'إغلاق النظام', en: 'System lockdown', icon: Ban },
  DECEPTION: { ar: 'الخداع النشط', en: 'Deception', icon: Eye },
  DEFAULT: { ar: 'المنصة', en: 'Platform', icon: ShieldCheck }
};
const sourceOf = (s: string) => SOURCE_META[s] ?? SOURCE_META.DEFAULT;

function relTime(iso: string, isAr: boolean): string {
  const diff = Date.now() - new Date(iso).getTime();
  const m = Math.floor(diff / 60000);
  if (m < 1) return isAr ? 'الآن' : 'now';
  if (m < 60) return isAr ? `قبل ${m} د` : `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return isAr ? `قبل ${h} س` : `${h}h ago`;
  return isAr ? `قبل ${Math.floor(h / 24)} ي` : `${Math.floor(h / 24)}d ago`;
}

export const IncidentQueue: React.FC<Props> = ({ lang = 'ar' }) => {
  const isAr = lang === 'ar';
  const [events, setEvents] = useState<TelemetryEvent[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [filter, setFilter] = useState<'ALL' | 'CRITICAL' | 'HIGH'>('ALL');

  const load = async () => {
    try {
      const res = await fetch('/api/v1/soc/unified-telemetry?limit=60');
      if (!res.ok) return;
      const data = await res.json();
      if (Array.isArray(data?.events)) setEvents(data.events);
    } catch {
      /* keep last known */
    }
  };

  useEffect(() => {
    load();
    const t = setInterval(load, 5000);
    return () => clearInterval(t);
  }, []);

  /**
   * Ordering is computed once per id and then frozen. Re-sorting on every
   * poll moved rows out from under the cursor mid-read, which is the most
   * disorienting thing a live list can do; new incidents take their place in
   * the order, existing ones stay put.
   */
  const orderRef = useRef<Map<string, number>>(new Map());
  const seqRef = useRef(0);

  const rows = useMemo(() => {
    const order = orderRef.current;
    for (const e of events) {
      if (!order.has(e.id)) order.set(e.id, seqRef.current++);
    }
    const f =
      filter === 'ALL' ? events : events.filter(e => (e.severity || '').toUpperCase() === filter);
    return [...f].sort((a, b) => {
      const d = sevOf(a.severity).rank - sevOf(b.severity).rank;
      if (d !== 0) return d;
      // Within a severity, keep first-seen order stable rather than
      // re-deriving it from timestamps on every refresh.
      return (order.get(a.id) ?? 0) - (order.get(b.id) ?? 0);
    });
  }, [events, filter]);

  const counts = useMemo(
    () => ({
      ALL: events.length,
      CRITICAL: events.filter(e => (e.severity || '').toUpperCase() === 'CRITICAL').length,
      HIGH: events.filter(e => (e.severity || '').toUpperCase() === 'HIGH').length
    }),
    [events]
  );

  const selected = rows.find(r => r.id === selectedId) ?? rows[0] ?? null;
  const Chevron = isAr ? ChevronLeft : ChevronRight;

  /* ---- context + actions for the selected row ---- */
  const sameActor = useMemo(
    () => (selected?.actorIp ? events.filter(e => e.actorIp === selected.actorIp) : []),
    [events, selected]
  );
  const relatedCount = sameActor.length;
  const relatedTactics = useMemo(() => {
    const s = new Set<string>();
    sameActor.forEach(e => {
      if (e.mitreTactic) s.add(e.mitreTactic);
    });
    const out: string[] = [];
    s.forEach(v => out.push(v));
    return out;
  }, [sameActor]);

  const [busy, setBusy] = useState<string | null>(null);
  const [actionMsg, setActionMsg] = useState<string | null>(null);

  const act = async (kind: 'ban' | 'quarantine' | 'export') => {
    if (!selected) return;
    setBusy(kind);
    setActionMsg(null);
    try {
      if (kind === 'export') {
        const blob = new Blob([JSON.stringify(selected, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `${selected.id}.json`;
        a.click();
        URL.revokeObjectURL(url);
        setActionMsg(isAr ? 'تم تصدير الحادثة كملف JSON.' : 'Incident exported as JSON.');
      } else {
        const res = await fetch('/api/v1/agent/ban', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            ip: selected.actorIp,
            reason: `Operator action from incident ${selected.id}`
          })
        });
        const d = await res.json().catch(() => null);
        setActionMsg(
          res.ok
            ? isAr
              ? `تم تنفيذ الإجراء على ${selected.actorIp}.`
              : `Action applied to ${selected.actorIp}.`
            : d?.error || (isAr ? 'تعذّر تنفيذ الإجراء.' : 'Action failed.')
        );
      }
    } catch {
      setActionMsg(isAr ? 'تعذّر تنفيذ الإجراء.' : 'Action failed.');
    } finally {
      setBusy(null);
    }
  };

  return (
    <section className="soc-panel flex flex-col overflow-hidden" dir={isAr ? 'rtl' : 'ltr'}>
      {/* Header + severity filter */}
      <div className="flex items-center justify-between gap-4 border-b border-slate-800 px-5 py-4">
        <div>
          <h2 className="text-base font-bold text-slate-100">
            {isAr ? 'قائمة الحوادث' : 'Incident queue'}
          </h2>
          <p className="mt-0.5 text-xs text-slate-400">
            {isAr
              ? 'مرتّبة حسب الخطورة ثم الأحدث — والإجراء المتخذ ظاهر لكل حادثة.'
              : 'Sorted by severity, then recency — with the response already taken on every row.'}
          </p>
        </div>

        <div className="flex shrink-0 items-center gap-1.5">
          <Filter className="h-3.5 w-3.5 text-slate-500" />
          {(['ALL', 'CRITICAL', 'HIGH'] as const).map(f => (
            <button
              key={f}
              onClick={() => setFilter(f)}
              className={`rounded-md border px-2.5 py-1.5 text-[11px] font-semibold transition-colors ${
                filter === f
                  ? 'border-slate-600 bg-slate-700 text-slate-100'
                  : 'border-slate-800 bg-slate-900 text-slate-400 hover:text-slate-200 shadow-[0_0_20px_rgba(0,255,255,0.08)]'
              }`}
            >
              {f === 'ALL'
                ? isAr
                  ? 'الكل'
                  : 'All'
                : f === 'CRITICAL'
                  ? isAr
                    ? 'حرجة'
                    : 'Critical'
                  : isAr
                    ? 'عالية'
                    : 'High'}
              <span className="ms-1.5 font-mono opacity-70">{counts[f]}</span>
            </button>
          ))}
        </div>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-[minmax(0,1.55fr)_minmax(0,1fr)]">
        {/* ---- the list ---- */}
        <div className="max-h-[430px] overflow-y-auto">
          {rows.length === 0 && (
            <p className="p-5 text-xs text-slate-500">
              {isAr ? 'لا توجد حوادث مطابقة.' : 'No matching incidents.'}
            </p>
          )}

          {rows.map(ev => {
            const sev = sevOf(ev.severity);
            const src = sourceOf(ev.source);
            const SrcIcon = src.icon;
            const active = selected?.id === ev.id;

            return (
              <button
                key={ev.id}
                onClick={() => setSelectedId(ev.id)}
                className={`flex w-full items-stretch gap-0 border-b border-slate-800/70 text-start transition-colors ${active ? 'bg-slate-800/60' : 'hover:bg-slate-800/30'}`}
              >
                {/* severity rail */}
                <span className={`w-[3px] shrink-0 ${sev.rail}`} />

                <span className="min-w-0 flex-1 px-4 py-3">
                  {/* line 1: severity + time + source */}
                  <span className="mb-1.5 flex flex-wrap items-center gap-2">
                    <span
                      className={`rounded border px-1.5 py-0.5 text-[10px] font-bold ${sev.chip} ${sev.text}`}
                    >
                      {isAr ? sev.ar : sev.en}
                    </span>
                    <span className="flex items-center gap-1 font-mono text-[11px] text-slate-500">
                      <Clock className="h-3 w-3" />
                      {relTime(ev.timestamp, isAr)}
                    </span>
                    <span className="flex items-center gap-1 text-[11px] text-slate-500">
                      <SrcIcon className="h-3 w-3" />
                      {isAr ? src.ar : src.en}
                    </span>
                  </span>

                  {/* line 2: what happened */}
                  <span className="block truncate text-[13px] leading-snug font-semibold text-slate-100">
                    {isAr ? ev.titleAr || ev.title : ev.title}
                  </span>

                  {/* line 3: who + technique + response */}
                  <span className="mt-1.5 flex flex-wrap items-center gap-x-4 gap-y-1 text-[11px]">
                    {ev.actorIp && <span className="font-mono text-slate-300">{ev.actorIp}</span>}
                    {ev.mitreTechnique && (
                      <span className="max-w-[200px] truncate font-mono text-slate-500">
                        {ev.mitreTechnique.split(' - ')[0]}
                      </span>
                    )}
                    {ev.actionTaken && (
                      <span className="inline-flex items-center gap-1 font-medium text-emerald-400">
                        <ShieldCheck className="h-3 w-3" />
                        {isAr
                          ? ev.actionTakenAr || ev.actionTaken
                          : ev.actionTaken.replace(/_/g, ' ').toLowerCase()}
                      </span>
                    )}
                  </span>
                </span>

                <span className="flex items-center pe-3">
                  <Chevron className={`h-4 w-4 ${active ? 'text-slate-300' : 'text-slate-700'}`} />
                </span>
              </button>
            );
          })}
        </div>

        {/* ---- detail of the selected row ---- */}
        <aside className="border-t border-slate-800 bg-slate-900/40 p-5 xl:border-s xl:border-t-0 shadow-[0_0_20px_rgba(0,255,255,0.08)]">
          {!selected && (
            <p className="text-xs text-slate-500">
              {isAr ? 'اختر حادثة لعرض تفاصيلها.' : 'Select an incident.'}
            </p>
          )}

          {selected && (
            <div className="space-y-4">
              <div>
                <div className="soc-label mb-1.5">{isAr ? 'الحادثة' : 'Incident'}</div>
                <h3 className="text-sm leading-snug font-bold text-slate-100">
                  {isAr ? selected.titleAr || selected.title : selected.title}
                </h3>
                <p className="mt-1.5 text-[11px] leading-relaxed text-slate-400">
                  {isAr ? selected.detailsAr || selected.details : selected.details}
                </p>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <div className="soc-label mb-1">{isAr ? 'الفاعل' : 'Actor'}</div>
                  <div className="font-mono text-xs text-slate-200">{selected.actorIp || '—'}</div>
                </div>
                <div>
                  <div className="soc-label mb-1">{isAr ? 'المعرّف' : 'ID'}</div>
                  <div className="font-mono text-xs text-slate-200">{selected.id}</div>
                </div>
                <div className="col-span-2">
                  <div className="soc-label mb-1">{isAr ? 'تكتيك MITRE' : 'MITRE tactic'}</div>
                  <div className="text-xs text-slate-200">{selected.mitreTactic || '—'}</div>
                  <div className="mt-0.5 font-mono text-[11px] text-slate-500">
                    {selected.mitreTechnique || ''}
                  </div>
                </div>
              </div>

              {/* the response — the part that proves the platform acted */}
              <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/[0.07] p-3">
                <div className="soc-label mb-1.5 text-emerald-400/80">
                  {isAr ? 'الإجراء المنفّذ آلياً' : 'Automated response'}
                </div>
                <div className="flex items-start gap-2">
                  <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0 text-emerald-400" />
                  <span className="text-xs leading-snug text-emerald-200">
                    {isAr
                      ? selected.actionTakenAr || selected.actionTaken || 'تم الاحتواء'
                      : (selected.actionTaken || 'Contained').replace(/_/g, ' ')}
                  </span>
                </div>
              </div>

              {/* Related activity from the same actor — the context that turns
                  a single alert into an assessment. */}
              {selected.actorIp && (
                <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-3 shadow-[0_0_20px_rgba(0,255,255,0.08)]">
                  <div className="soc-label mb-2">
                    {isAr ? 'نشاط المصدر نفسه' : 'Same-actor activity'}
                  </div>
                  <div className="mb-2 flex items-baseline gap-2">
                    <span className="font-mono text-lg leading-none font-bold text-slate-100 tabular-nums">
                      {relatedCount}
                    </span>
                    <span className="text-[11px] text-slate-400">
                      {isAr ? 'حادثة مرتبطة بهذا العنوان' : 'incidents from this address'}
                    </span>
                  </div>
                  <div className="flex flex-wrap gap-1">
                    {relatedTactics.slice(0, 4).map(t => (
                      <span
                        key={t}
                        className="rounded border border-slate-700 bg-slate-800/60 px-1.5 py-0.5 font-mono text-[10px] text-slate-400"
                      >
                        {t}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* Operator actions — a triage surface has to be actionable. */}
              <div className="grid grid-cols-3 gap-2">
                <button
                  onClick={() => act('ban')}
                  disabled={busy !== null}
                  className="flex flex-col items-center gap-1 rounded-lg border border-slate-700 bg-slate-800/60 py-2.5 text-[11px] font-semibold text-slate-200 transition-colors hover:border-rose-500/50 hover:text-rose-300 disabled:opacity-50"
                >
                  <Ban className="h-4 w-4" />
                  {isAr ? 'حظر' : 'Block'}
                </button>
                <button
                  onClick={() => act('quarantine')}
                  disabled={busy !== null}
                  className="flex flex-col items-center gap-1 rounded-lg border border-slate-700 bg-slate-800/60 py-2.5 text-[11px] font-semibold text-slate-200 transition-colors hover:border-amber-500/50 hover:text-amber-300 disabled:opacity-50"
                >
                  <ShieldAlert className="h-4 w-4" />
                  {isAr ? 'عزل' : 'Isolate'}
                </button>
                <button
                  onClick={() => act('export')}
                  disabled={busy !== null}
                  className="flex flex-col items-center gap-1 rounded-lg border border-slate-700 bg-slate-800/60 py-2.5 text-[11px] font-semibold text-slate-200 transition-colors hover:border-cyan-500/50 hover:text-cyan-300 disabled:opacity-50"
                >
                  <Download className="h-4 w-4" />
                  {isAr ? 'تصدير' : 'Export'}
                </button>
              </div>

              {actionMsg && (
                <div className="flex items-center gap-1.5 text-[11px] text-emerald-300">
                  <ShieldCheck className="h-3.5 w-3.5" />
                  {actionMsg}
                </div>
              )}

              <div className="flex items-center gap-1.5 pt-1 font-mono text-[11px] text-slate-500">
                <Activity className="h-3 w-3" />
                {new Date(selected.timestamp).toLocaleString(isAr ? 'ar' : 'en-GB')}
              </div>
            </div>
          )}
        </aside>
      </div>
    </section>
  );
};
