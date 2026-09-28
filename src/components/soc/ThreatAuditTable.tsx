import React from 'react';
import { motion, AnimatePresence, useReducedMotion } from 'motion/react';
import { Copy, Check, ArrowUpDown, Inbox, Ban } from 'lucide-react';
import {
  Card,
  CardHeader,
  CardTitle,
  Table,
  THead,
  TBody,
  TR,
  TH,
  TD,
  Badge,
  Button,
  Mono
} from '../ui/primitives';
import type { BadgeTone } from '../ui/primitives';
import { cn } from '../../lib/utils';
import type { ThreatEvent } from '../../hooks/useTelemetry';

/**
 * THREAT AUDIT TABLE
 *
 * Sortable, with ISO 8601 timestamps, monospaced source addresses, MITRE
 * technique on every row, and an isolate action per row.
 *
 * On MITRE identifiers
 *   The rule is that every alert shows its technique. The rule this code follows
 *   is that it shows the technique the *event carried* — a tactic name is mapped
 *   to its canonical ID only where that mapping is unambiguous, and anything else
 *   renders UNMAPPED. Guessing an ID would be worse than leaving it blank: an
 *   analyst pivots on T-numbers, and a plausible wrong one sends them into the
 *   wrong playbook.
 *
 * On the arrival animation
 *   New rows slide from the top with a decaying amber glow, but only rows that
 *   are genuinely new since the previous poll — the feed hook suppresses the
 *   first load, so mounting does not animate the whole table as if it had just
 *   arrived. Under `prefers-reduced-motion` the movement is dropped and only the
 *   opacity change remains; a console watched for a twelve-hour shift cannot
 *   force motion on someone who asked for none.
 */

interface Props {
  events: ThreatEvent[];
  freshIds: Set<string>;
  loading?: boolean;
  error?: string | null;
  lang?: 'ar' | 'en';
  onIsolate: (ip: string) => void;
  isolating?: string | null;
}

type SortKey = 'timestamp' | 'severity' | 'source' | 'mitre';

/**
 * Tactic → canonical technique ID, for the tactics this platform actually emits.
 * Intentionally sparse: an entry exists only where the mapping is unambiguous.
 */
const TACTIC_TO_TECHNIQUE: Record<string, { id: string; name: string }> = {
  execution: { id: 'T1059', name: 'Command and Scripting Interpreter' },
  impact: { id: 'T1486', name: 'Data Encrypted for Impact' },
  'initial access': { id: 'T1190', name: 'Exploit Public-Facing Application' },
  'credential access': { id: 'T1110', name: 'Brute Force' },
  exfiltration: { id: 'T1048', name: 'Exfiltration Over Alternative Protocol' },
  'lateral movement': { id: 'T1021', name: 'Remote Services' },
  'defense evasion': { id: 'T1070', name: 'Indicator Removal' },
  discovery: { id: 'T1046', name: 'Network Service Discovery' },
  persistence: { id: 'T1543', name: 'Create or Modify System Process' },
  reconnaissance: { id: 'T1595', name: 'Active Scanning' }
};

/**
 * The technique the event itself names, or null (rendered UNMAPPED).
 *
 * This used to fall back to TACTIC_TO_TECHNIQUE — "Defense Evasion" became T1070 — which
 * is a guess dressed as a mapping, and `.clauderules` §7 forbids exactly that. It also
 * ignored `mitreTechnique`, the field unified telemetry actually fills, so real mappings
 * were being replaced by inferred ones. The table below now only supplies a display
 * name for an ID the event already carries.
 */
function techniqueFor(e: ThreatEvent): { id: string; name?: string } | null {
  if (e.mitreId && /^T\d{4}(\.\d{3})?$/.test(e.mitreId)) {
    return { id: e.mitreId, name: Object.values(TACTIC_TO_TECHNIQUE).find(t => t.id === e.mitreId)?.name };
  }
  // "T1486 - Data Encrypted for Impact"
  const tech = e.mitreTechnique?.match(/^\s*(T\d{4}(?:\.\d{3})?)\s*(?:[-–:]\s*(.+))?$/i);
  if (tech) return { id: tech[1].toUpperCase(), name: tech[2]?.trim() };
  // A tactic string may embed its ID, e.g. "Credential Access (T1110.001)".
  const embedded = e.mitreTactic?.match(/t\d{4}(\.\d{3})?/i);
  if (embedded) return { id: embedded[0].toUpperCase() };
  return null;
}

const SEVERITY_TONE: Record<string, BadgeTone> = {
  critical: 'quarantine',
  high: 'quarantine',
  medium: 'tarpit',
  moderate: 'tarpit',
  low: 'secure',
  info: 'ebpf'
};

const SEVERITY_RANK: Record<string, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  moderate: 3,
  low: 2,
  info: 1
};

function sourceIpOf(e: ThreatEvent): string | null {
  return e.srcIp ?? e.sourceIp ?? e.actorIp ?? null;
}

const CopyableIp: React.FC<{ ip: string; lang: 'ar' | 'en' }> = ({ ip, lang }) => {
  const [done, setDone] = React.useState(false);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(ip);
      setDone(true);
      setTimeout(() => setDone(false), 1400);
    } catch {
      /* Clipboard blocked (insecure context or denied permission). The address
         is still selectable, so this degrades rather than fails. */
    }
  };
  return (
    <span className="inline-flex items-center gap-1">
      <Mono className="text-slate-300">{ip}</Mono>
      <button
        onClick={copy}
        aria-label={lang === 'ar' ? `نسخ ${ip}` : `Copy ${ip}`}
        className="text-slate-600 transition-colors hover:text-[#67e8f9]"
      >
        {done ? <Check className="h-3 w-3 text-[#6ee7b7]" /> : <Copy className="h-3 w-3" />}
      </button>
    </span>
  );
};

export const ThreatAuditTable: React.FC<Props> = ({
  events,
  freshIds,
  loading,
  error,
  lang = 'ar',
  onIsolate,
  isolating
}) => {
  const isAr = lang === 'ar';
  const reduce = useReducedMotion();
  const [sortKey, setSortKey] = React.useState<SortKey>('timestamp');
  const [asc, setAsc] = React.useState(false);

  const sorted = React.useMemo(() => {
    const rows = [...events];
    rows.sort((a, b) => {
      let d = 0;
      switch (sortKey) {
        case 'timestamp':
          d = new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime();
          break;
        case 'severity':
          d =
            (SEVERITY_RANK[a.severity?.toLowerCase() ?? ''] ?? 0) -
            (SEVERITY_RANK[b.severity?.toLowerCase() ?? ''] ?? 0);
          break;
        case 'source':
          d = (sourceIpOf(a) ?? '').localeCompare(sourceIpOf(b) ?? '');
          break;
        case 'mitre':
          d = (techniqueFor(a)?.id ?? '').localeCompare(techniqueFor(b)?.id ?? '');
          break;
      }
      return asc ? d : -d;
    });
    return rows;
  }, [events, sortKey, asc]);

  const toggle = (k: SortKey) => {
    if (k === sortKey) setAsc(v => !v);
    else {
      setSortKey(k);
      setAsc(false);
    }
  };

  const SortHead: React.FC<{ k: SortKey; children: React.ReactNode; className?: string }> = ({
    k,
    children,
    className
  }) => (
    <TH sorted={sortKey === k ? (asc ? 'asc' : 'desc') : false} className={className}>
      <button
        onClick={() => toggle(k)}
        className="inline-flex items-center gap-1 transition-colors hover:text-slate-200"
      >
        {children}
        <ArrowUpDown
          className={cn('h-2.5 w-2.5', sortKey === k ? 'text-[#67e8f9]' : 'text-slate-600')}
        />
      </button>
    </TH>
  );

  return (
    <Card dir={isAr ? 'rtl' : 'ltr'}>
      <CardHeader>
        <CardTitle>{isAr ? 'سجل تدقيق التهديدات' : 'THREAT AUDIT LOG'}</CardTitle>
        <Badge
          tone="neutral"
          label={isAr ? `${events.length} حدث` : `${events.length} events`}
          mono
        />
      </CardHeader>

      {error && (
        <div className="mx-4 mb-3 rounded border border-[#f43f5e]/30 bg-[#f43f5e]/5 px-3 py-2 text-[11px] text-[#fda4af]">
          {isAr ? 'تعذّر تحميل السجل: ' : 'Could not load the log: '}
          <Mono className="text-[10px]">{error}</Mono>
        </div>
      )}

      {!error && events.length === 0 && (
        <div className="flex flex-col items-center gap-1.5 px-6 py-10 text-center">
          <Inbox className="h-5 w-5 text-slate-700" aria-hidden />
          <p className="text-[11px] text-slate-500">
            {loading
              ? isAr
                ? 'جارٍ التحميل…'
                : 'Loading…'
              : isAr
                ? 'لا أحداث في السجل.'
                : 'No events in the log.'}
          </p>
          {!loading && (
            <Mono className="text-[9px] text-slate-600">/api/v1/soc/unified-telemetry</Mono>
          )}
        </div>
      )}

      {events.length > 0 && (
        <div className="overflow-x-auto border-t border-slate-800/80">
          <Table>
            <THead>
              <TR className="hover:bg-transparent">
                <SortHead k="timestamp">
                  {isAr ? 'الوقت (ISO 8601)' : 'Timestamp (ISO 8601)'}
                </SortHead>
                <SortHead k="severity">{isAr ? 'الخطورة' : 'Severity'}</SortHead>
                <SortHead k="source">{isAr ? 'المصدر' : 'Source'}</SortHead>
                <SortHead k="mitre">MITRE</SortHead>
                <TH>{isAr ? 'نوع الهجوم' : 'Attack type'}</TH>
                <TH>{isAr ? 'الإجراء المتخذ' : 'Action taken'}</TH>
                <TH className="text-right">{isAr ? 'تحكّم' : 'Control'}</TH>
              </TR>
            </THead>
            <TBody>
              <AnimatePresence initial={false}>
                {sorted.map(e => {
                  const fresh = freshIds.has(e.id);
                  const tech = techniqueFor(e);
                  const ip = sourceIpOf(e);
                  const sev = e.severity?.toLowerCase() ?? '';
                  return (
                    <motion.tr
                      key={e.id}
                      layout={!reduce}
                      initial={reduce ? { opacity: 0 } : { opacity: 0, y: -8 }}
                      animate={{
                        opacity: 1,
                        y: 0,
                        // Amber glow that decays to nothing. Only for rows that
                        // genuinely arrived since the last poll.
                        backgroundColor:
                          fresh && !reduce
                            ? ['rgba(245,158,11,0.16)', 'rgba(245,158,11,0)']
                            : 'rgba(0,0,0,0)'
                      }}
                      exit={reduce ? { opacity: 0 } : { opacity: 0, y: -4 }}
                      transition={{
                        duration: 0.22,
                        ease: 'easeOut',
                        backgroundColor: { duration: 1.2, ease: 'easeOut' }
                      }}
                      className="border-b border-slate-800/50 transition-colors hover:bg-slate-800/25"
                    >
                      <TD mono className="whitespace-nowrap text-slate-400">
                        {e.timestamp}
                      </TD>
                      <TD>
                        <Badge
                          tone={SEVERITY_TONE[sev] ?? 'neutral'}
                          label={(e.severity ?? 'UNKNOWN').toUpperCase()}
                        />
                      </TD>
                      <TD>
                        {ip ? (
                          <CopyableIp ip={ip} lang={lang} />
                        ) : (
                          <span className="text-slate-600">{e.source ?? '—'}</span>
                        )}
                      </TD>
                      <TD>
                        {tech ? (
                          <span className="inline-flex items-center gap-1.5">
                            <Mono className="text-[#67e8f9]">{tech.id}</Mono>
                            {tech.name && (
                              <span className="hidden max-w-[150px] truncate text-[10px] text-slate-500 lg:inline">
                                {tech.name}
                              </span>
                            )}
                          </span>
                        ) : (
                          // Never a guess. An analyst pivots on these.
                          <span className="text-[10px] tracking-wider text-slate-600">
                            UNMAPPED
                          </span>
                        )}
                      </TD>
                      <TD className="max-w-[220px]">
                        <span
                          className="block truncate text-slate-300"
                          title={(isAr ? e.titleAr : e.title) ?? ''}
                        >
                          {(isAr ? e.titleAr : e.title) ?? e.source ?? '—'}
                        </span>
                      </TD>
                      <TD className="max-w-[170px]">
                        <span
                          className="block truncate text-[10px] text-slate-400"
                          title={(isAr ? e.actionTakenAr : e.actionTaken) ?? ''}
                        >
                          {(isAr ? e.actionTakenAr : e.actionTaken) ?? '—'}
                        </span>
                      </TD>
                      <TD className="text-right">
                        {ip ? (
                          <Button
                            variant="danger"
                            size="sm"
                            disabled={isolating === ip}
                            onClick={() => onIsolate(ip)}
                          >
                            <Ban className="h-3 w-3" aria-hidden />
                            {isolating === ip
                              ? isAr
                                ? 'جارٍ…'
                                : 'Working…'
                              : isAr
                                ? 'عزل'
                                : 'Isolate'}
                          </Button>
                        ) : (
                          <span
                            className="text-[9px] text-slate-600"
                            title={
                              isAr
                                ? 'لا عنوان مصدر في هذا الحدث'
                                : 'no source address on this event'
                            }
                          >
                            —
                          </span>
                        )}
                      </TD>
                    </motion.tr>
                  );
                })}
              </AnimatePresence>
            </TBody>
          </Table>
        </div>
      )}
    </Card>
  );
};
