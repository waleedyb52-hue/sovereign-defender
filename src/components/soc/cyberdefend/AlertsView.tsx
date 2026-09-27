import React from 'react';
import { motion } from 'motion/react';
import { Bell, ShieldAlert, Inbox, Filter } from 'lucide-react';
import { Glass, Label, Mono, Value } from './parts';
import { cn } from '../../../lib/utils';
import type { CyberDefendData } from './useCyberDefendData';

/**
 * ALERTS VIEW — the fourth tab
 *
 * The reference's navigation had four pills and only three were built. This is the
 * missing one: the alert stream, filterable by severity, with each row carrying the
 * MITRE technique and the action the platform actually took.
 *
 * Two rules from `.clauderules` shape the rows.
 *
 *   Severity is never colour alone. Each row carries a coloured rail AND the word,
 *   because roughly one man in twelve has a red/green deficiency and this is a
 *   console where red and green mean "blocked" and "allowed".
 *
 *   An unmapped technique says UNMAPPED. The hook only passes through an ID the
 *   event actually carried or one embedded in its tactic string; nothing is
 *   inferred. An analyst pivots on T-numbers, so a plausible wrong one is worse
 *   than a blank — it sends them into the wrong playbook with confidence.
 */

interface Props {
  d: CyberDefendData;
  isAr: boolean;
  reduce: boolean;
}

const SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'MODERATE', 'LOW', 'INFO', 'UNKNOWN'];

const SEVERITY_STYLE: Record<string, { rail: string; text: string; bg: string }> = {
  CRITICAL: { rail: '#EF4444', text: 'text-[#fca5a5]', bg: 'bg-[#EF4444]/10' },
  HIGH: { rail: '#EF4444', text: 'text-[#fca5a5]', bg: 'bg-[#EF4444]/8' },
  MEDIUM: { rail: '#F59E0B', text: 'text-[#fcd34d]', bg: 'bg-[#F59E0B]/8' },
  MODERATE: { rail: '#F59E0B', text: 'text-[#fcd34d]', bg: 'bg-[#F59E0B]/8' },
  LOW: { rail: '#10B981', text: 'text-[#6ee7b7]', bg: 'bg-[#10B981]/8' },
  INFO: { rail: '#38BDF8', text: 'text-[#7dd3fc]', bg: 'bg-[#38BDF8]/8' },
  UNKNOWN: { rail: '#6b7a90', text: 'text-slate-400', bg: 'bg-white/[0.03]' }
};

export const AlertsView: React.FC<Props> = ({ d, isAr, reduce }) => {
  const [filter, setFilter] = React.useState<string | null>(null);

  const counts = d.alerts.reduce<Record<string, number>>((acc, a) => {
    acc[a.severity] = (acc[a.severity] ?? 0) + 1;
    return acc;
  }, {});
  const present = SEVERITY_ORDER.filter(s => counts[s]);
  const rows = filter ? d.alerts.filter(a => a.severity === filter) : d.alerts;

  return (
    <div className="space-y-3">
      {/* Emergency banner, driven by the real lockdown flag */}
      {d.emergencyLockdown && (
        <div className="flex items-center gap-2 rounded-2xl border border-[#EF4444]/40 bg-[#EF4444]/8 px-3 py-2">
          <ShieldAlert className="h-4 w-4 shrink-0 text-[#EF4444]" aria-hidden />
          <p className="text-[11px] font-semibold text-[#fca5a5]">
            {isAr ? 'إغلاق طارئ نشط على المنصّة' : 'EMERGENCY LOCKDOWN ACTIVE ON THE PLATFORM'}
          </p>
        </div>
      )}

      {/* Severity summary, doubling as the filter */}
      <div className="grid grid-cols-2 gap-2 sm:grid-cols-4 lg:grid-cols-6">
        <SummaryTile
          label={isAr ? 'الكل' : 'All'}
          value={d.alerts.length}
          rail="#FFFFFF"
          active={filter === null}
          onClick={() => setFilter(null)}
        />
        {present.map(sev => (
          <SummaryTile
            key={sev}
            label={sev}
            value={counts[sev]}
            rail={SEVERITY_STYLE[sev]?.rail ?? '#6b7a90'}
            active={filter === sev}
            onClick={() => setFilter(filter === sev ? null : sev)}
          />
        ))}
      </div>

      <Glass>
        <div className="flex items-center justify-between gap-2 border-b border-white/5 px-3 py-2.5">
          <div className="flex items-center gap-1.5">
            <Bell className="h-3.5 w-3.5 text-[#38BDF8]" aria-hidden />
            <Label>{isAr ? 'تيّار التنبيهات' : 'Alert stream'}</Label>
          </div>
          <div className="flex items-center gap-2 text-[9px] text-slate-500">
            {filter && (
              <button
                onClick={() => setFilter(null)}
                className="flex items-center gap-1 rounded-full border border-white/10 bg-white/5 px-2 py-0.5 text-slate-300 transition-colors hover:text-white"
              >
                <Filter className="h-2.5 w-2.5" aria-hidden />
                {filter}
                <span aria-hidden>✕</span>
              </button>
            )}
            <span>
              <Mono>{rows.length}</Mono> {isAr ? 'معروضة' : 'shown'}
            </span>
          </div>
        </div>

        {rows.length === 0 ? (
          <div className="flex flex-col items-center gap-1.5 px-6 py-12 text-center">
            <Inbox className="h-5 w-5 text-slate-700" aria-hidden />
            <p className="text-[11px] text-slate-500">
              {d.alerts.length === 0
                ? isAr
                  ? 'لا أحداث في التيّار.'
                  : 'No events in the stream.'
                : isAr
                  ? 'لا تنبيهات بهذه الخطورة.'
                  : 'No alerts at this severity.'}
            </p>
            {d.alerts.length === 0 && <Mono className="text-[9px] text-slate-600">/soc/unified-telemetry</Mono>}
          </div>
        ) : (
          <div className="max-h-[560px] overflow-y-auto">
            {rows.map((a, i) => {
              const st = SEVERITY_STYLE[a.severity] ?? SEVERITY_STYLE.UNKNOWN;
              return (
                <motion.div
                  key={a.id}
                  initial={reduce ? { opacity: 0 } : { opacity: 0, x: isAr ? 6 : -6 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: reduce ? 0 : Math.min(i * 0.02, 0.3), duration: 0.2 }}
                  className="flex gap-2.5 border-b border-white/[0.04] px-3 py-2 transition-colors hover:bg-white/[0.02]"
                >
                  {/* Severity rail — colour plus the word below, never colour alone */}
                  <div className="flex w-16 shrink-0 flex-col items-start gap-1">
                    <span className="h-full w-[3px] rounded-full" style={{ background: st.rail }} aria-hidden />
                    <span className={cn('text-[8px] font-bold tracking-wider', st.text)}>{a.severity}</span>
                  </div>

                  <div className="min-w-0 flex-1">
                    <p className="truncate text-[11px] text-slate-200" title={a.title}>
                      {a.title || (isAr ? '(بلا عنوان)' : '(untitled)')}
                    </p>
                    {a.details && (
                      <p className="mt-0.5 line-clamp-2 text-[9px] leading-relaxed text-slate-500">{a.details}</p>
                    )}
                    <div className="mt-1 flex flex-wrap items-center gap-2 text-[8px]">
                      <Mono className="text-slate-600">{a.at.slice(0, 19).replace('T', ' ')}</Mono>
                      {a.mitre ? (
                        <Mono className="text-[#7dd3fc]">{a.mitre}</Mono>
                      ) : (
                        <span className="tracking-wider text-slate-600">UNMAPPED</span>
                      )}
                      {a.srcIp && <Mono className="text-slate-500">{a.srcIp}</Mono>}
                      {a.source && <span className="text-slate-600">{a.source}</span>}
                    </div>
                  </div>

                  <div className="w-[120px] shrink-0 text-end">
                    <Label>{isAr ? 'الإجراء' : 'Action'}</Label>
                    <p className={cn('truncate text-[9px]', a.action ? 'text-slate-300' : 'text-slate-600')} title={a.action ?? undefined}>
                      {a.action ?? '—'}
                    </p>
                  </div>
                </motion.div>
              );
            })}
          </div>
        )}
      </Glass>
    </div>
  );
};

const SummaryTile: React.FC<{
  label: string;
  value: number;
  rail: string;
  active: boolean;
  onClick: () => void;
}> = ({ label, value, rail, active, onClick }) => (
  <button
    onClick={onClick}
    aria-pressed={active}
    className={cn(
      'rounded-xl border px-2.5 py-2 text-start transition-colors',
      'focus-visible:ring-2 focus-visible:ring-[#38BDF8]/60 focus-visible:outline-none',
      active ? 'border-white/25 bg-white/[0.07]' : 'border-white/8 bg-white/[0.02] hover:border-white/15'
    )}
  >
    <div className="flex items-center gap-1.5">
      <span className="h-2 w-2 rounded-full" style={{ background: rail }} aria-hidden />
      <span className="truncate text-[8px] tracking-wider text-slate-500 uppercase">{label}</span>
    </div>
    <p className="mt-1 text-[15px] font-bold text-white">
      <Value v={value} />
    </p>
  </button>
);
