import React from 'react';
import { Bug } from 'lucide-react';
import { ArsenalCard } from './CyberButton';
import type { useArsenal } from './useArsenal';

type Arsenal = ReturnType<typeof useArsenal>;

/**
 * HONEYPOT SENSOR GRID — one cell per decoy, lit by what adversaries do inside it.
 *
 * Two sources, kept in separate cells because they are different kinds of evidence:
 *
 *   /honeypot/sessions         interactive decoy services (SSH bait, admin APIs…)
 *   /soc/deception/entrapped   actors the shadow router diverted out of LIVE traffic
 *
 * FIXTURES. Every session /honeypot/sessions returns on a fresh server is a seeded
 * record, and nothing on the server adds new ones. Those records carry no provenance
 * flag, but their attacker addresses sit in RFC 5737 documentation ranges — 192.0.2/24,
 * 198.51.100/24, 203.0.113/24 — which are reserved for examples and cannot originate
 * real internet traffic. So a session from one of them is labelled FIXTURE, drawn in
 * slate rather than amber, and excluded from the engaged count. That is a fact read off
 * the address, not a guess about the record.
 *
 * ENGAGED means a non-fixture actor interacted within the last five minutes. The headline
 * counts only those, so a quiet grid reads 0 rather than a seeded total.
 */

const DOC_RANGES = [/^192\.0\.2\./, /^198\.51\.100\./, /^203\.0\.113\./, /^2001:db8:/i];
const isFixture = (ip: string | null) => ip != null && DOC_RANGES.some(r => r.test(ip));

const ENGAGED_MS = 5 * 60_000;

const toMs = (t: string | number | null) => (t == null ? null : typeof t === 'number' ? t : Date.parse(t) || null);

const riskHex = (r: string | null) => (r === 'CRITICAL' ? '#fb7185' : r === 'HIGH' ? '#fbbf24' : '#94a3b8');

/** "T1190 - Exploit Public-Facing Application" → "T1190". */
const tId = (t: string | null) => (t ? (t.split(' ')[0] ?? t) : null);

type CellState = 'ENGAGED' | 'IDLE' | 'FIXTURE';

const STATE_STYLE: Record<CellState, { border: string; fg: string; label: [string, string] }> = {
  ENGAGED: { border: 'rgba(245,158,11,0.6)', fg: '#fbbf24', label: ['مشتبك', 'ENGAGED'] },
  IDLE: { border: 'rgba(22,78,99,0.6)', fg: '#22d3ee', label: ['خامل', 'IDLE'] },
  FIXTURE: { border: 'rgba(71,85,105,0.5)', fg: '#94a3b8', label: ['بيانات تجريبية', 'FIXTURE'] }
};

const Cell: React.FC<{ title: string; state: CellState; isAr: boolean; children: React.ReactNode }> = ({
  title, state, isAr, children
}) => {
  const st = STATE_STYLE[state];
  return (
    <div className="min-w-0 border bg-black/50 p-1.5" style={{ borderColor: st.border }}>
      <div className="flex items-center gap-1">
        <span
          className={`h-1.5 w-1.5 shrink-0 ${state === 'ENGAGED' ? 'motion-safe:animate-pulse' : ''}`}
          style={{ background: st.fg, boxShadow: state === 'ENGAGED' ? `0 0 6px ${st.fg}` : undefined }}
          aria-hidden
        />
        <span className="min-w-0 truncate font-mono text-[10px] font-semibold tracking-wider text-slate-200" title={title}>
          {title}
        </span>
        <span className="ms-auto shrink-0 font-mono text-[10px] tracking-wider" style={{ color: st.fg }}>
          {isAr ? st.label[0] : st.label[1]}
        </span>
      </div>
      <div className="mt-1 space-y-0.5">{children}</div>
    </div>
  );
};

export const HoneypotSensorGrid: React.FC<{ a: Arsenal; isAr: boolean }> = ({ a, isAr }) => {
  const now = Date.now();
  const hpSilent = a.missing.includes('/honeypot/sessions');
  const shSilent = a.missing.includes('/soc/deception/entrapped');

  const services = React.useMemo(() => {
    const m = new Map<string, typeof a.intel.sessions>();
    for (const s of a.intel.sessions) {
      const k = s.service ?? 'UNNAMED_DECOY';
      m.set(k, [...(m.get(k) ?? []), s]);
    }
    return [...m.entries()];
  }, [a.intel.sessions]);

  const actors = a.intel.shadow.actors;

  const engagedSessions = a.intel.sessions.filter(s => {
    const t = toMs(s.lastAt ?? s.at);
    return !isFixture(s.ip) && t != null && now - t < ENGAGED_MS;
  }).length;
  const engagedActors = actors.filter(x => {
    const t = toMs(x.lastAt);
    return !isFixture(x.ip) && t != null && now - t < ENGAGED_MS;
  }).length;
  const engaged = hpSilent && shSilent ? null : engagedSessions + engagedActors;

  return (
    <ArsenalCard
      title={isAr ? 'شبكة مستشعرات المصائد' : 'HONEYPOT SENSOR GRID'}
      icon={Bug}
      tone={engaged ? 'amber' : 'cyan'}
      alert={Boolean(engaged)}
      headline={
        engaged == null ? (
          <span className="font-mono text-[10px] text-slate-500">—</span>
        ) : (
          <span
            className="font-mono text-xs font-bold tabular-nums"
            style={{ color: engaged ? '#fbbf24' : '#22d3ee' }}
            title={isAr ? 'جهات فاعلة غير تجريبية تفاعلت خلال ٥ دقائق' : 'non-fixture actors active in the last 5 min'}
          >
            {engaged}
          </span>
        )
      }
    >
      <div className="grid grid-cols-2 gap-1">
        {/* Interactive decoy services */}
        {hpSilent ? (
          <p className="col-span-2 font-mono text-[10px] text-slate-400">
            {isAr ? 'مصدر صامت · ' : 'SOURCE SILENT · '}/honeypot/sessions
          </p>
        ) : services.length === 0 ? (
          <p className="col-span-2 font-mono text-[10px] text-slate-400">
            {isAr ? 'لا جلسات مصائد · ' : 'NO DECOY SESSIONS · '}/honeypot/sessions
          </p>
        ) : (
          services.map(([svc, sessions]) => {
            const allFixture = sessions.every(s => isFixture(s.ip));
            const live = sessions.some(s => {
              const t = toMs(s.lastAt ?? s.at);
              return !isFixture(s.ip) && t != null && now - t < ENGAGED_MS;
            });
            return (
              <Cell key={svc} title={svc} state={live ? 'ENGAGED' : allFixture ? 'FIXTURE' : 'IDLE'} isAr={isAr}>
                {sessions.slice(0, 2).map(s => {
                  const last = s.commands[s.commands.length - 1] ?? null;
                  const fx = isFixture(s.ip);
                  return (
                    <div key={s.id} className="min-w-0">
                      <div className="flex items-baseline gap-1 font-mono text-[10px]" dir="ltr">
                        <span className={fx ? 'text-slate-400' : 'text-amber-300'}>{s.ip ?? '—'}</span>
                        {fx && <span className="text-slate-500">RFC5737</span>}
                      </div>
                      <p className="font-mono text-[10px] text-slate-400">
                        {s.keystrokes ?? '—'} {isAr ? 'ضغطة' : 'KS'} · {s.canaries} {isAr ? 'كناري' : 'CANARY'}
                      </p>
                      {last && (
                        <p
                          className="truncate font-mono text-[10px]"
                          style={{ color: fx ? '#94a3b8' : riskHex(last.risk) }}
                          title={last.cmd}
                          dir="ltr"
                        >
                          $ {last.cmd}
                        </p>
                      )}
                    </div>
                  );
                })}
                {sessions.length > 2 && <p className="font-mono text-[10px] text-slate-500">+{sessions.length - 2}</p>}
              </Cell>
            );
          })
        )}

        {/* Shadow router — diversions out of live traffic */}
        <div className="col-span-2">
          <Cell
            title={isAr ? 'الموجّه الظلّي · حركة حيّة' : 'SHADOW ROUTER · LIVE TRAFFIC'}
            state={engagedActors > 0 ? 'ENGAGED' : 'IDLE'}
            isAr={isAr}
          >
            {shSilent ? (
              <p className="font-mono text-[10px] text-slate-400">
                {isAr ? 'مصدر صامت · ' : 'SOURCE SILENT · '}/soc/deception/entrapped
              </p>
            ) : (
              <>
                <p className="font-mono text-[10px] text-slate-400">
                  {isAr ? 'مُحوَّل إجمالًا' : 'DIVERTED'}{' '}
                  <span className="text-cyan-400">{a.intel.shadow.diverted ?? '—'}</span>
                  {' · '}
                  {isAr ? 'تفاعلات' : 'INTERACTIONS'}{' '}
                  <span className="text-cyan-400">{a.intel.shadow.interactions ?? '—'}</span>
                </p>
                {actors.length === 0 ? (
                  <p className="font-mono text-[10px] text-slate-500">
                    {isAr ? 'لا جهات محتجزة الآن' : 'no actors held in a decoy right now'}
                  </p>
                ) : (
                  actors.slice(0, 4).map(x => (
                    <div key={x.id} className="flex min-w-0 items-baseline gap-1.5 font-mono text-[10px]" dir="ltr">
                      <span className="shrink-0 text-amber-300">{x.ip ?? '—'}</span>
                      <span className="shrink-0 text-slate-400">{x.band ?? '—'}</span>
                      <span className="shrink-0 text-slate-400">×{x.interactions ?? '—'}</span>
                      {x.canariesRedeemed > 0 && (
                        <span className="shrink-0 text-rose-400">
                          {x.canariesRedeemed} {isAr ? 'كناري مُستردّ' : 'CANARY REDEEMED'}
                        </span>
                      )}
                      <span className={`ms-auto shrink-0 ${x.technique ? 'text-cyan-400' : 'text-slate-500'}`}>
                        {tId(x.technique) ?? 'UNMAPPED'}
                      </span>
                    </div>
                  ))
                )}
              </>
            )}
          </Cell>
        </div>
      </div>
    </ArsenalCard>
  );
};

export default HoneypotSensorGrid;
