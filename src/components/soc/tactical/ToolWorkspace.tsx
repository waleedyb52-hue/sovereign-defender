import React from 'react';
import { Cpu, ShieldCheck, FileLock2, Radar, Globe2, Lock, Server, Network, X, LayoutList, ScrollText, Users } from 'lucide-react';
import { CyberButton } from './CyberButton';

/**
 * TOOL WORKSPACE — the defensive tools get room to be used.
 *
 * The arsenal lived as collapsible cards in a rail about 200px wide. That is enough to
 * show a headline number and nothing else: a FIM hash line, a WAF rule grid or a device
 * inventory cannot be read in that space, let alone worked in. So each tool now also
 * opens into a full workspace over the theatre, with an index of every tool down the side
 * — which is the "dedicated list" the rail could not provide.
 *
 * The rail stays. It is the always-visible status strip for the arsenal: an operator needs
 * to see that FIM has a critical alert without opening FIM. Expanding is for working;
 * the rail is for noticing. Replacing one with the other would cost whichever job it
 * dropped.
 *
 * Each tool's badge carries its own live headline so the index shows state without being
 * opened, and a tool whose feed is silent says so rather than showing an empty frame that
 * looks like a clean result.
 */

export type ToolId = 'FLEET' | 'NETWORK' | 'EBPF' | 'WAF' | 'FIM' | 'SCANNER' | 'INTEL' | 'ZTNA' | 'AUDIT' | 'OPERATORS';

export interface ToolSpec {
  id: ToolId;
  icon: React.ElementType;
  ar: string;
  en: string;
  /** Short live headline for the index, e.g. "5/7" or "2 CRIT". Null renders a dash. */
  badge?: string | null;
  /** Set when the tool needs attention, which tints its index row. */
  alert?: boolean;
  /** Named when the tool's feed is unreachable, so a quiet panel is explained. */
  silentEndpoint?: string | null;
}

export const TOOL_ICONS: Record<ToolId, React.ElementType> = {
  FLEET: Server,
  NETWORK: Network,
  EBPF: Cpu,
  WAF: ShieldCheck,
  FIM: FileLock2,
  SCANNER: Radar,
  INTEL: Globe2,
  ZTNA: Lock,
  AUDIT: ScrollText,
  OPERATORS: Users
};

export const ToolWorkspace: React.FC<{
  tools: ToolSpec[];
  active: ToolId;
  isAr: boolean;
  onSelect: (id: ToolId) => void;
  onClose: () => void;
  children: React.ReactNode;
}> = ({ tools, active, isAr, onSelect, onClose, children }) => {
  // Escape closes. A full-surface overlay with no keyboard exit traps anyone who opened
  // it by accident, and an operator mid-incident should never have to hunt for a way out.
  React.useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);

  const current = tools.find(t => t.id === active);

  return (
    <div
      className="absolute inset-2 z-30 flex border border-cyan-500/40 bg-[#030712]/95 shadow-[0_0_40px_rgba(0,0,0,0.92)] backdrop-blur-2xl"
      role="dialog"
      aria-modal="false"
      aria-label={isAr ? 'مساحة عمل الأدوات الدفاعية' : 'Defensive tool workspace'}
    >
      {/* Index: the list of every defensive tool, with live state. */}
      <nav className="flex w-[186px] shrink-0 flex-col border-e border-cyan-900/50 bg-black/40">
        <div className="flex items-center gap-1.5 border-b border-cyan-900/50 px-2 py-2">
          <LayoutList className="h-3 w-3 text-cyan-400" aria-hidden />
          <span className="font-mono text-[7px] font-bold tracking-widest text-cyan-400 uppercase">
            {isAr ? 'الترسانة الدفاعية' : 'DEFENSIVE ARSENAL'}
          </span>
        </div>

        <div className="min-h-0 flex-1 overflow-y-auto py-1">
          {tools.map(t => {
            const Icon = t.icon;
            const on = t.id === active;
            return (
              <button
                key={t.id}
                type="button"
                onClick={() => onSelect(t.id)}
                aria-current={on ? 'true' : undefined}
                className="flex w-full items-center gap-2 border-s-2 px-2 py-1.5 text-start transition-colors"
                style={{
                  borderInlineStartColor: on ? '#22d3ee' : t.alert ? '#e11d48' : 'transparent',
                  background: on ? 'rgba(34,211,238,0.09)' : 'transparent'
                }}
              >
                <Icon
                  className="h-3 w-3 shrink-0"
                  strokeWidth={1.5}
                  style={{ color: on ? '#22d3ee' : t.alert ? '#fb7185' : '#5c7484' }}
                  aria-hidden
                />
                <span className="min-w-0 flex-1">
                  <span
                    className="block truncate font-mono text-[7.5px] tracking-wider uppercase"
                    style={{ color: on ? '#e6edf3' : '#8aa4b8' }}
                  >
                    {isAr ? t.ar : t.en}
                  </span>
                  {t.silentEndpoint && (
                    <span className="block truncate font-mono text-[5.5px] text-rose-400/80">
                      {isAr ? 'مصدر صامت' : 'SOURCE SILENT'}
                    </span>
                  )}
                </span>
                <span
                  className="shrink-0 font-mono text-[8px] font-bold tabular-nums"
                  style={{ color: t.alert ? '#fb7185' : on ? '#22d3ee' : '#5c7484' }}
                >
                  {t.badge ?? '—'}
                </span>
              </button>
            );
          })}
        </div>

        <p className="border-t border-cyan-900/50 px-2 py-1.5 font-mono text-[6px] leading-relaxed text-slate-600">
          {isAr
            ? 'الشريحة الجانبية تبقى ظاهرة للتنبيه؛ هذه المساحة للعمل. ESC للإغلاق.'
            : 'the rail stays visible for noticing; this space is for working. ESC closes.'}
        </p>
      </nav>

      {/* Working area */}
      <section className="flex min-w-0 flex-1 flex-col">
        <header className="flex shrink-0 items-center gap-2 border-b border-cyan-900/50 px-3 py-2">
          {current && (
            <>
              <current.icon className="h-3.5 w-3.5 text-cyan-400" strokeWidth={1.5} aria-hidden />
              <h2
                className="font-mono text-[11px] font-bold tracking-widest text-white uppercase"
                style={{ textShadow: '0 0 10px rgba(34,211,238,0.5)' }}
              >
                {isAr ? current.ar : current.en}
              </h2>
              {current.silentEndpoint && (
                <span className="font-mono text-[6.5px] text-rose-400">{current.silentEndpoint}</span>
              )}
            </>
          )}
          <span className="ms-auto flex items-center gap-1">
            <CyberButton tone="cyan" size="sm" onClick={onClose}>
              <span className="flex items-center gap-1">
                <X className="h-2.5 w-2.5" aria-hidden />
                {isAr ? '[ إغلاق ]' : '[ CLOSE ]'}
              </span>
            </CyberButton>
          </span>
        </header>

        <div className="min-h-0 flex-1 overflow-y-auto p-3">{children}</div>
      </section>
    </div>
  );
};

export default ToolWorkspace;
