import React from 'react';

/**
 * CHAMFERED CYBER BUTTON — the blueprint from the design lexicon.
 *
 * One component rather than the class string repeated at each call site, because the
 * chamfer geometry, the disabled treatment and the focus ring have to agree everywhere
 * or the surface stops looking machined.
 *
 * Two departures from the blueprint string, both deliberate:
 *
 *   `clip-path-[...]` is not a Tailwind utility — there is no `clip-path` plugin in
 *   this project and an unrecognised class compiles to nothing, so the chamfer would
 *   have silently not rendered. It is applied as an inline style instead.
 *
 *   Disabled buttons lose the glow and the accent entirely rather than being dimmed.
 *   On a containment control that distinction is not cosmetic: an operator reaching
 *   for ISOLATE_NODE during an incident needs to know at a glance whether the button
 *   is armed, and a merely dimmed neon button still reads as live.
 */

export type CyberTone = 'cyan' | 'rose' | 'amber' | 'emerald';

const TONE: Record<CyberTone, { fg: string; border: string; bg: string; glow: string }> = {
  cyan: { fg: '#22d3ee', border: '#22d3ee', bg: 'rgba(8,51,68,0.4)', glow: 'rgba(34,211,238,0.5)' },
  rose: { fg: '#fb7185', border: '#e11d48', bg: 'rgba(76,5,25,0.4)', glow: 'rgba(225,29,72,0.5)' },
  amber: { fg: '#fbbf24', border: '#f59e0b', bg: 'rgba(69,39,3,0.4)', glow: 'rgba(251,191,36,0.5)' },
  emerald: { fg: '#34d399', border: '#10b981', bg: 'rgba(2,44,34,0.4)', glow: 'rgba(16,185,129,0.5)' }
};

const chamfer = (c: number) =>
  `polygon(${c}px 0, 100% 0, 100% calc(100% - ${c}px), calc(100% - ${c}px) 100%, 0 100%, 0 ${c}px)`;

export const CyberButton: React.FC<{
  children: React.ReactNode;
  tone?: CyberTone;
  size?: 'sm' | 'md';
  disabled?: boolean;
  active?: boolean;
  title?: string;
  className?: string;
  onClick?: () => void;
  /** 'submit' inside a form; everything else stays a plain button. */
  type?: 'button' | 'submit';
}> = ({ children, tone = 'cyan', size = 'md', disabled, active, title, className = '', onClick, type = 'button' }) => {
  const t = TONE[tone];
  const cut = size === 'sm' ? 6 : 10;

  return (
    <button
      type={type}
      onClick={onClick}
      disabled={disabled}
      title={title}
      className={`group relative font-mono uppercase tracking-widest transition-all duration-200 disabled:cursor-not-allowed ${
        size === 'sm' ? 'px-2.5 py-1 text-[10px]' : 'px-5 py-2 text-xs'
      } ${className}`}
      style={{
        clipPath: chamfer(cut),
        border: `1px solid ${disabled ? 'rgba(148,163,184,0.18)' : t.border}`,
        background: disabled ? 'rgba(255,255,255,0.015)' : active ? t.border + '33' : t.bg,
        color: disabled ? '#64748b' : t.fg,
        boxShadow: disabled ? 'none' : active ? `0 0 20px ${t.glow}` : `0 0 10px ${t.glow}44`,
        textShadow: disabled ? 'none' : `0 0 8px ${t.glow}`
      }}
      onMouseEnter={e => {
        if (!disabled) e.currentTarget.style.boxShadow = `0 0 20px ${t.glow}`;
      }}
      onMouseLeave={e => {
        if (!disabled) e.currentTarget.style.boxShadow = active ? `0 0 20px ${t.glow}` : `0 0 10px ${t.glow}44`;
      }}
    >
      {children}
    </button>
  );
};

/**
 * Collapsible glass module for the arsenal stack.
 *
 * Collapsed by default where a module is large, because the right rail holds six tools
 * and a stack that overflows the viewport hides the tool an operator needs. The header
 * keeps its live headline figure while collapsed — collapsing must cost detail, never
 * awareness that something is wrong.
 */
export const ArsenalCard: React.FC<{
  title: string;
  icon: React.ElementType;
  headline?: React.ReactNode;
  tone?: CyberTone;
  defaultOpen?: boolean;
  alert?: boolean;
  children: React.ReactNode;
}> = ({ title, icon: Icon, headline, tone = 'cyan', defaultOpen = false, alert, children }) => {
  const [open, setOpen] = React.useState(defaultOpen);
  const t = TONE[tone];

  return (
    <div
      className="relative border bg-[#030712]/60 backdrop-blur-2xl"
      style={{
        borderColor: alert ? 'rgba(225,29,72,0.5)' : 'rgba(22,78,99,0.5)',
        boxShadow: alert ? '0 0 22px rgba(225,29,72,0.18)' : '0 0 25px rgba(0,0,0,0.85)'
      }}
    >
      {/* Corner reticles */}
      {(['tl', 'tr', 'bl', 'br'] as const).map(c => (
        <span
          key={c}
          aria-hidden
          className="pointer-events-none absolute h-2 w-2"
          style={{
            top: c[0] === 't' ? -1 : undefined,
            bottom: c[0] === 'b' ? -1 : undefined,
            left: c[1] === 'l' ? -1 : undefined,
            right: c[1] === 'r' ? -1 : undefined,
            borderTop: c[0] === 't' ? `1.5px solid ${t.fg}` : undefined,
            borderBottom: c[0] === 'b' ? `1.5px solid ${t.fg}` : undefined,
            borderLeft: c[1] === 'l' ? `1.5px solid ${t.fg}` : undefined,
            borderRight: c[1] === 'r' ? `1.5px solid ${t.fg}` : undefined,
            opacity: 0.7
          }}
        />
      ))}

      <button
        type="button"
        onClick={() => setOpen(o => !o)}
        className="flex w-full items-center gap-1.5 px-2 py-1.5 text-start transition-colors hover:bg-white/[0.03]"
        aria-expanded={open}
      >
        <Icon className="h-3 w-3 shrink-0" strokeWidth={1.5} style={{ color: t.fg }} aria-hidden />
        <span
          className="truncate font-mono text-[10px] font-semibold tracking-widest uppercase"
          style={{ color: t.fg, textShadow: `0 0 8px ${t.glow}` }}
        >
          {title}
        </span>
        <span className="ms-auto flex shrink-0 items-center gap-1.5">
          {headline}
          <span className="font-mono text-[11px] text-slate-400" aria-hidden>{open ? '−' : '+'}</span>
        </span>
      </button>

      {open && <div className="border-t border-cyan-900/40 px-2 pt-1.5 pb-2">{children}</div>}
    </div>
  );
};

export default CyberButton;
