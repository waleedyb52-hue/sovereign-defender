import React from 'react';
import { cn } from '../../lib/utils';
import { Modal } from './modal';

/**
 * UI PRIMITIVES — button, card, table, badge, dialog
 *
 * Vendored by hand rather than generated with `shadcn-ui init`, for two reasons
 * that both matter here:
 *
 *   1. `shadcn-ui` is the deprecated package name — it was renamed to `shadcn` —
 *      and the directive governing this work forbids deprecated packages.
 *   2. Its init step writes a v3-style `tailwind.config.js` and rewrites
 *      `src/index.css`. This project is on Tailwind v4 via `@tailwindcss/vite`,
 *      where the design tokens live in an `@theme` block that roughly two
 *      thousand existing class usages depend on. Running init would have put
 *      forty-odd working panels at risk to obtain files that are, by shadcn's
 *      own design, meant to be copied in and owned locally.
 *
 * So these are those files, owned locally, styled to this project's tokens.
 * Nothing here is a runtime dependency.
 */

/* ── Button ─────────────────────────────────────────────────────────────── */

type ButtonVariant = 'default' | 'secondary' | 'ghost' | 'danger' | 'outline';
type ButtonSize = 'sm' | 'md' | 'lg' | 'icon';

const BUTTON_VARIANTS: Record<ButtonVariant, string> = {
  default: 'bg-[#38BDF8]/15 text-[#7dd3fc] border-[#38BDF8]/35 hover:bg-[#38BDF8]/25',
  secondary: 'bg-slate-700/40 text-slate-200 border-slate-600/50 hover:bg-slate-700/60',
  ghost: 'bg-transparent text-slate-300 border-transparent hover:bg-slate-800/60',
  danger: 'bg-[#EF4444]/15 text-[#fca5a5] border-[#EF4444]/40 hover:bg-[#EF4444]/25',
  outline: 'bg-transparent text-slate-200 border-slate-700 hover:border-slate-500'
};

const BUTTON_SIZES: Record<ButtonSize, string> = {
  sm: 'h-7 px-2.5 text-[11px]',
  md: 'h-9 px-3.5 text-xs',
  lg: 'h-11 px-5 text-sm',
  icon: 'h-8 w-8 p-0'
};

export interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  size?: ButtonSize;
}

export const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant = 'default', size = 'md', ...props }, ref) => (
    <button
      ref={ref}
      className={cn(
        'inline-flex items-center justify-center gap-1.5 rounded-md border font-medium',
        'transition-colors duration-150 select-none',
        // A visible focus ring is not optional: this console is operated under
        // pressure and keyboard-first by people who cannot hunt for focus.
        'focus-visible:ring-2 focus-visible:ring-[#38BDF8]/60 focus-visible:outline-none',
        'disabled:pointer-events-none disabled:opacity-40',
        BUTTON_VARIANTS[variant],
        BUTTON_SIZES[size],
        className
      )}
      {...props}
    />
  )
);
Button.displayName = 'Button';

/* ── Card ───────────────────────────────────────────────────────────────── */

export const Card: React.FC<React.HTMLAttributes<HTMLDivElement>> = ({ className, ...p }) => (
  <div
    className={cn(
      'rounded-lg border border-slate-800/80 bg-[#0F1420] shadow-2xl shadow-black/60',
      className
    )}
    {...p}
  />
);

export const CardHeader: React.FC<React.HTMLAttributes<HTMLDivElement>> = ({ className, ...p }) => (
  <div
    className={cn('flex items-center justify-between gap-3 px-4 pt-3.5 pb-2', className)}
    {...p}
  />
);

export const CardTitle: React.FC<React.HTMLAttributes<HTMLHeadingElement>> = ({
  className,
  ...p
}) => (
  <h3
    className={cn('text-[13px] font-semibold tracking-wide text-slate-200', className)}
    style={{ fontFamily: 'var(--font-sans)' }}
    {...p}
  />
);

export const CardContent: React.FC<React.HTMLAttributes<HTMLDivElement>> = ({
  className,
  ...p
}) => <div className={cn('px-4 pb-4', className)} {...p} />;

/* ── Badge ──────────────────────────────────────────────────────────────── */

export type BadgeTone = 'secure' | 'tarpit' | 'quarantine' | 'ebpf' | 'neutral';

const BADGE_TONES: Record<BadgeTone, string> = {
  secure: 'bg-[#10B981]/12 text-[#6ee7b7] border-[#10B981]/35',
  tarpit: 'bg-[#F59E0B]/12 text-[#fcd34d] border-[#F59E0B]/35',
  quarantine: 'bg-[#EF4444]/12 text-[#fca5a5] border-[#EF4444]/40',
  ebpf: 'bg-[#38BDF8]/12 text-[#7dd3fc] border-[#38BDF8]/35',
  neutral: 'bg-slate-700/30 text-slate-300 border-slate-600/40'
};

/**
 * Status badge.
 *
 * `label` is required rather than optional, and colour never carries the meaning
 * on its own — roughly one in twelve men has a red/green deficiency, and this is
 * a console where red and green mean "dropped" and "passed".
 */
export const Badge: React.FC<{
  tone?: BadgeTone;
  label: string;
  icon?: React.ElementType;
  className?: string;
  mono?: boolean;
}> = ({ tone = 'neutral', label, icon: Icon, className, mono }) => (
  <span
    className={cn(
      'inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-[10px] font-medium whitespace-nowrap',
      BADGE_TONES[tone],
      className
    )}
    style={mono ? { fontFamily: 'var(--font-mono)' } : undefined}
  >
    {Icon && <Icon className="h-3 w-3 shrink-0" aria-hidden />}
    {label}
  </span>
);

/* ── Table ──────────────────────────────────────────────────────────────── */

export const Table: React.FC<React.TableHTMLAttributes<HTMLTableElement>> = ({
  className,
  ...p
}) => <table className={cn('w-full border-collapse text-left', className)} {...p} />;

export const THead: React.FC<React.HTMLAttributes<HTMLTableSectionElement>> = ({
  className,
  ...p
}) => <thead className={cn('border-b border-slate-800/80', className)} {...p} />;

export const TBody: React.FC<React.HTMLAttributes<HTMLTableSectionElement>> = ({
  className,
  ...p
}) => <tbody className={cn('divide-y divide-slate-800/50', className)} {...p} />;

export const TR: React.FC<React.HTMLAttributes<HTMLTableRowElement>> = ({ className, ...p }) => (
  <tr className={cn('transition-colors hover:bg-slate-800/25', className)} {...p} />
);

/** Header cell. Pass `sorted` so assistive tech announces the sort, not just the arrow. */
export const TH: React.FC<
  React.ThHTMLAttributes<HTMLTableCellElement> & { sorted?: 'asc' | 'desc' | false }
> = ({ className, sorted, ...p }) => (
  <th
    scope="col"
    aria-sort={sorted === 'asc' ? 'ascending' : sorted === 'desc' ? 'descending' : 'none'}
    className={cn(
      'px-2.5 py-2 text-[10px] font-semibold tracking-wider text-slate-400 uppercase',
      className
    )}
    {...p}
  />
);

export const TD: React.FC<React.TdHTMLAttributes<HTMLTableCellElement> & { mono?: boolean }> = ({
  className,
  mono,
  ...p
}) => (
  <td
    className={cn('px-2.5 py-2 align-middle text-[11px] text-slate-300', className)}
    style={mono ? { fontFamily: 'var(--font-mono)' } : undefined}
    {...p}
  />
);

/* ── Dialog ─────────────────────────────────────────────────────────────── */

/**
 * Dialog.
 *
 * This was a hand-rolled focus trap. It is now a thin adapter over the Radix
 * modal in `./modal`, keeping the same props so existing callers did not change.
 *
 * The swap was made on capability, not preference. The hand-rolled version
 * handled the straightforward Tab case and nothing else — it did not do nested
 * dialogs, `aria-hidden` on siblings, background scroll lock, pointer-events
 * containment, or returning focus to a trigger that has unmounted. The last two
 * matter most for the isolation confirmation, where a stray click reaching a
 * control behind the overlay is a safety problem rather than a cosmetic one.
 *
 * See `./modal` for the full reasoning and for `ModalShell`, which the console's
 * pre-existing modals were migrated onto.
 */
export const Dialog: React.FC<{
  open: boolean;
  onClose: () => void;
  title: string;
  children: React.ReactNode;
  footer?: React.ReactNode;
  tone?: 'default' | 'danger';
  dismissible?: boolean;
  dir?: 'rtl' | 'ltr';
}> = ({
  open,
  onClose,
  title,
  children,
  footer,
  tone = 'default',
  dismissible = true,
  dir = 'ltr'
}) => (
  <Modal
    open={open}
    onClose={onClose}
    title={title}
    footer={footer}
    tone={tone}
    dismissible={dismissible}
    dir={dir}
    size="md"
  >
    {children}
  </Modal>
);

/* ── Mono ───────────────────────────────────────────────────────────────── */

/**
 * Machine data: IPs, digests, ports, CLI, rule text.
 *
 * A component rather than a class so the typography rule is enforced at the call
 * site — the reason mono is mandatory here is that an operator about to act on a
 * hash must be able to tell 0 from O.
 */
export const Mono: React.FC<{ children: React.ReactNode; className?: string; title?: string }> = ({
  children,
  className,
  title
}) => (
  <span
    className={cn('tracking-tight tabular-nums', className)}
    style={{ fontFamily: 'var(--font-mono)' }}
    title={title}
    dir="ltr"
  >
    {children}
  </span>
);
