import React from 'react';
import * as RadixDialog from '@radix-ui/react-dialog';
import { X } from 'lucide-react';
import { cn } from '../../lib/utils';

/**
 * MODAL SHELL — accessible dialog behaviour, once, for every modal in the console
 *
 * Why this replaced a hand-rolled focus trap
 *   An audit of the three existing modals found none of them carried
 *   `role="dialog"` or `aria-modal`, two did not handle Escape at all, none
 *   trapped focus, none locked background scroll, and none returned focus to the
 *   element that opened them. The trap this file's predecessor contained was
 *   about twenty lines and handled the straightforward Tab case only.
 *
 *   The cases it did not handle are the ones that matter in a console operated
 *   under pressure:
 *     - nested dialogs (a confirmation opened from inside a modal)
 *     - `aria-hidden` on sibling content, without which a screen reader reads
 *       the whole page behind the dialog
 *     - background scroll lock, so the page does not move under the dialog
 *     - `pointer-events` containment, so a stray click cannot reach a control
 *       behind the overlay — which for an isolation dialog is a safety property,
 *       not a polish item
 *     - returning focus to the trigger on close, including when the trigger has
 *       unmounted
 *
 *   Radix handles all of them, and it is the same primitive shadcn/ui builds its
 *   dialog on. The cost is 24 small single-purpose packages; the gain is that
 *   these guarantees hold in four modals rather than being re-implemented, partly,
 *   in each.
 *
 * On `dismissible={false}`
 *   The isolation confirmation uses it. Escape and outside-click are both
 *   suppressed, so a kill switch cannot be closed by reflex. Radix still keeps
 *   focus inside the dialog, so the operator is not trapped without a way out —
 *   the explicit Cancel control remains reachable.
 */

export interface ModalProps {
  open: boolean;
  onClose: () => void;
  /**
   * The dialog's accessible name. Required — Radix warns without one, and a
   * dialog a screen reader cannot announce is not an accessible dialog.
   */
  title: string;
  /** Render the title visually. Pass false when the content supplies its own header. */
  showTitle?: boolean;
  description?: string;
  children: React.ReactNode;
  footer?: React.ReactNode;
  tone?: 'default' | 'danger';
  /** When false, Escape and outside-click will not close the dialog. */
  dismissible?: boolean;
  dir?: 'rtl' | 'ltr';
  /** Tailwind max-width class for the panel. */
  size?: 'sm' | 'md' | 'lg' | 'xl' | 'full';
  className?: string;
}

const SIZES: Record<NonNullable<ModalProps['size']>, string> = {
  sm: 'max-w-sm',
  md: 'max-w-md',
  lg: 'max-w-2xl',
  xl: 'max-w-4xl',
  full: 'max-w-6xl'
};

export const Modal: React.FC<ModalProps> = ({
  open,
  onClose,
  title,
  showTitle = true,
  description,
  children,
  footer,
  tone = 'default',
  dismissible = true,
  dir = 'ltr',
  size = 'md',
  className
}) => (
  <RadixDialog.Root
    open={open}
    onOpenChange={next => {
      if (!next) onClose();
    }}
    // modal: scroll lock and aria-hidden on siblings.
    modal
  >
    <RadixDialog.Portal>
      <RadixDialog.Overlay className="data-[state=open]:animate-in data-[state=closed]:animate-out fixed inset-0 z-[120] bg-black/70 backdrop-blur-sm" />
      <RadixDialog.Content
        dir={dir}
        onEscapeKeyDown={e => {
          if (!dismissible) e.preventDefault();
        }}
        onPointerDownOutside={e => {
          if (!dismissible) e.preventDefault();
        }}
        onInteractOutside={e => {
          if (!dismissible) e.preventDefault();
        }}
        className={cn(
          'fixed top-1/2 left-1/2 z-[121] w-[calc(100vw-2rem)] -translate-x-1/2 -translate-y-1/2',
          'max-h-[calc(100vh-2rem)] overflow-y-auto rounded-lg border backdrop-blur-md',
          'bg-[#0F1420]/95 shadow-2xl shadow-black/60 focus:outline-none',
          tone === 'danger' ? 'border-[#f43f5e]/45' : 'border-slate-700/70',
          SIZES[size],
          className
        )}
      >
        <div
          className={cn(
            'flex items-center justify-between gap-3 border-b px-4 py-3',
            tone === 'danger' ? 'border-[#f43f5e]/25' : 'border-slate-800/80',
            !showTitle && 'sr-only'
          )}
        >
          <RadixDialog.Title
            className={cn(
              'text-[13px] font-semibold tracking-wide',
              tone === 'danger' ? 'text-[#fda4af]' : 'text-slate-200'
            )}
            style={{ fontFamily: 'var(--font-sans)' }}
          >
            {title}
          </RadixDialog.Title>
          {dismissible && showTitle && (
            <RadixDialog.Close
              aria-label={dir === 'rtl' ? 'إغلاق' : 'Close'}
              className="rounded p-0.5 text-slate-500 transition-colors hover:text-slate-200 focus-visible:ring-2 focus-visible:ring-[#22d3ee]/60 focus-visible:outline-none"
            >
              <X className="h-3.5 w-3.5" />
            </RadixDialog.Close>
          )}
        </div>

        {description && (
          <RadixDialog.Description className="px-4 pt-3 text-[11px] text-slate-400">
            {description}
          </RadixDialog.Description>
        )}

        <div className="px-4 py-3.5">{children}</div>

        {footer && (
          <div className="flex justify-end gap-2 border-t border-slate-800/80 px-4 py-3">
            {footer}
          </div>
        )}
      </RadixDialog.Content>
    </RadixDialog.Portal>
  </RadixDialog.Root>
);

/**
 * Bare shell for modals that already render their own chrome.
 *
 * The three pre-existing modals each open with `if (!isOpen) return null` and
 * their own `fixed inset-0` backdrop. Migrating them means replacing that outer
 * wrapper, not rewriting their contents — so this variant supplies the overlay,
 * focus management and accessible name, and otherwise stays out of the way.
 */
export const ModalShell: React.FC<{
  open: boolean;
  onClose: () => void;
  /** Accessible name. Rendered visually hidden, since the content has its own header. */
  title: string;
  children: React.ReactNode;
  dismissible?: boolean;
  dir?: 'rtl' | 'ltr';
  className?: string;
  overlayClassName?: string;
}> = ({
  open,
  onClose,
  title,
  children,
  dismissible = true,
  dir = 'ltr',
  className,
  overlayClassName
}) => (
  <RadixDialog.Root
    open={open}
    onOpenChange={next => {
      if (!next) onClose();
    }}
    modal
  >
    <RadixDialog.Portal>
      <RadixDialog.Overlay
        className={cn('fixed inset-0 z-50 bg-black/75 backdrop-blur-sm', overlayClassName)}
      />
      <RadixDialog.Content
        dir={dir}
        onEscapeKeyDown={e => {
          if (!dismissible) e.preventDefault();
        }}
        onPointerDownOutside={e => {
          if (!dismissible) e.preventDefault();
        }}
        className={cn(
          'fixed top-1/2 left-1/2 z-[51] w-[calc(100vw-2rem)] -translate-x-1/2 -translate-y-1/2',
          'max-h-[calc(100vh-2rem)] overflow-y-auto focus:outline-none',
          className
        )}
      >
        {/* Radix requires an accessible name; the visible heading lives in the
            migrated content, so this one is for assistive tech only. */}
        <RadixDialog.Title className="sr-only">{title}</RadixDialog.Title>
        {children}
      </RadixDialog.Content>
    </RadixDialog.Portal>
  </RadixDialog.Root>
);
