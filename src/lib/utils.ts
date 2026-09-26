import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';

/**
 * Conditional class join with conflict resolution.
 *
 * clsx handles the conditionals; tailwind-merge resolves collisions so a
 * caller-supplied `className` reliably wins over a component default. Without
 * the merge step, `cn('p-2', 'p-4')` emits both and the outcome depends on
 * stylesheet order, which is how override props silently stop working.
 */
export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

/** Byte formatter for ingress/egress counters. */
export function formatBytes(n: number, digits = 1): string {
  if (!Number.isFinite(n) || n < 0) return '—';
  if (n < 1024) return `${n} B`;
  const units = ['KiB', 'MiB', 'GiB', 'TiB'];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(digits)} ${units[i]}`;
}

/** Compact counter formatter that never invents precision it does not have. */
export function formatCount(n: number): string {
  if (!Number.isFinite(n)) return '—';
  if (n < 1000) return String(n);
  if (n < 1_000_000) return `${(n / 1000).toFixed(1)}K`;
  return `${(n / 1_000_000).toFixed(2)}M`;
}
