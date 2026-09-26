import { useEffect, useRef, useState, useSyncExternalStore } from 'react';

/**
 * UNIFIED REFRESH TICK
 *
 * The app previously ran 29 independent setIntervals, most of them at 4–6s.
 * Staggered like that, something on screen changes roughly every few hundred
 * milliseconds, which reads as constant restlessness even though each single
 * update is small.
 *
 * One shared clock fixes that: every subscriber refreshes on the SAME beat, so
 * the dashboard updates as one deliberate step and is otherwise still. The
 * clock also stops while the tab is hidden — there is no reason to poll, or to
 * animate, a dashboard nobody is looking at.
 */

type Listener = () => void;

const listeners = new Set<Listener>();
let timer: ReturnType<typeof setInterval> | null = null;
let tick = 0;

const BEAT_MS = 10_000;

function isVisible(): boolean {
  return typeof document === 'undefined' || document.visibilityState === 'visible';
}

function emit() {
  tick += 1;
  listeners.forEach(l => l());
}

function start() {
  if (timer !== null) return;
  timer = setInterval(() => {
    if (isVisible()) emit();
  }, BEAT_MS);
}

function stop() {
  if (timer === null) return;
  clearInterval(timer);
  timer = null;
}

function ensureRunning() {
  if (listeners.size === 0) {
    stop();
    return;
  }
  if (isVisible()) start();
  else stop();
}

if (typeof document !== 'undefined') {
  document.addEventListener('visibilitychange', () => {
    ensureRunning();
    // Catch up immediately when the viewer comes back, so they are not looking
    // at data frozen from whenever they last had the tab open.
    if (isVisible()) emit();
  });
}

function subscribe(l: Listener): () => void {
  listeners.add(l);
  ensureRunning();
  return () => {
    listeners.delete(l);
    ensureRunning();
  };
}

/** Re-renders on the shared beat. Use when a component polls on its own. */
export function useRefreshTick(): number {
  return useSyncExternalStore(
    subscribe,
    () => tick,
    () => tick
  );
}

/**
 * Fetches `url` on mount and on every shared beat, keeping the last good value
 * when a request fails so the UI never flashes empty on a transient error.
 *
 * `loading` is true only for the very first load — subsequent refreshes swap
 * data in silently, which is what keeps the dashboard from flickering.
 */
export function useLiveJson<T>(url: string, select?: (raw: any) => T | null) {
  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState(true);
  const beat = useRefreshTick();
  const selectRef = useRef(select);
  selectRef.current = select;

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const res = await fetch(url);
        if (!res.ok || cancelled) return;
        const raw = await res.json();
        if (cancelled) return;
        const next = selectRef.current ? selectRef.current(raw) : (raw as T);
        if (next !== null && next !== undefined) setData(next);
      } catch {
        /* keep the last good value */
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [url, beat]);

  return { data, loading };
}

/**
 * True when motion should be suppressed — either the OS accessibility setting
 * or the in-app calm toggle. Non-CSS consumers (the WebGL globe) read this so
 * they stop animating too, not just the DOM.
 */
export function usePrefersCalm(): boolean {
  const [calm, setCalm] = useState(() => readCalm());

  useEffect(() => {
    const mq = window.matchMedia('(prefers-reduced-motion: reduce)');
    const update = () => setCalm(readCalm());
    mq.addEventListener('change', update);
    const obs = new MutationObserver(update);
    obs.observe(document.documentElement, { attributes: true, attributeFilter: ['data-motion'] });
    return () => {
      mq.removeEventListener('change', update);
      obs.disconnect();
    };
  }, []);

  return calm;
}

function readCalm(): boolean {
  if (typeof window === 'undefined') return false;
  if (document.documentElement.dataset.motion === 'calm') return true;
  return window.matchMedia('(prefers-reduced-motion: reduce)').matches;
}

/** Flips the in-app calm toggle and remembers it for next visit. */
export function setCalmMode(on: boolean) {
  document.documentElement.dataset.motion = on ? 'calm' : 'full';
  try {
    localStorage.setItem('sd-motion', on ? 'calm' : 'full');
  } catch {
    /* private mode */
  }
}

/** Restores the saved preference. Call once at startup. */
export function initCalmMode() {
  try {
    const saved = localStorage.getItem('sd-motion');
    if (saved === 'calm' || saved === 'full') document.documentElement.dataset.motion = saved;
  } catch {
    /* private mode */
  }
}

/**
 * Reports whether the element is on screen. Used to stop the WebGL render loop
 * for a globe that has been scrolled past — it keeps a GPU busy for nothing and
 * keeps motion in peripheral vision.
 */
export function useOnScreen<T extends Element>(
  ref: React.RefObject<T | null>,
  rootMargin = '120px'
): boolean {
  const [onScreen, setOnScreen] = useState(true);
  useEffect(() => {
    const el = ref.current;
    if (!el || typeof IntersectionObserver === 'undefined') return;
    const obs = new IntersectionObserver(([e]) => setOnScreen(e.isIntersecting), { rootMargin });
    obs.observe(el);
    return () => obs.disconnect();
  }, [ref, rootMargin]);
  return onScreen;
}
