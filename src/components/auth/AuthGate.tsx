import React from 'react';
import { OperatorContext, SessionResponse, roleAtLeast, type Role, type SessionInfo } from './operatorContext';
import { LoginScreen } from './LoginScreen';
import { SetupScreen } from './SetupScreen';

/**
 * AUTH GATE — nothing in the console renders without a signed-in operator.
 *
 * Session state comes from GET /api/v1/auth/session: on mount, every minute, when the tab
 * regains focus, and whenever any API call comes back 401. The last one matters most: a
 * session that expires mid-shift would otherwise leave every panel quietly reporting its
 * feed as silent, which reads as an outage rather than a sign-in prompt.
 *
 * The 401 watch wraps window.fetch once. It only observes — it never alters a request or
 * a response — and ignores the auth routes themselves, whose 401s are expected.
 */

const EXPIRED_EVENT = 'sd:auth-expired';
let fetchWatchInstalled = false;

function installFetchWatch() {
  if (fetchWatchInstalled || typeof window === 'undefined') return;
  fetchWatchInstalled = true;
  const original = window.fetch.bind(window);
  window.fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
    const res = await original(input, init);
    if (res.status === 401) {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
      const path = url.startsWith('http') ? new URL(url).pathname : url;
      if (path.startsWith('/api/') && !path.startsWith('/api/v1/auth/')) {
        window.dispatchEvent(new Event(EXPIRED_EVENT));
      }
    }
    return res;
  };
}

type State =
  | { phase: 'LOADING' }
  | { phase: 'UNREACHABLE'; detail: string }
  | { phase: 'READY'; info: SessionInfo };

export const AuthGate: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [state, setState] = React.useState<State>({ phase: 'LOADING' });
  const [lang, setLang] = React.useState<'ar' | 'en'>(() => {
    try {
      return localStorage.getItem('sd_lang') === 'en' ? 'en' : 'ar';
    } catch {
      return 'ar';
    }
  });
  const toggleLang = () =>
    setLang(l => {
      const next = l === 'ar' ? 'en' : 'ar';
      try {
        localStorage.setItem('sd_lang', next);
      } catch {
        /* per-viewer convenience only */
      }
      return next;
    });

  const check = React.useCallback(async () => {
    try {
      const res = await fetch('/api/v1/auth/session', { credentials: 'same-origin' });
      if (!res.ok) throw new Error(`session -> ${res.status}`);
      const parsed = SessionResponse.safeParse(await res.json());
      if (!parsed.success) throw new Error('unexpected session response');
      setState({ phase: 'READY', info: parsed.data });
    } catch (err) {
      setState(prev =>
        // Keep a signed-in console on screen through a transient blip; only a first load
        // with no server at all shows the unreachable state.
        prev.phase === 'READY' ? prev : { phase: 'UNREACHABLE', detail: err instanceof Error ? err.message : 'network error' }
      );
    }
  }, []);

  React.useEffect(() => {
    installFetchWatch();
    void check();
    const t = setInterval(() => void check(), 60_000);
    let pending: ReturnType<typeof setTimeout> | null = null;
    const onExpired = () => {
      // Debounced: a dozen panels polling at once should cause one check, not twelve.
      if (pending) return;
      pending = setTimeout(() => {
        pending = null;
        void check();
      }, 400);
    };
    const onVisible = () => {
      if (document.visibilityState === 'visible') void check();
    };
    window.addEventListener(EXPIRED_EVENT, onExpired);
    document.addEventListener('visibilitychange', onVisible);
    return () => {
      clearInterval(t);
      if (pending) clearTimeout(pending);
      window.removeEventListener(EXPIRED_EVENT, onExpired);
      document.removeEventListener('visibilitychange', onVisible);
    };
  }, [check]);

  const signOut = React.useCallback(async () => {
    try {
      await fetch('/api/v1/auth/logout', { method: 'POST', credentials: 'same-origin' });
    } finally {
      await check();
    }
  }, [check]);

  const isAr = lang === 'ar';

  if (state.phase === 'LOADING') {
    return <div className="min-h-screen bg-black" aria-busy="true" />;
  }

  if (state.phase === 'UNREACHABLE') {
    return (
      <div className="flex min-h-screen items-center justify-center bg-black px-4" dir={isAr ? 'rtl' : 'ltr'}>
        <div className="max-w-sm border border-amber-500/40 bg-amber-950/20 p-5 text-center">
          <p className="text-sm font-semibold text-amber-200">
            {isAr ? 'تعذّر الوصول إلى خادم المنصّة' : 'The platform server cannot be reached'}
          </p>
          <p className="mt-1 font-mono text-xs text-amber-300/80" dir="ltr">
            GET /api/v1/auth/session · {state.detail}
          </p>
          <button
            type="button"
            onClick={() => void check()}
            className="mt-3 border border-amber-400/60 px-3 py-1 text-xs text-amber-200 hover:bg-amber-500/10"
          >
            {isAr ? 'إعادة المحاولة' : 'Retry'}
          </button>
        </div>
      </div>
    );
  }

  const { info } = state;

  if (info.setupRequired) {
    return (
      <SetupScreen
        isAr={isAr}
        onToggleLang={toggleLang}
        transport={info.transport}
        needsSecret={!info.setupFromHere}
        onDone={() => void check()}
      />
    );
  }

  if (!info.authenticated || !info.operator) {
    return <LoginScreen isAr={isAr} onToggleLang={toggleLang} transport={info.transport} onSignedIn={() => void check()} />;
  }

  const operator = info.operator;
  return (
    <OperatorContext.Provider
      value={{
        operator,
        transport: info.transport,
        can: (need: Role) => roleAtLeast(operator.role, need),
        signOut,
        refresh: () => void check()
      }}
    >
      {children}
    </OperatorContext.Provider>
  );
};

export default AuthGate;
