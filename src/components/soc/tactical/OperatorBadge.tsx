import React from 'react';
import { UserRound, LogOut, KeyRound } from 'lucide-react';
import { useOperator, postJson } from '../../auth/operatorContext';
import { CyberButton } from './CyberButton';

/**
 * The signed-in operator, in the header. One chip; everything else opens on demand —
 * session expiry, password change and sign-out — so identity is always visible without
 * adding a panel.
 */

const ROLE_TONE: Record<string, string> = { VIEWER: '#94a3b8', ANALYST: '#22d3ee', ADMIN: '#fbbf24' };

export const OperatorBadge: React.FC<{ isAr: boolean }> = ({ isAr }) => {
  const { operator, signOut, refresh } = useOperator();
  const [open, setOpen] = React.useState(false);
  const [pw, setPw] = React.useState({ current: '', next: '' });
  const [msg, setMsg] = React.useState<string | null>(null);
  const ref = React.useRef<HTMLDivElement>(null);

  React.useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && setOpen(false);
    document.addEventListener('mousedown', onDown);
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('mousedown', onDown);
      document.removeEventListener('keydown', onKey);
    };
  }, [open]);

  const change = async (e: React.FormEvent) => {
    e.preventDefault();
    const r = await postJson('/api/v1/auth/password', pw);
    if (r.ok) {
      // The server revokes every session of this account on a password change.
      refresh();
      return;
    }
    setMsg(r.json?.message ?? (isAr ? 'تعذّر تغيير كلمة المرور' : 'password change failed'));
  };

  const tone = ROLE_TONE[operator.role] ?? '#94a3b8';

  return (
    <div ref={ref} className="relative shrink-0">
      <button
        type="button"
        onClick={() => setOpen(o => !o)}
        aria-expanded={open}
        aria-haspopup="dialog"
        className="flex items-center gap-1.5 border border-cyan-800/60 bg-black/40 px-2 py-0.5 transition-colors hover:bg-cyan-500/10 focus-visible:ring-1 focus-visible:ring-cyan-400 focus-visible:outline-none"
      >
        <UserRound className="h-3 w-3 text-cyan-300" aria-hidden />
        <span className="max-w-[120px] truncate text-[11px] text-slate-200">{operator.displayName}</span>
        <span className="font-mono text-[10px] tracking-widest" style={{ color: tone }}>
          {operator.role}
        </span>
      </button>

      {open && (
        <div
          role="dialog"
          aria-label={isAr ? 'حساب المشغّل' : 'Operator account'}
          className="absolute end-0 top-full z-50 mt-1 w-72 border border-cyan-500/40 bg-[#030712]/95 p-3 shadow-[0_0_30px_rgba(0,0,0,0.9)] backdrop-blur-2xl"
        >
          <p className="text-sm font-semibold text-slate-100">{operator.displayName}</p>
          <p className="font-mono text-xs text-slate-400">
            {operator.username} · <span style={{ color: tone }}>{operator.role}</span>
          </p>
          <p className="mt-1 text-xs text-slate-400">
            {isAr ? 'تنتهي الجلسة عند الخمول بعد ' : 'Session idles out at '}
            <span className="font-mono text-slate-300" dir="ltr">{operator.expiresAt.slice(11, 16)} UTC</span>
          </p>

          <form onSubmit={change} className="mt-3 space-y-1.5 border-t border-cyan-900/50 pt-2.5">
            <p className="flex items-center gap-1.5 text-xs font-medium text-cyan-200">
              <KeyRound className="h-3.5 w-3.5" aria-hidden />
              {isAr ? 'تغيير كلمة المرور' : 'Change password'}
            </p>
            <input
              type="password"
              autoComplete="current-password"
              dir="ltr"
              placeholder={isAr ? 'الحالية' : 'current'}
              aria-label={isAr ? 'كلمة المرور الحالية' : 'current password'}
              value={pw.current}
              onChange={e => setPw({ ...pw, current: e.target.value })}
              className="w-full border border-cyan-900/70 bg-black/70 px-2 py-1 font-mono text-xs text-cyan-100 focus:border-cyan-400/80 focus:outline-none"
            />
            <input
              type="password"
              autoComplete="new-password"
              dir="ltr"
              placeholder={isAr ? 'الجديدة (١٢+)' : 'new (12+)'}
              aria-label={isAr ? 'كلمة المرور الجديدة' : 'new password'}
              value={pw.next}
              onChange={e => setPw({ ...pw, next: e.target.value })}
              className="w-full border border-cyan-900/70 bg-black/70 px-2 py-1 font-mono text-xs text-cyan-100 focus:border-cyan-400/80 focus:outline-none"
            />
            {msg && <p role="alert" className="text-xs text-rose-300">{msg}</p>}
            <p className="text-[10px] text-slate-400">
              {isAr ? 'سيُطلب منك الدخول مجددًا على كل الأجهزة.' : 'You will be signed out everywhere and asked to sign in again.'}
            </p>
            <CyberButton type="submit" size="sm" tone="cyan" className="w-full" disabled={!pw.current || [...pw.next].length < 12}>
              {isAr ? '[ تغيير ]' : '[ CHANGE ]'}
            </CyberButton>
          </form>

          <div className="mt-2.5 border-t border-cyan-900/50 pt-2.5">
            <CyberButton size="sm" tone="rose" className="w-full" onClick={() => void signOut()}>
              <span className="flex items-center justify-center gap-1.5">
                <LogOut className="h-3 w-3" aria-hidden />
                {isAr ? 'تسجيل الخروج' : 'SIGN OUT'}
              </span>
            </CyberButton>
          </div>
        </div>
      )}
    </div>
  );
};

export default OperatorBadge;
