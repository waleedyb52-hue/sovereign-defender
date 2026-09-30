import React from 'react';
import { Eye, EyeOff } from 'lucide-react';
import { CyberButton } from '../soc/tactical/CyberButton';
import { AccessError, AccessField, AccessShell } from './AccessShell';
import { postJson } from './operatorContext';

/**
 * Sign-in. The server returns one message for an unknown user, a wrong password and a
 * disabled account, so this screen cannot tell them apart either — it shows what the
 * server said. A lockout shows its real remaining time, counted down from Retry-After.
 */
export const LoginScreen: React.FC<{
  isAr: boolean;
  onToggleLang: () => void;
  transport: 'TLS' | 'CLEARTEXT';
  onSignedIn: () => void;
}> = ({ isAr, onToggleLang, transport, onSignedIn }) => {
  const [username, setUsername] = React.useState('');
  const [password, setPassword] = React.useState('');
  const [show, setShow] = React.useState(false);
  const [busy, setBusy] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);
  const [lockedUntil, setLockedUntil] = React.useState<number | null>(null);
  const [, tick] = React.useState(0);

  React.useEffect(() => {
    if (!lockedUntil) return;
    const t = setInterval(() => {
      if (Date.now() >= lockedUntil) setLockedUntil(null);
      tick(x => x + 1);
    }, 1000);
    return () => clearInterval(t);
  }, [lockedUntil]);

  const remaining = lockedUntil ? Math.max(0, Math.ceil((lockedUntil - Date.now()) / 1000)) : 0;

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (busy || remaining > 0) return;
    setBusy(true);
    setError(null);
    try {
      const r = await postJson('/api/v1/auth/login', { username, password });
      if (r.ok) {
        setPassword('');
        onSignedIn();
        return;
      }
      if (r.status === 429) setLockedUntil(Date.now() + (Number(r.json?.retryAfterSec) || 900) * 1000);
      setError((isAr ? r.json?.messageAr : r.json?.message) ?? (isAr ? 'تعذّر تسجيل الدخول.' : 'Sign-in failed.'));
    } catch {
      setError(isAr ? 'الخادم لا يستجيب.' : 'The server is not responding.');
    } finally {
      setBusy(false);
    }
  };

  return (
    <AccessShell
      isAr={isAr}
      onToggleLang={onToggleLang}
      transport={transport}
      title={isAr ? 'دخول المشغّل' : 'Operator sign-in'}
      subtitle={isAr ? 'سجّل الدخول بحسابك للوصول إلى مركز العمليات.' : 'Sign in with your account to reach the operations console.'}
    >
      <form onSubmit={submit} className="space-y-3.5" noValidate>
        <AccessField
          label={isAr ? 'اسم المستخدم' : 'Username'}
          autoComplete="username"
          autoCapitalize="none"
          spellCheck={false}
          dir="auto"
          value={username}
          onChange={e => setUsername(e.target.value)}
          required
          autoFocus
        />
        <AccessField
          label={isAr ? 'كلمة المرور' : 'Password'}
          type={show ? 'text' : 'password'}
          autoComplete="current-password"
          dir="ltr"
          value={password}
          onChange={e => setPassword(e.target.value)}
          required
          trailing={
            <button
              type="button"
              onClick={() => setShow(s => !s)}
              className="p-1 text-slate-400 hover:text-cyan-300 focus-visible:ring-1 focus-visible:ring-cyan-400 focus-visible:outline-none"
              aria-label={show ? (isAr ? 'إخفاء كلمة المرور' : 'Hide password') : isAr ? 'إظهار كلمة المرور' : 'Show password'}
              aria-pressed={show}
            >
              {show ? <EyeOff className="h-4 w-4" aria-hidden /> : <Eye className="h-4 w-4" aria-hidden />}
            </button>
          }
        />

        {error && (
          <AccessError>
            {error}
            {remaining > 0 && (
              <span className="mt-1 block font-mono text-xs text-rose-300" dir="ltr">
                {Math.floor(remaining / 60)}:{String(remaining % 60).padStart(2, '0')}
              </span>
            )}
          </AccessError>
        )}

        <CyberButton tone="cyan" className="w-full" disabled={busy || remaining > 0 || !username || !password} type="submit">
          {busy ? (isAr ? '… جارٍ التحقق' : '… VERIFYING') : isAr ? '[ دخول ]' : '[ SIGN IN ]'}
        </CyberButton>
      </form>
    </AccessShell>
  );
};

export default LoginScreen;
