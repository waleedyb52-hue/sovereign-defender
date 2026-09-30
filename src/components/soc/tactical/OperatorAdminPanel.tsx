import React from 'react';
import { UserPlus } from 'lucide-react';
import { CyberButton } from './CyberButton';
import { useOperators } from './useOperators';

/**
 * OPERATORS — accounts, roles and live sessions. ADMIN only; the server enforces that,
 * and this panel is not offered to anyone else.
 *
 * A new account is created with a temporary password the admin hands over; the operator
 * should change it at first sign-in. Accounts are disabled, never deleted, so every past
 * audit entry still resolves to a real account.
 */

const ROLE_HELP: Record<string, [string, string]> = {
  VIEWER: ['قراءة فقط', 'read only'],
  ANALYST: ['قراءة + احتواء وفك', 'read + contain / release'],
  ADMIN: ['كل ما سبق + الحسابات والمفاتيح', 'all of the above + accounts and keys']
};

export const OperatorAdminPanel: React.FC<{ isAr: boolean; selfId: string }> = ({ isAr, selfId }) => {
  const o = useOperators(isAr);
  const [form, setForm] = React.useState({ username: '', displayName: '', role: 'ANALYST', password: '' });
  const [problem, setProblem] = React.useState<string | null>(null);
  const [busy, setBusy] = React.useState(false);

  const create = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    const p = await o.create(form);
    setProblem(p);
    if (!p) setForm({ username: '', displayName: '', role: 'ANALYST', password: '' });
    setBusy(false);
  };

  const input = 'w-full border border-cyan-900/70 bg-black/70 px-2 py-1.5 text-xs text-cyan-100 focus:border-cyan-400/80 focus:outline-none';

  return (
    <div className="grid h-full min-h-[360px] gap-3 lg:grid-cols-[1fr_280px]" dir={isAr ? 'rtl' : 'ltr'}>
      <div className="min-h-0 overflow-auto border border-cyan-900/50 bg-black/50">
        {o.error ? (
          <p className="p-3 font-mono text-xs text-rose-300" dir="ltr">{o.error}</p>
        ) : (
          <table className="w-full border-collapse text-xs">
            <thead className="sticky top-0 bg-[#030712] text-slate-400">
              <tr>
                {[isAr ? 'المستخدم' : 'USER', isAr ? 'الدور' : 'ROLE', isAr ? 'آخر دخول' : 'LAST SIGN-IN', isAr ? 'الحالة' : 'STATUS'].map(h => (
                  <th key={h} scope="col" className="border-b border-cyan-900/60 px-2 py-1.5 text-start font-medium">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {o.operators.map(op => {
                const self = op.id === selfId;
                return (
                  <tr key={op.id} className="border-b border-white/[0.04]">
                    <td className="px-2 py-1.5">
                      <span className="font-mono text-slate-100">{op.username}</span>
                      {op.displayName !== op.username && <span className="ms-1.5 text-slate-400">· {op.displayName}</span>}
                      {self && <span className="ms-1.5 text-[10px] text-cyan-400">{isAr ? '(أنت)' : '(you)'}</span>}
                    </td>
                    <td className="px-2 py-1.5">
                      <select
                        value={op.role}
                        disabled={self}
                        title={self ? (isAr ? 'لا يمكنك تغيير دورك' : 'you cannot change your own role') : ROLE_HELP[op.role]?.[isAr ? 0 : 1]}
                        onChange={async e => setProblem(await o.setRole(op.id, e.target.value))}
                        className="border border-cyan-900/70 bg-black/70 px-1.5 py-0.5 font-mono text-xs text-cyan-200 disabled:opacity-60"
                        aria-label={isAr ? `دور ${op.username}` : `Role of ${op.username}`}
                      >
                        {['VIEWER', 'ANALYST', 'ADMIN'].map(r => (
                          <option key={r} value={r}>
                            {r}
                          </option>
                        ))}
                      </select>
                    </td>
                    <td className="px-2 py-1.5 font-mono text-slate-400" dir="ltr">
                      {op.lastLoginAt ? `${op.lastLoginAt.slice(5, 10)} ${op.lastLoginAt.slice(11, 16)}` : '—'}
                    </td>
                    <td className="px-2 py-1.5">
                      <CyberButton
                        size="sm"
                        tone={op.disabled ? 'emerald' : 'rose'}
                        disabled={self}
                        title={self ? (isAr ? 'لا يمكنك تعطيل حسابك' : 'you cannot disable your own account') : undefined}
                        onClick={async () => setProblem(await o.setDisabled(op.id, !op.disabled))}
                      >
                        {op.disabled ? (isAr ? 'تفعيل' : 'ENABLE') : isAr ? 'تعطيل' : 'DISABLE'}
                      </CyberButton>
                      {op.disabled && <span className="ms-1.5 text-[10px] text-rose-300">{isAr ? 'معطّل' : 'disabled'}</span>}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>

      <div className="space-y-3">
        <form onSubmit={create} className="space-y-2 border border-cyan-900/50 bg-black/40 p-2.5">
          <p className="flex items-center gap-1.5 text-xs font-semibold text-cyan-200">
            <UserPlus className="h-3.5 w-3.5" aria-hidden />
            {isAr ? 'مشغّل جديد' : 'New operator'}
          </p>
          <input className={`${input} font-mono`} dir="auto" placeholder={isAr ? 'اسم المستخدم' : 'username'} aria-label={isAr ? 'اسم المستخدم' : 'username'} value={form.username} onChange={e => setForm({ ...form, username: e.target.value })} autoCapitalize="none" spellCheck={false} />
          <input className={input} placeholder={isAr ? 'الاسم الظاهر' : 'display name'} aria-label={isAr ? 'الاسم الظاهر' : 'display name'} value={form.displayName} onChange={e => setForm({ ...form, displayName: e.target.value })} />
          <select className={`${input} font-mono`} value={form.role} onChange={e => setForm({ ...form, role: e.target.value })} aria-label={isAr ? 'الدور' : 'role'}>
            {['VIEWER', 'ANALYST', 'ADMIN'].map(r => (
              <option key={r} value={r}>
                {r} — {ROLE_HELP[r][isAr ? 0 : 1]}
              </option>
            ))}
          </select>
          <input className={`${input} font-mono`} dir="ltr" type="password" autoComplete="new-password" placeholder={isAr ? 'كلمة مرور مؤقتة (١٢+)' : 'temporary password (12+)'} aria-label={isAr ? 'كلمة مرور مؤقتة' : 'temporary password'} value={form.password} onChange={e => setForm({ ...form, password: e.target.value })} />
          {problem && <p role="alert" className="text-xs text-rose-300">{problem}</p>}
          <CyberButton type="submit" size="sm" tone="cyan" className="w-full" disabled={busy || !form.username || [...form.password].length < 12}>
            {isAr ? '[ إنشاء ]' : '[ CREATE ]'}
          </CyberButton>
        </form>

        <div className="border border-cyan-900/50 bg-black/40 p-2.5">
          <p className="text-xs font-semibold text-cyan-200">
            {isAr ? 'الجلسات النشطة' : 'Active sessions'} <span className="font-mono text-slate-400">{o.sessions.length}</span>
          </p>
          <ul className="mt-1 max-h-40 space-y-1 overflow-auto">
            {o.sessions.map(s => (
              <li key={s.id} className="flex items-baseline justify-between gap-2 text-xs">
                <span className="font-mono text-slate-200">{s.username}</span>
                <span className="font-mono text-slate-400" dir="ltr">{s.ip}</span>
              </li>
            ))}
          </ul>
        </div>
      </div>
    </div>
  );
};

export default OperatorAdminPanel;
