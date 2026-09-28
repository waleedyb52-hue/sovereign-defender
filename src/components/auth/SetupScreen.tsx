import React from 'react';
import { CyberButton } from '../soc/tactical/CyberButton';
import { AccessError, AccessField, AccessShell } from './AccessShell';
import { postJson } from './operatorContext';

/**
 * First-run setup: create the first administrator.
 *
 * Shown only while no operator exists. From the server's own machine no secret is asked
 * for; from anywhere else the server requires the one-time secret it printed to its
 * console, so the account cannot be claimed by whoever reaches port 3000 first.
 *
 * The length indicator is a length, not a "strength score". Scoring meters invite
 * P@ssw0rd!-style composition that NIST SP 800-63B specifically advises against; length
 * is what the server enforces and what actually matters.
 */
export const SetupScreen: React.FC<{
  isAr: boolean;
  onToggleLang: () => void;
  transport: 'TLS' | 'CLEARTEXT';
  needsSecret: boolean;
  onDone: () => void;
}> = ({ isAr, onToggleLang, transport, needsSecret, onDone }) => {
  const [username, setUsername] = React.useState('');
  const [displayName, setDisplayName] = React.useState('');
  const [password, setPassword] = React.useState('');
  const [confirm, setConfirm] = React.useState('');
  const [secret, setSecret] = React.useState('');
  const [busy, setBusy] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);

  const len = [...password].length;
  const mismatch = confirm.length > 0 && confirm !== password;
  const ready = /^[a-zA-Z0-9._-]{3,32}$/.test(username) && len >= 12 && confirm === password && (!needsSecret || secret.trim());

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!ready || busy) return;
    setBusy(true);
    setError(null);
    try {
      const r = await postJson('/api/v1/auth/setup', {
        username,
        displayName: displayName.trim() || undefined,
        password,
        setupToken: needsSecret ? secret.trim() : undefined
      });
      if (r.ok) {
        onDone();
        return;
      }
      setError((isAr ? r.json?.messageAr : null) ?? r.json?.message ?? (isAr ? 'تعذّر إنشاء الحساب.' : 'Could not create the account.'));
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
      title={isAr ? 'الإعداد الأول' : 'First-run setup'}
      subtitle={
        isAr
          ? 'لا يوجد حساب بعد. أنشئ حساب المسؤول الأول؛ ستُنشئ منه حسابات بقية المشغّلين.'
          : 'No account exists yet. Create the first administrator; the other operators are created from it.'
      }
    >
      <form onSubmit={submit} className="space-y-3" noValidate>
        {needsSecret && (
          <AccessField
            label={isAr ? 'رمز الإعداد' : 'Setup secret'}
            hint={isAr ? 'مطبوع في طرفية الخادم عند التشغيل، ويبدأ بـ sd_setup_' : 'Printed in the server console at start-up; begins with sd_setup_'}
            autoComplete="off"
            spellCheck={false}
            dir="ltr"
            value={secret}
            onChange={e => setSecret(e.target.value)}
          />
        )}
        <AccessField
          label={isAr ? 'اسم المستخدم' : 'Username'}
          hint={isAr ? '٣–٣٢ حرفًا: أحرف لاتينية وأرقام و . _ -' : '3–32 characters: letters, digits, . _ -'}
          autoComplete="username"
          autoCapitalize="none"
          spellCheck={false}
          dir="ltr"
          value={username}
          onChange={e => setUsername(e.target.value)}
          autoFocus={!needsSecret}
        />
        <AccessField
          label={isAr ? 'الاسم الظاهر (اختياري)' : 'Display name (optional)'}
          mono={false}
          value={displayName}
          onChange={e => setDisplayName(e.target.value)}
        />
        <AccessField
          label={isAr ? 'كلمة المرور' : 'Password'}
          type="password"
          autoComplete="new-password"
          dir="ltr"
          value={password}
          onChange={e => setPassword(e.target.value)}
          hint={
            len === 0
              ? isAr
                ? '١٢ حرفًا على الأقل. عبارة من عدة كلمات أسهل للتذكّر وأصعب للتخمين.'
                : 'At least 12 characters. A phrase of several words is easier to remember and harder to guess.'
              : `${len} / 12${len >= 12 ? ' ✓' : ''}`
          }
        />
        <AccessField
          label={isAr ? 'تأكيد كلمة المرور' : 'Confirm password'}
          type="password"
          autoComplete="new-password"
          dir="ltr"
          value={confirm}
          onChange={e => setConfirm(e.target.value)}
          hint={mismatch ? (isAr ? 'غير مطابقة' : 'does not match') : null}
        />

        {error && <AccessError>{error}</AccessError>}

        <CyberButton tone="cyan" className="w-full" type="submit" disabled={!ready || busy}>
          {busy ? (isAr ? '… جارٍ الإنشاء' : '… CREATING') : isAr ? '[ إنشاء حساب المسؤول ]' : '[ CREATE ADMINISTRATOR ]'}
        </CyberButton>
      </form>
    </AccessShell>
  );
};

export default SetupScreen;
