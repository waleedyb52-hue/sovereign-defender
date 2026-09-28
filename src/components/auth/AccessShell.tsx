import React from 'react';
import { motion, useReducedMotion } from 'motion/react';
import { Crosshair, Lock, LockOpen, ScrollText } from 'lucide-react';
import { CyberGridBackdrop, TacticalPanel } from '../soc/tactical/TacticalPrimitives';

/**
 * The frame shared by the sign-in and first-run screens.
 *
 * Two facts are always on it, because both are things an operator should know before
 * typing a password: whether the connection is encrypted (read from the server, not
 * assumed), and that the attempt will be recorded.
 */
export const AccessShell: React.FC<{
  isAr: boolean;
  onToggleLang: () => void;
  transport: 'TLS' | 'CLEARTEXT' | null;
  title: string;
  subtitle: string;
  children: React.ReactNode;
}> = ({ isAr, onToggleLang, transport, title, subtitle, children }) => {
  const reduce = useReducedMotion() ?? false;

  return (
    <div className="relative flex min-h-screen w-full items-center justify-center overflow-hidden bg-black px-4" dir={isAr ? 'rtl' : 'ltr'}>
      <CyberGridBackdrop reduce={reduce} />
      <div
        className="pointer-events-none absolute inset-0"
        style={{ background: 'radial-gradient(ellipse 50% 45% at 50% 45%, rgba(34,211,238,0.08), transparent 70%)' }}
        aria-hidden
      />

      <button
        type="button"
        onClick={onToggleLang}
        className="absolute end-4 top-4 border border-cyan-500/40 bg-black/60 px-2.5 py-1 font-mono text-xs tracking-widest text-cyan-300 transition-colors hover:bg-cyan-500/10 focus-visible:ring-2 focus-visible:ring-cyan-400 focus-visible:outline-none"
        aria-label={isAr ? 'Switch to English' : 'التبديل إلى العربية'}
      >
        {isAr ? 'EN' : 'ع'}
      </button>

      <motion.div
        className="relative w-full max-w-[400px]"
        initial={reduce ? { opacity: 0 } : { opacity: 0, y: 4 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.22, ease: 'easeOut' }}
      >
        <TacticalPanel tone="cyan" chamfer="lg" glow="strong" className="px-6 pt-6 pb-5">
          <div className="flex flex-col items-center text-center">
            <span
              className="grid h-11 w-11 place-items-center border border-cyan-400/60"
              style={{ clipPath: 'polygon(10px 0,100% 0,100% calc(100% - 10px),calc(100% - 10px) 100%,0 100%,0 10px)' }}
            >
              <Crosshair className="h-5 w-5 text-cyan-300" strokeWidth={1.25} aria-hidden />
            </span>
            <p
              className="mt-3 font-mono text-sm font-bold tracking-[0.3em] text-white uppercase"
              style={{ textShadow: '0 0 14px rgba(34,211,238,0.6)' }}
            >
              Sovereign Defender
            </p>
            <h1 className="mt-1 text-base font-semibold text-cyan-200">{title}</h1>
            <p className="mt-1 text-sm leading-relaxed text-slate-300">{subtitle}</p>
          </div>

          <div className="mt-5">{children}</div>

          <div className="mt-5 space-y-1.5 border-t border-cyan-900/50 pt-3 text-xs">
            {transport === 'TLS' ? (
              <p className="flex items-center gap-1.5 text-emerald-300">
                <Lock className="h-3.5 w-3.5 shrink-0" aria-hidden />
                {isAr ? 'الاتصال مشفّر (TLS).' : 'Connection is encrypted (TLS).'}
              </p>
            ) : transport === 'CLEARTEXT' ? (
              <p className="flex items-start gap-1.5 text-amber-300">
                <LockOpen className="mt-0.5 h-3.5 w-3.5 shrink-0" aria-hidden />
                {isAr
                  ? 'الاتصال غير مشفّر. استخدمه على هذا الجهاز فقط، أو فعّل TLS قبل الدخول من الشبكة.'
                  : 'This connection is not encrypted. Use it on this machine only, or enable TLS before signing in over the network.'}
              </p>
            ) : null}
            <p className="flex items-center gap-1.5 text-slate-400">
              <ScrollText className="h-3.5 w-3.5 shrink-0" aria-hidden />
              {isAr ? 'كل محاولة دخول تُسجَّل في سجل التدقيق.' : 'Every sign-in attempt is recorded in the audit trail.'}
            </p>
          </div>
        </TacticalPanel>
      </motion.div>
    </div>
  );
};

/** Labelled input in the access screens. Machine identifiers and secrets use mono (§4). */
export const AccessField: React.FC<
  React.InputHTMLAttributes<HTMLInputElement> & { label: string; hint?: string | null; mono?: boolean; trailing?: React.ReactNode }
> = ({ label, hint, mono = true, trailing, id, ...rest }) => {
  const autoId = React.useId();
  const fid = id ?? autoId;
  return (
    <div className="space-y-1">
      <label htmlFor={fid} className="block text-xs font-medium tracking-wide text-slate-300">
        {label}
      </label>
      <div className="relative">
        <input
          id={fid}
          {...rest}
          className={`w-full border border-cyan-900/70 bg-black/70 px-3 py-2 text-sm text-cyan-100 placeholder:text-slate-500 focus:border-cyan-400/80 focus:ring-1 focus:ring-cyan-400/40 focus:outline-none ${
            mono ? 'font-mono' : ''
          } ${trailing ? 'pe-10' : ''}`}
        />
        {trailing && <span className="absolute inset-y-0 end-0 flex items-center pe-2">{trailing}</span>}
      </div>
      {hint && <p className="text-xs text-slate-400">{hint}</p>}
    </div>
  );
};

export const AccessError: React.FC<{ children: React.ReactNode }> = ({ children }) => (
  <p role="alert" className="border border-rose-500/50 bg-rose-950/40 px-3 py-2 text-sm text-rose-200">
    {children}
  </p>
);
