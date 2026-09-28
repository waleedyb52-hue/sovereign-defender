import React from 'react';
import { FolderLock, TriangleAlert } from 'lucide-react';
import { CyberButton } from './CyberButton';
import type { Tripwire } from './useTripwire';

/**
 * RANSOMWARE TRIPWIRES — which folders carry decoys, whether the decoys are intact, and
 * what has tripped.
 *
 * Adding a folder writes two files into it, so the form says exactly which two before
 * the operator presses anything. People's own files in the folder are read, never
 * written; the panel says that too, because "the security tool will touch my documents"
 * is the first question anyone should ask.
 */

const KIND: Record<string, [string, string]> = {
  TRIPWIRE_ENCRYPTED: ['فخّ مُشفَّر', 'DECOY ENCRYPTED'],
  TRIPWIRE_REMOVED: ['فخّ محذوف', 'DECOY REMOVED'],
  TRIPWIRE_MODIFIED: ['فخّ مُعدَّل', 'DECOY MODIFIED'],
  ENCRYPTION_BURST: ['موجة تشفير', 'ENCRYPTION BURST']
};

export const TripwirePanel: React.FC<{ t: Tripwire; isAr: boolean; canAdmin: boolean }> = ({ t, isAr, canAdmin }) => {
  const [dir, setDir] = React.useState('');
  const [problem, setProblem] = React.useState<string | null>(null);
  const [busy, setBusy] = React.useState(false);
  const s = t.status;

  const protect = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    const p = await t.protect(dir.trim());
    setProblem(p);
    if (!p) setDir('');
    setBusy(false);
  };

  return (
    <section className="mt-3 border border-cyan-900/50 bg-black/40 p-3" dir={isAr ? 'rtl' : 'ltr'} aria-label={isAr ? 'فخاخ برامج الفدية' : 'Ransomware tripwires'}>
      <div className="flex flex-wrap items-center gap-2">
        <FolderLock className="h-4 w-4 text-cyan-300" aria-hidden />
        <h3 className="text-sm font-semibold text-cyan-100">{isAr ? 'فخاخ برامج الفدية' : 'Ransomware tripwires'}</h3>
        {s && (
          <span className="ms-auto font-mono text-[10px] text-slate-400" dir="ltr">
            burst ≥{s.burstRule.files} files / {s.burstRule.windowSec}s · H &gt; {s.entropyThreshold}
          </span>
        )}
      </div>

      {t.error && <p className="mt-2 font-mono text-xs text-rose-300" dir="ltr">{t.error}</p>}

      {/* Incidents first: they are the reason this panel exists. */}
      {s && s.incidents.length > 0 && (
        <ul className="mt-2 space-y-1.5" role="log" aria-label={isAr ? 'حوادث الفخاخ' : 'Tripwire incidents'}>
          {s.incidents.slice(0, 8).map(i => (
            <li key={i.id} className="border border-rose-500/50 bg-rose-950/30 px-2 py-1.5">
              <p className="flex flex-wrap items-baseline gap-2 text-xs">
                <TriangleAlert className="h-3.5 w-3.5 self-center text-rose-400" aria-hidden />
                <span className="font-mono font-bold text-rose-300">{isAr ? KIND[i.kind][0] : KIND[i.kind][1]}</span>
                <span className="font-mono text-slate-300" dir="ltr">{i.at.slice(11, 19)}</span>
                <span className="font-mono text-cyan-300">{i.mitre.split(' ')[0]}</span>
                {i.entropy != null && <span className="font-mono text-slate-400" dir="ltr">H={i.entropy}</span>}
                {i.count != null && <span className="font-mono text-slate-400" dir="ltr">{i.count} files</span>}
              </p>
              <p className="mt-0.5 text-xs text-rose-100/90" dir="auto">{i.detail}</p>
              {i.evidencePath && (
                <p className="mt-0.5 truncate font-mono text-[10px] text-slate-400" dir="ltr" title={i.evidencePath}>
                  evidence: {i.evidencePath}
                </p>
              )}
            </li>
          ))}
        </ul>
      )}

      {/* Protected folders */}
      <div className="mt-2">
        {!s ? null : s.dirs.length === 0 ? (
          <p className="text-xs text-slate-400">
            {isAr
              ? 'لا يوجد مجلد محمي بعد. اختر المجلدات التي تحوي عملًا مهمًا، مثل «المستندات» أو مجلد مشترك.'
              : 'No folder is protected yet. Choose folders that hold important work, such as Documents or a shared drive.'}
          </p>
        ) : (
          <ul className="space-y-1">
            {s.dirs.map(d => {
              const allIntact = d.decoys.length > 0 && d.decoys.every(x => x.intact);
              return (
                <li key={d.dir} className="flex flex-wrap items-center gap-2 border-b border-white/[0.05] pb-1 text-xs">
                  <span className="font-mono text-slate-100" dir="ltr">{d.dir}</span>
                  <span className={allIntact ? 'text-emerald-300' : 'text-rose-300'}>
                    {allIntact ? (isAr ? '✓ الفخاخ سليمة' : '✓ decoys intact') : isAr ? '✗ فخ غير سليم' : '✗ decoy not intact'}
                  </span>
                  {!d.watching && <span className="text-amber-300">{isAr ? 'المراقبة متوقفة' : 'not watching'}</span>}
                  <span className="text-[10px] text-slate-400">
                    {d.source === 'ENV' ? 'CANARY_DIRS' : `${d.addedBy} · ${d.addedAt.slice(0, 10)}`}
                  </span>
                  {canAdmin && d.source === 'OPERATOR' && (
                    <span className="ms-auto">
                      <CyberButton size="sm" tone="rose" onClick={async () => setProblem(await t.unprotect(d.dir))}>
                        {isAr ? 'إزالة الحماية' : 'UNPROTECT'}
                      </CyberButton>
                    </span>
                  )}
                </li>
              );
            })}
          </ul>
        )}
      </div>

      {canAdmin && (
        <form onSubmit={protect} className="mt-3 space-y-1.5 border-t border-cyan-900/50 pt-2.5">
          <label htmlFor="tripwire-dir" className="block text-xs font-medium text-slate-300">
            {isAr ? 'حماية مجلد (مسار كامل)' : 'Protect a folder (absolute path)'}
          </label>
          <div className="flex gap-2">
            <input
              id="tripwire-dir"
              dir="ltr"
              value={dir}
              onChange={e => setDir(e.target.value)}
              placeholder="C:\Users\name\Documents"
              spellCheck={false}
              className="min-w-0 flex-1 border border-cyan-900/70 bg-black/70 px-2 py-1.5 font-mono text-xs text-cyan-100 placeholder:text-slate-500 focus:border-cyan-400/80 focus:outline-none"
            />
            <CyberButton type="submit" size="sm" tone="cyan" disabled={busy || !dir.trim()}>
              {isAr ? 'حماية' : 'PROTECT'}
            </CyberButton>
          </div>
          <p className="text-[11px] leading-relaxed text-slate-400">
            {isAr ? 'سيُنشأ ملفّا فخّ في المجلد: ' : 'Two decoy files will be created in the folder: '}
            <code className="font-mono text-slate-300" dir="ltr">!000-sovereign-tripwire-do-not-edit.txt</code>{' '}
            {isAr ? 'و' : 'and'}{' '}
            <code className="font-mono text-slate-300" dir="ltr">zzz-sovereign-tripwire-do-not-edit.txt</code>.{' '}
            {isAr
              ? 'ملفاتك الأخرى تُقرأ فقط عند تغيّرها لرصد موجات التشفير، ولا تُعدَّل أبدًا.'
              : 'Your other files are only read when they change, to spot an encryption burst — never modified.'}
          </p>
          {problem && <p role="alert" className="text-xs text-rose-300">{problem}</p>}
        </form>
      )}
    </section>
  );
};

export default TripwirePanel;
