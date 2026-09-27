import React from 'react';
import { Swords, RotateCcw } from 'lucide-react';
import { CyberButton } from './CyberButton';
import { PHASES, type useWargames } from './useWargames';

/**
 * WARGAMING CONTROL PANEL — only ever mounted in the sandbox environment.
 *
 * Drill launchers do not exist in the DOM in LIVE mode. Not disabled, not hidden by
 * CSS: not rendered. A disabled launcher is one prop away from firing a synthetic APT
 * at a production board, and that is not a risk worth a styling convenience.
 *
 * Every figure here is the sandbox's own state read back from `/wargames/status`, so a
 * reload mid-drill still shows the drill. The panel reports the server's verdict on
 * each launch verbatim, including rejections — a drill reported as started when the
 * server refused it would leave an operator reading a quiet board as a defence that
 * held.
 */
export const WargamePanel: React.FC<{
  w: ReturnType<typeof useWargames>;
  isAr: boolean;
}> = ({ w, isAr }) => (
  <div className="flex h-full min-h-0 flex-col">
    <div className="flex items-center gap-1.5">
      <Swords className="h-3 w-3 text-amber-400" aria-hidden />
      <span
        className="font-mono text-[8px] font-bold tracking-widest text-amber-400 uppercase"
        style={{ textShadow: '0 0 8px rgba(251,191,36,0.8)' }}
      >
        {isAr ? 'سلسلة القتل — محاكاة' : 'KILL CHAIN DRILLS'}
      </span>
    </div>

    {w.unreachable ? (
      <p className="mt-2 font-mono text-[7px] leading-relaxed text-rose-400">
        {isAr
          ? 'تعذّر الوصول إلى /wargames/status — لا حكم على وجود محاكاة جارية، ولن أعرض أزرار إطلاق على حالة مجهولة.'
          : '/wargames/status unreachable — no claim about a running drill, and launchers stay inert against unknown state.'}
      </p>
    ) : (
      <>
        <div className="mt-1.5 grid grid-cols-2 gap-x-2 border-b border-amber-900/40 pb-1.5">
          {[
            [isAr ? 'المرحلة النشطة' : 'ACTIVE PHASE', w.activePhase || null],
            [isAr ? 'متجهات نشطة' : 'LIVE VECTORS', w.activeVectors],
            [isAr ? 'روبوتات' : 'BOTS', w.modBots],
            [isAr ? 'قائمة حجب' : 'BLACKLIST', w.blacklistCount]
          ].map(([k, v]) => (
            <div key={String(k)} className="flex items-baseline justify-between gap-1">
              <span className="font-mono text-[5.5px] tracking-widest text-amber-500/60 uppercase">{k}</span>
              {v == null ? (
                <span className="font-mono text-[8px] text-slate-700">—</span>
              ) : (
                <span className="font-mono text-[9px] font-bold text-amber-400 tabular-nums">{String(v)}</span>
              )}
            </div>
          ))}
        </div>

        {w.hasApt && (
          <p className="mt-1.5 font-mono text-[6.5px] text-rose-400">
            {isAr
              ? w.aptDropped ? 'موطئ APT مُحاكى — أُسقط' : 'موطئ APT مُحاكى — قائم'
              : w.aptDropped ? 'simulated APT foothold — dropped' : 'simulated APT foothold — established'}
          </p>
        )}

        <div className="mt-2 min-h-0 flex-1 space-y-1.5 overflow-y-auto">
          {PHASES.map((p, i) => {
            const active = w.activePhase === i + 1;
            return (
              <div key={p.id}>
                <CyberButton
                  tone="amber"
                  size="sm"
                  className="w-full"
                  active={active}
                  disabled={w.busy != null}
                  onClick={() => w.launch(p.id)}
                >
                  {w.busy === p.id ? (isAr ? '… جارٍ الإطلاق' : '… LAUNCHING') : isAr ? p.labelAr : p.labelEn}
                </CyberButton>
                <p className="mt-0.5 ps-1 font-mono text-[5.5px] text-slate-600">{isAr ? p.mitreAr : p.mitreEn}</p>
              </div>
            );
          })}
        </div>

        <div className="mt-2 border-t border-amber-900/40 pt-2">
          <CyberButton tone="rose" size="sm" className="w-full" disabled={w.busy != null} onClick={w.reset}>
            <span className="flex items-center justify-center gap-1">
              <RotateCcw className="h-2.5 w-2.5" aria-hidden />
              {isAr ? '[ تصفير الصندوق ]' : '[ RESET SANDBOX ]'}
            </span>
          </CyberButton>
          {w.lastResult && <p className="mt-1 font-mono text-[6px] break-words text-amber-300">{w.lastResult}</p>}
        </div>
      </>
    )}
  </div>
);

export default WargamePanel;
