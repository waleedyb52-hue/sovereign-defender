import React from 'react';
import { Boxes } from 'lucide-react';
import { CyberButton } from './CyberButton';
import { IpLink } from './ipDossier';
import { TWIN_SCENARIOS, type TwinProjection } from './digitalTwin';
import type { PhaseId } from './useWargames';

/**
 * DIGITAL TWIN PANEL — sits under the drill controls in the wargame environment only.
 *
 * It answers the question a drill is for — "which of my machines would this reach?" —
 * from the real inventory, and says plainly what it does not know: devices no sweep has
 * reached are counted as unknown, with the command that would find out.
 */
export const TwinPanel: React.FC<{
  twin: TwinProjection;
  isAr: boolean;
  onScenario: (id: PhaseId) => void;
}> = ({ twin, isAr, onScenario }) => (
  <div className="mt-2 border-t border-amber-500/30 pt-2" dir={isAr ? 'rtl' : 'ltr'}>
    <p className="flex items-center gap-1.5 text-xs font-semibold text-amber-200">
      <Boxes className="h-3.5 w-3.5" aria-hidden />
      {isAr ? 'التوأم الرقمي · محاكاة' : 'DIGITAL TWIN · SIMULATION'}
    </p>
    <div className="mt-1.5 flex flex-wrap gap-1">
      {TWIN_SCENARIOS.map(s => (
        <CyberButton key={s.id} size="sm" tone="amber" active={twin.scenario.id === s.id} onClick={() => onScenario(s.id)} title={isAr ? s.ar : s.en}>
          {s.mitre}
        </CyberButton>
      ))}
    </div>
    <p className="mt-1 text-[11px] text-amber-100/90">{isAr ? twin.scenario.ar : twin.scenario.en}</p>

    <div className="mt-1.5 grid grid-cols-3 gap-1 text-center">
      {(
        [
          [twin.exposed, isAr ? 'مكشوف' : 'EXPOSED', '#fbbf24'],
          [twin.unknown, isAr ? 'مجهول' : 'UNKNOWN', '#94a3b8'],
          [twin.clear, isAr ? 'سليم' : 'CLEAR', '#34d399']
        ] as const
      ).map(([n, label, tone]) => (
        <div key={label} className="border border-white/10 bg-black/40 py-1">
          <p className="font-mono text-base font-bold" style={{ color: tone }}>{n}</p>
          <p className="text-[10px] tracking-widest" style={{ color: tone }}>{label}</p>
        </div>
      ))}
    </div>

    {twin.rows.filter(r => r.state === 'EXPOSED').length > 0 && (
      <ul className="mt-1.5 max-h-28 space-y-0.5 overflow-y-auto">
        {twin.rows
          .filter(r => r.state === 'EXPOSED')
          .map(r => (
            <li key={r.ip} className="flex items-baseline gap-1.5 text-[11px]">
              <IpLink ip={r.ip} className="text-amber-200" />
              <span className="font-mono text-amber-300/80">{r.host ? (isAr ? 'مضيف مراقبة' : 'monitoring host') : r.ports.join(' · ')}</span>
            </li>
          ))}
      </ul>
    )}

    {twin.unknown > 0 && (
      <p className="mt-1 text-[10px] leading-snug text-slate-400">
        {isAr
          ? `${twin.unknown} جهاز لم يُمسح قط، فلا يُعرف انكشافه. مسح مصرّح به يحسم ذلك:`
          : `${twin.unknown} device(s) were never swept, so their exposure is unknown. An authorised sweep settles it:`}{' '}
        <code className="font-mono text-slate-300" dir="ltr">sovereign-sensor --sweep &lt;cidr&gt;</code>
      </p>
    )}
    <p className="mt-1 text-[10px] text-amber-300/70">
      {isAr ? 'إسقاط من المنافذ المفتوحة الحقيقية — ليس تنبؤًا بنجاح الهجوم.' : 'Projected from real open ports — not a prediction that the attack succeeds.'}
    </p>
  </div>
);

export default TwinPanel;
