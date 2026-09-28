import React from 'react';
import { Search, KeyRound, Terminal, Anchor, Radio, Upload, Cpu, ShieldCheck, Eye, FileLock2, Bot, Ban } from 'lucide-react';
import { CYAN, CRIMSON, AMBER, EMERALD, Readout } from './TacticalPrimitives';
import type { RibbonChain } from './useDefenseRibbon';

/**
 * KILL CHAIN & CONTAINMENT RAIL
 *
 * The MITRE chain from `KillChainPanel`, moved out of its own page and into the
 * cockpit as a vertical illuminated pipeline. The stage list and the control that owns
 * each stage are lifted from that panel unchanged rather than re-derived, because the
 * mapping between a chain stage and the defence that intercepts it is a security claim
 * this platform makes elsewhere, and two copies that drift would mean the cockpit and
 * the panel disagreeing about which control stopped an attack.
 *
 * The interception point is computed, not chosen: it is the first stage the observed
 * chain has NOT reached, i.e. the stage whose control is what stands between the
 * attacker and progress. With no observed chain there is no interception point, and
 * the rail says so instead of pointing at a default stage — a rail that always shows
 * an intercept implies a defence that has always engaged.
 *
 * Containment actions are surfaced but not fired blind: each is disabled unless a
 * real chain with a real actor IP is selected, because the alternative is a button
 * that looks armed and either does nothing or bans an address nobody identified.
 */

interface StageModel {
  key: string;
  labelAr: string;
  labelEn: string;
  icon: React.ElementType;
  defenceAr: string;
  defenceEn: string;
  defenceIcon: React.ElementType;
}

/** The canonical chain, ordered. Kept identical to KillChainPanel's CHAIN. */
const CHAIN: StageModel[] = [
  { key: 'Reconnaissance', labelAr: 'الاستطلاع', labelEn: 'Reconnaissance', icon: Search, defenceAr: 'فلترة النواة eBPF/XDP', defenceEn: 'eBPF/XDP Kernel Filter', defenceIcon: Cpu },
  { key: 'Initial Access', labelAr: 'الوصول الأولي', labelEn: 'Initial Access', icon: KeyRound, defenceAr: 'جدار الحماية WAF', defenceEn: 'WAF / Rate Limiting', defenceIcon: ShieldCheck },
  { key: 'Execution', labelAr: 'التنفيذ', labelEn: 'Execution', icon: Terminal, defenceAr: 'الفحص العميق للحمولة', defenceEn: 'Deep Payload Inspection', defenceIcon: Eye },
  { key: 'Persistence', labelAr: 'ترسيخ الوجود', labelEn: 'Persistence', icon: Anchor, defenceAr: 'مراقبة سلامة الملفات FIM', defenceEn: 'File Integrity (FIM)', defenceIcon: FileLock2 },
  { key: 'Command and Control', labelAr: 'القيادة والسيطرة', labelEn: 'Command & Control', icon: Radio, defenceAr: 'صندوق الخداع Honeypot', defenceEn: 'Deception / Tarpit', defenceIcon: Bot },
  { key: 'Exfiltration', labelAr: 'سحب البيانات', labelEn: 'Exfiltration', icon: Upload, defenceAr: 'منع تسريب البيانات DLP', defenceEn: 'DLP / Egress Block', defenceIcon: Ban }
];

/** Chamfered HUD button. Disabled states stay visibly inert, not merely dimmed. */
export const HudButton: React.FC<{
  children: React.ReactNode;
  tone?: 'cyan' | 'rose';
  disabled?: boolean;
  title?: string;
  onClick?: () => void;
}> = ({ children, tone = 'cyan', disabled, title, onClick }) => {
  const hex = tone === 'rose' ? CRIMSON : CYAN;
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      title={title}
      className="w-full px-2 py-1 text-[11px] tracking-[0.14em] transition-colors disabled:cursor-not-allowed"
      style={{
        fontFamily: 'var(--font-mono)',
        clipPath: 'polygon(6px 0,100% 0,100% calc(100% - 6px),calc(100% - 6px) 100%,0 100%,0 6px)',
        border: `1px solid ${hex}${disabled ? '22' : '66'}`,
        background: disabled ? 'rgba(255,255,255,0.015)' : `${hex}12`,
        color: disabled ? '#3d4a57' : hex,
        boxShadow: disabled ? 'none' : `0 0 14px ${hex}22`
      }}
    >
      {children}
    </button>
  );
};

interface Props {
  chains: RibbonChain[];
  isAr: boolean;
  /** Names the feed in the empty state so a quiet rail is explained. */
  endpoint?: string;
  onContain?: (action: ContainAction, actorIp: string) => void;
  /**
   * Actions the backend can actually perform. TARPIT defaults to unsupported: there is
   * no route that engages a tarpit by address (only /soc/sensors/tarpit/release), and
   * the button used to call contain-ip — a full blackhole — while saying TARPIT.
   */
  supported?: ReadonlyArray<ContainAction>;
  chainsUnavailable?: boolean;
}

export type ContainAction = 'ISOLATE' | 'BLACKHOLE' | 'TARPIT';

export const KillChainRail: React.FC<Props> = ({
  chains,
  isAr,
  endpoint = '/soc/attack-chains',
  onContain,
  supported = ['ISOLATE', 'BLACKHOLE'],
  chainsUnavailable = false
}) => {
  const [selected, setSelected] = React.useState(0);
  const chain = chains[selected] ?? chains[0] ?? null;

  const reached = new Set((chain?.stages ?? []).map(s => s.stage));

  /**
   * The interception point: the first stage the chain has not reached.
   *
   * Null when no chain is observed. A rail that always marks an intercept would be
   * claiming a defence engaged on an attack that was never seen.
   */
  const interceptIdx = chain ? CHAIN.findIndex(s => !reached.has(s.key)) : -1;

  return (
    <div className="flex h-full min-h-0 flex-col">
      {/* Chain selector, only when more than one is live */}
      {chains.length > 1 && (
        <div className="mb-2 flex flex-wrap gap-1">
          {chains.slice(0, 6).map((c, i) => (
            <button
              key={c.sessionId}
              type="button"
              onClick={() => setSelected(i)}
              className="px-1.5 py-0.5 text-[10px] transition-colors"
              style={{
                fontFamily: 'var(--font-mono)',
                border: `1px solid ${i === selected ? CYAN + '88' : 'rgba(255,255,255,0.08)'}`,
                color: i === selected ? CYAN : '#5c7484',
                background: i === selected ? `${CYAN}14` : 'transparent'
              }}
            >
              {c.actorIp ?? c.sessionId.slice(0, 8)}
            </button>
          ))}
        </div>
      )}

      {/* Selected actor */}
      {chain ? (
        <div className="mb-2 border-b pb-2" style={{ borderColor: `${CYAN}1a` }}>
          <div className="flex items-baseline justify-between gap-2">
            <Readout className="text-[11px] text-rose-400">{chain.actorIp ?? (isAr ? 'مصدر غير معرّف' : 'unidentified actor')}</Readout>
            {chain.threatScore != null ? (
              <Readout className="text-[10px] font-bold text-rose-500">{chain.threatScore}</Readout>
            ) : (
              <span className="text-[11px] text-slate-500" title={isAr ? 'لم تُصدر درجة' : 'no score issued'}>
                —
              </span>
            )}
          </div>
          <p className="mt-0.5 text-[10px] text-slate-600" style={{ fontFamily: 'var(--font-mono)' }}>
            {chain.stages.length}/{CHAIN.length} {isAr ? 'مرحلة مرصودة' : 'STAGES OBSERVED'}
          </p>
        </div>
      ) : (
        <div className="mb-2 border-b pb-2" style={{ borderColor: `${CYAN}1a` }}>
          <p className="text-[11px] leading-relaxed text-slate-500">
            {chainsUnavailable
              ? isAr
                ? `تعذّر قراءة ${endpoint} — لا حكم على وجود سلاسل.`
                : `${endpoint} unreachable — no claim made about chains.`
              : isAr
                ? 'لا سلاسل هجوم مرصودة. المسار أدناه هو الدفاع المتاح، لا اعتراضٌ جارٍ.'
                : 'No attack chains observed. The rail below shows available defence, not an engagement in progress.'}
          </p>
        </div>
      )}

      {/* The vertical pipeline */}
      <div className="min-h-0 flex-1 overflow-y-auto">
        {CHAIN.map((s, i) => {
          const hit = reached.has(s.key);
          const isIntercept = i === interceptIdx;
          const tone = hit ? CRIMSON : isIntercept ? AMBER : `${CYAN}55`;
          const Icon = s.icon;
          const DefIcon = s.defenceIcon;
          const stage = chain?.stages.find(x => x.stage === s.key);

          return (
            <div key={s.key} className="relative ps-5 pb-2.5">
              {/* Spine, brighter through the reached portion */}
              {i < CHAIN.length - 1 && (
                <span
                  className="absolute start-[6px] top-3 bottom-0 w-px"
                  style={{ background: hit ? `${CRIMSON}66` : `${CYAN}1f` }}
                  aria-hidden
                />
              )}
              {/* Node */}
              <span
                className="absolute start-[2px] top-[3px] h-2.5 w-2.5 rotate-45"
                style={{
                  border: `1.5px solid ${tone}`,
                  background: hit ? CRIMSON : isIntercept ? AMBER : 'transparent',
                  boxShadow: hit || isIntercept ? `0 0 8px ${tone}` : 'none'
                }}
                aria-hidden
              />

              <div className="flex items-baseline gap-1.5">
                <Icon className="h-2.5 w-2.5 shrink-0" style={{ color: tone }} aria-hidden />
                <span
                  className="text-[11px] font-semibold tracking-[0.1em]"
                  style={{ color: hit ? '#fda4af' : isIntercept ? '#fcd34d' : '#8aa4b8', fontFamily: 'var(--font-mono)' }}
                >
                  {isAr ? s.labelAr : s.labelEn}
                </span>
                {stage?.technique && (
                  <Readout className="ms-auto text-[10px] text-rose-400/80">{stage.technique}</Readout>
                )}
              </div>

              {/* The control that owns this stage */}
              <div className="mt-0.5 flex items-center gap-1">
                <DefIcon className="h-2 w-2 shrink-0" style={{ color: `${EMERALD}aa` }} aria-hidden />
                <span className="truncate text-[10px] text-slate-500">{isAr ? s.defenceAr : s.defenceEn}</span>
              </div>

              {isIntercept && (
                <p className="mt-0.5 text-[10px] tracking-[0.12em] text-amber-400" style={{ fontFamily: 'var(--font-mono)' }}>
                  {isAr ? '◂ نقطة الاعتراض' : '◂ INTERCEPT POINT'}
                </p>
              )}
            </div>
          );
        })}
      </div>

      {/* Containment actions */}
      <div className="mt-2 space-y-1 border-t pt-2" style={{ borderColor: `${CYAN}1a` }}>
        <p className="mb-1 text-[10px] tracking-[0.16em] text-slate-600" style={{ fontFamily: 'var(--font-mono)' }}>
          {isAr ? 'إجراءات الاحتواء' : 'CONTAINMENT'}
        </p>
        {(['ISOLATE', 'BLACKHOLE', 'TARPIT'] as const).map(action => {
          const can = supported.includes(action);
          const armed = can && Boolean(chain?.actorIp && onContain);
          return (
            <HudButton
              key={action}
              tone={action === 'TARPIT' ? 'cyan' : 'rose'}
              disabled={!armed}
              title={
                armed
                  ? undefined
                  : !can
                    ? isAr
                      ? 'لا مسار في الخادم يفعّل مصيدة الإبطاء لعنوان'
                      : 'no backend route engages a tarpit for an address'
                    : isAr
                      ? 'يتطلّب سلسلة مرصودة بعنوان مصدر محدّد'
                      : 'requires an observed chain with an identified actor IP'
              }
              onClick={armed ? () => onContain!(action, chain!.actorIp!) : undefined}
            >
              {action === 'ISOLATE'
                ? isAr ? 'عزل العقدة' : 'ISOLATE NODE'
                : action === 'BLACKHOLE'
                  ? isAr ? 'حجب كامل' : 'BLACKHOLE'
                  : isAr ? 'مصيدة إبطاء' : 'TARPIT'}
            </HudButton>
          );
        })}
      </div>
    </div>
  );
};

export default KillChainRail;
