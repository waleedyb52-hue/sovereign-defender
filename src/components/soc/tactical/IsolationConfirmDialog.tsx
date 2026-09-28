import React from 'react';
import { ShieldOff, AlertTriangle, CheckCircle2, XCircle } from 'lucide-react';
import { Modal } from '../../ui/modal';
import { CyberButton } from './CyberButton';
import type { ContainmentOutcome } from './useContainment';

/**
 * ISOLATION CONFIRMATION — the two-step gate in front of every ISOLATE_NODE control.
 *
 * `.clauderules` §8: crimson, unmistakable, two steps, the target named in the second.
 * Before this, both the ZTNA module and the kill-chain rail fired containment on a
 * single click.
 *
 * Step one says what will actually happen, which is not always what the button implied:
 *   - the server action is an eBPF blackhole of the /32, whichever button asked for it;
 *   - on a host whose driver reports emulation, no kernel XDP map is pinned, so the
 *     address lands in the in-process blacklist and not in a kernel map;
 *   - a private address is a host on the operator's own network, and containing it cuts
 *     that host off — the gateway included, if that is what was clicked.
 *
 * Step two names the address on the button itself. Focus opens on the safe control at
 * both steps, so a reflexive Enter backs out rather than isolating.
 *
 * Escape and outside-click are suppressed (`dismissible={false}`); CANCEL is the way out.
 * The result is the server's answer verbatim, including a refusal.
 */

export interface IsolationRequest {
  ip: string;
  /** Which control asked, e.g. "KILL CHAIN · BLACKHOLE". */
  origin: string;
  /** What the operator was looking at when they asked, e.g. the chain or alert title. */
  context?: string | null;
}

type Step = 'REVIEW' | 'CONFIRM' | 'RESULT';

const PRIVATE = [/^10\./, /^192\.168\./, /^172\.(1[6-9]|2\d|3[01])\./, /^127\./, /^169\.254\./];

const Fact: React.FC<{ k: string; children: React.ReactNode }> = ({ k, children }) => (
  <div className="grid grid-cols-[110px_1fr] gap-2 py-1">
    <span className="text-[11px] tracking-wide text-slate-400 uppercase">{k}</span>
    <span className="text-[12px] text-slate-200">{children}</span>
  </div>
);

export const IsolationConfirmDialog: React.FC<{
  request: IsolationRequest | null;
  isAr: boolean;
  driverMode: string | null;
  emulated: boolean;
  busy: boolean;
  onConfirm: (ip: string, reason: string) => Promise<ContainmentOutcome>;
  onClose: () => void;
}> = ({ request, isAr, driverMode, emulated, busy, onConfirm, onClose }) => {
  const [step, setStep] = React.useState<Step>('REVIEW');
  const [outcome, setOutcome] = React.useState<ContainmentOutcome | null>(null);

  // A new request always starts at the review step.
  React.useEffect(() => {
    setStep('REVIEW');
    setOutcome(null);
  }, [request?.ip, request?.origin]);

  if (!request) return null;

  const ip = request.ip;
  const internal = PRIVATE.some(r => r.test(ip));

  const fire = async () => {
    const res = await onConfirm(ip, `Operator isolation from unified cockpit (${request.origin})`);
    setOutcome(res);
    setStep('RESULT');
  };

  return (
    <Modal
      open
      onClose={onClose}
      title={isAr ? 'عزل مضيف' : 'ISOLATE HOST'}
      tone="danger"
      dismissible={false}
      dir={isAr ? 'rtl' : 'ltr'}
      size="md"
    >
      <div className="space-y-3">
        {/* Target, always visible, always in mono */}
        <div className="flex items-center gap-3 border border-rose-500/40 bg-rose-950/30 px-3 py-2.5">
          <ShieldOff className="h-5 w-5 shrink-0 text-rose-400" aria-hidden />
          <div className="min-w-0">
            <p className="text-[10px] tracking-widest text-rose-300/80 uppercase">{isAr ? 'الهدف' : 'TARGET'}</p>
            <p className="font-mono text-lg font-bold text-rose-300" dir="ltr">
              {ip}
              <span className="text-rose-300/60">/32</span>
            </p>
          </div>
          <span className="ms-auto shrink-0 font-mono text-[10px] tracking-widest text-slate-400 uppercase">
            {step === 'REVIEW' ? '1 / 2' : step === 'CONFIRM' ? '2 / 2' : isAr ? 'النتيجة' : 'RESULT'}
          </span>
        </div>

        {step === 'REVIEW' && (
          <>
            <div className="divide-y divide-slate-800/80">
              <Fact k={isAr ? 'الطالب' : 'Requested by'}>{request.origin}</Fact>
              {request.context && <Fact k={isAr ? 'السياق' : 'Context'}>{request.context}</Fact>}
              <Fact k={isAr ? 'إجراء الخادم' : 'Server action'}>
                <span className="font-mono text-[11px] text-rose-300" dir="ltr">
                  POST /soc/ebpf/contain-ip → ACTIVE_BLACKHOLE
                </span>
                <span className="mt-0.5 block text-[11px] text-slate-400">
                  {isAr ? 'تُسقَط كل الحزم الواردة من هذا العنوان.' : 'Every packet from this address is dropped.'}
                </span>
              </Fact>
              <Fact k={isAr ? 'مسار النواة' : 'Kernel path'}>
                <span className="font-mono text-[11px]" dir="ltr" style={{ color: emulated ? '#fbbf24' : '#22d3ee' }}>
                  {driverMode ?? (isAr ? 'غير مُبلَّغ' : 'not reported')}
                </span>
                {emulated && (
                  <span className="mt-0.5 block text-[11px] text-amber-300">
                    {isAr
                      ? 'لا توجد خريطة XDP مثبّتة على هذا المضيف؛ يُكتب العنوان في قائمة الحجب داخل العملية لا في النواة.'
                      : 'No XDP map is pinned on this host, so the address goes to the in-process blacklist, not a kernel map.'}
                  </span>
                )}
              </Fact>
              <Fact k={isAr ? 'قابل للعكس' : 'Reversible'}>
                {isAr
                  ? 'نعم — من «الاحتواءات النشطة» في وحدة الثقة الصفرية أو من إطار الطوارئ.'
                  : 'Yes. Release it from ACTIVE CONTAINMENTS in the ZTNA module, or from the emergency frame.'}
              </Fact>
            </div>

            {internal && (
              <p className="flex items-start gap-2 border border-amber-500/40 bg-amber-950/30 px-3 py-2 text-[12px] text-amber-200">
                <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-amber-400" aria-hidden />
                {isAr
                  ? 'هذا عنوان خاص على شبكتك. عزله يقطع ذلك الجهاز عن الشبكة، وإن كان البوابة فيقطع الشبكة كلها.'
                  : 'This is a private address on your own network. Containing it cuts that device off — and if it is the gateway, everything behind it.'}
              </p>
            )}

            <div className="flex justify-end gap-2 pt-1">
              {/* Safe control first in DOM order, so Radix's initial focus lands on it. */}
              <CyberButton tone="cyan" onClick={onClose}>
                {isAr ? '[ إلغاء ]' : '[ CANCEL ]'}
              </CyberButton>
              <CyberButton tone="rose" onClick={() => setStep('CONFIRM')}>
                {isAr ? '[ متابعة ]' : '[ CONTINUE ]'}
              </CyberButton>
            </div>
          </>
        )}

        {step === 'CONFIRM' && (
          <>
            <p className="text-[13px] leading-relaxed text-slate-200">
              {isAr ? 'تأكيد عزل ' : 'Confirm isolation of '}
              <span className="font-mono font-bold text-rose-300" dir="ltr">
                {ip}
              </span>
              {isAr ? '. يبدأ الإسقاط فور القبول.' : '. Dropping begins as soon as the server accepts.'}
            </p>
            <div className="flex justify-end gap-2 pt-1">
              <BackButton isAr={isAr} disabled={busy} onClick={() => setStep('REVIEW')} />
              <CyberButton tone="rose" disabled={busy} onClick={() => void fire()}>
                {busy ? (isAr ? '… جارٍ العزل' : '… ISOLATING') : `[ ISOLATE ${ip} ]`}
              </CyberButton>
            </div>
          </>
        )}

        {step === 'RESULT' && outcome && (
          <>
            <p
              role="status"
              className={`flex items-start gap-2 border px-3 py-2 text-[12px] ${
                outcome.ok
                  ? 'border-emerald-500/40 bg-emerald-950/30 text-emerald-200'
                  : 'border-rose-500/50 bg-rose-950/40 text-rose-200'
              }`}
            >
              {outcome.ok ? (
                <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-emerald-400" aria-hidden />
              ) : (
                <XCircle className="mt-0.5 h-4 w-4 shrink-0 text-rose-400" aria-hidden />
              )}
              <span>
                <span className="block font-semibold">
                  {outcome.ok
                    ? isAr ? 'قبل الخادم الاحتواء' : 'Server accepted the containment'
                    : isAr ? 'لم يُعزَل المضيف' : 'The host was NOT isolated'}
                </span>
                <span className="font-mono text-[11px]" dir="ltr">
                  {outcome.message}
                </span>
              </span>
            </p>
            <div className="flex justify-end pt-1">
              <CyberButton tone="cyan" onClick={onClose}>
                {isAr ? '[ إغلاق ]' : '[ CLOSE ]'}
              </CyberButton>
            </div>
          </>
        )}
      </div>
    </Modal>
  );
};

/** BACK takes initial focus at step two, so Enter never isolates by reflex. */
const BackButton: React.FC<{ isAr: boolean; disabled: boolean; onClick: () => void }> = ({ isAr, disabled, onClick }) => {
  const ref = React.useRef<HTMLSpanElement>(null);
  React.useEffect(() => {
    ref.current?.closest('button')?.focus();
  }, []);
  return (
    <CyberButton tone="cyan" disabled={disabled} onClick={onClick}>
      <span ref={ref}>{isAr ? '[ رجوع ]' : '[ BACK ]'}</span>
    </CyberButton>
  );
};

export default IsolationConfirmDialog;
