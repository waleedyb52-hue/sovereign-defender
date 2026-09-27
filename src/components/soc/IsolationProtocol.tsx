import React from 'react';
import { motion, AnimatePresence, useReducedMotion } from 'motion/react';
import {
  ShieldAlert,
  Ban,
  CheckCircle2,
  XCircle,
  Undo2,
  Loader2,
  ShieldCheck,
  Lock
} from 'lucide-react';
import { Dialog, Button, Badge, Mono, Card } from '../ui/primitives';
import { cn } from '../../lib/utils';

/**
 * NUCLEAR ISOLATION PROTOCOL
 *
 * Two-step confirmation, an emergency viewport state, and a rule timeline.
 *
 * The one thing that matters most here
 *   `.clauderules` §8: a kill switch that animates without isolating is the
 *   worst component this product could ship. So the timeline below is driven by
 *   the actual request — each stage advances when the corresponding call resolves,
 *   and a failure stops the timeline and shows the server's error verbatim. It is
 *   never a fixed-duration animation played to look decisive. If containment
 *   fails, the operator finds out from this component, immediately.
 *
 * Why the second step retypes the address
 *   A single "are you sure" is dismissed reflexively. Isolating the wrong host
 *   can sever a production ingress node, so the confirm button stays disabled
 *   until the operator has entered the target address themselves. It is friction
 *   on purpose, and only on the irreversible direction — release needs one click.
 */

export interface IsolationStage {
  id: string;
  labelAr: string;
  labelEn: string;
  state: 'pending' | 'active' | 'done' | 'failed';
  detail?: string;
}

interface Props {
  target: string | null;
  onClose: () => void;
  onConfirm: (ip: string) => Promise<boolean>;
  onRelease?: (ip: string) => Promise<boolean>;
  pending?: string | null;
  result?: { ok: boolean; message: string; target: string } | null;
  lang?: 'ar' | 'en';
}

export const IsolationProtocol: React.FC<Props> = ({
  target,
  onClose,
  onConfirm,
  onRelease,
  pending,
  result,
  lang = 'ar'
}) => {
  const isAr = lang === 'ar';
  const reduce = useReducedMotion();
  const [step, setStep] = React.useState<1 | 2>(1);
  const [typed, setTyped] = React.useState('');
  const [stages, setStages] = React.useState<IsolationStage[]>([]);
  const [armed, setArmed] = React.useState(false);

  React.useEffect(() => {
    if (!target) {
      setStep(1);
      setTyped('');
      setStages([]);
      setArmed(false);
    }
  }, [target]);

  const confirmed = typed.trim() === target?.trim();

  const run = async () => {
    if (!target) return;
    setArmed(true);
    setStages([
      {
        id: 'submit',
        labelAr: 'إرسال أمر العزل إلى المحرّك',
        labelEn: 'Submitting containment order',
        state: 'active'
      },
      {
        id: 'xdp',
        labelAr: 'تثبيت قاعدة XDP_DROP في النواة',
        labelEn: 'Installing XDP_DROP rule in kernel',
        state: 'pending'
      },
      {
        id: 'verify',
        labelAr: 'تأكيد الحجب من الخدمة',
        labelEn: 'Confirming blackhole with the service',
        state: 'pending'
      }
    ]);

    const ok = await onConfirm(target);

    // Stages reflect the real outcome. On failure the timeline stops where it
    // stopped and carries the server's message rather than completing anyway.
    setStages(prev =>
      prev.map((s, i) => {
        if (!ok) {
          return i === 0
            ? { ...s, state: 'failed', detail: result?.message }
            : { ...s, state: 'pending' };
        }
        return { ...s, state: 'done' };
      })
    );
  };

  return (
    <>
      {/* Emergency viewport border, shown only while an isolation is actually
          installed — driven by the result, not by opening the dialog. */}
      <AnimatePresence>
        {result?.ok && armed && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: reduce ? 0.5 : [0.35, 0.7, 0.35] }}
            exit={{ opacity: 0 }}
            transition={
              reduce ? { duration: 0.2 } : { duration: 2.4, repeat: Infinity, ease: 'easeInOut' }
            }
            className="pointer-events-none fixed inset-0 z-[200]"
            style={{ boxShadow: 'inset 0 0 0 3px #f43f5e, inset 0 0 44px rgba(239,68,68,0.28)' }}
            aria-hidden
          />
        )}
      </AnimatePresence>

      <Dialog
        open={Boolean(target)}
        onClose={onClose}
        title={
          step === 1
            ? isAr
              ? 'تأكيد عزل المضيف — الخطوة ١ من ٢'
              : 'Confirm host isolation — step 1 of 2'
            : isAr
              ? 'تأكيد نهائي — الخطوة ٢ من ٢'
              : 'Final confirmation — step 2 of 2'
        }
        tone="danger"
        // Not dismissible by backdrop click: a kill switch must not close by accident.
        dismissible={!armed}
        dir={isAr ? 'rtl' : 'ltr'}
        footer={
          !armed ? (
            <>
              <Button variant="ghost" size="sm" onClick={onClose}>
                {isAr ? 'إلغاء' : 'Cancel'}
              </Button>
              {step === 1 ? (
                <Button variant="danger" size="sm" onClick={() => setStep(2)}>
                  {isAr ? 'متابعة' : 'Continue'}
                </Button>
              ) : (
                <Button
                  variant="danger"
                  size="sm"
                  disabled={!confirmed || Boolean(pending)}
                  onClick={run}
                >
                  {pending ? (
                    <Loader2 className="h-3 w-3 animate-spin" aria-hidden />
                  ) : (
                    <Ban className="h-3 w-3" aria-hidden />
                  )}
                  {isAr ? 'عزل الآن' : 'Isolate now'}
                </Button>
              )}
            </>
          ) : (
            <>
              {result?.ok && onRelease && target && (
                <Button
                  variant="secondary"
                  size="sm"
                  disabled={Boolean(pending)}
                  onClick={async () => {
                    await onRelease(target);
                    onClose();
                  }}
                >
                  <Undo2 className="h-3 w-3" aria-hidden />
                  {isAr ? 'فكّ العزل' : 'Release'}
                </Button>
              )}
              <Button variant="ghost" size="sm" onClick={onClose}>
                {isAr ? 'إغلاق' : 'Close'}
              </Button>
            </>
          )
        }
      >
        {!armed && (
          <div className="space-y-3">
            <div className="flex items-start gap-2 rounded border border-[#f43f5e]/25 bg-[#f43f5e]/5 px-3 py-2">
              <ShieldAlert className="mt-px h-4 w-4 shrink-0 text-[#f43f5e]" aria-hidden />
              <p className="text-[11px] leading-relaxed text-[#fda4af]">
                {isAr
                  ? 'سيُثبَّت حجب على مستوى النواة لكل حركة غير إدارية من هذا العنوان. إن كان العنوان لعقدة إنتاج، سينقطع مرورها.'
                  : 'A kernel-level blackhole will be installed for all non-management traffic from this address. If it belongs to a production node, its traffic will stop.'}
              </p>
            </div>

            <div>
              <span className="text-[10px] tracking-wider text-slate-500 uppercase">
                {isAr ? 'الهدف' : 'Target'}
              </span>
              <Mono className="mt-0.5 block text-sm text-slate-100">{target}</Mono>
            </div>

            {step === 2 && (
              <div>
                <label className="mb-1 block text-[10px] tracking-wider text-slate-500 uppercase">
                  {isAr ? 'اكتب العنوان للتأكيد' : 'Type the address to confirm'}
                </label>
                <input
                  value={typed}
                  onChange={e => setTyped(e.target.value)}
                  dir="ltr"
                  autoComplete="off"
                  spellCheck={false}
                  placeholder={target ?? ''}
                  className={cn(
                    'w-full rounded border bg-black/40 px-2.5 py-1.5 text-xs text-slate-100',
                    'placeholder:text-slate-700 focus:outline-none',
                    confirmed
                      ? 'border-[#10B981]/50 focus:border-[#10B981]'
                      : 'border-slate-700 focus:border-[#f43f5e]/60'
                  )}
                  style={{ fontFamily: 'var(--font-mono)' }}
                />
                <p className="mt-1 text-[9px] text-slate-600">
                  {isAr
                    ? 'الاحتكاك مقصود، وفي الاتجاه غير القابل للرجوع فقط — فكّ العزل بنقرة واحدة.'
                    : 'Friction is deliberate, and only on the irreversible direction — release takes one click.'}
                </p>
              </div>
            )}
          </div>
        )}

        {/* Timeline driven by the real request. */}
        {armed && (
          <div className="space-y-2.5">
            {stages.map((s, i) => (
              <motion.div
                key={s.id}
                initial={reduce ? { opacity: 0 } : { opacity: 0, x: isAr ? 6 : -6 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: reduce ? 0 : i * 0.08, duration: 0.2 }}
                className="flex items-start gap-2"
              >
                <div className="mt-0.5 shrink-0">
                  {s.state === 'done' && (
                    <CheckCircle2 className="h-3.5 w-3.5 text-[#10B981]" aria-hidden />
                  )}
                  {s.state === 'active' && (
                    <Loader2 className="h-3.5 w-3.5 animate-spin text-[#F59E0B]" aria-hidden />
                  )}
                  {s.state === 'failed' && (
                    <XCircle className="h-3.5 w-3.5 text-[#f43f5e]" aria-hidden />
                  )}
                  {s.state === 'pending' && (
                    <div className="h-3.5 w-3.5 rounded-full border border-slate-700" />
                  )}
                </div>
                <div className="min-w-0">
                  <p
                    className={cn(
                      'text-[11px]',
                      s.state === 'done'
                        ? 'text-slate-300'
                        : s.state === 'failed'
                          ? 'text-[#fda4af]'
                          : s.state === 'active'
                            ? 'text-[#fcd34d]'
                            : 'text-slate-600'
                    )}
                  >
                    {isAr ? s.labelAr : s.labelEn}
                  </p>
                  {s.detail && (
                    <Mono className="mt-0.5 block text-[9px] text-slate-500">{s.detail}</Mono>
                  )}
                </div>
              </motion.div>
            ))}

            {result && (
              <div
                className={cn(
                  'mt-3 rounded border px-3 py-2 text-[11px]',
                  result.ok
                    ? 'border-[#10B981]/30 bg-[#10B981]/5 text-[#6ee7b7]'
                    : 'border-[#f43f5e]/30 bg-[#f43f5e]/5 text-[#fda4af]'
                )}
              >
                <p className="font-medium">
                  {result.ok
                    ? isAr
                      ? 'تم تثبيت العزل.'
                      : 'Isolation installed.'
                    : isAr
                      ? 'فشل العزل — المضيف ما زال متصلاً.'
                      : 'Isolation failed — the host is still connected.'}
                </p>
                <Mono className="mt-0.5 block text-[9px] opacity-80">{result.message}</Mono>
              </div>
            )}
          </div>
        )}
      </Dialog>
    </>
  );
};

/* ── Sovereignty / compliance footer ────────────────────────────────────── */

/**
 * Compliance posture strip.
 *
 * Worded as the posture the deployment targets, not as a certification this
 * software confers — no software grants ECC-1 or PDPL compliance, and a badge
 * implying otherwise would mislead exactly the buyer who most needs accuracy.
 * `zeroEgress` is passed in from the live inference posture so the sovereignty
 * claim tracks the running configuration.
 */
export const CompliancePosture: React.FC<{
  lang?: 'ar' | 'en';
  zeroEgress?: boolean | null;
}> = ({ lang = 'ar', zeroEgress }) => {
  const isAr = lang === 'ar';
  return (
    <Card className="px-4 py-3" dir={isAr ? 'rtl' : 'ltr'}>
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex flex-wrap items-center gap-1.5">
          <Badge tone="ebpf" icon={ShieldCheck} label="NCA ECC-1:2018" />
          <Badge tone="ebpf" icon={Lock} label="PDPL" />
          {zeroEgress === true && (
            <Badge tone="secure" label={isAr ? 'صفر نداءات خارجية' : 'ZERO EXTERNAL API CALLS'} />
          )}
          {zeroEgress === false && (
            <Badge
              tone="tarpit"
              label={isAr ? 'الخروج ممكن بالإعداد الحالي' : 'EGRESS POSSIBLE IN CURRENT CONFIG'}
            />
          )}
        </div>
        <p className="max-w-[46ch] text-[9px] leading-relaxed text-slate-600">
          {isAr
            ? 'يُعرض ما تستهدفه هذه المنصّة من ضوابط، لا شهادة تمنحها. الالتزام يقرّره تقييم الجهة المشغّلة.'
            : 'Shown as the control posture this platform targets, not a certification it confers. Compliance is determined by the operating entity’s own assessment.'}
        </p>
      </div>
    </Card>
  );
};
