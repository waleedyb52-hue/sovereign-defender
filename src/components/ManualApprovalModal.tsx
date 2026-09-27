import React, { useState } from 'react';
import { ModalShell } from './ui/modal';
import {
  Check,
  X,
  ShieldAlert,
  ShieldCheck,
  Terminal,
  AlertCircle,
  Clock,
  UserCheck,
  RefreshCw,
  Code2
} from 'lucide-react';
import { PendingRuleApproval } from '../types';

interface ManualApprovalModalProps {
  isOpen: boolean;
  onClose: () => void;
  lang: 'ar' | 'en';
  queue: PendingRuleApproval[];
  onActionComplete: () => void;
}

export const ManualApprovalModal: React.FC<ManualApprovalModalProps> = ({
  isOpen,
  onClose,
  lang,
  queue,
  onActionComplete
}) => {
  const isAr = lang === 'ar';
  const [processingId, setProcessingId] = useState<string | null>(null);

  // Early return removed: Radix owns mount and unmount, and bailing out
  // before it renders skips focus restoration to the trigger.

  const pendingItems = queue.filter(item => item.status === 'PENDING');

  const handleAction = async (id: string, action: 'APPROVE' | 'REJECT') => {
    setProcessingId(id);
    try {
      const res = await fetch('/api/v1/approval-queue/action', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id, action })
      });
      if (res.ok) {
        onActionComplete();
      }
    } catch (err) {
      console.error('Approval action error:', err);
    } finally {
      setProcessingId(null);
    }
  };

  return (
    <ModalShell
      open={isOpen}
      onClose={onClose}
      title={isAr ? 'طلبات الموافقة اليدوية' : 'Manual approval queue'}
      dir={isAr ? 'rtl' : 'ltr'}
      overlayClassName="bg-black/80"
      className="w-full max-w-2xl"
    >
      <div className="animate-in fade-in zoom-in-95 flex max-h-[85vh] w-full max-w-2xl flex-col space-y-4 overflow-hidden rounded-2xl border border-slate-800 bg-slate-900 p-6 text-left shadow-2xl duration-200 shadow-[0_0_20px_rgba(0,255,255,0.08)]">
        {/* Header */}
        <div className="flex flex-shrink-0 items-center justify-between border-b border-slate-800 pb-3">
          <div className="flex items-center gap-3">
            <div className="rounded-xl border border-amber-500/30 bg-amber-500/20 p-2.5 text-amber-400">
              <UserCheck className="h-5 w-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-base font-black text-white">
                  {isAr
                    ? 'قائمة انتظار موافقة المسؤول (Human-in-the-Loop Approval Queue)'
                    : 'Operator Approval Queue (Manual Flight Mode)'}
                </h3>
                <span className="rounded-full bg-amber-500/20 px-2 py-0.5 font-mono text-xs font-bold text-amber-300">
                  {pendingItems.length} {isAr ? 'معلق' : 'PENDING'}
                </span>
              </div>
              <p className="text-xs text-slate-400">
                {isAr
                  ? 'مراجعة وتأكيد قواعد الدفاع وتطبيقها يدوياً في جدار حماية النواة'
                  : 'Inspect and authorize AI-recommended kernel defense actions before deployment'}
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="rounded-lg p-1.5 text-slate-400 transition hover:bg-slate-800 hover:text-slate-200"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        {/* Queue Items List */}
        <div className="flex-1 space-y-3 overflow-y-auto pr-1">
          {pendingItems.length === 0 ? (
            <div className="rounded-xl border border-slate-800/80 bg-slate-950/60 p-12 text-center text-xs text-slate-400 shadow-[0_0_20px_rgba(0,255,255,0.08)]">
              <ShieldCheck className="mx-auto mb-2 h-8 w-8 text-emerald-400 opacity-80" />
              <span>
                {isAr
                  ? 'لا توجد قواعد معلقة بانتظار الموافقة حالياً.'
                  : 'No pending defense rules awaiting operator sign-off.'}
              </span>
            </div>
          ) : (
            pendingItems.map(item => {
              const isProcessing = processingId === item.id;
              return (
                <div
                  key={item.id}
                  className="space-y-3 rounded-xl border border-slate-800/80 bg-slate-950 p-4 shadow-[0_0_20px_rgba(0,255,255,0.08)]"
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-xs font-bold text-amber-400">
                        {item.incidentId}
                      </span>
                      <span className="rounded bg-slate-800 px-2 py-0.5 font-mono text-[10px] text-slate-300">
                        {item.mitreId}
                      </span>
                      <span className="text-xs font-bold text-white">{item.vector}</span>
                    </div>

                    <span className="rounded border border-rose-500/30 bg-rose-950/30 px-2 py-0.5 font-mono text-xs font-bold text-rose-400">
                      Score: {item.threatScore}%
                    </span>
                  </div>

                  <div className="text-xs text-slate-300">
                    <span className="mb-0.5 block text-slate-500">
                      {isAr ? 'المصدر والسبب:' : 'Source & AI Assessment:'}
                    </span>
                    <p className="mb-1 font-mono text-[11px] text-cyan-300">
                      Source IP: {item.srcIp}
                    </p>
                    <p className="text-xs leading-relaxed text-slate-300">{item.reason}</p>
                  </div>

                  {/* Proposed Rules */}
                  <div className="space-y-1.5 rounded-lg border border-slate-800/60 bg-slate-900 p-2.5 font-mono text-[10px] shadow-[0_0_20px_rgba(0,255,255,0.08)]">
                    <span className="block text-slate-500">
                      {isAr ? 'القواعد المقترحة للتطبيق:' : 'Proposed Kernel Rules:'}
                    </span>
                    <div className="truncate text-rose-300">
                      <code>{item.suggestedRules.iptables}</code>
                    </div>
                    <div className="truncate text-amber-300">
                      <code>{item.suggestedRules.suricata}</code>
                    </div>
                  </div>

                  {/* Actions */}
                  <div className="flex items-center justify-end gap-2 pt-1">
                    <button
                      onClick={() => handleAction(item.id, 'REJECT')}
                      disabled={isProcessing}
                      className="flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800 px-3 py-1.5 text-xs font-bold text-slate-300 transition hover:bg-slate-700 disabled:opacity-50"
                    >
                      <X className="h-3.5 w-3.5" />
                      <span>{isAr ? 'تجاهل ورفض' : 'Dismiss'}</span>
                    </button>

                    <button
                      onClick={() => handleAction(item.id, 'APPROVE')}
                      disabled={isProcessing}
                      className="flex items-center gap-1.5 rounded-lg bg-emerald-600 px-4 py-1.5 text-xs font-bold text-white shadow-md shadow-emerald-950 transition hover:bg-emerald-500 disabled:opacity-50"
                    >
                      {isProcessing ? (
                        <RefreshCw className="h-3.5 w-3.5 animate-spin" />
                      ) : (
                        <Check className="h-3.5 w-3.5" />
                      )}
                      <span>{isAr ? 'موافقة وتطبيق فوري' : 'Authorize & Apply'}</span>
                    </button>
                  </div>
                </div>
              );
            })
          )}
        </div>

        {/* Footer */}
        <div className="flex flex-shrink-0 items-center justify-between border-t border-slate-800 pt-3">
          <span className="text-xs text-slate-500">
            {isAr ? 'وضع الطيران: الموافقة اليدوية نشط' : 'Flight Mode: Manual Approval Active'}
          </span>
          <button
            onClick={onClose}
            className="rounded-xl bg-slate-800 px-4 py-2 text-xs font-bold text-slate-200 transition hover:bg-slate-700"
          >
            {isAr ? 'إغلاق' : 'Close'}
          </button>
        </div>
      </div>
    </ModalShell>
  );
};
