import React, { useState } from 'react';
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

  if (!isOpen) return null;

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
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
      <div className="w-full max-w-2xl max-h-[85vh] flex flex-col p-6 rounded-2xl bg-slate-900 border border-slate-800 shadow-2xl space-y-4 text-left animate-in fade-in zoom-in-95 duration-200 overflow-hidden">
        
        {/* Header */}
        <div className="flex items-center justify-between pb-3 border-b border-slate-800 flex-shrink-0">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-amber-500/20 text-amber-400 border border-amber-500/30">
              <UserCheck className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-base font-black text-white">
                  {isAr ? 'قائمة انتظار موافقة المسؤول (Human-in-the-Loop Approval Queue)' : 'Operator Approval Queue (Manual Flight Mode)'}
                </h3>
                <span className="px-2 py-0.5 rounded-full text-xs font-bold bg-amber-500/20 text-amber-300 font-mono">
                  {pendingItems.length} {isAr ? 'معلق' : 'PENDING'}
                </span>
              </div>
              <p className="text-xs text-slate-400">
                {isAr ? 'مراجعة وتأكيد قواعد الدفاع وتطبيقها يدوياً في جدار حماية النواة' : 'Inspect and authorize AI-recommended kernel defense actions before deployment'}
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Queue Items List */}
        <div className="flex-1 overflow-y-auto space-y-3 pr-1">
          {pendingItems.length === 0 ? (
            <div className="p-12 text-center rounded-xl bg-slate-950/60 border border-slate-800/80 text-slate-400 text-xs">
              <ShieldCheck className="w-8 h-8 text-emerald-400 mx-auto mb-2 opacity-80" />
              <span>{isAr ? 'لا توجد قواعد معلقة بانتظار الموافقة حالياً.' : 'No pending defense rules awaiting operator sign-off.'}</span>
            </div>
          ) : (
            pendingItems.map(item => {
              const isProcessing = processingId === item.id;
              return (
                <div key={item.id} className="p-4 rounded-xl bg-slate-950 border border-slate-800/80 space-y-3">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-mono font-bold text-amber-400">
                        {item.incidentId}
                      </span>
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                        {item.mitreId}
                      </span>
                      <span className="text-xs font-bold text-white">
                        {item.vector}
                      </span>
                    </div>

                    <span className="text-xs font-mono font-bold text-rose-400 bg-rose-950/30 px-2 py-0.5 rounded border border-rose-500/30">
                      Score: {item.threatScore}%
                    </span>
                  </div>

                  <div className="text-xs text-slate-300">
                    <span className="text-slate-500 block mb-0.5">{isAr ? 'المصدر والسبب:' : 'Source & AI Assessment:'}</span>
                    <p className="font-mono text-cyan-300 text-[11px] mb-1">Source IP: {item.srcIp}</p>
                    <p className="text-slate-300 leading-relaxed text-xs">{item.reason}</p>
                  </div>

                  {/* Proposed Rules */}
                  <div className="space-y-1.5 p-2.5 rounded-lg bg-slate-900 border border-slate-800/60 font-mono text-[10px]">
                    <span className="text-slate-500 block">{isAr ? 'القواعد المقترحة للتطبيق:' : 'Proposed Kernel Rules:'}</span>
                    <div className="text-rose-300 truncate"><code>{item.suggestedRules.iptables}</code></div>
                    <div className="text-amber-300 truncate"><code>{item.suggestedRules.suricata}</code></div>
                  </div>

                  {/* Actions */}
                  <div className="flex items-center justify-end gap-2 pt-1">
                    <button
                      onClick={() => handleAction(item.id, 'REJECT')}
                      disabled={isProcessing}
                      className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-bold border border-slate-700 transition disabled:opacity-50"
                    >
                      <X className="w-3.5 h-3.5" />
                      <span>{isAr ? 'تجاهل ورفض' : 'Dismiss'}</span>
                    </button>

                    <button
                      onClick={() => handleAction(item.id, 'APPROVE')}
                      disabled={isProcessing}
                      className="flex items-center gap-1.5 px-4 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-bold shadow-md shadow-emerald-950 transition disabled:opacity-50"
                    >
                      {isProcessing ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Check className="w-3.5 h-3.5" />}
                      <span>{isAr ? 'موافقة وتطبيق فوري' : 'Authorize & Apply'}</span>
                    </button>
                  </div>
                </div>
              );
            })
          )}
        </div>

        {/* Footer */}
        <div className="flex items-center justify-between pt-3 border-t border-slate-800 flex-shrink-0">
          <span className="text-xs text-slate-500">
            {isAr ? 'وضع الطيران: الموافقة اليدوية نشط' : 'Flight Mode: Manual Approval Active'}
          </span>
          <button
            onClick={onClose}
            className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-bold transition"
          >
            {isAr ? 'إغلاق' : 'Close'}
          </button>
        </div>

      </div>
    </div>
  );
};
