import React, { useState } from 'react';
import { ShieldAlert, Loader2, CheckCircle2, XCircle, Ban, Undo2 } from 'lucide-react';

export interface NodeIsolationButtonProps {
  targetId: string;
  /** Address of the target, when the caller knows it. */
  targetIp?: string;
  targetType?: 'NODE' | 'IP' | 'CIDR';
  targetLabel?: string;
  isAlreadyIsolated?: boolean;
  onSuccess?: (targetId: string, status: 'ISOLATED' | 'RELEASED') => void;
  onError?: (errorMessage: string) => void;
  lang?: 'ar' | 'en';
  className?: string;
  size?: 'sm' | 'md' | 'lg';
}

export const NodeIsolationButton: React.FC<NodeIsolationButtonProps> = ({
  targetId,
  targetIp,
  targetType = 'NODE',
  targetLabel,
  isAlreadyIsolated = false,
  onSuccess,
  onError,
  lang = 'ar',
  className = '',
  size = 'md'
}) => {
  const isAr = lang === 'ar';
  const [isIsolating, setIsIsolating] = useState<boolean>(false);
  const [isolationStatus, setIsolationStatus] = useState<'idle' | 'success' | 'error'>('idle');
  const [toastMessage, setToToastMessage] = useState<string | null>(null);

  const displayTarget = targetLabel || targetIp || targetId;

  const handleExecuteIsolation = async (e: React.MouseEvent) => {
    e.stopPropagation();
    if (isIsolating) return;

    setIsIsolating(true);
    setIsolationStatus('idle');
    setToToastMessage(null);

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 8000);

    try {
      if (isAlreadyIsolated) {
        // Asynchronous release call
        const response = await fetch('/api/v1/ebpf/release', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            target: targetId,
            targetType
          }),
          signal: controller.signal
        });

        clearTimeout(timeoutId);

        if (response.ok && response.status === 200) {
          setIsolationStatus('idle');
          setIsIsolating(false);
          setToToastMessage(isAr ? 'تم فك العزل واستعادة المسار' : 'Node Restored from Isolation');
          if (onSuccess) onSuccess(targetId, 'RELEASED');
          setTimeout(() => setToToastMessage(null), 4000);
          return;
        } else {
          throw new Error(isAr ? 'فشل فك العزل: الخادم غير متاح' : 'Release Failed: Backend Unreachable');
        }
      }

      // Execute Real Asynchronous eBPF Isolation API Call
      const response = await fetch('/api/v1/ebpf/quarantine', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          target: targetId,
          targetType,
          reason: `Military-Grade Zero-Trust Isolation for ${targetType} [${targetId}]`
        }),
        signal: controller.signal
      });

      clearTimeout(timeoutId);

      // ONLY if HTTP status is 200 OK
      if (response.ok && response.status === 200) {
        const payload = await response.json();
        setIsolationStatus('success');
        setIsIsolating(false);
        const confirmMsg = isAr ? 'تم تأكيد العزل في النواة (Isolation Confirmed)' : 'Isolation Confirmed';
        setToToastMessage(confirmMsg);

        if (onSuccess) {
          onSuccess(targetId, 'ISOLATED');
        }

        // Auto-clear success toast after 4.5 seconds
        setTimeout(() => {
          setToToastMessage(null);
        }, 4500);
      } else {
        const errJson = await response.json().catch(() => null);
        const serverErr = errJson?.error || (isAr ? 'فشل العزل: الخادم غير متاح' : 'Isolation Failed: Backend Unreachable');
        throw new Error(serverErr);
      }
    } catch (err: any) {
      clearTimeout(timeoutId);
      setIsIsolating(false);
      setIsolationStatus('error');

      const isAborted = err?.name === 'AbortError';
      const failMsg = isAborted
        ? (isAr ? 'فشل العزل: انتهاء مهلة الاتصال بالخادم' : 'Isolation Failed: Gateway Timeout (8s)')
        : (err?.message || (isAr ? 'فشل العزل: تعذر الوصول إلى الواجهة الخلفية' : 'Isolation Failed: Backend Unreachable'));

      setToToastMessage(failMsg);

      if (onError) {
        onError(failMsg);
      }

      // Auto-clear error toast after 5 seconds
      setTimeout(() => {
        setIsolationStatus('idle');
        setToToastMessage(null);
      }, 5000);
    }
  };

  const sizeClasses = {
    sm: 'px-2.5 py-1 text-xs',
    md: 'px-3.5 py-1.5 text-xs',
    lg: 'px-4 py-2 text-sm'
  }[size];

  return (
    <div className="relative inline-flex flex-col items-start gap-1">
      <button
        type="button"
        id={`btn-isolate-${targetId.replace(/[^a-zA-Z0-9_-]/g, '_')}`}
        onClick={handleExecuteIsolation}
        disabled={isIsolating}
        title={
          isAlreadyIsolated
            ? (isAr ? `إلغاء عزل ${displayTarget}` : `Release isolation for ${displayTarget}`)
            : (isAr ? `عزل فوري في النواة عبر eBPF لـ ${displayTarget}` : `Instant eBPF Zero-Trust Isolation for ${displayTarget}`)
        }
        className={`inline-flex items-center justify-center gap-2 rounded font-mono font-bold tracking-tight transition-all duration-150 border disabled:cursor-wait select-none ${sizeClasses} ${
          isAlreadyIsolated
            ? 'bg-[#131a24] hover:bg-[#161b22] text-[#3fb950] border-[#3fb950]/60 hover:border-[#3fb950] shadow-[0_0_10px_rgba(57,255,20,0.15)]'
            : isolationStatus === 'success'
            ? 'bg-[#131a24] text-[#3fb950] border-[#3fb950] shadow-[0_0_12px_rgba(57,255,20,0.3)]'
            : isolationStatus === 'error'
            ? 'bg-[#131a24] text-[#f85149] border-[#f85149] shadow-[0_0_12px_rgba(255,0,60,0.3)]'
            : isIsolating
            ? 'bg-[#131a24] text-[#fab219] border-[#fab219]/70'
            : 'bg-[#131a24] hover:bg-[#1f0a0e] text-[#f85149] border-[#f85149]/80 hover:border-[#f85149] shadow-[0_0_8px_rgba(255,0,60,0.2)]'
        } ${className}`}
      >
        {/* State Indicator Icon */}
        {isIsolating ? (
          <Loader2 className="w-3.5 h-3.5 text-[#fab219] animate-spin flex-shrink-0" />
        ) : isAlreadyIsolated ? (
          <Undo2 className="w-3.5 h-3.5 text-[#3fb950] flex-shrink-0" />
        ) : isolationStatus === 'success' ? (
          <CheckCircle2 className="w-3.5 h-3.5 text-[#3fb950] flex-shrink-0" />
        ) : isolationStatus === 'error' ? (
          <XCircle className="w-3.5 h-3.5 text-[#f85149] flex-shrink-0" />
        ) : (
          <Ban className="w-3.5 h-3.5 text-[#f85149] flex-shrink-0" />
        )}

        {/* Button Label */}
        <span>
          {isIsolating
            ? (isAr ? 'جاري العزل في النواة...' : 'Enforcing eBPF Drop...')
            : isAlreadyIsolated
            ? (isAr ? 'فك العزل' : 'Release Isolation')
            : isolationStatus === 'success'
            ? (isAr ? 'تم تأكيد العزل' : 'Isolation Confirmed')
            : (isAr ? 'عزل العقدة (eBPF)' : 'Isolate Node (eBPF)')}
        </span>
      </button>

      {/* Red Error Toast or Green Success Notification Banner */}
      {toastMessage && (
        <div
          role="alert"
          className={`absolute top-full mt-1.5 z-50 whitespace-nowrap px-3 py-1.5 rounded text-[11px] font-mono border shadow-2xl flex items-center gap-2 animate-in fade-in zoom-in-95 duration-150 ${
            isolationStatus === 'error'
              ? 'bg-[#131a24] text-[#f85149] border-[#f85149] shadow-[0_4px_20px_rgba(255,0,60,0.4)]'
              : 'bg-[#131a24] text-[#3fb950] border-[#3fb950] shadow-[0_4px_20px_rgba(57,255,20,0.3)]'
          }`}
        >
          {isolationStatus === 'error' ? (
            <XCircle className="w-3.5 h-3.5 text-[#f85149] flex-shrink-0" />
          ) : (
            <CheckCircle2 className="w-3.5 h-3.5 text-[#3fb950] flex-shrink-0" />
          )}
          <span className="font-semibold">{toastMessage}</span>
          <button
            type="button"
            onClick={() => setToToastMessage(null)}
            className="ms-1 text-[#93a1b3] hover:text-[#e6edf3] text-xs font-bold leading-none"
          >
            ✕
          </button>
        </div>
      )}
    </div>
  );
};
