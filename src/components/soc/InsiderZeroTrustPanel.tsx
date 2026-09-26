import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  Lock,
  Unlock,
  Key,
  AlertTriangle,
  UserCheck,
  UserX,
  Play,
  CheckCircle2,
  XCircle,
  Terminal,
  Clock,
  Send,
  Database,
  Trash2,
  FileCode,
  Sparkles,
  Smartphone,
  Check,
  AlertOctagon,
  RefreshCw
} from 'lucide-react';

export interface PrivilegedActionItem {
  id: string;
  timestamp: string;
  actor: {
    username: string;
    role: string;
    ipAddress: string;
    terminal: string;
    sessionPid: number;
    elevationMethod: string;
  };
  actionType: string;
  targetResource: string;
  commandSnippet: string;
  riskScore: number;
  status:
    'FROZEN_PENDING_APPROVAL' | 'APPROVED_BY_TEAM_LEAD' | 'REJECTED_TERMINATED' | 'EXPIRED_TIMEOUT';
  intentAnalysis: {
    summary: string;
    summaryAr: string;
    threatClassification: string;
    mitreTechnique: string;
    potentialImpact: string;
  };
  approvalVerification: {
    otpExpiry: string;
    attemptsRemaining: number;
    teamLeadRecipient: string;
    notifiedChannels: string[];
    approvedBy?: string;
    approvedAt?: string;
    decisionNotes?: string;
  };
  demoOtp?: string;
}

interface InsiderZeroTrustPanelProps {
  lang: 'en' | 'ar';
}

export const InsiderZeroTrustPanel: React.FC<InsiderZeroTrustPanelProps> = ({ lang }) => {
  const isAr = lang === 'ar';

  const [actions, setActions] = useState<PrivilegedActionItem[]>([]);
  const [selectedAction, setSelectedAction] = useState<PrivilegedActionItem | null>(null);
  const [otpInput, setOtpInput] = useState<string>('');
  const [teamLeadName, setTeamLeadName] = useState<string>('Major_AlHarbi_SecOps_Lead');
  const [rejectionNotes, setRejectionNotes] = useState<string>('');
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [actionFeedback, setActionFeedback] = useState<{
    type: 'success' | 'error';
    message: string;
  } | null>(null);

  const fetchActions = async () => {
    try {
      const res = await fetch('/api/v1/insider-zero-trust/actions');
      const data = await res.json();
      if (data.success && data.actions) {
        setActions(data.actions);
        if (!selectedAction && data.actions.length > 0) {
          setSelectedAction(data.actions[0]);
        }
      }
    } catch (err) {
      console.warn('Failed to fetch zero-trust actions:', err);
    }
  };

  useEffect(() => {
    fetchActions();
    const interval = setInterval(fetchActions, 4000);
    return () => clearInterval(interval);
  }, []);

  // Handle Privileged Simulation Trigger
  const handleTriggerSimulation = async (
    scenario: 'CREDENTIAL_EXFIL' | 'DB_MASS_EXPORT' | 'ROOT_LOG_DELETION'
  ) => {
    setIsLoading(true);
    setActionFeedback(null);
    try {
      const res = await fetch('/api/v1/insider-zero-trust/simulate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scenario })
      });
      const data = await res.json();
      if (data.success) {
        setActionFeedback({
          type: 'success',
          message: isAr ? data.messageAr : data.message
        });
        await fetchActions();
        if (data.action) {
          setSelectedAction({ ...data.action, demoOtp: data.demoOtp });
        }
      }
    } catch (err) {
      setActionFeedback({ type: 'error', message: 'Failed to simulate privileged action.' });
    } finally {
      setIsLoading(false);
    }
  };

  // Handle Verify OTP & Authorize / Deny
  const handleAuthorizeOrDeny = async (decision: 'APPROVE' | 'REJECT') => {
    if (!selectedAction) return;

    setIsLoading(true);
    setActionFeedback(null);
    try {
      const res = await fetch('/api/v1/insider-zero-trust/authorize', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          actionId: selectedAction.id,
          otpInput: otpInput.trim(),
          decision,
          teamLeadName,
          notes: rejectionNotes
        })
      });
      const data = await res.json();
      if (data.success) {
        setActionFeedback({
          type: 'success',
          message: isAr ? data.messageAr : data.message
        });
        setOtpInput('');
        await fetchActions();
      } else {
        setActionFeedback({
          type: 'error',
          message: isAr ? data.messageAr : data.message
        });
      }
    } catch (err) {
      setActionFeedback({
        type: 'error',
        message: 'Network error during authorization verification.'
      });
    } finally {
      setIsLoading(false);
    }
  };

  const frozenPendingCount = actions.filter(a => a.status === 'FROZEN_PENDING_APPROVAL').length;

  return (
    <div className="space-y-6 rounded-xl border border-slate-800 bg-slate-900/90 p-5 shadow-2xl backdrop-blur-md">
      {/* Header */}
      <div className="flex flex-col items-start justify-between gap-4 border-b border-slate-800 pb-4 md:flex-row md:items-center">
        <div className="flex items-center gap-3">
          <div className="rounded-lg border border-rose-500/30 bg-gradient-to-br from-rose-500/20 to-amber-500/20 p-2.5">
            <Lock className="h-5 w-5 animate-pulse text-rose-400" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-base font-bold text-slate-100">
                {isAr
                  ? 'نظام انعدام الثقة الديناميكي ومنع التهديدات الداخلية (Zero-Trust Insider Shield)'
                  : 'AI-Driven Insider Threat Prevention & Dynamic Zero-Trust'}
              </h3>
              <span className="rounded border border-rose-700/50 bg-rose-950/80 px-2 py-0.5 text-[10px] font-bold text-rose-300">
                Phase 3 Active
              </span>
            </div>
            <p className="text-xs text-slate-400">
              {isAr
                ? 'اعتراض فوري لكافة الأوامر الخطيرة حتى من مستخدمي Root ومسؤولي النظام، وتجميد التنفيذ لحين إدخال رمز تصريح قائد الفريق الأمني (OTP)'
                : 'Freezes privileged Root/Admin destructive transactions in real-time until approved by dynamic Team Lead OTP.'}
            </p>
          </div>
        </div>

        {/* Live Pending Counter Badge */}
        <div className="flex items-center gap-2">
          <span className="text-xs text-slate-400">
            {isAr ? 'العمليات المجمدة:' : 'Frozen In-Flight:'}
          </span>
          <span className="animate-pulse rounded-full border border-rose-500/40 bg-rose-500/20 px-2.5 py-1 font-mono text-xs font-bold text-rose-300">
            {frozenPendingCount} {isAr ? 'بانتظار الاعتماد' : 'Pending OTP'}
          </span>
          <button
            onClick={fetchActions}
            className="rounded-lg bg-slate-800 p-1.5 text-slate-400 hover:text-slate-200"
            title="Refresh"
          >
            <RefreshCw className="h-4 w-4" />
          </button>
        </div>
      </div>

      {/* Adversarial Simulation Bar */}
      <div className="space-y-2 rounded-xl border border-slate-800 bg-slate-950/80 p-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2 text-xs font-bold text-slate-300">
            <Terminal className="h-4 w-4 text-cyan-400" />
            <span>
              {isAr
                ? 'محاكاة اختبار التهديد الداخلي ومحاولات المشرفين المنحرفين (Rogue Admin Drills)'
                : 'Simulate Privileged Insider Violations'}
            </span>
          </div>
          <span className="text-[11px] text-slate-500">
            {isAr ? 'اختبار تجميد التنفيذ وطلب رمز التصريح' : 'Live Zero-Trust Interceptor'}
          </span>
        </div>

        <div className="flex flex-wrap items-center gap-2 pt-1">
          <button
            onClick={() => handleTriggerSimulation('CREDENTIAL_EXFIL')}
            disabled={isLoading}
            className="flex items-center gap-1.5 rounded-lg border border-rose-800/60 bg-rose-950/60 px-3 py-1.5 text-xs font-semibold text-rose-200 transition hover:bg-rose-900/80"
          >
            <Key className="h-3.5 w-3.5 text-rose-400" />
            <span>
              {isAr ? 'محاولة استخراج /etc/shadow وتسريبه' : 'Exfil /etc/shadow via curl'}
            </span>
          </button>

          <button
            onClick={() => handleTriggerSimulation('DB_MASS_EXPORT')}
            disabled={isLoading}
            className="flex items-center gap-1.5 rounded-lg border border-amber-800/60 bg-amber-950/60 px-3 py-1.5 text-xs font-semibold text-amber-200 transition hover:bg-amber-900/80"
          >
            <Database className="h-3.5 w-3.5 text-amber-400" />
            <span>
              {isAr ? 'محاولة تصدير كامل قاعدة البيانات للخارج' : 'Unencrypted DB Dump to Netcat'}
            </span>
          </button>

          <button
            onClick={() => handleTriggerSimulation('ROOT_LOG_DELETION')}
            disabled={isLoading}
            className="flex items-center gap-1.5 rounded-lg border border-purple-800/60 bg-purple-950/60 px-3 py-1.5 text-xs font-semibold text-purple-200 transition hover:bg-purple-900/80"
          >
            <Trash2 className="h-3.5 w-3.5 text-purple-400" />
            <span>
              {isAr ? 'حساب Root يحاول إتلاف السجلات الجنائية' : 'Root Shredd Audit Logs'}
            </span>
          </button>
        </div>
      </div>

      {/* Feedback Banner */}
      {actionFeedback && (
        <div
          className={`animate-in fade-in flex items-center gap-2.5 rounded-xl border p-3 text-xs ${
            actionFeedback.type === 'success'
              ? 'border-emerald-500/40 bg-emerald-950/60 text-emerald-200'
              : 'border-rose-500/40 bg-rose-950/60 text-rose-200'
          }`}
        >
          {actionFeedback.type === 'success' ? (
            <CheckCircle2 className="h-4 w-4 text-emerald-400" />
          ) : (
            <AlertOctagon className="h-4 w-4 text-rose-400" />
          )}
          <span>{actionFeedback.message}</span>
        </div>
      )}

      {/* Main Two-Column Layout */}
      <div className="grid grid-cols-1 gap-5 lg:grid-cols-12">
        {/* Left Column: List of Intercepted Actions */}
        <div className="space-y-3 lg:col-span-5">
          <div className="flex items-center justify-between text-xs font-semibold tracking-wider text-slate-400 uppercase">
            <span>
              {isAr
                ? 'العمليات الموقوفة بنظام انعدام الثقة'
                : 'Intercepted Privileged Transactions'}
            </span>
            <span className="font-mono text-[10px] text-slate-500">
              {actions.length} {isAr ? 'عملية' : 'logged'}
            </span>
          </div>

          <div className="max-h-[460px] space-y-2 overflow-y-auto pr-1">
            {actions.map(act => {
              const isSelected = selectedAction?.id === act.id;
              const isFrozen = act.status === 'FROZEN_PENDING_APPROVAL';

              return (
                <div
                  key={act.id}
                  onClick={() => setSelectedAction(act)}
                  className={`cursor-pointer space-y-2 rounded-xl border p-3.5 text-xs transition ${
                    isSelected
                      ? 'border-cyan-500 bg-slate-800/90 shadow-md'
                      : 'border-slate-800 bg-slate-950/60 hover:border-slate-700'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <span className="font-mono font-bold text-slate-200">{act.id}</span>
                      <span className="rounded bg-slate-800 px-1.5 py-0.5 font-mono text-[10px] text-slate-300">
                        {act.actor.username} ({act.actor.role})
                      </span>
                    </div>
                    <span
                      className={`rounded-full px-2 py-0.5 text-[10px] font-bold ${
                        act.status === 'FROZEN_PENDING_APPROVAL'
                          ? 'animate-pulse border border-rose-800 bg-rose-950 text-rose-300'
                          : act.status === 'APPROVED_BY_TEAM_LEAD'
                            ? 'border border-emerald-800 bg-emerald-950 text-emerald-300'
                            : 'border border-slate-700 bg-slate-800 text-slate-400'
                      }`}
                    >
                      {act.status === 'FROZEN_PENDING_APPROVAL'
                        ? isAr
                          ? 'مجمدة فورياً'
                          : 'FROZEN'
                        : act.status === 'APPROVED_BY_TEAM_LEAD'
                          ? isAr
                            ? 'مصرح بها'
                            : 'APPROVED'
                          : isAr
                            ? 'مرفوضة'
                            : 'TERMINATED'}
                    </span>
                  </div>

                  <div className="truncate rounded border border-slate-800/80 bg-slate-900/80 px-2 py-1 font-mono text-[11px] text-cyan-300">
                    $ {act.commandSnippet}
                  </div>

                  <div className="flex items-center justify-between pt-1 text-[10px] text-slate-400">
                    <span>
                      Target: <strong className="text-slate-300">{act.targetResource}</strong>
                    </span>
                    <span>
                      Risk: <strong className="font-mono text-rose-400">{act.riskScore}/100</strong>
                    </span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Right Column: Selected Action Deep Dive & Team Lead OTP Approval Terminal */}
        <div className="space-y-5 rounded-xl border border-slate-800 bg-slate-950/90 p-5 lg:col-span-7">
          {selectedAction ? (
            <>
              {/* Header Details */}
              <div className="flex items-start justify-between gap-3 border-b border-slate-800 pb-3">
                <div>
                  <div className="flex items-center gap-2">
                    <h4 className="text-sm font-bold text-slate-100">
                      {isAr
                        ? 'تفاصيل العملية واعتماد تصريح المشرف'
                        : 'Privileged Execution Authorization Terminal'}
                    </h4>
                    <span className="font-mono text-xs text-cyan-400">{selectedAction.id}</span>
                  </div>
                  <p className="mt-1 text-xs text-slate-400">
                    {isAr
                      ? selectedAction.intentAnalysis.summaryAr
                      : selectedAction.intentAnalysis.summary}
                  </p>
                </div>

                <div
                  className={`flex min-w-[70px] flex-col items-center justify-center rounded-xl border p-2.5 ${
                    selectedAction.riskScore > 90
                      ? 'border-rose-800 bg-rose-950/50 text-rose-300'
                      : 'border-amber-800 bg-amber-950/50 text-amber-300'
                  }`}
                >
                  <span className="text-[9px] font-bold uppercase">
                    {isAr ? 'الخطورة' : 'Risk'}
                  </span>
                  <span className="font-mono text-lg font-black">{selectedAction.riskScore}</span>
                </div>
              </div>

              {/* Actor & Execution Blueprint */}
              <div className="grid grid-cols-2 gap-2 text-xs sm:grid-cols-4">
                <div className="rounded-lg border border-slate-800 bg-slate-900 p-2.5">
                  <span className="block text-[10px] text-slate-500">
                    {isAr ? 'المستخدم' : 'Actor'}
                  </span>
                  <strong className="font-mono text-slate-200">
                    {selectedAction.actor.username}
                  </strong>
                </div>
                <div className="rounded-lg border border-slate-800 bg-slate-900 p-2.5">
                  <span className="block text-[10px] text-slate-500">
                    {isAr ? 'الصلاحية' : 'Elevation'}
                  </span>
                  <strong className="font-mono text-cyan-400">
                    {selectedAction.actor.role} ({selectedAction.actor.elevationMethod})
                  </strong>
                </div>
                <div className="rounded-lg border border-slate-800 bg-slate-900 p-2.5">
                  <span className="block text-[10px] text-slate-500">
                    {isAr ? 'عنوان IP' : 'Client IP'}
                  </span>
                  <strong className="font-mono text-slate-300">
                    {selectedAction.actor.ipAddress}
                  </strong>
                </div>
                <div className="rounded-lg border border-slate-800 bg-slate-900 p-2.5">
                  <span className="block text-[10px] text-slate-500">
                    {isAr ? 'تقنية MITRE' : 'MITRE'}
                  </span>
                  <strong className="font-mono text-amber-400">
                    {selectedAction.intentAnalysis.mitreTechnique}
                  </strong>
                </div>
              </div>

              {/* Frozen Command Box */}
              <div className="space-y-1.5 rounded-xl border border-rose-500/30 bg-black/80 p-3">
                <div className="flex items-center justify-between text-[11px] font-semibold text-rose-400">
                  <span className="flex items-center gap-1.5">
                    <Lock className="h-3.5 w-3.5" />
                    <span>
                      {isAr
                        ? 'الأمر التنفيذي المجمد في النواة (Kernel Paused Execution)'
                        : 'Intercepted & Frozen Execution Payload'}
                    </span>
                  </span>
                  <span className="font-mono text-[10px] text-slate-500">
                    PID: {selectedAction.actor.sessionPid}
                  </span>
                </div>
                <pre className="overflow-x-auto rounded border border-rose-900/40 bg-rose-950/20 p-2 font-mono text-xs whitespace-pre-wrap text-rose-300">
                  {selectedAction.commandSnippet}
                </pre>
              </div>

              {/* Approval / OTP Workflow Box */}
              {selectedAction.status === 'FROZEN_PENDING_APPROVAL' ? (
                <div className="space-y-4 rounded-xl border border-cyan-500/30 bg-gradient-to-br from-slate-900 to-slate-950 p-4">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <Smartphone className="h-4 w-4 animate-pulse text-cyan-400" />
                      <span className="text-xs font-bold text-slate-200">
                        {isAr
                          ? 'إجراء اعتماد قائد الفريق (Team Lead OTP Verification)'
                          : 'SOC Team Lead Dynamic OTP Verification'}
                      </span>
                    </div>

                    {/* Demo Helper: Display dispatched OTP so drill evaluator doesn't need external SMS */}
                    {selectedAction.demoOtp && (
                      <span className="rounded border border-cyan-700/60 bg-cyan-950 px-2 py-0.5 font-mono text-[10px] text-cyan-300">
                        {isAr ? 'رمز OTP التجريبي للمناورة:' : 'Drill OTP:'}{' '}
                        <strong>{selectedAction.demoOtp}</strong>
                      </span>
                    )}
                  </div>

                  <p className="text-xs text-slate-400">
                    {isAr
                      ? `تم إرسال رمز التحقق (OTP) المشفر إلى قنوات قائد الفريق: ${selectedAction.approvalVerification.teamLeadRecipient}. تنتهي الصلاحية خلال 3 دقائق.`
                      : `Cryptographic 6-digit OTP dispatched to Team Lead channels: ${selectedAction.approvalVerification.teamLeadRecipient}.`}
                  </p>

                  <div className="flex flex-col items-center gap-3 sm:flex-row">
                    <div className="w-full sm:w-1/2">
                      <input
                        type="text"
                        maxLength={6}
                        value={otpInput}
                        onChange={e => setOtpInput(e.target.value.replace(/\D/g, ''))}
                        placeholder={
                          isAr ? 'أدخل رمز الـ OTP المكون من 6 أرقام' : 'Enter 6-digit dynamic OTP'
                        }
                        className="w-full rounded-xl border border-cyan-500/50 bg-slate-950 px-3.5 py-2.5 text-center font-mono text-lg font-bold tracking-widest text-cyan-300 focus:ring-2 focus:ring-cyan-500 focus:outline-none"
                      />
                    </div>

                    <div className="flex w-full items-center gap-2 sm:w-1/2">
                      <button
                        onClick={() => handleAuthorizeOrDeny('APPROVE')}
                        disabled={isLoading || otpInput.length !== 6}
                        className="flex flex-1 items-center justify-center gap-1.5 rounded-xl bg-emerald-600 py-2.5 text-xs font-bold text-white transition hover:bg-emerald-500 disabled:opacity-50"
                      >
                        <UserCheck className="h-4 w-4" />
                        <span>{isAr ? 'تصريح وفك التجميد' : 'Verify & Authorize'}</span>
                      </button>

                      <button
                        onClick={() => handleAuthorizeOrDeny('REJECT')}
                        disabled={isLoading}
                        className="flex flex-1 items-center justify-center gap-1.5 rounded-xl bg-rose-600/80 py-2.5 text-xs font-bold text-white transition hover:bg-rose-600 disabled:opacity-50"
                      >
                        <UserX className="h-4 w-4" />
                        <span>{isAr ? 'رفض وعزل المستخدم' : 'Deny & Terminate'}</span>
                      </button>
                    </div>
                  </div>
                </div>
              ) : (
                <div className="space-y-1.5 rounded-xl border border-slate-800 bg-slate-900/60 p-3.5 text-xs">
                  <div className="flex items-center gap-2 font-semibold text-slate-300">
                    <CheckCircle2 className="h-4 w-4 text-emerald-400" />
                    <span>
                      {isAr ? 'سجل التوثيق والاعتماد' : 'Audit Trail & Verification Sign-off'}
                    </span>
                  </div>
                  <p className="text-slate-400">
                    Decision: <strong className="text-slate-200">{selectedAction.status}</strong> by{' '}
                    <strong className="text-cyan-300">
                      {selectedAction.approvalVerification.approvedBy || 'Team Lead'}
                    </strong>{' '}
                    at{' '}
                    <span className="font-mono text-slate-400">
                      {selectedAction.approvalVerification.approvedAt || 'N/A'}
                    </span>
                    .
                  </p>
                </div>
              )}
            </>
          ) : (
            <div className="flex h-64 items-center justify-center text-xs text-slate-500">
              {isAr
                ? 'اختر عملية موقوفة من القائمة لعرض تفاصيلها'
                : 'Select an intercepted transaction to review details.'}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
