import React, { useState, useEffect } from 'react';
import {
  Bell,
  Send,
  Check,
  X,
  Sliders,
  ShieldAlert,
  Radio,
  MessageSquare,
  Sparkles,
  RefreshCw,
  Zap,
  Globe
} from 'lucide-react';
import { AlertWebhookConfig } from '../types';

interface AlertConfigModalProps {
  isOpen: boolean;
  onClose: () => void;
  lang: 'ar' | 'en';
}

export const AlertConfigModal: React.FC<AlertConfigModalProps> = ({ isOpen, onClose, lang }) => {
  const isAr = lang === 'ar';
  const [config, setConfig] = useState<AlertWebhookConfig>({
    provider: 'DISCORD',
    webhookUrl: '',
    telegramBotToken: '',
    telegramChatId: '',
    totalDispatchedCount: 0,
    enabled: false,
    minSeverity: 'CRITICAL'
  });
  const [isSaving, setIsSaving] = useState<boolean>(false);
  const [isTesting, setIsTesting] = useState<boolean>(false);
  const [testResult, setTestResult] = useState<{ success: boolean; message: string } | null>(null);
  const [savedSuccess, setSavedSuccess] = useState<boolean>(false);

  useEffect(() => {
    if (isOpen) {
      fetch('/api/v1/alerts/config')
        .then(res => res.json())
        .then(data => {
          if (data.config) setConfig(data.config);
        })
        .catch(err => console.warn('Failed to load alert config:', err));
    }
  }, [isOpen]);

  if (!isOpen) return null;

  const handleSave = async () => {
    setIsSaving(true);
    setSavedSuccess(false);
    try {
      const res = await fetch('/api/v1/alerts/config', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(config)
      });
      if (res.ok) {
        setSavedSuccess(true);
        setTimeout(() => setSavedSuccess(false), 3000);
      }
    } catch (err) {
      console.error('Failed to save alert config:', err);
    } finally {
      setIsSaving(false);
    }
  };

  const handleTestAlert = async () => {
    setIsTesting(true);
    setTestResult(null);
    try {
      const res = await fetch('/api/v1/alerts/test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ config })
      });
      const data = await res.json();
      setTestResult({
        success: data.success,
        message: data.message || 'Alert dispatched successfully.'
      });
    } catch (err: any) {
      setTestResult({
        success: false,
        message: err.message || 'Failed to dispatch test notification.'
      });
    } finally {
      setIsTesting(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 p-4 backdrop-blur-sm">
      <div className="animate-in fade-in zoom-in-95 w-full max-w-xl space-y-5 rounded-2xl border border-slate-800 bg-slate-900 p-6 text-left shadow-2xl duration-200">
        {/* Modal Header */}
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <div className="flex items-center gap-3">
            <div className="rounded-xl border border-indigo-500/30 bg-indigo-500/20 p-2 text-indigo-400">
              <Bell className="h-5 w-5" />
            </div>
            <div>
              <h3 className="text-base font-black text-white">
                {isAr ? 'إعداد التنبيهات الفورية متعددة القنوات' : 'Multi-Channel Instant Alerting'}
              </h3>
              <p className="text-xs text-slate-400">
                {isAr
                  ? 'ربط الحوادث السيبرانية تلقائياً مع Discord و Slack و Telegram'
                  : 'Dispatch instant SOC incident webhooks to Discord, Slack & Telegram'}
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

        {/* Form Body */}
        <div className="space-y-4 text-xs">
          {/* Channel Selector */}
          <div className="space-y-2">
            <label className="block font-bold text-slate-200">
              {isAr ? 'قناة الإشعار المستهدفة:' : 'Target Dispatch Channel:'}
            </label>
            <div className="grid grid-cols-3 gap-2">
              {(['DISCORD', 'SLACK', 'TELEGRAM'] as const).map(p => (
                <button
                  key={p}
                  type="button"
                  onClick={() => setConfig(prev => ({ ...prev, provider: p }))}
                  className={`flex items-center justify-center gap-2 rounded-xl border p-2.5 text-xs font-bold transition ${
                    config.provider === p
                      ? 'border-indigo-500 bg-indigo-600/30 text-indigo-200 shadow-md shadow-indigo-950'
                      : 'border-slate-800 bg-slate-950 text-slate-400 hover:border-slate-700'
                  }`}
                >
                  <MessageSquare className="h-3.5 w-3.5" />
                  <span>{p}</span>
                </button>
              ))}
            </div>
          </div>

          {/* Webhook URL or Telegram Token */}
          {config.provider !== 'TELEGRAM' ? (
            <div className="space-y-1.5">
              <label className="block font-bold text-slate-200">
                {isAr ? 'رابط الـ Webhook:' : 'Webhook URL:'}
              </label>
              <input
                type="url"
                placeholder={
                  config.provider === 'DISCORD'
                    ? 'https://discord.com/api/webhooks/...'
                    : 'https://hooks.slack.com/services/...'
                }
                value={config.webhookUrl}
                onChange={e => setConfig(prev => ({ ...prev, webhookUrl: e.target.value }))}
                className="w-full rounded-xl border border-slate-800 bg-slate-950 p-2.5 font-mono text-xs text-slate-200 focus:border-indigo-500 focus:outline-none"
              />
            </div>
          ) : (
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <div className="space-y-1.5">
                <label className="block font-bold text-slate-200">
                  {isAr ? 'رمز بوت Telegram (Bot Token):' : 'Telegram Bot Token:'}
                </label>
                <input
                  type="text"
                  placeholder="123456789:ABCdef..."
                  value={config.telegramBotToken || ''}
                  onChange={e => setConfig(prev => ({ ...prev, telegramBotToken: e.target.value }))}
                  className="w-full rounded-xl border border-slate-800 bg-slate-950 p-2.5 font-mono text-xs text-slate-200 focus:border-indigo-500 focus:outline-none"
                />
              </div>
              <div className="space-y-1.5">
                <label className="block font-bold text-slate-200">
                  {isAr ? 'معرف الدردشة (Chat ID):' : 'Chat ID:'}
                </label>
                <input
                  type="text"
                  placeholder="-1001234567890"
                  value={config.telegramChatId || ''}
                  onChange={e => setConfig(prev => ({ ...prev, telegramChatId: e.target.value }))}
                  className="w-full rounded-xl border border-slate-800 bg-slate-950 p-2.5 font-mono text-xs text-slate-200 focus:border-indigo-500 focus:outline-none"
                />
              </div>
            </div>
          )}

          {/* Severity Threshold */}
          <div className="space-y-2">
            <label className="block font-bold text-slate-200">
              {isAr ? 'الحد الأدنى لدرجة الخطورة للإرسال:' : 'Minimum Severity Threshold:'}
            </label>
            <div className="grid grid-cols-3 gap-2">
              {[
                { key: 'ALL', labelAr: 'كافة التهديدات (>= 50%)', labelEn: 'All Threats (>= 50%)' },
                {
                  key: 'HIGH',
                  labelAr: 'عالية وحرجة (>= 70%)',
                  labelEn: 'High & Critical (>= 70%)'
                },
                {
                  key: 'CRITICAL',
                  labelAr: 'الحرجة فقط (>= 90%)',
                  labelEn: 'Critical Only (>= 90%)'
                }
              ].map(item => (
                <button
                  key={item.key}
                  type="button"
                  onClick={() => setConfig(prev => ({ ...prev, minSeverity: item.key as any }))}
                  className={`rounded-lg border p-2 text-center font-medium transition ${
                    config.minSeverity === item.key
                      ? 'border-indigo-500 bg-indigo-600/20 font-bold text-indigo-300'
                      : 'border-slate-800 bg-slate-950 text-slate-400 hover:border-slate-700'
                  }`}
                >
                  {isAr ? item.labelAr : item.labelEn}
                </button>
              ))}
            </div>
          </div>

          {/* Active Switch */}
          <div className="flex items-center justify-between rounded-xl border border-slate-800 bg-slate-950 p-3">
            <div>
              <span className="block font-bold text-slate-200">
                {isAr ? 'تفعيل الإرسال التلقائي للويب هوك' : 'Enable Automatic Webhook Dispatch'}
              </span>
              <span className="text-[11px] text-slate-500">
                {isAr
                  ? 'إرسال إشعار فوري عند رصد الهجمات وتطبيق قواعد النواة'
                  : 'Instantly trigger alerts on autonomous kernel defense actions'}
              </span>
            </div>
            <button
              type="button"
              onClick={() => setConfig(prev => ({ ...prev, enabled: !prev.enabled }))}
              className={`flex h-6 w-12 items-center rounded-full p-1 transition ${
                config.enabled ? 'justify-end bg-indigo-600' : 'justify-start bg-slate-800'
              }`}
            >
              <span className="h-4 w-4 transform rounded-full bg-white shadow-md transition" />
            </button>
          </div>

          {/* Feedback Test Alert result */}
          {testResult && (
            <div
              className={`flex items-center gap-2 rounded-xl border p-3 text-xs ${
                testResult.success
                  ? 'border-emerald-500/40 bg-emerald-950/40 text-emerald-300'
                  : 'border-rose-500/40 bg-rose-950/40 text-rose-300'
              }`}
            >
              {testResult.success ? (
                <Check className="h-4 w-4 flex-shrink-0" />
              ) : (
                <ShieldAlert className="h-4 w-4 flex-shrink-0" />
              )}
              <span>{testResult.message}</span>
            </div>
          )}

          {savedSuccess && (
            <div className="flex items-center gap-2 rounded-xl border border-emerald-500/40 bg-emerald-950/40 p-2.5 text-xs text-emerald-300">
              <Check className="h-4 w-4" />
              <span>
                {isAr
                  ? 'تم حفظ إعدادات التنبيهات بنجاح!'
                  : 'Alert configuration saved successfully!'}
              </span>
            </div>
          )}
        </div>

        {/* Modal Footer Actions */}
        <div className="flex items-center justify-between border-t border-slate-800 pt-4">
          <button
            type="button"
            onClick={handleTestAlert}
            disabled={isTesting}
            className="flex items-center gap-1.5 rounded-xl border border-slate-700 bg-slate-800 px-3.5 py-2 text-xs font-bold text-slate-200 transition hover:bg-slate-700 disabled:opacity-50"
          >
            {isTesting ? (
              <RefreshCw className="h-3.5 w-3.5 animate-spin" />
            ) : (
              <Send className="h-3.5 w-3.5" />
            )}
            <span>{isAr ? 'إرسال إشعار تجريبي' : 'Dispatch Test Alert'}</span>
          </button>

          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={onClose}
              className="rounded-xl px-4 py-2 text-xs font-bold text-slate-400 transition hover:text-slate-200"
            >
              {isAr ? 'إلغاء' : 'Cancel'}
            </button>
            <button
              type="button"
              onClick={handleSave}
              disabled={isSaving}
              className="flex items-center gap-1.5 rounded-xl bg-indigo-600 px-4 py-2 text-xs font-bold text-white shadow-lg shadow-indigo-950 transition hover:bg-indigo-500 disabled:opacity-50"
            >
              {isSaving ? (
                <RefreshCw className="h-3.5 w-3.5 animate-spin" />
              ) : (
                <Check className="h-3.5 w-3.5" />
              )}
              <span>{isAr ? 'حفظ الإعدادات' : 'Save Config'}</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
