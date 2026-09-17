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
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-sm">
      <div className="w-full max-w-xl p-6 rounded-2xl bg-slate-900 border border-slate-800 shadow-2xl space-y-5 text-left animate-in fade-in zoom-in-95 duration-200">
        
        {/* Modal Header */}
        <div className="flex items-center justify-between pb-3 border-b border-slate-800">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-xl bg-indigo-500/20 text-indigo-400 border border-indigo-500/30">
              <Bell className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-base font-black text-white">
                {isAr ? 'إعداد التنبيهات الفورية متعددة القنوات' : 'Multi-Channel Instant Alerting'}
              </h3>
              <p className="text-xs text-slate-400">
                {isAr ? 'ربط الحوادث السيبرانية تلقائياً مع Discord و Slack و Telegram' : 'Dispatch instant SOC incident webhooks to Discord, Slack & Telegram'}
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

        {/* Form Body */}
        <div className="space-y-4 text-xs">
          
          {/* Channel Selector */}
          <div className="space-y-2">
            <label className="font-bold text-slate-200 block">
              {isAr ? 'قناة الإشعار المستهدفة:' : 'Target Dispatch Channel:'}
            </label>
            <div className="grid grid-cols-3 gap-2">
              {(['DISCORD', 'SLACK', 'TELEGRAM'] as const).map(p => (
                <button
                  key={p}
                  type="button"
                  onClick={() => setConfig(prev => ({ ...prev, provider: p }))}
                  className={`flex items-center justify-center gap-2 p-2.5 rounded-xl border text-xs font-bold transition ${
                    config.provider === p
                      ? 'bg-indigo-600/30 border-indigo-500 text-indigo-200 shadow-md shadow-indigo-950'
                      : 'bg-slate-950 border-slate-800 text-slate-400 hover:border-slate-700'
                  }`}
                >
                  <MessageSquare className="w-3.5 h-3.5" />
                  <span>{p}</span>
                </button>
              ))}
            </div>
          </div>

          {/* Webhook URL or Telegram Token */}
          {config.provider !== 'TELEGRAM' ? (
            <div className="space-y-1.5">
              <label className="font-bold text-slate-200 block">
                {isAr ? 'رابط الـ Webhook:' : 'Webhook URL:'}
              </label>
              <input
                type="url"
                placeholder={config.provider === 'DISCORD' ? 'https://discord.com/api/webhooks/...' : 'https://hooks.slack.com/services/...'}
                value={config.webhookUrl}
                onChange={e => setConfig(prev => ({ ...prev, webhookUrl: e.target.value }))}
                className="w-full p-2.5 rounded-xl bg-slate-950 border border-slate-800 text-slate-200 font-mono text-xs focus:outline-none focus:border-indigo-500"
              />
            </div>
          ) : (
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div className="space-y-1.5">
                <label className="font-bold text-slate-200 block">
                  {isAr ? 'رمز بوت Telegram (Bot Token):' : 'Telegram Bot Token:'}
                </label>
                <input
                  type="text"
                  placeholder="123456789:ABCdef..."
                  value={config.telegramBotToken || ''}
                  onChange={e => setConfig(prev => ({ ...prev, telegramBotToken: e.target.value }))}
                  className="w-full p-2.5 rounded-xl bg-slate-950 border border-slate-800 text-slate-200 font-mono text-xs focus:outline-none focus:border-indigo-500"
                />
              </div>
              <div className="space-y-1.5">
                <label className="font-bold text-slate-200 block">
                  {isAr ? 'معرف الدردشة (Chat ID):' : 'Chat ID:'}
                </label>
                <input
                  type="text"
                  placeholder="-1001234567890"
                  value={config.telegramChatId || ''}
                  onChange={e => setConfig(prev => ({ ...prev, telegramChatId: e.target.value }))}
                  className="w-full p-2.5 rounded-xl bg-slate-950 border border-slate-800 text-slate-200 font-mono text-xs focus:outline-none focus:border-indigo-500"
                />
              </div>
            </div>
          )}

          {/* Severity Threshold */}
          <div className="space-y-2">
            <label className="font-bold text-slate-200 block">
              {isAr ? 'الحد الأدنى لدرجة الخطورة للإرسال:' : 'Minimum Severity Threshold:'}
            </label>
            <div className="grid grid-cols-3 gap-2">
              {[
                { key: 'ALL', labelAr: 'كافة التهديدات (>= 50%)', labelEn: 'All Threats (>= 50%)' },
                { key: 'HIGH', labelAr: 'عالية وحرجة (>= 70%)', labelEn: 'High & Critical (>= 70%)' },
                { key: 'CRITICAL', labelAr: 'الحرجة فقط (>= 90%)', labelEn: 'Critical Only (>= 90%)' }
              ].map(item => (
                <button
                  key={item.key}
                  type="button"
                  onClick={() => setConfig(prev => ({ ...prev, minSeverity: item.key as any }))}
                  className={`p-2 rounded-lg border text-center font-medium transition ${
                    config.minSeverity === item.key
                      ? 'bg-indigo-600/20 border-indigo-500 text-indigo-300 font-bold'
                      : 'bg-slate-950 border-slate-800 text-slate-400 hover:border-slate-700'
                  }`}
                >
                  {isAr ? item.labelAr : item.labelEn}
                </button>
              ))}
            </div>
          </div>

          {/* Active Switch */}
          <div className="flex items-center justify-between p-3 rounded-xl bg-slate-950 border border-slate-800">
            <div>
              <span className="font-bold text-slate-200 block">
                {isAr ? 'تفعيل الإرسال التلقائي للويب هوك' : 'Enable Automatic Webhook Dispatch'}
              </span>
              <span className="text-[11px] text-slate-500">
                {isAr ? 'إرسال إشعار فوري عند رصد الهجمات وتطبيق قواعد النواة' : 'Instantly trigger alerts on autonomous kernel defense actions'}
              </span>
            </div>
            <button
              type="button"
              onClick={() => setConfig(prev => ({ ...prev, enabled: !prev.enabled }))}
              className={`w-12 h-6 flex items-center rounded-full p-1 transition ${
                config.enabled ? 'bg-indigo-600 justify-end' : 'bg-slate-800 justify-start'
              }`}
            >
              <span className="w-4 h-4 rounded-full bg-white shadow-md transform transition" />
            </button>
          </div>

          {/* Feedback Test Alert result */}
          {testResult && (
            <div className={`p-3 rounded-xl border text-xs flex items-center gap-2 ${
              testResult.success 
                ? 'bg-emerald-950/40 border-emerald-500/40 text-emerald-300' 
                : 'bg-rose-950/40 border-rose-500/40 text-rose-300'
            }`}>
              {testResult.success ? <Check className="w-4 h-4 flex-shrink-0" /> : <ShieldAlert className="w-4 h-4 flex-shrink-0" />}
              <span>{testResult.message}</span>
            </div>
          )}

          {savedSuccess && (
            <div className="p-2.5 rounded-xl bg-emerald-950/40 border border-emerald-500/40 text-emerald-300 text-xs flex items-center gap-2">
              <Check className="w-4 h-4" />
              <span>{isAr ? 'تم حفظ إعدادات التنبيهات بنجاح!' : 'Alert configuration saved successfully!'}</span>
            </div>
          )}

        </div>

        {/* Modal Footer Actions */}
        <div className="flex items-center justify-between pt-4 border-t border-slate-800">
          <button
            type="button"
            onClick={handleTestAlert}
            disabled={isTesting}
            className="flex items-center gap-1.5 px-3.5 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-bold border border-slate-700 transition disabled:opacity-50"
          >
            {isTesting ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Send className="w-3.5 h-3.5" />}
            <span>{isAr ? 'إرسال إشعار تجريبي' : 'Dispatch Test Alert'}</span>
          </button>

          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 rounded-xl text-slate-400 hover:text-slate-200 text-xs font-bold transition"
            >
              {isAr ? 'إلغاء' : 'Cancel'}
            </button>
            <button
              type="button"
              onClick={handleSave}
              disabled={isSaving}
              className="flex items-center gap-1.5 px-4 py-2 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-bold shadow-lg shadow-indigo-950 transition disabled:opacity-50"
            >
              {isSaving ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Check className="w-3.5 h-3.5" />}
              <span>{isAr ? 'حفظ الإعدادات' : 'Save Config'}</span>
            </button>
          </div>
        </div>

      </div>
    </div>
  );
};
