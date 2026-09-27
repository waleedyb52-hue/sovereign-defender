import React, { useState, useEffect } from 'react';
import { HoneypotSession } from '../types';
import {
  ShieldCheck,
  Terminal,
  AlertTriangle,
  Zap,
  Skull,
  Eye,
  Send,
  PlusCircle,
  Trash2,
  CheckCircle2,
  Key,
  Database,
  Server,
  Cpu,
  Lock
} from 'lucide-react';

interface DeceptionCommandCenterProps {
  lang: 'ar' | 'en';
}

export const DeceptionCommandCenter: React.FC<DeceptionCommandCenterProps> = ({ lang }) => {
  const isAr = lang === 'ar';

  const [sessions, setSessions] = useState<HoneypotSession[]>([]);
  const [selectedSessionId, setSelectedSessionId] = useState<string>('');
  const [interactiveCmd, setInteractiveCmd] = useState<string>('cat /etc/shadow');
  const [isExecuting, setIsExecuting] = useState<boolean>(false);
  const [canaryType, setCanaryType] = useState<string>('AWS_SECRET_KEY');
  const [canaryLabel, setCanaryLabel] = useState<string>('Decoy Production AWS IAM Token');
  const [feedbackMsg, setFeedbackMsg] = useState<string | null>(null);

  const fetchHoneypotSessions = async () => {
    try {
      const res = await fetch('/api/v1/honeypot/sessions');
      if (res.ok) {
        const data = await res.json();
        if (data.sessions) {
          setSessions(data.sessions);
          if (!selectedSessionId && data.sessions.length > 0) {
            setSelectedSessionId(data.sessions[0].sessionId);
          }
        }
      }
    } catch (err) {
      console.warn('Honeypot fetch error:', err);
    }
  };

  useEffect(() => {
    fetchHoneypotSessions();
    const interval = setInterval(fetchHoneypotSessions, 6000);
    return () => clearInterval(interval);
  }, []);

  const currentSession = sessions.find(s => s.sessionId === selectedSessionId) || sessions[0];

  const handleExecuteCommand = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!interactiveCmd.trim()) return;
    setIsExecuting(true);
    try {
      const res = await fetch('/api/v1/honeypot/interact', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          sessionId: selectedSessionId || currentSession?.sessionId,
          command: interactiveCmd
        })
      });
      if (res.ok) {
        await fetchHoneypotSessions();
        setInteractiveCmd('');
      }
    } catch (err) {
      console.error('Honeypot command error:', err);
    } finally {
      setIsExecuting(false);
    }
  };

  const handleInjectCanary = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const res = await fetch('/api/v1/honeypot/inject-canary', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          type: canaryType,
          label: canaryLabel
        })
      });
      if (res.ok) {
        const data = await res.json();
        setFeedbackMsg(
          data.message ||
            (isAr
              ? 'تم نشر الطعم المشفر في بيئة الخداع بنجاح'
              : 'Canary Token deployed in decoy filesystem.')
        );
        setTimeout(() => setFeedbackMsg(null), 5000);
      }
    } catch (err) {
      console.error('Canary injection error:', err);
    }
  };

  const handleEvictSession = async (sessionId: string) => {
    try {
      const res = await fetch('/api/v1/honeypot/terminate-session', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ sessionId })
      });
      if (res.ok) {
        const data = await res.json();
        setFeedbackMsg(data.message);
        fetchHoneypotSessions();
        setTimeout(() => setFeedbackMsg(null), 5000);
      }
    } catch (err) {
      console.error('Evict session error:', err);
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Banner: Deception & Deep Honeypot Grid */}
      <div className="rounded-2xl border border-amber-500/40 bg-gradient-to-r from-amber-950/80 via-slate-900 to-rose-950/80 p-6 shadow-2xl">
        <div className="flex flex-wrap items-center justify-between gap-6">
          <div className="flex items-center gap-4">
            <div className="rounded-2xl border border-amber-500/40 bg-amber-500/20 p-4 text-amber-300 shadow-inner">
              <Skull className="h-8 w-8 animate-pulse text-amber-400" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-xl font-black text-white">
                  {isAr
                    ? 'مركز قيادة الخداع واستدراج المهاجمين (Deception Sandbox & Deep Honeypot)'
                    : 'Deception Command Center & Deep Honeypot'}
                </h2>
                <span className="rounded-full border border-amber-500/40 bg-amber-500/20 px-2.5 py-0.5 font-mono text-xs font-bold text-amber-300">
                  Sandbox Active
                </span>
              </div>
              <p className="mt-1 max-w-2xl text-xs text-slate-300">
                {isAr
                  ? 'إعادة توجيه المهاجمين ذوي المهارات العالية سراً إلى حاويات خادعة معزولة لاستنزاف مواردهم وتسجيل نواياهم وتلويث بياناتهم بالطعوم المشفرة (Canaries)'
                  : 'Transparently proxy high-skill attackers into synthetic jail sandboxes, logging keystrokes and poisoning telemetry with cryptographic canary tokens'}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-4 rounded-2xl border border-amber-500/30 bg-slate-950/90 p-3.5 text-center font-mono">
            <div>
              <span className="block font-sans text-[10px] text-slate-400">
                {isAr ? 'المهاجمون المحاصرون:' : 'Trapped Attackers:'}
              </span>
              <span className="text-2xl font-black text-amber-400">{sessions.length}</span>
              <span className="block text-[9px] font-bold text-rose-400">ISOLATED JAIL</span>
            </div>
            <div className="h-10 w-px bg-slate-800"></div>
            <div>
              <span className="block font-sans text-[10px] text-slate-400">
                {isAr ? 'الطعوم المفعلة:' : 'Tripped Canaries:'}
              </span>
              <span className="text-2xl font-black text-cyan-400">
                {sessions.reduce((acc, s) => acc + s.decoyCanariesTripped.length, 0)}
              </span>
              <span className="block text-[9px] text-emerald-400">Active Lures</span>
            </div>
          </div>
        </div>
      </div>

      {feedbackMsg && (
        <div className="flex items-center gap-2 rounded-xl border border-emerald-500/60 bg-emerald-950/80 p-3.5 text-xs font-bold text-emerald-300 shadow-lg">
          <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-400" />
          <span>{feedbackMsg}</span>
        </div>
      )}

      {/* Main Grid: Trapped Sessions List (Left) + Live Decoy Terminal & Canary Control (Right) */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
        {/* Left Column: Trapped Attacker Sessions (5 Cols) */}
        <div className="space-y-4 lg:col-span-5">
          <div className="space-y-3 rounded-2xl border border-slate-800 bg-slate-900/95 p-5 shadow-xl shadow-[0_0_20px_rgba(0,255,255,0.08)]">
            <div className="flex items-center justify-between">
              <h3 className="flex items-center gap-2 text-sm font-bold text-white">
                <Eye className="h-4 w-4 text-amber-400" />
                <span>
                  {isAr ? 'الجلسات المحاصرة في الحاوية الخادعة:' : 'Trapped Sandbox Sessions:'}
                </span>
              </h3>
              <span className="font-mono text-[10px] text-slate-400">{sessions.length} Active</span>
            </div>

            <div className="space-y-2.5">
              {sessions.map(session => {
                const isSelected =
                  session.sessionId === selectedSessionId ||
                  (!selectedSessionId && session.sessionId === currentSession?.sessionId);
                return (
                  <div
                    key={session.sessionId}
                    onClick={() => setSelectedSessionId(session.sessionId)}
                    className={`cursor-pointer rounded-xl border p-3.5 transition ${
                      isSelected
                        ? 'border-amber-500/60 bg-amber-950/40 shadow-md shadow-amber-950/40'
                        : 'border-slate-800 bg-slate-950/80 hover:border-slate-700 shadow-[0_0_20px_rgba(0,255,255,0.08)]'
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <span className="text-base">{session.countryFlag || '🌐'}</span>
                        <div>
                          <div className="flex items-center gap-1.5 font-mono text-xs font-bold text-white">
                            <span>{session.attackerIp}</span>
                            <span className="py-0.2 rounded bg-slate-800 px-1.5 text-[10px] text-slate-400">
                              {session.country}
                            </span>
                          </div>
                          <span className="block font-mono text-[10px] text-slate-400">
                            ID: {session.sessionId} • {session.jailContainerId}
                          </span>
                        </div>
                      </div>

                      <span
                        className={`rounded border px-2 py-0.5 text-[9px] font-bold ${
                          session.status === 'TRAPPED'
                            ? 'animate-pulse border-amber-500/40 bg-amber-500/20 text-amber-300'
                            : 'border-rose-500/40 bg-rose-500/20 text-rose-300'
                        }`}
                      >
                        {session.status}
                      </span>
                    </div>

                    <div className="mt-2 grid grid-cols-2 gap-2 border-t border-slate-800 pt-2 font-mono text-[11px]">
                      <span className="text-slate-400">
                        Keystrokes:{' '}
                        <strong className="text-cyan-300">{session.keystrokesCount}</strong>
                      </span>
                      <span className="text-right text-slate-400">
                        Canaries:{' '}
                        <strong className="text-rose-400">
                          {session.decoyCanariesTripped.length}
                        </strong>
                      </span>
                    </div>

                    <div className="mt-2 flex items-center justify-between gap-2">
                      <span className="text-[10px] text-slate-400">
                        Trigger:{' '}
                        <code className="text-amber-300">
                          {session.triggerVector || session.decoyService}
                        </code>
                      </span>
                      <button
                        type="button"
                        onClick={e => {
                          e.stopPropagation();
                          handleEvictSession(session.sessionId);
                        }}
                        className="flex items-center gap-1 rounded border border-rose-700/50 bg-rose-950/80 px-2 py-1 text-[10px] font-bold text-rose-300 transition hover:bg-rose-900"
                      >
                        <Trash2 className="h-3 w-3" />
                        <span>{isAr ? 'طرد وحظر IP' : 'Evict & Drop'}</span>
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Canary Token Deployment Module */}
          <form
            onSubmit={handleInjectCanary}
            className="space-y-3 rounded-2xl border border-slate-800 bg-slate-900/95 p-5 shadow-xl shadow-[0_0_20px_rgba(0,255,255,0.08)]"
          >
            <h3 className="flex items-center gap-2 text-xs font-bold text-white">
              <Key className="h-4 w-4 text-cyan-400" />
              <span>
                {isAr ? 'زرع طعوم مموهة (Deploy Bait Canary Token):' : 'Deploy Decoy Canary Token:'}
              </span>
            </h3>

            <div>
              <label className="mb-1 block text-[11px] font-semibold text-slate-300">
                {isAr ? 'نوع الطعم التضليلي:' : 'Canary Lure Archetype:'}
              </label>
              <select
                value={canaryType}
                onChange={e => setCanaryType(e.target.value)}
                className="w-full rounded-lg border border-slate-800 bg-slate-950 px-2.5 py-1.5 font-mono text-xs text-white focus:border-cyan-500 focus:outline-none shadow-[0_0_20px_rgba(0,255,255,0.08)]"
              >
                <option value="AWS_SECRET_KEY">AWS IAM Access Key (AKIA...)</option>
                <option value="DATABASE_CREDENTIAL">Database Connection String (PostgreSQL)</option>
                <option value="ROOT_SHADOW_HASH">Linux Root Shadow Hash Salt</option>
                <option value="SSH_PRIVATE_KEY">OpenSSH Private Key Decoy</option>
              </select>
            </div>

            <div>
              <label className="mb-1 block text-[11px] font-semibold text-slate-300">
                {isAr ? 'تسمية الطعم:' : 'Token Label:'}
              </label>
              <input
                type="text"
                value={canaryLabel}
                onChange={e => setCanaryLabel(e.target.value)}
                className="w-full rounded-lg border border-slate-800 bg-slate-950 px-2.5 py-1.5 font-mono text-xs text-white focus:border-cyan-500 focus:outline-none shadow-[0_0_20px_rgba(0,255,255,0.08)]"
              />
            </div>

            <button
              type="submit"
              className="flex w-full items-center justify-center gap-1.5 rounded-lg border border-cyan-500/50 bg-cyan-600/30 py-2 text-xs font-bold text-cyan-200 transition hover:bg-cyan-600 hover:text-white"
            >
              <PlusCircle className="h-3.5 w-3.5" />
              <span>{isAr ? 'حقن الطعم في الحاوية الخادعة' : 'Inject Canary Lure'}</span>
            </button>
          </form>
        </div>

        {/* Right Column: Live Decoy Terminal & Keystroke Monitor (7 Cols) */}
        <div className="space-y-5 lg:col-span-7">
          {currentSession ? (
            <div className="space-y-4 rounded-2xl border border-amber-500/40 bg-slate-900/95 p-6 shadow-2xl">
              {/* Terminal Header */}
              <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 pb-3">
                <div className="flex items-center gap-2">
                  <div className="rounded-lg border border-slate-800 bg-slate-950 p-2 text-amber-400 shadow-[0_0_20px_rgba(0,255,255,0.08)]">
                    <Terminal className="h-5 w-5" />
                  </div>
                  <div>
                    <h3 className="font-mono text-sm font-bold text-white">
                      root@{currentSession.jailContainerId}:~#
                    </h3>
                    <span className="text-[10px] text-slate-400">
                      Attacker:{' '}
                      <strong className="text-amber-400">{currentSession.attackerIp}</strong> (
                      {currentSession.country})
                    </span>
                  </div>
                </div>

                <div className="flex items-center gap-2 font-mono text-xs">
                  <span className="rounded border border-slate-800 bg-slate-950 px-2 py-0.5 text-slate-300 shadow-[0_0_20px_rgba(0,255,255,0.08)]">
                    Keystrokes: {currentSession.keystrokesCount}
                  </span>
                  <span className="rounded border border-rose-500/40 bg-rose-950/80 px-2 py-0.5 text-rose-300">
                    {currentSession.decoyCanariesTripped.length} Canaries Tripped
                  </span>
                </div>
              </div>

              {/* Terminal Screen with Real-Time Decoy Shell Output */}
              <div className="max-h-80 min-h-64 space-y-3 overflow-y-auto rounded-xl border border-slate-800/90 bg-slate-950 p-4 font-mono text-xs shadow-[0_0_20px_rgba(0,255,255,0.08)]">
                <div className="text-slate-500">
                  # Sovereign Defender v4.0 Deception Virtual Shell Attached (PID: 9021)
                  <br /># Trapped IP: {currentSession.attackerIp} | Mode: SYNTHETIC_DECOY_FS
                </div>

                {currentSession.capturedCommands.map(rec => (
                  <div key={`decoy-cmd-${rec.time}-${rec.cmd.slice(0, 20)}`} className="space-y-1">
                    <div className="flex items-center justify-between text-[11px] text-slate-400">
                      <span className="font-bold text-emerald-400">
                        root@decoy-srv:~# <strong className="text-white">{rec.cmd}</strong>
                      </span>
                      <span className="text-[10px] text-slate-500">{rec.time}</span>
                    </div>
                    <pre className="rounded border border-slate-800/80 bg-slate-900/90 p-2 text-[11px] leading-tight whitespace-pre-wrap text-slate-300 shadow-[0_0_20px_rgba(0,255,255,0.08)]">
                      {rec.decoyResponse}
                    </pre>
                  </div>
                ))}
              </div>

              {/* Interactive Decoy Command Execution Prompt */}
              <form onSubmit={handleExecuteCommand} className="flex gap-2">
                <div className="relative flex-1">
                  <span className="absolute top-1/2 left-3 -translate-y-1/2 font-mono text-xs font-bold text-emerald-400">
                    $
                  </span>
                  <input
                    type="text"
                    value={interactiveCmd}
                    onChange={e => setInteractiveCmd(e.target.value)}
                    placeholder="Run probe in decoy sandbox (e.g. cat /etc/shadow, env, ls, uname)..."
                    className="w-full rounded-xl border border-slate-800 bg-slate-950 py-2 pr-3 pl-7 font-mono text-xs text-white focus:border-amber-500 focus:outline-none shadow-[0_0_20px_rgba(0,255,255,0.08)]"
                  />
                </div>

                <button
                  type="submit"
                  disabled={isExecuting}
                  className="flex items-center gap-1.5 rounded-xl bg-amber-600 px-4 py-2 text-xs font-bold text-slate-950 shadow-lg shadow-amber-950/50 transition hover:bg-amber-500"
                >
                  <Send className="h-3.5 w-3.5" />
                  <span>{isExecuting ? 'Sending...' : 'Send to Decoy'}</span>
                </button>
              </form>

              {/* Quick Prompt Suggestions */}
              <div className="flex flex-wrap items-center gap-1.5 pt-1">
                <span className="font-mono text-[10px] text-slate-400">
                  {isAr ? 'أوامر سريعة:' : 'Quick Probes:'}
                </span>
                {[
                  'cat /etc/shadow',
                  'env',
                  'whoami',
                  'netstat -tulpn',
                  'SELECT * FROM users',
                  'ls -la'
                ].map(cmd => (
                  <button
                    key={cmd}
                    type="button"
                    onClick={() => setInteractiveCmd(cmd)}
                    className="rounded border border-slate-800 bg-slate-950 px-2 py-0.5 font-mono text-[10px] text-slate-300 transition hover:border-amber-500/50 hover:text-amber-300 shadow-[0_0_20px_rgba(0,255,255,0.08)]"
                  >
                    {cmd}
                  </button>
                ))}
              </div>
            </div>
          ) : (
            <div className="space-y-3 rounded-2xl border border-slate-800 bg-slate-900/50 p-12 text-center shadow-[0_0_20px_rgba(0,255,255,0.08)]">
              <Skull className="mx-auto h-12 w-12 text-slate-600" />
              <h4 className="text-sm font-bold text-slate-300">
                {isAr ? 'لا توجد جلسات محاصرة حالياً' : 'No Active Trapped Sessions'}
              </h4>
              <p className="mx-auto max-w-sm text-xs text-slate-500">
                {isAr
                  ? 'عند رصد روبوتات أو مهاجمين ذوي مهارات عالية سيتم تحويلهم تلقائياً إلى الحاوية الخادعة'
                  : 'High-skill attackers will be automatically trapped and redirected here.'}
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
