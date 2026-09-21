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
        setFeedbackMsg(data.message || (isAr ? 'تم نشر الطعم المشفر في بيئة الخداع بنجاح' : 'Canary Token deployed in decoy filesystem.'));
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
      <div className="p-6 rounded-2xl bg-gradient-to-r from-amber-950/80 via-slate-900 to-rose-950/80 border border-amber-500/40 shadow-2xl">
        <div className="flex flex-wrap items-center justify-between gap-6">
          <div className="flex items-center gap-4">
            <div className="p-4 rounded-2xl bg-amber-500/20 border border-amber-500/40 text-amber-300 shadow-inner">
              <Skull className="w-8 h-8 animate-pulse text-amber-400" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-xl font-black text-white">
                  {isAr ? 'مركز قيادة الخداع واستدراج المهاجمين (Deception Sandbox & Deep Honeypot)' : 'Deception Command Center & Deep Honeypot'}
                </h2>
                <span className="px-2.5 py-0.5 text-xs font-bold rounded-full bg-amber-500/20 text-amber-300 border border-amber-500/40 font-mono">
                  Sandbox Active
                </span>
              </div>
              <p className="text-xs text-slate-300 mt-1 max-w-2xl">
                {isAr
                  ? 'إعادة توجيه المهاجمين ذوي المهارات العالية سراً إلى حاويات خادعة معزولة لاستنزاف مواردهم وتسجيل نواياهم وتلويث بياناتهم بالطعوم المشفرة (Canaries)'
                  : 'Transparently proxy high-skill attackers into synthetic jail sandboxes, logging keystrokes and poisoning telemetry with cryptographic canary tokens'}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-4 bg-slate-950/90 p-3.5 rounded-2xl border border-amber-500/30 font-mono text-center">
            <div>
              <span className="text-[10px] text-slate-400 block font-sans">{isAr ? 'المهاجمون المحاصرون:' : 'Trapped Attackers:'}</span>
              <span className="text-2xl font-black text-amber-400">{sessions.length}</span>
              <span className="text-[9px] text-rose-400 block font-bold">ISOLATED JAIL</span>
            </div>
            <div className="h-10 w-px bg-slate-800"></div>
            <div>
              <span className="text-[10px] text-slate-400 block font-sans">{isAr ? 'الطعوم المفعلة:' : 'Tripped Canaries:'}</span>
              <span className="text-2xl font-black text-cyan-400">
                {sessions.reduce((acc, s) => acc + s.decoyCanariesTripped.length, 0)}
              </span>
              <span className="text-[9px] text-emerald-400 block">Active Lures</span>
            </div>
          </div>
        </div>
      </div>

      {feedbackMsg && (
        <div className="p-3.5 rounded-xl bg-emerald-950/80 border border-emerald-500/60 text-emerald-300 text-xs font-bold flex items-center gap-2 shadow-lg">
          <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
          <span>{feedbackMsg}</span>
        </div>
      )}

      {/* Main Grid: Trapped Sessions List (Left) + Live Decoy Terminal & Canary Control (Right) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: Trapped Attacker Sessions (5 Cols) */}
        <div className="lg:col-span-5 space-y-4">
          <div className="p-5 rounded-2xl bg-slate-900/95 border border-slate-800 shadow-xl space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <Eye className="w-4 h-4 text-amber-400" />
                <span>{isAr ? 'الجلسات المحاصرة في الحاوية الخادعة:' : 'Trapped Sandbox Sessions:'}</span>
              </h3>
              <span className="text-[10px] text-slate-400 font-mono">{sessions.length} Active</span>
            </div>

            <div className="space-y-2.5">
              {sessions.map(session => {
                const isSelected = (session.sessionId === selectedSessionId) || (!selectedSessionId && session.sessionId === currentSession?.sessionId);
                return (
                  <div
                    key={session.sessionId}
                    onClick={() => setSelectedSessionId(session.sessionId)}
                    className={`p-3.5 rounded-xl border transition cursor-pointer ${
                      isSelected
                        ? 'bg-amber-950/40 border-amber-500/60 shadow-md shadow-amber-950/40'
                        : 'bg-slate-950/80 border-slate-800 hover:border-slate-700'
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <span className="text-base">{session.countryFlag || '🌐'}</span>
                        <div>
                          <div className="font-mono text-xs font-bold text-white flex items-center gap-1.5">
                            <span>{session.attackerIp}</span>
                            <span className="text-[10px] px-1.5 py-0.2 rounded bg-slate-800 text-slate-400">
                              {session.country}
                            </span>
                          </div>
                          <span className="text-[10px] text-slate-400 font-mono block">
                            ID: {session.sessionId} • {session.jailContainerId}
                          </span>
                        </div>
                      </div>

                      <span
                        className={`text-[9px] font-bold px-2 py-0.5 rounded border ${
                          session.status === 'TRAPPED'
                            ? 'bg-amber-500/20 text-amber-300 border-amber-500/40 animate-pulse'
                            : 'bg-rose-500/20 text-rose-300 border-rose-500/40'
                        }`}
                      >
                        {session.status}
                      </span>
                    </div>

                    <div className="grid grid-cols-2 gap-2 mt-2 pt-2 border-t border-slate-800 text-[11px] font-mono">
                      <span className="text-slate-400">
                        Keystrokes: <strong className="text-cyan-300">{session.keystrokesCount}</strong>
                      </span>
                      <span className="text-slate-400 text-right">
                        Canaries: <strong className="text-rose-400">{session.decoyCanariesTripped.length}</strong>
                      </span>
                    </div>

                    <div className="mt-2 flex items-center justify-between gap-2">
                      <span className="text-[10px] text-slate-400">
                        Trigger: <code className="text-amber-300">{session.triggerVector || session.decoyService}</code>
                      </span>
                      <button
                        type="button"
                        onClick={(e) => {
                          e.stopPropagation();
                          handleEvictSession(session.sessionId);
                        }}
                        className="px-2 py-1 rounded bg-rose-950/80 hover:bg-rose-900 text-rose-300 border border-rose-700/50 text-[10px] font-bold transition flex items-center gap-1"
                      >
                        <Trash2 className="w-3 h-3" />
                        <span>{isAr ? 'طرد وحظر IP' : 'Evict & Drop'}</span>
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Canary Token Deployment Module */}
          <form onSubmit={handleInjectCanary} className="p-5 rounded-2xl bg-slate-900/95 border border-slate-800 shadow-xl space-y-3">
            <h3 className="text-xs font-bold text-white flex items-center gap-2">
              <Key className="w-4 h-4 text-cyan-400" />
              <span>{isAr ? 'زرع طعوم مموهة (Deploy Bait Canary Token):' : 'Deploy Decoy Canary Token:'}</span>
            </h3>

            <div>
              <label className="block text-[11px] font-semibold text-slate-300 mb-1">
                {isAr ? 'نوع الطعم التضليلي:' : 'Canary Lure Archetype:'}
              </label>
              <select
                value={canaryType}
                onChange={e => setCanaryType(e.target.value)}
                className="w-full px-2.5 py-1.5 bg-slate-950 border border-slate-800 rounded-lg text-xs font-mono text-white focus:outline-none focus:border-cyan-500"
              >
                <option value="AWS_SECRET_KEY">AWS IAM Access Key (AKIA...)</option>
                <option value="DATABASE_CREDENTIAL">Database Connection String (PostgreSQL)</option>
                <option value="ROOT_SHADOW_HASH">Linux Root Shadow Hash Salt</option>
                <option value="SSH_PRIVATE_KEY">OpenSSH Private Key Decoy</option>
              </select>
            </div>

            <div>
              <label className="block text-[11px] font-semibold text-slate-300 mb-1">
                {isAr ? 'تسمية الطعم:' : 'Token Label:'}
              </label>
              <input
                type="text"
                value={canaryLabel}
                onChange={e => setCanaryLabel(e.target.value)}
                className="w-full px-2.5 py-1.5 bg-slate-950 border border-slate-800 rounded-lg text-xs font-mono text-white focus:outline-none focus:border-cyan-500"
              />
            </div>

            <button
              type="submit"
              className="w-full py-2 rounded-lg bg-cyan-600/30 hover:bg-cyan-600 text-cyan-200 hover:text-white border border-cyan-500/50 text-xs font-bold transition flex items-center justify-center gap-1.5"
            >
              <PlusCircle className="w-3.5 h-3.5" />
              <span>{isAr ? 'حقن الطعم في الحاوية الخادعة' : 'Inject Canary Lure'}</span>
            </button>
          </form>
        </div>

        {/* Right Column: Live Decoy Terminal & Keystroke Monitor (7 Cols) */}
        <div className="lg:col-span-7 space-y-5">
          {currentSession ? (
            <div className="p-6 rounded-2xl bg-slate-900/95 border border-amber-500/40 shadow-2xl space-y-4">
              {/* Terminal Header */}
              <div className="flex flex-wrap items-center justify-between gap-3 pb-3 border-b border-slate-800">
                <div className="flex items-center gap-2">
                  <div className="p-2 rounded-lg bg-slate-950 border border-slate-800 text-amber-400">
                    <Terminal className="w-5 h-5" />
                  </div>
                  <div>
                    <h3 className="text-sm font-bold text-white font-mono">
                      root@{currentSession.jailContainerId}:~#
                    </h3>
                    <span className="text-[10px] text-slate-400">
                      Attacker: <strong className="text-amber-400">{currentSession.attackerIp}</strong> ({currentSession.country})
                    </span>
                  </div>
                </div>

                <div className="flex items-center gap-2 font-mono text-xs">
                  <span className="px-2 py-0.5 rounded bg-slate-950 border border-slate-800 text-slate-300">
                    Keystrokes: {currentSession.keystrokesCount}
                  </span>
                  <span className="px-2 py-0.5 rounded bg-rose-950/80 border border-rose-500/40 text-rose-300">
                    {currentSession.decoyCanariesTripped.length} Canaries Tripped
                  </span>
                </div>
              </div>

              {/* Terminal Screen with Real-Time Decoy Shell Output */}
              <div className="bg-slate-950 p-4 rounded-xl border border-slate-800/90 font-mono text-xs space-y-3 min-h-64 max-h-80 overflow-y-auto">
                <div className="text-slate-500">
                  # Sovereign Defender v4.0 Deception Virtual Shell Attached (PID: 9021)
                  <br />
                  # Trapped IP: {currentSession.attackerIp} | Mode: SYNTHETIC_DECOY_FS
                </div>

                {currentSession.capturedCommands.map((rec) => (
                  <div key={`decoy-cmd-${rec.time}-${rec.cmd.slice(0, 20)}`} className="space-y-1">
                    <div className="flex items-center justify-between text-slate-400 text-[11px]">
                      <span className="text-emerald-400 font-bold">
                        root@decoy-srv:~# <strong className="text-white">{rec.cmd}</strong>
                      </span>
                      <span className="text-[10px] text-slate-500">{rec.time}</span>
                    </div>
                    <pre className="text-slate-300 bg-slate-900/90 p-2 rounded border border-slate-800/80 text-[11px] whitespace-pre-wrap leading-tight">
                      {rec.decoyResponse}
                    </pre>
                  </div>
                ))}
              </div>

              {/* Interactive Decoy Command Execution Prompt */}
              <form onSubmit={handleExecuteCommand} className="flex gap-2">
                <div className="relative flex-1">
                  <span className="absolute left-3 top-1/2 -translate-y-1/2 text-emerald-400 font-mono text-xs font-bold">
                    $
                  </span>
                  <input
                    type="text"
                    value={interactiveCmd}
                    onChange={e => setInteractiveCmd(e.target.value)}
                    placeholder="Run probe in decoy sandbox (e.g. cat /etc/shadow, env, ls, uname)..."
                    className="w-full pl-7 pr-3 py-2 bg-slate-950 border border-slate-800 rounded-xl text-xs font-mono text-white focus:outline-none focus:border-amber-500"
                  />
                </div>

                <button
                  type="submit"
                  disabled={isExecuting}
                  className="px-4 py-2 rounded-xl bg-amber-600 hover:bg-amber-500 text-slate-950 font-bold text-xs transition flex items-center gap-1.5 shadow-lg shadow-amber-950/50"
                >
                  <Send className="w-3.5 h-3.5" />
                  <span>{isExecuting ? 'Sending...' : 'Send to Decoy'}</span>
                </button>
              </form>

              {/* Quick Prompt Suggestions */}
              <div className="flex flex-wrap items-center gap-1.5 pt-1">
                <span className="text-[10px] text-slate-400 font-mono">{isAr ? 'أوامر سريعة:' : 'Quick Probes:'}</span>
                {['cat /etc/shadow', 'env', 'whoami', 'netstat -tulpn', 'SELECT * FROM users', 'ls -la'].map(cmd => (
                  <button
                    key={cmd}
                    type="button"
                    onClick={() => setInteractiveCmd(cmd)}
                    className="px-2 py-0.5 rounded bg-slate-950 border border-slate-800 hover:border-amber-500/50 text-[10px] font-mono text-slate-300 hover:text-amber-300 transition"
                  >
                    {cmd}
                  </button>
                ))}
              </div>
            </div>
          ) : (
            <div className="p-12 rounded-2xl bg-slate-900/50 border border-slate-800 text-center space-y-3">
              <Skull className="w-12 h-12 text-slate-600 mx-auto" />
              <h4 className="text-sm font-bold text-slate-300">
                {isAr ? 'لا توجد جلسات محاصرة حالياً' : 'No Active Trapped Sessions'}
              </h4>
              <p className="text-xs text-slate-500 max-w-sm mx-auto">
                {isAr ? 'عند رصد روبوتات أو مهاجمين ذوي مهارات عالية سيتم تحويلهم تلقائياً إلى الحاوية الخادعة' : 'High-skill attackers will be automatically trapped and redirected here.'}
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
