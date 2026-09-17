import React, { useState, useEffect } from 'react';
import {
  Key,
  ShieldAlert,
  Flame,
  FileCode,
  FileWarning,
  Sparkles,
  Upload,
  Play,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  RefreshCw,
  Clock,
  Terminal,
  Layers,
  Search,
  Lock,
  Ban,
  Radio,
  Eye,
  Check,
  Cpu,
  Plus
} from 'lucide-react';

export interface CredentialStuffingEvent {
  id: string;
  timestamp: string;
  targetEndpoint: string;
  sourceIp: string;
  usernameAttempted: string;
  passwordEntropy: number;
  velocityPerMinute: number;
  isDistributed: boolean;
  botnetClusterName?: string;
  actionTaken: 'MONITOR' | 'CAPTCHA_CHALLENGE' | 'ACCOUNT_LOCKOUT' | 'IP_BANNED';
}

export interface HoneytokenTrap {
  id: string;
  endpointPath: string;
  trapType: 'ENV_SECRETS' | 'GIT_CONFIG' | 'ADMIN_PANEL' | 'WORDPRESS_WP_LOGIN' | 'AWS_IAM_CREDENTIALS' | 'ACTUATOR_HEAPDUMP';
  descriptionEn: string;
  descriptionAr: string;
  hitsCount: number;
  lastTriggered?: string;
  lastAttackerIp?: string;
  autoBanEnabled: boolean;
}

export interface SandboxUploadInspection {
  id: string;
  fileName: string;
  fileSizeBytes: number;
  declaredMimeType: string;
  detectedMagicBytes: string;
  isMagicByteSpoofed: boolean;
  isPolyglot: boolean;
  sha256: string;
  entropy: number;
  verdict: 'SAFE' | 'SUSPICIOUS' | 'MALICIOUS_WEBSHELL' | 'MALICIOUS_EXECUTABLE';
  threatScore: number;
  mitreMapping: string[];
  aiAnalysisSummaryEn: string;
  aiAnalysisSummaryAr: string;
  extractedSignatures: string[];
  status: 'QUARANTINED' | 'EXECUTION_BLOCKED' | 'CLEARED';
}

interface DeceptionSandboxPanelProps {
  lang: 'ar' | 'en';
  onRefreshTelemetry?: () => void;
}

export const DeceptionSandboxPanel: React.FC<DeceptionSandboxPanelProps> = ({ lang, onRefreshTelemetry }) => {
  const isAr = lang === 'ar';

  // Section Sub-Tab
  const [activeSection, setActiveSection] = useState<'credential_stuffing' | 'honeytokens' | 'malware_sandbox'>('credential_stuffing');

  // Credential Stuffing State
  const [credEvents, setCredEvents] = useState<CredentialStuffingEvent[]>([]);
  const [simTargetUser, setSimTargetUser] = useState<string>('ciso@sovereign-bank.com');
  const [isSimulatingBrute, setIsSimulatingBrute] = useState<boolean>(false);

  // Honeytoken State
  const [honeytokens, setHoneytokens] = useState<HoneytokenTrap[]>([]);
  const [newTrapPath, setNewTrapPath] = useState<string>('/backup/database.sql');
  const [newTrapType, setNewTrapType] = useState<any>('ENV_SECRETS');
  const [isCreatingTrap, setIsCreatingTrap] = useState<boolean>(false);

  // Sandbox Uploads State
  const [uploads, setUploads] = useState<SandboxUploadInspection[]>([]);
  const [selectedUpload, setSelectedUpload] = useState<SandboxUploadInspection | null>(null);
  const [testFileName, setTestFileName] = useState<string>('profile_avatar.jpg.php');
  const [testMime, setTestMime] = useState<string>('image/jpeg');
  const [testContent, setTestContent] = useState<string>(
    '<?php\n// Disguised WebShell\nif(isset($_POST["cmd"])) {\n  $c = base64_decode($_POST["cmd"]);\n  eval($c);\n  system($c);\n}\n?>'
  );
  const [isAnalyzingFile, setIsAnalyzingFile] = useState<boolean>(false);

  const fetchDeceptionData = async () => {
    try {
      const [credRes, htRes, upRes] = await Promise.all([
        fetch('/api/v1/traffic/credential-stuffing'),
        fetch('/api/v1/traffic/honeytokens'),
        fetch('/api/v1/traffic/sandbox/uploads')
      ]);

      if (credRes.ok) {
        const c = await credRes.json();
        setCredEvents(c.events || []);
      }
      if (htRes.ok) {
        const h = await htRes.json();
        setHoneytokens(h.honeytokens || []);
      }
      if (upRes.ok) {
        const u = await upRes.json();
        setUploads(u.uploads || []);
        if (!selectedUpload && u.uploads?.length > 0) {
          setSelectedUpload(u.uploads[0]);
        }
      }
    } catch (err) {
      console.warn('Deception data fetch error:', err);
    }
  };

  useEffect(() => {
    fetchDeceptionData();
    const interval = setInterval(fetchDeceptionData, 5000);
    return () => clearInterval(interval);
  }, []);

  const handleSimulateCredentialStuffing = async () => {
    setIsSimulatingBrute(true);
    try {
      const res = await fetch('/api/v1/traffic/credential-stuffing/simulate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ targetUser: simTargetUser })
      });
      if (res.ok) {
        fetchDeceptionData();
        if (onRefreshTelemetry) onRefreshTelemetry();
      }
    } catch (err) {
      console.error('Credential stuffing simulation error:', err);
    } finally {
      setIsSimulatingBrute(false);
    }
  };

  const handleCreateHoneytoken = async () => {
    if (!newTrapPath) return;
    setIsCreatingTrap(true);
    try {
      const res = await fetch('/api/v1/traffic/honeytoken/create', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          endpointPath: newTrapPath,
          trapType: newTrapType,
          descriptionEn: `Custom Deception Tripwire on ${newTrapPath}`,
          descriptionAr: `فخ خداع مخصص على المسار ${newTrapPath}`,
          autoBanEnabled: true
        })
      });
      if (res.ok) {
        setNewTrapPath('');
        fetchDeceptionData();
      }
    } catch (err) {
      console.error('Create honeytoken error:', err);
    } finally {
      setIsCreatingTrap(false);
    }
  };

  const handleInspectSandboxFile = async () => {
    if (!testFileName || !testContent) return;
    setIsAnalyzingFile(true);
    try {
      const res = await fetch('/api/v1/traffic/sandbox/inspect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: testFileName,
          size: testContent.length,
          declaredMime: testMime,
          rawContentSnippet: testContent
        })
      });
      if (res.ok) {
        const data = await res.json();
        setSelectedUpload(data.inspection);
        fetchDeceptionData();
        if (onRefreshTelemetry) onRefreshTelemetry();
      }
    } catch (err) {
      console.error('Sandbox analysis error:', err);
    } finally {
      setIsAnalyzingFile(false);
    }
  };

  return (
    <div className="space-y-4 font-sans">
      
      {/* Sub-Pillar Header Navigation */}
      <div className="flex items-center gap-2 border-b border-slate-800 pb-2">
        <button
          onClick={() => setActiveSection('credential_stuffing')}
          className={`px-3 py-1.5 rounded-lg text-xs font-bold transition flex items-center gap-1.5 ${
            activeSection === 'credential_stuffing'
              ? 'bg-orange-950/80 border border-orange-500/50 text-orange-200 shadow-md'
              : 'bg-slate-900/60 text-slate-400 hover:text-slate-200 border border-slate-800'
          }`}
        >
          <Key className="w-3.5 h-3.5 text-orange-400" />
          <span>{isAr ? '1. تعقب هجمات التخمين وقفل الحسابات' : '1. Credential Stuffing & Velocity Tracker'}</span>
          <span className="px-1.5 py-0.2 rounded text-[10px] font-mono bg-orange-900/50 text-orange-300">
            {credEvents.length}
          </span>
        </button>

        <button
          onClick={() => setActiveSection('honeytokens')}
          className={`px-3 py-1.5 rounded-lg text-xs font-bold transition flex items-center gap-1.5 ${
            activeSection === 'honeytokens'
              ? 'bg-amber-950/80 border border-amber-500/50 text-amber-200 shadow-md'
              : 'bg-slate-900/60 text-slate-400 hover:text-slate-200 border border-slate-800'
          }`}
        >
          <Flame className="w-3.5 h-3.5 text-amber-400" />
          <span>{isAr ? '2. فخاخ الخداع ومصائد العسل (Honeytokens)' : '2. Deception & Honeytokens'}</span>
          <span className="px-1.5 py-0.2 rounded text-[10px] font-mono bg-amber-900/50 text-amber-300">
            {honeytokens.length}
          </span>
        </button>

        <button
          onClick={() => setActiveSection('malware_sandbox')}
          className={`px-3 py-1.5 rounded-lg text-xs font-bold transition flex items-center gap-1.5 ${
            activeSection === 'malware_sandbox'
              ? 'bg-purple-950/80 border border-purple-500/50 text-purple-200 shadow-md'
              : 'bg-slate-900/60 text-slate-400 hover:text-slate-200 border border-slate-800'
          }`}
        >
          <FileCode className="w-3.5 h-3.5 text-purple-400" />
          <span>{isAr ? '3. فحص وتدقيق رفع الملفات (Malware Sandbox)' : '3. File Upload & Sandbox Inspector'}</span>
          <span className="px-1.5 py-0.2 rounded text-[10px] font-mono bg-purple-900/50 text-purple-300">
            {uploads.length}
          </span>
        </button>
      </div>

      {/* ========================================================================= */}
      {/* SECTION 1: CREDENTIAL STUFFING & VELOCITY TRACKER                         */}
      {/* ========================================================================= */}
      {activeSection === 'credential_stuffing' && (
        <div className="space-y-4">
          
          {/* Top Banner / Simulator */}
          <div className="bg-slate-900/90 border border-orange-500/30 rounded-xl p-3.5 shadow-lg">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <h4 className="text-xs font-bold text-orange-300 flex items-center gap-1.5">
                  <Key className="w-4 h-4 text-orange-400" />
                  {isAr ? 'محرك مراقبة سرعة تسجيل الدخول وكشف شبكات البوت الموزعة' : 'Adaptive Authentication Velocity & Distributed Botnet Sensor'}
                </h4>
                <p className="text-[11px] text-slate-400 mt-0.5">
                  {isAr
                    ? 'يراقب محاولات الدخول عبر /api/auth، ويقوم بعزل العناوين المشبوهة وتطبيق تحديات CAPTCHA وقفل الحسابات تلقائياً.'
                    : 'Real-time velocity analysis on auth endpoints with automated rate limiting, distributed IP correlation, and sub-second lockout.'}
                </p>
              </div>

              <div className="flex items-center gap-2">
                <input
                  type="text"
                  value={simTargetUser}
                  onChange={(e) => setSimTargetUser(e.target.value)}
                  placeholder="Target user email..."
                  className="bg-slate-950 border border-slate-700 rounded-lg px-3 py-1.5 text-xs font-mono text-slate-200 focus:outline-none focus:border-orange-500 w-52"
                />
                <button
                  onClick={handleSimulateCredentialStuffing}
                  disabled={isSimulatingBrute}
                  className="px-3.5 py-1.5 bg-orange-600 hover:bg-orange-500 text-white rounded-lg text-xs font-bold transition flex items-center gap-1.5 shadow-md shadow-orange-950/50 disabled:opacity-50"
                >
                  <Play className="w-3.5 h-3.5 fill-white" />
                  <span>{isSimulatingBrute ? (isAr ? 'جاري الاختبار...' : 'Simulating...') : (isAr ? 'محاكاة هجوم تخمين موزع' : 'Simulate Distributed Attack')}</span>
                </button>
              </div>
            </div>
          </div>

          {/* Events Table */}
          <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-3.5 shadow-md">
            <div className="flex items-center justify-between mb-3 pb-2 border-b border-slate-800">
              <h4 className="text-xs font-bold text-slate-200 flex items-center gap-2">
                <Radio className="w-4 h-4 text-orange-400 animate-pulse" />
                {isAr ? 'سجل هجمات التخمين المكتشفة وتدابير الحماية التلقائية' : 'Intercepted Credential Stuffing & Velocity Anomalies'}
              </h4>
              <span className="text-[10px] font-mono text-slate-400">
                {credEvents.length} {isAr ? 'أحداث مسجلة' : 'threat events logged'}
              </span>
            </div>

            <div className="overflow-x-auto font-mono text-xs">
              <table className="w-full text-left">
                <thead>
                  <tr className="border-b border-slate-800 text-slate-400 text-[10px]">
                    <th className="py-1.5 px-2">ID</th>
                    <th className="py-1.5 px-2">{isAr ? 'الوقت' : 'Timestamp'}</th>
                    <th className="py-1.5 px-2">{isAr ? 'المسار المستهدف' : 'Target Endpoint'}</th>
                    <th className="py-1.5 px-2">{isAr ? 'عنوان المهاجم' : 'Attacker IP'}</th>
                    <th className="py-1.5 px-2">{isAr ? 'المستخدم المستهدف' : 'Target Username'}</th>
                    <th className="py-1.5 px-2">{isAr ? 'السرعة (محاولة/د)' : 'Velocity (RPM)'}</th>
                    <th className="py-1.5 px-2">{isAr ? 'عنقود البوت' : 'Botnet Cluster'}</th>
                    <th className="py-1.5 px-2 text-right">{isAr ? 'الإجراء الدفاعي' : 'Action Taken'}</th>
                  </tr>
                </thead>
                <tbody>
                  {credEvents.map((evt) => (
                    <tr key={evt.id} className="border-b border-slate-800/50 hover:bg-slate-950/40 transition text-slate-300">
                      <td className="py-2 px-2 text-slate-500">{evt.id}</td>
                      <td className="py-2 px-2 text-slate-400">{new Date(evt.timestamp).toLocaleTimeString()}</td>
                      <td className="py-2 px-2 text-cyan-300 font-bold">{evt.targetEndpoint}</td>
                      <td className="py-2 px-2 text-red-400 font-bold">{evt.sourceIp}</td>
                      <td className="py-2 px-2 text-amber-300">{evt.usernameAttempted}</td>
                      <td className="py-2 px-2 text-orange-400 font-bold">{evt.velocityPerMinute} req/min</td>
                      <td className="py-2 px-2">
                        <span className="px-2 py-0.5 rounded text-[10px] bg-slate-800 text-purple-300 border border-slate-700">
                          {evt.botnetClusterName || 'Distributed Swarm'}
                        </span>
                      </td>
                      <td className="py-2 px-2 text-right">
                        <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-red-950 border border-red-500 text-red-200">
                          {evt.actionTaken}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

        </div>
      )}

      {/* ========================================================================= */}
      {/* SECTION 2: HONEYTOKENS & DECEPTION TRAPS                                  */}
      {/* ========================================================================= */}
      {activeSection === 'honeytokens' && (
        <div className="space-y-4">
          
          {/* Creator Bar */}
          <div className="bg-slate-900/90 border border-amber-500/30 rounded-xl p-3.5 shadow-lg">
            <div className="flex flex-wrap items-center justify-between gap-3 mb-2">
              <h4 className="text-xs font-bold text-amber-300 flex items-center gap-1.5">
                <Flame className="w-4 h-4 text-amber-400" />
                {isAr ? 'نشر مصائد العسل والأصول المسمومة (Deploy Deception Tripwires)' : 'Active Honeytokens & Canary Asset Deployment'}
              </h4>
              <span className="text-[10px] text-slate-400 font-mono">
                {isAr ? 'عزل فوري وتنبيه أحمر عند أدنى لمسة' : 'Auto-Jail & Red Alert on Access'}
              </span>
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <input
                type="text"
                value={newTrapPath}
                onChange={(e) => setNewTrapPath(e.target.value)}
                placeholder="/path/to/honeytoken (e.g. /.aws/credentials)..."
                className="flex-1 min-w-[200px] bg-slate-950 border border-slate-700 rounded-lg px-3 py-1.5 text-xs font-mono text-slate-200 focus:outline-none focus:border-amber-500"
              />

              <select
                value={newTrapType}
                onChange={(e) => setNewTrapType(e.target.value)}
                className="bg-slate-950 border border-slate-700 rounded-lg px-2.5 py-1.5 text-xs text-amber-300 font-mono focus:outline-none focus:border-amber-500"
              >
                <option value="ENV_SECRETS">Environment Secrets (.env)</option>
                <option value="GIT_CONFIG">Git Config Trap (.git/config)</option>
                <option value="ADMIN_PANEL">Admin Panel Decoy (/admin/config.php)</option>
                <option value="WORDPRESS_WP_LOGIN">WordPress CMS Trap (/wp-login.php)</option>
                <option value="AWS_IAM_CREDENTIALS">AWS Cloud Metadata Token</option>
                <option value="ACTUATOR_HEAPDUMP">Spring Actuator Dump Trap</option>
              </select>

              <button
                onClick={handleCreateHoneytoken}
                disabled={isCreatingTrap || !newTrapPath}
                className="px-4 py-1.5 bg-amber-600 hover:bg-amber-500 text-slate-950 rounded-lg text-xs font-bold transition flex items-center gap-1.5 shadow-md shadow-amber-950/50 disabled:opacity-50"
              >
                <Plus className="w-3.5 h-3.5" />
                <span>{isCreatingTrap ? (isAr ? 'جاري النشر...' : 'Deploying...') : (isAr ? 'نشر الفخ الأمني' : 'Deploy Canary Trap')}</span>
              </button>
            </div>
          </div>

          {/* Honeytokens Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
            {honeytokens.map((trap) => (
              <div
                key={trap.id}
                className="bg-slate-900/80 border border-slate-800 hover:border-amber-500/40 rounded-xl p-3.5 shadow-md flex flex-col justify-between transition"
              >
                <div>
                  <div className="flex items-center justify-between mb-2">
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-950/80 border border-amber-500/40 text-amber-300">
                      {trap.trapType}
                    </span>
                    <span className="text-[10px] font-mono text-slate-500">{trap.id}</span>
                  </div>

                  <div className="font-mono text-xs font-bold text-slate-200 mb-1 break-all">
                    {trap.endpointPath}
                  </div>

                  <p className="text-[11px] text-slate-400 mb-3">
                    {isAr ? trap.descriptionAr : trap.descriptionEn}
                  </p>
                </div>

                <div className="pt-2 border-t border-slate-800/80 flex items-center justify-between text-xs">
                  <div className="flex items-center gap-1.5">
                    <AlertTriangle className={`w-3.5 h-3.5 ${trap.hitsCount > 0 ? 'text-red-400 animate-pulse' : 'text-slate-600'}`} />
                    <span className="text-[11px] font-mono text-slate-300">
                      {trap.hitsCount} {isAr ? 'محاولات رصد' : 'trips'}
                    </span>
                  </div>

                  {trap.lastAttackerIp && (
                    <span className="text-[10px] font-mono text-red-400 bg-red-950/60 px-2 py-0.5 rounded border border-red-900">
                      Last: {trap.lastAttackerIp}
                    </span>
                  )}
                </div>
              </div>
            ))}
          </div>

        </div>
      )}

      {/* ========================================================================= */}
      {/* SECTION 3: MALWARE SANDBOX & FILE UPLOAD INSPECTOR                        */}
      {/* ========================================================================= */}
      {activeSection === 'malware_sandbox' && (
        <div className="space-y-4">
          
          {/* Live File Upload & AI Audit Tester */}
          <div className="bg-slate-900/90 border border-purple-500/30 rounded-xl p-3.5 shadow-lg">
            <div className="flex flex-wrap items-center justify-between gap-3 mb-2">
              <h4 className="text-xs font-bold text-purple-300 flex items-center gap-1.5">
                <Sparkles className="w-4 h-4 text-purple-400" />
                {isAr ? 'فاحص رفع الملفات التفاعلي والتحليل الذكي للنوايا (Gemini AI Sandbox)' : 'Interactive File Upload & Gemini AI Intent Audit'}
              </h4>
              <span className="text-[10px] font-mono text-purple-300 bg-purple-950 px-2 py-0.5 rounded border border-purple-800">
                MAGIC-BYTE & POLYGLOT SHIELD
              </span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-2 mb-2">
              <input
                type="text"
                value={testFileName}
                onChange={(e) => setTestFileName(e.target.value)}
                placeholder="Filename (e.g. image.jpg.php)..."
                className="bg-slate-950 border border-slate-700 rounded-lg px-3 py-1.5 text-xs font-mono text-slate-200 focus:outline-none focus:border-purple-500"
              />

              <input
                type="text"
                value={testMime}
                onChange={(e) => setTestMime(e.target.value)}
                placeholder="Declared MIME (e.g. image/jpeg)..."
                className="bg-slate-950 border border-slate-700 rounded-lg px-3 py-1.5 text-xs font-mono text-slate-200 focus:outline-none focus:border-purple-500"
              />

              <button
                onClick={handleInspectSandboxFile}
                disabled={isAnalyzingFile || !testFileName || !testContent}
                className="px-4 py-1.5 bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-500 hover:to-indigo-500 text-white rounded-lg text-xs font-bold transition flex items-center justify-center gap-1.5 shadow-md shadow-purple-950/50 disabled:opacity-50"
              >
                <Sparkles className="w-3.5 h-3.5" />
                <span>{isAnalyzingFile ? (isAr ? 'جاري الفحص الذكي...' : 'Auditing...') : (isAr ? 'فحص الملف في الساندبوكس' : 'Run Sandbox Audit')}</span>
              </button>
            </div>

            <div>
              <textarea
                value={testContent}
                onChange={(e) => setTestContent(e.target.value)}
                rows={3}
                placeholder="Raw file content or snippet to inspect in sandbox..."
                className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2.5 text-xs font-mono text-purple-200 focus:outline-none focus:border-purple-500"
              />
            </div>
          </div>

          {/* Sandbox Inspections Split-View */}
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-3">
            
            {/* List (5 cols) */}
            <div className="lg:col-span-5 bg-slate-900/80 border border-slate-800 rounded-xl p-3 shadow-md">
              <h4 className="text-xs font-bold text-slate-200 mb-2 pb-2 border-b border-slate-800 flex items-center justify-between">
                <span>{isAr ? 'الملفات المحجوزة والمفحوصة' : 'Analyzed & Quarantined Files'}</span>
                <span className="text-[10px] font-mono text-purple-400">{uploads.length} files</span>
              </h4>

              <div className="space-y-1.5 max-h-[380px] overflow-y-auto font-mono text-xs">
                {uploads.map((up) => {
                  const isSelected = selectedUpload?.id === up.id;
                  return (
                    <div
                      key={up.id}
                      onClick={() => setSelectedUpload(up)}
                      className={`p-2.5 rounded-lg border transition cursor-pointer flex items-center justify-between ${
                        isSelected
                          ? 'bg-purple-950/70 border-purple-400/60 text-purple-200 shadow-md'
                          : up.verdict !== 'SAFE'
                          ? 'bg-red-950/20 border-red-900/40 text-slate-300 hover:bg-red-950/40'
                          : 'bg-slate-950/60 border-slate-800 text-slate-400 hover:bg-slate-900/60'
                      }`}
                    >
                      <div className="truncate">
                        <div className="font-bold text-slate-200 truncate">{up.fileName}</div>
                        <div className="text-[10px] text-slate-500">{up.declaredMimeType} • {up.fileSizeBytes} B</div>
                      </div>

                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                        up.verdict === 'SAFE' ? 'bg-emerald-950 text-emerald-300' : 'bg-red-950 text-red-300 border border-red-800'
                      }`}>
                        {up.verdict}
                      </span>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Details (7 cols) */}
            <div className="lg:col-span-7 bg-slate-900/90 border border-purple-500/30 rounded-xl p-3.5 shadow-md flex flex-col justify-between">
              {selectedUpload ? (
                <div className="space-y-3 font-mono text-xs">
                  
                  <div className="flex items-center justify-between pb-2 border-b border-slate-800">
                    <div>
                      <span className="text-slate-500 text-[10px]">{selectedUpload.id}</span>
                      <h4 className="font-bold text-slate-200 text-sm">{selectedUpload.fileName}</h4>
                    </div>
                    <span className={`px-2.5 py-1 rounded text-xs font-bold ${
                      selectedUpload.verdict === 'SAFE'
                        ? 'bg-emerald-950 border border-emerald-500 text-emerald-300'
                        : 'bg-red-950 border border-red-500 text-red-300 animate-pulse'
                    }`}>
                      {selectedUpload.status}
                    </span>
                  </div>

                  {/* Magic Bytes vs Declared MIME */}
                  <div className="grid grid-cols-2 gap-2 bg-slate-950 p-2.5 rounded-lg border border-slate-800 text-[11px]">
                    <div>
                      <span className="text-slate-500 block">Declared MIME:</span>
                      <span className="text-slate-300">{selectedUpload.declaredMimeType}</span>
                    </div>
                    <div>
                      <span className="text-slate-500 block">Detected Magic Bytes:</span>
                      <span className="text-amber-300 font-bold">{selectedUpload.detectedMagicBytes}</span>
                    </div>
                    <div>
                      <span className="text-slate-500 block">Polyglot WebShell:</span>
                      <span className={`font-bold ${selectedUpload.isPolyglot ? 'text-red-400' : 'text-emerald-400'}`}>
                        {selectedUpload.isPolyglot ? 'DETECTED (SPOOFED)' : 'NEGATIVE'}
                      </span>
                    </div>
                    <div>
                      <span className="text-slate-500 block">Threat Score:</span>
                      <span className={`font-bold ${selectedUpload.threatScore > 80 ? 'text-red-400' : 'text-emerald-400'}`}>
                        {selectedUpload.threatScore} / 100
                      </span>
                    </div>
                  </div>

                  {/* Gemini AI Summary */}
                  <div className="p-3 bg-purple-950/40 border border-purple-500/40 rounded-lg">
                    <div className="flex items-center gap-1.5 text-purple-300 font-bold text-xs mb-1">
                      <Sparkles className="w-3.5 h-3.5 text-purple-400" />
                      <span>{isAr ? 'تقرير الذكاء الاصطناعي الجنائي (Gemini AI Audit):' : 'Gemini AI Deep Intent Analysis:'}</span>
                    </div>
                    <p className="text-slate-200 text-xs font-sans leading-relaxed">
                      {isAr ? selectedUpload.aiAnalysisSummaryAr : selectedUpload.aiAnalysisSummaryEn}
                    </p>
                  </div>

                  {/* SHA-256 Hash */}
                  <div>
                    <span className="text-[10px] text-slate-500 block">SHA-256 Checksum:</span>
                    <span className="text-[10px] text-slate-400 break-all select-all">{selectedUpload.sha256}</span>
                  </div>

                </div>
              ) : (
                <div className="p-12 text-center text-slate-500 text-xs">
                  {isAr ? 'اختر ملفاً من القائمة لعرض نتائج الفحص الجنائي' : 'Select an uploaded file to view sandbox inspection results'}
                </div>
              )}
            </div>

          </div>

        </div>
      )}

    </div>
  );
};
