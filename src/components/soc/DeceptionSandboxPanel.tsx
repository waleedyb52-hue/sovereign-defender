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
  trapType:
    | 'ENV_SECRETS'
    | 'GIT_CONFIG'
    | 'ADMIN_PANEL'
    | 'WORDPRESS_WP_LOGIN'
    | 'AWS_IAM_CREDENTIALS'
    | 'ACTUATOR_HEAPDUMP';
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

export const DeceptionSandboxPanel: React.FC<DeceptionSandboxPanelProps> = ({
  lang,
  onRefreshTelemetry
}) => {
  const isAr = lang === 'ar';

  // Section Sub-Tab
  const [activeSection, setActiveSection] = useState<
    'credential_stuffing' | 'honeytokens' | 'malware_sandbox'
  >('credential_stuffing');

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
          className={`flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-bold transition ${
            activeSection === 'credential_stuffing'
              ? 'border border-orange-500/50 bg-orange-950/80 text-orange-200 shadow-md'
              : 'border border-slate-800 bg-slate-900/60 text-slate-400 hover:text-slate-200'
          }`}
        >
          <Key className="h-3.5 w-3.5 text-orange-400" />
          <span>
            {isAr
              ? '1. تعقب هجمات التخمين وقفل الحسابات'
              : '1. Credential Stuffing & Velocity Tracker'}
          </span>
          <span className="py-0.2 rounded bg-orange-900/50 px-1.5 font-mono text-[10px] text-orange-300">
            {credEvents.length}
          </span>
        </button>

        <button
          onClick={() => setActiveSection('honeytokens')}
          className={`flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-bold transition ${
            activeSection === 'honeytokens'
              ? 'border border-amber-500/50 bg-amber-950/80 text-amber-200 shadow-md'
              : 'border border-slate-800 bg-slate-900/60 text-slate-400 hover:text-slate-200'
          }`}
        >
          <Flame className="h-3.5 w-3.5 text-amber-400" />
          <span>
            {isAr ? '2. فخاخ الخداع ومصائد العسل (Honeytokens)' : '2. Deception & Honeytokens'}
          </span>
          <span className="py-0.2 rounded bg-amber-900/50 px-1.5 font-mono text-[10px] text-amber-300">
            {honeytokens.length}
          </span>
        </button>

        <button
          onClick={() => setActiveSection('malware_sandbox')}
          className={`flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-bold transition ${
            activeSection === 'malware_sandbox'
              ? 'border border-purple-500/50 bg-purple-950/80 text-purple-200 shadow-md'
              : 'border border-slate-800 bg-slate-900/60 text-slate-400 hover:text-slate-200'
          }`}
        >
          <FileCode className="h-3.5 w-3.5 text-purple-400" />
          <span>
            {isAr
              ? '3. فحص وتدقيق رفع الملفات (Malware Sandbox)'
              : '3. File Upload & Sandbox Inspector'}
          </span>
          <span className="py-0.2 rounded bg-purple-900/50 px-1.5 font-mono text-[10px] text-purple-300">
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
          <div className="rounded-xl border border-orange-500/30 bg-slate-900/90 p-3.5 shadow-lg">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <h4 className="flex items-center gap-1.5 text-xs font-bold text-orange-300">
                  <Key className="h-4 w-4 text-orange-400" />
                  {isAr
                    ? 'محرك مراقبة سرعة تسجيل الدخول وكشف شبكات البوت الموزعة'
                    : 'Adaptive Authentication Velocity & Distributed Botnet Sensor'}
                </h4>
                <p className="mt-0.5 text-[11px] text-slate-400">
                  {isAr
                    ? 'يراقب محاولات الدخول عبر /api/auth، ويقوم بعزل العناوين المشبوهة وتطبيق تحديات CAPTCHA وقفل الحسابات تلقائياً.'
                    : 'Real-time velocity analysis on auth endpoints with automated rate limiting, distributed IP correlation, and sub-second lockout.'}
                </p>
              </div>

              <div className="flex items-center gap-2">
                <input
                  type="text"
                  value={simTargetUser}
                  onChange={e => setSimTargetUser(e.target.value)}
                  placeholder="Target user email..."
                  className="w-52 rounded-lg border border-slate-700 bg-slate-950 px-3 py-1.5 font-mono text-xs text-slate-200 focus:border-orange-500 focus:outline-none"
                />
                <button
                  onClick={handleSimulateCredentialStuffing}
                  disabled={isSimulatingBrute}
                  className="flex items-center gap-1.5 rounded-lg bg-orange-600 px-3.5 py-1.5 text-xs font-bold text-white shadow-md shadow-orange-950/50 transition hover:bg-orange-500 disabled:opacity-50"
                >
                  <Play className="h-3.5 w-3.5 fill-white" />
                  <span>
                    {isSimulatingBrute
                      ? isAr
                        ? 'جاري الاختبار...'
                        : 'Simulating...'
                      : isAr
                        ? 'محاكاة هجوم تخمين موزع'
                        : 'Simulate Distributed Attack'}
                  </span>
                </button>
              </div>
            </div>
          </div>

          {/* Events Table */}
          <div className="rounded-xl border border-slate-800 bg-slate-900/80 p-3.5 shadow-md">
            <div className="mb-3 flex items-center justify-between border-b border-slate-800 pb-2">
              <h4 className="flex items-center gap-2 text-xs font-bold text-slate-200">
                <Radio className="h-4 w-4 animate-pulse text-orange-400" />
                {isAr
                  ? 'سجل هجمات التخمين المكتشفة وتدابير الحماية التلقائية'
                  : 'Intercepted Credential Stuffing & Velocity Anomalies'}
              </h4>
              <span className="font-mono text-[10px] text-slate-400">
                {credEvents.length} {isAr ? 'أحداث مسجلة' : 'threat events logged'}
              </span>
            </div>

            <div className="overflow-x-auto font-mono text-xs">
              <table className="w-full text-left">
                <thead>
                  <tr className="border-b border-slate-800 text-[10px] text-slate-400">
                    <th className="px-2 py-1.5">ID</th>
                    <th className="px-2 py-1.5">{isAr ? 'الوقت' : 'Timestamp'}</th>
                    <th className="px-2 py-1.5">{isAr ? 'المسار المستهدف' : 'Target Endpoint'}</th>
                    <th className="px-2 py-1.5">{isAr ? 'عنوان المهاجم' : 'Attacker IP'}</th>
                    <th className="px-2 py-1.5">
                      {isAr ? 'المستخدم المستهدف' : 'Target Username'}
                    </th>
                    <th className="px-2 py-1.5">{isAr ? 'السرعة (محاولة/د)' : 'Velocity (RPM)'}</th>
                    <th className="px-2 py-1.5">{isAr ? 'عنقود البوت' : 'Botnet Cluster'}</th>
                    <th className="px-2 py-1.5 text-right">
                      {isAr ? 'الإجراء الدفاعي' : 'Action Taken'}
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {credEvents.map(evt => (
                    <tr
                      key={evt.id}
                      className="border-b border-slate-800/50 text-slate-300 transition hover:bg-slate-950/40"
                    >
                      <td className="px-2 py-2 text-slate-500">{evt.id}</td>
                      <td className="px-2 py-2 text-slate-400">
                        {new Date(evt.timestamp).toLocaleTimeString()}
                      </td>
                      <td className="px-2 py-2 font-bold text-cyan-300">{evt.targetEndpoint}</td>
                      <td className="px-2 py-2 font-bold text-red-400">{evt.sourceIp}</td>
                      <td className="px-2 py-2 text-amber-300">{evt.usernameAttempted}</td>
                      <td className="px-2 py-2 font-bold text-orange-400">
                        {evt.velocityPerMinute} req/min
                      </td>
                      <td className="px-2 py-2">
                        <span className="rounded border border-slate-700 bg-slate-800 px-2 py-0.5 text-[10px] text-purple-300">
                          {evt.botnetClusterName || 'Distributed Swarm'}
                        </span>
                      </td>
                      <td className="px-2 py-2 text-right">
                        <span className="rounded border border-red-500 bg-red-950 px-2 py-0.5 text-[10px] font-bold text-red-200">
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
          <div className="rounded-xl border border-amber-500/30 bg-slate-900/90 p-3.5 shadow-lg">
            <div className="mb-2 flex flex-wrap items-center justify-between gap-3">
              <h4 className="flex items-center gap-1.5 text-xs font-bold text-amber-300">
                <Flame className="h-4 w-4 text-amber-400" />
                {isAr
                  ? 'نشر مصائد العسل والأصول المسمومة (Deploy Deception Tripwires)'
                  : 'Active Honeytokens & Canary Asset Deployment'}
              </h4>
              <span className="font-mono text-[10px] text-slate-400">
                {isAr ? 'عزل فوري وتنبيه أحمر عند أدنى لمسة' : 'Auto-Jail & Red Alert on Access'}
              </span>
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <input
                type="text"
                value={newTrapPath}
                onChange={e => setNewTrapPath(e.target.value)}
                placeholder="/path/to/honeytoken (e.g. /.aws/credentials)..."
                className="min-w-[200px] flex-1 rounded-lg border border-slate-700 bg-slate-950 px-3 py-1.5 font-mono text-xs text-slate-200 focus:border-amber-500 focus:outline-none"
              />

              <select
                value={newTrapType}
                onChange={e => setNewTrapType(e.target.value)}
                className="rounded-lg border border-slate-700 bg-slate-950 px-2.5 py-1.5 font-mono text-xs text-amber-300 focus:border-amber-500 focus:outline-none"
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
                className="flex items-center gap-1.5 rounded-lg bg-amber-600 px-4 py-1.5 text-xs font-bold text-slate-950 shadow-md shadow-amber-950/50 transition hover:bg-amber-500 disabled:opacity-50"
              >
                <Plus className="h-3.5 w-3.5" />
                <span>
                  {isCreatingTrap
                    ? isAr
                      ? 'جاري النشر...'
                      : 'Deploying...'
                    : isAr
                      ? 'نشر الفخ الأمني'
                      : 'Deploy Canary Trap'}
                </span>
              </button>
            </div>
          </div>

          {/* Honeytokens Grid */}
          <div className="grid grid-cols-1 gap-3 md:grid-cols-2 lg:grid-cols-3">
            {honeytokens.map(trap => (
              <div
                key={trap.id}
                className="flex flex-col justify-between rounded-xl border border-slate-800 bg-slate-900/80 p-3.5 shadow-md transition hover:border-amber-500/40"
              >
                <div>
                  <div className="mb-2 flex items-center justify-between">
                    <span className="rounded border border-amber-500/40 bg-amber-950/80 px-2 py-0.5 font-mono text-[10px] font-bold text-amber-300">
                      {trap.trapType}
                    </span>
                    <span className="font-mono text-[10px] text-slate-500">{trap.id}</span>
                  </div>

                  <div className="mb-1 font-mono text-xs font-bold break-all text-slate-200">
                    {trap.endpointPath}
                  </div>

                  <p className="mb-3 text-[11px] text-slate-400">
                    {isAr ? trap.descriptionAr : trap.descriptionEn}
                  </p>
                </div>

                <div className="flex items-center justify-between border-t border-slate-800/80 pt-2 text-xs">
                  <div className="flex items-center gap-1.5">
                    <AlertTriangle
                      className={`h-3.5 w-3.5 ${trap.hitsCount > 0 ? 'animate-pulse text-red-400' : 'text-slate-600'}`}
                    />
                    <span className="font-mono text-[11px] text-slate-300">
                      {trap.hitsCount} {isAr ? 'محاولات رصد' : 'trips'}
                    </span>
                  </div>

                  {trap.lastAttackerIp && (
                    <span className="rounded border border-red-900 bg-red-950/60 px-2 py-0.5 font-mono text-[10px] text-red-400">
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
          <div className="rounded-xl border border-purple-500/30 bg-slate-900/90 p-3.5 shadow-lg">
            <div className="mb-2 flex flex-wrap items-center justify-between gap-3">
              <h4 className="flex items-center gap-1.5 text-xs font-bold text-purple-300">
                <Sparkles className="h-4 w-4 text-purple-400" />
                {isAr
                  ? 'فاحص رفع الملفات التفاعلي والتحليل الذكي للنوايا (Gemini AI Sandbox)'
                  : 'Interactive File Upload & Gemini AI Intent Audit'}
              </h4>
              <span className="rounded border border-purple-800 bg-purple-950 px-2 py-0.5 font-mono text-[10px] text-purple-300">
                MAGIC-BYTE & POLYGLOT SHIELD
              </span>
            </div>

            <div className="mb-2 grid grid-cols-1 gap-2 md:grid-cols-3">
              <input
                type="text"
                value={testFileName}
                onChange={e => setTestFileName(e.target.value)}
                placeholder="Filename (e.g. image.jpg.php)..."
                className="rounded-lg border border-slate-700 bg-slate-950 px-3 py-1.5 font-mono text-xs text-slate-200 focus:border-purple-500 focus:outline-none"
              />

              <input
                type="text"
                value={testMime}
                onChange={e => setTestMime(e.target.value)}
                placeholder="Declared MIME (e.g. image/jpeg)..."
                className="rounded-lg border border-slate-700 bg-slate-950 px-3 py-1.5 font-mono text-xs text-slate-200 focus:border-purple-500 focus:outline-none"
              />

              <button
                onClick={handleInspectSandboxFile}
                disabled={isAnalyzingFile || !testFileName || !testContent}
                className="flex items-center justify-center gap-1.5 rounded-lg bg-gradient-to-r from-purple-600 to-indigo-600 px-4 py-1.5 text-xs font-bold text-white shadow-md shadow-purple-950/50 transition hover:from-purple-500 hover:to-indigo-500 disabled:opacity-50"
              >
                <Sparkles className="h-3.5 w-3.5" />
                <span>
                  {isAnalyzingFile
                    ? isAr
                      ? 'جاري الفحص الذكي...'
                      : 'Auditing...'
                    : isAr
                      ? 'فحص الملف في الساندبوكس'
                      : 'Run Sandbox Audit'}
                </span>
              </button>
            </div>

            <div>
              <textarea
                value={testContent}
                onChange={e => setTestContent(e.target.value)}
                rows={3}
                placeholder="Raw file content or snippet to inspect in sandbox..."
                className="w-full rounded-lg border border-slate-700 bg-slate-950 p-2.5 font-mono text-xs text-purple-200 focus:border-purple-500 focus:outline-none"
              />
            </div>
          </div>

          {/* Sandbox Inspections Split-View */}
          <div className="grid grid-cols-1 gap-3 lg:grid-cols-12">
            {/* List (5 cols) */}
            <div className="rounded-xl border border-slate-800 bg-slate-900/80 p-3 shadow-md lg:col-span-5">
              <h4 className="mb-2 flex items-center justify-between border-b border-slate-800 pb-2 text-xs font-bold text-slate-200">
                <span>{isAr ? 'الملفات المحجوزة والمفحوصة' : 'Analyzed & Quarantined Files'}</span>
                <span className="font-mono text-[10px] text-purple-400">
                  {uploads.length} files
                </span>
              </h4>

              <div className="max-h-[380px] space-y-1.5 overflow-y-auto font-mono text-xs">
                {uploads.map(up => {
                  const isSelected = selectedUpload?.id === up.id;
                  return (
                    <div
                      key={up.id}
                      onClick={() => setSelectedUpload(up)}
                      className={`flex cursor-pointer items-center justify-between rounded-lg border p-2.5 transition ${
                        isSelected
                          ? 'border-purple-400/60 bg-purple-950/70 text-purple-200 shadow-md'
                          : up.verdict !== 'SAFE'
                            ? 'border-red-900/40 bg-red-950/20 text-slate-300 hover:bg-red-950/40'
                            : 'border-slate-800 bg-slate-950/60 text-slate-400 hover:bg-slate-900/60'
                      }`}
                    >
                      <div className="truncate">
                        <div className="truncate font-bold text-slate-200">{up.fileName}</div>
                        <div className="text-[10px] text-slate-500">
                          {up.declaredMimeType} • {up.fileSizeBytes} B
                        </div>
                      </div>

                      <span
                        className={`rounded px-2 py-0.5 text-[10px] font-bold ${
                          up.verdict === 'SAFE'
                            ? 'bg-emerald-950 text-emerald-300'
                            : 'border border-red-800 bg-red-950 text-red-300'
                        }`}
                      >
                        {up.verdict}
                      </span>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Details (7 cols) */}
            <div className="flex flex-col justify-between rounded-xl border border-purple-500/30 bg-slate-900/90 p-3.5 shadow-md lg:col-span-7">
              {selectedUpload ? (
                <div className="space-y-3 font-mono text-xs">
                  <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                    <div>
                      <span className="text-[10px] text-slate-500">{selectedUpload.id}</span>
                      <h4 className="text-sm font-bold text-slate-200">
                        {selectedUpload.fileName}
                      </h4>
                    </div>
                    <span
                      className={`rounded px-2.5 py-1 text-xs font-bold ${
                        selectedUpload.verdict === 'SAFE'
                          ? 'border border-emerald-500 bg-emerald-950 text-emerald-300'
                          : 'animate-pulse border border-red-500 bg-red-950 text-red-300'
                      }`}
                    >
                      {selectedUpload.status}
                    </span>
                  </div>

                  {/* Magic Bytes vs Declared MIME */}
                  <div className="grid grid-cols-2 gap-2 rounded-lg border border-slate-800 bg-slate-950 p-2.5 text-[11px]">
                    <div>
                      <span className="block text-slate-500">Declared MIME:</span>
                      <span className="text-slate-300">{selectedUpload.declaredMimeType}</span>
                    </div>
                    <div>
                      <span className="block text-slate-500">Detected Magic Bytes:</span>
                      <span className="font-bold text-amber-300">
                        {selectedUpload.detectedMagicBytes}
                      </span>
                    </div>
                    <div>
                      <span className="block text-slate-500">Polyglot WebShell:</span>
                      <span
                        className={`font-bold ${selectedUpload.isPolyglot ? 'text-red-400' : 'text-emerald-400'}`}
                      >
                        {selectedUpload.isPolyglot ? 'DETECTED (SPOOFED)' : 'NEGATIVE'}
                      </span>
                    </div>
                    <div>
                      <span className="block text-slate-500">Threat Score:</span>
                      <span
                        className={`font-bold ${selectedUpload.threatScore > 80 ? 'text-red-400' : 'text-emerald-400'}`}
                      >
                        {selectedUpload.threatScore} / 100
                      </span>
                    </div>
                  </div>

                  {/* Gemini AI Summary */}
                  <div className="rounded-lg border border-purple-500/40 bg-purple-950/40 p-3">
                    <div className="mb-1 flex items-center gap-1.5 text-xs font-bold text-purple-300">
                      <Sparkles className="h-3.5 w-3.5 text-purple-400" />
                      <span>
                        {isAr
                          ? 'تقرير الذكاء الاصطناعي الجنائي (Gemini AI Audit):'
                          : 'Gemini AI Deep Intent Analysis:'}
                      </span>
                    </div>
                    <p className="font-sans text-xs leading-relaxed text-slate-200">
                      {isAr
                        ? selectedUpload.aiAnalysisSummaryAr
                        : selectedUpload.aiAnalysisSummaryEn}
                    </p>
                  </div>

                  {/* SHA-256 Hash */}
                  <div>
                    <span className="block text-[10px] text-slate-500">SHA-256 Checksum:</span>
                    <span className="text-[10px] break-all text-slate-400 select-all">
                      {selectedUpload.sha256}
                    </span>
                  </div>
                </div>
              ) : (
                <div className="p-12 text-center text-xs text-slate-500">
                  {isAr
                    ? 'اختر ملفاً من القائمة لعرض نتائج الفحص الجنائي'
                    : 'Select an uploaded file to view sandbox inspection results'}
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
