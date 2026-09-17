import React, { useState, useEffect, useCallback, useMemo } from 'react';
import {
  Activity,
  Shield,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  RefreshCw,
  Play,
  Pause,
  Terminal,
  Zap,
  Lock,
  Unlock,
  Ban,
  Filter,
  Search,
  Eye,
  Copy,
  Check,
  Flame,
  Sliders,
  Cpu,
  Layers,
  FileCode,
  Radio,
  Clock,
  Sparkles,
  Database,
  Crosshair,
  ChevronDown,
  ChevronUp,
  X,
  ArrowRight,
  ExternalLink,
  Users,
  List,
  Workflow,
  History,
  RotateCcw,
  CheckCircle2
} from 'lucide-react';
import { InTransitFilesSecurityInspector } from './soc/InTransitFilesSecurityInspector';

export interface HttpRequestFrame {
  id: string;
  timestamp: string;
  clientIp: string;
  method: string;
  uriPath: string;
  queryString?: string;
  userAgent: string;
  threatScore: number;
  category: string;
  isBlocked: boolean;
  wafAction: 'PASS' | 'BLOCK' | 'CHALLENGE' | 'DIVERT_HONEYPOT';
  blockReasonEn?: string;
  blockReasonAr?: string;
  rawPayloadSnippet?: string;
  headers?: Record<string, string>;
  latencyMs?: number;
}

export interface WafMetrics {
  rps: number;
  totalRequests: number;
  droppedPackets: number;
  ebpfLatencyUs: number;
  activeBlockedSubnetsCount: number;
  wafConfig?: {
    owaspTop10Guard: boolean;
    rateLimitingEnabled: boolean;
    rateLimitThresholdRpm: number;
    challengeBotCaptcha: boolean;
    strictHeaderNormalization: boolean;
    sqlInjectionFilter: boolean;
    xssFilter: boolean;
    rceFilter: boolean;
    pathTraversalFilter: boolean;
    ssrfFilter: boolean;
  };
}

interface SiteTrafficSecurityInspectorProps {
  lang: 'ar' | 'en';
}

export const SiteTrafficSecurityInspector: React.FC<SiteTrafficSecurityInspectorProps> = ({ lang }) => {
  const isAr = lang === 'ar';

  // Live state
  const [frames, setFrames] = useState<HttpRequestFrame[]>([]);
  const [metrics, setMetrics] = useState<WafMetrics>({
    rps: 42.4,
    totalRequests: 198420,
    droppedPackets: 4120,
    ebpfLatencyUs: 0.42,
    activeBlockedSubnetsCount: 6,
    wafConfig: {
      owaspTop10Guard: true,
      rateLimitingEnabled: true,
      rateLimitThresholdRpm: 60,
      challengeBotCaptcha: true,
      strictHeaderNormalization: true,
      sqlInjectionFilter: true,
      xssFilter: true,
      rceFilter: true,
      pathTraversalFilter: true,
      ssrfFilter: true
    }
  });

  const [isLiveStreaming, setIsLiveStreaming] = useState<boolean>(true);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [lastSyncTime, setLastSyncTime] = useState<string>(new Date().toLocaleTimeString());
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [selectedCategory, setSelectedCategory] = useState<string>('ALL');
  const [selectedVerdict, setSelectedVerdict] = useState<'ALL' | 'SAFE_ONLY' | 'MALICIOUS_ONLY'>('ALL');
  const [selectedFrame, setSelectedFrame] = useState<HttpRequestFrame | null>(null);
  const [isModalOpen, setIsModalOpen] = useState<boolean>(false);
  const [isHardeningInProgress, setIsHardeningInProgress] = useState<boolean>(false);
  const [hardeningFeedback, setHardeningFeedback] = useState<{ msgEn: string; msgAr: string } | null>(null);
  const [copiedText, setCopiedText] = useState<string | null>(null);
  const [isLockdownActive, setIsLockdownActive] = useState<boolean>(false);

  // View Mode: Flat Stream vs Group by Actor IP
  const [viewMode, setViewMode] = useState<'FLAT' | 'GROUP_BY_IP'>('FLAT');
  const [expandedActorIps, setExpandedActorIps] = useState<Set<string>>(new Set());

  // Automated SOAR Playbooks Engine State
  const [soarAutoBan, setSoarAutoBan] = useState<boolean>(true);
  const [soarAutoRollback, setSoarAutoRollback] = useState<boolean>(true);
  const [soarAutoIsolate, setSoarAutoIsolate] = useState<boolean>(true);
  const [soarExecutionCount, setSoarExecutionCount] = useState<number>(14);
  const [soarLogs, setSoarLogs] = useState<Array<{ id: string; time: string; playbook: string; target: string; action: string; status: 'SUCCESS' | 'EXECUTING' }>>([
    {
      id: 'soar-1',
      time: '12:04:12',
      playbook: 'PB-01: Auto-Ban IP (Score > 85%)',
      target: '185.220.101.5',
      action: 'iptables -I INPUT -s 185.220.101.5 -j DROP (Kernel eBPF)',
      status: 'SUCCESS'
    },
    {
      id: 'soar-2',
      time: '12:01:45',
      playbook: 'PB-02: Auto-Rollback on FIM Tamper',
      target: '/etc/sudoers',
      action: 'Cryptographic SHA-256 baseline rollback enforced',
      status: 'SUCCESS'
    },
    {
      id: 'soar-3',
      time: '11:58:30',
      playbook: 'PB-03: Zero-Trust Ingress Lockdown',
      target: 'Subnet 194.26.29.0/24',
      action: 'Diverted 240 reqs to Decoy Honeypot container',
      status: 'SUCCESS'
    }
  ]);

  // Progressive Disclosure / Modular Section Collapses
  const [showAdvancedMetrics, setShowAdvancedMetrics] = useState<boolean>(false);
  const [isSimulatorExpanded, setIsSimulatorExpanded] = useState<boolean>(false);
  const [isOwaspMatrixExpanded, setIsOwaspMatrixExpanded] = useState<boolean>(false);

  // Manual Inspector Modal Handlers (Strictly on user click)
  const handleOpenInspector = (frame: HttpRequestFrame) => {
    setSelectedFrame(frame);
    setIsModalOpen(true);
  };

  const handleCloseInspector = () => {
    setSelectedFrame(null);
    setIsModalOpen(false);
  };

  // Keyboard shortcut (ESC) to dismiss modal cleanly
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        handleCloseInspector();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  // Compute Site Safety Status
  // GREEN: Secure (<10% high threats in recent 25 items)
  // AMBER: Under Recon (probes/scanners detected)
  // RED: Under Attack (active SQLi, RCE, XSS, honeytoken trips)
  const siteSafetyStatus = useMemo(() => {
    if (frames.length === 0) return { level: 'GREEN', labelEn: 'SECURE', labelAr: 'مؤمن بالكامل', bgClass: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40' };
    const recent = frames.slice(0, 25);
    const criticalThreats = recent.filter(f => f.threatScore >= 80 || f.category === 'RCE_ATTEMPT' || f.category === 'SQLI_ATTEMPT' || f.category === 'HONEYTOKEN_HIT').length;
    const suspiciousThreats = recent.filter(f => f.threatScore >= 40 && f.threatScore < 80).length;

    if (criticalThreats >= 2) {
      return {
        level: 'RED',
        labelEn: 'UNDER ATTACK',
        labelAr: 'الموقع تحت الهجوم',
        detailEn: `${criticalThreats} critical intrusions intercepted in stream`,
        detailAr: `تم اعتراض ${criticalThreats} محاولات اختراق خطيرة`,
        bgClass: 'bg-rose-600/30 text-rose-300 border-rose-500 shadow-rose-950/50'
      };
    } else if (suspiciousThreats >= 3 || criticalThreats === 1) {
      return {
        level: 'AMBER',
        labelEn: 'ELEVATED',
        labelAr: 'تهديد مرتفع',
        detailEn: 'Automated scanners & anomalous probes detected',
        detailAr: 'رصد أنشطة فحص وبوتات استطلاع مشبوهة',
        bgClass: 'bg-amber-500/20 text-amber-300 border-amber-500/40'
      };
    }
    return {
      level: 'GREEN',
      labelEn: 'SECURE',
      labelAr: 'مؤمن (آمن)',
      detailEn: 'Normal ingress; OWASP CRS verified',
      detailAr: 'حركة مرور طبيعية ومطابقة لمعايير OWASP',
      bgClass: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40'
    };
  }, [frames]);

  // Fetch telemetry frames & metrics
  const fetchTelemetry = useCallback(async () => {
    try {
      const [streamRes, metricsRes] = await Promise.all([
        fetch('/api/v1/traffic/stream?limit=70'),
        fetch('/api/v1/traffic/waf/metrics')
      ]);

      if (streamRes.ok) {
        const streamData = await streamRes.json();
        if (streamData.success && Array.isArray(streamData.frames)) {
          setFrames(streamData.frames);
        }
      }

      if (metricsRes.ok) {
        const metricsData = await metricsRes.json();
        if (metricsData.success && metricsData.metrics) {
          setMetrics(metricsData.metrics);
        }
      }

      setLastSyncTime(new Date().toLocaleTimeString());
    } catch (err) {
      console.warn('Telemetry fetch error:', err);
    }
  }, []);

  // Polling loop for live telemetry
  useEffect(() => {
    fetchTelemetry();
    if (!isLiveStreaming) return;

    const interval = setInterval(() => {
      fetchTelemetry();
    }, 2200);

    return () => clearInterval(interval);
  }, [isLiveStreaming, fetchTelemetry]);

  // One-Click Site Hardening Action
  const handleEnforceSiteHardening = async () => {
    setIsHardeningInProgress(true);
    setHardeningFeedback(null);
    try {
      const res = await fetch('/api/v1/traffic/harden-site', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
      });
      const data = await res.json();
      if (data.success) {
        setHardeningFeedback({
          msgEn: data.messageEn || 'OWASP Core Rule Set & eBPF Kernel Drops Activated.',
          msgAr: data.messageAr || 'تم تفعيل حماية OWASP الكاملة ومزامنة مرشحات النواة بنجاح.'
        });
        fetchTelemetry();
      }
    } catch (err) {
      console.error('Hardening error:', err);
    } finally {
      setIsHardeningInProgress(false);
    }
  };

  // Quick Ban IP
  const handleBanIp = async (ip: string, reason: string) => {
    try {
      await fetch('/api/v1/traffic/ban-ip', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ip,
          reason: reason || 'Manual Inspector Instant Drop',
          reasonAr: 'حظر فوري عبر شاشة فاحص أمان الموقع',
          threatActor: 'Flagged by Inspector'
        })
      });
      fetchTelemetry();
    } catch (err) {
      console.error('Ban IP error:', err);
    }
  };

  // Toggle Emergency Lockdown
  const handleToggleLockdown = async () => {
    try {
      const res = await fetch('/api/v1/agent/lockdown', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ active: !isLockdownActive })
      });
      const data = await res.json();
      if (data.success) {
        setIsLockdownActive(data.lockdownActive);
        fetchTelemetry();
      }
    } catch (err) {
      console.error('Lockdown toggle error:', err);
    }
  };

  // Test Packet Injector for live demonstration
  const handleSimulateAttack = async (category: string) => {
    setIsLoading(true);
    try {
      await fetch('/api/v1/traffic/simulate-packet', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ category })
      });
      await fetchTelemetry();
    } catch (err) {
      console.error('Simulation error:', err);
    } finally {
      setIsLoading(false);
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedText(text);
    setTimeout(() => setCopiedText(null), 2000);
  };

  // Filtered frames
  const filteredFrames = useMemo(() => {
    return frames.filter(f => {
      // Query filter
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const matchesIp = f.clientIp.toLowerCase().includes(q);
        const matchesPath = f.uriPath.toLowerCase().includes(q);
        const matchesQuery = f.queryString ? f.queryString.toLowerCase().includes(q) : false;
        const matchesCat = f.category.toLowerCase().includes(q);
        const matchesPayload = f.rawPayloadSnippet ? f.rawPayloadSnippet.toLowerCase().includes(q) : false;
        if (!matchesIp && !matchesPath && !matchesQuery && !matchesCat && !matchesPayload) {
          return false;
        }
      }

      // Category filter
      if (selectedCategory !== 'ALL') {
        if (selectedCategory === 'BLOCKED' && !f.isBlocked) return false;
        if (selectedCategory === 'SAFE' && (f.isBlocked || f.threatScore >= 40)) return false;
        if (selectedCategory === 'SQLI_ATTEMPT' && f.category !== 'SQLI_ATTEMPT') return false;
        if (selectedCategory === 'XSS_ATTEMPT' && f.category !== 'XSS_ATTEMPT') return false;
        if (selectedCategory === 'COMMAND_INJECTION' && f.category !== 'COMMAND_INJECTION') return false;
        if (selectedCategory === 'PATH_TRAVERSAL' && f.category !== 'PATH_TRAVERSAL') return false;
        if (selectedCategory === 'HONEYTOKEN_HIT' && f.category !== 'HONEYTOKEN_HIT') return false;
        if (!['BLOCKED', 'SAFE', 'SQLI_ATTEMPT', 'XSS_ATTEMPT', 'COMMAND_INJECTION', 'PATH_TRAVERSAL', 'HONEYTOKEN_HIT'].includes(selectedCategory) && f.category !== selectedCategory) return false;
      }

      // Verdict filter
      if (selectedVerdict === 'SAFE_ONLY' && (f.threatScore >= 40 || f.isBlocked)) return false;
      if (selectedVerdict === 'MALICIOUS_ONLY' && f.threatScore < 40 && !f.isBlocked) return false;

      return true;
    });
  }, [frames, searchQuery, selectedCategory, selectedVerdict]);

  // Aggregate frames by Actor IP
  const actorGroups = useMemo(() => {
    const groupsMap = new Map<string, {
      clientIp: string;
      frames: HttpRequestFrame[];
      totalCount: number;
      threatCount: number;
      maxThreatScore: number;
      primaryVector: string;
      latestTimestamp: string;
      isBlocked: boolean;
      methods: Set<string>;
    }>();

    filteredFrames.forEach(frame => {
      let group = groupsMap.get(frame.clientIp);
      if (!group) {
        group = {
          clientIp: frame.clientIp,
          frames: [],
          totalCount: 0,
          threatCount: 0,
          maxThreatScore: 0,
          primaryVector: frame.category,
          latestTimestamp: frame.timestamp,
          isBlocked: false,
          methods: new Set()
        };
        groupsMap.set(frame.clientIp, group);
      }
      group.frames.push(frame);
      group.totalCount += 1;
      group.methods.add(frame.method);
      if (frame.threatScore >= 40 || frame.isBlocked) {
        group.threatCount += 1;
      }
      if (frame.threatScore >= group.maxThreatScore) {
        group.maxThreatScore = frame.threatScore;
        group.primaryVector = frame.category;
      }
      if (frame.isBlocked) {
        group.isBlocked = true;
      }
    });

    return Array.from(groupsMap.values()).sort((a, b) => b.maxThreatScore - a.maxThreatScore || b.totalCount - a.totalCount);
  }, [filteredFrames]);

  const toggleExpandActor = (ip: string) => {
    setExpandedActorIps(prev => {
      const next = new Set(prev);
      if (next.has(ip)) {
        next.delete(ip);
      } else {
        next.add(ip);
      }
      return next;
    });
  };

  return (
    <div className="space-y-5" dir={isAr ? 'rtl' : 'ltr'}>
      {/* Top Header & Tactical Action Bar */}
      <div className="relative overflow-hidden rounded-2xl bg-slate-900 border border-slate-800 p-5 sm:p-6 shadow-xl">
        <div className="relative z-10 flex flex-col lg:flex-row lg:items-center lg:justify-between gap-5">
          {/* Title & Description */}
          <div className="flex items-start gap-4">
            <div className="p-3 rounded-xl bg-gradient-to-br from-cyan-600 to-emerald-700 text-white shadow-lg shadow-cyan-950/60 border border-cyan-400/30 shrink-0">
              <Activity className="w-6 h-6 animate-pulse" />
            </div>
            <div>
              <div className="flex items-center gap-2.5 flex-wrap">
                <h1 className="text-xl sm:text-2xl font-black text-white tracking-tight">
                  {isAr ? 'فاحص ومراقب حركة مرور الموقع' : 'Site Traffic & Security Inspector'}
                </h1>
                <span className="px-2.5 py-0.5 text-xs font-mono font-bold rounded-full bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 flex items-center gap-1.5">
                  <Radio className="w-3 h-3 text-cyan-400 animate-ping" />
                  {isAr ? 'مباشر' : 'LIVE'}
                </span>
                {isLockdownActive && (
                  <span className="px-2.5 py-0.5 text-xs font-bold rounded-full bg-rose-600/30 text-rose-300 border border-rose-500 animate-pulse flex items-center gap-1.5">
                    <Lock className="w-3 h-3 text-rose-400" />
                    {isAr ? 'حظر الصفر مفعّل' : 'ZERO-TRUST ACTIVE'}
                  </span>
                )}
              </div>
              <p className="text-xs sm:text-sm text-slate-400 mt-1 max-w-2xl">
                {isAr
                  ? 'مراقبة حركة طلبات الموقع وفحص التهديدات بالزمن الحقيقي مع التحكم التكتيكي الفوري.'
                  : 'Real-time ingress traffic monitoring, autonomous payload inspection, and one-click mitigation.'}
              </p>
            </div>
          </div>

          {/* Top Tactical Action Buttons */}
          <div className="flex items-center gap-2 flex-wrap">
            <button
              onClick={() => setIsLiveStreaming(!isLiveStreaming)}
              className={`flex items-center gap-1.5 px-3 py-2 rounded-xl text-xs font-bold transition border ${
                isLiveStreaming
                  ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40 hover:bg-emerald-500/30'
                  : 'bg-slate-800 text-slate-400 border-slate-700 hover:text-white'
              }`}
            >
              {isLiveStreaming ? <Pause className="w-3.5 h-3.5 text-emerald-400" /> : <Play className="w-3.5 h-3.5 text-slate-300" />}
              <span>{isLiveStreaming ? (isAr ? 'إيقاف البث' : 'Pause Feed') : (isAr ? 'استئناف' : 'Resume')}</span>
            </button>

            <button
              onClick={() => fetchTelemetry()}
              disabled={isLoading}
              className="flex items-center gap-1.5 px-3 py-2 rounded-xl text-xs font-bold bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition"
              title={isAr ? 'تحديث السجلات' : 'Refresh Telemetry'}
            >
              <RefreshCw className={`w-3.5 h-3.5 text-cyan-400 ${isLoading ? 'animate-spin' : ''}`} />
              <span className="font-mono text-[11px]">{lastSyncTime}</span>
            </button>

            {/* One-Click Site Hardening Button */}
            <button
              onClick={handleEnforceSiteHardening}
              disabled={isHardeningInProgress}
              className="flex items-center gap-1.5 px-3.5 py-2 rounded-xl text-xs font-black bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500 text-white shadow-lg shadow-emerald-950/60 border border-emerald-400/40 transition active:scale-95 disabled:opacity-50"
            >
              <ShieldCheck className={`w-3.5 h-3.5 text-white ${isHardeningInProgress ? 'animate-spin' : ''}`} />
              <span>{isHardeningInProgress ? (isAr ? 'جاري التعزيز...' : 'Enforcing...') : (isAr ? '⚡ تعزيز أمان OWASP' : '⚡ One-Click OWASP')}</span>
            </button>
          </div>
        </div>

        {/* Hardening Feedback Notification */}
        {hardeningFeedback && (
          <div className="mt-3 p-3 rounded-xl bg-emerald-950/60 border border-emerald-500/50 flex items-center justify-between gap-3 text-xs text-emerald-200">
            <div className="flex items-center gap-2">
              <Check className="w-4 h-4 text-emerald-400 shrink-0" />
              <span>{isAr ? hardeningFeedback.msgAr : hardeningFeedback.msgEn}</span>
            </div>
            <button onClick={() => setHardeningFeedback(null)} className="text-slate-400 hover:text-white">✕</button>
          </div>
        )}
      </div>

      {/* ========================================================================= */}
      {/* 1. UNIFIED SYSTEM HEALTH BANNER (EXACTLY 4 HERO METRICS)                   */}
      {/* ========================================================================= */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 sm:gap-4">
        {/* Metric 1: Site Security Status */}
        <div className={`rounded-2xl p-4 sm:p-5 border relative overflow-hidden transition-all duration-300 ${
          siteSafetyStatus.level === 'GREEN'
            ? 'bg-emerald-950/25 border-emerald-500/40 shadow-lg shadow-emerald-950/20'
            : siteSafetyStatus.level === 'AMBER'
            ? 'bg-amber-950/25 border-amber-500/40 shadow-lg shadow-amber-950/20'
            : 'bg-rose-950/35 border-rose-500/60 shadow-lg shadow-rose-950/40 animate-pulse'
        }`}>
          <div className="flex items-center justify-between mb-2">
            <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wider">
              {isAr ? 'حالة أمان الموقع' : 'Site Security Status'}
            </span>
            {siteSafetyStatus.level === 'GREEN' ? (
              <ShieldCheck className="w-4 h-4 text-emerald-400" />
            ) : siteSafetyStatus.level === 'AMBER' ? (
              <AlertTriangle className="w-4 h-4 text-amber-400" />
            ) : (
              <Flame className="w-4 h-4 text-rose-400" />
            )}
          </div>
          <div className="flex items-center gap-2">
            <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-black border font-mono ${siteSafetyStatus.bgClass}`}>
              <span className={`w-2 h-2 rounded-full ${siteSafetyStatus.level === 'GREEN' ? 'bg-emerald-400' : siteSafetyStatus.level === 'AMBER' ? 'bg-amber-400' : 'bg-rose-400'}`} />
              {siteSafetyStatus.labelEn}
            </span>
          </div>
          <p className="text-[11px] text-slate-400 mt-2 truncate">
            {isAr ? siteSafetyStatus.detailAr : siteSafetyStatus.detailEn}
          </p>
        </div>

        {/* Metric 2: Traffic Volume (RPS) */}
        <div className="rounded-2xl bg-slate-900/90 border border-slate-800 p-4 sm:p-5 shadow-lg relative overflow-hidden">
          <div className="flex items-center justify-between mb-2">
            <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wider">
              {isAr ? 'حجم حركة المرور (RPS)' : 'Traffic Volume'}
            </span>
            <Activity className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="flex items-baseline gap-1.5">
            <span className="text-2xl sm:text-3xl font-black text-white font-mono">{metrics.rps}</span>
            <span className="text-xs text-cyan-400 font-bold font-mono">RPS</span>
          </div>
          <p className="text-[11px] text-slate-400 mt-2">
            {isAr ? 'الطلبات المباشرة في الثانية' : 'Requests per second'}
          </p>
        </div>

        {/* Metric 3: Active Blocked Threats */}
        <div className="rounded-2xl bg-slate-900/90 border border-slate-800 p-4 sm:p-5 shadow-lg relative overflow-hidden">
          <div className="flex items-center justify-between mb-2">
            <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wider">
              {isAr ? 'التهديدات المحجوبة' : 'Active Blocked Threats'}
            </span>
            <Ban className="w-4 h-4 text-rose-400" />
          </div>
          <div className="flex items-baseline gap-1.5">
            <span className="text-2xl sm:text-3xl font-black text-rose-400 font-mono">
              {metrics.droppedPackets.toLocaleString()}
            </span>
            <span className="text-xs text-rose-300 font-bold font-mono">{isAr ? 'محظور' : 'dropped'}</span>
          </div>
          <p className="text-[11px] text-slate-400 mt-2">
            {isAr ? 'إجمالي الحزم المعترضة' : 'Total threats neutralized'}
          </p>
        </div>

        {/* Metric 4: eBPF Filter Status */}
        <div className="rounded-2xl bg-slate-900/90 border border-slate-800 p-4 sm:p-5 shadow-lg relative overflow-hidden">
          <div className="flex items-center justify-between mb-2">
            <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wider">
              {isAr ? 'مرشح النواة (eBPF)' : 'eBPF Filter Status'}
            </span>
            <Zap className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="flex items-baseline gap-1.5">
            <span className="text-2xl sm:text-3xl font-black text-emerald-400 font-mono">
              {metrics.ebpfLatencyUs}
            </span>
            <span className="text-xs text-emerald-300 font-bold font-mono">µs latency</span>
          </div>
          <p className="text-[11px] text-emerald-400 font-mono flex items-center gap-1 mt-2">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 inline-block" />
            {isAr ? 'نشط في النواة (Sub-µs)' : 'Active (XDP Driver Hook)'}
          </p>
        </div>
      </div>

      {/* PROGRESSIVE DISCLOSURE: Secondary Micro-Metrics Drawer Toggle */}
      <div className="flex items-center justify-between pt-1">
        <button
          onClick={() => setShowAdvancedMetrics(!showAdvancedMetrics)}
          className="text-xs text-slate-400 hover:text-cyan-300 flex items-center gap-1.5 font-medium transition"
        >
          {showAdvancedMetrics ? <ChevronUp className="w-3.5 h-3.5 text-cyan-400" /> : <ChevronDown className="w-3.5 h-3.5 text-cyan-400" />}
          <span>
            {showAdvancedMetrics
              ? (isAr ? 'إخفاء المقاييس التفصيلية' : 'Hide Secondary Metrics')
              : (isAr ? 'عرض المقاييس الإضافية (Secondary Metrics)' : 'Show Secondary Metrics & WAF Diagnostics')}
          </span>
        </button>

        <div className="flex items-center gap-2">
          {/* Toggle Simulator Drawer */}
          <button
            onClick={() => setIsSimulatorExpanded(!isSimulatorExpanded)}
            className={`text-xs px-2.5 py-1 rounded-lg border font-medium flex items-center gap-1 transition ${
              isSimulatorExpanded ? 'bg-purple-950/60 border-purple-500/40 text-purple-300' : 'bg-slate-900 border-slate-800 text-slate-400 hover:text-slate-200'
            }`}
          >
            <Crosshair className="w-3 h-3 text-purple-400" />
            <span>{isAr ? 'مختبر المحاكاة' : 'Attack Simulator Lab'}</span>
          </button>

          {/* Toggle OWASP Matrix */}
          <button
            onClick={() => setIsOwaspMatrixExpanded(!isOwaspMatrixExpanded)}
            className={`text-xs px-2.5 py-1 rounded-lg border font-medium flex items-center gap-1 transition ${
              isOwaspMatrixExpanded ? 'bg-cyan-950/60 border-cyan-500/40 text-cyan-300' : 'bg-slate-900 border-slate-800 text-slate-400 hover:text-slate-200'
            }`}
          >
            <Layers className="w-3 h-3 text-cyan-400" />
            <span>{isAr ? 'قواعد OWASP' : 'OWASP Rules'}</span>
          </button>
        </div>
      </div>

      {/* Advanced Secondary Metrics Collapsible Section */}
      {showAdvancedMetrics && (
        <div className="rounded-xl bg-slate-900/60 border border-slate-800 p-4 grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs animate-fadeIn">
          <div className="space-y-1">
            <span className="text-slate-500 block text-[10px] uppercase font-bold">{isAr ? 'إجمالي الطلبات' : 'Total Ingested'}</span>
            <span className="font-mono text-slate-200 font-bold">{metrics.totalRequests.toLocaleString()} reqs</span>
          </div>
          <div className="space-y-1">
            <span className="text-slate-500 block text-[10px] uppercase font-bold">{isAr ? 'النطاقات المحظورة' : 'Blocked Subnets'}</span>
            <span className="font-mono text-rose-300 font-bold">{metrics.activeBlockedSubnetsCount} CIDRs</span>
          </div>
          <div className="space-y-1">
            <span className="text-slate-500 block text-[10px] uppercase font-bold">{isAr ? 'حد معدل الطلبات' : 'Rate Limiter'}</span>
            <span className="font-mono text-emerald-300 font-bold">{metrics.wafConfig?.rateLimitThresholdRpm || 60} RPM / IP</span>
          </div>
          <div className="space-y-1">
            <span className="text-slate-500 block text-[10px] uppercase font-bold">{isAr ? 'حمل المعالج' : 'Kernel CPU Overhead'}</span>
            <span className="font-mono text-cyan-300 font-bold">&lt; 0.01%</span>
          </div>
        </div>
      )}

      {/* MODULAR COLLAPSIBLE SECTION: ATTACK SIMULATOR */}
      {isSimulatorExpanded && (
        <div className="rounded-2xl bg-slate-900/90 border border-purple-500/30 p-4 shadow-lg space-y-3 animate-fadeIn">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Crosshair className="w-4 h-4 text-purple-400" />
              <h2 className="text-xs font-bold text-white uppercase tracking-wider">
                {isAr ? 'مختبر محاكاة الهجمات وحقن الحزم' : 'Live Attack Simulation Lab'}
              </h2>
            </div>
            <button onClick={() => setIsSimulatorExpanded(false)} className="text-slate-400 hover:text-white text-xs">✕</button>
          </div>
          <div className="flex items-center gap-2 flex-wrap">
            <button
              onClick={() => handleSimulateAttack('SQLI_ATTEMPT')}
              disabled={isLoading}
              className="px-3 py-1.5 rounded-lg text-xs font-bold bg-rose-500/20 hover:bg-rose-500/30 text-rose-300 border border-rose-500/40 transition"
            >
              {isAr ? 'اختبار حقن SQLi' : 'Test SQL Injection'}
            </button>
            <button
              onClick={() => handleSimulateAttack('XSS_ATTEMPT')}
              disabled={isLoading}
              className="px-3 py-1.5 rounded-lg text-xs font-bold bg-amber-500/20 hover:bg-amber-500/30 text-amber-300 border border-amber-500/40 transition"
            >
              {isAr ? 'اختبار هجوم XSS' : 'Test XSS Attack'}
            </button>
            <button
              onClick={() => handleSimulateAttack('COMMAND_INJECTION')}
              disabled={isLoading}
              className="px-3 py-1.5 rounded-lg text-xs font-bold bg-purple-500/20 hover:bg-purple-500/30 text-purple-300 border border-purple-500/40 transition"
            >
              {isAr ? 'اختبار حقن الأوامر RCE' : 'Test RCE Command'}
            </button>
            <button
              onClick={() => handleSimulateAttack('HONEYTOKEN_HIT')}
              disabled={isLoading}
              className="px-3 py-1.5 rounded-lg text-xs font-bold bg-amber-600/20 hover:bg-amber-600/30 text-amber-300 border border-amber-500/40 transition"
            >
              {isAr ? 'لمس فخ Honeytoken' : 'Trip Honeytoken'}
            </button>
            <button
              onClick={() => handleSimulateAttack('PATH_TRAVERSAL')}
              disabled={isLoading}
              className="px-3 py-1.5 rounded-lg text-xs font-bold bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 border border-cyan-500/40 transition"
            >
              {isAr ? 'طلب طبيعي / مسار' : 'Test Safe Traffic'}
            </button>
          </div>
        </div>
      )}

      {/* MODULAR COLLAPSIBLE SECTION: OWASP ENFORCEMENT MATRIX */}
      {isOwaspMatrixExpanded && (
        <div className="rounded-2xl bg-slate-900/90 border border-slate-800 p-4 shadow-lg space-y-3 animate-fadeIn">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Layers className="w-4 h-4 text-cyan-400" />
              <h2 className="text-xs font-bold text-white uppercase tracking-wider">
                {isAr ? 'مصفوفة قواعد OWASP Top 10 النشطة' : 'OWASP Top 10 Security Enforcement Matrix'}
              </h2>
            </div>
            <button onClick={() => setIsOwaspMatrixExpanded(false)} className="text-slate-400 hover:text-white text-xs">✕</button>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5 text-xs">
            <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-between">
              <span className="text-slate-300 font-bold">SQL Injection (A03)</span>
              <span className="px-2 py-0.5 text-[10px] font-bold rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/40">ACTIVE</span>
            </div>
            <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-between">
              <span className="text-slate-300 font-bold">XSS Filter (A03)</span>
              <span className="px-2 py-0.5 text-[10px] font-bold rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/40">ACTIVE</span>
            </div>
            <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-between">
              <span className="text-slate-300 font-bold">RCE Command Shield</span>
              <span className="px-2 py-0.5 text-[10px] font-bold rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/40">ACTIVE</span>
            </div>
            <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-between">
              <span className="text-slate-300 font-bold">Path Traversal / LFI</span>
              <span className="px-2 py-0.5 text-[10px] font-bold rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/40">ACTIVE</span>
            </div>
            <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-between">
              <span className="text-slate-300 font-bold">Honeytoken Decoys (6)</span>
              <span className="px-2 py-0.5 text-[10px] font-bold rounded bg-amber-500/20 text-amber-300 border border-amber-500/40">ARMED</span>
            </div>
            <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-between">
              <span className="text-slate-300 font-bold">Rate Limiter (60 RPM)</span>
              <span className="px-2 py-0.5 text-[10px] font-bold rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/40">ENFORCING</span>
            </div>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* 2. SOAR AUTOMATED PLAYBOOKS & THREAT CONTAINMENT PANEL                     */}
      {/* ========================================================================= */}
      <div className="rounded-2xl bg-slate-900 border border-slate-800 p-4 sm:p-5 shadow-xl space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 pb-3 border-b border-slate-800">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-indigo-500/20 text-indigo-300 border border-indigo-500/40">
              <Workflow className="w-5 h-5 text-indigo-400" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-sm font-bold text-white tracking-wide">
                  {isAr ? 'محرك الاستجابة التلقائية المتقدم (SOAR Playbooks)' : 'SOAR Autonomous Defense Playbooks'}
                </h2>
                <span className="px-2 py-0.5 text-[10px] font-mono font-bold rounded bg-indigo-500/20 text-indigo-300 border border-indigo-500/40">
                  {soarExecutionCount} {isAr ? 'إجراء مُنفّذ' : 'Executed'}
                </span>
              </div>
              <p className="text-xs text-slate-400">
                {isAr
                  ? 'تفعيل وتكوين سيناريوهات الاستجابة اللحظية لعزل المهاجمين وحماية الملفات تلقائياً.'
                  : 'Configure real-time automated response playbooks for zero-latency threat neutralization.'}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <span className="text-[11px] font-mono text-emerald-400 bg-emerald-500/10 px-2.5 py-1 rounded-lg border border-emerald-500/30 flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
              {isAr ? 'المحرك الآلي: يعمل' : 'SOAR Engine: Active'}
            </span>
          </div>
        </div>

        {/* Playbook Toggles Grid */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          {/* Playbook 1: Auto-Ban IP */}
          <div
            onClick={() => setSoarAutoBan(!soarAutoBan)}
            className={`p-3.5 rounded-xl border cursor-pointer transition flex items-center justify-between gap-3 select-none ${
              soarAutoBan
                ? 'bg-indigo-950/40 border-indigo-500/50 shadow-lg shadow-indigo-950/40'
                : 'bg-slate-950/60 border-slate-800 hover:border-slate-700'
            }`}
          >
            <div className="flex items-start gap-2.5">
              <Ban className={`w-4 h-4 mt-0.5 shrink-0 ${soarAutoBan ? 'text-indigo-400' : 'text-slate-500'}`} />
              <div>
                <div className="text-xs font-bold text-slate-200">
                  {isAr ? 'حظر تلقائي للـ IP عند درجة خطر > 85%' : 'Auto-Ban IP if Threat Score > 85%'}
                </div>
                <div className="text-[10px] text-slate-400 mt-0.5">
                  {isAr ? 'تطبيق إسقاط فوري بنواة eBPF' : 'Instant kernel eBPF packet drop'}
                </div>
              </div>
            </div>
            <span className={`px-2 py-0.5 text-[10px] font-mono font-bold rounded ${
              soarAutoBan ? 'bg-indigo-500 text-white' : 'bg-slate-800 text-slate-400'
            }`}>
              {soarAutoBan ? (isAr ? 'مُفعّل' : 'ON') : (isAr ? 'معطل' : 'OFF')}
            </span>
          </div>

          {/* Playbook 2: Auto-Rollback FIM */}
          <div
            onClick={() => setSoarAutoRollback(!soarAutoRollback)}
            className={`p-3.5 rounded-xl border cursor-pointer transition flex items-center justify-between gap-3 select-none ${
              soarAutoRollback
                ? 'bg-cyan-950/40 border-cyan-500/50 shadow-lg shadow-cyan-950/40'
                : 'bg-slate-950/60 border-slate-800 hover:border-slate-700'
            }`}
          >
            <div className="flex items-start gap-2.5">
              <RotateCcw className={`w-4 h-4 mt-0.5 shrink-0 ${soarAutoRollback ? 'text-cyan-400' : 'text-slate-500'}`} />
              <div>
                <div className="text-xs font-bold text-slate-200">
                  {isAr ? 'استعادة فورية للملفات عند التلاعب (FIM)' : 'Auto-Rollback Files on FIM Mutation'}
                </div>
                <div className="text-[10px] text-slate-400 mt-0.5">
                  {isAr ? 'مزامنة النسخة التشفيرية المعتمدة' : 'Restore trusted Merkle baseline'}
                </div>
              </div>
            </div>
            <span className={`px-2 py-0.5 text-[10px] font-mono font-bold rounded ${
              soarAutoRollback ? 'bg-cyan-500 text-white' : 'bg-slate-800 text-slate-400'
            }`}>
              {soarAutoRollback ? (isAr ? 'مُفعّل' : 'ON') : (isAr ? 'معطل' : 'OFF')}
            </span>
          </div>

          {/* Playbook 3: Zero-Trust Auto Quarantine */}
          <div
            onClick={() => setSoarAutoIsolate(!soarAutoIsolate)}
            className={`p-3.5 rounded-xl border cursor-pointer transition flex items-center justify-between gap-3 select-none ${
              soarAutoIsolate
                ? 'bg-purple-950/40 border-purple-500/50 shadow-lg shadow-purple-950/40'
                : 'bg-slate-950/60 border-slate-800 hover:border-slate-700'
            }`}
          >
            <div className="flex items-start gap-2.5">
              <Lock className={`w-4 h-4 mt-0.5 shrink-0 ${soarAutoIsolate ? 'text-purple-400' : 'text-slate-500'}`} />
              <div>
                <div className="text-xs font-bold text-slate-200">
                  {isAr ? 'تحويل البوتات لفخ Honeypot Decoy' : 'Divert Scanners to Honeypot Decoy'}
                </div>
                <div className="text-[10px] text-slate-400 mt-0.5">
                  {isAr ? 'تضليل المهاجم واستنزاف موارده' : 'Autonomous cyber deception'}
                </div>
              </div>
            </div>
            <span className={`px-2 py-0.5 text-[10px] font-mono font-bold rounded ${
              soarAutoIsolate ? 'bg-purple-500 text-white' : 'bg-slate-800 text-slate-400'
            }`}>
              {soarAutoIsolate ? (isAr ? 'مُفعّل' : 'ON') : (isAr ? 'معطل' : 'OFF')}
            </span>
          </div>
        </div>

        {/* Live SOAR Execution Log Strip */}
        <div className="bg-slate-950/80 rounded-xl p-3 border border-slate-800/80">
          <div className="flex items-center justify-between text-[11px] text-slate-400 font-mono mb-2">
            <span className="flex items-center gap-1.5 text-slate-300 font-bold">
              <History className="w-3.5 h-3.5 text-indigo-400" />
              {isAr ? 'أحدث الإجراءات المنفذة ذاتياً بواسطة SOAR:' : 'Recent Autonomous SOAR Triggers:'}
            </span>
            <span>{isAr ? 'زمن الاستجابة: 0.18ms' : 'Avg Reaction Latency: 0.18ms'}</span>
          </div>
          <div className="space-y-1.5 text-[11px] font-mono">
            {soarLogs.map(log => (
              <div key={log.id} className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 p-2 rounded-lg bg-slate-900/60 border border-slate-800">
                <div className="flex items-center gap-2">
                  <span className="text-slate-500 text-[10px]">{log.time}</span>
                  <span className="font-bold text-indigo-300">{log.playbook}</span>
                  <span className="text-slate-400">→ Target: <strong className="text-cyan-300">{log.target}</strong></span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-slate-400 text-[10px] truncate max-w-xs">{log.action}</span>
                  <span className="px-1.5 py-0.5 rounded text-[9px] font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/40">
                    {log.status}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* ========================================================================= */}
      {/* 2.5 PRE-TRANSIT DEEP FILE INSPECTION & SHANNON ENTROPY PIPELINE           */}
      {/* ========================================================================= */}
      <InTransitFilesSecurityInspector lang={lang} />

      {/* ========================================================================= */}
      {/* 3. CLEAN & STREAMLINED TELEMETRY STREAM & ACTOR IP GROUPING               */}
      {/* ========================================================================= */}
      <div className="rounded-2xl bg-slate-900 border border-slate-800 shadow-xl overflow-hidden">
        {/* Table Header: Filters, View Mode Toggle, and Fast Category Chips */}
        <div className="p-3.5 sm:p-4 border-b border-slate-800 space-y-3 bg-slate-950/60">
          <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-3">
            <div className="flex items-center gap-2.5 w-full md:w-auto">
              {/* Search Bar */}
              <div className="relative flex-1 md:w-72">
                <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
                <input
                  type="text"
                  value={searchQuery}
                  onChange={e => setSearchQuery(e.target.value)}
                  placeholder={isAr ? 'بحث بالـ IP أو المسار أو الحمولة...' : 'Search IP, endpoint, or payload...'}
                  className="w-full pl-8 pr-3 py-1.5 text-xs bg-slate-900 border border-slate-700 rounded-xl text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 transition"
                />
              </div>

              {/* View Mode Toggle: Flat Stream vs Group by Actor IP */}
              <div className="flex items-center gap-1 p-1 bg-slate-900 border border-slate-800 rounded-xl text-xs shrink-0">
                <button
                  onClick={() => setViewMode('FLAT')}
                  className={`flex items-center gap-1.5 px-2.5 py-1 rounded-lg font-bold transition ${
                    viewMode === 'FLAT' ? 'bg-cyan-600 text-white shadow-md' : 'text-slate-400 hover:text-slate-200'
                  }`}
                  title={isAr ? 'عرض السجل المتتابع' : 'Flat Telemetry Stream'}
                >
                  <List className="w-3.5 h-3.5" />
                  <span>{isAr ? 'السجل المباشر' : 'Live Stream'}</span>
                </button>
                <button
                  onClick={() => setViewMode('GROUP_BY_IP')}
                  className={`flex items-center gap-1.5 px-2.5 py-1 rounded-lg font-bold transition ${
                    viewMode === 'GROUP_BY_IP' ? 'bg-indigo-600 text-white shadow-md' : 'text-slate-400 hover:text-slate-200'
                  }`}
                  title={isAr ? 'تجميع الهجمات حسب عنوان IP المهاجم' : 'Group by Actor IP'}
                >
                  <Users className="w-3.5 h-3.5" />
                  <span>{isAr ? 'تجميع حسب IP' : 'Group by IP'}</span>
                </button>
              </div>
            </div>

            {/* Verdict Filter Buttons & Total Count */}
            <div className="flex items-center gap-2 w-full md:w-auto justify-between md:justify-end text-xs">
              <div className="flex items-center gap-1 p-1 bg-slate-900 border border-slate-800 rounded-xl text-xs shrink-0">
                <button
                  onClick={() => setSelectedVerdict('ALL')}
                  className={`px-2 py-0.5 rounded-lg font-bold transition ${
                    selectedVerdict === 'ALL' ? 'bg-cyan-600 text-white' : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {isAr ? 'الكل' : 'All'}
                </button>
                <button
                  onClick={() => setSelectedVerdict('SAFE_ONLY')}
                  className={`px-2 py-0.5 rounded-lg font-bold transition ${
                    selectedVerdict === 'SAFE_ONLY' ? 'bg-emerald-600 text-white' : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {isAr ? 'الآمن' : 'Safe'}
                </button>
                <button
                  onClick={() => setSelectedVerdict('MALICIOUS_ONLY')}
                  className={`px-2 py-0.5 rounded-lg font-bold transition ${
                    selectedVerdict === 'MALICIOUS_ONLY' ? 'bg-rose-600 text-white' : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {isAr ? 'التهديدات' : 'Blocked'}
                </button>
              </div>

              <span className="text-slate-400 font-mono text-[11px] whitespace-nowrap">
                {viewMode === 'FLAT'
                  ? `${filteredFrames.length} ${isAr ? 'سجل' : 'logs'}`
                  : `${actorGroups.length} ${isAr ? 'عناوين فريدة' : 'actors'}`}
              </span>
            </div>
          </div>

          {/* High-Speed Category Filter Chips */}
          <div className="flex items-center gap-1.5 overflow-x-auto pb-1 text-[11px] font-mono scrollbar-none">
            {[
              { id: 'ALL', label: isAr ? 'جميع الفئات' : 'ALL CATEGORIES' },
              { id: 'SQLI_ATTEMPT', label: 'SQLi (A03)' },
              { id: 'XSS_ATTEMPT', label: 'XSS (A03)' },
              { id: 'COMMAND_INJECTION', label: 'RCE Shell' },
              { id: 'PATH_TRAVERSAL', label: 'LFI / Traversal' },
              { id: 'HONEYTOKEN_HIT', label: 'Honeytoken Trip' },
              { id: 'BLOCKED', label: isAr ? 'المحجوبة فقط' : 'Dropped Only' },
              { id: 'SAFE', label: isAr ? 'المرور النظيف' : 'Safe Clean' }
            ].map(chip => (
              <button
                key={chip.id}
                onClick={() => setSelectedCategory(chip.id)}
                className={`px-2.5 py-1 rounded-lg font-bold whitespace-nowrap transition border ${
                  selectedCategory === chip.id
                    ? 'bg-cyan-500/20 text-cyan-300 border-cyan-400/60 shadow-sm'
                    : 'bg-slate-900/80 text-slate-400 border-slate-800 hover:border-slate-700 hover:text-slate-200'
                }`}
              >
                {chip.label}
              </button>
            ))}
          </div>
        </div>

        {/* Dynamic Table Body: FLAT STREAM or GROUP BY ACTOR IP */}
        {viewMode === 'FLAT' ? (
          <div className="overflow-x-auto max-h-[500px] overflow-y-auto">
            <table className="w-full text-left border-collapse">
              <thead className="sticky top-0 bg-slate-950/95 backdrop-blur-md border-b border-slate-800 text-[11px] font-bold text-slate-400 uppercase tracking-wider z-10 font-mono">
                <tr>
                  <th className="py-2.5 px-4 w-28">{isAr ? 'الوقت' : 'Time'}</th>
                  <th className="py-2.5 px-4 w-44">{isAr ? 'عنوان IP العميل' : 'Client IP'}</th>
                  <th className="py-2.5 px-4">{isAr ? 'نقطة النهاية المستهدفة' : 'Target Endpoint'}</th>
                  <th className="py-2.5 px-4 text-right w-36">{isAr ? 'قرار الأمان' : 'Verdict'}</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/50 text-xs font-mono">
                {filteredFrames.length === 0 ? (
                  <tr>
                    <td colSpan={4} className="py-12 text-center text-slate-500">
                      <Shield className="w-7 h-7 mx-auto mb-2 text-slate-600 opacity-60" />
                      <p>{isAr ? 'لا توجد سجلات مطابقة لمعايير البحث' : 'No traffic logs matching search filter'}</p>
                    </td>
                  </tr>
                ) : (
                  filteredFrames.map((frame) => {
                    const isBlocked = frame.isBlocked || frame.threatScore >= 80;
                    const isSuspicious = !isBlocked && frame.threatScore >= 40;
                    const isSafe = !isBlocked && !isSuspicious;

                    return (
                      <tr
                        key={frame.id}
                        onClick={() => handleOpenInspector(frame)}
                        className={`hover:bg-slate-800/60 cursor-pointer transition-colors group ${
                          isBlocked ? 'bg-rose-950/15' : isSuspicious ? 'bg-amber-950/15' : ''
                        }`}
                      >
                        {/* Column 1: Time */}
                        <td className="py-2.5 px-4 text-slate-400 whitespace-nowrap text-[11px]">
                          {new Date(frame.timestamp).toLocaleTimeString()}
                        </td>

                        {/* Column 2: Client IP */}
                        <td className="py-2.5 px-4 whitespace-nowrap">
                          <span className="font-bold text-slate-200 group-hover:text-cyan-300 transition">
                            {frame.clientIp}
                          </span>
                        </td>

                        {/* Column 3: Target Endpoint */}
                        <td className="py-2.5 px-4">
                          <div className="flex items-center gap-2 truncate max-w-md lg:max-w-xl">
                            <span className={`px-1.5 py-0.5 rounded text-[9px] font-black shrink-0 ${
                              frame.method === 'GET' ? 'bg-blue-500/20 text-blue-300 border border-blue-500/30' :
                              frame.method === 'POST' ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30' :
                              frame.method === 'PUT' ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30' :
                              'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                            }`}>
                              {frame.method}
                            </span>
                            <span className="text-slate-300 truncate" title={frame.uriPath}>
                              {frame.uriPath}
                            </span>
                            {frame.queryString && (
                              <span className="text-slate-500 text-[10px] truncate max-w-[140px]">
                                ?{frame.queryString}
                              </span>
                            )}
                          </div>
                        </td>

                        {/* Column 4: Verdict Badge & Inspect Action Button */}
                        <td className="py-2.5 px-4 text-right whitespace-nowrap">
                          <div className="flex items-center justify-end gap-2">
                            {isSafe ? (
                              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 text-[10px] font-bold">
                                <ShieldCheck className="w-3 h-3 text-emerald-400" />
                                SAFE
                              </span>
                            ) : isBlocked ? (
                              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md bg-rose-600/30 text-rose-300 border border-rose-500 text-[10px] font-extrabold shadow-sm shadow-rose-950">
                                <ShieldAlert className="w-3 h-3 text-rose-400 animate-pulse" />
                                BLOCKED
                              </span>
                            ) : (
                              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md bg-amber-500/20 text-amber-300 border border-amber-500/40 text-[10px] font-bold">
                                <AlertTriangle className="w-3 h-3 text-amber-400" />
                                SUSPICIOUS
                              </span>
                            )}

                            {/* Explicit Manual Inspect Button */}
                            <button
                              type="button"
                              onClick={(e) => {
                                e.stopPropagation();
                                handleOpenInspector(frame);
                              }}
                              className="px-2 py-0.5 rounded-md bg-slate-800 hover:bg-cyan-950/80 text-slate-300 hover:text-cyan-300 border border-slate-700 hover:border-cyan-500/40 text-[10px] font-sans font-bold flex items-center gap-1 transition"
                              title={isAr ? 'فحص تفصيلي للحزمة' : 'Inspect Packet'}
                            >
                              <Eye className="w-3 h-3 text-cyan-400" />
                              <span>{isAr ? 'فحص' : 'Inspect'}</span>
                            </button>
                          </div>
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        ) : (
          /* GROUP BY ACTOR IP ACCORDION VIEW */
          <div className="overflow-x-auto max-h-[550px] overflow-y-auto divide-y divide-slate-800/60 font-mono text-xs">
            {actorGroups.length === 0 ? (
              <div className="py-12 text-center text-slate-500">
                <Users className="w-7 h-7 mx-auto mb-2 text-slate-600 opacity-60" />
                <p>{isAr ? 'لا توجد مجموعات مهاجمين مطابقة' : 'No threat actors matching filter'}</p>
              </div>
            ) : (
              actorGroups.map((actor) => {
                const isExpanded = expandedActorIps.has(actor.clientIp);
                const isCritical = actor.maxThreatScore >= 80 || actor.isBlocked;
                const isSuspicious = !isCritical && actor.threatCount > 0;

                return (
                  <div key={actor.clientIp} className="bg-slate-950/40 hover:bg-slate-900/40 transition">
                    {/* Actor Incident Summary Row */}
                    <div
                      onClick={() => toggleExpandActor(actor.clientIp)}
                      className="p-3.5 flex flex-col md:flex-row md:items-center justify-between gap-3 cursor-pointer select-none"
                    >
                      <div className="flex items-center gap-3">
                        <button className="p-1 rounded-md bg-slate-900 border border-slate-800 text-slate-400 hover:text-white">
                          {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                        </button>
                        <div>
                          <div className="flex items-center gap-2">
                            <span className="font-bold text-white text-sm">{actor.clientIp}</span>
                            <span className="px-2 py-0.5 text-[10px] font-bold rounded-md bg-slate-800 text-slate-300 border border-slate-700">
                              {actor.totalCount} {isAr ? 'طلبات' : 'requests'}
                            </span>
                            {actor.threatCount > 0 && (
                              <span className="px-2 py-0.5 text-[10px] font-bold rounded-md bg-rose-950/80 text-rose-300 border border-rose-500/40">
                                {actor.threatCount} {isAr ? 'هجمات مرصودة' : 'attacks'}
                              </span>
                            )}
                          </div>
                          <div className="flex items-center gap-2 text-[11px] text-slate-400 mt-1">
                            <span>{isAr ? 'المتجه الرئيسي:' : 'Primary Vector:'} <strong className="text-cyan-300">{actor.primaryVector}</strong></span>
                            <span>•</span>
                            <span>{isAr ? 'آخر نشاط:' : 'Latest:'} {new Date(actor.latestTimestamp).toLocaleTimeString()}</span>
                          </div>
                        </div>
                      </div>

                      {/* Right Threat Badge & Action Buttons */}
                      <div className="flex items-center gap-2 shrink-0">
                        <span className={`px-2.5 py-1 rounded-lg text-xs font-bold border ${
                          isCritical
                            ? 'bg-rose-500/20 text-rose-300 border-rose-500/50'
                            : isSuspicious
                            ? 'bg-amber-500/20 text-amber-300 border-amber-500/40'
                            : 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40'
                        }`}>
                          Score: {actor.maxThreatScore}/100
                        </span>

                        <button
                          type="button"
                          onClick={(e) => {
                            e.stopPropagation();
                            handleBanIp(actor.clientIp, `Instant drop for actor: ${actor.primaryVector}`);
                          }}
                          className="px-2.5 py-1 rounded-lg bg-rose-600/30 hover:bg-rose-600/50 text-rose-200 border border-rose-500/50 text-xs font-bold flex items-center gap-1.5 transition"
                        >
                          <Ban className="w-3.5 h-3.5" />
                          <span>{isAr ? 'حظر المهاجم' : 'Ban Actor'}</span>
                        </button>

                        <button
                          type="button"
                          onClick={(e) => {
                            e.stopPropagation();
                            if (actor.frames[0]) handleOpenInspector(actor.frames[0]);
                          }}
                          className="px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-cyan-950 text-slate-200 hover:text-cyan-300 border border-slate-700 text-xs font-bold flex items-center gap-1.5 transition"
                        >
                          <Eye className="w-3.5 h-3.5 text-cyan-400" />
                          <span>{isAr ? 'فحص الأحدث' : 'Inspect'}</span>
                        </button>
                      </div>
                    </div>

                    {/* Expandable Nested Child Logs */}
                    {isExpanded && (
                      <div className="bg-slate-950/90 border-t border-slate-800 p-3 space-y-1.5 pl-10 pr-4">
                        <div className="text-[11px] font-bold text-slate-400 mb-2 flex items-center justify-between">
                          <span>{isAr ? `السجلات المنفردة للعنوان ${actor.clientIp}:` : `Individual Request History for ${actor.clientIp}:`}</span>
                        </div>
                        {actor.frames.map((subFrame) => (
                          <div
                            key={subFrame.id}
                            onClick={() => handleOpenInspector(subFrame)}
                            className="p-2 rounded-lg bg-slate-900/70 border border-slate-800/80 hover:bg-slate-800/80 flex items-center justify-between gap-3 cursor-pointer transition"
                          >
                            <div className="flex items-center gap-2.5 truncate">
                              <span className="text-slate-500 text-[10px]">{new Date(subFrame.timestamp).toLocaleTimeString()}</span>
                              <span className={`px-1.5 py-0.2 rounded text-[9px] font-bold ${
                                subFrame.method === 'GET' ? 'bg-blue-500/20 text-blue-300' : 'bg-emerald-500/20 text-emerald-300'
                              }`}>{subFrame.method}</span>
                              <span className="text-slate-200 truncate">{subFrame.uriPath}</span>
                              {subFrame.category !== 'NORMAL_TRAFFIC' && (
                                <span className="px-1.5 py-0.2 rounded text-[9px] font-bold bg-rose-950 text-rose-300 border border-rose-500/40">
                                  {subFrame.category}
                                </span>
                              )}
                            </div>
                            <div className="flex items-center gap-2 shrink-0">
                              <span className={`text-[10px] font-bold ${subFrame.threatScore >= 50 ? 'text-rose-400' : 'text-slate-400'}`}>
                                {subFrame.threatScore}/100
                              </span>
                              <button
                                type="button"
                                onClick={(e) => {
                                  e.stopPropagation();
                                  handleOpenInspector(subFrame);
                                }}
                                className="text-cyan-400 hover:text-cyan-300 p-1"
                              >
                                <Eye className="w-3.5 h-3.5" />
                              </button>
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                );
              })
            )}
          </div>
        )}
      </div>

      {/* ========================================================================= */}
      {/* 3. SLIDE-OVER / MODAL DEEP PAYLOAD INSPECTION (STRICTLY ON USER CLICK)     */}
      {/* ========================================================================= */}
      {isModalOpen && selectedFrame && (
        <div
          onClick={(e) => {
            if (e.target === e.currentTarget) handleCloseInspector();
          }}
          className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-fadeIn"
        >
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-2xl w-full p-6 shadow-2xl space-y-4 max-h-[90vh] overflow-y-auto">
            {/* Modal Header */}
            <div className="flex items-start justify-between gap-4 border-b border-slate-800 pb-3">
              <div className="flex items-center gap-3">
                <div className={`p-2.5 rounded-xl ${
                  selectedFrame.threatScore >= 80 ? 'bg-rose-500/20 text-rose-400 border border-rose-500/40' : 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                }`}>
                  <Terminal className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="text-base font-bold text-white flex items-center gap-2">
                    {isAr ? 'فحص تفصيلي للطلب والحمولة' : 'Deep Request & Payload Dissection'}
                  </h3>
                  <p className="text-xs text-slate-400 font-mono">
                    {selectedFrame.clientIp} • {selectedFrame.method} {selectedFrame.uriPath}
                  </p>
                </div>
              </div>
              <button
                onClick={handleCloseInspector}
                className="p-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white transition text-xs"
              >
                ✕
              </button>
            </div>

            {/* Verdict & Threat Category */}
            <div className={`p-3.5 rounded-xl border ${
              selectedFrame.threatScore >= 80
                ? 'bg-rose-950/30 border-rose-500/40 text-rose-200'
                : 'bg-slate-950 border-slate-800 text-slate-300'
            }`}>
              <div className="flex items-center justify-between mb-1.5">
                <span className="text-[11px] font-bold uppercase tracking-wider font-mono">
                  {isAr ? 'القرار والتقييم الأمني' : 'Threat Intelligence Verdict'}
                </span>
                <span className="text-xs font-mono font-bold px-2 py-0.5 rounded bg-slate-900 border border-slate-700">
                  Threat Score: {selectedFrame.threatScore}/100
                </span>
              </div>
              <p className="text-xs leading-relaxed">
                {isAr
                  ? selectedFrame.blockReasonAr || 'الطلب اجتاز فحوصات الأمان بنجاح ولا يحتوي على حمولات خبيثة معروفة.'
                  : selectedFrame.blockReasonEn || 'Request successfully passed WAF inspection with zero malicious pattern matches.'}
              </p>
            </div>

            {/* Raw HTTP Payload Hex/ASCII */}
            <div className="space-y-1.5">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-slate-400">{isAr ? 'الحمولة وسياق الطلب الخام (Hex/ASCII)' : 'Raw Payload & Request Context'}</span>
                <button
                  onClick={() => copyToClipboard(selectedFrame.rawPayloadSnippet || selectedFrame.queryString || selectedFrame.uriPath)}
                  className="text-xs text-cyan-400 hover:text-cyan-300 flex items-center gap-1 font-mono"
                >
                  {copiedText ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
                  <span>{copiedText ? (isAr ? 'تم النسخ' : 'Copied') : (isAr ? 'نسخ' : 'Copy Payload')}</span>
                </button>
              </div>
              <pre className="p-3 rounded-xl bg-slate-950 border border-slate-800 text-xs font-mono text-emerald-300 overflow-x-auto max-h-40 leading-relaxed select-all">
{`METHOD: ${selectedFrame.method}
ENDPOINT: ${selectedFrame.uriPath}
QUERY: ${selectedFrame.queryString || 'NONE'}
USER-AGENT: ${selectedFrame.userAgent}
WAF_ACTION: ${selectedFrame.wafAction}
STATUS: ${selectedFrame.isBlocked ? 'DROPPED (Kernel eBPF)' : 'FORWARDED'}
PAYLOAD_SNIPPET: ${selectedFrame.rawPayloadSnippet || 'N/A'}`}
              </pre>
            </div>

            {/* Synthesized eBPF Drop Rule */}
            <div className="space-y-1.5">
              <span className="text-xs font-bold text-slate-400">{isAr ? 'قاعدة الإسقاط السريعة في النواة (eBPF / XDP)' : 'Synthesized Kernel eBPF Drop Rule'}</span>
              <div className="p-2.5 rounded-xl bg-slate-950 border border-slate-800 text-xs font-mono text-cyan-300 flex items-center justify-between gap-2">
                <code className="truncate">{`bpf_xdp_drop_src_ip(0x${selectedFrame.clientIp.split('.').map(n => parseInt(n).toString(16).padStart(2, '0')).join('')}); /* DROP ${selectedFrame.clientIp} */`}</code>
                <button
                  onClick={() => copyToClipboard(`iptables -I INPUT -s ${selectedFrame.clientIp} -j DROP`)}
                  className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[10px] font-bold shrink-0 font-mono"
                >
                  Copy Rule
                </button>
              </div>
            </div>

            {/* Modal Footer Actions */}
            <div className="flex items-center justify-between pt-2 border-t border-slate-800">
              <button
                onClick={handleCloseInspector}
                className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-bold transition"
              >
                {isAr ? 'إغلاق' : 'Close'}
              </button>
              {!selectedFrame.isBlocked && selectedFrame.threatScore >= 40 && (
                <button
                  onClick={() => {
                    handleBanIp(selectedFrame.clientIp, `Manual drop from Deep Inspector`);
                    handleCloseInspector();
                  }}
                  className="px-4 py-2 rounded-xl bg-rose-600 hover:bg-rose-500 text-white text-xs font-bold transition flex items-center gap-1.5 shadow-md shadow-rose-950/50"
                >
                  <Ban className="w-3.5 h-3.5" />
                  <span>{isAr ? 'حظر هذا العنوان فوراً' : 'Enforce Immediate IP Drop'}</span>
                </button>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
