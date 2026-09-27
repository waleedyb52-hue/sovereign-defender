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

export const SiteTrafficSecurityInspector: React.FC<SiteTrafficSecurityInspectorProps> = ({
  lang
}) => {
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
  const [selectedVerdict, setSelectedVerdict] = useState<'ALL' | 'SAFE_ONLY' | 'MALICIOUS_ONLY'>(
    'ALL'
  );
  const [selectedFrame, setSelectedFrame] = useState<HttpRequestFrame | null>(null);
  const [isModalOpen, setIsModalOpen] = useState<boolean>(false);
  const [isHardeningInProgress, setIsHardeningInProgress] = useState<boolean>(false);
  const [hardeningFeedback, setHardeningFeedback] = useState<{
    msgEn: string;
    msgAr: string;
  } | null>(null);
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
  const [soarLogs, setSoarLogs] = useState<
    Array<{
      id: string;
      time: string;
      playbook: string;
      target: string;
      action: string;
      status: 'SUCCESS' | 'EXECUTING';
    }>
  >([
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
    if (frames.length === 0)
      return {
        level: 'GREEN',
        labelEn: 'SECURE',
        labelAr: 'مؤمن بالكامل',
        bgClass: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40'
      };
    const recent = frames.slice(0, 25);
    const criticalThreats = recent.filter(
      f =>
        f.threatScore >= 80 ||
        f.category === 'RCE_ATTEMPT' ||
        f.category === 'SQLI_ATTEMPT' ||
        f.category === 'HONEYTOKEN_HIT'
    ).length;
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
        const matchesPayload = f.rawPayloadSnippet
          ? f.rawPayloadSnippet.toLowerCase().includes(q)
          : false;
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
        if (selectedCategory === 'COMMAND_INJECTION' && f.category !== 'COMMAND_INJECTION')
          return false;
        if (selectedCategory === 'PATH_TRAVERSAL' && f.category !== 'PATH_TRAVERSAL') return false;
        if (selectedCategory === 'HONEYTOKEN_HIT' && f.category !== 'HONEYTOKEN_HIT') return false;
        if (
          ![
            'BLOCKED',
            'SAFE',
            'SQLI_ATTEMPT',
            'XSS_ATTEMPT',
            'COMMAND_INJECTION',
            'PATH_TRAVERSAL',
            'HONEYTOKEN_HIT'
          ].includes(selectedCategory) &&
          f.category !== selectedCategory
        )
          return false;
      }

      // Verdict filter
      if (selectedVerdict === 'SAFE_ONLY' && (f.threatScore >= 40 || f.isBlocked)) return false;
      if (selectedVerdict === 'MALICIOUS_ONLY' && f.threatScore < 40 && !f.isBlocked) return false;

      return true;
    });
  }, [frames, searchQuery, selectedCategory, selectedVerdict]);

  // Aggregate frames by Actor IP
  const actorGroups = useMemo(() => {
    const groupsMap = new Map<
      string,
      {
        clientIp: string;
        frames: HttpRequestFrame[];
        totalCount: number;
        threatCount: number;
        maxThreatScore: number;
        primaryVector: string;
        latestTimestamp: string;
        isBlocked: boolean;
        methods: Set<string>;
      }
    >();

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

    return Array.from(groupsMap.values()).sort(
      (a, b) => b.maxThreatScore - a.maxThreatScore || b.totalCount - a.totalCount
    );
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
      <div className="relative overflow-hidden rounded-2xl border border-slate-800 bg-slate-900 p-5 shadow-xl sm:p-6 shadow-[0_0_20px_rgba(0,255,255,0.08)]">
        <div className="relative z-10 flex flex-col gap-5 lg:flex-row lg:items-center lg:justify-between">
          {/* Title & Description */}
          <div className="flex items-start gap-4">
            <div className="shrink-0 rounded-xl border border-cyan-400/30 bg-gradient-to-br from-cyan-600 to-emerald-700 p-3 text-white shadow-lg shadow-cyan-950/60">
              <Activity className="h-6 w-6 animate-pulse" />
            </div>
            <div>
              <div className="flex flex-wrap items-center gap-2.5">
                <h1 className="text-xl font-black tracking-tight text-white sm:text-2xl">
                  {isAr ? 'فاحص ومراقب حركة مرور الموقع' : 'Site Traffic & Security Inspector'}
                </h1>
                <span className="flex items-center gap-1.5 rounded-full border border-cyan-500/40 bg-cyan-500/20 px-2.5 py-0.5 font-mono text-xs font-bold text-cyan-300">
                  <Radio className="h-3 w-3 animate-ping text-cyan-400" />
                  {isAr ? 'مباشر' : 'LIVE'}
                </span>
                {isLockdownActive && (
                  <span className="flex animate-pulse items-center gap-1.5 rounded-full border border-rose-500 bg-rose-600/30 px-2.5 py-0.5 text-xs font-bold text-rose-300">
                    <Lock className="h-3 w-3 text-rose-400" />
                    {isAr ? 'حظر الصفر مفعّل' : 'ZERO-TRUST ACTIVE'}
                  </span>
                )}
              </div>
              <p className="mt-1 max-w-2xl text-xs text-slate-400 sm:text-sm">
                {isAr
                  ? 'مراقبة حركة طلبات الموقع وفحص التهديدات بالزمن الحقيقي مع التحكم التكتيكي الفوري.'
                  : 'Real-time ingress traffic monitoring, autonomous payload inspection, and one-click mitigation.'}
              </p>
            </div>
          </div>

          {/* Top Tactical Action Buttons */}
          <div className="flex flex-wrap items-center gap-2">
            <button
              onClick={() => setIsLiveStreaming(!isLiveStreaming)}
              className={`flex items-center gap-1.5 rounded-xl border px-3 py-2 text-xs font-bold transition ${
                isLiveStreaming
                  ? 'border-emerald-500/40 bg-emerald-500/20 text-emerald-300 hover:bg-emerald-500/30'
                  : 'border-slate-700 bg-slate-800 text-slate-400 hover:text-white'
              }`}
            >
              {isLiveStreaming ? (
                <Pause className="h-3.5 w-3.5 text-emerald-400" />
              ) : (
                <Play className="h-3.5 w-3.5 text-slate-300" />
              )}
              <span>
                {isLiveStreaming
                  ? isAr
                    ? 'إيقاف البث'
                    : 'Pause Feed'
                  : isAr
                    ? 'استئناف'
                    : 'Resume'}
              </span>
            </button>

            <button
              onClick={() => fetchTelemetry()}
              disabled={isLoading}
              className="flex items-center gap-1.5 rounded-xl border border-slate-700 bg-slate-800 px-3 py-2 text-xs font-bold text-slate-200 transition hover:bg-slate-700"
              title={isAr ? 'تحديث السجلات' : 'Refresh Telemetry'}
            >
              <RefreshCw
                className={`h-3.5 w-3.5 text-cyan-400 ${isLoading ? 'animate-spin' : ''}`}
              />
              <span className="font-mono text-[11px]">{lastSyncTime}</span>
            </button>

            {/* One-Click Site Hardening Button */}
            <button
              onClick={handleEnforceSiteHardening}
              disabled={isHardeningInProgress}
              className="flex items-center gap-1.5 rounded-xl border border-emerald-400/40 bg-gradient-to-r from-emerald-600 to-cyan-600 px-3.5 py-2 text-xs font-black text-white shadow-lg shadow-emerald-950/60 transition hover:from-emerald-500 hover:to-cyan-500 active:scale-95 disabled:opacity-50"
            >
              <ShieldCheck
                className={`h-3.5 w-3.5 text-white ${isHardeningInProgress ? 'animate-spin' : ''}`}
              />
              <span>
                {isHardeningInProgress
                  ? isAr
                    ? 'جاري التعزيز...'
                    : 'Enforcing...'
                  : isAr
                    ? '⚡ تعزيز أمان OWASP'
                    : '⚡ One-Click OWASP'}
              </span>
            </button>
          </div>
        </div>

        {/* Hardening Feedback Notification */}
        {hardeningFeedback && (
          <div className="mt-3 flex items-center justify-between gap-3 rounded-xl border border-emerald-500/50 bg-emerald-950/60 p-3 text-xs text-emerald-200">
            <div className="flex items-center gap-2">
              <Check className="h-4 w-4 shrink-0 text-emerald-400" />
              <span>{isAr ? hardeningFeedback.msgAr : hardeningFeedback.msgEn}</span>
            </div>
            <button
              onClick={() => setHardeningFeedback(null)}
              className="text-slate-400 hover:text-white"
            >
              ✕
            </button>
          </div>
        )}
      </div>

      {/* ========================================================================= */}
      {/* 1. UNIFIED SYSTEM HEALTH BANNER (EXACTLY 4 HERO METRICS)                   */}
      {/* ========================================================================= */}
      <div className="grid grid-cols-2 gap-3 sm:gap-4 lg:grid-cols-4">
        {/* Metric 1: Site Security Status */}
        <div
          className={`relative overflow-hidden rounded-2xl border p-4 transition-all duration-300 sm:p-5 ${
            siteSafetyStatus.level === 'GREEN'
              ? 'border-emerald-500/40 bg-emerald-950/25 shadow-lg shadow-emerald-950/20'
              : siteSafetyStatus.level === 'AMBER'
                ? 'border-amber-500/40 bg-amber-950/25 shadow-lg shadow-amber-950/20'
                : 'animate-pulse border-rose-500/60 bg-rose-950/35 shadow-lg shadow-rose-950/40'
          }`}
        >
          <div className="mb-2 flex items-center justify-between">
            <span className="text-[11px] font-bold tracking-wider text-slate-400 uppercase">
              {isAr ? 'حالة أمان الموقع' : 'Site Security Status'}
            </span>
            {siteSafetyStatus.level === 'GREEN' ? (
              <ShieldCheck className="h-4 w-4 text-emerald-400" />
            ) : siteSafetyStatus.level === 'AMBER' ? (
              <AlertTriangle className="h-4 w-4 text-amber-400" />
            ) : (
              <Flame className="h-4 w-4 text-rose-400" />
            )}
          </div>
          <div className="flex items-center gap-2">
            <span
              className={`inline-flex items-center gap-1.5 rounded-lg border px-2.5 py-1 font-mono text-xs font-black ${siteSafetyStatus.bgClass}`}
            >
              <span
                className={`h-2 w-2 rounded-full ${siteSafetyStatus.level === 'GREEN' ? 'bg-emerald-400' : siteSafetyStatus.level === 'AMBER' ? 'bg-amber-400' : 'bg-rose-400'}`}
              />
              {siteSafetyStatus.labelEn}
            </span>
          </div>
          <p className="mt-2 truncate text-[11px] text-slate-400">
            {isAr ? siteSafetyStatus.detailAr : siteSafetyStatus.detailEn}
          </p>
        </div>

        {/* Metric 2: Traffic Volume (RPS) */}
        <div className="relative overflow-hidden rounded-2xl border border-slate-800 bg-slate-900/90 p-4 shadow-lg sm:p-5 shadow-[0_0_20px_rgba(0,255,255,0.08)]">
          <div className="mb-2 flex items-center justify-between">
            <span className="text-[11px] font-bold tracking-wider text-slate-400 uppercase">
              {isAr ? 'حجم حركة المرور (RPS)' : 'Traffic Volume'}
            </span>
            <Activity className="h-4 w-4 text-cyan-400" />
          </div>
          <div className="flex items-baseline gap-1.5">
            <span className="font-mono text-2xl font-black text-white sm:text-3xl">
              {metrics.rps}
            </span>
            <span className="font-mono text-xs font-bold text-cyan-400">RPS</span>
          </div>
          <p className="mt-2 text-[11px] text-slate-400">
            {isAr ? 'الطلبات المباشرة في الثانية' : 'Requests per second'}
          </p>
        </div>

        {/* Metric 3: Active Blocked Threats */}
        <div className="relative overflow-hidden rounded-2xl border border-slate-800 bg-slate-900/90 p-4 shadow-lg sm:p-5 shadow-[0_0_20px_rgba(0,255,255,0.08)]">
          <div className="mb-2 flex items-center justify-between">
            <span className="text-[11px] font-bold tracking-wider text-slate-400 uppercase">
              {isAr ? 'التهديدات المحجوبة' : 'Active Blocked Threats'}
            </span>
            <Ban className="h-4 w-4 text-rose-400" />
          </div>
          <div className="flex items-baseline gap-1.5">
            <span className="font-mono text-2xl font-black text-rose-400 sm:text-3xl">
              {metrics.droppedPackets.toLocaleString()}
            </span>
            <span className="font-mono text-xs font-bold text-rose-300">
              {isAr ? 'محظور' : 'dropped'}
            </span>
          </div>
          <p className="mt-2 text-[11px] text-slate-400">
            {isAr ? 'إجمالي الحزم المعترضة' : 'Total threats neutralized'}
          </p>
        </div>

        {/* Metric 4: eBPF Filter Status */}
        <div className="relative overflow-hidden rounded-2xl border border-slate-800 bg-slate-900/90 p-4 shadow-lg sm:p-5 shadow-[0_0_20px_rgba(0,255,255,0.08)]">
          <div className="mb-2 flex items-center justify-between">
            <span className="text-[11px] font-bold tracking-wider text-slate-400 uppercase">
              {isAr ? 'مرشح النواة (eBPF)' : 'eBPF Filter Status'}
            </span>
            <Zap className="h-4 w-4 text-emerald-400" />
          </div>
          <div className="flex items-baseline gap-1.5">
            <span className="font-mono text-2xl font-black text-emerald-400 sm:text-3xl">
              {metrics.ebpfLatencyUs}
            </span>
            <span className="font-mono text-xs font-bold text-emerald-300">µs latency</span>
          </div>
          <p className="mt-2 flex items-center gap-1 font-mono text-[11px] text-emerald-400">
            <span className="inline-block h-1.5 w-1.5 rounded-full bg-emerald-400" />
            {isAr ? 'نشط في النواة (Sub-µs)' : 'Active (XDP Driver Hook)'}
          </p>
        </div>
      </div>

      {/* PROGRESSIVE DISCLOSURE: Secondary Micro-Metrics Drawer Toggle */}
      <div className="flex items-center justify-between pt-1">
        <button
          onClick={() => setShowAdvancedMetrics(!showAdvancedMetrics)}
          className="flex items-center gap-1.5 text-xs font-medium text-slate-400 transition hover:text-cyan-300"
        >
          {showAdvancedMetrics ? (
            <ChevronUp className="h-3.5 w-3.5 text-cyan-400" />
          ) : (
            <ChevronDown className="h-3.5 w-3.5 text-cyan-400" />
          )}
          <span>
            {showAdvancedMetrics
              ? isAr
                ? 'إخفاء المقاييس التفصيلية'
                : 'Hide Secondary Metrics'
              : isAr
                ? 'عرض المقاييس الإضافية (Secondary Metrics)'
                : 'Show Secondary Metrics & WAF Diagnostics'}
          </span>
        </button>

        <div className="flex items-center gap-2">
          {/* Toggle Simulator Drawer */}
          <button
            onClick={() => setIsSimulatorExpanded(!isSimulatorExpanded)}
            className={`flex items-center gap-1 rounded-lg border px-2.5 py-1 text-xs font-medium transition ${
              isSimulatorExpanded
                ? 'border-cyan-500/40 bg-cyan-950/60 text-cyan-300'
                : 'border-slate-800 bg-slate-900 text-slate-400 hover:text-slate-200 shadow-[0_0_20px_rgba(0,255,255,0.08)]'
            }`}
          >
            <Crosshair className="h-3 w-3 text-cyan-400" />
            <span>{isAr ? 'مختبر المحاكاة' : 'Attack Simulator Lab'}</span>
          </button>

          {/* Toggle OWASP Matrix */}
          <button
            onClick={() => setIsOwaspMatrixExpanded(!isOwaspMatrixExpanded)}
            className={`flex items-center gap-1 rounded-lg border px-2.5 py-1 text-xs font-medium transition ${
              isOwaspMatrixExpanded
                ? 'border-cyan-500/40 bg-cyan-950/60 text-cyan-300'
                : 'border-slate-800 bg-slate-900 text-slate-400 hover:text-slate-200 shadow-[0_0_20px_rgba(0,255,255,0.08)]'
            }`}
          >
            <Layers className="h-3 w-3 text-cyan-400" />
            <span>{isAr ? 'قواعد OWASP' : 'OWASP Rules'}</span>
          </button>
        </div>
      </div>

      {/* Advanced Secondary Metrics Collapsible Section */}
      {showAdvancedMetrics && (
        <div className="animate-fadeIn grid grid-cols-2 gap-3 rounded-xl border border-slate-800 bg-slate-900/60 p-4 text-xs sm:grid-cols-4 shadow-[0_0_20px_rgba(0,255,255,0.08)]">
          <div className="space-y-1">
            <span className="block text-[10px] font-bold text-slate-500 uppercase">
              {isAr ? 'إجمالي الطلبات' : 'Total Ingested'}
            </span>
            <span className="font-mono font-bold text-slate-200">
              {metrics.totalRequests.toLocaleString()} reqs
            </span>
          </div>
          <div className="space-y-1">
            <span className="block text-[10px] font-bold text-slate-500 uppercase">
              {isAr ? 'النطاقات المحظورة' : 'Blocked Subnets'}
            </span>
            <span className="font-mono font-bold text-rose-300">
              {metrics.activeBlockedSubnetsCount} CIDRs
            </span>
          </div>
          <div className="space-y-1">
            <span className="block text-[10px] font-bold text-slate-500 uppercase">
              {isAr ? 'حد معدل الطلبات' : 'Rate Limiter'}
            </span>
            <span className="font-mono font-bold text-emerald-300">
              {metrics.wafConfig?.rateLimitThresholdRpm || 60} RPM / IP
            </span>
          </div>
          <div className="space-y-1">
            <span className="block text-[10px] font-bold text-slate-500 uppercase">
              {isAr ? 'حمل المعالج' : 'Kernel CPU Overhead'}
            </span>
            <span className="font-mono font-bold text-cyan-300">&lt; 0.01%</span>
          </div>
        </div>
      )}

      {/* MODULAR COLLAPSIBLE SECTION: ATTACK SIMULATOR */}
      {isSimulatorExpanded && (
        <div className="animate-fadeIn space-y-3 rounded-2xl border border-cyan-500/30 bg-slate-900/90 p-4 shadow-lg">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Crosshair className="h-4 w-4 text-cyan-400" />
              <h2 className="text-xs font-bold tracking-wider text-white uppercase">
                {isAr ? 'مختبر محاكاة الهجمات وحقن الحزم' : 'Live Attack Simulation Lab'}
              </h2>
            </div>
            <button
              onClick={() => setIsSimulatorExpanded(false)}
              className="text-xs text-slate-400 hover:text-white"
            >
              ✕
            </button>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <button
              onClick={() => handleSimulateAttack('SQLI_ATTEMPT')}
              disabled={isLoading}
              className="rounded-lg border border-rose-500/40 bg-rose-500/20 px-3 py-1.5 text-xs font-bold text-rose-300 transition hover:bg-rose-500/30"
            >
              {isAr ? 'اختبار حقن SQLi' : 'Test SQL Injection'}
            </button>
            <button
              onClick={() => handleSimulateAttack('XSS_ATTEMPT')}
              disabled={isLoading}
              className="rounded-lg border border-amber-500/40 bg-amber-500/20 px-3 py-1.5 text-xs font-bold text-amber-300 transition hover:bg-amber-500/30"
            >
              {isAr ? 'اختبار هجوم XSS' : 'Test XSS Attack'}
            </button>
            <button
              onClick={() => handleSimulateAttack('COMMAND_INJECTION')}
              disabled={isLoading}
              className="rounded-lg border border-cyan-500/40 bg-cyan-500/20 px-3 py-1.5 text-xs font-bold text-cyan-300 transition hover:bg-cyan-500/30"
            >
              {isAr ? 'اختبار حقن الأوامر RCE' : 'Test RCE Command'}
            </button>
            <button
              onClick={() => handleSimulateAttack('HONEYTOKEN_HIT')}
              disabled={isLoading}
              className="rounded-lg border border-amber-500/40 bg-amber-600/20 px-3 py-1.5 text-xs font-bold text-amber-300 transition hover:bg-amber-600/30"
            >
              {isAr ? 'لمس فخ Honeytoken' : 'Trip Honeytoken'}
            </button>
            <button
              onClick={() => handleSimulateAttack('PATH_TRAVERSAL')}
              disabled={isLoading}
              className="rounded-lg border border-cyan-500/40 bg-cyan-500/20 px-3 py-1.5 text-xs font-bold text-cyan-300 transition hover:bg-cyan-500/30"
            >
              {isAr ? 'طلب طبيعي / مسار' : 'Test Safe Traffic'}
            </button>
          </div>
        </div>
      )}

      {/* MODULAR COLLAPSIBLE SECTION: OWASP ENFORCEMENT MATRIX */}
      {isOwaspMatrixExpanded && (
        <div className="animate-fadeIn space-y-3 rounded-2xl border border-slate-800 bg-slate-900/90 p-4 shadow-lg shadow-[0_0_20px_rgba(0,255,255,0.08)]">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Layers className="h-4 w-4 text-cyan-400" />
              <h2 className="text-xs font-bold tracking-wider text-white uppercase">
                {isAr
                  ? 'مصفوفة قواعد OWASP Top 10 النشطة'
                  : 'OWASP Top 10 Security Enforcement Matrix'}
              </h2>
            </div>
            <button
              onClick={() => setIsOwaspMatrixExpanded(false)}
              className="text-xs text-slate-400 hover:text-white"
            >
              ✕
            </button>
          </div>
          <div className="grid grid-cols-1 gap-2.5 text-xs sm:grid-cols-3">
            <div className="flex items-center justify-between rounded-lg border border-slate-800 bg-slate-950 p-2.5 shadow-[0_0_20px_rgba(0,255,255,0.08)]">
              <span className="font-bold text-slate-300">SQL Injection (A03)</span>
              <span className="rounded border border-emerald-500/40 bg-emerald-500/20 px-2 py-0.5 text-[10px] font-bold text-emerald-300">
                ACTIVE
              </span>
            </div>
            <div className="flex items-center justify-between rounded-lg border border-slate-800 bg-slate-950 p-2.5 shadow-[0_0_20px_rgba(0,255,255,0.08)]">
              <span className="font-bold text-slate-300">XSS Filter (A03)</span>
              <span className="rounded border border-emerald-500/40 bg-emerald-500/20 px-2 py-0.5 text-[10px] font-bold text-emerald-300">
                ACTIVE
              </span>
            </div>
            <div className="flex items-center justify-between rounded-lg border border-slate-800 bg-slate-950 p-2.5 shadow-[0_0_20px_rgba(0,255,255,0.08)]">
              <span className="font-bold text-slate-300">RCE Command Shield</span>
              <span className="rounded border border-emerald-500/40 bg-emerald-500/20 px-2 py-0.5 text-[10px] font-bold text-emerald-300">
                ACTIVE
              </span>
            </div>
            <div className="flex items-center justify-between rounded-lg border border-slate-800 bg-slate-950 p-2.5 shadow-[0_0_20px_rgba(0,255,255,0.08)]">
              <span className="font-bold text-slate-300">Path Traversal / LFI</span>
              <span className="rounded border border-emerald-500/40 bg-emerald-500/20 px-2 py-0.5 text-[10px] font-bold text-emerald-300">
                ACTIVE
              </span>
            </div>
            <div className="flex items-center justify-between rounded-lg border border-slate-800 bg-slate-950 p-2.5 shadow-[0_0_20px_rgba(0,255,255,0.08)]">
              <span className="font-bold text-slate-300">Honeytoken Decoys (6)</span>
              <span className="rounded border border-amber-500/40 bg-amber-500/20 px-2 py-0.5 text-[10px] font-bold text-amber-300">
                ARMED
              </span>
            </div>
            <div className="flex items-center justify-between rounded-lg border border-slate-800 bg-slate-950 p-2.5 shadow-[0_0_20px_rgba(0,255,255,0.08)]">
              <span className="font-bold text-slate-300">Rate Limiter (60 RPM)</span>
              <span className="rounded border border-emerald-500/40 bg-emerald-500/20 px-2 py-0.5 text-[10px] font-bold text-emerald-300">
                ENFORCING
              </span>
            </div>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* 2. SOAR AUTOMATED PLAYBOOKS & THREAT CONTAINMENT PANEL                     */}
      {/* ========================================================================= */}
      <div className="space-y-4 rounded-2xl border border-slate-800 bg-slate-900 p-4 shadow-xl sm:p-5 shadow-[0_0_20px_rgba(0,255,255,0.08)]">
        <div className="flex flex-col gap-3 border-b border-slate-800 pb-3 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex items-center gap-3">
            <div className="rounded-lg border border-cyan-500/40 bg-cyan-500/20 p-2 text-cyan-300">
              <Workflow className="h-5 w-5 text-cyan-400" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-sm font-bold tracking-wide text-white">
                  {isAr
                    ? 'محرك الاستجابة التلقائية المتقدم (SOAR Playbooks)'
                    : 'SOAR Autonomous Defense Playbooks'}
                </h2>
                <span className="rounded border border-cyan-500/40 bg-cyan-500/20 px-2 py-0.5 font-mono text-[10px] font-bold text-cyan-300">
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
            <span className="flex items-center gap-1.5 rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-2.5 py-1 font-mono text-[11px] text-emerald-400">
              <span className="h-2 w-2 animate-pulse rounded-full bg-emerald-400" />
              {isAr ? 'المحرك الآلي: يعمل' : 'SOAR Engine: Active'}
            </span>
          </div>
        </div>

        {/* Playbook Toggles Grid */}
        <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
          {/* Playbook 1: Auto-Ban IP */}
          <div
            onClick={() => setSoarAutoBan(!soarAutoBan)}
            className={`flex cursor-pointer items-center justify-between gap-3 rounded-xl border p-3.5 transition select-none ${
              soarAutoBan
                ? 'border-cyan-500/50 bg-cyan-950/40 shadow-lg shadow-cyan-950/40'
                : 'border-slate-800 bg-slate-950/60 hover:border-slate-700 shadow-[0_0_20px_rgba(0,255,255,0.08)]'
            }`}
          >
            <div className="flex items-start gap-2.5">
              <Ban
                className={`mt-0.5 h-4 w-4 shrink-0 ${soarAutoBan ? 'text-cyan-400' : 'text-slate-500'}`}
              />
              <div>
                <div className="text-xs font-bold text-slate-200">
                  {isAr
                    ? 'حظر تلقائي للـ IP عند درجة خطر > 85%'
                    : 'Auto-Ban IP if Threat Score > 85%'}
                </div>
                <div className="mt-0.5 text-[10px] text-slate-400">
                  {isAr ? 'تطبيق إسقاط فوري بنواة eBPF' : 'Instant kernel eBPF packet drop'}
                </div>
              </div>
            </div>
            <span
              className={`rounded px-2 py-0.5 font-mono text-[10px] font-bold ${
                soarAutoBan ? 'bg-cyan-500 text-white' : 'bg-slate-800 text-slate-400'
              }`}
            >
              {soarAutoBan ? (isAr ? 'مُفعّل' : 'ON') : isAr ? 'معطل' : 'OFF'}
            </span>
          </div>

          {/* Playbook 2: Auto-Rollback FIM */}
          <div
            onClick={() => setSoarAutoRollback(!soarAutoRollback)}
            className={`flex cursor-pointer items-center justify-between gap-3 rounded-xl border p-3.5 transition select-none ${
              soarAutoRollback
                ? 'border-cyan-500/50 bg-cyan-950/40 shadow-lg shadow-cyan-950/40'
                : 'border-slate-800 bg-slate-950/60 hover:border-slate-700 shadow-[0_0_20px_rgba(0,255,255,0.08)]'
            }`}
          >
            <div className="flex items-start gap-2.5">
              <RotateCcw
                className={`mt-0.5 h-4 w-4 shrink-0 ${soarAutoRollback ? 'text-cyan-400' : 'text-slate-500'}`}
              />
              <div>
                <div className="text-xs font-bold text-slate-200">
                  {isAr
                    ? 'استعادة فورية للملفات عند التلاعب (FIM)'
                    : 'Auto-Rollback Files on FIM Mutation'}
                </div>
                <div className="mt-0.5 text-[10px] text-slate-400">
                  {isAr ? 'مزامنة النسخة التشفيرية المعتمدة' : 'Restore trusted Merkle baseline'}
                </div>
              </div>
            </div>
            <span
              className={`rounded px-2 py-0.5 font-mono text-[10px] font-bold ${
                soarAutoRollback ? 'bg-cyan-500 text-white' : 'bg-slate-800 text-slate-400'
              }`}
            >
              {soarAutoRollback ? (isAr ? 'مُفعّل' : 'ON') : isAr ? 'معطل' : 'OFF'}
            </span>
          </div>

          {/* Playbook 3: Zero-Trust Auto Quarantine */}
          <div
            onClick={() => setSoarAutoIsolate(!soarAutoIsolate)}
            className={`flex cursor-pointer items-center justify-between gap-3 rounded-xl border p-3.5 transition select-none ${
              soarAutoIsolate
                ? 'border-cyan-500/50 bg-cyan-950/40 shadow-lg shadow-cyan-950/40'
                : 'border-slate-800 bg-slate-950/60 hover:border-slate-700 shadow-[0_0_20px_rgba(0,255,255,0.08)]'
            }`}
          >
            <div className="flex items-start gap-2.5">
              <Lock
                className={`mt-0.5 h-4 w-4 shrink-0 ${soarAutoIsolate ? 'text-cyan-400' : 'text-slate-500'}`}
              />
              <div>
                <div className="text-xs font-bold text-slate-200">
                  {isAr ? 'تحويل البوتات لفخ Honeypot Decoy' : 'Divert Scanners to Honeypot Decoy'}
                </div>
                <div className="mt-0.5 text-[10px] text-slate-400">
                  {isAr ? 'تضليل المهاجم واستنزاف موارده' : 'Autonomous cyber deception'}
                </div>
              </div>
            </div>
            <span
              className={`rounded px-2 py-0.5 font-mono text-[10px] font-bold ${
                soarAutoIsolate ? 'bg-cyan-500 text-white' : 'bg-slate-800 text-slate-400'
              }`}
            >
              {soarAutoIsolate ? (isAr ? 'مُفعّل' : 'ON') : isAr ? 'معطل' : 'OFF'}
            </span>
          </div>
        </div>

        {/* Live SOAR Execution Log Strip */}
        <div className="rounded-xl border border-slate-800/80 bg-slate-950/80 p-3 shadow-[0_0_20px_rgba(0,255,255,0.08)]">
          <div className="mb-2 flex items-center justify-between font-mono text-[11px] text-slate-400">
            <span className="flex items-center gap-1.5 font-bold text-slate-300">
              <History className="h-3.5 w-3.5 text-cyan-400" />
              {isAr
                ? 'أحدث الإجراءات المنفذة ذاتياً بواسطة SOAR:'
                : 'Recent Autonomous SOAR Triggers:'}
            </span>
            <span>{isAr ? 'زمن الاستجابة: 0.18ms' : 'Avg Reaction Latency: 0.18ms'}</span>
          </div>
          <div className="space-y-1.5 font-mono text-[11px]">
            {soarLogs.map(log => (
              <div
                key={log.id}
                className="flex flex-col justify-between gap-2 rounded-lg border border-slate-800 bg-slate-900/60 p-2 sm:flex-row sm:items-center shadow-[0_0_20px_rgba(0,255,255,0.08)]"
              >
                <div className="flex items-center gap-2">
                  <span className="text-[10px] text-slate-500">{log.time}</span>
                  <span className="font-bold text-cyan-300">{log.playbook}</span>
                  <span className="text-slate-400">
                    → Target: <strong className="text-cyan-300">{log.target}</strong>
                  </span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="max-w-xs truncate text-[10px] text-slate-400">{log.action}</span>
                  <span className="rounded border border-emerald-500/40 bg-emerald-500/20 px-1.5 py-0.5 text-[9px] font-bold text-emerald-300">
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
      <div className="overflow-hidden rounded-2xl border border-slate-800 bg-slate-900 shadow-xl shadow-[0_0_20px_rgba(0,255,255,0.08)]">
        {/* Table Header: Filters, View Mode Toggle, and Fast Category Chips */}
        <div className="space-y-3 border-b border-slate-800 bg-slate-950/60 p-3.5 sm:p-4 shadow-[0_0_20px_rgba(0,255,255,0.08)]">
          <div className="flex flex-col items-start justify-between gap-3 md:flex-row md:items-center">
            <div className="flex w-full items-center gap-2.5 md:w-auto">
              {/* Search Bar */}
              <div className="relative flex-1 md:w-72">
                <Search className="absolute top-1/2 left-3 h-3.5 w-3.5 -translate-y-1/2 text-slate-400" />
                <input
                  type="text"
                  value={searchQuery}
                  onChange={e => setSearchQuery(e.target.value)}
                  placeholder={
                    isAr
                      ? 'بحث بالـ IP أو المسار أو الحمولة...'
                      : 'Search IP, endpoint, or payload...'
                  }
                  className="w-full rounded-xl border border-slate-700 bg-slate-900 py-1.5 pr-3 pl-8 text-xs text-white placeholder-slate-500 transition focus:border-cyan-500 focus:outline-none shadow-[0_0_20px_rgba(0,255,255,0.08)]"
                />
              </div>

              {/* View Mode Toggle: Flat Stream vs Group by Actor IP */}
              <div className="flex shrink-0 items-center gap-1 rounded-xl border border-slate-800 bg-slate-900 p-1 text-xs shadow-[0_0_20px_rgba(0,255,255,0.08)]">
                <button
                  onClick={() => setViewMode('FLAT')}
                  className={`flex items-center gap-1.5 rounded-lg px-2.5 py-1 font-bold transition ${
                    viewMode === 'FLAT'
                      ? 'bg-cyan-600 text-white shadow-md'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                  title={isAr ? 'عرض السجل المتتابع' : 'Flat Telemetry Stream'}
                >
                  <List className="h-3.5 w-3.5" />
                  <span>{isAr ? 'السجل المباشر' : 'Live Stream'}</span>
                </button>
                <button
                  onClick={() => setViewMode('GROUP_BY_IP')}
                  className={`flex items-center gap-1.5 rounded-lg px-2.5 py-1 font-bold transition ${
                    viewMode === 'GROUP_BY_IP'
                      ? 'bg-cyan-600 text-white shadow-md'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                  title={isAr ? 'تجميع الهجمات حسب عنوان IP المهاجم' : 'Group by Actor IP'}
                >
                  <Users className="h-3.5 w-3.5" />
                  <span>{isAr ? 'تجميع حسب IP' : 'Group by IP'}</span>
                </button>
              </div>
            </div>

            {/* Verdict Filter Buttons & Total Count */}
            <div className="flex w-full items-center justify-between gap-2 text-xs md:w-auto md:justify-end">
              <div className="flex shrink-0 items-center gap-1 rounded-xl border border-slate-800 bg-slate-900 p-1 text-xs shadow-[0_0_20px_rgba(0,255,255,0.08)]">
                <button
                  onClick={() => setSelectedVerdict('ALL')}
                  className={`rounded-lg px-2 py-0.5 font-bold transition ${
                    selectedVerdict === 'ALL'
                      ? 'bg-cyan-600 text-white'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {isAr ? 'الكل' : 'All'}
                </button>
                <button
                  onClick={() => setSelectedVerdict('SAFE_ONLY')}
                  className={`rounded-lg px-2 py-0.5 font-bold transition ${
                    selectedVerdict === 'SAFE_ONLY'
                      ? 'bg-emerald-600 text-white'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {isAr ? 'الآمن' : 'Safe'}
                </button>
                <button
                  onClick={() => setSelectedVerdict('MALICIOUS_ONLY')}
                  className={`rounded-lg px-2 py-0.5 font-bold transition ${
                    selectedVerdict === 'MALICIOUS_ONLY'
                      ? 'bg-rose-600 text-white'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {isAr ? 'التهديدات' : 'Blocked'}
                </button>
              </div>

              <span className="font-mono text-[11px] whitespace-nowrap text-slate-400">
                {viewMode === 'FLAT'
                  ? `${filteredFrames.length} ${isAr ? 'سجل' : 'logs'}`
                  : `${actorGroups.length} ${isAr ? 'عناوين فريدة' : 'actors'}`}
              </span>
            </div>
          </div>

          {/* High-Speed Category Filter Chips */}
          <div className="flex scrollbar-none items-center gap-1.5 overflow-x-auto pb-1 font-mono text-[11px]">
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
                className={`rounded-lg border px-2.5 py-1 font-bold whitespace-nowrap transition ${
                  selectedCategory === chip.id
                    ? 'border-cyan-400/60 bg-cyan-500/20 text-cyan-300 shadow-sm'
                    : 'border-slate-800 bg-slate-900/80 text-slate-400 hover:border-slate-700 hover:text-slate-200 shadow-[0_0_20px_rgba(0,255,255,0.08)]'
                }`}
              >
                {chip.label}
              </button>
            ))}
          </div>
        </div>

        {/* Dynamic Table Body: FLAT STREAM or GROUP BY ACTOR IP */}
        {viewMode === 'FLAT' ? (
          <div className="max-h-[500px] overflow-x-auto overflow-y-auto">
            <table className="w-full border-collapse text-left">
              <thead className="sticky top-0 z-10 border-b border-slate-800 bg-slate-950/95 font-mono text-[11px] font-bold tracking-wider text-slate-400 uppercase backdrop-blur-md shadow-[0_0_20px_rgba(0,255,255,0.08)]">
                <tr>
                  <th className="w-28 px-4 py-2.5">{isAr ? 'الوقت' : 'Time'}</th>
                  <th className="w-44 px-4 py-2.5">{isAr ? 'عنوان IP العميل' : 'Client IP'}</th>
                  <th className="px-4 py-2.5">
                    {isAr ? 'نقطة النهاية المستهدفة' : 'Target Endpoint'}
                  </th>
                  <th className="w-36 px-4 py-2.5 text-right">
                    {isAr ? 'قرار الأمان' : 'Verdict'}
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/50 font-mono text-xs">
                {filteredFrames.length === 0 ? (
                  <tr>
                    <td colSpan={4} className="py-12 text-center text-slate-500">
                      <Shield className="mx-auto mb-2 h-7 w-7 text-slate-600 opacity-60" />
                      <p>
                        {isAr
                          ? 'لا توجد سجلات مطابقة لمعايير البحث'
                          : 'No traffic logs matching search filter'}
                      </p>
                    </td>
                  </tr>
                ) : (
                  filteredFrames.map(frame => {
                    const isBlocked = frame.isBlocked || frame.threatScore >= 80;
                    const isSuspicious = !isBlocked && frame.threatScore >= 40;
                    const isSafe = !isBlocked && !isSuspicious;

                    return (
                      <tr
                        key={frame.id}
                        onClick={() => handleOpenInspector(frame)}
                        className={`group cursor-pointer transition-colors hover:bg-slate-800/60 ${
                          isBlocked ? 'bg-rose-950/15' : isSuspicious ? 'bg-amber-950/15' : ''
                        }`}
                      >
                        {/* Column 1: Time */}
                        <td className="px-4 py-2.5 text-[11px] whitespace-nowrap text-slate-400">
                          {new Date(frame.timestamp).toLocaleTimeString()}
                        </td>

                        {/* Column 2: Client IP */}
                        <td className="px-4 py-2.5 whitespace-nowrap">
                          <span className="font-bold text-slate-200 transition group-hover:text-cyan-300">
                            {frame.clientIp}
                          </span>
                        </td>

                        {/* Column 3: Target Endpoint */}
                        <td className="px-4 py-2.5">
                          <div className="flex max-w-md items-center gap-2 truncate lg:max-w-xl">
                            <span
                              className={`shrink-0 rounded px-1.5 py-0.5 text-[9px] font-black ${
                                frame.method === 'GET'
                                  ? 'border border-cyan-500/30 bg-cyan-500/20 text-cyan-300'
                                  : frame.method === 'POST'
                                    ? 'border border-emerald-500/30 bg-emerald-500/20 text-emerald-300'
                                    : frame.method === 'PUT'
                                      ? 'border border-amber-500/30 bg-amber-500/20 text-amber-300'
                                      : 'border border-rose-500/30 bg-rose-500/20 text-rose-300'
                              }`}
                            >
                              {frame.method}
                            </span>
                            <span className="truncate text-slate-300" title={frame.uriPath}>
                              {frame.uriPath}
                            </span>
                            {frame.queryString && (
                              <span className="max-w-[140px] truncate text-[10px] text-slate-500">
                                ?{frame.queryString}
                              </span>
                            )}
                          </div>
                        </td>

                        {/* Column 4: Verdict Badge & Inspect Action Button */}
                        <td className="px-4 py-2.5 text-right whitespace-nowrap">
                          <div className="flex items-center justify-end gap-2">
                            {isSafe ? (
                              <span className="inline-flex items-center gap-1 rounded-md border border-emerald-500/40 bg-emerald-500/20 px-2 py-0.5 text-[10px] font-bold text-emerald-300">
                                <ShieldCheck className="h-3 w-3 text-emerald-400" />
                                SAFE
                              </span>
                            ) : isBlocked ? (
                              <span className="inline-flex items-center gap-1 rounded-md border border-rose-500 bg-rose-600/30 px-2 py-0.5 text-[10px] font-extrabold text-rose-300 shadow-sm shadow-rose-950">
                                <ShieldAlert className="h-3 w-3 animate-pulse text-rose-400" />
                                BLOCKED
                              </span>
                            ) : (
                              <span className="inline-flex items-center gap-1 rounded-md border border-amber-500/40 bg-amber-500/20 px-2 py-0.5 text-[10px] font-bold text-amber-300">
                                <AlertTriangle className="h-3 w-3 text-amber-400" />
                                SUSPICIOUS
                              </span>
                            )}

                            {/* Explicit Manual Inspect Button */}
                            <button
                              type="button"
                              onClick={e => {
                                e.stopPropagation();
                                handleOpenInspector(frame);
                              }}
                              className="flex items-center gap-1 rounded-md border border-slate-700 bg-slate-800 px-2 py-0.5 font-sans text-[10px] font-bold text-slate-300 transition hover:border-cyan-500/40 hover:bg-cyan-950/80 hover:text-cyan-300"
                              title={isAr ? 'فحص تفصيلي للحزمة' : 'Inspect Packet'}
                            >
                              <Eye className="h-3 w-3 text-cyan-400" />
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
          <div className="max-h-[550px] divide-y divide-slate-800/60 overflow-x-auto overflow-y-auto font-mono text-xs">
            {actorGroups.length === 0 ? (
              <div className="py-12 text-center text-slate-500">
                <Users className="mx-auto mb-2 h-7 w-7 text-slate-600 opacity-60" />
                <p>
                  {isAr ? 'لا توجد مجموعات مهاجمين مطابقة' : 'No threat actors matching filter'}
                </p>
              </div>
            ) : (
              actorGroups.map(actor => {
                const isExpanded = expandedActorIps.has(actor.clientIp);
                const isCritical = actor.maxThreatScore >= 80 || actor.isBlocked;
                const isSuspicious = !isCritical && actor.threatCount > 0;

                return (
                  <div
                    key={actor.clientIp}
                    className="bg-slate-950/40 transition hover:bg-slate-900/40"
                  >
                    {/* Actor Incident Summary Row */}
                    <div
                      onClick={() => toggleExpandActor(actor.clientIp)}
                      className="flex cursor-pointer flex-col justify-between gap-3 p-3.5 select-none md:flex-row md:items-center"
                    >
                      <div className="flex items-center gap-3">
                        <button className="rounded-md border border-slate-800 bg-slate-900 p-1 text-slate-400 hover:text-white shadow-[0_0_20px_rgba(0,255,255,0.08)]">
                          {isExpanded ? (
                            <ChevronUp className="h-4 w-4" />
                          ) : (
                            <ChevronDown className="h-4 w-4" />
                          )}
                        </button>
                        <div>
                          <div className="flex items-center gap-2">
                            <span className="text-sm font-bold text-white">{actor.clientIp}</span>
                            <span className="rounded-md border border-slate-700 bg-slate-800 px-2 py-0.5 text-[10px] font-bold text-slate-300">
                              {actor.totalCount} {isAr ? 'طلبات' : 'requests'}
                            </span>
                            {actor.threatCount > 0 && (
                              <span className="rounded-md border border-rose-500/40 bg-rose-950/80 px-2 py-0.5 text-[10px] font-bold text-rose-300">
                                {actor.threatCount} {isAr ? 'هجمات مرصودة' : 'attacks'}
                              </span>
                            )}
                          </div>
                          <div className="mt-1 flex items-center gap-2 text-[11px] text-slate-400">
                            <span>
                              {isAr ? 'المتجه الرئيسي:' : 'Primary Vector:'}{' '}
                              <strong className="text-cyan-300">{actor.primaryVector}</strong>
                            </span>
                            <span>•</span>
                            <span>
                              {isAr ? 'آخر نشاط:' : 'Latest:'}{' '}
                              {new Date(actor.latestTimestamp).toLocaleTimeString()}
                            </span>
                          </div>
                        </div>
                      </div>

                      {/* Right Threat Badge & Action Buttons */}
                      <div className="flex shrink-0 items-center gap-2">
                        <span
                          className={`rounded-lg border px-2.5 py-1 text-xs font-bold ${
                            isCritical
                              ? 'border-rose-500/50 bg-rose-500/20 text-rose-300'
                              : isSuspicious
                                ? 'border-amber-500/40 bg-amber-500/20 text-amber-300'
                                : 'border-emerald-500/40 bg-emerald-500/20 text-emerald-300'
                          }`}
                        >
                          Score: {actor.maxThreatScore}/100
                        </span>

                        <button
                          type="button"
                          onClick={e => {
                            e.stopPropagation();
                            handleBanIp(
                              actor.clientIp,
                              `Instant drop for actor: ${actor.primaryVector}`
                            );
                          }}
                          className="flex items-center gap-1.5 rounded-lg border border-rose-500/50 bg-rose-600/30 px-2.5 py-1 text-xs font-bold text-rose-200 transition hover:bg-rose-600/50"
                        >
                          <Ban className="h-3.5 w-3.5" />
                          <span>{isAr ? 'حظر المهاجم' : 'Ban Actor'}</span>
                        </button>

                        <button
                          type="button"
                          onClick={e => {
                            e.stopPropagation();
                            if (actor.frames[0]) handleOpenInspector(actor.frames[0]);
                          }}
                          className="flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800 px-2.5 py-1 text-xs font-bold text-slate-200 transition hover:bg-cyan-950 hover:text-cyan-300"
                        >
                          <Eye className="h-3.5 w-3.5 text-cyan-400" />
                          <span>{isAr ? 'فحص الأحدث' : 'Inspect'}</span>
                        </button>
                      </div>
                    </div>

                    {/* Expandable Nested Child Logs */}
                    {isExpanded && (
                      <div className="space-y-1.5 border-t border-slate-800 bg-slate-950/90 p-3 pr-4 pl-10 shadow-[0_0_20px_rgba(0,255,255,0.08)]">
                        <div className="mb-2 flex items-center justify-between text-[11px] font-bold text-slate-400">
                          <span>
                            {isAr
                              ? `السجلات المنفردة للعنوان ${actor.clientIp}:`
                              : `Individual Request History for ${actor.clientIp}:`}
                          </span>
                        </div>
                        {actor.frames.map(subFrame => (
                          <div
                            key={subFrame.id}
                            onClick={() => handleOpenInspector(subFrame)}
                            className="flex cursor-pointer items-center justify-between gap-3 rounded-lg border border-slate-800/80 bg-slate-900/70 p-2 transition hover:bg-slate-800/80 shadow-[0_0_20px_rgba(0,255,255,0.08)]"
                          >
                            <div className="flex items-center gap-2.5 truncate">
                              <span className="text-[10px] text-slate-500">
                                {new Date(subFrame.timestamp).toLocaleTimeString()}
                              </span>
                              <span
                                className={`py-0.2 rounded px-1.5 text-[9px] font-bold ${
                                  subFrame.method === 'GET'
                                    ? 'bg-cyan-500/20 text-cyan-300'
                                    : 'bg-emerald-500/20 text-emerald-300'
                                }`}
                              >
                                {subFrame.method}
                              </span>
                              <span className="truncate text-slate-200">{subFrame.uriPath}</span>
                              {subFrame.category !== 'NORMAL_TRAFFIC' && (
                                <span className="py-0.2 rounded border border-rose-500/40 bg-rose-950 px-1.5 text-[9px] font-bold text-rose-300">
                                  {subFrame.category}
                                </span>
                              )}
                            </div>
                            <div className="flex shrink-0 items-center gap-2">
                              <span
                                className={`text-[10px] font-bold ${subFrame.threatScore >= 50 ? 'text-rose-400' : 'text-slate-400'}`}
                              >
                                {subFrame.threatScore}/100
                              </span>
                              <button
                                type="button"
                                onClick={e => {
                                  e.stopPropagation();
                                  handleOpenInspector(subFrame);
                                }}
                                className="p-1 text-cyan-400 hover:text-cyan-300"
                              >
                                <Eye className="h-3.5 w-3.5" />
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
          onClick={e => {
            if (e.target === e.currentTarget) handleCloseInspector();
          }}
          className="animate-fadeIn fixed inset-0 z-50 flex items-center justify-center bg-slate-950/80 p-4 backdrop-blur-sm"
        >
          <div className="max-h-[90vh] w-full max-w-2xl space-y-4 overflow-y-auto rounded-2xl border border-slate-800 bg-slate-900 p-6 shadow-2xl shadow-[0_0_20px_rgba(0,255,255,0.08)]">
            {/* Modal Header */}
            <div className="flex items-start justify-between gap-4 border-b border-slate-800 pb-3">
              <div className="flex items-center gap-3">
                <div
                  className={`rounded-xl p-2.5 ${
                    selectedFrame.threatScore >= 80
                      ? 'border border-rose-500/40 bg-rose-500/20 text-rose-400'
                      : 'border border-cyan-500/40 bg-cyan-500/20 text-cyan-300'
                  }`}
                >
                  <Terminal className="h-5 w-5" />
                </div>
                <div>
                  <h3 className="flex items-center gap-2 text-base font-bold text-white">
                    {isAr ? 'فحص تفصيلي للطلب والحمولة' : 'Deep Request & Payload Dissection'}
                  </h3>
                  <p className="font-mono text-xs text-slate-400">
                    {selectedFrame.clientIp} • {selectedFrame.method} {selectedFrame.uriPath}
                  </p>
                </div>
              </div>
              <button
                onClick={handleCloseInspector}
                className="rounded-lg bg-slate-800 p-1 text-xs text-slate-400 transition hover:bg-slate-700 hover:text-white"
              >
                ✕
              </button>
            </div>

            {/* Verdict & Threat Category */}
            <div
              className={`rounded-xl border p-3.5 ${
                selectedFrame.threatScore >= 80
                  ? 'border-rose-500/40 bg-rose-950/30 text-rose-200'
                  : 'border-slate-800 bg-slate-950 text-slate-300 shadow-[0_0_20px_rgba(0,255,255,0.08)]'
              }`}
            >
              <div className="mb-1.5 flex items-center justify-between">
                <span className="font-mono text-[11px] font-bold tracking-wider uppercase">
                  {isAr ? 'القرار والتقييم الأمني' : 'Threat Intelligence Verdict'}
                </span>
                <span className="rounded border border-slate-700 bg-slate-900 px-2 py-0.5 font-mono text-xs font-bold shadow-[0_0_20px_rgba(0,255,255,0.08)]">
                  Threat Score: {selectedFrame.threatScore}/100
                </span>
              </div>
              <p className="text-xs leading-relaxed">
                {isAr
                  ? selectedFrame.blockReasonAr ||
                    'الطلب اجتاز فحوصات الأمان بنجاح ولا يحتوي على حمولات خبيثة معروفة.'
                  : selectedFrame.blockReasonEn ||
                    'Request successfully passed WAF inspection with zero malicious pattern matches.'}
              </p>
            </div>

            {/* Raw HTTP Payload Hex/ASCII */}
            <div className="space-y-1.5">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-slate-400">
                  {isAr ? 'الحمولة وسياق الطلب الخام (Hex/ASCII)' : 'Raw Payload & Request Context'}
                </span>
                <button
                  onClick={() =>
                    copyToClipboard(
                      selectedFrame.rawPayloadSnippet ||
                        selectedFrame.queryString ||
                        selectedFrame.uriPath
                    )
                  }
                  className="flex items-center gap-1 font-mono text-xs text-cyan-400 hover:text-cyan-300"
                >
                  {copiedText ? <Check className="h-3 w-3" /> : <Copy className="h-3 w-3" />}
                  <span>
                    {copiedText ? (isAr ? 'تم النسخ' : 'Copied') : isAr ? 'نسخ' : 'Copy Payload'}
                  </span>
                </button>
              </div>
              <pre className="max-h-40 overflow-x-auto rounded-xl border border-slate-800 bg-slate-950 p-3 font-mono text-xs leading-relaxed text-emerald-300 select-all shadow-[0_0_20px_rgba(0,255,255,0.08)]">
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
              <span className="text-xs font-bold text-slate-400">
                {isAr
                  ? 'قاعدة الإسقاط السريعة في النواة (eBPF / XDP)'
                  : 'Synthesized Kernel eBPF Drop Rule'}
              </span>
              <div className="flex items-center justify-between gap-2 rounded-xl border border-slate-800 bg-slate-950 p-2.5 font-mono text-xs text-cyan-300 shadow-[0_0_20px_rgba(0,255,255,0.08)]">
                <code className="truncate">{`bpf_xdp_drop_src_ip(0x${selectedFrame.clientIp
                  .split('.')
                  .map(n => parseInt(n).toString(16).padStart(2, '0'))
                  .join('')}); /* DROP ${selectedFrame.clientIp} */`}</code>
                <button
                  onClick={() =>
                    copyToClipboard(`iptables -I INPUT -s ${selectedFrame.clientIp} -j DROP`)
                  }
                  className="shrink-0 rounded bg-slate-800 px-2 py-1 font-mono text-[10px] font-bold text-slate-300 hover:bg-slate-700"
                >
                  Copy Rule
                </button>
              </div>
            </div>

            {/* Modal Footer Actions */}
            <div className="flex items-center justify-between border-t border-slate-800 pt-2">
              <button
                onClick={handleCloseInspector}
                className="rounded-xl bg-slate-800 px-4 py-2 text-xs font-bold text-slate-300 transition hover:bg-slate-700"
              >
                {isAr ? 'إغلاق' : 'Close'}
              </button>
              {!selectedFrame.isBlocked && selectedFrame.threatScore >= 40 && (
                <button
                  onClick={() => {
                    handleBanIp(selectedFrame.clientIp, `Manual drop from Deep Inspector`);
                    handleCloseInspector();
                  }}
                  className="flex items-center gap-1.5 rounded-xl bg-rose-600 px-4 py-2 text-xs font-bold text-white shadow-md shadow-rose-950/50 transition hover:bg-rose-500"
                >
                  <Ban className="h-3.5 w-3.5" />
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
