import React, { useState, useEffect, useMemo } from 'react';
import {
  Activity,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Zap,
  Sliders,
  Filter,
  Ban,
  Radio,
  Search,
  RefreshCw,
  Clock,
  Terminal,
  Globe,
  AlertTriangle,
  Play,
  CheckCircle2,
  XCircle,
  Copy,
  Check,
  Cpu,
  Layers,
  ChevronRight,
  ChevronDown,
  ChevronUp,
  Flame,
  Eye
} from 'lucide-react';

export interface HttpRequestFrame {
  id: string;
  timestamp: string;
  method: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'HEAD' | 'PATCH';
  uriPath: string;
  queryString?: string;
  clientIp: string;
  countryCode?: string;
  userAgent: string;
  responseCode: number;
  latencyMs: number;
  category:
    | 'NORMAL'
    | 'SQLI_ATTEMPT'
    | 'XSS_ATTEMPT'
    | 'PATH_TRAVERSAL'
    | 'COMMAND_INJECTION'
    | 'SSRF_ATTEMPT'
    | 'RCE_ATTEMPT'
    | 'HONEYTOKEN_HIT'
    | 'CREDENTIAL_STUFFING';
  threatConfidence: number;
  isBlocked: boolean;
  blockedBy?:
    'WAF_OWASP' | 'RATE_LIMITER' | 'HONEYTOKEN_JAIL' | 'EBPF_FILTER' | 'ZERO_TRUST_LOCKDOWN';
  mitreTechnique?: string;
  payloadSnippet?: string;
  wafRuleTriggered?: string;
}

export interface BlockedSubnet {
  id: string;
  cidrOrIp: string;
  reason: string;
  reasonAr: string;
  blockedAt: string;
  expiresAt: string;
  packetDropCount: number;
  threatActor?: string;
}

export interface WafMetrics {
  rps: number;
  totalRequests: number;
  droppedPackets: number;
  ebpfLatencyUs: number;
  activeBlockedSubnetsCount: number;
  wafConfig: {
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

interface WebTrafficWafPanelProps {
  lang: 'ar' | 'en';
  onRefreshTelemetry?: () => void;
}

export const WebTrafficWafPanel: React.FC<WebTrafficWafPanelProps> = ({
  lang,
  onRefreshTelemetry
}) => {
  const isAr = lang === 'ar';

  const [frames, setFrames] = useState<HttpRequestFrame[]>([]);
  const [metrics, setMetrics] = useState<WafMetrics | null>(null);
  const [blockedSubnets, setBlockedSubnets] = useState<BlockedSubnet[]>([]);
  const [selectedFrame, setSelectedFrame] = useState<HttpRequestFrame | null>(null);
  const [isModalOpen, setIsModalOpen] = useState<boolean>(false);
  const [categoryFilter, setCategoryFilter] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [isInjecting, setIsInjecting] = useState<boolean>(false);

  // Progressive Disclosure Toggles
  const [showAdvancedMetrics, setShowAdvancedMetrics] = useState<boolean>(false);
  const [isWafRulesExpanded, setIsWafRulesExpanded] = useState<boolean>(false);
  const [isSimulatorExpanded, setIsSimulatorExpanded] = useState<boolean>(false);
  const [isSubnetsExpanded, setIsSubnetsExpanded] = useState<boolean>(false);

  // Manual Inspector Modal Handlers (Manual click only)
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

  // Manual Ban State
  const [manualIp, setManualIp] = useState<string>('');
  const [manualReason, setManualReason] = useState<string>('');
  const [isBanning, setIsBanning] = useState<boolean>(false);

  // Simulation State
  const [simType, setSimType] = useState<string>('SQLI_ATTEMPT');
  const [simPayload, setSimPayload] = useState<string>('');
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const fetchTrafficData = async () => {
    setIsLoading(true);
    try {
      const [framesRes, metricsRes, subnetsRes] = await Promise.all([
        fetch(
          `/api/v1/traffic/stream?limit=60${categoryFilter !== 'ALL' ? `&filter=${categoryFilter}` : ''}`
        ),
        fetch('/api/v1/traffic/waf/metrics'),
        fetch('/api/v1/traffic/blocked-subnets')
      ]);

      if (framesRes.ok) {
        const d = await framesRes.json();
        setFrames(d.frames || []);
        // Background ingestion only - do NOT auto-select or pop up modal
      }
      if (metricsRes.ok) {
        const m = await metricsRes.json();
        setMetrics(m.metrics);
      }
      if (subnetsRes.ok) {
        const s = await subnetsRes.json();
        setBlockedSubnets(s.blockedSubnets || []);
      }
    } catch (err) {
      console.warn('Failed to fetch traffic stream:', err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchTrafficData();
    const interval = setInterval(fetchTrafficData, 4000);
    return () => clearInterval(interval);
  }, [categoryFilter]);

  // Compute Site Security Status
  const siteSecurityStatus = useMemo(() => {
    const criticalCount = frames.filter(f => f.isBlocked || f.threatConfidence >= 80).length;
    const elevatedCount = frames.filter(
      f => f.threatConfidence >= 40 && f.threatConfidence < 80
    ).length;

    if (criticalCount >= 2) {
      return {
        level: 'RED',
        labelEn: 'UNDER ATTACK',
        labelAr: 'الموقع تحت الهجوم',
        descEn: `${criticalCount} attacks dropped`,
        descAr: `${criticalCount} هجمات تم إسقاطها`,
        bgClass: 'bg-rose-950/40 border-rose-500/60 text-rose-300'
      };
    } else if (elevatedCount >= 3 || criticalCount === 1) {
      return {
        level: 'AMBER',
        labelEn: 'ELEVATED',
        labelAr: 'تهديد مرتفع',
        descEn: 'Suspicious scanning detected',
        descAr: 'رصد مسح استطلاعي مشبوه',
        bgClass: 'bg-amber-950/40 border-amber-500/50 text-amber-300'
      };
    }
    return {
      level: 'GREEN',
      labelEn: 'SECURE',
      labelAr: 'مؤمن بالكامل',
      descEn: 'Traffic verified by WAF',
      descAr: 'الحركة مفحوصة ومؤمنة',
      bgClass: 'bg-emerald-950/40 border-emerald-500/50 text-emerald-300'
    };
  }, [frames]);

  const handleToggleWafRule = async (ruleKey: string, currentValue: boolean) => {
    if (!metrics) return;
    try {
      const updatedConfig = { ...metrics.wafConfig, [ruleKey]: !currentValue };
      const res = await fetch('/api/v1/traffic/waf/config', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ config: updatedConfig })
      });
      if (res.ok) {
        const data = await res.json();
        setMetrics(prev => (prev ? { ...prev, wafConfig: data.config } : null));
      }
    } catch (err) {
      console.error('Failed to update WAF config:', err);
    }
  };

  const handleManualBan = async () => {
    if (!manualIp) return;
    setIsBanning(true);
    try {
      const res = await fetch('/api/v1/traffic/ban-ip', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ip: manualIp,
          reason: manualReason || 'Manual Blue Team SOC Quarantine Directive',
          reasonAr: 'أمر عزل أمني يدوي من قبل فريق الدفاع'
        })
      });
      if (res.ok) {
        setManualIp('');
        setManualReason('');
        fetchTrafficData();
        if (onRefreshTelemetry) onRefreshTelemetry();
      }
    } catch (err) {
      console.error('Failed to ban IP:', err);
    } finally {
      setIsBanning(false);
    }
  };

  const handleUnban = async (id: string) => {
    try {
      const res = await fetch('/api/v1/traffic/unban-ip', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id })
      });
      if (res.ok) {
        fetchTrafficData();
      }
    } catch (err) {
      console.error('Failed to unban IP:', err);
    }
  };

  const handleInjectSimulatedPacket = async () => {
    setIsInjecting(true);
    try {
      const res = await fetch('/api/v1/traffic/simulate-packet', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          category: simType,
          customPayload: simPayload || undefined
        })
      });
      if (res.ok) {
        fetchTrafficData();
        if (onRefreshTelemetry) onRefreshTelemetry();
      }
    } catch (err) {
      console.error('Simulation packet injection failed:', err);
    } finally {
      setIsInjecting(false);
    }
  };

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  // Filtered frames
  const filteredFrames = useMemo(() => {
    return frames.filter(f => {
      if (!searchQuery.trim()) return true;
      const q = searchQuery.toLowerCase();
      return (
        f.clientIp.toLowerCase().includes(q) ||
        f.uriPath.toLowerCase().includes(q) ||
        (f.queryString && f.queryString.toLowerCase().includes(q)) ||
        f.category.toLowerCase().includes(q)
      );
    });
  }, [frames, searchQuery]);

  return (
    <div className="space-y-4 font-sans text-slate-200">
      {/* ========================================================================= */}
      {/* 1. UNIFIED SYSTEM HEALTH BANNER (EXACTLY 4 HERO METRICS)                   */}
      {/* ========================================================================= */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        {/* Metric 1: Site Security Status */}
        <div
          className={`relative overflow-hidden rounded-xl border p-3.5 transition ${siteSecurityStatus.bgClass}`}
        >
          <div className="mb-1.5 flex items-center justify-between text-xs">
            <span className="font-bold tracking-wider text-slate-300 uppercase">
              {isAr ? 'حالة أمان الموقع' : 'Site Security Status'}
            </span>
            {siteSecurityStatus.level === 'GREEN' ? (
              <ShieldCheck className="h-4 w-4 text-emerald-400" />
            ) : siteSecurityStatus.level === 'AMBER' ? (
              <AlertTriangle className="h-4 w-4 text-amber-400" />
            ) : (
              <Flame className="h-4 w-4 animate-pulse text-rose-400" />
            )}
          </div>
          <div className="flex items-center gap-2">
            <span className="rounded border border-slate-700 bg-slate-950/70 px-2 py-0.5 font-mono text-sm font-black">
              {siteSecurityStatus.labelEn}
            </span>
          </div>
          <p className="mt-1.5 truncate text-[11px] text-slate-400">
            {isAr ? siteSecurityStatus.descAr : siteSecurityStatus.descEn}
          </p>
        </div>

        {/* Metric 2: Traffic Volume */}
        <div className="relative overflow-hidden rounded-xl border border-cyan-500/30 bg-slate-900/90 p-3.5 shadow-lg">
          <div className="mb-1.5 flex items-center justify-between text-xs text-cyan-300">
            <span className="font-bold tracking-wider text-slate-300 uppercase">
              {isAr ? 'حجم حركة المرور' : 'Traffic Volume'}
            </span>
            <Activity className="h-4 w-4 animate-pulse text-cyan-400" />
          </div>
          <div className="font-mono text-2xl font-bold text-cyan-200">
            {metrics?.rps || 42.5} <span className="text-xs text-slate-400">RPS</span>
          </div>
          <p className="mt-1.5 text-[11px] text-slate-400">
            {isAr ? 'الطلبات في الثانية' : 'Requests per second'}
          </p>
        </div>

        {/* Metric 3: Active Blocked Threats */}
        <div className="relative overflow-hidden rounded-xl border border-rose-500/30 bg-slate-900/90 p-3.5 shadow-lg">
          <div className="mb-1.5 flex items-center justify-between text-xs text-rose-300">
            <span className="font-bold tracking-wider text-slate-300 uppercase">
              {isAr ? 'التهديدات المحجوبة' : 'Active Blocked Threats'}
            </span>
            <Ban className="h-4 w-4 text-rose-400" />
          </div>
          <div className="font-mono text-2xl font-bold text-rose-300">
            {(metrics?.droppedPackets || 3841).toLocaleString()}
          </div>
          <p className="mt-1.5 text-[11px] text-slate-400">
            {isAr ? 'إجمالي الحزم المعترضة' : 'Total dropped frames'}
          </p>
        </div>

        {/* Metric 4: eBPF Filter Status */}
        <div className="relative overflow-hidden rounded-xl border border-emerald-500/30 bg-slate-900/90 p-3.5 shadow-lg">
          <div className="mb-1.5 flex items-center justify-between text-xs text-emerald-300">
            <span className="font-bold tracking-wider text-slate-300 uppercase">
              {isAr ? 'مرشح eBPF' : 'eBPF Filter Status'}
            </span>
            <Zap className="h-4 w-4 text-emerald-400" />
          </div>
          <div className="font-mono text-2xl font-bold text-emerald-300">
            {metrics?.ebpfLatencyUs || 0.38} <span className="text-xs text-slate-400">µs</span>
          </div>
          <p className="mt-1.5 flex items-center gap-1 font-mono text-[11px] text-emerald-400">
            <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" />
            {isAr ? 'نشط في النواة' : 'Active • Kernel XDP'}
          </p>
        </div>
      </div>

      {/* Progressive Disclosure Toggles Toolbar */}
      <div className="flex items-center justify-between pt-1">
        <button
          onClick={() => setShowAdvancedMetrics(!showAdvancedMetrics)}
          className="flex items-center gap-1.5 text-xs text-slate-400 transition hover:text-cyan-300"
        >
          {showAdvancedMetrics ? (
            <ChevronUp className="h-3.5 w-3.5 text-cyan-400" />
          ) : (
            <ChevronDown className="h-3.5 w-3.5 text-cyan-400" />
          )}
          <span>
            {showAdvancedMetrics
              ? isAr
                ? 'إخفاء المقاييس الإضافية'
                : 'Hide Secondary Metrics'
              : isAr
                ? 'عرض المقاييس الإضافية'
                : 'Show Secondary Metrics'}
          </span>
        </button>

        <div className="flex items-center gap-2">
          <button
            onClick={() => setIsWafRulesExpanded(!isWafRulesExpanded)}
            className={`flex items-center gap-1 rounded-lg border px-2.5 py-1 text-xs font-medium transition ${
              isWafRulesExpanded
                ? 'border-cyan-500/40 bg-cyan-950/60 text-cyan-300'
                : 'border-slate-800 bg-slate-900 text-slate-400 hover:text-slate-200'
            }`}
          >
            <Sliders className="h-3 w-3 text-cyan-400" />
            <span>{isAr ? 'قواعد WAF' : 'WAF Rules'}</span>
          </button>

          <button
            onClick={() => setIsSimulatorExpanded(!isSimulatorExpanded)}
            className={`flex items-center gap-1 rounded-lg border px-2.5 py-1 text-xs font-medium transition ${
              isSimulatorExpanded
                ? 'border-purple-500/40 bg-purple-950/60 text-purple-300'
                : 'border-slate-800 bg-slate-900 text-slate-400 hover:text-slate-200'
            }`}
          >
            <Terminal className="h-3 w-3 text-purple-400" />
            <span>{isAr ? 'حقن هجوم' : 'Simulate Packet'}</span>
          </button>

          <button
            onClick={() => setIsSubnetsExpanded(!isSubnetsExpanded)}
            className={`flex items-center gap-1 rounded-lg border px-2.5 py-1 text-xs font-medium transition ${
              isSubnetsExpanded
                ? 'border-rose-500/40 bg-rose-950/60 text-rose-300'
                : 'border-slate-800 bg-slate-900 text-slate-400 hover:text-slate-200'
            }`}
          >
            <Ban className="h-3 w-3 text-rose-400" />
            <span>
              {isAr ? `العزل (${blockedSubnets.length})` : `Quarantined (${blockedSubnets.length})`}
            </span>
          </button>
        </div>
      </div>

      {/* Secondary Metrics Drawer */}
      {showAdvancedMetrics && (
        <div className="animate-fadeIn grid grid-cols-2 gap-3 rounded-xl border border-slate-800 bg-slate-900/60 p-3.5 text-xs sm:grid-cols-4">
          <div>
            <span className="block text-[10px] font-bold text-slate-500 uppercase">
              {isAr ? 'إجمالي الطلبات' : 'Total Ingested'}
            </span>
            <span className="font-mono font-bold text-slate-200">
              {(metrics?.totalRequests || 192840).toLocaleString()} reqs
            </span>
          </div>
          <div>
            <span className="block text-[10px] font-bold text-slate-500 uppercase">
              {isAr ? 'النطاقات المعزولة' : 'Isolated Subnets'}
            </span>
            <span className="font-mono font-bold text-purple-300">
              {blockedSubnets.length} CIDRs
            </span>
          </div>
          <div>
            <span className="block text-[10px] font-bold text-slate-500 uppercase">
              {isAr ? 'حد معدل الطلبات' : 'Rate Limit Rate'}
            </span>
            <span className="font-mono font-bold text-emerald-300">120 RPM / IP</span>
          </div>
          <div>
            <span className="block text-[10px] font-bold text-slate-500 uppercase">
              {isAr ? 'نسبة الاعتراض' : 'Intercept Rate'}
            </span>
            <span className="font-mono font-bold text-cyan-300">100% Deterministic</span>
          </div>
        </div>
      )}

      {/* Collapsible WAF Rules Control Section */}
      {isWafRulesExpanded && metrics?.wafConfig && (
        <div className="animate-fadeIn rounded-xl border border-slate-800 bg-slate-900/90 p-3.5 shadow-md">
          <div className="mb-2.5 flex items-center justify-between">
            <h4 className="flex items-center gap-1.5 text-xs font-bold text-slate-200">
              <Sliders className="h-3.5 w-3.5 text-cyan-400" />
              {isAr ? 'لوحة تحكم قواعد الجدار الناري التفاعلية' : 'Interactive WAF Defense Rules'}
            </h4>
            <button
              onClick={() => setIsWafRulesExpanded(false)}
              className="text-xs text-slate-400 hover:text-white"
            >
              ✕
            </button>
          </div>
          <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-6">
            {[
              {
                key: 'owaspTop10Guard',
                label: 'OWASP Top 10',
                active: metrics.wafConfig.owaspTop10Guard
              },
              {
                key: 'sqlInjectionFilter',
                label: 'SQLi Filter',
                active: metrics.wafConfig.sqlInjectionFilter
              },
              { key: 'xssFilter', label: 'XSS Filter', active: metrics.wafConfig.xssFilter },
              { key: 'rceFilter', label: 'RCE Shield', active: metrics.wafConfig.rceFilter },
              {
                key: 'rateLimitingEnabled',
                label: 'Rate Limiting',
                active: metrics.wafConfig.rateLimitingEnabled
              },
              {
                key: 'challengeBotCaptcha',
                label: 'Anti-Bot CAPTCHA',
                active: metrics.wafConfig.challengeBotCaptcha
              }
            ].map(rule => (
              <button
                key={rule.key}
                onClick={() => handleToggleWafRule(rule.key, rule.active)}
                className={`flex flex-col justify-between rounded-lg border p-2 text-left text-xs transition ${
                  rule.active
                    ? 'border-cyan-500/40 bg-cyan-950/60 text-cyan-200'
                    : 'border-slate-800 bg-slate-950 text-slate-500'
                }`}
              >
                <div className="flex items-center justify-between">
                  <span className="text-[11px] font-bold">{rule.label}</span>
                  <span
                    className={`h-2 w-2 rounded-full ${rule.active ? 'bg-cyan-400' : 'bg-slate-600'}`}
                  />
                </div>
                <span className="mt-1 text-[9px] text-slate-400">
                  {rule.active ? 'ACTIVE' : 'OFF'}
                </span>
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Collapsible Attack Packet Simulator */}
      {isSimulatorExpanded && (
        <div className="animate-fadeIn rounded-xl border border-purple-500/30 bg-slate-900/90 p-3.5 shadow-md">
          <div className="mb-2 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Terminal className="h-4 w-4 text-purple-400" />
              <span className="text-xs font-bold text-slate-200">
                {isAr
                  ? 'حقن واختبار حزم الهجوم المباشرة'
                  : 'Live Attack Packet Injector (Red/Blue Simulation)'}
              </span>
            </div>
            <button
              onClick={() => setIsSimulatorExpanded(false)}
              className="text-xs text-slate-400 hover:text-white"
            >
              ✕
            </button>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <select
              value={simType}
              onChange={e => setSimType(e.target.value)}
              className="rounded-lg border border-slate-700 bg-slate-950 px-2.5 py-1.5 font-mono text-xs text-cyan-300 focus:border-cyan-500 focus:outline-none"
            >
              <option value="SQLI_ATTEMPT">SQL Injection (' OR '1'='1 -- UNION SELECT)</option>
              <option value="XSS_ATTEMPT">Cross-Site Scripting (&lt;script&gt;fetch cookie)</option>
              <option value="PATH_TRAVERSAL">Path Traversal (../../../../etc/shadow)</option>
              <option value="COMMAND_INJECTION">
                Command Injection (host=127.0.0.1; cat /etc/passwd)
              </option>
              <option value="SSRF_ATTEMPT">
                SSRF Cloud Metadata (169.254.169.254/latest/meta-data)
              </option>
              <option value="RCE_ATTEMPT">RCE Remote Code (eval(base64_decode(...)))</option>
              <option value="HONEYTOKEN_HIT">Honeytoken Access (GET /.env Canary)</option>
            </select>

            <input
              type="text"
              placeholder={isAr ? 'حمولة مخصصة اختيارية...' : 'Optional custom payload string...'}
              value={simPayload}
              onChange={e => setSimPayload(e.target.value)}
              className="min-w-[200px] flex-1 rounded-lg border border-slate-700 bg-slate-950 px-3 py-1.5 font-mono text-xs text-slate-200 placeholder-slate-500 focus:border-cyan-500 focus:outline-none"
            />

            <button
              onClick={handleInjectSimulatedPacket}
              disabled={isInjecting}
              className="flex items-center gap-1.5 rounded-lg bg-gradient-to-r from-purple-600 to-indigo-600 px-4 py-1.5 text-xs font-bold text-white transition hover:from-purple-500 hover:to-indigo-500 disabled:opacity-50"
            >
              <Play className="h-3.5 w-3.5 fill-white" />
              <span>
                {isInjecting
                  ? isAr
                    ? 'جاري الإرسال...'
                    : 'Injecting...'
                  : isAr
                    ? 'إرسال واختبار'
                    : 'Inject Packet'}
              </span>
            </button>
          </div>
        </div>
      )}

      {/* Collapsible Active Blocked Subnets Table */}
      {isSubnetsExpanded && (
        <div className="animate-fadeIn space-y-2 rounded-xl border border-rose-500/30 bg-slate-900/90 p-3.5 shadow-md">
          <div className="flex items-center justify-between border-b border-slate-800 pb-2">
            <div className="flex items-center gap-2">
              <Ban className="h-4 w-4 text-rose-400" />
              <span className="text-xs font-bold text-slate-200">
                {isAr
                  ? 'قائمة العناوين والشبكات المعزولة في نواة eBPF'
                  : 'Active eBPF Quarantined Subnets'}
              </span>
            </div>
            <button
              onClick={() => setIsSubnetsExpanded(false)}
              className="text-xs text-slate-400 hover:text-white"
            >
              ✕
            </button>
          </div>
          <div className="max-h-48 overflow-x-auto font-mono text-xs">
            <table className="w-full text-left">
              <thead>
                <tr className="border-b border-slate-800 text-[10px] text-slate-400">
                  <th className="px-2 py-1">{isAr ? 'العنوان / الشبكة' : 'CIDR / IP'}</th>
                  <th className="px-2 py-1">{isAr ? 'السبب' : 'Reason'}</th>
                  <th className="px-2 py-1">{isAr ? 'الحزم المسقطة' : 'Dropped Pkts'}</th>
                  <th className="px-2 py-1 text-right">{isAr ? 'الإجراء' : 'Action'}</th>
                </tr>
              </thead>
              <tbody>
                {blockedSubnets.map(sub => (
                  <tr
                    key={sub.id}
                    className="border-b border-slate-800/40 transition hover:bg-slate-950/40"
                  >
                    <td className="px-2 py-1.5 font-bold text-red-400">{sub.cidrOrIp}</td>
                    <td className="px-2 py-1.5 text-[11px] text-slate-300">
                      {isAr ? sub.reasonAr : sub.reason}
                    </td>
                    <td className="px-2 py-1.5 text-rose-400">
                      {sub.packetDropCount.toLocaleString()}
                    </td>
                    <td className="px-2 py-1.5 text-right">
                      <button
                        onClick={() => handleUnban(sub.id)}
                        className="rounded bg-slate-800 px-2 py-0.5 text-[10px] text-slate-300 hover:bg-slate-700"
                      >
                        {isAr ? 'إلغاء' : 'Unban'}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* 2. CLEAN & STREAMLINED 4-COLUMN TELEMETRY STREAM                           */}
      {/* ========================================================================= */}
      <div className="overflow-hidden rounded-xl border border-slate-800 bg-slate-900/90 shadow-xl">
        {/* Search & Filter Header */}
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 bg-slate-950/60 p-3">
          <div className="flex max-w-sm flex-1 items-center gap-2">
            <Search className="h-3.5 w-3.5 shrink-0 text-slate-400" />
            <input
              type="text"
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
              placeholder={isAr ? 'بحث بالـ IP أو المسار...' : 'Filter by IP or URI endpoint...'}
              className="w-full rounded-lg border border-slate-700 bg-slate-900 px-2.5 py-1 text-xs text-white placeholder-slate-500 focus:border-cyan-500 focus:outline-none"
            />
          </div>

          <div className="flex items-center gap-1 overflow-x-auto font-mono text-[10px]">
            {[
              'ALL',
              'SQLI_ATTEMPT',
              'XSS_ATTEMPT',
              'PATH_TRAVERSAL',
              'COMMAND_INJECTION',
              'SSRF_ATTEMPT',
              'RCE_ATTEMPT',
              'HONEYTOKEN_HIT'
            ].map(cat => (
              <button
                key={cat}
                onClick={() => setCategoryFilter(cat)}
                className={`rounded px-2 py-0.5 whitespace-nowrap transition ${
                  categoryFilter === cat
                    ? 'bg-cyan-600 font-bold text-white'
                    : 'border border-slate-800 bg-slate-950 text-slate-400 hover:text-slate-200'
                }`}
              >
                {cat === 'ALL' ? (isAr ? 'الكل' : 'All') : cat.replace('_ATTEMPT', '')}
              </button>
            ))}
          </div>
        </div>

        {/* 4-Column Streamlined Table */}
        <div className="max-h-[460px] overflow-x-auto overflow-y-auto">
          <table className="w-full border-collapse text-left font-mono text-xs">
            <thead className="sticky top-0 z-10 border-b border-slate-800 bg-slate-950 text-[10px] font-bold tracking-wider text-slate-400 uppercase">
              <tr>
                <th className="w-28 px-4 py-2.5">{isAr ? 'الوقت' : 'Time'}</th>
                <th className="w-40 px-4 py-2.5">{isAr ? 'عنوان IP' : 'Client IP'}</th>
                <th className="px-4 py-2.5">
                  {isAr ? 'نقطة النهاية المستهدفة' : 'Target Endpoint'}
                </th>
                <th className="w-32 px-4 py-2.5 text-right">{isAr ? 'القرار' : 'Verdict'}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/50">
              {filteredFrames.length === 0 ? (
                <tr>
                  <td colSpan={4} className="py-10 text-center text-xs text-slate-500">
                    {isAr ? 'لا توجد حزم تطابق شروط الفلترة' : 'No traffic frames matching filter'}
                  </td>
                </tr>
              ) : (
                filteredFrames.map(frame => {
                  const isBlocked = frame.isBlocked || frame.threatConfidence >= 80;
                  const isSuspicious = !isBlocked && frame.threatConfidence >= 40;

                  return (
                    <tr
                      key={frame.id}
                      onClick={() => handleOpenInspector(frame)}
                      className={`cursor-pointer transition hover:bg-slate-800/60 ${
                        selectedFrame?.id === frame.id
                          ? 'border-l-2 border-cyan-400 bg-cyan-950/40'
                          : isBlocked
                            ? 'bg-rose-950/15'
                            : ''
                      }`}
                    >
                      {/* Column 1: Time */}
                      <td className="px-4 py-2.5 text-[11px] whitespace-nowrap text-slate-400">
                        {new Date(frame.timestamp).toLocaleTimeString()}
                      </td>

                      {/* Column 2: Client IP */}
                      <td className="px-4 py-2.5 font-bold whitespace-nowrap text-slate-200">
                        {frame.clientIp}
                      </td>

                      {/* Column 3: Target Endpoint */}
                      <td className="px-4 py-2.5">
                        <div className="flex max-w-md items-center gap-2 truncate">
                          <span
                            className={`shrink-0 rounded px-1.5 py-0.5 text-[9px] font-black ${
                              frame.method === 'POST'
                                ? 'bg-blue-500/20 text-blue-300'
                                : 'bg-slate-800 text-slate-300'
                            }`}
                          >
                            {frame.method}
                          </span>
                          <span className="truncate text-slate-300" title={frame.uriPath}>
                            {frame.uriPath}
                          </span>
                          {frame.queryString && (
                            <span className="max-w-[120px] truncate text-[10px] text-amber-400/80">
                              ?{frame.queryString}
                            </span>
                          )}
                        </div>
                      </td>

                      {/* Column 4: Verdict Badge & Inspect Action */}
                      <td className="px-4 py-2.5 text-right whitespace-nowrap">
                        <div className="flex items-center justify-end gap-1.5">
                          {isBlocked ? (
                            <span className="inline-flex items-center gap-1 rounded border border-rose-500 bg-rose-600/30 px-2 py-0.5 text-[10px] font-bold text-rose-300">
                              <ShieldAlert className="h-3 w-3 text-rose-400" />
                              BLOCKED
                            </span>
                          ) : isSuspicious ? (
                            <span className="inline-flex items-center gap-1 rounded border border-amber-500/40 bg-amber-500/20 px-2 py-0.5 text-[10px] font-bold text-amber-300">
                              <AlertTriangle className="h-3 w-3 text-amber-400" />
                              SUSPICIOUS
                            </span>
                          ) : (
                            <span className="inline-flex items-center gap-1 rounded border border-emerald-500/40 bg-emerald-500/20 px-2 py-0.5 text-[10px] font-bold text-emerald-300">
                              <ShieldCheck className="h-3 w-3 text-emerald-400" />
                              SAFE
                            </span>
                          )}

                          <button
                            type="button"
                            onClick={e => {
                              e.stopPropagation();
                              handleOpenInspector(frame);
                            }}
                            className="flex items-center gap-1 rounded border border-slate-700 bg-slate-800 px-2 py-0.5 font-sans text-[10px] font-bold text-slate-300 transition hover:bg-cyan-950 hover:text-cyan-300"
                            title={isAr ? 'فحص تفصيلي' : 'Inspect'}
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
      </div>

      {/* Deep Payload Modal Drawer when frame is selected (Strictly on user click) */}
      {isModalOpen && selectedFrame && (
        <div
          onClick={e => {
            if (e.target === e.currentTarget) handleCloseInspector();
          }}
          className="animate-fadeIn fixed inset-0 z-50 flex items-center justify-center bg-slate-950/80 p-4 backdrop-blur-sm"
        >
          <div className="max-h-[85vh] w-full max-w-xl space-y-4 overflow-y-auto rounded-2xl border border-slate-800 bg-slate-900 p-5 font-mono text-xs shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2.5">
                <Terminal className="h-4 w-4 text-cyan-400" />
                <h3 className="font-sans text-sm font-bold text-white">
                  {isAr ? 'فحص تفصيلي للحزمة والطلب' : 'Deep Packet & Payload Inspection'}
                </h3>
              </div>
              <button
                onClick={handleCloseInspector}
                className="text-xs text-slate-400 hover:text-white"
              >
                ✕
              </button>
            </div>

            <div className="grid grid-cols-2 gap-2 rounded-lg border border-slate-800 bg-slate-950 p-2.5 text-[11px]">
              <div>
                <span className="block text-[10px] text-slate-500">
                  {isAr ? 'المصدر:' : 'Source IP:'}
                </span>
                <span className="font-bold text-amber-300">{selectedFrame.clientIp}</span>
              </div>
              <div>
                <span className="block text-[10px] text-slate-500">
                  {isAr ? 'التهديد:' : 'Threat Confidence:'}
                </span>
                <span
                  className={`font-bold ${selectedFrame.threatConfidence > 80 ? 'text-rose-400' : 'text-emerald-400'}`}
                >
                  {selectedFrame.threatConfidence}%
                </span>
              </div>
              <div className="col-span-2">
                <span className="block text-[10px] text-slate-500">
                  {isAr ? 'المسار:' : 'Full URI:'}
                </span>
                <span className="break-all text-slate-200">
                  {selectedFrame.method} {selectedFrame.uriPath}
                  {selectedFrame.queryString ? `?${selectedFrame.queryString}` : ''}
                </span>
              </div>
            </div>

            <div>
              <span className="mb-1 block text-[10px] text-slate-400">
                {isAr ? 'مقتطف الحمولة المكتشفة:' : 'Raw Detected Payload / Snippet:'}
              </span>
              <div className="max-h-36 overflow-y-auto rounded-lg border border-slate-800 bg-slate-950 p-2.5 break-all text-rose-300 select-all">
                {selectedFrame.payloadSnippet || `${selectedFrame.method} ${selectedFrame.uriPath}`}
              </div>
            </div>

            <div className="flex items-center justify-between border-t border-slate-800 pt-2 font-sans">
              <button
                onClick={handleCloseInspector}
                className="rounded-lg bg-slate-800 px-3.5 py-1.5 text-xs font-bold text-slate-300 hover:bg-slate-700"
              >
                {isAr ? 'إغلاق' : 'Close'}
              </button>
              <button
                onClick={() => {
                  setManualIp(selectedFrame.clientIp);
                  setManualReason(`Attacker IP isolated following ${selectedFrame.category}`);
                  handleManualBan();
                  handleCloseInspector();
                }}
                className="flex items-center gap-1.5 rounded-lg bg-rose-600 px-3.5 py-1.5 text-xs font-bold text-white hover:bg-rose-500"
              >
                <Ban className="h-3.5 w-3.5" />
                <span>{isAr ? 'حظر IP في النواة' : 'Hard Drop IP'}</span>
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
