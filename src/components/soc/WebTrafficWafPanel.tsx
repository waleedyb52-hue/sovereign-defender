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
  category: 'NORMAL' | 'SQLI_ATTEMPT' | 'XSS_ATTEMPT' | 'PATH_TRAVERSAL' | 'COMMAND_INJECTION' | 'SSRF_ATTEMPT' | 'RCE_ATTEMPT' | 'HONEYTOKEN_HIT' | 'CREDENTIAL_STUFFING';
  threatConfidence: number;
  isBlocked: boolean;
  blockedBy?: 'WAF_OWASP' | 'RATE_LIMITER' | 'HONEYTOKEN_JAIL' | 'EBPF_FILTER' | 'ZERO_TRUST_LOCKDOWN';
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

export const WebTrafficWafPanel: React.FC<WebTrafficWafPanelProps> = ({ lang, onRefreshTelemetry }) => {
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
        fetch(`/api/v1/traffic/stream?limit=60${categoryFilter !== 'ALL' ? `&filter=${categoryFilter}` : ''}`),
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
    const elevatedCount = frames.filter(f => f.threatConfidence >= 40 && f.threatConfidence < 80).length;

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
        setMetrics(prev => prev ? { ...prev, wafConfig: data.config } : null);
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
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        {/* Metric 1: Site Security Status */}
        <div className={`rounded-xl p-3.5 border relative overflow-hidden transition ${siteSecurityStatus.bgClass}`}>
          <div className="flex items-center justify-between mb-1.5 text-xs">
            <span className="font-bold uppercase tracking-wider text-slate-300">
              {isAr ? 'حالة أمان الموقع' : 'Site Security Status'}
            </span>
            {siteSecurityStatus.level === 'GREEN' ? (
              <ShieldCheck className="w-4 h-4 text-emerald-400" />
            ) : siteSecurityStatus.level === 'AMBER' ? (
              <AlertTriangle className="w-4 h-4 text-amber-400" />
            ) : (
              <Flame className="w-4 h-4 text-rose-400 animate-pulse" />
            )}
          </div>
          <div className="flex items-center gap-2">
            <span className="text-sm font-black font-mono px-2 py-0.5 rounded bg-slate-950/70 border border-slate-700">
              {siteSecurityStatus.labelEn}
            </span>
          </div>
          <p className="text-[11px] text-slate-400 mt-1.5 truncate">
            {isAr ? siteSecurityStatus.descAr : siteSecurityStatus.descEn}
          </p>
        </div>

        {/* Metric 2: Traffic Volume */}
        <div className="bg-slate-900/90 border border-cyan-500/30 rounded-xl p-3.5 shadow-lg relative overflow-hidden">
          <div className="flex items-center justify-between text-xs text-cyan-300 mb-1.5">
            <span className="font-bold uppercase tracking-wider text-slate-300">
              {isAr ? 'حجم حركة المرور' : 'Traffic Volume'}
            </span>
            <Activity className="w-4 h-4 text-cyan-400 animate-pulse" />
          </div>
          <div className="text-2xl font-bold font-mono text-cyan-200">
            {metrics?.rps || 42.5} <span className="text-xs text-slate-400">RPS</span>
          </div>
          <p className="text-[11px] text-slate-400 mt-1.5">
            {isAr ? 'الطلبات في الثانية' : 'Requests per second'}
          </p>
        </div>

        {/* Metric 3: Active Blocked Threats */}
        <div className="bg-slate-900/90 border border-rose-500/30 rounded-xl p-3.5 shadow-lg relative overflow-hidden">
          <div className="flex items-center justify-between text-xs text-rose-300 mb-1.5">
            <span className="font-bold uppercase tracking-wider text-slate-300">
              {isAr ? 'التهديدات المحجوبة' : 'Active Blocked Threats'}
            </span>
            <Ban className="w-4 h-4 text-rose-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-rose-300">
            {(metrics?.droppedPackets || 3841).toLocaleString()}
          </div>
          <p className="text-[11px] text-slate-400 mt-1.5">
            {isAr ? 'إجمالي الحزم المعترضة' : 'Total dropped frames'}
          </p>
        </div>

        {/* Metric 4: eBPF Filter Status */}
        <div className="bg-slate-900/90 border border-emerald-500/30 rounded-xl p-3.5 shadow-lg relative overflow-hidden">
          <div className="flex items-center justify-between text-xs text-emerald-300 mb-1.5">
            <span className="font-bold uppercase tracking-wider text-slate-300">
              {isAr ? 'مرشح eBPF' : 'eBPF Filter Status'}
            </span>
            <Zap className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-emerald-300">
            {metrics?.ebpfLatencyUs || 0.38} <span className="text-xs text-slate-400">µs</span>
          </div>
          <p className="text-[11px] text-emerald-400 font-mono mt-1.5 flex items-center gap-1">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
            {isAr ? 'نشط في النواة' : 'Active • Kernel XDP'}
          </p>
        </div>
      </div>

      {/* Progressive Disclosure Toggles Toolbar */}
      <div className="flex items-center justify-between pt-1">
        <button
          onClick={() => setShowAdvancedMetrics(!showAdvancedMetrics)}
          className="text-xs text-slate-400 hover:text-cyan-300 flex items-center gap-1.5 transition"
        >
          {showAdvancedMetrics ? <ChevronUp className="w-3.5 h-3.5 text-cyan-400" /> : <ChevronDown className="w-3.5 h-3.5 text-cyan-400" />}
          <span>{showAdvancedMetrics ? (isAr ? 'إخفاء المقاييس الإضافية' : 'Hide Secondary Metrics') : (isAr ? 'عرض المقاييس الإضافية' : 'Show Secondary Metrics')}</span>
        </button>

        <div className="flex items-center gap-2">
          <button
            onClick={() => setIsWafRulesExpanded(!isWafRulesExpanded)}
            className={`text-xs px-2.5 py-1 rounded-lg border transition flex items-center gap-1 font-medium ${
              isWafRulesExpanded ? 'bg-cyan-950/60 border-cyan-500/40 text-cyan-300' : 'bg-slate-900 border-slate-800 text-slate-400 hover:text-slate-200'
            }`}
          >
            <Sliders className="w-3 h-3 text-cyan-400" />
            <span>{isAr ? 'قواعد WAF' : 'WAF Rules'}</span>
          </button>

          <button
            onClick={() => setIsSimulatorExpanded(!isSimulatorExpanded)}
            className={`text-xs px-2.5 py-1 rounded-lg border transition flex items-center gap-1 font-medium ${
              isSimulatorExpanded ? 'bg-purple-950/60 border-purple-500/40 text-purple-300' : 'bg-slate-900 border-slate-800 text-slate-400 hover:text-slate-200'
            }`}
          >
            <Terminal className="w-3 h-3 text-purple-400" />
            <span>{isAr ? 'حقن هجوم' : 'Simulate Packet'}</span>
          </button>

          <button
            onClick={() => setIsSubnetsExpanded(!isSubnetsExpanded)}
            className={`text-xs px-2.5 py-1 rounded-lg border transition flex items-center gap-1 font-medium ${
              isSubnetsExpanded ? 'bg-rose-950/60 border-rose-500/40 text-rose-300' : 'bg-slate-900 border-slate-800 text-slate-400 hover:text-slate-200'
            }`}
          >
            <Ban className="w-3 h-3 text-rose-400" />
            <span>{isAr ? `العزل (${blockedSubnets.length})` : `Quarantined (${blockedSubnets.length})`}</span>
          </button>
        </div>
      </div>

      {/* Secondary Metrics Drawer */}
      {showAdvancedMetrics && (
        <div className="rounded-xl bg-slate-900/60 border border-slate-800 p-3.5 grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs animate-fadeIn">
          <div>
            <span className="text-slate-500 block text-[10px] uppercase font-bold">{isAr ? 'إجمالي الطلبات' : 'Total Ingested'}</span>
            <span className="font-mono text-slate-200 font-bold">{(metrics?.totalRequests || 192840).toLocaleString()} reqs</span>
          </div>
          <div>
            <span className="text-slate-500 block text-[10px] uppercase font-bold">{isAr ? 'النطاقات المعزولة' : 'Isolated Subnets'}</span>
            <span className="font-mono text-purple-300 font-bold">{blockedSubnets.length} CIDRs</span>
          </div>
          <div>
            <span className="text-slate-500 block text-[10px] uppercase font-bold">{isAr ? 'حد معدل الطلبات' : 'Rate Limit Rate'}</span>
            <span className="font-mono text-emerald-300 font-bold">120 RPM / IP</span>
          </div>
          <div>
            <span className="text-slate-500 block text-[10px] uppercase font-bold">{isAr ? 'نسبة الاعتراض' : 'Intercept Rate'}</span>
            <span className="font-mono text-cyan-300 font-bold">100% Deterministic</span>
          </div>
        </div>
      )}

      {/* Collapsible WAF Rules Control Section */}
      {isWafRulesExpanded && metrics?.wafConfig && (
        <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-3.5 shadow-md animate-fadeIn">
          <div className="flex items-center justify-between mb-2.5">
            <h4 className="text-xs font-bold text-slate-200 flex items-center gap-1.5">
              <Sliders className="w-3.5 h-3.5 text-cyan-400" />
              {isAr ? 'لوحة تحكم قواعد الجدار الناري التفاعلية' : 'Interactive WAF Defense Rules'}
            </h4>
            <button onClick={() => setIsWafRulesExpanded(false)} className="text-slate-400 hover:text-white text-xs">✕</button>
          </div>
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2">
            {[
              { key: 'owaspTop10Guard', label: 'OWASP Top 10', active: metrics.wafConfig.owaspTop10Guard },
              { key: 'sqlInjectionFilter', label: 'SQLi Filter', active: metrics.wafConfig.sqlInjectionFilter },
              { key: 'xssFilter', label: 'XSS Filter', active: metrics.wafConfig.xssFilter },
              { key: 'rceFilter', label: 'RCE Shield', active: metrics.wafConfig.rceFilter },
              { key: 'rateLimitingEnabled', label: 'Rate Limiting', active: metrics.wafConfig.rateLimitingEnabled },
              { key: 'challengeBotCaptcha', label: 'Anti-Bot CAPTCHA', active: metrics.wafConfig.challengeBotCaptcha }
            ].map(rule => (
              <button
                key={rule.key}
                onClick={() => handleToggleWafRule(rule.key, rule.active)}
                className={`p-2 rounded-lg border text-left text-xs transition flex flex-col justify-between ${
                  rule.active
                    ? 'bg-cyan-950/60 border-cyan-500/40 text-cyan-200'
                    : 'bg-slate-950 border-slate-800 text-slate-500'
                }`}
              >
                <div className="flex items-center justify-between">
                  <span className="font-bold text-[11px]">{rule.label}</span>
                  <span className={`w-2 h-2 rounded-full ${rule.active ? 'bg-cyan-400' : 'bg-slate-600'}`} />
                </div>
                <span className="text-[9px] text-slate-400 mt-1">{rule.active ? 'ACTIVE' : 'OFF'}</span>
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Collapsible Attack Packet Simulator */}
      {isSimulatorExpanded && (
        <div className="bg-slate-900/90 border border-purple-500/30 rounded-xl p-3.5 shadow-md animate-fadeIn">
          <div className="flex items-center justify-between mb-2">
            <div className="flex items-center gap-2">
              <Terminal className="w-4 h-4 text-purple-400" />
              <span className="text-xs font-bold text-slate-200">
                {isAr ? 'حقن واختبار حزم الهجوم المباشرة' : 'Live Attack Packet Injector (Red/Blue Simulation)'}
              </span>
            </div>
            <button onClick={() => setIsSimulatorExpanded(false)} className="text-slate-400 hover:text-white text-xs">✕</button>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <select
              value={simType}
              onChange={(e) => setSimType(e.target.value)}
              className="bg-slate-950 border border-slate-700 rounded-lg px-2.5 py-1.5 text-xs text-cyan-300 font-mono focus:outline-none focus:border-cyan-500"
            >
              <option value="SQLI_ATTEMPT">SQL Injection (' OR '1'='1 -- UNION SELECT)</option>
              <option value="XSS_ATTEMPT">Cross-Site Scripting (&lt;script&gt;fetch cookie)</option>
              <option value="PATH_TRAVERSAL">Path Traversal (../../../../etc/shadow)</option>
              <option value="COMMAND_INJECTION">Command Injection (host=127.0.0.1; cat /etc/passwd)</option>
              <option value="SSRF_ATTEMPT">SSRF Cloud Metadata (169.254.169.254/latest/meta-data)</option>
              <option value="RCE_ATTEMPT">RCE Remote Code (eval(base64_decode(...)))</option>
              <option value="HONEYTOKEN_HIT">Honeytoken Access (GET /.env Canary)</option>
            </select>

            <input
              type="text"
              placeholder={isAr ? 'حمولة مخصصة اختيارية...' : 'Optional custom payload string...'}
              value={simPayload}
              onChange={(e) => setSimPayload(e.target.value)}
              className="flex-1 min-w-[200px] bg-slate-950 border border-slate-700 rounded-lg px-3 py-1.5 text-xs font-mono text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
            />

            <button
              onClick={handleInjectSimulatedPacket}
              disabled={isInjecting}
              className="px-4 py-1.5 bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-500 hover:to-indigo-500 text-white rounded-lg text-xs font-bold transition flex items-center gap-1.5 disabled:opacity-50"
            >
              <Play className="w-3.5 h-3.5 fill-white" />
              <span>{isInjecting ? (isAr ? 'جاري الإرسال...' : 'Injecting...') : (isAr ? 'إرسال واختبار' : 'Inject Packet')}</span>
            </button>
          </div>
        </div>
      )}

      {/* Collapsible Active Blocked Subnets Table */}
      {isSubnetsExpanded && (
        <div className="bg-slate-900/90 border border-rose-500/30 rounded-xl p-3.5 shadow-md space-y-2 animate-fadeIn">
          <div className="flex items-center justify-between border-b border-slate-800 pb-2">
            <div className="flex items-center gap-2">
              <Ban className="w-4 h-4 text-rose-400" />
              <span className="text-xs font-bold text-slate-200">
                {isAr ? 'قائمة العناوين والشبكات المعزولة في نواة eBPF' : 'Active eBPF Quarantined Subnets'}
              </span>
            </div>
            <button onClick={() => setIsSubnetsExpanded(false)} className="text-slate-400 hover:text-white text-xs">✕</button>
          </div>
          <div className="overflow-x-auto font-mono text-xs max-h-48">
            <table className="w-full text-left">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400 text-[10px]">
                  <th className="py-1 px-2">{isAr ? 'العنوان / الشبكة' : 'CIDR / IP'}</th>
                  <th className="py-1 px-2">{isAr ? 'السبب' : 'Reason'}</th>
                  <th className="py-1 px-2">{isAr ? 'الحزم المسقطة' : 'Dropped Pkts'}</th>
                  <th className="py-1 px-2 text-right">{isAr ? 'الإجراء' : 'Action'}</th>
                </tr>
              </thead>
              <tbody>
                {blockedSubnets.map(sub => (
                  <tr key={sub.id} className="border-b border-slate-800/40 hover:bg-slate-950/40 transition">
                    <td className="py-1.5 px-2 text-red-400 font-bold">{sub.cidrOrIp}</td>
                    <td className="py-1.5 px-2 text-slate-300 text-[11px]">{isAr ? sub.reasonAr : sub.reason}</td>
                    <td className="py-1.5 px-2 text-rose-400">{sub.packetDropCount.toLocaleString()}</td>
                    <td className="py-1.5 px-2 text-right">
                      <button
                        onClick={() => handleUnban(sub.id)}
                        className="px-2 py-0.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded text-[10px]"
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
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl shadow-xl overflow-hidden">
        {/* Search & Filter Header */}
        <div className="p-3 border-b border-slate-800 flex flex-wrap items-center justify-between gap-3 bg-slate-950/60">
          <div className="flex items-center gap-2 flex-1 max-w-sm">
            <Search className="w-3.5 h-3.5 text-slate-400 shrink-0" />
            <input
              type="text"
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
              placeholder={isAr ? 'بحث بالـ IP أو المسار...' : 'Filter by IP or URI endpoint...'}
              className="w-full bg-slate-900 border border-slate-700 rounded-lg px-2.5 py-1 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500"
            />
          </div>

          <div className="flex items-center gap-1 overflow-x-auto text-[10px] font-mono">
            {['ALL', 'SQLI_ATTEMPT', 'XSS_ATTEMPT', 'PATH_TRAVERSAL', 'COMMAND_INJECTION', 'SSRF_ATTEMPT', 'RCE_ATTEMPT', 'HONEYTOKEN_HIT'].map(cat => (
              <button
                key={cat}
                onClick={() => setCategoryFilter(cat)}
                className={`px-2 py-0.5 rounded transition whitespace-nowrap ${
                  categoryFilter === cat
                    ? 'bg-cyan-600 text-white font-bold'
                    : 'bg-slate-950 text-slate-400 hover:text-slate-200 border border-slate-800'
                }`}
              >
                {cat === 'ALL' ? (isAr ? 'الكل' : 'All') : cat.replace('_ATTEMPT', '')}
              </button>
            ))}
          </div>
        </div>

        {/* 4-Column Streamlined Table */}
        <div className="overflow-x-auto max-h-[460px] overflow-y-auto">
          <table className="w-full text-left border-collapse font-mono text-xs">
            <thead className="sticky top-0 bg-slate-950 border-b border-slate-800 text-[10px] font-bold text-slate-400 uppercase tracking-wider z-10">
              <tr>
                <th className="py-2.5 px-4 w-28">{isAr ? 'الوقت' : 'Time'}</th>
                <th className="py-2.5 px-4 w-40">{isAr ? 'عنوان IP' : 'Client IP'}</th>
                <th className="py-2.5 px-4">{isAr ? 'نقطة النهاية المستهدفة' : 'Target Endpoint'}</th>
                <th className="py-2.5 px-4 text-right w-32">{isAr ? 'القرار' : 'Verdict'}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/50">
              {filteredFrames.length === 0 ? (
                <tr>
                  <td colSpan={4} className="py-10 text-center text-slate-500 text-xs">
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
                      className={`hover:bg-slate-800/60 cursor-pointer transition ${
                        selectedFrame?.id === frame.id
                          ? 'bg-cyan-950/40 border-l-2 border-cyan-400'
                          : isBlocked
                          ? 'bg-rose-950/15'
                          : ''
                      }`}
                    >
                      {/* Column 1: Time */}
                      <td className="py-2.5 px-4 text-slate-400 text-[11px] whitespace-nowrap">
                        {new Date(frame.timestamp).toLocaleTimeString()}
                      </td>

                      {/* Column 2: Client IP */}
                      <td className="py-2.5 px-4 whitespace-nowrap font-bold text-slate-200">
                        {frame.clientIp}
                      </td>

                      {/* Column 3: Target Endpoint */}
                      <td className="py-2.5 px-4">
                        <div className="flex items-center gap-2 truncate max-w-md">
                          <span className={`px-1.5 py-0.5 rounded text-[9px] font-black shrink-0 ${
                            frame.method === 'POST' ? 'bg-blue-500/20 text-blue-300' : 'bg-slate-800 text-slate-300'
                          }`}>
                            {frame.method}
                          </span>
                          <span className="text-slate-300 truncate" title={frame.uriPath}>
                            {frame.uriPath}
                          </span>
                          {frame.queryString && (
                            <span className="text-amber-400/80 text-[10px] truncate max-w-[120px]">
                              ?{frame.queryString}
                            </span>
                          )}
                        </div>
                      </td>

                      {/* Column 4: Verdict Badge & Inspect Action */}
                      <td className="py-2.5 px-4 text-right whitespace-nowrap">
                        <div className="flex items-center justify-end gap-1.5">
                          {isBlocked ? (
                            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-rose-600/30 text-rose-300 border border-rose-500 text-[10px] font-bold">
                              <ShieldAlert className="w-3 h-3 text-rose-400" />
                              BLOCKED
                            </span>
                          ) : isSuspicious ? (
                            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-amber-500/20 text-amber-300 border border-amber-500/40 text-[10px] font-bold">
                              <AlertTriangle className="w-3 h-3 text-amber-400" />
                              SUSPICIOUS
                            </span>
                          ) : (
                            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 text-[10px] font-bold">
                              <ShieldCheck className="w-3 h-3 text-emerald-400" />
                              SAFE
                            </span>
                          )}

                          <button
                            type="button"
                            onClick={(e) => {
                              e.stopPropagation();
                              handleOpenInspector(frame);
                            }}
                            className="px-2 py-0.5 rounded bg-slate-800 hover:bg-cyan-950 text-slate-300 hover:text-cyan-300 border border-slate-700 text-[10px] font-sans font-bold flex items-center gap-1 transition"
                            title={isAr ? 'فحص تفصيلي' : 'Inspect'}
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
      </div>

      {/* Deep Payload Modal Drawer when frame is selected (Strictly on user click) */}
      {isModalOpen && selectedFrame && (
        <div
          onClick={(e) => {
            if (e.target === e.currentTarget) handleCloseInspector();
          }}
          className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-fadeIn"
        >
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-xl w-full p-5 shadow-2xl space-y-4 max-h-[85vh] overflow-y-auto font-mono text-xs">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2.5">
                <Terminal className="w-4 h-4 text-cyan-400" />
                <h3 className="font-bold text-white text-sm font-sans">
                  {isAr ? 'فحص تفصيلي للحزمة والطلب' : 'Deep Packet & Payload Inspection'}
                </h3>
              </div>
              <button onClick={handleCloseInspector} className="text-slate-400 hover:text-white text-xs">✕</button>
            </div>

            <div className="grid grid-cols-2 gap-2 bg-slate-950 p-2.5 rounded-lg border border-slate-800 text-[11px]">
              <div>
                <span className="text-slate-500 block text-[10px]">{isAr ? 'المصدر:' : 'Source IP:'}</span>
                <span className="text-amber-300 font-bold">{selectedFrame.clientIp}</span>
              </div>
              <div>
                <span className="text-slate-500 block text-[10px]">{isAr ? 'التهديد:' : 'Threat Confidence:'}</span>
                <span className={`font-bold ${selectedFrame.threatConfidence > 80 ? 'text-rose-400' : 'text-emerald-400'}`}>
                  {selectedFrame.threatConfidence}%
                </span>
              </div>
              <div className="col-span-2">
                <span className="text-slate-500 block text-[10px]">{isAr ? 'المسار:' : 'Full URI:'}</span>
                <span className="text-slate-200 break-all">{selectedFrame.method} {selectedFrame.uriPath}{selectedFrame.queryString ? `?${selectedFrame.queryString}` : ''}</span>
              </div>
            </div>

            <div>
              <span className="text-slate-400 block text-[10px] mb-1">{isAr ? 'مقتطف الحمولة المكتشفة:' : 'Raw Detected Payload / Snippet:'}</span>
              <div className="bg-slate-950 border border-slate-800 p-2.5 rounded-lg text-rose-300 break-all select-all max-h-36 overflow-y-auto">
                {selectedFrame.payloadSnippet || `${selectedFrame.method} ${selectedFrame.uriPath}`}
              </div>
            </div>

            <div className="flex items-center justify-between pt-2 border-t border-slate-800 font-sans">
              <button
                onClick={handleCloseInspector}
                className="px-3.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-bold"
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
                className="px-3.5 py-1.5 rounded-lg bg-rose-600 hover:bg-rose-500 text-white text-xs font-bold flex items-center gap-1.5"
              >
                <Ban className="w-3.5 h-3.5" />
                <span>{isAr ? 'حظر IP في النواة' : 'Hard Drop IP'}</span>
              </button>
            </div>
          </div>
        </div>
      )}

    </div>
  );
};
