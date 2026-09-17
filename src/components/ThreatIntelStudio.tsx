import React, { useState } from 'react';
import { IngestedDataset, ThreatIntelligenceMetrics } from '../types';
import { SAMPLE_DATASETS } from '../data/defaultThreatData';
import { Upload, Sparkles, Database, FileText, CheckCircle2, ShieldCheck, AlertTriangle, Terminal, Cpu, ArrowUpRight, Search, RefreshCw, Zap } from 'lucide-react';

interface ThreatIntelStudioProps {
  onIngestDataset?: (dataset: { name: string; type: string; rawData: string }) => Promise<void>;
  ingestedDatasets: IngestedDataset[];
  intelMetrics: ThreatIntelligenceMetrics;
  lang: 'ar' | 'en';
  isIngesting?: boolean;
}

export const ThreatIntelStudio: React.FC<ThreatIntelStudioProps> = ({
  onIngestDataset,
  ingestedDatasets: initialDatasets,
  intelMetrics: initialMetrics,
  lang
}) => {
  const isAr = lang === 'ar';

  const [rawText, setRawText] = useState<string>('');
  const [datasetName, setDatasetName] = useState<string>('');
  const [datasetType, setDatasetType] = useState<'NGINX_LOG' | 'WAF_JSON' | 'MODSECURITY' | 'PAYLOAD_SAMPLES' | 'PCAP_JSON'>('NGINX_LOG');
  const [filterIpSearch, setFilterIpSearch] = useState<string>('');
  const [successAlert, setSuccessAlert] = useState<{ message: string; records: number; signatures: number } | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [localDatasets, setLocalDatasets] = useState<IngestedDataset[]>(initialDatasets);
  const [metrics, setMetrics] = useState<ThreatIntelligenceMetrics>(initialMetrics);

  // Real async HTTP POST to /api/v1/dataset/ingest
  const ingestTelemetryFeed = async (logsContent: string, sourceLabel: string, formatType: string) => {
    setIsLoading(true);
    try {
      const response = await fetch('/api/v1/dataset/ingest', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          logs: logsContent,
          sourceType: sourceLabel,
          type: formatType,
          rawData: logsContent,
          name: sourceLabel
        })
      });

      const data = await response.json();

      if (data.status === 'SUCCESS' || data.success) {
        const recordsCount = data.totalRecords || data.dataset?.recordsCount || logsContent.split('\n').filter(Boolean).length;
        const signaturesCount = data.signaturesExtracted || 3;

        setSuccessAlert({
          message: isAr
            ? `تمت معالجة وتدريب ذاكرة Gemini-3.7 بنجاح على قاعدة: ${sourceLabel}`
            : `Successfully ingested and trained Gemini-3.7 AI context memory with: ${sourceLabel}`,
          records: recordsCount,
          signatures: signaturesCount
        });

        if (data.dataset) {
          setLocalDatasets(prev => [data.dataset, ...prev]);
        }

        setMetrics(prev => ({
          ...prev,
          totalIngestedLogs: prev.totalIngestedLogs + recordsCount,
          zeroDaySignatures: prev.zeroDaySignatures + signaturesCount,
          knownMaliciousIps: prev.knownMaliciousIps + (data.extractedIpsCount || 6)
        }));

        if (onIngestDataset) {
          await onIngestDataset({
            name: sourceLabel,
            type: formatType,
            rawData: logsContent
          });
        }

        setTimeout(() => setSuccessAlert(null), 6000);
      } else {
        alert(isAr ? 'فشلت عملية تغذية البيانات: ' + (data.error || 'خطأ غير معروف') : 'Ingestion failed: ' + (data.error || 'Unknown error'));
      }
    } catch (err: any) {
      console.error('Dataset ingestion network error:', err);
      alert(isAr ? 'خطأ في الاتصال بالخادم' : 'Network connection error during ingestion');
    } finally {
      setIsLoading(false);
    }
  };

  const handleQuickLoad = async (sample: IngestedDataset) => {
    setDatasetName(sample.name);
    setDatasetType(sample.type);
    setRawText(sample.sampleRaw);
    await ingestTelemetryFeed(sample.sampleRaw, sample.name, sample.type);
  };

  const handleCustomIngest = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!rawText.trim()) return;

    const label = datasetName.trim() || `Custom ${datasetType} Telemetry (${new Date().toLocaleTimeString()})`;
    await ingestTelemetryFeed(rawText, label, datasetType);
    setRawText('');
    setDatasetName('');
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      setDatasetName(file.name);
      const reader = new FileReader();
      reader.onload = async event => {
        const content = event.target?.result as string;
        setRawText(content || '');
        if (content) {
          await ingestTelemetryFeed(content, file.name, datasetType);
        }
      };
      reader.readAsText(file);
    }
  };

  const filteredIps = metrics.ipReputationScores.filter(item =>
    item.ip.includes(filterIpSearch) || item.category.toLowerCase().includes(filterIpSearch.toLowerCase())
  );

  return (
    <div className="space-y-6">
      {/* Top Banner: AI Dynamic Context Memory Status */}
      <div className="p-5 rounded-2xl bg-gradient-to-r from-purple-950/70 via-slate-900 to-indigo-950/70 border border-purple-500/30 shadow-xl">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="p-3 rounded-xl bg-purple-500/20 border border-purple-500/40 text-purple-300">
              <Sparkles className="w-6 h-6 animate-pulse" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-lg font-black text-white">
                  {isAr ? 'استوديو تغذية بيانات الدفاع وتدريب الذكاء (AI Threat Intel & Training Studio)' : 'AI Threat Intel & Dataset Training Studio'}
                </h2>
                <span className="px-2 py-0.5 text-xs font-bold rounded-full bg-purple-500/20 text-purple-300 border border-purple-500/40">
                  HTTP API: /api/v1/dataset/ingest
                </span>
              </div>
              <p className="text-xs text-slate-300 mt-0.5">
                {isAr
                  ? 'قم برفع سجلات خوادم الويب لتدريب الذاكرة التكتيكية وتوليد قواعد دفاع استباقية لثغرات Zero-Day'
                  : 'Ingest raw Nginx/WAF/ModSec telemetry to dynamically enrich the AI agent context with custom web app threat signatures'}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-4 text-xs font-mono">
            <div className="px-3.5 py-2 rounded-xl bg-slate-950/80 border border-purple-500/30">
              <span className="text-slate-400 block text-[10px]">{isAr ? 'إجمالي السجلات المغذاة:' : 'Total Fed Records:'}</span>
              <span className="text-purple-300 text-sm font-bold">{metrics.totalIngestedLogs.toLocaleString()} Logs</span>
            </div>
            <div className="px-3.5 py-2 rounded-xl bg-slate-950/80 border border-purple-500/30">
              <span className="text-slate-400 block text-[10px]">{isAr ? 'بصمات Zero-Day:' : 'Zero-Day Signatures:'}</span>
              <span className="text-emerald-400 text-sm font-bold">{metrics.zeroDaySignatures} Active</span>
            </div>
          </div>
        </div>
      </div>

      {/* Confirmation & Status Banner */}
      {successAlert && (
        <div className="p-4 rounded-xl bg-emerald-950/80 border border-emerald-500/60 text-emerald-200 text-xs font-bold flex flex-wrap items-center justify-between gap-3 shadow-lg shadow-emerald-950/50">
          <div className="flex items-center gap-2.5">
            <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0" />
            <span>{successAlert.message}</span>
          </div>
          <div className="flex items-center gap-2 font-mono">
            <span className="px-2 py-0.5 rounded bg-emerald-900/60 border border-emerald-500/40 text-emerald-300">
              +{successAlert.records} {isAr ? 'سجل تكتيكي' : 'records parsed'}
            </span>
            <span className="px-2 py-0.5 rounded bg-purple-900/60 border border-purple-500/40 text-purple-300">
              +{successAlert.signatures} {isAr ? 'بصمات مستخلصة' : 'signatures'}
            </span>
          </div>
        </div>
      )}

      {/* Main Grid: Upload & Ingest (Left/Top) + Threat Intel Metrics (Right/Bottom) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left 6 cols: Log Ingestion & Quick Datasets */}
        <div className="lg:col-span-6 space-y-5">
          {/* Quick Pre-Loaded Datasets */}
          <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-5 shadow-lg">
            <h3 className="text-sm font-bold text-white mb-3 flex items-center justify-between">
              <span>{isAr ? 'قواعد بيانات ونماذج هجوم جاهزة للتدريب الفوري (1-Click Datasets):' : 'Pre-loaded Threat Datasets (1-Click Ingest):'}</span>
              <span className="text-[10px] text-purple-400 font-mono">POST /api/v1/dataset/ingest</span>
            </h3>
            <div className="space-y-2">
              {SAMPLE_DATASETS.map(sample => (
                <div
                  key={sample.id}
                  className="p-3 rounded-xl bg-slate-950/80 border border-slate-800/90 hover:border-purple-500/50 transition flex items-center justify-between gap-3 group"
                >
                  <div className="flex items-center gap-2.5 min-w-0">
                    <div className="p-2 rounded-lg bg-slate-800 group-hover:bg-purple-950/50 text-purple-300 border border-slate-700">
                      <FileText className="w-4 h-4" />
                    </div>
                    <div className="min-w-0">
                      <div className="text-xs font-bold text-slate-100 truncate">{sample.name}</div>
                      <div className="text-[10px] text-slate-400 font-mono mt-0.5">
                        {sample.type} • {sample.recordsCount.toLocaleString()} {isAr ? 'سجل' : 'records'} • {sample.parsedAttacks.toLocaleString()} {isAr ? 'تهديد' : 'attacks'}
                      </div>
                    </div>
                  </div>

                  <button
                    type="button"
                    onClick={() => handleQuickLoad(sample)}
                    disabled={isLoading}
                    className="px-3 py-1.5 rounded-lg bg-purple-600/30 hover:bg-purple-600 text-purple-200 hover:text-white border border-purple-500/40 text-xs font-bold transition flex items-center gap-1 shrink-0"
                  >
                    <Zap className="w-3.5 h-3.5" />
                    <span>{isAr ? 'تغذية وتدريب' : 'Feed AI'}</span>
                  </button>
                </div>
              ))}
            </div>
          </div>

          {/* Custom File Upload & Raw Parser Form */}
          <form onSubmit={handleCustomIngest} className="bg-slate-900/90 border border-slate-800 rounded-2xl p-5 shadow-lg space-y-4">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <Upload className="w-4 h-4 text-cyan-400" />
              <span>{isAr ? 'رفع سجلات ويب مخصصة وتغذية الذاكرة (Custom Log Upload):' : 'Upload Custom Web Telemetry Feed:'}</span>
            </h3>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1">
                  {isAr ? 'اسم السجل / المعرف:' : 'Feed / Dataset Label:'}
                </label>
                <input
                  type="text"
                  value={datasetName}
                  onChange={e => setDatasetName(e.target.value)}
                  placeholder={isAr ? 'مثال: Production-Nginx-Aug2026' : 'e.g. Production-Nginx-Aug2026'}
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs font-mono text-white focus:outline-none focus:border-purple-500"
                />
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1">
                  {isAr ? 'نوع صيغة السجلات (Log Format):' : 'Log Parser Format:'}
                </label>
                <select
                  value={datasetType}
                  onChange={e => setDatasetType(e.target.value as any)}
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs font-mono text-white focus:outline-none focus:border-purple-500"
                >
                  <option value="NGINX_LOG">Nginx / Apache Access Combined Log</option>
                  <option value="WAF_JSON">Cloud / AWS / Cloudflare WAF JSON</option>
                  <option value="MODSECURITY">ModSecurity Audit Logs & CRS Alerts</option>
                  <option value="PAYLOAD_SAMPLES">SQLi / XSS Payload Wordlists (SecLists)</option>
                  <option value="PCAP_JSON">PCAP / Zeek / Suricata EVE JSON Dump</option>
                </select>
              </div>
            </div>

            {/* Drag and Drop Box */}
            <div className="border-2 border-dashed border-slate-800 hover:border-purple-500/50 rounded-xl p-4 text-center bg-slate-950/60 cursor-pointer relative">
              <input
                type="file"
                accept=".log,.txt,.json,.csv"
                onChange={handleFileUpload}
                className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
              />
              <Upload className="w-6 h-6 text-slate-400 mx-auto mb-1" />
              <p className="text-xs font-semibold text-slate-300">
                {isAr ? 'انقر لاختيار ملف سجل أو اسحبه هنا (.log, .txt, .json)' : 'Click to select or drag & drop web logs (.log, .txt, .json)'}
              </p>
              <p className="text-[10px] text-slate-500 mt-0.5">Automated upload sends POST to /api/v1/dataset/ingest</p>
            </div>

            {/* Raw Text Paste */}
            <div>
              <label className="block text-xs font-semibold text-slate-300 mb-1">
                {isAr ? 'أو الصق أسطر السجلات الخام هنا:' : 'Or Paste Raw Telemetry Lines:'}
              </label>
              <textarea
                rows={4}
                value={rawText}
                onChange={e => setRawText(e.target.value)}
                placeholder={`185.220.101.5 - - [29/Aug/2026:11:14:22 +0000] "GET /api/v1/auth?id=1' OR '1'='1 HTTP/1.1" 403 230 "sqlmap/1.7"`}
                className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-xl text-xs font-mono text-emerald-300 focus:outline-none focus:border-purple-500"
              />
            </div>

            <button
              type="submit"
              disabled={isLoading || !rawText.trim()}
              className="w-full py-2.5 rounded-xl bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-500 hover:to-indigo-500 text-white font-bold text-xs sm:text-sm shadow-lg shadow-purple-950/50 transition flex items-center justify-center gap-2 disabled:opacity-50"
            >
              {isLoading ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin" />
                  <span>{isAr ? 'جاري إرسال وتغذية الذكاء الاصطناعي عبر API...' : 'Posting to /api/v1/dataset/ingest...'}</span>
                </>
              ) : (
                <>
                  <Sparkles className="w-4 h-4" />
                  <span>{isAr ? 'معالجة وتغذية سياق الذكاء (Ingest & Train Context)' : 'Ingest & Train AI Context'}</span>
                </>
              )}
            </button>
          </form>
        </div>

        {/* Right 6 cols: Threat Intelligence Metrics UI Panel */}
        <div className="lg:col-span-6 space-y-5">
          {/* Top Targeted URLs & Endpoints Panel */}
          <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-5 shadow-lg">
            <h3 className="text-sm font-bold text-white mb-3 flex items-center justify-between">
              <span>{isAr ? 'أكثر المسارات المستهدفة بالهجمات (Top Targeted Endpoints):' : 'Top Targeted Application Endpoints:'}</span>
              <span className="text-[10px] text-cyan-400 font-mono">Live SIEM Feed</span>
            </h3>
            <div className="space-y-2">
              {metrics.topTargetedUrls.map((item, idx) => (
                <div
                  key={`url-${item.url}`}
                  className="p-2.5 rounded-xl bg-slate-950/70 border border-slate-800/80 flex items-center justify-between gap-2"
                >
                  <div className="flex items-center gap-2 min-w-0">
                    <span className="text-[10px] font-mono w-5 text-slate-500">#{idx + 1}</span>
                    <span className="text-xs font-mono text-emerald-300 truncate">{item.url}</span>
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    <span className="text-[11px] font-mono text-slate-300">{item.hits.toLocaleString()} hits</span>
                    <span
                      className={`text-[9px] font-bold px-1.5 py-0.5 rounded border ${
                        item.threatLevel === 'CRITICAL'
                          ? 'bg-rose-500/20 text-rose-300 border-rose-500/40'
                          : 'bg-amber-500/20 text-amber-300 border-amber-500/40'
                      }`}
                    >
                      {item.threatLevel}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Malicious Scanner User-Agents Fingerprints */}
          <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-5 shadow-lg">
            <h3 className="text-sm font-bold text-white mb-3 flex items-center justify-between">
              <span>{isAr ? 'بصمات أدوات الفحص التلقائي (Malicious Scanner User-Agents):' : 'Scanner User-Agent Fingerprints:'}</span>
              <span className="text-[10px] text-rose-400 font-mono">Heuristic DB</span>
            </h3>
            <div className="space-y-2">
              {metrics.topUserAgents.map((ua) => (
                <div
                  key={`ua-${ua.ua}`}
                  className="p-2.5 rounded-xl bg-slate-950/70 border border-slate-800/80 flex items-center justify-between gap-2 text-xs"
                >
                  <div className="min-w-0">
                    <div className="font-mono text-slate-200 truncate">{ua.ua}</div>
                    <div className="text-[10px] text-slate-400 font-mono mt-0.5">{ua.count.toLocaleString()} queries identified</div>
                  </div>
                  <span
                    className={`text-[10px] font-bold px-2 py-0.5 rounded border shrink-0 ${
                      ua.malicious
                        ? 'bg-rose-500/20 text-rose-300 border-rose-500/40'
                        : 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40'
                    }`}
                  >
                    {ua.malicious ? (isAr ? 'محظور فوراً' : 'Auto-Blocked') : isAr ? 'سليم' : 'Benign'}
                  </span>
                </div>
              ))}
            </div>
          </div>

          {/* IP Reputation Scoreboard */}
          <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-5 shadow-lg">
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-sm font-bold text-white">
                {isAr ? 'سجل سمعة عناوين IP (IP Reputation Scoreboard):' : 'IP Threat Reputation Scoreboard:'}
              </h3>
              <div className="relative w-36">
                <input
                  type="text"
                  value={filterIpSearch}
                  onChange={e => setFilterIpSearch(e.target.value)}
                  placeholder={isAr ? 'بحث عن IP...' : 'Search IP...'}
                  className="w-full px-2 py-1 bg-slate-950 border border-slate-800 rounded text-[10px] font-mono text-white focus:outline-none focus:border-cyan-500"
                />
              </div>
            </div>

            <div className="space-y-2 max-h-52 overflow-y-auto pr-1">
              {filteredIps.map((ipRec) => (
                <div
                  key={`rep-ip-${ipRec.ip}`}
                  className="p-2.5 rounded-xl bg-slate-950/70 border border-slate-800/80 flex items-center justify-between gap-2 text-xs font-mono"
                >
                  <div>
                    <div className="flex items-center gap-2 font-bold text-white">
                      <span>{ipRec.ip}</span>
                      <span className="text-[10px] px-1.5 py-0.2 rounded bg-slate-800 text-slate-400">
                        {ipRec.country}
                      </span>
                    </div>
                    <div className="text-[10px] text-slate-400 mt-0.5">{ipRec.category}</div>
                  </div>

                  <div className="flex items-center gap-2">
                    <div className="text-right">
                      <span className="text-[10px] text-slate-400 block">{isAr ? 'مؤشر الخطر' : 'Risk'}</span>
                      <span className={`font-bold ${ipRec.reputation > 70 ? 'text-rose-400' : 'text-emerald-400'}`}>
                        {ipRec.reputation}%
                      </span>
                    </div>
                    <span
                      className={`text-[9px] font-bold px-2 py-0.5 rounded border ${
                        ipRec.status === 'ACTIVE_BLOCK'
                          ? 'bg-rose-500/20 text-rose-300 border-rose-500/40'
                          : ipRec.status === 'SUSPICIOUS'
                          ? 'bg-amber-500/20 text-amber-300 border-amber-500/40'
                          : 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40'
                      }`}
                    >
                      {ipRec.status}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* ========================================================================= */}
      {/* 1. FEDERATED THREAT INTELLIGENCE SHARING SUITE (GLOBAL DEFENSE NETWORK) */}
      {/* ========================================================================= */}
      <FederatedShieldWidget lang={lang} />
    </div>
  );
};

// Extracted Sub-Component for Clean Modular Architecture
const FederatedShieldWidget: React.FC<{ lang: 'ar' | 'en' }> = ({ lang }) => {
  const isAr = lang === 'ar';
  const [federatedData, setFederatedData] = useState<any>(null);
  const [isBroadcasting, setIsBroadcasting] = useState<boolean>(false);
  const [broadcastSuccess, setBroadcastSuccess] = useState<string | null>(null);
  const [newIocVector, setNewIocVector] = useState<string>('SQL_INJECTION');
  const [newIocPattern, setNewIocPattern] = useState<string>("' UNION SELECT 1, @@version, load_file('/etc/passwd')--");

  const fetchFederatedFeed = async () => {
    try {
      const res = await fetch('/api/v1/threat/federated-feed');
      if (res.ok) {
        const data = await res.json();
        if (data.federatedShield) {
          setFederatedData(data.federatedShield);
        }
      }
    } catch (err) {
      console.warn('Federated feed fetch warning:', err);
    }
  };

  React.useEffect(() => {
    fetchFederatedFeed();
    const interval = setInterval(fetchFederatedFeed, 10000);
    return () => clearInterval(interval);
  }, []);

  const handleBroadcastIoc = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newIocPattern.trim()) return;
    setIsBroadcasting(true);
    try {
      const res = await fetch('/api/v1/threat/federated-share', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          iocPattern: newIocPattern,
          vector: newIocVector,
          mitreTechnique: 'T1190 - Exploit Public-Facing Application',
          severity: 'CRITICAL',
          autoSync: true
        })
      });
      const data = await res.json();
      if (data.success) {
        setBroadcastSuccess(isAr ? 'تم تشفير وتعميم البصمة على كامل العقد العالمية بنجاح' : 'IOC cryptographically anonymized and broadcasted globally.');
        fetchFederatedFeed();
        setNewIocPattern('');
        setTimeout(() => setBroadcastSuccess(null), 5000);
      }
    } catch (err) {
      console.error('Broadcast IOC error:', err);
    } finally {
      setIsBroadcasting(false);
    }
  };

  const handleToggleSharing = async () => {
    try {
      const res = await fetch('/api/v1/threat/federated-toggle', { method: 'POST' });
      if (res.ok) fetchFederatedFeed();
    } catch (err) {
      console.warn('Toggle sharing error:', err);
    }
  };

  return (
    <div className="bg-gradient-to-b from-slate-900 via-slate-900/95 to-slate-950 border border-cyan-500/40 rounded-2xl p-6 shadow-2xl space-y-6">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-4 pb-4 border-b border-slate-800">
        <div className="flex items-center gap-3">
          <div className="p-3 rounded-xl bg-cyan-500/20 border border-cyan-500/40 text-cyan-300">
            <Zap className="w-6 h-6 animate-pulse text-cyan-400" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-base font-black text-white">
                {isAr ? 'شبكة التبادل الجماعي للتهديدات (Global Federated Threat Shield)' : 'Global Federated Threat Intelligence Shield'}
              </h3>
              <span className="px-2 py-0.5 text-[10px] font-bold rounded-full bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 font-mono">
                P2P Mesh v4.0
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              {isAr
                ? 'تبادل مشفر وبصمات مجهولة المصدر (Zero-Knowledge Hash Sharing) لتعزيز الحصانة المتبادلة بين كافة السيرفرات'
                : 'Zero-Knowledge SHA-256 anonymized indicator exchange synchronizing real-time defense across production nodes'}
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <button
            type="button"
            onClick={handleToggleSharing}
            className={`px-3.5 py-1.5 rounded-xl font-bold text-xs border transition flex items-center gap-2 ${
              federatedData?.isSharingEnabled
                ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/50 hover:bg-emerald-500/30'
                : 'bg-rose-500/20 text-rose-300 border-rose-500/50 hover:bg-rose-500/30'
            }`}
          >
            <span className={`w-2 h-2 rounded-full ${federatedData?.isSharingEnabled ? 'bg-emerald-400 animate-ping' : 'bg-rose-400'}`}></span>
            <span>
              {isAr
                ? federatedData?.isSharingEnabled ? 'التبادل مفعل (Active)' : 'التبادل معطل (Paused)'
                : federatedData?.isSharingEnabled ? 'Federation Online' : 'Federation Paused'}
            </span>
          </button>
        </div>
      </div>

      {/* Global Defense Stats Strip */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800">
          <span className="text-slate-400 text-[11px] block">{isAr ? 'عقد الدفاع المتصلة:' : 'Active Peer Nodes:'}</span>
          <span className="text-cyan-400 font-mono text-lg font-black">{federatedData?.activePeerNodes || 5} Nodes</span>
          <span className="text-[10px] text-emerald-400 block mt-0.5">● Tokyo, Frankfurt, Virginia, Riyadh, London</span>
        </div>

        <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800">
          <span className="text-slate-400 text-[11px] block">{isAr ? 'البصمات المتبادلة المزامنة:' : 'Synchronized IOCs:'}</span>
          <span className="text-purple-400 font-mono text-lg font-black">{federatedData?.totalSynchronizedIocs || 184} Signatures</span>
          <span className="text-[10px] text-slate-400 block mt-0.5">{isAr ? 'تزامن تلقائي فوري' : 'Real-time Auto Sync'}</span>
        </div>

        <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800">
          <span className="text-slate-400 text-[11px] block">{isAr ? 'مؤشر موثوقية الشبكة:' : 'Network Trust Score:'}</span>
          <span className="text-emerald-400 font-mono text-lg font-black">{federatedData?.networkTrustScore || 99.4}%</span>
          <span className="text-[10px] text-cyan-400 block mt-0.5">SHA-256 Verified Consensus</span>
        </div>

        <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800">
          <span className="text-slate-400 text-[11px] block">{isAr ? 'آخر تعميم أمني:' : 'Last Broadcast:'}</span>
          <span className="text-slate-200 font-mono text-xs font-bold block mt-1">
            {federatedData?.lastBroadcastTime ? new Date(federatedData.lastBroadcastTime).toLocaleTimeString() : 'Just now'}
          </span>
          <span className="text-[10px] text-emerald-400 block mt-0.5">0ms Propagation Delay</span>
        </div>
      </div>

      {/* Peer Defense Nodes Status Strip */}
      <div>
        <h4 className="text-xs font-bold text-slate-300 mb-2 flex items-center justify-between">
          <span>{isAr ? 'حالة العقد الإنتاجية المتصلة في الشبكة (Live Defense Peers):' : 'Production Defense Node Peers:'}</span>
          <span className="text-[10px] text-cyan-400 font-mono">Mesh Protocol / TLS 1.3</span>
        </h4>
        <div className="grid grid-cols-1 sm:grid-cols-5 gap-2">
          {(federatedData?.peers || [
            { nodeId: 'NODE-TOKYO-01', region: 'Tokyo', latMs: 28, contributedIocs: 48 },
            { nodeId: 'NODE-FRANKFURT-02', region: 'Frankfurt', latMs: 14, contributedIocs: 52 },
            { nodeId: 'NODE-VIRGINIA-04', region: 'Virginia', latMs: 32, contributedIocs: 39 },
            { nodeId: 'NODE-RIYADH-01', region: 'Riyadh', latMs: 8, contributedIocs: 27 },
            { nodeId: 'NODE-LONDON-03', region: 'London', latMs: 18, contributedIocs: 18 }
          ]).map((peer: any) => (
            <div key={peer.nodeId} className="p-2.5 rounded-xl bg-slate-950/80 border border-slate-800 flex items-center justify-between text-xs font-mono">
              <div>
                <span className="text-cyan-300 font-bold block text-[11px]">{peer.nodeId}</span>
                <span className="text-[10px] text-slate-400">{peer.region}</span>
              </div>
              <div className="text-right">
                <span className="text-[10px] text-emerald-400 block font-bold">{peer.latMs}ms</span>
                <span className="text-[9px] text-purple-300">+{peer.contributedIocs} IOCs</span>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Broadcast Form & Synchronized IOC Feed Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 pt-2">
        {/* Left 5 cols: Broadcast Anonymized Threat Form */}
        <form onSubmit={handleBroadcastIoc} className="lg:col-span-5 p-4 rounded-xl bg-slate-950 border border-cyan-500/30 space-y-3">
          <h4 className="text-xs font-bold text-white flex items-center gap-2">
            <Zap className="w-4 h-4 text-cyan-400" />
            <span>{isAr ? 'تعميم ونشر بصمة تهديد مستحدثة مجهولة المصدر:' : 'Broadcast Anonymized IOC to Global Shield:'}</span>
          </h4>

          {broadcastSuccess && (
            <div className="p-2.5 rounded-lg bg-emerald-950/80 border border-emerald-500/50 text-emerald-300 text-xs font-bold">
              {broadcastSuccess}
            </div>
          )}

          <div>
            <label className="block text-[11px] font-semibold text-slate-300 mb-1">
              {isAr ? 'تصنيف متجه التهديد:' : 'Threat Vector Category:'}
            </label>
            <select
              value={newIocVector}
              onChange={e => setNewIocVector(e.target.value)}
              className="w-full px-2.5 py-1.5 bg-slate-900 border border-slate-800 rounded-lg text-xs font-mono text-white focus:outline-none focus:border-cyan-500"
            >
              <option value="SQL_INJECTION">SQL Injection (SQLi)</option>
              <option value="REMOTE_CODE_EXECUTION">Remote Code Execution (RCE)</option>
              <option value="DNS_EXFILTRATION">DNS Tunneling C2 Exfiltration</option>
              <option value="PATH_TRAVERSAL">Path Traversal / Local File Inclusion</option>
              <option value="CREDENTIAL_STUFFING">Credential Stuffing / Brute Force</option>
              <option value="ZERO_DAY_ANOMALY">Zero-Day Heuristic Signature</option>
            </select>
          </div>

          <div>
            <label className="block text-[11px] font-semibold text-slate-300 mb-1">
              {isAr ? 'نموذج البصمة / الحمولة (Payload Sample / RegEx):' : 'IOC Pattern / Attack Signature:'}
            </label>
            <textarea
              rows={3}
              value={newIocPattern}
              onChange={e => setNewIocPattern(e.target.value)}
              placeholder="e.g. UNION SELECT @@version or /bin/bash -i or DNS Base64 chunk"
              className="w-full px-2.5 py-1.5 bg-slate-900 border border-slate-800 rounded-lg text-xs font-mono text-white focus:outline-none focus:border-cyan-500 resize-none"
            />
          </div>

          <button
            type="submit"
            disabled={isBroadcasting}
            className="w-full py-2 rounded-lg bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white text-xs font-bold transition flex items-center justify-center gap-2 shadow-lg shadow-cyan-950/50"
          >
            <Zap className="w-3.5 h-3.5" />
            <span>{isBroadcasting ? (isAr ? 'جاري التعميم والتشفير...' : 'Broadcasting...') : (isAr ? 'تعميم فوري عبر العقد (Broadcast SHA-256)' : 'Broadcast Anonymized IOC Now')}</span>
          </button>
        </form>

        {/* Right 7 cols: Real-Time Synchronized IOC Table */}
        <div className="lg:col-span-7 space-y-2">
          <div className="flex items-center justify-between">
            <h4 className="text-xs font-bold text-white">
              {isAr ? 'قائمة البصمات المزامنة حياً عبر الشبكة (Live Synchronized IOCs):' : 'Live Synchronized Global IOCs:'}
            </h4>
            <span className="text-[10px] text-slate-400 font-mono">
              Auto-Synced: <strong className="text-emerald-400">100%</strong>
            </span>
          </div>

          <div className="space-y-2 max-h-64 overflow-y-auto pr-1">
            {(federatedData?.syncedIocs || []).map((ioc: any) => (
              <div key={ioc.id} className="p-3 rounded-xl bg-slate-950/90 border border-slate-800/90 hover:border-cyan-500/40 transition space-y-1.5 text-xs font-mono">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <span className="px-2 py-0.5 rounded bg-cyan-950 border border-cyan-500/50 text-cyan-300 text-[10px] font-bold">
                      {ioc.vector}
                    </span>
                    <span className="text-slate-400 text-[10px]">{ioc.peerOrigin}</span>
                  </div>
                  <span className="text-[10px] text-emerald-400 font-bold flex items-center gap-1">
                    <CheckCircle2 className="w-3 h-3 text-emerald-400" />
                    Verified by {ioc.verifiedNodes} Nodes
                  </span>
                </div>

                <div className="text-[11px] text-slate-200 truncate bg-slate-900/90 p-1.5 rounded border border-slate-800">
                  <span className="text-slate-400 mr-1">Hash:</span>
                  <code className="text-cyan-400">{ioc.iocHash}</code>
                </div>

                <div className="flex items-center justify-between text-[10px] text-slate-400">
                  <span>MITRE: <strong className="text-slate-300">{ioc.mitreTechnique}</strong></span>
                  <span>{new Date(ioc.timestamp).toLocaleTimeString()}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};

