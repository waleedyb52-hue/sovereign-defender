import React, { useState, useEffect } from 'react';
import {
  FileSearch,
  Download,
  ShieldAlert,
  Terminal,
  Copy,
  Check,
  ExternalLink,
  Activity,
  Layers,
  Code2,
  Globe,
  Search,
  Filter,
  AlertTriangle,
  FileText,
  RefreshCw,
  Zap,
  Sliders,
  ChevronRight,
  ShieldCheck
} from 'lucide-react';
import { IncidentForensicReport, AttackVectorType } from '../types';

interface ForensicsVaultProps {
  lang: 'ar' | 'en';
  onSimulateVector?: (vector: AttackVectorType) => void;
}

export const ForensicsVault: React.FC<ForensicsVaultProps> = ({ lang, onSimulateVector }) => {
  const isAr = lang === 'ar';
  const [incidents, setIncidents] = useState<IncidentForensicReport[]>([]);
  const [selectedIncident, setSelectedIncident] = useState<IncidentForensicReport | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [filterVector, setFilterVector] = useState<string>('ALL');
  const [filterSeverity, setFilterSeverity] = useState<string>('ALL');
  const [searchTerm, setSearchTerm] = useState<string>('');

  // Custom Investigation Sandbox State
  const [customPayload, setCustomPayload] = useState<string>(
    "admin' UNION SELECT 1, table_name, column_name FROM information_schema.tables-- -"
  );
  const [customIp, setCustomIp] = useState<string>('198.51.100.42');
  const [isAnalyzingCustom, setIsAnalyzingCustom] = useState<boolean>(false);

  const fetchIncidents = async () => {
    setIsLoading(true);
    try {
      const res = await fetch(
        `/api/v1/forensics/incidents?vector=${filterVector}&severity=${filterSeverity}`
      );
      if (res.ok) {
        const data = await res.json();
        setIncidents(data.incidents || []);
        if (data.incidents?.length > 0 && !selectedIncident) {
          setSelectedIncident(data.incidents[0]);
        }
      }
    } catch (err) {
      console.warn('Failed to fetch forensic incidents:', err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchIncidents();
  }, [filterVector, filterSeverity]);

  const handleCopy = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const handleExportJson = (incidentId: string) => {
    window.open(`/api/v1/forensics/export/${incidentId}`, '_blank');
  };

  const handleAnalyzeCustom = async () => {
    if (!customPayload) return;
    setIsAnalyzingCustom(true);
    try {
      const res = await fetch('/api/v1/forensics/analyze-custom', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          rawText: customPayload,
          srcIp: customIp,
          vector: customPayload.toLowerCase().includes('union') ? 'SQL_INJECTION' : 'PATH_TRAVERSAL'
        })
      });
      if (res.ok) {
        const data = await res.json();
        if (data.report) {
          setIncidents(prev => [data.report, ...prev]);
          setSelectedIncident(data.report);
        }
      }
    } catch (err) {
      console.error('Custom forensic analysis error:', err);
    } finally {
      setIsAnalyzingCustom(false);
    }
  };

  const filteredIncidents = incidents.filter(inc => {
    const matchesSearch =
      inc.incidentId.toLowerCase().includes(searchTerm.toLowerCase()) ||
      inc.srcIp.toLowerCase().includes(searchTerm.toLowerCase()) ||
      inc.vector.toLowerCase().includes(searchTerm.toLowerCase()) ||
      inc.mitreId.toLowerCase().includes(searchTerm.toLowerCase());
    return matchesSearch;
  });

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="relative overflow-hidden rounded-2xl border border-slate-800 bg-gradient-to-r from-slate-900 via-slate-900 to-cyan-950/40 p-6 shadow-xl">
        <div className="relative z-10 flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
          <div>
            <div className="mb-2 flex items-center gap-3">
              <div className="rounded-xl border border-cyan-500/30 bg-cyan-500/20 p-2.5 text-cyan-400">
                <FileSearch className="h-6 w-6" />
              </div>
              <h2 className="text-xl font-black text-white sm:text-2xl">
                {isAr
                  ? 'طبقة التحليل الجنائي والتسجيل (Forensics & PCAP Vault)'
                  : 'Automated Forensics & PCAP Vault'}
              </h2>
              <span className="rounded-full border border-cyan-500/30 bg-cyan-500/20 px-2.5 py-0.5 text-xs font-bold text-cyan-300">
                SOC TIER-3
              </span>
            </div>
            <p className="max-w-3xl text-sm leading-relaxed text-slate-300">
              {isAr
                ? 'نظام التوثيق والتحقيق الجنائي الرقمي المؤتمت: استخراج حمولات الهجوم وتحليل الشواهد (Payload Dumps)، وفك تشفير حزم PCAP، وتصنيف الهجمات بدقة وفق مصفوفة MITRE ATT&CK، مع إمكانية تصدير التقارير المعتمدة لفرق الاستجابة للحوادث.'
                : 'Enterprise autonomous forensics engine: Captures raw payload dumps, performs deep PCAP Shannon entropy dissection, assigns MITRE ATT&CK tactical IDs, and exports standardized SOC incident packages.'}
            </p>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={fetchIncidents}
              className="flex items-center gap-2 rounded-xl border border-slate-700 bg-slate-800/80 px-4 py-2 text-xs font-bold text-slate-200 transition hover:bg-slate-700"
            >
              <RefreshCw className={`h-3.5 w-3.5 ${isLoading ? 'animate-spin' : ''}`} />
              <span>{isAr ? 'تحديث السجلات' : 'Sync Vault'}</span>
            </button>
          </div>
        </div>
      </div>

      {/* Main Grid: Incident List & Deep Investigation Dossier */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
        {/* Left Column: Incidents Directory (5 cols) */}
        <div className="space-y-4 lg:col-span-5">
          {/* Filters Bar */}
          <div className="space-y-3 rounded-xl border border-slate-800 bg-slate-900 p-4 shadow-[0_0_20px_rgba(0,255,255,0.08)]">
            <div className="relative">
              <Search className="absolute top-2.5 left-3 h-4 w-4 text-slate-500" />
              <input
                type="text"
                placeholder={
                  isAr
                    ? 'بحث بالـ IP أو رقم الحادث أو MITRE ID...'
                    : 'Search by IP, Incident ID, MITRE...'
                }
                value={searchTerm}
                onChange={e => setSearchTerm(e.target.value)}
                className="w-full rounded-lg border border-slate-800 bg-slate-950 py-2 pr-3 pl-9 text-xs text-slate-200 placeholder-slate-500 focus:border-cyan-500 focus:outline-none shadow-[0_0_20px_rgba(0,255,255,0.08)]"
              />
            </div>

            <div className="grid grid-cols-2 gap-2">
              <select
                value={filterVector}
                onChange={e => setFilterVector(e.target.value)}
                className="rounded-lg border border-slate-800 bg-slate-950 p-2 text-xs text-slate-300 focus:border-cyan-500 focus:outline-none shadow-[0_0_20px_rgba(0,255,255,0.08)]"
              >
                <option value="ALL">{isAr ? 'كافة متجهات الهجوم' : 'All Attack Vectors'}</option>
                <option value="SQL_INJECTION">SQL Injection</option>
                <option value="DNS_EXFILTRATION">DNS Exfiltration</option>
                <option value="REMOTE_CODE_EXECUTION">Remote Code Execution</option>
                <option value="SSH_BRUTE_FORCE">SSH Brute Force</option>
                <option value="LATERAL_MOVEMENT">Lateral Movement</option>
              </select>

              <select
                value={filterSeverity}
                onChange={e => setFilterSeverity(e.target.value)}
                className="rounded-lg border border-slate-800 bg-slate-950 p-2 text-xs text-slate-300 focus:border-cyan-500 focus:outline-none shadow-[0_0_20px_rgba(0,255,255,0.08)]"
              >
                <option value="ALL">{isAr ? 'كافة مستويات الخطورة' : 'All Severities'}</option>
                <option value="CRITICAL">
                  {isAr ? 'حرجة (Score >= 90)' : 'Critical (Score >= 90)'}
                </option>
                <option value="HIGH">{isAr ? 'عالية (Score 70-89)' : 'High (Score 70-89)'}</option>
              </select>
            </div>
          </div>

          {/* Incidents Scrollable List */}
          <div className="max-h-[640px] space-y-2.5 overflow-y-auto pr-1">
            {filteredIncidents.length === 0 ? (
              <div className="rounded-xl border border-slate-800/80 bg-slate-900/60 p-8 text-center text-xs text-slate-400 shadow-[0_0_20px_rgba(0,255,255,0.08)]">
                {isAr
                  ? 'لم يتم العثور على سجلات جنائية مطابقة.'
                  : 'No forensic incidents match the current filters.'}
              </div>
            ) : (
              filteredIncidents.map(inc => {
                const isSelected = selectedIncident?.id === inc.id;
                const isCritical = inc.threatSeverityScore >= 90;
                return (
                  <div
                    key={inc.id}
                    onClick={() => setSelectedIncident(inc)}
                    className={`cursor-pointer rounded-xl border p-4 text-left transition ${
                      isSelected
                        ? 'border-cyan-500/80 bg-cyan-950/30 shadow-lg shadow-cyan-950/30'
                        : 'hover:bg-slate-850 border-slate-800 bg-slate-900/80 hover:border-slate-700 shadow-[0_0_20px_rgba(0,255,255,0.08)]'
                    }`}
                  >
                    <div className="mb-1.5 flex items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-xs font-bold text-cyan-400">
                          {inc.incidentId}
                        </span>
                        <span className="rounded bg-slate-800 px-2 py-0.5 font-mono text-[10px] text-slate-300">
                          {inc.mitreId}
                        </span>
                      </div>
                      <span
                        className={`rounded-full px-2 py-0.5 text-[10px] font-bold ${
                          isCritical
                            ? 'border border-rose-500/40 bg-rose-500/20 text-rose-300'
                            : 'border border-amber-500/40 bg-amber-500/20 text-amber-300'
                        }`}
                      >
                        {inc.threatSeverityScore}%{' '}
                        {isCritical ? (isAr ? 'حرج' : 'CRITICAL') : isAr ? 'مرتفع' : 'HIGH'}
                      </span>
                    </div>

                    <div className="mb-1 flex items-center justify-between text-xs font-medium text-slate-300">
                      <span>{isAr ? inc.vectorNameAr : inc.vectorNameEn}</span>
                      <span className="font-mono text-[11px] text-slate-400">{inc.srcIp}</span>
                    </div>

                    <div className="flex items-center justify-between font-mono text-[10px] text-slate-500">
                      <span>{new Date(inc.timestamp).toLocaleTimeString()}</span>
                      <span className="max-w-[180px] truncate text-slate-400">
                        {inc.country} • {inc.asn}
                      </span>
                    </div>
                  </div>
                );
              })
            )}
          </div>

          {/* Quick Custom Forensic Inspector Sandbox */}
          <div className="space-y-3 rounded-xl border border-slate-800 bg-slate-900 p-4 shadow-[0_0_20px_rgba(0,255,255,0.08)]">
            <div className="flex items-center justify-between text-xs font-bold text-slate-200">
              <span className="flex items-center gap-1.5 text-cyan-400">
                <Zap className="h-3.5 w-3.5" />
                {isAr ? 'فحص وتحليل جنائي لحمولة مخصصة:' : 'Custom Payload Forensic Inspector:'}
              </span>
            </div>

            <textarea
              rows={2}
              value={customPayload}
              onChange={e => setCustomPayload(e.target.value)}
              placeholder={
                isAr
                  ? 'الصق حمولة HTTP المشبوهة أو بايتات PCAP...'
                  : 'Paste raw suspicious HTTP payload or PCAP hex...'
              }
              className="w-full rounded-lg border border-slate-800 bg-slate-950 p-2.5 font-mono text-xs text-slate-200 focus:border-cyan-500 focus:outline-none shadow-[0_0_20px_rgba(0,255,255,0.08)]"
            />

            <div className="flex items-center gap-2">
              <input
                type="text"
                value={customIp}
                onChange={e => setCustomIp(e.target.value)}
                placeholder="Source IP"
                className="w-1/2 rounded-lg border border-slate-800 bg-slate-950 p-2 font-mono text-xs text-slate-200 focus:border-cyan-500 focus:outline-none shadow-[0_0_20px_rgba(0,255,255,0.08)]"
              />
              <button
                onClick={handleAnalyzeCustom}
                disabled={isAnalyzingCustom || !customPayload}
                className="flex w-1/2 items-center justify-center gap-1.5 rounded-lg bg-gradient-to-r from-cyan-600 to-cyan-600 px-3 py-2 text-xs font-bold text-white transition hover:from-cyan-500 hover:to-cyan-500 disabled:opacity-50"
              >
                {isAnalyzingCustom ? (
                  <RefreshCw className="h-3.5 w-3.5 animate-spin" />
                ) : (
                  <FileSearch className="h-3.5 w-3.5" />
                )}
                <span>{isAr ? 'توليد تقرير جنائي' : 'Synthesize Dossier'}</span>
              </button>
            </div>
          </div>
        </div>

        {/* Right Column: Deep Forensic Dossier (7 cols) */}
        <div className="lg:col-span-7">
          {selectedIncident ? (
            <div className="space-y-6 rounded-2xl border border-slate-800 bg-slate-900 p-6 text-left shadow-xl shadow-[0_0_20px_rgba(0,255,255,0.08)]">
              {/* Dossier Header & Actions */}
              <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 pb-4">
                <div>
                  <div className="flex items-center gap-2.5">
                    <span className="rounded border border-cyan-500/30 bg-cyan-500/20 px-2.5 py-1 font-mono text-xs font-bold text-cyan-300">
                      INCIDENT #{selectedIncident.incidentId}
                    </span>
                    <span className="font-mono text-xs text-slate-400">
                      {new Date(selectedIncident.timestamp).toLocaleString()}
                    </span>
                  </div>
                  <h3 className="mt-1.5 text-lg font-black text-white">
                    {isAr ? selectedIncident.vectorNameAr : selectedIncident.vectorNameEn}
                  </h3>
                </div>

                <div className="flex items-center gap-2">
                  <button
                    onClick={() => handleExportJson(selectedIncident.incidentId)}
                    className="flex items-center gap-1.5 rounded-xl bg-cyan-600 px-3.5 py-2 text-xs font-bold text-white shadow-lg shadow-cyan-950 transition hover:bg-cyan-500"
                  >
                    <Download className="h-3.5 w-3.5" />
                    <span>{isAr ? 'تصدير تقرير SOC (JSON)' : 'Export SOC Log'}</span>
                  </button>
                </div>
              </div>

              {/* Tactical Overview Badges */}
              <div className="grid grid-cols-2 gap-3 text-xs sm:grid-cols-4">
                <div className="rounded-xl border border-slate-800/80 bg-slate-950 p-3 shadow-[0_0_20px_rgba(0,255,255,0.08)]">
                  <span className="mb-1 block text-[10px] text-slate-400">
                    {isAr ? 'مصفوفة MITRE:' : 'MITRE ATT&CK:'}
                  </span>
                  <span className="font-mono font-bold text-cyan-400">
                    {selectedIncident.mitreId}
                  </span>
                  <span className="block truncate text-[10px] text-slate-500">
                    {selectedIncident.mitreTactic}
                  </span>
                </div>

                <div className="rounded-xl border border-slate-800/80 bg-slate-950 p-3 shadow-[0_0_20px_rgba(0,255,255,0.08)]">
                  <span className="mb-1 block text-[10px] text-slate-400">
                    {isAr ? 'درجة الخطورة:' : 'Threat Severity:'}
                  </span>
                  <span className="font-mono text-sm font-black text-rose-400">
                    {selectedIncident.threatSeverityScore} / 100
                  </span>
                  <span className="block text-[10px] text-slate-500">
                    {selectedIncident.threatTier}
                  </span>
                </div>

                <div className="rounded-xl border border-slate-800/80 bg-slate-950 p-3 shadow-[0_0_20px_rgba(0,255,255,0.08)]">
                  <span className="mb-1 block text-[10px] text-slate-400">
                    {isAr ? 'المصدر والجغرافيا:' : 'Source & GeoIP:'}
                  </span>
                  <span className="block truncate font-mono font-bold text-slate-200">
                    {selectedIncident.srcIp}
                  </span>
                  <span className="block truncate text-[10px] text-slate-500">
                    {selectedIncident.country} • {selectedIncident.asn}
                  </span>
                </div>

                <div className="rounded-xl border border-slate-800/80 bg-slate-950 p-3 shadow-[0_0_20px_rgba(0,255,255,0.08)]">
                  <span className="mb-1 block text-[10px] text-slate-400">
                    {isAr ? 'الإنتروبيا والتشتت:' : 'Shannon Entropy:'}
                  </span>
                  <span className="font-mono font-bold text-cyan-400">
                    {selectedIncident.payloadEntropy} bits/byte
                  </span>
                  <span className="block text-[10px] text-slate-500">
                    {selectedIncident.protocol} :{selectedIncident.port}
                  </span>
                </div>
              </div>

              {/* Section 1: Payload Dump & Evidence */}
              <div className="space-y-2">
                <div className="flex items-center justify-between text-xs font-bold text-slate-200">
                  <span className="flex items-center gap-1.5 text-rose-400">
                    <Terminal className="h-3.5 w-3.5" />
                    {isAr
                      ? 'حمولة الهجوم المستخرجة (Extracted Payload Dump):'
                      : 'Extracted Malicious Payload Dump:'}
                  </span>
                  <button
                    onClick={() => handleCopy(selectedIncident.payloadDump, 'payload')}
                    className="flex items-center gap-1 font-mono text-[11px] text-slate-400 transition hover:text-slate-200"
                  >
                    {copiedKey === 'payload' ? (
                      <Check className="h-3 w-3 text-emerald-400" />
                    ) : (
                      <Copy className="h-3 w-3" />
                    )}
                    <span>
                      {copiedKey === 'payload'
                        ? isAr
                          ? 'تم النسخ'
                          : 'Copied'
                        : isAr
                          ? 'نسخ الحمولة'
                          : 'Copy'}
                    </span>
                  </button>
                </div>
                <div className="rounded-xl border border-slate-800 bg-slate-950 p-3.5 font-mono text-xs leading-relaxed break-all text-rose-300 select-all shadow-[0_0_20px_rgba(0,255,255,0.08)]">
                  {selectedIncident.payloadDump}
                </div>
              </div>

              {/* Section 2: Raw Request & PCAP Hex Dissection */}
              <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
                <div className="space-y-2">
                  <span className="flex items-center gap-1.5 text-xs font-bold text-slate-300">
                    <Code2 className="h-3.5 w-3.5 text-cyan-400" />
                    {isAr ? 'ترويسة الطلب (Raw Request Header):' : 'Raw Request Header Evidence:'}
                  </span>
                  <div className="max-h-36 overflow-y-auto rounded-xl border border-slate-800 bg-slate-950 p-3 font-mono text-[11px] whitespace-pre-wrap text-slate-300 shadow-[0_0_20px_rgba(0,255,255,0.08)]">
                    {selectedIncident.forensicEvidence.rawRequestHeader}
                  </div>
                </div>

                <div className="space-y-2">
                  <span className="flex items-center gap-1.5 text-xs font-bold text-slate-300">
                    <Layers className="h-3.5 w-3.5 text-amber-400" />
                    {isAr ? 'عينة بايتات PCAP (Hex Dissection):' : 'PCAP Byte Hex Sample:'}
                  </span>
                  <div className="max-h-36 overflow-y-auto rounded-xl border border-slate-800 bg-slate-950 p-3 font-mono text-[11px] break-all text-amber-300 shadow-[0_0_20px_rgba(0,255,255,0.08)]">
                    {selectedIncident.forensicEvidence.pcapHexSample}
                  </div>
                </div>
              </div>

              {/* Section 3: Anomaly Indicators & Threat Actor Attribution */}
              <div className="space-y-2.5 rounded-xl border border-slate-800/80 bg-slate-950 p-4 shadow-[0_0_20px_rgba(0,255,255,0.08)]">
                <div className="flex items-center justify-between text-xs font-bold">
                  <span className="flex items-center gap-1.5 text-cyan-400">
                    <ShieldAlert className="h-3.5 w-3.5" />
                    {isAr
                      ? 'مؤشرات الشذوذ ونسب التهديد (Threat Attribution):'
                      : 'Forensic Anomaly Indicators & Attribution:'}
                  </span>
                  <span className="rounded border border-cyan-500/30 bg-cyan-950/40 px-2 py-0.5 font-mono text-[11px] text-cyan-300">
                    {selectedIncident.forensicEvidence.threatActorAttribution}
                  </span>
                </div>
                <ul className="space-y-1.5 text-xs text-slate-300">
                  {selectedIncident.forensicEvidence.anomalyIndicators.map(ind => (
                    <li key={`ind-${ind}`} className="flex items-start gap-2">
                      <span className="mt-1.5 h-1.5 w-1.5 flex-shrink-0 rounded-full bg-cyan-400"></span>
                      <span>{ind}</span>
                    </li>
                  ))}
                </ul>
              </div>

              {/* Section 4: Recommended Blue Team SOC Playbook */}
              <div className="space-y-2.5 rounded-xl border border-emerald-500/30 bg-emerald-950/20 p-4">
                <span className="flex items-center gap-1.5 text-xs font-bold text-emerald-400">
                  <ShieldCheck className="h-4 w-4" />
                  {isAr
                    ? 'خطة المعالجة والتأمين الموصى بها لفرق الـ SOC:'
                    : 'Recommended SOC Playbook & Hardening Measures:'}
                </span>
                <ul className="space-y-1.5 text-xs text-slate-300">
                  {selectedIncident.forensicEvidence.recommendedRemediation.map(rem => (
                    <li key={`rem-${rem}`} className="flex items-start gap-2">
                      <span className="mt-1.5 h-1.5 w-1.5 flex-shrink-0 rounded-full bg-emerald-400"></span>
                      <span>{rem}</span>
                    </li>
                  ))}
                </ul>
              </div>

              {/* Section 5: Synthesized Kernel Rules applied */}
              <div className="space-y-2">
                <span className="block text-xs font-bold text-slate-300">
                  {isAr
                    ? 'قواعد النواة المطبقة تلقائياً للتصدي (Kernel Mitigation Rules):'
                    : 'Autonomous Synthesized Kernel Defenses:'}
                </span>
                <div className="grid grid-cols-1 gap-2 font-mono text-[11px] sm:grid-cols-3">
                  {selectedIncident.generatedRules.iptables && (
                    <div className="rounded-lg border border-slate-800 bg-slate-950 p-2.5 shadow-[0_0_20px_rgba(0,255,255,0.08)]">
                      <span className="mb-0.5 block text-[9px] text-slate-500">IPTables:</span>
                      <code className="block truncate text-rose-300">
                        {selectedIncident.generatedRules.iptables}
                      </code>
                    </div>
                  )}
                  {selectedIncident.generatedRules.suricata && (
                    <div className="rounded-lg border border-slate-800 bg-slate-950 p-2.5 shadow-[0_0_20px_rgba(0,255,255,0.08)]">
                      <span className="mb-0.5 block text-[9px] text-slate-500">Suricata:</span>
                      <code className="block truncate text-amber-300">
                        {selectedIncident.generatedRules.suricata}
                      </code>
                    </div>
                  )}
                  {selectedIncident.generatedRules.ebpf && (
                    <div className="rounded-lg border border-slate-800 bg-slate-950 p-2.5 shadow-[0_0_20px_rgba(0,255,255,0.08)]">
                      <span className="mb-0.5 block text-[9px] text-slate-500">eBPF XDP:</span>
                      <code className="block truncate text-cyan-300">
                        {selectedIncident.generatedRules.ebpf}
                      </code>
                    </div>
                  )}
                </div>
              </div>
            </div>
          ) : (
            <div className="rounded-2xl border border-slate-800 bg-slate-900/40 p-12 text-center text-sm text-slate-400 shadow-[0_0_20px_rgba(0,255,255,0.08)]">
              {isAr
                ? 'اختر حادثة من القائمة لعرض تفاصيل التحقيق الجنائي.'
                : 'Select an incident from the directory to review complete forensic analysis.'}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
