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
  const [customPayload, setCustomPayload] = useState<string>("admin' UNION SELECT 1, table_name, column_name FROM information_schema.tables-- -");
  const [customIp, setCustomIp] = useState<string>('198.51.100.42');
  const [isAnalyzingCustom, setIsAnalyzingCustom] = useState<boolean>(false);

  const fetchIncidents = async () => {
    setIsLoading(true);
    try {
      const res = await fetch(`/api/v1/forensics/incidents?vector=${filterVector}&severity=${filterSeverity}`);
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
      <div className="p-6 rounded-2xl bg-gradient-to-r from-slate-900 via-slate-900 to-indigo-950/40 border border-slate-800 shadow-xl relative overflow-hidden">
        <div className="relative z-10 flex flex-col md:flex-row md:items-center md:justify-between gap-4">
          <div>
            <div className="flex items-center gap-3 mb-2">
              <div className="p-2.5 rounded-xl bg-indigo-500/20 text-indigo-400 border border-indigo-500/30">
                <FileSearch className="w-6 h-6" />
              </div>
              <h2 className="text-xl sm:text-2xl font-black text-white">
                {isAr ? 'طبقة التحليل الجنائي والتسجيل (Forensics & PCAP Vault)' : 'Automated Forensics & PCAP Vault'}
              </h2>
              <span className="px-2.5 py-0.5 rounded-full text-xs font-bold bg-indigo-500/20 text-indigo-300 border border-indigo-500/30">
                SOC TIER-3
              </span>
            </div>
            <p className="text-sm text-slate-300 max-w-3xl leading-relaxed">
              {isAr
                ? 'نظام التوثيق والتحقيق الجنائي الرقمي المؤتمت: استخراج حمولات الهجوم وتحليل الشواهد (Payload Dumps)، وفك تشفير حزم PCAP، وتصنيف الهجمات بدقة وفق مصفوفة MITRE ATT&CK، مع إمكانية تصدير التقارير المعتمدة لفرق الاستجابة للحوادث.'
                : 'Enterprise autonomous forensics engine: Captures raw payload dumps, performs deep PCAP Shannon entropy dissection, assigns MITRE ATT&CK tactical IDs, and exports standardized SOC incident packages.'}
            </p>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={fetchIncidents}
              className="flex items-center gap-2 px-4 py-2 rounded-xl bg-slate-800/80 hover:bg-slate-700 text-slate-200 text-xs font-bold border border-slate-700 transition"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin' : ''}`} />
              <span>{isAr ? 'تحديث السجلات' : 'Sync Vault'}</span>
            </button>
          </div>
        </div>
      </div>

      {/* Main Grid: Incident List & Deep Investigation Dossier */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        
        {/* Left Column: Incidents Directory (5 cols) */}
        <div className="lg:col-span-5 space-y-4">
          
          {/* Filters Bar */}
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-3">
            <div className="relative">
              <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
              <input
                type="text"
                placeholder={isAr ? 'بحث بالـ IP أو رقم الحادث أو MITRE ID...' : 'Search by IP, Incident ID, MITRE...'}
                value={searchTerm}
                onChange={e => setSearchTerm(e.target.value)}
                className="w-full pl-9 pr-3 py-2 text-xs rounded-lg bg-slate-950 border border-slate-800 text-slate-200 placeholder-slate-500 focus:outline-none focus:border-indigo-500"
              />
            </div>

            <div className="grid grid-cols-2 gap-2">
              <select
                value={filterVector}
                onChange={e => setFilterVector(e.target.value)}
                className="text-xs bg-slate-950 border border-slate-800 rounded-lg p-2 text-slate-300 focus:outline-none focus:border-indigo-500"
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
                className="text-xs bg-slate-950 border border-slate-800 rounded-lg p-2 text-slate-300 focus:outline-none focus:border-indigo-500"
              >
                <option value="ALL">{isAr ? 'كافة مستويات الخطورة' : 'All Severities'}</option>
                <option value="CRITICAL">{isAr ? 'حرجة (Score >= 90)' : 'Critical (Score >= 90)'}</option>
                <option value="HIGH">{isAr ? 'عالية (Score 70-89)' : 'High (Score 70-89)'}</option>
              </select>
            </div>
          </div>

          {/* Incidents Scrollable List */}
          <div className="space-y-2.5 max-h-[640px] overflow-y-auto pr-1">
            {filteredIncidents.length === 0 ? (
              <div className="p-8 text-center rounded-xl bg-slate-900/60 border border-slate-800/80 text-slate-400 text-xs">
                {isAr ? 'لم يتم العثور على سجلات جنائية مطابقة.' : 'No forensic incidents match the current filters.'}
              </div>
            ) : (
              filteredIncidents.map(inc => {
                const isSelected = selectedIncident?.id === inc.id;
                const isCritical = inc.threatSeverityScore >= 90;
                return (
                  <div
                    key={inc.id}
                    onClick={() => setSelectedIncident(inc)}
                    className={`p-4 rounded-xl border transition cursor-pointer text-left ${
                      isSelected
                        ? 'bg-indigo-950/30 border-indigo-500/80 shadow-lg shadow-indigo-950/30'
                        : 'bg-slate-900/80 hover:bg-slate-850 border-slate-800 hover:border-slate-700'
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2 mb-1.5">
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-mono font-bold text-indigo-400">
                          {inc.incidentId}
                        </span>
                        <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                          {inc.mitreId}
                        </span>
                      </div>
                      <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full ${
                        isCritical
                          ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40'
                          : 'bg-amber-500/20 text-amber-300 border border-amber-500/40'
                      }`}>
                        {inc.threatSeverityScore}% {isCritical ? (isAr ? 'حرج' : 'CRITICAL') : (isAr ? 'مرتفع' : 'HIGH')}
                      </span>
                    </div>

                    <div className="flex items-center justify-between text-xs text-slate-300 font-medium mb-1">
                      <span>{isAr ? inc.vectorNameAr : inc.vectorNameEn}</span>
                      <span className="font-mono text-slate-400 text-[11px]">{inc.srcIp}</span>
                    </div>

                    <div className="flex items-center justify-between text-[10px] text-slate-500 font-mono">
                      <span>{new Date(inc.timestamp).toLocaleTimeString()}</span>
                      <span className="truncate max-w-[180px] text-slate-400">{inc.country} • {inc.asn}</span>
                    </div>
                  </div>
                );
              })
            )}
          </div>

          {/* Quick Custom Forensic Inspector Sandbox */}
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-3">
            <div className="flex items-center justify-between text-xs font-bold text-slate-200">
              <span className="flex items-center gap-1.5 text-cyan-400">
                <Zap className="w-3.5 h-3.5" />
                {isAr ? 'فحص وتحليل جنائي لحمولة مخصصة:' : 'Custom Payload Forensic Inspector:'}
              </span>
            </div>

            <textarea
              rows={2}
              value={customPayload}
              onChange={e => setCustomPayload(e.target.value)}
              placeholder={isAr ? 'الصق حمولة HTTP المشبوهة أو بايتات PCAP...' : 'Paste raw suspicious HTTP payload or PCAP hex...'}
              className="w-full p-2.5 text-xs font-mono rounded-lg bg-slate-950 border border-slate-800 text-slate-200 focus:outline-none focus:border-cyan-500"
            />

            <div className="flex items-center gap-2">
              <input
                type="text"
                value={customIp}
                onChange={e => setCustomIp(e.target.value)}
                placeholder="Source IP"
                className="w-1/2 p-2 text-xs font-mono rounded-lg bg-slate-950 border border-slate-800 text-slate-200 focus:outline-none focus:border-cyan-500"
              />
              <button
                onClick={handleAnalyzeCustom}
                disabled={isAnalyzingCustom || !customPayload}
                className="w-1/2 flex items-center justify-center gap-1.5 px-3 py-2 rounded-lg bg-gradient-to-r from-cyan-600 to-indigo-600 hover:from-cyan-500 hover:to-indigo-500 text-white text-xs font-bold transition disabled:opacity-50"
              >
                {isAnalyzingCustom ? (
                  <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                ) : (
                  <FileSearch className="w-3.5 h-3.5" />
                )}
                <span>{isAr ? 'توليد تقرير جنائي' : 'Synthesize Dossier'}</span>
              </button>
            </div>
          </div>
        </div>

        {/* Right Column: Deep Forensic Dossier (7 cols) */}
        <div className="lg:col-span-7">
          {selectedIncident ? (
            <div className="p-6 rounded-2xl bg-slate-900 border border-slate-800 space-y-6 shadow-xl text-left">
              
              {/* Dossier Header & Actions */}
              <div className="flex flex-wrap items-center justify-between gap-3 pb-4 border-b border-slate-800">
                <div>
                  <div className="flex items-center gap-2.5">
                    <span className="text-xs font-mono font-bold px-2.5 py-1 rounded bg-indigo-500/20 text-indigo-300 border border-indigo-500/30">
                      INCIDENT #{selectedIncident.incidentId}
                    </span>
                    <span className="text-xs font-mono text-slate-400">
                      {new Date(selectedIncident.timestamp).toLocaleString()}
                    </span>
                  </div>
                  <h3 className="text-lg font-black text-white mt-1.5">
                    {isAr ? selectedIncident.vectorNameAr : selectedIncident.vectorNameEn}
                  </h3>
                </div>

                <div className="flex items-center gap-2">
                  <button
                    onClick={() => handleExportJson(selectedIncident.incidentId)}
                    className="flex items-center gap-1.5 px-3.5 py-2 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-bold shadow-lg shadow-indigo-950 transition"
                  >
                    <Download className="w-3.5 h-3.5" />
                    <span>{isAr ? 'تصدير تقرير SOC (JSON)' : 'Export SOC Log'}</span>
                  </button>
                </div>
              </div>

              {/* Tactical Overview Badges */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
                <div className="p-3 rounded-xl bg-slate-950 border border-slate-800/80">
                  <span className="text-[10px] text-slate-400 block mb-1">{isAr ? 'مصفوفة MITRE:' : 'MITRE ATT&CK:'}</span>
                  <span className="font-mono font-bold text-indigo-400">{selectedIncident.mitreId}</span>
                  <span className="text-[10px] text-slate-500 block truncate">{selectedIncident.mitreTactic}</span>
                </div>

                <div className="p-3 rounded-xl bg-slate-950 border border-slate-800/80">
                  <span className="text-[10px] text-slate-400 block mb-1">{isAr ? 'درجة الخطورة:' : 'Threat Severity:'}</span>
                  <span className="font-mono font-black text-rose-400 text-sm">
                    {selectedIncident.threatSeverityScore} / 100
                  </span>
                  <span className="text-[10px] text-slate-500 block">{selectedIncident.threatTier}</span>
                </div>

                <div className="p-3 rounded-xl bg-slate-950 border border-slate-800/80">
                  <span className="text-[10px] text-slate-400 block mb-1">{isAr ? 'المصدر والجغرافيا:' : 'Source & GeoIP:'}</span>
                  <span className="font-mono font-bold text-slate-200 truncate block">{selectedIncident.srcIp}</span>
                  <span className="text-[10px] text-slate-500 block truncate">{selectedIncident.country} • {selectedIncident.asn}</span>
                </div>

                <div className="p-3 rounded-xl bg-slate-950 border border-slate-800/80">
                  <span className="text-[10px] text-slate-400 block mb-1">{isAr ? 'الإنتروبيا والتشتت:' : 'Shannon Entropy:'}</span>
                  <span className="font-mono font-bold text-cyan-400">{selectedIncident.payloadEntropy} bits/byte</span>
                  <span className="text-[10px] text-slate-500 block">{selectedIncident.protocol} :{selectedIncident.port}</span>
                </div>
              </div>

              {/* Section 1: Payload Dump & Evidence */}
              <div className="space-y-2">
                <div className="flex items-center justify-between text-xs font-bold text-slate-200">
                  <span className="flex items-center gap-1.5 text-rose-400">
                    <Terminal className="w-3.5 h-3.5" />
                    {isAr ? 'حمولة الهجوم المستخرجة (Extracted Payload Dump):' : 'Extracted Malicious Payload Dump:'}
                  </span>
                  <button
                    onClick={() => handleCopy(selectedIncident.payloadDump, 'payload')}
                    className="flex items-center gap-1 text-[11px] text-slate-400 hover:text-slate-200 font-mono transition"
                  >
                    {copiedKey === 'payload' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                    <span>{copiedKey === 'payload' ? (isAr ? 'تم النسخ' : 'Copied') : (isAr ? 'نسخ الحمولة' : 'Copy')}</span>
                  </button>
                </div>
                <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 font-mono text-xs text-rose-300 break-all leading-relaxed select-all">
                  {selectedIncident.payloadDump}
                </div>
              </div>

              {/* Section 2: Raw Request & PCAP Hex Dissection */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="space-y-2">
                  <span className="text-xs font-bold text-slate-300 flex items-center gap-1.5">
                    <Code2 className="w-3.5 h-3.5 text-cyan-400" />
                    {isAr ? 'ترويسة الطلب (Raw Request Header):' : 'Raw Request Header Evidence:'}
                  </span>
                  <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 font-mono text-[11px] text-slate-300 whitespace-pre-wrap max-h-36 overflow-y-auto">
                    {selectedIncident.forensicEvidence.rawRequestHeader}
                  </div>
                </div>

                <div className="space-y-2">
                  <span className="text-xs font-bold text-slate-300 flex items-center gap-1.5">
                    <Layers className="w-3.5 h-3.5 text-amber-400" />
                    {isAr ? 'عينة بايتات PCAP (Hex Dissection):' : 'PCAP Byte Hex Sample:'}
                  </span>
                  <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 font-mono text-[11px] text-amber-300 max-h-36 overflow-y-auto break-all">
                    {selectedIncident.forensicEvidence.pcapHexSample}
                  </div>
                </div>
              </div>

              {/* Section 3: Anomaly Indicators & Threat Actor Attribution */}
              <div className="p-4 rounded-xl bg-slate-950 border border-slate-800/80 space-y-2.5">
                <div className="flex items-center justify-between text-xs font-bold">
                  <span className="text-indigo-400 flex items-center gap-1.5">
                    <ShieldAlert className="w-3.5 h-3.5" />
                    {isAr ? 'مؤشرات الشذوذ ونسب التهديد (Threat Attribution):' : 'Forensic Anomaly Indicators & Attribution:'}
                  </span>
                  <span className="text-[11px] font-mono text-purple-300 bg-purple-950/40 px-2 py-0.5 rounded border border-purple-500/30">
                    {selectedIncident.forensicEvidence.threatActorAttribution}
                  </span>
                </div>
                <ul className="space-y-1.5 text-xs text-slate-300">
                  {selectedIncident.forensicEvidence.anomalyIndicators.map((ind) => (
                    <li key={`ind-${ind}`} className="flex items-start gap-2">
                      <span className="w-1.5 h-1.5 rounded-full bg-indigo-400 mt-1.5 flex-shrink-0"></span>
                      <span>{ind}</span>
                    </li>
                  ))}
                </ul>
              </div>

              {/* Section 4: Recommended Blue Team SOC Playbook */}
              <div className="p-4 rounded-xl bg-emerald-950/20 border border-emerald-500/30 space-y-2.5">
                <span className="text-xs font-bold text-emerald-400 flex items-center gap-1.5">
                  <ShieldCheck className="w-4 h-4" />
                  {isAr ? 'خطة المعالجة والتأمين الموصى بها لفرق الـ SOC:' : 'Recommended SOC Playbook & Hardening Measures:'}
                </span>
                <ul className="space-y-1.5 text-xs text-slate-300">
                  {selectedIncident.forensicEvidence.recommendedRemediation.map((rem) => (
                    <li key={`rem-${rem}`} className="flex items-start gap-2">
                      <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 mt-1.5 flex-shrink-0"></span>
                      <span>{rem}</span>
                    </li>
                  ))}
                </ul>
              </div>

              {/* Section 5: Synthesized Kernel Rules applied */}
              <div className="space-y-2">
                <span className="text-xs font-bold text-slate-300 block">
                  {isAr ? 'قواعد النواة المطبقة تلقائياً للتصدي (Kernel Mitigation Rules):' : 'Autonomous Synthesized Kernel Defenses:'}
                </span>
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 text-[11px] font-mono">
                  {selectedIncident.generatedRules.iptables && (
                    <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800">
                      <span className="text-[9px] text-slate-500 block mb-0.5">IPTables:</span>
                      <code className="text-rose-300 truncate block">{selectedIncident.generatedRules.iptables}</code>
                    </div>
                  )}
                  {selectedIncident.generatedRules.suricata && (
                    <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800">
                      <span className="text-[9px] text-slate-500 block mb-0.5">Suricata:</span>
                      <code className="text-amber-300 truncate block">{selectedIncident.generatedRules.suricata}</code>
                    </div>
                  )}
                  {selectedIncident.generatedRules.ebpf && (
                    <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800">
                      <span className="text-[9px] text-slate-500 block mb-0.5">eBPF XDP:</span>
                      <code className="text-cyan-300 truncate block">{selectedIncident.generatedRules.ebpf}</code>
                    </div>
                  )}
                </div>
              </div>

            </div>
          ) : (
            <div className="p-12 text-center rounded-2xl bg-slate-900/40 border border-slate-800 text-slate-400 text-sm">
              {isAr ? 'اختر حادثة من القائمة لعرض تفاصيل التحقيق الجنائي.' : 'Select an incident from the directory to review complete forensic analysis.'}
            </div>
          )}
        </div>

      </div>
    </div>
  );
};
