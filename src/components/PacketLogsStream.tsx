import React, { useState } from 'react';
import { PacketStatus, TelemetryPacket } from '../types';
import { Terminal, Shield, ShieldAlert, Sparkles, Radio, Search, Download, Trash2, ChevronRight, Eye, Copy, Check } from 'lucide-react';

interface PacketLogsStreamProps {
  packets: TelemetryPacket[];
  onInspectPacket: (packet: TelemetryPacket) => void;
  onClearLogs: () => void;
  lang: 'ar' | 'en';
}

export const PacketLogsStream: React.FC<PacketLogsStreamProps> = ({
  packets,
  onInspectPacket,
  onClearLogs,
  lang
}) => {
  const isAr = lang === 'ar';

  const [filterStatus, setFilterStatus] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [expandedPacketId, setExpandedPacketId] = useState<string | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const filteredPackets = packets.filter(p => {
    const matchesStatus = filterStatus === 'ALL' || p.status === filterStatus;
    const q = searchQuery.toLowerCase();
    const matchesSearch =
      !searchQuery ||
      p.srcIp.includes(q) ||
      p.dstIp.includes(q) ||
      p.vector.toLowerCase().includes(q) ||
      p.payload.toLowerCase().includes(q) ||
      String(p.port).includes(q);
    return matchesStatus && matchesSearch;
  });

  const copyText = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2500);
  };

  const handleExportJson = () => {
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(packets, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', dataStr);
    downloadAnchor.setAttribute('download', `sovereign_defender_telemetry_${Date.now()}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  const getStatusBadge = (status: PacketStatus) => {
    switch (status) {
      case 'BLOCKED':
        return (
          <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-500/20 text-rose-300 border border-rose-500/40 flex items-center gap-1">
            <ShieldAlert className="w-3 h-3 text-rose-400" />
            <span>BLOCKED</span>
          </span>
        );
      case 'HONEYPOT_DIVERTED':
        return (
          <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-purple-500/20 text-purple-300 border border-purple-500/40 flex items-center gap-1">
            <Radio className="w-3 h-3 text-purple-400" />
            <span>HONEYPOT</span>
          </span>
        );
      case 'ANALYZED':
        return (
          <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 flex items-center gap-1">
            <Sparkles className="w-3 h-3 text-cyan-400" />
            <span>AI_ANALYZED</span>
          </span>
        );
      default:
        return (
          <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 flex items-center gap-1">
            <Shield className="w-3 h-3 text-emerald-400" />
            <span>SAFE</span>
          </span>
        );
    }
  };

  return (
    <div className="bg-slate-900/90 border border-slate-800 rounded-2xl overflow-hidden shadow-xl">
      {/* Header & Controls Bar */}
      <div className="p-4 border-b border-slate-800 bg-slate-950/60 flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2.5">
          <div className="p-2 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-400">
            <Terminal className="w-4 h-4" />
          </div>
          <div>
            <h3 className="font-bold text-white text-sm sm:text-base">
              {isAr ? 'سجل تدفق الحزم المباشر' : 'Real-Time Telemetry Stream'}
            </h3>
            <p className="text-[11px] text-slate-400">
              {isAr ? 'المراقبة الحية لعمليات الفحص والحظر التلقائي' : 'Live stream of network requests, AI decisions, and synthesized firewall rules'}
            </p>
          </div>
        </div>

        {/* Action Buttons */}
        <div className="flex items-center gap-2">
          <button
            onClick={handleExportJson}
            className="flex items-center gap-1 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs font-bold transition"
            title="Export Logs as JSON"
          >
            <Download className="w-3.5 h-3.5" />
            <span>JSON</span>
          </button>
          <button
            onClick={onClearLogs}
            className="p-1.5 rounded-lg bg-slate-800 hover:bg-rose-950/60 hover:text-rose-400 text-slate-400 border border-slate-700 transition"
            title={isAr ? 'مسح السجلات' : 'Clear Telemetry'}
          >
            <Trash2 className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="px-4 py-3 bg-slate-950/40 border-b border-slate-800 flex flex-wrap items-center justify-between gap-3">
        {/* Status Filter Pills */}
        <div className="flex items-center gap-1.5 flex-wrap text-xs font-bold">
          {['ALL', 'BLOCKED', 'HONEYPOT_DIVERTED', 'PASSED'].map(status => (
            <button
              key={status}
              onClick={() => setFilterStatus(status)}
              className={`px-3 py-1 rounded-lg transition ${
                filterStatus === status
                  ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                  : 'bg-slate-800/80 text-slate-400 hover:text-slate-200'
              }`}
            >
              {status === 'ALL'
                ? isAr ? 'الكل' : 'All'
                : status === 'BLOCKED'
                ? isAr ? 'محظور ❌' : 'Blocked'
                : status === 'HONEYPOT_DIVERTED'
                ? isAr ? 'مصيدة 🍯' : 'Honeypot'
                : isAr ? 'ممرر ✅' : 'Safe'}
            </button>
          ))}
        </div>

        {/* Search Input */}
        <div className="relative w-full sm:w-64">
          <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-2.5" />
          <input
            type="text"
            value={searchQuery}
            onChange={e => setSearchQuery(e.target.value)}
            placeholder={isAr ? 'بحث بالـ IP أو الحمولة...' : 'Filter by IP, payload, vector...'}
            className="w-full pl-8 pr-3 py-1.5 bg-slate-950 border border-slate-800 rounded-lg text-xs font-mono text-white focus:outline-none focus:border-emerald-500"
          />
        </div>
      </div>

      {/* Table Header: 4 Columns (Time, Client IP, Target Endpoint, Verdict) */}
      <div className="hidden sm:grid grid-cols-12 gap-2 px-4 py-2 bg-slate-950/80 border-b border-slate-800 text-[10px] font-bold text-slate-400 font-mono uppercase tracking-wider">
        <div className="col-span-2">{isAr ? 'الوقت' : 'Time'}</div>
        <div className="col-span-3">{isAr ? 'عنوان IP العميل' : 'Client IP'}</div>
        <div className="col-span-4">{isAr ? 'نقطة النهاية المستهدفة' : 'Target Endpoint'}</div>
        <div className="col-span-3 text-right">{isAr ? 'قرار الأمان' : 'Verdict'}</div>
      </div>

      {/* Logs Table Stream */}
      <div className="max-h-96 overflow-y-auto divide-y divide-slate-800/60 font-mono text-xs">
        {filteredPackets.length === 0 ? (
          <div className="py-12 text-center text-slate-500 text-xs">
            {isAr ? 'لا توجد حزم تطابق شروط البحث الحالية.' : 'No telemetry packets match the active filter criteria.'}
          </div>
        ) : (
          filteredPackets.map(packet => {
            const isExpanded = expandedPacketId === packet.id;
            return (
              <div key={packet.uuid || `packet-${packet.id}-${packet.timestamp}`} className="hover:bg-slate-800/30 transition">
                <div
                  onClick={() => setExpandedPacketId(isExpanded ? null : packet.id)}
                  className="px-4 py-2.5 cursor-pointer grid grid-cols-1 sm:grid-cols-12 gap-2 items-center"
                >
                  {/* Col 1: Time */}
                  <div className="sm:col-span-2 flex items-center gap-1.5 text-[11px] text-slate-400">
                    <ChevronRight className={`w-3.5 h-3.5 text-slate-400 transition-transform shrink-0 ${isExpanded ? 'rotate-90' : ''}`} />
                    <span>{packet.timestamp.split('T')[1]?.substring(0, 8) || packet.timestamp}</span>
                  </div>

                  {/* Col 2: Client IP */}
                  <div className="sm:col-span-3 font-bold text-white truncate">
                    {packet.srcIp}
                  </div>

                  {/* Col 3: Target Endpoint */}
                  <div className="sm:col-span-4 text-slate-300 truncate">
                    <span className="text-slate-400 font-normal">{packet.dstIp}:{packet.port}</span>
                    {packet.vectorNameEn && (
                      <span className="text-cyan-400 text-[10px] ml-1.5 hidden md:inline">
                        ({isAr ? packet.vectorNameAr : packet.vectorNameEn})
                      </span>
                    )}
                  </div>

                  {/* Col 4: Verdict Badge & Inspect */}
                  <div className="sm:col-span-3 flex items-center justify-end gap-2">
                    {getStatusBadge(packet.status)}
                    <button
                      type="button"
                      onClick={e => {
                        e.stopPropagation();
                        onInspectPacket(packet);
                      }}
                      className="px-2 py-0.5 rounded bg-purple-950/60 hover:bg-purple-900/60 text-purple-300 border border-purple-500/40 text-[10px] font-sans font-bold flex items-center gap-1 transition"
                    >
                      <Sparkles className="w-3 h-3 text-purple-400" />
                      <span>{isAr ? 'فحص' : 'Inspect'}</span>
                    </button>
                  </div>
                </div>

                {/* Expanded Packet Inspector Drawer */}
                {isExpanded && (
                  <div className="px-6 py-3 bg-slate-950/90 border-t border-slate-800/80 space-y-2.5 text-slate-300 text-[11px]">
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                      <div>
                        <span className="text-slate-500 block text-[10px]">{isAr ? 'الحمولة / الرابط المختبر:' : 'Raw Payload / Request URI:'}</span>
                        <div className="p-2 rounded bg-slate-900 border border-slate-800 text-emerald-300 break-all select-all">
                          {packet.payload || 'No payload body (TCP/DNS probe)'}
                        </div>
                      </div>
                      <div>
                        <span className="text-slate-500 block text-[10px]">{isAr ? 'السبب التكتيكي للقرار:' : 'Autonomous Defense Reason:'}</span>
                        <div className="p-2 rounded bg-slate-900 border border-slate-800 text-slate-200">
                          {packet.reason}
                        </div>
                      </div>
                    </div>

                    {/* Generated Rules Snippet */}
                    {packet.generatedRules && (
                      <div className="p-2.5 rounded-lg bg-slate-900/90 border border-slate-800 space-y-1.5">
                        <div className="flex items-center justify-between">
                          <span className="text-[10px] text-cyan-400 font-bold">IPTables & Suricata Rules Synthesized:</span>
                          <button
                            onClick={() => copyText(packet.generatedRules?.iptables || '', packet.id)}
                            className="flex items-center gap-1 text-[10px] text-slate-400 hover:text-white"
                          >
                            {copiedId === packet.id ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                            <span>{copiedId === packet.id ? 'Copied' : 'Copy'}</span>
                          </button>
                        </div>
                        <code className="text-rose-300 text-[10px] block break-all">{packet.generatedRules.iptables}</code>
                        <code className="text-amber-300 text-[10px] block break-all">{packet.generatedRules.suricata}</code>
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};
