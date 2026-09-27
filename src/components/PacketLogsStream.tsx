import React, { useState } from 'react';
import { PacketStatus, TelemetryPacket } from '../types';
import {
  Terminal,
  Shield,
  ShieldAlert,
  Sparkles,
  Radio,
  Search,
  Download,
  Trash2,
  ChevronRight,
  Eye,
  Copy,
  Check
} from 'lucide-react';

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
    const dataStr =
      'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(packets, null, 2));
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
          <span className="flex items-center gap-1 rounded border border-rose-500/40 bg-rose-500/20 px-2 py-0.5 text-[10px] font-bold text-rose-300">
            <ShieldAlert className="h-3 w-3 text-rose-400" />
            <span>BLOCKED</span>
          </span>
        );
      case 'HONEYPOT_DIVERTED':
        return (
          <span className="flex items-center gap-1 rounded border border-cyan-500/40 bg-cyan-500/20 px-2 py-0.5 text-[10px] font-bold text-cyan-300">
            <Radio className="h-3 w-3 text-cyan-400" />
            <span>HONEYPOT</span>
          </span>
        );
      case 'ANALYZED':
        return (
          <span className="flex items-center gap-1 rounded border border-cyan-500/40 bg-cyan-500/20 px-2 py-0.5 text-[10px] font-bold text-cyan-300">
            <Sparkles className="h-3 w-3 text-cyan-400" />
            <span>AI_ANALYZED</span>
          </span>
        );
      default:
        return (
          <span className="flex items-center gap-1 rounded border border-emerald-500/40 bg-emerald-500/20 px-2 py-0.5 text-[10px] font-bold text-emerald-300">
            <Shield className="h-3 w-3 text-emerald-400" />
            <span>SAFE</span>
          </span>
        );
    }
  };

  return (
    <div className="overflow-hidden rounded-2xl border border-slate-800 bg-slate-900/90 shadow-xl shadow-[0_0_20px_rgba(0,255,255,0.08)]">
      {/* Header & Controls Bar */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 bg-slate-950/60 p-4 shadow-[0_0_20px_rgba(0,255,255,0.08)]">
        <div className="flex items-center gap-2.5">
          <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/10 p-2 text-emerald-400">
            <Terminal className="h-4 w-4" />
          </div>
          <div>
            <h3 className="text-sm font-bold text-white sm:text-base">
              {isAr ? 'سجل تدفق الحزم المباشر' : 'Real-Time Telemetry Stream'}
            </h3>
            <p className="text-[11px] text-slate-400">
              {isAr
                ? 'المراقبة الحية لعمليات الفحص والحظر التلقائي'
                : 'Live stream of network requests, AI decisions, and synthesized firewall rules'}
            </p>
          </div>
        </div>

        {/* Action Buttons */}
        <div className="flex items-center gap-2">
          <button
            onClick={handleExportJson}
            className="flex items-center gap-1 rounded-lg border border-slate-700 bg-slate-800 px-3 py-1.5 text-xs font-bold text-slate-200 transition hover:bg-slate-700"
            title="Export Logs as JSON"
          >
            <Download className="h-3.5 w-3.5" />
            <span>JSON</span>
          </button>
          <button
            onClick={onClearLogs}
            className="rounded-lg border border-slate-700 bg-slate-800 p-1.5 text-slate-400 transition hover:bg-rose-950/60 hover:text-rose-400"
            title={isAr ? 'مسح السجلات' : 'Clear Telemetry'}
          >
            <Trash2 className="h-4 w-4" />
          </button>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 bg-slate-950/40 px-4 py-3 shadow-[0_0_20px_rgba(0,255,255,0.08)]">
        {/* Status Filter Pills */}
        <div className="flex flex-wrap items-center gap-1.5 text-xs font-bold">
          {['ALL', 'BLOCKED', 'HONEYPOT_DIVERTED', 'PASSED'].map(status => (
            <button
              key={status}
              onClick={() => setFilterStatus(status)}
              className={`rounded-lg px-3 py-1 transition ${
                filterStatus === status
                  ? 'border border-emerald-500/40 bg-emerald-500/20 text-emerald-300'
                  : 'bg-slate-800/80 text-slate-400 hover:text-slate-200'
              }`}
            >
              {status === 'ALL'
                ? isAr
                  ? 'الكل'
                  : 'All'
                : status === 'BLOCKED'
                  ? isAr
                    ? 'محظور ❌'
                    : 'Blocked'
                  : status === 'HONEYPOT_DIVERTED'
                    ? isAr
                      ? 'مصيدة 🍯'
                      : 'Honeypot'
                    : isAr
                      ? 'ممرر ✅'
                      : 'Safe'}
            </button>
          ))}
        </div>

        {/* Search Input */}
        <div className="relative w-full sm:w-64">
          <Search className="absolute top-2.5 left-3 h-3.5 w-3.5 text-slate-400" />
          <input
            type="text"
            value={searchQuery}
            onChange={e => setSearchQuery(e.target.value)}
            placeholder={isAr ? 'بحث بالـ IP أو الحمولة...' : 'Filter by IP, payload, vector...'}
            className="w-full rounded-lg border border-slate-800 bg-slate-950 py-1.5 pr-3 pl-8 font-mono text-xs text-white focus:border-emerald-500 focus:outline-none shadow-[0_0_20px_rgba(0,255,255,0.08)]"
          />
        </div>
      </div>

      {/* Table Header: 4 Columns (Time, Client IP, Target Endpoint, Verdict) */}
      <div className="hidden grid-cols-12 gap-2 border-b border-slate-800 bg-slate-950/80 px-4 py-2 font-mono text-[10px] font-bold tracking-wider text-slate-400 uppercase sm:grid shadow-[0_0_20px_rgba(0,255,255,0.08)]">
        <div className="col-span-2">{isAr ? 'الوقت' : 'Time'}</div>
        <div className="col-span-3">{isAr ? 'عنوان IP العميل' : 'Client IP'}</div>
        <div className="col-span-4">{isAr ? 'نقطة النهاية المستهدفة' : 'Target Endpoint'}</div>
        <div className="col-span-3 text-right">{isAr ? 'قرار الأمان' : 'Verdict'}</div>
      </div>

      {/* Logs Table Stream */}
      <div className="max-h-96 divide-y divide-slate-800/60 overflow-y-auto font-mono text-xs">
        {filteredPackets.length === 0 ? (
          <div className="py-12 text-center text-xs text-slate-500">
            {isAr
              ? 'لا توجد حزم تطابق شروط البحث الحالية.'
              : 'No telemetry packets match the active filter criteria.'}
          </div>
        ) : (
          filteredPackets.map(packet => {
            const isExpanded = expandedPacketId === packet.id;
            return (
              <div
                key={packet.uuid || `packet-${packet.id}-${packet.timestamp}`}
                className="transition hover:bg-slate-800/30"
              >
                <div
                  onClick={() => setExpandedPacketId(isExpanded ? null : packet.id)}
                  className="grid cursor-pointer grid-cols-1 items-center gap-2 px-4 py-2.5 sm:grid-cols-12"
                >
                  {/* Col 1: Time */}
                  <div className="flex items-center gap-1.5 text-[11px] text-slate-400 sm:col-span-2">
                    <ChevronRight
                      className={`h-3.5 w-3.5 shrink-0 text-slate-400 transition-transform ${isExpanded ? 'rotate-90' : ''}`}
                    />
                    <span>
                      {packet.timestamp.split('T')[1]?.substring(0, 8) || packet.timestamp}
                    </span>
                  </div>

                  {/* Col 2: Client IP */}
                  <div className="truncate font-bold text-white sm:col-span-3">{packet.srcIp}</div>

                  {/* Col 3: Target Endpoint */}
                  <div className="truncate text-slate-300 sm:col-span-4">
                    <span className="font-normal text-slate-400">
                      {packet.dstIp}:{packet.port}
                    </span>
                    {packet.vectorNameEn && (
                      <span className="ml-1.5 hidden text-[10px] text-cyan-400 md:inline">
                        ({isAr ? packet.vectorNameAr : packet.vectorNameEn})
                      </span>
                    )}
                  </div>

                  {/* Col 4: Verdict Badge & Inspect */}
                  <div className="flex items-center justify-end gap-2 sm:col-span-3">
                    {getStatusBadge(packet.status)}
                    <button
                      type="button"
                      onClick={e => {
                        e.stopPropagation();
                        onInspectPacket(packet);
                      }}
                      className="flex items-center gap-1 rounded border border-cyan-500/40 bg-cyan-950/60 px-2 py-0.5 font-sans text-[10px] font-bold text-cyan-300 transition hover:bg-cyan-900/60"
                    >
                      <Sparkles className="h-3 w-3 text-cyan-400" />
                      <span>{isAr ? 'فحص' : 'Inspect'}</span>
                    </button>
                  </div>
                </div>

                {/* Expanded Packet Inspector Drawer */}
                {isExpanded && (
                  <div className="space-y-2.5 border-t border-slate-800/80 bg-slate-950/90 px-6 py-3 text-[11px] text-slate-300 shadow-[0_0_20px_rgba(0,255,255,0.08)]">
                    <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
                      <div>
                        <span className="block text-[10px] text-slate-500">
                          {isAr ? 'الحمولة / الرابط المختبر:' : 'Raw Payload / Request URI:'}
                        </span>
                        <div className="rounded border border-slate-800 bg-slate-900 p-2 break-all text-emerald-300 select-all shadow-[0_0_20px_rgba(0,255,255,0.08)]">
                          {packet.payload || 'No payload body (TCP/DNS probe)'}
                        </div>
                      </div>
                      <div>
                        <span className="block text-[10px] text-slate-500">
                          {isAr ? 'السبب التكتيكي للقرار:' : 'Autonomous Defense Reason:'}
                        </span>
                        <div className="rounded border border-slate-800 bg-slate-900 p-2 text-slate-200 shadow-[0_0_20px_rgba(0,255,255,0.08)]">
                          {packet.reason}
                        </div>
                      </div>
                    </div>

                    {/* Generated Rules Snippet */}
                    {packet.generatedRules && (
                      <div className="space-y-1.5 rounded-lg border border-slate-800 bg-slate-900/90 p-2.5 shadow-[0_0_20px_rgba(0,255,255,0.08)]">
                        <div className="flex items-center justify-between">
                          <span className="text-[10px] font-bold text-cyan-400">
                            IPTables & Suricata Rules Synthesized:
                          </span>
                          <button
                            onClick={() =>
                              copyText(packet.generatedRules?.iptables || '', packet.id)
                            }
                            className="flex items-center gap-1 text-[10px] text-slate-400 hover:text-white"
                          >
                            {copiedId === packet.id ? (
                              <Check className="h-3 w-3 text-emerald-400" />
                            ) : (
                              <Copy className="h-3 w-3" />
                            )}
                            <span>{copiedId === packet.id ? 'Copied' : 'Copy'}</span>
                          </button>
                        </div>
                        <code className="block text-[10px] break-all text-rose-300">
                          {packet.generatedRules.iptables}
                        </code>
                        <code className="block text-[10px] break-all text-amber-300">
                          {packet.generatedRules.suricata}
                        </code>
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
