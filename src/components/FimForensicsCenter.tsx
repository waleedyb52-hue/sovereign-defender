import React, { useState } from 'react';
import {
  ShieldCheck,
  FileCode,
  Cpu,
  FileSearch,
  Box,
  RotateCcw,
  Sparkles,
  Layers,
  Search,
  CheckCircle2,
  Lock,
  Terminal,
  Activity,
  Zap,
  Eye,
  X,
  Copy,
  Check
} from 'lucide-react';
import { FileIntegrityProcessPanel } from './soc/FileIntegrityProcessPanel';
import { ForensicsVault } from './ForensicsVault';
import { AttackVectorType } from '../types';

interface FimForensicsCenterProps {
  lang: 'ar' | 'en';
  onSimulateVector?: (vector: AttackVectorType) => void;
}

export const FimForensicsCenter: React.FC<FimForensicsCenterProps> = ({ lang, onSimulateVector }) => {
  const isAr = lang === 'ar';
  const [activeTab, setActiveTab] = useState<'FIM_WATCHER' | 'NETWORK_FORENSICS'>('FIM_WATCHER');

  return (
    <div className="space-y-6" dir={isAr ? 'rtl' : 'ltr'}>
      {/* Top Header & View Selector */}
      <div className="relative overflow-hidden rounded-2xl bg-slate-900 border border-slate-800 p-5 sm:p-6 shadow-xl">
        <div className="relative z-10 flex flex-col md:flex-row md:items-center md:justify-between gap-4">
          <div className="flex items-start gap-4">
            <div className="p-3 rounded-xl bg-gradient-to-br from-indigo-600 to-cyan-700 text-white shadow-lg shadow-indigo-950/60 border border-indigo-400/30 shrink-0">
              <FileSearch className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center gap-2.5 flex-wrap">
                <h1 className="text-xl sm:text-2xl font-black text-white tracking-tight">
                  {isAr ? 'مركز سلامة الملفات والتحليل الجنائي الرقمي' : 'File Integrity (FIM) & Digital Forensics'}
                </h1>
                <span className="px-2.5 py-0.5 text-xs font-mono font-bold rounded-full bg-indigo-500/20 text-indigo-300 border border-indigo-500/40 flex items-center gap-1.5">
                  <ShieldCheck className="w-3.5 h-3.5 text-indigo-400" />
                  {isAr ? 'مُفعّل (Merkle Tree)' : 'MERKLE TREE ACTIVE'}
                </span>
              </div>
              <p className="text-xs sm:text-sm text-slate-400 mt-1 max-w-2xl">
                {isAr
                  ? 'مراقبة التعديل الخبيث على ملفات النظام والشفرات المصدرية، شجرة العمليات بالذاكرة، وفحص حزم PCAP الجنائية.'
                  : 'Cryptographic file tampering detection, side-by-side code diffing, memory process inspection, and network PCAP timeline analysis.'}
              </p>
            </div>
          </div>

          {/* Sub-View Navigation Pills */}
          <div className="flex items-center gap-2 bg-slate-950/80 p-1.5 rounded-xl border border-slate-800 shrink-0">
            <button
              onClick={() => setActiveTab('FIM_WATCHER')}
              className={`flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-bold transition ${
                activeTab === 'FIM_WATCHER'
                  ? 'bg-gradient-to-r from-indigo-600/40 to-cyan-600/40 text-indigo-200 border border-indigo-400/60 shadow-lg'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <FileCode className="w-4 h-4 text-indigo-400" />
              <span>{isAr ? 'سلامة الملفات والذاكرة (FIM)' : 'File Integrity & Process Memory'}</span>
            </button>

            <button
              onClick={() => setActiveTab('NETWORK_FORENSICS')}
              className={`flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-bold transition ${
                activeTab === 'NETWORK_FORENSICS'
                  ? 'bg-gradient-to-r from-cyan-600/40 to-emerald-600/40 text-cyan-200 border border-cyan-400/60 shadow-lg'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Activity className="w-4 h-4 text-cyan-400" />
              <span>{isAr ? 'خزينة الأدلة الجنائية (PCAP)' : 'Forensics Vault & PCAP'}</span>
            </button>
          </div>
        </div>
      </div>

      {/* Main Content Pane */}
      {activeTab === 'FIM_WATCHER' && (
        <FileIntegrityProcessPanel lang={lang} />
      )}

      {activeTab === 'NETWORK_FORENSICS' && (
        <ForensicsVault lang={lang} onSimulateVector={onSimulateVector} />
      )}
    </div>
  );
};
