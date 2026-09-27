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

export const FimForensicsCenter: React.FC<FimForensicsCenterProps> = ({
  lang,
  onSimulateVector
}) => {
  const isAr = lang === 'ar';
  const [activeTab, setActiveTab] = useState<'FIM_WATCHER' | 'NETWORK_FORENSICS'>('FIM_WATCHER');

  return (
    <div className="space-y-6" dir={isAr ? 'rtl' : 'ltr'}>
      {/* Top Header & View Selector */}
      <div className="relative overflow-hidden rounded-2xl border border-slate-800 bg-slate-900 p-5 shadow-xl sm:p-6 shadow-[0_0_20px_rgba(0,255,255,0.08)]">
        <div className="relative z-10 flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
          <div className="flex items-start gap-4">
            <div className="shrink-0 rounded-xl border border-cyan-400/30 bg-gradient-to-br from-cyan-600 to-cyan-700 p-3 text-white shadow-lg shadow-cyan-950/60">
              <FileSearch className="h-6 w-6" />
            </div>
            <div>
              <div className="flex flex-wrap items-center gap-2.5">
                <h1 className="text-xl font-black tracking-tight text-white sm:text-2xl">
                  {isAr
                    ? 'مركز سلامة الملفات والتحليل الجنائي الرقمي'
                    : 'File Integrity (FIM) & Digital Forensics'}
                </h1>
                <span className="flex items-center gap-1.5 rounded-full border border-cyan-500/40 bg-cyan-500/20 px-2.5 py-0.5 font-mono text-xs font-bold text-cyan-300">
                  <ShieldCheck className="h-3.5 w-3.5 text-cyan-400" />
                  {isAr ? 'مُفعّل (Merkle Tree)' : 'MERKLE TREE ACTIVE'}
                </span>
              </div>
              <p className="mt-1 max-w-2xl text-xs text-slate-400 sm:text-sm">
                {isAr
                  ? 'مراقبة التعديل الخبيث على ملفات النظام والشفرات المصدرية، شجرة العمليات بالذاكرة، وفحص حزم PCAP الجنائية.'
                  : 'Cryptographic file tampering detection, side-by-side code diffing, memory process inspection, and network PCAP timeline analysis.'}
              </p>
            </div>
          </div>

          {/* Sub-View Navigation Pills */}
          <div className="flex shrink-0 items-center gap-2 rounded-xl border border-slate-800 bg-slate-950/80 p-1.5 shadow-[0_0_20px_rgba(0,255,255,0.08)]">
            <button
              onClick={() => setActiveTab('FIM_WATCHER')}
              className={`flex items-center gap-2 rounded-lg px-3.5 py-2 text-xs font-bold transition ${
                activeTab === 'FIM_WATCHER'
                  ? 'border border-cyan-400/60 bg-gradient-to-r from-cyan-600/40 to-cyan-600/40 text-cyan-200 shadow-lg'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <FileCode className="h-4 w-4 text-cyan-400" />
              <span>
                {isAr ? 'سلامة الملفات والذاكرة (FIM)' : 'File Integrity & Process Memory'}
              </span>
            </button>

            <button
              onClick={() => setActiveTab('NETWORK_FORENSICS')}
              className={`flex items-center gap-2 rounded-lg px-3.5 py-2 text-xs font-bold transition ${
                activeTab === 'NETWORK_FORENSICS'
                  ? 'border border-cyan-400/60 bg-gradient-to-r from-cyan-600/40 to-emerald-600/40 text-cyan-200 shadow-lg'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Activity className="h-4 w-4 text-cyan-400" />
              <span>{isAr ? 'خزينة الأدلة الجنائية (PCAP)' : 'Forensics Vault & PCAP'}</span>
            </button>
          </div>
        </div>
      </div>

      {/* Main Content Pane */}
      {activeTab === 'FIM_WATCHER' && <FileIntegrityProcessPanel lang={lang} />}

      {activeTab === 'NETWORK_FORENSICS' && (
        <ForensicsVault lang={lang} onSimulateVector={onSimulateVector} />
      )}
    </div>
  );
};
