import React from 'react';
import { Cpu, ShieldCheck, Eye, FileLock2, Bot, Ban, Activity } from 'lucide-react';

/**
 * DEFENSE-IN-DEPTH PANEL
 *
 * Presents the protection stack the way a defender reasons about it: ordered
 * from the wire inward, each layer stating what it stops, where it runs, and
 * how much it is currently absorbing. The bar is a share-of-traffic readout,
 * so a reviewer can see at a glance that the cheapest layer (kernel) is doing
 * the heaviest lifting — which is the whole architectural argument.
 */

interface Layer {
  id: string;
  nameAr: string;
  nameEn: string;
  whereAr: string;
  whereEn: string;
  stopsAr: string;
  stopsEn: string;
  icon: React.ElementType;
  /** Share of hostile traffic terminated at this layer (%) */
  share: number;
  latency: string;
  active: boolean;
}

const LAYERS: Layer[] = [
  {
    id: 'xdp',
    nameAr: 'فلترة النواة eBPF / XDP',
    nameEn: 'eBPF / XDP Kernel Filter',
    whereAr: 'بطاقة الشبكة — قبل نواة النظام',
    whereEn: 'NIC driver — before the kernel stack',
    stopsAr: 'الفيضانات الحجمية، القوائم السوداء، SYN Flood',
    stopsEn: 'Volumetric floods, blacklists, SYN flood',
    icon: Cpu,
    share: 96.5,
    latency: '0.3 µs',
    active: true
  },
  {
    id: 'waf',
    nameAr: 'جدار حماية التطبيقات WAF',
    nameEn: 'Application Firewall (WAF)',
    whereAr: 'طبقة 7 — بوابة الدخول',
    whereEn: 'Layer 7 — ingress gateway',
    stopsAr: 'حقن SQL، XSS، تجاوز المسار',
    stopsEn: 'SQL injection, XSS, path traversal',
    icon: ShieldCheck,
    share: 2.4,
    latency: '1.2 ms',
    active: true
  },
  {
    id: 'dpi',
    nameAr: 'الفحص العميق للحمولات',
    nameEn: 'Deep Payload Inspection',
    whereAr: 'قبل الوصول للتخزين',
    whereEn: 'Pre-storage, in-transit',
    stopsAr: 'الملفات المموّهة، الأصداف العكسية',
    stopsEn: 'Polyglot files, web shells',
    icon: Eye,
    share: 0.6,
    latency: '4 ms',
    active: true
  },
  {
    id: 'fim',
    nameAr: 'مراقبة سلامة الملفات FIM',
    nameEn: 'File Integrity Monitoring',
    whereAr: 'نظام الملفات — لحظي',
    whereEn: 'Filesystem — event driven',
    stopsAr: 'الأبواب الخلفية، تعديل الصلاحيات، الفدية',
    stopsEn: 'Backdoors, privilege edits, ransomware',
    icon: FileLock2,
    share: 0.3,
    latency: '< 100 ms',
    active: true
  },
  {
    id: 'deception',
    nameAr: 'الخداع النشط والمصائد',
    nameEn: 'Active Deception / Tarpit',
    whereAr: 'شبكة معزولة موازية',
    whereEn: 'Isolated parallel network',
    stopsAr: 'الاستطلاع، مسح المنافذ، حركة جانبية',
    stopsEn: 'Recon, port scans, lateral movement',
    icon: Bot,
    share: 0.15,
    latency: '—',
    active: true
  },
  {
    id: 'dlp',
    nameAr: 'منع تسريب البيانات DLP',
    nameEn: 'Data Loss Prevention',
    whereAr: 'حركة الخروج',
    whereEn: 'Egress path',
    stopsAr: 'سحب البيانات، قنوات C2 المشفّرة',
    stopsEn: 'Exfiltration, encrypted C2 channels',
    icon: Ban,
    share: 0.05,
    latency: '2 ms',
    active: true
  }
];

interface Props {
  lang?: 'ar' | 'en';
}

export const DefenseLayersPanel: React.FC<Props> = ({ lang = 'ar' }) => {
  const isAr = lang === 'ar';

  return (
    <section className="soc-panel p-5" dir={isAr ? 'rtl' : 'ltr'}>
      <div className="mb-5">
        <h2 className="text-base font-bold text-slate-100">
          {isAr ? 'طبقات الحماية المتعمّقة' : 'Defense-in-Depth Layers'}
        </h2>
        <p className="mt-1 text-xs leading-relaxed text-slate-400">
          {isAr
            ? 'مرتّبة من الشبكة إلى الداخل — ونسبة ما توقفه كل طبقة من الحركة العدائية.'
            : 'Ordered from the wire inward — and the share of hostile traffic each layer terminates.'}
        </p>
      </div>

      <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-3 2xl:grid-cols-6">
        {LAYERS.map((l, idx) => {
          const Icon = l.icon;
          return (
            <div
              key={l.id}
              className="flex flex-col rounded-lg border border-slate-800 bg-slate-900/50 p-3.5 transition-colors hover:border-slate-700 shadow-[0_0_20px_rgba(0,255,255,0.08)]"
            >
              {/* depth index + live state */}
              <div className="mb-2.5 flex items-center justify-between">
                <span className="rounded border border-slate-700 bg-slate-800 px-1.5 py-0.5 font-mono text-[10px] text-slate-400">
                  L{idx + 1}
                </span>
                {l.active && (
                  <span className="inline-flex items-center gap-1 text-[10px] font-semibold text-emerald-400">
                    <span className="h-1.5 w-1.5 rounded-full bg-emerald-500" />
                    {isAr ? 'نشطة' : 'Active'}
                  </span>
                )}
              </div>

              {/* identity */}
              <div className="mb-1 flex items-start gap-2">
                <Icon className="mt-0.5 h-4 w-4 shrink-0 text-cyan-400" />
                <span className="text-[13px] leading-snug font-semibold text-slate-100">
                  {isAr ? l.nameAr : l.nameEn}
                </span>
              </div>

              <div className="mb-2 text-[11px] text-slate-500">{isAr ? l.whereAr : l.whereEn}</div>

              <div className="mb-3 flex-1 text-[11px] leading-snug text-slate-300">
                <span className="text-slate-500">{isAr ? 'يوقف: ' : 'Stops: '}</span>
                {isAr ? l.stopsAr : l.stopsEn}
              </div>

              {/* share of hostile traffic terminated here */}
              <div className="mt-auto border-t border-slate-800 pt-2.5">
                <div className="mb-1.5 flex items-baseline justify-between">
                  <span className="font-mono text-base font-bold text-slate-100 tabular-nums">
                    {l.share}%
                  </span>
                  <span className="flex items-center gap-1 font-mono text-[10px] text-slate-500">
                    <Activity className="h-3 w-3" />
                    {l.latency}
                  </span>
                </div>
                <div className="h-1.5 overflow-hidden rounded-full bg-slate-800">
                  <div
                    className="h-full rounded-full bg-cyan-500/70"
                    style={{ width: `${Math.max(l.share, 2)}%` }}
                  />
                </div>
              </div>
            </div>
          );
        })}
      </div>

      <p className="mt-4 text-[11px] leading-relaxed text-slate-500">
        {isAr
          ? 'الطبقة الأولى (النواة) تستوعب 96.5% من الحركة العدائية بتكلفة معالجة شبه معدومة، فلا تصل إلا البقية للطبقات الأغلى.'
          : 'The kernel layer absorbs 96.5% of hostile traffic at near-zero CPU cost, so only the remainder ever reaches the expensive layers.'}
      </p>
    </section>
  );
};
