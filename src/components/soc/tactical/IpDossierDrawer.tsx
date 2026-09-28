import React from 'react';
import { motion, useReducedMotion } from 'motion/react';
import { X, Copy, Check, ShieldOff, ShieldCheck } from 'lucide-react';
import { CyberButton } from './CyberButton';
import { classifyIp, type IpClass } from './ipDossier';
import { useIpHistory } from './useIpHistory';
import type { useArsenal } from './useArsenal';
import type { Containment } from './useContainment';
import type { LanWatch } from './useLanWatch';
import type { AssetRow } from './useAssets';

type Arsenal = ReturnType<typeof useArsenal>;

export interface DossierAlert {
  at: string;
  severity: string;
  mitre: string | null;
  title: string;
  srcIp: string | null;
  action: string | null;
}

/**
 * IP DOSSIER — one address, every source, one place.
 *
 * Each section is a source, and each says where it came from. A source with nothing on
 * this address is listed as silent in one quiet line, not hidden: "the IOC store has
 * nothing" is a finding, and an operator deciding whether to isolate needs to know which
 * sources were asked.
 *
 * The opening "target lock" is four brackets closing onto the address — 280 ms, once,
 * and absent under reduced motion. It marks which address the whole panel is about.
 */

const CLASS_LABEL: Record<IpClass, [string, string, string]> = {
  LOOPBACK: ['حلقة محلية', 'LOOPBACK', '#94a3b8'],
  LAN: ['شبكة داخلية', 'LAN · RFC 1918', '#22d3ee'],
  LINK_LOCAL: ['رابط محلي', 'LINK-LOCAL', '#94a3b8'],
  CARRIER_NAT: ['NAT مزوّد', 'CARRIER NAT', '#94a3b8'],
  DOCUMENTATION: ['نطاق توثيق — بيانات تجريبية', 'DOCUMENTATION RANGE — FIXTURE', '#94a3b8'],
  PUBLIC: ['عنوان عام', 'PUBLIC', '#fbbf24'],
  UNKNOWN: ['غير معروف', 'UNKNOWN', '#94a3b8']
};

const Section: React.FC<{ title: string; source: string; empty?: string | null; children?: React.ReactNode }> = ({ title, source, empty, children }) => (
  <section className="border-t border-cyan-900/50 pt-2">
    <div className="flex items-baseline justify-between gap-2">
      <h3 className="text-xs font-semibold text-cyan-100">{title}</h3>
      <span className="font-mono text-[10px] text-slate-500" dir="ltr">{source}</span>
    </div>
    {empty ? <p className="mt-0.5 text-[11px] text-slate-400">{empty}</p> : <div className="mt-1 space-y-1">{children}</div>}
  </section>
);

export const IpDossierDrawer: React.FC<{
  ip: string;
  isAr: boolean;
  alerts: DossierAlert[];
  a: Arsenal;
  c: Containment;
  lan: LanWatch;
  assets: AssetRow[];
  canAct: boolean;
  onRequestIsolate?: (ip: string, context: string | null) => void;
  onClose: () => void;
}> = ({ ip, isAr, alerts, a, c, lan, assets, canAct, onRequestIsolate, onClose }) => {
  const reduce = useReducedMotion() ?? false;
  const h = useIpHistory(ip, canAct);
  const [copied, setCopied] = React.useState(false);
  const cls = classifyIp(ip);
  const [clsAr, clsEn, clsTone] = CLASS_LABEL[cls];

  React.useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && onClose();
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);

  const live = alerts.filter(x => x.srcIp === ip);
  const critical = live.filter(x => /CRITICAL|HIGH/.test(x.severity)).length;
  const iocs = a.intel.iocs.filter(i => i.value === ip);
  const containment = c.records.filter(r => r.ip === ip);
  const active = containment.find(r => r.active) ?? null;
  const decoy = a.intel.sessions.filter(s => s.ip === ip);
  const shadow = a.intel.shadow.actors.filter(s => s.ip === ip);
  const device = lan.status?.devices.find(d => d.ips.includes(ip)) ?? null;
  const asset = assets.find(x => x.primaryIp === ip) ?? null;
  const history = h.memory?.sameActor ?? [];

  const nothingAnywhere =
    live.length === 0 && iocs.length === 0 && !h.memory?.iocHit && history.length === 0 && containment.length === 0 && decoy.length === 0 && shadow.length === 0 && !device && !asset;

  const isolatable = cls !== 'LOOPBACK' && cls !== 'UNKNOWN' && !active;
  const lastTechnique = live.find(x => x.mitre)?.mitre ?? null;

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(ip);
      setCopied(true);
      setTimeout(() => setCopied(false), 1200);
    } catch {
      /* the address stays selectable */
    }
  };

  const bracket = (pos: 'tl' | 'tr' | 'bl' | 'br') => {
    const off = 10;
    const from = { x: pos[1] === 'l' ? -off : off, y: pos[0] === 't' ? -off : off, opacity: 0 };
    return (
      <motion.span
        key={pos}
        aria-hidden
        className="pointer-events-none absolute h-3 w-3"
        style={{
          top: pos[0] === 't' ? 0 : undefined,
          bottom: pos[0] === 'b' ? 0 : undefined,
          left: pos[1] === 'l' ? 0 : undefined,
          right: pos[1] === 'r' ? 0 : undefined,
          borderTop: pos[0] === 't' ? '2px solid #22d3ee' : undefined,
          borderBottom: pos[0] === 'b' ? '2px solid #22d3ee' : undefined,
          borderLeft: pos[1] === 'l' ? '2px solid #22d3ee' : undefined,
          borderRight: pos[1] === 'r' ? '2px solid #22d3ee' : undefined
        }}
        initial={reduce ? false : from}
        animate={{ x: 0, y: 0, opacity: 1 }}
        transition={{ duration: 0.28, ease: 'easeOut' }}
      />
    );
  };

  return (
    <aside
      className="absolute inset-y-0 end-0 z-40 flex w-[400px] max-w-full flex-col border-s border-cyan-500/40 bg-[#030712]/95 shadow-[0_0_40px_rgba(0,0,0,0.9)] backdrop-blur-2xl"
      role="dialog"
      aria-label={isAr ? `ملف العنوان ${ip}` : `Dossier for ${ip}`}
      dir={isAr ? 'rtl' : 'ltr'}
    >
      {/* Target lock */}
      <div className="flex items-start gap-2 border-b border-cyan-900/60 p-3">
        <div className="relative px-3 py-2">
          {(['tl', 'tr', 'bl', 'br'] as const).map(bracket)}
          <p className="font-mono text-lg font-bold text-white" dir="ltr" style={{ textShadow: '0 0 12px rgba(34,211,238,0.7)' }}>
            {ip}
          </p>
        </div>
        <div className="min-w-0 flex-1 pt-1">
          <p className="font-mono text-[10px] tracking-widest" style={{ color: clsTone }}>
            {isAr ? clsAr : clsEn}
          </p>
          <p className="mt-0.5 flex flex-wrap gap-x-2 text-[11px]">
            {active ? (
              <span className="flex items-center gap-1 text-rose-300">
                <ShieldOff className="h-3 w-3" aria-hidden />
                {isAr ? 'محتوى' : 'CONTAINED'}
              </span>
            ) : (
              <span className="flex items-center gap-1 text-slate-400">
                <ShieldCheck className="h-3 w-3" aria-hidden />
                {isAr ? 'غير محتوى' : 'not contained'}
              </span>
            )}
            {critical > 0 && <span className="text-rose-300">{critical} {isAr ? 'تنبيه حرج' : 'critical alerts'}</span>}
          </p>
        </div>
        <button type="button" onClick={onClose} aria-label={isAr ? 'إغلاق' : 'Close'} className="p-1 text-slate-400 hover:text-cyan-300">
          <X className="h-4 w-4" aria-hidden />
        </button>
      </div>

      <div className="min-h-0 flex-1 space-y-2.5 overflow-y-auto p-3">
        {nothingAnywhere && h.memory && (
          <p className="border border-cyan-900/50 bg-black/40 p-2 text-xs text-slate-300">
            {isAr ? 'لا يملك أي مصدر في المنصّة شيئًا عن هذا العنوان.' : 'No source on the platform has anything on this address.'}
          </p>
        )}

        <Section
          title={isAr ? 'تنبيهات حيّة' : 'Live alerts'}
          source="/soc/unified-telemetry"
          empty={live.length === 0 ? (isAr ? 'لا تنبيهات من هذا المصدر.' : 'no alerts from this source.') : null}
        >
          {live.slice(0, 8).map((x, i) => (
            <p key={i} className="flex items-baseline gap-2 text-[11px]">
              <span className="font-mono text-slate-400" dir="ltr">{x.at.slice(11, 19)}</span>
              <span className={/CRITICAL|HIGH/.test(x.severity) ? 'text-rose-300' : 'text-cyan-300'}>{x.severity.slice(0, 4)}</span>
              <span className={x.mitre ? 'font-mono text-cyan-300' : 'font-mono text-slate-500'}>{x.mitre ?? 'UNMAPPED'}</span>
              <span className="min-w-0 flex-1 truncate text-slate-200" title={x.title} dir="auto">{x.title}</span>
            </p>
          ))}
        </Section>

        <Section
          title={isAr ? 'الاستخبارات' : 'Intelligence'}
          source="/forensics/threat-intel/iocs · /memory"
          empty={iocs.length === 0 && !h.memory?.iocHit ? (h.memory ? (isAr ? 'غير مدرج في مخزن المؤشرات.' : 'not in the indicator store.') : '…') : null}
        >
          {iocs.map(i => (
            <p key={i.id} className="text-[11px] text-slate-200">
              <span className="font-mono text-rose-300">{i.score ?? '—'}</span> · {i.actor ?? '—'} · {i.family ?? '—'}{' '}
              <span className="font-mono text-cyan-300">{i.technique ?? 'UNMAPPED'}</span>
            </p>
          ))}
          {h.memory?.iocHit && (
            <p className="text-[11px] text-slate-200">
              {h.memory.iocHit.category} · {isAr ? 'ثقة' : 'confidence'} {h.memory.iocHit.confidence} · {h.memory.iocHit.sightings}{' '}
              {isAr ? 'مشاهدة' : 'sightings'} · <span className="font-mono text-slate-400">{h.memory.iocHit.source}</span>
            </p>
          )}
        </Section>

        <Section
          title={isAr ? 'السجل التاريخي' : 'History'}
          source="/memory/context"
          empty={h.memory && history.length === 0 ? (isAr ? `لا حوادث سابقة في ذاكرة التهديد (${h.memory.totalCorpus} حادثة).` : `no prior incidents in threat memory (${h.memory.totalCorpus} on file).`) : !h.memory ? '…' : null}
        >
          {history.slice(0, 5).map(x => (
            <p key={x.id} className="flex items-baseline gap-2 text-[11px]">
              <span className="font-mono text-slate-400" dir="ltr">{x.timestamp.slice(0, 10)}</span>
              <span className="min-w-0 flex-1 truncate text-slate-200" title={x.title} dir="auto">{x.title}</span>
              <span className="font-mono text-cyan-300">{x.mitreTechnique?.split(' ')[0] ?? 'UNMAPPED'}</span>
            </p>
          ))}
          {history.length > 5 && <p className="text-[10px] text-slate-400">+{history.length - 5}</p>}
        </Section>

        <Section
          title={isAr ? 'الخداع' : 'Deception'}
          source="/honeypot · /soc/deception"
          empty={decoy.length === 0 && shadow.length === 0 ? (isAr ? 'لم يلمس أي فخ.' : 'has not touched a decoy.') : null}
        >
          {decoy.map(s => (
            <p key={s.id} className="text-[11px] text-slate-200">
              {s.service} · {s.keystrokes ?? '—'} ks · {s.canaries} canary
              {cls === 'DOCUMENTATION' && <span className="ms-1 text-slate-400">(FIXTURE)</span>}
            </p>
          ))}
          {shadow.map(s => (
            <p key={s.id} className="text-[11px] text-amber-200">
              {isAr ? 'حُوِّل إلى الموجّه الظلّي' : 'diverted by the shadow router'} · ×{s.interactions ?? '—'} · {s.band ?? '—'}
            </p>
          ))}
        </Section>

        <Section
          title={isAr ? 'على شبكتك' : 'On your network'}
          source="/lan-watch · /assets"
          empty={!device && !asset ? (isAr ? 'ليس جهازًا مرصودًا على شبكتك.' : 'not a device observed on your network.') : null}
        >
          {asset && (
            <p className="text-[11px] text-cyan-200">
              {isAr ? 'مضيف مسجّل' : 'enrolled host'}: <span className="font-mono">{asset.label}</span> · {asset.liveness}
            </p>
          )}
          {device && (
            <p className="text-[11px] text-slate-200">
              <span className="font-mono" dir="ltr">{device.mac}</span> · {device.vendor ?? (isAr ? 'مُصنِّع مجهول' : 'unknown vendor')} ·{' '}
              <span className={device.state === 'NEW' ? 'text-amber-300' : 'text-slate-400'}>{device.state}</span> ·{' '}
              <span className="font-mono text-slate-400" dir="ltr">{device.firstSeen.slice(0, 10)}</span>
            </p>
          )}
        </Section>

        <Section
          title={isAr ? 'الاحتواء' : 'Containment'}
          source="/soc/ebpf/containment-records"
          empty={containment.length === 0 ? (isAr ? 'لم يُعزل قط.' : 'never contained.') : null}
        >
          {containment.slice(0, 4).map(r => (
            <p key={r.id} className="text-[11px] text-slate-200">
              <span className={r.active ? 'text-rose-300' : 'text-slate-400'}>{r.active ? 'ACTIVE' : 'RELEASED'}</span> ·{' '}
              <span className="font-mono" dir="ltr">{r.at?.slice(0, 16) ?? '—'}</span> · {r.ioc ?? '—'}
              {r.seeded && <span className="ms-1 text-slate-400">(SEEDED)</span>}
            </p>
          ))}
        </Section>

        {canAct && (
          <Section
            title={isAr ? 'ما فعله المشغّلون' : 'What operators did'}
            source="/audit"
            empty={h.audit && h.audit.length === 0 ? (isAr ? 'لا إجراءات مسجّلة على هذا العنوان.' : 'no recorded action on this address.') : !h.audit ? '…' : null}
          >
            {(h.audit ?? []).slice(0, 6).map(e => (
              <p key={e.seq} className="flex items-baseline gap-2 text-[11px]">
                <span className="font-mono text-slate-400" dir="ltr">{e.at.slice(5, 16)}</span>
                <span className="font-mono text-cyan-300">{e.action}</span>
                <span className="font-mono text-slate-200">{e.actor}</span>
                <span className={e.outcome === 'SUCCESS' ? 'text-emerald-300' : 'text-amber-300'}>{e.outcome}</span>
              </p>
            ))}
          </Section>
        )}

        {h.errors.length > 0 && (
          <p className="font-mono text-[10px] text-amber-300" dir="ltr">{h.errors.join(' · ')}</p>
        )}
      </div>

      <div className="flex flex-wrap gap-2 border-t border-cyan-900/60 p-3">
        {isolatable && (
          <CyberButton
            tone="rose"
            size="sm"
            disabled={!canAct || !onRequestIsolate}
            title={!canAct ? (isAr ? 'يتطلّب دور محلّل' : 'requires the ANALYST role') : undefined}
            onClick={() => onRequestIsolate?.(ip, lastTechnique ? `${lastTechnique} · ${live.length} alert(s)` : null)}
          >
            [ ISOLATE_NODE ]
          </CyberButton>
        )}
        {active && (
          <CyberButton
            tone="emerald"
            size="sm"
            disabled={!canAct || c.busyIp === ip}
            title={!canAct ? (isAr ? 'يتطلّب دور محلّل' : 'requires the ANALYST role') : undefined}
            onClick={() => void c.release(ip)}
          >
            {isAr ? 'فك العزل' : 'RELEASE'}
          </CyberButton>
        )}
        <button
          type="button"
          onClick={() => void copy()}
          className="ms-auto flex items-center gap-1 border border-cyan-800/60 px-2 py-1 text-[11px] text-cyan-300 hover:bg-cyan-500/10"
        >
          {copied ? <Check className="h-3 w-3" aria-hidden /> : <Copy className="h-3 w-3" aria-hidden />}
          {isAr ? 'نسخ' : 'Copy'}
        </button>
      </div>
    </aside>
  );
};

export default IpDossierDrawer;
