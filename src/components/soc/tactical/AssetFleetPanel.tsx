import React from 'react';
import { Server, Network, Plus, Copy, ShieldOff, ShieldCheck, Trash2, X } from 'lucide-react';
import { CyberButton, ArsenalCard } from './CyberButton';
import type { AssetRow, useAssets } from './useAssets';

type Fleet = ReturnType<typeof useAssets>;

/**
 * ASSET FLEET — the panel that makes the platform point at real hardware.
 *
 * Enrolment is the workflow that was missing entirely. An operator mints a single-use
 * token here, copies one command, runs it on the machine they want watched, and that
 * machine appears in this list with its measured posture and its flows in the detection
 * pipeline. No device is ever listed that did not enrol itself.
 *
 * The empty state says how to add a host rather than apologising for having none. That
 * is the difference between a console that looks broken and one that is waiting — and
 * showing sample hosts to avoid an empty panel would be the worst option of the three,
 * because an operator would not know which entries are theirs.
 */

const LIVENESS: Record<AssetRow['liveness'], { tone: string; ar: string; en: string }> = {
  ONLINE: { tone: '#34d399', ar: 'متّصل', en: 'ONLINE' },
  STALE: { tone: '#fbbf24', ar: 'متأخّر', en: 'STALE' },
  OFFLINE: { tone: '#e11d48', ar: 'منقطع', en: 'OFFLINE' },
  NEVER_REPORTED: { tone: '#64748b', ar: 'لم يُبلّغ', en: 'NO REPORT' }
};

export const AssetFleetPanel: React.FC<{
  f: Fleet;
  isAr: boolean;
  onSelect: (a: AssetRow) => void;
}> = ({ f, isAr, onSelect }) => {
  const [cidr, setCidr] = React.useState('');
  const [copied, setCopied] = React.useState(false);
  const cidrValid = /^(\d{1,3}\.){3}\d{1,3}\/(\d|[12]\d|3[0-2])$/.test(cidr.trim());

  const copy = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Clipboard is permission-gated and blocked in some contexts. The command stays
      // selectable on screen, so a failed copy costs convenience, not the workflow.
      setCopied(false);
    }
  };

  return (
    <ArsenalCard
      title={isAr ? 'أسطول الأصول' : 'ASSET FLEET'}
      icon={Server}
      tone={f.summary && f.summary.offline > 0 ? 'rose' : 'cyan'}
      alert={Boolean(f.summary && f.summary.offline > 0)}
      defaultOpen
      headline={
        f.summary ? (
          <span className="font-mono text-[9px] font-bold">
            <span className="text-emerald-400">{f.summary.online}</span>
            <span className="text-slate-600">/</span>
            <span className="text-cyan-400">{f.summary.hosts}</span>
          </span>
        ) : (
          <span className="font-mono text-[9px] text-slate-700">—</span>
        )
      }
    >
      {f.unreachable ? (
        <p className="py-2 font-mono text-[7px] leading-relaxed text-rose-400">
          {isAr
            ? 'تعذّر الوصول إلى /api/v1/assets — لا حكم على وجود أصول.'
            : '/api/v1/assets unreachable — no claim about enrolled assets.'}
        </p>
      ) : (
        <>
          {/* Durability warning. A fleet that will vanish must say so. */}
          {f.summary && !f.summary.durable && (
            <p className="mb-1.5 font-mono text-[6.5px] leading-relaxed text-amber-400">
              {isAr
                ? 'السجلّ في الذاكرة فقط — مجلّد data غير قابل للكتابة، والأسطول يضيع عند إعادة التشغيل.'
                : 'registry is in-memory — the data directory is unwritable and the fleet will not survive a restart.'}
            </p>
          )}

          {f.summary && (
            <div className="mb-1.5 flex flex-wrap gap-x-3 gap-y-0.5">
              {(
                [
                  [isAr ? 'أجهزة' : 'HOSTS', f.summary.hosts, '#22d3ee'],
                  [isAr ? 'شبكات' : 'NETWORKS', f.summary.networks, '#22d3ee'],
                  [isAr ? 'متأخّر' : 'STALE', f.summary.stale, '#fbbf24'],
                  [isAr ? 'منقطع' : 'OFFLINE', f.summary.offline, '#e11d48'],
                  [isAr ? 'معزول' : 'ISOLATED', f.summary.isolated, '#e11d48'],
                  [isAr ? 'تدفّقات' : 'FLOWS', f.summary.flowsIngested, '#34d399']
                ] as const
              ).map(([k, v, tone]) => (
                <span key={k} className="flex items-baseline gap-1">
                  <span className="font-mono text-[5.5px] tracking-widest text-slate-600 uppercase">{k}</span>
                  <span className="font-mono text-[8px] font-bold tabular-nums" style={{ color: tone }}>
                    {v.toLocaleString('en-US')}
                  </span>
                </span>
              ))}
            </div>
          )}

          {/* The list */}
          {f.assets.length === 0 ? (
            <div className="border border-cyan-900/40 bg-black/50 p-2">
              <p className="font-mono text-[7px] leading-relaxed text-slate-400">
                {isAr
                  ? 'لا أصول مسجّلة. لربط جهاز حقيقي: اصدر رمز تسجيل، ثم شغّل الأمر على ذلك الجهاز.'
                  : 'No assets enrolled. To watch a real machine: mint a token, then run the command on that machine.'}
              </p>
              <p className="mt-1 font-mono text-[6px] text-slate-600">
                {isAr
                  ? 'لن تُعرض أجهزة نموذجية — قائمة فارغة تعني أن شيئًا لم يُسجَّل.'
                  : 'no sample hosts are shown — an empty list means nothing enrolled.'}
              </p>
            </div>
          ) : (
            <div className="max-h-40 space-y-0.5 overflow-y-auto">
              {f.assets.map(a => {
                const L = LIVENESS[a.liveness];
                return (
                  <button
                    key={a.id}
                    type="button"
                    onClick={() => onSelect(a)}
                    className="flex w-full items-center gap-1.5 border-b border-white/[0.04] px-1 py-1 text-start transition-colors hover:bg-cyan-500/[0.06]"
                  >
                    {a.kind === 'HOST' ? (
                      <Server className="h-2.5 w-2.5 shrink-0" style={{ color: L.tone }} aria-hidden />
                    ) : (
                      <Network className="h-2.5 w-2.5 shrink-0 text-cyan-400" aria-hidden />
                    )}
                    <span className="min-w-0 flex-1">
                      <span className="block truncate font-mono text-[11px] text-slate-200">{a.label}</span>
                      <span className="block truncate font-mono text-[10px] text-slate-400">
                        {a.cidr ?? a.primaryIp ?? '—'} · {a.platform?.split(' ')[0] ?? '—'}
                      </span>
                    </span>
                    {a.isolated && <ShieldOff className="h-2.5 w-2.5 shrink-0 text-rose-500" aria-hidden />}
                    {/* Enrolled before sensor credentials existed: the server now refuses its
                        heartbeats, so without this it would simply drift to OFFLINE unexplained. */}
                    {a.kind === 'HOST' && a.credentialed === false && (
                      <span
                        className="shrink-0 border border-amber-500/60 px-1 font-mono text-[10px] text-amber-300"
                        title={
                          isAr
                            ? 'سُجِّل قبل اعتماد الحسّاسات؛ أعد تسجيله برمز جديد'
                            : 'enrolled before sensor credentials; re-enrol it with a fresh token'
                        }
                      >
                        {isAr ? 'أعد التسجيل' : 'RE-ENROL'}
                      </span>
                    )}
                    <span
                      className="shrink-0 font-mono text-[10px] tracking-widest"
                      style={{ color: L.tone }}
                      title={
                        a.lastSeenAt
                          ? `${isAr ? 'آخر إبلاغ' : 'last seen'} ${a.lastSeenAt}`
                          : isAr ? 'لم يُبلّغ قطّ' : 'never reported'
                      }
                    >
                      {isAr ? L.ar : L.en}
                    </span>
                  </button>
                );
              })}
            </div>
          )}

          {/* Enrolment */}
          <div className="mt-1.5 border-t border-cyan-900/40 pt-1.5">
            {f.enrollment ? (
              <div className="border border-emerald-900/50 bg-black/60 p-1.5">
                <div className="flex items-start justify-between gap-1">
                  <p className="font-mono text-[6px] tracking-widest text-emerald-400 uppercase">
                    {isAr ? 'شغّل هذا على الجهاز المستهدف' : 'RUN THIS ON THE TARGET MACHINE'}
                  </p>
                  <button
                    type="button"
                    onClick={f.clearEnrollment}
                    aria-label={isAr ? 'إخفاء' : 'dismiss'}
                    className="shrink-0 text-slate-500 transition-colors hover:text-white"
                  >
                    <X className="h-2.5 w-2.5" aria-hidden />
                  </button>
                </div>
                <code className="mt-1 block max-h-16 overflow-y-auto font-mono text-[6px] leading-relaxed break-all text-cyan-300 select-all">
                  {f.enrollment.command}
                </code>
                <div className="mt-1 flex items-center gap-1">
                  <CyberButton tone="emerald" size="sm" onClick={() => void copy(f.enrollment!.command)}>
                    <span className="flex items-center gap-1">
                      <Copy className="h-2 w-2" aria-hidden />
                      {copied ? (isAr ? 'نُسخ' : 'COPIED') : isAr ? 'نسخ' : 'COPY'}
                    </span>
                  </CyberButton>
                  <span className="font-mono text-[5.5px] text-amber-400">
                    {isAr ? 'استخدام واحد · ينتهي ' : 'SINGLE USE · EXPIRES '}
                    {f.enrollment.expiresAt.slice(0, 16).replace('T', ' ')}
                  </span>
                </div>
              </div>
            ) : (
              <CyberButton tone="cyan" size="sm" className="w-full" disabled={f.busy} onClick={() => void f.mintToken()}>
                <span className="flex items-center justify-center gap-1">
                  <Plus className="h-2.5 w-2.5" aria-hidden />
                  {isAr ? '[ ربط جهاز جديد ]' : '[ ENROL A MACHINE ]'}
                </span>
              </CyberButton>
            )}

            <div className="mt-1 flex gap-1">
              <input
                value={cidr}
                onChange={e => setCidr(e.target.value)}
                placeholder="10.0.0.0/24"
                aria-label={isAr ? 'نطاق شبكة' : 'network CIDR'}
                className="min-w-0 flex-1 border border-cyan-900/50 bg-black/60 px-1.5 py-1 font-mono text-[6.5px] text-cyan-400 placeholder:text-slate-700 focus:border-cyan-500/60 focus:outline-none"
              />
              <CyberButton
                tone="cyan"
                size="sm"
                disabled={!cidrValid || f.busy}
                title={cidrValid ? undefined : isAr ? 'أدخل نطاقًا مثل 10.0.0.0/24' : 'enter a CIDR such as 10.0.0.0/24'}
                onClick={() => void f.declareNetwork(cidr.trim())}
              >
                {isAr ? '[ شبكة ]' : '[ NET ]'}
              </CyberButton>
            </div>

            {f.lastResult && <p className="mt-1 font-mono text-[6px] break-words text-amber-400">{f.lastResult}</p>}
          </div>
        </>
      )}
    </ArsenalCard>
  );
};

/**
 * ENTITY DRAWER — the drill-down that separates a dashboard from a console.
 *
 * Every readout in this cockpit was a dead end: a number an operator could see and not
 * act on. That, more than any styling, is what "not professional" meant. In Falcon or
 * Gotham a detection is a doorway — click it and you get the entity, everything known
 * about it, and the actions available. This drawer is that doorway for an asset:
 * identity, self-reported posture, liveness derived from heartbeat age, ingestion
 * volume, and the containment controls in the same place as the evidence.
 *
 * Posture is labelled self-reported throughout. It is an assertion by software on a host
 * the server does not control, and an inventory that presents an agent's claim as a
 * verified fact is how asset databases end up confidently wrong.
 */
export const AssetDrawer: React.FC<{
  asset: AssetRow;
  f: Fleet;
  isAr: boolean;
  onClose: () => void;
}> = ({ asset, f, isAr, onClose }) => {
  const L = LIVENESS[asset.liveness];
  const ageSec = asset.lastSeenAt ? Math.round((Date.now() - new Date(asset.lastSeenAt).getTime()) / 1000) : null;

  const field = (k: string, v: React.ReactNode) => (
    <div className="flex items-baseline justify-between gap-2 border-b border-white/[0.04] py-1">
      <span className="font-mono text-[6px] tracking-widest text-slate-600 uppercase">{k}</span>
      <span className="min-w-0 truncate text-end font-mono text-[7.5px] text-slate-300">{v}</span>
    </div>
  );

  return (
    <aside
      className="absolute inset-y-0 z-40 w-[320px] overflow-y-auto border-s bg-[#030712]/95 p-3 shadow-[0_0_40px_rgba(0,0,0,0.9)] backdrop-blur-2xl"
      style={{ borderColor: 'rgba(22,78,99,0.6)', [isAr ? 'left' : 'right']: 0 }}
      role="dialog"
      aria-label={isAr ? `تفاصيل الأصل ${asset.label}` : `Asset detail ${asset.label}`}
    >
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <p
            className="truncate font-mono text-[11px] font-bold text-white"
            style={{ textShadow: '0 0 10px rgba(34,211,238,0.6)' }}
          >
            {asset.label}
          </p>
          <p className="font-mono text-[6.5px] tracking-widest text-cyan-400/70">{asset.id}</p>
        </div>
        <button
          type="button"
          onClick={onClose}
          aria-label={isAr ? 'إغلاق' : 'close'}
          className="shrink-0 text-slate-500 transition-colors hover:text-white"
        >
          <X className="h-3.5 w-3.5" aria-hidden />
        </button>
      </div>

      <span
        className="mt-2 inline-flex items-center gap-1 border px-1.5 py-0.5"
        style={{ borderColor: `${L.tone}88`, background: `${L.tone}14` }}
      >
        <span className="h-1 w-1 rounded-full" style={{ background: L.tone, boxShadow: `0 0 6px ${L.tone}` }} aria-hidden />
        <span className="font-mono text-[6.5px] tracking-widest" style={{ color: L.tone }}>
          {isAr ? L.ar : L.en}
        </span>
        {ageSec != null && (
          <span className="font-mono text-[6px] text-slate-500">
            {isAr ? `قبل ${ageSec}ث` : `${ageSec}s ago`}
          </span>
        )}
      </span>

      <div className="mt-2">
        <p className="font-mono text-[6px] tracking-widest text-cyan-400 uppercase">{isAr ? 'الهويّة' : 'IDENTITY'}</p>
        {field(isAr ? 'النوع' : 'KIND', asset.kind)}
        {field(isAr ? 'المضيف' : 'HOSTNAME', asset.hostname ?? '—')}
        {field(isAr ? 'المنصّة' : 'PLATFORM', asset.platform ?? '—')}
        {field(isAr ? 'المعمارية' : 'ARCH', asset.arch ?? '—')}
        {field('IP', asset.primaryIp ?? asset.cidr ?? '—')}
        {field(isAr ? 'إصدار المجسّ' : 'SENSOR', asset.sensorVersion ?? '—')}
        {field(isAr ? 'سُجّل' : 'ENROLLED', asset.enrolledAt.slice(0, 19).replace('T', ' '))}
        {field(isAr ? 'نبضة كل' : 'HEARTBEAT', asset.kind === 'HOST' ? `${asset.heartbeatIntervalSec}s` : '—')}
        {field(isAr ? 'تدفّقات مُستوعَبة' : 'FLOWS INGESTED', asset.flowsIngested.toLocaleString('en-US'))}
      </div>

      {asset.interfaces.length > 0 && (
        <div className="mt-2">
          <p className="font-mono text-[6px] tracking-widest text-cyan-400 uppercase">
            {isAr ? 'الواجهات' : 'INTERFACES'}
          </p>
          <div className="mt-0.5 space-y-0.5">
            {asset.interfaces.map(i => (
              <p key={i} className="truncate font-mono text-[6.5px] text-slate-400">
                {i}
              </p>
            ))}
          </div>
        </div>
      )}

      <div className="mt-2">
        <p className="font-mono text-[6px] tracking-widest text-cyan-400 uppercase">
          {isAr ? 'الحالة — كما أبلغ المجسّ' : 'POSTURE — SELF-REPORTED'}
        </p>
        <p className="mb-0.5 font-mono text-[5.5px] leading-relaxed text-amber-400/80">
          {isAr
            ? 'قياسات يُصرّح بها برنامجٌ على مضيف لا يتحكّم به الخادم. ليست حقائق مُتحقَّقة.'
            : 'measurements asserted by software on a host the server does not control. not verified facts.'}
        </p>
        {asset.posture ? (
          <>
            {field(isAr ? 'منافذ مُنصتة' : 'LISTENING PORTS', asset.posture.listeningPorts ?? '—')}
            {field(isAr ? 'اتصالات قائمة' : 'ESTABLISHED', asset.posture.establishedConnections ?? '—')}
            {field(isAr ? 'عمليّات' : 'PROCESSES', asset.posture.processes ?? '—')}
            {field(isAr ? 'مستخدمون' : 'LOGGED-IN USERS', asset.posture.loggedInUsers ?? '—')}
            {field(
              isAr ? 'مدّة التشغيل' : 'UPTIME',
              asset.posture.uptimeSec != null ? `${Math.floor(asset.posture.uptimeSec / 3600)}h` : '—'
            )}
            {asset.posture.extra &&
              Object.entries(asset.posture.extra).map(([k, v]) => field(k.toUpperCase(), v.toLocaleString('en-US')))}
            {/* A null field means the collector could not run on that host, which is a
                different statement from a measured zero, and is said rather than shown
                as a dash the operator has to guess at. */}
            {Object.values(asset.posture).some(v => v === null) && (
              <p className="mt-1 font-mono text-[5.5px] leading-relaxed text-slate-500">
                {isAr
                  ? 'الحقول بشرطة: المُجمِّع لم يعمل على ذلك المضيف — ليست صفرًا مقيسًا.'
                  : 'dashed fields: the collector could not run on that host — not a measured zero.'}
              </p>
            )}
          </>
        ) : (
          <p className="py-1.5 font-mono text-[7px] text-slate-600">
            {isAr ? 'لم تصل أيّ نبضة بعد.' : 'no heartbeat received yet.'}
          </p>
        )}
      </div>

      <div className="mt-3 space-y-1 border-t border-cyan-900/40 pt-2">
        <p className="font-mono text-[6px] tracking-widest text-rose-400 uppercase">
          {isAr ? 'الاحتواء' : 'CONTAINMENT'}
        </p>
        {asset.isolated ? (
          <>
            <p className="font-mono text-[6.5px] text-rose-400">
              {isAr ? 'معزول منذ ' : 'ISOLATED SINCE '}
              {asset.isolatedAt?.slice(0, 19).replace('T', ' ') ?? '—'}
            </p>
            <CyberButton
              tone="emerald"
              size="sm"
              className="w-full"
              disabled={f.busy}
              onClick={() => void f.setIsolated(asset.id, false)}
            >
              <span className="flex items-center justify-center gap-1">
                <ShieldCheck className="h-2.5 w-2.5" aria-hidden />
                {isAr ? '[ إطلاق ]' : '[ RELEASE ]'}
              </span>
            </CyberButton>
          </>
        ) : (
          <CyberButton
            tone="rose"
            size="sm"
            className="w-full"
            disabled={f.busy || !asset.primaryIp}
            title={
              asset.primaryIp
                ? undefined
                : isAr
                  ? 'لا عنوان IP معروف، فلا قاعدة نواة يمكن تطبيقها'
                  : 'no known IP, so no kernel rule could be applied'
            }
            onClick={() => void f.setIsolated(asset.id, true)}
          >
            <span className="flex items-center justify-center gap-1">
              <ShieldOff className="h-2.5 w-2.5" aria-hidden />
              {isAr ? '[ عزل الأصل ]' : '[ ISOLATE_NODE ]'}
            </span>
          </CyberButton>
        )}

        <CyberButton tone="amber" size="sm" className="w-full" disabled={f.busy} onClick={() => void f.remove(asset.id)}>
          <span className="flex items-center justify-center gap-1">
            <Trash2 className="h-2.5 w-2.5" aria-hidden />
            {isAr ? '[ إزالة من السجلّ ]' : '[ DEREGISTER ]'}
          </span>
        </CyberButton>

        {f.lastResult && <p className="mt-1 font-mono text-[6px] break-words text-amber-400">{f.lastResult}</p>}
      </div>
    </aside>
  );
};

export default AssetFleetPanel;
