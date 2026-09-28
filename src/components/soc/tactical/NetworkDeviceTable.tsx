import React from 'react';
import { Router, Smartphone, Server as ServerIcon, HelpCircle, Monitor, ShieldOff, ArrowUpDown, Search } from 'lucide-react';
import { CyberButton } from './CyberButton';
import type { AssetRow } from './useAssets';
import type { LanWatch } from './useLanWatch';
import { IpLink } from './ipDossier';

/**
 * NETWORK DEVICE INVENTORY — the list the graph was missing.
 *
 * A relationship graph answers "how is this connected". It cannot answer "how many
 * devices do I have", "which ones expose SMB", or "what changed since yesterday",
 * because those are questions about a set, and a set is read as a table. Falcon,
 * Darktrace and Zenmap all ship both views for exactly this reason: the picture for
 * structure, the list for work. Shipping only the picture was the gap.
 *
 * Every row is one device something observed on the wire. Columns are sortable, the
 * filter is a substring match across address, MAC and vendor, and each row carries the
 * evidence for its own claims — which host saw it, by what method, and when. A device
 * inventory whose rows cannot be traced back to an observation is a list of assertions.
 */

export interface DeviceRow {
  ip: string;
  mac: string;
  vendor: string | null;
  viaInterface: string | null;
  segment: string | null;
  openPorts: number[];
  sweepState: 'NOT_IN_RANGE' | 'RESPONDED' | 'NO_RESPONSE' | null;
  lastSweptAt: string | null;
  discoveredAt: string;
  method: string;
  /** The enrolled host that observed it, so every row is attributable. */
  seenBy: string;
  seenByAssetId: string;
  /** True when this address is itself an enrolled asset, not just a neighbour. */
  isEnrolled: boolean;
  isolated: boolean;
}

type SortKey = 'ip' | 'vendor' | 'ports' | 'state' | 'seen';

const SERVICE: Record<number, string> = {
  22: 'SSH', 23: 'TELNET', 25: 'SMTP', 53: 'DNS', 80: 'HTTP', 110: 'POP3',
  135: 'RPC', 139: 'NBT', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB', 587: 'SMTPS',
  993: 'IMAPS', 1433: 'MSSQL', 1521: 'ORACLE', 3306: 'MYSQL', 3389: 'RDP',
  5432: 'PGSQL', 5900: 'VNC', 5985: 'WINRM', 6379: 'REDIS', 8080: 'HTTP-ALT',
  8443: 'HTTPS-ALT', 9200: 'ELASTIC', 27017: 'MONGO'
};

/**
 * Ports that carry real risk when reachable from a LAN, flagged so an operator's eye
 * lands on them. This is not a severity score — it is a shortlist of services whose
 * exposure is worth a look, and it says so rather than printing a number.
 */
const NOTABLE = new Set([23, 135, 139, 445, 1433, 3306, 3389, 5432, 5900, 6379, 9200, 27017]);

function classify(d: DeviceRow): { icon: React.ElementType; en: string; ar: string } {
  const last = Number(d.ip.split('.')[3]);
  if ((last === 1 || last === 254) && (d.openPorts.includes(80) || d.openPorts.includes(443) || d.openPorts.length === 0))
    return { icon: Router, en: 'GATEWAY', ar: 'بوّابة' };
  if (d.openPorts.some(p => [445, 3389, 5985, 135, 139].includes(p)))
    return { icon: Monitor, en: 'WINDOWS HOST', ar: 'مضيف ويندوز' };
  if (d.openPorts.includes(22)) return { icon: ServerIcon, en: 'SSH HOST', ar: 'مضيف SSH' };
  if (/^.[26ae]:/i.test(d.mac)) return { icon: Smartphone, en: 'RANDOMISED MAC', ar: 'عنوان معشّى' };
  return { icon: HelpCircle, en: 'UNCLASSIFIED', ar: 'غير مصنّف' };
}

function inCidr(ip: string, cidr: string): boolean {
  const m = /^((?:\d{1,3}\.){3}\d{1,3})\/(\d{1,2})$/.exec(cidr);
  if (!m) return false;
  const bits = Number(m[2]);
  const toInt = (v: string) => v.split('.').map(Number).reduce((a, o) => (a << 8) | o, 0) >>> 0;
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return ((toInt(ip) & mask) >>> 0) === ((toInt(m[1]) & mask) >>> 0);
}

/**
 * Flattens the fleet into one device list.
 *
 * Deduplicated by address, because two sensors on the same segment see the same
 * neighbours and counting them twice would inflate the network's apparent size. When two
 * hosts saw the same device, the row that carries sweep evidence wins over one that does
 * not — the more-informed observation is the one worth keeping.
 */
export function buildDeviceRows(assets: AssetRow[]): DeviceRow[] {
  const enrolledIps = new Map(
    assets.filter(a => a.primaryIp).map(a => [a.primaryIp as string, a])
  );
  const out = new Map<string, DeviceRow>();

  for (const a of assets) {
    if (a.kind !== 'HOST') continue;
    const segments = a.posture?.segments ?? [];

    for (const n of a.posture?.neighbours ?? []) {
      const enrolled = enrolledIps.get(n.ip);
      const row: DeviceRow = {
        ip: n.ip,
        mac: n.mac,
        vendor: n.vendor,
        viaInterface: n.viaInterface,
        segment: segments.find(s => inCidr(n.ip, s.cidr))?.cidr ?? null,
        openPorts: n.openPorts ?? [],
        sweepState: n.sweepState ?? null,
        lastSweptAt: n.lastSweptAt ?? null,
        discoveredAt: n.discoveredAt,
        method: n.method,
        seenBy: a.label,
        seenByAssetId: a.id,
        isEnrolled: Boolean(enrolled),
        isolated: enrolled?.isolated ?? false
      };

      const prior = out.get(n.ip);
      if (!prior || (row.sweepState && !prior.sweepState)) out.set(n.ip, row);
    }

    // The enrolled host itself belongs in its own inventory. It is the one device whose
    // posture is measured from inside rather than observed from outside, and leaving it
    // out would mean the machine doing the watching never appears among the watched.
    if (a.primaryIp && !out.has(a.primaryIp)) {
      out.set(a.primaryIp, {
        ip: a.primaryIp,
        mac: '—',
        vendor: a.platform,
        viaInterface: null,
        segment: segments.find(s => inCidr(a.primaryIp!, s.cidr))?.cidr ?? null,
        openPorts: [],
        sweepState: null,
        lastSweptAt: null,
        discoveredAt: a.enrolledAt,
        method: 'ENROLLED_SENSOR',
        seenBy: a.label,
        seenByAssetId: a.id,
        isEnrolled: true,
        isolated: a.isolated
      });
    }
  }

  return [...out.values()];
}

const STATE_STYLE: Record<string, { tone: string; ar: string; en: string }> = {
  RESPONDED: { tone: '#fbbf24', ar: 'أجاب', en: 'RESPONDED' },
  NO_RESPONSE: { tone: '#0e7490', ar: 'يُرشِّح', en: 'FILTERING' },
  NOT_IN_RANGE: { tone: '#5c7484', ar: 'لم يُمسح', en: 'NOT SWEPT' }
};

export const NetworkDeviceTable: React.FC<{
  assets: AssetRow[];
  isAr: boolean;
  onOpenAsset: (a: AssetRow) => void;
  /** LAN watch state; absent renders the table without the watch column. */
  lan?: LanWatch;
  /** ANALYST or above may approve a new device. */
  canAct?: boolean;
  className?: string;
}> = ({ assets, isAr, onOpenAsset, lan, canAct = false, className }) => {
  const [sort, setSort] = React.useState<SortKey>('ip');
  const [desc, setDesc] = React.useState(false);
  const [q, setQ] = React.useState('');
  const [openOnly, setOpenOnly] = React.useState(false);

  const rows = React.useMemo(() => {
    let r = buildDeviceRows(assets);
    const needle = q.trim().toLowerCase();
    if (needle) {
      r = r.filter(
        d =>
          d.ip.includes(needle) ||
          d.mac.toLowerCase().includes(needle) ||
          (d.vendor ?? '').toLowerCase().includes(needle) ||
          d.openPorts.some(p => String(p).includes(needle) || (SERVICE[p] ?? '').toLowerCase().includes(needle))
      );
    }
    if (openOnly) r = r.filter(d => d.openPorts.length > 0);

    const ipNum = (ip: string) => ip.split('.').map(Number).reduce((a, o) => (a << 8) | o, 0) >>> 0;
    r.sort((a, b) => {
      let v = 0;
      if (sort === 'ip') v = ipNum(a.ip) - ipNum(b.ip);
      else if (sort === 'vendor') v = (a.vendor ?? 'zzz').localeCompare(b.vendor ?? 'zzz');
      else if (sort === 'ports') v = b.openPorts.length - a.openPorts.length;
      else if (sort === 'state') v = (a.sweepState ?? 'zzz').localeCompare(b.sweepState ?? 'zzz');
      else v = a.discoveredAt.localeCompare(b.discoveredAt);
      return desc ? -v : v;
    });
    return r;
  }, [assets, sort, desc, q, openOnly]);

  const head = (key: SortKey, label: string, width?: string) => (
    <button
      type="button"
      onClick={() => {
        if (sort === key) setDesc(d => !d);
        else {
          setSort(key);
          setDesc(false);
        }
      }}
      className="flex shrink-0 items-center gap-0.5 text-start font-mono text-[10px] tracking-widest uppercase transition-colors hover:text-cyan-300"
      style={{ width, flex: width ? undefined : 1, color: sort === key ? '#22d3ee' : '#5c7484' }}
    >
      {label}
      {sort === key && <ArrowUpDown className="h-2 w-2" aria-hidden />}
    </button>
  );

  const notable = rows.filter(d => d.openPorts.some(p => NOTABLE.has(p)));

  return (
    <div className={`flex min-h-0 flex-col ${className ?? ''}`}>
      {/* Controls */}
      <div className="flex shrink-0 flex-wrap items-center gap-1.5 pb-1.5">
        <span className="relative flex items-center">
          <Search className="pointer-events-none absolute start-1.5 h-2.5 w-2.5 text-slate-400" aria-hidden />
          <input
            value={q}
            onChange={e => setQ(e.target.value)}
            placeholder={isAr ? 'عنوان، MAC، مُصنِّع، منفذ…' : 'address, MAC, vendor, port…'}
            aria-label={isAr ? 'تصفية الأجهزة' : 'filter devices'}
            className="w-52 border border-cyan-900/50 bg-black/60 py-1 ps-5 pe-1.5 font-mono text-[10px] text-cyan-300 placeholder:text-slate-500 focus:border-cyan-500/60 focus:outline-none"
          />
        </span>
        <CyberButton tone={openOnly ? 'amber' : 'cyan'} size="sm" active={openOnly} onClick={() => setOpenOnly(v => !v)}>
          {openOnly ? (isAr ? '[ بمنافذ مفتوحة ]' : '[ WITH OPEN PORTS ]') : isAr ? '[ الكل ]' : '[ ALL ]'}
        </CyberButton>

        <span className="ms-auto flex items-center gap-3">
          <span className="font-mono text-[10px] text-slate-500">
            {rows.length} {isAr ? 'جهاز' : 'DEVICES'}
          </span>
          {notable.length > 0 && (
            <span
              className="font-mono text-[10px] text-amber-400"
              title={
                isAr
                  ? 'أجهزة تعرض خدمةً تستحقّ النظر عند وصولها من الشبكة المحلّية. ليست درجة خطورة.'
                  : 'devices exposing a service worth a look from the LAN. not a severity score.'
              }
            >
              {notable.length} {isAr ? 'تستحقّ النظر' : 'WORTH A LOOK'}
            </span>
          )}
        </span>
      </div>

      {/* ARP poisoning and gateway changes lead the table: they concern every device on it. */}
      {lan && lan.alarms.length > 0 && (
        <div role="alert" className="mb-1.5 shrink-0 space-y-1 border border-rose-500/60 bg-rose-950/40 px-2 py-1.5">
          {lan.alarms.slice(0, 3).map(e => (
            <p key={e.id} className="text-[11px] leading-snug text-rose-200">
              <span className="font-mono font-bold text-rose-300">
                {e.kind === 'ARP_SPOOF_SUSPECTED' ? (isAr ? 'اشتباه انتحال ARP' : 'ARP SPOOFING SUSPECTED') : isAr ? 'تغيّر MAC البوابة' : 'GATEWAY MAC CHANGED'}
              </span>{' '}
              <span className="font-mono" dir="ltr">
                {e.ip} · {e.mac} · {e.at.slice(11, 19)}
              </span>
              <span className="block text-rose-200/80" dir="auto">{e.detail}</span>
              {e.mitre && <span className="font-mono text-[10px] text-cyan-300">{e.mitre}</span>}
            </p>
          ))}
        </div>
      )}
      {lan?.status && (
        <p className="mb-1 shrink-0 font-mono text-[10px] text-slate-400">
          {isAr ? 'كشف انتحال ARP: ' : 'ARP-spoof detection: '}
          {Object.keys(lan.status.spoofDetection).length === 0 ? (
            isAr ? 'بانتظار نبضة حسّاس' : 'awaiting a sensor heartbeat'
          ) : Object.values(lan.status.spoofDetection).every(v => v === 'ACTIVE') ? (
            <span className="text-emerald-300">{isAr ? 'فعّال' : 'ACTIVE'}</span>
          ) : (
            <span className="text-amber-300">
              {isAr ? 'غير متاح لبعض المضيفين — البوابة غير مُبلَّغ عنها' : 'unavailable on some hosts — gateway not reported'}
            </span>
          )}
          {lan.status.newCount > 0 && (
            <span className="ms-3 text-amber-300">
              {lan.status.newCount} {isAr ? 'جهاز جديد بانتظار المراجعة' : 'new device(s) awaiting review'}
            </span>
          )}
        </p>
      )}

      {/* Header */}
      <div
        className="flex shrink-0 items-center gap-2 px-1.5 py-1"
        style={{ background: 'rgba(34,211,238,0.08)', borderBottom: '1px solid rgba(34,211,238,0.25)' }}
      >
        {head('ip', isAr ? 'العنوان' : 'ADDRESS', '118px')}
        {lan && (
          <span className="w-[92px] shrink-0 font-mono text-[10px] tracking-widest text-slate-400 uppercase">
            {isAr ? 'المراقبة' : 'WATCH'}
          </span>
        )}
        <span className="w-6 shrink-0" aria-hidden />
        {head('vendor', isAr ? 'المُصنِّع / النوع' : 'VENDOR / TYPE', '132px')}
        {head('ports', isAr ? 'المنافذ المفتوحة' : 'OPEN PORTS')}
        {head('state', isAr ? 'حالة الفحص' : 'SWEEP', '78px')}
        <span className="w-[104px] shrink-0 font-mono text-[10px] tracking-widest text-slate-400 uppercase">
          {isAr ? 'القطاع' : 'SEGMENT'}
        </span>
        <span className="w-[86px] shrink-0 font-mono text-[10px] tracking-widest text-slate-400 uppercase">
          {isAr ? 'رصده' : 'SEEN BY'}
        </span>
      </div>

      {/* Rows */}
      <div className="min-h-0 flex-1 overflow-y-auto">
        {rows.length === 0 ? (
          <div className="py-6 text-center">
            <p className="font-mono text-[11px] text-slate-500">
              {q || openOnly
                ? isAr ? 'لا جهاز يطابق التصفية.' : 'no device matches the filter.'
                : isAr
                  ? 'لا أجهزة مرصودة. شغّل المجسّ على مضيف ليُبلّغ عن جيرانه.'
                  : 'no devices observed. run the sensor on a host and it will report its neighbours.'}
            </p>
            {!q && !openOnly && (
              <p className="mt-1 font-mono text-[10px] text-slate-500">/api/v1/assets</p>
            )}
          </div>
        ) : (
          rows.map(d => {
            const cls = classify(d);
            const Icon = cls.icon;
            const st = d.sweepState ? STATE_STYLE[d.sweepState] : null;
            const asset = d.isEnrolled ? assets.find(a => a.id === d.seenByAssetId) : null;

            return (
              <div
                key={d.ip}
                className="flex items-center gap-2 border-b border-white/[0.04] px-1.5 py-[3px] transition-colors hover:bg-cyan-500/[0.05]"
              >
                <span className="flex w-[118px] shrink-0 items-center gap-1">
                  {d.isolated && <ShieldOff className="h-2.5 w-2.5 shrink-0 text-rose-500" aria-hidden />}
                  <IpLink ip={d.ip} className="text-[11px] text-slate-200 tabular-nums" />
                </span>

                {lan && <WatchCell lan={lan} mac={d.mac} isAr={isAr} canAct={canAct} />}

                <span className="w-6 shrink-0">
                  <Icon className="h-3 w-3" strokeWidth={1.5} style={{ color: d.isEnrolled ? '#22d3ee' : '#5c7484' }} aria-hidden />
                </span>

                <span className="w-[132px] shrink-0">
                  <span className="block truncate font-mono text-[10px] text-slate-300">
                    {d.vendor ?? (isAr ? 'مُصنِّع مجهول' : 'unknown vendor')}
                  </span>
                  <span className="block truncate font-mono text-[10px] text-slate-400">
                    {d.isEnrolled ? (isAr ? 'مُسجَّل — مجسّ' : 'ENROLLED — SENSOR') : isAr ? cls.ar : cls.en}
                  </span>
                </span>

                <span className="flex min-w-0 flex-1 flex-wrap gap-1">
                  {d.openPorts.length === 0 ? (
                    <span className="font-mono text-[10px] text-slate-500">
                      {d.sweepState === 'NO_RESPONSE'
                        ? isAr ? 'لم يُجب على الفحص' : 'no response to probe'
                        : d.sweepState === 'RESPONDED'
                          ? isAr ? 'لا شيء مفتوح مما فُحص' : 'none open among probed'
                          : isAr ? 'غير معروف — لم يُمسح' : 'unknown — not swept'}
                    </span>
                  ) : (
                    d.openPorts.map(p => (
                      <span
                        key={p}
                        className="border px-1 font-mono text-[10px] tabular-nums"
                        style={{
                          borderColor: NOTABLE.has(p) ? 'rgba(251,191,36,0.55)' : 'rgba(34,211,238,0.35)',
                          color: NOTABLE.has(p) ? '#fbbf24' : '#22d3ee'
                        }}
                        title={SERVICE[p] ?? undefined}
                      >
                        {p}
                        {SERVICE[p] && <span className="ms-0.5 opacity-70">{SERVICE[p]}</span>}
                      </span>
                    ))
                  )}
                </span>

                <span className="w-[78px] shrink-0">
                  {st ? (
                    <span className="font-mono text-[10px] tracking-wider" style={{ color: st.tone }}>
                      {isAr ? st.ar : st.en}
                    </span>
                  ) : (
                    <span className="font-mono text-[10px] text-slate-500">—</span>
                  )}
                  {d.lastSweptAt && (
                    <span className="block font-mono text-[10px] text-slate-500">{d.lastSweptAt.slice(11, 16)}</span>
                  )}
                </span>

                <span className="w-[104px] shrink-0">
                  <span className="block truncate font-mono text-[10px] text-slate-500">{d.segment ?? '—'}</span>
                  <span className="block truncate font-mono text-[10px] text-slate-500">{d.viaInterface ?? ''}</span>
                </span>

                <span className="w-[86px] shrink-0">
                  {asset ? (
                    <button
                      type="button"
                      onClick={() => onOpenAsset(asset)}
                      className="truncate font-mono text-[10px] text-cyan-400 underline-offset-2 transition-colors hover:text-cyan-300 hover:underline"
                    >
                      {d.seenBy}
                    </button>
                  ) : (
                    <span className="block truncate font-mono text-[10px] text-slate-400" title={d.method}>
                      {d.seenBy}
                    </span>
                  )}
                  <span className="block truncate font-mono text-[10px] text-slate-500">{d.method}</span>
                </span>
              </div>
            );
          })
        )}
      </div>

      {/* The provenance line. Every claim above traces to one of these two methods. */}
      <p className="shrink-0 border-t border-cyan-900/40 pt-1 font-mono text-[10px] leading-relaxed text-slate-400">
        {isAr
          ? 'ARP_CACHE: الجهاز ردّ فعلًا على الشبكة، دون إرسال أي حزمة منّا. TCP_CONNECT: فُحص بمسح مُصرَّح. المنافذ غير معروفة حتى يُشغَّل مسح — ولا تُخمَّن.'
          : 'ARP_CACHE: the device genuinely answered on the wire, with nothing sent from us. TCP_CONNECT: probed by an authorised sweep. Ports are unknown until a sweep runs, and are never guessed.'}
      </p>
    </div>
  );
};

/** One device's LAN-watch state: NEW (with APPROVE), APPROVED or BASELINE. */
const WatchCell: React.FC<{ lan: LanWatch; mac: string; isAr: boolean; canAct: boolean }> = ({ lan, mac, isAr, canAct }) => {
  const w = lan.byMac.get(mac.toLowerCase());
  if (!w) return <span className="w-[92px] shrink-0 font-mono text-[10px] text-slate-500">—</span>;
  if (w.state === 'NEW') {
    return (
      <span className="flex w-[92px] shrink-0 items-center gap-1">
        <span
          className="border border-amber-500/60 px-1 font-mono text-[10px] text-amber-300"
          title={w.randomized ? (isAr ? 'عنوان MAC عشوائي — جهاز شخصي على الأرجح' : 'randomised MAC — likely a personal device') : undefined}
        >
          {isAr ? 'جديد' : 'NEW'}
          {w.randomized ? '·R' : ''}
        </span>
        {canAct && (
          <button
            type="button"
            disabled={lan.busyMac === w.mac}
            onClick={() => void lan.approve(w.mac)}
            className="border border-emerald-600/60 px-1 font-mono text-[10px] text-emerald-300 hover:bg-emerald-500/10 disabled:opacity-50"
            title={isAr ? 'اعتماد الجهاز يوقف تنبيهه' : 'approving stops its alert'}
          >
            {isAr ? 'اعتماد' : 'APPROVE'}
          </button>
        )}
      </span>
    );
  }
  return (
    <span
      className="w-[92px] shrink-0 font-mono text-[10px]"
      style={{ color: w.state === 'APPROVED' ? '#34d399' : '#94a3b8' }}
      title={w.approvedBy ? `${w.approvedBy} · ${w.approvedAt?.slice(0, 16)}` : `${isAr ? 'أول رصد' : 'first seen'} ${w.firstSeen.slice(0, 16)}`}
    >
      {w.state === 'APPROVED' ? (isAr ? '✓ معتمد' : '✓ APPROVED') : isAr ? 'خط الأساس' : 'BASELINE'}
    </span>
  );
};

export default NetworkDeviceTable;
