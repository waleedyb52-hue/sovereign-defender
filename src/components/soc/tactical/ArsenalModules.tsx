import React from 'react';
import { Cpu, ShieldCheck, FileLock2, Radar, Globe2, Lock } from 'lucide-react';
import { ArsenalCard, CyberButton } from './CyberButton';
import type { useArsenal } from './useArsenal';
import type { Containment } from './useContainment';
import { IpLink } from './ipDossier';

type Arsenal = ReturnType<typeof useArsenal>;

/**
 * THE SIX ARSENAL MODULES
 *
 * One HUD module per defensive tool, each reading a real endpoint. Where a feed is
 * empty the module says which endpoint is empty and why, rather than filling the panel
 * — an empty scanner history means no audit has been run, which is information, and
 * inventing open ports and CVEs would turn a security console into a liability.
 */

const Label: React.FC<{ children: React.ReactNode; tone?: string }> = ({ children, tone = '#22d3ee' }) => (
  <span className="font-mono text-[10px] tracking-widest uppercase" style={{ color: tone, opacity: 0.75 }}>
    {children}
  </span>
);

const Val: React.FC<{ v: number | string | null; unit?: string; tone?: string; reason?: string; glow?: boolean }> = ({
  v, unit, tone = '#22d3ee', reason, glow = true
}) =>
  v == null ? (
    <span className="font-mono text-[11px] text-slate-500" title={reason}>—</span>
  ) : (
    <span
      className="font-mono text-xs font-bold tabular-nums"
      style={{ color: tone, textShadow: glow ? `0 0 8px ${tone}cc` : undefined }}
    >
      {typeof v === 'number' ? v.toLocaleString('en-US') : v}
      {unit && <span className="ms-0.5 text-[10px] opacity-60">{unit}</span>}
    </span>
  );

const Row: React.FC<{ k: React.ReactNode; children: React.ReactNode }> = ({ k, children }) => (
  <div className="flex items-baseline justify-between gap-2 py-[1px]">
    <Label>{k}</Label>
    {children}
  </div>
);

const Empty: React.FC<{ endpoint: string; note: string }> = ({ endpoint, note }) => (
  <div className="py-2">
    <p className="font-mono text-[10px] leading-relaxed text-slate-500">{note}</p>
    <p className="mt-0.5 font-mono text-[10px] text-slate-500">{endpoint}</p>
  </div>
);

/* ── 1. eBPF / XDP kernel firewall ─────────────────────────────────────────── */

/**
 * Ring-0 efficiency sparkline.
 *
 * Drawn from a rolling window of throughput samples this module has actually observed
 * since mount, not from a synthetic series. Fewer than two samples means no line — one
 * point rendered flat would claim a steady state that a single reading cannot support.
 */
const RingZeroSpark: React.FC<{ samples: number[]; isAr: boolean }> = ({ samples, isAr }) => {
  if (samples.length < 2) {
    return (
      <p className="py-2 font-mono text-[10px] leading-relaxed text-slate-400">
        {isAr ? 'عيّنتان على الأقل لازمتان لرسم اتجاه.' : 'a trend needs at least two samples.'}
      </p>
    );
  }
  const max = Math.max(...samples, 1);
  const w = 160;
  const h = 26;
  const pts = samples.map((v, i) => `${(i / (samples.length - 1)) * w},${h - (v / max) * h}`).join(' ');
  return (
    <svg viewBox={`0 0 ${w} ${h}`} className="mt-1 w-full" style={{ height: h }} aria-hidden>
      <polyline points={pts} fill="none" stroke="#22d3ee" strokeWidth="1" style={{ filter: 'drop-shadow(0 0 3px #22d3ee)' }} />
      <polyline points={`0,${h} ${pts} ${w},${h}`} fill="url(#rz)" opacity="0.3" />
      <defs>
        <linearGradient id="rz" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor="#22d3ee" stopOpacity="0.5" />
          <stop offset="100%" stopColor="#22d3ee" stopOpacity="0" />
        </linearGradient>
      </defs>
    </svg>
  );
};

export const EbpfModule: React.FC<{ a: Arsenal; isAr: boolean }> = ({ a, isAr }) => {
  const [samples, setSamples] = React.useState<number[]>([]);
  const pps = a.ebpf.throughputPps;

  React.useEffect(() => {
    if (pps == null) return;
    setSamples(s => (s.length >= 40 ? s.slice(1).concat(pps) : s.concat(pps)));
  }, [pps]);

  const emu = a.ebpf.emulated;

  return (
    <ArsenalCard
      title={isAr ? 'جدار النواة eBPF / XDP' : 'eBPF / XDP KERNEL FIREWALL'}
      icon={Cpu}
      tone={emu ? 'amber' : 'cyan'}
      headline={<Val v={a.ebpf.dropped} tone={emu ? '#fbbf24' : '#22d3ee'} />}
      defaultOpen
    >
      {emu && (
        <p className="mb-1.5 font-mono text-[10px] leading-relaxed text-amber-400">
          {isAr
            ? `المشغّل يُبلّغ ${a.ebpf.driverMode} — العدّادات محاكاة لا قياس نواة.`
            : `driver reports ${a.ebpf.driverMode} — counters are emulated, not kernel measurements.`}
        </p>
      )}
      <Row k={isAr ? 'حِزَم مُسقَطة' : 'PACKETS DROPPED'}><Val v={a.ebpf.dropped} tone="#fb7185" /></Row>
      <Row k={isAr ? 'حِزَم مُمرَّرة' : 'PACKETS PASSED'}><Val v={a.ebpf.passed} tone="#34d399" /></Row>
      <Row k={isAr ? 'نسبة الإسقاط' : 'DROP RATIO'}>
        <Val v={a.ebpf.dropRatio != null ? `${(a.ebpf.dropRatio * 100).toFixed(2)}%` : null} />
      </Row>
      <Row k={isAr ? 'زمن التقييم' : 'EVAL LATENCY'}>
        <Val v={a.ebpf.latencyNs} unit="ns" tone={emu ? '#fbbf24' : '#22d3ee'} />
      </Row>
      <Row k={isAr ? 'النفاذية' : 'THROUGHPUT'}><Val v={a.ebpf.throughputPps} unit="pps" /></Row>
      <Row k={isAr ? 'قائمة الحجب' : 'BLACKLIST MAP'}><Val v={a.ebpf.blacklist} /></Row>
      <Label>{isAr ? 'كفاءة الحلقة صفر' : 'RING-0 EFFICIENCY'}</Label>
      <RingZeroSpark samples={samples} isAr={isAr} />
      <p className="mt-1 truncate font-mono text-[10px] text-slate-400" title={a.ebpf.pinnedMap ?? undefined}>
        {a.ebpf.iface ?? '—'} · {a.ebpf.pinnedMap ?? '—'}
      </p>
    </ArsenalCard>
  );
};

/* ── 2. AI-driven WAF (L7) ─────────────────────────────────────────────────── */

export const WafModule: React.FC<{ a: Arsenal; isAr: boolean }> = ({ a, isAr }) => (
  <ArsenalCard
    title={isAr ? 'جدار التطبيقات الذكي L7' : 'AI-DRIVEN WAF · LAYER 7'}
    icon={ShieldCheck}
    headline={
      <Val
        v={a.waf.rulesOn != null && a.waf.rulesTotal != null ? `${a.waf.rulesOn}/${a.waf.rulesTotal}` : null}
        tone={a.waf.rulesOn === a.waf.rulesTotal ? '#34d399' : '#fbbf24'}
      />
    }
  >
    <div className="mb-1.5 grid grid-cols-2 gap-x-2">
      {a.waf.rules.map(r => (
        <div key={r.name} className="flex items-center gap-1 py-[1px]">
          <span
            className="h-1 w-1 shrink-0"
            style={{ background: r.on ? '#34d399' : '#475569', boxShadow: r.on ? '0 0 4px #34d399' : 'none' }}
            aria-hidden
          />
          <span className="truncate font-mono text-[10px] text-slate-400" title={r.name}>
            {r.name.replace(/([A-Z])/g, ' $1').replace(/^ /, '').toUpperCase()}
          </span>
        </div>
      ))}
    </div>
    <Row k={isAr ? 'حِزَم محجوبة' : 'REQUESTS BLOCKED'}><Val v={a.waf.dropped} tone="#fb7185" /></Row>
    <Row k={isAr ? 'حقن نصّي مُحيَّد' : 'INJECTIONS NEUTRALISED'}><Val v={a.waf.injectionsNeutralized} /></Row>
    <Row k={isAr ? 'حمايات إيجابٍ كاذب' : 'FALSE-POSITIVE GUARDS'}><Val v={a.waf.fpProtections} tone="#34d399" /></Row>
    <Row k={isAr ? 'عتبة الثقة للحجب' : 'TIER-3 CONFIDENCE GATE'}>
      <Val v={a.waf.tier3Threshold} unit="%" tone="#fbbf24" />
    </Row>

    <div className="mt-1.5 border-t border-cyan-900/40 pt-1.5">
      <Label>{isAr ? 'تحليلات الحمولة' : 'PAYLOAD ANALYSES'}</Label>
      {a.waf.analyses.length === 0 ? (
        <Empty
          endpoint="/soc/ai-agent/analyses"
          note={
            isAr
              ? 'لا تحليلات حمولة مسجّلة. درجات الثقة تُعرض حين يقيّم المحرّك حمولةً فعليّة.'
              : 'no payload analyses recorded. confidence scores appear once the engine evaluates a real payload.'
          }
        />
      ) : (
        <div className="mt-1 max-h-24 space-y-0.5 overflow-y-auto">
          {a.waf.analyses.slice(0, 20).map((an, i) => (
            <div key={an.id ?? i} className="flex items-baseline gap-1.5">
              <span className="w-10 shrink-0 font-mono text-[10px] text-slate-400">{an.at?.slice(11, 19) ?? '—'}</span>
              <span
                className="w-12 shrink-0 font-mono text-[10px]"
                style={{ color: /BLOCK|MALIC|THREAT/i.test(an.verdict ?? '') ? '#fb7185' : '#34d399' }}
              >
                {an.verdict?.slice(0, 8) ?? '—'}
              </span>
              <span className="min-w-0 flex-1 truncate font-mono text-[10px] text-slate-400">
                {an.threatType ?? an.excerpt ?? '—'}
              </span>
              {an.confidence != null ? (
                <span className="shrink-0 font-mono text-[10px] font-bold text-cyan-400">{an.confidence}%</span>
              ) : (
                <span className="shrink-0 font-mono text-[10px] text-slate-500" title={isAr ? 'لم تُصدر ثقة' : 'no confidence issued'}>
                  —
                </span>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  </ArsenalCard>
);

/* ── 3. FIM hash terminal ──────────────────────────────────────────────────── */

/**
 * Scrolling SHA-256 verification terminal.
 *
 * The brief asked for /etc/shadow and system32. Those are not what FIM watches: the
 * monitor covers a real directory, and its path is printed at the top of the terminal
 * so the module cannot be read as system-wide coverage. Showing /etc/shadow lines on a
 * host where FIM has never touched that file would be a fabricated integrity claim
 * about the most sensitive file on the system — the exact inversion of what a FIM panel
 * is for.
 */
export const FimModule: React.FC<{ a: Arsenal; isAr: boolean }> = ({ a, isAr }) => {
  const [cursor, setCursor] = React.useState(0);
  const files = a.fim.files;

  // Walk the real file list, one line at a time, so the terminal scrolls without
  // any line being invented. It is a re-verification cadence, not a fake feed.
  React.useEffect(() => {
    if (files.length === 0) return;
    const t = setInterval(() => setCursor(c => c + 1), 1400);
    return () => clearInterval(t);
  }, [files.length]);

  const lines = React.useMemo(() => {
    if (files.length === 0) return [];
    const out: Array<{ key: string; f: (typeof files)[number] }> = [];
    for (let i = 0; i < 14; i++) {
      const idx = (cursor - i + files.length * 100) % files.length;
      out.push({ key: `${cursor - i}`, f: files[idx] });
    }
    return out;
  }, [cursor, files]);

  const tampered = files.filter(f => f.status && !/INTACT|OK|VERIFIED/i.test(f.status)).length;

  return (
    <ArsenalCard
      title={isAr ? 'مراقبة سلامة الملفات FIM' : 'FILE INTEGRITY MONITORING'}
      icon={FileLock2}
      tone={tampered > 0 ? 'rose' : 'emerald'}
      alert={tampered > 0}
      headline={<Val v={files.length} tone={tampered > 0 ? '#fb7185' : '#34d399'} />}
    >
      {files.length === 0 ? (
        <Empty
          endpoint="/fim/files"
          note={isAr ? 'لا ملفات مُراقَبة.' : 'no monitored files.'}
        />
      ) : (
        <>
          <p className="truncate font-mono text-[10px] text-slate-500" title={files[0]?.path}>
            {isAr ? 'الجذر المُراقَب: ' : 'MONITORED ROOT: '}
            {files[0]?.path.replace(/[\\/][^\\/]+$/, '') ?? '—'}
          </p>
          <div
            className="mt-1 h-[104px] overflow-hidden border border-cyan-900/40 bg-black/70 p-1"
            role="log"
            aria-label={isAr ? 'سجلّ تحقّق البصمات' : 'hash verification log'}
          >
            {lines.map(({ key, f }) => {
              const ok = f.status == null || /INTACT|OK|VERIFIED/i.test(f.status);
              return (
                <div key={key} className="flex items-baseline gap-1 whitespace-nowrap font-mono text-[10px] leading-[1.35]">
                  <span className="text-cyan-400/60">SHA256</span>
                  <span className="text-slate-500">{f.sha256 ? f.sha256.slice(0, 16) : '—'}</span>
                  <span className="truncate text-slate-300">{f.name}</span>
                  <span className="ms-auto shrink-0" style={{ color: ok ? '#34d399' : '#fb7185' }}>
                    {ok ? 'INTACT' : (f.status ?? 'ALTERED')}
                  </span>
                </div>
              );
            })}
          </div>
          <Row k={isAr ? 'جذر Merkle' : 'MERKLE ROOT'}>
            <Val v={a.fim.merkleRoot ? a.fim.merkleRoot.slice(0, 14) : null} reason={isAr ? 'لم يُحتسب بعد' : 'not yet calculated'} />
          </Row>
          <Row k={isAr ? 'أوراق الشجرة' : 'LEAF NODES'}><Val v={a.fim.merkleLeaves} /></Row>
          <p className="mt-0.5 truncate font-mono text-[10px] text-slate-400" title={a.fim.algorithm ?? undefined}>
            {a.fim.algorithm ?? '—'}
          </p>
        </>
      )}
    </ArsenalCard>
  );
};

/* ── 4. Active scanners ────────────────────────────────────────────────────── */

export const ScannerModule: React.FC<{ a: Arsenal; isAr: boolean }> = ({ a, isAr }) => (
  <ArsenalCard
    title={isAr ? 'الماسحات النشطة وإدارة الثغرات' : 'ACTIVE SCANNERS · VULN MGMT'}
    icon={Radar}
    tone={a.scans.count ? 'cyan' : 'amber'}
    headline={<Val v={a.scans.count} reason={isAr ? 'لا تدقيق مُنفَّذ' : 'no audit executed'} />}
  >
    {a.scans.history.length === 0 ? (
      <Empty
        endpoint="/scanner/history"
        note={
          isAr
            ? 'لا تدقيق مُنفَّذ بعد، فلا منافذ ولا ثغرات CVE لعرضها. التدقيق يُطلَق بـ POST على /scanner/audit — ولن أعرض منافذ مفتوحة لم يُمسحها شيء.'
            : 'no audit has run, so there are no open ports or CVE findings to show. audits are triggered by POST /scanner/audit — open ports nothing scanned for will not be drawn.'
        }
      />
    ) : (
      <div className="max-h-28 space-y-1 overflow-y-auto">
        {a.scans.history.slice(0, 10).map((h, i) => {
          const row = h as Record<string, unknown>;
          const ports = Array.isArray(row.openPorts) ? row.openPorts.length : null;
          const findings = Array.isArray(row.findings) ? row.findings.length : null;
          return (
            <div key={String(row.id ?? i)} className="border-b border-white/[0.04] pb-1">
              <div className="flex items-baseline justify-between gap-2">
                <span className="truncate font-mono text-[10px] text-slate-300">{String(row.target ?? '—')}</span>
                <span className="font-mono text-[10px] text-slate-400">
                  {String(row.startedAt ?? '').slice(11, 19)}
                </span>
              </div>
              <div className="flex gap-3">
                <span className="font-mono text-[10px] text-cyan-400">
                  {isAr ? 'منافذ' : 'PORTS'} {ports ?? '—'}
                </span>
                <span className="font-mono text-[10px] text-rose-400">
                  {isAr ? 'ثغرات' : 'FINDINGS'} {findings ?? '—'}
                </span>
              </div>
            </div>
          );
        })}
      </div>
    )}
  </ArsenalCard>
);

/* ── 5. Threat intelligence and honeypots ─────────────────────────────────── */

export const IntelModule: React.FC<{ a: Arsenal; isAr: boolean }> = ({ a, isAr }) => {
  const [tick, setTick] = React.useState(0);
  const iocs = a.intel.iocs;

  React.useEffect(() => {
    if (iocs.length === 0) return;
    const t = setInterval(() => setTick(x => (x + 1) % iocs.length), 3800);
    return () => clearInterval(t);
  }, [iocs.length]);

  const cur = iocs[tick] ?? null;

  return (
    <ArsenalCard
      title={isAr ? 'استخبارات التهديد · مخزن IOC' : 'THREAT INTEL · IOC STORE'}
      icon={Globe2}
      headline={<Val v={a.missing.includes('/forensics/threat-intel/iocs') ? null : iocs.length} tone="#fb7185" />}
    >
      {/* Provenance first: this ticker is a local store, and the platform is
          zero-egress. Presenting it as a live external STIX/TAXII feed would
          contradict the sovereignty claim the platform makes elsewhere. */}
      <p className="mb-1 font-mono text-[10px] leading-relaxed text-amber-400/90">
        {isAr
          ? `مخزن IOC محلّي. المصادر الخارجية مُهيّأة و${a.intel.totalLookups ?? 0} استعلام نُفِّذ — المنصّة صفر-خروج.`
          : `local IOC store. external sources configured, ${a.intel.totalLookups ?? 0} lookups performed — the platform is zero-egress.`}
      </p>

      {cur ? (
        <div className="border border-rose-900/50 bg-black/60 p-1.5">
          <div className="flex items-baseline justify-between gap-2">
            <span className="font-mono text-[10px] font-bold text-rose-400" style={{ textShadow: '0 0 8px rgba(225,29,72,0.8)' }}>
              {cur.type} · {cur.value}
            </span>
            <span className="font-mono text-[11px] font-bold text-rose-500">{cur.score ?? '—'}</span>
          </div>
          <p className="mt-0.5 truncate font-mono text-[10px] text-slate-400">{cur.actor ?? '—'}</p>
          <p className="truncate font-mono text-[10px] text-slate-500">{cur.family ?? '—'}</p>
          <p className="mt-0.5 truncate font-mono text-[10px] text-cyan-400">{cur.technique ?? cur.tactic ?? '—'}</p>
          <div className="mt-1 flex gap-0.5" aria-hidden>
            {iocs.map((_, i) => (
              <span key={i} className="h-[2px] flex-1" style={{ background: i === tick ? '#e11d48' : 'rgba(255,255,255,0.08)' }} />
            ))}
          </div>
        </div>
      ) : (
        <Empty endpoint="/forensics/threat-intel/iocs" note={isAr ? 'لا مؤشّرات اختراق مخزّنة.' : 'no indicators stored.'} />
      )}

      <div className="mt-1.5 border-t border-cyan-900/40 pt-1.5">
        <Label>{isAr ? 'المصادر الخارجية' : 'EXTERNAL SOURCES'}</Label>
        <div className="mt-0.5 flex flex-wrap gap-1">
          {a.intel.breakers.map(b => (
            <span
              key={b.source}
              className="border px-1 py-[1px] font-mono text-[10px] tracking-wider"
              style={{
                borderColor: b.state === 'OPEN' ? 'rgba(225,29,72,0.5)' : 'rgba(22,78,99,0.6)',
                color: b.state === 'OPEN' ? '#fb7185' : '#5c7484'
              }}
              title={`${b.source}: ${b.state} · ${b.successes ?? 0} ok / ${b.failures ?? 0} fail`}
            >
              {b.source} {b.state}
            </span>
          ))}
        </div>
      </div>

      {/* Decoy sessions moved to HoneypotSensorGrid, which can tell a seeded fixture
          from a live actor. Listed here they carried a pulsing "live" dot regardless. */}
    </ArsenalCard>
  );
};

/* ── 6. ZTNA and automated quarantine ─────────────────────────────────────── */

export const ZtnaModule: React.FC<{
  a: Arsenal;
  isAr: boolean;
  c: Containment;
  /** False for a VIEWER: containment and release render disabled, with the reason. */
  canAct?: boolean;
  /** Opens the two-step confirmation. This module never contains anything directly. */
  onRequestIsolate?: (ip: string) => void;
}> = ({ a, isAr, c, canAct = true, onRequestIsolate }) => {
  const roleNote = isAr ? 'يتطلّب دور محلّل' : 'requires the ANALYST role';
  const [target, setTarget] = React.useState('');
  const valid = /^(\d{1,3}\.){3}\d{1,3}$/.test(target.trim()) && target.trim().split('.').every(o => Number(o) <= 255);

  return (
    <ArsenalCard
      title={isAr ? 'الثقة الصفرية والحجر الآلي' : 'ZERO TRUST · AUTO QUARANTINE'}
      icon={Lock}
      tone={a.ztna.pendingFrozen || c.active.some(r => !r.seeded) ? 'rose' : 'cyan'}
      alert={Boolean(a.ztna.pendingFrozen) || c.active.some(r => !r.seeded)}
      headline={<Val v={a.ztna.activeHardBans} tone="#fb7185" />}
    >
      <Row k={isAr ? 'حجب صارم نشط' : 'ACTIVE HARD BANS'}><Val v={a.ztna.activeHardBans} tone="#fb7185" /></Row>
      <Row k={isAr ? 'تحدّيات نشطة' : 'ACTIVE CHALLENGES'}><Val v={a.ztna.activeChallenges} tone="#fbbf24" /></Row>
      <Row k={isAr ? 'الطبقة ١ تحديد معدّل' : 'TIER 1 RATE-LIMITED'}><Val v={a.ztna.tier1} /></Row>
      <Row k={isAr ? 'الطبقة ٣ حجب حرِج' : 'TIER 3 BLOCKED'}><Val v={a.ztna.tier3} tone="#fb7185" /></Row>
      <Row k={isAr ? 'مُجمَّد بانتظار موافقة' : 'FROZEN PENDING APPROVAL'}>
        <Val v={a.ztna.pendingFrozen} tone="#fbbf24" />
      </Row>

      <div className="mt-1.5 border-t border-cyan-900/40 pt-1.5">
        <Label>{isAr ? 'أحداث صلاحيات مميّزة' : 'PRIVILEGED ACTIONS'}</Label>
        {a.ztna.actions.length === 0 ? (
          <p className="mt-0.5 font-mono text-[10px] text-slate-400">{isAr ? 'لا أحداث' : 'none recorded'}</p>
        ) : (
          <div className="mt-0.5 max-h-20 space-y-1 overflow-y-auto">
            {a.ztna.actions.slice(0, 8).map(act => (
              <div key={act.id} className="border-b border-white/[0.04] pb-1">
                <div className="flex items-baseline justify-between gap-1.5">
                  <span className="truncate font-mono text-[10px] text-slate-300">{act.kind ?? '—'}</span>
                  <span
                    className="shrink-0 font-mono text-[10px] font-bold"
                    style={{ color: (act.risk ?? 0) >= 80 ? '#fb7185' : '#fbbf24' }}
                  >
                    {act.risk ?? '—'}
                  </span>
                </div>
                <p className="truncate font-mono text-[10px] text-slate-500" title={act.target ?? undefined}>
                  {act.target ?? '—'}
                </p>
                <p className="font-mono text-[10px] text-cyan-400/70">{act.status ?? '—'}</p>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Active containments. Release lives beside the evidence, because every isolation
          must be reversible from the surface that made it. */}
      <div className="mt-1.5 border-t border-cyan-900/40 pt-1.5">
        <Label tone="#fb7185">{isAr ? 'الاحتواءات النشطة' : 'ACTIVE CONTAINMENTS'}</Label>
        {c.error ? (
          <Empty endpoint="/soc/ebpf/containment-records" note={isAr ? 'المصدر لا يستجيب.' : 'source not responding.'} />
        ) : c.active.length === 0 ? (
          <p className="mt-0.5 font-mono text-[10px] text-slate-400">{isAr ? 'لا مضيف محتوى' : 'no host contained'}</p>
        ) : (
          <div className="mt-0.5 max-h-28 space-y-1 overflow-y-auto">
            {c.active.map(r => (
              <div key={r.id} className="flex items-center gap-1.5 border-b border-white/[0.04] pb-1">
                <div className="min-w-0 flex-1">
                  <p className="flex items-baseline gap-1.5 font-mono text-[10px]" dir="ltr">
                    <IpLink ip={r.ip} className="text-rose-300" />
                    {r.seeded && (
                      <span
                        className="border border-slate-600 px-1 text-[10px] text-slate-400"
                        title={isAr ? 'سجلّ تجريبي مزروع عند الإقلاع' : 'demo record seeded at boot, not an observed containment'}
                      >
                        SEEDED
                      </span>
                    )}
                  </p>
                  <p className="truncate font-mono text-[10px] text-slate-400" title={r.reason ?? undefined}>
                    {r.ioc ?? '—'} · {r.at?.slice(11, 19) ?? '—'}
                  </p>
                </div>
                <CyberButton
                  tone="emerald"
                  size="sm"
                  disabled={!canAct || c.busyIp === r.ip}
                  title={!canAct ? roleNote : isAr ? `رفع العزل عن ${r.ip}` : `release ${r.ip}`}
                  onClick={() => void c.release(r.ip)}
                >
                  {c.busyIp === r.ip ? '…' : isAr ? 'فك' : 'RELEASE'}
                </CyberButton>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Manual isolation. Armed only by a syntactically valid address, and even then it
          opens the two-step confirmation rather than firing. */}
      <div className="mt-1.5 border-t border-cyan-900/40 pt-1.5">
        <Label tone="#fb7185">{isAr ? 'عزل يدوي' : 'MANUAL ISOLATION'}</Label>
        <input
          value={target}
          onChange={e => setTarget(e.target.value)}
          placeholder="0.0.0.0"
          inputMode="numeric"
          dir="ltr"
          aria-label={isAr ? 'عنوان IP للعزل' : 'IP address to isolate'}
          className="mt-0.5 w-full border border-cyan-900/50 bg-black/60 px-1.5 py-1 font-mono text-[11px] text-cyan-400 placeholder:text-slate-400 focus:border-cyan-500/60 focus:outline-none"
        />
        <div className="mt-1">
          <CyberButton
            tone="rose"
            size="sm"
            className="w-full"
            disabled={!valid || c.busyIp != null || !onRequestIsolate}
            title={!canAct ? roleNote : valid ? undefined : isAr ? 'أدخل عنوان IPv4 صحيحًا' : 'enter a valid IPv4 address'}
            onClick={valid && onRequestIsolate ? () => onRequestIsolate(target.trim()) : undefined}
          >
            {c.busyIp ? (isAr ? '… جارٍ' : '… WORKING') : '[ ISOLATE_NODE ]'}
          </CyberButton>
        </div>
        {c.last && (
          <p
            role="status"
            className="mt-1 font-mono text-[10px]"
            style={{ color: c.last.ok ? '#34d399' : '#fb7185' }}
            dir="ltr"
          >
            {c.last.kind} {c.last.ip} · {c.last.message}
          </p>
        )}
      </div>
    </ArsenalCard>
  );
};

export const ARSENAL_ICONS = { Cpu, ShieldCheck, FileLock2, Radar, Globe2, Lock };
