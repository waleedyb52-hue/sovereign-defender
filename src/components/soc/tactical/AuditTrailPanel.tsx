import React from 'react';
import { ShieldCheck, ShieldAlert, Copy, Check } from 'lucide-react';
import { CyberButton } from './CyberButton';
import { useAuditTrail, type AuditFilter } from './useAuditTrail';
import { IpLink } from './ipDossier';

/**
 * AUDIT TRAIL — who did what, and proof that the record was not rewritten.
 *
 * The verify result is stated precisely rather than as "immutable". The chain and HMAC
 * make any edit, deletion or re-hash detectable; they cannot stop someone with the key
 * file from forging a fresh consistent log. Copying the head hash somewhere else — a
 * ticket, a shift report — is what makes a later rewrite provable, so the panel offers
 * exactly that.
 */

const OUTCOME: Record<'SUCCESS' | 'DENIED' | 'FAILURE', { fg: string; glyph: string; ar: string }> = {
  SUCCESS: { fg: '#34d399', glyph: '✓', ar: 'نجح' },
  DENIED: { fg: '#fbbf24', glyph: '⛔', ar: 'مرفوض' },
  FAILURE: { fg: '#fb7185', glyph: '✕', ar: 'فشل' }
};

const FILTERS: Array<{ id: AuditFilter; ar: string; en: string }> = [
  { id: 'ALL', ar: 'الكل', en: 'ALL' },
  { id: 'CONTAIN', ar: 'عزل', en: 'CONTAIN' },
  { id: 'RELEASE', ar: 'فك', en: 'RELEASE' },
  { id: 'LOGIN', ar: 'دخول', en: 'LOGIN' },
  { id: 'DENIED', ar: 'مرفوض/فاشل', en: 'DENIED / FAILED' }
];

export const AuditTrailPanel: React.FC<{ isAr: boolean }> = ({ isAr }) => {
  const [filter, setFilter] = React.useState<AuditFilter>('ALL');
  const t = useAuditTrail(filter);
  const [copied, setCopied] = React.useState(false);
  const v = t.verification;

  const copyHead = async () => {
    if (!v?.headHash) return;
    try {
      await navigator.clipboard.writeText(`seq ${v.headSeq} ${v.headHash} @ ${v.at}`);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard refused; the hash is still selectable on screen */
    }
  };

  return (
    <div className="flex h-full min-h-[360px] flex-col gap-2" dir={isAr ? 'rtl' : 'ltr'}>
      {/* Verification */}
      <div
        className="border p-2.5"
        style={{
          borderColor: !v ? 'rgba(22,78,99,0.6)' : v.ok ? 'rgba(16,185,129,0.5)' : 'rgba(244,63,94,0.6)',
          background: !v ? 'rgba(0,0,0,0.4)' : v.ok ? 'rgba(2,44,34,0.35)' : 'rgba(76,5,25,0.4)'
        }}
      >
        <div className="flex flex-wrap items-center gap-2">
          {v ? (
            v.ok ? (
              <ShieldCheck className="h-4 w-4 text-emerald-400" aria-hidden />
            ) : (
              <ShieldAlert className="h-4 w-4 text-rose-400" aria-hidden />
            )
          ) : null}
          <p className="text-sm font-semibold" style={{ color: !v ? '#cbd5e1' : v.ok ? '#6ee7b7' : '#fda4af' }} role="status">
            {!v
              ? isAr
                ? 'لم تُفحص السلسلة في هذه الجلسة'
                : 'Chain not checked this session'
              : v.ok
                ? isAr
                  ? `السلسلة سليمة · ${v.checked} قيد`
                  : `Chain intact · ${v.checked} entries`
                : isAr
                  ? `السلسلة مكسورة عند القيد #${v.brokenAt}`
                  : `Chain broken at entry #${v.brokenAt}`}
          </p>
          <span className="ms-auto">
            <CyberButton tone={v && !v.ok ? 'rose' : 'cyan'} size="sm" disabled={t.verifying} onClick={() => void t.verify()}>
              {t.verifying ? '…' : isAr ? '[ افحص السلسلة ]' : '[ VERIFY CHAIN ]'}
            </CyberButton>
          </span>
        </div>
        {v && !v.ok && v.reason && <p className="mt-1 font-mono text-xs text-rose-200" dir="ltr">{v.reason}</p>}
        {v?.headHash && (
          <div className="mt-1.5 flex flex-wrap items-center gap-2">
            <span className="text-xs text-slate-300">{isAr ? 'بصمة الرأس' : 'Head hash'}</span>
            <code className="font-mono text-xs break-all text-cyan-300 select-all" dir="ltr">
              #{v.headSeq} {v.headHash}
            </code>
            <button
              type="button"
              onClick={() => void copyHead()}
              className="flex items-center gap-1 border border-cyan-700/60 px-1.5 py-0.5 text-xs text-cyan-300 hover:bg-cyan-500/10"
            >
              {copied ? <Check className="h-3 w-3" aria-hidden /> : <Copy className="h-3 w-3" aria-hidden />}
              {isAr ? 'نسخ' : 'Copy'}
            </button>
          </div>
        )}
        <p className="mt-1.5 text-xs leading-relaxed text-slate-400">
          {isAr
            ? 'كل قيد مربوط ببصمة سابقه ومختوم بـ HMAC، فأي تعديل أو حذف يُكتشف. احفظ بصمة الرأس خارج هذا الخادم ليصبح أي تزوير لاحق قابلًا للإثبات.'
            : 'Each entry is chained to the one before and sealed with an HMAC, so any edit or deletion is detected. Keep the head hash somewhere off this server to make a later rewrite provable.'}
        </p>
        {v?.keySource === 'EPHEMERAL' && (
          <p className="mt-1 text-xs text-amber-300">
            {isAr
              ? 'مفتاح الختم مؤقت (لا يوجد تخزين دائم)؛ القيود السابقة لإعادة التشغيل لن تتحقق.'
              : 'The sealing key is ephemeral (no durable storage); entries from before a restart will not verify.'}
          </p>
        )}
        {t.durable === false && (
          <p className="mt-1 text-xs text-amber-300">
            {isAr ? 'السجل في الذاكرة فقط ولن ينجو من إعادة التشغيل.' : 'The trail is in memory only and will not survive a restart.'}
          </p>
        )}
      </div>

      {/* Filters */}
      <div className="flex flex-wrap gap-1" role="group" aria-label={isAr ? 'تصفية' : 'Filter'}>
        {FILTERS.map(f => (
          <CyberButton key={f.id} size="sm" tone="cyan" active={filter === f.id} onClick={() => setFilter(f.id)}>
            {isAr ? f.ar : f.en}
          </CyberButton>
        ))}
      </div>

      {/* Entries */}
      <div className="min-h-0 flex-1 overflow-auto border border-cyan-900/50 bg-black/50">
        {t.error ? (
          <p className="p-3 font-mono text-xs text-rose-300" dir="ltr">{t.error}</p>
        ) : t.loading && t.entries.length === 0 ? (
          <p className="p-3 text-xs text-slate-400">{isAr ? 'جارٍ التحميل…' : 'Loading…'}</p>
        ) : t.entries.length === 0 ? (
          <p className="p-3 text-xs text-slate-400">
            {isAr ? 'لا قيود لهذا التصنيف.' : 'No entries for this filter.'}{' '}
            <span className="font-mono text-slate-500" dir="ltr">GET /api/v1/audit</span>
          </p>
        ) : (
          <table className="w-full border-collapse text-start text-xs">
            <thead className="sticky top-0 bg-[#030712]">
              <tr className="text-slate-400">
                {[isAr ? '#' : '#', isAr ? 'الوقت' : 'TIME', isAr ? 'المشغّل' : 'ACTOR', isAr ? 'الإجراء' : 'ACTION', isAr ? 'الهدف' : 'TARGET', isAr ? 'النتيجة' : 'OUTCOME', 'IP'].map(h => (
                  <th key={h} scope="col" className="border-b border-cyan-900/60 px-2 py-1.5 text-start font-medium tracking-wide">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {t.entries.map(e => {
                const o = OUTCOME[e.outcome];
                return (
                  <tr key={e.seq} className="border-b border-white/[0.04] hover:bg-cyan-500/[0.04]">
                    <td className="px-2 py-1 font-mono text-slate-500">{e.seq}</td>
                    <td className="px-2 py-1 font-mono whitespace-nowrap text-slate-300" dir="ltr" title={e.at}>
                      {e.at.slice(5, 10)} {e.at.slice(11, 19)}
                    </td>
                    <td className="px-2 py-1 text-slate-200">
                      <span className="font-mono">{e.actor}</span>
                      {e.role && <span className="ms-1 text-[10px] text-slate-500">{e.role}</span>}
                    </td>
                    <td className="px-2 py-1 font-mono text-cyan-300">{e.action}</td>
                    <td className="max-w-[220px] truncate px-2 py-1 font-mono text-slate-300" dir="ltr" title={e.target ?? undefined}>
                      {e.target && /^(\d{1,3}\.){3}\d{1,3}$/.test(e.target) ? <IpLink ip={e.target} /> : (e.target ?? '—')}
                    </td>
                    <td className="px-2 py-1 whitespace-nowrap" style={{ color: o.fg }}>
                      <span aria-hidden>{o.glyph}</span> {isAr ? o.ar : e.outcome}
                    </td>
                    <td className="px-2 py-1 font-mono text-slate-400" dir="ltr">{e.ip ?? '—'}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
};

export default AuditTrailPanel;
