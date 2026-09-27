import React from 'react';
import { motion, useReducedMotion } from 'motion/react';
import { Activity, RefreshCw, ShieldAlert } from 'lucide-react';
import { useTelemetry, useThreatFeed, useIsolation } from '../../hooks/useTelemetry';
import { TelemetryHud } from './TelemetryHud';
import { EbpfTopologyGraph } from './EbpfTopologyGraph';
import { ThreatAuditTable } from './ThreatAuditTable';
import { IsolationProtocol, CompliancePosture } from './IsolationProtocol';
import { Button, Badge, Mono } from '../ui/primitives';

/**
 * SOC DASHBOARD
 *
 * Assembles the telemetry HUD, the eBPF topology, the threat audit log and the
 * isolation protocol over three hooks. The dashboard itself holds no parsing and
 * no fetching — that is all in `useTelemetry.ts`, so this file is layout and
 * wiring and can be read in one sitting.
 *
 * What this component deliberately does not do
 *   It does not supply fallback data. Every panel below receives whatever the
 *   server actually returned, including nothing, and each renders its own empty
 *   state naming the endpoint that came back quiet. A dashboard that fills its
 *   own gaps is worse than an incomplete one, because the operator cannot tell
 *   which parts of it are load-bearing.
 *
 * Isolation is lifted to this level on purpose: the target can be chosen from
 * either the topology or the audit table, and both must drive the same confirmed,
 * real-endpoint path rather than each growing its own.
 */

interface Props {
  lang?: 'ar' | 'en';
}

export const Dashboard: React.FC<Props> = ({ lang = 'ar' }) => {
  const isAr = lang === 'ar';
  const reduce = useReducedMotion();
  const telemetry = useTelemetry();
  const feed = useThreatFeed();
  const isolation = useIsolation();
  const [isolationTarget, setIsolationTarget] = React.useState<string | null>(null);

  /**
   * Threat nodes for the topology.
   *
   * Derived from quarantined hosts in the audit feed rather than from a separate
   * request, and deduplicated by address. Only events that actually carry a
   * source address contribute — a threat node without an address would be a
   * decorative shape on a network diagram.
   */
  const threats = React.useMemo(() => {
    const seen = new Map<string, { ip: string; threatScore?: number | null; isolated?: boolean }>();
    for (const e of feed.events) {
      const ip = e.srcIp ?? e.sourceIp;
      if (!ip || seen.has(ip)) continue;
      const sev = e.severity?.toUpperCase() ?? '';
      if (!/CRITICAL|HIGH|MEDIUM/.test(sev)) continue;
      seen.set(ip, {
        ip,
        isolated: /ISOLAT|CONTAIN|BLOCK|QUARANT/i.test(e.actionTaken ?? '')
      });
    }
    return [...seen.values()].slice(0, 6);
  }, [feed.events]);

  const refreshAll = () => {
    telemetry.refresh();
    feed.refresh();
  };

  return (
    <div className="min-h-screen bg-[#080B11] p-4 lg:p-6" dir={isAr ? 'rtl' : 'ltr'}>
      <motion.div
        initial={reduce ? { opacity: 0 } : { opacity: 0, y: 4 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.25, ease: 'easeOut' }}
        className="mx-auto max-w-[1600px] space-y-4"
      >
        {/* Header */}
        <header className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2.5">
            <Activity className="h-5 w-5 text-[#22d3ee]" aria-hidden />
            <div>
              <h1
                className="text-base leading-tight font-semibold text-slate-100"
                style={{ fontFamily: 'var(--font-sans)' }}
              >
                {isAr ? 'المدافع السيادي — مركز العمليات' : 'Sovereign Defender — Operations'}
              </h1>
              <p className="text-[10px] text-slate-500">
                {isAr
                  ? 'كل رقم هنا مقروء من الخدمة، أو معلَن أنه غير متوفر.'
                  : 'Every figure here is read from the service, or declared unavailable.'}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            {feed.emergencyLockdown && (
              <Badge
                tone="quarantine"
                icon={ShieldAlert}
                label={isAr ? 'إغلاق طارئ نشط' : 'EMERGENCY LOCKDOWN'}
              />
            )}
            <Button variant="secondary" size="sm" onClick={refreshAll} disabled={telemetry.loading}>
              <RefreshCw
                className={telemetry.loading ? 'h-3 w-3 animate-spin' : 'h-3 w-3'}
                aria-hidden
              />
              {isAr ? 'تحديث' : 'Refresh'}
            </Button>
          </div>
        </header>

        {/* 1 — Telemetry HUD */}
        <TelemetryHud telemetry={telemetry} lang={lang} />

        {/* 2 — Topology and audit log. The graph is narrower: the table is the
               surface an analyst actually works in for long stretches. */}
        <div className="grid grid-cols-1 gap-4 xl:grid-cols-5">
          <div className="xl:col-span-2">
            <EbpfTopologyGraph
              nodes={telemetry.nodes}
              threats={threats}
              lang={lang}
              onIsolate={setIsolationTarget}
            />
          </div>
          <div className="xl:col-span-3">
            <ThreatAuditTable
              events={feed.events}
              freshIds={feed.freshIds}
              loading={feed.loading}
              error={feed.error}
              lang={lang}
              onIsolate={setIsolationTarget}
              isolating={isolation.pending}
            />
          </div>
        </div>

        {/* 3 — Sovereignty posture, driven by the live configuration. */}
        <CompliancePosture lang={lang} zeroEgress={telemetry.inference.zeroExternalApiCalls} />

        <footer className="flex flex-wrap items-center justify-between gap-2 pt-1 text-[9px] text-slate-600">
          <span>
            {isAr ? 'المحرّك: ' : 'Engine: '}
            <Mono>{telemetry.inference.engine ?? '—'}</Mono>
          </span>
          <span>
            {isAr ? 'التقييمات: ' : 'Evaluations: '}
            <Mono>{telemetry.inference.evaluations ?? '—'}</Mono>
          </span>
        </footer>
      </motion.div>

      {/* Isolation, shared by both surfaces. */}
      <IsolationProtocol
        target={isolationTarget}
        onClose={() => {
          setIsolationTarget(null);
          isolation.clearResult();
        }}
        onConfirm={isolation.isolate}
        onRelease={isolation.release}
        pending={isolation.pending}
        result={isolation.result}
        lang={lang}
      />
    </div>
  );
};

export default Dashboard;
