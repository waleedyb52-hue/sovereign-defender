import React from 'react';
import { useReducedMotion } from 'motion/react';
import { Crosshair } from 'lucide-react';
import { useCyberDefendData } from '../cyberdefend/useCyberDefendData';
import { useAssets } from './useAssets';
import { useArsenal } from './useArsenal';
import { useContainment } from './useContainment';
import { useLanWatch } from './useLanWatch';
import { useLiveAttackStream } from './useLiveAttackStream';
import { useIncidentMode } from './useIncidentMode';
import { useOperator } from '../../auth/operatorContext';
import { NetworkTopologyView } from './NetworkTopologyView';
import { TacticalTheater } from './TacticalTheater';
import { IncidentBanner } from './IncidentBanner';
import { IpDossierContext, IpLink } from './ipDossier';
import { IpDossierDrawer } from './IpDossierDrawer';
import { postWall, useWallChannel, WALL_PANELS, type WallPanel } from './wallChannel';

const NetworkTopology3D = React.lazy(() => import('./NetworkTopology3D').then(m => ({ default: m.NetworkTopology3D })));

/**
 * WALL VIEW — one theatre per screen, for a room with more than one display.
 *
 * Opened from the cockpit as /?wall=<panel>. Each window reads the same endpoints as the
 * cockpit (it is the same data, not a copy) and follows the operator's selection over a
 * same-machine BroadcastChannel: pick an address anywhere and its dossier opens on every
 * screen. The incident banner, and its shared acknowledgement, appear on every screen too
 * — a wall that showed calm while the console showed an incident would be worse than no
 * wall. There are no controls to lose on a display across the room: acting stays at the
 * console, and the dossier's containment buttons still pass through the two-step dialog
 * only there.
 */
export const WallView: React.FC<{ panel: WallPanel; lang: 'ar' | 'en' }> = ({ panel, lang }) => {
  const isAr = lang === 'ar';
  const reduce = useReducedMotion() ?? false;
  const { can } = useOperator();
  const d = useCyberDefendData();
  const fleet = useAssets();
  const a = useArsenal();
  const c = useContainment();
  const lan = useLanWatch();
  const stream = useLiveAttackStream();
  const inc = useIncidentMode(d.alerts, c.records);
  const [dossierIp, setDossierIp] = React.useState<string | null>(null);
  const [utc, setUtc] = React.useState(() => new Date().toISOString());

  React.useEffect(() => {
    const t = setInterval(() => setUtc(new Date().toISOString()), 1000);
    return () => clearInterval(t);
  }, []);

  React.useEffect(() => {
    document.documentElement.setAttribute('data-surface', 'tactical');
    document.title = `Sovereign Defender · ${WALL_PANELS.find(p => p.id === panel)?.en ?? 'WALL'}`;
  }, [panel]);

  useWallChannel(msg => {
    if (msg.type === 'select-ip') setDossierIp(msg.ip);
    if (msg.type === 'close-dossier') setDossierIp(null);
  });

  const dossier = React.useMemo(
    () => ({
      open: (ip: string) => {
        setDossierIp(ip);
        postWall({ type: 'select-ip', ip });
      }
    }),
    []
  );

  const hot = React.useMemo(() => {
    const m = new Map<string, string>();
    for (const x of d.alerts) if (x.srcIp && /CRITICAL|HIGH/.test(x.severity) && !m.has(x.srcIp)) m.set(x.srcIp, `${x.severity} alert`);
    for (const x of c.active) if (!x.seeded) m.set(x.ip, 'contained');
    return m;
  }, [d.alerts, c.active]);

  const alertCounts = React.useMemo(() => {
    const cutoff = Date.now() - 10 * 60_000;
    const m = new Map<string, number>();
    for (const x of d.alerts) if (x.srcIp && /CRITICAL|HIGH/.test(x.severity) && Date.parse(x.at) >= cutoff) m.set(x.srcIp, (m.get(x.srcIp) ?? 0) + 1);
    return m;
  }, [d.alerts]);

  const meta = WALL_PANELS.find(p => p.id === panel);
  const critical = d.alerts.filter(x => x.severity === 'CRITICAL');

  return (
    <IpDossierContext.Provider value={dossier}>
      <div className="fixed inset-0 flex flex-col overflow-hidden bg-black text-slate-100" dir={isAr ? 'rtl' : 'ltr'}>
        <header className="flex shrink-0 items-center gap-3 border-b border-cyan-900/60 bg-[#030712]/80 px-4 py-2">
          <Crosshair className="h-4 w-4 text-cyan-300" aria-hidden />
          <span className="font-mono text-sm font-bold tracking-[0.25em] text-white">SOVEREIGN DEFENDER</span>
          <span className="font-mono text-sm tracking-widest text-cyan-300">· {isAr ? meta?.ar : meta?.en}</span>
          <span className="ms-auto font-mono text-xs" style={{ color: stream.status === 'LIVE' ? '#34d399' : '#fb7185' }}>
            {stream.status === 'LIVE' ? `WS · ${stream.packetsSeen}` : 'WS DOWN'}
          </span>
          <span className="font-mono text-lg font-bold text-cyan-200 tabular-nums" dir="ltr">{utc.slice(11, 19)} UTC</span>
        </header>

        <IncidentBanner inc={inc} isAr={isAr} canAct={can('ANALYST')} onShowCritical={() => undefined} />

        <main className="relative min-h-0 flex-1">
          {panel === 'net' && <NetworkTopologyView assets={fleet.assets} isAr={isAr} onSelectAsset={() => undefined} hot={hot} className="h-full w-full" />}

          {panel === 'net3d' && (
            <React.Suspense fallback={<p className="grid h-full place-items-center font-mono text-sm text-cyan-400/70">LOADING 3D…</p>}>
              <NetworkTopology3D
                assets={fleet.assets}
                hot={hot}
                alertCounts={alertCounts}
                lanStates={new Map((lan.status?.devices ?? []).map(x => [x.mac.toLowerCase(), x.state] as const))}
                isAr={isAr}
                onSelectIp={ip => dossier.open(ip)}
                className="h-full w-full"
              />
            </React.Suspense>
          )}

          {panel === 'geo' && (
            <TacticalTheater
              contacts={d.geo.map(g => ({ code: g.code, country: g.country, count: g.count }))}
              nodes={d.nodes.map(n => ({ name: n.name, ip: n.ip, isolated: n.isolated, threatScore: n.threatScore }))}
              tracers={stream.tracers}
              status={stream.status}
              reduce={reduce}
              isAr={isAr}
              className="h-full w-full"
            />
          )}

          {panel === 'feed' && (
            <div className="h-full overflow-y-auto p-4">
              {d.alerts.length === 0 ? (
                <p className="text-lg text-slate-400">{isAr ? 'لا أحداث.' : 'No events.'} <span className="font-mono text-sm text-slate-500">/soc/unified-telemetry</span></p>
              ) : (
                <table className="w-full border-collapse text-start">
                  <thead>
                    <tr className="text-sm tracking-widest text-slate-400">
                      {[isAr ? 'الوقت' : 'TIME', isAr ? 'الخطورة' : 'SEV', 'MITRE', isAr ? 'المصدر' : 'SOURCE', isAr ? 'الحدث' : 'EVENT'].map(h => (
                        <th key={h} className="border-b border-cyan-900/60 px-3 py-2 text-start font-medium">{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {[...d.alerts].sort((x, y) => y.at.localeCompare(x.at)).slice(0, 40).map(x => (
                      <tr key={x.id} className={`border-b border-white/[0.05] text-base ${x.severity === 'CRITICAL' ? 'bg-rose-950/30' : ''}`}>
                        <td className="px-3 py-2 font-mono text-slate-300" dir="ltr">{x.at.slice(11, 19)}</td>
                        <td className={`px-3 py-2 font-mono font-bold ${/CRITICAL|HIGH/.test(x.severity) ? 'text-rose-300' : 'text-cyan-300'}`}>{x.severity}</td>
                        <td className={`px-3 py-2 font-mono ${x.mitre ? 'text-cyan-300' : 'text-slate-500'}`}>{x.mitre ?? 'UNMAPPED'}</td>
                        <td className="px-3 py-2"><IpLink ip={x.srcIp} className="text-slate-200" /></td>
                        <td className="px-3 py-2 text-slate-100" dir="auto">{x.title}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          )}

          {panel === 'incident' && (
            <div className="grid h-full place-items-center p-8">
              {inc.active && inc.since ? (
                <div className="w-full max-w-5xl text-center">
                  <p className="text-2xl font-bold tracking-widest text-rose-300">{isAr ? 'حادثة نشطة' : 'ACTIVE INCIDENT'}</p>
                  <p className="mt-2 font-mono text-8xl font-bold text-white tabular-nums" dir="ltr" style={{ textShadow: '0 0 40px rgba(244,63,94,0.7)' }}>
                    T+{Math.floor((inc.now - Date.parse(inc.since)) / 60000).toString().padStart(2, '0')}:
                    {Math.floor(((inc.now - Date.parse(inc.since)) % 60000) / 1000).toString().padStart(2, '0')}
                  </p>
                  <p className="mt-3 text-xl text-rose-200">
                    {inc.criticalCount} {isAr ? 'حدث حرج' : 'critical events'} · {inc.containedAt ? (isAr ? 'محتوى' : 'contained') : isAr ? 'لم يُحتوَ' : 'not contained'}
                    {inc.ack && <span className="text-emerald-300"> · {isAr ? 'استلمها' : 'taken by'} {inc.ack.by}</span>}
                  </p>
                  <ul className="mx-auto mt-6 max-w-3xl space-y-1 text-start">
                    {critical.slice(-8).reverse().map(x => (
                      <li key={x.id} className="flex items-baseline gap-3 text-lg">
                        <span className="font-mono text-slate-400" dir="ltr">{x.at.slice(11, 19)}</span>
                        <span className="font-mono text-cyan-300">{x.mitre ?? 'UNMAPPED'}</span>
                        <span className="truncate text-slate-100" dir="auto">{x.title}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              ) : (
                <div className="text-center">
                  <p className="text-3xl font-semibold tracking-widest text-emerald-300">{isAr ? 'لا حادثة نشطة' : 'NO ACTIVE INCIDENT'}</p>
                  <p className="mt-3 text-lg text-slate-400">
                    {critical.length
                      ? `${isAr ? 'آخر حدث حرج' : 'last critical event'} ${[...critical.map(x => x.at)].sort().pop()?.slice(11, 19)} UTC`
                      : isAr ? 'لا أحداث حرجة في التغذية.' : 'no critical events in the feed.'}
                  </p>
                </div>
              )}
            </div>
          )}

          {dossierIp && (
            <IpDossierDrawer
              ip={dossierIp}
              isAr={isAr}
              alerts={d.alerts}
              a={a}
              c={c}
              lan={lan}
              assets={fleet.assets}
              canAct={false}
              displayOnly
              onClose={() => {
                setDossierIp(null);
                postWall({ type: 'close-dossier' });
              }}
            />
          )}
        </main>
      </div>
    </IpDossierContext.Provider>
  );
};

export default WallView;
