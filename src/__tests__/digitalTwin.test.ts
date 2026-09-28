import { describe, expect, it } from 'vitest';
import { projectExposure, scenarioForPhase } from '../components/soc/tactical/digitalTwin';
import type { AssetRow } from '../components/soc/tactical/useAssets';

const nb = (ip: string, openPorts: number[] | undefined, sweepState: 'RESPONDED' | 'NO_RESPONSE' | 'NOT_IN_RANGE' | null) => ({
  ip, mac: '00:11:22:33:44:' + ip.split('.')[3].padStart(2, '0'), vendor: null, arpType: null, viaInterface: null,
  method: 'ARP_CACHE', discoveredAt: '2026-09-28T00:00:00Z', openPorts, sweepState
});

const host = (neighbours: ReturnType<typeof nb>[]): AssetRow =>
  ({
    id: 'AST-1', kind: 'HOST', label: 'h', hostname: 'h', platform: 'win32', arch: 'x64', primaryIp: '10.0.0.5',
    interfaces: [], cidr: null, enrolledAt: '', lastSeenAt: '', heartbeatIntervalSec: 30, sensorVersion: '1',
    isolated: false, isolatedAt: null, flowsIngested: 0, liveness: 'ONLINE', lastSweep: null,
    posture: { neighbours, segments: [], listeningPorts: null, establishedConnections: null, processes: null, loggedInUsers: null, uptimeSec: null, extra: null }
  }) as unknown as AssetRow;

describe('projectExposure', () => {
  const assets = [
    host([
      nb('10.0.0.10', [22, 80], 'RESPONDED'),
      nb('10.0.0.11', [443], 'RESPONDED'),
      nb('10.0.0.12', [], 'NO_RESPONSE'),
      nb('10.0.0.13', undefined, null)
    ])
  ];

  it('marks a device EXPOSED only for ports the scenario uses, and lists them', () => {
    const p = projectExposure(assets, 'phase2-apt');
    const r = p.rows.find(x => x.ip === '10.0.0.10')!;
    expect(r.state).toBe('EXPOSED');
    expect(r.ports).toEqual([22]);
    expect(p.rows.find(x => x.ip === '10.0.0.11')!.state).toBe('CLEAR');
  });

  it('never assumes anything about an unswept device', () => {
    const p = projectExposure(assets, 'phase1-ddos');
    expect(p.rows.find(x => x.ip === '10.0.0.13')!.state).toBe('UNKNOWN');
    expect(p.rows.find(x => x.ip === '10.0.0.12')!.state).toBe('CLEAR');
    expect(p.exposed).toBe(2);
    expect(p.unknown).toBe(1);
  });

  it('targets the enrolled hosts themselves for the impair-defences drill', () => {
    const p = projectExposure(assets, 'phase3-ebpf');
    expect(p.rows).toHaveLength(1);
    expect(p.rows[0]).toMatchObject({ ip: '10.0.0.5', state: 'EXPOSED', host: true });
  });

  it('maps a running phase to its scenario', () => {
    expect(scenarioForPhase(2)).toBe('phase2-apt');
    expect(scenarioForPhase(0)).toBe('phase1-ddos');
  });
});
