import { DatabaseSync } from 'node:sqlite';
import fs from 'fs';
import path from 'path';
import { globalUnifiedTelemetryService } from './unifiedTelemetry.service.js';

/**
 * LAN WATCH — new devices, and ARP poisoning of the gateway.
 *
 * Input is what enrolled sensors already report on every heartbeat: the ARP neighbours
 * they have exchanged frames with, and (new) the default gateway from their routing
 * table. Nothing here sends a packet.
 *
 * NEW DEVICE (MITRE T1200, Hardware Additions)
 *   A host's first report sets its baseline silently — every device already on the
 *   network would otherwise alert at once. After that, a MAC never seen before raises an
 *   alert until an operator approves it. Randomised (locally administered) MACs — phones
 *   and laptops with private addressing — rotate by design, so they alert at LOW with
 *   that stated, instead of crying wolf at MEDIUM every time a phone reconnects.
 *
 * ARP POISONING (MITRE T1557.002, ARP Cache Poisoning)
 *   Two signals, both about the gateway, because the gateway is what a man-in-the-middle
 *   impersonates:
 *     - the gateway's MAC changed since it was first bound (HIGH: a replaced router does
 *       this too, so it asks for verification rather than declaring an attack);
 *     - the gateway's MAC also answers for another address on the same segment
 *       (CRITICAL: a host claiming both its own address and the gateway's is the
 *       textbook poisoning signature).
 *   Only runs for hosts whose sensor reported a gateway. Where the route table could not
 *   be read, the status says detection is unavailable — it does not guess from ".1".
 */

export type DeviceState = 'BASELINE' | 'NEW' | 'APPROVED';

export interface LanDevice {
  mac: string;
  lastIp: string | null;
  ips: string[];
  vendor: string | null;
  randomized: boolean;
  state: DeviceState;
  firstSeen: string;
  lastSeen: string;
  seenBy: string[];
  approvedBy: string | null;
  approvedAt: string | null;
}

export interface LanEvent {
  id: string;
  at: string;
  kind: 'NEW_DEVICE' | 'GATEWAY_MAC_CHANGED' | 'ARP_SPOOF_SUSPECTED' | 'BASELINE_RECORDED';
  severity: 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  assetId: string;
  ip: string | null;
  mac: string | null;
  detail: string;
  mitre: string | null;
}

interface NeighbourIn {
  ip: string;
  mac: string;
  vendor?: string | null;
}

const MAX_EVENTS = 300;

/** Locally administered bit set: the second hex digit is 2, 6, A or E. */
export const isRandomizedMac = (mac: string) => /^.[26ae][:-]/i.test(mac);

export class LanWatchService {
  private db: DatabaseSync;
  private persistent = false;
  private events: LanEvent[] = [];
  /** Active spoof signatures, so a standing condition alerts once, not every heartbeat. */
  private activeSpoofs = new Set<string>();
  private gatewayReporting = new Map<string, boolean>();

  constructor(dbPath?: string) {
    const target = dbPath ?? path.join(process.cwd(), 'data', 'lan_watch.db');
    try {
      fs.mkdirSync(path.dirname(target), { recursive: true });
      this.db = new DatabaseSync(target);
      this.persistent = target !== ':memory:';
    } catch (err: any) {
      console.warn('[lan-watch] falling back to in-memory store:', err?.message);
      this.db = new DatabaseSync(':memory:');
      this.persistent = false;
    }
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS lan_devices (
        mac         TEXT PRIMARY KEY,
        last_ip     TEXT,
        ips         TEXT NOT NULL DEFAULT '[]',
        vendor      TEXT,
        randomized  INTEGER NOT NULL DEFAULT 0,
        state       TEXT NOT NULL,
        first_seen  TEXT NOT NULL,
        last_seen   TEXT NOT NULL,
        seen_by     TEXT NOT NULL DEFAULT '[]',
        approved_by TEXT,
        approved_at TEXT
      );
      CREATE TABLE IF NOT EXISTS lan_baselines (
        asset_id     TEXT PRIMARY KEY,
        baselined_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS gateway_bindings (
        asset_id   TEXT NOT NULL,
        gateway_ip TEXT NOT NULL,
        mac        TEXT NOT NULL,
        first_seen TEXT NOT NULL,
        last_seen  TEXT NOT NULL,
        PRIMARY KEY (asset_id, gateway_ip)
      );
    `);
  }

  public durable(): boolean {
    return this.persistent;
  }

  private emit(e: Omit<LanEvent, 'id' | 'at'>) {
    const ev: LanEvent = { id: 'LAN-' + Math.random().toString(36).slice(2, 10).toUpperCase(), at: new Date().toISOString(), ...e };
    this.events.push(ev);
    while (this.events.length > MAX_EVENTS) this.events.shift();
    if (e.kind === 'BASELINE_RECORDED') return;
    try {
      globalUnifiedTelemetryService.recordEvent({
        source: 'LAN_WATCH',
        severity: e.severity,
        title:
          e.kind === 'NEW_DEVICE'
            ? `New device on the LAN: ${e.ip} (${e.mac})`
            : e.kind === 'GATEWAY_MAC_CHANGED'
              ? `Gateway ${e.ip} now answers from a different MAC (${e.mac})`
              : `ARP spoofing suspected: gateway MAC ${e.mac} also answers for ${e.ip}`,
        titleAr:
          e.kind === 'NEW_DEVICE'
            ? `جهاز جديد على الشبكة: ${e.ip} (${e.mac})`
            : e.kind === 'GATEWAY_MAC_CHANGED'
              ? `البوابة ${e.ip} تجيب الآن من عنوان MAC مختلف (${e.mac})`
              : `اشتباه انتحال ARP: عنوان MAC للبوابة ${e.mac} يجيب أيضًا عن ${e.ip}`,
        details: e.detail,
        actorIp: e.ip ?? undefined,
        mitreTactic: e.kind === 'NEW_DEVICE' ? 'Initial Access' : 'Credential Access',
        mitreTechnique: e.mitre ?? undefined,
        actionTaken: 'ALERT_RAISED',
        actionTakenAr: 'تم رفع تنبيه',
        metadata: { lanWatch: true, kind: e.kind, assetId: e.assetId, mac: e.mac }
      });
    } catch (err: any) {
      console.warn('[lan-watch] telemetry publish failed:', err?.message);
    }
  }

  /**
   * Called after each accepted heartbeat with the host's cleaned posture.
   * `neighbours` null means the ARP collector did not run: nothing is inferred from it.
   */
  public observe(assetId: string, neighbours: NeighbourIn[] | null | undefined, gateways: string[] | null | undefined) {
    if (!Array.isArray(neighbours)) return;
    const now = new Date().toISOString();
    const baselined = Boolean(this.db.prepare('SELECT 1 FROM lan_baselines WHERE asset_id = ?').get(assetId));

    let fresh = 0;
    for (const n of neighbours) {
      if (!n?.mac || !n?.ip) continue;
      const mac = n.mac.toLowerCase();
      const row = this.db.prepare('SELECT * FROM lan_devices WHERE mac = ?').get(mac) as any;
      const randomized = isRandomizedMac(mac);
      if (!row) {
        const state: DeviceState = baselined ? 'NEW' : 'BASELINE';
        this.db
          .prepare(
            `INSERT INTO lan_devices (mac, last_ip, ips, vendor, randomized, state, first_seen, last_seen, seen_by)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
          )
          .run(mac, n.ip, JSON.stringify([n.ip]), n.vendor ?? null, randomized ? 1 : 0, state, now, now, JSON.stringify([assetId]));
        if (baselined) {
          fresh++;
          this.emit({
            kind: 'NEW_DEVICE',
            severity: randomized ? 'LOW' : 'MEDIUM',
            assetId,
            ip: n.ip,
            mac,
            mitre: 'T1200 - Hardware Additions',
            detail: randomized
              ? `First sighting of ${mac} at ${n.ip}, reported by ${assetId}. The MAC is randomised (locally administered), which phones and laptops rotate by design; approve it if it is a known personal device.`
              : `First sighting of ${mac}${n.vendor ? ` (${n.vendor})` : ''} at ${n.ip}, reported by ${assetId}. Approve it if it is expected.`
          });
        }
      } else {
        const ips = new Set<string>(JSON.parse(row.ips || '[]'));
        ips.add(n.ip);
        const seen = new Set<string>(JSON.parse(row.seen_by || '[]'));
        seen.add(assetId);
        this.db
          .prepare('UPDATE lan_devices SET last_ip = ?, ips = ?, last_seen = ?, seen_by = ?, vendor = COALESCE(vendor, ?) WHERE mac = ?')
          .run(n.ip, JSON.stringify([...ips].slice(-16)), now, JSON.stringify([...seen].slice(-16)), n.vendor ?? null, mac);
      }
    }

    if (!baselined) {
      this.db.prepare('INSERT OR IGNORE INTO lan_baselines (asset_id, baselined_at) VALUES (?, ?)').run(assetId, now);
      this.emit({
        kind: 'BASELINE_RECORDED',
        severity: 'INFO',
        assetId,
        ip: null,
        mac: null,
        mitre: null,
        detail: `${neighbours.length} device(s) recorded as the baseline for ${assetId}.`
      });
    }

    this.checkGateways(assetId, neighbours, gateways, now);
    return { fresh };
  }

  private checkGateways(assetId: string, neighbours: NeighbourIn[], gateways: string[] | null | undefined, now: string) {
    this.gatewayReporting.set(assetId, Array.isArray(gateways));
    if (!Array.isArray(gateways) || gateways.length === 0) return;

    const current = new Set<string>();
    for (const gw of gateways) {
      const hit = neighbours.find(n => n.ip === gw);
      if (!hit) continue; // gateway not in the ARP cache this cycle: nothing to compare
      const mac = hit.mac.toLowerCase();

      const binding = this.db.prepare('SELECT * FROM gateway_bindings WHERE asset_id = ? AND gateway_ip = ?').get(assetId, gw) as any;
      if (!binding) {
        this.db
          .prepare('INSERT INTO gateway_bindings (asset_id, gateway_ip, mac, first_seen, last_seen) VALUES (?, ?, ?, ?, ?)')
          .run(assetId, gw, mac, now, now);
      } else if (binding.mac !== mac) {
        this.emit({
          kind: 'GATEWAY_MAC_CHANGED',
          severity: 'HIGH',
          assetId,
          ip: gw,
          mac,
          mitre: 'T1557.002 - Adversary-in-the-Middle: ARP Cache Poisoning',
          detail: `Gateway ${gw} was bound to ${binding.mac} since ${binding.first_seen}; it now answers from ${mac}. A replaced router does this too — verify before acting.`
        });
        this.db.prepare('UPDATE gateway_bindings SET mac = ?, last_seen = ? WHERE asset_id = ? AND gateway_ip = ?').run(mac, now, assetId, gw);
      } else {
        this.db.prepare('UPDATE gateway_bindings SET last_seen = ? WHERE asset_id = ? AND gateway_ip = ?').run(now, assetId, gw);
      }

      // The poisoning signature: the gateway's MAC also answering for another address.
      for (const other of neighbours) {
        if (other.ip === gw || other.mac.toLowerCase() !== mac) continue;
        const sig = `${assetId}|${gw}|${mac}|${other.ip}`;
        current.add(sig);
        if (!this.activeSpoofs.has(sig)) {
          this.emit({
            kind: 'ARP_SPOOF_SUSPECTED',
            severity: 'CRITICAL',
            assetId,
            ip: other.ip,
            mac,
            mitre: 'T1557.002 - Adversary-in-the-Middle: ARP Cache Poisoning',
            detail: `${assetId}'s ARP cache maps both the gateway ${gw} and ${other.ip} to ${mac}. A host answering for the gateway's address is the man-in-the-middle signature; ${other.ip} is the likely source.`
          });
        }
      }
    }
    // Conditions that cleared are forgotten, so a recurrence alerts again.
    for (const sig of [...this.activeSpoofs]) if (sig.startsWith(assetId + '|') && !current.has(sig)) this.activeSpoofs.delete(sig);
    for (const sig of current) this.activeSpoofs.add(sig);
  }

  public approve(mac: string, by: string): LanDevice | null {
    const m = mac.toLowerCase();
    const res = this.db
      .prepare(`UPDATE lan_devices SET state = 'APPROVED', approved_by = ?, approved_at = ? WHERE mac = ?`)
      .run(by, new Date().toISOString(), m);
    return Number(res.changes) > 0 ? this.get(m) : null;
  }

  public get(mac: string): LanDevice | null {
    const r = this.db.prepare('SELECT * FROM lan_devices WHERE mac = ?').get(mac.toLowerCase()) as any;
    return r ? this.hydrate(r) : null;
  }

  private hydrate(r: any): LanDevice {
    return {
      mac: String(r.mac),
      lastIp: r.last_ip ?? null,
      ips: JSON.parse(r.ips || '[]'),
      vendor: r.vendor ?? null,
      randomized: Number(r.randomized) === 1,
      state: r.state as DeviceState,
      firstSeen: String(r.first_seen),
      lastSeen: String(r.last_seen),
      seenBy: JSON.parse(r.seen_by || '[]'),
      approvedBy: r.approved_by ?? null,
      approvedAt: r.approved_at ?? null
    };
  }

  public status() {
    const devices = (this.db.prepare('SELECT * FROM lan_devices ORDER BY last_seen DESC').all() as any[]).map(r => this.hydrate(r));
    const bindings = this.db.prepare('SELECT * FROM gateway_bindings').all() as any[];
    return {
      durable: this.persistent,
      devices,
      newCount: devices.filter(d => d.state === 'NEW').length,
      gateways: bindings.map(b => ({ assetId: String(b.asset_id), ip: String(b.gateway_ip), mac: String(b.mac), since: String(b.first_seen) })),
      // Per host: is ARP-spoof detection actually running, or is the gateway unknown?
      spoofDetection: Object.fromEntries([...this.gatewayReporting.entries()].map(([k, v]) => [k, v ? 'ACTIVE' : 'NO_GATEWAY_DATA'])),
      activeSpoofs: this.activeSpoofs.size,
      events: this.events.slice(-100).reverse()
    };
  }
}

export const globalLanWatch = new LanWatchService();
