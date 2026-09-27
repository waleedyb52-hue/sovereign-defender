import { DatabaseSync } from 'node:sqlite';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';

/**
 * ASSET REGISTRY — the platform's missing link to real machines.
 *
 * Until now nothing in this codebase represented a device. Telemetry arrived as
 * anonymous flows, the cluster view showed synthetic nodes, and there was no way for an
 * operator to point the platform at their own host or subnet. That is the substance of
 * "I can't connect it to devices and networks": not a styling gap, an absent domain
 * object.
 *
 * An asset here is a machine that enrolled itself by running the sensor, or a network
 * range an operator declared. It carries:
 *
 *   identity      hostname, platform, architecture, interfaces — all self-reported
 *   liveness      last heartbeat, derived ONLINE / STALE / OFFLINE
 *   posture       counts the sensor measured on that host: listening ports, established
 *                 connections, running processes, logged-in users
 *   containment   whether an operator has isolated it, and when
 *
 * Three design decisions that matter more than the schema:
 *
 * SELF-REPORTED IS LABELLED SELF-REPORTED. Everything a sensor sends is an assertion by
 * software running on a host the server does not control. The registry stores it as
 * such and never promotes it to a verified fact. A platform that renders an agent's
 * claim about its own patch level as ground truth is how asset inventories end up
 * confidently wrong, which is worse than empty.
 *
 * LIVENESS IS DERIVED FROM TIME, NOT FROM A FLAG. A sensor that dies cannot send
 * `status: offline`. So status is computed from the age of the last heartbeat against
 * the interval the sensor declared. An asset that stops reporting goes STALE then
 * OFFLINE on its own, which is the only way silence becomes visible.
 *
 * ENROLMENT IS TOKEN-GATED AND THE TOKEN IS STORED HASHED. A registry that accepts any
 * POST is an open door for an attacker to flood the fleet with fake hosts and bury the
 * real one. Tokens are single-purpose, revocable, and compared by digest.
 */

export type AssetKind = 'HOST' | 'NETWORK_RANGE';
export type Liveness = 'ONLINE' | 'STALE' | 'OFFLINE' | 'NEVER_REPORTED';

/**
 * A device this host has exchanged frames with on a local segment.
 *
 * Observed from the ARP cache, which means it is a device that genuinely answered on
 * the wire — stronger evidence than a ping reply, and obtained without sending anything.
 * `vendor` is null when the MAC prefix is not in the sensor's small OUI table OR when the
 * address is randomised, which modern phones do by default. Null is the honest answer in
 * both cases: a guessed vendor is a false lead an analyst will chase.
 */
export interface Neighbour {
  ip: string;
  mac: string;
  vendor: string | null;
  arpType: string | null;
  viaInterface: string | null;
  method: string;
  discoveredAt: string;
  /** Ports found open by an authorised sweep, if one has run against this address. */
  openPorts?: number[];
  lastSweptAt?: string;
  /**
   * Three states, because two were not enough to be honest.
   *
   *   NOT_IN_RANGE  no sweep has covered this address — nothing was looked for
   *   RESPONDED     completed or refused a handshake; openPorts is the finding
   *   NO_RESPONSE   probed and silent
   *
   * The third is the one that matters and was missing. A device that answers ARP but
   * not TCP is filtering: it is demonstrably alive on the wire and refusing to talk,
   * which is security-relevant in itself. Collapsing it into "not swept" hid a
   * firewalled host behind the same label as a host nobody had examined.
   */
  sweepState?: 'NOT_IN_RANGE' | 'RESPONDED' | 'NO_RESPONSE';
}

export interface Segment {
  interface: string;
  address: string;
  netmask: string;
  cidr: string;
}

export interface SweepResult {
  cidr: string;
  startedAt: string;
  finishedAt: string;
  portsProbed: number[];
  addressesProbed: number;
  respondedCount: number;
  silentCount: number;
  truncated: boolean;
  hosts: Array<{ ip: string; openPorts: number[]; refusedPortCount: number; state: string; method: string }>;
  note: string;
}

export interface AssetPosture {
  listeningPorts: number | null;
  establishedConnections: number | null;
  processes: number | null;
  loggedInUsers: number | null;
  uptimeSec: number | null;
  /** Free-form counts the sensor measured. Stored verbatim, never interpreted. */
  extra: Record<string, number> | null;
  /** LAN devices seen from this host. Absent means the collector could not look. */
  neighbours: Neighbour[] | null;
  /** The host's own local segments, so the UI can offer them for an authorised sweep. */
  segments: Segment[] | null;
}

export interface Asset {
  id: string;
  kind: AssetKind;
  label: string;
  hostname: string | null;
  platform: string | null;
  arch: string | null;
  primaryIp: string | null;
  interfaces: string[];
  /** CIDR, for a declared network range. */
  cidr: string | null;
  enrolledAt: string;
  lastSeenAt: string | null;
  heartbeatIntervalSec: number;
  sensorVersion: string | null;
  isolated: boolean;
  isolatedAt: string | null;
  flowsIngested: number;
  posture: AssetPosture | null;
  /** The most recent authorised sweep reported from this host, if any. */
  lastSweep: SweepResult | null;
  /** Derived from heartbeat age. Never taken from the sensor. */
  liveness: Liveness;
}

export interface EnrollmentToken {
  id: string;
  createdAt: string;
  expiresAt: string;
  usedByAssetId: string | null;
  revoked: boolean;
  note: string | null;
}

/** Grace multiples of the declared interval before an asset is downgraded. */
const STALE_AFTER = 3;
const OFFLINE_AFTER = 10;
const TOKEN_TTL_MS = 24 * 60 * 60 * 1000;

function sha256(v: string) {
  return crypto.createHash('sha256').update(v).digest('hex');
}

export class AssetRegistryService {
  private db: DatabaseSync;
  private persistent = false;

  constructor(dbPath?: string) {
    const target = dbPath ?? path.join(process.cwd(), 'data', 'assets.db');
    try {
      fs.mkdirSync(path.dirname(target), { recursive: true });
      this.db = new DatabaseSync(target);
      this.persistent = target !== ':memory:';
    } catch (err: any) {
      // Per the platform resilience rule: an unwritable disk degrades the registry,
      // it does not take the SOC down. `durable()` reports the truth either way, so
      // the UI can say the fleet will not survive a restart rather than implying it will.
      console.warn('[assets] falling back to in-memory registry:', err?.message);
      this.db = new DatabaseSync(':memory:');
      this.persistent = false;
    }
    this.migrate();
  }

  private migrate() {
    if (this.persistent) {
      try {
        this.db.exec('PRAGMA journal_mode = WAL');
      } catch {
        /* WAL is an optimisation; its absence is not fatal. */
      }
    }
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS assets (
        id             TEXT PRIMARY KEY,
        kind           TEXT NOT NULL,
        label          TEXT NOT NULL,
        hostname       TEXT,
        platform       TEXT,
        arch           TEXT,
        primary_ip     TEXT,
        interfaces     TEXT NOT NULL DEFAULT '[]',
        cidr           TEXT,
        enrolled_at    TEXT NOT NULL,
        last_seen_at   TEXT,
        hb_interval    INTEGER NOT NULL DEFAULT 30,
        sensor_version TEXT,
        isolated       INTEGER NOT NULL DEFAULT 0,
        isolated_at    TEXT,
        flows_ingested INTEGER NOT NULL DEFAULT 0,
        posture        TEXT,
        last_sweep     TEXT
      )
    `);
    // Additive migration for registries created before sweeps existed. A failure here
    // means the column is already present, which is the normal case after the first run.
    try {
      this.db.exec(`ALTER TABLE assets ADD COLUMN last_sweep TEXT`);
    } catch {
      /* column exists */
    }
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS enrollment_tokens (
        id          TEXT PRIMARY KEY,
        token_sha   TEXT NOT NULL UNIQUE,
        created_at  TEXT NOT NULL,
        expires_at  TEXT NOT NULL,
        used_by     TEXT,
        revoked     INTEGER NOT NULL DEFAULT 0,
        note        TEXT
      )
    `);
    this.db.exec(`CREATE INDEX IF NOT EXISTS idx_assets_seen ON assets(last_seen_at)`);
  }

  /** Whether the fleet survives a restart. Surfaced so the UI never implies it does. */
  public durable(): boolean {
    return this.persistent;
  }

  /* ── Enrolment tokens ──────────────────────────────────────────────────── */

  public createToken(note?: string): { id: string; token: string; expiresAt: string } {
    const id = 'ENR-' + crypto.randomBytes(5).toString('hex').toUpperCase();
    // The plaintext is returned exactly once. Only its digest is stored, so a
    // registry dump cannot be replayed to enrol hosts.
    const token = 'sd_enroll_' + crypto.randomBytes(24).toString('hex');
    const now = new Date();
    const expiresAt = new Date(now.getTime() + TOKEN_TTL_MS).toISOString();

    this.db
      .prepare(
        `INSERT INTO enrollment_tokens (id, token_sha, created_at, expires_at, note)
         VALUES (?, ?, ?, ?, ?)`
      )
      .run(id, sha256(token), now.toISOString(), expiresAt, note ?? null);

    return { id, token, expiresAt };
  }

  public listTokens(): EnrollmentToken[] {
    const rows = this.db
      .prepare(`SELECT id, created_at, expires_at, used_by, revoked, note FROM enrollment_tokens ORDER BY created_at DESC`)
      .all() as any[];
    return rows.map(r => ({
      id: String(r.id),
      createdAt: String(r.created_at),
      expiresAt: String(r.expires_at),
      usedByAssetId: r.used_by ? String(r.used_by) : null,
      revoked: Number(r.revoked) === 1,
      note: r.note ? String(r.note) : null
    }));
  }

  public revokeToken(id: string): boolean {
    const res = this.db.prepare(`UPDATE enrollment_tokens SET revoked = 1 WHERE id = ?`).run(id);
    return Number(res.changes) > 0;
  }

  private consumeToken(token: string, assetId: string): { ok: true } | { ok: false; reason: string } {
    const row = this.db
      .prepare(`SELECT id, expires_at, used_by, revoked FROM enrollment_tokens WHERE token_sha = ?`)
      .get(sha256(token)) as any;

    if (!row) return { ok: false, reason: 'Unknown enrolment token.' };
    if (Number(row.revoked) === 1) return { ok: false, reason: 'Enrolment token was revoked.' };
    if (new Date(String(row.expires_at)).getTime() < Date.now())
      return { ok: false, reason: 'Enrolment token has expired.' };
    // Single use. A reusable token spreads with every host image it is baked into.
    if (row.used_by) return { ok: false, reason: `Token already used by asset ${row.used_by}.` };

    this.db.prepare(`UPDATE enrollment_tokens SET used_by = ? WHERE id = ?`).run(assetId, String(row.id));
    return { ok: true };
  }

  /* ── Enrolment and heartbeat ───────────────────────────────────────────── */

  public enroll(input: {
    token: string;
    hostname?: string;
    platform?: string;
    arch?: string;
    primaryIp?: string;
    interfaces?: string[];
    heartbeatIntervalSec?: number;
    sensorVersion?: string;
    label?: string;
  }): { ok: true; asset: Asset } | { ok: false; reason: string } {
    if (!input.token || typeof input.token !== 'string') return { ok: false, reason: '"token" is required.' };

    // Re-enrolment of a known host updates it rather than creating a duplicate.
    // Without this, every sensor restart would add a new row and the fleet count
    // would climb forever — an inventory that miscounts is worse than none.
    const existing = input.hostname
      ? (this.db.prepare(`SELECT id FROM assets WHERE hostname = ? AND kind = 'HOST'`).get(input.hostname) as any)
      : null;

    const id = existing ? String(existing.id) : 'AST-' + crypto.randomBytes(5).toString('hex').toUpperCase();

    if (!existing) {
      const consumed = this.consumeToken(input.token, id);
      if ('reason' in consumed) return { ok: false as const, reason: consumed.reason };
    }

    const now = new Date().toISOString();
    const interval = Number.isFinite(input.heartbeatIntervalSec) ? Number(input.heartbeatIntervalSec) : 30;
    const label = input.label?.trim() || input.hostname || id;

    if (existing) {
      this.db
        .prepare(
          `UPDATE assets SET label=?, platform=?, arch=?, primary_ip=?, interfaces=?, hb_interval=?,
             sensor_version=?, last_seen_at=? WHERE id=?`
        )
        .run(
          label,
          input.platform ?? null,
          input.arch ?? null,
          input.primaryIp ?? null,
          JSON.stringify(input.interfaces ?? []),
          Math.max(5, Math.min(3600, interval)),
          input.sensorVersion ?? null,
          now,
          id
        );
    } else {
      this.db
        .prepare(
          `INSERT INTO assets (id, kind, label, hostname, platform, arch, primary_ip, interfaces,
             enrolled_at, last_seen_at, hb_interval, sensor_version)
           VALUES (?, 'HOST', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
        )
        .run(
          id,
          label,
          input.hostname ?? null,
          input.platform ?? null,
          input.arch ?? null,
          input.primaryIp ?? null,
          JSON.stringify(input.interfaces ?? []),
          now,
          now,
          Math.max(5, Math.min(3600, interval)),
          input.sensorVersion ?? null
        );
    }

    return { ok: true, asset: this.get(id)! };
  }

  /** A declared network range. No sensor runs on it; it scopes scans and reporting. */
  public declareNetwork(cidr: string, label?: string): { ok: true; asset: Asset } | { ok: false; reason: string } {
    const m = /^(\d{1,3}\.){3}\d{1,3}\/(\d|[12]\d|3[0-2])$/.exec(cidr.trim());
    if (!m) return { ok: false, reason: 'CIDR must look like 10.0.0.0/24.' };

    const dup = this.db.prepare(`SELECT id FROM assets WHERE cidr = ?`).get(cidr.trim()) as any;
    if (dup) return { ok: true, asset: this.get(String(dup.id))! };

    const id = 'NET-' + crypto.randomBytes(4).toString('hex').toUpperCase();
    const now = new Date().toISOString();
    this.db
      .prepare(
        `INSERT INTO assets (id, kind, label, cidr, enrolled_at, hb_interval)
         VALUES (?, 'NETWORK_RANGE', ?, ?, ?, 0)`
      )
      .run(id, label?.trim() || cidr.trim(), cidr.trim(), now);
    return { ok: true, asset: this.get(id)! };
  }

  public heartbeat(
    id: string,
    posture: Partial<AssetPosture> & { flowsSent?: number }
  ): { ok: true; asset: Asset } | { ok: false; reason: string } {
    const row = this.db.prepare(`SELECT id, flows_ingested, last_sweep FROM assets WHERE id = ?`).get(id) as any;
    if (!row) return { ok: false, reason: `Unknown asset ${id}.` };

    const clean: AssetPosture = {
      neighbours: Array.isArray(posture.neighbours)
        ? (posture.neighbours as Neighbour[])
            .filter(n => n && typeof n.ip === 'string' && /^(\d{1,3}\.){3}\d{1,3}$/.test(n.ip))
            .slice(0, 512)
        : null,
      segments: Array.isArray(posture.segments) ? (posture.segments as Segment[]).slice(0, 32) : null,
      listeningPorts: numOrNull(posture.listeningPorts),
      establishedConnections: numOrNull(posture.establishedConnections),
      processes: numOrNull(posture.processes),
      loggedInUsers: numOrNull(posture.loggedInUsers),
      uptimeSec: numOrNull(posture.uptimeSec),
      extra:
        posture.extra && typeof posture.extra === 'object'
          ? Object.fromEntries(
              Object.entries(posture.extra)
                .filter(([, v]) => typeof v === 'number' && Number.isFinite(v))
                .slice(0, 24)
            )
          : null
    };

    /**
     * Re-apply the stored sweep's open ports onto the incoming neighbours.
     *
     * The sweep runs once at sensor startup, before the first heartbeat, so at that
     * moment there is no neighbour list to merge onto — and the heartbeat that follows
     * would then overwrite the merge with a fresh ARP read carrying no ports. Folding the
     * sweep in on every heartbeat makes the merge order-independent and idempotent, which
     * is the only version that survives a sensor restart. Found by running it: every
     * device reported "not swept" while the sweep had plainly found open ports.
     */
    if (clean.neighbours && row.last_sweep) {
      const sweep = safeJson<SweepResult | null>(row.last_sweep, null);
      if (sweep) clean.neighbours = this.applySweep(clean.neighbours, sweep);
    }

    const added = Number.isFinite(posture.flowsSent) ? Math.max(0, Number(posture.flowsSent)) : 0;

    this.db
      .prepare(`UPDATE assets SET last_seen_at = ?, posture = ?, flows_ingested = ? WHERE id = ?`)
      .run(new Date().toISOString(), JSON.stringify(clean), Number(row.flows_ingested) + added, id);

    return { ok: true, asset: this.get(id)! };
  }

  /**
   * Folds a sweep onto a neighbour list, assigning all three sweep states.
   *
   * Shared by `recordSweep` and `heartbeat` so the two paths cannot disagree about what
   * a sweep found — which they did when only one of them merged.
   */
  private applySweep(neighbours: Neighbour[], sweep: SweepResult): Neighbour[] {
    const byIp = new Map((sweep.hosts ?? []).map(h => [h.ip, h]));
    return neighbours.map(n => {
      const hit = byIp.get(n.ip);
      if (hit) {
        return { ...n, openPorts: hit.openPorts, lastSweptAt: sweep.finishedAt, sweepState: 'RESPONDED' as const };
      }
      if (inCidr(n.ip, sweep.cidr)) {
        // Probed and silent. Alive on the wire per ARP, refusing TCP: a filtered host.
        return { ...n, openPorts: [], lastSweptAt: sweep.finishedAt, sweepState: 'NO_RESPONSE' as const };
      }
      return { ...n, sweepState: 'NOT_IN_RANGE' as const };
    });
  }

  /**
   * Records an authorised sweep and folds its open ports back onto the matching
   * neighbours, so a device discovered passively and then probed carries both facts.
   * The sweep is stored whole as well, because the counts of silent addresses are part
   * of the finding and must not be lost when the per-host rows are merged.
   */
  public recordSweep(id: string, sweep: SweepResult): { ok: true; asset: Asset } | { ok: false; reason: string } {
    const asset = this.get(id);
    if (!asset) return { ok: false, reason: `Unknown asset ${id}.` };

    this.db.prepare(`UPDATE assets SET last_sweep = ? WHERE id = ?`).run(JSON.stringify(sweep), id);

    if (asset.posture?.neighbours) {
      this.db
        .prepare(`UPDATE assets SET posture = ? WHERE id = ?`)
        .run(
          JSON.stringify({ ...asset.posture, neighbours: this.applySweep(asset.posture.neighbours, sweep) }),
          id
        );
    }

    return { ok: true, asset: this.get(id)! };
  }

  public setIsolated(id: string, isolated: boolean): { ok: true; asset: Asset } | { ok: false; reason: string } {
    const row = this.db.prepare(`SELECT id FROM assets WHERE id = ?`).get(id) as any;
    if (!row) return { ok: false, reason: `Unknown asset ${id}.` };
    this.db
      .prepare(`UPDATE assets SET isolated = ?, isolated_at = ? WHERE id = ?`)
      .run(isolated ? 1 : 0, isolated ? new Date().toISOString() : null, id);
    return { ok: true, asset: this.get(id)! };
  }

  public remove(id: string): boolean {
    return Number(this.db.prepare(`DELETE FROM assets WHERE id = ?`).run(id).changes) > 0;
  }

  /* ── Reads ─────────────────────────────────────────────────────────────── */

  public get(id: string): Asset | null {
    const r = this.db.prepare(`SELECT * FROM assets WHERE id = ?`).get(id) as any;
    return r ? this.hydrate(r) : null;
  }

  public list(): Asset[] {
    const rows = this.db.prepare(`SELECT * FROM assets ORDER BY kind, label`).all() as any[];
    return rows.map(r => this.hydrate(r));
  }

  public summary() {
    const all = this.list();
    const hosts = all.filter(a => a.kind === 'HOST');
    return {
      durable: this.persistent,
      total: all.length,
      hosts: hosts.length,
      networks: all.filter(a => a.kind === 'NETWORK_RANGE').length,
      online: hosts.filter(a => a.liveness === 'ONLINE').length,
      stale: hosts.filter(a => a.liveness === 'STALE').length,
      offline: hosts.filter(a => a.liveness === 'OFFLINE').length,
      neverReported: hosts.filter(a => a.liveness === 'NEVER_REPORTED').length,
      isolated: all.filter(a => a.isolated).length,
      flowsIngested: all.reduce((s, a) => s + a.flowsIngested, 0),
      // Distinct LAN devices seen across every reporting host. Deduplicated by address,
      // because two sensors on the same segment see the same neighbours and counting
      // them twice would inflate the network's apparent size.
      lanDevices: new Set(
        all.flatMap(a => (a.posture?.neighbours ?? []).map(n => n.ip))
      ).size
    };
  }

  private hydrate(r: any): Asset {
    const lastSeenAt = r.last_seen_at ? String(r.last_seen_at) : null;
    const interval = Math.max(5, Number(r.hb_interval) || 30);
    const kind = String(r.kind) as AssetKind;

    return {
      id: String(r.id),
      kind,
      label: String(r.label),
      hostname: r.hostname ? String(r.hostname) : null,
      platform: r.platform ? String(r.platform) : null,
      arch: r.arch ? String(r.arch) : null,
      primaryIp: r.primary_ip ? String(r.primary_ip) : null,
      interfaces: safeJson<string[]>(r.interfaces, []),
      cidr: r.cidr ? String(r.cidr) : null,
      enrolledAt: String(r.enrolled_at),
      lastSeenAt,
      heartbeatIntervalSec: interval,
      sensorVersion: r.sensor_version ? String(r.sensor_version) : null,
      isolated: Number(r.isolated) === 1,
      isolatedAt: r.isolated_at ? String(r.isolated_at) : null,
      flowsIngested: Number(r.flows_ingested) || 0,
      posture: r.posture ? safeJson<AssetPosture | null>(r.posture, null) : null,
      lastSweep: r.last_sweep ? safeJson<SweepResult | null>(r.last_sweep, null) : null,
      liveness: deriveLiveness(kind, lastSeenAt, interval)
    };
  }
}

/**
 * Liveness from heartbeat age. A dead sensor cannot report that it is dead, so the
 * only honest source for this is elapsed time against the cadence the sensor declared.
 */
function deriveLiveness(kind: AssetKind, lastSeenAt: string | null, intervalSec: number): Liveness {
  // A declared range has no agent, so liveness does not apply and is not claimed.
  if (kind === 'NETWORK_RANGE') return 'NEVER_REPORTED';
  if (!lastSeenAt) return 'NEVER_REPORTED';
  const ageSec = (Date.now() - new Date(lastSeenAt).getTime()) / 1000;
  if (ageSec <= intervalSec * STALE_AFTER) return 'ONLINE';
  if (ageSec <= intervalSec * OFFLINE_AFTER) return 'STALE';
  return 'OFFLINE';
}

/** Whether an address falls inside a CIDR. Tells "probed and silent" from "never looked at". */
function inCidr(ip: string, cidr: string): boolean {
  const m = /^((?:\d{1,3}\.){3}\d{1,3})\/(\d{1,2})$/.exec(cidr ?? '');
  if (!m) return false;
  const bits = Number(m[2]);
  const toInt = (v: string) => v.split('.').map(Number).reduce((a, o) => (a << 8) | o, 0) >>> 0;
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return ((toInt(ip) & mask) >>> 0) === ((toInt(m[1]) & mask) >>> 0);
}

function numOrNull(v: unknown): number | null {
  return typeof v === 'number' && Number.isFinite(v) ? v : null;
}

function safeJson<T>(raw: unknown, fallback: T): T {
  try {
    return JSON.parse(String(raw)) as T;
  } catch {
    return fallback;
  }
}

export const globalAssetRegistry = new AssetRegistryService();
