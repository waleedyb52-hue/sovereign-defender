import { DatabaseSync } from 'node:sqlite';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';

/**
 * OPERATOR AUTHENTICATION — named accounts, roles, sessions.
 *
 * WHAT IT REPLACED. The console had no operator identity. `/agent/status` returned the
 * live API key to any unauthenticated caller, and admin routes accepted any request whose
 * Origin header named localhost — a header curl sets in one flag. So every privileged
 * route was reachable by anyone on the network, and no action was attributable to a
 * person.
 *
 * STANDARDS FOLLOWED
 *   Passwords   NIST SP 800-63B: length over composition (12–128 chars), no forced
 *               rotation, a blocklist of common choices, the username refused.
 *               Stored as scrypt, N=2^17 r=8 p=1 — the OWASP Password Storage floor.
 *   Sessions    OWASP ASVS V3: 256-bit random token, stored server-side only as its
 *               SHA-256, HttpOnly + SameSite=Strict cookie, 30-minute idle and 12-hour
 *               absolute lifetime (one shift), revoked on logout, role change and disable.
 *   Guessing    ASVS V2.2: per-account and per-address lockout. The lockout is keyed by
 *               the attempted name whether or not it exists, and unknown names still pay
 *               a full scrypt, so neither the message nor the timing reveals which
 *               accounts exist.
 *   Roles       VIEWER reads. ANALYST also acts — triage, containment, release.
 *               ADMIN also manages operators and credentials.
 *
 * Sessions live in memory: a restart signs everyone out. That is the conservative
 * direction to fail in, and it keeps session tokens off the disk entirely.
 */

export type Role = 'VIEWER' | 'ANALYST' | 'ADMIN';
export const ROLE_RANK: Record<Role, number> = { VIEWER: 1, ANALYST: 2, ADMIN: 3 };
export const ROLES: Role[] = ['VIEWER', 'ANALYST', 'ADMIN'];

export interface OperatorPublic {
  id: string;
  username: string;
  displayName: string;
  role: Role;
  disabled: boolean;
  createdAt: string;
  createdBy: string | null;
  lastLoginAt: string | null;
}

export interface Session {
  id: string;
  operatorId: string;
  username: string;
  displayName: string;
  role: Role;
  createdAt: number;
  lastSeenAt: number;
  ip: string;
}

const SCRYPT = { N: 2 ** 17, r: 8, p: 1, keylen: 64, maxmem: 256 * 1024 * 1024 };
const IDLE_MS = 30 * 60_000;
const ABSOLUTE_MS = 12 * 60 * 60_000;
const LOCK_WINDOW_MS = 15 * 60_000;
const ACCOUNT_MAX_FAILS = 5;
const ADDRESS_MAX_FAILS = 20;

/** A short list of the choices breach corpora show first. Not exhaustive; a floor. */
const COMMON = new Set([
  'password', 'password1', 'password123', '123456789012', 'qwertyuiop', 'administrator',
  'letmein12345', 'welcome12345', 'changeme1234', 'iloveyou1234', 'sovereign123',
  'sovereigndefender', 'defender1234', 'admin1234567', 'p@ssw0rd1234', '111111111111'
]);

function sha256(v: string): string {
  return crypto.createHash('sha256').update(v).digest('hex');
}

function scrypt(password: string, salt: Buffer): Promise<Buffer> {
  return new Promise((resolve, reject) =>
    crypto.scrypt(password.normalize('NFKC'), salt, SCRYPT.keylen, { N: SCRYPT.N, r: SCRYPT.r, p: SCRYPT.p, maxmem: SCRYPT.maxmem }, (err, key) =>
      err ? reject(err) : resolve(key)
    )
  );
}

async function hashPassword(password: string): Promise<string> {
  const salt = crypto.randomBytes(16);
  const key = await scrypt(password, salt);
  return `scrypt$${Math.log2(SCRYPT.N)}$${SCRYPT.r}$${SCRYPT.p}$${salt.toString('base64')}$${key.toString('base64')}`;
}

async function verifyPassword(password: string, encoded: string): Promise<boolean> {
  const parts = encoded.split('$');
  if (parts.length !== 6 || parts[0] !== 'scrypt') return false;
  const salt = Buffer.from(parts[4], 'base64');
  const expected = Buffer.from(parts[5], 'base64');
  const got = await scrypt(password, salt);
  return got.length === expected.length && crypto.timingSafeEqual(got, expected);
}

/** Paid by unknown usernames so a miss costs the same as a wrong password. */
let DUMMY_HASH: Promise<string> | null = null;
const dummyHash = () => (DUMMY_HASH ??= hashPassword(crypto.randomBytes(18).toString('base64')));

export function passwordProblem(password: string, username: string): string | null {
  if (typeof password !== 'string') return 'password is required';
  const len = [...password].length;
  if (len < 12) return 'use at least 12 characters — a passphrase of several words works well';
  if (len > 128) return 'use at most 128 characters';
  const lower = password.toLowerCase();
  if (COMMON.has(lower)) return 'this password appears in breach lists';
  if (username && lower.includes(username.toLowerCase())) return 'the password must not contain the username';
  if (/^(.)\1+$/.test(password)) return 'the password must not be one repeated character';
  return null;
}

function usernameProblem(username: string): string | null {
  if (typeof username !== 'string' || !/^[a-zA-Z0-9._-]{3,32}$/.test(username)) {
    return 'username: 3–32 characters, letters, digits, dot, dash or underscore';
  }
  return null;
}

interface Failures {
  count: number;
  first: number;
  lockedUntil: number;
}

export type LoginResult =
  | { ok: true; token: string; session: Session }
  | { ok: false; reason: 'INVALID' | 'LOCKED' | 'DISABLED'; retryAfterSec?: number };

export class OperatorAuthService {
  private db: DatabaseSync;
  private persistent = false;
  private sessions = new Map<string, Session>(); // key: sha256(token)
  private accountFails = new Map<string, Failures>();
  private addressFails = new Map<string, Failures>();
  private setupSecret: string | null = null;

  constructor(dbPath?: string) {
    const target = dbPath ?? path.join(process.cwd(), 'data', 'operators.db');
    try {
      fs.mkdirSync(path.dirname(target), { recursive: true });
      this.db = new DatabaseSync(target);
      this.persistent = target !== ':memory:';
    } catch (err: any) {
      console.warn('[auth] falling back to an in-memory operator store:', err?.message);
      this.db = new DatabaseSync(':memory:');
      this.persistent = false;
    }
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS operators (
        id            TEXT PRIMARY KEY,
        username      TEXT NOT NULL UNIQUE COLLATE NOCASE,
        display_name  TEXT NOT NULL,
        role          TEXT NOT NULL,
        pw_hash       TEXT NOT NULL,
        disabled      INTEGER NOT NULL DEFAULT 0,
        created_at    TEXT NOT NULL,
        created_by    TEXT,
        last_login_at TEXT
      );
    `);
    // Expired sessions are swept, not merely ignored, so the map cannot grow unbounded.
    setInterval(() => this.sweep(), 60_000).unref();
    // Pre-compute the decoy hash so the first unknown-user attempt is not slower than later ones.
    void dummyHash();
  }

  public durable(): boolean {
    return this.persistent;
  }

  public hasOperators(): boolean {
    const r = this.db.prepare('SELECT COUNT(*) AS n FROM operators').get() as { n: number };
    return Number(r.n) > 0;
  }

  /**
   * One-time bootstrap secret, generated only while no operator exists. It is printed to
   * the server console, so claiming the first admin account requires either sitting at
   * the server (loopback) or reading its console — not merely reaching port 3000 first.
   */
  public ensureSetupSecret(): string | null {
    if (this.hasOperators()) {
      this.setupSecret = null;
      return null;
    }
    this.setupSecret ??= 'sd_setup_' + crypto.randomBytes(16).toString('hex');
    return this.setupSecret;
  }

  public setupSecretMatches(candidate: unknown): boolean {
    if (!this.setupSecret || typeof candidate !== 'string') return false;
    const a = Buffer.from(sha256(candidate));
    const b = Buffer.from(sha256(this.setupSecret));
    return crypto.timingSafeEqual(a, b);
  }

  private row(id: string): any | undefined {
    return this.db.prepare('SELECT * FROM operators WHERE id = ?').get(id);
  }

  private toPublic(r: any): OperatorPublic {
    return {
      id: String(r.id),
      username: String(r.username),
      displayName: String(r.display_name),
      role: r.role as Role,
      disabled: Number(r.disabled) === 1,
      createdAt: String(r.created_at),
      createdBy: r.created_by ?? null,
      lastLoginAt: r.last_login_at ?? null
    };
  }

  public list(): OperatorPublic[] {
    return (this.db.prepare('SELECT * FROM operators ORDER BY created_at ASC').all() as any[]).map(r => this.toPublic(r));
  }

  public async create(
    input: { username: string; password: string; displayName?: string; role: Role },
    createdBy: string | null
  ): Promise<{ ok: true; operator: OperatorPublic } | { ok: false; reason: string }> {
    const u = usernameProblem(input.username);
    if (u) return { ok: false, reason: u };
    if (!ROLES.includes(input.role)) return { ok: false, reason: 'unknown role' };
    const p = passwordProblem(input.password, input.username);
    if (p) return { ok: false, reason: p };
    if (this.db.prepare('SELECT 1 FROM operators WHERE username = ?').get(input.username)) {
      return { ok: false, reason: 'that username is taken' };
    }
    const id = 'OPR-' + crypto.randomBytes(5).toString('hex').toUpperCase();
    const pw = await hashPassword(input.password);
    const display = (input.displayName ?? '').trim().slice(0, 64) || input.username;
    this.db
      .prepare(
        `INSERT INTO operators (id, username, display_name, role, pw_hash, created_at, created_by)
         VALUES (?, ?, ?, ?, ?, ?, ?)`
      )
      .run(id, input.username, display, input.role, pw, new Date().toISOString(), createdBy);
    if (this.hasOperators()) this.setupSecret = null;
    return { ok: true, operator: this.toPublic(this.row(id)) };
  }

  /** The last enabled ADMIN cannot be demoted or disabled: that would lock the console. */
  private isLastAdmin(id: string): boolean {
    const r = this.row(id);
    if (!r || r.role !== 'ADMIN' || Number(r.disabled) === 1) return false;
    const n = this.db.prepare(`SELECT COUNT(*) AS n FROM operators WHERE role = 'ADMIN' AND disabled = 0`).get() as { n: number };
    return Number(n.n) <= 1;
  }

  public setRole(id: string, role: Role): { ok: true; operator: OperatorPublic } | { ok: false; reason: string } {
    if (!ROLES.includes(role)) return { ok: false, reason: 'unknown role' };
    if (!this.row(id)) return { ok: false, reason: 'no such operator' };
    if (role !== 'ADMIN' && this.isLastAdmin(id)) return { ok: false, reason: 'cannot demote the last active admin' };
    this.db.prepare('UPDATE operators SET role = ? WHERE id = ?').run(role, id);
    this.revokeSessionsFor(id);
    return { ok: true, operator: this.toPublic(this.row(id)) };
  }

  public setDisabled(id: string, disabled: boolean): { ok: true; operator: OperatorPublic } | { ok: false; reason: string } {
    if (!this.row(id)) return { ok: false, reason: 'no such operator' };
    if (disabled && this.isLastAdmin(id)) return { ok: false, reason: 'cannot disable the last active admin' };
    this.db.prepare('UPDATE operators SET disabled = ? WHERE id = ?').run(disabled ? 1 : 0, id);
    if (disabled) this.revokeSessionsFor(id);
    return { ok: true, operator: this.toPublic(this.row(id)) };
  }

  public async changePassword(
    id: string,
    current: string,
    next: string
  ): Promise<{ ok: true } | { ok: false; reason: string }> {
    const r = this.row(id);
    if (!r) return { ok: false, reason: 'no such operator' };
    if (!(await verifyPassword(current, r.pw_hash))) return { ok: false, reason: 'current password is wrong' };
    const p = passwordProblem(next, r.username);
    if (p) return { ok: false, reason: p };
    this.db.prepare('UPDATE operators SET pw_hash = ? WHERE id = ?').run(await hashPassword(next), id);
    this.revokeSessionsFor(id);
    return { ok: true };
  }

  private bump(map: Map<string, Failures>, key: string, max: number, now: number) {
    const f = map.get(key);
    if (!f || now - f.first > LOCK_WINDOW_MS) {
      map.set(key, { count: 1, first: now, lockedUntil: 0 });
      return;
    }
    f.count++;
    if (f.count >= max) f.lockedUntil = now + LOCK_WINDOW_MS;
  }

  private lockedFor(map: Map<string, Failures>, key: string, now: number): number {
    const f = map.get(key);
    return f && f.lockedUntil > now ? Math.ceil((f.lockedUntil - now) / 1000) : 0;
  }

  public async login(usernameIn: unknown, passwordIn: unknown, ip: string): Promise<LoginResult> {
    const now = Date.now();
    const username = typeof usernameIn === 'string' ? usernameIn.trim().slice(0, 64) : '';
    const password = typeof passwordIn === 'string' ? passwordIn.slice(0, 256) : '';
    const acctKey = username.toLowerCase();

    const locked = Math.max(this.lockedFor(this.accountFails, acctKey, now), this.lockedFor(this.addressFails, ip, now));
    if (locked > 0) return { ok: false, reason: 'LOCKED', retryAfterSec: locked };

    const r = username ? (this.db.prepare('SELECT * FROM operators WHERE username = ?').get(username) as any) : undefined;
    let good = false;
    if (r) good = await verifyPassword(password, r.pw_hash);
    else await verifyPassword(password, await dummyHash()); // same cost as a real miss

    if (!good) {
      this.bump(this.accountFails, acctKey, ACCOUNT_MAX_FAILS, now);
      this.bump(this.addressFails, ip, ADDRESS_MAX_FAILS, now);
      return { ok: false, reason: 'INVALID' };
    }
    if (Number(r.disabled) === 1) return { ok: false, reason: 'DISABLED' };

    this.accountFails.delete(acctKey);
    const token = crypto.randomBytes(32).toString('base64url');
    const session: Session = {
      id: 'SES-' + crypto.randomBytes(4).toString('hex').toUpperCase(),
      operatorId: String(r.id),
      username: String(r.username),
      displayName: String(r.display_name),
      role: r.role as Role,
      createdAt: now,
      lastSeenAt: now,
      ip
    };
    this.sessions.set(sha256(token), session);
    this.db.prepare('UPDATE operators SET last_login_at = ? WHERE id = ?').run(new Date(now).toISOString(), r.id);
    return { ok: true, token, session };
  }

  /**
   * Resolve a cookie token to a live session. Role and disabled state are re-read from
   * the operator row every time, so a demotion or disable takes effect on the very next
   * request rather than at session expiry.
   */
  public resolve(token: string | null | undefined): Session | null {
    if (!token) return null;
    const key = sha256(token);
    const s = this.sessions.get(key);
    if (!s) return null;
    const now = Date.now();
    if (now - s.lastSeenAt > IDLE_MS || now - s.createdAt > ABSOLUTE_MS) {
      this.sessions.delete(key);
      return null;
    }
    const r = this.row(s.operatorId);
    if (!r || Number(r.disabled) === 1) {
      this.sessions.delete(key);
      return null;
    }
    s.role = r.role as Role;
    s.displayName = String(r.display_name);
    s.lastSeenAt = now;
    return s;
  }

  public logout(token: string | null | undefined): Session | null {
    if (!token) return null;
    const key = sha256(token);
    const s = this.sessions.get(key) ?? null;
    this.sessions.delete(key);
    return s;
  }

  public revokeSessionsFor(operatorId: string): number {
    let n = 0;
    for (const [k, s] of this.sessions) {
      if (s.operatorId === operatorId) {
        this.sessions.delete(k);
        n++;
      }
    }
    return n;
  }

  public activeSessions(): Array<Omit<Session, 'operatorId'> & { expiresAt: string }> {
    return [...this.sessions.values()].map(s => ({
      id: s.id,
      username: s.username,
      displayName: s.displayName,
      role: s.role,
      createdAt: s.createdAt,
      lastSeenAt: s.lastSeenAt,
      ip: s.ip,
      expiresAt: new Date(Math.min(s.lastSeenAt + IDLE_MS, s.createdAt + ABSOLUTE_MS)).toISOString()
    }));
  }

  private sweep() {
    const now = Date.now();
    for (const [k, s] of this.sessions) {
      if (now - s.lastSeenAt > IDLE_MS || now - s.createdAt > ABSOLUTE_MS) this.sessions.delete(k);
    }
    for (const m of [this.accountFails, this.addressFails]) {
      for (const [k, f] of m) if (now - f.first > LOCK_WINDOW_MS && f.lockedUntil < now) m.delete(k);
    }
  }
}

export const SESSION_LIMITS = { idleMs: IDLE_MS, absoluteMs: ABSOLUTE_MS };

export const globalOperatorAuth = new OperatorAuthService();
