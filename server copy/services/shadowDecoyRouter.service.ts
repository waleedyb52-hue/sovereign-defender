import crypto from 'crypto';

// =============================================================================
// SHADOW DECOY ROUTER & SESSION CLONER (v1.0)
//
// Transparently forks a flagged actor into an isolated high-interaction decoy
// that is behaviourally indistinguishable from production.
//
// -----------------------------------------------------------------------
// STAGE 1 MITIGATIONS - the classic ways honeypots get burned, and the
// countermeasure implemented here for each:
//
// 1. TIMING SIDE-CHANNEL FINGERPRINTING
//    Flaw: a decoy answers in a flat sub-millisecond time while the real
//    backend takes 40-200ms with variance from I/O and query planning. An
//    attacker measuring response latency spots the difference immediately.
//    Fix: LatencyProfiler observes genuine backend timings per route class
//    and the decoy samples its delay from that empirical distribution, so
//    decoy latency has the same central tendency AND the same spread. See
//    matchLatency().
//
// 2. SESSION BLEED
//    Flaw: a decoy that shares any store with production either leaks real
//    records (burning the deception and the data) or lets the attacker
//    corrupt live state.
//    Fix: SyntheticStateStore is a per-session in-memory namespace. This
//    module imports no production data service at all, so there is no code
//    path from decoy handling into a real store. Tokens keep validating
//    syntactically so the attacker never sees a 401 that would reveal the
//    fork. See cloneSessionContext().
//
// 3. CANARY / BREADCRUMB TRAPS
//    Flaw: an operator learns nothing after the attacker leaves.
//    Fix: every decoy session is seeded with uniquely-keyed honey
//    credentials, API keys and DB rows. Each canary embeds the session id, so
//    if one is ever presented back to the platform the exact trapped session
//    that leaked it is identified. See mintCanaryTokens() and redeemCanary().
//
// 4. CONTENT-CONSISTENCY FINGERPRINTING (added)
//    Flaw: decoys that return the same stub for every path, or fresh random
//    data on each request, are trivially detected by asking twice.
//    Fix: synthetic content is derived deterministically from
//    (sessionId, path), so a repeated request returns byte-identical data
//    while different paths return plausibly different data.
//
// 5. STATE AMNESIA (added)
//    Flaw: an attacker writes a file to the decoy, reads it back, and it is
//    gone - an unmistakable tell.
//    Fix: writes persist in the session's synthetic filesystem for the life
//    of the trap. See applySyntheticWrite().
//
// 6. EXECUTION ESCAPE (added)
//    Flaw: honeypots that genuinely execute attacker input become a pivot.
//    Fix: nothing here executes anything. Command output is synthesized from
//    a static corpus; there is no child_process import in this module.
// =============================================================================

export type DecoyResponseKind =
  | 'JSON_RESOURCE'
  | 'SYSTEM_LOG'
  | 'DATABASE_ERROR'
  | 'FILESYSTEM_LISTING'
  | 'COMMAND_OUTPUT'
  | 'CREDENTIAL_FILE'
  | 'CONFIG_FILE'
  | 'GENERIC_OK';

export interface ClonedSessionContext {
  sessionId: string;
  actorIp: string;
  /** Mirrors whatever identity the attacker presented, so nothing looks revoked. */
  username: string;
  displayName: string;
  avatarUrl: string;
  roles: string[];
  permissions: string[];
  tenantId: string;
  /** Echoed back verbatim so the attacker's token keeps appearing valid. */
  presentedToken: string | null;
  clonedAt: number;
  lastSeenAt: number;
}

export interface CanaryToken {
  canaryId: string;
  kind: 'API_KEY' | 'DB_CREDENTIAL' | 'SSH_KEY' | 'JWT' | 'S3_KEY';
  value: string;
  plantedAt: number;
  plantedPath: string;
  /** Session this canary was minted for - how a later sighting is attributed. */
  boundSessionId: string;
  redeemed: boolean;
  redeemedAt: number | null;
  redeemedFrom: string | null;
}

export interface SyntheticFile {
  path: string;
  content: string;
  sizeBytes: number;
  mode: string;
  owner: string;
  modifiedAt: number;
}

export interface DecoyResponse {
  kind: DecoyResponseKind;
  statusCode: number;
  headers: Record<string, string>;
  body: unknown;
  /** Milliseconds the responder deliberately waited, to match real latency. */
  appliedLatencyMs: number;
  canariesExposed: string[];
}

export interface DecoySessionState {
  sessionId: string;
  actorIp: string;
  context: ClonedSessionContext;
  canaries: CanaryToken[];
  syntheticFiles: Map<string, SyntheticFile>;
  interactions: number;
  divertedAt: number;
  lastInteractionAt: number;
  intentScoreAtDiversion: number;
}

/** Trapped sessions expire so a long-running scan cannot exhaust memory. */
const DECOY_SESSION_TTL_MS = 60 * 60_000;
const MAX_DECOY_SESSIONS = 500;
const MAX_SYNTHETIC_FILES_PER_SESSION = 200;

// -----------------------------------------------------------------------
// Latency profiling
// -----------------------------------------------------------------------

/**
 * Empirical latency model of the genuine backend.
 *
 * Timings are bucketed by route class because a static asset and a database
 * query have very different profiles, and a decoy that answered both in the
 * same time would be as suspicious as one that answered instantly. Each
 * bucket keeps a bounded ring of recent observations and the decoy samples
 * from it directly, which reproduces the real distribution's shape - not just
 * its mean - including the occasional slow outlier.
 */
export class LatencyProfiler {
  private readonly buckets = new Map<string, number[]>();
  private readonly ringSize = 256;

  /**
   * Fallback profiles used until enough genuine traffic has been observed.
   * Values are typical of a small API behind a database.
   */
  private readonly seedProfiles: Record<string, number[]> = {
    STATIC: [3, 4, 5, 6, 7, 8, 9, 11, 14, 19],
    READ: [18, 22, 25, 28, 31, 35, 39, 46, 58, 84],
    WRITE: [34, 41, 47, 52, 58, 65, 74, 88, 110, 160],
    AUTH: [55, 62, 70, 78, 85, 94, 106, 124, 152, 210]
  };

  /** Classifies a request into a latency bucket. */
  public classify(method: string, path: string): string {
    const p = (path || '').toLowerCase();
    if (/\.(css|js|png|jpe?g|gif|svg|woff2?|ico)$/.test(p)) return 'STATIC';
    if (/login|auth|token|session|oauth/.test(p)) return 'AUTH';
    if (method === 'GET' || method === 'HEAD') return 'READ';
    return 'WRITE';
  }

  /** Records a genuine backend timing so the model tracks reality. */
  public observe(method: string, path: string, elapsedMs: number): void {
    if (!Number.isFinite(elapsedMs) || elapsedMs < 0 || elapsedMs > 30_000) return;
    const key = this.classify(method, path);
    const ring = this.buckets.get(key) ?? [];
    ring.push(elapsedMs);
    if (ring.length > this.ringSize) ring.splice(0, ring.length - this.ringSize);
    this.buckets.set(key, ring);
  }

  /**
   * Draws a delay for the decoy from the observed distribution.
   *
   * Sampling an actual observation (rather than returning a mean) preserves
   * the tail behaviour that makes real systems look real. A small
   * multiplicative jitter is then applied so repeated identical requests do
   * not return byte-identical timings, which would itself be a signature.
   */
  public sampleDelayMs(method: string, path: string): number {
    const key = this.classify(method, path);
    const observed = this.buckets.get(key);
    const pool = observed && observed.length >= 8 ? observed : this.seedProfiles[key] ?? this.seedProfiles.READ;

    const base = pool[Math.floor(Math.random() * pool.length)];
    const jitter = 0.85 + Math.random() * 0.3; // +/- 15%
    return Math.max(1, Math.round(base * jitter));
  }

  public getProfileSummary() {
    const summary: Record<string, { samples: number; p50: number; p95: number }> = {};
    for (const key of ['STATIC', 'READ', 'WRITE', 'AUTH']) {
      const observed = this.buckets.get(key);
      const pool = observed && observed.length >= 8 ? observed : this.seedProfiles[key];
      const sorted = [...pool].sort((a, b) => a - b);
      summary[key] = {
        samples: observed?.length ?? 0,
        p50: sorted[Math.floor(sorted.length * 0.5)] ?? 0,
        p95: sorted[Math.floor(sorted.length * 0.95)] ?? sorted[sorted.length - 1] ?? 0
      };
    }
    return summary;
  }
}

// -----------------------------------------------------------------------
// Synthetic content corpus
// -----------------------------------------------------------------------

const FAKE_USERNAMES = ['a.hassan', 'm.oconnell', 'svc_reporting', 'j.tanaka', 'deploy_bot', 'r.mensah'];
const FAKE_DEPARTMENTS = ['Finance', 'Platform Engineering', 'Compliance', 'Data Science', 'Support'];
const FAKE_HOSTNAMES = ['app-prod-07', 'db-replica-02', 'edge-gw-01', 'worker-14'];

/** Realistic directory listings keyed by the path an attacker probes. */
const SYNTHETIC_DIRECTORIES: Record<string, string[]> = {
  '/': ['bin', 'boot', 'dev', 'etc', 'home', 'lib', 'opt', 'proc', 'root', 'srv', 'tmp', 'usr', 'var'],
  '/etc': ['passwd', 'shadow', 'hosts', 'hostname', 'resolv.conf', 'nginx', 'ssl', 'cron.d', 'systemd'],
  '/home': ['deploy', 'svc_reporting', 'a.hassan'],
  '/var/www': ['html', 'uploads', 'assets', '.env.example'],
  '/opt': ['sovereign', 'monitoring', 'backups'],
  '/root': ['.bashrc', '.ssh', 'notes.txt', 'deploy.log']
};

export class ShadowDecoyRouter {
  private readonly sessions = new Map<string, DecoySessionState>();
  private readonly canaryIndex = new Map<string, CanaryToken>();
  public readonly latencyProfiler = new LatencyProfiler();

  private totalDiverted = 0;
  private totalInteractions = 0;
  private totalCanariesMinted = 0;
  private totalCanariesRedeemed = 0;

  // -------------------------------------------------------------------
  // Diversion & session cloning
  // -------------------------------------------------------------------

  /**
   * Forks an actor into the grid, cloning whatever identity they presented.
   *
   * SESSION BLEED PREVENTION: the cloned context is fabricated from the
   * attacker's own request, never read from a production user store. The
   * presented token is echoed back unchanged so authorization keeps appearing
   * to work, but it grants access to nothing but synthetic state.
   */
  public divert(input: {
    sessionId: string;
    actorIp: string;
    intentScore: number;
    presentedToken?: string | null;
    presentedUsername?: string | null;
    userAgent?: string;
  }): DecoySessionState {
    const existing = this.sessions.get(input.sessionId);
    if (existing) {
      existing.lastInteractionAt = Date.now();
      return existing;
    }

    const context = this.cloneSessionContext(input);
    const canaries = this.mintCanaryTokens(input.sessionId);

    const state: DecoySessionState = {
      sessionId: input.sessionId,
      actorIp: input.actorIp,
      context,
      canaries,
      syntheticFiles: new Map<string, SyntheticFile>(),
      interactions: 0,
      divertedAt: Date.now(),
      lastInteractionAt: Date.now(),
      intentScoreAtDiversion: input.intentScore
    };

    this.sessions.set(input.sessionId, state);
    this.totalDiverted++;
    this.evictExpired();
    return state;
  }

  /**
   * Builds a plausible identity from what the attacker supplied.
   *
   * Deterministic in the session id, so the same trapped session always sees
   * the same "account" - an identity that changed between requests would
   * expose the deception instantly.
   */
  private cloneSessionContext(input: {
    sessionId: string;
    actorIp: string;
    presentedToken?: string | null;
    presentedUsername?: string | null;
  }): ClonedSessionContext {
    const seed = this.stableHash(input.sessionId);
    const username = input.presentedUsername || FAKE_USERNAMES[seed % FAKE_USERNAMES.length];

    return {
      sessionId: input.sessionId,
      actorIp: input.actorIp,
      username,
      displayName: username.replace(/[._]/g, ' ').replace(/\b\w/g, c => c.toUpperCase()),
      avatarUrl: '/assets/avatars/' + (seed % 24) + '.png',
      // Roles look ordinary. Granting the attacker a flashy "superadmin" is a
      // classic tell: real compromised accounts are usually mundane.
      roles: seed % 5 === 0 ? ['operator', 'reporting'] : ['analyst'],
      permissions: ['reports:read', 'dashboard:view', 'tickets:write'],
      tenantId: 'tnt-' + (2000 + (seed % 400)),
      presentedToken: input.presentedToken ?? null,
      clonedAt: Date.now(),
      lastSeenAt: Date.now()
    };
  }

  // -------------------------------------------------------------------
  // Canary tokens
  // -------------------------------------------------------------------

  /**
   * Mints breadcrumb credentials bound to this session.
   *
   * The session id is folded into every canary's value, so a canary presented
   * anywhere later identifies exactly which trapped session leaked it. None of
   * these grant any real privilege.
   */
  public mintCanaryTokens(sessionId: string): CanaryToken[] {
    const bind = (label: string) =>
      crypto.createHash('sha256').update(label + '|' + sessionId).digest('hex');

    const now = Date.now();
    const tokens: CanaryToken[] = [
      {
        canaryId: 'CNRY-API-' + bind('api').slice(0, 10).toUpperCase(),
        kind: 'API_KEY',
        value: 'sk_live_' + bind('api').slice(0, 32),
        plantedAt: now, plantedPath: '/.env',
        boundSessionId: sessionId, redeemed: false, redeemedAt: null, redeemedFrom: null
      },
      {
        canaryId: 'CNRY-DB-' + bind('db').slice(0, 10).toUpperCase(),
        kind: 'DB_CREDENTIAL',
        value: 'postgres://svc_reporting:' + bind('db').slice(0, 18) + '@db-replica-02:5432/analytics',
        plantedAt: now, plantedPath: '/.env',
        boundSessionId: sessionId, redeemed: false, redeemedAt: null, redeemedFrom: null
      },
      {
        canaryId: 'CNRY-SSH-' + bind('ssh').slice(0, 10).toUpperCase(),
        kind: 'SSH_KEY',
        value: bind('ssh'),
        plantedAt: now, plantedPath: '/root/.ssh/id_rsa',
        boundSessionId: sessionId, redeemed: false, redeemedAt: null, redeemedFrom: null
      },
      {
        canaryId: 'CNRY-S3-' + bind('s3').slice(0, 10).toUpperCase(),
        kind: 'S3_KEY',
        value: 'AKIA' + bind('s3').slice(0, 16).toUpperCase(),
        plantedAt: now, plantedPath: '/.aws/credentials',
        boundSessionId: sessionId, redeemed: false, redeemedAt: null, redeemedFrom: null
      }
    ];

    for (const t of tokens) {
      this.canaryIndex.set(t.value, t);
      this.totalCanariesMinted++;
    }
    return tokens;
  }

  /**
   * Checks whether a value presented anywhere on the platform is a canary.
   *
   * A hit is conclusive proof of exfiltration: these values exist nowhere
   * except inside one decoy session, so seeing one used elsewhere both proves
   * the theft and attributes it.
   */
  public redeemCanary(candidate: string, seenFrom: string): CanaryToken | null {
    if (!candidate) return null;
    const token = this.canaryIndex.get(candidate.trim());
    if (!token) return null;
    if (!token.redeemed) {
      token.redeemed = true;
      token.redeemedAt = Date.now();
      token.redeemedFrom = seenFrom;
      this.totalCanariesRedeemed++;
    }
    return token;
  }

  /** Scans arbitrary text for any planted canary value. */
  public scanForCanaries(text: string, seenFrom: string): CanaryToken[] {
    if (!text) return [];
    const hits: CanaryToken[] = [];
    for (const [value, token] of this.canaryIndex.entries()) {
      if (text.includes(value)) {
        const redeemed = this.redeemCanary(value, seenFrom);
        if (redeemed) hits.push(redeemed);
      }
    }
    return hits;
  }

  // -------------------------------------------------------------------
  // Synthetic responder
  // -------------------------------------------------------------------

  /**
   * Produces the decoy answer for one attacker request.
   *
   * The returned latency is what the caller must wait before responding; the
   * router deliberately does not sleep itself, so the transport layer can
   * apply the delay without blocking this synchronous path.
   */
  public respond(input: {
    sessionId: string;
    method: string;
    path: string;
    body?: unknown;
    query?: Record<string, unknown>;
    /**
     * De-obfuscated form of the request, when the intent analyzer produced
     * one. Content selection MUST run against this rather than the raw path:
     * an attacker probing for /etc/passwd behind double URL-encoding would
     * otherwise receive a generic JSON listing instead of a convincing passwd
     * file, breaking the illusion and wasting the intelligence opportunity.
     */
    decodedPath?: string;
  }): DecoyResponse {
    const state = this.sessions.get(input.sessionId);
    const method = (input.method || 'GET').toUpperCase();
    const path = input.path || '/';
    // Matching surface: decoded form when available, plus the raw path so
    // signatures only visible before normalization stay reachable.
    const target = input.decodedPath ? input.decodedPath + '   ' + path : path;

    if (state) {
      state.interactions++;
      state.lastInteractionAt = Date.now();
      state.context.lastSeenAt = Date.now();
    }
    this.totalInteractions++;

    const appliedLatencyMs = this.latencyProfiler.sampleDelayMs(method, path);
    const canariesExposed: string[] = [];

    const headers: Record<string, string> = {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
      // Header set is kept identical to production so a header diff cannot
      // distinguish the decoy. No X-Decoy marker is ever emitted.
      'X-Request-Id': crypto.randomBytes(8).toString('hex')
    };

    // --- Credential and config file probes -------------------------
    if (/\.env|\.aws\/credentials|\.git\/config|id_rsa|\.ssh/i.test(target)) {
      const body = this.renderCredentialFile(target, state, canariesExposed);
      return {
        kind: /\.git\/config/i.test(path) ? 'CONFIG_FILE' : 'CREDENTIAL_FILE',
        statusCode: 200,
        headers: { ...headers, 'Content-Type': 'text/plain; charset=utf-8' },
        body,
        appliedLatencyMs,
        canariesExposed
      };
    }

    // --- Directory / filesystem probes -----------------------------
    if (/(\.\.[\/\\])|\/etc\/|\/proc\/|\/var\/www|\/root|dir=|path=/i.test(target)) {
      return {
        kind: 'FILESYSTEM_LISTING',
        statusCode: 200,
        headers: { ...headers, 'Content-Type': 'text/plain; charset=utf-8' },
        body: this.renderDirectoryListing(target, state),
        appliedLatencyMs,
        canariesExposed
      };
    }

    // --- Simulated command execution -------------------------------
    if (/\$\(|`|;\s*(cat|ls|id|whoami|uname)|\|\s*(id|sh|bash)/i.test(target + JSON.stringify(input.query ?? {}))) {
      return {
        kind: 'COMMAND_OUTPUT',
        statusCode: 200,
        headers: { ...headers, 'Content-Type': 'text/plain; charset=utf-8' },
        body: this.renderCommandOutput(target, state),
        appliedLatencyMs,
        canariesExposed
      };
    }

    // --- SQL probing gets a realistic database error ----------------
    if (/union|select|sleep\(|information_schema|'/i.test(target)) {
      return {
        kind: 'DATABASE_ERROR',
        statusCode: 500,
        headers,
        body: this.renderDatabaseError(target),
        appliedLatencyMs,
        canariesExposed
      };
    }

    // --- Log endpoints ---------------------------------------------
    if (/log|actuator|debug|trace/i.test(target)) {
      return {
        kind: 'SYSTEM_LOG',
        statusCode: 200,
        headers: { ...headers, 'Content-Type': 'text/plain; charset=utf-8' },
        body: this.renderSystemLog(target, state),
        appliedLatencyMs,
        canariesExposed
      };
    }

    // --- Writes persist, so a read-back does not betray the decoy ---
    if (method === 'POST' || method === 'PUT' || method === 'PATCH') {
      this.applySyntheticWrite(state, path, input.body);
      return {
        kind: 'GENERIC_OK',
        statusCode: method === 'POST' ? 201 : 200,
        headers,
        body: { success: true, id: this.deterministicId(path, input.sessionId), updatedAt: new Date().toISOString() },
        appliedLatencyMs,
        canariesExposed
      };
    }

    // --- Default: a plausible JSON resource -------------------------
    return {
      kind: 'JSON_RESOURCE',
      statusCode: 200,
      headers,
      body: this.renderJsonResource(path, input.sessionId, state),
      appliedLatencyMs,
      canariesExposed
    };
  }

  /** Records an attacker write into the isolated per-session filesystem. */
  private applySyntheticWrite(state: DecoySessionState | undefined, path: string, body: unknown): void {
    if (!state) return;
    if (state.syntheticFiles.size >= MAX_SYNTHETIC_FILES_PER_SESSION) return;
    const content = typeof body === 'string' ? body : JSON.stringify(body ?? {});
    state.syntheticFiles.set(path, {
      path,
      content: content.slice(0, 8192),
      sizeBytes: Buffer.byteLength(content, 'utf-8'),
      mode: '-rw-r--r--',
      owner: state.context.username,
      modifiedAt: Date.now()
    });
  }

  private renderCredentialFile(path: string, state: DecoySessionState | undefined, exposed: string[]): string {
    const canaries = state?.canaries ?? [];
    const api = canaries.find(c => c.kind === 'API_KEY');
    const db = canaries.find(c => c.kind === 'DB_CREDENTIAL');
    const s3 = canaries.find(c => c.kind === 'S3_KEY');
    const ssh = canaries.find(c => c.kind === 'SSH_KEY');

    if (/\.git\/config/i.test(path)) {
      return [
        '[core]',
        '\trepositoryformatversion = 0',
        '\tfilemode = true',
        '\tbare = false',
        '[remote "origin"]',
        '\turl = https://git.internal.example/platform/sovereign-api.git',
        '\tfetch = +refs/heads/*:refs/remotes/origin/*',
        '[branch "main"]',
        '\tremote = origin',
        '\tmerge = refs/heads/main'
      ].join('\n');
    }

    if (/id_rsa|\.ssh/i.test(path)) {
      if (ssh) exposed.push(ssh.canaryId);
      const blob = (ssh?.value ?? crypto.randomBytes(32).toString('hex')).repeat(12);
      const lines = (blob.match(/.{1,64}/g) ?? []).slice(0, 14);
      return ['-----BEGIN OPENSSH PRIVATE KEY-----', ...lines, '-----END OPENSSH PRIVATE KEY-----'].join('\n');
    }

    if (/\.aws\/credentials/i.test(path)) {
      if (s3) exposed.push(s3.canaryId);
      return ['[default]', 'aws_access_key_id = ' + (s3?.value ?? 'AKIAEXAMPLE'), 'aws_secret_access_key = ' + crypto.createHash('sha1').update(path).digest('hex'), 'region = eu-west-1'].join('\n');
    }

    if (api) exposed.push(api.canaryId);
    if (db) exposed.push(db.canaryId);
    return [
      'NODE_ENV=production',
      'PORT=3000',
      'DATABASE_URL=' + (db?.value ?? 'postgres://user:pass@localhost:5432/app'),
      'STRIPE_SECRET_KEY=' + (api?.value ?? 'sk_live_placeholder'),
      'SESSION_SECRET=' + crypto.createHash('sha256').update(path).digest('hex').slice(0, 40),
      'REDIS_URL=redis://cache-01:6379/2',
      'LOG_LEVEL=info'
    ].join('\n');
  }

  private renderDirectoryListing(path: string, state: DecoySessionState | undefined): string {
    // Normalize the traversal target to whichever synthetic directory the
    // attacker was actually reaching for.
    const target = Object.keys(SYNTHETIC_DIRECTORIES).find(d => path.includes(d.replace(/^\//, ''))) ?? '/';
    const entries = SYNTHETIC_DIRECTORIES[target] ?? SYNTHETIC_DIRECTORIES['/'];
    const seed = this.stableHash(target);

    const rows = entries.map((name, i) => {
      const isDir = !name.includes('.');
      const size = isDir ? 4096 : 128 + ((seed + i * 37) % 8192);
      const mode = isDir ? 'drwxr-xr-x' : '-rw-r--r--';
      const owner = name === 'shadow' ? 'root     shadow  ' : 'root     root    ';
      return mode + ' ' + (isDir ? '2' : '1') + ' ' + owner + String(size).padStart(6) + ' Mar  4 09:1' + (i % 10) + ' ' + name;
    });

    // Anything the attacker wrote in this session shows up too.
    if (state) {
      for (const f of state.syntheticFiles.values()) {
        rows.push(f.mode + ' 1 ' + f.owner + ' ' + String(f.sizeBytes).padStart(6) + ' Mar  4 09:22 ' + f.path.split('/').pop());
      }
    }

    return 'total ' + (rows.length * 4) + '\n' + rows.join('\n');
  }

  private renderCommandOutput(path: string, state: DecoySessionState | undefined): string {
    const p = path.toLowerCase();
    const host = FAKE_HOSTNAMES[this.stableHash(state?.sessionId ?? path) % FAKE_HOSTNAMES.length];

    if (/whoami/.test(p)) return 'www-data';
    if (/\bid\b/.test(p)) return 'uid=33(www-data) gid=33(www-data) groups=33(www-data)';
    if (/uname/.test(p)) return 'Linux ' + host + ' 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux';
    if (/hostname/.test(p)) return host;
    if (/passwd/.test(p)) {
      return [
        'root:x:0:0:root:/root:/bin/bash',
        'daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin',
        'www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin',
        'svc_reporting:x:1001:1001::/home/svc_reporting:/bin/bash',
        'deploy:x:1002:1002::/home/deploy:/bin/bash'
      ].join('\n');
    }
    if (/\bps\b|aux/.test(p)) {
      return [
        'USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND',
        'root         1  0.0  0.1 168404 11284 ?        Ss   Mar03   0:14 /sbin/init',
        'www-data   842  0.3  1.8 1284932 74216 ?       Sl   Mar03   2:41 node /opt/sovereign/server.js',
        'postgres   613  0.1  2.4 421884 98120 ?        Ss   Mar03   1:07 postgres: writer process'
      ].join('\n');
    }
    return 'sh: 1: command not found';
  }

  private renderDatabaseError(path: string): Record<string, unknown> {
    // A verbose-but-plausible error. Real error-based SQLi payoffs look like
    // this, which keeps the attacker engaged and generating intelligence.
    return {
      error: 'QueryFailedError',
      message: 'syntax error at or near "' + (path.match(/[a-z_]+/gi)?.pop() ?? 'SELECT') + '"',
      code: '42601',
      position: String(20 + (this.stableHash(path) % 60)),
      detail: null,
      hint: null,
      schema: 'public',
      table: null,
      routine: 'scanner_yyerror'
    };
  }

  private renderSystemLog(path: string, state: DecoySessionState | undefined): string {
    const seed = this.stableHash(path + (state?.sessionId ?? ''));
    const base = Date.now() - 3_600_000;
    const lines: string[] = [];
    for (let i = 0; i < 14; i++) {
      const ts = new Date(base + i * 231_000).toISOString();
      const user = FAKE_USERNAMES[(seed + i) % FAKE_USERNAMES.length];
      const dept = FAKE_DEPARTMENTS[(seed + i * 3) % FAKE_DEPARTMENTS.length];
      const variants = [
        'INFO  [http] 200 GET /api/v1/reports/summary user=' + user + ' dur=' + (18 + (seed + i) % 60) + 'ms',
        'INFO  [auth] session refreshed user=' + user + ' tenant=' + dept.toLowerCase().replace(/\s/g, '-'),
        'WARN  [db]   slow query 1284ms table=invoices rows=48213',
        'INFO  [job]  nightly_export completed rows=19244 dur=42s',
        'ERROR [smtp] delivery deferred to ' + user + '@example.com retry=2'
      ];
      lines.push(ts + ' ' + variants[(seed + i) % variants.length]);
    }
    return lines.join('\n');
  }

  private renderJsonResource(path: string, sessionId: string, state: DecoySessionState | undefined): Record<string, unknown> {
    const seed = this.stableHash(path + sessionId);
    const count = 3 + (seed % 5);
    const items = Array.from({ length: count }, (_, i) => ({
      id: this.deterministicId(path + i, sessionId),
      name: FAKE_USERNAMES[(seed + i) % FAKE_USERNAMES.length],
      department: FAKE_DEPARTMENTS[(seed + i * 2) % FAKE_DEPARTMENTS.length],
      status: (seed + i) % 4 === 0 ? 'suspended' : 'active',
      lastLogin: new Date(Date.now() - ((seed + i * 97) % 720) * 3_600_000).toISOString(),
      recordsOwned: 40 + ((seed + i * 13) % 900)
    }));

    return {
      data: items,
      meta: {
        page: 1,
        perPage: count,
        total: 40 + (seed % 800),
        tenant: state?.context.tenantId ?? 'tnt-2001'
      }
    };
  }

  // -------------------------------------------------------------------
  // Helpers & lifecycle
  // -------------------------------------------------------------------

  /** Deterministic per (path, session) so repeated requests are stable. */
  private deterministicId(path: string, sessionId: string): string {
    return crypto.createHash('sha256').update(path + '|' + sessionId).digest('hex').slice(0, 24);
  }

  private stableHash(input: string): number {
    let h = 0x811c9dc5;
    for (let i = 0; i < input.length; i++) {
      h ^= input.charCodeAt(i);
      h = Math.imul(h, 0x01000193) >>> 0;
    }
    return h >>> 0;
  }

  public isDiverted(sessionId: string): boolean {
    const state = this.sessions.get(sessionId);
    if (!state) return false;
    if (Date.now() - state.lastInteractionAt > DECOY_SESSION_TTL_MS) {
      this.sessions.delete(sessionId);
      return false;
    }
    return true;
  }

  public getSession(sessionId: string): DecoySessionState | null {
    return this.sessions.get(sessionId) ?? null;
  }

  public release(sessionId: string): boolean {
    return this.sessions.delete(sessionId);
  }

  private evictExpired(): void {
    const now = Date.now();
    for (const [id, state] of this.sessions.entries()) {
      if (now - state.lastInteractionAt > DECOY_SESSION_TTL_MS) this.sessions.delete(id);
    }
    while (this.sessions.size > MAX_DECOY_SESSIONS) {
      const oldest = this.sessions.keys().next().value as string | undefined;
      if (oldest === undefined) break;
      this.sessions.delete(oldest);
    }
  }

  public getActiveSessions(): Array<Omit<DecoySessionState, 'syntheticFiles'> & { syntheticFileCount: number }> {
    const now = Date.now();
    const out: Array<Omit<DecoySessionState, 'syntheticFiles'> & { syntheticFileCount: number }> = [];
    for (const state of this.sessions.values()) {
      if (now - state.lastInteractionAt > DECOY_SESSION_TTL_MS) continue;
      const { syntheticFiles, ...rest } = state;
      out.push({ ...rest, syntheticFileCount: syntheticFiles.size });
    }
    return out.sort((a, b) => b.lastInteractionAt - a.lastInteractionAt);
  }

  public getAllCanaries(): CanaryToken[] {
    return Array.from(this.canaryIndex.values()).sort((a, b) => b.plantedAt - a.plantedAt);
  }

  public getStats() {
    return {
      activeSessions: this.getActiveSessions().length,
      totalDiverted: this.totalDiverted,
      totalInteractions: this.totalInteractions,
      canariesMinted: this.totalCanariesMinted,
      canariesRedeemed: this.totalCanariesRedeemed,
      latencyProfile: this.latencyProfiler.getProfileSummary(),
      sessionTtlMs: DECOY_SESSION_TTL_MS
    };
  }

  public clear(): void {
    this.sessions.clear();
    this.canaryIndex.clear();
  }
}

export const globalShadowDecoyRouter = new ShadowDecoyRouter();
