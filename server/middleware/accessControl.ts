import type express from 'express';
import crypto from 'crypto';
import { globalOperatorAuth, ROLE_RANK, type Role, type Session } from '../services/operatorAuth.service.js';
import { globalAuditTrail, type AuditOutcome } from '../services/auditTrail.service.js';
import { globalAssetRegistry } from '../services/assetRegistry.service.js';

/**
 * ACCESS CONTROL — who is calling, and what they may do.
 *
 * Three kinds of caller, told apart by credential, never by network position:
 *
 *   OPERATOR  a person, by session cookie. Role-bound: VIEWER reads, ANALYST acts,
 *             ADMIN administers.
 *   API_KEY   automation, by x-api-key / Bearer. ADMIN_API_KEY or the rotating key.
 *   SENSOR    a host sensor, by the credential it was issued at enrolment. May only
 *             reach the sensor routes, and only for its own asset.
 *
 * What was removed: the Origin-header bypass. `Origin: http://localhost` was accepted as
 * proof of a same-origin browser session, but it is a request header like any other and
 * curl sets it with one flag. Origin is now used only for what it can actually prove —
 * that a browser request carrying a session cookie was issued by this console's own page
 * (CSRF defence) — and never as a credential.
 */

export interface Principal {
  kind: 'OPERATOR' | 'API_KEY' | 'SENSOR';
  id: string;
  name: string;
  role: Role | null;
  session?: Session;
}

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      principal?: Principal | null;
    }
  }
}

export const SESSION_COOKIE = 'sd_session';

/** Admin routes whose individual calls are telemetry, not decisions. See auditOnFinish. */
const AUDIT_QUIET = [/^\/api\/v1\/soc\/sensors\/(dns-query|kernel-audit|kill-safety)$/];

export function readCookie(req: express.Request, name: string): string | null {
  const raw = req.headers.cookie;
  if (!raw) return null;
  for (const part of raw.split(';')) {
    const i = part.indexOf('=');
    if (i > 0 && part.slice(0, i).trim() === name) return decodeURIComponent(part.slice(i + 1).trim());
  }
  return null;
}

export function sessionCookie(token: string, secure: boolean, maxAgeSec: number): string {
  return `${SESSION_COOKIE}=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${maxAgeSec}${secure ? '; Secure' : ''}`;
}

export function clearedSessionCookie(secure: boolean): string {
  return `${SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0${secure ? '; Secure' : ''}`;
}

/** The address Express resolved under the configured trust-proxy policy. */
export function clientIp(req: express.Request): string {
  return (req.ip || req.socket.remoteAddress || '').replace(/^::ffff:/, '').trim();
}

/**
 * True only for a direct loopback connection. Uses the socket, not req.ip, and refuses
 * when a forwarding header is present: behind a local reverse proxy every request arrives
 * from loopback, and treating those as "at the console" would open setup to the network.
 */
export function isDirectLoopback(req: express.Request): boolean {
  const a = (req.socket.remoteAddress || '').replace(/^::ffff:/, '');
  const loop = a === '127.0.0.1' || a === '::1';
  return loop && !req.headers['x-forwarded-for'] && !req.headers['forwarded'];
}

function safeEqual(a: string, b: string): boolean {
  const x = crypto.createHash('sha256').update(a).digest();
  const y = crypto.createHash('sha256').update(b).digest();
  return crypto.timingSafeEqual(x, y);
}

function presentedKey(req: express.Request): string | null {
  const k = req.headers['x-api-key'];
  if (typeof k === 'string' && k) return k;
  const auth = req.headers.authorization;
  if (typeof auth === 'string' && /^Bearer\s+/i.test(auth)) return auth.replace(/^Bearer\s+/i, '').trim();
  return null;
}

export interface AccessControlOptions {
  /** Keys that authenticate automation as ADMIN. Read on every call so rotation applies at once. */
  apiKeys: () => Array<string | null | undefined>;
  /** Extra browser origins permitted to issue state-changing requests (ALLOWED_ORIGINS). */
  extraOrigins: () => string[];
}

export function createAccessControl(opts: AccessControlOptions) {
  function authenticate(req: express.Request): Principal | null {
    const key = presentedKey(req);
    if (key) {
      for (const k of opts.apiKeys()) {
        if (k && safeEqual(key, k)) return { kind: 'API_KEY', id: 'api-key', name: 'api-key', role: 'ADMIN' };
      }
      const assetId = globalAssetRegistry.sensorFor(key);
      if (assetId) return { kind: 'SENSOR', id: assetId, name: assetId, role: null };
      // An unrecognised key is not a failure yet: the browser console still sends a
      // placeholder key on some requests, and its cookie is the real credential.
    }
    const s = globalOperatorAuth.resolve(readCookie(req, SESSION_COOKIE));
    if (s) return { kind: 'OPERATOR', id: s.operatorId, name: s.username, role: s.role, session: s };
    return null;
  }

  /**
   * CSRF: a cookie-authenticated state change must come from this console's own page.
   * SameSite=Strict already withholds the cookie from other sites, but "site" ignores the
   * port, so a page on localhost:8080 counts as same-site with localhost:3000. The
   * Origin check closes that gap.
   */
  function sameOrigin(req: express.Request): boolean {
    let origin = typeof req.headers.origin === 'string' ? req.headers.origin : null;
    if (!origin && typeof req.headers.referer === 'string') {
      try {
        origin = new URL(req.headers.referer).origin;
      } catch {
        origin = null;
      }
    }
    if (!origin) return false;
    try {
      if (new URL(origin).host === req.headers.host) return true;
    } catch {
      return false;
    }
    return opts.extraOrigins().includes(origin);
  }

  function actorOf(req: express.Request): { actor: string; role: string | null } {
    const p = req.principal;
    if (!p) return { actor: 'anonymous', role: null };
    return { actor: p.kind === 'OPERATOR' ? p.name : p.kind === 'SENSOR' ? `sensor:${p.id}` : 'api-key', role: p.role };
  }

  function audit(
    req: express.Request,
    action: string,
    outcome: AuditOutcome,
    target?: string | null,
    detail?: Record<string, unknown> | null
  ) {
    const { actor, role } = actorOf(req);
    globalAuditTrail.append({ actor, role, ip: clientIp(req), action, target: target ?? null, outcome, detail: detail ?? null });
  }

  function deny(res: express.Response, status: number, error: string, message: string, messageAr: string) {
    return res.status(status).json({ success: false, error, message, messageAr });
  }

  /** Routes reachable without any credential. Paths are relative to the /api mount. */
  const PUBLIC: Array<[string, RegExp]> = [
    ['GET', /^\/health$/],
    ['*', /^\/v1\/auth\/(login|setup|session|logout)$/]
  ];

  /** Routes a sensor credential may reach. Each handler also checks the credential's asset. */
  const SENSOR_ROUTES: Array<[string, RegExp]> = [
    ['POST', /^\/v1\/assets\/enroll$/],
    ['POST', /^\/v1\/assets\/[^/]+\/(heartbeat|discovery)$/],
    ['POST', /^\/v1\/soc\/ingest-telemetry\/batch$/]
  ];

  const matches = (list: Array<[string, RegExp]>, method: string, p: string) =>
    list.some(([m, re]) => (m === '*' || m === method) && re.test(p));

  /**
   * The gate, mounted on /api before every route. GET/HEAD need VIEWER; every other
   * method needs ANALYST. Routes that need ADMIN add requireRole('ADMIN') themselves.
   */
  function gate(req: express.Request, res: express.Response, next: express.NextFunction) {
    if (req.method === 'OPTIONS') return next();
    const p = req.path;
    req.principal = authenticate(req);

    if (matches(PUBLIC, req.method, p)) return next();

    const pr = req.principal;
    const sensorRoute = matches(SENSOR_ROUTES, req.method, p);

    if (pr?.kind === 'SENSOR') {
      if (sensorRoute) return next();
      return deny(res, 403, 'SENSOR_SCOPE', 'A sensor credential only reaches the sensor routes.', 'اعتماد الحساس لا يصل إلا إلى مسارات الحساس.');
    }
    // Enrolment carries its own proof (a single-use token or the host's credential).
    if (p === '/v1/assets/enroll' && req.method === 'POST') return next();

    if (!pr) {
      return deny(res, 401, 'AUTH_REQUIRED', 'Sign in to the console, or present an API key.', 'سجّل الدخول إلى الكونسول، أو قدّم مفتاح API.');
    }

    const mutating = req.method !== 'GET' && req.method !== 'HEAD';
    if (pr.kind === 'OPERATOR' && mutating && !sameOrigin(req)) {
      audit(req, 'CSRF_REFUSED', 'DENIED', `${req.method} ${req.originalUrl.split('?')[0]}`, {
        origin: req.headers.origin ?? null
      });
      return deny(res, 403, 'CROSS_ORIGIN_REFUSED', 'State-changing requests must come from the console itself.', 'الطلبات المغيِّرة يجب أن تصدر من الكونسول نفسه.');
    }

    const need: Role = mutating ? 'ANALYST' : 'VIEWER';
    if (ROLE_RANK[pr.role as Role] < ROLE_RANK[need]) {
      if (mutating) {
        audit(req, 'ROLE_REFUSED', 'DENIED', `${req.method} ${req.originalUrl.split('?')[0]}`, { need });
      }
      return deny(res, 403, 'ROLE_INSUFFICIENT', `This action needs the ${need} role.`, `هذا الإجراء يتطلّب دور ${need}.`);
    }
    return next();
  }

  function requireRole(role: Role) {
    return (req: express.Request, res: express.Response, next: express.NextFunction) => {
      const pr = req.principal ?? authenticate(req);
      req.principal = pr;
      if (!pr) return deny(res, 401, 'AUTH_REQUIRED', 'Sign in required.', 'يلزم تسجيل الدخول.');
      if (pr.kind === 'SENSOR' || ROLE_RANK[pr.role as Role] < ROLE_RANK[role]) {
        audit(req, 'ROLE_REFUSED', 'DENIED', `${req.method} ${req.originalUrl.split('?')[0]}`, { need: role });
        return deny(res, 403, 'ROLE_INSUFFICIENT', `This action needs the ${role} role.`, `هذا الإجراء يتطلّب دور ${role}.`);
      }
      return next();
    };
  }

  /**
   * Records a privileged route's outcome once the response is sent, so the entry carries
   * the real status rather than the intent. Attached by adminAuthMiddleware.
   */
  function auditOnFinish(req: express.Request, res: express.Response) {
    if (req.method === 'GET' || req.method === 'HEAD') return;
    // Observation feeds and read-style checks that happen to be POSTs. They still need
    // ANALYST, but recording each one would bury every real decision under sensor volume:
    // a DNS sensor alone posts one per query.
    const p = req.originalUrl.split('?')[0];
    if (AUDIT_QUIET.some(re => re.test(p))) return;
    res.on('finish', () => {
      const outcome: AuditOutcome = res.statusCode < 400 ? 'SUCCESS' : res.statusCode === 401 || res.statusCode === 403 ? 'DENIED' : 'FAILURE';
      audit(req, 'ADMIN_ROUTE', outcome, `${req.method} ${req.originalUrl.split('?')[0]}`, { status: res.statusCode });
    });
  }

  return { authenticate, gate, requireRole, audit, auditOnFinish, sameOrigin };
}

export type AccessControl = ReturnType<typeof createAccessControl>;

/* ── Response hardening ─────────────────────────────────────────────────────── */

/**
 * Security headers for every response. A security console that scans other sites for
 * these headers did not send them itself.
 *
 * CSP is applied in production only: Vite's dev server injects inline scripts for hot
 * reload that a strict policy would block. `style-src 'unsafe-inline'` stays because the
 * console sets inline style attributes throughout; scripts get no such allowance.
 */
export function securityHeaders(opts: { production: boolean; tls: boolean; frameAncestors: string }) {
  return (req: express.Request, res: express.Response, next: express.NextFunction) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'same-origin');
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=(), usb=(), serial=()');
    res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
    res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
    if (opts.frameAncestors === "'none'") res.setHeader('X-Frame-Options', 'DENY');
    if (opts.tls) res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    if (opts.production) {
      const host = String(req.headers.host ?? '').replace(/[^a-zA-Z0-9.:\-[\]]/g, '');
      res.setHeader(
        'Content-Security-Policy',
        [
          "default-src 'self'",
          "script-src 'self'",
          "style-src 'self' 'unsafe-inline'",
          "img-src 'self' data: blob:",
          "font-src 'self' data:",
          `connect-src 'self'${host ? ` ws://${host} wss://${host}` : ''}`,
          "worker-src 'self' blob:",
          "object-src 'none'",
          "base-uri 'self'",
          "form-action 'self'",
          `frame-ancestors ${opts.frameAncestors}`
        ].join('; ')
      );
    }
    next();
  };
}
