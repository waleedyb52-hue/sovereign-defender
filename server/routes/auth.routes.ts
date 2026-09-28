import express from 'express';
import { globalOperatorAuth, ROLES, SESSION_LIMITS, type Role } from '../services/operatorAuth.service.js';
import { globalAuditTrail } from '../services/auditTrail.service.js';
import {
  clearedSessionCookie,
  clientIp,
  isDirectLoopback,
  readCookie,
  SESSION_COOKIE,
  sessionCookie,
  type AccessControl
} from '../middleware/accessControl.js';

/**
 * AUTH, OPERATORS AND AUDIT ROUTES
 *
 *   GET  /api/v1/auth/session            who am I; does the console need first-run setup
 *   POST /api/v1/auth/setup              create the first ADMIN (loopback or setup secret)
 *   POST /api/v1/auth/login              → HttpOnly session cookie
 *   POST /api/v1/auth/logout
 *   POST /api/v1/auth/password           change own password (revokes own sessions)
 *   GET  /api/v1/auth/operators          ADMIN
 *   POST /api/v1/auth/operators          ADMIN — create
 *   PATCH /api/v1/auth/operators/:id     ADMIN — role, disabled
 *   GET  /api/v1/auth/sessions           ADMIN — live sessions
 *   GET  /api/v1/auth/api-key            ADMIN — reveal the rotating integration key
 *   GET  /api/v1/audit                   ANALYST — the trail, newest first
 *   GET  /api/v1/audit/verify            ANALYST — walk the chain
 */

export function createAuthRouter(ac: AccessControl, opts: { tls: boolean; rotatingApiKey: () => string }) {
  const r = express.Router();
  const maxAge = Math.floor(SESSION_LIMITS.absoluteMs / 1000);
  const secure = (req: express.Request) => opts.tls || req.secure;

  /** Login and setup are public, but a browser request from another origin is refused. */
  const foreignBrowser = (req: express.Request) => Boolean(req.headers.origin) && !ac.sameOrigin(req);

  r.get('/auth/session', (req, res) => {
    const p = req.principal;
    const setupRequired = !globalOperatorAuth.hasOperators();
    res.json({
      success: true,
      authenticated: p?.kind === 'OPERATOR',
      operator:
        p?.kind === 'OPERATOR' && p.session
          ? {
              id: p.id,
              username: p.name,
              displayName: p.session.displayName,
              role: p.role,
              sessionId: p.session.id,
              expiresAt: new Date(
                Math.min(p.session.lastSeenAt + SESSION_LIMITS.idleMs, p.session.createdAt + SESSION_LIMITS.absoluteMs)
              ).toISOString()
            }
          : null,
      setupRequired,
      // Tells the setup screen whether it must ask for the console-printed secret.
      setupFromHere: setupRequired && isDirectLoopback(req),
      transport: opts.tls || req.secure ? 'TLS' : 'CLEARTEXT',
      storeDurable: globalOperatorAuth.durable()
    });
  });

  r.post('/auth/setup', async (req, res) => {
    if (foreignBrowser(req)) return res.status(403).json({ success: false, error: 'CROSS_ORIGIN_REFUSED' });
    if (globalOperatorAuth.hasOperators()) {
      return res.status(409).json({ success: false, error: 'ALREADY_INITIALISED', message: 'An operator already exists. Sign in instead.' });
    }
    const { username, password, displayName, setupToken } = req.body || {};
    if (!isDirectLoopback(req) && !globalOperatorAuth.setupSecretMatches(setupToken)) {
      ac.audit(req, 'SETUP_REFUSED', 'DENIED', typeof username === 'string' ? username : null);
      return res.status(403).json({
        success: false,
        error: 'SETUP_SECRET_REQUIRED',
        message: 'First-run setup from another machine needs the setup secret printed in the server console.',
        messageAr: 'الإعداد الأول من جهاز آخر يتطلّب الرمز السرّي المطبوع في طرفية الخادم.'
      });
    }
    const created = await globalOperatorAuth.create({ username, password, displayName, role: 'ADMIN' }, 'first-run-setup');
    if ('reason' in created) return res.status(400).json({ success: false, error: 'INVALID', message: created.reason });

    const login = await globalOperatorAuth.login(username, password, clientIp(req));
    if ('reason' in login) return res.status(500).json({ success: false, error: 'LOGIN_AFTER_SETUP_FAILED' });
    res.setHeader('Set-Cookie', sessionCookie(login.token, secure(req), maxAge));
    req.principal = { kind: 'OPERATOR', id: login.session.operatorId, name: login.session.username, role: 'ADMIN', session: login.session };
    ac.audit(req, 'OPERATOR_CREATED', 'SUCCESS', created.operator.username, { role: 'ADMIN', via: 'first-run-setup' });
    return res.json({ success: true, operator: created.operator });
  });

  r.post('/auth/login', async (req, res) => {
    if (foreignBrowser(req)) return res.status(403).json({ success: false, error: 'CROSS_ORIGIN_REFUSED' });
    const { username, password } = req.body || {};
    const name = typeof username === 'string' ? username.slice(0, 64) : null;
    const result = await globalOperatorAuth.login(username, password, clientIp(req));
    if ('reason' in result) {
      ac.audit(req, 'LOGIN', result.reason === 'LOCKED' ? 'DENIED' : 'FAILURE', name, { reason: result.reason });
      if (result.reason === 'LOCKED') {
        res.setHeader('Retry-After', String(result.retryAfterSec ?? 900));
        return res.status(429).json({
          success: false,
          error: 'LOCKED',
          retryAfterSec: result.retryAfterSec,
          message: 'Too many failed attempts. Try again later.',
          messageAr: 'محاولات فاشلة كثيرة. حاول لاحقًا.'
        });
      }
      // One message for unknown user, wrong password and disabled account alike.
      return res.status(401).json({
        success: false,
        error: 'INVALID_CREDENTIALS',
        message: 'Username or password is incorrect.',
        messageAr: 'اسم المستخدم أو كلمة المرور غير صحيحة.'
      });
    }
    res.setHeader('Set-Cookie', sessionCookie(result.token, secure(req), maxAge));
    req.principal = { kind: 'OPERATOR', id: result.session.operatorId, name: result.session.username, role: result.session.role, session: result.session };
    ac.audit(req, 'LOGIN', 'SUCCESS', result.session.username, { sessionId: result.session.id });
    return res.json({
      success: true,
      operator: {
        id: result.session.operatorId,
        username: result.session.username,
        displayName: result.session.displayName,
        role: result.session.role
      }
    });
  });

  r.post('/auth/logout', (req, res) => {
    const s = globalOperatorAuth.logout(readCookie(req, SESSION_COOKIE));
    res.setHeader('Set-Cookie', clearedSessionCookie(secure(req)));
    if (s) ac.audit(req, 'LOGOUT', 'SUCCESS', s.username, { sessionId: s.id });
    res.json({ success: true });
  });

  r.post('/auth/password', async (req, res) => {
    const p = req.principal;
    if (p?.kind !== 'OPERATOR') return res.status(403).json({ success: false, error: 'OPERATORS_ONLY' });
    const { current, next } = req.body || {};
    const done = await globalOperatorAuth.changePassword(p.id, String(current ?? ''), String(next ?? ''));
    const why = 'reason' in done ? done.reason : null;
    ac.audit(req, 'PASSWORD_CHANGED', why ? 'FAILURE' : 'SUCCESS', p.name, why ? { reason: why } : null);
    if (why) return res.status(400).json({ success: false, error: 'INVALID', message: why });
    res.setHeader('Set-Cookie', clearedSessionCookie(secure(req)));
    return res.json({ success: true, signedOut: true });
  });

  /* ── Operator administration ─────────────────────────────────────────── */

  r.get('/auth/operators', ac.requireRole('ADMIN'), (_req, res) => {
    res.json({ success: true, operators: globalOperatorAuth.list(), roles: ROLES });
  });

  r.post('/auth/operators', ac.requireRole('ADMIN'), async (req, res) => {
    const { username, password, displayName, role } = req.body || {};
    const created = await globalOperatorAuth.create({ username, password, displayName, role: role as Role }, req.principal?.name ?? null);
    ac.audit(req, 'OPERATOR_CREATED', 'reason' in created ? 'FAILURE' : 'SUCCESS', typeof username === 'string' ? username : null, 'reason' in created ? { reason: created.reason } : { role });
    if ('reason' in created) return res.status(400).json({ success: false, error: 'INVALID', message: created.reason });
    return res.json({ success: true, operator: created.operator });
  });

  r.patch('/auth/operators/:id', ac.requireRole('ADMIN'), (req, res) => {
    const { role, disabled } = req.body || {};
    const id = req.params.id;
    if (id === req.principal?.id && (disabled === true || (role && role !== 'ADMIN'))) {
      return res.status(400).json({ success: false, error: 'SELF_LOCKOUT', message: 'You cannot demote or disable your own account.' });
    }
    let result: ReturnType<typeof globalOperatorAuth.setRole> | null = null;
    if (role !== undefined) {
      result = globalOperatorAuth.setRole(id, role);
      ac.audit(req, 'OPERATOR_ROLE_CHANGED', 'reason' in result ? 'FAILURE' : 'SUCCESS', id, 'reason' in result ? { reason: result.reason } : { role });
      if ('reason' in result) return res.status(400).json({ success: false, error: 'INVALID', message: result.reason });
    }
    if (disabled !== undefined) {
      result = globalOperatorAuth.setDisabled(id, Boolean(disabled));
      ac.audit(req, disabled ? 'OPERATOR_DISABLED' : 'OPERATOR_ENABLED', 'reason' in result ? 'FAILURE' : 'SUCCESS', id, 'reason' in result ? { reason: result.reason } : null);
      if ('reason' in result) return res.status(400).json({ success: false, error: 'INVALID', message: result.reason });
    }
    if (!result) return res.status(400).json({ success: false, error: 'NOTHING_TO_CHANGE' });
    return res.json({ success: true, operator: 'operator' in result ? result.operator : null });
  });

  r.get('/auth/sessions', ac.requireRole('ADMIN'), (_req, res) => {
    res.json({ success: true, sessions: globalOperatorAuth.activeSessions() });
  });

  /** The rotating integration key is revealed only to an ADMIN, and each reveal is logged. */
  r.get('/auth/api-key', ac.requireRole('ADMIN'), (req, res) => {
    ac.audit(req, 'API_KEY_REVEALED', 'SUCCESS', 'rotating-key');
    res.json({ success: true, apiKey: opts.rotatingApiKey() });
  });

  /* ── Audit trail ─────────────────────────────────────────────────────── */

  r.get('/audit', ac.requireRole('ANALYST'), (req, res) => {
    const q = req.query;
    res.json({
      success: true,
      durable: globalAuditTrail.durable(),
      entries: globalAuditTrail.list({
        limit: Number(q.limit) || 100,
        beforeSeq: Number(q.before) || undefined,
        action: typeof q.action === 'string' && q.action ? q.action : undefined,
        actor: typeof q.actor === 'string' && q.actor ? q.actor : undefined
      })
    });
  });

  r.get('/audit/verify', ac.requireRole('ANALYST'), (req, res) => {
    const v = globalAuditTrail.verify();
    // Verification is itself an auditable act: it is how an operator anchors the head.
    ac.audit(req, 'AUDIT_VERIFIED', v.ok ? 'SUCCESS' : 'FAILURE', v.headHash, { checked: v.checked, brokenAt: v.brokenAt });
    res.json({ success: true, verification: v });
  });

  return r;
}
