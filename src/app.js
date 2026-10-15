import express from 'express';
import session from 'express-session';
import connectPgSimple from 'connect-pg-simple';
import helmet from 'helmet';
import { createHmac, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { OAuth2Client, CodeChallengeMethod } from 'google-auth-library';
import { hashPassword, passwordProblem, verifyPassword } from './passwords.js';

const PgStore = connectPgSimple(session);
const roles = new Set(['member', 'analyst', 'admin']);
const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const normalizeEmail = (value) => typeof value === 'string' ? value.trim().toLowerCase() : '';
const csrf = () => randomBytes(32).toString('base64url');
const safeEqual = (left, right) => {
  if (typeof left !== 'string' || typeof right !== 'string') return false;
  const a = Buffer.from(left);
  const b = Buffer.from(right);
  return a.length === b.length && timingSafeEqual(a, b);
};
const saveSession = (req) => new Promise((resolve, reject) => req.session.save((error) => error ? reject(error) : resolve()));
const regenerateSession = (req) => new Promise((resolve, reject) => req.session.regenerate((error) => error ? reject(error) : resolve()));
const destroySession = (req) => new Promise((resolve, reject) => req.session.destroy((error) => error ? reject(error) : resolve()));

function publicUser(row) {
  return {
    id: row.id, name: row.name, email: row.email, role: row.role,
    emailVerified: row.email_verified,
    authMethods: [row.password_hash ? 'password' : null, row.google_subject ? 'google' : null].filter(Boolean),
    createdAt: row.created_at,
  };
}

export function createApp({ pool, config, oauthClient: suppliedOauthClient }) {
  const app = express();
  const googleEnabled = Boolean(config.googleClientId && config.googleClientSecret);
  const googleClient = suppliedOauthClient || (googleEnabled ? new OAuth2Client({
    clientId: config.googleClientId,
    clientSecret: config.googleClientSecret,
    redirectUri: `${config.appOrigin}/api/auth/google/callback`,
  }) : null);
  const cookieName = config.production ? '__Host-lab_auth' : 'lab_auth';
  const hash = (value) => createHmac('sha256', config.auditSecret).update(String(value)).digest('hex');
  const store = new PgStore({
    pool, tableName: 'sessions', createTableIfMissing: false, pruneSessionInterval: 15 * 60,
    errorLog: (...args) => console.error(JSON.stringify({ level: 'error', code: args.find((arg) => arg?.code)?.code || 'SESSION_STORE_ERROR' })),
  });
  app.locals.sessionStore = store;
  app.disable('x-powered-by');
  // TRUST_PROXY=1 is only safe on the isolated network where Caddy is the sole app ingress.
  app.set('trust proxy', config.trustProxy ?? 'loopback');
  app.use(helmet({
    contentSecurityPolicy: { directives: {
      defaultSrc: ["'self'"], scriptSrc: ["'self'"], styleSrc: ["'self'"],
      imgSrc: ["'self'", 'data:'], connectSrc: ["'self'"], fontSrc: ["'self'"],
      objectSrc: ["'none'"], frameAncestors: ["'none'"], formAction: ["'self'"],
      baseUri: ["'none'"], upgradeInsecureRequests: config.production ? [] : null,
    } },
    strictTransportSecurity: config.production ? { maxAge: 31536000, includeSubDomains: false } : false,
    referrerPolicy: { policy: 'no-referrer' },
  }));
  app.use((req, res, next) => {
    req.requestId = randomUUID();
    res.setHeader('X-Request-Id', req.requestId);
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    if (req.path.toLowerCase().startsWith('/api/')) res.setHeader('Cache-Control', 'no-store');
    next();
  });
  app.get('/healthz', (_req, res) => res.json({ status: 'ok' }));
  app.get('/readyz', async (_req, res) => {
    try { await pool.query('SELECT 1'); res.json({ status: 'ready' }); }
    catch { res.status(503).json({ status: 'unavailable' }); }
  });
  app.use(express.json({ limit: '8kb', strict: true }));
  app.use(session({
    name: cookieName, secret: config.sessionSecret, store, resave: false,
    saveUninitialized: false, rolling: true,
    cookie: { secure: config.production, httpOnly: true, sameSite: 'lax', path: '/', maxAge: config.idleSessionMs },
  }));

  async function event(req, type, outcome, metadata = {}, actorId = req.user?.id || null) {
    await pool.query(
      'INSERT INTO security_events(type,outcome,actor_id,ip_hash,request_id,metadata) VALUES($1,$2,$3,$4,$5,$6)',
      [type, outcome, actorId, hash(req.ip), req.requestId, JSON.stringify(metadata)],
    );
  }
  const fail = (res, status, code, message) => res.status(status).json({ error: { code, message } });

  app.use(async (req, _res, next) => {
    if (req.session?.userId) {
      const { rows } = await pool.query('SELECT * FROM users WHERE id=$1', [req.session.userId]);
      const user = rows[0];
      if (!user || user.session_version !== req.session.version || Date.now() - req.session.authAt > config.absoluteSessionMs) {
        await regenerateSession(req);
      } else {
        req.user = user;
        req.session.lastSeenAt = Date.now();
      }
    }
    next();
  });
  app.use('/api', async (req, res, next) => {
    if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
    if (req.get('origin') !== config.appOrigin || req.get('sec-fetch-site') === 'cross-site' || !safeEqual(req.get('x-csrf-token'), req.session.csrfToken)) {
      await event(req, 'csrf.rejected', 'blocked');
      return fail(res, 403, 'CSRF_REJECTED', 'This request could not be verified. Refresh the page and try again.');
    }
    if (!req.is('application/json')) return fail(res, 415, 'JSON_REQUIRED', 'Send requests as application/json.');
    next();
  });

  function requireUser(req, res, next) {
    if (!req.user) return fail(res, 401, 'AUTH_REQUIRED', 'Sign in to continue.');
    next();
  }
  const requireRole = (...allowed) => async (req, res, next) => {
    if (!req.user) return fail(res, 401, 'AUTH_REQUIRED', 'Sign in to continue.');
    if (!allowed.includes(req.user.role)) {
      await event(req, 'authorization.denied', 'blocked', { route: req.route?.path || 'restricted', role: req.user.role });
      return fail(res, 403, 'FORBIDDEN', 'Your role does not allow this action.');
    }
    next();
  };
  const limit = (name, maximum, account = false) => async (req, res, next) => {
    const identifier = account ? normalizeEmail(req.body?.email) : req.ip;
    const windowStart = Math.floor(Date.now() / config.rateWindowMs);
    const { rows } = await pool.query(
      `INSERT INTO rate_buckets(key,window_start,count) VALUES($1,$2,1)
       ON CONFLICT(key,window_start) DO UPDATE SET count=rate_buckets.count+1 RETURNING count`,
      [`${name}:${hash(identifier)}`, windowStart],
    );
    if (rows[0].count > maximum) {
      await event(req, 'auth.rate_limited', 'blocked', { category: name });
      res.setHeader('Retry-After', String(Math.ceil(config.rateWindowMs / 1000)));
      return fail(res, 429, 'RATE_LIMITED', 'Too many attempts. Try again later.');
    }
    next();
  };
  async function authenticate(req, user) {
    await regenerateSession(req);
    req.session.userId = user.id;
    req.session.version = user.session_version;
    req.session.authAt = Date.now();
    req.session.createdAt = Date.now();
    req.session.lastSeenAt = Date.now();
    req.session.csrfToken = csrf();
    await saveSession(req);
    req.user = user;
  }
  const sessionResponse = (req) => {
    req.session.csrfToken ||= csrf();
    return { user: req.user ? publicUser(req.user) : null, csrfToken: req.session.csrfToken, googleEnabled };
  };
  app.get(['/api/me', '/api/auth/session'], (req, res) => res.json(sessionResponse(req)));
  app.get('/api/auth/csrf', (req, res) => res.json({ csrfToken: sessionResponse(req).csrfToken }));

  app.post('/api/auth/register', limit('register-ip', config.registrationRateLimit), async (req, res) => {
    const email = normalizeEmail(req.body?.email);
    const name = typeof req.body?.name === 'string' ? req.body.name.trim() : '';
    const problem = passwordProblem(req.body?.password);
    if (!emailPattern.test(email) || email.length > 254 || !name || name.length > 80 || problem) {
      return fail(res, 400, 'INVALID_INPUT', problem || 'Enter a valid email address and a name containing 1–80 characters.');
    }
    const passwordHash = await hashPassword(req.body.password);
    const result = await pool.query(
      'INSERT INTO users(id,email,name,password_hash) VALUES($1,$2,$3,$4) ON CONFLICT(email) DO NOTHING RETURNING id',
      [randomUUID(), email, name, passwordHash],
    );
    // The response is identical for existing addresses and successful registration.
    await event(req, 'auth.registration_requested', 'success', {}, result.rows[0]?.id || null);
    res.status(201).json({ user: null, csrfToken: req.session.csrfToken, message: 'If this address can be registered, your account is ready. Sign in to continue.' });
  });
  app.post('/api/auth/login', limit('login-ip', config.authRateLimit), limit('login-account', config.authRateLimit * 2, true), async (req, res) => {
    const email = normalizeEmail(req.body?.email);
    const password = req.body?.password;
    if (typeof password !== 'string' || password.length > 128 || email.length > 254) return fail(res, 400, 'INVALID_INPUT', 'Enter an email address and password.');
    const { rows } = await pool.query('SELECT * FROM users WHERE email=$1', [email]);
    const user = rows[0];
    const valid = await verifyPassword(password, user?.password_hash);
    if (!valid) {
      await event(req, 'auth.login_failed', 'failure');
      return fail(res, 401, 'INVALID_CREDENTIALS', 'Email or password is incorrect.');
    }
    await authenticate(req, user);
    await event(req, 'auth.login_succeeded', 'success', { method: 'password' });
    res.json({ user: publicUser(user), csrfToken: req.session.csrfToken });
  });
  app.post('/api/auth/logout', async (req, res) => {
    if (req.user) await event(req, 'auth.logout', 'success');
    await destroySession(req);
    res.clearCookie(cookieName, { path: '/', secure: config.production, httpOnly: true, sameSite: 'lax' });
    res.json({ ok: true });
  });
  app.post('/api/auth/password', requireUser, limit('password-ip', 5), async (req, res) => {
    const problem = passwordProblem(req.body?.newPassword);
    if (problem) return fail(res, 400, 'INVALID_INPUT', problem);
    if (typeof req.body?.currentPassword !== 'string' || req.body.currentPassword.length > 128 || !await verifyPassword(req.body.currentPassword, req.user.password_hash)) {
      await event(req, 'auth.password_change_failed', 'failure');
      return fail(res, 401, 'INVALID_CREDENTIALS', 'Current password is incorrect.');
    }
    const { rows } = await pool.query(
      'UPDATE users SET password_hash=$1,session_version=session_version+1,updated_at=now() WHERE id=$2 RETURNING *',
      [await hashPassword(req.body.newPassword), req.user.id],
    );
    await authenticate(req, rows[0]);
    await event(req, 'auth.password_changed', 'success');
    res.json({ user: publicUser(rows[0]), csrfToken: req.session.csrfToken });
  });

  app.get('/api/auth/google', limit('google-ip', 30), async (req, res) => {
    if (!googleEnabled) return fail(res, 503, 'GOOGLE_NOT_CONFIGURED', 'Google sign-in is not configured for this deployment.');
    const codes = await googleClient.generateCodeVerifierAsync();
    req.session.oauth = { state: csrf(), nonce: csrf(), verifier: codes.codeVerifier, createdAt: Date.now() };
    await saveSession(req);
    const url = googleClient.generateAuthUrl({
      scope: ['openid', 'email', 'profile'], state: req.session.oauth.state, nonce: req.session.oauth.nonce,
      code_challenge: codes.codeChallenge, code_challenge_method: CodeChallengeMethod.S256, prompt: 'select_account',
      access_type: 'online',
    });
    res.redirect(url);
  });
  app.get('/api/auth/google/callback', limit('google-callback-ip', 30), async (req, res) => {
    if (!googleEnabled) return fail(res, 503, 'GOOGLE_NOT_CONFIGURED', 'Google sign-in is not configured for this deployment.');
    const oauth = req.session.oauth;
    delete req.session.oauth;
    await saveSession(req);
    if (!oauth || !safeEqual(req.query.state, oauth.state) || Date.now() - oauth.createdAt > 10 * 60_000 || typeof req.query.code !== 'string' || req.query.code.length > 4096) {
      await event(req, 'auth.google_failed', 'failure', { reason: 'invalid_callback' });
      return res.redirect('/?auth_error=google_failed');
    }
    try {
      const { tokens } = await googleClient.getToken({ code: req.query.code, codeVerifier: oauth.verifier });
      const ticket = await googleClient.verifyIdToken({ idToken: tokens.id_token, audience: config.googleClientId });
      const payload = ticket.getPayload();
      if (!payload || !safeEqual(payload.nonce, oauth.nonce) || !payload.sub || !payload.email_verified || !emailPattern.test(payload.email || '') || !['accounts.google.com', 'https://accounts.google.com'].includes(payload.iss)) throw new Error('Invalid Google identity');
      const email = normalizeEmail(payload.email);
      let { rows } = await pool.query('SELECT * FROM users WHERE google_subject=$1', [payload.sub]);
      let user = rows[0];
      if (!user) {
        const result = await pool.query(
          `INSERT INTO users(id,email,name,google_subject,email_verified) VALUES($1,$2,$3,$4,true) ON CONFLICT DO NOTHING RETURNING *`,
          [randomUUID(), email, String(payload.name || 'Google member').slice(0, 80), payload.sub],
        );
        user = result.rows[0];
        // Another successful callback may have created the same subject while this request was in flight.
        if (!user) user = (await pool.query('SELECT * FROM users WHERE google_subject=$1', [payload.sub])).rows[0];
        if (!user) {
          // Email is never sufficient proof for silently linking an existing password identity.
          await event(req, 'auth.google_failed', 'failure', { reason: 'identity_conflict' });
          return res.redirect('/?auth_error=account_exists');
        }
      }
      await authenticate(req, user);
      await event(req, 'auth.login_succeeded', 'success', { method: 'google' });
      res.redirect('/?auth=success');
    } catch {
      await event(req, 'auth.google_failed', 'failure', { reason: 'provider_verification' });
      res.redirect('/?auth_error=google_failed');
    }
  });

  app.get('/api/dashboard', requireUser, (req, res) => res.json({
    user: publicUser(req.user),
    stats: { projects: 3, activeMembers: 8, openTasks: 12, uptime: '99.9%' },
    projects: [
      { id: 'atlas', name: 'Atlas workspace', description: 'A shared space for the next product launch.', status: 'Active', progress: 72, members: 4 },
      { id: 'northstar', name: 'Northstar API', description: 'A small integration built by the platform team.', status: 'Active', progress: 48, members: 3 },
      { id: 'paperplane', name: 'Paperplane design', description: 'A refreshed experience for our community.', status: 'Planning', progress: 24, members: 2 },
    ],
    activity: [
      { id: '1', type: 'project', title: 'Atlas milestone reached', description: 'The team completed the onboarding flow.', createdAt: '2026-10-01T10:00:00Z' },
      { id: '2', type: 'team', title: 'Workspace updated', description: 'Demo project access was reviewed.', createdAt: '2026-10-01T09:15:00Z' },
      { id: '3', type: 'task', title: 'New design ready', description: 'Paperplane design has a new review task.', createdAt: '2026-10-01T08:30:00Z' },
    ],
    team: [ { id: 'demo-a', name: 'Alex Rivera', role: 'Product lead', avatar: 'AR' }, { id: 'demo-m', name: 'Morgan Chen', role: 'Engineer', avatar: 'MC' }, { id: 'demo-j', name: 'Jamie Taylor', role: 'Designer', avatar: 'JT' } ],
  }));
  app.get('/api/security', requireRole('analyst', 'admin'), async (req, res) => {
    const [events, sessions] = await Promise.all([
      pool.query('SELECT id,type,outcome,actor_id,request_id,metadata,created_at FROM security_events ORDER BY created_at DESC,id DESC LIMIT 100'),
      pool.query(`SELECT sid,sess,expire FROM sessions WHERE sess->>'userId'=$1 AND expire>now() AND (sess->>'version')::int=$2 ORDER BY expire DESC LIMIT 20`, [req.user.id, req.user.session_version]),
    ]);
    res.json({
      events: events.rows.map((row) => ({ id: row.id, type: row.type, outcome: row.outcome, actorId: row.actor_id, requestId: row.request_id, metadata: row.metadata, createdAt: row.created_at })),
      sessions: sessions.rows.map((row) => ({ id: hash(row.sid).slice(0, 16), current: row.sid === req.sessionID, createdAt: new Date(row.sess.createdAt).toISOString(), lastSeenAt: new Date(row.sess.lastSeenAt).toISOString(), expiresAt: row.expire })),
    });
  });
  app.get('/api/admin/users', requireRole('admin'), async (_req, res) => {
    const { rows } = await pool.query('SELECT * FROM users ORDER BY created_at DESC LIMIT 100');
    res.json({ users: rows.map(publicUser) });
  });
  app.patch(['/api/admin/users/:id', '/api/admin/users/:id/role'], requireRole('admin'), async (req, res) => {
    if (!/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i.test(req.params.id) || !roles.has(req.body?.role)) return fail(res, 400, 'INVALID_INPUT', 'Choose member, analyst, or admin.');
    if (req.params.id === req.user.id && req.body.role !== 'admin') return fail(res, 409, 'SELF_DEMOTION', 'Ask another administrator to change your role.');
    const { rows } = await pool.query('UPDATE users SET role=$1,session_version=session_version+CASE WHEN role<>$1 THEN 1 ELSE 0 END,updated_at=CASE WHEN role<>$1 THEN now() ELSE updated_at END WHERE id=$2 RETURNING *', [req.body.role, req.params.id]);
    if (!rows[0]) return fail(res, 404, 'NOT_FOUND', 'User not found.');
    // A changed role invalidates existing sessions; the next request must authenticate again.
    await event(req, 'admin.role_changed', 'success', { targetUserId: rows[0].id, role: rows[0].role });
    res.json({ user: publicUser(rows[0]) });
  });
  app.use('/api', (_req, res) => fail(res, 404, 'NOT_FOUND', 'API route not found.'));
  const publicDir = fileURLToPath(new URL('../public', import.meta.url));
  app.use(express.static(publicDir, { dotfiles: 'deny', index: 'index.html', maxAge: '5m' }));
  app.use((_req, res) => res.status(404).type('text').send('Not found'));
  app.use((error, req, res, _next) => {
    if (error.type === 'entity.too.large') return fail(res, 413, 'BODY_TOO_LARGE', 'The request is too large.');
    if (error instanceof SyntaxError && error.status === 400) return fail(res, 400, 'INVALID_JSON', 'The request contains invalid JSON.');
    // Do not log request bodies, credentials, database URLs, query strings, or OAuth provider tokens.
    console.error(JSON.stringify({ level: 'error', requestId: req.requestId, code: error.code || 'INTERNAL_ERROR' }));
    fail(res, 500, 'INTERNAL_ERROR', 'Something went wrong. Try again later.');
  });
  return app;
}
