import express from 'express';
import session from 'express-session';
import connectPgSimple from 'connect-pg-simple';
import helmet from 'helmet';
import { createHmac, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { OAuth2Client, CodeChallengeMethod } from 'google-auth-library';
import { guard } from 'securenow/sessions';
import { hashPassword, passwordProblem, verifyPassword } from './passwords.js';
import { createBridge } from './securenow-bridge.js';

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
  // F6: match routes exactly, so /API/AUTH/LOGIN and /api/auth/login/ return 404 and cannot sidestep
  // SecureNow's route-scoped controls (which compare the path exactly and case-sensitively).
  app.set('case sensitive routing', true);
  app.set('strict routing', true);
  const googleEnabled = Boolean(config.googleClientId && config.googleClientSecret);
  const googleClient = suppliedOauthClient || (googleEnabled ? new OAuth2Client({
    clientId: config.googleClientId,
    clientSecret: config.googleClientSecret,
    redirectUri: `${config.appOrigin}/api/auth/google/callback`,
  }) : null);
  const cookieName = config.production ? '__Host-lab_auth' : 'lab_auth';
  const hash = (value) => createHmac('sha256', config.auditSecret).update(String(value)).digest('hex');
  const { emit, ref, sessionRef } = createBridge(config);
  // F1: anonymous CSRF is a signed double-submit cookie, so a cookieless GET never persists a session row.
  const csrfCookieName = config.production ? '__Host-lab_csrf' : 'lab_csrf';
  const signCsrf = (nonce) => `${nonce}.${createHmac('sha256', config.sessionSecret).update(nonce).digest('base64url')}`;
  const readCsrf = (req) => {
    const part = (req.headers.cookie || '').split(';').map((c) => c.trim()).find((c) => c.startsWith(`${csrfCookieName}=`));
    const value = part ? part.slice(csrfCookieName.length + 1) : '';
    const dot = value.indexOf('.');
    return dot > 0 && safeEqual(value, signCsrf(value.slice(0, dot))) ? value : '';
  };
  // F3: a signed device-trust cookie (bound to the account) lets a returning owner skip the per-account
  // limit, so an attacker cannot hold a known member out. The account bucket counts failures only.
  const deviceCookieName = config.production ? '__Host-lab_device' : 'lab_device';
  const deviceMac = (id, email) => createHmac('sha256', config.sessionSecret).update(`${id}:${hash(email)}`).digest('base64url');
  const signDevice = (email) => { const id = csrf(); return `${id}.${deviceMac(id, email)}`; };
  const verifyDevice = (req, email) => {
    const part = (req.headers.cookie || '').split(';').map((c) => c.trim()).find((c) => c.startsWith(`${deviceCookieName}=`));
    const value = part ? part.slice(deviceCookieName.length + 1) : '';
    const dot = value.indexOf('.');
    return dot > 0 && safeEqual(value, `${value.slice(0, dot)}.${deviceMac(value.slice(0, dot), email)}`);
  };
  const windowStart = () => Math.floor(Date.now() / config.rateWindowMs);
  const readBucket = async (key) => Number((await pool.query('SELECT count FROM rate_buckets WHERE key=$1 AND window_start=$2', [key, windowStart()])).rows[0]?.count ?? 0);
  const bumpBucket = async (key) => Number((await pool.query(
    `INSERT INTO rate_buckets(key,window_start,count) VALUES($1,$2,1)
     ON CONFLICT(key,window_start) DO UPDATE SET count=rate_buckets.count+1 RETURNING count`, [key, windowStart()])).rows[0].count);
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
  // SecureNow sessions: emits session.seen for signed-in users and enforces `securenow revoke`.
  // The default cookie list does not know this app's cookie, so the extractors are explicit.
  app.use(guard({
    getSessionId: (req) => (req.user ? sessionRef(req) : null),
    getUserId: (req) => req.user?.id ?? null,
    onRevoked: async (req, res) => {
      await destroySession(req);
      res.clearCookie(cookieName, { path: '/', secure: config.production, httpOnly: true, sameSite: 'lax' });
      // A page load gets the sign-in page; API calls keep the JSON error the single-page app expects.
      if (req.method === 'GET' && !req.path.startsWith('/api/') && req.accepts(['json', 'html']) === 'html') {
        return res.redirect(303, '/');
      }
      return fail(res, 401, 'AUTH_REQUIRED', 'Your session has ended. Sign in to continue.');
    },
  }));
  app.use('/api', async (req, res, next) => {
    if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
    const expectedCsrf = req.session.csrfToken || readCsrf(req);
    if (req.get('origin') !== config.appOrigin || req.get('sec-fetch-site') === 'cross-site' || !expectedCsrf || !safeEqual(req.get('x-csrf-token'), expectedCsrf)) {
      // F2: cap audit writes — log at most one csrf.rejected per IP per window.
      const windowStart = Math.floor(Date.now() / config.rateWindowMs);
      const { rows } = await pool.query(
        `INSERT INTO rate_buckets(key,window_start,count) VALUES($1,$2,1)
         ON CONFLICT(key,window_start) DO UPDATE SET count=rate_buckets.count+1 RETURNING count`,
        [`csrf-reject:${hash(req.ip)}`, windowStart],
      );
      if (rows[0].count === 1) await event(req, 'csrf.rejected', 'blocked');
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
      const route = req.route?.path || req.baseUrl + req.path || 'restricted';
      await event(req, 'authorization.denied', 'blocked', { route, role: req.user.role });
      // AZ-1: export the authorization decision to SecureNow so role-boundary probing is detectable.
      emit('authz.denied', req, { userId: req.user.id, attributes: {
        decision: 'deny', reason: 'role_denied', route, method: req.method,
        have_role: req.user.role, need_role: allowed.join('|'), target_ref: req.params?.id ?? null,
      } });
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
      // F2: record at most one rejection per (category, client) per window.
      if (rows[0].count === maximum + 1) await event(req, 'auth.rate_limited', 'blocked', { category: name });
      emit('api.ratelimit.exceeded', req, { userId: req.user?.id, attributes: { scope: name, route: req.path.toLowerCase(), reason: 'fixed_window', ...(account ? { account_ref: ref('acct', identifier) } : {}) } });
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
  const sessionResponse = (req, res) => {
    if (req.user || req.session.userId) {
      req.session.csrfToken ||= csrf();
      return { user: req.user ? publicUser(req.user) : null, csrfToken: req.session.csrfToken, googleEnabled };
    }
    // Anonymous: issue the token as a signed cookie instead of persisting a session (F1).
    let value = readCsrf(req);
    if (!value) {
      value = signCsrf(csrf());
      res.cookie(csrfCookieName, value, { httpOnly: true, secure: config.production, sameSite: 'strict', path: '/', maxAge: config.idleSessionMs });
    }
    return { user: null, csrfToken: value, googleEnabled };
  };
  app.get(['/api/me', '/api/auth/session'], (req, res) => res.json(sessionResponse(req, res)));
  app.get('/api/auth/csrf', (req, res) => res.json({ csrfToken: sessionResponse(req, res).csrfToken }));

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
    emit('auth.signup', req, { userId: result.rows[0]?.id, attributes: { auth_method: 'password', provider: 'local', outcome: result.rows[0] ? 'created' : 'existing', account_ref: ref('acct', email) } });
    res.status(201).json({ user: null, csrfToken: req.session.csrfToken || readCsrf(req), message: 'If this address can be registered, your account is ready. Sign in to continue.' });
  });
  app.post('/api/auth/login', limit('login-ip', config.authRateLimit), async (req, res) => {
    const email = normalizeEmail(req.body?.email);
    const password = req.body?.password;
    if (typeof password !== 'string' || password.length > 128 || email.length > 254) return fail(res, 400, 'INVALID_INPUT', 'Enter an email address and password.');
    // F3: a returning owner (valid device cookie) is exempt; the account bucket counts failed attempts only.
    const accountKey = `login-account:${hash(email)}`;
    const trusted = verifyDevice(req, email);
    if (!trusted && await readBucket(accountKey) >= config.authRateLimit * 2) {
      emit('api.ratelimit.exceeded', req, { attributes: { scope: 'login-account', route: '/api/auth/login', reason: 'fixed_window', account_ref: ref('acct', email) } });
      res.setHeader('Retry-After', String(Math.ceil(config.rateWindowMs / 1000)));
      return fail(res, 429, 'RATE_LIMITED', 'Too many attempts. Try again later.');
    }
    const { rows } = await pool.query('SELECT * FROM users WHERE email=$1', [email]);
    const user = rows[0];
    const valid = await verifyPassword(password, user?.password_hash);
    if (!valid) {
      if (!trusted) await bumpBucket(accountKey);
      await event(req, 'auth.login_failed', 'failure');
      emit('auth.login.failure', req, { userId: user?.id, attributes: { auth_method: 'password', provider: 'local', reason: user ? 'bad_password' : 'unknown_account', account_ref: ref('acct', email), mfa_state: 'none', sso_required: false } });
      return fail(res, 401, 'INVALID_CREDENTIALS', 'Email or password is incorrect.');
    }
    await authenticate(req, user);
    res.cookie(deviceCookieName, signDevice(email), { httpOnly: true, secure: config.production, sameSite: 'lax', path: '/', maxAge: 400 * 24 * 60 * 60_000 });
    await event(req, 'auth.login_succeeded', 'success', { method: 'password' });
    emit('auth.login.success', req, { userId: user.id, attributes: { auth_method: 'password', provider: 'local', account_ref: ref('acct', email), mfa_state: 'none', sso_required: false } });
    res.json({ user: publicUser(user), csrfToken: req.session.csrfToken });
  });
  app.post('/api/auth/logout', async (req, res) => {
    if (req.user) {
      await event(req, 'auth.logout', 'success');
      emit('auth.logout', req, { userId: req.user.id });
    }
    await destroySession(req);
    res.clearCookie(cookieName, { path: '/', secure: config.production, httpOnly: true, sameSite: 'lax' });
    res.clearCookie(csrfCookieName, { path: '/', secure: config.production, httpOnly: true, sameSite: 'strict' });
    res.json({ ok: true });
  });
  app.post('/api/auth/password', requireUser, limit('password-ip', 5), async (req, res) => {
    const problem = passwordProblem(req.body?.newPassword);
    if (problem) return fail(res, 400, 'INVALID_INPUT', problem);
    if (typeof req.body?.currentPassword !== 'string' || req.body.currentPassword.length > 128 || !await verifyPassword(req.body.currentPassword, req.user.password_hash)) {
      await event(req, 'auth.password_change_failed', 'failure');
      emit('auth.security.change', req, { userId: req.user.id, attributes: { action: 'password_changed', outcome: 'failure', step_up: true } });
      return fail(res, 401, 'INVALID_CREDENTIALS', 'Current password is incorrect.');
    }
    const { rows } = await pool.query(
      'UPDATE users SET password_hash=$1,session_version=session_version+1,updated_at=now() WHERE id=$2 RETURNING *',
      [await hashPassword(req.body.newPassword), req.user.id],
    );
    const priorSession = sessionRef(req);
    await authenticate(req, rows[0]);
    await event(req, 'auth.password_changed', 'success');
    emit('auth.security.change', req, { userId: rows[0].id, sessionId: priorSession, attributes: { action: 'password_changed', outcome: 'completed', step_up: true } });
    res.json({ user: publicUser(rows[0]), csrfToken: req.session.csrfToken });
  });
  // F5: step-up re-authentication. A sensitive action (admin role change) requires a password check
  // in the last 5 minutes. Google-only admins would re-auth through Google (prompt=login) — left as a plan.
  app.post('/api/auth/reauth', requireUser, limit('reauth-ip', 5), async (req, res) => {
    if (typeof req.body?.password !== 'string' || req.body.password.length > 128 || !await verifyPassword(req.body.password, req.user.password_hash)) {
      await event(req, 'auth.reauth_failed', 'failure');
      return fail(res, 401, 'INVALID_CREDENTIALS', 'Password is incorrect.');
    }
    req.session.reauthAt = Date.now();
    await saveSession(req);
    res.json({ ok: true });
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
      emit('auth.login.failure', req, { attributes: { auth_method: 'oauth', provider: 'google', reason: 'invalid_callback' } });
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
        if (user) emit('auth.signup', req, { userId: user.id, attributes: { auth_method: 'oauth', provider: 'google', outcome: 'created', account_ref: ref('acct', email) } });
        // Another successful callback may have created the same subject while this request was in flight.
        if (!user) user = (await pool.query('SELECT * FROM users WHERE google_subject=$1', [payload.sub])).rows[0];
        if (!user) {
          // Email is never sufficient proof for silently linking an existing password identity.
          await event(req, 'auth.google_failed', 'failure', { reason: 'identity_conflict' });
          emit('auth.login.failure', req, { attributes: { auth_method: 'oauth', provider: 'google', reason: 'identity_conflict', account_ref: ref('acct', email) } });
          emit('auth.account.link', req, { attributes: { outcome: 'rejected', provider: 'google', verified_email: true, join_key: 'iss_sub', reason: 'existing_email_other_method', account_ref: ref('acct', email) } });
          return res.redirect('/?auth_error=account_exists');
        }
      }
      await authenticate(req, user);
      await event(req, 'auth.login_succeeded', 'success', { method: 'google' });
      emit('auth.login.success', req, { userId: user.id, attributes: { auth_method: 'oauth', provider: 'google', account_ref: ref('acct', email), mfa_state: 'none', sso_required: false } });
      res.redirect('/?auth=success');
    } catch {
      await event(req, 'auth.google_failed', 'failure', { reason: 'provider_verification' });
      emit('auth.login.failure', req, { attributes: { auth_method: 'oauth', provider: 'google', reason: 'provider_verification' } });
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
    // F2: let analysts filter by event type so a flood of one type cannot hide another.
    const type = typeof req.query.type === 'string' && /^[a-z0-9._-]{1,64}$/.test(req.query.type) ? req.query.type : null;
    const [events, sessions] = await Promise.all([
      pool.query(
        `SELECT id,type,outcome,actor_id,request_id,metadata,created_at FROM security_events${type ? ' WHERE type=$1' : ''} ORDER BY created_at DESC,id DESC LIMIT 100`,
        type ? [type] : [],
      ),
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
    // F5: require a password re-check in the last 5 minutes before changing a role.
    if (!(req.session.reauthAt && Date.now() - req.session.reauthAt < 5 * 60_000)) {
      // AZ-1: export the step-up denial so a session-only (no password) admin probing is detectable.
      emit('authz.denied', req, { userId: req.user.id, attributes: {
        decision: 'deny', reason: 'step_up_required', route: '/api/admin/users/:id/role', method: 'PATCH',
        have_role: req.user.role, need_role: 'admin+recent_reauth', target_ref: req.params.id,
      } });
      return fail(res, 403, 'STEP_UP_REQUIRED', 'Re-enter your password, then change the role.');
    }
    // AZ-2: admin-quorum invariant + race safety. Lock the admin set FOR UPDATE inside one transaction so
    // two concurrent role changes serialize — the second blocks until the first commits, then recounts —
    // and refuse any demotion that would leave zero admins. (A single-statement subquery would NOT close the
    // race under READ COMMITTED: its count takes no lock on the admin rows.)
    let before;
    let rows;
    let targetExists = false;
    const tx = await pool.connect();
    try {
      await tx.query('BEGIN');
      await tx.query("SELECT 1 FROM users WHERE role='admin' FOR UPDATE");
      const cur = (await tx.query('SELECT role FROM users WHERE id=$1 FOR UPDATE', [req.params.id])).rows[0];
      targetExists = Boolean(cur);
      before = cur?.role;
      const wouldRemoveLastAdmin = targetExists && before === 'admin' && req.body.role !== 'admin'
        && (await tx.query("SELECT count(*)::int AS n FROM users WHERE role='admin' AND id<>$1", [req.params.id])).rows[0].n === 0;
      if (targetExists && !wouldRemoveLastAdmin) {
        rows = (await tx.query(
          `UPDATE users SET role=$1,
             session_version=session_version+CASE WHEN role<>$1 THEN 1 ELSE 0 END,
             updated_at=CASE WHEN role<>$1 THEN now() ELSE updated_at END
           WHERE id=$2 RETURNING *`,
          [req.body.role, req.params.id],
        )).rows;
      }
      await tx.query('COMMIT');
    } catch (err) {
      await tx.query('ROLLBACK').catch(() => {});
      throw err;
    } finally {
      tx.release();
    }
    if (!rows?.[0]) {
      if (targetExists) {
        emit('authz.denied', req, { userId: req.user.id, attributes: {
          decision: 'deny', reason: 'last_admin', route: '/api/admin/users/:id/role', method: 'PATCH',
          have_role: req.user.role, need_role: 'admin', target_ref: req.params.id,
        } });
        return fail(res, 409, 'LAST_ADMIN', 'At least one administrator must remain. Promote another admin first.');
      }
      return fail(res, 404, 'NOT_FOUND', 'User not found.');
    }
    // A changed role invalidates existing sessions; the next request must authenticate again.
    await event(req, 'admin.role_changed', 'success', { targetUserId: rows[0].id, role: rows[0].role });
    const rank = { member: 1, analyst: 2, admin: 3 };
    const direction = rank[rows[0].role] > rank[before] ? 'elevate' : rank[rows[0].role] < rank[before] ? 'reduce' : 'same';
    emit('auth.security.change', req, { userId: req.user.id, attributes: { action: 'role_changed', outcome: 'completed', step_up: true, target_ref: rows[0].id, direction } });
    res.json({ user: publicUser(rows[0]) });
  });

  // ─── Notes: a per-user object with a predictable integer key ──────────────────────────────────
  // Create a note owned by the signed-in user.
  app.post('/api/notes', requireUser, limit('notes-write-ip', 60), async (req, res) => {
    const title = typeof req.body?.title === 'string' ? req.body.title.trim() : '';
    const body = typeof req.body?.body === 'string' ? req.body.body : '';
    if (!title || title.length > 120 || body.length > 4000) return fail(res, 400, 'INVALID_INPUT', 'A note needs a title (1–120 chars).');
    const { rows } = await pool.query('INSERT INTO notes(owner_id,title,body) VALUES($1,$2,$3) RETURNING id,title,created_at', [req.user.id, title, body]);
    res.status(201).json({ note: rows[0] });
  });
  // List the caller's OWN notes — correctly scoped (the legitimate baseline).
  app.get('/api/notes', requireUser, async (req, res) => {
    const { rows } = await pool.query('SELECT id,title,created_at FROM notes WHERE owner_id=$1 ORDER BY id DESC LIMIT 100', [req.user.id]);
    res.json({ notes: rows });
  });
  // Export the caller's notes as CSV (id, title, word count, created). Registered before /api/notes/:id.
  app.get('/api/notes/export', requireUser, async (req, res) => {
    try {
      const { rows } = await pool.query('SELECT id,title,body,created_at FROM notes WHERE owner_id=$1 ORDER BY id', [req.user.id]);
      const lines = rows.map((note) => {
        // match() returns null when the body has no words (empty or whitespace-only).
        const words = note.body.match(/\S+/g)?.length ?? 0;
        return [note.id, JSON.stringify(note.title), words, note.created_at.toISOString()].join(',');
      });
      // One line per export: who exported how many notes. No titles or bodies in logs.
      console.info(JSON.stringify({ level: 'info', event: 'notes.export', userId: req.user.id, notes: rows.length, requestId: req.requestId }));
      res.type('text/csv').attachment('notes.csv').send(['id,title,words,created_at', ...lines].join('\n'));
    } catch (error) {
      console.error('[notes.export] export failed', error);
      fail(res, 500, 'EXPORT_FAILED', 'Could not export your notes.');
    }
  });
  // Read one note by id.
  // AZ-IDOR fix: the row is scoped to the caller (`AND owner_id=$2`), so a note that exists but isn't yours
  // is indistinguishable from one that doesn't exist (404) — no ownership leak. Before this fix any signed-in
  // user could read any note by id; SecureNow caught the hunting behaviour from traffic (scan / walk / dump)
  // and the actual breach from the cross-owner authz.granted event.
  app.get('/api/notes/:id', requireUser, async (req, res) => {
    const id = Number(req.params.id);
    if (!Number.isInteger(id) || id < 1 || id > 2_000_000_000) return fail(res, 400, 'INVALID_INPUT', 'Invalid note id.');
    const { rows } = await pool.query('SELECT id,owner_id,title,body,created_at FROM notes WHERE id=$1 AND owner_id=$2', [id, req.user.id]);
    const note = rows[0];
    if (!note) {
      emit('authz.denied', req, { userId: req.user.id, attributes: {
        decision: 'deny', reason: 'not_found', route: '/api/notes/:id', method: 'GET', object_type: 'note', target_ref: String(id),
      } });
      return fail(res, 404, 'NOT_FOUND', 'Note not found.');
    }
    // Export the GRANT with the object's real owner, so cross-owner reads (the definitive IDOR breach) are detectable.
    emit('authz.granted', req, { userId: req.user.id, attributes: {
      decision: 'allow', route: '/api/notes/:id', method: 'GET', object_type: 'note',
      object_id: String(id), owner_id: note.owner_id,
    } });
    res.json({ note });
  });

  // ─── Teams / orgs: the collaboration surface (threat model 02-authorization, Category O) ──────────
  // The membership lifecycle done RIGHT, with every attempt exported so SecureNow can catch the modern-
  // SaaS authorization attacks no single request reveals: invite privilege-escalation, invite-identity
  // rebinding, member self-escalation, and active-org context tampering.
  const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  const orgRank = { member: 1, admin: 2, owner: 3 };
  const orgRoleOf = async (orgId, userId) =>
    (await pool.query('SELECT role FROM org_members WHERE org_id=$1 AND user_id=$2', [orgId, userId])).rows[0]?.role || null;

  // Create an org — the creator becomes its owner.
  app.post('/api/orgs', requireUser, limit('orgs-write-ip', 30), async (req, res) => {
    const name = typeof req.body?.name === 'string' ? req.body.name.trim() : '';
    if (!name || name.length > 80) return fail(res, 400, 'INVALID_INPUT', 'An org needs a name (1–80 chars).');
    const id = randomUUID();
    await pool.query('INSERT INTO orgs(id,name,created_by) VALUES($1,$2,$3)', [id, name, req.user.id]);
    await pool.query('INSERT INTO org_members(org_id,user_id,role) VALUES($1,$2,$3)', [id, req.user.id, 'owner']);
    res.status(201).json({ org: { id, name, role: 'owner' } });
  });

  // List the orgs the caller belongs to (the legitimate baseline).
  app.get('/api/orgs', requireUser, async (req, res) => {
    const { rows } = await pool.query(
      'SELECT o.id,o.name,m.role FROM org_members m JOIN orgs o ON o.id=m.org_id WHERE m.user_id=$1 ORDER BY o.created_at DESC LIMIT 100',
      [req.user.id]);
    res.json({ orgs: rows });
  });

  // Invite someone. O-72/O-73: only an admin/owner may invite, and the granted role is CAPPED at the
  // inviter's rank (an admin cannot mint an owner). The role is server-set and bound to the invited
  // email — never read back from the accept request. The attempt is exported BEFORE the decision, so
  // an escalation attempt is visible even when it is denied.
  app.post('/api/orgs/:orgId/invites', requireUser, limit('orgs-write-ip', 30), async (req, res) => {
    const orgId = req.params.orgId;
    const email = normalizeEmail(req.body?.email);
    const invitedRole = req.body?.role === 'admin' ? 'admin' : 'member';
    if (!uuidPattern.test(orgId)) return fail(res, 400, 'INVALID_INPUT', 'Invalid org id.');
    if (!emailPattern.test(email) || email.length > 254) return fail(res, 400, 'INVALID_INPUT', 'Enter a valid email address.');
    const actorRole = await orgRoleOf(orgId, req.user.id);
    const allowed = actorRole && orgRank[actorRole] >= orgRank.admin && orgRank[invitedRole] <= orgRank[actorRole];
    emit('membership.invite.created', req, { userId: req.user.id, attributes: {
      org_ref: ref('org', orgId), inviter_role: actorRole || 'none', invited_role: invitedRole,
      invited_ref: ref('acct', email), decision: allowed ? 'allow' : 'deny',
    } });
    if (!actorRole || orgRank[actorRole] < orgRank.admin) return fail(res, 403, 'FORBIDDEN', 'Only an org admin or owner can invite.');
    if (orgRank[invitedRole] > orgRank[actorRole]) return fail(res, 403, 'FORBIDDEN', 'You cannot grant a role above your own.');
    const token = randomUUID();
    try {
      // The shareable link the inviter copies into an email or chat. INVITE_LINK_BASE is optional.
      const link = new URL(`/invite/${token}`, process.env.INVITE_LINK_BASE || config.appOrigin).toString();
      await pool.query('INSERT INTO org_invites(token,org_id,email,role,invited_by) VALUES($1,$2,$3,$4,$5)',
        [token, orgId, email, invitedRole, req.user.id]);
      res.status(201).json({ invite: { token, email, role: invitedRole, link } });
    } catch (error) {
      console.error('[invites] could not create invite', error);
      fail(res, 500, 'INVITE_FAILED', 'Could not create the invite.');
    }
  });

  // Accept an invite. O-75 (invite-identity rebinding): the invite is bound to the invited email and may
  // be accepted ONLY by the signed-in, verified owner of that address. A different account claiming the
  // link is the classic SaaS account-takeover — rejected here, and exported as identity_match=false either
  // way so the attempt is catchable. Single-use is enforced by the status transition.
  app.post('/api/invites/:token/accept', requireUser, limit('orgs-write-ip', 30), async (req, res) => {
    const token = req.params.token;
    if (!uuidPattern.test(token)) return fail(res, 400, 'INVALID_INPUT', 'Invalid invite token.');
    const invite = (await pool.query(
      "SELECT * FROM org_invites WHERE token=$1 AND status='pending' AND expires_at>now()", [token])).rows[0];
    if (!invite) return fail(res, 404, 'NOT_FOUND', 'This invite is not valid.');
    const identityMatch = req.user.email === invite.email && req.user.email_verified === true;
    emit('membership.invite.accepted', req, { userId: req.user.id, attributes: {
      org_ref: ref('org', invite.org_id), granted_role: invite.role, invited_ref: ref('acct', invite.email),
      identity_match: String(identityMatch), decision: identityMatch ? 'allow' : 'deny',
    } });
    if (!identityMatch) {
      await event(req, 'membership.invite_rebinding_blocked', 'blocked', { org: invite.org_id });
      return fail(res, 403, 'FORBIDDEN', 'This invite was issued to a different address.');
    }
    const tx = await pool.connect();
    try {
      await tx.query('BEGIN');
      const claimed = (await tx.query(
        "UPDATE org_invites SET status='accepted',accepted_by=$2 WHERE token=$1 AND status='pending' RETURNING org_id,role",
        [token, req.user.id])).rows[0];
      if (!claimed) { await tx.query('ROLLBACK'); return fail(res, 409, 'ALREADY_USED', 'This invite was already used.'); }
      await tx.query('INSERT INTO org_members(org_id,user_id,role) VALUES($1,$2,$3) ON CONFLICT(org_id,user_id) DO UPDATE SET role=EXCLUDED.role',
        [claimed.org_id, req.user.id, claimed.role]);
      await tx.query('COMMIT');
      res.json({ org: { id: claimed.org_id, role: claimed.role } });
    } catch (error) { await tx.query('ROLLBACK').catch(() => {}); throw error; } finally { tx.release(); }
  });

  // List members — O-85/O-86: the active org is the one in the path, and membership is RE-VERIFIED here.
  // A caller poking at an org they don't belong to is rejected and exported as member=false.
  app.get('/api/orgs/:orgId/members', requireUser, async (req, res) => {
    const orgId = req.params.orgId;
    if (!uuidPattern.test(orgId)) return fail(res, 400, 'INVALID_INPUT', 'Invalid org id.');
    const actorRole = await orgRoleOf(orgId, req.user.id);
    if (!actorRole) {
      emit('org.context.switched', req, { userId: req.user.id, attributes: { org_ref: ref('org', orgId), member: 'false', source: 'path' } });
      return fail(res, 403, 'FORBIDDEN', 'You are not a member of this org.');
    }
    const { rows } = await pool.query('SELECT user_id,role,created_at FROM org_members WHERE org_id=$1 ORDER BY created_at LIMIT 200', [orgId]);
    res.json({ members: rows });
  });

  // Change a member's role. O-79 (self-escalation) + O-80 (horizontal tampering): the actor must be an
  // admin/owner OF THIS ORG, cannot change their OWN role, and cannot move anyone above the actor's own
  // rank. Every attempt is exported with self + actor_role, so self-escalation is catchable even though
  // it is rejected.
  app.patch('/api/orgs/:orgId/members/:userId/role', requireUser, async (req, res) => {
    const { orgId, userId } = req.params;
    const toRole = req.body?.role;
    if (!uuidPattern.test(orgId) || !uuidPattern.test(userId)) return fail(res, 400, 'INVALID_INPUT', 'Invalid id.');
    if (!['owner', 'admin', 'member'].includes(toRole)) return fail(res, 400, 'INVALID_INPUT', 'Invalid role.');
    const actorRole = await orgRoleOf(orgId, req.user.id);
    const self = req.user.id === userId;
    const fromRole = (await pool.query('SELECT role FROM org_members WHERE org_id=$1 AND user_id=$2', [orgId, userId])).rows[0]?.role || null;
    const allowed = !!actorRole && orgRank[actorRole] >= orgRank.admin && !self && !!fromRole
      && orgRank[toRole] <= orgRank[actorRole] && orgRank[fromRole] <= orgRank[actorRole];
    emit('membership.role.changed', req, { userId: req.user.id, attributes: {
      org_ref: ref('org', orgId), target_ref: ref('acct', userId), from_role: fromRole || 'none', to_role: toRole,
      self: String(self), actor_role: actorRole || 'none', decision: allowed ? 'allow' : 'deny',
    } });
    if (!allowed) return fail(res, 403, 'FORBIDDEN', self ? 'You cannot change your own role.' : 'Your role does not allow this change.');
    await pool.query('UPDATE org_members SET role=$3 WHERE org_id=$1 AND user_id=$2', [orgId, userId, toRole]);
    res.json({ member: { user_id: userId, role: toRole } });
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
