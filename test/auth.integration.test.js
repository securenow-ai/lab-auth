import { test, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { randomUUID } from 'node:crypto';
import { createApp } from '../src/app.js';
import { createPool, migrate } from '../src/db.js';
import { hashPassword } from '../src/passwords.js';
import { bootstrapAdmin } from '../src/bootstrap.js';

// Tests must never report to the real SecureNow app through the project's .securenow credentials.
process.env.SECURENOW_DISABLED ??= '1';

const databaseUrl = process.env.TEST_DATABASE_URL;
const enabled = Boolean(databaseUrl);
if (enabled && !/(^|[_-])test($|[_-])/i.test(new URL(databaseUrl).pathname.slice(1))) {
  throw new Error('Integration tests truncate their database. Use a database name containing a separate test segment, such as lab_auth_test.');
}
const config = {
  production: false, appOrigin: 'http://localhost:3000',
  sessionSecret: 'test-session-secret-unique-32-characters-long',
  auditSecret: 'test-audit-secret-different-32-characters-long',
  googleClientId: '', googleClientSecret: '',
  authRateLimit: 3, registrationRateLimit: 10, rateWindowMs: 900_000,
  idleSessionMs: 1_800_000, absoluteSessionMs: 28_800_000,
};
let pool;
let servers = [];
let apps = [];
const password = 'a-private-test-password-712';

before(async () => {
  if (!enabled) return;
  pool = createPool(databaseUrl);
  await migrate(pool);
});
beforeEach(async () => {
  if (enabled) await pool.query('TRUNCATE security_events,rate_buckets,sessions,users RESTART IDENTITY CASCADE');
});
after(async () => {
  for (const app of apps) app.locals.sessionStore.close();
  await Promise.all(servers.map((server) => new Promise((resolve) => server.close(resolve))));
  if (pool) await pool.end();
});

async function client(options = {}) {
  const app = createApp({ pool, config: { ...config, ...options.config }, oauthClient: options.oauthClient });
  const server = app.listen(0, '127.0.0.1');
  await once(server, 'listening');
  servers.push(server);
  apps.push(app);
  const origin = `http://127.0.0.1:${server.address().port}`;
  let cookie = '';
  let token;
  return {
    get cookie() { return cookie; },
    get token() { return token; },
    async request(path, { method = 'GET', body, headers = {}, csrf = true } = {}) {
      const mutation = !['GET', 'HEAD'].includes(method);
      const response = await fetch(origin + path, {
        method, redirect: 'manual',
        headers: {
          ...(cookie ? { cookie } : {}),
          ...(mutation ? { 'content-type': 'application/json', origin: config.appOrigin } : {}),
          ...(mutation && csrf && token ? { 'x-csrf-token': token } : {}), ...headers,
        },
        ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
      });
      const setCookie = response.headers.getSetCookie();
      if (setCookie.length) cookie = setCookie.map((value) => value.split(';')[0]).join('; ');
      const text = await response.text();
      let data;
      try { data = JSON.parse(text); } catch { data = null; }
      if (data?.csrfToken) token = data.csrfToken;
      return { status: response.status, data, headers: response.headers, text };
    },
    async init() { return this.request('/api/me'); },
    async register(email = 'member@example.com', extra = {}) { return this.request('/api/auth/register', { method: 'POST', body: { name: 'Example member', email, password, ...extra } }); },
    async login(email = 'member@example.com', pass = password) { return this.request('/api/auth/login', { method: 'POST', body: { email, password: pass } }); },
  };
}

test('real PostgreSQL: registration is generic, ignores role injection, and stores only a KDF hash', { skip: !enabled }, async () => {
  const c = await client();
  assert.equal((await c.init()).data.user, null);
  const first = await c.register('member@example.com', { role: 'admin', emailVerified: true });
  assert.equal(first.status, 201);
  assert.equal(first.data.user, null);
  const repeated = await c.register();
  assert.deepEqual(repeated.data, first.data);
  const { rows } = await pool.query('SELECT * FROM users');
  assert.equal(rows.length, 1);
  assert.equal(rows[0].role, 'member');
  assert.equal(rows[0].email_verified, false);
  assert.match(rows[0].password_hash, /^scrypt\$32768\$8\$1\$/);
  assert.ok(!rows[0].password_hash.includes(password));
  assert.equal((await c.request('/api/dashboard')).status, 401);
});

test('real PostgreSQL: anonymous requests never create a session row (F1)', { skip: !enabled }, async () => {
  const c = await client();
  for (let i = 0; i < 65; i += 1) assert.equal((await c.request('/api/me')).status, 200);
  assert.equal((await pool.query('SELECT count(*) FROM sessions')).rows[0].count, '0');
  // A signed double-submit CSRF cookie still lets an anonymous visitor register and sign in.
  assert.equal((await c.register()).status, 201);
  assert.equal((await c.login()).status, 200);
  assert.equal((await pool.query('SELECT count(*) FROM sessions')).rows[0].count, '1');
});

test('real PostgreSQL: routing is strict and case-sensitive so aliases return 404 (F6)', { skip: !enabled }, async () => {
  const c = await client();
  await c.init();
  // Canonical routes still work.
  assert.equal((await c.request('/api/me')).status, 200);
  assert.equal((await c.login('nobody@example.com', 'wrong')).status, 401);
  // Case and trailing-slash aliases no longer match any route.
  assert.equal((await c.request('/API/ME')).status, 404);
  assert.equal((await c.request('/api/me/')).status, 404);
  assert.equal((await c.request('/API/AUTH/LOGIN', { method: 'POST', body: { email: 'a@b.co', password: 'x' } })).status, 404);
  assert.equal((await c.request('/api/auth/login/', { method: 'POST', body: { email: 'a@b.co', password: 'x' } })).status, 404);
});

test('real PostgreSQL: rejected requests are audit-capped per window and filterable by type (F2)', { skip: !enabled }, async () => {
  const c = await client();
  await c.init();
  // 100 CSRF-rejected mutations from one client -> at most one csrf.rejected row this window.
  for (let i = 0; i < 100; i += 1) assert.equal((await c.request('/api/auth/logout', { method: 'POST', body: {}, csrf: false })).status, 403);
  assert.equal((await pool.query("SELECT count(*) FROM security_events WHERE type='csrf.rejected'")).rows[0].count, '1');
  // An analyst/admin can filter the security page by event type (done before the shared per-IP
  // login limit is exhausted below).
  const a = await client();
  await a.init();
  await a.register('admin@example.com');
  await pool.query("UPDATE users SET role='admin' WHERE email='admin@example.com'");
  assert.equal((await a.login('admin@example.com')).status, 200);
  const sec = await a.request('/api/security?type=csrf.rejected');
  assert.equal(sec.status, 200);
  assert.ok(sec.data.events.length >= 1 && sec.data.events.every((e) => e.type === 'csrf.rejected'));
  // Over-limit login attempts log auth.rate_limited at most once per category per window.
  await c.register('victim@example.com');
  for (let i = 0; i < 10; i += 1) await c.login('victim@example.com', 'wrong');
  for (const row of (await pool.query("SELECT metadata->>'category' c, count(*) n FROM security_events WHERE type='auth.rate_limited' GROUP BY 1")).rows) {
    assert.equal(row.n, '1', `category ${row.c} logged ${row.n} times`);
  }
});

test('real PostgreSQL: login rotates sessions, CSRF rejects cross-origin mutations, logout revokes access', { skip: !enabled }, async () => {
  const c = await client();
  await c.init();
  await c.register();
  const beforeCookie = c.cookie;
  const beforeToken = c.token;
  const signedIn = await c.login();
  assert.equal(signedIn.status, 200);
  assert.equal(signedIn.data.user.role, 'member');
  assert.notEqual(c.cookie, beforeCookie);
  assert.notEqual(c.token, beforeToken);
  assert.equal((await c.request('/api/dashboard')).status, 200);
  assert.equal((await c.request('/api/auth/logout', { method: 'POST', body: {}, csrf: false })).status, 403);
  assert.equal((await c.request('/api/auth/logout', { method: 'POST', body: {}, headers: { origin: 'https://attacker.example' } })).status, 403);
  assert.equal((await c.request('/api/auth/logout', { method: 'POST', body: {}, headers: { 'x-csrf-token': 'é'.repeat(c.token.length) } })).status, 403);
  assert.equal((await c.request('/api/auth/logout', { method: 'POST', body: {} })).status, 200);
  assert.equal((await c.request('/api/dashboard')).status, 401);
  const { rows } = await pool.query('SELECT type,metadata FROM security_events');
  assert.ok(rows.some((event) => event.type === 'csrf.rejected'));
  assert.ok(rows.some((event) => event.type === 'auth.logout'));
  assert.ok(!JSON.stringify(rows).includes(password));
  assert.ok(!JSON.stringify(rows).includes('member@example.com'));
});

test('real PostgreSQL: failed login is generic and durable rate limiting blocks repeated attempts', { skip: !enabled }, async () => {
  const c = await client();
  await c.init();
  await c.register();
  const wrong = await c.login('member@example.com', 'incorrect-password');
  const unknown = await c.login('unknown@example.com', 'incorrect-password');
  assert.equal(wrong.status, 401);
  assert.deepEqual(unknown.data, wrong.data);
  assert.equal((await c.login('unknown@example.com', 'incorrect-password')).status, 401);
  const blocked = await c.login();
  assert.equal(blocked.status, 429);
  assert.ok(blocked.headers.get('retry-after'));
  // A second app instance shares the database-backed counter.
  const second = await client();
  await second.init();
  assert.equal((await second.login()).status, 429);
  // F2: auth.rate_limited is capped to one row per (category, window), not one per blocked request.
  assert.equal((await pool.query("SELECT count(*) FROM security_events WHERE type='auth.rate_limited'")).rows[0].count, '1');
});

test('real PostgreSQL: role gates hold server-side and role changes revoke sessions', { skip: !enabled }, async () => {
  const c = await client({ config: { authRateLimit: 20 } });
  await c.init(); await c.register(); await c.login();
  assert.equal((await c.request('/api/security')).status, 403);
  assert.equal((await c.request('/api/admin/users')).status, 403);
  const member = (await pool.query("SELECT * FROM users WHERE email='member@example.com'")).rows[0];
  assert.equal((await c.request(`/api/admin/users/${member.id}`, { method: 'PATCH', body: { role: 'admin' } })).status, 403);
  const adminId = randomUUID();
  await pool.query("INSERT INTO users(id,email,name,password_hash,role) VALUES($1,'admin@example.com','Administrator',$2,'admin')", [adminId, await hashPassword(password)]);
  const admin = await client({ config: { authRateLimit: 20 } });
  await admin.init(); await admin.login('admin@example.com');
  assert.equal((await admin.request(`/api/admin/users/${adminId}`, { method: 'PATCH', body: { role: 'admin' } })).status, 200);
  assert.equal((await admin.request('/api/admin/users')).status, 200);
  assert.equal((await admin.request(`/api/admin/users/${adminId}`, { method: 'PATCH', body: { role: 'member' } })).status, 409);
  assert.equal((await admin.request(`/api/admin/users/${member.id}`, { method: 'PATCH', body: { role: 'analyst' } })).status, 200);
  assert.equal((await c.request('/api/dashboard')).status, 401);
  await c.init(); await c.login();
  const security = await c.request('/api/security');
  assert.equal(security.status, 200);
  assert.ok(security.data.events.some((event) => event.type === 'admin.role_changed'));
  assert.ok(security.data.sessions.every((item) => item.id.length === 16));
  assert.ok(security.data.sessions.every((item) => new Date(item.expiresAt) > new Date(item.createdAt)));
  assert.equal((await c.request('/api/admin/users')).status, 403);
});

test('real PostgreSQL: password changes reject wrong proof and revoke other active sessions', { skip: !enabled }, async () => {
  const c = await client({ config: { authRateLimit: 20 } });
  await c.init(); await c.register(); await c.login();
  const other = await client({ config: { authRateLimit: 20 } });
  await other.init(); await other.login();
  assert.equal((await c.request('/api/auth/password', { method: 'POST', body: { currentPassword: 'wrong', newPassword: 'a-new-private-test-password' } })).status, 401);
  assert.equal((await c.request('/api/auth/password', { method: 'POST', body: { currentPassword: password, newPassword: 'a-new-private-test-password' } })).status, 200);
  assert.equal((await c.request('/api/dashboard')).status, 200);
  assert.equal((await other.request('/api/dashboard')).status, 401);
  await other.init();
  assert.equal((await other.login('member@example.com', password)).status, 401);
});

test('real PostgreSQL: Google disabled reports configuration and invalid callback state is rejected', { skip: !enabled }, async () => {
  const c = await client();
  assert.equal((await c.request('/api/auth/google')).status, 503);
  assert.equal((await c.request('/api/auth/google/callback?state=x&code=x')).status, 503);
  let authParams;
  const oauthClient = {
    async generateCodeVerifierAsync() { return { codeVerifier: 'verifier', codeChallenge: 'challenge' }; },
    generateAuthUrl(params) { authParams = params; return 'https://accounts.google.com/o/oauth2/v2/auth'; },
  };
  const google = await client({ config: { googleClientId: 'test-id', googleClientSecret: 'test-provider-secret' }, oauthClient });
  assert.equal((await google.request('/api/auth/google')).status, 302);
  assert.equal(authParams.code_challenge_method, 'S256');
  assert.ok(authParams.nonce);
  const rejected = await google.request('/api/auth/google/callback?state=invalid&code=test');
  assert.equal(rejected.headers.get('location'), '/?auth_error=google_failed');
});

test('real PostgreSQL: Google verifies nonce and never links a password account by email', { skip: !enabled }, async () => {
  let authParams;
  let nonceValid = true;
  let email = 'google-member@example.com';
  const oauthClient = {
    async generateCodeVerifierAsync() { return { codeVerifier: 'verifier', codeChallenge: 'challenge' }; },
    generateAuthUrl(params) { authParams = params; return 'https://accounts.google.com/o/oauth2/v2/auth'; },
    async getToken(options) { assert.equal(options.codeVerifier, 'verifier'); return { tokens: { id_token: 'opaque-id-token' } }; },
    async verifyIdToken(options) {
      assert.equal(options.audience, 'test-id');
      return { getPayload() { return { sub: 'verified-google-subject', iss: 'https://accounts.google.com', email, email_verified: true, name: 'Google member', nonce: nonceValid ? authParams.nonce : 'incorrect' }; } };
    },
  };
  const google = await client({ config: { googleClientId: 'test-id', googleClientSecret: 'test-provider-secret' }, oauthClient });
  await google.request('/api/auth/google');
  nonceValid = false;
  assert.equal((await google.request(`/api/auth/google/callback?state=${authParams.state}&code=test`)).headers.get('location'), '/?auth_error=google_failed');
  nonceValid = true;
  const local = await client(); await local.init(); await local.register('google-member@example.com');
  await google.request('/api/auth/google');
  assert.equal((await google.request(`/api/auth/google/callback?state=${authParams.state}&code=test`)).headers.get('location'), '/?auth_error=account_exists');
  assert.equal((await pool.query("SELECT google_subject FROM users WHERE email='google-member@example.com'")).rows[0].google_subject, null);
  email = 'new-google@example.com';
  await google.request('/api/auth/google');
  assert.equal((await google.request(`/api/auth/google/callback?state=${authParams.state}&code=test`)).headers.get('location'), '/?auth=success');
  const me = (await google.init()).data.user;
  assert.equal(me.role, 'member');
  assert.deepEqual(me.authMethods, ['google']);
});

test('real PostgreSQL: administrator bootstrap is idempotent and never elevates an existing member', { skip: !enabled }, async () => {
  const env = { ADMIN_EMAIL: 'bootstrap@example.com', ADMIN_PASSWORD: password };
  assert.deepEqual(await bootstrapAdmin(pool, env), { created: true });
  const original = (await pool.query("SELECT password_hash FROM users WHERE email='bootstrap@example.com'")).rows[0].password_hash;
  assert.deepEqual(await bootstrapAdmin(pool, { ADMIN_EMAIL: 'bootstrap@example.com' }), { created: false });
  assert.deepEqual(await bootstrapAdmin(pool, { ...env, ADMIN_PASSWORD: 'a-different-private-password' }), { created: false });
  assert.equal((await pool.query("SELECT password_hash FROM users WHERE email='bootstrap@example.com'")).rows[0].password_hash, original);
  const c = await client(); await c.init(); await c.register('member@example.com');
  await assert.rejects(bootstrapAdmin(pool, { ...env, ADMIN_EMAIL: 'member@example.com' }), /will not elevate/);
  assert.equal((await pool.query("SELECT role FROM users WHERE email='member@example.com'")).rows[0].role, 'member');
});

test('integration test setup', { skip: enabled }, () => {
  console.log('Set TEST_DATABASE_URL to an isolated PostgreSQL database to run the integration suite.');
});
