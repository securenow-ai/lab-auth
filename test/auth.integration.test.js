import { test, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { randomUUID } from 'node:crypto';
import { createApp } from '../src/app.js';
import { createPool, migrate, revokeExpiredInvites } from '../src/db.js';
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
  if (enabled) await pool.query('TRUNCATE orgs,security_events,rate_buckets,sessions,users RESTART IDENTITY CASCADE');
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

test('real PostgreSQL: the account limit cannot lock out an owner with a device cookie (F3)', { skip: !enabled }, async () => {
  const cfg = { authRateLimit: 5 }; // login-ip limit 5, per-account failure limit 10
  const xff = (ip) => ({ 'x-forwarded-for': ip });
  // Owner registers and signs in once from their browser -> receives a device-trust cookie.
  const owner = await client({ config: cfg });
  await owner.request('/api/me', { headers: xff('198.51.100.1') });
  await owner.request('/api/auth/register', { method: 'POST', body: { name: 'Owner', email: 'owner@example.com', password }, headers: xff('198.51.100.1') });
  assert.equal((await owner.request('/api/auth/login', { method: 'POST', body: { email: 'owner@example.com', password }, headers: xff('198.51.100.1') })).status, 200);
  // Attacker spreads 12 failed attempts over 3 IPs (4 each, under the per-IP limit) to fill the account bucket.
  const atk = await client({ config: cfg });
  await atk.request('/api/me', { headers: xff('203.0.113.1') });
  for (const ip of ['203.0.113.1', '203.0.113.2', '203.0.113.3']) {
    for (let i = 0; i < 4; i += 1) await atk.request('/api/auth/login', { method: 'POST', body: { email: 'owner@example.com', password: 'wrong' }, headers: xff(ip) });
  }
  // A brand-new browser (no device cookie) is locked out, even with the right password.
  const fresh = await client({ config: cfg });
  await fresh.request('/api/me', { headers: xff('203.0.113.9') });
  assert.equal((await fresh.request('/api/auth/login', { method: 'POST', body: { email: 'owner@example.com', password }, headers: xff('203.0.113.9') })).status, 429);
  // The owner's own browser still signs in, because the device cookie bypasses the account bucket.
  assert.equal((await owner.request('/api/auth/login', { method: 'POST', body: { email: 'owner@example.com', password }, headers: xff('198.51.100.1') })).status, 200);
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

test('real PostgreSQL: admin role changes require recent re-authentication (F5)', { skip: !enabled }, async () => {
  const c = await client({ config: { authRateLimit: 20 } });
  await c.init();
  await c.register('admin@example.com');
  await pool.query("UPDATE users SET role='admin' WHERE email='admin@example.com'");
  await c.login('admin@example.com');
  await c.register('target@example.com');
  const target = (await pool.query("SELECT id FROM users WHERE email='target@example.com'")).rows[0];
  // Without step-up, a role change is refused.
  assert.equal((await c.request(`/api/admin/users/${target.id}`, { method: 'PATCH', body: { role: 'analyst' } })).status, 403);
  // A wrong password does not grant step-up.
  assert.equal((await c.request('/api/auth/reauth', { method: 'POST', body: { password: 'wrong' } })).status, 401);
  assert.equal((await c.request(`/api/admin/users/${target.id}`, { method: 'PATCH', body: { role: 'analyst' } })).status, 403);
  // Re-authenticate, then the role change succeeds.
  assert.equal((await c.request('/api/auth/reauth', { method: 'POST', body: { password } })).status, 200);
  assert.equal((await c.request(`/api/admin/users/${target.id}`, { method: 'PATCH', body: { role: 'analyst' } })).status, 200);
  assert.equal((await pool.query("SELECT role FROM users WHERE email='target@example.com'")).rows[0].role, 'analyst');
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
  // F5: role changes now require a recent re-authentication (step-up).
  assert.equal((await admin.request('/api/auth/reauth', { method: 'POST', body: { password } })).status, 200);
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

test('real PostgreSQL: concurrent admin demotions cannot leave zero admins (AZ-2)', { skip: !enabled }, async () => {
  // Two admins, each trying to demote the OTHER at the same instant. Without the FOR UPDATE lock both
  // would read "another admin still exists" and both would commit, racing the system down to zero admins.
  const aId = randomUUID();
  const bId = randomUUID();
  await pool.query("INSERT INTO users(id,email,name,password_hash,role) VALUES($1,'adm-a@example.com','A',$2,'admin'),($3,'adm-b@example.com','B',$2,'admin')", [aId, await hashPassword(password), bId]);
  const a = await client({ config: { authRateLimit: 50 } });
  const b = await client({ config: { authRateLimit: 50 } });
  await a.init(); await a.login('adm-a@example.com'); await a.request('/api/auth/reauth', { method: 'POST', body: { password } });
  await b.init(); await b.login('adm-b@example.com'); await b.request('/api/auth/reauth', { method: 'POST', body: { password } });
  const [ra, rb] = await Promise.all([
    a.request(`/api/admin/users/${bId}`, { method: 'PATCH', body: { role: 'member' } }),
    b.request(`/api/admin/users/${aId}`, { method: 'PATCH', body: { role: 'member' } }),
  ]);
  const statuses = [ra.status, rb.status].sort();
  // Exactly one demotion succeeds (200); the other is refused as the last admin (409).
  assert.deepEqual(statuses, [200, 409]);
  // The invariant held: at least one admin remains.
  const admins = (await pool.query("SELECT count(*)::int AS n FROM users WHERE role='admin' AND id IN ($1,$2)", [aId, bId])).rows[0].n;
  assert.equal(admins, 1);
});

test('real PostgreSQL: a note is readable only by its owner (IDOR fix)', { skip: !enabled }, async () => {
  const owner = await client({ config: { authRateLimit: 20 } });
  await owner.init(); await owner.register('noteowner@example.com'); await owner.login('noteowner@example.com');
  const created = await owner.request('/api/notes', { method: 'POST', body: { title: 'secret', body: 'mine' } });
  assert.equal(created.status, 201);
  const noteId = created.data.note.id;
  // the owner reads their own note
  assert.equal((await owner.request(`/api/notes/${noteId}`)).status, 200);
  // a different signed-in user gets 404 (not 200) — no IDOR, and no existence leak
  const other = await client({ config: { authRateLimit: 20 } });
  await other.init(); await other.register('nosey@example.com'); await other.login('nosey@example.com');
  assert.equal((await other.request(`/api/notes/${noteId}`)).status, 404);
});

test('real PostgreSQL: notes export counts zero words for an empty or whitespace-only body', { skip: !enabled }, async () => {
  const c = await client({ config: { authRateLimit: 20 } });
  await c.init(); await c.register(); await c.login();
  for (const body of ['two words', '', '  \n\t ']) {
    assert.equal((await c.request('/api/notes', { method: 'POST', body: { title: 'note', body } })).status, 201);
  }
  const exported = await c.request('/api/notes/export');
  assert.equal(exported.status, 200);
  const words = exported.text.split('\n').slice(1).map((line) => line.split(',')[2]);
  assert.deepEqual(words, ['2', '0', '0']);
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

// ─── Teams / orgs: Category O (collaboration, invites, membership) ────────────────────────────────
async function verifiedUser(email) {
  const c = await client();
  await c.init();
  await c.register(email);
  await pool.query('UPDATE users SET email_verified=true WHERE email=$1', [email]);
  await c.login(email);
  return c;
}
const userId = async (email) => (await pool.query('SELECT id FROM users WHERE email=$1', [email])).rows[0].id;

test('real PostgreSQL: an invite is bound to the invited identity (O-75 invite rebinding)', { skip: !enabled }, async () => {
  const owner = await verifiedUser('owner@example.com');
  const org = (await owner.request('/api/orgs', { method: 'POST', body: { name: 'Acme' } })).data.org;
  assert.equal(org.role, 'owner');
  const invite = (await owner.request(`/api/orgs/${org.id}/invites`, { method: 'POST', body: { email: 'alice@example.com', role: 'admin' } })).data.invite;
  assert.equal(invite.role, 'admin');
  // A DIFFERENT verified account cannot claim Alice's invite — the identity doesn't match.
  const mallory = await verifiedUser('mallory@example.com');
  assert.equal((await mallory.request(`/api/invites/${invite.token}/accept`, { method: 'POST', body: {} })).status, 403);
  assert.equal((await pool.query('SELECT count(*) FROM org_members WHERE org_id=$1', [org.id])).rows[0].count, '1');
  // The invited identity accepts and becomes an admin.
  const alice = await verifiedUser('alice@example.com');
  assert.equal((await alice.request(`/api/invites/${invite.token}/accept`, { method: 'POST', body: {} })).status, 200);
  assert.equal((await pool.query('SELECT role FROM org_members WHERE org_id=$1 AND user_id=$2', [org.id, await userId('alice@example.com')])).rows[0].role, 'admin');
  // Single-use: the same token can't be replayed.
  assert.equal((await alice.request(`/api/invites/${invite.token}/accept`, { method: 'POST', body: {} })).status, 404);
});

test('real PostgreSQL: invite links fall back to APP_ORIGIN when INVITE_LINK_BASE is unset', { skip: !enabled }, async () => {
  const saved = process.env.INVITE_LINK_BASE;
  try {
    const owner = await verifiedUser('linkowner@example.com');
    const org = (await owner.request('/api/orgs', { method: 'POST', body: { name: 'Links' } })).data.org;
    delete process.env.INVITE_LINK_BASE;
    const fallback = await owner.request(`/api/orgs/${org.id}/invites`, { method: 'POST', body: { email: 'a@example.com' } });
    assert.equal(fallback.status, 201);
    assert.equal(fallback.data.invite.link, `${config.appOrigin}/invite/${fallback.data.invite.token}`);
    process.env.INVITE_LINK_BASE = 'https://invites.example.com';
    const configured = await owner.request(`/api/orgs/${org.id}/invites`, { method: 'POST', body: { email: 'b@example.com' } });
    assert.equal(configured.data.invite.link, `https://invites.example.com/invite/${configured.data.invite.token}`);
  } finally {
    if (saved === undefined) delete process.env.INVITE_LINK_BASE; else process.env.INVITE_LINK_BASE = saved;
  }
});

test('real PostgreSQL: the invite expiry job revokes only pending invites past expires_at', { skip: !enabled }, async () => {
  const owner = await verifiedUser('expiry@example.com');
  const org = (await owner.request('/api/orgs', { method: 'POST', body: { name: 'Expiry' } })).data.org;
  const invite = async (email) => (await owner.request(`/api/orgs/${org.id}/invites`, { method: 'POST', body: { email } })).data.invite.token;
  const stale = await invite('stale@example.com');
  const fresh = await invite('fresh@example.com');
  await pool.query("UPDATE org_invites SET expires_at=now() - interval '1 minute' WHERE token=$1", [stale]);
  assert.equal(await revokeExpiredInvites(pool), 1);
  const status = async (token) => (await pool.query('SELECT status FROM org_invites WHERE token=$1', [token])).rows[0].status;
  assert.equal(await status(stale), 'revoked');
  assert.equal(await status(fresh), 'pending');
});

test('real PostgreSQL: only an admin may invite, capped at their rank (O-72/O-73)', { skip: !enabled }, async () => {
  const owner = await verifiedUser('owner2@example.com');
  const org = (await owner.request('/api/orgs', { method: 'POST', body: { name: 'Beta' } })).data.org;
  // Add a plain member via an invite they accept.
  const inv = (await owner.request(`/api/orgs/${org.id}/invites`, { method: 'POST', body: { email: 'mem@example.com', role: 'member' } })).data.invite;
  const member = await verifiedUser('mem@example.com');
  await member.request(`/api/invites/${inv.token}/accept`, { method: 'POST', body: {} });
  // A member cannot invite anyone.
  assert.equal((await member.request(`/api/orgs/${org.id}/invites`, { method: 'POST', body: { email: 'x@example.com', role: 'member' } })).status, 403);
  // A non-member cannot invite (and cannot list members — active-org re-verified).
  const outsider = await verifiedUser('out@example.com');
  assert.equal((await outsider.request(`/api/orgs/${org.id}/invites`, { method: 'POST', body: { email: 'y@example.com', role: 'member' } })).status, 403);
  assert.equal((await outsider.request(`/api/orgs/${org.id}/members`)).status, 403);
});

test('real PostgreSQL: a member cannot escalate their own role (O-79 self-escalation)', { skip: !enabled }, async () => {
  const owner = await verifiedUser('owner3@example.com');
  const org = (await owner.request('/api/orgs', { method: 'POST', body: { name: 'Gamma' } })).data.org;
  const inv = (await owner.request(`/api/orgs/${org.id}/invites`, { method: 'POST', body: { email: 'adm@example.com', role: 'admin' } })).data.invite;
  const admin = await verifiedUser('adm@example.com');
  await admin.request(`/api/invites/${inv.token}/accept`, { method: 'POST', body: {} });
  const admId = await userId('adm@example.com');
  // An admin cannot change their OWN role (to owner, or anything).
  assert.equal((await admin.request(`/api/orgs/${org.id}/members/${admId}/role`, { method: 'PATCH', body: { role: 'owner' } })).status, 403);
  assert.equal((await pool.query('SELECT role FROM org_members WHERE org_id=$1 AND user_id=$2', [org.id, admId])).rows[0].role, 'admin');
  // The admin also cannot promote another member ABOVE the admin's own rank (to owner).
  const inv2 = (await owner.request(`/api/orgs/${org.id}/invites`, { method: 'POST', body: { email: 'mem3@example.com', role: 'member' } })).data.invite;
  const member = await verifiedUser('mem3@example.com');
  await member.request(`/api/invites/${inv2.token}/accept`, { method: 'POST', body: {} });
  const memId = await userId('mem3@example.com');
  assert.equal((await admin.request(`/api/orgs/${org.id}/members/${memId}/role`, { method: 'PATCH', body: { role: 'owner' } })).status, 403);
  // But a legitimate admin CAN promote a member to admin (same rank).
  assert.equal((await admin.request(`/api/orgs/${org.id}/members/${memId}/role`, { method: 'PATCH', body: { role: 'admin' } })).status, 200);
});

test('integration test setup', { skip: enabled }, () => {
  console.log('Set TEST_DATABASE_URL to an isolated PostgreSQL database to run the integration suite.');
});
