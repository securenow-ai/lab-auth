import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';

const base = new URL(process.argv[2] || 'http://localhost:3000').origin;
const local = ['localhost', '127.0.0.1', '[::1]'].includes(new URL(base).hostname);
if (!local && !process.argv.includes('--allow-remote')) throw new Error('Pass --allow-remote only for a deployment you own.');
const password = randomBytes(24).toString('base64url');
const email = `smoke-${Date.now()}-${randomBytes(4).toString('hex')}@example.invalid`;
const checks = [];
function client() {
  let cookie = '', csrfToken = '';
  return {
    get cookie() { return cookie; },
    async request(path, method = 'GET', body, useCsrf = true) {
      const response = await fetch(base + path, {
        method, redirect: 'manual',
        headers: { ...(cookie ? { cookie } : {}), ...(method !== 'GET' ? { origin: base, 'content-type': 'application/json', ...(useCsrf ? { 'x-csrf-token': csrfToken } : {}) } : {}) },
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      });
      const cookies = response.headers.getSetCookie();
      if (cookies.length) cookie = cookies.map(value => value.split(';')[0]).join('; ');
      const data = await response.json();
      if (data.csrfToken) csrfToken = data.csrfToken;
      return { status: response.status, data, headers: response.headers };
    },
  };
}
const member = client();
assert.equal((await member.request('/readyz')).status, 200);
const anonymous = await member.request('/api/me');
assert.equal(anonymous.data.user, null);
assert.equal(anonymous.headers.get('cache-control'), 'no-store');
const cookie = anonymous.headers.get('set-cookie');
assert.match(cookie, /HttpOnly/i);
assert.match(cookie, /SameSite=Lax/i);
if (base.startsWith('https:')) { assert.match(cookie, /Secure/i); assert.match(cookie, /^__Host-lab_auth=/); }
assert.equal((await member.request('/API/ME')).headers.get('cache-control'), 'no-store');
checks.push('HTTPS/readiness, session cookie, and private-response cache headers');
assert.equal((await member.request('/api/auth/register', 'POST', { name: 'Fictional smoke-test member', email, password, role: 'admin' })).status, 201);
assert.equal((await member.request('/api/dashboard')).status, 401);
assert.equal((await member.request('/api/auth/login', 'POST', { email, password: 'wrong-test-password' })).status, 401);
const beforeLogin = member.cookie;
const login = await member.request('/api/auth/login', 'POST', { email, password });
assert.equal(login.status, 200);
assert.equal(login.data.user.role, 'member');
assert.notEqual(member.cookie, beforeLogin);
assert.equal((await member.request('/api/dashboard')).status, 200);
assert.equal((await member.request('/api/security')).status, 403);
assert.equal((await member.request('/api/admin/users')).status, 403);
assert.equal((await member.request('/api/auth/logout', 'POST', {}, false)).status, 403);
checks.push('Registration, password login, session rotation, role-injection rejection, RBAC, and CSRF');
if (process.env.SMOKE_ADMIN_EMAIL && process.env.SMOKE_ADMIN_PASSWORD) {
  const admin = client();
  await admin.request('/api/me');
  assert.equal((await admin.request('/api/auth/login', 'POST', { email: process.env.SMOKE_ADMIN_EMAIL, password: process.env.SMOKE_ADMIN_PASSWORD })).status, 200);
  assert.equal((await admin.request('/api/admin/users')).status, 200);
  const path = `/api/admin/users/${login.data.user.id}/role`;
  assert.equal((await admin.request(path, 'PATCH', { role: 'analyst' })).status, 200);
  assert.equal((await member.request('/api/dashboard')).status, 401);
  await member.request('/api/me');
  assert.equal((await member.request('/api/auth/login', 'POST', { email, password })).status, 200);
  assert.equal((await member.request('/api/security')).status, 200);
  assert.equal((await member.request('/api/admin/users')).status, 403);
  assert.equal((await admin.request(path, 'PATCH', { role: 'member' })).status, 200);
  await member.request('/api/me');
  assert.equal((await member.request('/api/auth/login', 'POST', { email, password })).status, 200);
  assert.equal((await admin.request('/api/auth/logout', 'POST', {})).status, 200);
  checks.push('Administrator and analyst roles, role updates, and immediate session revocation');
}
const second = client();
await second.request('/api/me');
assert.equal((await second.request('/api/auth/login', 'POST', { email, password })).status, 200);
const changedPassword = randomBytes(24).toString('base64url');
assert.equal((await member.request('/api/auth/password', 'POST', { currentPassword: password, newPassword: changedPassword })).status, 200);
assert.equal((await second.request('/api/dashboard')).status, 401);
await second.request('/api/me');
assert.equal((await second.request('/api/auth/login', 'POST', { email, password })).status, 401);
assert.equal((await second.request('/api/auth/login', 'POST', { email, password: changedPassword })).status, 200);
assert.equal((await second.request('/api/auth/logout', 'POST', {})).status, 200);
checks.push('Password change rejects the old password and invalidates other sessions');
assert.equal((await member.request('/api/auth/logout', 'POST', {})).status, 200);
assert.equal((await member.request('/api/dashboard')).status, 401);
checks.push('Logout invalidates dashboard access');
console.log(JSON.stringify({ base, result: 'passed', checks, note: 'A fictional member account remains in this deployment; its random password was not printed or saved.' }, null, 2));
