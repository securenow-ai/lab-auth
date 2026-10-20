// Teams / Category-O attack harness — drives the live lab over HTTP so real membership.* telemetry
// flows to SecureNow. A clean baseline plus two attack shapes (invite abuse, membership abuse). The
// two Category-O rules then catch each shape and stay quiet on the baseline.
//   Run:  node -r securenow/register src/server.js            # lab under SecureNow (emits to your app)
//         APP_ORIGIN=http://localhost:3000 node attack-simulation/teams-attack.mjs
// DATABASE_URL + APP_ORIGIN come from the environment / .env (never hard-code a credential).
import 'dotenv/config';
import pg from 'pg';

const ORIGIN = process.env.LAB_ORIGIN || 'http://localhost:3000';
const APP_ORIGIN = process.env.APP_ORIGIN || 'http://localhost:3000';
const PASS = 'a-private-harness-password-914';
if (!process.env.DATABASE_URL) throw new Error('Set DATABASE_URL (the harness verifies test accounts directly).');
const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL });

function session(ip) {
  let cookie = ''; let token;
  return {
    async req(path, { method = 'GET', body } = {}) {
      const mut = !['GET', 'HEAD'].includes(method);
      const res = await fetch(ORIGIN + path, {
        method, redirect: 'manual',
        headers: {
          'x-forwarded-for': ip,
          ...(cookie ? { cookie } : {}),
          ...(mut ? { 'content-type': 'application/json', origin: APP_ORIGIN } : {}),
          ...(mut && token ? { 'x-csrf-token': token } : {}),
        },
        ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
      });
      const sc = res.headers.getSetCookie?.() || [];
      if (sc.length) cookie = sc.map((v) => v.split(';')[0]).join('; ');
      let data = null; try { data = JSON.parse(await res.text()); } catch {}
      if (data?.csrfToken) token = data.csrfToken;
      return { status: res.status, data };
    },
  };
}
async function user(email, ip) {
  const s = session(ip);
  await s.req('/api/me'); // seed csrf cookie
  await s.req('/api/auth/register', { method: 'POST', body: { name: email.split('@')[0], email, password: PASS } });
  await pool.query('UPDATE users SET email_verified=true WHERE email=$1', [email]);
  await s.req('/api/auth/login', { method: 'POST', body: { email, password: PASS } });
  return s;
}
const rndUuid = () => crypto.randomUUID();
const log = (t, r) => console.log(`  ${t.padEnd(34)} → ${r.status}${r.data?.error ? ' ' + r.data.error.code : ''}`);

const owner = await user('owner@harness.test', '198.51.100.10');
console.log('\n== BASELINE (legit, ip .10) ==');
const org = (await owner.req('/api/orgs', { method: 'POST', body: { name: 'Acme HQ' } })).data.org;
console.log(`  created org ${org.id.slice(0, 8)} as ${org.role}`);
const legitInv = (await owner.req(`/api/orgs/${org.id}/invites`, { method: 'POST', body: { email: 'mem@harness.test', role: 'member' } })).data.invite;
const mem = await user('mem@harness.test', '198.51.100.10');
log('member accepts own invite', await mem.req(`/api/invites/${legitInv.token}/accept`, { method: 'POST', body: {} }));
log('owner lists members (allowed)', await owner.req(`/api/orgs/${org.id}/members`));

console.log('\n== ATTACK A — invite abuse (ip .50) ==');
const victimInv = (await owner.req(`/api/orgs/${org.id}/invites`, { method: 'POST', body: { email: 'victim@harness.test', role: 'admin' } })).data.invite;
const attacker = await user('attacker@harness.test', '203.0.113.50');
log('attacker claims victim invite', await attacker.req(`/api/invites/${victimInv.token}/accept`, { method: 'POST', body: {} })); // deny: identity_match=false
const memAtk = session('203.0.113.50'); await memAtk.req('/api/me');
await memAtk.req('/api/auth/login', { method: 'POST', body: { email: 'mem@harness.test', password: PASS } });
log('member invites as admin', await memAtk.req(`/api/orgs/${org.id}/invites`, { method: 'POST', body: { email: 'x@harness.test', role: 'admin' } })); // deny: escalation

console.log('\n== ATTACK B — membership abuse (ip .60) ==');
const memEsc = session('203.0.113.60'); await memEsc.req('/api/me');
await memEsc.req('/api/auth/login', { method: 'POST', body: { email: 'mem@harness.test', password: PASS } });
const memId = (await pool.query("SELECT id FROM users WHERE email='mem@harness.test'")).rows[0].id;
log('member self-escalates to admin', await memEsc.req(`/api/orgs/${org.id}/members/${memId}/role`, { method: 'PATCH', body: { role: 'admin' } })); // deny: self
const prober = await user('prober@harness.test', '203.0.113.60');
for (let i = 0; i < 4; i += 1) log(`probe non-member org #${i + 1}`, await prober.req(`/api/orgs/${rndUuid()}/members`)); // 4× member=false

await pool.end();
console.log('\nDone. Telemetry emitted to df7ab010 (membership.invite.*, membership.role.changed, org.context.switched).');
