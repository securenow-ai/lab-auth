// Episode 10, "Who leaked Dana's notes?": one account-takeover against the local lab, with ordinary
// traffic around it, recorded so every forensics answer can be checked against what really happened.
//
//   users     198.51.100.231-.235  five ordinary users browsing the whole time; one mistypes a password once
//   dana      198.51.100.230       signs in, writes notes, later finds she can no longer sign in
//   stuffing  192.0.2.100-.139     40 addresses, one shared browser string, many failed logins against a
//                                  list of accounts — the shape of a credential-stuffing run
//   takeover  203.0.113.252        a second network signs in AS Dana (her password was reused and leaked),
//                                  then: recon, admin probes, a walk over note ids, exports, a password
//                                  change that locks Dana out, and a planted org invite
//
// The point of the episode is that no single request looks like a breach; the story only appears when you
// follow it across failed logins, a success from a new network, note reads, an export and a password change.
//
// Every request goes to ep10/run/incident-log.jsonl and the ground-truth facts to incident-summary.json.
// Usage: node ep10/incident.mjs            (about 12 minutes, against http://localhost:3102)
// LOCAL ONLY: client addresses are sent as X-Forwarded-For, which only the local lab trusts. Never aim at a deployment.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Client, PASSWORD, assertLocal, sleep } from '../ep8/client.mjs';

const BASE = process.env.LAB_BASE || 'http://localhost:3102';
assertLocal(BASE);
const RUN = path.join(path.dirname(fileURLToPath(import.meta.url)), 'run');
fs.mkdirSync(RUN, { recursive: true });
const log = fs.createWriteStream(path.join(RUN, 'incident-log.jsonl'), { flags: 'a' });

const DANA_EMAIL = process.env.DANA_EMAIL || 'dana@northstar.test';
// Dana reused this on a hobby site that was later breached; it is the whole reason the takeover works.
const DANA_PASSWORD = 'Sunflower-Northstar-2019';
const TAKEOVER_PASSWORD = 'Kite-Archive-77-Lockout';
const ARCHIVE_EMAIL = 'd.archive@proton.test';
// A single obviously-fake password the stuffing run throws at every account. None of these succeed; the run
// is here only so the forensics chat has a wave of failed logins with one shared browser string to find.
const DUMP_PASSWORD = 'from-a-dump-not-real';

const UA = {
  stuffing: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36',
  takeover: 'Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0',
  dana: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15',
  users: [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36',
  ],
};

const t0 = Date.now();
const minutes = (m) => t0 + m * 60_000;
const until = async (m) => { const wait = minutes(m) - Date.now(); if (wait > 0) await sleep(wait); };
const jitter = (lo, hi) => sleep(lo + Math.random() * (hi - lo));
const facts = { startedAt: new Date(t0).toISOString(), base: BASE };

async function call(actor, c, method, route, body) {
  const r = await c.req(method, route, body, { 'user-agent': c.ua });
  log.write(`${JSON.stringify({ t: new Date().toISOString(), actor, ip: c.ip, method, route, status: r.status })}\n`);
  return r;
}

function client(ip, ua) {
  const c = new Client(BASE, ip);
  c.ua = ua;
  return c;
}

async function login(actor, c, email, password) {
  await call(actor, c, 'GET', '/api/auth/csrf');
  return call(actor, c, 'POST', '/api/auth/login', { email, password });
}

// Fictional account names the stuffing run and ordinary users sign in as.
const PEOPLE = ['Priya Raman', 'Marcus Bell', 'Lena Vogel', 'Omar Haddad', 'Sam Ortiz'];

// ── Ordinary users: steady, believable traffic for the whole window ────────────────────────────────
async function ordinaryUser(n) {
  const c = client(`198.51.100.${231 + n}`, UA.users[n]);
  const email = `ep10-user-${n + 1}@northstar.test`;
  await jitter(0, 20_000);
  if (n === 3) await login('user', c, email, 'Northstar-ep8-Lab-2025!'); // Omar mistypes the year once
  let r = await login('user', c, email, PASSWORD);
  if (r.status === 401) {
    await call('user', c, 'POST', '/api/auth/register', { email, name: PEOPLE[n], password: PASSWORD });
    r = await login('user', c, email, PASSWORD);
  }
  let exported = false;
  while (Date.now() < minutes(12)) {
    const roll = Math.random();
    if (roll < 0.35) await call('user', c, 'GET', '/api/dashboard');
    else if (roll < 0.7) await call('user', c, 'GET', '/api/notes');
    else if (roll < 0.9) await call('user', c, 'POST', '/api/notes', { title: `Standup ${new Date().toISOString().slice(11, 16)}`, body: 'Shipped the onboarding fix; reviewing Atlas next.' });
    else await call('user', c, 'GET', '/api/me');
    // One ordinary user exports their own notes once — a benign export, so "who exported" is not trivially one row.
    if (n === 1 && !exported && Date.now() > minutes(6)) { await call('user', c, 'GET', '/api/notes/export'); exported = true; }
    await jitter(12_000, 35_000);
  }
}

// ── Dana: the victim. Works normally, then comes back to find she is locked out. ───────────────────
const DANA_NOTES = [
  ['Q4 board prep', 'Revenue bridge, churn by cohort, hiring plan. Draft for Thursday.'],
  ['Project Kite - acquisition notes', 'Target valuation range, diligence list, people to keep in the loop.'],
  ['Salary bands draft', 'Proposed bands for platform and design, effective January.'],
  ['Customer escalations', 'Three enterprise accounts waiting on SSO; owners and dates.'],
  ['1:1 with Lena', 'Promotion case, growth areas, next review in December.'],
  ['Vendor contracts', 'Renewal dates and the two contracts we want to renegotiate.'],
  ['Offsite agenda', 'Day one strategy, day two planning, dinner on the river.'],
];

async function dana() {
  const c = client('198.51.100.230', UA.dana);
  let r = await login('dana', c, DANA_EMAIL, DANA_PASSWORD);
  if (r.status === 401) {
    await call('dana', c, 'POST', '/api/auth/register', { email: DANA_EMAIL, name: 'Dana Whitfield', password: DANA_PASSWORD });
    r = await login('dana', c, DANA_EMAIL, DANA_PASSWORD);
  }
  if (r.status !== 200) throw new Error(`Dana could not sign in (${r.status}); use a fresh DANA_EMAIL`);
  facts.dana = { userId: r.json.user.id, ip: c.ip, userAgent: UA.dana, signedInAt: new Date().toISOString(), noteIds: [] };
  for (const [title, body] of DANA_NOTES) {
    const created = await call('dana', c, 'POST', '/api/notes', { title, body });
    if (created.json?.note?.id) facts.dana.noteIds.push(created.json.note.id);
    await jitter(8_000, 20_000);
  }
  await call('dana', c, 'GET', '/api/notes');
  await call('dana', c, 'GET', '/api/dashboard');
  // She comes back after lunch: her session is gone and her password no longer works.
  await until(9.4);
  const back = await call('dana', c, 'GET', '/api/notes');
  facts.dana.returnStatus = back.status;
  facts.dana.lockedOutAttempts = 0;
  for (let i = 0; i < 3; i++) {
    const again = await login('dana', c, DANA_EMAIL, DANA_PASSWORD);
    if (again.status !== 200) facts.dana.lockedOutAttempts++;
    await jitter(15_000, 25_000);
  }
  facts.dana.lockedOutAt = new Date().toISOString();
}

// ── Credential stuffing: 40 addresses, one shared browser string, many failed logins. ─────────────
// Every attempt here fails (DUMP_PASSWORD is never valid). It exists so the investigation has a wave to
// find and so the real breach (a single success, from a different place, minutes later) stands out against it.
const TARGETS = [DANA_EMAIL, ...Array.from({ length: 24 }, (_, i) => `ep10-user-${(i % 5) + 1}@northstar.test`)];

async function stuffing() {
  await until(2);
  facts.stuffing = { startedAt: new Date().toISOString(), ipBase: '192.0.2.0/25', userAgent: UA.stuffing, attempts: 0, successes: 0 };
  for (let n = 0; n < 40; n++) {
    const c = client(`192.0.2.${100 + n}`, UA.stuffing);
    for (let k = 0; k < 3; k++) {
      const email = TARGETS[(n * 3 + k) % TARGETS.length];
      const r = await login('stuffing', c, email, DUMP_PASSWORD);
      facts.stuffing.attempts++;
      if (r.status === 200) facts.stuffing.successes++;
      await jitter(200, 900);
    }
    await jitter(1_000, 3_000);
  }
  facts.stuffing.endedAt = new Date().toISOString();
}

// ── Takeover: a second network signs in as Dana and ransacks the account. ──────────────────────────
async function takeover() {
  await until(6.5);
  const c = client('203.0.113.252', UA.takeover);
  facts.takeover = { ip: c.ip, userAgent: UA.takeover, startedAt: new Date().toISOString(), steps: [] };
  const step = (name, r) => { facts.takeover.steps.push({ name, status: r.status, at: new Date().toISOString() }); return r; };

  // The breach: Dana's reused password works from an address she has never used.
  const signin = await login('takeover', c, DANA_EMAIL, DANA_PASSWORD);
  facts.takeover.breachStatus = signin.status;
  if (signin.status !== 200) { facts.takeover.failed = true; return; }

  // Recon — where am I, what can I see.
  step('whoami', await call('takeover', c, 'GET', '/api/me'));
  await jitter(1_500, 4_000);
  step('dashboard', await call('takeover', c, 'GET', '/api/dashboard'));
  await jitter(1_500, 4_000);
  step('own-notes', await call('takeover', c, 'GET', '/api/notes'));

  // Admin probes — try to reach data and controls the account should not have (all denied/forbidden).
  await jitter(2_000, 5_000);
  step('probe-admin-users', await call('takeover', c, 'GET', '/api/admin/users'));
  step('probe-security', await call('takeover', c, 'GET', '/api/security'));
  step('probe-role-change', await call('takeover', c, 'PATCH', `/api/admin/users/${facts.dana?.userId || '00000000-0000-4000-8000-000000000000'}/role`, { role: 'admin' }));

  // Walk note ids around Dana's own, looking for other people's notes (the app scopes by owner, so these 404).
  await jitter(2_000, 4_000);
  const base = facts.dana?.noteIds?.[0] || 1;
  facts.takeover.walkFrom = base - 5;
  facts.takeover.walkTo = base + 20;
  for (let id = base - 5; id <= base + 20; id++) {
    step(`note-${id}`, await call('takeover', c, 'GET', `/api/notes/${id}`));
    await jitter(150, 500);
  }

  // Exfiltrate: pull the export a few times.
  await jitter(1_000, 3_000);
  for (let i = 0; i < 3; i++) { step('export', await call('takeover', c, 'GET', '/api/notes/export')); await jitter(800, 2_000); }

  // Persist: change the password (locks Dana out) and plant an invite to an attacker-controlled address.
  await jitter(1_500, 3_000);
  step('password-change', await call('takeover', c, 'POST', '/api/auth/password', { currentPassword: DANA_PASSWORD, newPassword: TAKEOVER_PASSWORD }));
  const orgCreate = await call('takeover', c, 'POST', '/api/orgs', { name: 'Kite Archive' });
  const orgId = orgCreate.json?.org?.id;
  facts.takeover.orgId = orgId || null;
  if (orgId) step('plant-invite', await call('takeover', c, 'POST', `/api/orgs/${orgId}/invites`, { email: ARCHIVE_EMAIL, role: 'admin' }));
  facts.takeover.archiveEmail = ARCHIVE_EMAIL;
  facts.takeover.endedAt = new Date().toISOString();
}

// ── Run everything together ────────────────────────────────────────────────────────────────────────
console.log(`Incident starting against ${BASE} — about 12 minutes. Log: ep10/run/incident-log.jsonl`);
await Promise.all([
  dana(),
  ...Array.from({ length: 5 }, (_, n) => ordinaryUser(n)),
  stuffing(),
  takeover(),
]);
facts.endedAt = new Date().toISOString();
fs.writeFileSync(path.join(RUN, 'incident-summary.json'), JSON.stringify(facts, null, 2));
log.end();
console.log('Incident complete. Ground truth: ep10/run/incident-summary.json');
console.log(`  Dana: ${facts.dana?.userId} from ${facts.dana?.ip}; notes ${facts.dana?.noteIds?.join(', ')}`);
console.log(`  Stuffing: ${facts.stuffing?.attempts} attempts, ${facts.stuffing?.successes} success, from 192.0.2.100-139`);
console.log(`  Takeover: from ${facts.takeover?.ip}, breach ${facts.takeover?.breachStatus}, ${facts.takeover?.steps?.length} actions`);
