// Episode 11, "Turn any attack into an alert": ordinary traffic, plus one attack per rule in the episode's
// ladder, each run on its own so you can watch the matching rule fire.
//
//   normal       five colleagues, Dana, and an "integration" account that exports notes every minute
//                (busy, but normal for it). Start this first and leave it running: the baseline rule
//                compares an account with its own history, and the instant rule's check replays these requests.
//   scan         203.0.113.50   asks for secrets files (/.env, /.git/config, a database dump)    -> instant rule
//   brute        192.0.2.77     12 wrong passwords on one account in about a minute            -> threshold
//   stuffing     192.0.2.100-139 40 addresses, 3 tries each, one browser string, 6 accounts    -> distinct count
//                (the per-address rule stays quiet: no address goes past 3)
//   idor         203.0.113.60   a signed-in account walks 30 note ids, most of them not its own -> ratio
//   exfil        203.0.113.252  signs in as Dana and exports her notes 8 times in two minutes   -> baseline
//   takeover     203.0.113.253  signs in as Dana from an address she never used, then changes
//                               her password a few seconds later                                -> sequence
//   persistence  203.0.113.254  signs in as Dana, changes the password, then creates an org and
//                               invites an outside address as admin                             -> the agent's rule
//
// Every request goes to ep11/run/attacks.jsonl. Dana's current password and ids live in ep11/run/state.json.
// Usage: LAB_BASE=http://localhost:3105 node ep11/attack.mjs <normal|scan|brute|stuffing|idor|exfil|takeover|persistence>
// LOCAL ONLY: client addresses are sent as X-Forwarded-For, which only the local lab trusts. Never aim at a deployment.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Client, PASSWORD, assertLocal, sleep } from '../ep8/client.mjs';

const BASE = process.env.LAB_BASE || 'http://localhost:3105';
assertLocal(BASE);
const RUN = path.join(path.dirname(fileURLToPath(import.meta.url)), 'run');
fs.mkdirSync(RUN, { recursive: true });
const log = fs.createWriteStream(path.join(RUN, 'attacks.jsonl'), { flags: 'a' });
const STATE = path.join(RUN, 'state.json');
const readState = () => (fs.existsSync(STATE) ? JSON.parse(fs.readFileSync(STATE, 'utf8')) : {});
const writeState = (patch) => fs.writeFileSync(STATE, JSON.stringify({ ...readState(), ...patch }, null, 2));

const TAG = process.env.EP11_TAG || 'ep11';
const DANA_EMAIL = `dana.${TAG}@northstar.test`;
const DANA_FIRST_PASSWORD = 'Sunflower-Northstar-2019';
const INTEGRATION_EMAIL = `integration.${TAG}@northstar.test`;
const EVE_EMAIL = `eve.${TAG}@northstar.test`;
const OUTSIDE_EMAIL = 'd.archive@proton.test';
// A single obviously fake password the stuffing run tries everywhere. It never works.
const DUMP_PASSWORD = 'from-a-dump-not-real';
const PEOPLE = ['Priya Raman', 'Marcus Bell', 'Lena Vogel', 'Omar Haddad', 'Sam Ortiz'];
const userEmail = (n) => `${TAG}-user-${n + 1}@northstar.test`;

const UA = {
  dana: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15',
  integration: 'northstar-backup/2.3 (+https://northstar.test/integrations)',
  scanner: 'Mozilla/5.0 zgrab/0.x',
  brute: 'python-requests/2.32.3',
  stuffing: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36',
  attacker: 'Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0',
  users: [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36',
  ],
};

const jitter = (lo, hi) => sleep(lo + Math.random() * (hi - lo));
function client(ip, ua) { const c = new Client(BASE, ip); c.ua = ua; return c; }
async function call(actor, c, method, route, body) {
  const r = await c.req(method, route, body, { 'user-agent': c.ua });
  log.write(`${JSON.stringify({ t: new Date().toISOString(), actor, ip: c.ip, method, route, status: r.status })}\n`);
  return r;
}
async function login(actor, c, email, password) {
  await call(actor, c, 'GET', '/api/auth/csrf');
  return call(actor, c, 'POST', '/api/auth/login', { email, password });
}
async function signInOrRegister(actor, c, email, name, password = PASSWORD) {
  let r = await login(actor, c, email, password);
  if (r.status === 401) {
    await call(actor, c, 'POST', '/api/auth/register', { email, name, password });
    r = await login(actor, c, email, password);
  }
  if (r.status !== 200) throw new Error(`${actor} could not sign in as ${email} (${r.status})`);
  return r;
}
const danaPassword = () => readState().danaPassword || DANA_FIRST_PASSWORD;

// ── normal: steady, believable traffic ───────────────────────────────────────────────────────────────
async function colleague(n, until) {
  const c = client(`198.51.100.${231 + n}`, UA.users[n]);
  await jitter(0, 20_000);
  await signInOrRegister('user', c, userEmail(n), PEOPLE[n]);
  while (Date.now() < until) {
    const roll = Math.random();
    if (roll < 0.35) await call('user', c, 'GET', '/api/dashboard');
    else if (roll < 0.7) await call('user', c, 'GET', '/api/notes');
    else if (roll < 0.9) await call('user', c, 'POST', '/api/notes', { title: `Standup ${new Date().toISOString().slice(11, 16)}`, body: 'Shipped the onboarding fix; reviewing Atlas next.' });
    else await call('user', c, 'GET', '/api/me');
    await jitter(15_000, 45_000);
  }
}

const DANA_NOTES = [
  ['Q4 board prep', 'Revenue bridge, churn by cohort, hiring plan. Draft for Thursday.'],
  ['Project Kite - acquisition notes', 'Target valuation range, diligence list, people to keep in the loop.'],
  ['Salary bands draft', 'Proposed bands for platform and design, effective January.'],
  ['Customer escalations', 'Three enterprise accounts waiting on SSO; owners and dates.'],
  ['Vendor contracts', 'Renewal dates and the two contracts we want to renegotiate.'],
];

async function dana(until) {
  const c = client('198.51.100.230', UA.dana);
  const r = await signInOrRegister('dana', c, DANA_EMAIL, 'Dana Whitfield', danaPassword());
  const ids = [];
  for (const [title, body] of DANA_NOTES) {
    const created = await call('dana', c, 'POST', '/api/notes', { title, body });
    if (created.json?.note?.id) ids.push(created.json.note.id);
    await jitter(5_000, 15_000);
  }
  writeState({ danaId: r.json?.user?.id, danaNoteIds: ids, danaPassword: danaPassword() });
  // Dana exports her notes once, like anyone might.
  await call('dana', c, 'GET', '/api/notes/export');
  while (Date.now() < until) {
    await call('dana', c, 'GET', Math.random() < 0.5 ? '/api/notes' : '/api/dashboard');
    await jitter(60_000, 150_000);
  }
}

// The integration exports every minute, all day. Busy, but normal for this account.
async function integration(until) {
  const c = client('198.51.100.40', UA.integration);
  await signInOrRegister('integration', c, INTEGRATION_EMAIL, 'Nightly backup');
  await call('integration', c, 'POST', '/api/notes', { title: 'Backup manifest', body: 'Rotated keys, retention 30 days.' });
  while (Date.now() < until) {
    const r = await call('integration', c, 'GET', '/api/notes/export');
    if (r.status === 401) await signInOrRegister('integration', c, INTEGRATION_EMAIL, 'Nightly backup');
    await jitter(55_000, 65_000);
  }
}

async function normal() {
  const minutes = Number(process.env.NORMAL_MINUTES || 300);
  const until = Date.now() + minutes * 60_000;
  console.log(`Normal traffic for ${minutes} minutes against ${BASE}. Stop with Ctrl+C.`);
  await Promise.all([dana(until), integration(until), ...PEOPLE.map((_, n) => colleague(n, until))]);
}

// ── the attacks ──────────────────────────────────────────────────────────────────────────────────────
async function scan() {
  const c = client('203.0.113.50', UA.scanner);
  for (const route of ['/', '/robots.txt', '/.env', '/.git/config', '/backup.sql', '/.env.production', '/wp-login.php']) {
    await call('scan', c, 'GET', route);
    await jitter(300, 900);
  }
}

async function brute() {
  const c = client('192.0.2.77', UA.brute);
  const target = userEmail(3);
  for (let i = 0; i < 12; i++) {
    await login('brute', c, target, `Summer${2014 + i}!`);
    await jitter(2_000, 5_000);
  }
}

async function stuffing() {
  const targets = [DANA_EMAIL, userEmail(0), userEmail(1), userEmail(2), userEmail(4), EVE_EMAIL];
  for (let n = 0; n < 40; n++) {
    const c = client(`192.0.2.${100 + n}`, UA.stuffing);
    for (let k = 0; k < 3; k++) {
      await login('stuffing', c, targets[(n * 3 + k) % targets.length], DUMP_PASSWORD);
      await jitter(150, 600);
    }
    await jitter(500, 1_500);
  }
}

async function idor() {
  const c = client('203.0.113.60', UA.attacker);
  await signInOrRegister('idor', c, EVE_EMAIL, 'Eve Marsh');
  const mine = await call('idor', c, 'POST', '/api/notes', { title: 'Grocery list', body: 'Coffee, oats, lemons.' });
  const start = (readState().danaNoteIds?.[0] || mine.json?.note?.id || 100) - 12;
  for (let id = start; id < start + 30; id++) {
    await call('idor', c, 'GET', `/api/notes/${id}`);
    await jitter(250, 800);
  }
}

async function exfil() {
  const c = client('203.0.113.252', UA.attacker);
  const r = await login('exfil', c, DANA_EMAIL, danaPassword());
  if (r.status !== 200) throw new Error(`exfil could not sign in as Dana (${r.status})`);
  await call('exfil', c, 'GET', '/api/notes');
  for (let i = 0; i < 8; i++) {
    await call('exfil', c, 'GET', '/api/notes/export');
    await jitter(8_000, 16_000);
  }
}

async function changePassword(actor, c) {
  const next = `Kite-Archive-${Math.floor(Math.random() * 90 + 10)}-Lockout`;
  const r = await call(actor, c, 'POST', '/api/auth/password', { currentPassword: danaPassword(), newPassword: next });
  if (r.status === 200) writeState({ danaPassword: next });
  return r;
}

async function takeover() {
  const c = client('203.0.113.253', UA.attacker);
  const r = await login('takeover', c, DANA_EMAIL, danaPassword());
  if (r.status !== 200) throw new Error(`takeover could not sign in as Dana (${r.status})`);
  await call('takeover', c, 'GET', '/api/me');
  await jitter(3_000, 6_000);
  await call('takeover', c, 'GET', '/api/notes');
  await jitter(5_000, 10_000);
  await changePassword('takeover', c);
}

async function persistence() {
  const c = client('203.0.113.254', UA.attacker);
  const r = await login('persistence', c, DANA_EMAIL, danaPassword());
  if (r.status !== 200) throw new Error(`persistence could not sign in as Dana (${r.status})`);
  await call('persistence', c, 'GET', '/api/me');
  await jitter(2_000, 4_000);
  await changePassword('persistence', c);
  await jitter(20_000, 40_000);
  const org = await call('persistence', c, 'POST', '/api/orgs', { name: 'Kite Archive' });
  const orgId = org.json?.org?.id;
  if (orgId) await call('persistence', c, 'POST', `/api/orgs/${orgId}/invites`, { email: OUTSIDE_EMAIL, role: 'admin' });
}

const SCENARIOS = { normal, scan, brute, stuffing, idor, exfil, takeover, persistence };
const name = process.argv[2];
if (!SCENARIOS[name]) {
  console.error(`Usage: node ep11/attack.mjs <${Object.keys(SCENARIOS).join('|')}>`);
  process.exit(1);
}
const started = new Date();
console.log(`${name} against ${BASE} at ${started.toISOString()}`);
await SCENARIOS[name]();
log.end();
console.log(`${name} done in ${Math.round((Date.now() - started) / 1000)} s`);
