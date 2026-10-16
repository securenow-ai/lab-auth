// Bounded auth-abuse simulations for the tutorial. Each scenario reproduces one threat from the
// authentication threat model against YOUR LOCAL copy of the lab (http://localhost:3000), so you can watch
// SecureNow detect it and, where a response is armed, answer it automatically. Counts are small and capped;
// this is a teaching demo, not a load test. Never point it at a deployment (see assertLocal in lib.mjs).
//
// Usage: node attack.mjs <scenario> ; scenarios listed at the bottom (node attack.mjs list).
import { assertLocal, BASE, browserSession, postJson, get, tally, testAccount, sleep } from './lib.mjs';

assertLocal();
const wrong = () => 'not-the-password-' + Math.random().toString(36).slice(2, 8);

// Attacker addresses live in one TEST-NET /24 (RFC 5737). SecureNow groups an alert by rule + IP, so to see
// a fresh detect→respond loop on an IP you have attacked before, pick an unused block with SIM_NET.
// Valid TEST-NET blocks: 203.0.113, 198.51.100, 192.0.2.
const NET = (process.env.SIM_NET || '203.0.113').replace(/\.$/, '');
const ip = (host) => `${NET}.${host}`;

const scenarios = {
  // R01 + R10 + R02 → AUTO-A rate limit. One IP guesses passwords across six accounts and keeps going
  // past the app's own 429. Over ~5 clean days SecureNow would also arm AUTO-B (risk>=90 route block).
  async 'password-guessing'() {
    const src = ip('10');
    const s = await browserSession(src);
    const codes = [];
    for (let i = 0; i < 20; i++) codes.push(await postJson(src, s, '/api/auth/login', { email: `member${i % 6}@northstar.example`, password: wrong() }));
    return { ip: src, line: `20 sign-in attempts over 6 accounts from ${src}`, result: tally(codes) };
  },

  // R06 → network rate limit (manual). Five addresses of one /24 share the work, 3 tries each, so no single
  // IP crosses the per-IP limit; only the per-network rule sees it.
  async 'network-spread'() {
    const codes = [];
    for (let n = 21; n <= 25; n++) {
      const src = ip(String(n));
      const s = await browserSession(src);
      for (let i = 0; i < 3; i++) codes.push(await postJson(src, s, '/api/auth/login', { email: 'finance.lead@northstar.example', password: wrong() }));
    }
    return { ip: `${NET}.21-25`, line: '15 sign-in attempts on one account, 3 from each of 5 addresses in one /24', result: tally(codes) };
  },

  // R05 (instant block, armed) → AUTO-E challenge. Forced browsing for credential files and admin panels.
  // The first dotfile request should be blocked outright once R05's instant block has synced.
  async 'surface-probing'() {
    const src = ip('50');
    const rows = [];
    for (const p of ['/.env', '/.git/config', '/wp-login.php', '/phpmyadmin/', '/backup.sql', '/.aws/credentials']) {
      const r = await get(src, p);
      rows.push(`GET ${p.padEnd(18)} → ${r.status}${r.firewall ? ` SecureNow ${r.firewall}` : ''}`);
    }
    return { ip: src, line: `probing for credential files and admin panels from ${src}`, rows };
  },

  // R04 → AUTO-D rate limit. API writes with no CSRF token; each also writes an audit row (finding F2).
  async 'csrf-flood'() {
    const src = ip('60');
    const s = await browserSession(src);
    const codes = [];
    for (let i = 0; i < 22; i++) codes.push(await postJson(src, s, '/api/auth/logout', {}, { csrf: false }));
    return { ip: src, line: `22 API writes with no CSRF token from ${src}`, result: tally(codes) };
  },

  // R03 → AUTO-C rate limit. Cookieless session checks; each makes the app write a session row (finding F1).
  async 'session-minting'() {
    const src = ip('70');
    const codes = [];
    for (let i = 0; i < 65; i++) codes.push(await get(src, '/api/me'));
    return { ip: src, line: `65 cookieless /api/me requests from ${src}`, result: tally(codes) };
  },

  // R12 → notify + human review (revoke). Five wrong passwords on the fictional test account, then the real
  // one: the shape of a guessed password being used. Uses a local account you registered yourself.
  async 'credential-stuffing-success'() {
    const account = testAccount();
    const src = ip('80');
    const s = await browserSession(src);
    const codes = [];
    for (let i = 0; i < 5; i++) codes.push(await postJson(src, s, '/api/auth/login', { email: account.email, password: wrong() }));
    codes.push(await postJson(src, s, '/api/auth/login', { email: account.email, password: account.password }));
    return { ip: src, line: `5 wrong then 1 correct sign-in on the test account from ${src}`, result: tally(codes) };
  },

  // R23 → AUTO-G rate limit. Registering addresses that already have accounts (enumeration via register).
  async 'registration-probing'() {
    const account = testAccount();
    const src = ip('90');
    const s = await browserSession(src);
    const codes = [];
    for (let i = 0; i < 4; i++) codes.push(await postJson(src, s, '/api/auth/register', { name: 'Probe', email: account.email, password: 'x'.repeat(14) + i }));
    return { ip: src, line: `4 registrations of an already-registered email from ${src}`, result: tally(codes) };
  },
};

const name = process.argv[2];
if (name === 'list' || !scenarios[name]) {
  console.log('Scenarios (run: node attack.mjs <name>):\n  ' + Object.keys(scenarios).join('\n  '));
  process.exit(name === 'list' ? 0 : 1);
}
const out = await scenarios[name]();
console.log(`\n${out.line}  (lab: ${BASE})`);
if (out.rows) for (const r of out.rows) console.log(`  ${r}`);
if (out.result) console.log(`  → ${out.result}`);
