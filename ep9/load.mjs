// Episode 9 — rate-limit scenarios against the LOCAL lab. Every response is logged to
// ep9/run/<scenario>.jsonl ({t, ip, port, status, rule, retryAfter}) and summarised every 10 s.
//
//   node ep9/load.mjs rotating-scraper [--seconds 180]   one signed-in session, a new IP every request
//   node ep9/load.mjs login-spray      [--seconds 60]    one IP guessing passwords on POST /api/auth/login
//   node ep9/load.mjs burst            [--seconds 30]    one session, 10 exports as fast as possible, then 1/s
//   node ep9/load.mjs two-processes    [--seconds 60] [--ports 3102,3103]   the same export spread over two
//                                                         server processes (like two workers or two servers)
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Client, assertLocal, sleep } from '../ep8/client.mjs';

const [scenario, ...rest] = process.argv.slice(2);
const opt = (name, def) => { const i = rest.indexOf(`--${name}`); return i >= 0 ? rest[i + 1] : def; };
const SECONDS = Number(opt('seconds', 60));
const PORTS = String(opt('ports', '3102')).split(',').map(Number);
const bases = PORTS.map((p) => `http://localhost:${p}`);
bases.forEach(assertLocal);
const DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), 'run');
fs.mkdirSync(DIR, { recursive: true });
const log = fs.createWriteStream(path.join(DIR, `${scenario}.jsonl`), { flags: 'a' });
const until = Date.now() + SECONDS * 1000;
const counts = new Map();
function record(ip, port, r) {
  const status = r ? r.status : 0;
  const rule = r?.headers?.get('x-securenow-rate-limit-rule') || '';
  const retryAfter = r?.headers?.get('retry-after') || '';
  log.write(`${JSON.stringify({ t: new Date().toISOString(), ip, port, status, rule, retryAfter })}\n`);
  const k = `${port} ${status}${rule ? '(securenow)' : ''}`;
  counts.set(k, (counts.get(k) || 0) + 1);
}
const timer = setInterval(() => {
  console.log(`${new Date().toISOString().slice(11, 19)}  ${[...counts].sort().map(([k, v]) => `${k}:${v}`).join('  ')}`);
  counts.clear();
}, 10_000);

// One signed-in account whose session cookie is replayed from every client.
async function sharedSession(base, email) {
  const c = new Client(base, '198.51.100.99');
  if (!(await c.signIn(email, 'Scraper account'))) throw new Error('sign-in failed');
  return c;
}

if (scenario === 'rotating-scraper') {
  const owner = await sharedSession(bases[0], 'ep9-scraper@northstar.test');
  let n = 100;
  while (Date.now() < until) {
    const ip = `198.51.100.${n}`;
    n = n >= 199 ? 100 : n + 1;
    const c = new Client(bases[0], ip);
    c.jar = new Map(owner.jar);
    try { record(ip, PORTS[0], await c.req('GET', '/api/notes/export')); } catch { record(ip, PORTS[0], null); }
    await sleep(200);
  }
} else if (scenario === 'login-spray') {
  const c = new Client(bases[0], '192.0.2.50');
  await c.req('GET', '/api/auth/csrf');
  let i = 0;
  while (Date.now() < until) {
    try { record(c.ip, PORTS[0], await c.req('POST', '/api/auth/login', { email: `admin${i++}@northstar.test`, password: 'Winter2026!' })); } catch { record(c.ip, PORTS[0], null); }
    await sleep(1000);
  }
} else if (scenario === 'burst') {
  const c = await sharedSession(bases[0], 'ep9-burst@northstar.test');
  c.ip = '198.51.100.98';
  for (let i = 0; i < 10; i++) {
    try { record(c.ip, PORTS[0], await c.req('GET', '/api/notes/export')); } catch { record(c.ip, PORTS[0], null); }
  }
  while (Date.now() < until) {
    try { record(c.ip, PORTS[0], await c.req('GET', '/api/notes/export')); } catch { record(c.ip, PORTS[0], null); }
    await sleep(1000);
  }
} else if (scenario === 'two-processes') {
  const owner = await sharedSession(bases[0], 'ep9-shared@northstar.test');
  let i = 0;
  while (Date.now() < until) {
    const port = PORTS[i % PORTS.length];
    const c = new Client(`http://localhost:${port}`, `198.51.100.${150 + (i % 40)}`);
    c.jar = new Map(owner.jar);
    i++;
    try { record(c.ip, port, await c.req('GET', '/api/notes/export')); } catch { record(c.ip, port, null); }
    await sleep(250);
  }
} else {
  console.log('scenarios: rotating-scraper | login-spray | burst | two-processes');
}

clearInterval(timer);
log.end();
const rows = fs.readFileSync(path.join(DIR, `${scenario}.jsonl`), 'utf8').trim().split('\n').map(JSON.parse);
const total = rows.reduce((a, r) => (a[r.status] = (a[r.status] || 0) + 1, a), {});
console.log(`TOTAL ${scenario}: ${JSON.stringify(total)}`);
