// Episode 8 — two attacks on production at once, plus ordinary users:
//   scraper      198.51.100.77         signs in once, pulls GET /api/notes/export 4×/second
//   signup spam  203.0.113.10–.250     a /24 creating fake accounts on POST /api/auth/register
//   users        198.51.100.21–.24     normal browsing
// Every response is logged to ep8/run/attack-log.jsonl ({t, group, ip, status}) and a summary
// prints every 10 s, so you can see the exact second the 403s start.
// Usage: node ep8/attack.mjs [--base http://localhost:3102] [--minutes 8]
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Client, assertLocal, sleep } from './client.mjs';

const args = process.argv.slice(2);
const opt = (name, def) => { const i = args.indexOf(`--${name}`); return i >= 0 ? args[i + 1] : def; };
const BASE = opt('base', 'http://localhost:3102');
const MINUTES = Number(opt('minutes', 8));
assertLocal(BASE);
const DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), 'run');
fs.mkdirSync(DIR, { recursive: true });
const log = fs.createWriteStream(path.join(DIR, 'attack-log.jsonl'), { flags: 'a' });
const until = Date.now() + MINUTES * 60_000;
const counts = new Map();
const record = (group, ip, status) => {
  log.write(`${JSON.stringify({ t: new Date().toISOString(), group, ip, status })}\n`);
  const k = `${group} ${status}`;
  counts.set(k, (counts.get(k) || 0) + 1);
};

async function scraper() {
  const c = new Client(BASE, '198.51.100.77');
  await c.signIn('ep8-scraper@northstar.test', 'Scraper');
  while (Date.now() < until) {
    try { record('scraper', c.ip, (await c.req('GET', '/api/notes/export')).status); } catch { record('scraper', c.ip, 0); }
    await sleep(250);
  }
}

async function signupSpam() {
  let n = 10;
  while (Date.now() < until) {
    const ip = `203.0.113.${n}`;
    n = n >= 250 ? 10 : n + 1;
    const c = new Client(BASE, ip);
    try {
      await c.req('GET', '/api/auth/csrf');
      const r = await c.req('POST', '/api/auth/register', {
        email: `promo${Date.now() % 1e7}${n}@spam.test`, name: 'Free Crypto Bonus', password: 'Spam-account-2026-x',
      });
      record('signup-spam', ip, r.status);
    } catch { record('signup-spam', ip, 0); }
    await sleep(300);
  }
}

async function user(n) {
  const c = new Client(BASE, `198.51.100.${20 + n}`);
  await c.signIn(`ep8-user-${n}@northstar.test`, `Northstar user ${n}`);
  while (Date.now() < until) {
    const route = Math.random() < 0.5 ? '/api/me' : '/api/notes';
    try { record('users', c.ip, (await c.req('GET', route)).status); } catch { record('users', c.ip, 0); }
    await sleep(2000 + Math.random() * 2000);
  }
}

const timer = setInterval(() => {
  const line = [...counts].sort().map(([k, v]) => `${k}:${v}`).join('  ');
  console.log(`${new Date().toISOString().slice(11, 19)}  ${line}`);
  counts.clear();
}, 10_000);

await Promise.all([scraper(), signupSpam(), ...[1, 2, 3, 4].map(user)]);
clearInterval(timer);
log.end();
