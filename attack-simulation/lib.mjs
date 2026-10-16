// Shared helpers for the attack simulations. Everything here targets YOUR LOCAL copy of the lab only.
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

export const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const BASE = (process.env.LAB_URL || 'http://localhost:3000').replace(/\/+$/, '');
export const ENV = process.env.SECURENOW_ENV || 'test';

// Attackers are TEST-NET addresses (RFC 5737), sent in X-Forwarded-For exactly like the reverse proxy
// forwards the real client in production. The local app trusts only the loopback proxy, so the app's own
// limits, its auth events and the SecureNow traces all see the simulated address. Never aim this at a
// deployment: the forwarded header would be ignored and every request would come from your own IP.
export function assertLocal() {
  if (!/^http:\/\/(localhost|127\.0\.0\.1|\[::1\])(:\d+)?$/.test(BASE)) {
    throw new Error(`Attack simulations only run against a local copy (LAB_URL=${BASE}). Start the lab locally first.`);
  }
}

export function appKey() {
  if (process.env.SECURENOW_APP_KEY) return process.env.SECURENOW_APP_KEY;
  try {
    return JSON.parse(fs.readFileSync(path.join(ROOT, '.securenow', 'runtime.json'), 'utf8')).app.key;
  } catch {
    throw new Error('No SecureNow app key: run `npx securenow app connect` in the lab root or set SECURENOW_APP_KEY.');
  }
}

// Fictional test account for the "takeover" and "register" scenarios. Never use a real password.
export function testAccount() {
  if (process.env.LAB_TEST_EMAIL && process.env.LAB_TEST_PASSWORD) {
    return { email: process.env.LAB_TEST_EMAIL, password: process.env.LAB_TEST_PASSWORD };
  }
  const file = path.join(ROOT, 'attack-simulation', 'test-account.local.json');
  if (fs.existsSync(file)) return JSON.parse(fs.readFileSync(file, 'utf8'));
  throw new Error('Set LAB_TEST_EMAIL / LAB_TEST_PASSWORD, or create attack-simulation/test-account.local.json (gitignored), for a fictional account you registered on your local copy.');
}

// The SecureNow CLI shipped in node_modules, run from the lab root so it uses this project's .securenow.
export function securenowCli(args, { json = false } = {}) {
  const cli = path.join(ROOT, 'node_modules', 'securenow', 'cli.js');
  const p = spawnSync(process.execPath, [cli, ...args, ...(json ? ['--json'] : [])], { cwd: ROOT, encoding: 'utf8' });
  if (!json) return p;
  const out = p.stdout || '';
  const start = out.search(/[[{]/);
  if (start < 0) throw new Error(`securenow ${args.join(' ')} returned no JSON: ${(p.stderr || out).trim().split('\n').pop()}`);
  return JSON.parse(out.slice(start));
}

// The SecureNow API client (admin auth from the lab's .securenow/admin.json, written by `npx securenow login`).
export function securenowApi() {
  process.chdir(ROOT);
  const require = createRequire(path.join(ROOT, 'package.json'));
  return require('securenow/cli/client').api;
}

export async function browserSession(ip) {
  const r = await fetch(`${BASE}/api/auth/csrf`, { headers: { 'x-forwarded-for': ip } });
  const cookie = (r.headers.get('set-cookie') || '').split(';')[0];
  const body = await r.json().catch(() => ({}));
  return { cookie, csrf: body.csrfToken };
}

export async function postJson(ip, session, route, payload, { csrf = true } = {}) {
  const headers = { 'x-forwarded-for': ip, origin: BASE, 'content-type': 'application/json', cookie: session.cookie };
  if (csrf) headers['x-csrf-token'] = session.csrf;
  const r = await fetch(BASE + route, { method: 'POST', headers, body: JSON.stringify(payload) });
  const text = await r.text();
  return { status: r.status, body: text, firewall: securenowAnswer(r, text) };
}

export async function get(ip, route, headers = {}) {
  const r = await fetch(BASE + route, { headers: { 'x-forwarded-for': ip, ...headers }, redirect: 'manual' });
  const text = await r.text();
  return { status: r.status, body: text, firewall: securenowAnswer(r, text) };
}

// Which layer answered? The SDK firewall answers 403 {"error":"Forbidden"} (block), 429 {"error":"Too Many
// Requests"} + X-SecureNow-Rate-Limit-Rule (rate limit) or 403 challenge_required + X-SecureNow-Challenge
// (proof-of-work challenge). The app's own errors look like {"error":{"code":"..."}}.
export function securenowAnswer(response, text = '') {
  if (response.headers.get('x-securenow-challenge')) return 'challenge';
  if (response.headers.get('x-securenow-rate-limit-rule') || /"error":"Too Many Requests"/.test(text)) return 'rate limit';
  if (/"error":"Forbidden"/.test(text) || /<title>[^<]*(Access denied|Blocked)/i.test(text)) return 'block';
  return '';
}
export const isSecureNowAnswer = (response, text) => Boolean(securenowAnswer(response, text));

export function tally(results) {
  const counts = {};
  for (const r of results) {
    const key = `${r.status}${r.firewall ? ` SecureNow ${r.firewall}` : ''}`;
    counts[key] = (counts[key] || 0) + 1;
  }
  return Object.entries(counts).map(([k, n]) => `${n}×${k}`).join('  ');
}

export const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
