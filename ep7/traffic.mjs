// Ordinary product usage against the two local environments, so the ep7 bugs show up the way they would in
// real life: people browse, write notes (some leave the body empty), export their notes, and invite teammates.
// Users are fictional (@northstar.test); each one comes from its own TEST-NET address via X-Forwarded-For
// (the local app trusts only the loopback proxy). Stop: create ep7/run/STOP.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const RUN = path.join(path.dirname(fileURLToPath(import.meta.url)), 'run');
const ENVS = { staging: 'http://localhost:3101', production: 'http://localhost:3102' };
const PASSWORD = 'Northstar-ep7-Lab-2026!';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const jitter = (a, b) => a + Math.random() * (b - a);

class Client {
  constructor(base, ip) { this.base = base; this.ip = ip; this.jar = new Map(); this.csrf = null; }
  absorb(res) {
    for (const c of res.headers.getSetCookie?.() || []) {
      const [pair] = c.split(';');
      const i = pair.indexOf('=');
      this.jar.set(pair.slice(0, i), pair.slice(i + 1));
    }
  }
  headers(extra = {}) {
    const cookie = [...this.jar].map(([k, v]) => `${k}=${v}`).join('; ');
    return { 'x-forwarded-for': this.ip, origin: this.base, ...(cookie && { cookie }), ...extra };
  }
  async req(method, route, body) {
    const headers = this.headers(body !== undefined ? { 'content-type': 'application/json' } : {});
    if (method !== 'GET' && this.csrf) headers['x-csrf-token'] = this.csrf;
    const res = await fetch(this.base + route, { method, headers, body: body !== undefined ? JSON.stringify(body) : undefined });
    this.absorb(res);
    const text = await res.text();
    let json = null;
    try { json = JSON.parse(text); } catch {}
    if (json?.csrfToken) this.csrf = json.csrfToken;
    return { status: res.status, json, text };
  }
  async refreshCsrf() { await this.req('GET', '/api/auth/csrf'); }
}

async function signIn(c, email, name) {
  await c.refreshCsrf();
  let r = await c.req('POST', '/api/auth/login', { email, password: PASSWORD });
  if (r.status === 401) {
    await c.req('POST', '/api/auth/register', { email, name, password: PASSWORD });
    await c.refreshCsrf();
    r = await c.req('POST', '/api/auth/login', { email, password: PASSWORD });
  }
  return r.status === 200;
}

async function persona(envName, base, n) {
  const email = `ep7-${envName}-${n}@northstar.test`;
  const c = new Client(base, `198.51.100.${(envName === 'staging' ? 20 : 60) + n}`);
  let orgId = null;
  let inviteSeq = 0;
  let wroteEmptyNote = false;
  while (!fs.existsSync(path.join(RUN, 'STOP'))) {
    try {
      const me = await c.req('GET', '/api/me');
      if (!me.json?.user) {
        if (!(await signIn(c, email, `Northstar ${envName} ${n}`))) { await sleep(20_000); continue; }
      }
      const roll = Math.random();
      if (roll < 0.25) await c.req('GET', '/api/dashboard');
      else if (roll < 0.45) await c.req('GET', '/api/notes');
      else if (roll < 0.6) {
        // Personas 2 and 4 jot down a title-only note once (empty body), like real people do.
        const empty = (n === 2 || n === 4) && !wroteEmptyNote;
        const r = await c.req('POST', '/api/notes', { title: empty ? 'Ideas for Q4' : `Standup ${new Date().toISOString().slice(11, 16)}`, body: empty ? '' : 'Shipped the export. Next: invites.' });
        if (empty && r.status === 201) wroteEmptyNote = true;
      } else if (roll < 0.78) await c.req('GET', '/api/notes/export');
      else if (n === 1) {
        if (!orgId) {
          const orgs = await c.req('GET', '/api/orgs');
          orgId = orgs.json?.orgs?.[0]?.id || (await c.req('POST', '/api/orgs', { name: `Northstar ${envName}` })).json?.org?.id || null;
        }
        if (orgId) await c.req('POST', `/api/orgs/${orgId}/invites`, { email: `teammate${++inviteSeq}-${Date.now() % 100000}@northstar.test`, role: 'member' });
      } else await c.req('GET', '/api/orgs');
    } catch {
      // The server is restarting (crash loop): wait and carry on.
      await sleep(3000);
    }
    await sleep(jitter(4000, 9000));
  }
}

for (const [envName, base] of Object.entries(ENVS)) for (const n of [1, 2, 3, 4]) persona(envName, base, n);
