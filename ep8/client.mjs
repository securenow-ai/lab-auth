// A tiny HTTP client for the local lab: cookie jar, CSRF token, and a client IP sent as
// X-Forwarded-For (the local app trusts only the loopback proxy, so the app, its limits and
// SecureNow all see that address). LOCAL ONLY — never aim it at a deployment.
export const PASSWORD = 'Northstar-ep8-Lab-2026!';

export function assertLocal(base) {
  if (!/^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(base)) throw new Error(`local lab only (got ${base})`);
}

export class Client {
  constructor(base, ip) { this.base = base; this.ip = ip; this.jar = new Map(); this.csrf = null; }
  absorb(res) {
    for (const c of res.headers.getSetCookie?.() || []) {
      const [pair] = c.split(';');
      const i = pair.indexOf('=');
      this.jar.set(pair.slice(0, i), pair.slice(i + 1));
    }
  }
  cookieHeader() { return [...this.jar].map(([k, v]) => `${k}=${v}`).join('; '); }
  async req(method, route, body, extraHeaders = {}) {
    const headers = { 'x-forwarded-for': this.ip, origin: this.base, ...extraHeaders };
    const cookie = this.cookieHeader();
    if (cookie) headers.cookie = cookie;
    if (body !== undefined) headers['content-type'] = 'application/json';
    if (method !== 'GET' && this.csrf) headers['x-csrf-token'] = this.csrf;
    const res = await fetch(this.base + route, { method, headers, body: body !== undefined ? JSON.stringify(body) : undefined });
    this.absorb(res);
    const text = await res.text();
    let json = null;
    try { json = JSON.parse(text); } catch {}
    if (json?.csrfToken) this.csrf = json.csrfToken;
    return { status: res.status, json, headers: res.headers };
  }
  async signIn(email, name) {
    await this.req('GET', '/api/auth/csrf');
    let r = await this.req('POST', '/api/auth/login', { email, password: PASSWORD });
    if (r.status === 401) {
      await this.req('POST', '/api/auth/register', { email, name, password: PASSWORD });
      await this.req('GET', '/api/auth/csrf');
      r = await this.req('POST', '/api/auth/login', { email, password: PASSWORD });
    }
    return r.status === 200;
  }
}

export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
