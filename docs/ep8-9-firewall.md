# Episodes 8 and 9 — IP blocking and rate limiting, outside your code

This branch (`tutorial/ep8-9-firewall`) is the companion to the two "How to Secure Your Apps" episodes on SecureNow's
firewall: blocking IPs and ranges (Episode 8) and rate limiting (Episode 9). Nothing in `src/` changes. Every rule
below was added from the dashboard, the CLI or a coding agent over MCP, and reached the running app on its next
firewall sync.

## What's on this branch

1. `c79f906` moves the lab to `securenow@8.14.0`: rate limits per header or cookie value, optional shared counters in
   Redis, and the firewall hits view (`securenow firewall hits`, MCP `securenow_firewall_hits`).
2. `ep8/client.mjs` is a tiny HTTP client with a cookie jar and the CSRF token. It sends each fictional client's
   address as `X-Forwarded-For`. That only works because the local app trusts a loopback proxy (`TRUST_PROXY` unset),
   which is how one script plays hundreds of clients. Never aim it at a deployment.
3. `ep8/attack.mjs` runs two attacks on production at once, plus four ordinary users:
   a scraper on `198.51.100.77` pulling `GET /api/notes/export` four times a second, and a signup flood from
   `203.0.113.10`–`.250` creating fake accounts on `POST /api/auth/register`.
4. `ep9/load.mjs` has four rate-limit scenarios: `rotating-scraper` (one signed-in session, a new IP on every
   request), `login-spray` (one IP guessing passwords), `burst`, and `two-processes` (one session spread over two
   server processes). Every response is logged with its status, the SecureNow rule ID and `Retry-After`.

All addresses are documentation ranges (RFC 5737). All accounts are fictional and live in the local database.

## Episode 8 run (2026-10-27)

A coding agent (Claude Code, headless, SecureNow MCP server connected, read-only tools) was asked:

> Production for the lab-auth app is getting hammered right now. Using SecureNow, find out what is hitting it in the
> last 10 minutes and who is behind it. Then propose exactly how to stop it without changing any code: which blocks
> to add, scoped as narrowly as possible (IP or range, route, method, environment) and for how long. Don't apply
> anything yet.

It found 466 fake accounts from 241 IPs and one IP exporting about 3.8 times a second. Each signup IP came back only
every ~92 seconds, so the app's own per-IP signup limit never fired. After approval it added two blocks:
`203.0.113.0/24` on `POST /api/auth/register` only, and `198.51.100.77` on `GET /api/notes/export` only, both in
production for 24 hours. The first 403s arrived 8 to 10 seconds after each block was created; the same addresses
could still load `/api/auth/csrf` and everything else. `securenow firewall hits` then counted 618 blocked requests
from 241 IPs.

## Episode 9 run (2026-10-27)

1. **Per IP isn't enough.** `ratelimit add --route /api/notes/export --mode exact --method GET --limit 10 --window 1m`
   (10 a minute per IP). A scraper that changes IP on every request got 275 of 275 exports through in a minute.
2. **Per session.** The agent was asked why the limit wasn't working. It found about 245 exports a minute from 100
   IPs, none over 3 a minute, and proposed counting per session cookie instead. After approval it created
   `keyBy: cookie`, `keyName: lab_auth`, 10 per 60 s (`securenow_rate_limit_create`). The 429s started 6 seconds
   later, and from then on the scraper got 10 exports a minute.
3. **Plain English.** `securenow ratelimit from-text "rate limit POST /api/auth/login to 5 attempts per minute per IP"`
   then a password spray from one IP: 5 tries a minute reached the app, the rest got 429 with `Retry-After`. A second
   rule, `20 login attempts per hour per IP`, stacks on the same route.
4. **Shared counters.** Production ran as two processes (ports 3102 and 3103). With in-process counting the same
   session got 20 exports a minute through a 10-a-minute rule (10 per process). With
   `config.firewall.rateLimitStore: "redis://127.0.0.1:6379"` in both processes' `.securenow/runtime.json` it got 11.
   Redis only ever holds a hash of the cookie.

## Reproduce it locally

1. Connect the lab to SecureNow (Episode 2) and set up `ep7/run/production/` as in Episode 7 (port 3102,
   `deploymentEnvironment: "production"`). For the shared-counter demo, copy it to `ep7/run/production-b/` with
   `PORT=3103` and `APP_ORIGIN=http://localhost:3103`.
2. Start production with `node ep7/supervise.mjs production`, then run `node ep8/attack.mjs --minutes 8` or
   `node ep9/load.mjs <scenario>`.
3. Connect your agent with `claude mcp add securenow -- npx securenow mcp` and give it the prompt above. Remove the
   rules afterwards (`securenow blocklist unblock <id> --yes`, `securenow ratelimit remove <id> --yes`); every rule
   above was created with an expiry anyway.
