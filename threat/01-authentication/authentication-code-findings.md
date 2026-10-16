# Authentication — Code Findings & Recommendations

**App:** lab-auth (`df7ab010-37ac-4732-88ac-a8ac23afe1a4`, lab-auth.labs.securenow.ai) · **securenow 8.12.0** · **Commit:** `5f87235` · **Date:** 2026-10-16 · **Scope:** Authentication only
Companion: [Detection & mitigation runbook](authentication-detection-mitigation.md)

> **Findings only — no application code was modified.**

**Totals:** 16 findings · 0 critical · 0 high · 6 medium · 10 low

<a id="summary"></a>
## 1. Executive summary — code posture

> **Findings only — no application code was modified.** Every change below is described, never applied.

**Verdict.** The authentication code is above average for a small Express app: there are no critical or high findings, and the classic flaws (fixation, CSRF, email-based account linking, weak cookies, plaintext or truncated password hashing, ID-token decoding without verification) are already handled. What an attacker can still do is mostly **abuse**: keep a known member locked out (F3), grow the database and bury the audit trail without signing in (F1, F2), squat someone else’s email and block their Google sign-in (F4), and — with one stolen admin session — mint new admins without re-authenticating (F5). The fixes that reduce the most risk first are F3, F1 and F6 (a two-line routing change that makes SecureNow’s route-scoped controls impossible to sidestep).

**Findings by severity:** 0 critical · 0 high · 6 medium · 10 low (16 total).

### Top 3 code risks

1. [F3](#finding-f3) — the per-account limit counts the owner’s own attempts, so anyone who knows an email can lock that member out (`src/app.js:124-131, 173`).
2. [F1](#finding-f1) + [F2](#finding-f2) — unauthenticated requests write unlimited PostgreSQL rows: one session per cookieless `GET /api/me`, one audit row per rejected request (`src/app.js:150-155, 104-106, 132-134`).
3. [F4](#finding-f4) — registrations are never email-verified, so an address can be squatted and its real owner’s Google sign-in refused with no recovery path (`src/app.js:164-171, 247-250`).


<a id="todo"></a>
## 2. Start here — code TODO board

25 of the 36 master TODOs are App-owned code, config or instrumentation work; IDs and statuses are identical on the [master board](authentication-detection-mitigation.md#todo). The remaining 11 are SecureNow, Provider or External-monitor tasks.



### DO NOW (4)


<a id="todo-auth-01"></a>
#### AUTH-01 · Add the SDK with safe capture settings and start it as a preload — DO NOW · HIGH
- **Owner:** App · **Priority:** high · **Effort:** S
- **Where / concrete change:** `npm install --save-exact securenow@8.12.0` (commit package.json + package-lock.json); run `npx securenow app connect` and pick lab-auth; merge `capture.body=false`, `capture.multipart=false`, `runtime.deploymentEnvironment="test"` into the runtime file (docs/securenow-integration.md:32-48); change the start command to `node -r securenow/register src/server.js` (Dockerfile:16, compose.yaml:30); mount the runtime credential at `/app/.securenow/credentials.json` in production.
- **Dependency:** None.
- **Outcome:** HTTP traces start flowing; once AUTH-05 creates R01–R09, the 11 traffic-based threats become detectable.
- **Verification / definition of done:** `npx securenow env --json` → captureBody false, deploymentEnvironment test; `npx securenow telemetry fields --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --since 24h --source traces --env test` lists http.target, http.client_ip, http.request.headers.
- **Rollback:** Revert the start command to `node src/server.js`.
- **Links:** [F13](#finding-f13) · [A1](authentication-detection-mitigation.md#threat-a1) · [D21](authentication-detection-mitigation.md#threat-d21) · [K52](authentication-detection-mitigation.md#threat-k52) · [AUTH-01](authentication-detection-mitigation.md#todo-auth-01) (master board)


<a id="todo-auth-06"></a>
#### AUTH-06 · Stop anonymous visitors from creating database sessions — DO NOW · HIGH
- **Owner:** App · **Priority:** high · **Effort:** M
- **Where / concrete change:** Finding F1 — signed double-submit CSRF cookie for anonymous visitors; create the server session only in `authenticate()` (`src/app.js:150-155`).
- **Dependency:** None.
- **Outcome:** Unauthenticated traffic no longer grows the database.
- **Verification / definition of done:** 65 cookieless GETs against a local copy add 0 `sessions` rows; CSRF tests still pass.
- **Rollback:** Revert the commit.
- **Links:** [F1](#finding-f1) · [J47](authentication-detection-mitigation.md#threat-j47) · [AUTH-06](authentication-detection-mitigation.md#todo-auth-06) (master board)


<a id="todo-auth-07"></a>
#### AUTH-07 · Cap audit writes from rejected requests — DO NOW · MEDIUM
- **Owner:** App · **Priority:** medium · **Effort:** S
- **Where / concrete change:** Finding F2 (`src/app.js:104-106, 132-134, 279`).
- **Dependency:** None.
- **Outcome:** The audit trail stays readable under attack.
- **Verification / definition of done:** 100 rejected requests add ≤ 1 row per window.
- **Rollback:** Revert the commit.
- **Links:** [F2](#finding-f2) · [S1](authentication-detection-mitigation.md#threat-s1) · [C13](authentication-detection-mitigation.md#threat-c13) · [AUTH-07](authentication-detection-mitigation.md#todo-auth-07) (master board)


<a id="todo-auth-08"></a>
#### AUTH-08 · Make routing strict and case-sensitive — DO NOW · HIGH
- **Owner:** App · **Priority:** high · **Effort:** S
- **Where / concrete change:** Finding F6: `app.set('case sensitive routing', true); app.set('strict routing', true);` right after `express()` (`src/app.js:35`); update `scripts/smoke.mjs:37`.
- **Dependency:** None.
- **Outcome:** Edge mitigations cannot be sidestepped by letter case; SecureNow rules can use exact paths.
- **Verification / definition of done:** `POST /API/AUTH/LOGIN` → 404 locally.
- **Rollback:** Remove the two settings.
- **Links:** [F6](#finding-f6) · [M62](authentication-detection-mitigation.md#threat-m62) · [AUTH-08](authentication-detection-mitigation.md#todo-auth-08) (master board)




### NEXT 7 DAYS (4)


<a id="todo-auth-09"></a>
#### AUTH-09 · Export auth events with track() and wire the sessions guard — NEXT 7 DAYS · HIGH
- **Owner:** App · **Priority:** high · **Effort:** M
- **Where / concrete change:** Add `src/securenow-bridge.js` and the 13 `emit(...)` calls plus `guard()` at the exact lines in the code report’s instrumentation section.
- **Dependency:** AUTH-01.
- **Outcome:** Event-based rules R10–R27 have data; manual session revocation becomes enforceable.
- **Verification / definition of done:** `npx securenow telemetry fields --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --since 24h --source logs --env test` lists event types auth.login.failure, auth.login.success, auth.signup, auth.security.change, session.seen and the attribute account_ref.
- **Rollback:** Remove the bridge import; events stop, the app is unaffected (track() never throws).
- **Links:** [A3](authentication-detection-mitigation.md#threat-a3) · [C9](authentication-detection-mitigation.md#threat-c9) · [C11](authentication-detection-mitigation.md#threat-c11) · [H41](authentication-detection-mitigation.md#threat-h41) · [AUTH-09](authentication-detection-mitigation.md#todo-auth-09) (master board)


<a id="todo-auth-13"></a>
#### AUTH-13 · Stop attackers from locking a known member out — NEXT 7 DAYS · HIGH
- **Owner:** App · **Priority:** high · **Effort:** M
- **Where / concrete change:** Finding F3 (device-trust cookie; count failures only) at `src/app.js:124-131, 173`.
- **Dependency:** None.
- **Outcome:** Owners keep signing in from their usual browser during an attack.
- **Verification / definition of done:** Lockout test in F3’s definition of done.
- **Rollback:** Revert the commit.
- **Links:** [F3](#finding-f3) · [H41](authentication-detection-mitigation.md#threat-h41) · [A2](authentication-detection-mitigation.md#threat-a2) · [AUTH-13](authentication-detection-mitigation.md#todo-auth-13) (master board)


<a id="todo-auth-14"></a>
#### AUTH-14 · Require recent re-authentication for admin role changes — NEXT 7 DAYS · HIGH
- **Owner:** App · **Priority:** high · **Effort:** M
- **Where / concrete change:** Finding F5, step-up part (`src/app.js:291-299`).
- **Dependency:** None.
- **Outcome:** A stolen admin cookie alone cannot grant roles.
- **Verification / definition of done:** Role change without re-auth in 5 min → 403.
- **Rollback:** Revert the commit.
- **Links:** [F5](#finding-f5) · [L54a](authentication-detection-mitigation.md#threat-l54a) · [AUTH-14](authentication-detection-mitigation.md#todo-auth-14) (master board)


<a id="todo-auth-15"></a>
#### AUTH-15 · Let the single-page app complete a SecureNow challenge — NEXT 7 DAYS · MEDIUM
- **Owner:** App · **Priority:** medium · **Effort:** S
- **Where / concrete change:** Finding F15 (`public/app.js:76-84`).
- **Dependency:** None.
- **Outcome:** Challenges become a safe response on `/api/auth` too.
- **Verification / definition of done:** F15 definition of done.
- **Rollback:** Revert the commit.
- **Links:** [F15](#finding-f15) · [M63](authentication-detection-mitigation.md#threat-m63) · [AUTH-15](authentication-detection-mitigation.md#todo-auth-15) (master board)




### LATER / HARDENING (10)


<a id="todo-auth-18"></a>
#### AUTH-18 · Verify email ownership and let a verified Google sign-in reclaim a squatted address — LATER / HARDENING · MEDIUM
- **Owner:** App · **Priority:** medium · **Effort:** L
- **Where / concrete change:** Finding F4.
- **Dependency:** An email channel with the auth-message limits from this model’s E-section.
- **Outcome:** Only mailbox owners hold accounts.
- **Verification / definition of done:** F4 definition of done.
- **Rollback:** Feature flag.
- **Links:** [F4](#finding-f4) · [B6](authentication-detection-mitigation.md#threat-b6) · [G36c](authentication-detection-mitigation.md#threat-g36c) · [H40a](authentication-detection-mitigation.md#threat-h40a) · [H40b](authentication-detection-mitigation.md#threat-h40b) · [AUTH-18](authentication-detection-mitigation.md#todo-auth-18) (master board)


<a id="todo-auth-19"></a>
#### AUTH-19 · Add passkeys or TOTP for admin and analyst, and notify on security changes — LATER / HARDENING · MEDIUM
- **Owner:** App · **Priority:** medium · **Effort:** L
- **Where / concrete change:** Finding F5 (MFA + notifications part).
- **Dependency:** AUTH-14; email channel for notices.
- **Outcome:** Phishing a password alone no longer grants admin.
- **Verification / definition of done:** Admin sign-in requires the second factor.
- **Rollback:** Feature flag per role.
- **Links:** [F5](#finding-f5) · [S2](authentication-detection-mitigation.md#threat-s2) · [C16](authentication-detection-mitigation.md#threat-c16) · [H39a](authentication-detection-mitigation.md#threat-h39a) · [AUTH-19](authentication-detection-mitigation.md#todo-auth-19) (master board)


<a id="todo-auth-20"></a>
#### AUTH-20 · Add sign-out-everywhere, a members’ own-sessions view and an admin revoke action — LATER / HARDENING · MEDIUM
- **Owner:** App · **Priority:** medium · **Effort:** M
- **Where / concrete change:** Finding F7.
- **Dependency:** None.
- **Outcome:** Any member or admin can end stolen sessions.
- **Verification / definition of done:** F7 definition of done.
- **Rollback:** Revert.
- **Links:** [F7](#finding-f7) · [C11](authentication-detection-mitigation.md#threat-c11) · [C9](authentication-detection-mitigation.md#threat-c9) · [AUTH-20](authentication-detection-mitigation.md#todo-auth-20) (master board)


<a id="todo-auth-21"></a>
#### AUTH-21 · Raise scrypt cost with rehash-on-sign-in and bound concurrent hashing — LATER / HARDENING · LOW
- **Owner:** App · **Priority:** low · **Effort:** S
- **Where / concrete change:** Findings F8 and F9.
- **Dependency:** Do F9 before or with F8.
- **Outcome:** Stronger hashes without a DoS lever.
- **Verification / definition of done:** F8/F9 definitions of done.
- **Rollback:** Revert; old hashes still verify.
- **Links:** [F8](#finding-f8) · [F9](#finding-f9) · [K49](authentication-detection-mitigation.md#threat-k49) · [A5a](authentication-detection-mitigation.md#threat-a5a) · [J46](authentication-detection-mitigation.md#threat-j46) · [AUTH-21](authentication-detection-mitigation.md#todo-auth-21) (master board)


<a id="todo-auth-22"></a>
#### AUTH-22 · Screen breached passwords and normalize Unicode — LATER / HARDENING · LOW
- **Owner:** App · **Priority:** low · **Effort:** S
- **Where / concrete change:** Finding F10.
- **Dependency:** None.
- **Outcome:** Sprayed and breached passwords are refused.
- **Verification / definition of done:** F10 definition of done.
- **Rollback:** Feature flag.
- **Links:** [F10](#finding-f10) · [A3](authentication-detection-mitigation.md#threat-a3) · [A4](authentication-detection-mitigation.md#threat-a4) · [A5a](authentication-detection-mitigation.md#threat-a5a) · [AUTH-22](authentication-detection-mitigation.md#todo-auth-22) (master board)


<a id="todo-auth-23"></a>
#### AUTH-23 · Key IPv6 clients by /64 and smooth the rate-limit window — LATER / HARDENING · LOW
- **Owner:** App · **Priority:** low · **Effort:** S
- **Where / concrete change:** Finding F11.
- **Dependency:** None.
- **Outcome:** Per-IP limits hold for IPv6.
- **Verification / definition of done:** F11 definition of done.
- **Rollback:** Revert.
- **Links:** [F11](#finding-f11) · [A4a](authentication-detection-mitigation.md#threat-a4a) · [A2](authentication-detection-mitigation.md#threat-a2) · [AUTH-23](authentication-detection-mitigation.md#todo-auth-23) (master board)


<a id="todo-auth-24"></a>
#### AUTH-24 · Remove the bootstrap admin password from the runtime secret — LATER / HARDENING · LOW
- **Owner:** App · **Priority:** low · **Effort:** S
- **Where / concrete change:** Finding F12 (`infra/update.sh`).
- **Dependency:** Admin has changed their password.
- **Outcome:** No standing admin credential in AWS.
- **Verification / definition of done:** Secret has no usable ADMIN_PASSWORD.
- **Rollback:** Re-add a one-time value for a fresh bootstrap.
- **Links:** [F12](#finding-f12) · [A5](authentication-detection-mitigation.md#threat-a5) · [AUTH-24](authentication-detection-mitigation.md#todo-auth-24) (master board)


<a id="todo-auth-25"></a>
#### AUTH-25 · Leave live sessions out of database backups — LATER / HARDENING · LOW
- **Owner:** App · **Priority:** low · **Effort:** S
- **Where / concrete change:** Finding F14 (`infra/backup.sh:6`).
- **Dependency:** None.
- **Outcome:** Backups contain no session material.
- **Verification / definition of done:** Restore drill shows empty sessions table.
- **Rollback:** Remove the two flags.
- **Links:** [F14](#finding-f14) · [D21a](authentication-detection-mitigation.md#threat-d21a) · [AUTH-25](authentication-detection-mitigation.md#todo-auth-25) (master board)


<a id="todo-auth-26"></a>
#### AUTH-26 · Record the previous sign-in time so dormant accounts can be flagged — LATER / HARDENING · LOW
- **Owner:** App · **Priority:** low · **Effort:** S
- **Where / concrete change:** Migration `ALTER TABLE users ADD COLUMN last_login_at timestamptz`; in `authenticate()` (`src/app.js:139-149`) read the old value, compute days, then update it; pass `dormant_days` on `auth.login.success`.
- **Dependency:** AUTH-09.
- **Outcome:** Dormant-account sign-ins are visible.
- **Verification / definition of done:** R22 synthetic test; a real 90-day-old test account triggers it.
- **Rollback:** Drop the column.
- **Links:** [C16b](authentication-detection-mitigation.md#threat-c16b) · [H40c](authentication-detection-mitigation.md#threat-h40c) · [AUTH-26](authentication-detection-mitigation.md#todo-auth-26) (master board)


<a id="todo-auth-29"></a>
#### AUTH-29 · Page and search the admin user list — LATER / HARDENING · LOW
- **Owner:** App · **Priority:** low · **Effort:** S
- **Where / concrete change:** Finding F16 (`src/app.js:287-289`).
- **Dependency:** None.
- **Outcome:** Admins can always find an account.
- **Verification / definition of done:** F16 definition of done.
- **Rollback:** Revert.
- **Links:** [F16](#finding-f16) · [H40](authentication-detection-mitigation.md#threat-h40) · [AUTH-29](authentication-detection-mitigation.md#todo-auth-29) (master board)




### ALREADY IN PLACE (7)


<a id="todo-auth-30"></a>
#### AUTH-30 · Atomic, shared rate limits and race-safe account creation — ALREADY IN PLACE · LOW
- **Owner:** App · **Priority:** low · **Effort:** S
- **Where / concrete change:** PostgreSQL-backed counters (`src/app.js:124-138`), unique lowercase email and Google subject (`db/001_initial.sql:3,6`), ON CONFLICT inserts, explicit field picking on signup.
- **Dependency:** —
- **Outcome:** In place.
- **Verification / definition of done:** Integration tests “durable rate limiting” and “registration is generic”.
- **Rollback:** —
- **Links:** [H38a](authentication-detection-mitigation.md#threat-h38a) · [H40d](authentication-detection-mitigation.md#threat-h40d) · [H40g](authentication-detection-mitigation.md#threat-h40g) · [L54](authentication-detection-mitigation.md#threat-l54) · [AUTH-30](authentication-detection-mitigation.md#todo-auth-30) (master board)


<a id="todo-auth-31"></a>
#### AUTH-31 · Session hardening — ALREADY IN PLACE · LOW
- **Owner:** App · **Priority:** low · **Effort:** S
- **Where / concrete change:** Regenerate on sign-in, `__Host-lab_auth` Secure/HttpOnly/SameSite=Lax, 30 min idle / 8 h absolute, version-based invalidation, ≥ 32-character secrets, HTTPS + HSTS.
- **Dependency:** —
- **Outcome:** In place (verified live 2026-10-16).
- **Verification / definition of done:** `scripts/smoke.mjs` cookie assertions.
- **Rollback:** —
- **Links:** [C10](authentication-detection-mitigation.md#threat-c10) · [C14](authentication-detection-mitigation.md#threat-c14) · [C15](authentication-detection-mitigation.md#threat-c15) · [D18](authentication-detection-mitigation.md#threat-d18) · [K50](authentication-detection-mitigation.md#threat-k50) · [AUTH-31](authentication-detection-mitigation.md#todo-auth-31) (master board)


<a id="todo-auth-32"></a>
#### AUTH-32 · CSRF protection on every API write — ALREADY IN PLACE · LOW
- **Owner:** App · **Priority:** low · **Effort:** S
- **Where / concrete change:** Exact Origin + Sec-Fetch-Site + per-session token + JSON content type (`src/app.js:102-110`).
- **Dependency:** —
- **Outcome:** In place.
- **Verification / definition of done:** Integration test “CSRF rejects cross-origin mutations”.
- **Rollback:** —
- **Links:** [C13](authentication-detection-mitigation.md#threat-c13) · [AUTH-32](authentication-detection-mitigation.md#todo-auth-32) (master board)


<a id="todo-auth-33"></a>
#### AUTH-33 · Hardened Google sign-in — ALREADY IN PLACE · LOW
- **Owner:** App · **Priority:** low · **Effort:** S
- **Where / concrete change:** State + nonce + PKCE S256, 10-minute single-use transaction, verifyIdToken (audience), issuer/subject/verified-email checks, identity keyed on subject, no email auto-linking, server-constant redirect URI.
- **Dependency:** —
- **Outcome:** In place.
- **Verification / definition of done:** Integration tests for nonce and linking.
- **Rollback:** —
- **Links:** [G31](authentication-detection-mitigation.md#threat-g31) · [G32](authentication-detection-mitigation.md#threat-g32) · [G33](authentication-detection-mitigation.md#threat-g33) · [G34](authentication-detection-mitigation.md#threat-g34) · [G36a](authentication-detection-mitigation.md#threat-g36a) · [G36b](authentication-detection-mitigation.md#threat-g36b) · [D19](authentication-detection-mitigation.md#threat-d19) · [AUTH-33](authentication-detection-mitigation.md#todo-auth-33) (master board)


<a id="todo-auth-34"></a>
#### AUTH-34 · Careful password storage and uniform answers — ALREADY IN PLACE · LOW
- **Owner:** App · **Priority:** low · **Effort:** S
- **Where / concrete change:** Salted scrypt, constant-time compare, dummy hash for unknown accounts, identical login/registration responses.
- **Dependency:** —
- **Outcome:** In place.
- **Verification / definition of done:** Integration test “failed login is generic”.
- **Rollback:** —
- **Links:** [B6](authentication-detection-mitigation.md#threat-b6) · [A5a](authentication-detection-mitigation.md#threat-a5a) · [AUTH-34](authentication-detection-mitigation.md#todo-auth-34) (master board)


<a id="todo-auth-35"></a>
#### AUTH-35 · Trustworthy client IPs and private internals — ALREADY IN PLACE · LOW
- **Owner:** App · **Priority:** low · **Effort:** S
- **Where / concrete change:** Caddy overwrites X-Forwarded-For; app trusts one hop; app/database ports unpublished; health endpoints minimal.
- **Dependency:** —
- **Outcome:** In place (docs/verification.md).
- **Verification / definition of done:** R09 stays at zero.
- **Rollback:** —
- **Links:** [I45](authentication-detection-mitigation.md#threat-i45) · [I45a](authentication-detection-mitigation.md#threat-i45a) · [AUTH-35](authentication-detection-mitigation.md#todo-auth-35) (master board)


<a id="todo-auth-36"></a>
#### AUTH-36 · Secrets kept out of Git and images — ALREADY IN PLACE · LOW
- **Owner:** App · **Priority:** low · **Effort:** S
- **Where / concrete change:** CI secret scan, .gitignore/.dockerignore, AWS Secrets Manager; Git history (4 commits) scanned clean in this run.
- **Dependency:** —
- **Outcome:** In place.
- **Verification / definition of done:** `node scripts/check-secrets.mjs` in CI.
- **Rollback:** —
- **Links:** [K51](authentication-detection-mitigation.md#threat-k51) · [AUTH-36](authentication-detection-mitigation.md#todo-auth-36) (master board)







<a id="together"></a>
## 3. How the app and SecureNow work together

The **app prevents** attacks (it decides who may sign in, how many attempts are allowed, what a session can do) and **emits business context** (“sign-in failed for account X”, “role elevated”) as privacy-safe events. **SecureNow observes** HTTP traffic and those events, **detects** patterns across requests and time, **notifies** a person, and **contains** the actor with scoped rate limits, challenges, route blocks or session revocation. **Provider and external controls** cover what neither can see: Google Cloud’s own audit logs, certificate expiry, or SecureNow’s pipeline being down.

**Real example from this repo — the lockout (F3):** an attacker sends 31 sign-ins for a member’s email from three IPs every 15 minutes. The app correctly throttles — but also throttles the member. SecureNow, fed by the `api.ratelimit.exceeded` event, sees that one account’s bucket is held full by two or more IPs (rule R14) and a person rate-limits those IPs. Only the app can stop counting the member’s own attempts (device cookie).

| Threat | SecureNow helps | App must fix |
| --- | --- | --- |
| [H41](authentication-detection-mitigation.md#threat-h41) lockout | R14/R11 detect the pressure; rate-limit contributing IPs | [F3](#finding-f3) device-trust cookie; count failures only |
| [J47](authentication-detection-mitigation.md#threat-j47) session-row growth | R03 detects cookieless minting; AUTO-C rate-limits the IP | [F1](#finding-f1) stop persisting anonymous sessions |
| [S1](authentication-detection-mitigation.md#threat-s1) audit flooding | R04/R02 detect; AUTO-D/AUTO-A rate-limit; SecureNow keeps its own copy of traffic | [F2](#finding-f2) log one rejection per window |
| [M62](authentication-detection-mitigation.md#threat-m62) route aliases | Rules normalize paths; mitigations use case-insensitive regexes | [F6](#finding-f6) strict, case-sensitive routing |
| [G36c](authentication-detection-mitigation.md#threat-g36c) squatted email | R16/R23 notice refusals and probing | [F4](#finding-f4) verify email; let Google reclaim |
| [L54a](authentication-detection-mitigation.md#threat-l54a) admin step-up | R21/R20 alert on elevations and network mismatch | [F5](#finding-f5) re-auth + MFA + notifications |


<a id="surface"></a>
## 4. Surface & inventory

**Real attack surface for this stack.** Small and deliberate: one password sign-in form, one registration form, Google sign-in (authorization code + PKCE), one password-change form, one admin role endpoint, and a server-side session cookie. No email/SMS, no reset, no MFA, no API keys, no SSO tenants. The meaningful risks are abuse and availability (lockout, unlimited anonymous writes, hashing load), identity hygiene (unverified emails), and the lack of a second factor or step-up for admins.

### Components

| Component | What is implemented | Evidence |
| --- | --- | --- |
| Login | Email + password; Google OIDC (authorization code, PKCE S256, state, nonce); registration; logout. No magic link, OTP, SAML, WebAuthn, API keys, basic auth or dev backdoor. One-time bootstrap admin from env vars. | `src/app.js:157-260`; `scripts/seed.js`; `src/bootstrap.js` |
| Session | express-session 1.19.0 + connect-pg-simple 10 (PostgreSQL `sessions`); cookie `__Host-lab_auth` (prod) — Secure, HttpOnly, SameSite=Lax, Path=/, no Domain; 30 min idle (rolling), 8 h absolute; signed with SESSION_SECRET (≥ 32 chars); revoked by logout (current) or `session_version` bump on password/role change. | `src/app.js:42, 75-79, 89-101, 139-149`; `src/config.js:8, 27-28` |
| Credential storage | scrypt N=32768 r=8 p=1, 16-byte random salt, 64-byte key, self-describing string; `timingSafeEqual`; dummy hash for unknown and Google-only accounts; no pepper; no breach screening. | `src/passwords.js` |
| MFA | None. | — |
| Recovery | None (no password reset, no email verification, no support recovery). Fixes are manual database work by an operator. | SECURITY.md:17 |
| Existing limits | PostgreSQL fixed 15-minute windows, atomic UPSERT, shared across instances and restarts, not reset on success: sign-in 15/IP + 30/account (HMAC of normalized email), registration 10/IP, password change 5/IP, Google start 30/IP, Google callback 30/IP. No CAPTCHA, no WAF/CDN. Client IP trustworthy behind Caddy (overwrites X-Forwarded-For; app trusts one hop). | `src/app.js:124-138, 157, 173, 194, 210, 222`; `infra/Caddyfile:5`; `compose.production.yaml:28` |
| Sensitive paths | `/api/auth/*`, `/api/admin/users*` (admin), `/api/security` (analyst/admin), `/healthz`, `/readyz`; static `public/` with dotfiles denied. | `src/app.js:69-73, 154-302` |

### Endpoints

| Method + path | Purpose | Guard | Limit | Code |
| --- | --- | --- | --- | --- |
| GET /healthz, /readyz | Liveness / DB readiness | Public | — | src/app.js:69-73 |
| GET /api/me, /api/auth/session, /api/auth/csrf | Session state + CSRF token | Public | — (F1) | src/app.js:154-155 |
| POST /api/auth/register | Create password account (uniform response) | CSRF | 10/IP/15 min | src/app.js:157-172 |
| POST /api/auth/login | Password sign-in | CSRF | 15/IP + 30/account per 15 min | src/app.js:173-187 |
| POST /api/auth/logout | Destroy current session | CSRF | — | src/app.js:188-193 |
| POST /api/auth/password | Change password (current required) | requireUser + CSRF | 5/IP/15 min | src/app.js:194-208 |
| GET /api/auth/google | Start Google sign-in | Public | 30/IP/15 min | src/app.js:210-221 |
| GET /api/auth/google/callback | Finish Google sign-in | Bound transaction | 30/IP/15 min | src/app.js:222-260 |
| GET /api/dashboard | Fictional workspace data | requireUser | — | src/app.js:262-276 |
| GET /api/security | Last 100 audit events + caller’s sessions | requireRole(analyst, admin) | — | src/app.js:277-286 |
| GET /api/admin/users | Newest 100 users | requireRole(admin) | — | src/app.js:287-290 |
| PATCH /api/admin/users/:id, /:id/role | Change role (bumps session_version) | requireRole(admin) + CSRF | — | src/app.js:291-299 |

### Authentication message & cost map

| Paid send path | Target source | Cost / retry / fallback | Quota dimensions | Fraud guard | Global circuit breaker |
| --- | --- | --- | --- | --- | --- |
| **None.** The app sends no OTP, magic-link, verification, reset, MFA or recovery message (no mail/SMS dependency in package.json, no such routes). | — | — | — | — | — |

F4 (email verification) and F5 (security-change notices) would add the first paid send path. Before shipping either: atomic per-target + per-account + per-device + per-IP counters **before** the provider call, one active link at a time, idempotency for retries, generic responses, a daily volume/spend cap with a kill switch, and the per-target/per-source SecureNow rules from this model’s E-section.

### Identity-resolution matrix

| Login method | Resolves to | Provider email verified? | Linking policy | Second method for an existing email | SSO enforced? | Deprovisioning | Domain / IdP binding |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Email + password | `users.email` (trim + lowercase; unique; CHECK lower) | n/a — `email_verified=false`, never checked | none | Google sign-in for that address is refused (`account_exists`) | No | n/a | n/a |
| Google OIDC | `users.google_subject` (`sub`; `iss` checked) | Required (`email_verified`) | never auto-links; refuses on email conflict | Password registration for a Google account’s address returns the uniform response and creates nothing | No | Not propagated (8 h absolute cap only) | None (public lab; no `hd` restriction) |

No domain-based auto-join, no invitations, no account deletion or identifier re-use.

### Single-use token inventory

| Token | At rest | Bound to | Lifetime | Invalidated by | Atomic redemption | Redeemable by GET | Appears in URL / response / log |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Google transaction (state, nonce, PKCE verifier) | Plaintext JSON in `sessions.sess` (F14) | The browser session | 10 min | Next `/api/auth/google` overwrites it | Yes — removed from the session before validation (`src/app.js:224-226`) | Yes (OAuth redirect, by design) | `state` and `code` in the callback URL; the SDK redacts `code`, not `state` (F13); the app does not log query strings |
| CSRF token (per session, reusable) | Plaintext in session JSON | Session | Session lifetime | Rotated at sign-in and password change | n/a | n/a | Returned in JSON bodies; sent as `X-CSRF-Token` (recorded by SDK header capture — F13) |
| Session ID | Plaintext primary key `sessions.sid`; cookie carries the signed ID | User + `session_version` | 30 min idle / 8 h absolute | Logout (current); version bump (all) | n/a | n/a | Cookie only; `/api/security` returns a 16-char HMAC prefix, never the ID; backups contain it (F14) |
| Reset, magic link, OTP, email verification, invite, refresh, recovery code, remember-device, CLI login | None exist | — | — | — | — | — | — |

### Where authentication is enforced

Server-side, per route, in Express 5.3.0 (not Next.js — CVE-2025-29927 does not apply): `requireUser` on `/api/auth/password` and `/api/dashboard`; `requireRole` on `/api/security` and `/api/admin/*`; the user is reloaded from PostgreSQL on every request (`src/app.js:89-101`). The SPA hides navigation by role (`public/app.js:105`), which is cosmetic. The credential issued after the password step is the full session — there is no MFA step to skip. Routing is case-insensitive and non-strict by default (F6).

### Hosted identity-provider configuration — questions for you (not verifiable from the repo)

1. Google Auth Platform: is the production client published to the intended audience, requesting only `openid email profile`?
2. Are the authorized redirect URIs on the production client exactly `https://lab-auth.labs.securenow.ai/api/auth/google/callback` (and is the localhost URI on a separate development client)?
3. Who holds Owner/Editor on the Google Cloud project, and is there a Cloud Audit Logs alert for OAuth client edits (AUTH-28)?
4. When was the OAuth client secret last rotated, and is it rotated when operators change?

### Security-change & attack-chain map

| Change | Route / code | Durable IDs available | Step-up | User notified | Today’s audit row | Proposed SecureNow event |
| --- | --- | --- | --- | --- | --- | --- |
| Password change | POST /api/auth/password, src/app.js:194-208 | user.id; session ID before and after; req.ip (trusted); requestId | Current password | No | `auth.password_changed` / `_failed` | `auth.security.change` action=password_changed |
| Role change | PATCH /api/admin/users/:id[/role], src/app.js:291-299 | admin id; target id; session; req.ip; requestId | None (F5) | No | `admin.role_changed` | `auth.security.change` action=role_changed, direction, target_ref |
| Session creation | authenticate(), src/app.js:139-149 | user.id; new session ID | — | No | `auth.login_succeeded` | `auth.login.success` |
| Session revocation | logout src/app.js:188-193; version bump 202, 294 | user.id; session ID | — | No | `auth.logout` | `auth.logout` |
| OAuth link | Refused, src/app.js:247-250 | Google sub; normalized email | — | Shown on screen | `auth.google_failed` reason=identity_conflict | `auth.account.link` outcome=rejected |
| Email/phone change, factor enroll/remove, recovery codes, API keys, export, payout | None exist | — | — | — | — | — |

### Provider control plane & quality telemetry

- Google Cloud (OAuth client, consent screen, audit logs): not ingested; no webhooks reach the app; provider activity outside the app is invisible (M58).
- AWS (Secrets Manager runtime secret, CloudFormation, SSM): CloudTrail not ingested by SecureNow.
- Caddy access logs stay in the container’s json-file log driver; they are not exported.
- Signals that will enter SecureNow: HTTP traces (after the SDK preload) and app events (after the bridge). Nothing else needs an adapter for this lab today.

### Detection-pipeline health

- Expected ratio: one `auth.login.*` event per traced 200/401 on `POST /api/auth/login` (rule R25).
- Deployment: one app container on one EC2 host (compose.production.yaml), so per-process rate-limit counters equal the configured limit.
- `track()` never throws and silently drops events when no app key is configured (`node_modules/securenow/events.js:39-44`); its buffer drops the oldest events past 1,000 (`events.js:18, 145`).
- When the SDK loads it also forwards `console.*` lines as OpenTelemetry logs (`node_modules/securenow/tracing.js:653-676`); the app’s error lines contain only codes and request IDs (`src/app.js:307-309`).
- Notification channel: in-app only. No independent monitor exists. A total exporter or ingestion outage cannot alert through the same path (M56).

### Evasion & response safety

- Case and trailing-slash aliases reach the handlers (F6); percent-encoded aliases return 404 (tested locally in memory).
- IPv6 rotation within a /64 gets fresh per-IP buckets (F11).
- Spoofed X-Forwarded-For is neutralized by Caddy (`header_up X-Forwarded-For {remote_host}`) and `trust proxy 1`; the SDK resolves the client IP from a private proxy socket the same way.
- Parallel requests cannot beat the counter (atomic UPSERT before verification).
- Shared NAT: per-IP limits and per-IP SecureNow responses can hit classrooms and offices — prefer rate limits and GET-page challenges.
- Responses that could punish victims: the per-account bucket (F3); the account-wide SecureNow auto-block automations (detection report AUTH-03); a challenge on JSON routes (F15).

### Detection governance

There are no existing SecureNow rules for lab-auth. Owner, threshold source, mode, channel, last validation, false-positive budget, runbook and reversible action for each of the 27 proposed rules are in the [detection report’s governance table](authentication-detection-mitigation.md#governance).

### Machine auth

None: no API keys, no service-to-service calls, no inbound webhooks. The Google client secret is server-side only (Secrets Manager → `/etc/lab-auth/app.env`, mode 0600). The SecureNow runtime key will be the first machine credential: mount it read-only for the `node` user, never bake it into the image (the build context already excludes `.securenow`), and rotate it with `npx securenow credentials runtime --env test`.

### Secrets hygiene

- Git history (4 commits) scanned for Google OAuth secrets, AWS keys, private keys, SecureNow runtime keys and GitHub tokens: the only matches are the scanner’s own regexes in `scripts/check-secrets.mjs`.
- CI runs `node scripts/check-secrets.mjs`; `.gitignore` and `.dockerignore` cover `.env*`, `.securenow/*.json`, `.deployment/`, keys and dumps.
- Local, untracked operator files exist under `.deployment/` and `.securenow/` on this workstation; they were not read for this report and are not in Git.
- The client bundle contains no secrets (`public/app.js` reads only `googleEnabled`).
- The bootstrap admin password remains in the runtime secret after first use (F12).

### SecureNow instrumentation already present

None. There is no `securenow/register`, `securenow run`, `guard()`/`capture()` or `track()` anywhere in `src/`, `scripts/`, the Dockerfile or the compose files; `securenow@8.12.0` sits in `node_modules` only (installed with `--no-save` for this report). The app’s audit helper (`src/app.js:81-86`) writes to PostgreSQL only.


<a id="catalog"></a>
## 5. Threat catalog

All 115 catalog items (numbered and letter-suffixed) plus 2 stack-specific additions: 67 modeled (scenario cards in the detection report), 50 explicit N/A with evidence, 8 deferred rows. OWASP Top 10:2021 categories.

### A. Credential attacks (8)

| # | Threat | OWASP | CWE | Status |
| --- | --- | --- | --- | --- |
| [A1](authentication-detection-mitigation.md#threat-a1) | Single-IP password guessing on the sign-in form | A07:2021 | CWE-307 | modeled — 🟡 PARTIAL, NATIVE_TRAFFIC |
| [A2](authentication-detection-mitigation.md#threat-a2) | Distributed / low-and-slow guessing that rotates addresses | A07:2021 | CWE-307 | modeled — 🟡 PARTIAL, NATIVE_TRAFFIC |
| [A3](authentication-detection-mitigation.md#threat-a3) | Credential stuffing with breached email/password pairs | A07:2021 | CWE-307 | modeled — 🟡 PARTIAL, APP_EVENT |
| [A4](authentication-detection-mitigation.md#threat-a4) | Password spraying (one common password, many accounts) | A07:2021 | CWE-307 | modeled — 🟡 PARTIAL, APP_EVENT |
| [A4a](authentication-detection-mitigation.md#threat-a4a) | Rate-limit counter weaknesses (window boundary, IPv6 rotation) | A07:2021 | CWE-307 | modeled — 🟡 PARTIAL, NATIVE_TRAFFIC |
| [A5](authentication-detection-mitigation.md#threat-a5) | Default, seeded or leftover bootstrap credentials | A07:2021 | CWE-1392 | modeled — 🔴 GAP, APP_OR_PROVIDER_CONTROL |
| [A5a](authentication-detection-mitigation.md#threat-a5a) | Password-handling gaps (no breach screening, no Unicode normalization, scrypt below OWASP minimum) | A02:2021 | CWE-916 | modeled — 🔴 GAP, APP_OR_PROVIDER_CONTROL |
| A5b | Hosted identity-provider misconfiguration | A07:2021 | CWE-287 | N/A — Authentication is implemented in this app, not on Supabase/Firebase/Clerk/Auth0/Cognito. Google is only an OIDC provider; its console settings are listed as questions in the code report. |

### B. Enumeration & reconnaissance (4)

| # | Threat | OWASP | CWE | Status |
| --- | --- | --- | --- | --- |
| [B6](authentication-detection-mitigation.md#threat-b6) | Account enumeration via register-then-sign-in | A07:2021 | CWE-204 | modeled — 🟡 PARTIAL, APP_EVENT |
| [B7](authentication-detection-mitigation.md#threat-b7) | Identifier harvesting at scale | A07:2021 | CWE-204 | modeled — 🟡 PARTIAL, APP_EVENT |
| [B8](authentication-detection-mitigation.md#threat-b8) | Auth-surface scanning (forced browsing for .env, .git, admin panels) | A05:2021 | CWE-425 | modeled — 🟡 PARTIAL, NATIVE_TRAFFIC |
| [B8a](authentication-detection-mitigation.md#threat-b8a) | Google sign-in conflict message as an enumeration oracle | A07:2021 | CWE-204 | modeled — 🟡 PARTIAL, APP_EVENT |

### C. Session & account takeover (14)

| # | Threat | OWASP | CWE | Status |
| --- | --- | --- | --- | --- |
| [C9](authentication-detection-mitigation.md#threat-c9) | Session cookie theft (malware, XSS, phishing proxy) | A07:2021 | CWE-294 | modeled — 🟡 PARTIAL, APP_EVENT |
| [C10](authentication-detection-mitigation.md#threat-c10) | Session fixation | A07:2021 | CWE-384 | modeled — 🔴 GAP, APP_OR_PROVIDER_CONTROL |
| [C11](authentication-detection-mitigation.md#threat-c11) | Limited revocation (no sign-out-everywhere, Google-only users, no admin kill switch) | A07:2021 | CWE-613 | modeled — 🟡 PARTIAL, APP_EVENT |
| [C11a](authentication-detection-mitigation.md#threat-c11a) | Sessions surviving a password change or role downgrade (regression) | A07:2021 | CWE-613 | modeled — 🟡 PARTIAL, APP_EVENT |
| [C12](authentication-detection-mitigation.md#threat-c12) | Concurrent use of one account from several networks | A07:2021 | CWE-613 | modeled — 🟡 PARTIAL, APP_EVENT |
| [C13](authentication-detection-mitigation.md#threat-c13) | CSRF against auth endpoints (and floods of CSRF-rejected requests) | A01:2021 | CWE-352 | modeled — 🟡 PARTIAL, NATIVE_TRAFFIC |
| [C14](authentication-detection-mitigation.md#threat-c14) | Weak session-cookie configuration | A05:2021 | CWE-614 | modeled — 🔴 GAP, APP_OR_PROVIDER_CONTROL |
| [C15](authentication-detection-mitigation.md#threat-c15) | Excessive session lifetime | A07:2021 | CWE-613 | modeled — 🔴 GAP, APP_OR_PROVIDER_CONTROL |
| [C16](authentication-detection-mitigation.md#threat-c16) | Sign-in from an unusual network (hosting/VPN provider, new operator) | A07:2021 | CWE-308 | modeled — 🟡 PARTIAL, APP_EVENT |
| [C16a](authentication-detection-mitigation.md#threat-c16a) | Successful sign-in right after failures, or one IP into several accounts | A07:2021 | CWE-307 | modeled — 🟡 PARTIAL, APP_EVENT |
| [C16b](authentication-detection-mitigation.md#threat-c16b) | Dormant-account reactivation | A07:2021 | CWE-308 | modeled — 🟡 PARTIAL, APP_EVENT |
| [C16c](authentication-detection-mitigation.md#threat-c16c) | Multi-step takeover: failures → sign-in → password or role change | A07:2021 | CWE-308 | modeled — 🟡 PARTIAL, APP_EVENT |
| [C16d](authentication-detection-mitigation.md#threat-c16d) | Sensitive action from a different network than the sign-in | A07:2021 | CWE-294 | modeled — 🟡 PARTIAL, APP_EVENT |
| C16e | Cross-device approval logs in the wrong browser | A07:2021 | CWE-287 | N/A — No magic link, push approval or QR login exists. |

### D. Token attacks (8)

| # | Threat | OWASP | CWE | Status |
| --- | --- | --- | --- | --- |
| D17 | alg=none / algorithm confusion | A02:2021 | CWE-347 | N/A — The app issues no JWTs (server-side sessions). The only JWT is Google’s ID token, verified by google-auth-library (src/app.js:233); protocol depth → ../07-oauth-sso-integrations/. |
| [D18](authentication-detection-mitigation.md#threat-d18) | Weak or guessable session-cookie signing secret | A02:2021 | CWE-326 | modeled — 🔴 GAP, APP_OR_PROVIDER_CONTROL |
| [D19](authentication-detection-mitigation.md#threat-d19) | Google ID-token validation (signature, audience, expiry, issuer, nonce) | A07:2021 | CWE-347 | modeled — 🟡 PARTIAL, APP_EVENT |
| D20 | Refresh-token theft / rotation | A07:2021 | CWE-613 | N/A — No refresh tokens: Google is requested with access_type=online (src/app.js:218) and tokens are discarded after verification. |
| [D21](authentication-detection-mitigation.md#threat-d21) | Token leakage into URLs, logs, Referer or telemetry | A09:2021 | CWE-532 | modeled — 🔴 GAP, APP_OR_PROVIDER_CONTROL |
| [D21a](authentication-detection-mitigation.md#threat-d21a) | Live session IDs and OAuth transactions readable from database backups | A02:2021 | CWE-312 | modeled — 🔴 GAP, APP_OR_PROVIDER_CONTROL |
| D21b | Token not bound to user + purpose + target | A07:2021 | CWE-287 | N/A — No reset, OTP, magic-link, verification, invite, remember-device or recovery tokens exist. The only single-use artifact (the Google transaction) is bound to the session, state, nonce and PKCE verifier (src/app.js:213, 227, 235). |
| D21c | JWT header trust (kid/jku/x5u/jwk) or decode() instead of verify() | A08:2021 | CWE-347 | N/A — The app never decodes a JWT itself; verifyIdToken is used (src/app.js:233). |

### E. Passwordless / OTP / magic links (12)

| # | Threat | OWASP | CWE | Status |
| --- | --- | --- | --- | --- |
| E22 | Magic-link / OTP request flooding | A04:2021 | CWE-799 | N/A — No OTP, magic link, SMS or email sending exists (no mail/SMS dependency in package.json, no such routes). |
| E22a | One source → many send targets | A04:2021 | CWE-799 | N/A — No auth messages are sent. |
| E22b | Many sources → one send target (victim bombing) | A04:2021 | CWE-799 | N/A — No auth messages are sent. |
| E22c | SMS/voice traffic pumping | A04:2021 | CWE-799 | N/A — No SMS or voice. |
| E22d | Retry/resend/fallback amplification | A04:2021 | CWE-799 | N/A — No auth messages are sent. |
| E22e | Provider spend/quota exhaustion | A04:2021 | CWE-770 | N/A — No paid messaging provider. |
| E22f | Send-to-verification conversion collapse | A04:2021 | CWE-799 | N/A — No sends or verifications. |
| E23 | OTP / magic-link brute force | A07:2021 | CWE-307 | N/A — No OTP or magic links. |
| E24 | Link/OTP interception and reuse | A07:2021 | CWE-294 | N/A — No OTP or magic links. |
| E25 | Long-lived or reusable login tokens | A07:2021 | CWE-613 | N/A — No login tokens besides the session; see C15. |
| E25a | Multiple valid resend codes / redemption race | A04:2021 | CWE-362 | N/A — No codes or links. |
| E25b | Link scanners consuming single-use links | A04:2021 | CWE-799 | N/A — No emailed links. |

### F. MFA (12)

| # | Threat | OWASP | CWE | Status |
| --- | --- | --- | --- | --- |
| F26 | MFA bypass routes | A07:2021 | CWE-308 | N/A — No MFA exists (the absence itself is modeled as S2). |
| F26a | MFA/verification enforced only by the client or flow order | A07:2021 | CWE-602 | N/A — No MFA or email-verification gate exists (absence modeled as S2 and F4). |
| F26b | OTP/reset/verification code returned in an API response | A01:2021 | CWE-200 | N/A — No such codes exist; publicUser() never returns password_hash (src/app.js:25-32). |
| F27 | Push fatigue / MFA prompt bombing | A07:2021 | CWE-308 | N/A — No push MFA. |
| F27a | OTP/MFA phishing relay | A07:2021 | CWE-294 | N/A — No OTP/MFA (password phishing relay is covered by C9). |
| F27b | Factor downgrade / channel-choice abuse | A07:2021 | CWE-757 | N/A — No factors. |
| F28 | Recovery-code brute force | A07:2021 | CWE-307 | N/A — No recovery codes. |
| F28a | TOTP replay / drift / unverified enrollment | A07:2021 | CWE-294 | N/A — No TOTP. |
| F29 | Post-takeover factor enrollment / MFA reset hijack | A07:2021 | CWE-308 | N/A — No factors. |
| F29a | Support-assisted recovery or MFA reset abuse | A07:2021 | CWE-640 | N/A — No support or recovery tooling in code; any manual database fix by an operator → ../08-admin-support-tools/. |
| F30 | SMS SIM-swap exposure | A07:2021 | CWE-308 | N/A — No SMS factor. |
| F30a | WebAuthn/passkey validation failures | A07:2021 | CWE-287 | N/A — No WebAuthn. |

### G. OAuth / OIDC / SSO / SAML (14)

| # | Threat | OWASP | CWE | Status |
| --- | --- | --- | --- | --- |
| [G31](authentication-detection-mitigation.md#threat-g31) | redirect_uri manipulation / open redirect after Google sign-in | A01:2021 | CWE-601 | modeled — 🔴 GAP, APP_OR_PROVIDER_CONTROL |
| [G32](authentication-detection-mitigation.md#threat-g32) | Missing state or PKCE (login CSRF / code injection) | A07:2021 | CWE-352 | modeled — 🟡 PARTIAL, APP_EVENT |
| [G33](authentication-detection-mitigation.md#threat-g33) | Authorization-code interception or replay | A07:2021 | CWE-294 | modeled — 🟡 PARTIAL, APP_EVENT |
| [G34](authentication-detection-mitigation.md#threat-g34) | Account-linking confusion (auto-link on email) | A07:2021 | CWE-287 | modeled — 🟡 PARTIAL, APP_EVENT |
| G35 | SAML signature wrapping / unsigned assertions | A08:2021 | CWE-347 | N/A — No SAML. |
| [G36](authentication-detection-mitigation.md#threat-g36) | Open just-in-time provisioning through Google sign-in | A01:2021 | CWE-269 | modeled — 🟡 PARTIAL, APP_EVENT |
| [G36a](authentication-detection-mitigation.md#threat-g36a) | OIDC replay without nonce | A07:2021 | CWE-294 | modeled — 🟡 PARTIAL, APP_EVENT |
| [G36b](authentication-detection-mitigation.md#threat-g36b) | Identity keyed on a mutable claim (email instead of subject) | A07:2021 | CWE-290 | modeled — 🔴 GAP, APP_OR_PROVIDER_CONTROL |
| [G36c](authentication-detection-mitigation.md#threat-g36c) | Real users locked out across sign-in methods (password squat blocks Google) | A07:2021 | CWE-287 | modeled — 🟡 PARTIAL, APP_EVENT |
| G36d | SSO enforcement bypass | A07:2021 | CWE-288 | N/A — No per-domain or per-tenant SSO enforcement exists. |
| [G36e](authentication-detection-mitigation.md#threat-g36e) | Google account disabled, but lab session continues | A07:2021 | CWE-613 | modeled — 🔴 GAP, PROVIDER_EVENT |
| G36f | Multi-tenant SSO domain confusion | A07:2021 | CWE-290 | N/A — Single tenant; one Google client; no per-tenant IdPs. |
| G36g | Domain-based auto-join | A01:2021 | CWE-284 | N/A — No organizations or auto-join. |
| G36h | Loopback CLI/desktop login | A07:2021 | CWE-601 | N/A — No CLI or desktop login flow. |

### H. Account lifecycle & recovery (15)

| # | Threat | OWASP | CWE | Status |
| --- | --- | --- | --- | --- |
| H37 | Password-reset poisoning | A07:2021 | CWE-640 | N/A — No password reset; the only server-built URL (Google redirect) comes from APP_ORIGIN, not the Host header (src/app.js:40). |
| H37a | Recovery sent to the request-supplied address | A07:2021 | CWE-640 | N/A — No recovery or verification messages. |
| H38 | Reset-token brute force or predictable tokens | A07:2021 | CWE-640 | N/A — No reset tokens. |
| [H38a](authentication-detection-mitigation.md#threat-h38a) | Races in identity-state changes (duplicate registration, parallel guesses) | A04:2021 | CWE-362 | modeled — 🔴 GAP, APP_OR_PROVIDER_CONTROL |
| H39 | Email/phone change without re-auth | A07:2021 | CWE-620 | N/A — No email or phone change feature. |
| [H39a](authentication-detection-mitigation.md#threat-h39a) | Password change with a stolen session; no notification | A07:2021 | CWE-620 | modeled — 🟡 PARTIAL, APP_EVENT |
| [H40](authentication-detection-mitigation.md#threat-h40) | Signup abuse / mass account creation | A04:2021 | CWE-799 | modeled — 🟡 PARTIAL, NATIVE_TRAFFIC |
| [H40a](authentication-detection-mitigation.md#threat-h40a) | Account pre-hijacking / email squatting | A07:2021 | CWE-287 | modeled — 🟡 PARTIAL, APP_EVENT |
| [H40b](authentication-detection-mitigation.md#threat-h40b) | Email canonicalization mismatch (Unicode, Gmail dots, plus-aliases) | A07:2021 | CWE-176 | modeled — 🔴 GAP, APP_OR_PROVIDER_CONTROL |
| [H40c](authentication-detection-mitigation.md#threat-h40c) | Dormant-account takeover followed by changes | A07:2021 | CWE-308 | modeled — 🟡 PARTIAL, APP_EVENT |
| [H40d](authentication-detection-mitigation.md#threat-h40d) | Signup overwriting or shadowing an existing account | A07:2021 | CWE-287 | modeled — 🔴 GAP, APP_OR_PROVIDER_CONTROL |
| H40e | Invite links as credentials | A07:2021 | CWE-287 | N/A — No invitations. |
| H40f | Account deletion and identifier reuse | A07:2021 | CWE-287 | N/A — No account deletion; emails are never released. |
| [H40g](authentication-detection-mitigation.md#threat-h40g) | Mass assignment of auth fields on signup | A01:2021 | CWE-915 | modeled — 🔴 GAP, APP_OR_PROVIDER_CONTROL |
| [H41](authentication-detection-mitigation.md#threat-h41) | Targeted lockout of a member through the per-account limit | A07:2021 | CWE-645 | modeled — 🟡 PARTIAL, APP_EVENT |

### I. API & machine-to-machine auth (6)

| # | Threat | OWASP | CWE | Status |
| --- | --- | --- | --- | --- |
| I42 | API key leakage | A05:2021 | CWE-798 | N/A — The app has no API keys. (The future SecureNow runtime key is covered by M61; the Google client secret by K51.) |
| I43 | Over-privileged API keys | A01:2021 | CWE-250 | N/A — No API keys. |
| I44 | Invalid-key spray | A07:2021 | CWE-307 | N/A — No API keys. |
| [I45](authentication-detection-mitigation.md#threat-i45) | Unauthenticated health endpoints reachable from outside | A01:2021 | CWE-306 | modeled — 🔴 GAP, APP_OR_PROVIDER_CONTROL |
| [I45a](authentication-detection-mitigation.md#threat-i45a) | Spoofed forwarding headers or proxy bypass | A07:2021 | CWE-348 | modeled — 🟡 PARTIAL, NATIVE_TRAFFIC |
| I45b | Auth enforced only in middleware or client (Next.js CVE-2025-29927 class) | A01:2021 | CWE-288 | N/A — Express app, not Next.js; every protected route has its own server-side guard (src/app.js:194, 262, 277, 287, 291); client navigation hiding is cosmetic. |

### J. Availability (5)

| # | Threat | OWASP | CWE | Status |
| --- | --- | --- | --- | --- |
| [J46](authentication-detection-mitigation.md#threat-j46) | Password-hashing CPU/memory amplification on sign-in routes | A04:2021 | CWE-405 | modeled — 🟡 PARTIAL, NATIVE_TRAFFIC |
| [J47](authentication-detection-mitigation.md#threat-j47) | Session-store and audit-table growth from anonymous requests | A04:2021 | CWE-770 | modeled — 🟡 PARTIAL, NATIVE_TRAFFIC |
| J48 | Email/SMS provider quota exhaustion | A04:2021 | CWE-770 | N/A — No messaging provider. |
| J48a | Voice/WhatsApp/push fallback storm | A04:2021 | CWE-770 | N/A — No messaging. |
| J48b | No global send spend ceiling | A04:2021 | CWE-770 | N/A — No paid sends. |

### K. Transport, storage & secrets (4)

| # | Threat | OWASP | CWE | Status |
| --- | --- | --- | --- | --- |
| [K49](authentication-detection-mitigation.md#threat-k49) | Password-hash work factor below current guidance | A02:2021 | CWE-916 | modeled — 🔴 GAP, APP_OR_PROVIDER_CONTROL |
| [K50](authentication-detection-mitigation.md#threat-k50) | Missing TLS/HSTS or cookies over plain HTTP | A02:2021 | CWE-319 | modeled — 🔴 GAP, EXTERNAL_MONITOR |
| [K51](authentication-detection-mitigation.md#threat-k51) | Auth secrets committed to Git or baked into images | A05:2021 | CWE-798 | modeled — 🔴 GAP, APP_OR_PROVIDER_CONTROL |
| [K52](authentication-detection-mitigation.md#threat-k52) | Credentials or tokens captured in logs and traces | A09:2021 | CWE-532 | modeled — 🔴 GAP, APP_OR_PROVIDER_CONTROL |

### L. Post-auth privilege boundary (3)

| # | Threat | OWASP | CWE | Status |
| --- | --- | --- | --- | --- |
| [L53](authentication-detection-mitigation.md#threat-l53) | Privilege escalation through client-controlled role claims | A01:2021 | CWE-269 | modeled — 🟡 PARTIAL, APP_EVENT |
| [L54](authentication-detection-mitigation.md#threat-l54) | IDOR on account-management endpoints | A01:2021 | CWE-639 | modeled — 🔴 GAP, APP_OR_PROVIDER_CONTROL |
| [L54a](authentication-detection-mitigation.md#threat-l54a) | No step-up re-authentication for admin role changes | A07:2021 | CWE-306 | modeled — 🟡 PARTIAL, APP_EVENT |

### M. Detection, telemetry & control-plane integrity (10)

| # | Threat | OWASP | CWE | Status |
| --- | --- | --- | --- | --- |
| [M55](authentication-detection-mitigation.md#threat-m55) | Auth requests traced but their events missing (coverage drift) | A09:2021 | CWE-778 | modeled — 🟡 PARTIAL, APP_EVENT |
| [M56](authentication-detection-mitigation.md#threat-m56) | Telemetry exporter or ingestion outage | A09:2021 | CWE-778 | modeled — 🔴 GAP, EXTERNAL_MONITOR |
| M57 | Provider delivery/fraud callbacks stop or are forged | A08:2021 | CWE-345 | N/A — No provider webhooks reach this app. |
| [M58](authentication-detection-mitigation.md#threat-m58) | Google Cloud OAuth client or project compromise | A07:2021 | CWE-284 | modeled — 🔴 GAP, PROVIDER_EVENT |
| M59 | Provider volume with no matching app attempt_id | A09:2021 | CWE-778 | N/A — No paid provider sends. |
| [M60](authentication-detection-mitigation.md#threat-m60) | Alert rule disabled, edited or never run; alerts only in-app | A09:2021 | CWE-778 | modeled — 🔴 GAP, EXTERNAL_MONITOR |
| [M60a](authentication-detection-mitigation.md#threat-m60a) | Detection-logic defects that look healthy | A09:2021 | CWE-778 | modeled — 🔴 GAP, EXTERNAL_MONITOR |
| [M61](authentication-detection-mitigation.md#threat-m61) | Forged or replayed security events; stolen runtime key | A08:2021 | CWE-345 | modeled — 🟡 PARTIAL, APP_EVENT |
| [M62](authentication-detection-mitigation.md#threat-m62) | Evasion via route aliases, IPv6 rotation or spoofed headers | A07:2021 | CWE-290 | modeled — 🟡 PARTIAL, NATIVE_TRAFFIC |
| [M63](authentication-detection-mitigation.md#threat-m63) | Unsafe automated response (global blocks, challenges that break sign-in) | A04:2021 | CWE-693 | modeled — 🟡 PARTIAL, APP_OR_PROVIDER_CONTROL |

### S. Stack-specific (added for this codebase) (2)

| # | Threat | OWASP | CWE | Status |
| --- | --- | --- | --- | --- |
| [S1](authentication-detection-mitigation.md#threat-s1) | Audit-trail flushing: rejected requests bury real events | A09:2021 | CWE-779 | modeled — 🟡 PARTIAL, NATIVE_TRAFFIC |
| [S2](authentication-detection-mitigation.md#threat-s2) | No second factor or step-up anywhere | A07:2021 | CWE-308 | modeled — 🔴 GAP, APP_OR_PROVIDER_CONTROL |

### Deferred to sibling models (8)

| Owner model | Topic | Auth-visible symptom |
| --- | --- | --- |
| deferred — see `../07-oauth-sso-integrations/` | OAuth/OIDC protocol depth (redirect_uri registration, PKCE, JWKS/kid handling, iss+sub linking, consent) | Auth-visible symptom here: callback failure reasons in R15 (invalid_callback, provider_verification) and link refusals in R16. |
| deferred — see `../08-admin-support-tools/` | Admin impersonation, break-glass accounts, support tooling | None exists in code. Auth-visible symptom: role changes and mass changes by one admin (R21). |
| deferred — see `../04-xss-csrf-cors/` | Cookie prefixes/scope, CORS on session endpoints, clickjacking | __Host- prefix, frame-ancestors none and X-Frame-Options are present. Auth-visible symptom: CSRF-rejected mutations (R04). |
| deferred — see `../02-authorization/` | Where authorization is enforced, role-field mass assignment, method override | requireRole on every privileged route. The app’s authorization.denied audit rows are not exported to SecureNow by this model. |
| deferred — see `../14-api-security/` | Web cache deception, generic parameter pollution | API responses are Cache-Control: no-store (src/app.js:66); duplicate query parameters fail the string checks in the Google callback. |
| deferred — see `../11-messaging-notifications/` | Email/SMS transport, sender spoofing, deliverability | No auth messages are sent today. Email verification (F4) and owner notifications (F5) will introduce them — re-run this model’s E-section then. |
| deferred — see `../26-secrets-and-api-key-hygiene/` | Secrets in URLs, key hygiene and rotation | Google state appears in the callback URL (single-use); runtime-key rotation is listed in M61; bootstrap admin secret in F12. |
| deferred — see `../12-rate-limits-and-abuse/` | CAPTCHA/challenge bypass, generic rate-limit evasion | Auth-visible symptoms: post-limit requests (R02) and per-network spread (R06). |


<a id="findings"></a>
## 6. Code-level findings (audit)

| # | Location (file:line) | Threat | OWASP/CWE | Sev | Issue | Recommended fix |
| --- | --- | --- | --- | --- | --- | --- |
| [F1](#finding-f1) | `src/app.js:150-155` | [J47](authentication-detection-mitigation.md#threat-j47) | A04:2021 / CWE-770 | MEDIUM | Anonymous visitors create a PostgreSQL session row on every request, with no limit | Stop persisting anonymous sessions. |
| [F2](#finding-f2) | `src/app.js:104-106, 132-134, 279` | [S1](authentication-detection-mitigation.md#threat-s1) | A09:2021 / CWE-779 | MEDIUM | Rejected requests write unlimited audit rows and can push real events out of view | Record at most one rejection per (category, client) per window: in `limit()`, log `auth.rate_limited` only when `rows[0].count === maximum + 1`; in the CSRF guard, run the existing `limit()` helper as `limit('csrf-reject-ip', 20)` before writing `csrf.rejected`, and log only the first rejection in each window. |
| [F3](#finding-f3) | `src/app.js:124-131, 173` | [H41](authentication-detection-mitigation.md#threat-h41) | A07:2021 / CWE-645 | MEDIUM | Anyone who knows an email can keep that member locked out | Use the OWASP “device cookie” pattern: after a successful sign-in, set a long-lived signed `__Host-lab_device` cookie (random ID + HMAC). |
| [F4](#finding-f4) | `src/app.js:164-171, 247-250; db/001_initial.sql:7; public/app.js:356` | [G36c](authentication-detection-mitigation.md#threat-g36c) | A07:2021 / CWE-287 | MEDIUM | No email-ownership check: squatted addresses, Google lock-out and an enumeration oracle | Make password registrations pending until a one-time link is clicked: store only a SHA-256 hash of a 32-byte random token with a 30-minute expiry, single use, bound to user + purpose + address; refuse sign-in for pending accounts; for an already-registered address, send a “someone tried to register” notice instead of a second account. |
| [F5](#finding-f5) | `src/app.js:291-299` | [L54a](authentication-detection-mitigation.md#threat-l54a) | A07:2021 / CWE-306 | MEDIUM | No second factor, no step-up for admin role changes, no security-change notices | Step-up (AUTH-14): add `POST /api/auth/reauth` that verifies the current password and sets `req.session.reauthAt`; reject role changes unless `Date.now() - req.session.reauthAt < 5 * 60_000` (Google-only admins re-authenticate through Google with `prompt=login` / `max_age`). |
| [F6](#finding-f6) | `src/app.js:35, 173; node_modules/securenow/firewall.js:913-921` | [M62](authentication-detection-mitigation.md#threat-m62) | A07:2021 / CWE-290 | MEDIUM | Route aliases (`/API/AUTH/LOGIN`, trailing slash) slip past SecureNow route-scoped controls | Right after `const app = express();` add `app.set('case sensitive routing', true); app.set('strict routing', true);` (or an early middleware that 404s any `/api` path whose `req.path !== req.path.toLowerCase()` or ends with `/`). |
| [F7](#finding-f7) | `src/app.js:188-193, 277, 294` | [C11](authentication-detection-mitigation.md#threat-c11) | A07:2021 / CWE-613 | LOW | No “sign out everywhere”; Google-only members have no kill switch; admins cannot revoke a user’s sessions | Add `POST /api/auth/sessions/revoke-others` (increment `session_version`, then call `authenticate()` for the current request), show members their own sessions (split `/api/security` into “my sessions” for every signed-in user and “audit events” for analysts), and add an admin `POST /api/admin/users/:id/revoke-sessions` that increments `session_version`. |
| [F8](#finding-f8) | `src/passwords.js:5, 24` | [K49](authentication-detection-mitigation.md#threat-k49) | A02:2021 / CWE-916 | LOW | scrypt cost is about one third of the OWASP minimum and can never be upgraded | Parse N/r/p from the stored string and verify with those values; on a successful sign-in with outdated parameters, rehash with the new ones and update the row. |
| [F9](#finding-f9) | `src/app.js:164, 179, 197, 203` | [J46](authentication-detection-mitigation.md#threat-j46) | A04:2021 / CWE-405 | LOW | No bound on concurrent password hashing | Wrap `hashPassword`/`verifyPassword` in a small semaphore (for example 4 concurrent, queue of 50); when the queue is full, answer 503 with `Retry-After: 5` before hashing. |
| [F10](#finding-f10) | `src/passwords.js:7-10` | [A5a](authentication-detection-mitigation.md#threat-a5a) | A07:2021 / CWE-521 | LOW | Passwords are only length-checked: no breached-password screening, no Unicode normalization | At registration and password change, check the SHA-1 prefix against the Have I Been Pwned range API (k-anonymity; fail open with a log line if the API is down) and refuse matches. |
| [F11](#finding-f11) | `src/app.js:124-126` | [A4a](authentication-detection-mitigation.md#threat-a4a) | A07:2021 / CWE-307 | LOW | Rate-limit keys use the full IPv6 address and a fixed window | Key IPv6 clients by their /64 (and IPv4 by the full address), and count the current plus the previous window weighted by elapsed time (sliding-window approximation) using the existing `rate_buckets` rows. |
| [F12](#finding-f12) | `infra/update.sh:17, 28-34` | [A5](authentication-detection-mitigation.md#threat-a5) | A07:2021 / CWE-1392 | LOW | The bootstrap admin password stays in the runtime secret after first use | After the first successful bootstrap, overwrite `ADMIN_PASSWORD` in the runtime secret with an empty value (the seed already treats an existing admin as a no-op), and add a `must_change_password` flag that forces a password change on the bootstrap admin’s first sign-in. |
| [F13](#finding-f13) | `node_modules/securenow/tracing.js:602-606; docs/securenow-integration.md:32-48` | [D21](authentication-detection-mitigation.md#threat-d21) | A09:2021 / CWE-532 | LOW | SDK defaults would export more than the lab intends (request bodies, CSRF header, OAuth state) | Write `.securenow/credentials.json` (or the runtime file) with `capture.body=false`, `capture.multipart=false` and `runtime.deploymentEnvironment=test` before the first instrumented start, exactly as `docs/securenow-integration.md:30-51` describes, and verify with `npx securenow env --json`. |
| [F14](#finding-f14) | `infra/backup.sh:6; db/001_initial.sql:15-19; src/app.js:213` | [D21a](authentication-detection-mitigation.md#threat-d21a) | A02:2021 / CWE-312 | LOW | Daily backups contain live session IDs and in-flight Google transactions | Add `--exclude-table-data=sessions --exclude-table-data=rate_buckets` to the `pg_dump` command in `infra/backup.sh:6`; keep the table definitions. |
| [F15](#finding-f15) | `public/app.js:76-84; node_modules/securenow/firewall.js:1117-1133` | [M63](authentication-detection-mitigation.md#threat-m63) | A04:2021 / CWE-693 | LOW | The single-page app cannot complete a SecureNow challenge on API routes | In `api()`, when `response.headers.get('X-SecureNow-Challenge') === 'required'`, reload the page (`location.reload()`) so the HTML interstitial runs on the next GET (the clearance cookie is bound to IP + user agent, not to a route), then retry. |
| [F16](#finding-f16) | `src/app.js:287-289` | [H40](authentication-detection-mitigation.md#threat-h40) | A04:2021 / CWE-799 | LOW | The admin user list shows only the newest 100 accounts | Add `?cursor=` paging and an email/name search parameter to `/api/admin/users`, and a search box in `renderAdmin`. |

<a id="finding-f1"></a>
#### F1 · Anonymous visitors create a PostgreSQL session row on every request, with no limit
**MEDIUM** · `src/app.js:150-155` · A04:2021 · CWE-770 · [J47](authentication-detection-mitigation.md#threat-j47) · [R03](authentication-detection-mitigation.md#rule-r03) · [AUTH-06](#todo-auth-06)

```js
// src/app.js:150-155
 150    const sessionResponse = (req) => {
 151      req.session.csrfToken ||= csrf();
 152      return { user: req.user ? publicUser(req.user) : null, csrfToken: req.session.csrfToken, googleEnabled };
 153    };
 154    app.get(['/api/me', '/api/auth/session'], (req, res) => res.json(sessionResponse(req)));
 155    app.get('/api/auth/csrf', (req, res) => res.json({ csrfToken: sessionResponse(req).csrfToken }));
```

**In one sentence:** An attacker can loop `curl https://lab-auth.labs.securenow.ai/api/me` (no sign-in, no CSRF token needed) from a few machines and write millions of rows per hour, growing the database and its daily backup and slowing every session lookup for real users. Once the SDK preload runs, SecureNow sees each request and whether it carried a cookie (`http.request.headers`). The app must stop persisting sessions for anonymous visitors (a signed double-submit CSRF cookie instead).

- **What is wrong:** `GET /api/me`, `/api/auth/session` and `/api/auth/csrf` assign a CSRF token to anonymous sessions, which makes express-session persist a new row for every cookieless request. None of these routes is rate-limited. Each request without a cookie gets a brand-new session that is immediately saved to the `sessions` table (30-minute expiry, pruned every 15 minutes). A passive GET of `/api/me` on the live lab on 2026-10-16 returned a fresh `Set-Cookie: __Host-lab_auth=…`, confirming the write.
- **How an attacker could use it:** An attacker can loop `curl https://lab-auth.labs.securenow.ai/api/me` (no sign-in, no CSRF token needed) from a few machines and write millions of rows per hour, growing the database and its daily backup and slowing every session lookup for real users.
- **What SecureNow sees and detects:** Once the SDK preload runs, SecureNow sees each request and whether it carried a cookie (`http.request.headers`). Rule R03 alerts at 60 cookieless session requests per IP in 15 minutes and AUTO-C rate-limits those endpoints for that IP.
- **What SecureNow cannot fix:** SecureNow cannot stop the write itself or see a distributed version spread thinly over many IPs.
- **Exact recommended change (not applied):** Stop persisting anonymous sessions. Issue the pre-login CSRF token as a signed double-submit cookie instead: on anonymous GETs, set `__Host-lab_csrf=<nonce>.<HMAC(SESSION_SECRET, nonce)>` (HttpOnly, Secure, SameSite=Strict) and return the same value in the JSON; in the `/api` mutation guard (`src/app.js:102-110`), accept the request when the header equals the cookie and the HMAC verifies, and only then create the server session in `authenticate()`. Keep the per-session token after sign-in. Alternatively (smaller change): only call `sessionResponse()` for requests that already have a session, and rate-limit the three GET routes with the existing `limit('session-ip', 60)` helper.
- **Definition of done:** 65 cookieless `GET /api/me` against a local copy add 0 rows to `sessions`; sign-in, register and CSRF tests still pass.
- **Effort:** M · **TODO:** [AUTH-06](#todo-auth-06) (DO NOW)

<a id="finding-f2"></a>
#### F2 · Rejected requests write unlimited audit rows and can push real events out of view
**MEDIUM** · `src/app.js:104-106, 132-134, 279` · A09:2021 · CWE-779 · [S1](authentication-detection-mitigation.md#threat-s1) · [R04](authentication-detection-mitigation.md#rule-r04) · [R02](authentication-detection-mitigation.md#rule-r02) · [AUTH-07](#todo-auth-07)

```js
// src/app.js:104-106
 104      if (req.get('origin') !== config.appOrigin || req.get('sec-fetch-site') === 'cross-site' || !safeEqual(req.get('x-csrf-token'), req.session.csrfToken)) {
 105        await event(req, 'csrf.rejected', 'blocked');
 106        return fail(res, 403, 'CSRF_REJECTED', 'This request could not be verified. Refresh the page and try again.');

// src/app.js:132-134
 132      if (rows[0].count > maximum) {
 133        await event(req, 'auth.rate_limited', 'blocked', { category: name });
 134        res.setHeader('Retry-After', String(Math.ceil(config.rateWindowMs / 1000)));

// src/app.js:279
 279        pool.query('SELECT id,type,outcome,actor_id,request_id,metadata,created_at FROM security_events ORDER BY created_at DESC,id DESC LIMIT 100'),
```

**In one sentence:** An attacker can send a few hundred unauthenticated POSTs with no CSRF token (or keep hammering after a 429) to fill the audit table and bury the trail of their real sign-in attempts below the 100-row window that analysts see. SecureNow sees the 403/429 answers in traces. The app must log at most one rejection per client and category per window.

- **What is wrong:** Every CSRF-rejected API mutation and every request over a rate limit inserts a row into `security_events`, before and regardless of any limit. The Security page reads only the newest 100 rows. The cost of rejecting a request is a database insert, and there is no cap. Rows are kept for 14 days (`src/server.js:13`).
- **How an attacker could use it:** An attacker can send a few hundred unauthenticated POSTs with no CSRF token (or keep hammering after a 429) to fill the audit table and bury the trail of their real sign-in attempts below the 100-row window that analysts see.
- **What SecureNow sees and detects:** SecureNow sees the 403/429 answers in traces. R04 and R02 alert per IP; AUTO-D / AUTO-A rate-limit the source. SecureNow’s own copy of the traces keeps the evidence even when the app’s view is flooded.
- **What SecureNow cannot fix:** SecureNow cannot change what the app writes to its own table.
- **Exact recommended change (not applied):** Record at most one rejection per (category, client) per window: in `limit()`, log `auth.rate_limited` only when `rows[0].count === maximum + 1`; in the CSRF guard, run the existing `limit()` helper as `limit('csrf-reject-ip', 20)` before writing `csrf.rejected`, and log only the first rejection in each window. Add type filtering and paging to `/api/security` so a flood of one type cannot hide another.
- **Definition of done:** 100 rejected requests from one client add at most 1 row per 15-minute window; the Security page can filter by event type.
- **Effort:** S · **TODO:** [AUTH-07](#todo-auth-07) (DO NOW)

<a id="finding-f3"></a>
#### F3 · Anyone who knows an email can keep that member locked out
**MEDIUM** · `src/app.js:124-131, 173` · A07:2021 · CWE-645 · [H41](authentication-detection-mitigation.md#threat-h41) · [R14](authentication-detection-mitigation.md#rule-r14) · [R11](authentication-detection-mitigation.md#rule-r11) · [AUTH-13](#todo-auth-13)

```js
// src/app.js:124-131
 124    const limit = (name, maximum, account = false) => async (req, res, next) => {
 125      const identifier = account ? normalizeEmail(req.body?.email) : req.ip;
 126      const windowStart = Math.floor(Date.now() / config.rateWindowMs);
 127      const { rows } = await pool.query(
 128        `INSERT INTO rate_buckets(key,window_start,count) VALUES($1,$2,1)
 129         ON CONFLICT(key,window_start) DO UPDATE SET count=rate_buckets.count+1 RETURNING count`,
 130        [`${name}:${hash(identifier)}`, windowStart],
 131      );

// src/app.js:173
 173    app.post('/api/auth/login', limit('login-ip', config.authRateLimit), limit('login-account', config.authRateLimit * 2, true), async (req, res) => {
```

**In one sentence:** An attacker can lock any member who signs in with a password out of the lab indefinitely, with about two requests per minute from three addresses — no password knowledge needed. After the event bridge exports `api.ratelimit.exceeded` with a keyed `account_ref`, R14 detects one account’s bucket held full by 2+ IPs; R11 sees the failures. The app must stop counting the owner’s own attempts from a known browser (device-trust cookie).

- **What is wrong:** The per-account bucket (30 attempts per 15 minutes) counts every request for that email before the password is checked, including the owner’s correct attempts. There is no bypass for the owner and no notification. The same counter that slows an attacker also rejects the real member. Spreading 31 requests over 3 IPs (each IP is capped at 15) is enough to hold an account at 429 for the whole window, and the attacker can repeat it every 15 minutes.
- **How an attacker could use it:** An attacker can lock any member who signs in with a password out of the lab indefinitely, with about two requests per minute from three addresses — no password knowledge needed.
- **What SecureNow sees and detects:** After the event bridge exports `api.ratelimit.exceeded` with a keyed `account_ref`, R14 detects one account’s bucket held full by 2+ IPs; R11 sees the failures. A person can then rate-limit or challenge the contributing IPs.
- **What SecureNow cannot fix:** SecureNow has no per-account quota and cannot tell the app to let the owner through.
- **Exact recommended change (not applied):** Use the OWASP “device cookie” pattern: after a successful sign-in, set a long-lived signed `__Host-lab_device` cookie (random ID + HMAC). In the account limiter, skip (or use a much higher limit for) requests that present a valid device cookie previously used by that account, and increment the account bucket only on failed verification rather than on every request. Keep the per-IP limit for everyone. Emit `api.ratelimit.exceeded` with `scope` and `account_ref` so R14 works.
- **Definition of done:** With an attacker holding the account bucket full from 3 IPs, the owner signs in successfully from their usual browser; a new browser still gets 429.
- **Effort:** M · **TODO:** [AUTH-13](#todo-auth-13) (NEXT 7 DAYS)

<a id="finding-f4"></a>
#### F4 · No email-ownership check: squatted addresses, Google lock-out and an enumeration oracle
**MEDIUM** · `src/app.js:164-171, 247-250; db/001_initial.sql:7; public/app.js:356` · A07:2021 · CWE-287 · [G36c](authentication-detection-mitigation.md#threat-g36c) · [R23](authentication-detection-mitigation.md#rule-r23) · [R16](authentication-detection-mitigation.md#rule-r16) · [AUTH-18](#todo-auth-18)

```js
// src/app.js:164-171
 164      const passwordHash = await hashPassword(req.body.password);
 165      const result = await pool.query(
 166        'INSERT INTO users(id,email,name,password_hash) VALUES($1,$2,$3,$4) ON CONFLICT(email) DO NOTHING RETURNING id',
 167        [randomUUID(), email, name, passwordHash],
 168      );
 169      // The response is identical for existing addresses and successful registration.
 170      await event(req, 'auth.registration_requested', 'success', {}, result.rows[0]?.id || null);
 171      res.status(201).json({ user: null, csrfToken: req.session.csrfToken, message: 'If this address can be registered, your account is ready. Sign in to continue.' });

// src/app.js:247-250
 247          if (!user) {
 248            // Email is never sufficient proof for silently linking an existing password identity.
 249            await event(req, 'auth.google_failed', 'failure', { reason: 'identity_conflict' });
 250            return res.redirect('/?auth_error=account_exists');
```

**In one sentence:** An attacker can pre-register colleagues’ or a target’s addresses to block their Google sign-in, appear under their name in the admin list, and quietly test which addresses already have accounts. With the bridge, R23 sees registrations on existing emails and account farming per IP, and R16 sees Google link refusals per IP and app-wide. The app must verify email ownership and let a verified Google sign-in reclaim a squatted address.

- **What is wrong:** Password registration activates the account immediately with `email_verified=false`, and nothing ever reads that flag. A later Google sign-in for the same address is refused, and there is no recovery flow. Whoever registers an address first owns it forever. The real owner who later clicks “Sign in with Google” is told to use a password they never set. The uniform registration response is undone by register-then-sign-in: if the attacker’s password works, the address was free.
- **How an attacker could use it:** An attacker can pre-register colleagues’ or a target’s addresses to block their Google sign-in, appear under their name in the admin list, and quietly test which addresses already have accounts.
- **What SecureNow sees and detects:** With the bridge, R23 sees registrations on existing emails and account farming per IP, and R16 sees Google link refusals per IP and app-wide.
- **What SecureNow cannot fix:** SecureNow cannot prove who owns a mailbox or move an identity between accounts.
- **Exact recommended change (not applied):** Make password registrations pending until a one-time link is clicked: store only a SHA-256 hash of a 32-byte random token with a 30-minute expiry, single use, bound to user + purpose + address; refuse sign-in for pending accounts; for an already-registered address, send a “someone tried to register” notice instead of a second account. Let a verified Google identity for the same normalized address reclaim a still-pending (unverified) password account — never the reverse. Normalize emails with NFKC before lower-casing. Sending email adds an auth-message channel: apply the per-target/per-IP/global send limits from the E-section of this model before shipping.
- **Definition of done:** An unverified account cannot sign in; a Google sign-in for its address replaces it; register-then-sign-in no longer reveals existence.
- **Effort:** L · **TODO:** [AUTH-18](#todo-auth-18) (LATER / HARDENING)

<a id="finding-f5"></a>
#### F5 · No second factor, no step-up for admin role changes, no security-change notices
**MEDIUM** · `src/app.js:291-299` · A07:2021 · CWE-306 · [L54a](authentication-detection-mitigation.md#threat-l54a) · [R21](authentication-detection-mitigation.md#rule-r21) · [R20](authentication-detection-mitigation.md#rule-r20) · [R19](authentication-detection-mitigation.md#rule-r19) · [AUTH-14](#todo-auth-14)

```js
// src/app.js:291-294
 291    app.patch(['/api/admin/users/:id', '/api/admin/users/:id/role'], requireRole('admin'), async (req, res) => {
 292      if (!/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i.test(req.params.id) || !roles.has(req.body?.role)) return fail(res, 400, 'INVALID_INPUT', 'Choose member, analyst, or admin.');
 293      if (req.params.id === req.user.id && req.body.role !== 'admin') return fail(res, 409, 'SELF_DEMOTION', 'Ask another administrator to change your role.');
 294      const { rows } = await pool.query('UPDATE users SET role=$1,session_version=session_version+CASE WHEN role<>$1 THEN 1 ELSE 0 END,updated_at=CASE WHEN role<>$1 THEN now() ELSE updated_at END WHERE id=$2 RETURNING *', [req.body.role, req.params.id]);
```

**In one sentence:** An attacker who steals or phishes an admin session can promote their own throwaway account to admin within seconds and keep access after the stolen session expires. With the bridge, R21 alerts on every privilege elevation and on one admin changing 3+ accounts; R20 alerts when the change comes from a different IP than the sign-in; R19 catches failures → sign-in → change. The app must require recent re-authentication for role changes, then add MFA and change notices.

- **What is wrong:** Promoting any account to admin requires only an admin session and the CSRF token. No role has a second factor, and neither password nor role changes notify anyone. A stolen admin session (valid up to 8 hours) is enough to create more admins silently. Members are never told that their password or role changed.
- **How an attacker could use it:** An attacker who steals or phishes an admin session can promote their own throwaway account to admin within seconds and keep access after the stolen session expires.
- **What SecureNow sees and detects:** With the bridge, R21 alerts on every privilege elevation and on one admin changing 3+ accounts; R20 alerts when the change comes from a different IP than the sign-in; R19 catches failures → sign-in → change.
- **What SecureNow cannot fix:** SecureNow cannot require re-authentication or a second factor, and cannot notify the user.
- **Exact recommended change (not applied):** Step-up (AUTH-14): add `POST /api/auth/reauth` that verifies the current password and sets `req.session.reauthAt`; reject role changes unless `Date.now() - req.session.reauthAt < 5 * 60_000` (Google-only admins re-authenticate through Google with `prompt=login` / `max_age`). MFA (AUTH-19): passkeys (WebAuthn) or TOTP for admin and analyst first. Notifications (AUTH-19): email the affected user and the other admins on role changes and password changes once a mail channel exists.
- **Definition of done:** A role change without re-auth in the last 5 minutes returns 403; with it, 200 and an `auth.security.change` event with `step_up=true`.
- **Effort:** M · **TODO:** [AUTH-14](#todo-auth-14) (NEXT 7 DAYS)

<a id="finding-f6"></a>
#### F6 · Route aliases (`/API/AUTH/LOGIN`, trailing slash) slip past SecureNow route-scoped controls
**MEDIUM** · `src/app.js:35, 173; node_modules/securenow/firewall.js:913-921` · A07:2021 · CWE-290 · [M62](authentication-detection-mitigation.md#threat-m62) · [R01](authentication-detection-mitigation.md#rule-r01) · [R06](authentication-detection-mitigation.md#rule-r06) · [AUTH-08](#todo-auth-08)

```js
// src/app.js:35
  35    const app = express();

// node_modules/securenow/firewall.js:913-921
 913  
 914  function rulePathMatches(rule, path) {
 915    const pattern = String(rule.pathPattern || '').trim();
 916    if (!pattern) return true;
 917    const mode = rule.pathMatchMode || 'prefix';
 918    if (mode === 'exact') return path === pattern;
 919    if (mode === 'regex') {
 920      try { return new RegExp(pattern).test(path); } catch (_) { return false; }
 921    }
```

**In one sentence:** An attacker who gets rate-limited by SecureNow on `/api/auth/login` can continue guessing at `/Api/auth/login` (still capped by the app’s 15-per-15-minutes limit). All traffic rules in this report lowercase the path and trim trailing slashes, so detection still works. The app must turn on strict, case-sensitive routing so aliases return 404.

- **What is wrong:** Express 5 routes paths case-insensitively and ignores a trailing slash by default, while the SecureNow SDK firewall compares paths exactly and case-sensitively. A rate limit, block or challenge for `/api/auth/login` does not match `/API/AUTH/LOGIN` or `/api/auth/login/`, yet the app answers them. Every edge mitigation written for the exact path can be sidestepped by changing letter case. The app’s own limiter is not affected (it keys by name, not by path), and the repo’s smoke test even relies on `/API/ME` working.
- **How an attacker could use it:** An attacker who gets rate-limited by SecureNow on `/api/auth/login` can continue guessing at `/Api/auth/login` (still capped by the app’s 15-per-15-minutes limit).
- **What SecureNow sees and detects:** All traffic rules in this report lowercase the path and trim trailing slashes, so detection still works. The mitigations in this report use case-insensitive regex patterns until this is fixed.
- **What SecureNow cannot fix:** SecureNow’s firewall has no option to normalize paths (feature request in the detection report).
- **Exact recommended change (not applied):** Right after `const app = express();` add `app.set('case sensitive routing', true); app.set('strict routing', true);` (or an early middleware that 404s any `/api` path whose `req.path !== req.path.toLowerCase()` or ends with `/`). Update `scripts/smoke.mjs:37` to expect 404 for `/API/ME`, and keep the `Cache-Control` check at `src/app.js:66` lower-casing as defense in depth.
- **Definition of done:** `POST /API/AUTH/LOGIN` and `POST /api/auth/login/` return 404; normal routes unchanged; SecureNow mitigations can switch to `--mode exact`.
- **Effort:** S · **TODO:** [AUTH-08](#todo-auth-08) (DO NOW)

<a id="finding-f7"></a>
#### F7 · No “sign out everywhere”; Google-only members have no kill switch; admins cannot revoke a user’s sessions
**LOW** · `src/app.js:188-193, 277, 294` · A07:2021 · CWE-613 · [C11](authentication-detection-mitigation.md#threat-c11) · [R17](authentication-detection-mitigation.md#rule-r17) · [R18](authentication-detection-mitigation.md#rule-r18) · [AUTH-20](#todo-auth-20)

```js
// src/app.js:188-193
 188    app.post('/api/auth/logout', async (req, res) => {
 189      if (req.user) await event(req, 'auth.logout', 'success');
 190      await destroySession(req);
 191      res.clearCookie(cookieName, { path: '/', secure: config.production, httpOnly: true, sameSite: 'lax' });
 192      res.json({ ok: true });
 193    });

// src/app.js:294
 294      const { rows } = await pool.query('UPDATE users SET role=$1,session_version=session_version+CASE WHEN role<>$1 THEN 1 ELSE 0 END,updated_at=CASE WHEN role<>$1 THEN now() ELSE updated_at END WHERE id=$2 RETURNING *', [req.body.role, req.params.id]);
```

**In one sentence:** An attacker with a stolen Google-member session keeps it for the rest of the 8-hour window even after the victim notices. With `guard()` wired, `npx securenow revoke user <enduser.id>` would end every session of that user on the next request (see the CLI 404 caveat in the detection report). The app must add sign-out-everywhere, a members’ own-sessions view and an admin revoke action.

- **What is wrong:** Logout destroys only the current session; members cannot see their own sessions (the Security page needs analyst); the only server-side kill switches are a password change or an admin changing the user’s role. A Google-only member has no password to change, so a stolen session lives until it expires (up to 8 hours). An admin who suspects an account cannot end its sessions without changing its role.
- **How an attacker could use it:** An attacker with a stolen Google-member session keeps it for the rest of the 8-hour window even after the victim notices.
- **What SecureNow sees and detects:** With `guard()` wired, `npx securenow revoke user <enduser.id>` would end every session of that user on the next request (see the CLI 404 caveat in the detection report).
- **What SecureNow cannot fix:** SecureNow revocation only works where the guard runs, fails open, and is manual.
- **Exact recommended change (not applied):** Add `POST /api/auth/sessions/revoke-others` (increment `session_version`, then call `authenticate()` for the current request), show members their own sessions (split `/api/security` into “my sessions” for every signed-in user and “audit events” for analysts), and add an admin `POST /api/admin/users/:id/revoke-sessions` that increments `session_version`. Wire `securenow/sessions` `guard()` as shown in the instrumentation section.
- **Definition of done:** Each of the three actions makes another browser’s session return 401 on its next request.
- **Effort:** M · **TODO:** [AUTH-20](#todo-auth-20) (LATER / HARDENING)

<a id="finding-f8"></a>
#### F8 · scrypt cost is about one third of the OWASP minimum and can never be upgraded
**LOW** · `src/passwords.js:5, 24` · A02:2021 · CWE-916 · [K49](authentication-detection-mitigation.md#threat-k49) · [AUTH-21](#todo-auth-21)

```js
// src/passwords.js:5
   5  const parameters = { N: 32768, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };

// src/passwords.js:21-24
  21  export async function verifyPassword(password, stored) {
  22    const encoded = stored || await dummyHashPromise;
  23    const [algorithm, n, r, p, salt, expected] = encoded.split('$');
  24    if (algorithm !== 'scrypt' || n !== '32768' || r !== '8' || p !== '1' || !/^[a-f0-9]{32}$/.test(salt) || !/^[a-f0-9]{128}$/.test(expected)) return false;
```

**In one sentence:** An attacker with a database backup can test roughly three times as many guesses per second as with OWASP-minimum hashes. SecureNow sees nothing that reveals it. The app must store parameters per hash, raise the cost and rehash on sign-in.

- **What is wrong:** Parameters are N=32768, r=8, p=1. OWASP’s minimum for scrypt is N=2^17, r=8, p=1 (or an equivalent such as N=2^15, r=8, p=3). `verifyPassword` rejects any hash whose parameters differ, so no migration path exists. Stolen hashes are cheaper to attack than current guidance intends, and raising the cost later would lock every existing user out.
- **How an attacker could use it:** An attacker with a database backup can test roughly three times as many guesses per second as with OWASP-minimum hashes.
- **What SecureNow sees and detects:** Nothing — hashing never appears in traffic.
- **What SecureNow cannot fix:** SecureNow cannot inspect stored hashes.
- **Exact recommended change (not applied):** Parse N/r/p from the stored string and verify with those values; on a successful sign-in with outdated parameters, rehash with the new ones and update the row. Use N=32768, r=8, p=3 (same 32 MiB memory, 3× CPU) or move to Argon2id (m=19 MiB, t=2, p=1). Pair with F9 so the higher cost cannot be used to exhaust the server.
- **Definition of done:** Old hashes still verify; after sign-in the stored hash carries the new parameters.
- **Effort:** S · **TODO:** [AUTH-21](#todo-auth-21) (LATER / HARDENING)

<a id="finding-f9"></a>
#### F9 · No bound on concurrent password hashing
**LOW** · `src/app.js:164, 179, 197, 203` · A04:2021 · CWE-405 · [J46](authentication-detection-mitigation.md#threat-j46) · [R07](authentication-detection-mitigation.md#rule-r07) · [AUTH-21](#todo-auth-21)

```js
// src/app.js:179
 179      const valid = await verifyPassword(password, user?.password_hash);

// src/passwords.js:12-15
  12  export async function hashPassword(password) {
  13    const salt = randomBytes(16).toString('hex');
  14    const hash = await scrypt(password, salt, 64, parameters);
  15    return `scrypt$32768$8$1$${salt}$${hash.toString('hex')}`;
```

**In one sentence:** An attacker with a few hundred addresses can make sign-in time out for real users. R07 alerts on app-wide hashing volume or p95 latency and lists the top IPs. The app must cap concurrent hashes and answer 503 when the queue is full.

- **What is wrong:** Every sign-in, registration and password change runs a 32 MiB scrypt hash on Node’s 4-thread pool with no queue limit. Per-IP limits do not bound the total. Many IPs each staying under their limits can still saturate the thread pool (which DNS lookups also use) and make sign-in slow for everyone.
- **How an attacker could use it:** An attacker with a few hundred addresses can make sign-in time out for real users.
- **What SecureNow sees and detects:** R07 alerts on app-wide hashing volume or p95 latency and lists the top IPs.
- **What SecureNow cannot fix:** SecureNow cannot queue or shed the app’s hashing work.
- **Exact recommended change (not applied):** Wrap `hashPassword`/`verifyPassword` in a small semaphore (for example 4 concurrent, queue of 50); when the queue is full, answer 503 with `Retry-After: 5` before hashing. Optionally raise `UV_THREADPOOL_SIZE` to 8 with matching container memory.
- **Definition of done:** A local burst of 200 parallel sign-ins returns some 503s quickly instead of timing out; normal sign-in latency is unchanged.
- **Effort:** S · **TODO:** [AUTH-21](#todo-auth-21) (LATER / HARDENING)

<a id="finding-f10"></a>
#### F10 · Passwords are only length-checked: no breached-password screening, no Unicode normalization
**LOW** · `src/passwords.js:7-10` · A07:2021 · CWE-521 · [A5a](authentication-detection-mitigation.md#threat-a5a) · [R10](authentication-detection-mitigation.md#rule-r10) · [AUTH-22](#todo-auth-22)

```js
// src/passwords.js:7-10
   7  export function passwordProblem(password) {
   8    if (typeof password !== 'string' || password.length < 12 || password.length > 128) return 'Use a password containing 12–128 characters.';
   9    return null;
  10  }
```

**In one sentence:** An attacker spraying “Password1234” or replaying breached pairs succeeds for every member who picked one. With the bridge, R10 sees one IP failing across many accounts. The app must refuse breached passwords and normalize Unicode before hashing.

- **What is wrong:** Any 12–128 character string is accepted, including well-known breached passwords. Passwords are hashed as typed, so the same password entered as NFC on one device and NFD on another fails. Reused and sprayed passwords succeed; some users are locked out by their keyboard.
- **How an attacker could use it:** An attacker spraying “Password1234” or replaying breached pairs succeeds for every member who picked one.
- **What SecureNow sees and detects:** With the bridge, R10 sees one IP failing across many accounts.
- **What SecureNow cannot fix:** SecureNow never sees passwords and cannot judge them.
- **Exact recommended change (not applied):** At registration and password change, check the SHA-1 prefix against the Have I Been Pwned range API (k-anonymity; fail open with a log line if the API is down) and refuse matches. Normalize with `password.normalize('NFC')` before hashing; on sign-in, try the normalized form first and the raw form for hashes created before the change, then rehash.
- **Definition of done:** Registering a known-breached password fails with a clear message; an NFD-typed password signs in.
- **Effort:** S · **TODO:** [AUTH-22](#todo-auth-22) (LATER / HARDENING)

<a id="finding-f11"></a>
#### F11 · Rate-limit keys use the full IPv6 address and a fixed window
**LOW** · `src/app.js:124-126` · A07:2021 · CWE-307 · [A4a](authentication-detection-mitigation.md#threat-a4a) · [R06](authentication-detection-mitigation.md#rule-r06) · [AUTH-23](#todo-auth-23)

```js
// src/app.js:124-126
 124    const limit = (name, maximum, account = false) => async (req, res, next) => {
 125      const identifier = account ? normalizeEmail(req.body?.email) : req.ip;
 126      const windowStart = Math.floor(Date.now() / config.rateWindowMs);
```

**In one sentence:** An attacker on IPv6 can get thousands of fresh per-IP buckets from one connection. R06 groups failures by /64 and /24. The app must key IPv6 clients by /64 and smooth the rate-limit window.

- **What is wrong:** An IPv6 client usually controls a whole /64 and can rotate addresses for fresh 15-attempt buckets. The fixed 15-minute window allows 30 attempts in about a minute around the boundary. The per-IP limit is weaker than it looks for IPv6 clients.
- **How an attacker could use it:** An attacker on IPv6 can get thousands of fresh per-IP buckets from one connection.
- **What SecureNow sees and detects:** R06 groups failures by /64 and /24.
- **What SecureNow cannot fix:** SecureNow cannot change the app’s keys.
- **Exact recommended change (not applied):** Key IPv6 clients by their /64 (and IPv4 by the full address), and count the current plus the previous window weighted by elapsed time (sliding-window approximation) using the existing `rate_buckets` rows.
- **Definition of done:** Two addresses in one /64 share a bucket in a unit test; 30 attempts across a boundary are refused after 15.
- **Effort:** S · **TODO:** [AUTH-23](#todo-auth-23) (LATER / HARDENING)

<a id="finding-f12"></a>
#### F12 · The bootstrap admin password stays in the runtime secret after first use
**LOW** · `infra/update.sh:17, 28-34` · A07:2021 · CWE-1392 · [A5](authentication-detection-mitigation.md#threat-a5) · [AUTH-24](#todo-auth-24)

```bash
// infra/update.sh:28-34
  28  docker compose -f compose.production.yaml run --rm app npm run migrate
  29  docker compose -f compose.production.yaml run --rm app npm run seed
  30  python3 - <<'PY'
  31  from pathlib import Path
  32  p=Path('/etc/lab-auth/app.env')
  33  p.write_text(''.join(line+'\n' for line in p.read_text().splitlines() if not line.startswith(('ADMIN_PASSWORD=','ADMIN_EMAIL='))))
  34  PY
```

**In one sentence:** An attacker who obtains the instance role (for example through a future server-side bug) can read the secret and sign in as the lab admin. SecureNow sees nothing that reveals it. The app must remove the bootstrap password from the runtime secret and force a first-login change.

- **What is wrong:** Every deploy reads `ADMIN_PASSWORD` from AWS Secrets Manager, runs the seed, and strips it from the container environment — but the secret itself keeps it, and the instance role can read the secret. If the operator did not change the admin password after first sign-in (the docs ask them to), the value in the secret is a working admin credential for as long as the lab exists.
- **How an attacker could use it:** An attacker who obtains the instance role (for example through a future server-side bug) can read the secret and sign in as the lab admin.
- **What SecureNow sees and detects:** Nothing until the password is used; then R13/R27 may notice an unusual admin sign-in.
- **What SecureNow cannot fix:** SecureNow cannot see AWS secrets.
- **Exact recommended change (not applied):** After the first successful bootstrap, overwrite `ADMIN_PASSWORD` in the runtime secret with an empty value (the seed already treats an existing admin as a no-op), and add a `must_change_password` flag that forces a password change on the bootstrap admin’s first sign-in.
- **Definition of done:** The runtime secret has no usable ADMIN_PASSWORD; first admin sign-in forces a change.
- **Effort:** S · **TODO:** [AUTH-24](#todo-auth-24) (LATER / HARDENING)

<a id="finding-f13"></a>
#### F13 · SDK defaults would export more than the lab intends (request bodies, CSRF header, OAuth state)
**LOW** · `node_modules/securenow/tracing.js:602-606; docs/securenow-integration.md:32-48` · A09:2021 · CWE-532 · [D21](authentication-detection-mitigation.md#threat-d21) · [AUTH-01](#todo-auth-01)

```js
// node_modules/securenow/tracing.js:602-606
 602          const SKIP_HEADERS = new Set(['cookie', 'authorization', 'proxy-authorization', 'set-cookie', 'x-api-key', 'x-auth-token']);
 603          const safe = {};
 604          for (const [k, v] of Object.entries(request.headers)) {
 605            if (SKIP_HEADERS.has(k.toLowerCase()) || matchesSensitiveField(k, OTP_SENSITIVE_FIELDS)) { safe[k] = '[REDACTED]'; continue; }
 606            safe[k] = redactOtpQuery(typeof v === 'string' ? v : String(v)).substring(0, 500);
```

**In one sentence:** A person with telemetry access could read CSRF tokens (useless without the cookie) and registrants’ names. SecureNow sees nothing that reveals it. The app must turn body and multipart capture off before the first instrumented start.

- **What is wrong:** `npx securenow env` resolves `captureBody: true` and `captureMultipart: true` with no runtime file. The tracer records request headers as JSON and redacts only cookie/authorization/proxy-authorization/set-cookie/x-api-key/x-auth-token and OTP-like names, so `x-csrf-token` is exported; the Google callback `state` stays in `http.target` (`code` is redacted). The runbook’s `sensitiveFields` list applies to bodies, not headers. If the SDK is started before the runtime file is written, registration names and CSRF tokens land in telemetry.
- **How an attacker could use it:** A person with telemetry access could read CSRF tokens (useless without the cookie) and registrants’ names.
- **What SecureNow sees and detects:** —
- **What SecureNow cannot fix:** The SDK has no header-redaction setting today (feature request).
- **Exact recommended change (not applied):** Write `.securenow/credentials.json` (or the runtime file) with `capture.body=false`, `capture.multipart=false` and `runtime.deploymentEnvironment=test` before the first instrumented start, exactly as `docs/securenow-integration.md:30-51` describes, and verify with `npx securenow env --json`.
- **Definition of done:** `npx securenow env --json` shows `captureBody: false`; a sample trace contains no `http.request.body`.
- **Effort:** S · **TODO:** [AUTH-01](#todo-auth-01) (DO NOW)

<a id="finding-f14"></a>
#### F14 · Daily backups contain live session IDs and in-flight Google transactions
**LOW** · `infra/backup.sh:6; db/001_initial.sql:15-19; src/app.js:213` · A02:2021 · CWE-312 · [D21a](authentication-detection-mitigation.md#threat-d21a) · [AUTH-25](#todo-auth-25)

```text
// db/001_initial.sql:15-19
  15  CREATE TABLE IF NOT EXISTS sessions (
  16    sid varchar NOT NULL PRIMARY KEY,
  17    sess json NOT NULL,
  18    expire timestamptz NOT NULL
  19  );

// src/app.js:213
 213      req.session.oauth = { state: csrf(), nonce: csrf(), verifier: codes.codeVerifier, createdAt: Date.now() };
```

**In one sentence:** An attacker who obtains a backup and the session secret can hijack every session that was live at backup time. SecureNow sees nothing that reveals it. The app must leave session data out of database backups.

- **What is wrong:** The full `pg_dump` includes the `sessions` table: plaintext session IDs and, for anyone mid-Google-sign-in, the state, nonce and PKCE verifier. Backup readers get material they never need for recovery. (Forging a cookie still needs SESSION_SECRET, so this is defense in depth.)
- **How an attacker could use it:** An attacker who obtains a backup and the session secret can hijack every session that was live at backup time.
- **What SecureNow sees and detects:** Nothing.
- **What SecureNow cannot fix:** SecureNow cannot see backups.
- **Exact recommended change (not applied):** Add `--exclude-table-data=sessions --exclude-table-data=rate_buckets` to the `pg_dump` command in `infra/backup.sh:6`; keep the table definitions.
- **Definition of done:** A restore drill shows empty `sessions` and `rate_buckets` tables and intact users.
- **Effort:** S · **TODO:** [AUTH-25](#todo-auth-25) (LATER / HARDENING)

<a id="finding-f15"></a>
#### F15 · The single-page app cannot complete a SecureNow challenge on API routes
**LOW** · `public/app.js:76-84; node_modules/securenow/firewall.js:1117-1133` · A04:2021 · CWE-693 · [M63](authentication-detection-mitigation.md#threat-m63) · [R05](authentication-detection-mitigation.md#rule-r05) · [AUTH-15](#todo-auth-15)

```js
// public/app.js:76-84
  76    if (!response.ok) {
  77      if (response.status === 401 && state.user && data.error?.code === 'AUTH_REQUIRED') {
  78        state.user = null;
  79        state.dashboard = null;
  80        const session = await fetch('/api/me', { credentials: 'same-origin' }).then(r => r.json()).catch(() => null);
  81        if (session?.csrfToken) state.csrfToken = session.csrfToken;
  82        renderAuth('login', 'Your session has ended. Sign in to continue.');
  83      }
  84      throw Object.assign(new Error(data.error?.message || 'Something went wrong. Please try again.'), { status: response.status, code: data.error?.code });
```

**In one sentence:** Not an attacker path — a safety issue: an automated challenge response becomes self-inflicted denial of service. SecureNow sees nothing that reveals it. The app must reload the page when SecureNow answers with a challenge so the browser can solve it.

- **What is wrong:** For `fetch()` requests the SDK answers a challenge with JSON 403 `{"error":"challenge_required",…}` and header `X-SecureNow-Challenge: required`. The SPA treats any error without `error.message` as “Something went wrong. Please try again.” A challenge rule on `/api/auth` would silently stop real users from signing in instead of asking their browser to solve the puzzle.
- **How an attacker could use it:** Not an attacker path — a safety issue: an automated challenge response becomes self-inflicted denial of service.
- **What SecureNow sees and detects:** —
- **What SecureNow cannot fix:** The SDK cannot solve the challenge on behalf of a JSON client.
- **Exact recommended change (not applied):** In `api()`, when `response.headers.get('X-SecureNow-Challenge') === 'required'`, reload the page (`location.reload()`) so the HTML interstitial runs on the next GET (the clearance cookie is bound to IP + user agent, not to a route), then retry. Until this ships, use rate limits (not challenges) on JSON routes — as this report does.
- **Definition of done:** With a challenge rule on `/api/auth` for a test IP, the browser shows the interstitial once and sign-in then succeeds.
- **Effort:** S · **TODO:** [AUTH-15](#todo-auth-15) (NEXT 7 DAYS)

<a id="finding-f16"></a>
#### F16 · The admin user list shows only the newest 100 accounts
**LOW** · `src/app.js:287-289` · A04:2021 · CWE-799 · [H40](authentication-detection-mitigation.md#threat-h40) · [R08](authentication-detection-mitigation.md#rule-r08) · [AUTH-29](#todo-auth-29)

```js
// src/app.js:287-289
 287    app.get('/api/admin/users', requireRole('admin'), async (_req, res) => {
 288      const { rows } = await pool.query('SELECT * FROM users ORDER BY created_at DESC LIMIT 100');
 289      res.json({ users: rows.map(publicUser) });
```

**In one sentence:** An attacker can create 100 accounts to push a specific member (or a suspicious account they control) out of the admin’s view. R08 alerts on the registration burst. The app must page and search the admin user list.

- **What is wrong:** `GET /api/admin/users` returns `ORDER BY created_at DESC LIMIT 100` with no paging or search. After a registration burst, older real accounts disappear from the only screen where an admin can change roles.
- **How an attacker could use it:** An attacker can create 100 accounts to push a specific member (or a suspicious account they control) out of the admin’s view.
- **What SecureNow sees and detects:** R08 alerts on the registration burst.
- **What SecureNow cannot fix:** SecureNow cannot page the app’s UI.
- **Exact recommended change (not applied):** Add `?cursor=` paging and an email/name search parameter to `/api/admin/users`, and a search box in `renderAdmin`.
- **Definition of done:** The admin can find and edit the 101st-newest account.
- **Effort:** S · **TODO:** [AUTH-29](#todo-auth-29) (LATER / HARDENING)


<a id="docs-vs-code"></a>
### Where the repository docs and the code (or the installed SDK) disagree

| Doc | Doc says | Code / SDK reality |
| --- | --- | --- |
| docs/securenow-integration.md:99 | SQL must “explicitly filter the observed deployment-environment field to test”. | Not done in these rules on purpose: the app key is used only by this lab, and the SDK’s default environment is `production` (`npx securenow env`). An environment filter would silently zero every rule if `runtime.deploymentEnvironment` were ever left unset. Add `AND resources_string['deployment.environment'] = 'test'` only after `telemetry fields` shows that value. |
| docs/securenow-integration.md:38-41 | `sensitiveFields` includes csrfToken, state, code, nonce… | Those names apply to captured bodies. Header capture redacts only a fixed list plus OTP-like names (`node_modules/securenow/tracing.js:602-606`), so the `x-csrf-token` header and the Google `state` query value are still recorded; `code` is redacted by the SDK’s OTP redactor. Keep body capture off (F13). |
| docs/securenow-integration.md:102 | `alerts rules validate --sql @auth-rule.sql --app YOUR_LAB_APP_KEY` before creating | In 8.12.0, `validate` needs an existing rule that covers the app to host the dry-run; for the first lab rule it fails with “No existing rule covers app”. The first `alerts rules create` validates itself (and rolls back on failure); later validates can use that rule’s ID. |
| docs/securenow-integration.md:127 | `blocklist add YOUR_TEST_PUBLIC_IP … --env test --reason …` | No `--duration`: the block is permanent until removed. Always add `--duration 24h` (or shorter) for exercises. |
| docs/securenow-integration.md:142 | `ratelimit add YOUR_TEST_PUBLIC_IP --route /api/auth/login --limit 2 --window 1m --duration 15m` | Without `--app` and `--env test`, the CLI uses the logged-in app (none here) and environment `production`. Also, an exact path is bypassed by `/API/AUTH/LOGIN` until F6 is fixed. |
| docs/securenow-integration.md:30 | “The connection flow enables telemetry and the application firewall by default.” | `npx securenow firewall status --app … --env test` reports “DISABLED FOR APP/ENV” today (production env shows on). Enable it for `test` explicitly (AUTH-02). |
| docs/securenow-integration.md:147 | “CAPTCHA is a future code integration in this baseline.” | SecureNow’s proof-of-work challenge needs no CAPTCHA provider; it runs inside the SDK firewall. It does need the SPA change in F15 before it can be used on JSON routes. |
| docs/threat-model-authentication.md:27 | Lists the native limits and says they “do not eliminate distributed abuse or shared-IP friction”. | Accurate. The code also shows the per-account bucket rejects the owner’s correct attempts (F3), which the doc does not mention. |
| docs/threat-model-authentication.md:62 | “current failed-login audit rows intentionally omit an email/account identifier” | Accurate (`src/app.js:181`). The proposed bridge adds only a keyed HMAC `account_ref` to telemetry; the PostgreSQL rows stay unchanged. |
| README.md:20 | “There are no shared admin passwords … or intentionally weakened public authentication switches.” | Accurate for the repo. Note F12: the bootstrap admin password stays in the deployment’s runtime secret. |


<a id="strengths"></a>
## 7. Strengths

- **Stops password guessing beyond 15 tries per IP per 15 minutes**, on every instance and across restarts: counters are atomic PostgreSQL rows, and a successful sign-in does not reset them, so an attacker cannot interleave their own valid login (`src/app.js:124-138`).
- **Slows offline cracking:** salted, memory-hard scrypt with constant-time comparison and no 72-byte truncation (`src/passwords.js`).
- **Stops account enumeration by response or timing:** identical sign-in errors, a dummy hash for unknown accounts, and an identical registration response (`src/app.js:169-182`).
- **Stops session fixation:** the session is regenerated at every sign-in (`src/app.js:140`).
- **Stops cookie theft over HTTP or JavaScript and subdomain cookie injection:** `__Host-` prefix, Secure, HttpOnly, SameSite=Lax (verified live), strict same-origin CSP, `no-referrer`.
- **Limits replay of an old cookie:** 30 minutes idle, 8 hours absolute, server-side store, and every password or role change ends all older sessions (`session_version`).
- **Stops CSRF, including login CSRF:** exact Origin, Sec-Fetch-Site, a per-session token and JSON-only writes (`src/app.js:102-110`).
- **Stops Google code injection, replay, token forgery and email-based takeover:** state + nonce + PKCE S256, a 10-minute single-use transaction, `verifyIdToken` with audience, issuer/subject/verified-email checks, identity keyed on `sub`, never auto-linking by email, and a server-constant redirect URI (`src/app.js:210-260`).
- **Stops privilege escalation through the client:** roles are read from PostgreSQL on every request; registration ignores injected `role`/`emailVerified`; an admin cannot demote themselves; the bootstrap never elevates an existing member.
- **Stops IP spoofing around per-IP limits and direct access to internals:** Caddy is the sole ingress and overwrites X-Forwarded-For; the app trusts one hop; app and database ports are unpublished; IMDSv2; SSM instead of SSH.
- **Keeps secrets out of Git and images:** CI secret scan, ignore lists, AWS Secrets Manager; history scanned clean in this run.
- **Leaks little when something fails:** parameterized SQL, 8 KB JSON limit, `no-store` on the API, dotfiles denied, generic 500s, IP addresses HMAC’d in the audit table.


<a id="fixes"></a>
## 8. App / config fixes (primary remediation)

| Fix | Change (described, not applied) | Backs matrix row(s) | TODO |
| --- | --- | --- | --- |
| [F1](#finding-f1) Anonymous visitors create a PostgreSQL session row on every request, with no limit | Stop persisting anonymous sessions. Issue the pre-login CSRF token as a signed double-submit cookie instead: on anonymous GETs, set `__Host-lab_csrf=<nonce>.<HMAC(SESSION_SECRET, nonce)>` (HttpOnly, Secure, SameSite=Strict) and return the same value in the JSON; in the `/api` mutation guard (`src/app.js:102-110`), accept the request when the header equals the cookie and the HMAC verifies, and only then create the server session in `authenticate()`. Keep the per-session token after sign-in. Alternatively (smaller change): only call `sessionResponse()` for requests that already have a session, and rate-limit the three GET routes with the existing `limit('session-ip', 60)` helper. | [J47](authentication-detection-mitigation.md#threat-j47) | [AUTH-06](#todo-auth-06) |
| [F2](#finding-f2) Rejected requests write unlimited audit rows and can push real events out of view | Record at most one rejection per (category, client) per window: in `limit()`, log `auth.rate_limited` only when `rows[0].count === maximum + 1`; in the CSRF guard, run the existing `limit()` helper as `limit('csrf-reject-ip', 20)` before writing `csrf.rejected`, and log only the first rejection in each window. Add type filtering and paging to `/api/security` so a flood of one type cannot hide another. | [S1](authentication-detection-mitigation.md#threat-s1), [C13](authentication-detection-mitigation.md#threat-c13) | [AUTH-07](#todo-auth-07) |
| [F3](#finding-f3) Anyone who knows an email can keep that member locked out | Use the OWASP “device cookie” pattern: after a successful sign-in, set a long-lived signed `__Host-lab_device` cookie (random ID + HMAC). In the account limiter, skip (or use a much higher limit for) requests that present a valid device cookie previously used by that account, and increment the account bucket only on failed verification rather than on every request. Keep the per-IP limit for everyone. Emit `api.ratelimit.exceeded` with `scope` and `account_ref` so R14 works. | [H41](authentication-detection-mitigation.md#threat-h41), [A2](authentication-detection-mitigation.md#threat-a2) | [AUTH-13](#todo-auth-13) |
| [F4](#finding-f4) No email-ownership check: squatted addresses, Google lock-out and an enumeration oracle | Make password registrations pending until a one-time link is clicked: store only a SHA-256 hash of a 32-byte random token with a 30-minute expiry, single use, bound to user + purpose + address; refuse sign-in for pending accounts; for an already-registered address, send a “someone tried to register” notice instead of a second account. Let a verified Google identity for the same normalized address reclaim a still-pending (unverified) password account — never the reverse. Normalize emails with NFKC before lower-casing. Sending email adds an auth-message channel: apply the per-target/per-IP/global send limits from the E-section of this model before shipping. | [G36c](authentication-detection-mitigation.md#threat-g36c), [B6](authentication-detection-mitigation.md#threat-b6), [B7](authentication-detection-mitigation.md#threat-b7), [B8a](authentication-detection-mitigation.md#threat-b8a), [G34](authentication-detection-mitigation.md#threat-g34), [H40](authentication-detection-mitigation.md#threat-h40), [H40a](authentication-detection-mitigation.md#threat-h40a), [H40b](authentication-detection-mitigation.md#threat-h40b) | [AUTH-18](#todo-auth-18) |
| [F5](#finding-f5) No second factor, no step-up for admin role changes, no security-change notices | Step-up (AUTH-14): add `POST /api/auth/reauth` that verifies the current password and sets `req.session.reauthAt`; reject role changes unless `Date.now() - req.session.reauthAt < 5 * 60_000` (Google-only admins re-authenticate through Google with `prompt=login` / `max_age`). MFA (AUTH-19): passkeys (WebAuthn) or TOTP for admin and analyst first. Notifications (AUTH-19): email the affected user and the other admins on role changes and password changes once a mail channel exists. | [L54a](authentication-detection-mitigation.md#threat-l54a), [C16](authentication-detection-mitigation.md#threat-c16), [C16a](authentication-detection-mitigation.md#threat-c16a), [C16c](authentication-detection-mitigation.md#threat-c16c), [C16d](authentication-detection-mitigation.md#threat-c16d), [H39a](authentication-detection-mitigation.md#threat-h39a), [S2](authentication-detection-mitigation.md#threat-s2) | [AUTH-14](#todo-auth-14) |
| [F6](#finding-f6) Route aliases (`/API/AUTH/LOGIN`, trailing slash) slip past SecureNow route-scoped controls | Right after `const app = express();` add `app.set('case sensitive routing', true); app.set('strict routing', true);` (or an early middleware that 404s any `/api` path whose `req.path !== req.path.toLowerCase()` or ends with `/`). Update `scripts/smoke.mjs:37` to expect 404 for `/API/ME`, and keep the `Cache-Control` check at `src/app.js:66` lower-casing as defense in depth. | [M62](authentication-detection-mitigation.md#threat-m62), [A1](authentication-detection-mitigation.md#threat-a1) | [AUTH-08](#todo-auth-08) |
| [F7](#finding-f7) No “sign out everywhere”; Google-only members have no kill switch; admins cannot revoke a user’s sessions | Add `POST /api/auth/sessions/revoke-others` (increment `session_version`, then call `authenticate()` for the current request), show members their own sessions (split `/api/security` into “my sessions” for every signed-in user and “audit events” for analysts), and add an admin `POST /api/admin/users/:id/revoke-sessions` that increments `session_version`. Wire `securenow/sessions` `guard()` as shown in the instrumentation section. | [C11](authentication-detection-mitigation.md#threat-c11), [C9](authentication-detection-mitigation.md#threat-c9), [C11a](authentication-detection-mitigation.md#threat-c11a), [C12](authentication-detection-mitigation.md#threat-c12) | [AUTH-20](#todo-auth-20) |
| [F8](#finding-f8) scrypt cost is about one third of the OWASP minimum and can never be upgraded | Parse N/r/p from the stored string and verify with those values; on a successful sign-in with outdated parameters, rehash with the new ones and update the row. Use N=32768, r=8, p=3 (same 32 MiB memory, 3× CPU) or move to Argon2id (m=19 MiB, t=2, p=1). Pair with F9 so the higher cost cannot be used to exhaust the server. | [K49](authentication-detection-mitigation.md#threat-k49), [A5a](authentication-detection-mitigation.md#threat-a5a) | [AUTH-21](#todo-auth-21) |
| [F9](#finding-f9) No bound on concurrent password hashing | Wrap `hashPassword`/`verifyPassword` in a small semaphore (for example 4 concurrent, queue of 50); when the queue is full, answer 503 with `Retry-After: 5` before hashing. Optionally raise `UV_THREADPOOL_SIZE` to 8 with matching container memory. | [J46](authentication-detection-mitigation.md#threat-j46) | [AUTH-21](#todo-auth-21) |
| [F10](#finding-f10) Passwords are only length-checked: no breached-password screening, no Unicode normalization | At registration and password change, check the SHA-1 prefix against the Have I Been Pwned range API (k-anonymity; fail open with a log line if the API is down) and refuse matches. Normalize with `password.normalize('NFC')` before hashing; on sign-in, try the normalized form first and the raw form for hashes created before the change, then rehash. | [A5a](authentication-detection-mitigation.md#threat-a5a), [A3](authentication-detection-mitigation.md#threat-a3), [A4](authentication-detection-mitigation.md#threat-a4) | [AUTH-22](#todo-auth-22) |
| [F11](#finding-f11) Rate-limit keys use the full IPv6 address and a fixed window | Key IPv6 clients by their /64 (and IPv4 by the full address), and count the current plus the previous window weighted by elapsed time (sliding-window approximation) using the existing `rate_buckets` rows. | [A4a](authentication-detection-mitigation.md#threat-a4a), [A1](authentication-detection-mitigation.md#threat-a1), [A2](authentication-detection-mitigation.md#threat-a2), [M62](authentication-detection-mitigation.md#threat-m62) | [AUTH-23](#todo-auth-23) |
| [F12](#finding-f12) The bootstrap admin password stays in the runtime secret after first use | After the first successful bootstrap, overwrite `ADMIN_PASSWORD` in the runtime secret with an empty value (the seed already treats an existing admin as a no-op), and add a `must_change_password` flag that forces a password change on the bootstrap admin’s first sign-in. | [A5](authentication-detection-mitigation.md#threat-a5) | [AUTH-24](#todo-auth-24) |
| [F13](#finding-f13) SDK defaults would export more than the lab intends (request bodies, CSRF header, OAuth state) | Write `.securenow/credentials.json` (or the runtime file) with `capture.body=false`, `capture.multipart=false` and `runtime.deploymentEnvironment=test` before the first instrumented start, exactly as `docs/securenow-integration.md:30-51` describes, and verify with `npx securenow env --json`. | [D21](authentication-detection-mitigation.md#threat-d21), [K52](authentication-detection-mitigation.md#threat-k52) | [AUTH-01](#todo-auth-01) |
| [F14](#finding-f14) Daily backups contain live session IDs and in-flight Google transactions | Add `--exclude-table-data=sessions --exclude-table-data=rate_buckets` to the `pg_dump` command in `infra/backup.sh:6`; keep the table definitions. | [D21a](authentication-detection-mitigation.md#threat-d21a) | [AUTH-25](#todo-auth-25) |
| [F15](#finding-f15) The single-page app cannot complete a SecureNow challenge on API routes | In `api()`, when `response.headers.get('X-SecureNow-Challenge') === 'required'`, reload the page (`location.reload()`) so the HTML interstitial runs on the next GET (the clearance cookie is bound to IP + user agent, not to a route), then retry. Until this ships, use rate limits (not challenges) on JSON routes — as this report does. | [M63](authentication-detection-mitigation.md#threat-m63) | [AUTH-15](#todo-auth-15) |
| [F16](#finding-f16) The admin user list shows only the newest 100 accounts | Add `?cursor=` paging and an email/name search parameter to `/api/admin/users`, and a search box in `renderAdmin`. | [H40](authentication-detection-mitigation.md#threat-h40) | [AUTH-29](#todo-auth-29) |
| Keep (no change) | Session regeneration, cookie flags, session_version checks, CSRF gate, Google state/nonce/PKCE/sub keying, explicit signup fields, Caddy forwarding, secret scan. | [C10](authentication-detection-mitigation.md#threat-c10), [C14](authentication-detection-mitigation.md#threat-c14), [C15](authentication-detection-mitigation.md#threat-c15), [C13](authentication-detection-mitigation.md#threat-c13), [G32](authentication-detection-mitigation.md#threat-g32), [G36b](authentication-detection-mitigation.md#threat-g36b), [H40g](authentication-detection-mitigation.md#threat-h40g), [I45a](authentication-detection-mitigation.md#threat-i45a), [K51](authentication-detection-mitigation.md#threat-k51) | [AUTH-30](#todo-auth-30), [AUTH-31](#todo-auth-31), [AUTH-32](#todo-auth-32), [AUTH-33](#todo-auth-33), [AUTH-35](#todo-auth-35), [AUTH-36](#todo-auth-36) |
| Last sign-in time (feeds R22) | `ALTER TABLE users ADD COLUMN last_login_at timestamptz`; in `authenticate()` compute `dormant_days` from the old value, then update it. | [C16b](authentication-detection-mitigation.md#threat-c16b), [H40c](authentication-detection-mitigation.md#threat-h40c) | [AUTH-26](#todo-auth-26) |


<a id="instrumentation"></a>
## 9. Instrumentation recommendations

These are the `track()` calls and the guard the detection rules consume, with exact placement. Event names are **proposed instrumentation** (the installed `track(type, props)` accepts any string type); only `session.seen` is emitted by the SDK itself. Line numbers refer to commit `5f87235`.

| What | Where | Code (proposed) | Feeds |
| --- | --- | --- | --- |
| Install + preload | package.json, Dockerfile:16, compose.yaml:30 | `npm install --save-exact securenow@8.12.0`; `CMD ["node", "-r", "securenow/register", "src/server.js"]`; compose command `node scripts/migrate.js && exec node -r securenow/register src/server.js` | all traffic rules |
| Bridge module | new file src/securenow-bridge.js | see snippet below | all event rules |
| Imports + bridge instance | src/app.js:8 (imports), src/app.js:43 (instance) | `import { guard } from 'securenow/sessions'; import { createBridge } from './securenow-bridge.js';` … `const { emit, ref, sessionRef } = createBridge(config);` | — |
| Sessions guard | after src/app.js:101 | guard({ getSessionId, getUserId, onRevoked }) — snippet below | R17, R18; enforces `revoke` |
| Rate-limit rejections | src/app.js:133 | `emit('api.ratelimit.exceeded', req, { userId: req.user?.id, attributes: { scope: name, route: req.path.toLowerCase(), reason: 'fixed_window', ...(account ? { account_ref: ref('acct', identifier) } : {}) } });` | R14 |
| Registration | src/app.js:170 | `emit('auth.signup', req, { userId: result.rows[0]?.id, attributes: { auth_method: 'password', provider: 'local', outcome: result.rows[0] ? 'created' : 'existing', account_ref: ref('acct', email) } });` | R23 |
| Password sign-in failure | src/app.js:181 | `emit('auth.login.failure', req, { userId: user?.id, attributes: { auth_method: 'password', provider: 'local', reason: user ? 'bad_password' : 'unknown_account', account_ref: ref('acct', email), mfa_state: 'none', sso_required: false } });` | R10 R11 R12 R19 R24 R25 R26 |
| Password sign-in success | src/app.js:185 | `emit('auth.login.success', req, { userId: user.id, attributes: { auth_method: 'password', provider: 'local', account_ref: ref('acct', email), mfa_state: 'none', sso_required: false } });` (+ `dormant_days` after AUTH-26, `device_hash: ref('dev', deviceId)` after AUTH-13) | R12 R13 R19 R20 R22 R25 R27 |
| Logout | src/app.js:189 (before destroySession) | `if (req.user) emit('auth.logout', req, { userId: req.user.id });` | — |
| Wrong current password | src/app.js:198 | `emit('auth.security.change', req, { userId: req.user.id, attributes: { action: 'password_changed', outcome: 'failure', step_up: true } });` | R21 |
| Password changed | before src/app.js:205 and after 206 | `const priorSession = sessionRef(req);` before `authenticate()`; then `emit('auth.security.change', req, { userId: rows[0].id, sessionId: priorSession, attributes: { action: 'password_changed', outcome: 'completed', step_up: true } });` | R18 R19 R20 |
| Google invalid callback | src/app.js:228 | `emit('auth.login.failure', req, { attributes: { auth_method: 'oauth', provider: 'google', reason: 'invalid_callback' } });` | R15 |
| Google account created | after src/app.js:244 | `if (user) emit('auth.signup', req, { userId: user.id, attributes: { auth_method: 'oauth', provider: 'google', outcome: 'created', account_ref: ref('acct', email) } });` | R23 |
| Google identity conflict | src/app.js:249 | `emit('auth.login.failure', req, { attributes: { auth_method: 'oauth', provider: 'google', reason: 'identity_conflict', account_ref: ref('acct', email) } });` and `emit('auth.account.link', req, { attributes: { outcome: 'rejected', provider: 'google', verified_email: true, join_key: 'iss_sub', reason: 'existing_email_other_method', account_ref: ref('acct', email) } });` | R16 |
| Google sign-in success | src/app.js:254 | `emit('auth.login.success', req, { userId: user.id, attributes: { auth_method: 'oauth', provider: 'google', account_ref: ref('acct', email), mfa_state: 'none', sso_required: false } });` | R13 R20 R27 |
| Google verification failure | src/app.js:257 | `emit('auth.login.failure', req, { attributes: { auth_method: 'oauth', provider: 'google', reason: 'provider_verification' } });` | R15 |
| Role changed | before src/app.js:294 and after 297 | before: `const before = (await pool.query('SELECT role FROM users WHERE id=$1', [req.params.id])).rows[0]?.role;` after: `const rank = { member: 1, analyst: 2, admin: 3 }; emit('auth.security.change', req, { userId: req.user.id, attributes: { action: 'role_changed', outcome: 'completed', step_up: false, target_ref: rows[0].id, direction: rank[rows[0].role] > rank[before] ? 'elevate' : rank[rows[0].role] < rank[before] ? 'reduce' : 'same' } });` | R20 R21 |

```js
// src/securenow-bridge.js — NEW FILE (proposed; not applied). Privacy-safe export of auth decisions to SecureNow.
import { createHash, createHmac } from 'node:crypto';
import { track } from 'securenow/events';

export function createBridge(config) {
  // Keyed, domain-separated references: stable for correlation, meaningless without AUDIT_HMAC_SECRET.
  const ref = (kind, value) => createHmac('sha256', config.auditSecret).update(`${kind}:${value}`).digest('hex').slice(0, 32);
  // Same value securenow/sessions guard() reports as session.id — and what "revoke session" expects.
  const sessionRef = (req) => (req.sessionID ? createHash('sha256').update(req.sessionID).digest('hex') : undefined);
  function emit(type, req, { userId, sessionId, attributes = {} } = {}) {
    track(type, {                                   // fire-and-forget; never throws into the request
      userId: userId ?? undefined,
      sessionId: sessionId ?? sessionRef(req),
      ip: req.ip,                                   // trusted: Caddy overwrites X-Forwarded-For, app trusts one hop
      userAgent: String(req.get('user-agent') || '').slice(0, 256),
      attributes: { request_id: req.requestId, ...attributes },
    });
  }
  return { emit, ref, sessionRef };
}
```

```js
// src/app.js — add after line 8:
import { guard } from 'securenow/sessions';
import { createBridge } from './securenow-bridge.js';
// inside createApp(), after line 43 (const hash = ...):
const { emit, ref, sessionRef } = createBridge(config);
// insert after line 101 (after the user loader, before the CSRF gate) — the guard's default cookie list
// does not know __Host-lab_auth, so pass explicit extractors:
app.use(guard({
  getSessionId: (req) => (req.user ? sessionRef(req) : null),
  getUserId: (req) => req.user?.id ?? null,
  onRevoked: async (req, res) => {
    await destroySession(req);
    res.clearCookie(cookieName, { path: '/', secure: config.production, httpOnly: true, sameSite: 'lax' });
    return fail(res, 401, 'AUTH_REQUIRED', 'Your session has ended. Sign in to continue.');
  },
}));
```

### App events vs provider adapters vs external monitors

- **App events (build now):** the 14 `emit(...)` calls above plus `guard()`. They describe decisions only the app can make (password right/wrong, account created or existing, role elevated).
- **Provider adapters (none needed today):** a Google Cloud audit-log adapter would emit `auth.provider.activity` for OAuth client changes (M58). It must authenticate to Google’s API before emitting; until then this stays a gap.
- **External monitors (AUTH-27):** uptime, telemetry freshness, rule-manifest drift and certificate expiry must run outside SecureNow; an in-process heartbeat cannot prove its own exporter works.

### Runtime key, replay, bounded attributes, redaction

- **Runtime key:** mount `/app/.securenow/credentials.json` read-only for the `node` user (the compose file already runs read-only with `cap_drop: ALL`); never commit or bake it; rotate with `npx securenow credentials runtime --env test` on any suspicion (M61).
- **Replay / dedup:** every event carries `request_id` (the app’s per-request UUID, `src/app.js:63`); rule R24 flags duplicates and future-dated events. Events have no server-side ID and keep the sender’s timestamp.
- **Bounded attributes:** `auth_method` ∈ {password, oauth}, `provider` ∈ {local, google}, `reason`, `outcome`, `action`, `direction`, `scope` are fixed enums; `account_ref` is a 32-hex HMAC; `target_ref` is an opaque UUID. No role names, emails, passwords, tokens or session IDs in clear.
- **Redaction:** keep `capture.body=false` and `capture.multipart=false` (F13). The `x-csrf-token` header will still be recorded by the tracer (low value without the cookie); there is no setting to redact it today.
- **Reserved prefixes:** none of the custom keys start with `event.`, `enduser.`, `session.`, `http.`, `service.`, `securenow.` or `client.` (those would be stored as `attr.<key>`).


<a id="verification"></a>
## 10. Verification checklist / definition of done

|  | TODO | Test | Expected evidence | Linked rule / finding | Status |
| --- | --- | --- | --- | --- | --- |
| ☐ | [AUTH-01](#todo-auth-01) Add the SDK with safe capture settings and start it as a preload | `npx securenow env --json` → captureBody false, deploymentEnvironment test; `npx securenow telemetry fields --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --since 24h --source traces --env test` lists http.target, http.client_ip, http.request.headers. | HTTP traces start flowing; once AUTH-05 creates R01–R09, the 11 traffic-based threats become detectable. | [F13](#finding-f13) | not started |
| ☐ | [AUTH-06](#todo-auth-06) Stop anonymous visitors from creating database sessions | 65 cookieless GETs against a local copy add 0 `sessions` rows; CSRF tests still pass. | Unauthenticated traffic no longer grows the database. | [R03](authentication-detection-mitigation.md#rule-r03), [F1](#finding-f1) | not started |
| ☐ | [AUTH-07](#todo-auth-07) Cap audit writes from rejected requests | 100 rejected requests add ≤ 1 row per window. | The audit trail stays readable under attack. | [R04](authentication-detection-mitigation.md#rule-r04), [R02](authentication-detection-mitigation.md#rule-r02), [F2](#finding-f2) | not started |
| ☐ | [AUTH-08](#todo-auth-08) Make routing strict and case-sensitive | `POST /API/AUTH/LOGIN` → 404 locally. | Edge mitigations cannot be sidestepped by letter case; SecureNow rules can use exact paths. | [F6](#finding-f6) | not started |
| ☐ | [AUTH-09](#todo-auth-09) Export auth events with track() and wire the sessions guard | `npx securenow telemetry fields --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --since 24h --source logs --env test` lists event types auth.login.failure, auth.login.success, auth.signup, auth.security.change, session.seen and the attribute account_ref. | Event-based rules R10–R27 have data; manual session revocation becomes enforceable. | — | not started |
| ☐ | [AUTH-13](#todo-auth-13) Stop attackers from locking a known member out | Lockout test in F3’s definition of done. | Owners keep signing in from their usual browser during an attack. | [R14](authentication-detection-mitigation.md#rule-r14), [F3](#finding-f3) | not started |
| ☐ | [AUTH-14](#todo-auth-14) Require recent re-authentication for admin role changes | Role change without re-auth in 5 min → 403. | A stolen admin cookie alone cannot grant roles. | [R21](authentication-detection-mitigation.md#rule-r21), [F5](#finding-f5) | not started |
| ☐ | [AUTH-15](#todo-auth-15) Let the single-page app complete a SecureNow challenge | F15 definition of done. | Challenges become a safe response on `/api/auth` too. | [R05](authentication-detection-mitigation.md#rule-r05), [F15](#finding-f15) | not started |
| ☐ | [AUTH-18](#todo-auth-18) Verify email ownership and let a verified Google sign-in reclaim a squatted address | F4 definition of done. | Only mailbox owners hold accounts. | [R23](authentication-detection-mitigation.md#rule-r23), [R16](authentication-detection-mitigation.md#rule-r16), [F4](#finding-f4) | not started |
| ☐ | [AUTH-19](#todo-auth-19) Add passkeys or TOTP for admin and analyst, and notify on security changes | Admin sign-in requires the second factor. | Phishing a password alone no longer grants admin. | [F5](#finding-f5) | not started |
| ☐ | [AUTH-20](#todo-auth-20) Add sign-out-everywhere, a members’ own-sessions view and an admin revoke action | F7 definition of done. | Any member or admin can end stolen sessions. | [R17](authentication-detection-mitigation.md#rule-r17), [R18](authentication-detection-mitigation.md#rule-r18), [F7](#finding-f7) | not started |
| ☐ | [AUTH-21](#todo-auth-21) Raise scrypt cost with rehash-on-sign-in and bound concurrent hashing | F8/F9 definitions of done. | Stronger hashes without a DoS lever. | [R07](authentication-detection-mitigation.md#rule-r07), [F8](#finding-f8), [F9](#finding-f9) | not started |
| ☐ | [AUTH-22](#todo-auth-22) Screen breached passwords and normalize Unicode | F10 definition of done. | Sprayed and breached passwords are refused. | [R10](authentication-detection-mitigation.md#rule-r10), [F10](#finding-f10) | not started |
| ☐ | [AUTH-23](#todo-auth-23) Key IPv6 clients by /64 and smooth the rate-limit window | F11 definition of done. | Per-IP limits hold for IPv6. | [R06](authentication-detection-mitigation.md#rule-r06), [F11](#finding-f11) | not started |
| ☐ | [AUTH-24](#todo-auth-24) Remove the bootstrap admin password from the runtime secret | Secret has no usable ADMIN_PASSWORD. | No standing admin credential in AWS. | [F12](#finding-f12) | not started |
| ☐ | [AUTH-25](#todo-auth-25) Leave live sessions out of database backups | Restore drill shows empty sessions table. | Backups contain no session material. | [F14](#finding-f14) | not started |
| ☐ | [AUTH-26](#todo-auth-26) Record the previous sign-in time so dormant accounts can be flagged | R22 synthetic test; a real 90-day-old test account triggers it. | Dormant-account sign-ins are visible. | [R22](authentication-detection-mitigation.md#rule-r22) | not started |
| ☐ | [AUTH-29](#todo-auth-29) Page and search the admin user list | F16 definition of done. | Admins can always find an account. | [R08](authentication-detection-mitigation.md#rule-r08), [F16](#finding-f16) | not started |
| ☑ | [AUTH-30](#todo-auth-30) Atomic, shared rate limits and race-safe account creation | Integration tests “durable rate limiting” and “registration is generic”. | In place. | — | verified (existing tests / live check) |
| ☑ | [AUTH-31](#todo-auth-31) Session hardening | `scripts/smoke.mjs` cookie assertions. | In place (verified live 2026-10-16). | — | verified (existing tests / live check) |
| ☑ | [AUTH-32](#todo-auth-32) CSRF protection on every API write | Integration test “CSRF rejects cross-origin mutations”. | In place. | — | verified (existing tests / live check) |
| ☑ | [AUTH-33](#todo-auth-33) Hardened Google sign-in | Integration tests for nonce and linking. | In place. | — | verified (existing tests / live check) |
| ☑ | [AUTH-34](#todo-auth-34) Careful password storage and uniform answers | Integration test “failed login is generic”. | In place. | — | verified (existing tests / live check) |
| ☑ | [AUTH-35](#todo-auth-35) Trustworthy client IPs and private internals | R09 stays at zero. | In place (docs/verification.md). | [R09](authentication-detection-mitigation.md#rule-r09) | verified (existing tests / live check) |
| ☑ | [AUTH-36](#todo-auth-36) Secrets kept out of Git and images | `node scripts/check-secrets.mjs` in CI. | In place. | — | verified (existing tests / live check) |


<a id="appendix"></a>
## 11. Appendix

| Item | Value |
| --- | --- |
| Files reviewed (application) | `src/app.js`, `src/config.js`, `src/passwords.js`, `src/server.js`, `src/bootstrap.js`, `src/db.js`, `db/001_initial.sql`, `scripts/check-secrets.mjs`, `scripts/migrate.js`, `scripts/seed.js`, `scripts/smoke.mjs`, `public/app.js`, `public/index.html`, `test/auth.integration.test.js`, `package.json`, `package-lock.json` (versions) |
| Files reviewed (infra) | `Dockerfile`, `compose.yaml`, `compose.production.yaml`, `infra/Caddyfile`, `infra/bootstrap.sh`, `infra/update.sh`, `infra/backup.sh`, `infra/deploy.ps1`, `infra/generate-template.cjs`, `.env.example`, `.gitignore`, `.dockerignore`, `.github/workflows/ci.yml` |
| Files reviewed (docs) | `README.md`, `SECURITY.md`, `docs/threat-model-authentication.md`, `docs/securenow-integration.md`, `docs/api.md`, `docs/verification.md`, `docs/google-oauth.md`, `docs/aws-deployment.md` |
| SDK files consulted | `node_modules/securenow/{package.json, telemetry-schema.json, events.js, sessions.js, tracing.js, resolve-ip.js, otp-redaction.js, firewall.js, challenge.js, register.js, cli.js, cli/security.js, cli/rateLimits.js, cli/automation.js, cli/diagnostics.js, mcp/catalog.js}` |
| Not read (credential files) | `.deployment/*`, `.securenow/admin.json`, any `.env` — existence noted only |
| Resolved SDK version | securenow 8.12.0 (node_modules, via npx); global CLI 8.11.3 not used |
| Repository commit | 5f87235 |
| Date | 2026-10-16 |
| Detection & mitigation report | [authentication-detection-mitigation](authentication-detection-mitigation.md) |

