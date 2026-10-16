# Authentication — Detection & Mitigation

**App:** lab-auth (`df7ab010-37ac-4732-88ac-a8ac23afe1a4`, lab-auth.labs.securenow.ai) · **securenow 8.12.0** · **Environment:** test · **Commit:** `5f87235` · **Date:** 2026-10-16 · **Scope:** Authentication only
Companion: [Code findings & recommendations](authentication-code-findings.md)

**Posture in one sentence:** strong sign-in code, but SecureNow sees nothing yet — load the SDK preload to enable 9 traffic rules today, add the event bridge to enable the other 18.

**Totals:** 67 threats modeled · 0 covered · 41 partial · 26 gaps · 27 rules to create

<a id="summary"></a>
## 1. Executive summary — security posture

**Verdict.** Northstar’s sign-in code is careful — salted scrypt, uniform error messages, PostgreSQL-backed rate limits, server-side sessions with strict cookies, strong CSRF checks and a properly bound Google sign-in. **SecureNow protects nothing yet**: the SDK (8.12.0) is installed in `node_modules` only so this report could be grounded in it, it is not loaded by the app, and lab-auth has ingested 0 telemetry fields in the last 30 days. Loading the SDK preload ([AUTH-01](#todo-auth-01)) immediately enables 9 traffic rules covering 11 threats; exporting the app’s auth decisions with `track()` and wiring the sessions guard ([AUTH-09](#todo-auth-09)) enables 18 more rules covering 29 threats. 26 threats stay outside SecureNow: prevention properties the app already has or must add, plus items that need an external monitor or Google-side data. The three most useful code fixes are F3 (lockout), F1 (anonymous session rows) and F6 (route aliases).

**Stats:** 67 threats modeled · 0 covered · 41 partial · 26 gaps · 50 N/A · 8 deferred to sibling models · 27 rules to create · 7 rule-bound automations + 13 scoped manual mitigation commands.

### Top 3 attack stories for this app

1. **Keep a member locked out, or guess slowly from many addresses.** Anyone who knows a password member’s email can hold that account at “Too many attempts” with about two requests a minute from three IPs, because the per-account bucket also rejects the owner ([H41](#threat-h41), [F3](authentication-code-findings.md#finding-f3)). Spreading guesses across a /64 or a botnet stays under every per-IP limit ([A2](#threat-a2)).
2. **Grow the database and bury the audit trail without signing in.** Every cookieless `GET /api/me` writes a new PostgreSQL session row, and every rejected POST writes an audit row — neither is rate-limited, and the analyst’s Security page shows only the newest 100 events ([J47](#threat-j47), [S1](#threat-s1), [F1](authentication-code-findings.md#finding-f1), [F2](authentication-code-findings.md#finding-f2)).
3. **Sidestep edge controls with `/API/AUTH/LOGIN`.** Express answers upper-case and trailing-slash aliases, while SecureNow’s firewall matches paths exactly; every mitigation in this report therefore uses a case-insensitive regex until routing is made strict ([M62](#threat-m62), [F6](authentication-code-findings.md#finding-f6)).

### What is protected now? What becomes protected after the TODOs? What remains outside SecureNow?

- **Now:** nothing by SecureNow. The app’s own controls (listed under ALREADY IN PLACE) already stop session fixation, cookie theft over HTTP/JS, CSRF, Google code injection/replay, email-based account takeover and single-IP guessing beyond 15 attempts per 15 minutes.
- **After DO NOW (SDK preload + 9 traffic rules):** 11 threats are detected from HTTP traffic alone — repeated failed sign-ins, post-limit hammering, anonymous session minting, CSRF floods, auth-surface scanning, network-spread guessing, hashing load spikes, sign-up surges and proxy/IP-chain anomalies. Rules start in test mode (notify only).
- **After NEXT 7 DAYS (event bridge + guard + 18 event rules + 7 disabled automations):** 29 more threats — stuffing across accounts, one account from many IPs, lockout pressure, success-after-failures, takeover sequences, session theft signals, security changes, Google callback abuse, registration probing and event integrity. A person promotes clean rules after 3–7 days.
- **Outside SecureNow:** 21 prevention items (most already in place; F4/F5/F8/F10/F12/F14 still to do), 4 that need an independent monitor (telemetry outage, rule/channel health, certificates), and 2 that need Google-side data (Cloud audit logs, account deprovisioning).

**Installed SDK:** `securenow@8.12.0` (node_modules, installed with `--no-save`; the global CLI on this machine is 8.11.3, so every command here uses `npx`). **App:** lab-auth `df7ab010-37ac-4732-88ac-a8ac23afe1a4` (lab-auth.labs.securenow.ai). **Telemetry environment:** `test`. **Firewall:** off for env `test` (`firewall status` → “DISABLED FOR APP/ENV”); the dashboard shows it on for `production`, which the lab does not use. **Repository commit:** `5f87235`. **Date:** 2026-10-16. **Scope:** Authentication only.


<a id="todo"></a>
## 2. Start here — prioritized TODO board

36 deduplicated actions (each action appears once; threats, rules and findings link to it). The 25 App-owned items are repeated, with the same IDs, on the [code TODO board](authentication-code-findings.md#todo). Owners: SecureNow = you, in the SecureNow CLI/dashboard; App = code/config in this repo; Provider = Google Cloud; External monitor = a scheduler outside SecureNow.



### DO NOW (8)


<a id="todo-auth-01"></a>
#### AUTH-01 · Add the SDK with safe capture settings and start it as a preload — DO NOW · HIGH
- **Owner:** App · **Effort:** S · **Priority:** high
- **Why it matters:** SecureNow sees nothing today: the SDK is in node_modules only for this report and is not loaded, and lab-auth has ingested 0 telemetry fields in 30 days. With default settings it would also capture request bodies and CSRF headers (F13).
- **Action:** `npm install --save-exact securenow@8.12.0` (commit package.json + package-lock.json); run `npx securenow app connect` and pick lab-auth; merge `capture.body=false`, `capture.multipart=false`, `runtime.deploymentEnvironment="test"` into the runtime file (docs/securenow-integration.md:32-48); change the start command to `node -r securenow/register src/server.js` (Dockerfile:16, compose.yaml:30); mount the runtime credential at `/app/.securenow/credentials.json` in production.
- **Prerequisite:** None.
- **Expected security outcome:** HTTP traces start flowing; once AUTH-05 creates R01–R09, the 11 traffic-based threats become detectable.
- **Verify / definition of done:** `npx securenow env --json` → captureBody false, deploymentEnvironment test; `npx securenow telemetry fields --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --since 24h --source traces --env test` lists http.target, http.client_ip, http.request.headers.
- **Rollback:** Revert the start command to `node src/server.js`.
- **Links:** [A1](#threat-a1) · [D21](#threat-d21) · [K52](#threat-k52) · [F13](authentication-code-findings.md#finding-f13)


<a id="todo-auth-02"></a>
#### AUTH-02 · Turn on the firewall for the lab’s test environment — DO NOW · MEDIUM
- **Owner:** SecureNow · **Effort:** S · **Priority:** medium
- **Why it matters:** `firewall status --env test` reports “DISABLED FOR APP/ENV”; the hourly known-bad IP feed and every block/rate-limit/challenge rule need it.
- **Action:** `npx securenow firewall enable --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --env test`
- **Prerequisite:** AUTH-01 (the firewall runs inside the SDK).
- **Expected security outcome:** Known-bad scanners and stuffing IPs are refused before the app runs; scoped rules can be enforced.
- **Verify / definition of done:** `npx securenow firewall status --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --env test` shows enabled; `npx securenow firewall test-ip 203.0.113.99 --path /api/auth/login --method POST --env test --app df7ab010-37ac-4732-88ac-a8ac23afe1a4` returns a decision.
- **Rollback:** `npx securenow firewall disable --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --env test`
- **Links:** [B8](#threat-b8)


<a id="todo-auth-03"></a>
#### AUTH-03 · Keep the account-wide auto-block automations from hitting the lab by surprise — DO NOW · HIGH
- **Owner:** SecureNow · **Effort:** S · **Priority:** high
- **Why it matters:** Four active automations apply to every app, including one that blocks an IP on all routes for 24 h when a prod-mode alert name contains “brute force”, “flood”, “many accounts” or “credential stuffing”, plus three risk-score auto-blocks (24 h / 72 h / 168 h). The presenter’s own IP could be blocked mid-recording.
- **Action:** Keep every lab rule in test mode while recording. All rule names in this report avoid the four trigger phrases. Review with `npx securenow automation show 6a2a70daec31fced2eb2a9dc` and decide whether to scope it away from lab-auth (dashboard or `automation update`).
- **Prerequisite:** None.
- **Expected security outcome:** No lab notification can trigger a global block until a person promotes a rule on purpose.
- **Verify / definition of done:** `npx securenow automation dry-run 6a2a70daec31fced2eb2a9dc` shows no lab-auth matches.
- **Rollback:** —
- **Links:** [M63](#threat-m63) · [F15](authentication-code-findings.md#finding-f15)


<a id="todo-auth-04"></a>
#### AUTH-04 · Add an out-of-band alert channel before creating rules — DO NOW · HIGH
- **Owner:** SecureNow · **Effort:** S · **Priority:** high
- **Why it matters:** `alerts channels` lists only the in-app SecureNow channel, so nobody is paged. Channels can only be attached when a rule is created from the CLI (`alerts rules update` cannot change them).
- **Action:** Add an email, Slack or webhook channel in the SecureNow dashboard, then `npx securenow alerts channels --json` and add `--channel <in-app id>,<new id>` to every create command in §7.
- **Prerequisite:** None.
- **Expected security outcome:** Alerts reach a person outside the dashboard.
- **Verify / definition of done:** A test-mode alert arrives in the new channel.
- **Rollback:** Remove the channel in the dashboard.
- **Links:** [M60](#threat-m60)


<a id="todo-auth-05"></a>
#### AUTH-05 · Create the 9 traffic rules (R01–R09) in test mode — DO NOW · HIGH
- **Owner:** SecureNow · **Effort:** S · **Priority:** high
- **Why it matters:** They need no app code — only the SDK preload.
- **Action:** Run §10 steps ③–④ for R01–R09.
- **Prerequisite:** AUTH-01, ideally AUTH-04.
- **Expected security outcome:** Guessing, post-limit hammering, session minting, CSRF floods, scanning, network rotation, hashing load, sign-up spikes and proxy anomalies are detected (notify-only while in test mode).
- **Verify / definition of done:** Each create prints “dry-run clean”; `npx securenow alerts rules list --mode test --json` lists them.
- **Rollback:** `npx securenow alerts rules update <id> --disable`
- **Links:** [A1](#threat-a1) · [A2](#threat-a2) · [B8](#threat-b8) · [C13](#threat-c13) · [H40](#threat-h40) · [I45a](#threat-i45a) · [J46](#threat-j46) · [J47](#threat-j47) · [M62](#threat-m62) · [S1](#threat-s1) · [R01](#rule-r01) · [R02](#rule-r02) · [R03](#rule-r03) · [R04](#rule-r04) · [R05](#rule-r05) · [R06](#rule-r06) · [R07](#rule-r07) · [R08](#rule-r08) · [R09](#rule-r09)


<a id="todo-auth-06"></a>
#### AUTH-06 · Stop anonymous visitors from creating database sessions — DO NOW · HIGH
- **Owner:** App · **Effort:** M · **Priority:** high
- **Why it matters:** Each cookieless GET of `/api/me` writes a PostgreSQL row with no limit.
- **Action:** Finding F1 — signed double-submit CSRF cookie for anonymous visitors; create the server session only in `authenticate()` (`src/app.js:150-155`).
- **Prerequisite:** None.
- **Expected security outcome:** Unauthenticated traffic no longer grows the database.
- **Verify / definition of done:** 65 cookieless GETs against a local copy add 0 `sessions` rows; CSRF tests still pass.
- **Rollback:** Revert the commit.
- **Links:** [J47](#threat-j47) · [R03](#rule-r03) · [F1](authentication-code-findings.md#finding-f1)


<a id="todo-auth-07"></a>
#### AUTH-07 · Cap audit writes from rejected requests — DO NOW · MEDIUM
- **Owner:** App · **Effort:** S · **Priority:** medium
- **Why it matters:** Each CSRF rejection and each over-limit request writes an audit row; a flood hides real events from the 100-row Security page.
- **Action:** Finding F2 (`src/app.js:104-106, 132-134, 279`).
- **Prerequisite:** None.
- **Expected security outcome:** The audit trail stays readable under attack.
- **Verify / definition of done:** 100 rejected requests add ≤ 1 row per window.
- **Rollback:** Revert the commit.
- **Links:** [S1](#threat-s1) · [C13](#threat-c13) · [R04](#rule-r04) · [R02](#rule-r02) · [F2](authentication-code-findings.md#finding-f2)


<a id="todo-auth-08"></a>
#### AUTH-08 · Make routing strict and case-sensitive — DO NOW · HIGH
- **Owner:** App · **Effort:** S · **Priority:** high
- **Why it matters:** `/API/AUTH/LOGIN` and `/api/auth/login/` reach the login handler but not exact-path SecureNow rules.
- **Action:** Finding F6: `app.set('case sensitive routing', true); app.set('strict routing', true);` right after `express()` (`src/app.js:35`); update `scripts/smoke.mjs:37`.
- **Prerequisite:** None.
- **Expected security outcome:** Edge mitigations cannot be sidestepped by letter case; SecureNow rules can use exact paths.
- **Verify / definition of done:** `POST /API/AUTH/LOGIN` → 404 locally.
- **Rollback:** Remove the two settings.
- **Links:** [M62](#threat-m62) · [F6](authentication-code-findings.md#finding-f6)




### NEXT 7 DAYS (9)


<a id="todo-auth-09"></a>
#### AUTH-09 · Export auth events with track() and wire the sessions guard — NEXT 7 DAYS · HIGH
- **Owner:** App · **Effort:** M · **Priority:** high
- **Why it matters:** The audit helper writes only to PostgreSQL; 29 threats need privacy-safe events in SecureNow.
- **Action:** Add `src/securenow-bridge.js` and the 13 `emit(...)` calls plus `guard()` at the exact lines in the code report’s instrumentation section.
- **Prerequisite:** AUTH-01.
- **Expected security outcome:** Event-based rules R10–R27 have data; manual session revocation becomes enforceable.
- **Verify / definition of done:** `npx securenow telemetry fields --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --since 24h --source logs --env test` lists event types auth.login.failure, auth.login.success, auth.signup, auth.security.change, session.seen and the attribute account_ref.
- **Rollback:** Remove the bridge import; events stop, the app is unaffected (track() never throws).
- **Links:** [A3](#threat-a3) · [C9](#threat-c9) · [C11](#threat-c11) · [H41](#threat-h41)


<a id="todo-auth-10"></a>
#### AUTH-10 · Create the 18 event-based rules (R10–R27) in test mode — NEXT 7 DAYS · HIGH
- **Owner:** SecureNow · **Effort:** S · **Priority:** high
- **Why it matters:** Detections for stuffing, distributed guessing, lockout, session theft, takeover sequences and event integrity.
- **Action:** §10 steps ③–④ for R10–R27.
- **Prerequisite:** AUTH-09 verified.
- **Expected security outcome:** 29 event-based threats detected (notify-only while in test mode).
- **Verify / definition of done:** Each create prints “dry-run clean”.
- **Rollback:** `npx securenow alerts rules update <id> --disable`
- **Links:** [A3](#threat-a3) · [H41](#threat-h41) · [C16c](#threat-c16c) · [R10](#rule-r10) · [R11](#rule-r11) · [R12](#rule-r12) · [R13](#rule-r13) · [R14](#rule-r14) · [R15](#rule-r15) · [R16](#rule-r16) · [R17](#rule-r17) · [R18](#rule-r18) · [R19](#rule-r19) · [R20](#rule-r20) · [R21](#rule-r21) · [R22](#rule-r22) · [R23](#rule-r23) · [R24](#rule-r24) · [R25](#rule-r25) · [R26](#rule-r26) · [R27](#rule-r27)


<a id="todo-auth-11"></a>
#### AUTH-11 · Create the 7 rule-bound automations, disabled — NEXT 7 DAYS · MEDIUM
- **Owner:** SecureNow · **Effort:** S · **Priority:** medium
- **Why it matters:** Scoped responses (rate limits, a risk-gated route block, a GET-only challenge) that act only on named lab rules.
- **Action:** §10 step ⑥ (AUTO-A … AUTO-G, all `--app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --env test --status disabled`).
- **Prerequisite:** AUTH-05, AUTH-10.
- **Expected security outcome:** Responses are ready but inert until promotion.
- **Verify / definition of done:** `npx securenow automation dry-run <id>` for each.
- **Rollback:** `npx securenow automation delete <id> --yes`
- **Links:** [A1](#threat-a1) · [B8](#threat-b8) · [J47](#threat-j47) · [R01](#rule-r01) · [R03](#rule-r03) · [R05](#rule-r05)


<a id="todo-auth-12"></a>
#### AUTH-12 · Run synthetic tests and dry-runs; measure baselines after 3–7 days — NEXT 7 DAYS · MEDIUM
- **Owner:** SecureNow · **Effort:** S · **Priority:** medium
- **Why it matters:** Every threshold here comes from the app’s own limits or is a conservative start — no lab baseline exists yet.
- **Action:** §11 recipes; then `npx securenow alerts rules validate <any lab rule id> --sql @threat/01-authentication/rules/_baseline-auth-posts.sql --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --json`.
- **Prerequisite:** AUTH-05/10.
- **Expected security outcome:** Each rule proven to fire; thresholds re-based on p99 × 3–5.
- **Verify / definition of done:** Each event test returns `resultCount ≥ 1`; baseline returns p99/max per route.
- **Rollback:** —
- **Links:** [A1](#threat-a1) · [H41](#threat-h41) · [C11a](#threat-c11a) · [R01](#rule-r01) · [R10](#rule-r10) · [R18](#rule-r18) · [§11 Testing & validation](#testing)


<a id="todo-auth-13"></a>
#### AUTH-13 · Stop attackers from locking a known member out — NEXT 7 DAYS · HIGH
- **Owner:** App · **Effort:** M · **Priority:** high
- **Why it matters:** 31 requests per 15 minutes from 3 IPs keep any password member out.
- **Action:** Finding F3 (device-trust cookie; count failures only) at `src/app.js:124-131, 173`.
- **Prerequisite:** None.
- **Expected security outcome:** Owners keep signing in from their usual browser during an attack.
- **Verify / definition of done:** Lockout test in F3’s definition of done.
- **Rollback:** Revert the commit.
- **Links:** [H41](#threat-h41) · [A2](#threat-a2) · [R14](#rule-r14) · [F3](authentication-code-findings.md#finding-f3)


<a id="todo-auth-14"></a>
#### AUTH-14 · Require recent re-authentication for admin role changes — NEXT 7 DAYS · HIGH
- **Owner:** App · **Effort:** M · **Priority:** high
- **Why it matters:** A stolen admin session can create new admins silently.
- **Action:** Finding F5, step-up part (`src/app.js:291-299`).
- **Prerequisite:** None.
- **Expected security outcome:** A stolen admin cookie alone cannot grant roles.
- **Verify / definition of done:** Role change without re-auth in 5 min → 403.
- **Rollback:** Revert the commit.
- **Links:** [L54a](#threat-l54a) · [R21](#rule-r21) · [F5](authentication-code-findings.md#finding-f5)


<a id="todo-auth-15"></a>
#### AUTH-15 · Let the single-page app complete a SecureNow challenge — NEXT 7 DAYS · MEDIUM
- **Owner:** App · **Effort:** S · **Priority:** medium
- **Why it matters:** Challenges on JSON routes would otherwise lock real users out.
- **Action:** Finding F15 (`public/app.js:76-84`).
- **Prerequisite:** None.
- **Expected security outcome:** Challenges become a safe response on `/api/auth` too.
- **Verify / definition of done:** F15 definition of done.
- **Rollback:** Revert the commit.
- **Links:** [M63](#threat-m63) · [R05](#rule-r05) · [F15](authentication-code-findings.md#finding-f15)


<a id="todo-auth-16"></a>
#### AUTH-16 · A person promotes clean rules and enables their automations (after 3–7 days) — NEXT 7 DAYS · MEDIUM
- **Owner:** SecureNow · **Effort:** S · **Priority:** medium
- **Why it matters:** Test mode is detect-only; mitigations act only on prod-mode rules.
- **Action:** `npx securenow alerts rules promote <id>` per rule, then `npx securenow automation update <AUTO_ID> --status active`. Never during a recording unless intended.
- **Prerequisite:** AUTH-12 clean for 3–7 days; AUTH-03 decided.
- **Expected security outcome:** Scoped responses start working.
- **Verify / definition of done:** `npx securenow alerts rules list --mode prod --json`.
- **Rollback:** `npx securenow alerts rules demote <id>`; `npx securenow automation update <id> --status disabled`.
- **Links:** [M63](#threat-m63) · [§10 step ⑧](#plan) · [§13 governance](#governance)


<a id="todo-auth-17"></a>
#### AUTH-17 · Report the SecureNow product issues found in this run — NEXT 7 DAYS · MEDIUM
- **Owner:** SecureNow · **Effort:** S · **Priority:** medium
- **Why it matters:** `revoke list` returned HTTP 404 (the 8.12.0 CLI calls `/api/revocations` while the SDK guard syncs from `/api/v1/revocations/sync`), so manual revocation may not work; header capture cannot be redacted by config; firewall path matching is case-sensitive with no normalization option.
- **Action:** Contact your SecureNow account contact (or in-dashboard support) with the “SecureNow product issues” list in §14.
- **Prerequisite:** None.
- **Expected security outcome:** Revocation, redaction and path normalization become reliable.
- **Verify / definition of done:** `npx securenow revoke list --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --json` returns a list.
- **Rollback:** —
- **Links:** [C9](#threat-c9) · [C11](#threat-c11) · [D21](#threat-d21)




### LATER / HARDENING (12)


<a id="todo-auth-18"></a>
#### AUTH-18 · Verify email ownership and let a verified Google sign-in reclaim a squatted address — LATER / HARDENING · MEDIUM
- **Owner:** App · **Effort:** L · **Priority:** medium
- **Why it matters:** Removes squatting, the Google lock-out and the register-then-sign-in oracle.
- **Action:** Finding F4.
- **Prerequisite:** An email channel with the auth-message limits from this model’s E-section.
- **Expected security outcome:** Only mailbox owners hold accounts.
- **Verify / definition of done:** F4 definition of done.
- **Rollback:** Feature flag.
- **Links:** [B6](#threat-b6) · [G36c](#threat-g36c) · [H40a](#threat-h40a) · [H40b](#threat-h40b) · [R23](#rule-r23) · [R16](#rule-r16) · [F4](authentication-code-findings.md#finding-f4)


<a id="todo-auth-19"></a>
#### AUTH-19 · Add passkeys or TOTP for admin and analyst, and notify on security changes — LATER / HARDENING · MEDIUM
- **Owner:** App · **Effort:** L · **Priority:** medium
- **Why it matters:** One password or one stolen admin session is the whole account today.
- **Action:** Finding F5 (MFA + notifications part).
- **Prerequisite:** AUTH-14; email channel for notices.
- **Expected security outcome:** Phishing a password alone no longer grants admin.
- **Verify / definition of done:** Admin sign-in requires the second factor.
- **Rollback:** Feature flag per role.
- **Links:** [S2](#threat-s2) · [C16](#threat-c16) · [H39a](#threat-h39a) · [F5](authentication-code-findings.md#finding-f5)


<a id="todo-auth-20"></a>
#### AUTH-20 · Add sign-out-everywhere, a members’ own-sessions view and an admin revoke action — LATER / HARDENING · MEDIUM
- **Owner:** App · **Effort:** M · **Priority:** medium
- **Why it matters:** Google-only members have no kill switch.
- **Action:** Finding F7.
- **Prerequisite:** None.
- **Expected security outcome:** Any member or admin can end stolen sessions.
- **Verify / definition of done:** F7 definition of done.
- **Rollback:** Revert.
- **Links:** [C11](#threat-c11) · [C9](#threat-c9) · [R17](#rule-r17) · [R18](#rule-r18) · [F7](authentication-code-findings.md#finding-f7)


<a id="todo-auth-21"></a>
#### AUTH-21 · Raise scrypt cost with rehash-on-sign-in and bound concurrent hashing — LATER / HARDENING · LOW
- **Owner:** App · **Effort:** S · **Priority:** low
- **Why it matters:** Hashes are below OWASP minimum and cannot be upgraded; hashing has no concurrency cap.
- **Action:** Findings F8 and F9.
- **Prerequisite:** Do F9 before or with F8.
- **Expected security outcome:** Stronger hashes without a DoS lever.
- **Verify / definition of done:** F8/F9 definitions of done.
- **Rollback:** Revert; old hashes still verify.
- **Links:** [K49](#threat-k49) · [A5a](#threat-a5a) · [J46](#threat-j46) · [R07](#rule-r07) · [F8](authentication-code-findings.md#finding-f8) · [F9](authentication-code-findings.md#finding-f9)


<a id="todo-auth-22"></a>
#### AUTH-22 · Screen breached passwords and normalize Unicode — LATER / HARDENING · LOW
- **Owner:** App · **Effort:** S · **Priority:** low
- **Why it matters:** Reused passwords succeed; NFC/NFD users get locked out.
- **Action:** Finding F10.
- **Prerequisite:** None.
- **Expected security outcome:** Sprayed and breached passwords are refused.
- **Verify / definition of done:** F10 definition of done.
- **Rollback:** Feature flag.
- **Links:** [A3](#threat-a3) · [A4](#threat-a4) · [A5a](#threat-a5a) · [R10](#rule-r10) · [F10](authentication-code-findings.md#finding-f10)


<a id="todo-auth-23"></a>
#### AUTH-23 · Key IPv6 clients by /64 and smooth the rate-limit window — LATER / HARDENING · LOW
- **Owner:** App · **Effort:** S · **Priority:** low
- **Why it matters:** IPv6 rotation and boundary bursts weaken per-IP limits.
- **Action:** Finding F11.
- **Prerequisite:** None.
- **Expected security outcome:** Per-IP limits hold for IPv6.
- **Verify / definition of done:** F11 definition of done.
- **Rollback:** Revert.
- **Links:** [A4a](#threat-a4a) · [A2](#threat-a2) · [R06](#rule-r06) · [F11](authentication-code-findings.md#finding-f11)


<a id="todo-auth-24"></a>
#### AUTH-24 · Remove the bootstrap admin password from the runtime secret — LATER / HARDENING · LOW
- **Owner:** App · **Effort:** S · **Priority:** low
- **Why it matters:** It stays readable by the instance role forever.
- **Action:** Finding F12 (`infra/update.sh`).
- **Prerequisite:** Admin has changed their password.
- **Expected security outcome:** No standing admin credential in AWS.
- **Verify / definition of done:** Secret has no usable ADMIN_PASSWORD.
- **Rollback:** Re-add a one-time value for a fresh bootstrap.
- **Links:** [A5](#threat-a5) · [F12](authentication-code-findings.md#finding-f12)


<a id="todo-auth-25"></a>
#### AUTH-25 · Leave live sessions out of database backups — LATER / HARDENING · LOW
- **Owner:** App · **Effort:** S · **Priority:** low
- **Why it matters:** Backups hold every live session ID and in-flight Google transaction.
- **Action:** Finding F14 (`infra/backup.sh:6`).
- **Prerequisite:** None.
- **Expected security outcome:** Backups contain no session material.
- **Verify / definition of done:** Restore drill shows empty sessions table.
- **Rollback:** Remove the two flags.
- **Links:** [D21a](#threat-d21a) · [F14](authentication-code-findings.md#finding-f14)


<a id="todo-auth-26"></a>
#### AUTH-26 · Record the previous sign-in time so dormant accounts can be flagged — LATER / HARDENING · LOW
- **Owner:** App · **Effort:** S · **Priority:** low
- **Why it matters:** R22 needs `dormant_days`; the users table has no last-sign-in column.
- **Action:** Migration `ALTER TABLE users ADD COLUMN last_login_at timestamptz`; in `authenticate()` (`src/app.js:139-149`) read the old value, compute days, then update it; pass `dormant_days` on `auth.login.success`.
- **Prerequisite:** AUTH-09.
- **Expected security outcome:** Dormant-account sign-ins are visible.
- **Verify / definition of done:** R22 synthetic test; a real 90-day-old test account triggers it.
- **Rollback:** Drop the column.
- **Links:** [C16b](#threat-c16b) · [H40c](#threat-h40c) · [R22](#rule-r22)


<a id="todo-auth-27"></a>
#### AUTH-27 · Independent checks for uptime, telemetry freshness, certificates and the rule set — LATER / HARDENING · MEDIUM
- **Owner:** External monitor · **Effort:** M · **Priority:** medium
- **Why it matters:** A dead exporter, a paused rule or a lapsed certificate cannot alert through SecureNow itself.
- **Action:** From a separate scheduler (for example a GitHub Actions cron or an uptime service): `curl -f https://lab-auth.labs.securenow.ai/readyz`; `npx securenow telemetry fields --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --since 1h --source traces --env test --json` must list `http.target`; diff `npx securenow alerts rules list --json` against the 27-rule manifest in §13; certificate expiry > 14 days.
- **Prerequisite:** AUTH-05.
- **Expected security outcome:** Silence is noticed within an hour.
- **Verify / definition of done:** Stop the app on a copy: the external check fails.
- **Rollback:** Disable the cron.
- **Links:** [M56](#threat-m56) · [M60](#threat-m60) · [M60a](#threat-m60a) · [K50](#threat-k50)


<a id="todo-auth-28"></a>
#### AUTH-28 · Watch the Google Cloud OAuth client and confirm its settings — LATER / HARDENING · LOW
- **Owner:** Provider · **Effort:** S · **Priority:** low
- **Why it matters:** Changes to redirect URIs or the client secret are invisible to SecureNow, and console settings cannot be verified from the repo.
- **Action:** Enable a Cloud Audit Logs alert on OAuth client changes; confirm the authorized redirect URIs are exactly the two in docs/google-oauth.md and that the audience/publishing status is intended; rotate the client secret on staff changes.
- **Prerequisite:** Google Cloud project access.
- **Expected security outcome:** Google-side tampering is noticed.
- **Verify / definition of done:** Editing a test client raises the alert.
- **Rollback:** —
- **Links:** [M58](#threat-m58) · [G31](#threat-g31) · [G36e](#threat-g36e)


<a id="todo-auth-29"></a>
#### AUTH-29 · Page and search the admin user list — LATER / HARDENING · LOW
- **Owner:** App · **Effort:** S · **Priority:** low
- **Why it matters:** Only the newest 100 accounts are visible to admins.
- **Action:** Finding F16 (`src/app.js:287-289`).
- **Prerequisite:** None.
- **Expected security outcome:** Admins can always find an account.
- **Verify / definition of done:** F16 definition of done.
- **Rollback:** Revert.
- **Links:** [H40](#threat-h40) · [R08](#rule-r08) · [F16](authentication-code-findings.md#finding-f16)




### ALREADY IN PLACE (7)


<a id="todo-auth-30"></a>
#### AUTH-30 · Atomic, shared rate limits and race-safe account creation — ALREADY IN PLACE · LOW
- **Owner:** App · **Effort:** S · **Priority:** low
- **Why it matters:** Stops single-IP guessing and duplicate/overwritten accounts.
- **Action:** PostgreSQL-backed counters (`src/app.js:124-138`), unique lowercase email and Google subject (`db/001_initial.sql:3,6`), ON CONFLICT inserts, explicit field picking on signup.
- **Prerequisite:** —
- **Expected security outcome:** In place.
- **Verify / definition of done:** Integration tests “durable rate limiting” and “registration is generic”.
- **Rollback:** —
- **Links:** [H38a](#threat-h38a) · [H40d](#threat-h40d) · [H40g](#threat-h40g) · [L54](#threat-l54)


<a id="todo-auth-31"></a>
#### AUTH-31 · Session hardening — ALREADY IN PLACE · LOW
- **Owner:** App · **Effort:** S · **Priority:** low
- **Why it matters:** Stops fixation, cookie theft over HTTP/JS and long-lived replay.
- **Action:** Regenerate on sign-in, `__Host-lab_auth` Secure/HttpOnly/SameSite=Lax, 30 min idle / 8 h absolute, version-based invalidation, ≥ 32-character secrets, HTTPS + HSTS.
- **Prerequisite:** —
- **Expected security outcome:** In place (verified live 2026-10-16).
- **Verify / definition of done:** `scripts/smoke.mjs` cookie assertions.
- **Rollback:** —
- **Links:** [C10](#threat-c10) · [C14](#threat-c14) · [C15](#threat-c15) · [D18](#threat-d18) · [K50](#threat-k50)


<a id="todo-auth-32"></a>
#### AUTH-32 · CSRF protection on every API write — ALREADY IN PLACE · LOW
- **Owner:** App · **Effort:** S · **Priority:** low
- **Why it matters:** Stops forged sign-in, sign-out, password and role changes.
- **Action:** Exact Origin + Sec-Fetch-Site + per-session token + JSON content type (`src/app.js:102-110`).
- **Prerequisite:** —
- **Expected security outcome:** In place.
- **Verify / definition of done:** Integration test “CSRF rejects cross-origin mutations”.
- **Rollback:** —
- **Links:** [C13](#threat-c13)


<a id="todo-auth-33"></a>
#### AUTH-33 · Hardened Google sign-in — ALREADY IN PLACE · LOW
- **Owner:** App · **Effort:** S · **Priority:** low
- **Why it matters:** Stops code injection, replay, token forgery and email-based account takeover.
- **Action:** State + nonce + PKCE S256, 10-minute single-use transaction, verifyIdToken (audience), issuer/subject/verified-email checks, identity keyed on subject, no email auto-linking, server-constant redirect URI.
- **Prerequisite:** —
- **Expected security outcome:** In place.
- **Verify / definition of done:** Integration tests for nonce and linking.
- **Rollback:** —
- **Links:** [G31](#threat-g31) · [G32](#threat-g32) · [G33](#threat-g33) · [G34](#threat-g34) · [G36a](#threat-g36a) · [G36b](#threat-g36b) · [D19](#threat-d19)


<a id="todo-auth-34"></a>
#### AUTH-34 · Careful password storage and uniform answers — ALREADY IN PLACE · LOW
- **Owner:** App · **Effort:** S · **Priority:** low
- **Why it matters:** Stops timing/response enumeration and offline cracking at plain-hash speed.
- **Action:** Salted scrypt, constant-time compare, dummy hash for unknown accounts, identical login/registration responses.
- **Prerequisite:** —
- **Expected security outcome:** In place.
- **Verify / definition of done:** Integration test “failed login is generic”.
- **Rollback:** —
- **Links:** [B6](#threat-b6) · [A5a](#threat-a5a)


<a id="todo-auth-35"></a>
#### AUTH-35 · Trustworthy client IPs and private internals — ALREADY IN PLACE · LOW
- **Owner:** App · **Effort:** S · **Priority:** low
- **Why it matters:** Stops IP spoofing around per-IP limits and direct access to the app or database.
- **Action:** Caddy overwrites X-Forwarded-For; app trusts one hop; app/database ports unpublished; health endpoints minimal.
- **Prerequisite:** —
- **Expected security outcome:** In place (docs/verification.md).
- **Verify / definition of done:** R09 stays at zero.
- **Rollback:** —
- **Links:** [I45](#threat-i45) · [I45a](#threat-i45a) · [R09](#rule-r09)


<a id="todo-auth-36"></a>
#### AUTH-36 · Secrets kept out of Git and images — ALREADY IN PLACE · LOW
- **Owner:** App · **Effort:** S · **Priority:** low
- **Why it matters:** Stops leaked OAuth/session/runtime credentials.
- **Action:** CI secret scan, .gitignore/.dockerignore, AWS Secrets Manager; Git history (4 commits) scanned clean in this run.
- **Prerequisite:** —
- **Expected security outcome:** In place.
- **Verify / definition of done:** `node scripts/check-secrets.mjs` in CI.
- **Rollback:** —
- **Links:** [K51](#threat-k51)




> **Order matters:** AUTH-04 (out-of-band channel) before AUTH-05/AUTH-10, because the CLI can attach channels only when a rule is created. Keep every rule in test mode during recordings (AUTH-03).



<a id="lanes"></a>
## 3. How SecureNow helps — at a glance

- **Protected now from traffic — 11:** Once the SDK preload runs, SecureNow sees every HTTP request: method, normalized path, status, latency, client IP and redacted headers. Example: 10 HTTP 401s on `POST /api/auth/login` from one IP (R01). It can alert, rate-limit, challenge or block that IP on a route. It cannot see which account was targeted or whether a password was right.
- **Protected after app events — 29:** SecureNow receives the privacy-safe events the app emits with `track()` and `guard()`: outcome, method, keyed account reference, session hash, IP. Example: one account failing from 6 IPs (R11) or a session surviving a password change (R18). It can correlate across requests and time; it cannot invent events the app does not send.
- **Protected after provider data — 2:** Needs Google-side signals delivered by an authenticated adapter. Example: an OAuth client’s redirect URIs edited in Google Cloud (M58). No adapter exists, so these are gaps today.
- **Needs an external monitor — 4:** Things SecureNow cannot prove about itself: a dead exporter, a paused rule, an unread in-app alert, an expiring certificate. Example: the app runs but `telemetry fields` shows no traces for an hour (M56).
- **App/provider prevention — 21:** Properties that live in code or configuration and never show up in traffic: hash cost, cookie flags, session lifetime, backups, response safety. Example: scrypt parameters below OWASP minimum (K49). SecureNow cannot detect or fix these; the app must.


Lane counts are the signal-source classes of the 67 modeled threats (they add up to 67). “Protected now from traffic” means: works the moment the SDK preload is running — no app code. Nothing is protected by SecureNow today because the SDK is not loaded.

`Attacker action → HTTP / event / provider signal → SecureNow SQL rule → notification (human queue) → scoped response (rate limit, challenge, route block, revoke) → permanent app/provider fix`


**Detect, mitigate and fix are different things.** Detection notices the behavior (a rule fires). Mitigation contains the current actor (rate limit, challenge, route-scoped block, session revocation). The fix removes the weakness in code or configuration so the attack stops working at all.


<a id="scenarios"></a>
## 4. Attack scenarios — what happens and how we stop it

One card per modeled threat (67), highest priority first. Filter labels: **Works now** = traffic rules that need only the SDK preload (nothing is detected today because the SDK is not loaded); **Needs event** = needs the `track()`/`guard()` bridge; **Needs provider** = needs Google-side data; **Gap** = outside SecureNow (app prevention or external monitor).

<a id="threat-a1"></a>
#### A1 · Single-IP password guessing on the sign-in form
**HIGH · 🟡 PARTIAL · NATIVE_TRAFFIC · works on SDK load (traffic)** · OWASP A07:2021 · CWE-307 · [R01](#rule-r01) · [R02](#rule-r02) · [R10](#rule-r10) · [F6](authentication-code-findings.md#finding-f6) · [F11](authentication-code-findings.md#finding-f11) · [AUTH-01](#todo-auth-01) · [AUTH-05](#todo-auth-05) · [AUTH-11](#todo-auth-11)

**In one sentence:** An attacker can script wrong-password attempts against `POST /api/auth/login` from one address to guess a member’s password. SecureNow sees every sign-in request as an HTTP trace, detects 10 or more 401 answers from one IP in 15 minutes, and contains the IP with a 24-hour route-scoped rate limit. Your app must keep its own 15-per-15-minute limit and make routing strict so `/API/AUTH/LOGIN` cannot dodge the SecureNow rule.

- **Attack scenario:** An attacker can send wrong passwords to `POST /api/auth/login` from one IP. The app already answers 429 after 15 requests per 15 minutes (`src/app.js:173`, `src/config.js:24`), so a single IP gets at most about 1,440 attempts a day (and one account at most 2,880 a day across all IPs). Because Express 5 routing is case-insensitive and ignores a trailing slash, the same handler also answers `/API/AUTH/LOGIN` — harmless for the app’s own limiter (keyed by name), but it can dodge an exact-path SecureNow rule.
- **How SecureNow detects it:** Works the moment the SDK preload runs (no app events). Rule [R01](#rule-r01) counts HTTP 401 answers on the normalized route `/api/auth/login` per IP: 10 in 15 minutes, every 5 minutes, test mode. [R02](#rule-r02) adds IPs that keep going after the app’s 429. With events, [R10](#rule-r10) also sees how many different accounts one IP targets. Each hit becomes a test-mode notification in the human queue. Signal: ≥ 10 HTTP 401 on POST /api/auth/login per IP / 15 min (R01); ≥ 5 HTTP 429 per IP / 15 min (R02), evaluated every 5 minutes. Rules are created in test mode, so each hit is a notification in the human queue (`npx securenow human list`) with no automatic action until a person promotes the rule (test-first).
- **How SecureNow mitigates it:** After promotion, automation AUTO-A rate-limits that IP to 5 sign-in POSTs per 15 minutes for 24 hours on a case-insensitive login regex; AUTO-B blocks POSTs to `/api/auth/*` for 24 hours only when SecureNow’s risk score is ≥ 90. Reverse with `ratelimit remove` / `blocklist unblock` (commands in §9).
- **What you still need to do:** Keep the native limiter. Make routing strict and case-sensitive ([F6](authentication-code-findings.md#finding-f6)) and key IPv6 clients by /64 ([F11](authentication-code-findings.md#finding-f11)).
- **Limits and false-positive safety:** Shared office/classroom IPs (and the tutorial presenter) can trip R01 — it ships in test mode and the response is a rate limit, not a block. A guessed password still works; detection does not fix weak passwords.
- **Definition of done:** R01 created in test mode; 10 wrong passwords against the local copy produce `resultCount ≥ 1` on `alerts rules test --mode dry_run`; AUTO-A exists with `--status disabled`. Commands: [R01](#rule-r01), [R02](#rule-r02), [R10](#rule-r10).

<a id="threat-i45a"></a>
#### I45a · Spoofed forwarding headers or proxy bypass
**HIGH · 🟡 PARTIAL · NATIVE_TRAFFIC · works on SDK load (traffic)** · OWASP A07:2021 · CWE-348 · [R09](#rule-r09) · [AUTH-05](#todo-auth-05) · [AUTH-35](#todo-auth-35)

**In one sentence:** An attacker cannot fake their IP to dodge the app’s per-IP limits today, because Caddy overwrites X-Forwarded-For and the app trusts exactly one hop. SecureNow sees the recorded forwarding chain on every request, detects any request with a multi-hop chain or one that bypassed Caddy, and alerts immediately. Your deployment must keep Caddy as the only ingress.

- **Attack scenario:** An attacker cannot fake their IP to dodge the app’s per-IP limits today, because Caddy overwrites X-Forwarded-For and the app trusts exactly one hop. `infra/Caddyfile:5`, `TRUST_PROXY=1` (`compose.production.yaml:28`, `src/app.js:51`); verified in `docs/verification.md`.
- **How SecureNow detects it:** [R09](#rule-r09) + optional instant condition. Signal: any multi-hop X-Forwarded-For or untrusted direct socket, evaluated every 5 minutes. Rules are created in test mode, so each hit is a notification in the human queue (`npx securenow human list`) with no automatic action until a person promotes the rule (prod-ready).
- **How SecureNow mitigates it:** Notify — the fix is in the proxy config. Any manual action from §9 is time-boxed (`--duration`) and reversible (`ratelimit remove`, `blocklist unblock`, `revoke restore`).
- **What you still need to do:** Keep.
- **Limits and false-positive safety:** A future CDN in front will legitimately add a hop — update the rule then.
- **Definition of done:** R09 created; zero results for a week in production. Commands: [R09](#rule-r09).

<a id="threat-m63"></a>
#### M63 · Unsafe automated response (global blocks, challenges that break sign-in)
**HIGH · 🟡 PARTIAL · APP_OR_PROVIDER_CONTROL · outside SecureNow (app/external)** · OWASP A04:2021 · CWE-693 · [F15](authentication-code-findings.md#finding-f15) · [AUTH-03](#todo-auth-03) · [AUTH-15](#todo-auth-15) · [AUTH-16](#todo-auth-16)

**In one sentence:** An attacker (or the tutorial itself) can trigger a response that hurts real users: this account already has 4 active automations that apply to every app — including a custom one that blocks an IP on all routes for 24 hours whenever a prod-mode alert name contains “brute force”, “flood”, “many accounts” or “credential stuffing”. SecureNow lets you scope, approve and reverse every action. You must keep lab rules out of that automation’s reach and fix the SPA before using challenges on API routes.

- **Attack scenario:** An attacker (or the tutorial itself) can trigger a response that hurts real users: this account already has 4 active automations that apply to every app — including a custom one that blocks an IP on all routes for 24 hours whenever a prod-mode alert name contains “brute force”, “flood”, “many accounts” or “credential stuffing”. Automations ignore test-mode rules, so nothing happens until promotion. After promotion, a rule given a typical name such as “failed-login brute force” would globally block the presenter. A challenge on `/api/auth` answers the SPA’s `fetch()` with JSON 403 `challenge_required`, which `public/app.js:76-84` shows as “Something went wrong.”
- **How SecureNow detects it:** Not applicable. No rule: configuration review (not a detection).
- **How SecureNow mitigates it:** All 27 rule names here avoid the four trigger phrases; all 7 automations are scoped `--app … --env test` and created disabled. No SecureNow action, so nothing to reverse.
- **What you still need to do:** [F15](authentication-code-findings.md#finding-f15); review the account-wide automation (AUTH-03).
- **Limits and false-positive safety:** —
- **Definition of done:** `automation dry-run` of the account-wide automation shows no lab notifications.

<a id="threat-b8"></a>
#### B8 · Auth-surface scanning (forced browsing for .env, .git, admin panels)
**MEDIUM · 🟡 PARTIAL · NATIVE_TRAFFIC · works on SDK load (traffic)** · OWASP A05:2021 · CWE-425 · [R05](#rule-r05) · [AUTH-02](#todo-auth-02) · [AUTH-05](#todo-auth-05) · [AUTH-11](#todo-auth-11)

**In one sentence:** An attacker can scan the site for `/.env`, `/.git/config` or admin panels looking for leaked credentials. SecureNow sees every request path in traces, detects 3 such probes (or 30 not-found answers) from one IP in 15 minutes — or a single dotfile request with instant detection — and challenges or blocks that IP. Your app already answers 403/404; keep secrets out of the image (it does).

- **Attack scenario:** An attacker can scan the site for `/.env`, `/.git/config` or admin panels looking for leaked credentials. `express.static` denies dotfiles (`src/app.js:302`) and unknown paths return 404 (`src/app.js:300,303`), and the image excludes `.env`, `.securenow` and `.deployment` (`.dockerignore`). Scanning still burns resources and is the first step of most attacks.
- **How SecureNow detects it:** [R05](#rule-r05) (works on SDK load) plus the optional instant condition on dotfile paths (MCP payload in §7). Signal: ≥ 3 sensitive-path probes or ≥ 30 404/403 per IP / 15 min; instant on one dotfile request, evaluated every 5 minutes. Rules are created in test mode, so each hit is a notification in the human queue (`npx securenow human list`) with no automatic action until a person promotes the rule (test-first).
- **How SecureNow mitigates it:** Firewall feed (`firewall enable --env test`); AUTO-E challenges GET page loads from the IP for 24 h; instant block 24 h once promoted. Automated responses (AUTO-E) are created disabled, time-boxed to 24 h and reversible with `ratelimit remove` / `blocklist unblock` / `challenge remove` or `automation update <id> --status disabled` (§9).
- **What you still need to do:** Nothing new — keep `dotfiles: deny` and the `.dockerignore` list.
- **Limits and false-positive safety:** Scanners rotate IPs; the firewall’s hourly known-bad feed covers the noisy ones.
- **Definition of done:** R05 fires on the 3-path local test; firewall enabled for env test. Commands: [R05](#rule-r05).

<a id="threat-c13"></a>
#### C13 · CSRF against auth endpoints (and floods of CSRF-rejected requests)
**MEDIUM · 🟡 PARTIAL · NATIVE_TRAFFIC · works on SDK load (traffic)** · OWASP A01:2021 · CWE-352 · [R04](#rule-r04) · [F2](authentication-code-findings.md#finding-f2) · [AUTH-05](#todo-auth-05) · [AUTH-07](#todo-auth-07) · [AUTH-32](#todo-auth-32)

**In one sentence:** An attacker cannot make a victim’s browser sign in, sign out or change a password through a forged request, because every API write needs the exact Origin, a per-session token and JSON. But they can send thousands of rejected writes, each of which makes the app store an audit row. SecureNow sees the 403 answers and their headers, detects 20+ unverifiable writes from one IP in 15 minutes, and rate-limits API POSTs from it. Your app must stop writing one audit row per rejected request.

- **Attack scenario:** An attacker cannot make a victim’s browser sign in, sign out or change a password through a forged request, because every API write needs the exact Origin, a per-session token and JSON. But they can send thousands of rejected writes, each of which makes the app store an audit row. The CSRF gate (`src/app.js:102-110`) is strong. Every rejection, though, runs `INSERT INTO security_events` with no limit in front of it (`src/app.js:104-106`).
- **How SecureNow detects it:** [R04](#rule-r04) reads `origin` and `x-csrf-token` from the recorded request headers. Signal: ≥ 20 unverifiable 403 API mutations per IP / 15 min, evaluated every 5 minutes. Rules are created in test mode, so each hit is a notification in the human queue (`npx securenow human list`) with no automatic action until a person promotes the rule (test-first).
- **How SecureNow mitigates it:** AUTO-D after promotion. Automated responses (AUTO-D) are created disabled, time-boxed to 24 h and reversible with `ratelimit remove` / `blocklist unblock` / `challenge remove` or `automation update <id> --status disabled` (§9).
- **What you still need to do:** [F2](authentication-code-findings.md#finding-f2).
- **Limits and false-positive safety:** A real CSRF attempt arrives from many victims’ IPs at low volume — prevention, not detection, stops it.
- **Definition of done:** R04 fires on the 21-request local test. Commands: [R04](#rule-r04).

<a id="threat-j47"></a>
#### J47 · Session-store and audit-table growth from anonymous requests
**MEDIUM · 🟡 PARTIAL · NATIVE_TRAFFIC · works on SDK load (traffic)** · OWASP A04:2021 · CWE-770 · [R03](#rule-r03) · [R08](#rule-r08) · [F1](authentication-code-findings.md#finding-f1) · [AUTH-05](#todo-auth-05) · [AUTH-06](#todo-auth-06) · [AUTH-11](#todo-auth-11)

**In one sentence:** An attacker can make the app write a new PostgreSQL session row for every `GET /api/me` sent without a cookie — no sign-in and no rate limit needed — and fill the database. SecureNow sees each request and whether it carried a cookie, detects 60+ cookieless session requests from one IP in 15 minutes, and rate-limits those endpoints for that IP. Your app must stop persisting sessions for anonymous visitors.

- **Attack scenario:** An attacker can make the app write a new PostgreSQL session row for every `GET /api/me` sent without a cookie — no sign-in and no rate limit needed — and fill the database. `sessionResponse()` sets a CSRF token on every anonymous session (`src/app.js:150-155`), which makes express-session save it; a passive GET on 2026-10-16 confirmed a fresh `Set-Cookie` for `/api/me`.
- **How SecureNow detects it:** [R03](#rule-r03) (works on SDK load; needs the recorded request headers). Signal: ≥ 60 cookieless session-endpoint GETs per IP / 15 min (R03), evaluated every 5 minutes. Rules are created in test mode, so each hit is a notification in the human queue (`npx securenow human list`) with no automatic action until a person promotes the rule (test-first).
- **How SecureNow mitigates it:** AUTO-C after promotion. Automated responses (AUTO-C) are created disabled, time-boxed to 24 h and reversible with `ratelimit remove` / `blocklist unblock` / `challenge remove` or `automation update <id> --status disabled` (§9).
- **What you still need to do:** [F1](authentication-code-findings.md#finding-f1).
- **Limits and false-positive safety:** Distributed minting from many IPs stays under per-IP thresholds; only the app fix removes it.
- **Definition of done:** R03 fires on the 65-request local test; after F1, the same test creates no rows. Commands: [R03](#rule-r03), [R08](#rule-r08).

<a id="threat-m60"></a>
#### M60 · Alert rule disabled, edited or never run; alerts only in-app
**MEDIUM · 🔴 GAP · EXTERNAL_MONITOR · outside SecureNow (app/external)** · OWASP A09:2021 · CWE-778 · [AUTH-04](#todo-auth-04) · [AUTH-27](#todo-auth-27)

**In one sentence:** An attacker benefits if a rule is paused or a notification is never seen. Today the account has only the in-app notification channel, so nobody is paged. SecureNow cannot watch its own rule set; an outside check must. You must add an out-of-band channel before creating the rules.

- **Attack scenario:** An attacker benefits if a rule is paused or a notification is never seen. `alerts channels` returned one channel of type `securenow` (in-app).
- **How SecureNow detects it:** None in-band. (manifest diff of `alerts rules list --json` (external).)
- **How SecureNow mitigates it:** None. No SecureNow action, so nothing to reverse.
- **What you still need to do:** AUTH-04, AUTH-27.
- **Limits and false-positive safety:** Channels can only be attached at create time from the CLI.
- **Definition of done:** A test alert reaches email/Slack.

<a id="threat-m62"></a>
#### M62 · Evasion via route aliases, IPv6 rotation or spoofed headers
**MEDIUM · 🟡 PARTIAL · NATIVE_TRAFFIC · works on SDK load (traffic)** · OWASP A07:2021 · CWE-290 · [R06](#rule-r06) · [R09](#rule-r09) · [F6](authentication-code-findings.md#finding-f6) · [F11](authentication-code-findings.md#finding-f11) · [AUTH-05](#todo-auth-05) · [AUTH-08](#todo-auth-08)

**In one sentence:** An attacker can send `POST /API/AUTH/LOGIN` or `/api/auth/login/` — Express answers both — and slip past a SecureNow rate limit or block written for the exact path `/api/auth/login`, because the SDK firewall compares paths exactly. SecureNow’s detection rules in this report normalize paths, and every mitigation here uses a case-insensitive regex. Your app must make routing strict and case-sensitive so aliases return 404.

- **Attack scenario:** An attacker can send `POST /API/AUTH/LOGIN` or `/api/auth/login/` — Express answers both — and slip past a SecureNow rate limit or block written for the exact path `/api/auth/login`, because the SDK firewall compares paths exactly. Express 5 defaults: case-insensitive, non-strict routing; the repo’s own smoke test calls `/API/ME`. The SDK firewall’s `rulePathMatches` uses `===` / `startsWith` / an uncased RegExp (`node_modules/securenow/firewall.js:913-921`).
- **How SecureNow detects it:** All traffic rules apply `lower()` + trailing-slash trimming; [R06](#rule-r06), [R09](#rule-r09). Signal: per-network grouping; forwarding-chain anomaly; every traffic rule lowercases and strips trailing slashes, evaluated every 10 minutes. Rules are created in test mode, so each hit is a notification in the human queue (`npx securenow human list`) with no automatic action until a person promotes the rule (test-first).
- **How SecureNow mitigates it:** Use the regex patterns in §9 until F6 ships. Any manual action from §9 is time-boxed (`--duration`) and reversible (`ratelimit remove`, `blocklist unblock`, `revoke restore`).
- **What you still need to do:** [F6](authentication-code-findings.md#finding-f6).
- **Limits and false-positive safety:** —
- **Definition of done:** `/API/AUTH/LOGIN` returns 404 after F6. Commands: [R06](#rule-r06), [R09](#rule-r09).

<a id="threat-s1"></a>
#### S1 · Audit-trail flushing: rejected requests bury real events
**MEDIUM · 🟡 PARTIAL · NATIVE_TRAFFIC · works on SDK load (traffic)** · OWASP A09:2021 · CWE-779 · [R04](#rule-r04) · [R02](#rule-r02) · [F2](authentication-code-findings.md#finding-f2) · [AUTH-05](#todo-auth-05) · [AUTH-07](#todo-auth-07)

**In one sentence:** An attacker can push the evidence of their own sign-in attempts out of the analyst’s Security page, which shows only the newest 100 audit rows, by sending a few hundred unauthenticated rejected requests — each one writes a row. SecureNow sees the 403/429 answers in traces, detects the burst per IP, and rate-limits it. Your app must log at most one rejection per IP and category per window.

- **Attack scenario:** An attacker can push the evidence of their own sign-in attempts out of the analyst’s Security page, which shows only the newest 100 audit rows, by sending a few hundred unauthenticated rejected requests — each one writes a row. `csrf.rejected` (`src/app.js:105`) and `auth.rate_limited` (`src/app.js:133`) write on every rejected request; the view reads `LIMIT 100` (`src/app.js:279`); retention is 14 days (`src/server.js:13`).
- **How SecureNow detects it:** [R04](#rule-r04), [R02](#rule-r02). Signal: ≥ 20 CSRF-rejected writes (R04) or ≥ 5 post-limit requests (R02) per IP / 15 min, evaluated every 5 minutes. Rules are created in test mode, so each hit is a notification in the human queue (`npx securenow human list`) with no automatic action until a person promotes the rule (test-first).
- **How SecureNow mitigates it:** AUTO-D, AUTO-A. Automated responses (AUTO-D, AUTO-A, AUTO-B) are created disabled, time-boxed to 24 h and reversible with `ratelimit remove` / `blocklist unblock` / `challenge remove` or `automation update <id> --status disabled` (§9).
- **What you still need to do:** [F2](authentication-code-findings.md#finding-f2).
- **Limits and false-positive safety:** SecureNow keeps its own copy of the traces, so evidence survives there.
- **Definition of done:** After F2, 100 rejected requests add ≤ 1 audit row per window. Commands: [R04](#rule-r04), [R02](#rule-r02).

<a id="threat-d21"></a>
#### D21 · Token leakage into URLs, logs, Referer or telemetry
**LOW · 🔴 GAP · APP_OR_PROVIDER_CONTROL · outside SecureNow (app/external)** · OWASP A09:2021 · CWE-532 · [F13](authentication-code-findings.md#finding-f13) · [AUTH-01](#todo-auth-01) · [AUTH-17](#todo-auth-17)

**In one sentence:** An attacker who gains read access to the lab’s telemetry (a leaked SecureNow login, a screen share) could read values the lab never meant to export: with the SDK’s default settings, request bodies are captured, and the `X-CSRF-Token` header and the Google `state` query value are recorded. SecureNow cannot detect its own capture settings. Your app must turn body capture off before the first instrumented start, as the repo’s runbook already says.

- **Attack scenario:** An attacker who gains read access to the lab’s telemetry (a leaked SecureNow login, a screen share) could read values the lab never meant to export: with the SDK’s default settings, request bodies are captured, and the `X-CSRF-Token` header and the Google `state` query value are recorded. The app itself logs nothing sensitive (`src/app.js:307-309`), uses `Referrer-Policy: no-referrer` and keeps no tokens in localStorage. `npx securenow env` resolves `captureBody: true`; the tracer redacts cookie/authorization and OTP-like names in headers but not `x-csrf-token` (`node_modules/securenow/tracing.js:602-606`); the Google `code` is redacted, `state` is not.
- **How SecureNow detects it:** None. (no signal — a capture-configuration property.)
- **How SecureNow mitigates it:** None. No SecureNow action, so nothing to reverse.
- **What you still need to do:** [F13](authentication-code-findings.md#finding-f13).
- **Limits and false-positive safety:** Telemetry readers are operators, so impact is low.
- **Definition of done:** `npx securenow env` shows captureBody false; a sample trace has no request body.

<a id="threat-k52"></a>
#### K52 · Credentials or tokens captured in logs and traces
**LOW · 🔴 GAP · APP_OR_PROVIDER_CONTROL · outside SecureNow (app/external)** · OWASP A09:2021 · CWE-532 · [F13](authentication-code-findings.md#finding-f13) · [AUTH-01](#todo-auth-01)

**In one sentence:** An attacker with read access to telemetry could see request bodies (names, redacted emails/passwords) and CSRF header values if the SDK starts with its defaults. SecureNow cannot detect its own capture settings. Your deployment must set body and multipart capture off first.

- **Attack scenario:** An attacker with read access to telemetry could see request bodies (names, redacted emails/passwords) and CSRF header values if the SDK starts with its defaults. See D21.
- **How SecureNow detects it:** None. (no signal.)
- **How SecureNow mitigates it:** None. No SecureNow action, so nothing to reverse.
- **What you still need to do:** [F13](authentication-code-findings.md#finding-f13).
- **Limits and false-positive safety:** —
- **Definition of done:** Sample trace has no `http.request.body`.

<a id="threat-a2"></a>
#### A2 · Distributed / low-and-slow guessing that rotates addresses
**HIGH · 🟡 PARTIAL · NATIVE_TRAFFIC · works on SDK load (traffic)** · OWASP A07:2021 · CWE-307 · [R06](#rule-r06) · [R11](#rule-r11) · [R26](#rule-r26) · [F3](authentication-code-findings.md#finding-f3) · [F11](authentication-code-findings.md#finding-f11) · [AUTH-05](#todo-auth-05) · [AUTH-13](#todo-auth-13) · [AUTH-23](#todo-auth-23)

**In one sentence:** An attacker can spread guesses over many addresses of one network so no single IP reaches the app’s 15-attempt limit. SecureNow sees the failed sign-ins in HTTP traces, detects 15 failures from 4+ addresses of one /24 or /64 in 30 minutes, and alerts with the latest address for a scoped CIDR rate limit. Your app must add per-account and per-device controls that do not depend on IPs.

- **Attack scenario:** An attacker can rotate through IPv6 addresses in one /64 or IPv4 addresses in one /24 and stay under 15 failures per address. The per-account bucket (30 per 15 minutes) still caps guesses per account, but it also locks the real owner out (A2 and H41 share a root cause).
- **How SecureNow detects it:** Traffic rule [R06](#rule-r06) groups 401s by network block (works on SDK load). With events, [R11](#rule-r11) groups failures by the keyed `account_ref` (many IPs → one account), and [R26](#rule-r26) by ASN where the instance enriches events. All test mode. Signal: ≥ 4 IPs & ≥ 15 failures per /24 or /64 / 30 min (R06); ≥ 5 IPs & ≥ 12 failures per account / 30 min (R11), evaluated every 10 minutes. Rules are created in test mode, so each hit is a notification in the human queue (`npx securenow human list`) with no automatic action until a person promotes the rule (test-first).
- **How SecureNow mitigates it:** Notify. A person rate-limits the network block on the sign-in route: `npx securenow ratelimit add 203.0.113.0/24 --route ... --mode regex --method POST --limit 5 --window 15m --duration 24h --app … --env test`. Never lock the targeted account. Any manual action from §9 is time-boxed (`--duration`) and reversible (`ratelimit remove`, `blocklist unblock`, `revoke restore`).
- **What you still need to do:** Device-trust cookie so a known browser bypasses the per-account bucket ([F3](authentication-code-findings.md#finding-f3)); /64 keying ([F11](authentication-code-findings.md#finding-f11)).
- **Limits and false-positive safety:** Residential-proxy pools spread across unrelated networks defeat per-network grouping; only the per-account view (R11) and app-side controls catch those.
- **Definition of done:** R06 and R11 created; R11 fires on the 13-event synthetic test from 6 TEST-NET IPs. Commands: [R06](#rule-r06), [R11](#rule-r11), [R26](#rule-r26).

<a id="threat-a3"></a>
#### A3 · Credential stuffing with breached email/password pairs
**HIGH · 🟡 PARTIAL · APP_EVENT · needs app event** · OWASP A07:2021 · CWE-307 · [R10](#rule-r10) · [R13](#rule-r13) · [F10](authentication-code-findings.md#finding-f10) · [AUTH-09](#todo-auth-09) · [AUTH-10](#todo-auth-10) · [AUTH-22](#todo-auth-22)

**In one sentence:** An attacker can replay leaked email/password pairs from other sites against the sign-in form. SecureNow receives the app’s sign-in failure and success events, detects one IP failing against 5+ different accounts (or succeeding into 3+), and contains it with a 24-hour sign-in rate limit. Your app must emit those events and reject known-breached passwords.

- **Attack scenario:** An attacker can try one leaked pair per account from a single IP. Today HTTP traces show only “401 on /api/auth/login” — the app’s audit rows deliberately omit which account was targeted, so a list of 15 different accounts looks like one user mistyping.
- **How SecureNow detects it:** Needs the proposed `auth.login.failure` / `auth.login.success` events with a keyed `account_ref`. [R10](#rule-r10) fires on 10 failures over 5+ accounts per IP in 15 minutes; [R13](#rule-r13) on one IP signing into 3+ accounts in an hour. Signal: ≥ 10 failures over ≥ 5 accounts per IP / 15 min (R10); ≥ 3 accounts signed in per IP / 60 min (R13), evaluated every 5 minutes. Rules are created in test mode, so each hit is a notification in the human queue (`npx securenow human list`) with no automatic action until a person promotes the rule (test-first).
- **How SecureNow mitigates it:** AUTO-A (rate limit) after promotion; AUTO-B (24 h POST block on `/api/auth/*`) only at risk score ≥ 90. R13 is notify-only. Automated responses (AUTO-A, AUTO-B) are created disabled, time-boxed to 24 h and reversible with `ratelimit remove` / `blocklist unblock` / `challenge remove` or `automation update <id> --status disabled` (§9).
- **What you still need to do:** Add the event bridge ([instrumentation](authentication-code-findings.md#instrumentation)) and breached-password screening at registration and password change ([F10](authentication-code-findings.md#finding-f10)).
- **Limits and false-positive safety:** A stuffing run that uses one IP per account looks like A2, not A3; R11/R26 cover that shape.
- **Definition of done:** Bridge deployed; `telemetry fields --source logs` lists `auth.login.failure` with `account_ref`; R10 fires on the 11-event synthetic test. Commands: [R10](#rule-r10), [R13](#rule-r13).

<a id="threat-c9"></a>
#### C9 · Session cookie theft (malware, XSS, phishing proxy)
**HIGH · 🟡 PARTIAL · APP_EVENT · needs app event** · OWASP A07:2021 · CWE-294 · [R17](#rule-r17) · [R20](#rule-r20) · [F7](authentication-code-findings.md#finding-f7) · [AUTH-09](#todo-auth-09) · [AUTH-10](#todo-auth-10) · [AUTH-17](#todo-auth-17) · [AUTH-20](#todo-auth-20)

**In one sentence:** An attacker can steal a member’s session cookie (malware, a phishing proxy that relays the password) and use it from their own network for up to 8 hours. SecureNow receives `session.seen` events from the sessions guard, detects one account active from 3+ IPs in an hour or a password/role change from a different IP than the sign-in, and lets a person revoke that session. Your app must wire `guard()` to its express-session and give users a “sign out everywhere” button.

- **Attack scenario:** An attacker can steal a member’s session cookie (malware, a phishing proxy that relays the password) and use it from their own network for up to 8 hours. The cookie is HttpOnly + Secure + SameSite=Lax with a `__Host-` prefix and a strict CSP (good), so script theft is hard; malware and phishing proxies remain. A stolen session is a bearer credential until 30 minutes idle or 8 hours absolute.
- **How SecureNow detects it:** Needs `session.seen` from `securenow/sessions` `guard()` with `getSessionId`/`getUserId` (the guard’s default cookie list does not know `__Host-lab_auth`). [R17](#rule-r17) and [R20](#rule-r20), test mode, notify. Signal: one account seen from ≥ 3 IPs / 60 min (R17); security change from a different IP than sign-in (R20), evaluated every 15 minutes. Rules are created in test mode, so each hit is a notification in the human queue (`npx securenow human list`) with no automatic action until a person promotes the rule (test-first).
- **How SecureNow mitigates it:** A person runs `npx securenow revoke session <session.id> --app … --env test --duration 24h`; the guard rejects that session on its next request. In this run `revoke list` returned HTTP 404 (the 8.12.0 CLI calls `/api/revocations` while the SDK guard syncs from `/api/v1/revocations/sync`), so confirm the command works before relying on it — gap G-R1. Any manual action from §9 is time-boxed (`--duration`) and reversible (`ratelimit remove`, `blocklist unblock`, `revoke restore`).
- **What you still need to do:** Wire `guard()` ([instrumentation](authentication-code-findings.md#instrumentation)) and add sign-out-everywhere ([F7](authentication-code-findings.md#finding-f7)).
- **Limits and false-positive safety:** Travellers and mobile users trip R17. A phishing proxy used from the victim’s own region may never trip it.
- **Definition of done:** guard() deployed; R17 fires on the 3-IP synthetic test; a test revocation logs a session out. Commands: [R17](#rule-r17), [R20](#rule-r20).

<a id="threat-c11a"></a>
#### C11a · Sessions surviving a password change or role downgrade (regression)
**HIGH · 🟡 PARTIAL · APP_EVENT · needs app event** · OWASP A07:2021 · CWE-613 · [R18](#rule-r18) · [F7](authentication-code-findings.md#finding-f7) · [AUTH-09](#todo-auth-09) · [AUTH-10](#todo-auth-10)

**In one sentence:** An attacker who already holds a member’s session would keep it after the member changes their password if the version check ever regressed. SecureNow receives the password-change event and `session.seen`, detects any session that existed before the change still being used 5+ minutes after it, and a person revokes it. Your app must keep the `session_version` check (it does today).

- **Attack scenario:** An attacker who already holds a member’s session would keep it after the member changes their password if the version check ever regressed. Today a password or role change increments `session_version` and the next request from an older session is regenerated (`src/app.js:93`, `202`, `294`) — tested in the suite.
- **How SecureNow detects it:** [R18](#rule-r18) compares session IDs seen before and after the change, so a user signing in again elsewhere does not trip it. Signal: a pre-change session seen ≥ 5 min after a completed password change (1-day window), evaluated every 15 minutes. Rules are created in test mode, so each hit is a notification in the human queue (`npx securenow human list`) with no automatic action until a person promotes the rule (prod-ready).
- **How SecureNow mitigates it:** Revoke the surviving session; never an IP block. Any manual action from §9 is time-boxed (`--duration`) and reversible (`ratelimit remove`, `blocklist unblock`, `revoke restore`).
- **What you still need to do:** Keep the check; [F7](authentication-code-findings.md#finding-f7) adds user-facing controls.
- **Limits and false-positive safety:** Needs guard() on every authenticated route.
- **Definition of done:** R18 synthetic test (with the 5-minute wait) returns `surviving_sessions = 1`. Commands: [R18](#rule-r18).

<a id="threat-c16a"></a>
#### C16a · Successful sign-in right after failures, or one IP into several accounts
**HIGH · 🟡 PARTIAL · APP_EVENT · needs app event** · OWASP A07:2021 · CWE-307 · [R12](#rule-r12) · [R13](#rule-r13) · [F5](authentication-code-findings.md#finding-f5) · [AUTH-09](#todo-auth-09) · [AUTH-10](#todo-auth-10)

**In one sentence:** An attacker who finally guesses a password signs in right after a string of failures. SecureNow receives the failure and success events, detects 5+ failures followed by a success on one account within 30 minutes, and alerts with the IP that got in. Your app must give owners a way to be notified and to kill sessions.

- **Attack scenario:** An attacker who finally guesses a password signs in right after a string of failures. The app does not warn the owner about a sign-in after failures.
- **How SecureNow detects it:** [R12](#rule-r12) (ordered `sequenceMatch`), [R13](#rule-r13). Signal: ≥ 5 failures then success within 30 min (R12); ≥ 3 accounts per IP / 60 min (R13), evaluated every 10 minutes. Rules are created in test mode, so each hit is a notification in the human queue (`npx securenow human list`) with no automatic action until a person promotes the rule (test-first).
- **How SecureNow mitigates it:** Human review; revoke; never block the account owner’s IP automatically. Any manual action from §9 is time-boxed (`--duration`) and reversible (`ratelimit remove`, `blocklist unblock`, `revoke restore`).
- **What you still need to do:** [F5](authentication-code-findings.md#finding-f5) (notifications, MFA).
- **Limits and false-positive safety:** Owners who forget their password look identical — review first.
- **Definition of done:** R12 synthetic test passes. Commands: [R12](#rule-r12), [R13](#rule-r13).

<a id="threat-c16c"></a>
#### C16c · Multi-step takeover: failures → sign-in → password or role change
**HIGH · 🟡 PARTIAL · APP_EVENT · needs app event** · OWASP A07:2021 · CWE-308 · [R19](#rule-r19) · [F5](authentication-code-findings.md#finding-f5) · [AUTH-09](#todo-auth-09) · [AUTH-10](#todo-auth-10)

**In one sentence:** An attacker who guesses a password can immediately change it to lock the owner out — or, on an admin account, grant themselves a role. SecureNow receives the failure, success and security-change events, detects that order within an hour on one account, and alerts for human review. Your app must notify the owner and require step-up for these changes.

- **Attack scenario:** An attacker who guesses a password can immediately change it to lock the owner out — or, on an admin account, grant themselves a role. Password change needs the current password (good) — which the attacker now has. Role changes need nothing more than an admin session.
- **How SecureNow detects it:** [R19](#rule-r19) (`windowFunnel`). Signal: ordered funnel within 1 h (2 h window), evaluated every 15 minutes. Rules are created in test mode, so each hit is a notification in the human queue (`npx securenow human list`) with no automatic action until a person promotes the rule (test-first).
- **How SecureNow mitigates it:** Revoke the user’s sessions after review; restore access through the operator.
- **What you still need to do:** [F5](authentication-code-findings.md#finding-f5).
- **Limits and false-positive safety:** An owner who mistypes once then changes their password matches too.
- **Definition of done:** R19 synthetic test returns steps = 3. Commands: [R19](#rule-r19).

<a id="threat-j46"></a>
#### J46 · Password-hashing CPU/memory amplification on sign-in routes
**HIGH · 🟡 PARTIAL · NATIVE_TRAFFIC · works on SDK load (traffic)** · OWASP A04:2021 · CWE-405 · [R07](#rule-r07) · [F9](authentication-code-findings.md#finding-f9) · [AUTH-05](#todo-auth-05) · [AUTH-21](#todo-auth-21)

**In one sentence:** An attacker with many IPs can keep every sign-in, registration and password change busy running 32 MiB scrypt hashes on Node’s 4-thread pool, slowing sign-in for everyone. SecureNow sees request volume and latency in traces, detects 200+ hashing requests in 5 minutes or a 2-second p95, and lists the top contributors for a person to throttle. Your app must cap concurrent hashes and shed load with 503.

- **Attack scenario:** An attacker with many IPs can keep every sign-in, registration and password change busy running 32 MiB scrypt hashes on Node’s 4-thread pool, slowing sign-in for everyone. Unknown accounts hash too (dummy path), which is right for enumeration but costs the same. No concurrency bound exists.
- **How SecureNow detects it:** [R07](#rule-r07) (two-stage global rule). Signal: ≥ 200 hashing POSTs app-wide / 5 min or p95 ≥ 2 s (≥ 50 requests), evaluated every 5 minutes. Rules are created in test mode, so each hit is a notification in the human queue (`npx securenow human list`) with no automatic action until a person promotes the rule (test-first).
- **How SecureNow mitigates it:** Never auto-block every contributor; a person adds `ratelimit add --route <hashing regex> --mode regex --method POST --limit 60 --window 1m --key-by global --duration 1h …`. Any manual action from §9 is time-boxed (`--duration`) and reversible (`ratelimit remove`, `blocklist unblock`, `revoke restore`).
- **What you still need to do:** [F9](authentication-code-findings.md#finding-f9).
- **Limits and false-positive safety:** A global limit also slows real users — time-box it.
- **Definition of done:** R07 created. Commands: [R07](#rule-r07).

<a id="threat-l53"></a>
#### L53 · Privilege escalation through client-controlled role claims
**HIGH · 🟡 PARTIAL · APP_EVENT · needs app event** · OWASP A01:2021 · CWE-269 · [R21](#rule-r21) · [AUTH-09](#todo-auth-09) · [AUTH-10](#todo-auth-10)

**In one sentence:** An attacker cannot give themselves admin by editing a cookie or response, because the role is read from PostgreSQL on every request. If an admin account is misused, SecureNow receives the role-change event, alerts on every elevation, and a person reviews it. Your app must emit the event. Depth: `../02-authorization/`.

- **Attack scenario:** An attacker cannot give themselves admin by editing a cookie or response, because the role is read from PostgreSQL on every request. User loaded per request (`src/app.js:89-101`); `requireRole` checks the database copy.
- **How SecureNow detects it:** [R21](#rule-r21). Signal: any privilege elevation, evaluated every 15 minutes. Rules are created in test mode, so each hit is a notification in the human queue (`npx securenow human list`) with no automatic action until a person promotes the rule (test-first).
- **How SecureNow mitigates it:** Review; demote; revoke.
- **What you still need to do:** Keep.
- **Limits and false-positive safety:** —
- **Definition of done:** R21 synthetic test passes. Commands: [R21](#rule-r21).

<a id="threat-l54a"></a>
#### L54a · No step-up re-authentication for admin role changes
**HIGH · 🟡 PARTIAL · APP_EVENT · needs app event** · OWASP A07:2021 · CWE-306 · [R21](#rule-r21) · [R20](#rule-r20) · [F5](authentication-code-findings.md#finding-f5) · [AUTH-09](#todo-auth-09) · [AUTH-10](#todo-auth-10) · [AUTH-14](#todo-auth-14)

**In one sentence:** An attacker who steals an admin’s session can promote any account to admin with one request — no password re-entry. SecureNow receives the role-change event, alerts on every elevation and on mass changes, and a person revokes the admin session. Your app must require the admin password again before role changes.

- **Attack scenario:** An attacker who steals an admin’s session can promote any account to admin with one request — no password re-entry. `PATCH /api/admin/users/:id[/role]` needs only an admin session + CSRF token (`src/app.js:291-299`).
- **How SecureNow detects it:** [R21](#rule-r21), [R20](#rule-r20). Signal: elevation; ≥ 3 accounts changed by one admin / 60 min, evaluated every 15 minutes. Rules are created in test mode, so each hit is a notification in the human queue (`npx securenow human list`) with no automatic action until a person promotes the rule (test-first).
- **How SecureNow mitigates it:** Revoke the admin session after review. Any manual action from §9 is time-boxed (`--duration`) and reversible (`ratelimit remove`, `blocklist unblock`, `revoke restore`).
- **What you still need to do:** [F5](authentication-code-findings.md#finding-f5).
- **Limits and false-positive safety:** The presenter promoting test accounts on camera trips R21 — expected in test mode.
- **Definition of done:** Role change without recent re-auth returns 403 in tests. Commands: [R21](#rule-r21), [R20](#rule-r20).

<a id="threat-a4"></a>
#### A4 · Password spraying (one common password, many accounts)
**MEDIUM · 🟡 PARTIAL · APP_EVENT · needs app event** · OWASP A07:2021 · CWE-307 · [R10](#rule-r10) · [R26](#rule-r26) · [F10](authentication-code-findings.md#finding-f10) · [AUTH-09](#todo-auth-09) · [AUTH-10](#todo-auth-10) · [AUTH-22](#todo-auth-22)

**In one sentence:** An attacker can try one popular 12-character password against many accounts, one attempt each, so no account bucket fills. SecureNow receives the failure events, detects one IP (or one network operator) touching 5+ accounts, and rate-limits it. Your app must refuse common and breached passwords so the sprayed password does not exist.

- **Attack scenario:** An attacker can try one popular 12-character password against many accounts, one attempt each, so no account bucket fills. The app only checks length (12–128, `src/passwords.js:7-10`), so “Password1234” is accepted. A sprayer can try it once per account.
- **How SecureNow detects it:** [R10](#rule-r10) (distinct accounts per IP) and [R26](#rule-r26) (per-ASN breadth, needs ASN enrichment). The password itself is never sent to SecureNow. Signal: ≥ 10 failures over ≥ 5 accounts per IP / 15 min; per-ASN breadth (R26), evaluated every 5 minutes. Rules are created in test mode, so each hit is a notification in the human queue (`npx securenow human list`) with no automatic action until a person promotes the rule (test-first).
- **How SecureNow mitigates it:** AUTO-A rate-limit after promotion; notify for R26. Automated responses (AUTO-A, AUTO-B) are created disabled, time-boxed to 24 h and reversible with `ratelimit remove` / `blocklist unblock` / `challenge remove` or `automation update <id> --status disabled` (§9).
- **What you still need to do:** Breached/common-password check ([F10](authentication-code-findings.md#finding-f10)).
- **Limits and false-positive safety:** Slow sprays (one try per account per day) stay below every threshold — prevention is the only real fix.
- **Definition of done:** R10 synthetic test passes; registration refuses a known-breached password in the app’s tests. Commands: [R10](#rule-r10), [R26](#rule-r26).

<a id="threat-b6"></a>
#### B6 · Account enumeration via register-then-sign-in
**MEDIUM · 🟡 PARTIAL · APP_EVENT · needs app event** · OWASP A07:2021 · CWE-204 · [R23](#rule-r23) · [F4](authentication-code-findings.md#finding-f4) · [AUTH-09](#todo-auth-09) · [AUTH-10](#todo-auth-10) · [AUTH-18](#todo-auth-18)

**In one sentence:** An attacker can find out whether an email has an account by registering it with a password they choose and then trying to sign in with that password: success means it was free, failure means it already existed. SecureNow receives a privacy-safe sign-up event that says created or existing, detects 3+ registrations on existing emails from one IP in an hour, and rate-limits registrations from that IP. Your app must verify email ownership before an account becomes usable.

- **Attack scenario:** An attacker can find out whether an email has an account by registering it with a password they choose and then trying to sign in with that password: success means it was free, failure means it already existed. Login and registration responses are deliberately identical and a dummy hash equalizes timing (`src/app.js:169-171`, `src/passwords.js:18-26`). But the two-step trick still works, and every “free” address the attacker tests becomes an account they own under someone else’s email (see H40a).
- **How SecureNow detects it:** [R23](#rule-r23) on the proposed `auth.signup` event with `outcome=created|existing` (the outcome is only visible to the operator, never to the caller). Signal: ≥ 3 registrations on already-registered emails per IP / 60 min, evaluated every 15 minutes. Rules are created in test mode, so each hit is a notification in the human queue (`npx securenow human list`) with no automatic action until a person promotes the rule (test-first).
- **How SecureNow mitigates it:** AUTO-G: 3 registrations per hour per IP for 24 hours after promotion. Automated responses (AUTO-G) are created disabled, time-boxed to 24 h and reversible with `ratelimit remove` / `blocklist unblock` / `challenge remove` or `automation update <id> --status disabled` (§9).
- **What you still need to do:** Email verification with pending accounts ([F4](authentication-code-findings.md#finding-f4)).
- **Limits and false-positive safety:** Slow probing (a few emails a day from many IPs) stays below the threshold.
- **Definition of done:** R23 synthetic test passes; AUTO-G created disabled. Commands: [R23](#rule-r23).

<a id="threat-b7"></a>
#### B7 · Identifier harvesting at scale
**MEDIUM · 🟡 PARTIAL · APP_EVENT · needs app event** · OWASP A07:2021 · CWE-204 · [R10](#rule-r10) · [R23](#rule-r23) · [F4](authentication-code-findings.md#finding-f4) · [AUTH-09](#todo-auth-09) · [AUTH-10](#todo-auth-10)

**In one sentence:** An attacker can run a long list of emails through registration or sign-in to build a list of real members. SecureNow receives the sign-in and sign-up events, detects one IP touching 5+ accounts or 3+ existing emails, and rate-limits it. Your app must close the register-then-sign-in oracle with email verification.

- **Attack scenario:** An attacker can run a long list of emails through registration or sign-in to build a list of real members. Responses do not leak existence directly; harvesting relies on the B6 oracle.
- **How SecureNow detects it:** [R10](#rule-r10), [R23](#rule-r23). Signal: distinct accounts per IP (R10); existing-email registrations (R23), evaluated every 5 minutes. Rules are created in test mode, so each hit is a notification in the human queue (`npx securenow human list`) with no automatic action until a person promotes the rule (test-first).
- **How SecureNow mitigates it:** AUTO-A, AUTO-G after promotion. Automated responses (AUTO-A, AUTO-B, AUTO-G) are created disabled, time-boxed to 24 h and reversible with `ratelimit remove` / `blocklist unblock` / `challenge remove` or `automation update <id> --status disabled` (§9).
- **What you still need to do:** [F4](authentication-code-findings.md#finding-f4).
- **Limits and false-positive safety:** Distributed harvesting needs the per-network/ASN views.
- **Definition of done:** R10 and R23 synthetic tests pass. Commands: [R10](#rule-r10), [R23](#rule-r23).

<a id="threat-c11"></a>
#### C11 · Limited revocation (no sign-out-everywhere, Google-only users, no admin kill switch)
**MEDIUM · 🟡 PARTIAL · APP_EVENT · needs app event** · OWASP A07:2021 · CWE-613 · [F7](authentication-code-findings.md#finding-f7) · [AUTH-09](#todo-auth-09) · [AUTH-17](#todo-auth-17) · [AUTH-20](#todo-auth-20)

**In one sentence:** An attacker holding a stolen session keeps it until it expires if the victim signs in only with Google, because only a password change (or an admin role change) kills other sessions. SecureNow can add a server-side kill switch — the sessions guard rejects revoked sessions — once the app wires it in. Your app must add “sign out everywhere” and an admin “revoke sessions” action.

- **Attack scenario:** An attacker holding a stolen session keeps it until it expires if the victim signs in only with Google, because only a password change (or an admin role change) kills other sessions. Logout destroys only the current session (`src/app.js:188-193`). Members cannot see their own sessions (`/api/security` needs analyst, `src/app.js:277`). An admin can only invalidate a user by changing their role (`src/app.js:294`).
- **How SecureNow detects it:** Not a detection — an enforcement path. With guard() wired, `npx securenow revoke user <enduser.id>` blocks every session of that user on the next request. No rule: enforcement only: revocations apply on the next request where guard() runs.
- **How SecureNow mitigates it:** Manual revoke (CLI-only; see gap G-R1 for the 404). No SecureNow action, so nothing to reverse.
- **What you still need to do:** [F7](authentication-code-findings.md#finding-f7).
- **Limits and false-positive safety:** Fail-open: if SecureNow is unreachable, the guard lets traffic through.
- **Definition of done:** A revoked test user gets 401 on the next request.

<a id="threat-c12"></a>
#### C12 · Concurrent use of one account from several networks
**MEDIUM · 🟡 PARTIAL · APP_EVENT · needs app event** · OWASP A07:2021 · CWE-613 · [R17](#rule-r17) · [F7](authentication-code-findings.md#finding-f7) · [AUTH-09](#todo-auth-09) · [AUTH-10](#todo-auth-10)

**In one sentence:** An attacker can use a stolen session at the same time as its owner. SecureNow receives `session.seen` per session and network, detects 3+ networks for one account within an hour, and notifies. Your app must wire the guard and offer sign-out-everywhere.

- **Attack scenario:** An attacker can use a stolen session at the same time as its owner. The app allows unlimited concurrent sessions per account.
- **How SecureNow detects it:** [R17](#rule-r17). Signal: ≥ 3 IPs per account / 60 min, evaluated every 15 minutes. Rules are created in test mode, so each hit is a notification in the human queue (`npx securenow human list`) with no automatic action until a person promotes the rule (test-first).
- **How SecureNow mitigates it:** Notify; revoke after review. Any manual action from §9 is time-boxed (`--duration`) and reversible (`ratelimit remove`, `blocklist unblock`, `revoke restore`).
- **What you still need to do:** [F7](authentication-code-findings.md#finding-f7).
- **Limits and false-positive safety:** Mobile carriers rotate IPs.
- **Definition of done:** R17 synthetic test passes. Commands: [R17](#rule-r17).

<a id="threat-c16d"></a>
#### C16d · Sensitive action from a different network than the sign-in
**MEDIUM · 🟡 PARTIAL · APP_EVENT · needs app event** · OWASP A07:2021 · CWE-294 · [R20](#rule-r20) · [F5](authentication-code-findings.md#finding-f5) · [AUTH-09](#todo-auth-09) · [AUTH-10](#todo-auth-10)

**In one sentence:** An attacker replaying a stolen cookie performs the password or role change from their own network, not the one that signed in. SecureNow receives both events with the same session reference, detects the IP mismatch, and notifies. Your app must pass the pre-change session reference with the event and add step-up for sensitive changes.

- **Attack scenario:** An attacker replaying a stolen cookie performs the password or role change from their own network, not the one that signed in. Nothing binds a session to its network today (by design — roaming is normal).
- **How SecureNow detects it:** [R20](#rule-r20). Signal: security change IP ≠ sign-in IP for the same session (8 h), evaluated every 15 minutes. Rules are created in test mode, so each hit is a notification in the human queue (`npx securenow human list`) with no automatic action until a person promotes the rule (test-first).
- **How SecureNow mitigates it:** Notify; revoke after review. Any manual action from §9 is time-boxed (`--duration`) and reversible (`ratelimit remove`, `blocklist unblock`, `revoke restore`).
- **What you still need to do:** [F5](authentication-code-findings.md#finding-f5).
- **Limits and false-positive safety:** Roaming users.
- **Definition of done:** R20 synthetic test passes. Commands: [R20](#rule-r20).

<a id="threat-d19"></a>
#### D19 · Google ID-token validation (signature, audience, expiry, issuer, nonce)
**MEDIUM · 🟡 PARTIAL · APP_EVENT · needs app event** · OWASP A07:2021 · CWE-347 · [R15](#rule-r15) · [AUTH-09](#todo-auth-09) · [AUTH-10](#todo-auth-10) · [AUTH-11](#todo-auth-11)

**In one sentence:** An attacker cannot sign in with a forged or replayed Google ID token: `verifyIdToken` checks signature, audience and expiry, and the app checks issuer, nonce, subject and verified email. They can still hammer the callback with bad tokens. SecureNow receives the callback-failure event with its reason, detects 5+ per IP in 15 minutes, and rate-limits Google sign-in for that IP. Your app must emit those failure events.

- **Attack scenario:** An attacker cannot sign in with a forged or replayed Google ID token: `verifyIdToken` checks signature, audience and expiry, and the app checks issuer, nonce, subject and verified email. They can still hammer the callback with bad tokens. Validation lives at `src/app.js:233-235`. Protocol depth (JWKS, `kid`, algorithm handling) is owned by `../07-oauth-sso-integrations/`.
- **How SecureNow detects it:** [R15](#rule-r15). Signal: ≥ 5 provider-verification or invalid-callback failures per IP / 15 min, evaluated every 5 minutes. Rules are created in test mode, so each hit is a notification in the human queue (`npx securenow human list`) with no automatic action until a person promotes the rule (test-first).
- **How SecureNow mitigates it:** AUTO-F after promotion. Automated responses (AUTO-F) are created disabled, time-boxed to 24 h and reversible with `ratelimit remove` / `blocklist unblock` / `challenge remove` or `automation update <id> --status disabled` (§9).
- **What you still need to do:** Keep `google-auth-library` updated.
- **Limits and false-positive safety:** Symptom only.
- **Definition of done:** R15 synthetic test passes. Commands: [R15](#rule-r15).

<a id="threat-g32"></a>
#### G32 · Missing state or PKCE (login CSRF / code injection)
**MEDIUM · 🟡 PARTIAL · APP_EVENT · needs app event** · OWASP A07:2021 · CWE-352 · [R15](#rule-r15) · [AUTH-09](#todo-auth-09) · [AUTH-10](#todo-auth-10) · [AUTH-33](#todo-auth-33)

**In one sentence:** An attacker cannot inject their own Google code into a victim’s browser, because the callback needs the session-bound `state` and the PKCE verifier. Attempts end as `invalid_callback`. SecureNow receives those failure events, detects 5+ per IP in 15 minutes, and rate-limits Google sign-in for the IP. Your app must emit the failure reason.

- **Attack scenario:** An attacker cannot inject their own Google code into a victim’s browser, because the callback needs the session-bound `state` and the PKCE verifier. State/nonce/PKCE at `src/app.js:212-219`, checked at `224-230`.
- **How SecureNow detects it:** [R15](#rule-r15). Signal: ≥ 5 invalid_callback per IP / 15 min, evaluated every 5 minutes. Rules are created in test mode, so each hit is a notification in the human queue (`npx securenow human list`) with no automatic action until a person promotes the rule (test-first).
- **How SecureNow mitigates it:** AUTO-F. Automated responses (AUTO-F) are created disabled, time-boxed to 24 h and reversible with `ratelimit remove` / `blocklist unblock` / `challenge remove` or `automation update <id> --status disabled` (§9).
- **What you still need to do:** Keep.
- **Limits and false-positive safety:** Symptom only.
- **Definition of done:** R15 synthetic test passes. Commands: [R15](#rule-r15).

<a id="threat-g33"></a>
#### G33 · Authorization-code interception or replay
**MEDIUM · 🟡 PARTIAL · APP_EVENT · needs app event** · OWASP A07:2021 · CWE-294 · [R15](#rule-r15) · [AUTH-09](#todo-auth-09) · [AUTH-10](#todo-auth-10)

**In one sentence:** An attacker who intercepts a Google code cannot redeem it without the PKCE verifier stored in the victim’s server-side session, and the transaction is deleted before validation. A replay fails at Google or at state validation. SecureNow receives the failure reason and rate-limits repeat offenders. Your app must emit it.

- **Attack scenario:** An attacker who intercepts a Google code cannot redeem it without the PKCE verifier stored in the victim’s server-side session, and the transaction is deleted before validation. The transaction is removed from the session before any check (`src/app.js:224-226`).
- **How SecureNow detects it:** [R15](#rule-r15). Signal: provider_verification failures per IP, evaluated every 5 minutes. Rules are created in test mode, so each hit is a notification in the human queue (`npx securenow human list`) with no automatic action until a person promotes the rule (test-first).
- **How SecureNow mitigates it:** AUTO-F. Automated responses (AUTO-F) are created disabled, time-boxed to 24 h and reversible with `ratelimit remove` / `blocklist unblock` / `challenge remove` or `automation update <id> --status disabled` (§9).
- **What you still need to do:** Keep.
- **Limits and false-positive safety:** —
- **Definition of done:** R15 created. Commands: [R15](#rule-r15).

<a id="threat-g36a"></a>
#### G36a · OIDC replay without nonce
**MEDIUM · 🟡 PARTIAL · APP_EVENT · needs app event** · OWASP A07:2021 · CWE-294 · [R15](#rule-r15) · [AUTH-09](#todo-auth-09) · [AUTH-10](#todo-auth-10)

**In one sentence:** An attacker cannot replay an old ID token because the app compares its `nonce` with the one stored for this transaction. A replay is recorded as a verification failure. SecureNow receives it and rate-limits repeat offenders. Your app must emit the reason.

- **Attack scenario:** An attacker cannot replay an old ID token because the app compares its `nonce` with the one stored for this transaction. Nonce comparison at `src/app.js:235`; tested with a wrong nonce.
- **How SecureNow detects it:** [R15](#rule-r15). Signal: nonce mismatch surfaces as provider_verification, evaluated every 5 minutes. Rules are created in test mode, so each hit is a notification in the human queue (`npx securenow human list`) with no automatic action until a person promotes the rule (test-first).
- **How SecureNow mitigates it:** AUTO-F. Automated responses (AUTO-F) are created disabled, time-boxed to 24 h and reversible with `ratelimit remove` / `blocklist unblock` / `challenge remove` or `automation update <id> --status disabled` (§9).
- **What you still need to do:** Keep.
- **Limits and false-positive safety:** —
- **Definition of done:** R15 created. Commands: [R15](#rule-r15).

<a id="threat-h39a"></a>
#### H39a · Password change with a stolen session; no notification
**MEDIUM · 🟡 PARTIAL · APP_EVENT · needs app event** · OWASP A07:2021 · CWE-620 · [R21](#rule-r21) · [R19](#rule-r19) · [F5](authentication-code-findings.md#finding-f5) · [AUTH-09](#todo-auth-09) · [AUTH-10](#todo-auth-10) · [AUTH-19](#todo-auth-19)

**In one sentence:** An attacker with a stolen session cannot change the password without the current one, but can guess it 5 times per 15 minutes per IP — and if they know it, nobody tells the owner. SecureNow receives the password-change events, detects 3+ wrong current passwords per account in an hour, and notifies. Your app must notify the owner of every password change.

- **Attack scenario:** An attacker with a stolen session cannot change the password without the current one, but can guess it 5 times per 15 minutes per IP — and if they know it, nobody tells the owner. Current password required (`src/app.js:197`), limited per IP only (`src/app.js:194`).
- **How SecureNow detects it:** [R21](#rule-r21), [R19](#rule-r19). Signal: ≥ 3 wrong current-password attempts per account / 60 min (R21), evaluated every 15 minutes. Rules are created in test mode, so each hit is a notification in the human queue (`npx securenow human list`) with no automatic action until a person promotes the rule (test-first).
- **How SecureNow mitigates it:** Revoke the session after review. Any manual action from §9 is time-boxed (`--duration`) and reversible (`ratelimit remove`, `blocklist unblock`, `revoke restore`).
- **What you still need to do:** [F5](authentication-code-findings.md#finding-f5).
- **Limits and false-positive safety:** —
- **Definition of done:** R21 created. Commands: [R21](#rule-r21), [R19](#rule-r19).

<a id="threat-h40"></a>
#### H40 · Signup abuse / mass account creation
**MEDIUM · 🟡 PARTIAL · NATIVE_TRAFFIC · works on SDK load (traffic)** · OWASP A04:2021 · CWE-799 · [R08](#rule-r08) · [R23](#rule-r23) · [F4](authentication-code-findings.md#finding-f4) · [F16](authentication-code-findings.md#finding-f16) · [AUTH-05](#todo-auth-05) · [AUTH-18](#todo-auth-18) · [AUTH-29](#todo-auth-29)

**In one sentence:** An attacker can create thousands of accounts by rotating IPs under the 10-per-IP limit, filling the database and pushing real members out of the admin list (which shows only the newest 100). SecureNow sees every accepted registration in traces, detects 30+ app-wide in an hour, and lists the top contributing IPs for a scoped response. Your app must verify email ownership and page the admin list.

- **Attack scenario:** An attacker can create thousands of accounts by rotating IPs under the 10-per-IP limit, filling the database and pushing real members out of the admin list (which shows only the newest 100). Registration costs one scrypt hash and one row; no CAPTCHA or verification (`src/app.js:157-172`). `/api/admin/users` returns `LIMIT 100` (`src/app.js:288`).
- **How SecureNow detects it:** [R08](#rule-r08) (works on SDK load), [R23](#rule-r23). Signal: ≥ 30 registrations app-wide / 60 min (R08); ≥ 5 created per IP / 60 min (R23), evaluated every 15 minutes. Rules are created in test mode, so each hit is a notification in the human queue (`npx securenow human list`) with no automatic action until a person promotes the rule (test-first).
- **How SecureNow mitigates it:** A person adds a temporary global limit: `ratelimit add --route <register regex> --mode regex --method POST --limit 20 --window 1h --key-by global --duration 24h …`. Automated responses (AUTO-G) are created disabled, time-boxed to 24 h and reversible with `ratelimit remove` / `blocklist unblock` / `challenge remove` or `automation update <id> --status disabled` (§9).
- **What you still need to do:** [F4](authentication-code-findings.md#finding-f4), [F16](authentication-code-findings.md#finding-f16).
- **Limits and false-positive safety:** A global limit also slows real sign-ups during an attack — time-box it.
- **Definition of done:** R08 created. Commands: [R08](#rule-r08), [R23](#rule-r23).

<a id="threat-h41"></a>
#### H41 · Targeted lockout of a member through the per-account limit
**MEDIUM · 🟡 PARTIAL · APP_EVENT · needs app event** · OWASP A07:2021 · CWE-645 · [R14](#rule-r14) · [R11](#rule-r11) · [F3](authentication-code-findings.md#finding-f3) · [AUTH-09](#todo-auth-09) · [AUTH-10](#todo-auth-10) · [AUTH-13](#todo-auth-13)

**In one sentence:** An attacker who knows a member’s email can keep them out indefinitely: 31 sign-in attempts per 15 minutes from 3 IPs fill that account’s bucket, and the member’s correct password then gets “Too many attempts”. SecureNow receives the app’s rate-limit events, detects one account’s bucket held full by 2+ IPs, and alerts so a person can throttle those IPs. Your app must stop counting the owner’s own attempts from a known browser.

- **Attack scenario:** An attacker who knows a member’s email can keep them out indefinitely: 31 sign-in attempts per 15 minutes from 3 IPs fill that account’s bucket, and the member’s correct password then gets “Too many attempts”. The account bucket counts every attempt before the password is checked (`src/app.js:124-131,173`), so the owner is rejected too, with no bypass and no notice.
- **How SecureNow detects it:** [R14](#rule-r14) (and [R11](#rule-r11)) after the bridge exports `api.ratelimit.exceeded`. Signal: ≥ 3 per-account rejections from ≥ 2 IPs / 15 min (R14), evaluated every 5 minutes. Rules are created in test mode, so each hit is a notification in the human queue (`npx securenow human list`) with no automatic action until a person promotes the rule (test-first).
- **How SecureNow mitigates it:** Never lock harder; rate-limit or challenge the contributing IPs. Any manual action from §9 is time-boxed (`--duration`) and reversible (`ratelimit remove`, `blocklist unblock`, `revoke restore`).
- **What you still need to do:** [F3](authentication-code-findings.md#finding-f3).
- **Limits and false-positive safety:** Google sign-in still works for Google-linked members.
- **Definition of done:** R14 synthetic test passes; device-cookie bypass tested. Commands: [R14](#rule-r14), [R11](#rule-r11).

<a id="threat-m60a"></a>
#### M60a · Detection-logic defects that look healthy
**MEDIUM · 🔴 GAP · EXTERNAL_MONITOR · outside SecureNow (app/external)** · OWASP A09:2021 · CWE-778 · [AUTH-27](#todo-auth-27)

**In one sentence:** An attacker benefits from rules that pass every dry-run but never match: an unbounded logs time filter, the wrong tenant column, an attribute the app never sends, or a dry-run that ran on another app. SecureNow’s dry-run proves the SQL runs, not that it means anything. You must re-check each rule against real lab telemetry.

- **Attack scenario:** An attacker benefits from rules that pass every dry-run but never match: an unbounded logs time filter, the wrong tenant column, an attribute the app never sends, or a dry-run that ran on another app. In this run every SQL was syntax-checked on a different app because no lab rule or telemetry exists yet.
- **How SecureNow detects it:** R25 catches missing events; the rest is review. No rule: operator lint (this report) + coverage rule R25.
- **How SecureNow mitigates it:** None. No SecureNow action, so nothing to reverse.
- **What you still need to do:** Repeat `alerts rules test --mode dry_run --app <lab key>` after a week of traffic.
- **Limits and false-positive safety:** —
- **Definition of done:** Every rule has a real lab dry-run.

<a id="threat-m61"></a>
#### M61 · Forged or replayed security events; stolen runtime key
**MEDIUM · 🟡 PARTIAL · APP_EVENT · needs app event** · OWASP A08:2021 · CWE-345 · [R24](#rule-r24) · [AUTH-09](#todo-auth-09) · [AUTH-10](#todo-auth-10)

**In one sentence:** An attacker with the runtime key could send fake “failure” events to frame an innocent IP, or fake successes to hide activity. SecureNow detects duplicate request IDs, missing required attributes and future timestamps in the lab’s auth events, and notifies. Your deployment must keep the runtime key private and rotate it on suspicion.

- **Attack scenario:** An attacker with the runtime key could send fake “failure” events to frame an innocent IP, or fake successes to hide activity. Events carry a sender-supplied timestamp and no event ID; any holder of the key can emit them.
- **How SecureNow detects it:** [R24](#rule-r24). Signal: any duplicate request_id, missing auth_method, or future-dated event / 60 min, evaluated every 15 minutes. Rules are created in test mode, so each hit is a notification in the human queue (`npx securenow human list`) with no automatic action until a person promotes the rule (test-first).
- **How SecureNow mitigates it:** Rotate the key; ignore forged notifications. Any manual action from §9 is time-boxed (`--duration`) and reversible (`ratelimit remove`, `blocklist unblock`, `revoke restore`).
- **What you still need to do:** Mount the runtime credential read-only for the app user only.
- **Limits and false-positive safety:** A careful forger who copies the format is not caught.
- **Definition of done:** R24 synthetic test passes. Commands: [R24](#rule-r24).

<a id="threat-m55"></a>
#### M55 · Auth requests traced but their events missing (coverage drift)
**LOW · 🟡 PARTIAL · APP_EVENT · needs app event** · OWASP A09:2021 · CWE-778 · [R25](#rule-r25) · [AUTH-09](#todo-auth-09) · [AUTH-10](#todo-auth-10)

**In one sentence:** An attacker benefits when a deploy silently breaks the event bridge, because every event-based rule goes quiet. SecureNow compares traced sign-in requests with exported sign-in events and alerts when events fall below half. Your app must keep the bridge and its runtime key healthy.

- **Attack scenario:** An attacker benefits when a deploy silently breaks the event bridge, because every event-based rule goes quiet. The bridge is fire-and-forget and silently drops events without an app key (`node_modules/securenow/events.js:39-44`).
- **How SecureNow detects it:** [R25](#rule-r25). Signal: events < 50% of traced sign-in verdicts (≥ 10) / 30 min, evaluated every 15 minutes. Rules are created in test mode, so each hit is a notification in the human queue (`npx securenow human list`) with no automatic action until a person promotes the rule (test-first).
- **How SecureNow mitigates it:** Notify. Any manual action from §9 is time-boxed (`--duration`) and reversible (`ratelimit remove`, `blocklist unblock`, `revoke restore`).
- **What you still need to do:** Deploy check: `telemetry fields --source logs` after each release.
- **Limits and false-positive safety:** Cannot see a total outage (both sides zero) — see M56.
- **Definition of done:** R25 created. Commands: [R25](#rule-r25).

<a id="threat-g36c"></a>
#### G36c · Real users locked out across sign-in methods (password squat blocks Google)
**MEDIUM · 🟡 PARTIAL · APP_EVENT · needs app event** · OWASP A07:2021 · CWE-287 · [R16](#rule-r16) · [F4](authentication-code-findings.md#finding-f4) · [AUTH-09](#todo-auth-09) · [AUTH-10](#todo-auth-10) · [AUTH-18](#todo-auth-18)

**In one sentence:** An attacker can register a victim’s email with a password first; when the real owner later tries “Sign in with Google”, the app refuses and tells them to use a password they never set — and there is no recovery flow. SecureNow receives the refusal event and notifies on spikes. Your app must let a verified Google sign-in reclaim an unverified password account.

- **Attack scenario:** An attacker can register a victim’s email with a password first; when the real owner later tries “Sign in with Google”, the app refuses and tells them to use a password they never set — and there is no recovery flow. Registration is unverified (`src/app.js:164-171`); the conflict message is at `public/app.js:356`; no reset flow exists.
- **How SecureNow detects it:** [R16](#rule-r16). Signal: ≥ 5 link refusals app-wide / 60 min, evaluated every 15 minutes. Rules are created in test mode, so each hit is a notification in the human queue (`npx securenow human list`) with no automatic action until a person promotes the rule (test-first).
- **How SecureNow mitigates it:** Notify; the operator fixes the account manually. Any manual action from §9 is time-boxed (`--duration`) and reversible (`ratelimit remove`, `blocklist unblock`, `revoke restore`).
- **What you still need to do:** [F4](authentication-code-findings.md#finding-f4).
- **Limits and false-positive safety:** —
- **Definition of done:** Reclaim flow tested; R16 created. Commands: [R16](#rule-r16).

<a id="threat-h40a"></a>
#### H40a · Account pre-hijacking / email squatting
**MEDIUM · 🟡 PARTIAL · APP_EVENT · needs app event** · OWASP A07:2021 · CWE-287 · [R23](#rule-r23) · [R16](#rule-r16) · [F4](authentication-code-findings.md#finding-f4) · [AUTH-09](#todo-auth-09) · [AUTH-10](#todo-auth-10) · [AUTH-18](#todo-auth-18)

**In one sentence:** An attacker can pre-register a victim’s address so the victim’s later Google sign-in is refused. Because the app never auto-links, this is a lock-out, not a takeover. SecureNow receives the sign-up and link-refusal events and notifies. Your app must verify ownership and offer reclaim.

- **Attack scenario:** An attacker can pre-register a victim’s address so the victim’s later Google sign-in is refused. See G36c and B6.
- **How SecureNow detects it:** [R23](#rule-r23), [R16](#rule-r16). Signal: accounts created per IP; link refusals, evaluated every 15 minutes. Rules are created in test mode, so each hit is a notification in the human queue (`npx securenow human list`) with no automatic action until a person promotes the rule (test-first).
- **How SecureNow mitigates it:** AUTO-G. Automated responses (AUTO-G) are created disabled, time-boxed to 24 h and reversible with `ratelimit remove` / `blocklist unblock` / `challenge remove` or `automation update <id> --status disabled` (§9).
- **What you still need to do:** [F4](authentication-code-findings.md#finding-f4).
- **Limits and false-positive safety:** —
- **Definition of done:** Reclaim flow tested. Commands: [R23](#rule-r23), [R16](#rule-r16).

<a id="threat-m56"></a>
#### M56 · Telemetry exporter or ingestion outage
**MEDIUM · 🔴 GAP · EXTERNAL_MONITOR · outside SecureNow (app/external)** · OWASP A09:2021 · CWE-778 · [AUTH-27](#todo-auth-27)

**In one sentence:** An attacker benefits from any period when the SDK stops exporting (bad key, crash loop, network). SecureNow cannot reliably alert on its own missing data. You need an outside check that compares the app’s health with fresh telemetry.

- **Attack scenario:** An attacker benefits from any period when the SDK stops exporting (bad key, crash loop, network).
- **How SecureNow detects it:** None in-band — 🔴 gap. (needs an independent monitor — a dead pipeline cannot alert through itself.)
- **How SecureNow mitigates it:** None. No SecureNow action, so nothing to reverse.
- **What you still need to do:** AUTH-27 (cron: `telemetry fields --since 1h` must list `http.target`).
- **Limits and false-positive safety:** —
- **Definition of done:** External check pages someone within 1 hour of silence.

<a id="threat-m58"></a>
#### M58 · Google Cloud OAuth client or project compromise
**MEDIUM · 🔴 GAP · PROVIDER_EVENT · needs provider data** · OWASP A07:2021 · CWE-284 · [AUTH-28](#todo-auth-28)

**In one sentence:** An attacker who gets into the Google Cloud project could add a redirect URI or read the client secret. SecureNow sees none of Google’s control plane. Google Cloud must alert on OAuth client changes.

- **Attack scenario:** An attacker who gets into the Google Cloud project could add a redirect URI or read the client secret.
- **How SecureNow detects it:** None — 🔴 gap. (Google Cloud audit logs are not ingested by SecureNow.)
- **How SecureNow mitigates it:** None. No SecureNow action, so nothing to reverse.
- **What you still need to do:** AUTH-28.
- **Limits and false-positive safety:** —
- **Definition of done:** Audit-log alert on OAuth client edits.

<a id="threat-s2"></a>
#### S2 · No second factor or step-up anywhere
**MEDIUM · 🔴 GAP · APP_OR_PROVIDER_CONTROL · outside SecureNow (app/external)** · OWASP A07:2021 · CWE-308 · [F5](authentication-code-findings.md#finding-f5) · [AUTH-19](#todo-auth-19)

**In one sentence:** An attacker who learns one password (or steals one admin session) has the whole account — there is no second factor for any role. SecureNow can only notice the aftermath (R12, R19, R21). Your app must add a phishing-resistant factor, starting with admin and analyst.

- **Attack scenario:** An attacker who learns one password (or steals one admin session) has the whole account — there is no second factor for any role. The repo documents MFA as out of scope for the baseline (SECURITY.md).
- **How SecureNow detects it:** Compensating only. No rule: no signal — compensating detections R12, R19, R21.
- **How SecureNow mitigates it:** None. No SecureNow action, so nothing to reverse.
- **What you still need to do:** [F5](authentication-code-findings.md#finding-f5).
- **Limits and false-positive safety:** —
- **Definition of done:** Admin sign-in requires a passkey or TOTP.

<a id="threat-a4a"></a>
#### A4a · Rate-limit counter weaknesses (window boundary, IPv6 rotation)
**LOW · 🟡 PARTIAL · NATIVE_TRAFFIC · works on SDK load (traffic)** · OWASP A07:2021 · CWE-307 · [R06](#rule-r06) · [F11](authentication-code-findings.md#finding-f11) · [AUTH-23](#todo-auth-23)

**In one sentence:** An attacker can send 15 guesses at 14:59 and 15 more at 15:00, or switch IPv6 addresses inside one /64, to get more attempts than intended. SecureNow sees the failed requests in traces and detects the /64 spread with a 30-minute rule, alerting for review. Your app must key IPv6 by /64 and smooth the window.

- **Attack scenario:** An attacker can send 15 guesses at 14:59 and 15 more at 15:00, or switch IPv6 addresses inside one /64, to get more attempts than intended. Counters are stored atomically in PostgreSQL and are not reset by a success (good), and arrays of passwords are rejected (`src/app.js:176`). But the window is fixed (`src/app.js:126`), so the boundary doubles the burst, and the IP key is the full IPv6 address.
- **How SecureNow detects it:** [R06](#rule-r06) (network grouping). Signal: per-/64 grouping of failures (R06), evaluated every 10 minutes. Rules are created in test mode, so each hit is a notification in the human queue (`npx securenow human list`) with no automatic action until a person promotes the rule (test-first).
- **How SecureNow mitigates it:** Notify; manual CIDR rate limit. Any manual action from §9 is time-boxed (`--duration`) and reversible (`ratelimit remove`, `blocklist unblock`, `revoke restore`).
- **What you still need to do:** [F11](authentication-code-findings.md#finding-f11).
- **Limits and false-positive safety:** The 2× boundary burst stays under every SecureNow threshold by design; it is a code fix, not a detection.
- **Definition of done:** App limiter keys IPv6 by /64 (unit test) and R06 created. Commands: [R06](#rule-r06).

<a id="threat-a5"></a>
#### A5 · Default, seeded or leftover bootstrap credentials
**LOW · 🔴 GAP · APP_OR_PROVIDER_CONTROL · outside SecureNow (app/external)** · OWASP A07:2021 · CWE-1392 · [F12](authentication-code-findings.md#finding-f12) · [AUTH-24](#todo-auth-24)

**In one sentence:** An attacker who gets read access to the instance role or the runtime secret can read the bootstrap admin password, which stays in AWS Secrets Manager after the first deploy. SecureNow sees nothing until that password is used, so it cannot detect the leak itself. Your app/deployment must remove the bootstrap password after first use and force an admin password change.

- **Attack scenario:** An attacker who gets read access to the instance role or the runtime secret can read the bootstrap admin password, which stays in AWS Secrets Manager after the first deploy. No default credentials ship in the repo (good). But `infra/update.sh:17` re-reads `ADMIN_PASSWORD` from the runtime secret on every deploy and only strips it from the container env afterwards (`infra/update.sh:30-34`); the secret itself keeps it, and the instance role can read it (`infra/generate-template.cjs:8`). If the operator never rotated the admin password as the docs ask, that value is a working admin login.
- **How SecureNow detects it:** No SecureNow signal for “a secret is readable”. A successful admin sign-in from a new network would surface in [R27](#rule-r27)/[R13](#rule-r13) only after the fact. (no signal — the credential lives in AWS Secrets Manager.)
- **How SecureNow mitigates it:** None in SecureNow. No SecureNow action, so nothing to reverse.
- **What you still need to do:** [F12](authentication-code-findings.md#finding-f12).
- **Limits and false-positive safety:** Requires AWS-side access first; the risk is the long tail after the lab is forgotten.
- **Definition of done:** Runtime secret no longer contains ADMIN_PASSWORD; first admin sign-in forces a change.

<a id="threat-a5a"></a>
#### A5a · Password-handling gaps (no breach screening, no Unicode normalization, scrypt below OWASP minimum)
**LOW · 🔴 GAP · APP_OR_PROVIDER_CONTROL · outside SecureNow (app/external)** · OWASP A02:2021 · CWE-916 · [F8](authentication-code-findings.md#finding-f8) · [F10](authentication-code-findings.md#finding-f10) · [AUTH-21](#todo-auth-21) · [AUTH-22](#todo-auth-22)

**In one sentence:** An attacker who steals a database backup can test guesses against scrypt hashes set below the OWASP minimum cost, and a user can pick a known-breached password. SecureNow sees none of this — hashing and password policy never appear in traffic. Your app must raise the cost with rehash-on-login and screen breached passwords.

- **Attack scenario:** An attacker who steals a database backup can test guesses against scrypt hashes set below the OWASP minimum cost, and a user can pick a known-breached password. Hashing is salted scrypt with constant-time comparison and no bcrypt 72-byte truncation (good). Parameters N=32768, r=8, p=1 (`src/passwords.js:5`) are about a third of OWASP’s minimum (N=2^17 r=8 p=1, or the equivalent N=2^15 r=8 p=3), and `verifyPassword` rejects any other parameters (`src/passwords.js:24`), so they can never be upgraded without a code change.
- **How SecureNow detects it:** No SecureNow signal. (no signal — properties of stored hashes and accepted passwords.)
- **How SecureNow mitigates it:** None in SecureNow. No SecureNow action, so nothing to reverse.
- **What you still need to do:** [F8](authentication-code-findings.md#finding-f8), [F10](authentication-code-findings.md#finding-f10).
- **Limits and false-positive safety:** Pure prevention.
- **Definition of done:** Stored hashes carry their own parameters; logins rehash to the new cost; breached passwords rejected.

<a id="threat-b8a"></a>
#### B8a · Google sign-in conflict message as an enumeration oracle
**LOW · 🟡 PARTIAL · APP_EVENT · needs app event** · OWASP A07:2021 · CWE-204 · [R16](#rule-r16) · [F4](authentication-code-findings.md#finding-f4) · [AUTH-09](#todo-auth-09) · [AUTH-10](#todo-auth-10)

**In one sentence:** An attacker can learn that an email has a password account by signing in with Google as that email and reading “There’s already an account with this email” — but only if they control that Google identity. SecureNow receives a link-refused event, detects clusters per IP or app-wide, and notifies. Your app must offer a verified reclaim path instead of a dead end.

- **Attack scenario:** An attacker can learn that an email has a password account by signing in with Google as that email and reading “There’s already an account with this email” — but only if they control that Google identity. The message (`public/app.js:356`) only appears after Google proves the caller owns that verified email, so the oracle is low value. The bigger problem is the lock-out it causes (G36c).
- **How SecureNow detects it:** [R16](#rule-r16). Signal: ≥ 3 link refusals per IP or ≥ 5 app-wide / 60 min, evaluated every 15 minutes. Rules are created in test mode, so each hit is a notification in the human queue (`npx securenow human list`) with no automatic action until a person promotes the rule (test-first).
- **How SecureNow mitigates it:** Notify only. Any manual action from §9 is time-boxed (`--duration`) and reversible (`ratelimit remove`, `blocklist unblock`, `revoke restore`).
- **What you still need to do:** [F4](authentication-code-findings.md#finding-f4).
- **Limits and false-positive safety:** Low severity.
- **Definition of done:** R16 synthetic test passes. Commands: [R16](#rule-r16).

<a id="threat-c16"></a>
#### C16 · Sign-in from an unusual network (hosting/VPN provider, new operator)
**LOW · 🟡 PARTIAL · APP_EVENT · needs app event** · OWASP A07:2021 · CWE-308 · [R27](#rule-r27) · [F5](authentication-code-findings.md#finding-f5) · [AUTH-09](#todo-auth-09) · [AUTH-10](#todo-auth-10) · [AUTH-19](#todo-auth-19)

**In one sentence:** An attacker with a member’s password usually signs in from a different network operator than the member does. SecureNow receives the sign-in success event, adds the network operator at ingest when ASN enrichment is on, detects an operator the account has not used in 7 days, and notifies. Your app must add a second factor for sensitive roles so a new network can trigger step-up.

- **Attack scenario:** An attacker with a member’s password usually signs in from a different network operator than the member does. Password alone grants full access; nothing compares networks.
- **How SecureNow detects it:** [R27](#rule-r27) — unverified until `client.as_org` appears in `telemetry fields --source logs`. Signal: account signs in from a network operator unseen in its previous 7 days (needs ASN enrichment), evaluated every 15 minutes. Rules are created in test mode, so each hit is a notification in the human queue (`npx securenow human list`) with no automatic action until a person promotes the rule (test-first).
- **How SecureNow mitigates it:** Notify only. Any manual action from §9 is time-boxed (`--duration`) and reversible (`ratelimit remove`, `blocklist unblock`, `revoke restore`).
- **What you still need to do:** [F5](authentication-code-findings.md#finding-f5).
- **Limits and false-positive safety:** Cannot be tested with TEST-NET addresses (no ASN); noisy for travellers.
- **Definition of done:** client.as_org observed; R27 created. Commands: [R27](#rule-r27).

<a id="threat-c16b"></a>
#### C16b · Dormant-account reactivation
**LOW · 🟡 PARTIAL · APP_EVENT · needs app event** · OWASP A07:2021 · CWE-308 · [R22](#rule-r22) · [AUTH-26](#todo-auth-26)

**In one sentence:** An attacker prefers abandoned accounts because nobody notices them being used. SecureNow receives the sign-in event carrying “days since last sign-in”, detects 90+ days, and notifies. Your app must record the previous sign-in time (it does not today).

- **Attack scenario:** An attacker prefers abandoned accounts because nobody notices them being used. The `users` table has no last-sign-in column (`db/001_initial.sql:1-13`).
- **How SecureNow detects it:** [R22](#rule-r22) after AUTH-26. Signal: sign-in with dormant_days ≥ 90, evaluated every 15 minutes. Rules are created in test mode, so each hit is a notification in the human queue (`npx securenow human list`) with no automatic action until a person promotes the rule (test-first).
- **How SecureNow mitigates it:** Notify. Any manual action from §9 is time-boxed (`--duration`) and reversible (`ratelimit remove`, `blocklist unblock`, `revoke restore`).
- **What you still need to do:** AUTH-26 adds `last_login_at`.
- **Limits and false-positive safety:** SecureNow cannot compute dormancy itself: telemetry retention is far shorter than 90 days.
- **Definition of done:** R22 synthetic test passes. Commands: [R22](#rule-r22).

<a id="threat-d21a"></a>
#### D21a · Live session IDs and OAuth transactions readable from database backups
**LOW · 🔴 GAP · APP_OR_PROVIDER_CONTROL · outside SecureNow (app/external)** · OWASP A02:2021 · CWE-312 · [F14](authentication-code-findings.md#finding-f14) · [AUTH-25](#todo-auth-25)

**In one sentence:** An attacker who obtains a daily backup gets every live session ID and any in-flight Google transaction (state, nonce, PKCE verifier) in plaintext. SecureNow cannot see backups. Your deployment must leave session data out of backups (the session secret is still needed to forge a cookie, so this is defense in depth).

- **Attack scenario:** An attacker who obtains a daily backup gets every live session ID and any in-flight Google transaction (state, nonce, PKCE verifier) in plaintext. `sessions.sid` is the primary key (`db/001_initial.sql:15-19`); the OAuth transaction sits in the session JSON (`src/app.js:213`); `infra/backup.sh:6` dumps everything.
- **How SecureNow detects it:** None. (no signal.)
- **How SecureNow mitigates it:** None. No SecureNow action, so nothing to reverse.
- **What you still need to do:** [F14](authentication-code-findings.md#finding-f14).
- **Limits and false-positive safety:** —
- **Definition of done:** Restore drill shows an empty sessions table.

<a id="threat-g34"></a>
#### G34 · Account-linking confusion (auto-link on email)
**LOW · 🟡 PARTIAL · APP_EVENT · needs app event** · OWASP A07:2021 · CWE-287 · [R16](#rule-r16) · [F4](authentication-code-findings.md#finding-f4) · [AUTH-09](#todo-auth-09) · [AUTH-10](#todo-auth-10)

**In one sentence:** An attacker cannot take over a password account by signing in with a Google account of the same email, because the app keys Google identities by subject and refuses to link. SecureNow receives the refusal event and notifies on clusters. Your app must keep refusing — and add a safe reclaim path ([F4](authentication-code-findings.md#finding-f4)).

- **Attack scenario:** An attacker cannot take over a password account by signing in with a Google account of the same email, because the app keys Google identities by subject and refuses to link. Refusal at `src/app.js:247-250`; tested.
- **How SecureNow detects it:** [R16](#rule-r16). Signal: link refusals (R16), evaluated every 15 minutes. Rules are created in test mode, so each hit is a notification in the human queue (`npx securenow human list`) with no automatic action until a person promotes the rule (test-first).
- **How SecureNow mitigates it:** Notify. Any manual action from §9 is time-boxed (`--duration`) and reversible (`ratelimit remove`, `blocklist unblock`, `revoke restore`).
- **What you still need to do:** Keep; F4.
- **Limits and false-positive safety:** —
- **Definition of done:** R16 created. Commands: [R16](#rule-r16).

<a id="threat-g36"></a>
#### G36 · Open just-in-time provisioning through Google sign-in
**LOW · 🟡 PARTIAL · APP_EVENT · needs app event** · OWASP A01:2021 · CWE-269 · [R23](#rule-r23) · [AUTH-09](#todo-auth-09) · [AUTH-10](#todo-auth-10)

**In one sentence:** An attacker can mass-create member accounts with throwaway Google identities, because any Google user can create a member account (intended for this public lab). SecureNow receives the sign-up event (including Google-created accounts), detects 5+ new accounts per IP per hour, and notifies or rate-limits. Your app must keep new accounts at `member` (it does).

- **Attack scenario:** An attacker can mass-create member accounts with throwaway Google identities, because any Google user can create a member account (intended for this public lab). New Google users get `member` with no role mapping (`src/app.js:240-243`).
- **How SecureNow detects it:** [R23](#rule-r23) (needs the signup event after `src/app.js:244`). Signal: ≥ 5 accounts created per IP / 60 min (Google-created accounts included), evaluated every 15 minutes. Rules are created in test mode, so each hit is a notification in the human queue (`npx securenow human list`) with no automatic action until a person promotes the rule (test-first).
- **How SecureNow mitigates it:** Manual `ratelimit add <ip> --route <Google regex> …`. Automated responses (AUTO-G) are created disabled, time-boxed to 24 h and reversible with `ratelimit remove` / `blocklist unblock` / `challenge remove` or `automation update <id> --status disabled` (§9).
- **What you still need to do:** None required.
- **Limits and false-positive safety:** —
- **Definition of done:** R23 created. Commands: [R23](#rule-r23).

<a id="threat-g36e"></a>
#### G36e · Google account disabled, but lab session continues
**LOW · 🔴 GAP · PROVIDER_EVENT · needs provider data** · OWASP A07:2021 · CWE-613

**In one sentence:** An attacker using a Google account that Google later disables keeps their lab session until it expires (at most 8 hours). SecureNow would need a provider deprovisioning event that does not exist for consumer Google sign-in. Your app relies on its 8-hour absolute limit.

- **Attack scenario:** An attacker using a Google account that Google later disables keeps their lab session until it expires (at most 8 hours). No SCIM or back-channel logout for consumer Google.
- **How SecureNow detects it:** None — 🔴 gap. (no provider feed — consumer Google accounts have no SCIM/deprovisioning signal for this app.)
- **How SecureNow mitigates it:** None. No SecureNow action, so nothing to reverse.
- **What you still need to do:** Accept (public lab).
- **Limits and false-positive safety:** —
- **Definition of done:** Documented as accepted risk.

<a id="threat-h40b"></a>
#### H40b · Email canonicalization mismatch (Unicode, Gmail dots, plus-aliases)
**LOW · 🔴 GAP · APP_OR_PROVIDER_CONTROL · outside SecureNow (app/external)** · OWASP A07:2021 · CWE-176 · [F4](authentication-code-findings.md#finding-f4) · [AUTH-18](#todo-auth-18)

**In one sentence:** An attacker can register look-alike variants of an address (dots, plus-tags, Unicode look-alikes) that the app stores as separate accounts. Impact is low because the app never emails anyone. SecureNow cannot judge canonical forms. Your app must normalize (NFKC) and rely on verified addresses once email is added.

- **Attack scenario:** An attacker can register look-alike variants of an address (dots, plus-tags, Unicode look-alikes) that the app stores as separate accounts. Normalization is trim + lowercase only (`src/app.js:13`).
- **How SecureNow detects it:** None. (no signal.)
- **How SecureNow mitigates it:** None. No SecureNow action, so nothing to reverse.
- **What you still need to do:** [F4](authentication-code-findings.md#finding-f4).
- **Limits and false-positive safety:** —
- **Definition of done:** —

<a id="threat-h40c"></a>
#### H40c · Dormant-account takeover followed by changes
**LOW · 🟡 PARTIAL · APP_EVENT · needs app event** · OWASP A07:2021 · CWE-308 · [R22](#rule-r22) · [R19](#rule-r19) · [AUTH-26](#todo-auth-26)

**In one sentence:** An attacker who gets into an abandoned account can change its password without anyone noticing. SecureNow receives the dormant sign-in and the change, detects either, and notifies. Your app must record last sign-in times.

- **Attack scenario:** An attacker who gets into an abandoned account can change its password without anyone noticing. See C16b.
- **How SecureNow detects it:** [R22](#rule-r22), [R19](#rule-r19). Signal: dormant sign-in; takeover sequence, evaluated every 15 minutes. Rules are created in test mode, so each hit is a notification in the human queue (`npx securenow human list`) with no automatic action until a person promotes the rule (test-first).
- **How SecureNow mitigates it:** Notify. Any manual action from §9 is time-boxed (`--duration`) and reversible (`ratelimit remove`, `blocklist unblock`, `revoke restore`).
- **What you still need to do:** AUTH-26.
- **Limits and false-positive safety:** —
- **Definition of done:** R22 created. Commands: [R22](#rule-r22), [R19](#rule-r19).

<a id="threat-k49"></a>
#### K49 · Password-hash work factor below current guidance
**LOW · 🔴 GAP · APP_OR_PROVIDER_CONTROL · outside SecureNow (app/external)** · OWASP A02:2021 · CWE-916 · [F8](authentication-code-findings.md#finding-f8) · [AUTH-21](#todo-auth-21)

**In one sentence:** An attacker with a stolen backup can test guesses against scrypt hashes faster than OWASP’s minimum would allow. SecureNow cannot see hashes. Your app must raise the cost (same memory, p=3) and rehash on sign-in.

- **Attack scenario:** An attacker with a stolen backup can test guesses against scrypt hashes faster than OWASP’s minimum would allow. See A5a.
- **How SecureNow detects it:** None. (no signal.)
- **How SecureNow mitigates it:** None. No SecureNow action, so nothing to reverse.
- **What you still need to do:** [F8](authentication-code-findings.md#finding-f8).
- **Limits and false-positive safety:** —
- **Definition of done:** New hashes use the new parameters.

<a id="threat-c10"></a>
#### C10 · Session fixation
**LOW · 🔴 GAP · APP_OR_PROVIDER_CONTROL · outside SecureNow (app/external)** · OWASP A07:2021 · CWE-384 · [AUTH-31](#todo-auth-31)

**In one sentence:** An attacker cannot plant a known session ID before sign-in because the app regenerates the session on every successful authentication. SecureNow sees nothing that would distinguish a fixation attempt, so it cannot detect it. Your app must keep `regenerateSession` in `authenticate()`.

- **Attack scenario:** An attacker cannot plant a known session ID before sign-in because the app regenerates the session on every successful authentication. `authenticate()` calls `req.session.regenerate` before storing the user (`src/app.js:139-149`), and the test suite asserts the cookie changes at login.
- **How SecureNow detects it:** None (prevention only). (no signal — prevented in code.)
- **How SecureNow mitigates it:** None needed. No SecureNow action, so nothing to reverse.
- **What you still need to do:** Keep it; add a regression test for Google sign-in too.
- **Limits and false-positive safety:** —
- **Definition of done:** Integration test “login rotates sessions” stays green.

<a id="threat-c14"></a>
#### C14 · Weak session-cookie configuration
**LOW · 🔴 GAP · APP_OR_PROVIDER_CONTROL · outside SecureNow (app/external)** · OWASP A05:2021 · CWE-614 · [AUTH-31](#todo-auth-31)

**In one sentence:** An attacker cannot read the session cookie from JavaScript, receive it over plain HTTP, or set it from a subdomain, because the production cookie is `__Host-lab_auth` with Secure, HttpOnly and SameSite=Lax. SecureNow does not see response cookies, so it cannot detect a regression. Your app must keep these flags (an external check can watch them).

- **Attack scenario:** An attacker cannot read the session cookie from JavaScript, receive it over plain HTTP, or set it from a subdomain, because the production cookie is `__Host-lab_auth` with Secure, HttpOnly and SameSite=Lax. Verified on 2026-10-16 with one passive GET of `/api/me` against the live lab.
- **How SecureNow detects it:** None in SecureNow. (no signal — verified live: __Host-lab_auth; Secure; HttpOnly; SameSite=Lax; Path=/.)
- **How SecureNow mitigates it:** None. No SecureNow action, so nothing to reverse.
- **What you still need to do:** Keep `scripts/smoke.mjs` cookie assertions in CI.
- **Limits and false-positive safety:** —
- **Definition of done:** Smoke check passes against production.

<a id="threat-c15"></a>
#### C15 · Excessive session lifetime
**LOW · 🔴 GAP · APP_OR_PROVIDER_CONTROL · outside SecureNow (app/external)** · OWASP A07:2021 · CWE-613 · [AUTH-31](#todo-auth-31)

**In one sentence:** An attacker holding an old cookie cannot reuse it for days: sessions end after 30 idle minutes and 8 hours absolute. SecureNow cannot see session age, so it does not detect this. Your app must keep both limits server-side (it does).

- **Attack scenario:** An attacker holding an old cookie cannot reuse it for days: sessions end after 30 idle minutes and 8 hours absolute. Idle expiry is the cookie/store maxAge with `rolling: true`; the absolute limit is checked on every request from `authAt`.
- **How SecureNow detects it:** None. (no signal — 30 min idle (rolling), 8 h absolute.)
- **How SecureNow mitigates it:** None. No SecureNow action, so nothing to reverse.
- **What you still need to do:** Keep.
- **Limits and false-positive safety:** —
- **Definition of done:** Unit test for absolute expiry (suggested).

<a id="threat-d18"></a>
#### D18 · Weak or guessable session-cookie signing secret
**LOW · 🔴 GAP · APP_OR_PROVIDER_CONTROL · outside SecureNow (app/external)** · OWASP A02:2021 · CWE-326 · [AUTH-31](#todo-auth-31)

**In one sentence:** An attacker cannot forge a signed session cookie unless SESSION_SECRET is weak, and the app refuses to start with fewer than 32 characters or with the audit secret reused. SecureNow cannot observe secret strength. Your deployment must keep generating random secrets (it does).

- **Attack scenario:** An attacker cannot forge a signed session cookie unless SESSION_SECRET is weak, and the app refuses to start with fewer than 32 characters or with the audit secret reused. Sessions are server-side, so a forged signature alone still needs a valid session ID.
- **How SecureNow detects it:** None. (no signal — startup refuses secrets under 32 characters.)
- **How SecureNow mitigates it:** None. No SecureNow action, so nothing to reverse.
- **What you still need to do:** Keep.
- **Limits and false-positive safety:** —
- **Definition of done:** Config tests (suggested).

<a id="threat-g31"></a>
#### G31 · redirect_uri manipulation / open redirect after Google sign-in
**LOW · 🔴 GAP · APP_OR_PROVIDER_CONTROL · outside SecureNow (app/external)** · OWASP A01:2021 · CWE-601 · [AUTH-33](#todo-auth-33) · [AUTH-28](#todo-auth-28)

**In one sentence:** An attacker cannot steer the Google authorization code to their own site: the app computes the redirect URI from `APP_ORIGIN` and never takes a return URL from the request. SecureNow would see nothing, because Google refuses a bad redirect before the app is involved. Your Google Cloud project must list only the exact production callback (not verifiable from the repo — a question for you).

- **Attack scenario:** An attacker cannot steer the Google authorization code to their own site: the app computes the redirect URI from `APP_ORIGIN` and never takes a return URL from the request.
- **How SecureNow detects it:** None. (no app signal — Google rejects unregistered redirect URIs before the callback.)
- **How SecureNow mitigates it:** None. No SecureNow action, so nothing to reverse.
- **What you still need to do:** Confirm the console list (AUTH-28). Depth: `../07-oauth-sso-integrations/`.
- **Limits and false-positive safety:** —
- **Definition of done:** Console shows exactly the two documented URIs (local + production).

<a id="threat-g36b"></a>
#### G36b · Identity keyed on a mutable claim (email instead of subject)
**LOW · 🔴 GAP · APP_OR_PROVIDER_CONTROL · outside SecureNow (app/external)** · OWASP A07:2021 · CWE-290 · [AUTH-33](#todo-auth-33)

**In one sentence:** An attacker cannot take over an account by controlling a Google account whose email later matches: identity is the Google subject, not the email. SecureNow has nothing to detect. Your app must keep keying on `sub`.

- **Attack scenario:** An attacker cannot take over an account by controlling a Google account whose email later matches: identity is the Google subject, not the email. `SELECT … WHERE google_subject=$1`; the stored email is never updated from Google (harmless here).
- **How SecureNow detects it:** None. (no signal — keyed on Google `sub`.)
- **How SecureNow mitigates it:** None. No SecureNow action, so nothing to reverse.
- **What you still need to do:** Keep.
- **Limits and false-positive safety:** —
- **Definition of done:** Test “never links by email” stays green.

<a id="threat-h38a"></a>
#### H38a · Races in identity-state changes (duplicate registration, parallel guesses)
**LOW · 🔴 GAP · APP_OR_PROVIDER_CONTROL · outside SecureNow (app/external)** · OWASP A04:2021 · CWE-362 · [AUTH-30](#todo-auth-30)

**In one sentence:** An attacker cannot win a race to create two accounts for one email or slip guesses past the counter: email and Google subject are unique, inserts use ON CONFLICT, and the limiter increments atomically before the password is checked. SecureNow has nothing to detect. Your app must keep these guarantees.

- **Attack scenario:** An attacker cannot win a race to create two accounts for one email or slip guesses past the counter: email and Google subject are unique, inserts use ON CONFLICT, and the limiter increments atomically before the password is checked.
- **How SecureNow detects it:** None. (no signal — prevented by unique indexes and an atomic counter.)
- **How SecureNow mitigates it:** None. No SecureNow action, so nothing to reverse.
- **What you still need to do:** Keep.
- **Limits and false-positive safety:** —
- **Definition of done:** Existing tests.

<a id="threat-h40d"></a>
#### H40d · Signup overwriting or shadowing an existing account
**LOW · 🔴 GAP · APP_OR_PROVIDER_CONTROL · outside SecureNow (app/external)** · OWASP A07:2021 · CWE-287 · [AUTH-30](#todo-auth-30)

**In one sentence:** An attacker cannot reset someone’s password by registering their email again: the insert does nothing on conflict and the response is identical. SecureNow has nothing to detect. Your app must keep the constraint.

- **Attack scenario:** An attacker cannot reset someone’s password by registering their email again: the insert does nothing on conflict and the response is identical.
- **How SecureNow detects it:** None. (no signal — ON CONFLICT DO NOTHING + unique lowercase email.)
- **How SecureNow mitigates it:** None. No SecureNow action, so nothing to reverse.
- **What you still need to do:** Keep.
- **Limits and false-positive safety:** —
- **Definition of done:** Test “registration is generic” stays green.

<a id="threat-h40g"></a>
#### H40g · Mass assignment of auth fields on signup
**LOW · 🔴 GAP · APP_OR_PROVIDER_CONTROL · outside SecureNow (app/external)** · OWASP A01:2021 · CWE-915 · [AUTH-30](#todo-auth-30)

**In one sentence:** An attacker cannot register as admin or as email-verified by adding fields to the JSON: the handler reads only name, email and password. SecureNow could only see this with body capture, which this lab keeps off. Your app must keep explicit field picking. Role-field depth: `../02-authorization/`.

- **Attack scenario:** An attacker cannot register as admin or as email-verified by adding fields to the JSON: the handler reads only name, email and password.
- **How SecureNow detects it:** None. (no signal (request bodies are not captured, by design).)
- **How SecureNow mitigates it:** None. No SecureNow action, so nothing to reverse.
- **What you still need to do:** Keep.
- **Limits and false-positive safety:** —
- **Definition of done:** Integration test stays green.

<a id="threat-i45"></a>
#### I45 · Unauthenticated health endpoints reachable from outside
**LOW · 🔴 GAP · APP_OR_PROVIDER_CONTROL · outside SecureNow (app/external)** · OWASP A01:2021 · CWE-306 · [AUTH-35](#todo-auth-35)

**In one sentence:** An attacker learns nothing useful from `/healthz` and `/readyz` (status only), though `/readyz` runs `SELECT 1` on each call. SecureNow does not need a rule here. Your app must keep them minimal.

- **Attack scenario:** An attacker learns nothing useful from `/healthz` and `/readyz` (status only), though `/readyz` runs `SELECT 1` on each call. `src/app.js:69-73`. The app and database ports are not published (`compose.production.yaml`).
- **How SecureNow detects it:** None. (no signal needed — /healthz and /readyz return only a status word.)
- **How SecureNow mitigates it:** Optional `ratelimit add --route /readyz …`. No SecureNow action, so nothing to reverse.
- **What you still need to do:** Keep.
- **Limits and false-positive safety:** —
- **Definition of done:** —

<a id="threat-k50"></a>
#### K50 · Missing TLS/HSTS or cookies over plain HTTP
**LOW · 🔴 GAP · EXTERNAL_MONITOR · outside SecureNow (app/external)** · OWASP A02:2021 · CWE-319 · [AUTH-27](#todo-auth-27) · [AUTH-31](#todo-auth-31)

**In one sentence:** An attacker on the network cannot downgrade the site to HTTP: port 80 answers 308 to HTTPS and HSTS is one year. SecureNow cannot watch certificates or response headers, so an expiring certificate or a dropped header needs an external monitor. Your deployment must keep Caddy’s TLS and add an outside check.

- **Attack scenario:** An attacker on the network cannot downgrade the site to HTTP: port 80 answers 308 to HTTPS and HSTS is one year. Verified 2026-10-16: 308 redirect; `Strict-Transport-Security: max-age=31536000` (sent twice — Caddy and helmet — harmless).
- **How SecureNow detects it:** None in SecureNow. (no in-band signal; an external check must watch certificate and headers.)
- **How SecureNow mitigates it:** None. No SecureNow action, so nothing to reverse.
- **What you still need to do:** Optional: send HSTS from one place only.
- **Limits and false-positive safety:** —
- **Definition of done:** External monitor alerts 14 days before expiry.

<a id="threat-k51"></a>
#### K51 · Auth secrets committed to Git or baked into images
**LOW · 🔴 GAP · APP_OR_PROVIDER_CONTROL · outside SecureNow (app/external)** · OWASP A05:2021 · CWE-798 · [AUTH-36](#todo-auth-36)

**In one sentence:** An attacker browsing the public repo finds no OAuth secret, session secret or runtime key: all 4 commits were scanned and only the scanner’s own patterns matched. SecureNow cannot scan repositories. Your repo must keep the CI scan and ignore lists. Depth: `../26-secrets-and-api-key-hygiene/`.

- **Attack scenario:** An attacker browsing the public repo finds no OAuth secret, session secret or runtime key: all 4 commits were scanned and only the scanner’s own patterns matched. Local operator files (`.deployment/`, `.securenow/admin.json`) exist on the workstation but are ignored by Git and Docker.
- **How SecureNow detects it:** None. (no signal — Git history scanned clean in this run.)
- **How SecureNow mitigates it:** None. No SecureNow action, so nothing to reverse.
- **What you still need to do:** Keep.
- **Limits and false-positive safety:** —
- **Definition of done:** CI secret scan stays required.

<a id="threat-l54"></a>
#### L54 · IDOR on account-management endpoints
**LOW · 🔴 GAP · APP_OR_PROVIDER_CONTROL · outside SecureNow (app/external)** · OWASP A01:2021 · CWE-639 · [AUTH-30](#todo-auth-30)

**In one sentence:** An attacker cannot list another member’s sessions or change roles without admin, because `/api/security` queries only the caller’s sessions and role changes need the admin role. SecureNow has no signal here. Your app must keep scoping every account query to the caller. Depth: `../02-authorization/`.

- **Attack scenario:** An attacker cannot list another member’s sessions or change roles without admin, because `/api/security` queries only the caller’s sessions and role changes need the admin role. `src/app.js:280`, `287-299`.
- **How SecureNow detects it:** None. (no signal.)
- **How SecureNow mitigates it:** None. No SecureNow action, so nothing to reverse.
- **What you still need to do:** Keep.
- **Limits and false-positive safety:** —
- **Definition of done:** —



<a id="sdk-env"></a>
## 5. SDK & environment

### Ready / Needs setup / Unknown

| Item | Status | Evidence (this run, 2026-10-16) |
| --- | --- | --- |
| Admin CLI auth | Ready | `npx securenow whoami` → connected (project admin file), expires in 29 days |
| SDK installed | Ready (grounding only) | `node_modules/securenow/package.json` → 8.12.0; `npm ls` marks it extraneous (installed with --no-save) |
| SDK loaded by the app | Needs setup | No `securenow` import or preload in src/, Dockerfile or compose files (AUTH-01) |
| Runtime credentials | Needs setup | `whoami` → SDK runtime “no app selected”, runtime API key missing; `doctor` → ingest probes HTTP 401 (expected without a runtime key) |
| Telemetry flowing | Needs setup | `telemetry fields --app lab-auth --since 30d --source all --env all` → 0 fields, 0 event types |
| Capture settings | Needs setup | `npx securenow env` → captureBody true, captureMultipart true, deploymentEnvironment production (defaults) — set body/multipart off and environment test first (F13) |
| Firewall (env test) | Needs setup | `firewall status --env test` → DISABLED FOR APP/ENV (AUTH-02) |
| Out-of-band alert channel | Needs setup | `alerts channels` → 1 channel, type `securenow` (in-app only) (AUTH-04) |
| Rules covering lab-auth | Needs setup | 0 of the account’s 169 rules are scoped to lab-auth; none uses applicationsAll — nothing to lint for this app |
| Automations that already apply | Unknown → review | 4 active, all apps: one custom auth-abuse auto-block (24 h, all routes, alert-name match) + 3 SecureNow default risk-score auto-blocks (AUTH-03) |
| Revocation path | Unknown | `revoke list` → HTTP 404 (the CLI calls /api/revocations — node_modules/securenow/cli/security.js:1008 — while the SDK guard syncs from /api/v1/revocations/sync — sessions.js:39) (AUTH-17) |
| ASN enrichment on events | Unknown | Not observable without events; R26/R27 depend on it |
| Client IP trust | Ready | Caddy overwrites X-Forwarded-For; app trusts one hop; SDK resolves the chain from a private proxy socket (node_modules/securenow/resolve-ip.js:72-99) |

### Raw values

| Command | Result |
| --- | --- |
| `npx securenow version` | securenow v8.12.0 (global `securenow` = v8.11.3 → not used) |
| `npx securenow doctor` | API reachable (HTTP 200); traces/logs ingest probes rejected HTTP 401; warnings: no app key, runtime API key missing; “One or more checks failed” |
| `npx securenow whoami` | Admin connected; SDK runtime: no app selected, environment production (default), runtime source not configured |
| `npx securenow status --json` | 13 applications; lab-auth `df7ab010-37ac-4732-88ac-a8ac23afe1a4`, host lab-auth.labs.securenow.ai; production protection: firewall on, traces idle, 0 in 15 min. (The command printed the human table, not JSON.) |
| `npx securenow alerts rules list --json` | 169 rules, all test/Active/scheduled; 0 scoped to lab-auth; 0 applicationsAll; 0 logs-table rules with the unbounded `now() - INTERVAL` filter |
| `npx securenow alerts channels --json` | 1 channel: “SecureNow Notifications”, type securenow (in-app) |
| `npx securenow automation list --json` | 8 rules; 4 apply to lab-auth: “Auto-block: auth-abuse IPs (brute-force / flood / credential-stuffing)” (active, all apps, addToBlocklist 24 h all routes when alertName contains brute force \| flood \| many accounts \| credential stuffing) and SecureNow Default Elevated / High / Critical Risk Auto-Block (riskScore 85–89 → 24 h, 90–94 → 72 h, ≥ 95 → 168 h, all routes) |
| `npx securenow challenge list --json` | 0 challenge rules |
| `npx securenow ratelimit list --json` | 2 rules, both scoped to another app — none for lab-auth |
| `npx securenow blocklist list --json --status active` | 886 entries in the account; `firewall status` counts 885 global blocks that also apply to lab-auth; 0 scoped rules |
| `npx securenow trusted list --json` | 5 entries; 4 are global and therefore also suppress detection AND mitigation for lab-auth: the account's existing trusted-IP entries (SecureNow infrastructure and two crawler ranges) |
| `npx securenow fp list --json` | 0 exclusion rules |
| `npx securenow revoke list --json` | Failed: HTTP 404 (also with --app) |
| `npx securenow env --json` | serviceName lab-auth-<uuid-per-worker> (no app key yet), appKey null, deploymentEnvironment production, captureBody true, captureMultipart true, firewallEnabled false |
| `npx securenow telemetry schema --json` | logs: signoz_logs.distributed_logs_v2, UInt64 ns timestamp, tenant resources_string['service.name']; traces: signoz_traces.distributed_signoz_index_v3, DateTime64(9), tenant `resource_string_service$$name`; required `ip` column |
| `npx securenow telemetry fields --app … --since 7d --source all --env all --json` | 0 fields, 0 event types (also 0 over 30d) |
| `npx securenow firewall status --app … --env test` | DISABLED FOR APP/ENV; 885 global blocked IPs; 0 scoped block rules; 0 rate-limit rules; allowlist empty |

**Baselines.** The prompt’s baseline step (p99/max per IP per 15 minutes) could not be measured: there is no lab telemetry. Every threshold below therefore cites the app’s own limit from code or says “baseline required — conservative start”. The baseline query is saved as `threat/01-authentication/rules/_baseline-auth-posts.sql` for AUTH-12.

**Live probe (passive GET/HEAD only).** `HEAD /` → 200 with strict CSP, `X-Frame-Options`, `Referrer-Policy: no-referrer` and two identical `Strict-Transport-Security: max-age=31536000` headers (Caddy + helmet); `HEAD http://…` → 308 to HTTPS; `GET /healthz` → `{"status":"ok"}`; one `GET /api/me` → `Cache-Control: no-store` and `Set-Cookie: __Host-lab_auth=…; Path=/; HttpOnly; Secure; SameSite=Lax` (a new anonymous session — see F1).


<a id="matrix"></a>
## 6. Threat → Detection → Mitigation matrix (technical reference)

67 modeled rows: 0 🟢 covered · 41 🟡 partial · 26 🔴 gap. Coverage is 🟡 rather than 🟢 for every rule because no telemetry exists yet for lab-auth — a rule whose attributes are absent from `telemetry fields` is partial by definition. Schedules are cron minute fields (`*/5` = every 5 minutes). Mode: test-first = observe 3–7 days before promotion; prod-ready = may be promoted after one clean week.

| # | Threat | OWASP/CWE | Coverage | Signal source | Detection rule | Signal (threshold + window) | Schedule | Sev | Mode | Mitigation |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| [A1](#threat-a1) | Single-IP password guessing on the sign-in form | A07:2021 / CWE-307 | 🟡 PARTIAL | NATIVE_TRAFFIC | [R01](#rule-r01), [R02](#rule-r02), [R10](#rule-r10) — creatable now — data after SDK load | ≥ 10 HTTP 401 on POST /api/auth/login per IP / 15 min (R01); ≥ 5 HTTP 429 per IP / 15 min (R02) | */5 | HIGH | test-first | AUTO-A rate-limit (5 sign-ins / 15 min / IP on a case-insensitive login regex, 24 h) → AUTO-B route-scoped POST /api/auth/* block 24 h only if riskScore ≥ 90; app limit 15 / 15 min stays |
| [A2](#threat-a2) | Distributed / low-and-slow guessing that rotates addresses | A07:2021 / CWE-307 | 🟡 PARTIAL | NATIVE_TRAFFIC | [R06](#rule-r06), [R11](#rule-r11), [R26](#rule-r26) — creatable now — data after SDK load | ≥ 4 IPs & ≥ 15 failures per /24 or /64 / 30 min (R06); ≥ 5 IPs & ≥ 12 failures per account / 30 min (R11) | */10 | HIGH | test-first | notify; manual CIDR rate-limit on the login regex 24 h; app per-account/device controls (F3) |
| [A3](#threat-a3) | Credential stuffing with breached email/password pairs | A07:2021 / CWE-307 | 🟡 PARTIAL | APP_EVENT | [R10](#rule-r10), [R13](#rule-r13) — creatable after instrumentation | ≥ 10 failures over ≥ 5 accounts per IP / 15 min (R10); ≥ 3 accounts signed in per IP / 60 min (R13) | */5 | HIGH | test-first | AUTO-A rate-limit → AUTO-B route block at riskScore ≥ 90; app breached-password screening (F10) |
| [A4](#threat-a4) | Password spraying (one common password, many accounts) | A07:2021 / CWE-307 | 🟡 PARTIAL | APP_EVENT | [R10](#rule-r10), [R26](#rule-r26) — creatable after instrumentation | ≥ 10 failures over ≥ 5 accounts per IP / 15 min; per-ASN breadth (R26) | */5 | MEDIUM | test-first | AUTO-A rate-limit; app common/breached password block (F10) |
| [A4a](#threat-a4a) | Rate-limit counter weaknesses (window boundary, IPv6 rotation) | A07:2021 / CWE-307 | 🟡 PARTIAL | NATIVE_TRAFFIC | [R06](#rule-r06) — creatable now — data after SDK load | per-/64 grouping of failures (R06) | */10 | LOW | test-first | notify; app /64 keys + sliding window (F11) |
| [A5](#threat-a5) | Default, seeded or leftover bootstrap credentials | A07:2021 / CWE-1392 | 🔴 GAP | APP_OR_PROVIDER_CONTROL | not currently creatable | no signal — the credential lives in AWS Secrets Manager | — | LOW | — | app fix: strip ADMIN_PASSWORD from the runtime secret after first use; force a password change on first admin sign-in (F12) |
| [A5a](#threat-a5a) | Password-handling gaps (no breach screening, no Unicode normalization, scrypt below OWASP minimum) | A02:2021 / CWE-916 | 🔴 GAP | APP_OR_PROVIDER_CONTROL | not currently creatable | no signal — properties of stored hashes and accepted passwords | — | LOW | — | app fix F8 (scrypt cost + rehash) and F10 (breach screening + NFC) |
| [B6](#threat-b6) | Account enumeration via register-then-sign-in | A07:2021 / CWE-204 | 🟡 PARTIAL | APP_EVENT | [R23](#rule-r23) — creatable after instrumentation | ≥ 3 registrations on already-registered emails per IP / 60 min | */15 | MEDIUM | test-first | AUTO-G registration rate-limit (3 / h / IP, 24 h); app email verification (F4) |
| [B7](#threat-b7) | Identifier harvesting at scale | A07:2021 / CWE-204 | 🟡 PARTIAL | APP_EVENT | [R10](#rule-r10), [R23](#rule-r23) — creatable after instrumentation | distinct accounts per IP (R10); existing-email registrations (R23) | */5 | MEDIUM | test-first | AUTO-A, AUTO-G |
| [B8](#threat-b8) | Auth-surface scanning (forced browsing for .env, .git, admin panels) | A05:2021 / CWE-425 | 🟡 PARTIAL | NATIVE_TRAFFIC | [R05](#rule-r05) — creatable now — data after SDK load | ≥ 3 sensitive-path probes or ≥ 30 404/403 per IP / 15 min; instant on one dotfile request | */5 | MEDIUM | test-first | firewall known-bad IP feed (env test); AUTO-E proof-of-work challenge on GET pages 24 h; instant block 24 h on dotfile probes after promotion |
| [B8a](#threat-b8a) | Google sign-in conflict message as an enumeration oracle | A07:2021 / CWE-204 | 🟡 PARTIAL | APP_EVENT | [R16](#rule-r16) — creatable after instrumentation | ≥ 3 link refusals per IP or ≥ 5 app-wide / 60 min | */15 | LOW | test-first | notify only |
| [C9](#threat-c9) | Session cookie theft (malware, XSS, phishing proxy) | A07:2021 / CWE-294 | 🟡 PARTIAL | APP_EVENT | [R17](#rule-r17), [R20](#rule-r20) — creatable after instrumentation | one account seen from ≥ 3 IPs / 60 min (R17); security change from a different IP than sign-in (R20) | */15 | HIGH | test-first | human review → `revoke session` / `revoke user` (needs guard(); CLI currently returns 404) + owner changes password |
| [C10](#threat-c10) | Session fixation | A07:2021 / CWE-384 | 🔴 GAP | APP_OR_PROVIDER_CONTROL | not currently creatable | no signal — prevented in code | — | LOW | — | already prevented: session regenerated on every sign-in (src/app.js:140) |
| [C11](#threat-c11) | Limited revocation (no sign-out-everywhere, Google-only users, no admin kill switch) | A07:2021 / CWE-613 | 🟡 PARTIAL | APP_EVENT | creatable after instrumentation | enforcement only: revocations apply on the next request where guard() runs | — | MEDIUM | — | `revoke session/user` once guard() is wired (CLI 404 today); app session controls (F7) |
| [C11a](#threat-c11a) | Sessions surviving a password change or role downgrade (regression) | A07:2021 / CWE-613 | 🟡 PARTIAL | APP_EVENT | [R18](#rule-r18) — creatable after instrumentation | a pre-change session seen ≥ 5 min after a completed password change (1-day window) | */15 | HIGH | prod-ready | revoke session (manual) + fix the regression |
| [C12](#threat-c12) | Concurrent use of one account from several networks | A07:2021 / CWE-613 | 🟡 PARTIAL | APP_EVENT | [R17](#rule-r17) — creatable after instrumentation | ≥ 3 IPs per account / 60 min | */15 | MEDIUM | test-first | notify → human review → revoke |
| [C13](#threat-c13) | CSRF against auth endpoints (and floods of CSRF-rejected requests) | A01:2021 / CWE-352 | 🟡 PARTIAL | NATIVE_TRAFFIC | [R04](#rule-r04) — creatable now — data after SDK load | ≥ 20 unverifiable 403 API mutations per IP / 15 min | */5 | MEDIUM | test-first | AUTO-D rate-limit API POSTs 30 / 15 min / IP, 24 h; prevention already in place |
| [C14](#threat-c14) | Weak session-cookie configuration | A05:2021 / CWE-614 | 🔴 GAP | APP_OR_PROVIDER_CONTROL | not currently creatable | no signal — verified live: __Host-lab_auth; Secure; HttpOnly; SameSite=Lax; Path=/ | — | LOW | — | already in place (src/app.js:42, 75-79) |
| [C15](#threat-c15) | Excessive session lifetime | A07:2021 / CWE-613 | 🔴 GAP | APP_OR_PROVIDER_CONTROL | not currently creatable | no signal — 30 min idle (rolling), 8 h absolute | — | LOW | — | already in place (src/config.js:27-28, src/app.js:93) |
| [C16](#threat-c16) | Sign-in from an unusual network (hosting/VPN provider, new operator) | A07:2021 / CWE-308 | 🟡 PARTIAL | APP_EVENT | [R27](#rule-r27) — creatable after instrumentation | account signs in from a network operator unseen in its previous 7 days (needs ASN enrichment) | */15 | LOW | test-first | notify; app step-up/MFA later (F5) |
| [C16a](#threat-c16a) | Successful sign-in right after failures, or one IP into several accounts | A07:2021 / CWE-307 | 🟡 PARTIAL | APP_EVENT | [R12](#rule-r12), [R13](#rule-r13) — creatable after instrumentation | ≥ 5 failures then success within 30 min (R12); ≥ 3 accounts per IP / 60 min (R13) | */10 | HIGH | test-first | human review → owner resets password (password change kills other sessions) / `revoke user` |
| [C16b](#threat-c16b) | Dormant-account reactivation | A07:2021 / CWE-308 | 🟡 PARTIAL | APP_EVENT | [R22](#rule-r22) — creatable after instrumentation | sign-in with dormant_days ≥ 90 | */15 | LOW | test-first | notify |
| [C16c](#threat-c16c) | Multi-step takeover: failures → sign-in → password or role change | A07:2021 / CWE-308 | 🟡 PARTIAL | APP_EVENT | [R19](#rule-r19) — creatable after instrumentation | ordered funnel within 1 h (2 h window) | */15 | HIGH | test-first | human review → `revoke user`, restore password/role |
| [C16d](#threat-c16d) | Sensitive action from a different network than the sign-in | A07:2021 / CWE-294 | 🟡 PARTIAL | APP_EVENT | [R20](#rule-r20) — creatable after instrumentation | security change IP ≠ sign-in IP for the same session (8 h) | */15 | MEDIUM | test-first | notify → revoke session |
| [D18](#threat-d18) | Weak or guessable session-cookie signing secret | A02:2021 / CWE-326 | 🔴 GAP | APP_OR_PROVIDER_CONTROL | not currently creatable | no signal — startup refuses secrets under 32 characters | — | LOW | — | already in place (src/config.js:8-10; deploy generates 48 random bytes) |
| [D19](#threat-d19) | Google ID-token validation (signature, audience, expiry, issuer, nonce) | A07:2021 / CWE-347 | 🟡 PARTIAL | APP_EVENT | [R15](#rule-r15) — creatable after instrumentation | ≥ 5 provider-verification or invalid-callback failures per IP / 15 min | */5 | MEDIUM | test-first | AUTO-F rate-limit Google routes 10 / 15 min / IP, 24 h; validation already in place |
| [D21](#threat-d21) | Token leakage into URLs, logs, Referer or telemetry | A09:2021 / CWE-532 | 🔴 GAP | APP_OR_PROVIDER_CONTROL | not currently creatable | no signal — a capture-configuration property | — | LOW | — | config: capture.body=false and multipart=false before first SDK start; SDK header-redaction feature request (F13) |
| [D21a](#threat-d21a) | Live session IDs and OAuth transactions readable from database backups | A02:2021 / CWE-312 | 🔴 GAP | APP_OR_PROVIDER_CONTROL | not currently creatable | no signal | — | LOW | — | app/ops fix: exclude sessions and rate_buckets table data from pg_dump (F14) |
| [G31](#threat-g31) | redirect_uri manipulation / open redirect after Google sign-in | A01:2021 / CWE-601 | 🔴 GAP | APP_OR_PROVIDER_CONTROL | not currently creatable | no app signal — Google rejects unregistered redirect URIs before the callback | — | LOW | — | already in place: redirect URI is a server constant (src/app.js:40); post-login redirects are fixed paths (src/app.js:229,250,255,258) |
| [G32](#threat-g32) | Missing state or PKCE (login CSRF / code injection) | A07:2021 / CWE-352 | 🟡 PARTIAL | APP_EVENT | [R15](#rule-r15) — creatable after instrumentation | ≥ 5 invalid_callback per IP / 15 min | */5 | MEDIUM | test-first | AUTO-F; prevention in place (state + PKCE S256 + 10-min single-use transaction) |
| [G33](#threat-g33) | Authorization-code interception or replay | A07:2021 / CWE-294 | 🟡 PARTIAL | APP_EVENT | [R15](#rule-r15) — creatable after instrumentation | provider_verification failures per IP | */5 | MEDIUM | test-first | AUTO-F; PKCE + single-use transaction in place |
| [G34](#threat-g34) | Account-linking confusion (auto-link on email) | A07:2021 / CWE-287 | 🟡 PARTIAL | APP_EVENT | [R16](#rule-r16) — creatable after instrumentation | link refusals (R16) | */15 | LOW | test-first | notify; prevention in place (never links by email) |
| [G36](#threat-g36) | Open just-in-time provisioning through Google sign-in | A01:2021 / CWE-269 | 🟡 PARTIAL | APP_EVENT | [R23](#rule-r23) — creatable after instrumentation | ≥ 5 accounts created per IP / 60 min (Google-created accounts included) | */15 | LOW | test-first | AUTO-G for password registration; manual Google rate-limit |
| [G36a](#threat-g36a) | OIDC replay without nonce | A07:2021 / CWE-294 | 🟡 PARTIAL | APP_EVENT | [R15](#rule-r15) — creatable after instrumentation | nonce mismatch surfaces as provider_verification | */5 | MEDIUM | test-first | AUTO-F; nonce check in place |
| [G36b](#threat-g36b) | Identity keyed on a mutable claim (email instead of subject) | A07:2021 / CWE-290 | 🔴 GAP | APP_OR_PROVIDER_CONTROL | not currently creatable | no signal — keyed on Google `sub` | — | LOW | — | already in place (src/app.js:237) |
| [G36c](#threat-g36c) | Real users locked out across sign-in methods (password squat blocks Google) | A07:2021 / CWE-287 | 🟡 PARTIAL | APP_EVENT | [R16](#rule-r16) — creatable after instrumentation | ≥ 5 link refusals app-wide / 60 min | */15 | MEDIUM | test-first | notify; app reclaim flow (F4) |
| [G36e](#threat-g36e) | Google account disabled, but lab session continues | A07:2021 / CWE-613 | 🔴 GAP | PROVIDER_EVENT | not currently creatable | no provider feed — consumer Google accounts have no SCIM/deprovisioning signal for this app | — | LOW | — | 8-hour absolute session cap (in place); none further |
| [H38a](#threat-h38a) | Races in identity-state changes (duplicate registration, parallel guesses) | A04:2021 / CWE-362 | 🔴 GAP | APP_OR_PROVIDER_CONTROL | not currently creatable | no signal — prevented by unique indexes and an atomic counter | — | LOW | — | already in place (db/001_initial.sql:3,6; src/app.js:127-131,166,241-246) |
| [H39a](#threat-h39a) | Password change with a stolen session; no notification | A07:2021 / CWE-620 | 🟡 PARTIAL | APP_EVENT | [R21](#rule-r21), [R19](#rule-r19) — creatable after instrumentation | ≥ 3 wrong current-password attempts per account / 60 min (R21) | */15 | MEDIUM | test-first | notify → revoke session; app owner notification (F5) |
| [H40](#threat-h40) | Signup abuse / mass account creation | A04:2021 / CWE-799 | 🟡 PARTIAL | NATIVE_TRAFFIC | [R08](#rule-r08), [R23](#rule-r23) — creatable now — data after SDK load | ≥ 30 registrations app-wide / 60 min (R08); ≥ 5 created per IP / 60 min (R23) | */15 | MEDIUM | test-first | notify; manual global registration rate-limit 20 / h, 24 h; app verification (F4) and admin-list paging (F16) |
| [H40a](#threat-h40a) | Account pre-hijacking / email squatting | A07:2021 / CWE-287 | 🟡 PARTIAL | APP_EVENT | [R23](#rule-r23), [R16](#rule-r16) — creatable after instrumentation | accounts created per IP; link refusals | */15 | MEDIUM | test-first | AUTO-G; app F4 |
| [H40b](#threat-h40b) | Email canonicalization mismatch (Unicode, Gmail dots, plus-aliases) | A07:2021 / CWE-176 | 🔴 GAP | APP_OR_PROVIDER_CONTROL | not currently creatable | no signal | — | LOW | — | app fix with F4 (NFKC + verified address) |
| [H40c](#threat-h40c) | Dormant-account takeover followed by changes | A07:2021 / CWE-308 | 🟡 PARTIAL | APP_EVENT | [R22](#rule-r22), [R19](#rule-r19) — creatable after instrumentation | dormant sign-in; takeover sequence | */15 | LOW | test-first | notify |
| [H40d](#threat-h40d) | Signup overwriting or shadowing an existing account | A07:2021 / CWE-287 | 🔴 GAP | APP_OR_PROVIDER_CONTROL | not currently creatable | no signal — ON CONFLICT DO NOTHING + unique lowercase email | — | LOW | — | already in place (db/001_initial.sql:3; src/app.js:165-168) |
| [H40g](#threat-h40g) | Mass assignment of auth fields on signup | A01:2021 / CWE-915 | 🔴 GAP | APP_OR_PROVIDER_CONTROL | not currently creatable | no signal (request bodies are not captured, by design) | — | LOW | — | already in place: only name/email/password read; tested with role and emailVerified injection |
| [H41](#threat-h41) | Targeted lockout of a member through the per-account limit | A07:2021 / CWE-645 | 🟡 PARTIAL | APP_EVENT | [R14](#rule-r14), [R11](#rule-r11) — creatable after instrumentation | ≥ 3 per-account rejections from ≥ 2 IPs / 15 min (R14) | */5 | MEDIUM | test-first | notify; manual rate-limit/challenge of contributing IPs; app device-trust fix (F3) |
| [I45](#threat-i45) | Unauthenticated health endpoints reachable from outside | A01:2021 / CWE-306 | 🔴 GAP | APP_OR_PROVIDER_CONTROL | not currently creatable | no signal needed — /healthz and /readyz return only a status word | — | LOW | — | already in place; optional rate limit on /readyz |
| [I45a](#threat-i45a) | Spoofed forwarding headers or proxy bypass | A07:2021 / CWE-348 | 🟡 PARTIAL | NATIVE_TRAFFIC | [R09](#rule-r09) — creatable now — data after SDK load | any multi-hop X-Forwarded-For or untrusted direct socket | */5 | HIGH | prod-ready | notify (instant detection, no block) |
| [J46](#threat-j46) | Password-hashing CPU/memory amplification on sign-in routes | A04:2021 / CWE-405 | 🟡 PARTIAL | NATIVE_TRAFFIC | [R07](#rule-r07) — creatable now — data after SDK load | ≥ 200 hashing POSTs app-wide / 5 min or p95 ≥ 2 s (≥ 50 requests) | */5 | HIGH | test-first | notify; manual time-boxed global rate-limit on the hashing routes; app KDF concurrency bound (F9) |
| [J47](#threat-j47) | Session-store and audit-table growth from anonymous requests | A04:2021 / CWE-770 | 🟡 PARTIAL | NATIVE_TRAFFIC | [R03](#rule-r03), [R08](#rule-r08) — creatable now — data after SDK load | ≥ 60 cookieless session-endpoint GETs per IP / 15 min (R03) | */5 | MEDIUM | test-first | AUTO-C rate-limit the session endpoints 30 / 15 min / IP, 24 h; app fix F1 |
| [K49](#threat-k49) | Password-hash work factor below current guidance | A02:2021 / CWE-916 | 🔴 GAP | APP_OR_PROVIDER_CONTROL | not currently creatable | no signal | — | LOW | — | app fix F8 |
| [K50](#threat-k50) | Missing TLS/HSTS or cookies over plain HTTP | A02:2021 / CWE-319 | 🔴 GAP | EXTERNAL_MONITOR | not currently creatable | no in-band signal; an external check must watch certificate and headers | — | LOW | — | already in place (HTTP→308, HSTS 1 year, Secure cookie); external certificate/header monitor (AUTH-27) |
| [K51](#threat-k51) | Auth secrets committed to Git or baked into images | A05:2021 / CWE-798 | 🔴 GAP | APP_OR_PROVIDER_CONTROL | not currently creatable | no signal — Git history scanned clean in this run | — | LOW | — | already in place: CI secret scan, .gitignore/.dockerignore, Secrets Manager |
| [K52](#threat-k52) | Credentials or tokens captured in logs and traces | A09:2021 / CWE-532 | 🔴 GAP | APP_OR_PROVIDER_CONTROL | not currently creatable | no signal | — | LOW | — | config: capture off before first SDK start (F13) |
| [L53](#threat-l53) | Privilege escalation through client-controlled role claims | A01:2021 / CWE-269 | 🟡 PARTIAL | APP_EVENT | [R21](#rule-r21) — creatable after instrumentation | any privilege elevation | */15 | HIGH | test-first | notify → human review; role read from the database on every request (in place) |
| [L54](#threat-l54) | IDOR on account-management endpoints | A01:2021 / CWE-639 | 🔴 GAP | APP_OR_PROVIDER_CONTROL | not currently creatable | no signal | — | LOW | — | already in place: own sessions only; admin routes role-gated |
| [L54a](#threat-l54a) | No step-up re-authentication for admin role changes | A07:2021 / CWE-306 | 🟡 PARTIAL | APP_EVENT | [R21](#rule-r21), [R20](#rule-r20) — creatable after instrumentation | elevation; ≥ 3 accounts changed by one admin / 60 min | */15 | HIGH | test-first | notify → revoke admin session; app step-up (F5) |
| [M55](#threat-m55) | Auth requests traced but their events missing (coverage drift) | A09:2021 / CWE-778 | 🟡 PARTIAL | APP_EVENT | [R25](#rule-r25) — creatable after instrumentation | events < 50% of traced sign-in verdicts (≥ 10) / 30 min | */15 | LOW | test-first | notify; fix the bridge |
| [M56](#threat-m56) | Telemetry exporter or ingestion outage | A09:2021 / CWE-778 | 🔴 GAP | EXTERNAL_MONITOR | not currently creatable | needs an independent monitor — a dead pipeline cannot alert through itself | — | MEDIUM | — | external monitor (AUTH-27) |
| [M58](#threat-m58) | Google Cloud OAuth client or project compromise | A07:2021 / CWE-284 | 🔴 GAP | PROVIDER_EVENT | not currently creatable | Google Cloud audit logs are not ingested by SecureNow | — | MEDIUM | — | provider: Cloud Audit Logs alerting + secret rotation (AUTH-28) |
| [M60](#threat-m60) | Alert rule disabled, edited or never run; alerts only in-app | A09:2021 / CWE-778 | 🔴 GAP | EXTERNAL_MONITOR | not currently creatable | manifest diff of `alerts rules list --json` (external) | — | MEDIUM | — | add an out-of-band channel (AUTH-04); external manifest check (AUTH-27) |
| [M60a](#threat-m60a) | Detection-logic defects that look healthy | A09:2021 / CWE-778 | 🔴 GAP | EXTERNAL_MONITOR | not currently creatable | operator lint (this report) + coverage rule R25 | — | MEDIUM | — | lint before create; validate on the lab app; R25 |
| [M61](#threat-m61) | Forged or replayed security events; stolen runtime key | A08:2021 / CWE-345 | 🟡 PARTIAL | APP_EVENT | [R24](#rule-r24) — creatable after instrumentation | any duplicate request_id, missing auth_method, or future-dated event / 60 min | */15 | MEDIUM | test-first | notify; rotate the runtime key |
| [M62](#threat-m62) | Evasion via route aliases, IPv6 rotation or spoofed headers | A07:2021 / CWE-290 | 🟡 PARTIAL | NATIVE_TRAFFIC | [R06](#rule-r06), [R09](#rule-r09) — creatable now — data after SDK load | per-network grouping; forwarding-chain anomaly; every traffic rule lowercases and strips trailing slashes | */10 | MEDIUM | test-first | case-insensitive regex SecureNow scopes now; app strict + case-sensitive routing (F6) |
| [M63](#threat-m63) | Unsafe automated response (global blocks, challenges that break sign-in) | A04:2021 / CWE-693 | 🟡 PARTIAL | APP_OR_PROVIDER_CONTROL | not currently creatable | configuration review (not a detection) | — | HIGH | — | keep lab rules in test mode while recording; rule names avoid the account-wide trigger words; scope automations to app + env test; SPA challenge support (F15) |
| [S1](#threat-s1) | Audit-trail flushing: rejected requests bury real events | A09:2021 / CWE-779 | 🟡 PARTIAL | NATIVE_TRAFFIC | [R04](#rule-r04), [R02](#rule-r02) — creatable now — data after SDK load | ≥ 20 CSRF-rejected writes (R04) or ≥ 5 post-limit requests (R02) per IP / 15 min | */5 | MEDIUM | test-first | AUTO-D and AUTO-A rate limits; app fix F2 |
| [S2](#threat-s2) | No second factor or step-up anywhere | A07:2021 / CWE-308 | 🔴 GAP | APP_OR_PROVIDER_CONTROL | not currently creatable | no signal — compensating detections R12, R19, R21 | — | MEDIUM | — | app: passkeys/TOTP for admin and analyst first (F5) |

<a id="out-of-scope"></a>
### Out of scope — explicit N/A (50)

| # | Threat | Why N/A here |
| --- | --- | --- |
| A5b | Hosted identity-provider misconfiguration | Authentication is implemented in this app, not on Supabase/Firebase/Clerk/Auth0/Cognito. Google is only an OIDC provider; its console settings are listed as questions in the code report. |
| C16e | Cross-device approval logs in the wrong browser | No magic link, push approval or QR login exists. |
| D17 | alg=none / algorithm confusion | The app issues no JWTs (server-side sessions). The only JWT is Google’s ID token, verified by google-auth-library (src/app.js:233); protocol depth → ../07-oauth-sso-integrations/. |
| D20 | Refresh-token theft / rotation | No refresh tokens: Google is requested with access_type=online (src/app.js:218) and tokens are discarded after verification. |
| D21b | Token not bound to user + purpose + target | No reset, OTP, magic-link, verification, invite, remember-device or recovery tokens exist. The only single-use artifact (the Google transaction) is bound to the session, state, nonce and PKCE verifier (src/app.js:213, 227, 235). |
| D21c | JWT header trust (kid/jku/x5u/jwk) or decode() instead of verify() | The app never decodes a JWT itself; verifyIdToken is used (src/app.js:233). |
| E22 | Magic-link / OTP request flooding | No OTP, magic link, SMS or email sending exists (no mail/SMS dependency in package.json, no such routes). |
| E22a | One source → many send targets | No auth messages are sent. |
| E22b | Many sources → one send target (victim bombing) | No auth messages are sent. |
| E22c | SMS/voice traffic pumping | No SMS or voice. |
| E22d | Retry/resend/fallback amplification | No auth messages are sent. |
| E22e | Provider spend/quota exhaustion | No paid messaging provider. |
| E22f | Send-to-verification conversion collapse | No sends or verifications. |
| E23 | OTP / magic-link brute force | No OTP or magic links. |
| E24 | Link/OTP interception and reuse | No OTP or magic links. |
| E25 | Long-lived or reusable login tokens | No login tokens besides the session; see C15. |
| E25a | Multiple valid resend codes / redemption race | No codes or links. |
| E25b | Link scanners consuming single-use links | No emailed links. |
| F26 | MFA bypass routes | No MFA exists (the absence itself is modeled as S2). |
| F26a | MFA/verification enforced only by the client or flow order | No MFA or email-verification gate exists (absence modeled as S2 and F4). |
| F26b | OTP/reset/verification code returned in an API response | No such codes exist; publicUser() never returns password_hash (src/app.js:25-32). |
| F27 | Push fatigue / MFA prompt bombing | No push MFA. |
| F27a | OTP/MFA phishing relay | No OTP/MFA (password phishing relay is covered by C9). |
| F27b | Factor downgrade / channel-choice abuse | No factors. |
| F28 | Recovery-code brute force | No recovery codes. |
| F28a | TOTP replay / drift / unverified enrollment | No TOTP. |
| F29 | Post-takeover factor enrollment / MFA reset hijack | No factors. |
| F29a | Support-assisted recovery or MFA reset abuse | No support or recovery tooling in code; any manual database fix by an operator → ../08-admin-support-tools/. |
| F30 | SMS SIM-swap exposure | No SMS factor. |
| F30a | WebAuthn/passkey validation failures | No WebAuthn. |
| G35 | SAML signature wrapping / unsigned assertions | No SAML. |
| G36d | SSO enforcement bypass | No per-domain or per-tenant SSO enforcement exists. |
| G36f | Multi-tenant SSO domain confusion | Single tenant; one Google client; no per-tenant IdPs. |
| G36g | Domain-based auto-join | No organizations or auto-join. |
| G36h | Loopback CLI/desktop login | No CLI or desktop login flow. |
| H37 | Password-reset poisoning | No password reset; the only server-built URL (Google redirect) comes from APP_ORIGIN, not the Host header (src/app.js:40). |
| H37a | Recovery sent to the request-supplied address | No recovery or verification messages. |
| H38 | Reset-token brute force or predictable tokens | No reset tokens. |
| H39 | Email/phone change without re-auth | No email or phone change feature. |
| H40e | Invite links as credentials | No invitations. |
| H40f | Account deletion and identifier reuse | No account deletion; emails are never released. |
| I42 | API key leakage | The app has no API keys. (The future SecureNow runtime key is covered by M61; the Google client secret by K51.) |
| I43 | Over-privileged API keys | No API keys. |
| I44 | Invalid-key spray | No API keys. |
| I45b | Auth enforced only in middleware or client (Next.js CVE-2025-29927 class) | Express app, not Next.js; every protected route has its own server-side guard (src/app.js:194, 262, 277, 287, 291); client navigation hiding is cosmetic. |
| J48 | Email/SMS provider quota exhaustion | No messaging provider. |
| J48a | Voice/WhatsApp/push fallback storm | No messaging. |
| J48b | No global send spend ceiling | No paid sends. |
| M57 | Provider delivery/fraud callbacks stop or are forged | No provider webhooks reach this app. |
| M59 | Provider volume with no matching app attempt_id | No paid provider sends. |

<a id="deferred"></a>
### Deferred to sibling models (8)

| Owner model | Topic | Auth-visible symptom (no SQL authored here) |
| --- | --- | --- |
| deferred — see `../07-oauth-sso-integrations/` | OAuth/OIDC protocol depth (redirect_uri registration, PKCE, JWKS/kid handling, iss+sub linking, consent) | Auth-visible symptom here: callback failure reasons in R15 (invalid_callback, provider_verification) and link refusals in R16. |
| deferred — see `../08-admin-support-tools/` | Admin impersonation, break-glass accounts, support tooling | None exists in code. Auth-visible symptom: role changes and mass changes by one admin (R21). |
| deferred — see `../04-xss-csrf-cors/` | Cookie prefixes/scope, CORS on session endpoints, clickjacking | __Host- prefix, frame-ancestors none and X-Frame-Options are present. Auth-visible symptom: CSRF-rejected mutations (R04). |
| deferred — see `../02-authorization/` | Where authorization is enforced, role-field mass assignment, method override | requireRole on every privileged route. The app’s authorization.denied audit rows are not exported to SecureNow by this model. |
| deferred — see `../14-api-security/` | Web cache deception, generic parameter pollution | API responses are Cache-Control: no-store (src/app.js:66); duplicate query parameters fail the string checks in the Google callback. |
| deferred — see `../11-messaging-notifications/` | Email/SMS transport, sender spoofing, deliverability | No auth messages are sent today. Email verification (F4) and owner notifications (F5) will introduce them — re-run this model’s E-section then. |
| deferred — see `../26-secrets-and-api-key-hygiene/` | Secrets in URLs, key hygiene and rotation | Google state appears in the callback URL (single-use); runtime-key rotation is listed in M61; bootstrap admin secret in F12. |
| deferred — see `../12-rate-limits-and-abuse/` | CAPTCHA/challenge bypass, generic rate-limit evasion | Auth-visible symptoms: post-limit requests (R02) and per-network spread (R06). |

### Required detection set (§3b.1) → this report

| §3b.1 item | Where it is covered |
| --- | --- |
| 1 Auth-route burst per IP (cheap vs expensive) | [R01](#rule-r01), [R02](#rule-r02) (per IP), [R03](#rule-r03) (cheap session routes), [R07](#rule-r07) (expensive hashing routes, global) |
| 2 One source → many targets | No paid sends exist (N/A). The sign-in equivalent — one IP → many accounts — is [R10](#rule-r10) |
| 3 Many sources → one target | No paid sends (N/A). Many IPs → one account: [R11](#rule-r11) |
| 4 Destination pumping | N/A — no SMS/voice/email sends |
| 5 Spend/quota tripwire | N/A for spend. The two-stage global pattern is used for hashing load [R07](#rule-r07) and registrations [R08](#rule-r08) |
| 6 Send → verification conversion | N/A — no sends or verification |
| 7 Resend/retry/fallback amplification | N/A — no sends |
| 8 Quota/cool-down ceiling abuse | [R14](#rule-r14) (per account), [R02](#rule-r02) (per IP, by route) |
| 9 Credential attack both directions | [R01](#rule-r01)/[R10](#rule-r10) (one IP → many), [R11](#rule-r11) (many IPs → one), [R12](#rule-r12) (success after failures), [R13](#rule-r13) (one IP into many accounts) |
| 10 Token/session replay | [R17](#rule-r17) (concurrent incompatible sessions), [R15](#rule-r15) (Google callback replay); refresh/OTP N/A |
| 11 Multi-step ATO sequences | [R19](#rule-r19), [R20](#rule-r20), [R22](#rule-r22) (dormant → sign-in); reset/recovery N/A |
| 12 Post-auth security changes | [R21](#rule-r21) |
| 13 Recovery/support abuse | N/A — no recovery or support tooling (→ ../08-admin-support-tools/) |
| 14 Evasion & identity quality | [R06](#rule-r06), [R26](#rule-r26), [R09](#rule-r09); every traffic rule normalizes case and trailing slashes |
| 15 Provider control plane | 🔴 gap — no Google Cloud audit adapter ([M58](#threat-m58)) |
| 16 Detection coverage and health | [R25](#rule-r25); total outage = external monitor gap ([M56](#threat-m56)) |
| 17 Event/integration integrity | [R24](#rule-r24) |
| 18 Rule/control-plane drift | External monitor ([M60](#threat-m60), [AUTH-27](#todo-auth-27)); SQL lint: 0 existing lab rules |
| 19 Cross-method identity & SSO | [R16](#rule-r16) (link refusals); SSO enforcement/deprovisioning N/A; one-email-one-account is enforced by a unique index (code) |
| 20 Single-use token abuse | N/A — no reset/magic/OTP/verification/invite/refresh/recovery/CLI tokens; Google transaction replay → [R15](#rule-r15) |
| 21 Server-side gate refusals | N/A — no MFA or email-verification gate exists (code findings F4, F5) |
| 22 Recovery-flow request signatures | N/A — no reset/magic-link/verify routes; not Next.js (no x-middleware-subrequest); request bodies are not captured by design |
| 23 Sessions surviving a credential change | [R18](#rule-r18) |
| 24 Cross-device approval | N/A — no magic link/push/QR login |
| 25 Loopback/CLI login | N/A — no CLI login |


<a id="rules"></a>
## 7. Detection rules to create (27)

Every SQL below was saved to `threat/01-authentication/rules/` and passed a syntax/semantics dry-run (status complete, no error) on 2026-10-16 — see the appendix for how. Run all commands from the lab-auth repository root (the `event send` tests route through that project’s `.securenow` runtime credentials). `<Rnn_ID>` is the rule ID printed by its create command (the implementation plan captures it into `$Rnn`). Rule names deliberately avoid the words that trigger the account-wide auto-block automation (AUTH-03).

> **Validate before create.** `alerts rules validate` needs an existing rule that covers lab-auth to host the dry-run. No lab rule exists yet, so the first create (R01) validates itself — the CLI dry-runs every new rule on its first app and deletes it if the SQL fails. For every later rule, pass R01’s ID as the host.

<a id="rule-r01"></a>
### R01 · lab-auth: repeated failed sign-ins per IP

**🟡 PARTIAL · NATIVE_TRAFFIC · HIGH · `test-first`** · threats [A1](#threat-a1) · schedule `*/5 * * * *`, throttle 4 min

- **Fires on:** ≥ 10 HTTP 401 answers to POST /api/auth/login from one IP in 15 min.
- **Threshold source:** App limit: 15 sign-in POSTs per IP per 15 min (src/config.js:24, src/app.js:173). Alert at 10 failures = two-thirds of that ceiling, before the app’s own 429.
- **Needs (not yet in telemetry):** http.target, http.client_ip, response_status_code, http_method (automatic once the SDK preload runs).
- **Tag:** test-first: real people mistype passwords and offices share one IP; watch 3–7 days of real traffic before letting it rate-limit anyone.

```sql
-- rules/lab-auth-failed-signins-per-ip.sql
-- Traffic only: works as soon as the SDK preload runs (no app events needed).
-- Threshold source: the app's own limit of 15 POST /api/auth/login per IP per 15 min (src/config.js:24, src/app.js:173).
WITH
  coalesce(nullIf(attributes_string['http.client_ip'], ''), nullIf(attributes_string['net.peer.ip'], ''), nullIf(attributes_string['network.peer.address'], ''), nullIf(attributes_string['client.address'], ''), nullIf(attributes_string['net.sock.peer.addr'], '')) AS client_ip,
  replaceRegexpOne(lower(decodeURLComponent(splitByChar('?', attributes_string['http.target'])[1])), '/+$', '') AS route
SELECT
  client_ip AS ip,
  countIf(response_status_code = '401') AS failed_signins,
  countIf(response_status_code = '429') AS throttled_by_app,
  count() AS signin_posts
FROM signoz_traces.distributed_signoz_index_v3
WHERE `resource_string_service$$name` IN (__USER_APP_KEYS__)
  AND timestamp >= now64(9) - INTERVAL 15 MINUTE
  AND ts_bucket_start >= toUInt64(toUnixTimestamp(now() - INTERVAL 15 MINUTE)) - 1800
  AND kind = 2
  AND http_method = 'POST'
  AND route = '/api/auth/login'
GROUP BY ip
HAVING ip != '' AND failed_signins >= 10
```

```bash
# the SQL above is saved as threat/01-authentication/rules/lab-auth-failed-signins-per-ip.sql
# R01 is the first lab rule: no host rule exists yet, so its create step below is the validation.
npx securenow alerts rules validate <ANY_LAB_RULE_ID> --sql @threat/01-authentication/rules/lab-auth-failed-signins-per-ip.sql --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --json
```

```bash
npx securenow alerts rules create \
  --name "lab-auth: repeated failed sign-ins per IP" \
  --sql @threat/01-authentication/rules/lab-auth-failed-signins-per-ip.sql \
  --apps df7ab010-37ac-4732-88ac-a8ac23afe1a4 --severity high \
  --schedule "*/5 * * * *" --throttle-minutes 4 \
  --category authentication \
  --description "Threat model 01-authentication (A1); test-first" \
  --nlp "one IP with 10 or more failed password sign-ins (HTTP 401 on POST /api/auth/login) in 15 minutes"
# -> created Active in mode=test (detect-only); a failing SQL is rolled back automatically
# add --channel <in-app id>,<new channel id> after AUTH-04 (channels cannot be changed later from the CLI)
```

```bash
npx securenow alerts rules test <R01_ID> --mode dry_run --wait --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --json
# expect: "status": "complete" (resultCount 0 until real or synthetic data exists)
```

**Test:** On your local copy (http://localhost:3000, started with the SDK preload and runtime environment test), sign in 10 times with a wrong password for a fictional account from one machine, then dry-run. Expect resultCount ≥ 1 with your own IP. Stop before 15 attempts so the app’s own 429 does not hide the test.

**Response AUTO-A — lab-auth: rate-limit sign-in guessing** (created disabled; enable only after the rule is promoted): For 24 hours, the flagged IP may send at most 5 sign-in POSTs per 15 minutes (the app itself allows 15). Requests over the limit get HTTP 429 from the SDK before the app hashes anything.

```bash
npx securenow automation create --name "lab-auth: rate-limit sign-in guessing" \
  --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --env test \
  --conditions '[{"field":"alertName","operator":"in","value":["lab-auth: repeated failed sign-ins per IP","lab-auth: auth requests past the native limit per IP","lab-auth: failed sign-ins across multiple accounts per IP"]}]' \
  --actions '[{"type":"addToRateLimit","config":{"pathPattern":"^/[aA][pP][iI]/[aA][uU][tT][hH]/[lL][oO][gG][iI][nN]/*$","pathMatchMode":"regex","method":"POST","limit":5,"windowSeconds":900,"keyBy":"ip","ttlHours":24,"reason":"lab-auth sign-in guessing"}}]' \
  --status disabled
# reverse: npx securenow ratelimit list --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --env test   # find the rule id, then: npx securenow ratelimit remove <id> --reason "false positive"
```

**Response AUTO-B — lab-auth: block high-risk sign-in abuse on auth routes** (created disabled; enable only after the rule is promoted): Only when SecureNow’s investigation scores the IP 90 or higher: block that IP from POSTing to /api/auth/* for 24 hours. Page loads and other routes still work, so a shared office IP is not cut off from the site.

```bash
npx securenow automation create --name "lab-auth: block high-risk sign-in abuse on auth routes" \
  --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --env test \
  --conditions '[{"field":"alertName","operator":"in","value":["lab-auth: repeated failed sign-ins per IP","lab-auth: auth requests past the native limit per IP","lab-auth: failed sign-ins across multiple accounts per IP"]},{"field":"riskScore","operator":"gte","value":90}]' \
  --actions '[{"type":"addToBlocklist","config":{"pathPattern":"^/[aA][pP][iI]/[aA][uU][tT][hH](/|$)","pathMatchMode":"regex","method":"POST","ttlHours":24,"reason":"lab-auth high-risk sign-in abuse"}}]' \
  --logic AND \
  --status disabled
# reverse: npx securenow blocklist list --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --env test --status active   # then: npx securenow blocklist unblock <id> --reason "false positive"
```

```bash
# after 3-7 days of real traffic with no unexplained hits — a person decides:
npx securenow alerts rules promote <R01_ID>
# then enable its response(s):
npx securenow automation update <AUTO-A_ID> --status active
npx securenow automation update <AUTO-B_ID> --status active
```

<a id="rule-r02"></a>
### R02 · lab-auth: auth requests past the native limit per IP

**🟡 PARTIAL · NATIVE_TRAFFIC · MEDIUM · `test-first`** · threats [A1](#threat-a1), [S1](#threat-s1) · schedule `*/5 * * * *`, throttle 4 min

- **Fires on:** ≥ 5 HTTP 429 answers on /api/auth/* to one IP in 15 min.
- **Threshold source:** App limits in src/config.js:24-26 and the route limiters at src/app.js:157,173,194,210,222. A person stops after the first 429; 5 more is automation.
- **Needs (not yet in telemetry):** http.target, http.client_ip, response_status_code (automatic once the SDK preload runs).
- **Tag:** test-first: a buggy client retry loop looks the same as a script. Note: once AUTO-A rate-limits an IP, SecureNow’s own 429s also count here, so this rule keeps re-reporting that IP (harmless; throttle groups repeats).

```sql
-- rules/lab-auth-native-limit-429-per-ip.sql
-- Traffic only. An IP that keeps sending auth requests after the app answered 429 (its own PostgreSQL-backed limit).
-- Threshold source: native limits in src/config.js:24-26 and src/app.js:157,173,194,210,222 (5 post-limit requests = automation, not a person).
WITH
  coalesce(nullIf(attributes_string['http.client_ip'], ''), nullIf(attributes_string['net.peer.ip'], ''), nullIf(attributes_string['network.peer.address'], ''), nullIf(attributes_string['client.address'], ''), nullIf(attributes_string['net.sock.peer.addr'], '')) AS client_ip,
  replaceRegexpOne(lower(decodeURLComponent(splitByChar('?', attributes_string['http.target'])[1])), '/+$', '') AS route
SELECT
  client_ip AS ip,
  count() AS throttled_requests,
  countIf(route = '/api/auth/login') AS throttled_signins,
  countIf(route = '/api/auth/register') AS throttled_registrations,
  countIf(route = '/api/auth/password') AS throttled_password_changes,
  countIf(route LIKE '/api/auth/google%') AS throttled_google
FROM signoz_traces.distributed_signoz_index_v3
WHERE `resource_string_service$$name` IN (__USER_APP_KEYS__)
  AND timestamp >= now64(9) - INTERVAL 15 MINUTE
  AND ts_bucket_start >= toUInt64(toUnixTimestamp(now() - INTERVAL 15 MINUTE)) - 1800
  AND kind = 2
  AND response_status_code = '429'
  AND route LIKE '/api/auth/%'
GROUP BY ip
HAVING ip != '' AND throttled_requests >= 5
```

```bash
# the SQL above is saved as threat/01-authentication/rules/lab-auth-native-limit-429-per-ip.sql
npx securenow alerts rules validate <R01_ID> --sql @threat/01-authentication/rules/lab-auth-native-limit-429-per-ip.sql --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --json
```

```bash
npx securenow alerts rules create \
  --name "lab-auth: auth requests past the native limit per IP" \
  --sql @threat/01-authentication/rules/lab-auth-native-limit-429-per-ip.sql \
  --apps df7ab010-37ac-4732-88ac-a8ac23afe1a4 --severity medium \
  --schedule "*/5 * * * *" --throttle-minutes 4 \
  --category authentication \
  --description "Threat model 01-authentication (A1, S1); test-first" \
  --nlp "one IP that keeps calling /api/auth routes after the app answered 429 (5 or more throttled requests in 15 minutes)"
# -> created Active in mode=test (detect-only); a failing SQL is rolled back automatically
# add --channel <in-app id>,<new channel id> after AUTH-04 (channels cannot be changed later from the CLI)
```

```bash
npx securenow alerts rules test <R02_ID> --mode dry_run --wait --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --json
# expect: "status": "complete" (resultCount 0 until real or synthetic data exists)
```

**Test:** On your local copy (http://localhost:3000), send 20 wrong-password sign-ins (the app answers 429 from the 16th), then dry-run. Expect resultCount ≥ 1. Wait 15 minutes before signing in again.

**Response:** uses AUTO-A (created under [R01](#rule-r01)).

**Response:** uses AUTO-B (created under [R01](#rule-r01)).

```bash
# after 3-7 days of real traffic with no unexplained hits — a person decides:
npx securenow alerts rules promote <R02_ID>
# then enable its response(s):
npx securenow automation update <AUTO-A_ID> --status active
npx securenow automation update <AUTO-B_ID> --status active
```

<a id="rule-r03"></a>
### R03 · lab-auth: anonymous session minting per IP

**🟡 PARTIAL · NATIVE_TRAFFIC · MEDIUM · `test-first`** · threats [J47](#threat-j47) · schedule `*/5 * * * *`, throttle 4 min

- **Fires on:** ≥ 60 cookieless GETs to /api/me, /api/auth/session, /api/auth/csrf or /api/auth/google from one IP in 15 min.
- **Threshold source:** Baseline required — conservative start. A browser mints one session per visit; 60 in 15 minutes (4 per minute) is a script. Re-check with the baseline query after 7 days.
- **Needs (not yet in telemetry):** http.request.headers (Node tracer; the cookie value is redacted but the key stays), http.target, http.client_ip.
- **Tag:** test-first: uptime monitors and link-preview bots also call /api/me without cookies; add exclusions for yours before promoting.

```sql
-- rules/lab-auth-anonymous-session-minting-per-ip.sql
-- Traffic only (Node tracer records redacted request headers as http.request.headers; the cookie VALUE is redacted, the key stays).
-- Every cookieless GET to these routes makes the app write a new row to the PostgreSQL sessions table (src/app.js:151-155).
-- Threshold: baseline required - conservative start. A browser mints one session per visit; 60 in 15 min is scripted.
WITH
  coalesce(nullIf(attributes_string['http.client_ip'], ''), nullIf(attributes_string['net.peer.ip'], ''), nullIf(attributes_string['network.peer.address'], ''), nullIf(attributes_string['client.address'], ''), nullIf(attributes_string['net.sock.peer.addr'], '')) AS client_ip,
  replaceRegexpOne(lower(decodeURLComponent(splitByChar('?', attributes_string['http.target'])[1])), '/+$', '') AS route,
  attributes_string['http.request.headers'] AS headers_json
SELECT
  client_ip AS ip,
  countIf(headers_json != '' AND NOT JSONHas(headers_json, 'cookie')) AS cookieless_session_requests,
  count() AS session_endpoint_requests
FROM signoz_traces.distributed_signoz_index_v3
WHERE `resource_string_service$$name` IN (__USER_APP_KEYS__)
  AND timestamp >= now64(9) - INTERVAL 15 MINUTE
  AND ts_bucket_start >= toUInt64(toUnixTimestamp(now() - INTERVAL 15 MINUTE)) - 1800
  AND kind = 2
  AND http_method IN ('GET', 'HEAD')
  AND route IN ('/api/me', '/api/auth/session', '/api/auth/csrf', '/api/auth/google')
GROUP BY ip
HAVING ip != '' AND cookieless_session_requests >= 60
```

```bash
# the SQL above is saved as threat/01-authentication/rules/lab-auth-anonymous-session-minting-per-ip.sql
npx securenow alerts rules validate <R01_ID> --sql @threat/01-authentication/rules/lab-auth-anonymous-session-minting-per-ip.sql --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --json
```

```bash
npx securenow alerts rules create \
  --name "lab-auth: anonymous session minting per IP" \
  --sql @threat/01-authentication/rules/lab-auth-anonymous-session-minting-per-ip.sql \
  --apps df7ab010-37ac-4732-88ac-a8ac23afe1a4 --severity medium \
  --schedule "*/5 * * * *" --throttle-minutes 4 \
  --category authentication \
  --description "Threat model 01-authentication (J47); test-first" \
  --nlp "one IP creating 60 or more brand-new anonymous sessions in 15 minutes by calling the session endpoints without a cookie"
# -> created Active in mode=test (detect-only); a failing SQL is rolled back automatically
# add --channel <in-app id>,<new channel id> after AUTH-04 (channels cannot be changed later from the CLI)
```

```bash
npx securenow alerts rules test <R03_ID> --mode dry_run --wait --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --json
# expect: "status": "complete" (resultCount 0 until real or synthetic data exists)
```

**Test:** On your local copy: for i in $(seq 1 65); do curl -s -o /dev/null http://localhost:3000/api/me; done — then dry-run. Expect resultCount ≥ 1. Each call leaves a 30-minute session row; they expire on their own.

**Response AUTO-C — lab-auth: rate-limit anonymous session minting** (created disabled; enable only after the rule is promoted): For 24 hours, the flagged IP may call /api/me, /api/auth/session and /api/auth/csrf at most 30 times per 15 minutes; each call it can no longer make is a PostgreSQL row the app never writes. (/api/auth/google also mints sessions but is already limited to 30 per IP by the app and covered by AUTO-F.)

```bash
npx securenow automation create --name "lab-auth: rate-limit anonymous session minting" \
  --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --env test \
  --conditions '[{"field":"alertName","operator":"eq","value":"lab-auth: anonymous session minting per IP"}]' \
  --actions '[{"type":"addToRateLimit","config":{"pathPattern":"^/[aA][pP][iI]/([mM][eE]|[aA][uU][tT][hH]/([sS][eE][sS][sS][iI][oO][nN]|[cC][sS][rR][fF]))/*$","pathMatchMode":"regex","method":"GET","limit":30,"windowSeconds":900,"keyBy":"ip","ttlHours":24,"reason":"lab-auth session minting"}}]' \
  --status disabled
# reverse: npx securenow ratelimit list --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --env test   # then: npx securenow ratelimit remove <id> --reason "false positive"
```

```bash
# after 3-7 days of real traffic with no unexplained hits — a person decides:
npx securenow alerts rules promote <R03_ID>
# then enable its response(s):
npx securenow automation update <AUTO-C_ID> --status active
```

<a id="rule-r04"></a>
### R04 · lab-auth: CSRF-rejected API mutations per IP

**🟡 PARTIAL · NATIVE_TRAFFIC · MEDIUM · `test-first`** · threats [C13](#threat-c13), [S1](#threat-s1) · schedule `*/5 * * * *`, throttle 4 min

- **Fires on:** ≥ 20 HTTP 403 API mutations without X-CSRF-Token or with a foreign Origin from one IP in 15 min.
- **Threshold source:** Baseline required — conservative start. A real browser produces 0–2 after a stale tab; each rejection writes an audit row (src/app.js:104-106).
- **Needs (not yet in telemetry):** http.request.headers (origin, x-csrf-token keys), http.target, response_status_code.
- **Tag:** test-first: confirm a stale-tab user never reaches 20.

```sql
-- rules/lab-auth-csrf-rejected-mutations-per-ip.sql
-- Traffic only. 403 API mutations that arrived without the X-CSRF-Token header or with a foreign Origin.
-- Each one also writes a csrf.rejected row to PostgreSQL before any rate limit (src/app.js:104-106).
-- Threshold: baseline required - conservative start (a real browser produces 0-2 after a stale tab).
WITH
  coalesce(nullIf(attributes_string['http.client_ip'], ''), nullIf(attributes_string['net.peer.ip'], ''), nullIf(attributes_string['network.peer.address'], ''), nullIf(attributes_string['client.address'], ''), nullIf(attributes_string['net.sock.peer.addr'], '')) AS client_ip,
  replaceRegexpOne(lower(decodeURLComponent(splitByChar('?', attributes_string['http.target'])[1])), '/+$', '') AS route,
  attributes_string['http.request.headers'] AS headers_json
SELECT
  client_ip AS ip,
  countIf(headers_json != '' AND (NOT JSONHas(headers_json, 'x-csrf-token') OR JSONExtractString(headers_json, 'origin') != 'https://lab-auth.labs.securenow.ai')) AS unverifiable_mutations,
  count() AS rejected_mutations
FROM signoz_traces.distributed_signoz_index_v3
WHERE `resource_string_service$$name` IN (__USER_APP_KEYS__)
  AND timestamp >= now64(9) - INTERVAL 15 MINUTE
  AND ts_bucket_start >= toUInt64(toUnixTimestamp(now() - INTERVAL 15 MINUTE)) - 1800
  AND kind = 2
  AND http_method IN ('POST', 'PUT', 'PATCH', 'DELETE')
  AND response_status_code = '403'
  AND route LIKE '/api/%'
GROUP BY ip
HAVING ip != '' AND unverifiable_mutations >= 20
```

```bash
# the SQL above is saved as threat/01-authentication/rules/lab-auth-csrf-rejected-mutations-per-ip.sql
npx securenow alerts rules validate <R01_ID> --sql @threat/01-authentication/rules/lab-auth-csrf-rejected-mutations-per-ip.sql --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --json
```

```bash
npx securenow alerts rules create \
  --name "lab-auth: CSRF-rejected API mutations per IP" \
  --sql @threat/01-authentication/rules/lab-auth-csrf-rejected-mutations-per-ip.sql \
  --apps df7ab010-37ac-4732-88ac-a8ac23afe1a4 --severity medium \
  --schedule "*/5 * * * *" --throttle-minutes 4 \
  --category authentication \
  --description "Threat model 01-authentication (C13, S1); test-first" \
  --nlp "one IP sending 20 or more API writes that fail the CSRF check (no token or wrong Origin) in 15 minutes"
# -> created Active in mode=test (detect-only); a failing SQL is rolled back automatically
# add --channel <in-app id>,<new channel id> after AUTH-04 (channels cannot be changed later from the CLI)
```

```bash
npx securenow alerts rules test <R04_ID> --mode dry_run --wait --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --json
# expect: "status": "complete" (resultCount 0 until real or synthetic data exists)
```

**Test:** On your local copy: for i in $(seq 1 21); do curl -s -o /dev/null -X POST -H "content-type: application/json" -d "{}" http://localhost:3000/api/auth/logout; done — then dry-run. Expect resultCount ≥ 1.

**Response AUTO-D — lab-auth: rate-limit rejected API mutations** (created disabled; enable only after the rule is promoted): For 24 hours, the flagged IP may send at most 30 POSTs to /api/* per 15 minutes, which caps how many csrf.rejected audit rows it can force the app to write.

```bash
npx securenow automation create --name "lab-auth: rate-limit rejected API mutations" \
  --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --env test \
  --conditions '[{"field":"alertName","operator":"eq","value":"lab-auth: CSRF-rejected API mutations per IP"}]' \
  --actions '[{"type":"addToRateLimit","config":{"pathPattern":"^/[aA][pP][iI](/|$)","pathMatchMode":"regex","method":"POST","limit":30,"windowSeconds":900,"keyBy":"ip","ttlHours":24,"reason":"lab-auth rejected mutation burst"}}]' \
  --status disabled
# reverse: npx securenow ratelimit list --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --env test   # then: npx securenow ratelimit remove <id> --reason "false positive"
```

```bash
# after 3-7 days of real traffic with no unexplained hits — a person decides:
npx securenow alerts rules promote <R04_ID>
# then enable its response(s):
npx securenow automation update <AUTO-D_ID> --status active
```

<a id="rule-r05"></a>
### R05 · lab-auth: auth-surface probing per IP

**🟡 PARTIAL · NATIVE_TRAFFIC · MEDIUM · `test-first`** · threats [B8](#threat-b8) · schedule `*/5 * * * *`, throttle 4 min

- **Fires on:** ≥ 3 requests for credential files / VCS folders / common admin panels, or ≥ 30 404/403 answers, from one IP in 15 min.
- **Threshold source:** Baseline required — conservative start. Nothing on this site lives under /.env, /.git or /wp-admin, so 3 such requests is deliberate.
- **Needs (not yet in telemetry):** http.target, response_status_code, http.client_ip.
- **Tag:** test-first for the threshold rule; the single-request instant signature on dotfile paths is prod-ready after one clean week.

```sql
-- rules/lab-auth-auth-surface-probing-per-ip.sql
-- Traffic only. Forced browsing for credential files, VCS folders, and common admin/login panels.
-- The app answers these with 404 (src/app.js:300,303) or 403 for dotfiles (src/app.js:302).
-- Threshold: baseline required - conservative start (3 sensitive-path probes, or 30 not-found/denied responses, in 15 min).
WITH
  coalesce(nullIf(attributes_string['http.client_ip'], ''), nullIf(attributes_string['net.peer.ip'], ''), nullIf(attributes_string['network.peer.address'], ''), nullIf(attributes_string['client.address'], ''), nullIf(attributes_string['net.sock.peer.addr'], '')) AS client_ip,
  replaceRegexpOne(lower(decodeURLComponent(splitByChar('?', attributes_string['http.target'])[1])), '/+$', '') AS route
SELECT
  client_ip AS ip,
  countIf(match(route, '(^|/)\\.(env|git|aws|ssh|securenow|deployment|docker|npmrc)|/(wp-login\\.php|wp-admin|phpmyadmin|xmlrpc\\.php|server-status|actuator|vendor/phpunit|admin\\.php|login\\.php)|\\.(bak|sql|gz|zip|pem|key|tfstate)$')) AS sensitive_path_probes,
  countIf(response_status_code IN ('403', '404')) AS not_found_or_denied,
  count() AS requests
FROM signoz_traces.distributed_signoz_index_v3
WHERE `resource_string_service$$name` IN (__USER_APP_KEYS__)
  AND timestamp >= now64(9) - INTERVAL 15 MINUTE
  AND ts_bucket_start >= toUInt64(toUnixTimestamp(now() - INTERVAL 15 MINUTE)) - 1800
  AND kind = 2
GROUP BY ip
HAVING ip != '' AND (sensitive_path_probes >= 3 OR not_found_or_denied >= 30)
```

```bash
# the SQL above is saved as threat/01-authentication/rules/lab-auth-auth-surface-probing-per-ip.sql
npx securenow alerts rules validate <R01_ID> --sql @threat/01-authentication/rules/lab-auth-auth-surface-probing-per-ip.sql --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --json
```

```bash
npx securenow alerts rules create \
  --name "lab-auth: auth-surface probing per IP" \
  --sql @threat/01-authentication/rules/lab-auth-auth-surface-probing-per-ip.sql \
  --apps df7ab010-37ac-4732-88ac-a8ac23afe1a4 --severity medium \
  --schedule "*/5 * * * *" --throttle-minutes 4 \
  --category authentication \
  --description "Threat model 01-authentication (B8); test-first" \
  --nlp "one IP probing for credential files, git folders or admin panels (3 or more) or collecting 30 or more not-found answers in 15 minutes"
# -> created Active in mode=test (detect-only); a failing SQL is rolled back automatically
# add --channel <in-app id>,<new channel id> after AUTH-04 (channels cannot be changed later from the CLI)
```

```bash
npx securenow alerts rules test <R05_ID> --mode dry_run --wait --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --json
# expect: "status": "complete" (resultCount 0 until real or synthetic data exists)
```

**Test:** On your local copy: for p in /.env /.git/config /wp-login.php; do curl -s -o /dev/null http://localhost:3000$p; done — then dry-run. Expect resultCount ≥ 1.

**Response AUTO-E — lab-auth: challenge auth-surface scanners on page loads** (created disabled; enable only after the rule is promoted): For 24 hours, GET requests from the flagged IP must solve an invisible proof-of-work first. A browser solves it once on the next page load (the clearance cookie is bound to IP + user agent); a scanner script stalls. Scoped to GET because the sign-in form posts JSON and the SPA cannot complete a challenge yet (finding F15).

```bash
npx securenow automation create --name "lab-auth: challenge auth-surface scanners on page loads" \
  --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --env test \
  --conditions '[{"field":"alertName","operator":"eq","value":"lab-auth: auth-surface probing per IP"}]' \
  --actions '[{"type":"requireCaptcha","config":{"pathPattern":"/","pathMatchMode":"prefix","method":"GET","difficulty":16,"clearanceTtlSeconds":1800,"ttlHours":24,"reason":"lab-auth auth-surface scanning"}}]' \
  --status disabled
# reverse: npx securenow challenge list --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --env test   # then: npx securenow challenge remove <id> --reason "false positive"
```

**Instant detection (MCP only).** A single request for a credential file or VCS folder is never legitimate on this site, so it can be stopped on the first request instead of at the next 5-minute run. Call `securenow_alert_rule_get` for `<R05_ID>` first, then `securenow_alert_rule_instant_update` with:

```json
{
  "id": "<R05_ID>",
  "expectedRuleVersion": "<reviewState.reviewVersion from securenow_alert_rule_get>",
  "expectedCurrentInstantHash": "<instantHash from securenow_alert_rule_get>",
  "enabled": true,
  "source": "trace",
  "matchMode": "all",
  "executionMode": "hybrid",
  "conditions": [
    {
      "field": "path",
      "operator": "regex",
      "value": "(^|/)\\.(env|git|aws|ssh|securenow|deployment|npmrc)(/|$)"
    }
  ],
  "block": false,
  "blockTtlHours": 24,
  "dryRun": true,
  "fixtures": [
    {
      "kind": "attack",
      "label": "dotenv probe",
      "path": "/.env",
      "method": "GET",
      "expectMatch": true
    },
    {
      "kind": "attack",
      "label": "git config probe",
      "path": "/.git/config",
      "method": "GET",
      "expectMatch": true
    },
    {
      "kind": "benign",
      "label": "sign-in page",
      "path": "/",
      "method": "GET",
      "expectMatch": false
    },
    {
      "kind": "benign",
      "label": "session check",
      "path": "/api/me",
      "method": "GET",
      "expectMatch": false
    }
  ],
  "confirm": true,
  "reason": "lab-auth: instant detection of credential-file probes (dry run)"
}
```

After one clean test-mode week and `alerts rules promote <R05_ID>`, repeat the call with `"dryRun": false` and `"block": true, "blockTtlHours": 24`. Blocks are skipped while the rule is in test mode.

```bash
# after 3-7 days of real traffic with no unexplained hits — a person decides:
npx securenow alerts rules promote <R05_ID>
# then enable its response(s):
npx securenow automation update <AUTO-E_ID> --status active
```

<a id="rule-r06"></a>
### R06 · lab-auth: failed sign-ins spread across one network

**🟡 PARTIAL · NATIVE_TRAFFIC · HIGH · `test-first`** · threats [A2](#threat-a2), [A4a](#threat-a4a), [M62](#threat-m62) · schedule `*/10 * * * *`, throttle 9 min

- **Fires on:** ≥ 4 addresses and ≥ 15 failed sign-ins from one /24 (IPv4) or /64 (IPv6) in 30 min.
- **Threshold source:** Baseline required — conservative start. Sized so a rotating attacker who stays under the app’s 15-per-IP limit still adds up.
- **Needs (not yet in telemetry):** http.target, http.client_ip, response_status_code.
- **Tag:** test-first: a university or mobile carrier block can legitimately contain several failing users.

```sql
-- rules/lab-auth-failed-signins-per-network.sql
-- Traffic only. Failed sign-ins spread over many addresses of ONE network (/24 for IPv4, /64 for IPv6),
-- which stays under the app's per-IP limit (15 per IP per 15 min, src/config.js:24) by rotating addresses.
-- Threshold: baseline required - conservative start (4+ addresses, 15+ failures in 30 min). Returns the latest contributing IP.
WITH
  coalesce(nullIf(attributes_string['http.client_ip'], ''), nullIf(attributes_string['net.peer.ip'], ''), nullIf(attributes_string['network.peer.address'], ''), nullIf(attributes_string['client.address'], ''), nullIf(attributes_string['net.sock.peer.addr'], '')) AS client_ip,
  replaceRegexpOne(lower(decodeURLComponent(splitByChar('?', attributes_string['http.target'])[1])), '/+$', '') AS route
SELECT
  cutIPv6(IPv6StringToNumOrDefault(client_ip), 8, 1) AS network,
  uniqExact(client_ip) AS distinct_ips,
  count() AS failed_signins,
  argMax(client_ip, timestamp) AS ip
FROM signoz_traces.distributed_signoz_index_v3
WHERE `resource_string_service$$name` IN (__USER_APP_KEYS__)
  AND timestamp >= now64(9) - INTERVAL 30 MINUTE
  AND ts_bucket_start >= toUInt64(toUnixTimestamp(now() - INTERVAL 30 MINUTE)) - 1800
  AND kind = 2
  AND http_method = 'POST'
  AND route = '/api/auth/login'
  AND response_status_code = '401'
  AND client_ip != ''
GROUP BY network
HAVING ip != '' AND distinct_ips >= 4 AND failed_signins >= 15
```

```bash
# the SQL above is saved as threat/01-authentication/rules/lab-auth-failed-signins-per-network.sql
npx securenow alerts rules validate <R01_ID> --sql @threat/01-authentication/rules/lab-auth-failed-signins-per-network.sql --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --json
```

```bash
npx securenow alerts rules create \
  --name "lab-auth: failed sign-ins spread across one network" \
  --sql @threat/01-authentication/rules/lab-auth-failed-signins-per-network.sql \
  --apps df7ab010-37ac-4732-88ac-a8ac23afe1a4 --severity high \
  --schedule "*/10 * * * *" --throttle-minutes 9 \
  --category authentication \
  --description "Threat model 01-authentication (A2, A4a, M62); test-first" \
  --nlp "failed sign-ins spread over 4 or more addresses of one network block (/24 or /64), 15 or more failures in 30 minutes"
# -> created Active in mode=test (detect-only); a failing SQL is rolled back automatically
# add --channel <in-app id>,<new channel id> after AUTH-04 (channels cannot be changed later from the CLI)
```

```bash
npx securenow alerts rules test <R06_ID> --mode dry_run --wait --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --json
# expect: "status": "complete" (resultCount 0 until real or synthetic data exists)
```

**Test:** Traffic rule: validate with the create-time dry-run and `alerts rules test --mode dry_run` (expect status complete). Generating it for real needs several addresses in one /24 or /64 against your own isolated copy (for example IPv6 privacy addresses on one host).

**Response:** notify only — see the runbook in §12 for the human-approved action.

```bash
# after 3-7 days of real traffic with no unexplained hits — a person decides:
npx securenow alerts rules promote <R06_ID>
```

<a id="rule-r07"></a>
### R07 · lab-auth: sign-in hashing load spike (all IPs)

**🟡 PARTIAL · NATIVE_TRAFFIC · HIGH · `test-first`** · threats [J46](#threat-j46) · schedule `*/5 * * * *`, throttle 4 min

- **Fires on:** ≥ 200 POSTs to the password-hashing routes across all IPs in 5 min, or p95 latency ≥ 2 s with ≥ 50 requests; returns the top 5 contributing IPs.
- **Threshold source:** Baseline required — conservative start. Each request runs scrypt (32 MiB, src/passwords.js:5) on Node’s 4-thread pool; the lab normally sees a handful per hour.
- **Needs (not yet in telemetry):** http.target, duration_nano, http.client_ip.
- **Tag:** test-first and notify-only: a global anomaly never justifies auto-blocking every contributor.

```sql
-- rules/lab-auth-signin-load-spike-global.sql
-- Traffic only. Two-stage global rule: (1) prove the whole app crossed a volume or latency budget for the
-- password-hashing routes (scrypt N=32768, r=8: src/passwords.js:5), then (2) return the top contributing IPs.
-- Notify / manual containment only - never auto-block every contributor of a global anomaly.
-- Threshold: baseline required - conservative start (200 hashing POSTs in 5 min, or p95 >= 2 s with 50+ requests).
SELECT
  per_ip.ip AS ip,
  per_ip.hits AS hashing_posts_from_ip,
  g.total AS hashing_posts_all_ips_5m,
  g.p95_ms AS p95_latency_ms
FROM
(
  WITH
    coalesce(nullIf(attributes_string['http.client_ip'], ''), nullIf(attributes_string['net.peer.ip'], ''), nullIf(attributes_string['network.peer.address'], ''), nullIf(attributes_string['client.address'], ''), nullIf(attributes_string['net.sock.peer.addr'], '')) AS client_ip,
    replaceRegexpOne(lower(decodeURLComponent(splitByChar('?', attributes_string['http.target'])[1])), '/+$', '') AS route
  SELECT client_ip AS ip, count() AS hits
  FROM signoz_traces.distributed_signoz_index_v3
  WHERE `resource_string_service$$name` IN (__USER_APP_KEYS__)
    AND timestamp >= now64(9) - INTERVAL 5 MINUTE
    AND ts_bucket_start >= toUInt64(toUnixTimestamp(now() - INTERVAL 5 MINUTE)) - 1800
    AND kind = 2
    AND http_method = 'POST'
    AND route IN ('/api/auth/login', '/api/auth/register', '/api/auth/password')
  GROUP BY ip
  HAVING ip != ''
) AS per_ip
CROSS JOIN
(
  WITH
    replaceRegexpOne(lower(decodeURLComponent(splitByChar('?', attributes_string['http.target'])[1])), '/+$', '') AS route
  SELECT count() AS total, round(quantile(0.95)(duration_nano) / 1000000) AS p95_ms
  FROM signoz_traces.distributed_signoz_index_v3
  WHERE `resource_string_service$$name` IN (__USER_APP_KEYS__)
    AND timestamp >= now64(9) - INTERVAL 5 MINUTE
    AND ts_bucket_start >= toUInt64(toUnixTimestamp(now() - INTERVAL 5 MINUTE)) - 1800
    AND kind = 2
    AND http_method = 'POST'
    AND route IN ('/api/auth/login', '/api/auth/register', '/api/auth/password')
) AS g
WHERE g.total >= 200 OR (g.p95_ms >= 2000 AND g.total >= 50)
ORDER BY hashing_posts_from_ip DESC
LIMIT 5
```

```bash
# the SQL above is saved as threat/01-authentication/rules/lab-auth-signin-load-spike-global.sql
npx securenow alerts rules validate <R01_ID> --sql @threat/01-authentication/rules/lab-auth-signin-load-spike-global.sql --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --json
```

```bash
npx securenow alerts rules create \
  --name "lab-auth: sign-in hashing load spike (all IPs)" \
  --sql @threat/01-authentication/rules/lab-auth-signin-load-spike-global.sql \
  --apps df7ab010-37ac-4732-88ac-a8ac23afe1a4 --severity high \
  --schedule "*/5 * * * *" --throttle-minutes 4 \
  --category authentication \
  --description "Threat model 01-authentication (J46); test-first" \
  --nlp "app-wide spike of password-hashing requests (200+ in 5 minutes) or slow sign-ins (p95 2 seconds or more), listing the top contributing IPs"
# -> created Active in mode=test (detect-only); a failing SQL is rolled back automatically
# add --channel <in-app id>,<new channel id> after AUTH-04 (channels cannot be changed later from the CLI)
```

```bash
npx securenow alerts rules test <R07_ID> --mode dry_run --wait --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --json
# expect: "status": "complete" (resultCount 0 until real or synthetic data exists)
```

**Test:** Traffic rule: validate with the create-time dry-run and `alerts rules test --mode dry_run` (expect status complete). Do not load-test the public lab.

**Response:** notify only — see the runbook in §12 for the human-approved action.

```bash
# after 3-7 days of real traffic with no unexplained hits — a person decides:
npx securenow alerts rules promote <R07_ID>
```

<a id="rule-r08"></a>
### R08 · lab-auth: registration volume spike (all IPs)

**🟡 PARTIAL · NATIVE_TRAFFIC · MEDIUM · `test-first`** · threats [H40](#threat-h40), [J47](#threat-j47) · schedule `*/15 * * * *`, throttle 14 min

- **Fires on:** ≥ 30 accepted registrations (HTTP 201) across all IPs in 60 min; returns the top 10 contributing IPs.
- **Threshold source:** Baseline required — conservative start (the public lab sees a few sign-ups a day). The app allows 10 per IP per 15 min (src/config.js:25), so a rotating script stays under it.
- **Needs (not yet in telemetry):** http.target, response_status_code, http.client_ip.
- **Tag:** test-first and notify-only: a tutorial video going live can cause a real spike.

```sql
-- rules/lab-auth-registration-spike-global.sql
-- Traffic only. Two-stage global rule for mass account creation that rotates IPs to stay under the app's
-- 10 registrations per IP per 15 min (src/config.js:25, src/app.js:157). Returns the top contributing IPs.
-- Threshold: baseline required - conservative start (30 accepted registrations across all IPs in 60 min).
SELECT
  per_ip.ip AS ip,
  per_ip.registrations AS registrations_from_ip,
  g.total AS registrations_all_ips_60m
FROM
(
  WITH
    coalesce(nullIf(attributes_string['http.client_ip'], ''), nullIf(attributes_string['net.peer.ip'], ''), nullIf(attributes_string['network.peer.address'], ''), nullIf(attributes_string['client.address'], ''), nullIf(attributes_string['net.sock.peer.addr'], '')) AS client_ip,
    replaceRegexpOne(lower(decodeURLComponent(splitByChar('?', attributes_string['http.target'])[1])), '/+$', '') AS route
  SELECT client_ip AS ip, count() AS registrations
  FROM signoz_traces.distributed_signoz_index_v3
  WHERE `resource_string_service$$name` IN (__USER_APP_KEYS__)
    AND timestamp >= now64(9) - INTERVAL 60 MINUTE
    AND ts_bucket_start >= toUInt64(toUnixTimestamp(now() - INTERVAL 60 MINUTE)) - 1800
    AND kind = 2
    AND http_method = 'POST'
    AND route = '/api/auth/register'
    AND response_status_code = '201'
  GROUP BY ip
  HAVING ip != ''
) AS per_ip
CROSS JOIN
(
  WITH
    replaceRegexpOne(lower(decodeURLComponent(splitByChar('?', attributes_string['http.target'])[1])), '/+$', '') AS route
  SELECT count() AS total
  FROM signoz_traces.distributed_signoz_index_v3
  WHERE `resource_string_service$$name` IN (__USER_APP_KEYS__)
    AND timestamp >= now64(9) - INTERVAL 60 MINUTE
    AND ts_bucket_start >= toUInt64(toUnixTimestamp(now() - INTERVAL 60 MINUTE)) - 1800
    AND kind = 2
    AND http_method = 'POST'
    AND route = '/api/auth/register'
    AND response_status_code = '201'
) AS g
WHERE g.total >= 30
ORDER BY registrations_from_ip DESC
LIMIT 10
```

```bash
# the SQL above is saved as threat/01-authentication/rules/lab-auth-registration-spike-global.sql
npx securenow alerts rules validate <R01_ID> --sql @threat/01-authentication/rules/lab-auth-registration-spike-global.sql --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --json
```

```bash
npx securenow alerts rules create \
  --name "lab-auth: registration volume spike (all IPs)" \
  --sql @threat/01-authentication/rules/lab-auth-registration-spike-global.sql \
  --apps df7ab010-37ac-4732-88ac-a8ac23afe1a4 --severity medium \
  --schedule "*/15 * * * *" --throttle-minutes 14 \
  --category authentication \
  --description "Threat model 01-authentication (H40, J47); test-first" \
  --nlp "30 or more registrations across all IPs in one hour, listing the top contributing IPs"
# -> created Active in mode=test (detect-only); a failing SQL is rolled back automatically
# add --channel <in-app id>,<new channel id> after AUTH-04 (channels cannot be changed later from the CLI)
```

```bash
npx securenow alerts rules test <R08_ID> --mode dry_run --wait --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --json
# expect: "status": "complete" (resultCount 0 until real or synthetic data exists)
```

**Test:** Traffic rule: validate with the create-time dry-run and `alerts rules test --mode dry_run` (expect status complete). Do not mass-register on the public lab.

**Response:** notify only — see the runbook in §12 for the human-approved action.

```bash
# after 3-7 days of real traffic with no unexplained hits — a person decides:
npx securenow alerts rules promote <R08_ID>
```

<a id="rule-r09"></a>
### R09 · lab-auth: forwarded client-IP chain anomaly

**🟡 PARTIAL · NATIVE_TRAFFIC · HIGH · `prod-ready`** · threats [I45a](#threat-i45a), [M62](#threat-m62) · schedule `*/5 * * * *`, throttle 4 min

- **Fires on:** any request whose X-Forwarded-For has more than one hop, or whose client IP came from an untrusted public socket (Caddy bypassed).
- **Threshold source:** Exact signature — should be zero: Caddy overwrites X-Forwarded-For with the real peer (infra/Caddyfile:5) and the app port is not published (compose.production.yaml:21-38).
- **Needs (not yet in telemetry):** http.forwarded_for, http.client_ip.source, http.proxy.trusted (Node tracer).
- **Tag:** prod-ready after one clean week (single-request, high precision). Notify only: a hit usually means a proxy change, and blocking would hit every client.

```sql
-- rules/lab-auth-forwarded-ip-chain-anomaly.sql
-- Traffic only. Single-request identity-quality signature. In production, Caddy overwrites X-Forwarded-For with the
-- real peer (infra/Caddyfile:5) and the app trusts exactly one hop (compose.production.yaml:28, src/app.js:51).
-- So a multi-hop X-Forwarded-For, or a request whose client IP came from an untrusted public socket (Caddy bypassed),
-- should never happen. Any hit = proxy misconfiguration or spoofed client identity. Instant-detection candidate.
WITH
  coalesce(nullIf(attributes_string['http.client_ip'], ''), nullIf(attributes_string['net.peer.ip'], ''), nullIf(attributes_string['network.peer.address'], ''), nullIf(attributes_string['client.address'], ''), nullIf(attributes_string['net.sock.peer.addr'], '')) AS client_ip
SELECT
  client_ip AS ip,
  countIf(position(attributes_string['http.forwarded_for'], ',') > 0) AS multi_hop_forwarded_for,
  countIf(attributes_string['http.client_ip.source'] = 'socket' AND attributes_string['http.proxy.trusted'] = 'false') AS direct_untrusted_socket,
  count() AS requests
FROM signoz_traces.distributed_signoz_index_v3
WHERE `resource_string_service$$name` IN (__USER_APP_KEYS__)
  AND timestamp >= now64(9) - INTERVAL 15 MINUTE
  AND ts_bucket_start >= toUInt64(toUnixTimestamp(now() - INTERVAL 15 MINUTE)) - 1800
  AND kind = 2
GROUP BY ip
HAVING ip != '' AND (multi_hop_forwarded_for + direct_untrusted_socket) >= 1
```

```bash
# the SQL above is saved as threat/01-authentication/rules/lab-auth-forwarded-ip-chain-anomaly.sql
npx securenow alerts rules validate <R01_ID> --sql @threat/01-authentication/rules/lab-auth-forwarded-ip-chain-anomaly.sql --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --json
```

```bash
npx securenow alerts rules create \
  --name "lab-auth: forwarded client-IP chain anomaly" \
  --sql @threat/01-authentication/rules/lab-auth-forwarded-ip-chain-anomaly.sql \
  --apps df7ab010-37ac-4732-88ac-a8ac23afe1a4 --severity high \
  --schedule "*/5 * * * *" --throttle-minutes 4 \
  --category authentication \
  --description "Threat model 01-authentication (I45a, M62); prod-ready" \
  --nlp "any request where the client IP chain shows a spoofed or multi-hop X-Forwarded-For, or the request reached the app without the reverse proxy"
# -> created Active in mode=test (detect-only); a failing SQL is rolled back automatically
# add --channel <in-app id>,<new channel id> after AUTH-04 (channels cannot be changed later from the CLI)
```

```bash
npx securenow alerts rules test <R09_ID> --mode dry_run --wait --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --json
# expect: "status": "complete" (resultCount 0 until real or synthetic data exists)
```

**Test:** Traffic rule: create-time dry-run + `alerts rules test --mode dry_run` (status complete). On your local copy (no Caddy in front): curl -s -o /dev/null -H "X-Forwarded-For: 198.51.100.7, 203.0.113.9" http://localhost:3000/healthz — the SDK records a two-hop chain and the dry-run returns ip 203.0.113.9. In production it must stay at zero.

**Response:** notify only — see the runbook in §12 for the human-approved action.

**Instant detection (MCP only).** A multi-hop X-Forwarded-For can only reach the app if the proxy configuration changed; detect it on the first request. Notify only (no block): if Caddy is misconfigured, every client would match. Call `securenow_alert_rule_get` for `<R09_ID>` first, then `securenow_alert_rule_instant_update` with:

```json
{
  "id": "<R09_ID>",
  "expectedRuleVersion": "<reviewState.reviewVersion from securenow_alert_rule_get>",
  "expectedCurrentInstantHash": "<instantHash from securenow_alert_rule_get>",
  "enabled": true,
  "source": "trace",
  "matchMode": "all",
  "executionMode": "hybrid",
  "conditions": [
    {
      "field": "request_headers",
      "operator": "regex",
      "value": "\"x-forwarded-for\":\"[^\"]*,"
    }
  ],
  "block": false,
  "dryRun": true,
  "fixtures": [
    {
      "kind": "attack",
      "label": "two-hop forwarded-for",
      "path": "/api/auth/login",
      "method": "POST",
      "requestHeaders": {
        "x-forwarded-for": "198.51.100.7, 203.0.113.9"
      },
      "expectMatch": true
    },
    {
      "kind": "benign",
      "label": "Caddy single hop",
      "path": "/api/auth/login",
      "method": "POST",
      "requestHeaders": {
        "x-forwarded-for": "203.0.113.9"
      },
      "expectMatch": false
    }
  ],
  "confirm": true,
  "reason": "lab-auth: instant detection of forwarded-IP chain anomalies (dry run, notify only)"
}
```

Keep `"block": false`. Confirm with the dry-run fixtures that the regex matches the header JSON format your instance stores; adjust if the fixture result differs.

```bash
# after one clean test-mode week — a person decides:
npx securenow alerts rules promote <R09_ID>
```

<a id="rule-r10"></a>
### R10 · lab-auth: failed sign-ins across multiple accounts per IP

**🟡 PARTIAL · APP_EVENT · HIGH · `test-first`** · threats [A1](#threat-a1), [A3](#threat-a3), [A4](#threat-a4), [B7](#threat-b7) · schedule `*/5 * * * *`, throttle 4 min

- **Fires on:** ≥ 10 password failures over ≥ 5 different accounts from one IP in 15 min.
- **Threshold source:** App limit: 15 sign-in POSTs per IP per 15 min (src/config.js:24). Five distinct accounts rules out one person mistyping.
- **Needs (not yet in telemetry):** event auth.login.failure with auth_method and account_ref (proposed instrumentation, src/app.js:181).
- **Tag:** test-first: a shared classroom IP during the tutorial can trip it.

```sql
-- rules/lab-auth-failed-signins-multiple-accounts-per-ip.sql
-- APP_EVENT: needs the proposed auth.login.failure export with account_ref (keyed HMAC of the normalized email).
-- One IP failing against several different accounts = reused-password lists or password spraying.
-- Threshold source: native limit 15 sign-in POSTs per IP per 15 min (src/config.js:24) -> alert at 10 failures over 5+ accounts.
SELECT
  attributes_string['http.client_ip'] AS ip,
  count() AS failed_signins,
  uniqExact(attributes_string['account_ref']) AS distinct_accounts
FROM signoz_logs.distributed_logs_v2
WHERE resources_string['service.name'] IN (__USER_APP_KEYS__)
  AND timestamp >= toUnixTimestamp64Nano(now64() - INTERVAL 15 MINUTE)
  AND attributes_string['event.type'] = 'auth.login.failure'
  AND attributes_string['auth_method'] = 'password'
GROUP BY ip
HAVING ip != '' AND failed_signins >= 10 AND distinct_accounts >= 5
```

```bash
# the SQL above is saved as threat/01-authentication/rules/lab-auth-failed-signins-multiple-accounts-per-ip.sql
npx securenow alerts rules validate <R01_ID> --sql @threat/01-authentication/rules/lab-auth-failed-signins-multiple-accounts-per-ip.sql --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --json
```

```bash
npx securenow alerts rules create \
  --name "lab-auth: failed sign-ins across multiple accounts per IP" \
  --sql @threat/01-authentication/rules/lab-auth-failed-signins-multiple-accounts-per-ip.sql \
  --apps df7ab010-37ac-4732-88ac-a8ac23afe1a4 --severity high \
  --schedule "*/5 * * * *" --throttle-minutes 4 \
  --category authentication \
  --description "Threat model 01-authentication (A1, A3, A4, B7); test-first" \
  --nlp "one IP failing password sign-in against 5 or more different accounts (10 or more failures) in 15 minutes"
# -> created Active in mode=test (detect-only); a failing SQL is rolled back automatically
# add --channel <in-app id>,<new channel id> after AUTH-04 (channels cannot be changed later from the CLI)
```

```bash
npx securenow alerts rules test <R10_ID> --mode dry_run --wait --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --json
# expect: "status": "complete" (resultCount 0 until real or synthetic data exists)
```

```bash
# synthetic test — run from the lab-auth root after `npx securenow app connect` (TEST-NET IPs only; every event carries test=true)
for i in $(seq 1 11); do npx securenow event send auth.login.failure --env test --ip 203.0.113.10 --attrs auth_method=password,provider=local,reason=bad_password,account_ref=test-acct-$((i % 6)),test=true; done
# wait ~45 s for ingest, then re-run the dry-run above -> expect resultCount ≥ 1 for ip 203.0.113.10 (11 failures, 6 accounts)
```

**Response:** uses AUTO-A (created under [R01](#rule-r01)).

**Response:** uses AUTO-B (created under [R01](#rule-r01)).

```bash
# after 3-7 days of real traffic with no unexplained hits — a person decides:
npx securenow alerts rules promote <R10_ID>
# then enable its response(s):
npx securenow automation update <AUTO-A_ID> --status active
npx securenow automation update <AUTO-B_ID> --status active
```

<a id="rule-r11"></a>
### R11 · lab-auth: one account targeted from multiple IPs

**🟡 PARTIAL · APP_EVENT · HIGH · `test-first`** · threats [A2](#threat-a2), [H41](#threat-h41) · schedule `*/10 * * * *`, throttle 9 min

- **Fires on:** ≥ 12 password failures from ≥ 5 IPs against one account_ref in 30 min (returns the latest IP).
- **Threshold source:** App per-account limit: 30 per 15 min (src/app.js:173). 12 from 5 IPs is well below it — this is the early warning.
- **Needs (not yet in telemetry):** event auth.login.failure with account_ref (proposed instrumentation, src/app.js:181).
- **Tag:** test-first. Never respond by blocking the victim account — challenge or rate-limit the contributing IPs and fix F3.

```sql
-- rules/lab-auth-one-account-multiple-ips.sql
-- APP_EVENT: needs auth.login.failure with account_ref. Many IPs failing against ONE account (distributed guessing,
-- or an attacker deliberately filling the per-account bucket to lock the owner out).
-- Threshold source: native per-account limit 30 per 15 min (src/app.js:173) -> alert at 12 failures from 5+ IPs in 30 min.
-- Returns the latest contributing IP; the victim account is never the thing to block.
SELECT
  attributes_string['account_ref'] AS account_ref,
  uniqExact(attributes_string['http.client_ip']) AS distinct_ips,
  count() AS failed_signins,
  argMax(attributes_string['http.client_ip'], timestamp) AS ip
FROM signoz_logs.distributed_logs_v2
WHERE resources_string['service.name'] IN (__USER_APP_KEYS__)
  AND timestamp >= toUnixTimestamp64Nano(now64() - INTERVAL 30 MINUTE)
  AND attributes_string['event.type'] = 'auth.login.failure'
  AND attributes_string['auth_method'] = 'password'
GROUP BY account_ref
HAVING account_ref != '' AND ip != '' AND distinct_ips >= 5 AND failed_signins >= 12
```

```bash
# the SQL above is saved as threat/01-authentication/rules/lab-auth-one-account-multiple-ips.sql
npx securenow alerts rules validate <R01_ID> --sql @threat/01-authentication/rules/lab-auth-one-account-multiple-ips.sql --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --json
```

```bash
npx securenow alerts rules create \
  --name "lab-auth: one account targeted from multiple IPs" \
  --sql @threat/01-authentication/rules/lab-auth-one-account-multiple-ips.sql \
  --apps df7ab010-37ac-4732-88ac-a8ac23afe1a4 --severity high \
  --schedule "*/10 * * * *" --throttle-minutes 9 \
  --category authentication \
  --description "Threat model 01-authentication (A2, H41); test-first" \
  --nlp "one account receiving 12 or more failed sign-ins from 5 or more different IPs in 30 minutes"
# -> created Active in mode=test (detect-only); a failing SQL is rolled back automatically
# add --channel <in-app id>,<new channel id> after AUTH-04 (channels cannot be changed later from the CLI)
```

```bash
npx securenow alerts rules test <R11_ID> --mode dry_run --wait --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --json
# expect: "status": "complete" (resultCount 0 until real or synthetic data exists)
```

```bash
# synthetic test — run from the lab-auth root after `npx securenow app connect` (TEST-NET IPs only; every event carries test=true)
for i in $(seq 1 13); do npx securenow event send auth.login.failure --env test --ip 198.51.100.$(( (i % 6) + 1 )) --attrs auth_method=password,provider=local,reason=bad_password,account_ref=test-victim,test=true; done
# wait ~45 s for ingest, then re-run the dry-run above -> expect resultCount ≥ 1 for account_ref test-victim (13 failures, 6 IPs)
```

**Response:** notify only — see the runbook in §12 for the human-approved action.

```bash
# after 3-7 days of real traffic with no unexplained hits — a person decides:
npx securenow alerts rules promote <R11_ID>
```

<a id="rule-r12"></a>
### R12 · lab-auth: successful sign-in after repeated failures

**🟡 PARTIAL · APP_EVENT · HIGH · `test-first`** · threats [C16a](#threat-c16a) · schedule `*/10 * * * *`, throttle 9 min

- **Fires on:** ≥ 5 failures then a success for one account_ref within 30 min (returns the IP that succeeded).
- **Threshold source:** Baseline required — conservative start (five misses then a hit is rare for a real owner).
- **Needs (not yet in telemetry):** events auth.login.failure + auth.login.success with account_ref (src/app.js:181, 185, 254).
- **Tag:** test-first: forgetful owners do this too — always human review before any account action.

```sql
-- rules/lab-auth-signin-after-failures.sql
-- APP_EVENT: needs auth.login.failure + auth.login.success, both carrying account_ref.
-- Ordered sequence per account: at least 5 failures, then a success, within 30 minutes = probable guessed password.
-- Threshold: baseline required - conservative start. Returns the IP that SUCCEEDED (the one to contain).
SELECT
  attributes_string['account_ref'] AS account_ref,
  countIf(attributes_string['event.type'] = 'auth.login.failure') AS failures,
  uniqExactIf(attributes_string['http.client_ip'], attributes_string['event.type'] = 'auth.login.failure') AS failure_ips,
  sequenceMatch('(?1).*(?1).*(?1).*(?1).*(?1).*(?2)')(
    timestamp,
    attributes_string['event.type'] = 'auth.login.failure',
    attributes_string['event.type'] = 'auth.login.success') AS failures_then_success,
  argMaxIf(attributes_string['http.client_ip'], timestamp, attributes_string['event.type'] = 'auth.login.success') AS ip
FROM signoz_logs.distributed_logs_v2
WHERE resources_string['service.name'] IN (__USER_APP_KEYS__)
  AND timestamp >= toUnixTimestamp64Nano(now64() - INTERVAL 30 MINUTE)
  AND attributes_string['event.type'] IN ('auth.login.failure', 'auth.login.success')
GROUP BY account_ref
HAVING account_ref != '' AND ip != '' AND failures_then_success = 1
```

```bash
# the SQL above is saved as threat/01-authentication/rules/lab-auth-signin-after-failures.sql
npx securenow alerts rules validate <R01_ID> --sql @threat/01-authentication/rules/lab-auth-signin-after-failures.sql --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --json
```

```bash
npx securenow alerts rules create \
  --name "lab-auth: successful sign-in after repeated failures" \
  --sql @threat/01-authentication/rules/lab-auth-signin-after-failures.sql \
  --apps df7ab010-37ac-4732-88ac-a8ac23afe1a4 --severity high \
  --schedule "*/10 * * * *" --throttle-minutes 9 \
  --category authentication \
  --description "Threat model 01-authentication (C16a); test-first" \
  --nlp "an account that signs in successfully right after 5 or more failed attempts within 30 minutes"
# -> created Active in mode=test (detect-only); a failing SQL is rolled back automatically
# add --channel <in-app id>,<new channel id> after AUTH-04 (channels cannot be changed later from the CLI)
```

```bash
npx securenow alerts rules test <R12_ID> --mode dry_run --wait --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --json
# expect: "status": "complete" (resultCount 0 until real or synthetic data exists)
```

```bash
# synthetic test — run from the lab-auth root after `npx securenow app connect` (TEST-NET IPs only; every event carries test=true)
for i in $(seq 1 5); do npx securenow event send auth.login.failure --env test --ip 203.0.113.20 --attrs auth_method=password,provider=local,reason=bad_password,account_ref=test-acct-seq,test=true; done
npx securenow event send auth.login.success --env test --user test-user-seq --session test-sess-seq --ip 203.0.113.21 --attrs auth_method=password,provider=local,account_ref=test-acct-seq,mfa_state=none,test=true
# wait ~45 s for ingest, then re-run the dry-run above -> expect resultCount ≥ 1 for account_ref test-acct-seq with ip 203.0.113.21
```

**Response:** notify only — see the runbook in §12 for the human-approved action.

```bash
# after 3-7 days of real traffic with no unexplained hits — a person decides:
npx securenow alerts rules promote <R12_ID>
```

<a id="rule-r13"></a>
### R13 · lab-auth: one IP signs in to multiple accounts

**🟡 PARTIAL · APP_EVENT · MEDIUM · `test-first`** · threats [A3](#threat-a3), [C16a](#threat-c16a) · schedule `*/15 * * * *`, throttle 14 min

- **Fires on:** ≥ 3 different accounts successfully signed in from one IP in 60 min.
- **Threshold source:** Baseline required — conservative start. The tutorial presenter switching between member/analyst/admin test accounts will trip it: that is expected in test mode.
- **Needs (not yet in telemetry):** event auth.login.success with userId (src/app.js:185, 254).
- **Tag:** test-first and notify-only: shared NAT and demo machines are normal here.

```sql
-- rules/lab-auth-one-ip-signs-into-multiple-accounts.sql
-- APP_EVENT: needs auth.login.success with userId. One IP successfully entering several different accounts =
-- working a list of valid credentials, or account farming. Shared NAT / office egress can trip it: notify only.
-- Threshold: baseline required - conservative start (3 distinct accounts in 60 min).
SELECT
  attributes_string['http.client_ip'] AS ip,
  uniqExact(attributes_string['enduser.id']) AS accounts_signed_in,
  count() AS successful_signins
FROM signoz_logs.distributed_logs_v2
WHERE resources_string['service.name'] IN (__USER_APP_KEYS__)
  AND timestamp >= toUnixTimestamp64Nano(now64() - INTERVAL 60 MINUTE)
  AND attributes_string['event.type'] = 'auth.login.success'
GROUP BY ip
HAVING ip != '' AND accounts_signed_in >= 3
```

```bash
# the SQL above is saved as threat/01-authentication/rules/lab-auth-one-ip-signs-into-multiple-accounts.sql
npx securenow alerts rules validate <R01_ID> --sql @threat/01-authentication/rules/lab-auth-one-ip-signs-into-multiple-accounts.sql --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --json
```

```bash
npx securenow alerts rules create \
  --name "lab-auth: one IP signs in to multiple accounts" \
  --sql @threat/01-authentication/rules/lab-auth-one-ip-signs-into-multiple-accounts.sql \
  --apps df7ab010-37ac-4732-88ac-a8ac23afe1a4 --severity medium \
  --schedule "*/15 * * * *" --throttle-minutes 14 \
  --category authentication \
  --description "Threat model 01-authentication (A3, C16a); test-first" \
  --nlp "one IP that successfully signs in to 3 or more different accounts within an hour"
# -> created Active in mode=test (detect-only); a failing SQL is rolled back automatically
# add --channel <in-app id>,<new channel id> after AUTH-04 (channels cannot be changed later from the CLI)
```

```bash
npx securenow alerts rules test <R13_ID> --mode dry_run --wait --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --json
# expect: "status": "complete" (resultCount 0 until real or synthetic data exists)
```

```bash
# synthetic test — run from the lab-auth root after `npx securenow app connect` (TEST-NET IPs only; every event carries test=true)
for i in 1 2 3; do npx securenow event send auth.login.success --env test --user test-user-$i --session test-s-$i --ip 203.0.113.30 --attrs auth_method=password,provider=local,account_ref=test-acct-$i,mfa_state=none,test=true; done
# wait ~45 s for ingest, then re-run the dry-run above -> expect resultCount ≥ 1 for ip 203.0.113.30
```

**Response:** notify only — see the runbook in §12 for the human-approved action.

```bash
# after 3-7 days of real traffic with no unexplained hits — a person decides:
npx securenow alerts rules promote <R13_ID>
```

<a id="rule-r14"></a>
### R14 · lab-auth: per-account sign-in limit held full

**🟡 PARTIAL · APP_EVENT · MEDIUM · `test-first`** · threats [H41](#threat-h41) · schedule `*/5 * * * *`, throttle 4 min

- **Fires on:** ≥ 3 per-account limit rejections from ≥ 2 IPs for one account_ref in 15 min (returns the latest IP).
- **Threshold source:** App per-account limit: 30 per 15 min (src/app.js:173). Two or more IPs filling one account’s bucket = deliberate lockout.
- **Needs (not yet in telemetry):** event api.ratelimit.exceeded with scope and account_ref (proposed instrumentation, src/app.js:133).
- **Tag:** test-first. The response is to throttle the contributing IPs and fix F3 — never to lock the account harder.

```sql
-- rules/lab-auth-account-limit-pressure.sql
-- APP_EVENT: needs api.ratelimit.exceeded (exported from the app's limit() helper, src/app.js:132-136) with
-- scope=login-account and account_ref. Two or more IPs keeping ONE account's sign-in bucket full = the owner is
-- being locked out on purpose (the per-account bucket counts the owner's correct attempts too).
-- Threshold source: native per-account limit 30 per 15 min (src/app.js:173); 3 rejections from 2+ IPs in 15 min.
SELECT
  attributes_string['account_ref'] AS account_ref,
  count() AS account_bucket_rejections,
  uniqExact(attributes_string['http.client_ip']) AS distinct_ips,
  argMax(attributes_string['http.client_ip'], timestamp) AS ip
FROM signoz_logs.distributed_logs_v2
WHERE resources_string['service.name'] IN (__USER_APP_KEYS__)
  AND timestamp >= toUnixTimestamp64Nano(now64() - INTERVAL 15 MINUTE)
  AND attributes_string['event.type'] = 'api.ratelimit.exceeded'
  AND attributes_string['scope'] = 'login-account'
GROUP BY account_ref
HAVING account_ref != '' AND ip != '' AND account_bucket_rejections >= 3 AND distinct_ips >= 2
```

```bash
# the SQL above is saved as threat/01-authentication/rules/lab-auth-account-limit-pressure.sql
npx securenow alerts rules validate <R01_ID> --sql @threat/01-authentication/rules/lab-auth-account-limit-pressure.sql --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --json
```

```bash
npx securenow alerts rules create \
  --name "lab-auth: per-account sign-in limit held full" \
  --sql @threat/01-authentication/rules/lab-auth-account-limit-pressure.sql \
  --apps df7ab010-37ac-4732-88ac-a8ac23afe1a4 --severity medium \
  --schedule "*/5 * * * *" --throttle-minutes 4 \
  --category authentication \
  --description "Threat model 01-authentication (H41); test-first" \
  --nlp "one account kept at its sign-in rate limit by requests from 2 or more IPs in 15 minutes (someone locking the owner out)"
# -> created Active in mode=test (detect-only); a failing SQL is rolled back automatically
# add --channel <in-app id>,<new channel id> after AUTH-04 (channels cannot be changed later from the CLI)
```

```bash
npx securenow alerts rules test <R14_ID> --mode dry_run --wait --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --json
# expect: "status": "complete" (resultCount 0 until real or synthetic data exists)
```

```bash
# synthetic test — run from the lab-auth root after `npx securenow app connect` (TEST-NET IPs only; every event carries test=true)
for ip in 203.0.113.40 203.0.113.41 203.0.113.40; do npx securenow event send api.ratelimit.exceeded --env test --ip $ip --attrs scope=login-account,route=/api/auth/login,reason=fixed_window,account_ref=test-victim,test=true; done
# wait ~45 s for ingest, then re-run the dry-run above -> expect resultCount ≥ 1 for account_ref test-victim (3 rejections, 2 IPs)
```

**Response:** notify only — see the runbook in §12 for the human-approved action.

```bash
# after 3-7 days of real traffic with no unexplained hits — a person decides:
npx securenow alerts rules promote <R14_ID>
```

<a id="rule-r15"></a>
### R15 · lab-auth: Google sign-in callback failures per IP

**🟡 PARTIAL · APP_EVENT · MEDIUM · `test-first`** · threats [D19](#threat-d19), [G32](#threat-g32), [G33](#threat-g33), [G36a](#threat-g36a) · schedule `*/5 * * * *`, throttle 4 min

- **Fires on:** ≥ 5 Google callback failures (invalid/expired/replayed state, or Google-token verification failure) from one IP in 15 min.
- **Threshold source:** App limit: 30 callbacks per IP per 15 min (src/app.js:222). A real user fails once (stale tab) and retries.
- **Needs (not yet in telemetry):** event auth.login.failure with auth_method=oauth, provider=google, reason (src/app.js:228, 257).
- **Tag:** test-first: stale tabs and cookie-blocking browsers produce occasional invalid_callback.

```sql
-- rules/lab-auth-google-callback-failures-per-ip.sql
-- APP_EVENT: needs auth.login.failure with auth_method=oauth, provider=google and reason, exported where the app
-- records auth.google_failed (src/app.js:228, 257). Repeated invalid/expired/replayed callbacks or rejected Google
-- tokens from one IP = callback replay, forged state, or code-injection attempts. Protocol depth: ../07-oauth-sso-integrations/.
-- Threshold source: native limit 30 callbacks per IP per 15 min (src/app.js:222) -> alert at 5 failures.
SELECT
  attributes_string['http.client_ip'] AS ip,
  count() AS failed_callbacks,
  countIf(attributes_string['reason'] = 'invalid_callback') AS invalid_or_replayed_state,
  countIf(attributes_string['reason'] = 'provider_verification') AS provider_rejections
FROM signoz_logs.distributed_logs_v2
WHERE resources_string['service.name'] IN (__USER_APP_KEYS__)
  AND timestamp >= toUnixTimestamp64Nano(now64() - INTERVAL 15 MINUTE)
  AND attributes_string['event.type'] = 'auth.login.failure'
  AND attributes_string['auth_method'] = 'oauth'
  AND attributes_string['provider'] = 'google'
  AND attributes_string['reason'] IN ('invalid_callback', 'provider_verification')
GROUP BY ip
HAVING ip != '' AND failed_callbacks >= 5
```

```bash
# the SQL above is saved as threat/01-authentication/rules/lab-auth-google-callback-failures-per-ip.sql
npx securenow alerts rules validate <R01_ID> --sql @threat/01-authentication/rules/lab-auth-google-callback-failures-per-ip.sql --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --json
```

```bash
npx securenow alerts rules create \
  --name "lab-auth: Google sign-in callback failures per IP" \
  --sql @threat/01-authentication/rules/lab-auth-google-callback-failures-per-ip.sql \
  --apps df7ab010-37ac-4732-88ac-a8ac23afe1a4 --severity medium \
  --schedule "*/5 * * * *" --throttle-minutes 4 \
  --category authentication \
  --description "Threat model 01-authentication (D19, G32, G33, G36a); test-first" \
  --nlp "one IP with 5 or more failed Google sign-in callbacks (bad state, replayed code or rejected token) in 15 minutes"
# -> created Active in mode=test (detect-only); a failing SQL is rolled back automatically
# add --channel <in-app id>,<new channel id> after AUTH-04 (channels cannot be changed later from the CLI)
```

```bash
npx securenow alerts rules test <R15_ID> --mode dry_run --wait --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --json
# expect: "status": "complete" (resultCount 0 until real or synthetic data exists)
```

```bash
# synthetic test — run from the lab-auth root after `npx securenow app connect` (TEST-NET IPs only; every event carries test=true)
for i in $(seq 1 5); do npx securenow event send auth.login.failure --env test --ip 203.0.113.50 --attrs auth_method=oauth,provider=google,reason=invalid_callback,test=true; done
# wait ~45 s for ingest, then re-run the dry-run above -> expect resultCount ≥ 1 for ip 203.0.113.50
```

**Response AUTO-F — lab-auth: rate-limit Google sign-in callback abuse** (created disabled; enable only after the rule is promoted): For 24 hours, the flagged IP may start or complete Google sign-in at most 10 times per 15 minutes (the app allows 30 of each).

```bash
npx securenow automation create --name "lab-auth: rate-limit Google sign-in callback abuse" \
  --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --env test \
  --conditions '[{"field":"alertName","operator":"eq","value":"lab-auth: Google sign-in callback failures per IP"}]' \
  --actions '[{"type":"addToRateLimit","config":{"pathPattern":"^/[aA][pP][iI]/[aA][uU][tT][hH]/[gG][oO][oO][gG][lL][eE]","pathMatchMode":"regex","method":"GET","limit":10,"windowSeconds":900,"keyBy":"ip","ttlHours":24,"reason":"lab-auth Google callback abuse"}}]' \
  --status disabled
# reverse: npx securenow ratelimit list --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --env test   # then: npx securenow ratelimit remove <id> --reason "false positive"
```

```bash
# after 3-7 days of real traffic with no unexplained hits — a person decides:
npx securenow alerts rules promote <R15_ID>
# then enable its response(s):
npx securenow automation update <AUTO-F_ID> --status active
```

<a id="rule-r16"></a>
### R16 · lab-auth: Google sign-in refused for an existing password account

**🟡 PARTIAL · APP_EVENT · LOW · `test-first`** · threats [B8a](#threat-b8a), [G34](#threat-g34), [G36c](#threat-g36c), [H40a](#threat-h40a) · schedule `*/15 * * * *`, throttle 14 min

- **Fires on:** ≥ 3 link refusals from one IP, or ≥ 5 app-wide, in 60 min.
- **Threshold source:** Baseline required — conservative start. One refusal is a confused real user; a cluster is either probing or a UX bug locking people out.
- **Needs (not yet in telemetry):** event auth.account.link with outcome=rejected (proposed instrumentation, src/app.js:249).
- **Tag:** test-first and notify-only: it points at an app fix (F4), never at a block.

```sql
-- rules/lab-auth-google-link-refusals.sql
-- APP_EVENT: needs auth.account.link (outcome=rejected, provider=google, reason=existing_email_other_method), exported where
-- the app refuses to attach a Google identity to an existing password account (src/app.js:247-250).
-- Two-stage: per-IP probing (3+ in 60 min) OR an app-wide spike (5+ in 60 min) that usually means real users are locked out.
-- Notify only - this points at a UX/code fix (verified-email linking), never at an automated block.
SELECT
  per_ip.ip AS ip,
  per_ip.refusals AS refusals_from_ip,
  g.total AS refusals_all_ips_60m
FROM
(
  SELECT attributes_string['http.client_ip'] AS ip, count() AS refusals
  FROM signoz_logs.distributed_logs_v2
  WHERE resources_string['service.name'] IN (__USER_APP_KEYS__)
    AND timestamp >= toUnixTimestamp64Nano(now64() - INTERVAL 60 MINUTE)
    AND attributes_string['event.type'] = 'auth.account.link'
    AND attributes_string['outcome'] = 'rejected'
  GROUP BY ip
  HAVING ip != ''
) AS per_ip
CROSS JOIN
(
  SELECT count() AS total
  FROM signoz_logs.distributed_logs_v2
  WHERE resources_string['service.name'] IN (__USER_APP_KEYS__)
    AND timestamp >= toUnixTimestamp64Nano(now64() - INTERVAL 60 MINUTE)
    AND attributes_string['event.type'] = 'auth.account.link'
    AND attributes_string['outcome'] = 'rejected'
) AS g
WHERE per_ip.refusals >= 3 OR g.total >= 5
ORDER BY refusals_from_ip DESC
LIMIT 10
```

```bash
# the SQL above is saved as threat/01-authentication/rules/lab-auth-google-link-refusals.sql
npx securenow alerts rules validate <R01_ID> --sql @threat/01-authentication/rules/lab-auth-google-link-refusals.sql --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --json
```

```bash
npx securenow alerts rules create \
  --name "lab-auth: Google sign-in refused for an existing password account" \
  --sql @threat/01-authentication/rules/lab-auth-google-link-refusals.sql \
  --apps df7ab010-37ac-4732-88ac-a8ac23afe1a4 --severity low \
  --schedule "*/15 * * * *" --throttle-minutes 14 \
  --category authentication \
  --description "Threat model 01-authentication (B8a, G34, G36c, H40a); test-first" \
  --nlp "Google sign-in refused because a password account already uses that email: 3 or more from one IP or 5 or more app-wide within an hour"
# -> created Active in mode=test (detect-only); a failing SQL is rolled back automatically
# add --channel <in-app id>,<new channel id> after AUTH-04 (channels cannot be changed later from the CLI)
```

```bash
npx securenow alerts rules test <R16_ID> --mode dry_run --wait --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --json
# expect: "status": "complete" (resultCount 0 until real or synthetic data exists)
```

```bash
# synthetic test — run from the lab-auth root after `npx securenow app connect` (TEST-NET IPs only; every event carries test=true)
for i in 1 2 3; do npx securenow event send auth.account.link --env test --ip 203.0.113.60 --attrs outcome=rejected,provider=google,verified_email=true,join_key=iss_sub,reason=existing_email_other_method,account_ref=test-acct-$i,test=true; done
# wait ~45 s for ingest, then re-run the dry-run above -> expect resultCount ≥ 1 for ip 203.0.113.60
```

**Response:** notify only — see the runbook in §12 for the human-approved action.

```bash
# after 3-7 days of real traffic with no unexplained hits — a person decides:
npx securenow alerts rules promote <R16_ID>
```

<a id="rule-r17"></a>
### R17 · lab-auth: account active from several networks

**🟡 PARTIAL · APP_EVENT · MEDIUM · `test-first`** · threats [C9](#threat-c9), [C12](#threat-c12) · schedule `*/15 * * * *`, throttle 14 min

- **Fires on:** one account’s live sessions seen from ≥ 3 different IPs in 60 min.
- **Threshold source:** Baseline required — conservative start (phone on mobile data + laptop at home = 2).
- **Needs (not yet in telemetry):** event session.seen with enduser.id from securenow/sessions guard() wired with getUserId (proposed, after src/app.js:101).
- **Tag:** test-first and notify-only: travellers and mobile networks trip it. Response is a human decision to revoke.

```sql
-- rules/lab-auth-account-on-several-networks.sql
-- APP_EVENT: needs session.seen from securenow/sessions guard() with getSessionId/getUserId wired to the lab's
-- express-session (the guard's default cookie list does not include __Host-lab_auth). One account's live sessions
-- seen from 3+ different IPs within an hour = possible stolen session cookie in use elsewhere.
-- Threshold: baseline required - conservative start. Mobile/roaming users trip it: notify + human review, response = revoke.
SELECT
  attributes_string['enduser.id'] AS account,
  uniqExact(attributes_string['http.client_ip']) AS networks,
  uniqExact(attributes_string['session.id']) AS sessions,
  argMax(attributes_string['http.client_ip'], timestamp) AS ip
FROM signoz_logs.distributed_logs_v2
WHERE resources_string['service.name'] IN (__USER_APP_KEYS__)
  AND timestamp >= toUnixTimestamp64Nano(now64() - INTERVAL 60 MINUTE)
  AND attributes_string['event.type'] = 'session.seen'
GROUP BY account
HAVING account != '' AND ip != '' AND networks >= 3
```

```bash
# the SQL above is saved as threat/01-authentication/rules/lab-auth-account-on-several-networks.sql
npx securenow alerts rules validate <R01_ID> --sql @threat/01-authentication/rules/lab-auth-account-on-several-networks.sql --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --json
```

```bash
npx securenow alerts rules create \
  --name "lab-auth: account active from several networks" \
  --sql @threat/01-authentication/rules/lab-auth-account-on-several-networks.sql \
  --apps df7ab010-37ac-4732-88ac-a8ac23afe1a4 --severity medium \
  --schedule "*/15 * * * *" --throttle-minutes 14 \
  --category authentication \
  --description "Threat model 01-authentication (C9, C12); test-first" \
  --nlp "one account whose sessions are seen from 3 or more different IPs within an hour"
# -> created Active in mode=test (detect-only); a failing SQL is rolled back automatically
# add --channel <in-app id>,<new channel id> after AUTH-04 (channels cannot be changed later from the CLI)
```

```bash
npx securenow alerts rules test <R17_ID> --mode dry_run --wait --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --json
# expect: "status": "complete" (resultCount 0 until real or synthetic data exists)
```

```bash
# synthetic test — run from the lab-auth root after `npx securenow app connect` (TEST-NET IPs only; every event carries test=true)
for ip in 203.0.113.70 198.51.100.70 192.0.2.70; do npx securenow event send session.seen --env test --user test-user-net --session test-sess-net --ip $ip --attrs test=true; done
# wait ~45 s for ingest, then re-run the dry-run above -> expect resultCount ≥ 1 for account test-user-net
```

**Response:** notify only — see the runbook in §12 for the human-approved action.

```bash
# after 3-7 days of real traffic with no unexplained hits — a person decides:
npx securenow alerts rules promote <R17_ID>
```

<a id="rule-r18"></a>
### R18 · lab-auth: session still used after password change

**🟡 PARTIAL · APP_EVENT · HIGH · `prod-ready`** · threats [C11a](#threat-c11a) · schedule `*/15 * * * *`, throttle 14 min

- **Fires on:** a session already live before a completed password change is seen again ≥ 5 min after it (1-day window).
- **Threshold source:** Exact regression signal: the app invalidates older sessions via session_version (src/app.js:93, 202), so the expected count is zero.
- **Needs (not yet in telemetry):** events auth.security.change (src/app.js:206) + session.seen (guard).
- **Tag:** prod-ready after one clean week: near-zero false positives, and the response is revoking a session, not blocking an IP.

```sql
-- rules/lab-auth-session-survives-password-change.sql
-- APP_EVENT: needs auth.security.change (action=password_changed, outcome=completed) and session.seen (guard()).
-- The app is supposed to kill every older session on password change via session_version (src/app.js:93, 202).
-- This fires only if a session that was ALREADY live before the change is still seen 5+ minutes after it,
-- so a user simply signing in again on a second device does not trip it. Near-zero false positives.
SELECT account, surviving_sessions, ip
FROM
(
  SELECT
    attributes_string['enduser.id'] AS account,
    maxIf(timestamp, attributes_string['event.type'] = 'auth.security.change'
                     AND attributes_string['action'] = 'password_changed'
                     AND attributes_string['outcome'] = 'completed') AS t_changed,
    groupArrayIf((timestamp, attributes_string['session.id']), attributes_string['event.type'] = 'session.seen') AS seen,
    arrayDistinct(arrayMap(x -> x.2, arrayFilter(x -> x.1 < t_changed, seen))) AS sessions_before,
    arrayDistinct(arrayMap(x -> x.2, arrayFilter(x -> x.1 > t_changed + 300000000000, seen))) AS sessions_after,
    length(arrayIntersect(sessions_before, sessions_after)) AS surviving_sessions,
    argMax(attributes_string['http.client_ip'], timestamp) AS ip
  FROM signoz_logs.distributed_logs_v2
  WHERE resources_string['service.name'] IN (__USER_APP_KEYS__)
    AND timestamp >= toUnixTimestamp64Nano(now64() - INTERVAL 1 DAY)
    AND attributes_string['event.type'] IN ('auth.security.change', 'session.seen')
  GROUP BY account
  HAVING account != '' AND ip != '' AND t_changed > 0
)
WHERE surviving_sessions >= 1
```

```bash
# the SQL above is saved as threat/01-authentication/rules/lab-auth-session-survives-password-change.sql
npx securenow alerts rules validate <R01_ID> --sql @threat/01-authentication/rules/lab-auth-session-survives-password-change.sql --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --json
```

```bash
npx securenow alerts rules create \
  --name "lab-auth: session still used after password change" \
  --sql @threat/01-authentication/rules/lab-auth-session-survives-password-change.sql \
  --apps df7ab010-37ac-4732-88ac-a8ac23afe1a4 --severity high \
  --schedule "*/15 * * * *" --throttle-minutes 14 \
  --category authentication \
  --description "Threat model 01-authentication (C11a); prod-ready" \
  --nlp "a session that existed before a password change is still being used more than 5 minutes after the change"
# -> created Active in mode=test (detect-only); a failing SQL is rolled back automatically
# add --channel <in-app id>,<new channel id> after AUTH-04 (channels cannot be changed later from the CLI)
```

```bash
npx securenow alerts rules test <R18_ID> --mode dry_run --wait --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --json
# expect: "status": "complete" (resultCount 0 until real or synthetic data exists)
```

```bash
# synthetic test — run from the lab-auth root after `npx securenow app connect` (TEST-NET IPs only; every event carries test=true)
npx securenow event send session.seen --env test --user test-user-pw --session test-old-1 --ip 203.0.113.80 --attrs test=true
npx securenow event send auth.security.change --env test --user test-user-pw --session test-new-1 --ip 203.0.113.81 --attrs action=password_changed,outcome=completed,step_up=true,test=true
# wait more than 5 minutes, then:
npx securenow event send session.seen --env test --user test-user-pw --session test-old-1 --ip 203.0.113.80 --attrs test=true
# wait ~45 s for ingest, then re-run the dry-run above -> expect resultCount ≥ 1 for account test-user-pw (surviving_sessions = 1)
```

**Response:** notify only — see the runbook in §12 for the human-approved action.

```bash
# after one clean test-mode week — a person decides:
npx securenow alerts rules promote <R18_ID>
```

<a id="rule-r19"></a>
### R19 · lab-auth: takeover sequence (failures, sign-in, security change)

**🟡 PARTIAL · APP_EVENT · HIGH · `test-first`** · threats [C16c](#threat-c16c), [H39a](#threat-h39a), [H40c](#threat-h40c) · schedule `*/15 * * * *`, throttle 14 min

- **Fires on:** failed sign-in → successful sign-in → completed security change on one account within 1 h (2-hour window).
- **Threshold source:** Baseline required — conservative start. One miss before a password change is also how a real owner rotates a forgotten-ish password.
- **Needs (not yet in telemetry):** events auth.login.failure (with userId when the account exists), auth.login.success, auth.security.change.
- **Tag:** test-first; respond only after human review.

```sql
-- rules/lab-auth-takeover-sequence.sql
-- APP_EVENT: needs auth.login.failure (with userId when the account exists), auth.login.success and auth.security.change.
-- Ordered within 1 hour on the same account: failed sign-in -> successful sign-in -> completed security change
-- (password changed, or - for an admin account - a role changed). That is the shape of a guessed password being used
-- to lock the owner out or to grant someone else admin. windowFunnel window is in nanoseconds (3600000000000 = 1 h).
SELECT
  attributes_string['enduser.id'] AS account,
  windowFunnel(3600000000000)(timestamp,
    attributes_string['event.type'] = 'auth.login.failure',
    attributes_string['event.type'] = 'auth.login.success',
    attributes_string['event.type'] = 'auth.security.change' AND attributes_string['outcome'] = 'completed') AS steps,
  argMax(attributes_string['http.client_ip'], timestamp) AS ip
FROM signoz_logs.distributed_logs_v2
WHERE resources_string['service.name'] IN (__USER_APP_KEYS__)
  AND timestamp >= toUnixTimestamp64Nano(now64() - INTERVAL 2 HOUR)
  AND attributes_string['event.type'] IN ('auth.login.failure', 'auth.login.success', 'auth.security.change')
GROUP BY account
HAVING account != '' AND ip != '' AND steps >= 3
```

```bash
# the SQL above is saved as threat/01-authentication/rules/lab-auth-takeover-sequence.sql
npx securenow alerts rules validate <R01_ID> --sql @threat/01-authentication/rules/lab-auth-takeover-sequence.sql --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --json
```

```bash
npx securenow alerts rules create \
  --name "lab-auth: takeover sequence (failures, sign-in, security change)" \
  --sql @threat/01-authentication/rules/lab-auth-takeover-sequence.sql \
  --apps df7ab010-37ac-4732-88ac-a8ac23afe1a4 --severity high \
  --schedule "*/15 * * * *" --throttle-minutes 14 \
  --category authentication \
  --description "Threat model 01-authentication (C16c, H39a, H40c); test-first" \
  --nlp "an account with a failed sign-in, then a successful sign-in, then a password or role change, all within one hour"
# -> created Active in mode=test (detect-only); a failing SQL is rolled back automatically
# add --channel <in-app id>,<new channel id> after AUTH-04 (channels cannot be changed later from the CLI)
```

```bash
npx securenow alerts rules test <R19_ID> --mode dry_run --wait --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --json
# expect: "status": "complete" (resultCount 0 until real or synthetic data exists)
```

```bash
# synthetic test — run from the lab-auth root after `npx securenow app connect` (TEST-NET IPs only; every event carries test=true)
npx securenow event send auth.login.failure --env test --user test-user-ato --ip 203.0.113.90 --attrs auth_method=password,provider=local,reason=bad_password,account_ref=test-acct-ato,test=true
npx securenow event send auth.login.success --env test --user test-user-ato --session test-sess-ato --ip 203.0.113.91 --attrs auth_method=password,provider=local,account_ref=test-acct-ato,mfa_state=none,test=true
npx securenow event send auth.security.change --env test --user test-user-ato --session test-sess-ato --ip 203.0.113.91 --attrs action=password_changed,outcome=completed,step_up=true,test=true
# wait ~45 s for ingest, then re-run the dry-run above -> expect resultCount ≥ 1 for account test-user-ato (steps = 3)
```

**Response:** notify only — see the runbook in §12 for the human-approved action.

```bash
# after 3-7 days of real traffic with no unexplained hits — a person decides:
npx securenow alerts rules promote <R19_ID>
```

<a id="rule-r20"></a>
### R20 · lab-auth: security change from a different network than sign-in

**🟡 PARTIAL · APP_EVENT · MEDIUM · `test-first`** · threats [C9](#threat-c9), [C16d](#threat-c16d), [L54a](#threat-l54a) · schedule `*/15 * * * *`, throttle 14 min

- **Fires on:** password or role change made from a different IP than the one that signed the same session in (8-hour window).
- **Threshold source:** Exact comparison per session; noisy only for roaming users.
- **Needs (not yet in telemetry):** events auth.login.success and auth.security.change sharing the same session.id (sessionId captured before src/app.js:205).
- **Tag:** test-first and notify-only: mobile users change IPs mid-session.

```sql
-- rules/lab-auth-security-change-from-other-network.sql
-- APP_EVENT: needs auth.login.success and auth.security.change carrying the SAME session_ref (sha256 of the
-- express-session id that performed the action, captured before authenticate() rotates it - src/app.js:205).
-- A password or role change made from a different IP than the one that signed this session in = the session cookie
-- is being replayed somewhere else. Roaming users can trip it: notify + human review.
SELECT
  attributes_string['session.id'] AS session_ref,
  any(attributes_string['enduser.id']) AS account,
  argMaxIf(attributes_string['http.client_ip'], timestamp, attributes_string['event.type'] = 'auth.login.success') AS signin_ip,
  argMaxIf(attributes_string['http.client_ip'], timestamp, attributes_string['event.type'] = 'auth.security.change') AS ip
FROM signoz_logs.distributed_logs_v2
WHERE resources_string['service.name'] IN (__USER_APP_KEYS__)
  AND timestamp >= toUnixTimestamp64Nano(now64() - INTERVAL 8 HOUR)
  AND attributes_string['event.type'] IN ('auth.login.success', 'auth.security.change')
GROUP BY session_ref
HAVING session_ref != '' AND ip != '' AND signin_ip != '' AND signin_ip != ip
```

```bash
# the SQL above is saved as threat/01-authentication/rules/lab-auth-security-change-from-other-network.sql
npx securenow alerts rules validate <R01_ID> --sql @threat/01-authentication/rules/lab-auth-security-change-from-other-network.sql --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --json
```

```bash
npx securenow alerts rules create \
  --name "lab-auth: security change from a different network than sign-in" \
  --sql @threat/01-authentication/rules/lab-auth-security-change-from-other-network.sql \
  --apps df7ab010-37ac-4732-88ac-a8ac23afe1a4 --severity medium \
  --schedule "*/15 * * * *" --throttle-minutes 14 \
  --category authentication \
  --description "Threat model 01-authentication (C9, C16d, L54a); test-first" \
  --nlp "a password or role change made from a different IP than the sign-in of the same session"
# -> created Active in mode=test (detect-only); a failing SQL is rolled back automatically
# add --channel <in-app id>,<new channel id> after AUTH-04 (channels cannot be changed later from the CLI)
```

```bash
npx securenow alerts rules test <R20_ID> --mode dry_run --wait --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --json
# expect: "status": "complete" (resultCount 0 until real or synthetic data exists)
```

```bash
# synthetic test — run from the lab-auth root after `npx securenow app connect` (TEST-NET IPs only; every event carries test=true)
npx securenow event send auth.login.success --env test --user test-user-net2 --session test-sess-net2 --ip 203.0.113.100 --attrs auth_method=password,provider=local,account_ref=test-acct-net2,mfa_state=none,test=true
npx securenow event send auth.security.change --env test --user test-user-net2 --session test-sess-net2 --ip 198.51.100.100 --attrs action=password_changed,outcome=completed,step_up=true,test=true
# wait ~45 s for ingest, then re-run the dry-run above -> expect resultCount ≥ 1 for session test-sess-net2 with ip 198.51.100.100
```

**Response:** notify only — see the runbook in §12 for the human-approved action.

```bash
# after 3-7 days of real traffic with no unexplained hits — a person decides:
npx securenow alerts rules promote <R20_ID>
```

<a id="rule-r21"></a>
### R21 · lab-auth: post-sign-in security changes needing review

**🟡 PARTIAL · APP_EVENT · HIGH · `test-first`** · threats [H39a](#threat-h39a), [L53](#threat-l53), [L54a](#threat-l54a) · schedule `*/15 * * * *`, throttle 14 min

- **Fires on:** any privilege elevation, or one admin changing ≥ 3 accounts, or ≥ 3 wrong current-password attempts, per acting account in 60 min.
- **Threshold source:** Elevation = every occurrence (rare, high value). The other two are baseline required — conservative start (native password-change limit 5 per IP per 15 min, src/app.js:194).
- **Needs (not yet in telemetry):** event auth.security.change with action, outcome, direction, target_ref (src/app.js:198, 206, 297).
- **Tag:** test-first: the presenter promoting test accounts on camera will trip it (expected).

```sql
-- rules/lab-auth-post-signin-security-changes.sql
-- APP_EVENT: needs auth.security.change exported from the password route (src/app.js:198, 206) and the admin role
-- route (src/app.js:297). Grouped by the acting account. Fires on any privilege elevation, on one admin changing
-- 3+ accounts in an hour, or on 3+ wrong current-password attempts (a stolen session guessing the password).
-- Thresholds: elevation = every occurrence (rare, high value); others baseline required - conservative start
-- (native password-change limit is 5 per IP per 15 min, src/app.js:194).
SELECT
  attributes_string['enduser.id'] AS account,
  countIf(attributes_string['action'] = 'role_changed' AND attributes_string['direction'] = 'elevate') AS privilege_elevations,
  uniqExactIf(attributes_string['target_ref'], attributes_string['action'] = 'role_changed') AS accounts_changed,
  countIf(attributes_string['action'] = 'password_changed' AND attributes_string['outcome'] = 'failure') AS wrong_current_password,
  argMax(attributes_string['http.client_ip'], timestamp) AS ip
FROM signoz_logs.distributed_logs_v2
WHERE resources_string['service.name'] IN (__USER_APP_KEYS__)
  AND timestamp >= toUnixTimestamp64Nano(now64() - INTERVAL 60 MINUTE)
  AND attributes_string['event.type'] = 'auth.security.change'
GROUP BY account
HAVING account != '' AND ip != '' AND (privilege_elevations >= 1 OR accounts_changed >= 3 OR wrong_current_password >= 3)
```

```bash
# the SQL above is saved as threat/01-authentication/rules/lab-auth-post-signin-security-changes.sql
npx securenow alerts rules validate <R01_ID> --sql @threat/01-authentication/rules/lab-auth-post-signin-security-changes.sql --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --json
```

```bash
npx securenow alerts rules create \
  --name "lab-auth: post-sign-in security changes needing review" \
  --sql @threat/01-authentication/rules/lab-auth-post-signin-security-changes.sql \
  --apps df7ab010-37ac-4732-88ac-a8ac23afe1a4 --severity high \
  --schedule "*/15 * * * *" --throttle-minutes 14 \
  --category authentication \
  --description "Threat model 01-authentication (H39a, L53, L54a); test-first" \
  --nlp "privilege elevation, an admin changing 3 or more accounts, or 3 or more wrong current-password attempts within an hour"
# -> created Active in mode=test (detect-only); a failing SQL is rolled back automatically
# add --channel <in-app id>,<new channel id> after AUTH-04 (channels cannot be changed later from the CLI)
```

```bash
npx securenow alerts rules test <R21_ID> --mode dry_run --wait --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --json
# expect: "status": "complete" (resultCount 0 until real or synthetic data exists)
```

```bash
# synthetic test — run from the lab-auth root after `npx securenow app connect` (TEST-NET IPs only; every event carries test=true)
npx securenow event send auth.security.change --env test --user test-admin --session test-sess-adm --ip 203.0.113.110 --attrs action=role_changed,outcome=completed,step_up=false,direction=elevate,target_ref=test-target-1,test=true
# wait ~45 s for ingest, then re-run the dry-run above -> expect resultCount ≥ 1 for account test-admin (privilege_elevations = 1)
```

**Response:** notify only — see the runbook in §12 for the human-approved action.

```bash
# after 3-7 days of real traffic with no unexplained hits — a person decides:
npx securenow alerts rules promote <R21_ID>
```

<a id="rule-r22"></a>
### R22 · lab-auth: sign-in to a dormant account

**🟡 PARTIAL · APP_EVENT · LOW · `test-first`** · threats [C16b](#threat-c16b), [H40c](#threat-h40c) · schedule `*/15 * * * *`, throttle 14 min

- **Fires on:** a successful sign-in whose dormant_days ≥ 90.
- **Threshold source:** 90 days — conservative start. Needs the app to record the previous sign-in (TODO AUTH-26).
- **Needs (not yet in telemetry):** event auth.login.success with dormant_days — requires a new last-sign-in column (db/001_initial.sql has none).
- **Tag:** test-first and notify-only.

```sql
-- rules/lab-auth-dormant-account-signin.sql
-- APP_EVENT + code change: needs auth.login.success with dormant_days (days since the previous successful sign-in).
-- The users table has no last-sign-in column today (db/001_initial.sql:1-13), so the app must add one first.
-- SecureNow cannot compute dormancy itself: the telemetry retention window is far shorter than "dormant".
-- track() sends dormant_days as a number (attributes_number); `event send` sends every value as a string, so both are read.
-- Threshold: 90 days (conservative start). Notify only.
SELECT
  attributes_string['http.client_ip'] AS ip,
  any(attributes_string['enduser.id']) AS account,
  max(greatest(attributes_number['dormant_days'], toFloat64OrZero(attributes_string['dormant_days']))) AS dormant_days,
  count() AS signins
FROM signoz_logs.distributed_logs_v2
WHERE resources_string['service.name'] IN (__USER_APP_KEYS__)
  AND timestamp >= toUnixTimestamp64Nano(now64() - INTERVAL 15 MINUTE)
  AND attributes_string['event.type'] = 'auth.login.success'
  AND greatest(attributes_number['dormant_days'], toFloat64OrZero(attributes_string['dormant_days'])) >= 90
GROUP BY ip
HAVING ip != '' AND signins >= 1
```

```bash
# the SQL above is saved as threat/01-authentication/rules/lab-auth-dormant-account-signin.sql
npx securenow alerts rules validate <R01_ID> --sql @threat/01-authentication/rules/lab-auth-dormant-account-signin.sql --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --json
```

```bash
npx securenow alerts rules create \
  --name "lab-auth: sign-in to a dormant account" \
  --sql @threat/01-authentication/rules/lab-auth-dormant-account-signin.sql \
  --apps df7ab010-37ac-4732-88ac-a8ac23afe1a4 --severity low \
  --schedule "*/15 * * * *" --throttle-minutes 14 \
  --category authentication \
  --description "Threat model 01-authentication (C16b, H40c); test-first" \
  --nlp "a successful sign-in to an account that had not signed in for 90 days or more"
# -> created Active in mode=test (detect-only); a failing SQL is rolled back automatically
# add --channel <in-app id>,<new channel id> after AUTH-04 (channels cannot be changed later from the CLI)
```

```bash
npx securenow alerts rules test <R22_ID> --mode dry_run --wait --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --json
# expect: "status": "complete" (resultCount 0 until real or synthetic data exists)
```

```bash
# synthetic test — run from the lab-auth root after `npx securenow app connect` (TEST-NET IPs only; every event carries test=true)
npx securenow event send auth.login.success --env test --user test-user-dormant --session test-sess-dormant --ip 203.0.113.120 --attrs auth_method=password,provider=local,account_ref=test-acct-dormant,mfa_state=none,dormant_days=120,test=true
# wait ~45 s for ingest, then re-run the dry-run above -> expect resultCount ≥ 1 for ip 203.0.113.120 (the rule reads dormant_days as a number or a string)
```

**Response:** notify only — see the runbook in §12 for the human-approved action.

```bash
# after 3-7 days of real traffic with no unexplained hits — a person decides:
npx securenow alerts rules promote <R22_ID>
```

<a id="rule-r23"></a>
### R23 · lab-auth: registration probing per IP

**🟡 PARTIAL · APP_EVENT · MEDIUM · `test-first`** · threats [B6](#threat-b6), [B7](#threat-b7), [G36](#threat-g36), [H40](#threat-h40), [H40a](#threat-h40a) · schedule `*/15 * * * *`, throttle 14 min

- **Fires on:** ≥ 3 registrations on already-registered emails, or ≥ 5 new accounts, from one IP in 60 min.
- **Threshold source:** App limit: 10 registrations per IP per 15 min (src/config.js:25).
- **Needs (not yet in telemetry):** event auth.signup with outcome=created|existing (src/app.js:170, and after src/app.js:244 for Google-created accounts).
- **Tag:** test-first: a workshop where everyone shares one IP will create several accounts.

```sql
-- rules/lab-auth-registration-probing-per-ip.sql
-- APP_EVENT: needs auth.signup with outcome=created|existing exported at src/app.js:170 (result.rows[0] tells which).
-- The HTTP response is deliberately identical either way, but the operator can see the difference in telemetry.
-- existing = someone registering addresses that already have accounts (enumeration via register-then-sign-in);
-- created  = one IP creating several accounts (account farming / squatting other people's addresses).
-- Threshold source: native limit 10 registrations per IP per 15 min (src/config.js:25) -> 3 existing or 5 created in 60 min.
SELECT
  attributes_string['http.client_ip'] AS ip,
  countIf(attributes_string['outcome'] = 'existing') AS signups_on_existing_emails,
  countIf(attributes_string['outcome'] = 'created') AS accounts_created,
  count() AS signups
FROM signoz_logs.distributed_logs_v2
WHERE resources_string['service.name'] IN (__USER_APP_KEYS__)
  AND timestamp >= toUnixTimestamp64Nano(now64() - INTERVAL 60 MINUTE)
  AND attributes_string['event.type'] = 'auth.signup'
GROUP BY ip
HAVING ip != '' AND (signups_on_existing_emails >= 3 OR accounts_created >= 5)
```

```bash
# the SQL above is saved as threat/01-authentication/rules/lab-auth-registration-probing-per-ip.sql
npx securenow alerts rules validate <R01_ID> --sql @threat/01-authentication/rules/lab-auth-registration-probing-per-ip.sql --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --json
```

```bash
npx securenow alerts rules create \
  --name "lab-auth: registration probing per IP" \
  --sql @threat/01-authentication/rules/lab-auth-registration-probing-per-ip.sql \
  --apps df7ab010-37ac-4732-88ac-a8ac23afe1a4 --severity medium \
  --schedule "*/15 * * * *" --throttle-minutes 14 \
  --category authentication \
  --description "Threat model 01-authentication (B6, B7, G36, H40, H40a); test-first" \
  --nlp "one IP registering 3 or more already-registered emails, or creating 5 or more accounts, within an hour"
# -> created Active in mode=test (detect-only); a failing SQL is rolled back automatically
# add --channel <in-app id>,<new channel id> after AUTH-04 (channels cannot be changed later from the CLI)
```

```bash
npx securenow alerts rules test <R23_ID> --mode dry_run --wait --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --json
# expect: "status": "complete" (resultCount 0 until real or synthetic data exists)
```

```bash
# synthetic test — run from the lab-auth root after `npx securenow app connect` (TEST-NET IPs only; every event carries test=true)
for i in 1 2 3; do npx securenow event send auth.signup --env test --ip 203.0.113.130 --attrs auth_method=password,provider=local,outcome=existing,account_ref=test-acct-reg-$i,test=true; done
# wait ~45 s for ingest, then re-run the dry-run above -> expect resultCount ≥ 1 for ip 203.0.113.130
```

**Response AUTO-G — lab-auth: rate-limit registration probing** (created disabled; enable only after the rule is promoted): For 24 hours, the flagged IP may submit at most 3 registrations per hour (the app allows 10 per 15 minutes).

```bash
npx securenow automation create --name "lab-auth: rate-limit registration probing" \
  --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --env test \
  --conditions '[{"field":"alertName","operator":"eq","value":"lab-auth: registration probing per IP"}]' \
  --actions '[{"type":"addToRateLimit","config":{"pathPattern":"^/[aA][pP][iI]/[aA][uU][tT][hH]/[rR][eE][gG][iI][sS][tT][eE][rR]/*$","pathMatchMode":"regex","method":"POST","limit":3,"windowSeconds":3600,"keyBy":"ip","ttlHours":24,"reason":"lab-auth registration probing"}}]' \
  --status disabled
# reverse: npx securenow ratelimit list --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --env test   # then: npx securenow ratelimit remove <id> --reason "false positive"
```

```bash
# after 3-7 days of real traffic with no unexplained hits — a person decides:
npx securenow alerts rules promote <R23_ID>
# then enable its response(s):
npx securenow automation update <AUTO-G_ID> --status active
```

<a id="rule-r24"></a>
### R24 · lab-auth: auth event integrity

**🟡 PARTIAL · APP_EVENT · MEDIUM · `test-first`** · threats [M61](#threat-m61) · schedule `*/15 * * * *`, throttle 14 min

- **Fires on:** any duplicate request_id on one event type, any auth.login.* without auth_method, or any event dated > 5 min in the future (60 min).
- **Threshold source:** Exact — expected zero once the bridge is correct.
- **Needs (not yet in telemetry):** request_id and auth_method on the exported auth events (proposed instrumentation).
- **Tag:** test-first: run one clean week to prove the bridge emits every required attribute.

```sql
-- rules/lab-auth-event-integrity.sql
-- APP_EVENT: checks the lab's own exported auth events for signs of forging, replay, or a broken bridge.
-- duplicate_request_ids: the same request_id (the app's per-request UUID, src/app.js:63) on two events of one type;
-- missing_auth_method:   auth.login.* without the required auth_method attribute;
-- future_dated:          events stamped more than 5 minutes in the future (events carry a sender-supplied timestamp).
-- Any hit is worth a look; synthetic `event send` tests in this report always include auth_method.
SELECT
  attributes_string['http.client_ip'] AS ip,
  countIf(attributes_string['request_id'] != '')
    - uniqExactIf(concat(attributes_string['event.type'], '|', attributes_string['request_id']), attributes_string['request_id'] != '') AS duplicate_request_ids,
  countIf(attributes_string['event.type'] IN ('auth.login.success', 'auth.login.failure') AND attributes_string['auth_method'] = '') AS missing_auth_method,
  countIf(timestamp > toUnixTimestamp64Nano(now64() + INTERVAL 5 MINUTE)) AS future_dated,
  count() AS events
FROM signoz_logs.distributed_logs_v2
WHERE resources_string['service.name'] IN (__USER_APP_KEYS__)
  AND timestamp >= toUnixTimestamp64Nano(now64() - INTERVAL 60 MINUTE)
  AND attributes_string['event.type'] IN ('auth.login.success', 'auth.login.failure', 'auth.signup', 'auth.logout',
      'auth.security.change', 'auth.account.link', 'api.ratelimit.exceeded')
GROUP BY ip
HAVING ip != '' AND (duplicate_request_ids >= 1 OR missing_auth_method >= 1 OR future_dated >= 1)
```

```bash
# the SQL above is saved as threat/01-authentication/rules/lab-auth-event-integrity.sql
npx securenow alerts rules validate <R01_ID> --sql @threat/01-authentication/rules/lab-auth-event-integrity.sql --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --json
```

```bash
npx securenow alerts rules create \
  --name "lab-auth: auth event integrity" \
  --sql @threat/01-authentication/rules/lab-auth-event-integrity.sql \
  --apps df7ab010-37ac-4732-88ac-a8ac23afe1a4 --severity medium \
  --schedule "*/15 * * * *" --throttle-minutes 14 \
  --category authentication \
  --description "Threat model 01-authentication (M61); test-first" \
  --nlp "auth events that look forged, replayed or broken: duplicate request ids, missing auth_method, or future timestamps"
# -> created Active in mode=test (detect-only); a failing SQL is rolled back automatically
# add --channel <in-app id>,<new channel id> after AUTH-04 (channels cannot be changed later from the CLI)
```

```bash
npx securenow alerts rules test <R24_ID> --mode dry_run --wait --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --json
# expect: "status": "complete" (resultCount 0 until real or synthetic data exists)
```

```bash
# synthetic test — run from the lab-auth root after `npx securenow app connect` (TEST-NET IPs only; every event carries test=true)
for i in 1 2; do npx securenow event send auth.login.failure --env test --ip 203.0.113.140 --attrs auth_method=password,provider=local,reason=bad_password,account_ref=test-acct-int,request_id=test-dup-1,test=true; done
# wait ~45 s for ingest, then re-run the dry-run above -> expect resultCount ≥ 1 for ip 203.0.113.140 (duplicate_request_ids = 1)
```

**Response:** notify only — see the runbook in §12 for the human-approved action.

```bash
# after 3-7 days of real traffic with no unexplained hits — a person decides:
npx securenow alerts rules promote <R24_ID>
```

<a id="rule-r25"></a>
### R25 · lab-auth: auth event coverage drift

**🟡 PARTIAL · NATIVE_TRAFFIC + APP_EVENT · LOW · `test-first`** · threats [M55](#threat-m55) · schedule `*/15 * * * *`, throttle 14 min

- **Fires on:** fewer exported password sign-in events than half the traced sign-in verdicts (≥ 10 traced) in 30 min.
- **Threshold source:** Ratio, not volume: every traced 200/401 on POST /api/auth/login should produce exactly one auth.login.* event.
- **Needs (not yet in telemetry):** both the traces (SDK preload) and the auth.login.* events (bridge).
- **Tag:** test-first; severity low on purpose so no automation acts on the IP it returns.

```sql
-- rules/lab-auth-event-coverage-drift.sql
-- Health rule (traces + events). While HTTP traces still flow, compare password sign-in requests that reached a
-- verdict (200 or 401 on POST /api/auth/login) with exported auth.login.* password events over 30 minutes.
-- Fewer than half as many events as traced requests = the track() bridge broke (deploy, missing runtime key, bad import).
-- Returns the busiest traced IP only so the row has a non-empty ip; create it with severity low so no automation acts on it.
-- It cannot detect a TOTAL telemetry outage (then both sides are zero) - that needs an external monitor.
SELECT
  busiest.ip AS ip,
  tr.traced AS traced_signins_30m,
  ev.events AS signin_events_30m
FROM
(
  WITH
    replaceRegexpOne(lower(decodeURLComponent(splitByChar('?', attributes_string['http.target'])[1])), '/+$', '') AS route
  SELECT count() AS traced
  FROM signoz_traces.distributed_signoz_index_v3
  WHERE `resource_string_service$$name` IN (__USER_APP_KEYS__)
    AND timestamp >= now64(9) - INTERVAL 30 MINUTE
    AND ts_bucket_start >= toUInt64(toUnixTimestamp(now() - INTERVAL 30 MINUTE)) - 1800
    AND kind = 2
    AND http_method = 'POST'
    AND route = '/api/auth/login'
    AND response_status_code IN ('200', '401')
) AS tr
CROSS JOIN
(
  SELECT count() AS events
  FROM signoz_logs.distributed_logs_v2
  WHERE resources_string['service.name'] IN (__USER_APP_KEYS__)
    AND timestamp >= toUnixTimestamp64Nano(now64() - INTERVAL 30 MINUTE)
    AND attributes_string['event.type'] IN ('auth.login.success', 'auth.login.failure')
    AND attributes_string['auth_method'] = 'password'
) AS ev
CROSS JOIN
(
  WITH
    coalesce(nullIf(attributes_string['http.client_ip'], ''), nullIf(attributes_string['net.peer.ip'], ''), nullIf(attributes_string['network.peer.address'], ''), nullIf(attributes_string['client.address'], ''), nullIf(attributes_string['net.sock.peer.addr'], '')) AS client_ip,
    replaceRegexpOne(lower(decodeURLComponent(splitByChar('?', attributes_string['http.target'])[1])), '/+$', '') AS route
  SELECT client_ip AS ip, count() AS hits
  FROM signoz_traces.distributed_signoz_index_v3
  WHERE `resource_string_service$$name` IN (__USER_APP_KEYS__)
    AND timestamp >= now64(9) - INTERVAL 30 MINUTE
    AND ts_bucket_start >= toUInt64(toUnixTimestamp(now() - INTERVAL 30 MINUTE)) - 1800
    AND kind = 2
    AND http_method = 'POST'
    AND route = '/api/auth/login'
  GROUP BY ip
  HAVING ip != ''
  ORDER BY hits DESC
  LIMIT 1
) AS busiest
WHERE tr.traced >= 10 AND ev.events * 2 < tr.traced
```

```bash
# the SQL above is saved as threat/01-authentication/rules/lab-auth-event-coverage-drift.sql
npx securenow alerts rules validate <R01_ID> --sql @threat/01-authentication/rules/lab-auth-event-coverage-drift.sql --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --json
```

```bash
npx securenow alerts rules create \
  --name "lab-auth: auth event coverage drift" \
  --sql @threat/01-authentication/rules/lab-auth-event-coverage-drift.sql \
  --apps df7ab010-37ac-4732-88ac-a8ac23afe1a4 --severity low \
  --schedule "*/15 * * * *" --throttle-minutes 14 \
  --category authentication \
  --description "Threat model 01-authentication (M55); test-first" \
  --nlp "password sign-ins are traced but their auth events are missing (event bridge broken)"
# -> created Active in mode=test (detect-only); a failing SQL is rolled back automatically
# add --channel <in-app id>,<new channel id> after AUTH-04 (channels cannot be changed later from the CLI)
```

```bash
npx securenow alerts rules test <R25_ID> --mode dry_run --wait --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --json
# expect: "status": "complete" (resultCount 0 until real or synthetic data exists)
```

**Test:** Mixed rule: validate with the create-time dry-run and `alerts rules test --mode dry_run`. To see it fire, run 10+ wrong-password sign-ins against your local copy after the SDK preload is on but before the track() bridge is deployed.

**Response:** notify only — see the runbook in §12 for the human-approved action.

```bash
# after 3-7 days of real traffic with no unexplained hits — a person decides:
npx securenow alerts rules promote <R25_ID>
```

<a id="rule-r26"></a>
### R26 · lab-auth: failed sign-ins spread across one network operator (ASN)

**🟡 PARTIAL · APP_EVENT · HIGH · `test-first`** · threats [A2](#threat-a2), [A4](#threat-a4) · schedule `*/10 * * * *`, throttle 9 min

- **Fires on:** ≥ 5 addresses and ≥ 20 failed sign-ins from one ASN in 30 min (returns the latest IP).
- **Threshold source:** Baseline required — conservative start. Large consumer ISPs share one ASN: tune after a week.
- **Needs (not yet in telemetry):** auth.login.failure events plus client.asn / client.as_org (added at ingest only when the instance has ASN enrichment — unverified for this app).
- **Tag:** test-first. Cannot be fired synthetically: TEST-NET addresses carry no ASN.

```sql
-- rules/lab-auth-failed-signins-per-asn.sql
-- APP_EVENT + ingest enrichment: needs auth.login.failure (with the trusted client ip) AND client.asn / client.as_org,
-- which SecureNow adds to EVENTS only when the instance has ASN enrichment enabled (HTTP spans are never ASN-enriched).
-- Confirm with: npx securenow telemetry fields --app <APP_KEY> --since 24h --source logs --env test   (look for client.asn)
-- Failed sign-ins spread over 5+ addresses of one network operator (botnet / residential-proxy pool) in 30 min.
-- Threshold: baseline required - conservative start. TEST-NET IPs carry no ASN, so this rule cannot be fired synthetically.
SELECT
  attributes_string['client.asn'] AS asn,
  any(attributes_string['client.as_org']) AS as_org,
  uniqExact(attributes_string['http.client_ip']) AS distinct_ips,
  uniqExact(attributes_string['account_ref']) AS distinct_accounts,
  count() AS failed_signins,
  argMax(attributes_string['http.client_ip'], timestamp) AS ip
FROM signoz_logs.distributed_logs_v2
WHERE resources_string['service.name'] IN (__USER_APP_KEYS__)
  AND timestamp >= toUnixTimestamp64Nano(now64() - INTERVAL 30 MINUTE)
  AND attributes_string['event.type'] = 'auth.login.failure'
GROUP BY asn
HAVING asn != '' AND ip != '' AND distinct_ips >= 5 AND failed_signins >= 20
```

```bash
# the SQL above is saved as threat/01-authentication/rules/lab-auth-failed-signins-per-asn.sql
npx securenow alerts rules validate <R01_ID> --sql @threat/01-authentication/rules/lab-auth-failed-signins-per-asn.sql --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --json
```

```bash
npx securenow alerts rules create \
  --name "lab-auth: failed sign-ins spread across one network operator (ASN)" \
  --sql @threat/01-authentication/rules/lab-auth-failed-signins-per-asn.sql \
  --apps df7ab010-37ac-4732-88ac-a8ac23afe1a4 --severity high \
  --schedule "*/10 * * * *" --throttle-minutes 9 \
  --category authentication \
  --description "Threat model 01-authentication (A2, A4); test-first" \
  --nlp "failed sign-ins from 5 or more addresses of one network operator (ASN), 20 or more failures in 30 minutes"
# -> created Active in mode=test (detect-only); a failing SQL is rolled back automatically
# add --channel <in-app id>,<new channel id> after AUTH-04 (channels cannot be changed later from the CLI)
```

```bash
npx securenow alerts rules test <R26_ID> --mode dry_run --wait --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --json
# expect: "status": "complete" (resultCount 0 until real or synthetic data exists)
```

**Test:** Cannot be fired with `event send` (TEST-NET IPs have no ASN). Validate with the create-time dry-run and `alerts rules test --mode dry_run`, and confirm client.asn appears in `telemetry fields --source logs` before trusting it.

**Response:** notify only — see the runbook in §12 for the human-approved action.

```bash
# after 3-7 days of real traffic with no unexplained hits — a person decides:
npx securenow alerts rules promote <R26_ID>
```

<a id="rule-r27"></a>
### R27 · lab-auth: sign-in from a new network operator

**🟡 PARTIAL · APP_EVENT · LOW · `test-first`** · threats [C16](#threat-c16) · schedule `*/15 * * * *`, throttle 14 min

- **Fires on:** an account signs in from a network operator (as_org) it has not used in the previous 7 days.
- **Threshold source:** Any new operator for an account with history — conservative start, notify only.
- **Needs (not yet in telemetry):** auth.login.success with userId plus client.as_org (ASN enrichment — unverified for this app).
- **Tag:** test-first, notify-only, severity low: travel and new ISPs are normal.

```sql
-- rules/lab-auth-signin-from-new-network-provider.sql
-- APP_EVENT + ingest enrichment: needs auth.login.success with userId AND client.as_org (events only, when the instance
-- has ASN enrichment). Fires when an account signs in from a network operator it has not used in the previous 7 days
-- (for example a hosting/VPN provider after months of a home ISP). Accounts with no earlier sign-in are ignored.
-- Threshold: any new operator for an account with history. Noisy for travellers: notify only, severity low.
SELECT account, latest_network_operator, ip
FROM
(
  SELECT
    attributes_string['enduser.id'] AS account,
    argMax(attributes_string['client.as_org'], timestamp) AS latest_network_operator,
    max(timestamp) AS t_latest,
    groupUniqArrayIf(attributes_string['client.as_org'], timestamp < toUnixTimestamp64Nano(now64() - INTERVAL 15 MINUTE)) AS earlier_operators,
    argMax(attributes_string['http.client_ip'], timestamp) AS ip
  FROM signoz_logs.distributed_logs_v2
  WHERE resources_string['service.name'] IN (__USER_APP_KEYS__)
    AND timestamp >= toUnixTimestamp64Nano(now64() - INTERVAL 7 DAY)
    AND attributes_string['event.type'] = 'auth.login.success'
    AND attributes_string['client.as_org'] != ''
  GROUP BY account
  HAVING account != '' AND ip != '' AND t_latest >= toUnixTimestamp64Nano(now64() - INTERVAL 15 MINUTE)
)
WHERE length(earlier_operators) > 0 AND NOT has(earlier_operators, latest_network_operator)
```

```bash
# the SQL above is saved as threat/01-authentication/rules/lab-auth-signin-from-new-network-provider.sql
npx securenow alerts rules validate <R01_ID> --sql @threat/01-authentication/rules/lab-auth-signin-from-new-network-provider.sql --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --json
```

```bash
npx securenow alerts rules create \
  --name "lab-auth: sign-in from a new network operator" \
  --sql @threat/01-authentication/rules/lab-auth-signin-from-new-network-provider.sql \
  --apps df7ab010-37ac-4732-88ac-a8ac23afe1a4 --severity low \
  --schedule "*/15 * * * *" --throttle-minutes 14 \
  --category authentication \
  --description "Threat model 01-authentication (C16); test-first" \
  --nlp "an account signing in from a network provider it has not used in the last 7 days"
# -> created Active in mode=test (detect-only); a failing SQL is rolled back automatically
# add --channel <in-app id>,<new channel id> after AUTH-04 (channels cannot be changed later from the CLI)
```

```bash
npx securenow alerts rules test <R27_ID> --mode dry_run --wait --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --json
# expect: "status": "complete" (resultCount 0 until real or synthetic data exists)
```

**Test:** Cannot be fired with `event send` (TEST-NET IPs have no ASN). Validate with the create-time dry-run and `alerts rules test --mode dry_run`.

**Response:** notify only — see the runbook in §12 for the human-approved action.

```bash
# after 3-7 days of real traffic with no unexplained hits — a person decides:
npx securenow alerts rules promote <R27_ID>
```


<a id="instrumentation"></a>
## 8. Instrumentation the detections need

The installed `securenow/events` `track(type, props)` accepts any string type (`node_modules/securenow/events.js:119-151`), so the event names below are allowed — but they are **proposed instrumentation**, not automatic SDK events. Only `session.seen` is emitted by the SDK itself (by `guard()`). Exact file:line placement is in the [code report’s instrumentation section](authentication-code-findings.md#instrumentation).

| Event (proposed unless noted) | Emit where | Key attributes | Consumed by |
| --- | --- | --- | --- |
| `auth.login.failure` | src/app.js:181 (password), 228/249/257 (Google) | auth_method, provider, reason, account_ref, mfa_state, sso_required | [R10](#rule-r10) [R11](#rule-r11) [R12](#rule-r12) [R15](#rule-r15) [R19](#rule-r19) [R24](#rule-r24) [R25](#rule-r25) [R26](#rule-r26) |
| `auth.login.success` | src/app.js:185, 254 | auth_method, provider, account_ref, mfa_state, sso_required, dormant_days (after AUTH-26) | [R12](#rule-r12) [R13](#rule-r13) [R19](#rule-r19) [R20](#rule-r20) [R22](#rule-r22) [R25](#rule-r25) [R27](#rule-r27) |
| `auth.signup` | src/app.js:170; after 244 (Google) | auth_method, provider, outcome=created\|existing, account_ref | [R23](#rule-r23) |
| `auth.logout` | src/app.js:189 | — | — |
| `auth.security.change` | src/app.js:198, 206, 297 | action, outcome, step_up, target_ref, direction | [R18](#rule-r18) [R19](#rule-r19) [R20](#rule-r20) [R21](#rule-r21) |
| `auth.account.link` (reused from the OAuth model) | src/app.js:249 | outcome=rejected, provider, verified_email, join_key, reason, account_ref | [R16](#rule-r16) |
| `api.ratelimit.exceeded` (reused cross-model event) | src/app.js:133 | scope, route, reason, account_ref (account-keyed buckets only) | [R14](#rule-r14) |
| `session.seen` (automatic via guard()) | guard() after src/app.js:101 | session.id = sha256(express session id), enduser.id, IP | [R17](#rule-r17) [R18](#rule-r18) |

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

```js
// src/app.js:181 — failed password sign-in (next to the existing audit row)
emit('auth.login.failure', req, { userId: user?.id, attributes: {
  auth_method: 'password', provider: 'local', reason: user ? 'bad_password' : 'unknown_account',
  account_ref: ref('acct', email), mfa_state: 'none', sso_required: false } });
// src/app.js:185 — successful password sign-in (session already rotated by authenticate())
emit('auth.login.success', req, { userId: user.id, attributes: {
  auth_method: 'password', provider: 'local', account_ref: ref('acct', email), mfa_state: 'none', sso_required: false } });
// ...the other 12 calls are listed with exact lines in the code report.
```

**Privacy rules for every event:** never send a raw email, password, token, session ID or role name. `account_ref` and `target_ref`-style values are keyed HMACs or opaque UUIDs; `session.id` is a SHA-256 of the server-side session ID; the IP is `req.ip` (trusted because Caddy overwrites X-Forwarded-For). Custom attribute names avoid the reserved prefixes `event.`, `enduser.`, `session.`, `http.`, `service.`, `securenow.`, `client.`.


<a id="mitigations"></a>
## 9. Mitigation mechanisms

Commands below are checked against `npx securenow <cmd> --help` and the CLI source in `node_modules/securenow/cli/` (8.12.0). Every one is scoped to lab-auth and environment `test`; every block carries `--duration`. **Route patterns are case-insensitive regexes** because the SDK firewall compares paths exactly while Express also answers `/API/AUTH/LOGIN` and `/api/auth/login/` (F6). After F6 ships you can switch to `--mode exact`.

| # | Mitigation | Command (ready to copy) | Use / scope |
| --- | --- | --- | --- |
| 1 | Firewall (network) | `npx securenow firewall enable --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --env test` · runs inside the SDK (`node -r securenow/register`; `securenow run --firewall-only` without telemetry) · test `npx securenow firewall test-ip 203.0.113.99 --path /api/auth/login --method POST --env test --app df7ab010-37ac-4732-88ac-a8ac23afe1a4` | Known-bad IP feed refreshed hourly (scanners, bots, credential stuffers); legitimate crawlers stay allowed. Included in the SecureNow subscription. No app change beyond the preload. |
| 2 | Instant detection + block (single-request signatures) | Create the traces rule with the CLI, then MCP `securenow_alert_rule_instant_update` (payloads under R05 and R09) | Only for exact signatures: credential-file probes (R05, block after promotion) and multi-hop X-Forwarded-For (R09, notify only). Evaluates HTTP spans only; blocks are skipped in test mode. No pre-built signature rules exist; injection payloads belong to `../06-injection/`. |
| 3 | IP block — global | `npx securenow blocklist add <ip> --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --env test --duration 24h --reason "…"` | Confirmed scanner/attacker, all routes. Without `--duration` the block is permanent. |
| 4 | IP block — route + method | `npx securenow blocklist add <ip> --route '^/[aA][pP][iI]/[aA][uU][tT][hH](/\|$)' --mode regex --method POST --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --env test --duration 24h --reason "…"` | Least collateral: the IP can still load pages. |
| 5 | Reverse / review a block | `npx securenow blocklist unblock <id> --reason "…"` · `blocklist list --approval-status pending` → `blocklist approve <id>` / `reject <id>` | Audit-preserving reversal; human approval for queued blocks. |
| 6 | Rate limit — per IP | `npx securenow ratelimit add <ip> --limit 100 --window 1m --duration 24h --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --env test --reason "…"` | Throttle one abusive client across the app. |
| 7 | Rate limit — per route (all clients) | `npx securenow ratelimit add --route '^/[aA][pP][iI]/[aA][uU][tT][hH]/[rR][eE][gG][iI][sS][tT][eE][rR]/*$' --mode regex --method POST --limit 20 --window 1h --key-by ip --duration 24h --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --env test --reason "…"` (`--key-by global` = one shared bucket) | Counters live in memory per SDK process (one app container here; N instances = N× the limit; a restart resets them). Never an account/target quota. `--key-by` is parsed by 8.12.0 but not listed in `--help`. |
| 8 | Rate limit — route + IP | `npx securenow ratelimit add <ip> --route '^/[aA][pP][iI]/[aA][uU][tT][hH]/[lL][oO][gG][iI][nN]/*$' --mode regex --method POST --limit 5 --window 15m --duration 24h --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --env test` · NL `npx securenow ratelimit from-text "rate limit /api/auth/login to 5 per 15 minutes for 24h" --yes` · test `npx securenow ratelimit test <ip> --path /api/auth/login --method POST --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --env test` | Precise throttle of one client on one route (`--window` accepts s/m/h). The natural-language form produces an exact path — prefer the regex form until F6. |
| 9 | Proof-of-work challenge | `npx securenow challenge add <ip> --route / --mode prefix --method GET --difficulty 16 --clearance 30m --duration 24h --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --env test --reason "…"` (add `--escalate-to-block --fail-threshold 10 --block-ttl-hours 24` if wanted) · test `npx securenow challenge test <ip> --path / --method GET --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --env test` | Bots on shared/NAT egress. **GET pages only for this lab** until F15: on `fetch()` the SDK answers JSON 403 `challenge_required`, which the SPA cannot solve. Difficulty 4–28; clearance bound to IP + user agent. Not available through MCP. |
| 10 | Risk-scored auto-block | Already active account-wide: SecureNow Default Elevated/High/Critical (85–89 → 24 h, 90–94 → 72 h, ≥ 95 → 168 h) · preview `npx securenow automation dry-run <id>` | Hands-off global blocks for high investigation scores. Acts only on prod-mode rules of severity ≥ medium (so test-mode lab rules are untouched). |
| 11 | Rule-bound automation | AUTO-A … AUTO-G under §7 (`automation create … --app … --env test --status disabled`) · `automation dry-run <id>` · enable `automation update <id> --status active` | One named detection → one scoped action. Actions: addToBlocklist, addToRateLimit, requireCaptcha. Always set pathPattern and ttlHours. **Cannot revoke sessions or notify.** |
| 12 | Session / user revocation (manual) | `npx securenow revoke session <session.id> --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --env test --duration 24h --reason "…"` · `revoke user <enduser.id> …` · `revoke list` · `revoke restore <id> --reason "…"` | Session theft / takeover. Enforced only where `guard()` runs (AUTH-09). `--duration` without a unit = hours; default 7d. CLI-only. **In this run `revoke list` returned HTTP 404** — verify before relying on it (AUTH-17). |
| 13 | Trusted IP (suppress) | `npx securenow trusted add <ip> --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --env test --label "Uptime monitor"` | Known-good infra only — suppresses detection AND mitigation. Note: 4 global trusted entries already apply to lab-auth (SecureNow infrastructure and two crawler ranges). |
| 14 | Allowlist (deny-by-default) | `npx securenow allowlist add <ip> --app … --env test --label "…" --reason "…"` | ⚠️ Once any entry exists only listed IPs reach the app. **Never for this public lab.** |
| 15 | False-positive exclusion | `npx securenow alerts rules exclusions <RULE_ID> add --conditions '[…]' --match-mode all --reason "…"` · from a notification `npx securenow fp mark <notification-id> <ip> --rule-scope this_rule` · account-wide `fp create --conditions '[…]' --rule-scope any_rule --reason "…"` (preview `fp dry-run`) | Condition fields: path, method, user_agent, status_code, request_body, request_headers (HTTP fields). For event rules, tighten the SQL or use trusted instead. |
| 16 | Triage & ongoing operation | `npx securenow notifications list --limit 20` · `human list` → `human show <row>` → `human block <row> --yes --reason "…"` / `human fp <row>` / `human report <row> --outcome …` · runbooks `npx securenow agent prompt patrol\|alert-review\|human-queue` | How a person (or their own agent) works these alerts. Test-mode notifications land here with no mitigation. |
| 17 | App / config / code fix | Described in the [code-findings report](authentication-code-findings.md#fixes), never auto-applied | The actual fix. SecureNow contains; the fix removes. |

**MCP equivalents** (writes need `confirm: true` and a `reason`): blocklist → `securenow_blocklist_add` / `_unblock`; rate limits → `securenow_rate_limit_create_from_text` / `_remove`; automations → `securenow_automation_rule_create` / `_update` / `_dry_run`; trusted → `securenow_trusted_add`; rule exclusions → `securenow_alert_rule_exclusion_add`; instant config → `securenow_alert_rule_instant_update`; human queue → `securenow_human_action_block` / `_false_positive`. **No MCP path** for: creating a rule, test→prod promotion, challenges, session revocation, sending events.

**Choosing per threat.** Exact single-request signature → instant detection (+ block once promoted). Probable bot on shared egress → challenge (GET pages only here). Noisy, legit-mixed traffic (guessing, enumeration, floods, sign-up counts) → rate limit via a rule-bound automation, test mode first. Session compromise → revoke, never an IP block. Many IPs → one account → notify + app per-account control (F3); at most rate-limit/challenge the contributors. Known-good noise → trusted / exclusion. Always the narrowest route/method/IP/duration; on NAT/CGNAT prefer challenge or rate limit over a block; always pair with the app fix.

### Auth response recipes (adapted to this lab)

| Detection family | Default SecureNow response | Never |
| --- | --- | --- |
| Single-IP guessing / stuffing (R01, R02, R10) | AUTO-A: 24 h sign-in rate limit (5 / 15 min) on the case-insensitive login regex; AUTO-B: 24 h POST /api/auth/* block only with riskScore ≥ 90. (requireCaptcha is not the default here: the SPA cannot complete a challenge on fetch() — F15.) | Global permanent block |
| Distributed attack on one account (R06, R11, R14, R26) | Notify; a person rate-limits contributing IPs or the network block (MC-02/MC-03); app device-trust fix (F3) | Lock or block the victim account |
| Paid-send abuse / spend tripwire / conversion collapse | N/A — the lab sends no auth messages. Re-run this model when F4/F5 add email. | — |
| Session theft, sessions surviving a change (R17, R18, R20) | `revoke session` (or `revoke user` when confirmed) + owner changes password; app adds sign-out-everywhere (F7) | IP block as the only response |
| Multi-step takeover / security change (R12, R19, R21) | `revoke user` after human review; restore password/role through the operator; notify the owner out of band | Silent auto-revert |
| Single-request signatures (R05 instant, R09) | Instant detection; R05 block 24 h after promotion; R09 notify only | Block before a week of clean test-mode history; block on R09 (would hit every client if the proxy changed) |
| Link refusals, dormant/new-network sign-ins, coverage drift (R16, R22, R25, R27) | Notify only | Any automated action |
| Scanning, session minting, CSRF floods, registration probing, Google callback abuse (R05, R03, R04, R23, R15) | AUTO-E (GET-page challenge), AUTO-C/AUTO-D/AUTO-G/AUTO-F (route-scoped rate limits), all 24 h | Unscoped (all-route) automated blocks |
| Global anomalies (R07, R08) | Notify; a person applies a time-boxed global route limit (MC-04/MC-05) | Auto-block every contributor |

**Victim safety.** A targeted account (R11, R14) is never the actor: throttle the sources, keep the owner’s path open (F3’s device cookie), and tell the owner through a channel they already verified (none exists yet — F4/F5). On uncertain or shared source identity prefer scoped rate limits and human review. A global anomaly (R07/R08) degrades gracefully with a time-boxed route limit; it never auto-blocks every contributor.

### Per-threat ready-to-copy mitigation commands

<a id="mc-mc-01"></a>
#### MC-01 · Firewall known-bad IP feed for the lab’s test environment — for [B8](#threat-b8), [A3](#threat-a3)

```bash
npx securenow firewall enable --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --env test
npx securenow firewall test-ip 203.0.113.99 --path /api/auth/login --method POST --env test --app df7ab010-37ac-4732-88ac-a8ac23afe1a4
```

**Reverse:** 

```bash
npx securenow firewall disable --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --env test
```

<a id="mc-mc-02"></a>
#### MC-02 · Rate-limit one guessing IP on the sign-in route (case-insensitive) — for [A1](#threat-a1), [A3](#threat-a3)

```bash
npx securenow ratelimit add 203.0.113.99 --route '^/[aA][pP][iI]/[aA][uU][tT][hH]/[lL][oO][gG][iI][nN]/*$' --mode regex --method POST --limit 5 --window 15m --duration 24h --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --env test --reason "lab-auth: sign-in guessing"
npx securenow ratelimit test 203.0.113.99 --path /api/auth/login --method POST --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --env test
```

**Reverse:** 

```bash
npx securenow ratelimit list --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --env test
npx securenow ratelimit remove <RATE_LIMIT_ID> --reason "lab-auth: reviewed, false positive"
```

<a id="mc-mc-03"></a>
#### MC-03 · Rate-limit a whole network block on the sign-in route — for [A2](#threat-a2), [A4a](#threat-a4a)

```bash
npx securenow ratelimit add 203.0.113.0/24 --route '^/[aA][pP][iI]/[aA][uU][tT][hH]/[lL][oO][gG][iI][nN]/*$' --mode regex --method POST --limit 5 --window 15m --duration 24h --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --env test --reason "lab-auth: distributed sign-in failures"
```

**Reverse:** 

```bash
npx securenow ratelimit remove <RATE_LIMIT_ID> --reason "lab-auth: attack over"
```

<a id="mc-mc-04"></a>
#### MC-04 · Temporary app-wide cap on registrations during a sign-up surge — for [H40](#threat-h40)

```bash
npx securenow ratelimit add --route '^/[aA][pP][iI]/[aA][uU][tT][hH]/[rR][eE][gG][iI][sS][tT][eE][rR]/*$' --mode regex --method POST --limit 20 --window 1h --key-by global --duration 24h --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --env test --reason "lab-auth: registration surge"
# --key-by is accepted by securenow 8.12.0 although --help does not list it; counters live in memory per SDK process (one app container here)
```

**Reverse:** 

```bash
npx securenow ratelimit remove <RATE_LIMIT_ID> --reason "lab-auth: surge over"
```

<a id="mc-mc-05"></a>
#### MC-05 · Temporary app-wide cap on password-hashing routes during a load spike — for [J46](#threat-j46)

```bash
npx securenow ratelimit add --route '^/[aA][pP][iI]/[aA][uU][tT][hH]/([lL][oO][gG][iI][nN]|[rR][eE][gG][iI][sS][tT][eE][rR]|[pP][aA][sS][sS][wW][oO][rR][dD])/*$' --mode regex --method POST --limit 60 --window 1m --key-by global --duration 1h --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --env test --reason "lab-auth: hashing load spike"
```

**Reverse:** 

```bash
npx securenow ratelimit remove <RATE_LIMIT_ID> --reason "lab-auth: load normal"
```

<a id="mc-mc-06"></a>
#### MC-06 · Route-scoped 24-hour block (POST to /api/auth/* only) — for [A1](#threat-a1), [A3](#threat-a3), [B6](#threat-b6)

```bash
npx securenow blocklist add 203.0.113.99 --route '^/[aA][pP][iI]/[aA][uU][tT][hH](/|$)' --mode regex --method POST --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --env test --duration 24h --reason "lab-auth: confirmed sign-in abuse"
```

**Reverse:** 

```bash
npx securenow blocklist list --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --env test --status active
npx securenow blocklist unblock <BLOCK_ID> --reason "lab-auth: reviewed"
```

<a id="mc-mc-07"></a>
#### MC-07 · Global 24-hour block for a confirmed scanner — for [B8](#threat-b8)

```bash
npx securenow blocklist add 203.0.113.99 --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --env test --duration 24h --reason "lab-auth: confirmed auth-surface scanner"
```

**Reverse:** 

```bash
npx securenow blocklist unblock <BLOCK_ID> --reason "lab-auth: reviewed"
```

<a id="mc-mc-08"></a>
#### MC-08 · Proof-of-work challenge on page loads for one IP (shared/NAT egress) — for [B8](#threat-b8), [A1](#threat-a1)

```bash
npx securenow challenge add 203.0.113.99 --route / --mode prefix --method GET --difficulty 16 --clearance 30m --duration 24h --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --env test --reason "lab-auth: probable bot on shared egress"
npx securenow challenge test 203.0.113.99 --path / --method GET --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --env test
# GET only until F15 ships: the SPA cannot solve a challenge returned to fetch() on /api/*
```

**Reverse:** 

```bash
npx securenow challenge list --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --env test
npx securenow challenge remove <CHALLENGE_ID> --reason "lab-auth: reviewed"
```

<a id="mc-mc-09"></a>
#### MC-09 · Revoke one stolen session, or every session of a confirmed-compromised user — for [C9](#threat-c9), [C11](#threat-c11), [C11a](#threat-c11a), [C16a](#threat-c16a), [C16c](#threat-c16c)

```bash
npx securenow revoke session <session.id from the notification> --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --env test --duration 24h --reason "lab-auth: session used from a second network"
npx securenow revoke user <enduser.id from the notification> --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --env test --duration 24h --reason "lab-auth: confirmed takeover"
# enforced only where securenow/sessions guard() runs (TODO AUTH-09); in this run "revoke list" returned HTTP 404 — verify before relying on it (AUTH-17)
```

**Reverse:** 

```bash
npx securenow revoke list --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --json
npx securenow revoke restore <REVOCATION_ID> --reason "lab-auth: owner verified"
```

<a id="mc-mc-10"></a>
#### MC-10 · Trust a known-good monitor (suppresses detection AND mitigation) — for [J47](#threat-j47), [B8](#threat-b8)

```bash
npx securenow trusted add 198.51.100.200 --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --env test --label "lab-auth uptime monitor"
# never trust the presenter's own IP during a recording — it would hide the demo
```

**Reverse:** 

```bash
npx securenow trusted list --json
npx securenow trusted remove <TRUSTED_ID>
```

<a id="mc-mc-11"></a>
#### MC-11 · Exclude a known-good client from one rule only — for [J47](#threat-j47)

```bash
npx securenow alerts rules exclusions <R03_ID> add --conditions '[{"field":"path","operator":"equals","value":"/api/me"},{"field":"user_agent","operator":"contains","value":"UptimeRobot"}]' --match-mode all --reason "lab-auth: uptime monitor polls /api/me without cookies"
```

**Reverse:** 

```bash
npx securenow alerts rules exclusions <R03_ID> list
npx securenow alerts rules exclusions <R03_ID> delete <EXCLUSION_ID>
```

<a id="mc-mc-12"></a>
#### MC-12 · Review queued automation blocks before they apply — for [M63](#threat-m63)

```bash
npx securenow blocklist list --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --env test --approval-status pending
npx securenow blocklist approve <PENDING_BLOCK_ID> --reason "lab-auth: confirmed"
npx securenow blocklist reject <PENDING_BLOCK_ID> --reason "lab-auth: shared NAT, not the attacker"
```

**Reverse:** `blocklist unblock <id>` for an approved block.

<a id="mc-mc-13"></a>
#### MC-13 · Work the alerts these rules create — for [A1](#threat-a1), [C9](#threat-c9), [M63](#threat-m63)

```bash
npx securenow notifications list --limit 20
npx securenow human list --search lab-auth
npx securenow human show <ROW>
npx securenow human fp <ROW> --reason "lab-auth: presenter test traffic"
```

**Reverse:** —

### What SecureNow cannot do

- Enforce per-account, per-target or per-device quotas — rate limits key only by IP or one global bucket, in memory per SDK process.
- Revoke sessions automatically — revocation is manual, CLI-only, and enforced only where `guard()` runs (and the CLI path returned 404 in this run).
- Send notifications from automations — automations can only block, rate-limit or challenge.
- Normalize request paths in firewall rules — scope with the case-insensitive regexes above until F6.
- See request bodies, passwords, response cookies, hash parameters or Google’s control plane.


<a id="plan"></a>
## 10. Implementation plan (copy-paste, ordered)

The command-oriented expansion of the TODO board, for bash/zsh (Git Bash on Windows). Run from the lab-auth root. Steps ② and ⑨ are code changes described in the code report.

```bash
export MSYS_NO_PATHCONV=1        # Git Bash on Windows: stop "/api/..." arguments being rewritten as paths
APP=df7ab010-37ac-4732-88ac-a8ac23afe1a4
RULES=threat/01-authentication/rules
snid() { node -e "let t='';process.stdin.on('data',d=>t+=d).on('end',()=>{const j=JSON.parse(t);const r=j.alertRule||j.rule||j;console.log(r.id||r._id||'')})"; }
npx securenow version            # expect securenow v8.12.0
npx securenow whoami
```

#### ① Firewall for env test + (no existing lab rules to fix with set-sql)

```bash
npx securenow firewall enable --app $APP --env test
npx securenow firewall status --app $APP --env test
# SQL lint: 0 of the account's rules cover lab-auth, so no "alerts rules set-sql" fix is needed for this app.
```

#### ② Instrumentation (AUTH-01, AUTH-09) — code changes, see the code report

```bash
npm install --save-exact securenow@8.12.0
npx securenow app connect            # pick lab-auth; then set capture.body/multipart=false and runtime.deploymentEnvironment="test"
npx securenow env --json             # verify before the first instrumented start
node -r securenow/register src/server.js
# after deploying the track()/guard() bridge:
npx securenow telemetry fields --app $APP --since 24h --source all --env test --json
```

#### ③ Baselines (after 3–7 days of traffic; needs one lab rule as host — run after ④ for R01)

```bash
npx securenow alerts rules validate "$R01" --sql @$RULES/_baseline-auth-posts.sql --app $APP --json
```

#### ④ Create the rules (all start Active in test mode)

```bash
R01=$(npx securenow alerts rules create --name "lab-auth: repeated failed sign-ins per IP" \
  --sql @$RULES/lab-auth-failed-signins-per-ip.sql --apps $APP --severity high \
  --schedule "*/5 * * * *" --throttle-minutes 4 --category authentication \
  --description "Threat model 01-authentication (A1); test-first" \
  --nlp "one IP with 10 or more failed password sign-ins (HTTP 401 on POST /api/auth/login) in 15 minutes" --json | snid); echo "R01=$R01"
R02=$(npx securenow alerts rules create --name "lab-auth: auth requests past the native limit per IP" \
  --sql @$RULES/lab-auth-native-limit-429-per-ip.sql --apps $APP --severity medium \
  --schedule "*/5 * * * *" --throttle-minutes 4 --category authentication \
  --description "Threat model 01-authentication (A1, S1); test-first" \
  --nlp "one IP that keeps calling /api/auth routes after the app answered 429 (5 or more throttled requests in 15 minutes)" --json | snid); echo "R02=$R02"
R03=$(npx securenow alerts rules create --name "lab-auth: anonymous session minting per IP" \
  --sql @$RULES/lab-auth-anonymous-session-minting-per-ip.sql --apps $APP --severity medium \
  --schedule "*/5 * * * *" --throttle-minutes 4 --category authentication \
  --description "Threat model 01-authentication (J47); test-first" \
  --nlp "one IP creating 60 or more brand-new anonymous sessions in 15 minutes by calling the session endpoints without a cookie" --json | snid); echo "R03=$R03"
R04=$(npx securenow alerts rules create --name "lab-auth: CSRF-rejected API mutations per IP" \
  --sql @$RULES/lab-auth-csrf-rejected-mutations-per-ip.sql --apps $APP --severity medium \
  --schedule "*/5 * * * *" --throttle-minutes 4 --category authentication \
  --description "Threat model 01-authentication (C13, S1); test-first" \
  --nlp "one IP sending 20 or more API writes that fail the CSRF check (no token or wrong Origin) in 15 minutes" --json | snid); echo "R04=$R04"
R05=$(npx securenow alerts rules create --name "lab-auth: auth-surface probing per IP" \
  --sql @$RULES/lab-auth-auth-surface-probing-per-ip.sql --apps $APP --severity medium \
  --schedule "*/5 * * * *" --throttle-minutes 4 --category authentication \
  --description "Threat model 01-authentication (B8); test-first" \
  --nlp "one IP probing for credential files, git folders or admin panels (3 or more) or collecting 30 or more not-found answers in 15 minutes" --json | snid); echo "R05=$R05"
R06=$(npx securenow alerts rules create --name "lab-auth: failed sign-ins spread across one network" \
  --sql @$RULES/lab-auth-failed-signins-per-network.sql --apps $APP --severity high \
  --schedule "*/10 * * * *" --throttle-minutes 9 --category authentication \
  --description "Threat model 01-authentication (A2, A4a, M62); test-first" \
  --nlp "failed sign-ins spread over 4 or more addresses of one network block (/24 or /64), 15 or more failures in 30 minutes" --json | snid); echo "R06=$R06"
R07=$(npx securenow alerts rules create --name "lab-auth: sign-in hashing load spike (all IPs)" \
  --sql @$RULES/lab-auth-signin-load-spike-global.sql --apps $APP --severity high \
  --schedule "*/5 * * * *" --throttle-minutes 4 --category authentication \
  --description "Threat model 01-authentication (J46); test-first" \
  --nlp "app-wide spike of password-hashing requests (200+ in 5 minutes) or slow sign-ins (p95 2 seconds or more), listing the top contributing IPs" --json | snid); echo "R07=$R07"
R08=$(npx securenow alerts rules create --name "lab-auth: registration volume spike (all IPs)" \
  --sql @$RULES/lab-auth-registration-spike-global.sql --apps $APP --severity medium \
  --schedule "*/15 * * * *" --throttle-minutes 14 --category authentication \
  --description "Threat model 01-authentication (H40, J47); test-first" \
  --nlp "30 or more registrations across all IPs in one hour, listing the top contributing IPs" --json | snid); echo "R08=$R08"
R09=$(npx securenow alerts rules create --name "lab-auth: forwarded client-IP chain anomaly" \
  --sql @$RULES/lab-auth-forwarded-ip-chain-anomaly.sql --apps $APP --severity high \
  --schedule "*/5 * * * *" --throttle-minutes 4 --category authentication \
  --description "Threat model 01-authentication (I45a, M62); prod-ready" \
  --nlp "any request where the client IP chain shows a spoofed or multi-hop X-Forwarded-For, or the request reached the app without the reverse proxy" --json | snid); echo "R09=$R09"
R10=$(npx securenow alerts rules create --name "lab-auth: failed sign-ins across multiple accounts per IP" \
  --sql @$RULES/lab-auth-failed-signins-multiple-accounts-per-ip.sql --apps $APP --severity high \
  --schedule "*/5 * * * *" --throttle-minutes 4 --category authentication \
  --description "Threat model 01-authentication (A1, A3, A4, B7); test-first" \
  --nlp "one IP failing password sign-in against 5 or more different accounts (10 or more failures) in 15 minutes" --json | snid); echo "R10=$R10"
R11=$(npx securenow alerts rules create --name "lab-auth: one account targeted from multiple IPs" \
  --sql @$RULES/lab-auth-one-account-multiple-ips.sql --apps $APP --severity high \
  --schedule "*/10 * * * *" --throttle-minutes 9 --category authentication \
  --description "Threat model 01-authentication (A2, H41); test-first" \
  --nlp "one account receiving 12 or more failed sign-ins from 5 or more different IPs in 30 minutes" --json | snid); echo "R11=$R11"
R12=$(npx securenow alerts rules create --name "lab-auth: successful sign-in after repeated failures" \
  --sql @$RULES/lab-auth-signin-after-failures.sql --apps $APP --severity high \
  --schedule "*/10 * * * *" --throttle-minutes 9 --category authentication \
  --description "Threat model 01-authentication (C16a); test-first" \
  --nlp "an account that signs in successfully right after 5 or more failed attempts within 30 minutes" --json | snid); echo "R12=$R12"
R13=$(npx securenow alerts rules create --name "lab-auth: one IP signs in to multiple accounts" \
  --sql @$RULES/lab-auth-one-ip-signs-into-multiple-accounts.sql --apps $APP --severity medium \
  --schedule "*/15 * * * *" --throttle-minutes 14 --category authentication \
  --description "Threat model 01-authentication (A3, C16a); test-first" \
  --nlp "one IP that successfully signs in to 3 or more different accounts within an hour" --json | snid); echo "R13=$R13"
R14=$(npx securenow alerts rules create --name "lab-auth: per-account sign-in limit held full" \
  --sql @$RULES/lab-auth-account-limit-pressure.sql --apps $APP --severity medium \
  --schedule "*/5 * * * *" --throttle-minutes 4 --category authentication \
  --description "Threat model 01-authentication (H41); test-first" \
  --nlp "one account kept at its sign-in rate limit by requests from 2 or more IPs in 15 minutes (someone locking the owner out)" --json | snid); echo "R14=$R14"
R15=$(npx securenow alerts rules create --name "lab-auth: Google sign-in callback failures per IP" \
  --sql @$RULES/lab-auth-google-callback-failures-per-ip.sql --apps $APP --severity medium \
  --schedule "*/5 * * * *" --throttle-minutes 4 --category authentication \
  --description "Threat model 01-authentication (D19, G32, G33, G36a); test-first" \
  --nlp "one IP with 5 or more failed Google sign-in callbacks (bad state, replayed code or rejected token) in 15 minutes" --json | snid); echo "R15=$R15"
R16=$(npx securenow alerts rules create --name "lab-auth: Google sign-in refused for an existing password account" \
  --sql @$RULES/lab-auth-google-link-refusals.sql --apps $APP --severity low \
  --schedule "*/15 * * * *" --throttle-minutes 14 --category authentication \
  --description "Threat model 01-authentication (B8a, G34, G36c, H40a); test-first" \
  --nlp "Google sign-in refused because a password account already uses that email: 3 or more from one IP or 5 or more app-wide within an hour" --json | snid); echo "R16=$R16"
R17=$(npx securenow alerts rules create --name "lab-auth: account active from several networks" \
  --sql @$RULES/lab-auth-account-on-several-networks.sql --apps $APP --severity medium \
  --schedule "*/15 * * * *" --throttle-minutes 14 --category authentication \
  --description "Threat model 01-authentication (C9, C12); test-first" \
  --nlp "one account whose sessions are seen from 3 or more different IPs within an hour" --json | snid); echo "R17=$R17"
R18=$(npx securenow alerts rules create --name "lab-auth: session still used after password change" \
  --sql @$RULES/lab-auth-session-survives-password-change.sql --apps $APP --severity high \
  --schedule "*/15 * * * *" --throttle-minutes 14 --category authentication \
  --description "Threat model 01-authentication (C11a); prod-ready" \
  --nlp "a session that existed before a password change is still being used more than 5 minutes after the change" --json | snid); echo "R18=$R18"
R19=$(npx securenow alerts rules create --name "lab-auth: takeover sequence (failures, sign-in, security change)" \
  --sql @$RULES/lab-auth-takeover-sequence.sql --apps $APP --severity high \
  --schedule "*/15 * * * *" --throttle-minutes 14 --category authentication \
  --description "Threat model 01-authentication (C16c, H39a, H40c); test-first" \
  --nlp "an account with a failed sign-in, then a successful sign-in, then a password or role change, all within one hour" --json | snid); echo "R19=$R19"
R20=$(npx securenow alerts rules create --name "lab-auth: security change from a different network than sign-in" \
  --sql @$RULES/lab-auth-security-change-from-other-network.sql --apps $APP --severity medium \
  --schedule "*/15 * * * *" --throttle-minutes 14 --category authentication \
  --description "Threat model 01-authentication (C9, C16d, L54a); test-first" \
  --nlp "a password or role change made from a different IP than the sign-in of the same session" --json | snid); echo "R20=$R20"
R21=$(npx securenow alerts rules create --name "lab-auth: post-sign-in security changes needing review" \
  --sql @$RULES/lab-auth-post-signin-security-changes.sql --apps $APP --severity high \
  --schedule "*/15 * * * *" --throttle-minutes 14 --category authentication \
  --description "Threat model 01-authentication (H39a, L53, L54a); test-first" \
  --nlp "privilege elevation, an admin changing 3 or more accounts, or 3 or more wrong current-password attempts within an hour" --json | snid); echo "R21=$R21"
R22=$(npx securenow alerts rules create --name "lab-auth: sign-in to a dormant account" \
  --sql @$RULES/lab-auth-dormant-account-signin.sql --apps $APP --severity low \
  --schedule "*/15 * * * *" --throttle-minutes 14 --category authentication \
  --description "Threat model 01-authentication (C16b, H40c); test-first" \
  --nlp "a successful sign-in to an account that had not signed in for 90 days or more" --json | snid); echo "R22=$R22"
R23=$(npx securenow alerts rules create --name "lab-auth: registration probing per IP" \
  --sql @$RULES/lab-auth-registration-probing-per-ip.sql --apps $APP --severity medium \
  --schedule "*/15 * * * *" --throttle-minutes 14 --category authentication \
  --description "Threat model 01-authentication (B6, B7, G36, H40, H40a); test-first" \
  --nlp "one IP registering 3 or more already-registered emails, or creating 5 or more accounts, within an hour" --json | snid); echo "R23=$R23"
R24=$(npx securenow alerts rules create --name "lab-auth: auth event integrity" \
  --sql @$RULES/lab-auth-event-integrity.sql --apps $APP --severity medium \
  --schedule "*/15 * * * *" --throttle-minutes 14 --category authentication \
  --description "Threat model 01-authentication (M61); test-first" \
  --nlp "auth events that look forged, replayed or broken: duplicate request ids, missing auth_method, or future timestamps" --json | snid); echo "R24=$R24"
R25=$(npx securenow alerts rules create --name "lab-auth: auth event coverage drift" \
  --sql @$RULES/lab-auth-event-coverage-drift.sql --apps $APP --severity low \
  --schedule "*/15 * * * *" --throttle-minutes 14 --category authentication \
  --description "Threat model 01-authentication (M55); test-first" \
  --nlp "password sign-ins are traced but their auth events are missing (event bridge broken)" --json | snid); echo "R25=$R25"
R26=$(npx securenow alerts rules create --name "lab-auth: failed sign-ins spread across one network operator (ASN)" \
  --sql @$RULES/lab-auth-failed-signins-per-asn.sql --apps $APP --severity high \
  --schedule "*/10 * * * *" --throttle-minutes 9 --category authentication \
  --description "Threat model 01-authentication (A2, A4); test-first" \
  --nlp "failed sign-ins from 5 or more addresses of one network operator (ASN), 20 or more failures in 30 minutes" --json | snid); echo "R26=$R26"
R27=$(npx securenow alerts rules create --name "lab-auth: sign-in from a new network operator" \
  --sql @$RULES/lab-auth-signin-from-new-network-provider.sql --apps $APP --severity low \
  --schedule "*/15 * * * *" --throttle-minutes 14 --category authentication \
  --description "Threat model 01-authentication (C16); test-first" \
  --nlp "an account signing in from a network provider it has not used in the last 7 days" --json | snid); echo "R27=$R27"
```

#### ⑤ Instant conditions via MCP (R05 dotfile probes, R09 forwarding chain)

Use the JSON payloads under R05 and R09 in §7 with `securenow_alert_rule_get` → `securenow_alert_rule_instant_update` (`dryRun: true` first).

#### ⑥ Rule-bound automations (created disabled)

```bash
# AUTO-A
npx securenow automation create --name "lab-auth: rate-limit sign-in guessing" \
  --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --env test \
  --conditions '[{"field":"alertName","operator":"in","value":["lab-auth: repeated failed sign-ins per IP","lab-auth: auth requests past the native limit per IP","lab-auth: failed sign-ins across multiple accounts per IP"]}]' \
  --actions '[{"type":"addToRateLimit","config":{"pathPattern":"^/[aA][pP][iI]/[aA][uU][tT][hH]/[lL][oO][gG][iI][nN]/*$","pathMatchMode":"regex","method":"POST","limit":5,"windowSeconds":900,"keyBy":"ip","ttlHours":24,"reason":"lab-auth sign-in guessing"}}]' \
  --status disabled
# reverse: npx securenow ratelimit list --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --env test   # find the rule id, then: npx securenow ratelimit remove <id> --reason "false positive"

# AUTO-B
npx securenow automation create --name "lab-auth: block high-risk sign-in abuse on auth routes" \
  --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --env test \
  --conditions '[{"field":"alertName","operator":"in","value":["lab-auth: repeated failed sign-ins per IP","lab-auth: auth requests past the native limit per IP","lab-auth: failed sign-ins across multiple accounts per IP"]},{"field":"riskScore","operator":"gte","value":90}]' \
  --actions '[{"type":"addToBlocklist","config":{"pathPattern":"^/[aA][pP][iI]/[aA][uU][tT][hH](/|$)","pathMatchMode":"regex","method":"POST","ttlHours":24,"reason":"lab-auth high-risk sign-in abuse"}}]' \
  --logic AND \
  --status disabled
# reverse: npx securenow blocklist list --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --env test --status active   # then: npx securenow blocklist unblock <id> --reason "false positive"

# AUTO-C
npx securenow automation create --name "lab-auth: rate-limit anonymous session minting" \
  --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --env test \
  --conditions '[{"field":"alertName","operator":"eq","value":"lab-auth: anonymous session minting per IP"}]' \
  --actions '[{"type":"addToRateLimit","config":{"pathPattern":"^/[aA][pP][iI]/([mM][eE]|[aA][uU][tT][hH]/([sS][eE][sS][sS][iI][oO][nN]|[cC][sS][rR][fF]))/*$","pathMatchMode":"regex","method":"GET","limit":30,"windowSeconds":900,"keyBy":"ip","ttlHours":24,"reason":"lab-auth session minting"}}]' \
  --status disabled
# reverse: npx securenow ratelimit list --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --env test   # then: npx securenow ratelimit remove <id> --reason "false positive"

# AUTO-D
npx securenow automation create --name "lab-auth: rate-limit rejected API mutations" \
  --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --env test \
  --conditions '[{"field":"alertName","operator":"eq","value":"lab-auth: CSRF-rejected API mutations per IP"}]' \
  --actions '[{"type":"addToRateLimit","config":{"pathPattern":"^/[aA][pP][iI](/|$)","pathMatchMode":"regex","method":"POST","limit":30,"windowSeconds":900,"keyBy":"ip","ttlHours":24,"reason":"lab-auth rejected mutation burst"}}]' \
  --status disabled
# reverse: npx securenow ratelimit list --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --env test   # then: npx securenow ratelimit remove <id> --reason "false positive"

# AUTO-E
npx securenow automation create --name "lab-auth: challenge auth-surface scanners on page loads" \
  --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --env test \
  --conditions '[{"field":"alertName","operator":"eq","value":"lab-auth: auth-surface probing per IP"}]' \
  --actions '[{"type":"requireCaptcha","config":{"pathPattern":"/","pathMatchMode":"prefix","method":"GET","difficulty":16,"clearanceTtlSeconds":1800,"ttlHours":24,"reason":"lab-auth auth-surface scanning"}}]' \
  --status disabled
# reverse: npx securenow challenge list --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --env test   # then: npx securenow challenge remove <id> --reason "false positive"

# AUTO-F
npx securenow automation create --name "lab-auth: rate-limit Google sign-in callback abuse" \
  --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --env test \
  --conditions '[{"field":"alertName","operator":"eq","value":"lab-auth: Google sign-in callback failures per IP"}]' \
  --actions '[{"type":"addToRateLimit","config":{"pathPattern":"^/[aA][pP][iI]/[aA][uU][tT][hH]/[gG][oO][oO][gG][lL][eE]","pathMatchMode":"regex","method":"GET","limit":10,"windowSeconds":900,"keyBy":"ip","ttlHours":24,"reason":"lab-auth Google callback abuse"}}]' \
  --status disabled
# reverse: npx securenow ratelimit list --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --env test   # then: npx securenow ratelimit remove <id> --reason "false positive"

# AUTO-G
npx securenow automation create --name "lab-auth: rate-limit registration probing" \
  --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --env test \
  --conditions '[{"field":"alertName","operator":"eq","value":"lab-auth: registration probing per IP"}]' \
  --actions '[{"type":"addToRateLimit","config":{"pathPattern":"^/[aA][pP][iI]/[aA][uU][tT][hH]/[rR][eE][gG][iI][sS][tT][eE][rR]/*$","pathMatchMode":"regex","method":"POST","limit":3,"windowSeconds":3600,"keyBy":"ip","ttlHours":24,"reason":"lab-auth registration probing"}}]' \
  --status disabled
# reverse: npx securenow ratelimit list --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --env test   # then: npx securenow ratelimit remove <id> --reason "false positive"
```

#### ⑦ Synthetic tests + dry-runs

```bash
# R10
for i in $(seq 1 11); do npx securenow event send auth.login.failure --env test --ip 203.0.113.10 --attrs auth_method=password,provider=local,reason=bad_password,account_ref=test-acct-$((i % 6)),test=true; done
# R11
for i in $(seq 1 13); do npx securenow event send auth.login.failure --env test --ip 198.51.100.$(( (i % 6) + 1 )) --attrs auth_method=password,provider=local,reason=bad_password,account_ref=test-victim,test=true; done
# R12
for i in $(seq 1 5); do npx securenow event send auth.login.failure --env test --ip 203.0.113.20 --attrs auth_method=password,provider=local,reason=bad_password,account_ref=test-acct-seq,test=true; done
npx securenow event send auth.login.success --env test --user test-user-seq --session test-sess-seq --ip 203.0.113.21 --attrs auth_method=password,provider=local,account_ref=test-acct-seq,mfa_state=none,test=true
# R13
for i in 1 2 3; do npx securenow event send auth.login.success --env test --user test-user-$i --session test-s-$i --ip 203.0.113.30 --attrs auth_method=password,provider=local,account_ref=test-acct-$i,mfa_state=none,test=true; done
# R14
for ip in 203.0.113.40 203.0.113.41 203.0.113.40; do npx securenow event send api.ratelimit.exceeded --env test --ip $ip --attrs scope=login-account,route=/api/auth/login,reason=fixed_window,account_ref=test-victim,test=true; done
# R15
for i in $(seq 1 5); do npx securenow event send auth.login.failure --env test --ip 203.0.113.50 --attrs auth_method=oauth,provider=google,reason=invalid_callback,test=true; done
# R16
for i in 1 2 3; do npx securenow event send auth.account.link --env test --ip 203.0.113.60 --attrs outcome=rejected,provider=google,verified_email=true,join_key=iss_sub,reason=existing_email_other_method,account_ref=test-acct-$i,test=true; done
# R17
for ip in 203.0.113.70 198.51.100.70 192.0.2.70; do npx securenow event send session.seen --env test --user test-user-net --session test-sess-net --ip $ip --attrs test=true; done
# R18
npx securenow event send session.seen --env test --user test-user-pw --session test-old-1 --ip 203.0.113.80 --attrs test=true
npx securenow event send auth.security.change --env test --user test-user-pw --session test-new-1 --ip 203.0.113.81 --attrs action=password_changed,outcome=completed,step_up=true,test=true
# wait more than 5 minutes, then:
npx securenow event send session.seen --env test --user test-user-pw --session test-old-1 --ip 203.0.113.80 --attrs test=true
# R19
npx securenow event send auth.login.failure --env test --user test-user-ato --ip 203.0.113.90 --attrs auth_method=password,provider=local,reason=bad_password,account_ref=test-acct-ato,test=true
npx securenow event send auth.login.success --env test --user test-user-ato --session test-sess-ato --ip 203.0.113.91 --attrs auth_method=password,provider=local,account_ref=test-acct-ato,mfa_state=none,test=true
npx securenow event send auth.security.change --env test --user test-user-ato --session test-sess-ato --ip 203.0.113.91 --attrs action=password_changed,outcome=completed,step_up=true,test=true
# R20
npx securenow event send auth.login.success --env test --user test-user-net2 --session test-sess-net2 --ip 203.0.113.100 --attrs auth_method=password,provider=local,account_ref=test-acct-net2,mfa_state=none,test=true
npx securenow event send auth.security.change --env test --user test-user-net2 --session test-sess-net2 --ip 198.51.100.100 --attrs action=password_changed,outcome=completed,step_up=true,test=true
# R21
npx securenow event send auth.security.change --env test --user test-admin --session test-sess-adm --ip 203.0.113.110 --attrs action=role_changed,outcome=completed,step_up=false,direction=elevate,target_ref=test-target-1,test=true
# R22
npx securenow event send auth.login.success --env test --user test-user-dormant --session test-sess-dormant --ip 203.0.113.120 --attrs auth_method=password,provider=local,account_ref=test-acct-dormant,mfa_state=none,dormant_days=120,test=true
# R23
for i in 1 2 3; do npx securenow event send auth.signup --env test --ip 203.0.113.130 --attrs auth_method=password,provider=local,outcome=existing,account_ref=test-acct-reg-$i,test=true; done
# R24
for i in 1 2; do npx securenow event send auth.login.failure --env test --ip 203.0.113.140 --attrs auth_method=password,provider=local,reason=bad_password,account_ref=test-acct-int,request_id=test-dup-1,test=true; done
sleep 60
for id in $R10 $R11 $R12 $R13 $R14 $R15 $R16 $R17 $R19 $R20 $R21 $R22 $R23 $R24; do npx securenow alerts rules test "$id" --mode dry_run --wait --app $APP --json; done
# R18 needs the 5-minute gap described under its rule; traffic rules: run the local-copy recipes in §11
```

#### ⑧ After 3–7 clean days, a person promotes each rule and enables its automation

```bash
npx securenow alerts rules list --mode test --json
npx securenow alerts rules promote "$R01"     # repeat per rule; asks for confirmation
npx securenow automation update <AUTO-A_ID> --status active
# rollback at any time:
npx securenow alerts rules demote "$R01"
npx securenow automation update <AUTO-A_ID> --status disabled
```

#### ⑨ Schedule the app/config fixes

In order: F1, F2, F6 (DO NOW) → F3, F5 step-up, F15 (NEXT 7 DAYS) → F4, F5 MFA, F7–F14, F16 (LATER). Details and definitions of done: [code report](authentication-code-findings.md#fixes).


<a id="testing"></a>
## 11. Testing & validation

- **Events-based rules:** `npx securenow event send` from the lab-auth root (routing comes from that project’s `.securenow` runtime credentials; `--env test` is honored by 8.12.0). One call = one event; values are strings and cannot contain commas. Send threshold + 1 events, wait ~45 s, then `alerts rules test <id> --mode dry_run --wait --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --json` and expect `resultCount ≥ 1`.
- **Traffic rules:** `event send` cannot feed them. Validate with the create-time dry-run and `test --mode dry_run` (expect `status: complete`), or generate real requests against your local copy (`http://localhost:3000`, SDK preload on, environment test). Your own IP (127.0.0.1/::1 locally) will appear; nothing is mitigated in test mode.
- **Instant conditions:** MCP `securenow_alert_rule_instant_update` with `dryRun: true` and the fixtures shown.
- **Mitigations:** `firewall test-ip`, `ratelimit test`, `challenge test`, `automation dry-run`, `fp dry-run` — never by blocking a real user.
- **Synthetic source IPs** are TEST-NET only (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24). They carry no ASN, so R26/R27 cannot be fired synthetically.
- **Never load-test the public lab** (R07/R08 are validated by dry-run only).

| Rule | How to test | Expected outcome |
| --- | --- | --- |
| [R01](#rule-r01) | On your local copy (http://localhost:3000, started with the SDK preload and runtime environment test), sign in 10 times with a wrong password for a fictional account from one machine, then dry-run. Expect resultCount ≥ 1 with your own IP. Stop before 15 attempts so the app’s own 429 does not hide the test. | status complete; for the local-copy recipes resultCount ≥ 1 and a test-mode notification |
| [R02](#rule-r02) | On your local copy (http://localhost:3000), send 20 wrong-password sign-ins (the app answers 429 from the 16th), then dry-run. Expect resultCount ≥ 1. Wait 15 minutes before signing in again. | status complete; for the local-copy recipes resultCount ≥ 1 and a test-mode notification |
| [R03](#rule-r03) | On your local copy: for i in $(seq 1 65); do curl -s -o /dev/null http://localhost:3000/api/me; done — then dry-run. Expect resultCount ≥ 1. Each call leaves a 30-minute session row; they expire on their own. | status complete; for the local-copy recipes resultCount ≥ 1 and a test-mode notification |
| [R04](#rule-r04) | On your local copy: for i in $(seq 1 21); do curl -s -o /dev/null -X POST -H "content-type: application/json" -d "{}" http://localhost:3000/api/auth/logout; done — then dry-run. Expect resultCount ≥ 1. | status complete; for the local-copy recipes resultCount ≥ 1 and a test-mode notification |
| [R05](#rule-r05) | On your local copy: for p in /.env /.git/config /wp-login.php; do curl -s -o /dev/null http://localhost:3000$p; done — then dry-run. Expect resultCount ≥ 1. | status complete; for the local-copy recipes resultCount ≥ 1 and a test-mode notification |
| [R06](#rule-r06) | Traffic rule: validate with the create-time dry-run and `alerts rules test --mode dry_run` (expect status complete). Generating it for real needs several addresses in one /24 or /64 against your own isolated copy (for example IPv6 privacy addresses on one host). | status complete; for the local-copy recipes resultCount ≥ 1 and a test-mode notification |
| [R07](#rule-r07) | Traffic rule: validate with the create-time dry-run and `alerts rules test --mode dry_run` (expect status complete). Do not load-test the public lab. | status complete; for the local-copy recipes resultCount ≥ 1 and a test-mode notification |
| [R08](#rule-r08) | Traffic rule: validate with the create-time dry-run and `alerts rules test --mode dry_run` (expect status complete). Do not mass-register on the public lab. | status complete; for the local-copy recipes resultCount ≥ 1 and a test-mode notification |
| [R09](#rule-r09) | Traffic rule: create-time dry-run + `alerts rules test --mode dry_run` (status complete). On your local copy (no Caddy in front): curl -s -o /dev/null -H "X-Forwarded-For: 198.51.100.7, 203.0.113.9" http://localhost:3000/healthz — the SDK records a two-hop chain and the dry-run returns ip 203.0.113.9. In production it must stay at zero. | status complete; for the local-copy recipes resultCount ≥ 1 and a test-mode notification |
| [R10](#rule-r10) | `event send` × 1 command(s) in §7 | resultCount ≥ 1 for ip 203.0.113.10 (11 failures, 6 accounts); a test-mode notification in `notifications list`; no mitigation |
| [R11](#rule-r11) | `event send` × 1 command(s) in §7 | resultCount ≥ 1 for account_ref test-victim (13 failures, 6 IPs); a test-mode notification in `notifications list`; no mitigation |
| [R12](#rule-r12) | `event send` × 2 command(s) in §7 | resultCount ≥ 1 for account_ref test-acct-seq with ip 203.0.113.21; a test-mode notification in `notifications list`; no mitigation |
| [R13](#rule-r13) | `event send` × 1 command(s) in §7 | resultCount ≥ 1 for ip 203.0.113.30; a test-mode notification in `notifications list`; no mitigation |
| [R14](#rule-r14) | `event send` × 1 command(s) in §7 | resultCount ≥ 1 for account_ref test-victim (3 rejections, 2 IPs); a test-mode notification in `notifications list`; no mitigation |
| [R15](#rule-r15) | `event send` × 1 command(s) in §7 | resultCount ≥ 1 for ip 203.0.113.50; a test-mode notification in `notifications list`; no mitigation |
| [R16](#rule-r16) | `event send` × 1 command(s) in §7 | resultCount ≥ 1 for ip 203.0.113.60; a test-mode notification in `notifications list`; no mitigation |
| [R17](#rule-r17) | `event send` × 1 command(s) in §7 | resultCount ≥ 1 for account test-user-net; a test-mode notification in `notifications list`; no mitigation |
| [R18](#rule-r18) | `event send` × 3 command(s) in §7 | resultCount ≥ 1 for account test-user-pw (surviving_sessions = 1); a test-mode notification in `notifications list`; no mitigation |
| [R19](#rule-r19) | `event send` × 3 command(s) in §7 | resultCount ≥ 1 for account test-user-ato (steps = 3); a test-mode notification in `notifications list`; no mitigation |
| [R20](#rule-r20) | `event send` × 2 command(s) in §7 | resultCount ≥ 1 for session test-sess-net2 with ip 198.51.100.100; a test-mode notification in `notifications list`; no mitigation |
| [R21](#rule-r21) | `event send` × 1 command(s) in §7 | resultCount ≥ 1 for account test-admin (privilege_elevations = 1); a test-mode notification in `notifications list`; no mitigation |
| [R22](#rule-r22) | `event send` × 1 command(s) in §7 | resultCount ≥ 1 for ip 203.0.113.120 (the rule reads dormant_days as a number or a string); a test-mode notification in `notifications list`; no mitigation |
| [R23](#rule-r23) | `event send` × 1 command(s) in §7 | resultCount ≥ 1 for ip 203.0.113.130; a test-mode notification in `notifications list`; no mitigation |
| [R24](#rule-r24) | `event send` × 1 command(s) in §7 | resultCount ≥ 1 for ip 203.0.113.140 (duplicate_request_ids = 1); a test-mode notification in `notifications list`; no mitigation |
| [R25](#rule-r25) | Mixed rule: validate with the create-time dry-run and `alerts rules test --mode dry_run`. To see it fire, run 10+ wrong-password sign-ins against your local copy after the SDK preload is on but before the track() bridge is deployed. | status complete; for the local-copy recipes resultCount ≥ 1 and a test-mode notification |
| [R26](#rule-r26) | Cannot be fired with `event send` (TEST-NET IPs have no ASN). Validate with the create-time dry-run and `alerts rules test --mode dry_run`, and confirm client.asn appears in `telemetry fields --source logs` before trusting it. | status complete; for the local-copy recipes resultCount ≥ 1 and a test-mode notification |
| [R27](#rule-r27) | Cannot be fired with `event send` (TEST-NET IPs have no ASN). Validate with the create-time dry-run and `alerts rules test --mode dry_run`. | status complete; for the local-copy recipes resultCount ≥ 1 and a test-mode notification |

```bash
# mitigation checks (no real user affected)
npx securenow firewall test-ip 203.0.113.99 --path /api/auth/login --method POST --env test --app df7ab010-37ac-4732-88ac-a8ac23afe1a4
npx securenow ratelimit test 203.0.113.99 --path /api/auth/login --method POST --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --env test
npx securenow challenge test 203.0.113.99 --path / --method GET --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --env test
npx securenow automation dry-run <AUTO-A_ID>
npx securenow revoke list --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --json      # returned HTTP 404 in this run (AUTH-17)

# confirm + clean up
npx securenow notifications list --limit 10
npx securenow human list --search lab-auth
npx securenow blocklist list --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --env test --status active   # then: npx securenow blocklist unblock <id> --reason "threat-model test"
```


<a id="runbooks"></a>
## 12. Response runbooks

### Sign-in guessing from one IP (R01, R02, R10)

**Confirm it is real:** Open the notification; check whether the IP is the presenter, a classroom or office NAT (`npx securenow ip <ip>`), and whether failures span several accounts (R10). Check `human show <row>` for the investigation score.

```bash
npx securenow ratelimit add <ip> --route '^/[aA][pP][iI]/[aA][uU][tT][hH]/[lL][oO][gG][iI][nN]/*$' --mode regex --method POST --limit 5 --window 15m --duration 24h --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --env test --reason "lab-auth: confirmed guessing"
# only if the risk score is >= 90 and the source is not shared:
npx securenow blocklist add <ip> --route '^/[aA][pP][iI]/[aA][uU][tT][hH](/|$)' --mode regex --method POST --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --env test --duration 24h --reason "lab-auth: high-risk guessing"
```

**Reverse:**

```bash
npx securenow ratelimit remove <id> --reason "lab-auth: reviewed"
npx securenow blocklist unblock <id> --reason "lab-auth: reviewed"
```

### Distributed attack or lockout on one account (R06, R11, R14, R26)

**Confirm it is real:** The account_ref in the notification is a keyed hash: an operator can match it to a user by computing the same HMAC over the normalized email. Confirm several IPs are hitting it; do NOT lock the account. Tell the owner through a channel they already verified (none in the lab yet).

```bash
# throttle the contributing IP(s) or the network block — never the victim
npx securenow ratelimit add <ip-or-cidr> --route '^/[aA][pP][iI]/[aA][uU][tT][hH]/[lL][oO][gG][iI][nN]/*$' --mode regex --method POST --limit 3 --window 15m --duration 24h --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --env test --reason "lab-auth: distributed attempts on one account"
```

**Reverse:**

```bash
npx securenow ratelimit remove <id> --reason "lab-auth: attack over"
```

### Session theft or session surviving a change (R17, R18, R20)

**Confirm it is real:** Check the account’s sessions (`session.id` values) and networks in the notification; ask the owner if they travel. For R18 there is no innocent explanation: it is a regression.

```bash
npx securenow revoke session <session.id> --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --env test --duration 24h --reason "lab-auth: session used from a second network"
# confirmed takeover:
npx securenow revoke user <enduser.id> --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --env test --duration 24h --reason "lab-auth: confirmed takeover"
# then ask the owner to change their password (kills all other sessions in the app)
```

**Reverse:**

```bash
npx securenow revoke list --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --json
npx securenow revoke restore <id> --reason "lab-auth: owner verified"
```

### Multi-step takeover / security change (R12, R19, R21)

**Confirm it is real:** Confirm with the account owner (or, for a role change, with the other admins) that they made the change. Check the sign-in IP vs the change IP (R20).

```bash
npx securenow revoke user <enduser.id> --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --env test --duration 24h --reason "lab-auth: takeover sequence confirmed"
# operator restores the role or password in the app (admin UI or database), then the owner signs in again
```

**Reverse:**

```bash
npx securenow revoke restore <id> --reason "lab-auth: false alarm"
```

### Registration probing / sign-up surge (R08, R23)

**Confirm it is real:** Look at the created/existing split and the top IPs. A tutorial going live can produce a real surge.

```bash
npx securenow ratelimit add <ip> --route '^/[aA][pP][iI]/[aA][uU][tT][hH]/[rR][eE][gG][iI][sS][tT][eE][rR]/*$' --mode regex --method POST --limit 3 --window 1h --duration 24h --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --env test --reason "lab-auth: registration probing"
# app-wide surge, time-boxed:
npx securenow ratelimit add --route '^/[aA][pP][iI]/[aA][uU][tT][hH]/[rR][eE][gG][iI][sS][tT][eE][rR]/*$' --mode regex --method POST --limit 20 --window 1h --key-by global --duration 24h --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --env test --reason "lab-auth: registration surge"
```

**Reverse:**

```bash
npx securenow ratelimit remove <id> --reason "lab-auth: surge over"
```

### Auth-surface scanning (R05)

**Confirm it is real:** Paths like /.env or /.git/config are never legitimate here.

```bash
npx securenow challenge add <ip> --route / --mode prefix --method GET --difficulty 16 --clearance 30m --duration 24h --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --env test --reason "lab-auth: scanner"
# confirmed scanner:
npx securenow blocklist add <ip> --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --env test --duration 24h --reason "lab-auth: confirmed scanner"
```

**Reverse:**

```bash
npx securenow challenge remove <id> --reason "lab-auth: reviewed"
npx securenow blocklist unblock <id> --reason "lab-auth: reviewed"
```

### Availability: session minting, hashing load, CSRF floods (R03, R07, R04)

**Confirm it is real:** Check database size and sign-in latency (`docker compose -f compose.production.yaml logs app` via SSM). For R07 look at the top 5 IPs and the p95.

```bash
npx securenow ratelimit add <ip> --route '^/[aA][pP][iI]/([mM][eE]|[aA][uU][tT][hH]/([sS][eE][sS][sS][iI][oO][nN]|[cC][sS][rR][fF]))/*$' --mode regex --method GET --limit 30 --window 15m --duration 24h --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --env test --reason "lab-auth: session minting"
npx securenow ratelimit add --route '^/[aA][pP][iI]/[aA][uU][tT][hH]/([lL][oO][gG][iI][nN]|[rR][eE][gG][iI][sS][tT][eE][rR]|[pP][aA][sS][sS][wW][oO][rR][dD])/*$' --mode regex --method POST --limit 60 --window 1m --key-by global --duration 1h --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --env test --reason "lab-auth: hashing load spike"
```

**Reverse:**

```bash
npx securenow ratelimit remove <id> --reason "lab-auth: load normal"
```

### Shared-egress handling (any per-IP rule)

**Confirm it is real:** If the IP is a university, office, mobile carrier or the presenter: prefer a GET-page challenge or a rate limit over a block, add a rule-specific exclusion for known monitors, and never trust the presenter IP during demos.

```bash
npx securenow challenge add <ip> --route / --mode prefix --method GET --difficulty 14 --clearance 30m --duration 12h --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --env test --reason "lab-auth: shared egress"
npx securenow fp mark <notification-id> <ip> --rule-scope this_rule
```

**Reverse:**

```bash
npx securenow challenge remove <id> --reason "lab-auth: reviewed"
```

### Proxy / client-IP anomaly (R09)

**Confirm it is real:** A hit means Caddy is no longer the only ingress or the forwarding config changed. Check infra/Caddyfile and compose ports on the host via SSM. Do not block: every client could match.

```bash
# notify-only rule; fix the proxy, then confirm zero hits on the next run
npx securenow alerts rules test <R09_ID> --mode dry_run --wait --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --json
```

**Reverse:**

```bash
# nothing to reverse
```

### Telemetry degradation (R24, R25, external check)

**Confirm it is real:** R25 = events missing while traces flow (bridge broken); R24 = duplicates/future-dated (forging or a retry bug). A silent pipeline is caught only by the external check (AUTH-27).

```bash
npx securenow doctor
npx securenow telemetry fields --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --since 1h --source all --env test --json
# suspected key leak: issue a new runtime credential and redeploy
npx securenow credentials runtime --env test
```

**Reverse:**

```bash
# redeploy the previous credential file only if the new one fails
```

### Google sign-in abuse or refusals (R15, R16)

**Confirm it is real:** R15 = bad/replayed callbacks from one IP; R16 = real users bounced because a password account squats their email (UX) or probing.

```bash
npx securenow ratelimit add <ip> --route '^/[aA][pP][iI]/[aA][uU][tT][hH]/[gG][oO][oO][gG][lL][eE]' --mode regex --method GET --limit 10 --window 15m --duration 24h --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --env test --reason "lab-auth: Google callback abuse"
# R16: no SecureNow action — fix the account manually and prioritize F4
```

**Reverse:**

```bash
npx securenow ratelimit remove <id> --reason "lab-auth: reviewed"
```

### Provider-account compromise (Google Cloud)

**Confirm it is real:** Not detectable in SecureNow (M58). Triggered by a Google Cloud audit-log alert or an unexpected consent-screen change.

```bash
# Google Cloud console: rotate the OAuth client secret, review authorized redirect URIs
# then update the lab-auth/runtime secret in AWS Secrets Manager and redeploy:
# sudo /opt/lab-auth/infra/update.sh   (on the host, via SSM)
```

**Reverse:**

```bash
# none — rotation is one-way
```

### Victim-safe recipient bombing

**Confirm it is real:** N/A for this lab: no auth emails or SMS are sent. When F4/F5 add email, re-run this prompt and add the per-target send rules before shipping.

```bash
# nothing to run today
```

**Reverse:**

```bash
# —
```


<a id="governance"></a>
## 13. Detection health & governance

| Rule / id | Owner | Signal source | Expected coverage / ratio | Threshold source | Mode | Channel | Last dry-run | Last synthetic test | FP budget | Runbook | Reversible action |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| [R01](#rule-r01) `<R01_ID>` | Lab operator (SecureNow) | NATIVE_TRAFFIC | every request (SDK preload) | app limit in code | test (test-first) | in-app only → add out-of-band (AUTH-04) | 2026-10-16 syntax-only on a non-lab host app (complete); lab dry-run pending | not run — local-copy recipe in §11 | ≤ 2 / week before promotion | §12 | AUTO-A, AUTO-B (disable) |
| [R02](#rule-r02) `<R02_ID>` | Lab operator (SecureNow) | NATIVE_TRAFFIC | every request (SDK preload) | app limit in code | test (test-first) | in-app only → add out-of-band (AUTH-04) | 2026-10-16 syntax-only on a non-lab host app (complete); lab dry-run pending | not run — local-copy recipe in §11 | ≤ 2 / week before promotion | §12 | AUTO-A, AUTO-B (disable) |
| [R03](#rule-r03) `<R03_ID>` | Lab operator (SecureNow) | NATIVE_TRAFFIC | every request (SDK preload) | baseline required — conservative start | test (test-first) | in-app only → add out-of-band (AUTH-04) | 2026-10-16 syntax-only on a non-lab host app (complete); lab dry-run pending | not run — local-copy recipe in §11 | ≤ 2 / week before promotion | §12 | AUTO-C (disable) |
| [R04](#rule-r04) `<R04_ID>` | Lab operator (SecureNow) | NATIVE_TRAFFIC | every request (SDK preload) | baseline required — conservative start | test (test-first) | in-app only → add out-of-band (AUTH-04) | 2026-10-16 syntax-only on a non-lab host app (complete); lab dry-run pending | not run — local-copy recipe in §11 | ≤ 2 / week before promotion | §12 | AUTO-D (disable) |
| [R05](#rule-r05) `<R05_ID>` | Lab operator (SecureNow) | NATIVE_TRAFFIC | every request (SDK preload) | baseline required — conservative start | test (test-first) | in-app only → add out-of-band (AUTH-04) | 2026-10-16 syntax-only on a non-lab host app (complete); lab dry-run pending | not run — local-copy recipe in §11 | ≤ 2 / week before promotion | §12 | AUTO-E (disable) |
| [R06](#rule-r06) `<R06_ID>` | Lab operator (SecureNow) | NATIVE_TRAFFIC | every request (SDK preload) | baseline required — conservative start | test (test-first) | in-app only → add out-of-band (AUTH-04) | 2026-10-16 syntax-only on a non-lab host app (complete); lab dry-run pending | not run — local-copy recipe in §11 | ≤ 2 / week before promotion | §12 | notify only |
| [R07](#rule-r07) `<R07_ID>` | Lab operator (SecureNow) | NATIVE_TRAFFIC | every request (SDK preload) | baseline required — conservative start | test (test-first) | in-app only → add out-of-band (AUTH-04) | 2026-10-16 syntax-only on a non-lab host app (complete); lab dry-run pending | not run — local-copy recipe in §11 | ≤ 2 / week before promotion | §12 | notify only |
| [R08](#rule-r08) `<R08_ID>` | Lab operator (SecureNow) | NATIVE_TRAFFIC | every request (SDK preload) | baseline required — conservative start | test (test-first) | in-app only → add out-of-band (AUTH-04) | 2026-10-16 syntax-only on a non-lab host app (complete); lab dry-run pending | not run — local-copy recipe in §11 | ≤ 2 / week before promotion | §12 | notify only |
| [R09](#rule-r09) `<R09_ID>` | Lab operator (SecureNow) | NATIVE_TRAFFIC | every request (SDK preload) | exact signature | test (prod-ready) | in-app only → add out-of-band (AUTH-04) | 2026-10-16 syntax-only on a non-lab host app (complete); lab dry-run pending | not run — local-copy recipe in §11 | 0 / week | §12 | notify only |
| [R10](#rule-r10) `<R10_ID>` | Lab operator (SecureNow) | APP_EVENT | one event per app decision | app limit in code | test (test-first) | in-app only → add out-of-band (AUTH-04) | 2026-10-16 syntax-only on a non-lab host app (complete); lab dry-run pending | not run (read-only run) — recipe in §7 | ≤ 2 / week before promotion | §12 | AUTO-A, AUTO-B (disable) |
| [R11](#rule-r11) `<R11_ID>` | Lab operator (SecureNow) | APP_EVENT | one event per app decision | app limit in code | test (test-first) | in-app only → add out-of-band (AUTH-04) | 2026-10-16 syntax-only on a non-lab host app (complete); lab dry-run pending | not run (read-only run) — recipe in §7 | ≤ 2 / week before promotion | §12 | notify only |
| [R12](#rule-r12) `<R12_ID>` | Lab operator (SecureNow) | APP_EVENT | one event per app decision | baseline required — conservative start | test (test-first) | in-app only → add out-of-band (AUTH-04) | 2026-10-16 syntax-only on a non-lab host app (complete); lab dry-run pending | not run (read-only run) — recipe in §7 | ≤ 2 / week before promotion | §12 | notify only |
| [R13](#rule-r13) `<R13_ID>` | Lab operator (SecureNow) | APP_EVENT | one event per app decision | baseline required — conservative start | test (test-first) | in-app only → add out-of-band (AUTH-04) | 2026-10-16 syntax-only on a non-lab host app (complete); lab dry-run pending | not run (read-only run) — recipe in §7 | ≤ 2 / week before promotion | §12 | notify only |
| [R14](#rule-r14) `<R14_ID>` | Lab operator (SecureNow) | APP_EVENT | one event per app decision | app limit in code | test (test-first) | in-app only → add out-of-band (AUTH-04) | 2026-10-16 syntax-only on a non-lab host app (complete); lab dry-run pending | not run (read-only run) — recipe in §7 | ≤ 2 / week before promotion | §12 | notify only |
| [R15](#rule-r15) `<R15_ID>` | Lab operator (SecureNow) | APP_EVENT | one event per app decision | app limit in code | test (test-first) | in-app only → add out-of-band (AUTH-04) | 2026-10-16 syntax-only on a non-lab host app (complete); lab dry-run pending | not run (read-only run) — recipe in §7 | ≤ 2 / week before promotion | §12 | AUTO-F (disable) |
| [R16](#rule-r16) `<R16_ID>` | Lab operator (SecureNow) | APP_EVENT | one event per app decision | baseline required — conservative start | test (test-first) | in-app only → add out-of-band (AUTH-04) | 2026-10-16 syntax-only on a non-lab host app (complete); lab dry-run pending | not run (read-only run) — recipe in §7 | ≤ 5 / week, notify only | §12 | notify only |
| [R17](#rule-r17) `<R17_ID>` | Lab operator (SecureNow) | APP_EVENT | one event per app decision | baseline required — conservative start | test (test-first) | in-app only → add out-of-band (AUTH-04) | 2026-10-16 syntax-only on a non-lab host app (complete); lab dry-run pending | not run (read-only run) — recipe in §7 | ≤ 2 / week before promotion | §12 | notify only |
| [R18](#rule-r18) `<R18_ID>` | Lab operator (SecureNow) | APP_EVENT | one event per app decision | exact signature | test (prod-ready) | in-app only → add out-of-band (AUTH-04) | 2026-10-16 syntax-only on a non-lab host app (complete); lab dry-run pending | not run (read-only run) — recipe in §7 | 0 / week | §12 | notify only |
| [R19](#rule-r19) `<R19_ID>` | Lab operator (SecureNow) | APP_EVENT | one event per app decision | baseline required — conservative start | test (test-first) | in-app only → add out-of-band (AUTH-04) | 2026-10-16 syntax-only on a non-lab host app (complete); lab dry-run pending | not run (read-only run) — recipe in §7 | ≤ 2 / week before promotion | §12 | notify only |
| [R20](#rule-r20) `<R20_ID>` | Lab operator (SecureNow) | APP_EVENT | one event per app decision | exact signature | test (test-first) | in-app only → add out-of-band (AUTH-04) | 2026-10-16 syntax-only on a non-lab host app (complete); lab dry-run pending | not run (read-only run) — recipe in §7 | ≤ 2 / week before promotion | §12 | notify only |
| [R21](#rule-r21) `<R21_ID>` | Lab operator (SecureNow) | APP_EVENT | one event per app decision | app limit in code | test (test-first) | in-app only → add out-of-band (AUTH-04) | 2026-10-16 syntax-only on a non-lab host app (complete); lab dry-run pending | not run (read-only run) — recipe in §7 | ≤ 2 / week before promotion | §12 | notify only |
| [R22](#rule-r22) `<R22_ID>` | Lab operator (SecureNow) | APP_EVENT | one event per app decision | conservative start (no baseline yet) | test (test-first) | in-app only → add out-of-band (AUTH-04) | 2026-10-16 syntax-only on a non-lab host app (complete); lab dry-run pending | not run (read-only run) — recipe in §7 | ≤ 5 / week, notify only | §12 | notify only |
| [R23](#rule-r23) `<R23_ID>` | Lab operator (SecureNow) | APP_EVENT | one event per app decision | app limit in code | test (test-first) | in-app only → add out-of-band (AUTH-04) | 2026-10-16 syntax-only on a non-lab host app (complete); lab dry-run pending | not run (read-only run) — recipe in §7 | ≤ 2 / week before promotion | §12 | AUTO-G (disable) |
| [R24](#rule-r24) `<R24_ID>` | Lab operator (SecureNow) | APP_EVENT | one event per app decision | exact signature | test (test-first) | in-app only → add out-of-band (AUTH-04) | 2026-10-16 syntax-only on a non-lab host app (complete); lab dry-run pending | not run (read-only run) — recipe in §7 | ≤ 2 / week before promotion | §12 | notify only |
| [R25](#rule-r25) `<R25_ID>` | Lab operator (SecureNow) | NATIVE_TRAFFIC + APP_EVENT | 1 event per traced 200/401 sign-in | conservative start (no baseline yet) | test (test-first) | in-app only → add out-of-band (AUTH-04) | 2026-10-16 syntax-only on a non-lab host app (complete); lab dry-run pending | not run — local-copy recipe in §11 | ≤ 5 / week, notify only | §12 | notify only |
| [R26](#rule-r26) `<R26_ID>` | Lab operator (SecureNow) | APP_EVENT | one event per app decision | baseline required — conservative start | test (test-first) | in-app only → add out-of-band (AUTH-04) | 2026-10-16 syntax-only on a non-lab host app (complete); lab dry-run pending | not run — local-copy recipe in §11 | ≤ 2 / week before promotion | §12 | notify only |
| [R27](#rule-r27) `<R27_ID>` | Lab operator (SecureNow) | APP_EVENT | one event per app decision | conservative start (no baseline yet) | test (test-first) | in-app only → add out-of-band (AUTH-04) | 2026-10-16 syntax-only on a non-lab host app (complete); lab dry-run pending | not run — local-copy recipe in §11 | ≤ 5 / week, notify only | §12 | notify only |

**Instrumentation coverage check (while traces still flow):** rule R25 compares traced `POST /api/auth/login` verdicts with exported `auth.login.*` events every 15 minutes. After each deploy also run `npx securenow telemetry fields --app df7ab010-37ac-4732-88ac-a8ac23afe1a4 --since 1h --source logs --env test` and confirm the event types are present.

**Provider reconciliation:** there are no paid provider sends to reconcile. The only provider is Google OIDC; compare Google sign-in successes (R15’s source events) with Google Cloud console sign-in metrics occasionally — no adapter exists (M58 gap).

**External checks (independent of SecureNow, AUTH-27):** (1) `curl -f https://lab-auth.labs.securenow.ai/readyz` every 5 minutes; (2) `telemetry fields --since 1h --source traces` must list `http.target` while /readyz is up; (3) diff `npx securenow alerts rules list --json` (name, status, mode, schedule, alertChannelIds) against the 27-rule manifest below; (4) certificate expiry > 14 days; (5) a weekly test alert through the out-of-band channel. A dead exporter, a paused scheduler or a broken channel cannot report itself in-band.

```text
# manifest — expected lab-auth rules (name | severity | schedule)
lab-auth: repeated failed sign-ins per IP | high | */5 * * * *
lab-auth: auth requests past the native limit per IP | medium | */5 * * * *
lab-auth: anonymous session minting per IP | medium | */5 * * * *
lab-auth: CSRF-rejected API mutations per IP | medium | */5 * * * *
lab-auth: auth-surface probing per IP | medium | */5 * * * *
lab-auth: failed sign-ins spread across one network | high | */10 * * * *
lab-auth: sign-in hashing load spike (all IPs) | high | */5 * * * *
lab-auth: registration volume spike (all IPs) | medium | */15 * * * *
lab-auth: forwarded client-IP chain anomaly | high | */5 * * * *
lab-auth: failed sign-ins across multiple accounts per IP | high | */5 * * * *
lab-auth: one account targeted from multiple IPs | high | */10 * * * *
lab-auth: successful sign-in after repeated failures | high | */10 * * * *
lab-auth: one IP signs in to multiple accounts | medium | */15 * * * *
lab-auth: per-account sign-in limit held full | medium | */5 * * * *
lab-auth: Google sign-in callback failures per IP | medium | */5 * * * *
lab-auth: Google sign-in refused for an existing password account | low | */15 * * * *
lab-auth: account active from several networks | medium | */15 * * * *
lab-auth: session still used after password change | high | */15 * * * *
lab-auth: takeover sequence (failures, sign-in, security change) | high | */15 * * * *
lab-auth: security change from a different network than sign-in | medium | */15 * * * *
lab-auth: post-sign-in security changes needing review | high | */15 * * * *
lab-auth: sign-in to a dormant account | low | */15 * * * *
lab-auth: registration probing per IP | medium | */15 * * * *
lab-auth: auth event integrity | medium | */15 * * * *
lab-auth: auth event coverage drift | low | */15 * * * *
lab-auth: failed sign-ins spread across one network operator (ASN) | high | */10 * * * *
lab-auth: sign-in from a new network operator | low | */15 * * * *
```


<a id="gaps"></a>
## 14. Known gaps & SecureNow feature requests

26 threats are 🔴 gaps. Most are prevention properties the app already implements (marked “in place”); each still gets an interim fix and the required SecureNow line.

| # | Threat | Why SecureNow cannot cover it | Interim fix (code report) | Request |
| --- | --- | --- | --- | --- |
| [A5](#threat-a5) | Default, seeded or leftover bootstrap credentials | no signal — the credential lives in AWS Secrets Manager | [F12](authentication-code-findings.md#finding-f12) — app fix: strip ADMIN_PASSWORD from the runtime secret after first use; force a password change on first admin sign-in (F12) | Requires SecureNow team — contact your SecureNow account contact (or in-dashboard support) to request support for this threat. |
| [A5a](#threat-a5a) | Password-handling gaps (no breach screening, no Unicode normalization, scrypt below OWASP minimum) | no signal — properties of stored hashes and accepted passwords | [F8](authentication-code-findings.md#finding-f8), [F10](authentication-code-findings.md#finding-f10) — app fix F8 (scrypt cost + rehash) and F10 (breach screening + NFC) | Requires SecureNow team — contact your SecureNow account contact (or in-dashboard support) to request support for this threat. |
| [C10](#threat-c10) | Session fixation | no signal — prevented in code | already prevented: session regenerated on every sign-in (src/app.js:140) | Requires SecureNow team — contact your SecureNow account contact (or in-dashboard support) to request support for this threat. |
| [C14](#threat-c14) | Weak session-cookie configuration | no signal — verified live: __Host-lab_auth; Secure; HttpOnly; SameSite=Lax; Path=/ | already in place (src/app.js:42, 75-79) | Requires SecureNow team — contact your SecureNow account contact (or in-dashboard support) to request support for this threat. |
| [C15](#threat-c15) | Excessive session lifetime | no signal — 30 min idle (rolling), 8 h absolute | already in place (src/config.js:27-28, src/app.js:93) | Requires SecureNow team — contact your SecureNow account contact (or in-dashboard support) to request support for this threat. |
| [D18](#threat-d18) | Weak or guessable session-cookie signing secret | no signal — startup refuses secrets under 32 characters | already in place (src/config.js:8-10; deploy generates 48 random bytes) | Requires SecureNow team — contact your SecureNow account contact (or in-dashboard support) to request support for this threat. |
| [D21](#threat-d21) | Token leakage into URLs, logs, Referer or telemetry | no signal — a capture-configuration property | [F13](authentication-code-findings.md#finding-f13) — config: capture.body=false and multipart=false before first SDK start; SDK header-redaction feature request (F13) | Requires SecureNow team — contact your SecureNow account contact (or in-dashboard support) to request support for this threat. |
| [D21a](#threat-d21a) | Live session IDs and OAuth transactions readable from database backups | no signal | [F14](authentication-code-findings.md#finding-f14) — app/ops fix: exclude sessions and rate_buckets table data from pg_dump (F14) | Requires SecureNow team — contact your SecureNow account contact (or in-dashboard support) to request support for this threat. |
| [G31](#threat-g31) | redirect_uri manipulation / open redirect after Google sign-in | no app signal — Google rejects unregistered redirect URIs before the callback | already in place: redirect URI is a server constant (src/app.js:40); post-login redirects are fixed paths (src/app.js:229,250,255,258) | Requires SecureNow team — contact your SecureNow account contact (or in-dashboard support) to request support for this threat. |
| [G36b](#threat-g36b) | Identity keyed on a mutable claim (email instead of subject) | no signal — keyed on Google `sub` | already in place (src/app.js:237) | Requires SecureNow team — contact your SecureNow account contact (or in-dashboard support) to request support for this threat. |
| [G36e](#threat-g36e) | Google account disabled, but lab session continues | no provider feed — consumer Google accounts have no SCIM/deprovisioning signal for this app | 8-hour absolute session cap (in place); none further | Requires SecureNow team — contact your SecureNow account contact (or in-dashboard support) to request support for this threat. |
| [H38a](#threat-h38a) | Races in identity-state changes (duplicate registration, parallel guesses) | no signal — prevented by unique indexes and an atomic counter | already in place (db/001_initial.sql:3,6; src/app.js:127-131,166,241-246) | Requires SecureNow team — contact your SecureNow account contact (or in-dashboard support) to request support for this threat. |
| [H40b](#threat-h40b) | Email canonicalization mismatch (Unicode, Gmail dots, plus-aliases) | no signal | [F4](authentication-code-findings.md#finding-f4) — app fix with F4 (NFKC + verified address) | Requires SecureNow team — contact your SecureNow account contact (or in-dashboard support) to request support for this threat. |
| [H40d](#threat-h40d) | Signup overwriting or shadowing an existing account | no signal — ON CONFLICT DO NOTHING + unique lowercase email | already in place (db/001_initial.sql:3; src/app.js:165-168) | Requires SecureNow team — contact your SecureNow account contact (or in-dashboard support) to request support for this threat. |
| [H40g](#threat-h40g) | Mass assignment of auth fields on signup | no signal (request bodies are not captured, by design) | already in place: only name/email/password read; tested with role and emailVerified injection | Requires SecureNow team — contact your SecureNow account contact (or in-dashboard support) to request support for this threat. |
| [I45](#threat-i45) | Unauthenticated health endpoints reachable from outside | no signal needed — /healthz and /readyz return only a status word | already in place; optional rate limit on /readyz | Requires SecureNow team — contact your SecureNow account contact (or in-dashboard support) to request support for this threat. |
| [K49](#threat-k49) | Password-hash work factor below current guidance | no signal | [F8](authentication-code-findings.md#finding-f8) — app fix F8 | Requires SecureNow team — contact your SecureNow account contact (or in-dashboard support) to request support for this threat. |
| [K50](#threat-k50) | Missing TLS/HSTS or cookies over plain HTTP | no in-band signal; an external check must watch certificate and headers | already in place (HTTP→308, HSTS 1 year, Secure cookie); external certificate/header monitor (AUTH-27) | Requires SecureNow team — contact your SecureNow account contact (or in-dashboard support) to request support for this threat. |
| [K51](#threat-k51) | Auth secrets committed to Git or baked into images | no signal — Git history scanned clean in this run | already in place: CI secret scan, .gitignore/.dockerignore, Secrets Manager | Requires SecureNow team — contact your SecureNow account contact (or in-dashboard support) to request support for this threat. |
| [K52](#threat-k52) | Credentials or tokens captured in logs and traces | no signal | [F13](authentication-code-findings.md#finding-f13) — config: capture off before first SDK start (F13) | Requires SecureNow team — contact your SecureNow account contact (or in-dashboard support) to request support for this threat. |
| [L54](#threat-l54) | IDOR on account-management endpoints | no signal | already in place: own sessions only; admin routes role-gated | Requires SecureNow team — contact your SecureNow account contact (or in-dashboard support) to request support for this threat. |
| [M56](#threat-m56) | Telemetry exporter or ingestion outage | needs an independent monitor — a dead pipeline cannot alert through itself | external monitor (AUTH-27) | Requires SecureNow team — contact your SecureNow account contact (or in-dashboard support) to request support for this threat. |
| [M58](#threat-m58) | Google Cloud OAuth client or project compromise | Google Cloud audit logs are not ingested by SecureNow | provider: Cloud Audit Logs alerting + secret rotation (AUTH-28) | Requires SecureNow team — contact your SecureNow account contact (or in-dashboard support) to request support for this threat. |
| [M60](#threat-m60) | Alert rule disabled, edited or never run; alerts only in-app | manifest diff of `alerts rules list --json` (external) | add an out-of-band channel (AUTH-04); external manifest check (AUTH-27) | Requires SecureNow team — contact your SecureNow account contact (or in-dashboard support) to request support for this threat. |
| [M60a](#threat-m60a) | Detection-logic defects that look healthy | operator lint (this report) + coverage rule R25 | lint before create; validate on the lab app; R25 | Requires SecureNow team — contact your SecureNow account contact (or in-dashboard support) to request support for this threat. |
| [S2](#threat-s2) | No second factor or step-up anywhere | no signal — compensating detections R12, R19, R21 | [F5](authentication-code-findings.md#finding-f5) — app: passkeys/TOTP for admin and analyst first (F5) | Requires SecureNow team — contact your SecureNow account contact (or in-dashboard support) to request support for this threat. |

<a id="product-issues"></a>
### SecureNow product issues found in this run

| Issue | Evidence | Interim workaround | Request |
| --- | --- | --- | --- |
| `revoke` CLI cannot reach the API | `npx securenow revoke list --json` → HTTP 404 (with and without --app). The 8.12.0 CLI calls `/api/revocations` (`node_modules/securenow/cli/security.js:1008`, prefixed with `/api` by `cli/client.js:19`), while the same package’s session guard syncs from `/api/v1/revocations/sync` (`sessions.js:39`) — the CLI path looks wrong. | Treat manual revocation as unverified; rely on the app’s own kill switches (password change, role change, F7). | Requires SecureNow team — contact your SecureNow account contact (or in-dashboard support) to request support for this threat. |
| No header-redaction setting | `capture.sensitiveFields` applies to bodies; headers are redacted only for a fixed list plus OTP-like names (`node_modules/securenow/tracing.js:602-606`), so `x-csrf-token` is exported. | Keep body capture off; accept CSRF-header capture (low value without the cookie). | Requires SecureNow team — contact your SecureNow account contact (or in-dashboard support) to request support for this threat. |
| Firewall rules match paths exactly and case-sensitively | `rulePathMatches` uses `===` / `startsWith` / an uncased RegExp (`node_modules/securenow/firewall.js:913-921`), while frameworks such as Express 5 route case-insensitively. | Case-insensitive regex scopes (this report) + F6. | Requires SecureNow team — contact your SecureNow account contact (or in-dashboard support) to request support for this threat. |
| Challenge on JSON routes needs client support | fetch() gets JSON 403 `challenge_required` (`firewall.js:1117-1133`); generic SPAs show an error. | Challenge GET pages only; F15. | Requires SecureNow team — contact your SecureNow account contact (or in-dashboard support) to request support for this threat. |
| `validate` cannot check the first rule of an app | `alerts rules validate --app <new app>` needs a host rule that already covers the app (“No existing rule covers app …”). | Let the first `create` validate itself; host later validates on it. | Requires SecureNow team — contact your SecureNow account contact (or in-dashboard support) to request support for this threat. |
| `status --json` prints the human table | Output of `npx securenow status --json` in this run. | Use `apps`/`firewall status` for machine-readable data. | Requires SecureNow team — contact your SecureNow account contact (or in-dashboard support) to request support for this threat. |
| Account-wide alert-name automations are easy to trigger by accident | A `contains` match (case-insensitive) on words like “brute force” or “flood” fires for every app, including new labs. | Rule names avoid the phrases; scope or narrow that automation (AUTH-03). | Requires SecureNow team — contact your SecureNow account contact (or in-dashboard support) to request support for this threat. |


<a id="appendix"></a>
## 15. Appendix

| Item | Value |
| --- | --- |
| Resolved SDK/CLI | securenow 8.12.0 from node_modules (all commands via npx); global CLI 8.11.3 not used |
| App key | df7ab010-37ac-4732-88ac-a8ac23afe1a4 (lab-auth, lab-auth.labs.securenow.ai) |
| Telemetry environment | test (docs/securenow-integration.md:45); SDK default would be production |
| Repository commit | 5f87235 |
| Report date | 2026-10-16 |
| Scope | Authentication only (episode 1) |
| Rule IDs created | None — this run was read-only against the SecureNow account. Every create/automation/mitigation is emitted as a command. |
| SQL validation method | Each of the 27 rule files plus the baseline query (28 files) was dry-run with `npx securenow alerts rules validate <HOST_RULE_ID> --sql @<file> --app <OTHER_APP_KEY> --json`, one at a time. That host rule and app belong to the operator’s own dashboard app and were used **purely as a ClickHouse syntax/semantics check** — their results are not lab data. All 28 returned status complete with no error (one earlier attempt of R25 failed with SYNTAX_ERROR because `top` is a reserved word; renamed and re-validated). Lab baselines are not measurable yet (no telemetry), so thresholds come from the app’s limits in code or are “baseline required — conservative start”. |
| Commands that failed | `revoke list --json` → HTTP 404 (the CLI calls /api/revocations; the SDK guard uses /api/v1/revocations/sync — a path mismatch inside securenow 8.12.0). `doctor` → ingest probes HTTP 401 (expected: no runtime key). `status --json` printed the human table instead of JSON. |
| Live probes | Passive GET/HEAD only: `HEAD /`, `HEAD http://…/`, `GET /healthz`, one `GET /api/me` (cookie attributes). No logins, registrations, POSTs, scans or load. |
| OWASP labels | OWASP Top 10:2021 categories |
| Companion report | [Code findings & recommendations](authentication-code-findings.md) |

