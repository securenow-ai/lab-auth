# SecureNow integration and verification

This is the runbook for the next tutorial phase. The checked-in baseline does not load the SecureNow SDK. A completed app smoke test does not establish that SecureNow threat modeling, telemetry, alerts, notification delivery, or mitigations have been verified.

Use a separate SecureNow application/environment for your copy of the lab. Run every exercise against a deployment and test accounts you control. Prefer an isolated copy for mitigation testing so a test block cannot affect other viewers.

## 1. Capture the baseline and model authentication

1. Record the repository commit and deployment origin. Read the [authentication threat model](threat-model-authentication.md) and identify the browser, reverse proxy, app, PostgreSQL, and Google trust boundaries.
2. Register a fictional account; sign in with a valid and an invalid password; sign out. Record status codes and the corresponding audit-event types. Inspect member, analyst, and admin authorization using separate test accounts.
3. In SecureNow, create or select the application for this lab. Use its threat-modeling workflow to model **Authentication** only for episode 1. Describe the implemented flows and remaining gaps accurately; supply the relevant repository code and architecture as permitted by your account's workflow.
4. Save the report with its creation date, commit, scope, and assumptions. Review each finding against the code. Mark false assumptions and missing evidence explicitly.
5. For each confirmed risk, record the required **code change**, any useful **detection**, and a possible **response**. A firewall block does not implement MFA or correct an authorization defect.

No threat-model report is fabricated or pre-certified by this repository. Keep reports containing account details or sensitive infrastructure information private; publish a sanitized teaching copy separately.

## 2. Add the SDK deliberately

On a development checkout, with Node.js 22 and the app dependencies installed:

```sh
npm install --save-exact securenow@latest
npx securenow version
npx securenow login
npx securenow app connect
```

The CLI creates the login callback/state values; start login from the CLI. Select the lab application when connecting. Current SecureNow 8.x separates operator/control-plane authentication in `.securenow/admin.json` from scoped application runtime authentication in `.securenow/runtime.json`. The latter can ingest telemetry and synchronize firewall decisions; an admin login file is not the runtime credential.

The connection flow enables telemetry and the application firewall by default. Configure the private runtime file **before starting the instrumented process**. For this authentication lab, begin with request body and multipart capture disabled:

```json
{
  "config": {
    "capture": {
      "body": false,
      "multipart": false,
      "sensitiveFields": [
        "email", "password", "name", "cookie", "authorization",
        "csrfToken", "state", "nonce", "code", "codeVerifier",
        "access_token", "refresh_token", "id_token"
      ]
    },
    "runtime": {
      "deploymentEnvironment": "lab"
    }
  }
}
```

Merge this fragment into the generated file without removing `app`, `apiKey`, or existing required configuration. Review the resolved configuration and exported sample telemetry. Disable capture or add redaction for any remaining personal data; never log secrets to test redaction. The application's own audit events deliberately avoid email addresses and password/token values. SDK request tracing can have a different data footprint, so verify it separately.

Start with the preload so instrumentation runs before Express:

```sh
node -r securenow/register src/server.js
npx securenow doctor
```

The equivalent launch is `npx securenow run src/server.js`. Keep the package version and lockfile in the tutorial branch, and record the exact tested SDK version. The unmodified Docker image continues to use its baseline command until you deliberately update the deployment command.

For a deployed copy, generate a runtime-only credential file using:

```sh
npx securenow credentials runtime --env production
```

Store and mount the generated file privately at the project runtime path supported by the SDK, such as `/app/.securenow/credentials.production.json`, readable only by the runtime user. Do not bake it into an image or copy admin authentication into the container. The repository ignores credential filenames and excludes `.securenow` from the build context. Add the SDK to the production build and change the app command to `node -r securenow/register src/server.js` only when ready for the instrumentation exercise.

Confirm the observed client IP is the real test client. Caddy overwrites `X-Forwarded-For`, the app trusts a single proxy hop, and app/database ports stay private. The SDK has its own IP-resolution configuration; verify it at the SDK layer too. Never fix incorrect IP attribution by trusting forwarded headers from every public client.

## 3. Observe events before writing detectors

Use one invalid password on your fictional account, then one valid login. Confirm the request traces arrive in the intended application/environment and the application audit view contains the corresponding database records. The baseline audit helper writes only to PostgreSQL. For detectors using `auth.*` events, first implement a privacy-preserving export bridge that emits a minimal structured event through the SDK logger; loading the HTTP preload alone does not export existing database rows. Test successful export and failure behavior. Until that bridge exists, use only verified trace fields and mark event-based candidates as needing instrumentation.

Inspect timestamps, route, method, status, client IP, and request correlation; inspect event names only when their export is implemented. Confirm request bodies, cookies, password hashes, Google codes, session IDs, and secrets are absent.

Candidate authentication detections:

| Candidate | Required evidence | Application safeguard |
| --- | --- | --- |
| Repeated failed login | `auth.login_failed` events, client IP, time window | Persistent IP and account-key rate limits |
| Distributed attempts on one account | Stable pseudonymous account correlation, distinct source IPs | Account-key throttling; stronger identity controls later |
| Repeated OAuth transaction failures | `auth.google_failed`, callback path, reason category | State, nonce, PKCE, verified ID token |
| Password-change abuse | Failed/successful password-change events and request context | Existing password required; session revocation |
| Access to higher roles | `authorization.denied` and route/status evidence | Server-side role checks |
| CSRF failures | `csrf.rejected`, method, route, source IP | Origin plus per-session token verification |

Some correlation fields may be missing from exported telemetry. Mark those detectors `NEEDS_INSTRUMENTATION`; do not claim a working rule from its name alone. IP-only signals cannot prove credential stuffing or identify a user behind shared NAT.

List existing rules and notification channels first:

```sh
npx securenow alerts rules
npx securenow alerts channels
npx securenow alerts history --limit 10
```

Choose explicit thresholds using a small baseline and the app's existing limits. Scope every candidate to the lab application/environment. SQL must use observed fields and the `__USER_APP_KEYS__` placeholder for tenant scope, and select `ip` when per-IP remediation is intended. Validate a real candidate before creating it:

```sh
npx securenow alerts rules validate --sql @auth-rule.sql --app YOUR_LAB_APP_KEY
npx securenow alerts rules create --name "Lab: repeated failed login" --sql @auth-rule.sql --apps YOUR_LAB_APP_KEY --severity medium --schedule "*/5 * * * *" --nlp "Repeated failed sign-ins to the lab from one source IP"
```

`auth-rule.sql` is created after you inspect your telemetry schema; this repository does not ship unvalidated detector SQL. A created rule is not evidence of delivery. Select and verify the intended notification channel, review its destination, and record a test alert arriving there.

## 4. Generate a bounded test and verify the alert

1. Record the test start time and your real public source IP. Use your own fictional account on your isolated lab.
2. Through the UI, send a small agreed number of invalid logins below the local abuse-control ceiling. Record each response and stop when the threshold is reached or a `429` appears. Do not run password lists, external scans, or unbounded load.
3. Find the matching traces and audit events. Confirm the detector uses those events and the correct application/environment.
4. Allow for the configured scheduling/ingestion interval. Open the resulting alert and its evidence; confirm its source IP and time window.
5. Confirm delivery to the configured notification destination. Save sanitized evidence of both the matched event and delivered alert.
6. Send a normal login from the same test context after the relevant window, and verify the baseline does not create a false positive.

If there is no alert, inspect missing telemetry, field names, thresholds, rule state, environment scope, and channel delivery separately. Do not call a simulated log or a configuration screen an end-to-end detection test.

## 5. Verify one mitigation at a time

Use a disposable test source and retain a separate operator session. Never choose a shared proxy, office/VPN gateway, or the operator's only access path without a recovery method.

For a reviewed test IP, current CLI examples are:

```sh
npx securenow firewall status --app YOUR_LAB_APP_KEY --env lab
npx securenow blocklist add YOUR_TEST_PUBLIC_IP --app YOUR_LAB_APP_KEY --env lab --reason "Controlled authentication lab exercise"
npx securenow firewall test-ip YOUR_TEST_PUBLIC_IP --app YOUR_LAB_APP_KEY --env lab
```

After synchronization, repeat a request from that source. Confirm the actual response is denied and a different legitimate client still works. Record the block ID and remove the exercise block afterward:

```sh
npx securenow blocklist unblock YOUR_BLOCK_ID --reason "Controlled lab exercise completed"
```

Then verify access returns. A positive `test-ip` result is a configuration check; the real denied HTTP response is the enforcement evidence.

For a separate rate-limit exercise, inspect `npx securenow ratelimit add --help` in the installed version, scope it to the lab app/environment and `POST /api/auth/login`, and use the SDK-supported rule fields. A documented basic pattern is:

```sh
npx securenow ratelimit add YOUR_TEST_PUBLIC_IP --route /api/auth/login --limit 2 --window 1m --duration 15m
```

Verify allowed requests, the subsequent `429`, the matching decision, expiry/removal, and legitimate traffic. Confirm the CLI's selected app/environment before executing the basic pattern. Native app throttling is independent and can also produce `429`; use decision evidence to distinguish them.

CAPTCHA is a future code integration in this baseline. A proper exercise needs a real challenge provider, server-side token verification, replay/expiry handling, an accessible fallback, and a measured escalation policy. A button or alert label is not CAPTCHA enforcement. Similarly, detections do not supply missing MFA, verified email ownership, recovery procedures, or secure identity linking.

## Evidence checklist for the later episode

For each finding, publish a sanitized record containing: threat, affected code/commit, baseline behavior, code fix, test result, observed telemetry fields, validated rule, real alert, real delivery, enforced response, legitimate-user check, and rollback result. Mark unavailable steps explicitly as pending. Keep private credentials, real identities, IP addresses, and account configuration out of the public teaching artifacts.
