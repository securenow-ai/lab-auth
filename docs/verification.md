# Hosted deployment verification

Verified on **15 October 2026** at **https://lab-auth.labs.securenow.ai**. Functional application and infrastructure revision: `f8ae4e3`. This is a dated test record for the teaching deployment, not a certification or a claim that every possible authentication attack is prevented.

| Check | Observed result |
| --- | --- |
| PostgreSQL integration suite | Eight tests passed against real PostgreSQL 17; the setup-only fallback was skipped because a test database was supplied |
| GitHub CI | Tests, secret scan, dependency audit, and Docker build passed on the application revision |
| Dependency audit | No known npm vulnerabilities reported at verification time |
| HTTPS and readiness | Valid hostname certificate; `/healthz` and `/readyz` returned 200 |
| Email/password | Registration, wrong/correct login, session rotation, password change, old-password rejection, and logout passed over the live HTTPS origin |
| Role enforcement | Member denied analyst/admin access; administrator role updates worked; analyst could read audit events but could not manage users; changed roles invalidated existing sessions |
| CSRF and cookies | Missing CSRF token rejected; production session cookie used Secure, HttpOnly, SameSite=Lax, host-only scope; API responses used no-store |
| Google | Real Google account registration, logout, and returning sign-in passed; database contained one Google identity and two successful Google sign-ins, with no duplicate identity |
| OAuth callback boundary | Callback without its initiating transaction rejected |
| Native rate limit | Bounded private-container test produced fifteen 401 responses followed by 429 with Retry-After; the real audit view showed auth.rate_limited |
| Forwarded headers | Public requests could not reuse a throttled synthetic private client by supplying X-Forwarded-For; Caddy overrode the supplied forwarding headers |
| Private files | Public credential, Git, source, and dependency paths returned 404 |
| Restart persistence | AWS host restarted during the final CloudFormation update; PostgreSQL users and the existing Google browser session survived; HTTPS readiness returned 200 afterward |
| Backup and recovery | Encrypted S3 dump uploaded; retrieved archive passed gzip integrity check, restored into an isolated disposable database, and matched all three account rows; disposable recovery data was removed |
| Browser interface | Registration/sign-in, role-aware navigation, settings, administration, and audit screens checked; desktop and 390-pixel mobile layouts checked |
| Secret handling | Runtime values stored in AWS Secrets Manager; private files ignored; deployed password/session/audit/Google secret values checked against every published Git revision and absent |

The backup timer was active. The deployment is a single EC2 host with private container-network PostgreSQL, encrypted EBS, no inbound SSH or database port, and Systems Manager administration. CloudFormation reached `UPDATE_COMPLETE`.

## Reproduce the checks

Use the disposable PostgreSQL setup in CI for `npm test`. Use [the smoke script](api.md#automated-smoke-checks) only against a deployment you own. The smoke script leaves a fictional member account and consumes login-rate-limit allowance. Browser Google verification needs your own authorized Google identity and OAuth configuration.

## Next tutorial phase

The SecureNow SDK remains disconnected in this baseline. No generated SecureNow threat-model report, exported telemetry, custom detection rule, delivered alert, IP block, SecureNow rate-limit rule, or CAPTCHA has been claimed as verified. Those are the next episode's exercises, following the [integration runbook](securenow-integration.md). Native application audit records and native 429 responses are separate evidence.
