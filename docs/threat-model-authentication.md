# Authentication threat model · Episode 1 foundation

This document is a code-grounded teaching inventory for the checked-in baseline. It is not a generated SecureNow audit report, a penetration-test certificate, or evidence that a detection has fired. When the tutorial report is produced, record its date and repository commit and reconcile its findings with this inventory.

## Scope and assets

Scope: registration, password sign-in, Google OpenID Connect sign-in, session lifecycle, password change, and role checks supporting those flows. Dashboard projects and metrics are fictional static data. Email delivery, password recovery, MFA, and deliberate account linking are not implemented.

Assets include password hashes, live session identifiers, Google OAuth client credentials and transient authorization material, user identities/roles, security audit records, and cloud/runtime credentials. Authentication is an entry boundary; authorization still has to be checked on every privileged operation.

| Boundary | Security assumption |
| --- | --- |
| Browser → Caddy | HTTPS protects credentials in transit; browser content is untrusted |
| Caddy → Express | Caddy is the only ingress to the app container and overwrites forwarded client-IP headers |
| Express → PostgreSQL | Database is private; database role/runtime secrets remain protected |
| Express ↔ Google | Server verifies the provider's identity evidence and binds it to the initiating session |
| Member → analyst/admin API | Role is authoritative in PostgreSQL; browser navigation visibility grants no authority |
| Operator → AWS | Least-privilege AWS principal and Systems Manager access are separately controlled |
| App → future SecureNow SDK | Exported telemetry must be scoped, minimized, and redacted; runtime key stays private |

## Implemented baseline controls

The main implementation is in [src/app.js](../src/app.js), [src/passwords.js](../src/passwords.js), [src/config.js](../src/config.js), and the [database schema](../db/).

- Passwords are 12–128 characters and hashed with Node's `scrypt`, a random 16-byte salt, and parameters `N=32768`, `r=8`, `p=1`, using a 64-byte derived key. Comparisons use `timingSafeEqual`. Missing accounts use a dummy password-hash verification path.
- Login uses the same error for unknown email and wrong password. Registration returns the same `201` envelope for a new or already registered email and requires a separate login.
- Fixed-window abuse buckets are stored in PostgreSQL. The configured window is 15 minutes: login 15 requests/IP and 30 requests/account key, registration 10/IP, password change 5/IP, and Google initiation/callback 30/IP per route category. These survive app restarts; they do not eliminate distributed abuse or shared-IP friction.
- Sessions are stored server-side in PostgreSQL. Production cookies use `__Host-lab_auth`, `Secure`, `HttpOnly`, `SameSite=Lax`, path `/`, and no Domain attribute. The configured idle expiry is 30 minutes and absolute authenticated lifetime eight hours.
- Successful authentication regenerates the session. Password changes and role changes increment a user's `session_version`, invalidating that user's previous sessions on their next request. Password changes require the current password. Logout destroys the current session.
- JSON API mutations require the configured exact `Origin`, a valid per-session `X-CSRF-Token`, and JSON content type. Cross-site fetch metadata is rejected. A fresh token is returned after authentication/password changes.
- Google sign-in uses session-bound state and nonce, PKCE S256, a ten-minute transaction lifetime, and a single-use transaction record. `google-auth-library` verifies the ID token; the application also checks nonce, issuer, subject, and verified email. Identity is keyed by Google subject. It does not silently link an existing password account by matching email.
- Role enforcement runs on the server and reads the user from PostgreSQL on each authenticated request. Public registration creates a `member`. Analyst/admin routes require their explicit roles. Changing roles invalidates existing sessions. An administrator cannot demote their own account through the role endpoint.
- SQL values use parameters. JSON bodies are limited to 8 KiB. Responses apply a restrictive same-origin content-security policy, anti-framing headers, no-referrer policy, and `no-store` for API responses.
- Audit records contain event type/outcome, opaque user/request identifiers, selected bounded metadata, and an HMAC of client IP. They do not intentionally contain password/token values or email addresses. IP HMAC values are not returned by the security API. Retention cleanup is configured by the server; review its running configuration and successful maintenance before relying on deletion.

These are implementation facts, not claims of complete attack resistance. Integration tests and deployment checks provide narrower evidence about the behaviors they exercise.

## Threats, observation, and code work

| Threat | Baseline protection and remaining risk | Useful observation | Required code/design work if risk is accepted as a finding |
| --- | --- | --- | --- |
| Guessing or credential stuffing | Persistent IP/account-key throttling and expensive salted hashes; distributed sources and reused credentials remain possible | Failed logins, rate-limit events, source diversity, success after failures | Add breached-password checks, risk-based step-up, and MFA/passkeys; tune limits using real usage |
| User enumeration | Generic login/registration responses and dummy KDF path; equal wording does not prove equal timing | Repeated failures/registration attempts and response-distribution tests | Measure timing and error consistency, review every new recovery/linking endpoint |
| Registration with an unowned email | Password registrations are deliberately unverified | Registration/request patterns; verification state at authorization boundaries | Add verified-email flow with expiring one-time token and safe delivery before granting email-dependent access |
| Session theft or fixation | HTTPS/cookie flags, server-side state, regeneration, bounded lifetime; a stolen live cookie is still a bearer credential | Session changes and unusual access patterns, without logging the cookie | Add MFA/step-up for sensitive work, user session revocation controls, and evaluated device-risk logic |
| CSRF, including login CSRF | Exact origin and session token for JSON mutations; OAuth state binds the redirect | `csrf.rejected`, invalid OAuth callback evidence | Preserve defenses when adding endpoints; test cross-origin, missing-token, and stale-token cases |
| OAuth identity substitution/replay | State, nonce, PKCE, verified token claims, transaction expiry/single use | `auth.google_failed` with reason category | Keep library/security updates current; test bad nonce/state/audience/expiry; never replace verification with token decoding |
| Unsafe account linking | Google subject is authoritative; same-email password account conflict is rejected | `identity_conflict` Google failure | Implement linking only inside an authenticated session, with recent reauthentication and proof of both identities |
| Privilege escalation | Server-side role checks and session-version invalidation; admin compromise is highly consequential | `authorization.denied`, `admin.role_changed` | Add admin MFA/recent reauthentication, role-change review and notifications as the app grows |
| Password-change takeover | Current password required, limited attempts, other sessions invalidated | `auth.password_change_failed`, `auth.password_changed` | Add MFA step-up, user notification, and tested recovery procedures |
| Lockout or resource-exhaustion abuse | Fixed windows bound expensive operations; shared IPs/account-key limits can affect legitimate users | `429`, latency, KDF load, database health | Add bounded concurrency, adaptive challenges, fair limits, and measured recovery; avoid permanent attacker-triggered lockout |
| Injection or script stealing credentials | Parameterized queries, external scripts, CSP, escaped UI values; future features can break these assumptions | Error anomalies and independent code review | Maintain encoding and query parameters; review future HTML, rich text, uploads, and redirects |
| Leaked secrets or sensitive telemetry | Private env/secret storage and minimized audit table; a future SDK may capture more | Sanitized export inspection and credential-access audit | Disable unnecessary body capture, verify field redaction, rotate leaked credentials, restrict backup access |
| Missing account recovery or MFA | Neither feature is present | A detector cannot supply the feature | Design, implement, and test the actual flows, including lost-device and support abuse cases |

## Detection is separate from correction

A code fix changes what the application permits: for example, rejecting a forged OAuth state or requiring a second factor. Detection identifies suspicious evidence. Response changes access after that evidence, such as a scoped rate limit or an IP block. Each has a separate verification step.

Blocking an abusive source does not correct missing MFA, unsafe identity linking, weak password hashing, or a role-check defect. CAPTCHA needs a real challenge and server-side verification in application code; the baseline has no CAPTCHA provider. An IP block may also affect legitimate users behind the same address, so record the scope and rollback.

The audit event helper currently writes to PostgreSQL. Loading an HTTP tracing SDK does not automatically export those database audit rows as structured logs. During the SecureNow phase, either use verified route/status traces or add a privacy-preserving structured export bridge and test it before writing event-based detectors. Stable account correlation for distributed login attempts is also a separate instrumentation decision; current failed-login audit rows intentionally omit an email/account identifier.

## Audit event catalogue

| Event | Meaning |
| --- | --- |
| `auth.registration_requested` | Uniformly recorded registration request; not proof of email ownership |
| `auth.login_failed` / `auth.login_succeeded` | Password result, or successful verified Google authentication |
| `auth.logout` | Authenticated user ended the current session |
| `auth.rate_limited` | A native application rate bucket rejected a request |
| `auth.password_change_failed` / `auth.password_changed` | Password-change result |
| `auth.google_failed` | Invalid callback, provider verification failure, or identity conflict |
| `csrf.rejected` | API mutation failed origin/session-token verification |
| `authorization.denied` | Authenticated user's role did not permit a route |
| `admin.role_changed` | Administrator changed another account's role |

Audit logging can fail when the database is unavailable. Monitor database health and logging failures; do not assume a missing record proves a request never happened. The application does not provide immutable external audit storage or alert delivery in its baseline.

## Review and verification record

For the later report, maintain a row per finding with: identifier, affected commit/code, assumptions, severity rationale, code change, regression check, detection status, mitigation status, evidence reference, and residual risk. Use statuses such as `CONFIRMED`, `NEEDS_INSTRUMENTATION`, `NEEDS_BASELINE`, `NEEDS_CUSTOMER_DECISION`, and `FIXED_AND_TESTED` only when the associated evidence exists.

The [SecureNow runbook](securenow-integration.md) describes a controlled sequence from model to instrumentation, validated rule, delivered alert, enforced mitigation, legitimate-user check, and rollback. The later video should show those observed results and explain the code fixes independently.
