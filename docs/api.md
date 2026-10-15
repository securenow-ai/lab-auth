# API and local verification

The app serves its UI and JSON API from one origin. It does not require browser local-storage tokens or a public OAuth secret. JSON API errors use `{ "error": { "code": "...", "message": "..." } }`.

## Session and CSRF contract

Fetch `GET /api/auth/session` (alias `GET /api/me`) with cookies enabled. It returns `{ user, csrfToken, googleEnabled }`, with `user: null` before login. `GET /api/auth/csrf` returns just the current CSRF token.

For every JSON mutation, send the cookie, `Origin` equal to `APP_ORIGIN`, `Content-Type: application/json`, and `X-CSRF-Token` from that session. A successful login or password change rotates the session and returns a replacement token; use that token for the next mutation. Browser fetches from the app do this through the frontend helper.

| Method/path | Purpose | Access |
| --- | --- | --- |
| `GET /healthz` | Process liveness | Public |
| `GET /readyz` | Database readiness | Public |
| `GET /api/auth/session` | Current session, CSRF token, Google enabled flag | Public |
| `POST /api/auth/register` | `{ name, email, password }`; uniform registration response, then sign in | Public + CSRF + registration limit |
| `POST /api/auth/login` | `{ email, password }`; new authenticated session | Public + CSRF + IP/account limits |
| `POST /api/auth/logout` | Destroy current session | CSRF |
| `POST /api/auth/password` | `{ currentPassword, newPassword }`; rotate sessions | Authenticated + CSRF + limit |
| `GET /api/auth/google` | Begin Google authorization redirect | Public + limit, provider configured |
| `GET /api/auth/google/callback` | Complete bound Google transaction | Valid single-use transaction + limit |
| `GET /api/dashboard` | Fictional projects, metrics, and team data | Member, analyst, admin |
| `GET /api/security` | Recent audit events and caller's session summaries | Analyst, admin |
| `GET /api/admin/users` | Up to 100 user summaries | Admin |
| `PATCH /api/admin/users/:id/role` | `{ role: "member" | "analyst" | "admin" }` | Admin + CSRF |

`PATCH /api/admin/users/:id` is a role-update alias. Public registration ignores any requested privileged role. The security API does not return raw session IDs or IP hashes. All API responses use `Cache-Control: no-store`.

## Smoke-test sequence

Use invented accounts and a local deployment. Keep browser developer tools open to inspect status codes and cookies without sharing secret values.

1. Confirm `/healthz` and `/readyz` succeed. Confirm an anonymous dashboard request returns `401`.
2. Register a new account using a 12–128 character password, then sign in. Confirm it has `member` role.
3. Register the same address again. Confirm the registration envelope is unchanged and does not authenticate the caller.
4. Sign in with a wrong password and with an unknown address. Confirm both use the same `401` error envelope.
5. Attempt a mutation without its CSRF token and with a mismatched origin. Confirm `403` and a corresponding audit event.
6. As a member, request analyst/admin routes. Confirm `403`, even when manually entering a route or modifying browser state.
7. As a bootstrap admin, promote a different fictional account to analyst. Confirm that account's existing session is invalidated, then reauthenticate and inspect the security view. Confirm it still cannot manage roles.
8. Change a password with the correct current password. Confirm the current session rotates and a second browser's old session no longer authenticates. Confirm the old password fails on a subsequent login.
9. Sign out and confirm the session no longer authenticates.
10. When configured, complete the [real Google flow](google-oauth.md) with an authorized test account. Mocked provider tests and callback-rejection checks do not replace this step.

Run rate-limit checks only against your own isolated copy, with bounded request counts and a recovery path. The native `429` response is application enforcement, not evidence that a SecureNow detector or remediation rule is active.
