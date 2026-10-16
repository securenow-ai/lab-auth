# Attack simulations

Bounded authentication-abuse simulations that drive the SecureNow detections built from this lab's
threat model, so you can watch the full loop: **attack → SecureNow detects → SecureNow responds**.

Every scenario runs against **your own local copy** of the lab (`http://localhost:3000`). Attacker
addresses are TEST-NET documentation ranges (RFC 5737) sent in `X-Forwarded-For`, exactly as a reverse
proxy forwards the real client IP in production; the local app trusts only its loopback proxy, so the
app's own limits, its audit events and the SecureNow traces all see the simulated address. The scripts
refuse to run against anything that is not localhost. Counts are small and capped — this is a teaching
demo, not a load test. **Do not point these at a deployment.**

## Prerequisites

1. The lab running locally with SecureNow loaded: `node -r securenow/register src/server.js`.
2. The SecureNow app connected (`npx securenow app connect`) so `.securenow/runtime.json` has the app key.
3. For the `credential-stuffing-success` and `registration-probing` scenarios, a **fictional** account
   you registered on your local copy: create `attack-simulation/test-account.local.json` (gitignored)
   with `{ "email": "...", "password": "..." }`, or set `LAB_TEST_EMAIL` / `LAB_TEST_PASSWORD`.

## Run

```sh
node attack-simulation/attack.mjs list              # list scenarios
node attack-simulation/attack.mjs password-guessing # run one

# To see a fresh detect→respond loop on an IP you have attacked before, pick an unused TEST-NET block:
SIM_NET=198.51.100 node attack-simulation/attack.mjs password-guessing
```

SecureNow groups an alert by rule + IP, so re-attacking the same IP updates the existing alert instead
of raising a new one. Use a different `SIM_NET` (203.0.113, 198.51.100, or 192.0.2) for a clean run.

## Scenarios

| Scenario | The attack | SecureNow detection | Automatic / assisted response |
| --- | --- | --- | --- |
| `password-guessing` | One IP tries wrong passwords across six accounts, past the app's own 429. | **R01 / R10** repeated failed sign-ins per IP / across accounts. | **AUTO-A** rate-limits the IP on `/api/auth/login` (5 / 15 min). High-confidence hits are parked for human block approval. |
| `network-spread` | Five addresses of one /24 share the guessing, 3 each, under every per-IP limit. | **R06** failed sign-ins spread across one network block. | Notify + human review; apply a network rate limit. |
| `surface-probing` | Forced browsing for `.env`, `.git`, `wp-login.php`, backups, admin panels. | **R05** auth-surface probing, with an **instant** condition on credential-file paths. | **Instant block** on the first dotfile request (seconds), plus **AUTO-E** proof-of-work challenge. |
| `csrf-flood` | API writes with no CSRF token (each also writes an audit row — finding F2). | **R04** CSRF-rejected API mutations per IP. | **AUTO-D** rate-limits the IP on `/api/*`. |
| `session-minting` | Cookieless `/api/me` requests; each makes the app write a session row (finding F1). | **R03** anonymous session minting per IP. | **AUTO-C** rate-limits the session endpoints. |
| `credential-stuffing-success` | Five wrong passwords, then the correct one — a guessed password being used. | **R12** successful sign-in after repeated failures. | Notify + human review → **revoke** the session/user (`securenow revoke`). |
| `registration-probing` | Registering addresses that already have accounts (enumeration via register). | **R23** registration probing per IP. | **AUTO-G** rate-limits registrations (3 / hour). |

The response thresholds, rule SQL and the exact `automation` definitions are in the threat-model report
under `threat/01-authentication/` (sections 7 and 10).

## What the output means

Each line shows the HTTP status and, when SecureNow answered rather than the app, which layer did:

- `403 SecureNow block` — the firewall blocked the IP (instant block, or an approved block).
- `429 SecureNow rate limit` — the firewall's rate limit (stricter than the app's own limit).
- a plain status (`401`, `403`, `201`, `200`) — the app answered; SecureNow is still detecting, or the
  automatic response has not synced yet (the SDK firewall syncs new rules about once a minute).

Re-run a scenario after a minute to see the app's answers replaced by SecureNow's.

## Cleaning up

Mitigation entries created during a run carry a TTL and expire on their own. To remove them now:

```sh
APP=<your lab app key>
npx securenow blocklist list  --app $APP --env test --status active     # then: blocklist unblock <id> --yes
npx securenow ratelimit list  --app $APP --env test                     # then: ratelimit remove <id> --yes
npx securenow challenge list  --app $APP --env test                     # then: challenge remove <id> --yes
npx securenow revoke list     --app $APP --env test                     # then: revoke restore <id> --yes
```
