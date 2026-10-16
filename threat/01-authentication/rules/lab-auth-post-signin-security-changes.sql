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
