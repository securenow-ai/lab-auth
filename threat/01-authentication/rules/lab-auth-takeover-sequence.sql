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
