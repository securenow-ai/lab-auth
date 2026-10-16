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
