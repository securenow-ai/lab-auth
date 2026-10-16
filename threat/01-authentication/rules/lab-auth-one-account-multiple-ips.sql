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
