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
