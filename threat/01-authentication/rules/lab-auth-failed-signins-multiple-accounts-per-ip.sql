-- rules/lab-auth-failed-signins-multiple-accounts-per-ip.sql
-- APP_EVENT: needs the proposed auth.login.failure export with account_ref (keyed HMAC of the normalized email).
-- One IP failing against several different accounts = reused-password lists or password spraying.
-- Threshold source: native limit 15 sign-in POSTs per IP per 15 min (src/config.js:24) -> alert at 10 failures over 5+ accounts.
SELECT
  attributes_string['http.client_ip'] AS ip,
  count() AS failed_signins,
  uniqExact(attributes_string['account_ref']) AS distinct_accounts
FROM signoz_logs.distributed_logs_v2
WHERE resources_string['service.name'] IN (__USER_APP_KEYS__)
  AND timestamp >= toUnixTimestamp64Nano(now64() - INTERVAL 15 MINUTE)
  AND attributes_string['event.type'] = 'auth.login.failure'
  AND attributes_string['auth_method'] = 'password'
GROUP BY ip
HAVING ip != '' AND failed_signins >= 10 AND distinct_accounts >= 5
