-- rules/lab-auth-signin-after-failures.sql
-- APP_EVENT: needs auth.login.failure + auth.login.success, both carrying account_ref.
-- Ordered sequence per account: at least 5 failures, then a success, within 30 minutes = probable guessed password.
-- Threshold: baseline required - conservative start. Returns the IP that SUCCEEDED (the one to contain).
SELECT
  attributes_string['account_ref'] AS account_ref,
  countIf(attributes_string['event.type'] = 'auth.login.failure') AS failures,
  uniqExactIf(attributes_string['http.client_ip'], attributes_string['event.type'] = 'auth.login.failure') AS failure_ips,
  sequenceMatch('(?1).*(?1).*(?1).*(?1).*(?1).*(?2)')(
    timestamp,
    attributes_string['event.type'] = 'auth.login.failure',
    attributes_string['event.type'] = 'auth.login.success') AS failures_then_success,
  argMaxIf(attributes_string['http.client_ip'], timestamp, attributes_string['event.type'] = 'auth.login.success') AS ip
FROM signoz_logs.distributed_logs_v2
WHERE resources_string['service.name'] IN (__USER_APP_KEYS__)
  AND timestamp >= toUnixTimestamp64Nano(now64() - INTERVAL 30 MINUTE)
  AND attributes_string['event.type'] IN ('auth.login.failure', 'auth.login.success')
GROUP BY account_ref
HAVING account_ref != '' AND ip != '' AND failures_then_success = 1
