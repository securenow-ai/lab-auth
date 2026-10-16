-- rules/lab-auth-one-ip-signs-into-multiple-accounts.sql
-- APP_EVENT: needs auth.login.success with userId. One IP successfully entering several different accounts =
-- working a list of valid credentials, or account farming. Shared NAT / office egress can trip it: notify only.
-- Threshold: baseline required - conservative start (3 distinct accounts in 60 min).
SELECT
  attributes_string['http.client_ip'] AS ip,
  uniqExact(attributes_string['enduser.id']) AS accounts_signed_in,
  count() AS successful_signins
FROM signoz_logs.distributed_logs_v2
WHERE resources_string['service.name'] IN (__USER_APP_KEYS__)
  AND timestamp >= toUnixTimestamp64Nano(now64() - INTERVAL 60 MINUTE)
  AND attributes_string['event.type'] = 'auth.login.success'
GROUP BY ip
HAVING ip != '' AND accounts_signed_in >= 3
