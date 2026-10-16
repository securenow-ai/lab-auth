-- rules/lab-auth-registration-probing-per-ip.sql
-- APP_EVENT: needs auth.signup with outcome=created|existing exported at src/app.js:170 (result.rows[0] tells which).
-- The HTTP response is deliberately identical either way, but the operator can see the difference in telemetry.
-- existing = someone registering addresses that already have accounts (enumeration via register-then-sign-in);
-- created  = one IP creating several accounts (account farming / squatting other people's addresses).
-- Threshold source: native limit 10 registrations per IP per 15 min (src/config.js:25) -> 3 existing or 5 created in 60 min.
SELECT
  attributes_string['http.client_ip'] AS ip,
  countIf(attributes_string['outcome'] = 'existing') AS signups_on_existing_emails,
  countIf(attributes_string['outcome'] = 'created') AS accounts_created,
  count() AS signups
FROM signoz_logs.distributed_logs_v2
WHERE resources_string['service.name'] IN (__USER_APP_KEYS__)
  AND timestamp >= toUnixTimestamp64Nano(now64() - INTERVAL 60 MINUTE)
  AND attributes_string['event.type'] = 'auth.signup'
GROUP BY ip
HAVING ip != '' AND (signups_on_existing_emails >= 3 OR accounts_created >= 5)
