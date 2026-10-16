-- rules/lab-auth-google-link-refusals.sql
-- APP_EVENT: needs auth.account.link (outcome=rejected, provider=google, reason=existing_email_other_method), exported where
-- the app refuses to attach a Google identity to an existing password account (src/app.js:247-250).
-- Two-stage: per-IP probing (3+ in 60 min) OR an app-wide spike (5+ in 60 min) that usually means real users are locked out.
-- Notify only - this points at a UX/code fix (verified-email linking), never at an automated block.
SELECT
  per_ip.ip AS ip,
  per_ip.refusals AS refusals_from_ip,
  g.total AS refusals_all_ips_60m
FROM
(
  SELECT attributes_string['http.client_ip'] AS ip, count() AS refusals
  FROM signoz_logs.distributed_logs_v2
  WHERE resources_string['service.name'] IN (__USER_APP_KEYS__)
    AND timestamp >= toUnixTimestamp64Nano(now64() - INTERVAL 60 MINUTE)
    AND attributes_string['event.type'] = 'auth.account.link'
    AND attributes_string['outcome'] = 'rejected'
  GROUP BY ip
  HAVING ip != ''
) AS per_ip
CROSS JOIN
(
  SELECT count() AS total
  FROM signoz_logs.distributed_logs_v2
  WHERE resources_string['service.name'] IN (__USER_APP_KEYS__)
    AND timestamp >= toUnixTimestamp64Nano(now64() - INTERVAL 60 MINUTE)
    AND attributes_string['event.type'] = 'auth.account.link'
    AND attributes_string['outcome'] = 'rejected'
) AS g
WHERE per_ip.refusals >= 3 OR g.total >= 5
ORDER BY refusals_from_ip DESC
LIMIT 10
