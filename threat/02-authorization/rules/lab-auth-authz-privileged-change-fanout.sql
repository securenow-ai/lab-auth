-- rules/lab-auth-authz-privileged-change-fanout.sql
-- Threat model 02-authorization (compromised-admin privilege grant / role fan-out, OWASP API5:2023, CWE-269).
-- APP_EVENT: reads auth.security.change (action=role_changed) already exported from the role route (src/app.js:413).
-- The role route stamps direction=elevate|reduce|same and target_ref (the changed account) - so no new instrumentation
-- is needed for this rule; it reuses what the 01-authentication bridge already sends.
-- Two shapes, grouped by the acting admin over 1 hour:
--   privilege_elevations: ANY member/analyst -> admin (or analyst) elevation. Rare and high value on its own.
--   accounts_changed:     one admin touching >= 3 distinct accounts' roles = a compromised admin spraying grants.
-- NOTE: the 01-authentication rule "post-sign-in security changes needing review" (rule 6ad21772...d004, H39a/L53)
-- already covers elevation + admin-changing-3+-accounts from the AUTHENTICATION angle. Prefer promoting/scoping that
-- rule over running a duplicate; this SQL is the authorization-category framing and the fallback if that rule is paused.
-- Threshold: elevation = every occurrence; fan-out >= 3 accounts/hour. prod-ready (exact action + direction).
SELECT
  attributes_string['enduser.id']                                                              AS admin_account,
  countIf(attributes_string['action'] = 'role_changed' AND attributes_string['direction'] = 'elevate') AS privilege_elevations,
  uniqExactIf(attributes_string['target_ref'], attributes_string['action'] = 'role_changed')   AS accounts_changed,
  argMax(attributes_string['http.client_ip'], timestamp)                                        AS ip
FROM signoz_logs.distributed_logs_v2
WHERE resources_string['service.name'] IN (__USER_APP_KEYS__)
  AND timestamp >= toUnixTimestamp64Nano(now64() - INTERVAL 60 MINUTE)
  AND attributes_string['event.type'] = 'auth.security.change'
  AND attributes_string['action'] = 'role_changed'
GROUP BY admin_account
HAVING privilege_elevations >= 1 OR accounts_changed >= 3
ORDER BY privilege_elevations DESC, accounts_changed DESC
LIMIT 100
