-- rules/lab-auth-authz-denied-probing.sql
-- Threat model 02-authorization (BFLA / forced browsing, OWASP API5:2023, CWE-285/CWE-862).
-- APP_EVENT: needs authz.denied exported from the requireRole gate (src/app.js:171-178). Today that gate
-- writes an authorization.denied row to the app's OWN security_events table (src/app.js:174) but does NOT
-- track() it to SecureNow, so this rule cannot fire until the gate is bridged (see code finding AZ-1).
-- Fires when ONE client is turned away from restricted routes repeatedly: >= 8 denials across >= 2 distinct
-- restricted routes in 30 minutes = a signed-in member (or a stolen low-privilege session) walking the admin
-- and analyst surface looking for a function-level hole. A member hitting one forbidden link once is normal,
-- so the floor is deliberately above casual misclicks. Grouped by the acting account AND client ip.
-- Threshold: baseline required - conservative start; test-first (promote after 3-7 days of real traffic).
SELECT
  account,
  ip,
  distinct_routes,
  denials
FROM
(
  SELECT
    attributes_string['enduser.id']                                   AS account,
    argMax(attributes_string['http.client_ip'], timestamp)            AS ip,
    uniqExact(attributes_string['route'])                             AS distinct_routes,
    count()                                                           AS denials
  FROM signoz_logs.distributed_logs_v2
  WHERE resources_string['service.name'] IN (__USER_APP_KEYS__)
    AND timestamp >= toUnixTimestamp64Nano(now64() - INTERVAL 30 MINUTE)
    AND attributes_string['event.type'] = 'authz.denied'
  GROUP BY account
)
WHERE denials >= 8 AND distinct_routes >= 2
ORDER BY denials DESC
LIMIT 100
