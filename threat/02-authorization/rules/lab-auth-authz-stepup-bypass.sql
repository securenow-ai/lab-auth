-- rules/lab-auth-authz-stepup-bypass.sql
-- Threat model 02-authorization (missing step-up on a privileged function, OWASP API5:2023, CWE-306/CWE-862).
-- APP_EVENT: needs authz.denied with reason='step_up_required' exported from the role route's step-up gate
-- (src/app.js:403-405). The gate already returns 403 STEP_UP_REQUIRED; it must also track() the denial (finding AZ-1).
-- A real admin re-enters their password once (POST /api/auth/reauth) and proceeds, so one step-up prompt is normal.
-- This fires when an admin SESSION repeatedly reaches the role-change route WITHOUT a fresh re-auth: >= 3
-- step_up_required denials from one account in 15 minutes = a stolen/replayed admin cookie that holds the session
-- but not the password, probing the one function that still asks for it. Near-zero false positives.
-- Threshold: 3 in 15 min; prod-ready (exact reason string, high-value function).
SELECT
  attributes_string['enduser.id']                          AS account,
  argMax(attributes_string['http.client_ip'], timestamp)   AS ip,
  attributes_string['session.id']                          AS session_ref,
  count()                                                  AS stepup_blocks
FROM signoz_logs.distributed_logs_v2
WHERE resources_string['service.name'] IN (__USER_APP_KEYS__)
  AND timestamp >= toUnixTimestamp64Nano(now64() - INTERVAL 15 MINUTE)
  AND attributes_string['event.type'] = 'authz.denied'
  AND attributes_string['reason'] = 'step_up_required'
GROUP BY account, session_ref
HAVING stepup_blocks >= 3
ORDER BY stepup_blocks DESC
LIMIT 100
