-- rules/lab-auth-session-survives-password-change.sql
-- APP_EVENT: needs auth.security.change (action=password_changed, outcome=completed) and session.seen (guard()).
-- The app is supposed to kill every older session on password change via session_version (src/app.js:93, 202).
-- This fires only if a session that was ALREADY live before the change is still seen 5+ minutes after it,
-- so a user simply signing in again on a second device does not trip it. Near-zero false positives.
SELECT account, surviving_sessions, ip
FROM
(
  SELECT
    attributes_string['enduser.id'] AS account,
    maxIf(timestamp, attributes_string['event.type'] = 'auth.security.change'
                     AND attributes_string['action'] = 'password_changed'
                     AND attributes_string['outcome'] = 'completed') AS t_changed,
    groupArrayIf((timestamp, attributes_string['session.id']), attributes_string['event.type'] = 'session.seen') AS seen,
    arrayDistinct(arrayMap(x -> x.2, arrayFilter(x -> x.1 < t_changed, seen))) AS sessions_before,
    arrayDistinct(arrayMap(x -> x.2, arrayFilter(x -> x.1 > t_changed + 300000000000, seen))) AS sessions_after,
    length(arrayIntersect(sessions_before, sessions_after)) AS surviving_sessions,
    argMax(attributes_string['http.client_ip'], timestamp) AS ip
  FROM signoz_logs.distributed_logs_v2
  WHERE resources_string['service.name'] IN (__USER_APP_KEYS__)
    AND timestamp >= toUnixTimestamp64Nano(now64() - INTERVAL 1 DAY)
    AND attributes_string['event.type'] IN ('auth.security.change', 'session.seen')
  GROUP BY account
  HAVING account != '' AND ip != '' AND t_changed > 0
)
WHERE surviving_sessions >= 1
