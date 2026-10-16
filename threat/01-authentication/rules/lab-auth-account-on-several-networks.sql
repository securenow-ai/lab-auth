-- rules/lab-auth-account-on-several-networks.sql
-- APP_EVENT: needs session.seen from securenow/sessions guard() with getSessionId/getUserId wired to the lab's
-- express-session (the guard's default cookie list does not include __Host-lab_auth). One account's live sessions
-- seen from 3+ different IPs within an hour = possible stolen session cookie in use elsewhere.
-- Threshold: baseline required - conservative start. Mobile/roaming users trip it: notify + human review, response = revoke.
SELECT
  attributes_string['enduser.id'] AS account,
  uniqExact(attributes_string['http.client_ip']) AS networks,
  uniqExact(attributes_string['session.id']) AS sessions,
  argMax(attributes_string['http.client_ip'], timestamp) AS ip
FROM signoz_logs.distributed_logs_v2
WHERE resources_string['service.name'] IN (__USER_APP_KEYS__)
  AND timestamp >= toUnixTimestamp64Nano(now64() - INTERVAL 60 MINUTE)
  AND attributes_string['event.type'] = 'session.seen'
GROUP BY account
HAVING account != '' AND ip != '' AND networks >= 3
