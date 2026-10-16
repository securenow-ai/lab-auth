-- rules/lab-auth-event-integrity.sql
-- APP_EVENT: checks the lab's own exported auth events for signs of forging, replay, or a broken bridge.
-- duplicate_request_ids: the same request_id (the app's per-request UUID, src/app.js:63) on two events of one type;
-- missing_auth_method:   auth.login.* without the required auth_method attribute;
-- future_dated:          events stamped more than 5 minutes in the future (events carry a sender-supplied timestamp).
-- Any hit is worth a look; synthetic `event send` tests in this report always include auth_method.
SELECT
  attributes_string['http.client_ip'] AS ip,
  countIf(attributes_string['request_id'] != '')
    - uniqExactIf(concat(attributes_string['event.type'], '|', attributes_string['request_id']), attributes_string['request_id'] != '') AS duplicate_request_ids,
  countIf(attributes_string['event.type'] IN ('auth.login.success', 'auth.login.failure') AND attributes_string['auth_method'] = '') AS missing_auth_method,
  countIf(timestamp > toUnixTimestamp64Nano(now64() + INTERVAL 5 MINUTE)) AS future_dated,
  count() AS events
FROM signoz_logs.distributed_logs_v2
WHERE resources_string['service.name'] IN (__USER_APP_KEYS__)
  AND timestamp >= toUnixTimestamp64Nano(now64() - INTERVAL 60 MINUTE)
  AND attributes_string['event.type'] IN ('auth.login.success', 'auth.login.failure', 'auth.signup', 'auth.logout',
      'auth.security.change', 'auth.account.link', 'api.ratelimit.exceeded')
GROUP BY ip
HAVING ip != '' AND (duplicate_request_ids >= 1 OR missing_auth_method >= 1 OR future_dated >= 1)
