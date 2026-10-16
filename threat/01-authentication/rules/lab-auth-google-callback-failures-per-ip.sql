-- rules/lab-auth-google-callback-failures-per-ip.sql
-- APP_EVENT: needs auth.login.failure with auth_method=oauth, provider=google and reason, exported where the app
-- records auth.google_failed (src/app.js:228, 257). Repeated invalid/expired/replayed callbacks or rejected Google
-- tokens from one IP = callback replay, forged state, or code-injection attempts. Protocol depth: ../07-oauth-sso-integrations/.
-- Threshold source: native limit 30 callbacks per IP per 15 min (src/app.js:222) -> alert at 5 failures.
SELECT
  attributes_string['http.client_ip'] AS ip,
  count() AS failed_callbacks,
  countIf(attributes_string['reason'] = 'invalid_callback') AS invalid_or_replayed_state,
  countIf(attributes_string['reason'] = 'provider_verification') AS provider_rejections
FROM signoz_logs.distributed_logs_v2
WHERE resources_string['service.name'] IN (__USER_APP_KEYS__)
  AND timestamp >= toUnixTimestamp64Nano(now64() - INTERVAL 15 MINUTE)
  AND attributes_string['event.type'] = 'auth.login.failure'
  AND attributes_string['auth_method'] = 'oauth'
  AND attributes_string['provider'] = 'google'
  AND attributes_string['reason'] IN ('invalid_callback', 'provider_verification')
GROUP BY ip
HAVING ip != '' AND failed_callbacks >= 5
