-- rules/lab-auth-native-limit-429-per-ip.sql
-- Traffic only. An IP that keeps sending auth requests after the app answered 429 (its own PostgreSQL-backed limit).
-- Threshold source: native limits in src/config.js:24-26 and src/app.js:157,173,194,210,222 (5 post-limit requests = automation, not a person).
WITH
  coalesce(nullIf(attributes_string['http.client_ip'], ''), nullIf(attributes_string['net.peer.ip'], ''), nullIf(attributes_string['network.peer.address'], ''), nullIf(attributes_string['client.address'], ''), nullIf(attributes_string['net.sock.peer.addr'], '')) AS client_ip,
  replaceRegexpOne(lower(decodeURLComponent(splitByChar('?', attributes_string['http.target'])[1])), '/+$', '') AS route
SELECT
  client_ip AS ip,
  count() AS throttled_requests,
  countIf(route = '/api/auth/login') AS throttled_signins,
  countIf(route = '/api/auth/register') AS throttled_registrations,
  countIf(route = '/api/auth/password') AS throttled_password_changes,
  countIf(route LIKE '/api/auth/google%') AS throttled_google
FROM signoz_traces.distributed_signoz_index_v3
WHERE `resource_string_service$$name` IN (__USER_APP_KEYS__)
  AND timestamp >= now64(9) - INTERVAL 15 MINUTE
  AND ts_bucket_start >= toUInt64(toUnixTimestamp(now() - INTERVAL 15 MINUTE)) - 1800
  AND kind = 2
  AND response_status_code = '429'
  AND route LIKE '/api/auth/%'
GROUP BY ip
HAVING ip != '' AND throttled_requests >= 5
