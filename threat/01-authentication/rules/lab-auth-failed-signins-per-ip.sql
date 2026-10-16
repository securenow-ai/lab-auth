-- rules/lab-auth-failed-signins-per-ip.sql
-- Traffic only: works as soon as the SDK preload runs (no app events needed).
-- Threshold source: the app's own limit of 15 POST /api/auth/login per IP per 15 min (src/config.js:24, src/app.js:173).
WITH
  coalesce(nullIf(attributes_string['http.client_ip'], ''), nullIf(attributes_string['net.peer.ip'], ''), nullIf(attributes_string['network.peer.address'], ''), nullIf(attributes_string['client.address'], ''), nullIf(attributes_string['net.sock.peer.addr'], '')) AS client_ip,
  replaceRegexpOne(lower(decodeURLComponent(splitByChar('?', attributes_string['http.target'])[1])), '/+$', '') AS route
SELECT
  client_ip AS ip,
  countIf(response_status_code = '401') AS failed_signins,
  countIf(response_status_code = '429') AS throttled_by_app,
  count() AS signin_posts
FROM signoz_traces.distributed_signoz_index_v3
WHERE `resource_string_service$$name` IN (__USER_APP_KEYS__)
  AND timestamp >= now64(9) - INTERVAL 15 MINUTE
  AND ts_bucket_start >= toUInt64(toUnixTimestamp(now() - INTERVAL 15 MINUTE)) - 1800
  AND kind = 2
  AND http_method = 'POST'
  AND route = '/api/auth/login'
GROUP BY ip
HAVING ip != '' AND failed_signins >= 10
