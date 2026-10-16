-- rules/lab-auth-anonymous-session-minting-per-ip.sql
-- Traffic only (Node tracer records redacted request headers as http.request.headers; the cookie VALUE is redacted, the key stays).
-- Every cookieless GET to these routes makes the app write a new row to the PostgreSQL sessions table (src/app.js:151-155).
-- Threshold: baseline required - conservative start. A browser mints one session per visit; 60 in 15 min is scripted.
WITH
  coalesce(nullIf(attributes_string['http.client_ip'], ''), nullIf(attributes_string['net.peer.ip'], ''), nullIf(attributes_string['network.peer.address'], ''), nullIf(attributes_string['client.address'], ''), nullIf(attributes_string['net.sock.peer.addr'], '')) AS client_ip,
  replaceRegexpOne(lower(decodeURLComponent(splitByChar('?', attributes_string['http.target'])[1])), '/+$', '') AS route,
  attributes_string['http.request.headers'] AS headers_json
SELECT
  client_ip AS ip,
  countIf(headers_json != '' AND NOT JSONHas(headers_json, 'cookie')) AS cookieless_session_requests,
  count() AS session_endpoint_requests
FROM signoz_traces.distributed_signoz_index_v3
WHERE `resource_string_service$$name` IN (__USER_APP_KEYS__)
  AND timestamp >= now64(9) - INTERVAL 15 MINUTE
  AND ts_bucket_start >= toUInt64(toUnixTimestamp(now() - INTERVAL 15 MINUTE)) - 1800
  AND kind = 2
  AND http_method IN ('GET', 'HEAD')
  AND route IN ('/api/me', '/api/auth/session', '/api/auth/csrf', '/api/auth/google')
GROUP BY ip
HAVING ip != '' AND cookieless_session_requests >= 60
