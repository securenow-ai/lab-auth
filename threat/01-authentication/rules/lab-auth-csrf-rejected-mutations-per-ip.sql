-- rules/lab-auth-csrf-rejected-mutations-per-ip.sql
-- Traffic only. 403 API mutations that arrived without the X-CSRF-Token header or with a foreign Origin.
-- Each one also writes a csrf.rejected row to PostgreSQL before any rate limit (src/app.js:104-106).
-- Threshold: baseline required - conservative start (a real browser produces 0-2 after a stale tab).
WITH
  coalesce(nullIf(attributes_string['http.client_ip'], ''), nullIf(attributes_string['net.peer.ip'], ''), nullIf(attributes_string['network.peer.address'], ''), nullIf(attributes_string['client.address'], ''), nullIf(attributes_string['net.sock.peer.addr'], '')) AS client_ip,
  replaceRegexpOne(lower(decodeURLComponent(splitByChar('?', attributes_string['http.target'])[1])), '/+$', '') AS route,
  attributes_string['http.request.headers'] AS headers_json
SELECT
  client_ip AS ip,
  countIf(headers_json != '' AND (NOT JSONHas(headers_json, 'x-csrf-token') OR JSONExtractString(headers_json, 'origin') != 'https://lab-auth.labs.securenow.ai')) AS unverifiable_mutations,
  count() AS rejected_mutations
FROM signoz_traces.distributed_signoz_index_v3
WHERE `resource_string_service$$name` IN (__USER_APP_KEYS__)
  AND timestamp >= now64(9) - INTERVAL 15 MINUTE
  AND ts_bucket_start >= toUInt64(toUnixTimestamp(now() - INTERVAL 15 MINUTE)) - 1800
  AND kind = 2
  AND http_method IN ('POST', 'PUT', 'PATCH', 'DELETE')
  AND response_status_code = '403'
  AND route LIKE '/api/%'
GROUP BY ip
HAVING ip != '' AND unverifiable_mutations >= 20
