-- rules/lab-auth-failed-signins-per-network.sql
-- Traffic only. Failed sign-ins spread over many addresses of ONE network (/24 for IPv4, /64 for IPv6),
-- which stays under the app's per-IP limit (15 per IP per 15 min, src/config.js:24) by rotating addresses.
-- Threshold: baseline required - conservative start (4+ addresses, 15+ failures in 30 min). Returns the latest contributing IP.
WITH
  coalesce(nullIf(attributes_string['http.client_ip'], ''), nullIf(attributes_string['net.peer.ip'], ''), nullIf(attributes_string['network.peer.address'], ''), nullIf(attributes_string['client.address'], ''), nullIf(attributes_string['net.sock.peer.addr'], '')) AS client_ip,
  replaceRegexpOne(lower(decodeURLComponent(splitByChar('?', attributes_string['http.target'])[1])), '/+$', '') AS route
SELECT
  cutIPv6(IPv6StringToNumOrDefault(client_ip), 8, 1) AS network,
  uniqExact(client_ip) AS distinct_ips,
  count() AS failed_signins,
  argMax(client_ip, timestamp) AS ip
FROM signoz_traces.distributed_signoz_index_v3
WHERE `resource_string_service$$name` IN (__USER_APP_KEYS__)
  AND timestamp >= now64(9) - INTERVAL 30 MINUTE
  AND ts_bucket_start >= toUInt64(toUnixTimestamp(now() - INTERVAL 30 MINUTE)) - 1800
  AND kind = 2
  AND http_method = 'POST'
  AND route = '/api/auth/login'
  AND response_status_code = '401'
  AND client_ip != ''
GROUP BY network
HAVING ip != '' AND distinct_ips >= 4 AND failed_signins >= 15
