-- rules/lab-auth-registration-spike-global.sql
-- Traffic only. Two-stage global rule for mass account creation that rotates IPs to stay under the app's
-- 10 registrations per IP per 15 min (src/config.js:25, src/app.js:157). Returns the top contributing IPs.
-- Threshold: baseline required - conservative start (30 accepted registrations across all IPs in 60 min).
SELECT
  per_ip.ip AS ip,
  per_ip.registrations AS registrations_from_ip,
  g.total AS registrations_all_ips_60m
FROM
(
  WITH
    coalesce(nullIf(attributes_string['http.client_ip'], ''), nullIf(attributes_string['net.peer.ip'], ''), nullIf(attributes_string['network.peer.address'], ''), nullIf(attributes_string['client.address'], ''), nullIf(attributes_string['net.sock.peer.addr'], '')) AS client_ip,
    replaceRegexpOne(lower(decodeURLComponent(splitByChar('?', attributes_string['http.target'])[1])), '/+$', '') AS route
  SELECT client_ip AS ip, count() AS registrations
  FROM signoz_traces.distributed_signoz_index_v3
  WHERE `resource_string_service$$name` IN (__USER_APP_KEYS__)
    AND timestamp >= now64(9) - INTERVAL 60 MINUTE
    AND ts_bucket_start >= toUInt64(toUnixTimestamp(now() - INTERVAL 60 MINUTE)) - 1800
    AND kind = 2
    AND http_method = 'POST'
    AND route = '/api/auth/register'
    AND response_status_code = '201'
  GROUP BY ip
  HAVING ip != ''
) AS per_ip
CROSS JOIN
(
  WITH
    replaceRegexpOne(lower(decodeURLComponent(splitByChar('?', attributes_string['http.target'])[1])), '/+$', '') AS route
  SELECT count() AS total
  FROM signoz_traces.distributed_signoz_index_v3
  WHERE `resource_string_service$$name` IN (__USER_APP_KEYS__)
    AND timestamp >= now64(9) - INTERVAL 60 MINUTE
    AND ts_bucket_start >= toUInt64(toUnixTimestamp(now() - INTERVAL 60 MINUTE)) - 1800
    AND kind = 2
    AND http_method = 'POST'
    AND route = '/api/auth/register'
    AND response_status_code = '201'
) AS g
WHERE g.total >= 30
ORDER BY registrations_from_ip DESC
LIMIT 10
