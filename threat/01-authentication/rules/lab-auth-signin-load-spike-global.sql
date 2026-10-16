-- rules/lab-auth-signin-load-spike-global.sql
-- Traffic only. Two-stage global rule: (1) prove the whole app crossed a volume or latency budget for the
-- password-hashing routes (scrypt N=32768, r=8: src/passwords.js:5), then (2) return the top contributing IPs.
-- Notify / manual containment only - never auto-block every contributor of a global anomaly.
-- Threshold: baseline required - conservative start (200 hashing POSTs in 5 min, or p95 >= 2 s with 50+ requests).
SELECT
  per_ip.ip AS ip,
  per_ip.hits AS hashing_posts_from_ip,
  g.total AS hashing_posts_all_ips_5m,
  g.p95_ms AS p95_latency_ms
FROM
(
  WITH
    coalesce(nullIf(attributes_string['http.client_ip'], ''), nullIf(attributes_string['net.peer.ip'], ''), nullIf(attributes_string['network.peer.address'], ''), nullIf(attributes_string['client.address'], ''), nullIf(attributes_string['net.sock.peer.addr'], '')) AS client_ip,
    replaceRegexpOne(lower(decodeURLComponent(splitByChar('?', attributes_string['http.target'])[1])), '/+$', '') AS route
  SELECT client_ip AS ip, count() AS hits
  FROM signoz_traces.distributed_signoz_index_v3
  WHERE `resource_string_service$$name` IN (__USER_APP_KEYS__)
    AND timestamp >= now64(9) - INTERVAL 5 MINUTE
    AND ts_bucket_start >= toUInt64(toUnixTimestamp(now() - INTERVAL 5 MINUTE)) - 1800
    AND kind = 2
    AND http_method = 'POST'
    AND route IN ('/api/auth/login', '/api/auth/register', '/api/auth/password')
  GROUP BY ip
  HAVING ip != ''
) AS per_ip
CROSS JOIN
(
  WITH
    replaceRegexpOne(lower(decodeURLComponent(splitByChar('?', attributes_string['http.target'])[1])), '/+$', '') AS route
  SELECT count() AS total, round(quantile(0.95)(duration_nano) / 1000000) AS p95_ms
  FROM signoz_traces.distributed_signoz_index_v3
  WHERE `resource_string_service$$name` IN (__USER_APP_KEYS__)
    AND timestamp >= now64(9) - INTERVAL 5 MINUTE
    AND ts_bucket_start >= toUInt64(toUnixTimestamp(now() - INTERVAL 5 MINUTE)) - 1800
    AND kind = 2
    AND http_method = 'POST'
    AND route IN ('/api/auth/login', '/api/auth/register', '/api/auth/password')
) AS g
WHERE g.total >= 200 OR (g.p95_ms >= 2000 AND g.total >= 50)
ORDER BY hashing_posts_from_ip DESC
LIMIT 5
