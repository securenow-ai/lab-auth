-- rules/_baseline-auth-posts.sql
-- BASELINE ONLY - run with `alerts rules validate`, never create it as a rule.
-- p99 and max requests per IP per 15-minute bucket over 7 days, per hashing auth route (path-normalized: Express 5
-- routes /API/AUTH/LOGIN and /api/auth/login/ to the same handler). Re-run after 3-7 days of real traffic.
SELECT
  'baseline' AS ip,
  route,
  count() AS ip_buckets,
  quantileExact(0.99)(hits) AS p99_per_ip_15m,
  max(hits) AS max_per_ip_15m
FROM
(
  WITH
    coalesce(nullIf(attributes_string['http.client_ip'], ''), nullIf(attributes_string['net.peer.ip'], ''), nullIf(attributes_string['network.peer.address'], ''), nullIf(attributes_string['client.address'], ''), nullIf(attributes_string['net.sock.peer.addr'], '')) AS client_ip,
    replaceRegexpOne(lower(decodeURLComponent(splitByChar('?', attributes_string['http.target'])[1])), '/+$', '') AS norm_route
  SELECT
    client_ip,
    norm_route AS route,
    toStartOfFifteenMinutes(timestamp) AS bucket,
    count() AS hits
  FROM signoz_traces.distributed_signoz_index_v3
  WHERE `resource_string_service$$name` IN (__USER_APP_KEYS__)
    AND timestamp >= now64(9) - INTERVAL 7 DAY
    AND ts_bucket_start >= toUInt64(toUnixTimestamp(now() - INTERVAL 7 DAY)) - 1800
    AND kind = 2
    AND http_method = 'POST'
    AND norm_route IN ('/api/auth/login', '/api/auth/register', '/api/auth/password')
  GROUP BY client_ip, route, bucket
  HAVING client_ip != ''
)
GROUP BY route
