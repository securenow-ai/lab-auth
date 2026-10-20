-- rules/lab-auth-idor-scan.sql
-- Threat model 02-authorization (3a: ID brute-forcing / scanning the id space, OWASP API1, CWE-639).
-- Tier 1, STATISTICAL, trace-only. One client probing many distinct note ids with a HIGH miss ratio
-- (mostly 404) = hunting for which objects exist. A legit user reads a handful of their own (low distinct,
-- near-zero miss). Thresholds tuned for the lab's small dataset.
WITH
  coalesce(nullIf(attributes_string['http.client_ip'], ''), nullIf(attributes_string['net.peer.ip'], ''), nullIf(attributes_string['network.peer.address'], '')) AS client_ip,
  splitByChar('?', attributes_string['http.target'])[1] AS path,
  if(attributes_string['http.route'] != '', attributes_string['http.route'],
     replaceRegexpAll(lower(path), '/[0-9]+', '/:id')) AS route_tmpl
SELECT
  client_ip AS ip, route_tmpl,
  uniqExact(path) AS distinct_ids,
  countIf(response_status_code IN ('404','403','401')) AS misses,
  count() AS attempts,
  round(countIf(response_status_code IN ('404','403','401')) / greatest(count(),1), 2) AS miss_ratio
FROM signoz_traces.distributed_signoz_index_v3
WHERE `resource_string_service$$name` IN (__USER_APP_KEYS__)
  AND timestamp >= now64(9) - INTERVAL 30 MINUTE
  AND ts_bucket_start >= toUInt64(toUnixTimestamp(now() - INTERVAL 30 MINUTE)) - 1800
  AND kind = 2 AND route_tmpl LIKE '%/:id%'
GROUP BY ip, route_tmpl
HAVING ip != '' AND distinct_ids >= 20 AND miss_ratio >= 0.4
ORDER BY distinct_ids DESC LIMIT 100
