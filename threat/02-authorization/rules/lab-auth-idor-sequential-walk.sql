-- rules/lab-auth-idor-sequential-walk.sql
-- Threat model 02-authorization (3c: sequential / incrementing id walk, OWASP API1, CWE-639).
-- Tier 1, trace-only. A dense, near-consecutive integer id range from one client (/api/notes/1,2,3,...) --
-- the lowest-effort IDOR hunt on predictable keys, even at a volume below the enumeration threshold.
WITH
  coalesce(nullIf(attributes_string['http.client_ip'], ''), nullIf(attributes_string['net.peer.ip'], ''), nullIf(attributes_string['network.peer.address'], '')) AS client_ip,
  splitByChar('?', attributes_string['http.target'])[1] AS path,
  if(attributes_string['http.route'] != '', attributes_string['http.route'],
     replaceRegexpAll(lower(path), '/[0-9]+', '/:id')) AS route_tmpl,
  toUInt64OrZero(extract(path, '/([0-9]{1,})(?:/|$)')) AS oid
SELECT client_ip AS ip, route_tmpl,
       uniqExact(oid) AS distinct_ids,
       max(oid) - min(oid) AS id_span
FROM signoz_traces.distributed_signoz_index_v3
WHERE `resource_string_service$$name` IN (__USER_APP_KEYS__)
  AND timestamp >= now64(9) - INTERVAL 30 MINUTE
  AND ts_bucket_start >= toUInt64(toUnixTimestamp(now() - INTERVAL 30 MINUTE)) - 1800
  AND kind = 2 AND route_tmpl LIKE '%/:id%' AND oid > 0
GROUP BY ip, route_tmpl
HAVING ip != '' AND distinct_ids >= 12 AND id_span <= distinct_ids * 3
ORDER BY distinct_ids DESC LIMIT 100
