-- rules/lab-auth-idor-dump.sql
-- Threat model 02-authorization (3b: IDOR dump / bulk exfiltration, OWASP API1, CWE-639).
-- Tier 1, trace-only. One client that SUCCESSFULLY reads many distinct objects on a :id route = pulling data.
-- A normal user reads only their own handful, so a high distinct-success count is the anomaly.
WITH
  coalesce(nullIf(attributes_string['http.client_ip'], ''), nullIf(attributes_string['net.peer.ip'], ''), nullIf(attributes_string['network.peer.address'], '')) AS client_ip,
  splitByChar('?', attributes_string['http.target'])[1] AS path,
  if(attributes_string['http.route'] != '', attributes_string['http.route'],
     replaceRegexpAll(lower(path), '/[0-9]+', '/:id')) AS route_tmpl
SELECT client_ip AS ip, route_tmpl,
       uniqExactIf(path, response_status_code = '200') AS distinct_objects_read,
       count() AS requests
FROM signoz_traces.distributed_signoz_index_v3
WHERE `resource_string_service$$name` IN (__USER_APP_KEYS__)
  AND timestamp >= now64(9) - INTERVAL 30 MINUTE
  AND ts_bucket_start >= toUInt64(toUnixTimestamp(now() - INTERVAL 30 MINUTE)) - 1800
  AND kind = 2 AND route_tmpl LIKE '%/:id%'
GROUP BY ip, route_tmpl
HAVING ip != '' AND distinct_objects_read >= 15
ORDER BY distinct_objects_read DESC LIMIT 100
