-- rules/lab-auth-authz-boundary-opened.sql
-- Threat model 02-authorization — privilege boundary opened: 403 -> 200 (Tier 1, TRACE-ONLY, no app code).
-- The detector for *sudden escalation* when no role-change event fires on the victim path: the SAME client,
-- on the SAME restricted route template, is first DENIED (403) and then ALLOWED (200) inside the window — a
-- boundary that just opened (a mid-session role grant, a stolen higher-privilege session replayed, or a gate
-- that regressed). Built only from the HTTP traffic SecureNow captures automatically; needs no authz.* events.
-- Scoped to the lab's restricted surface (/api/admin, /api/security) to keep it precise. Test-first: a normal
-- user who is legitimately granted access, or a re-auth retry, can trip it, so notify + human review.
SELECT ip, route_tmpl, denied_at, allowed_at
FROM (
  SELECT
    coalesce(nullIf(attributes_string['http.client_ip'], ''), nullIf(attributes_string['net.peer.ip'], ''), nullIf(attributes_string['network.peer.address'], '')) AS ip,
    if(attributes_string['http.route'] != '', attributes_string['http.route'],
       replaceRegexpAll(replaceRegexpAll(lower(splitByChar('?', attributes_string['http.target'])[1]),
         '/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', '/:uuid'),
         '/[0-9]+', '/:id')) AS route_tmpl,
    minIf(timestamp, response_status_code = '403') AS denied_at,
    maxIf(timestamp, response_status_code = '200') AS allowed_at
  FROM signoz_traces.distributed_signoz_index_v3
  WHERE `resource_string_service$$name` IN (__USER_APP_KEYS__)
    AND timestamp >= now64(9) - INTERVAL 30 MINUTE
    AND ts_bucket_start >= toUInt64(toUnixTimestamp(now() - INTERVAL 30 MINUTE)) - 1800
    AND kind = 2
    AND response_status_code IN ('200','403')
    AND (attributes_string['http.target'] LIKE '/api/admin%' OR attributes_string['http.target'] LIKE '/api/security%')
  GROUP BY ip, route_tmpl
)
WHERE ip != '' AND denied_at > 0 AND allowed_at > denied_at
ORDER BY allowed_at DESC
LIMIT 100
