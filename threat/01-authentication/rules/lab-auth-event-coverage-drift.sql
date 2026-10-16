-- rules/lab-auth-event-coverage-drift.sql
-- Health rule (traces + events). While HTTP traces still flow, compare password sign-in requests that reached a
-- verdict (200 or 401 on POST /api/auth/login) with exported auth.login.* password events over 30 minutes.
-- Fewer than half as many events as traced requests = the track() bridge broke (deploy, missing runtime key, bad import).
-- Returns the busiest traced IP only so the row has a non-empty ip; create it with severity low so no automation acts on it.
-- It cannot detect a TOTAL telemetry outage (then both sides are zero) - that needs an external monitor.
SELECT
  busiest.ip AS ip,
  tr.traced AS traced_signins_30m,
  ev.events AS signin_events_30m
FROM
(
  WITH
    replaceRegexpOne(lower(decodeURLComponent(splitByChar('?', attributes_string['http.target'])[1])), '/+$', '') AS route
  SELECT count() AS traced
  FROM signoz_traces.distributed_signoz_index_v3
  WHERE `resource_string_service$$name` IN (__USER_APP_KEYS__)
    AND timestamp >= now64(9) - INTERVAL 30 MINUTE
    AND ts_bucket_start >= toUInt64(toUnixTimestamp(now() - INTERVAL 30 MINUTE)) - 1800
    AND kind = 2
    AND http_method = 'POST'
    AND route = '/api/auth/login'
    AND response_status_code IN ('200', '401')
) AS tr
CROSS JOIN
(
  SELECT count() AS events
  FROM signoz_logs.distributed_logs_v2
  WHERE resources_string['service.name'] IN (__USER_APP_KEYS__)
    AND timestamp >= toUnixTimestamp64Nano(now64() - INTERVAL 30 MINUTE)
    AND attributes_string['event.type'] IN ('auth.login.success', 'auth.login.failure')
    AND attributes_string['auth_method'] = 'password'
) AS ev
CROSS JOIN
(
  WITH
    coalesce(nullIf(attributes_string['http.client_ip'], ''), nullIf(attributes_string['net.peer.ip'], ''), nullIf(attributes_string['network.peer.address'], ''), nullIf(attributes_string['client.address'], ''), nullIf(attributes_string['net.sock.peer.addr'], '')) AS client_ip,
    replaceRegexpOne(lower(decodeURLComponent(splitByChar('?', attributes_string['http.target'])[1])), '/+$', '') AS route
  SELECT client_ip AS ip, count() AS hits
  FROM signoz_traces.distributed_signoz_index_v3
  WHERE `resource_string_service$$name` IN (__USER_APP_KEYS__)
    AND timestamp >= now64(9) - INTERVAL 30 MINUTE
    AND ts_bucket_start >= toUInt64(toUnixTimestamp(now() - INTERVAL 30 MINUTE)) - 1800
    AND kind = 2
    AND http_method = 'POST'
    AND route = '/api/auth/login'
  GROUP BY ip
  HAVING ip != ''
  ORDER BY hits DESC
  LIMIT 1
) AS busiest
WHERE tr.traced >= 10 AND ev.events * 2 < tr.traced
