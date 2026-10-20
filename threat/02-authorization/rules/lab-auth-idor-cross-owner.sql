-- rules/lab-auth-idor-cross-owner.sql
-- Threat model 02-authorization (4a: cross-owner access rate -- the DEFINITIVE IDOR breach, CWE-639).
-- Tier 2 (events). Reads where the app GRANTED access to a note whose owner is NOT the caller. A legit 200 on
-- your own object never fires this; an IDOR the app wrongly allowed does. Needs authz.granted + owner_id
-- (src/app.js GET /api/notes/:id).
SELECT
  attributes_string['enduser.id'] AS principal,
  argMax(attributes_string['http.client_ip'], timestamp) AS ip,
  count() AS cross_owner_reads,
  uniqExact(attributes_string['object_id']) AS distinct_objects
FROM signoz_logs.distributed_logs_v2
WHERE resources_string['service.name'] IN (__USER_APP_KEYS__)
  AND timestamp >= toUnixTimestamp64Nano(now64() - INTERVAL 30 MINUTE)
  AND attributes_string['event.type'] = 'authz.granted'
  AND attributes_string['owner_id'] != ''
  AND attributes_string['owner_id'] != attributes_string['enduser.id']
GROUP BY principal
HAVING cross_owner_reads >= 5
ORDER BY cross_owner_reads DESC LIMIT 100
