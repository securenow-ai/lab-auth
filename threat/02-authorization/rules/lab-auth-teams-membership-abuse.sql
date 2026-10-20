-- rules/lab-auth-teams-membership-abuse.sql
-- Threat model 02-authorization, Category O (79/80 self-escalation & horizontal membership tampering;
-- 85/86 active-org context tampering; OWASP API5, CWE-285/CWE-639). APP_EVENT: needs
-- membership.role.changed + org.context.switched exported from the orgs routes (src/app.js — shipped).
-- Two patterns, each caught in aggregate, never from one request:
--   • a member raising their OWN role to admin/owner (self=true) — self-escalation; one denied attempt
--     is already a strong signal, so the floor is 1.
--   • a principal poking at orgs they are NOT a member of (org.context.switched member=false) across
--     several distinct orgs — active-org context probing / tenant hopping; floor of 3 distinct orgs
--     keeps a single mistaken link from firing.
-- Grouped by acting account AND client ip.
SELECT
  attributes_string['enduser.id']      AS actor,
  attributes_string['http.client_ip']  AS ip,
  countIf(attributes_string['event.type'] = 'membership.role.changed'
            AND attributes_string['self'] = 'true'
            AND attributes_string['to_role'] IN ('admin','owner'))                   AS self_escalations,
  uniqExactIf(attributes_string['org_ref'],
            attributes_string['event.type'] = 'org.context.switched'
            AND attributes_string['member'] = 'false')                              AS nonmember_orgs
FROM signoz_logs.distributed_logs_v2
WHERE resources_string['service.name'] IN (__USER_APP_KEYS__)
  AND attributes_string['event.type'] IN ('membership.role.changed','org.context.switched')
  AND timestamp >= toUnixTimestamp64Nano(now64() - INTERVAL 60 MINUTE)
GROUP BY actor, ip
HAVING ip != '' AND (self_escalations >= 1 OR nonmember_orgs >= 3)
ORDER BY self_escalations DESC, nonmember_orgs DESC
LIMIT 100
