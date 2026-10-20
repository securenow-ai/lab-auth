-- rules/lab-auth-teams-invite-abuse.sql
-- Threat model 02-authorization, Category O (72/73/75: invitation privilege-escalation & invite-identity
-- rebinding; OWASP API1/API3, CWE-269/CWE-863). APP_EVENT: needs membership.invite.* exported from the
-- orgs routes (src/app.js — shipped). Two shapes of invite abuse, both invisible one request at a time:
--   • an invite accepted by an account that is NOT the invited identity (identity_match=false) — the
--     classic SaaS invite-rebinding / account-takeover; one event is definitive, so the floor is 1.
--   • an invite created granting admin/owner — surfaced for review (benign in volume on a healthy org,
--     so this arm is test-first: tune the window, exclude trusted admins, before promoting).
-- Grouped by acting account AND client ip so remediation can scope to the attacker.
SELECT
  attributes_string['enduser.id']      AS actor,
  attributes_string['http.client_ip']  AS ip,
  attributes_string['org_ref']         AS org,
  countIf(attributes_string['event.type'] = 'membership.invite.accepted'
            AND attributes_string['identity_match'] = 'false')                       AS rebinding_attempts,
  countIf(attributes_string['event.type'] = 'membership.invite.created'
            AND attributes_string['invited_role'] IN ('admin','owner')
            AND attributes_string['decision'] = 'deny')                              AS escalation_invites
FROM signoz_logs.distributed_logs_v2
WHERE resources_string['service.name'] IN (__USER_APP_KEYS__)
  AND attributes_string['event.type'] IN ('membership.invite.created','membership.invite.accepted')
  AND timestamp >= toUnixTimestamp64Nano(now64() - INTERVAL 60 MINUTE)
GROUP BY actor, ip, org
HAVING ip != '' AND (rebinding_attempts >= 1 OR escalation_invites >= 1)
ORDER BY rebinding_attempts DESC, escalation_invites DESC
LIMIT 100
