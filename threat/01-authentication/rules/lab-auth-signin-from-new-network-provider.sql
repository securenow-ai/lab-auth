-- rules/lab-auth-signin-from-new-network-provider.sql
-- APP_EVENT + ingest enrichment: needs auth.login.success with userId AND client.as_org (events only, when the instance
-- has ASN enrichment). Fires when an account signs in from a network operator it has not used in the previous 7 days
-- (for example a hosting/VPN provider after months of a home ISP). Accounts with no earlier sign-in are ignored.
-- Threshold: any new operator for an account with history. Noisy for travellers: notify only, severity low.
SELECT account, latest_network_operator, ip
FROM
(
  SELECT
    attributes_string['enduser.id'] AS account,
    argMax(attributes_string['client.as_org'], timestamp) AS latest_network_operator,
    max(timestamp) AS t_latest,
    groupUniqArrayIf(attributes_string['client.as_org'], timestamp < toUnixTimestamp64Nano(now64() - INTERVAL 15 MINUTE)) AS earlier_operators,
    argMax(attributes_string['http.client_ip'], timestamp) AS ip
  FROM signoz_logs.distributed_logs_v2
  WHERE resources_string['service.name'] IN (__USER_APP_KEYS__)
    AND timestamp >= toUnixTimestamp64Nano(now64() - INTERVAL 7 DAY)
    AND attributes_string['event.type'] = 'auth.login.success'
    AND attributes_string['client.as_org'] != ''
  GROUP BY account
  HAVING account != '' AND ip != '' AND t_latest >= toUnixTimestamp64Nano(now64() - INTERVAL 15 MINUTE)
)
WHERE length(earlier_operators) > 0 AND NOT has(earlier_operators, latest_network_operator)
