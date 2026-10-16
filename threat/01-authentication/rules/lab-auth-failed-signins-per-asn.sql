-- rules/lab-auth-failed-signins-per-asn.sql
-- APP_EVENT + ingest enrichment: needs auth.login.failure (with the trusted client ip) AND client.asn / client.as_org,
-- which SecureNow adds to EVENTS only when the instance has ASN enrichment enabled (HTTP spans are never ASN-enriched).
-- Confirm with: npx securenow telemetry fields --app <APP_KEY> --since 24h --source logs --env test   (look for client.asn)
-- Failed sign-ins spread over 5+ addresses of one network operator (botnet / residential-proxy pool) in 30 min.
-- Threshold: baseline required - conservative start. TEST-NET IPs carry no ASN, so this rule cannot be fired synthetically.
SELECT
  attributes_string['client.asn'] AS asn,
  any(attributes_string['client.as_org']) AS as_org,
  uniqExact(attributes_string['http.client_ip']) AS distinct_ips,
  uniqExact(attributes_string['account_ref']) AS distinct_accounts,
  count() AS failed_signins,
  argMax(attributes_string['http.client_ip'], timestamp) AS ip
FROM signoz_logs.distributed_logs_v2
WHERE resources_string['service.name'] IN (__USER_APP_KEYS__)
  AND timestamp >= toUnixTimestamp64Nano(now64() - INTERVAL 30 MINUTE)
  AND attributes_string['event.type'] = 'auth.login.failure'
GROUP BY asn
HAVING asn != '' AND ip != '' AND distinct_ips >= 5 AND failed_signins >= 20
