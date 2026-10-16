-- rules/lab-auth-forwarded-ip-chain-anomaly.sql
-- Traffic only. Single-request identity-quality signature. In production, Caddy overwrites X-Forwarded-For with the
-- real peer (infra/Caddyfile:5) and the app trusts exactly one hop (compose.production.yaml:28, src/app.js:51).
-- So a multi-hop X-Forwarded-For, or a request whose client IP came from an untrusted public socket (Caddy bypassed),
-- should never happen. Any hit = proxy misconfiguration or spoofed client identity. Instant-detection candidate.
WITH
  coalesce(nullIf(attributes_string['http.client_ip'], ''), nullIf(attributes_string['net.peer.ip'], ''), nullIf(attributes_string['network.peer.address'], ''), nullIf(attributes_string['client.address'], ''), nullIf(attributes_string['net.sock.peer.addr'], '')) AS client_ip
SELECT
  client_ip AS ip,
  countIf(position(attributes_string['http.forwarded_for'], ',') > 0) AS multi_hop_forwarded_for,
  countIf(attributes_string['http.client_ip.source'] = 'socket' AND attributes_string['http.proxy.trusted'] = 'false') AS direct_untrusted_socket,
  count() AS requests
FROM signoz_traces.distributed_signoz_index_v3
WHERE `resource_string_service$$name` IN (__USER_APP_KEYS__)
  AND timestamp >= now64(9) - INTERVAL 15 MINUTE
  AND ts_bucket_start >= toUInt64(toUnixTimestamp(now() - INTERVAL 15 MINUTE)) - 1800
  AND kind = 2
GROUP BY ip
HAVING ip != '' AND (multi_hop_forwarded_for + direct_untrusted_socket) >= 1
