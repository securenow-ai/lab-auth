-- rules/lab-auth-auth-surface-probing-per-ip.sql
-- Traffic only. Forced browsing for credential files, VCS folders, and common admin/login panels.
-- The app answers these with 404 (src/app.js:300,303) or 403 for dotfiles (src/app.js:302).
-- Threshold: baseline required - conservative start (3 sensitive-path probes, or 30 not-found/denied responses, in 15 min).
WITH
  coalesce(nullIf(attributes_string['http.client_ip'], ''), nullIf(attributes_string['net.peer.ip'], ''), nullIf(attributes_string['network.peer.address'], ''), nullIf(attributes_string['client.address'], ''), nullIf(attributes_string['net.sock.peer.addr'], '')) AS client_ip,
  replaceRegexpOne(lower(decodeURLComponent(splitByChar('?', attributes_string['http.target'])[1])), '/+$', '') AS route
SELECT
  client_ip AS ip,
  countIf(match(route, '(^|/)\\.(env|git|aws|ssh|securenow|deployment|docker|npmrc)|/(wp-login\\.php|wp-admin|phpmyadmin|xmlrpc\\.php|server-status|actuator|vendor/phpunit|admin\\.php|login\\.php)|\\.(bak|sql|gz|zip|pem|key|tfstate)$')) AS sensitive_path_probes,
  countIf(response_status_code IN ('403', '404')) AS not_found_or_denied,
  count() AS requests
FROM signoz_traces.distributed_signoz_index_v3
WHERE `resource_string_service$$name` IN (__USER_APP_KEYS__)
  AND timestamp >= now64(9) - INTERVAL 15 MINUTE
  AND ts_bucket_start >= toUInt64(toUnixTimestamp(now() - INTERVAL 15 MINUTE)) - 1800
  AND kind = 2
GROUP BY ip
HAVING ip != '' AND (sensitive_path_probes >= 3 OR not_found_or_denied >= 30)
