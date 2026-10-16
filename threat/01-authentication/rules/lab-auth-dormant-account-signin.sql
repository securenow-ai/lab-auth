-- rules/lab-auth-dormant-account-signin.sql
-- APP_EVENT + code change: needs auth.login.success with dormant_days (days since the previous successful sign-in).
-- The users table has no last-sign-in column today (db/001_initial.sql:1-13), so the app must add one first.
-- SecureNow cannot compute dormancy itself: the telemetry retention window is far shorter than "dormant".
-- track() sends dormant_days as a number (attributes_number); `event send` sends every value as a string, so both are read.
-- Threshold: 90 days (conservative start). Notify only.
SELECT
  attributes_string['http.client_ip'] AS ip,
  any(attributes_string['enduser.id']) AS account,
  max(greatest(attributes_number['dormant_days'], toFloat64OrZero(attributes_string['dormant_days']))) AS dormant_days,
  count() AS signins
FROM signoz_logs.distributed_logs_v2
WHERE resources_string['service.name'] IN (__USER_APP_KEYS__)
  AND timestamp >= toUnixTimestamp64Nano(now64() - INTERVAL 15 MINUTE)
  AND attributes_string['event.type'] = 'auth.login.success'
  AND greatest(attributes_number['dormant_days'], toFloat64OrZero(attributes_string['dormant_days'])) >= 90
GROUP BY ip
HAVING ip != '' AND signins >= 1
