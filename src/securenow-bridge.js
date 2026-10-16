// Privacy-safe export of authentication decisions to SecureNow.
// The application's own audit table (security_events) stays the source of record; this bridge
// sends a minimal structured event for each decision so SecureNow detections can use it.
// Never pass emails, passwords, tokens, cookies, or names: correlate with keyed references.
import { createHash, createHmac } from 'node:crypto';
import { track } from 'securenow/events';

export function createBridge(config) {
  // Keyed, domain-separated references: stable for correlation, meaningless without AUDIT_HMAC_SECRET.
  const ref = (kind, value) => createHmac('sha256', config.auditSecret).update(`${kind}:${value}`).digest('hex').slice(0, 32);
  // The same value securenow/sessions guard() reports as session.id, and what `revoke session` expects.
  const sessionRef = (req) => (req.sessionID ? createHash('sha256').update(req.sessionID).digest('hex') : undefined);

  function emit(type, req, { userId, sessionId, attributes = {} } = {}) {
    track(type, { // fire-and-forget; never throws into the request
      userId: userId ?? undefined,
      sessionId: sessionId ?? sessionRef(req),
      ip: req.ip, // trusted: Caddy overwrites X-Forwarded-For and the app trusts one proxy hop
      userAgent: String(req.get('user-agent') || '').slice(0, 256),
      attributes: { request_id: req.requestId, ...attributes },
    });
  }

  return { emit, ref, sessionRef };
}
