import 'dotenv/config';

export function readConfig(env = process.env) {
  const production = env.NODE_ENV === 'production';
  const appOrigin = new URL(env.APP_ORIGIN || 'http://localhost:3000').origin;
  if (production && !appOrigin.startsWith('https://')) throw new Error('Production APP_ORIGIN must use HTTPS');
  if (!env.DATABASE_URL) throw new Error('DATABASE_URL is required');
  if (!env.SESSION_SECRET || env.SESSION_SECRET.length < 32) throw new Error('SESSION_SECRET must contain at least 32 characters');
  if (!env.AUDIT_HMAC_SECRET || env.AUDIT_HMAC_SECRET.length < 32) throw new Error('AUDIT_HMAC_SECRET must contain at least 32 characters');
  if (env.AUDIT_HMAC_SECRET === env.SESSION_SECRET) throw new Error('Audit and session secrets must differ');
  if (Boolean(env.GOOGLE_CLIENT_ID) !== Boolean(env.GOOGLE_CLIENT_SECRET)) throw new Error('Both Google OAuth credentials must be set together');
  if (env.TRUST_PROXY && !['1', 'loopback'].includes(env.TRUST_PROXY)) throw new Error('TRUST_PROXY must be 1 or loopback');
  return {
    production,
    appOrigin,
    databaseUrl: env.DATABASE_URL,
    sessionSecret: env.SESSION_SECRET,
    auditSecret: env.AUDIT_HMAC_SECRET,
    googleClientId: env.GOOGLE_CLIENT_ID || '',
    googleClientSecret: env.GOOGLE_CLIENT_SECRET || '',
    host: env.HOST || '127.0.0.1',
    port: Number(env.PORT || 3000),
    trustProxy: env.TRUST_PROXY === '1' ? 1 : 'loopback',
    authRateLimit: 15,
    registrationRateLimit: 10,
    rateWindowMs: 15 * 60_000,
    idleSessionMs: 30 * 60_000,
    absoluteSessionMs: 8 * 60 * 60_000,
  };
}
