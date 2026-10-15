import { readConfig } from './config.js';
import { createPool } from './db.js';
import { createApp } from './app.js';

const config = readConfig();
const pool = createPool(config.databaseUrl);
pool.on('error', (error) => console.error(JSON.stringify({ level: 'error', code: error.code || 'DATABASE_POOL_ERROR' })));
const app = createApp({ pool, config });
const server = app.listen(config.port, config.host, () => console.log(`Auth Lab listening on ${config.host}:${config.port}`));
// Retention is deliberate: audit events contain pseudonymous identifiers, never credentials.
const cleanup = setInterval(async () => {
  try {
    await pool.query("DELETE FROM security_events WHERE created_at < now() - interval '14 days'");
    await pool.query('DELETE FROM rate_buckets WHERE window_start < $1', [Math.floor(Date.now() / config.rateWindowMs) - 2]);
  } catch (error) {
    console.error(JSON.stringify({ level: 'error', code: error.code || 'RETENTION_ERROR' }));
  }
}, 60 * 60_000);
cleanup.unref();
for (const signal of ['SIGTERM', 'SIGINT']) process.on(signal, () => {
  clearInterval(cleanup);
  app.locals.sessionStore.close();
  server.close(async () => { await pool.end(); process.exit(0); });
  setTimeout(() => process.exit(1), 10_000).unref();
});
