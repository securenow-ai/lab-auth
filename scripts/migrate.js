import { readConfig } from '../src/config.js';
import { createPool, migrate } from '../src/db.js';

const pool = createPool(readConfig().databaseUrl);
try {
  await migrate(pool);
  console.log('Database migrations complete.');
} catch (error) {
  console.error('Migration failed:', error.code || error.name);
  process.exitCode = 1;
} finally {
  await pool.end();
}
