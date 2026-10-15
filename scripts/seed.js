import { readConfig } from '../src/config.js';
import { createPool } from '../src/db.js';
import { bootstrapAdmin } from '../src/bootstrap.js';

const pool = createPool(readConfig().databaseUrl);
try {
  const result = await bootstrapAdmin(pool);
  console.log(result.created ? 'Administrator created. Remove ADMIN_PASSWORD from the runtime environment.' : 'Administrator already exists; credentials unchanged.');
} catch (error) {
  console.error('Bootstrap failed:', error.code || error.message);
  process.exitCode = 1;
} finally {
  await pool.end();
}
