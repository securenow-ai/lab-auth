import pg from 'pg';
import { readFile } from 'node:fs/promises';

export function createPool(databaseUrl) {
  return new pg.Pool({ connectionString: databaseUrl, max: 10, connectionTimeoutMillis: 5000, idleTimeoutMillis: 30_000 });
}

// Revoke pending org invites past their expiry so old invite links stop working.
export async function revokeExpiredInvites(pool) {
  const { rowCount } = await pool.query("UPDATE org_invites SET status='revoked' WHERE status='pending' AND expires_at < now()");
  return rowCount;
}

export async function migrate(pool) {
  const sql = await readFile(new URL('../db/001_initial.sql', import.meta.url), 'utf8');
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('SELECT pg_advisory_xact_lock(807420126)');
    await client.query(sql);
    await client.query('COMMIT');
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}
