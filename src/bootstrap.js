import { randomUUID } from 'node:crypto';
import { hashPassword, passwordProblem } from './passwords.js';

export async function bootstrapAdmin(pool, env = process.env) {
  const email = env.ADMIN_EMAIL?.trim().toLowerCase();
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254) throw new Error('Valid ADMIN_EMAIL is required');
  const existing = await pool.query('SELECT role FROM users WHERE email=$1', [email]);
  if (existing.rowCount) {
    if (existing.rows[0].role !== 'admin') throw new Error('Email belongs to a non-admin user; bootstrap will not elevate it');
    return { created: false };
  }
  if (passwordProblem(env.ADMIN_PASSWORD)) throw new Error('ADMIN_PASSWORD must contain 12–128 characters');
  const result = await pool.query(
    `INSERT INTO users (id,email,name,password_hash,role) VALUES ($1,$2,$3,$4,'admin') ON CONFLICT (email) DO NOTHING RETURNING id`,
    [randomUUID(), email, (env.ADMIN_NAME || 'Lab administrator').slice(0, 80), await hashPassword(env.ADMIN_PASSWORD)],
  );
  if (!result.rowCount) {
    const conflict = await pool.query('SELECT role FROM users WHERE email=$1', [email]);
    if (conflict.rows[0]?.role !== 'admin') throw new Error('Email belongs to a non-admin user; bootstrap will not elevate it');
  }
  return { created: Boolean(result.rowCount) };
}
