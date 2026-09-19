import { Pool } from 'pg';
import { loadConfig } from '../config/env';

let pool: Pool | null = null;

/** Singleton pool for the process. Tests construct their own Pool against
 * a throwaway database instead of using this — see test helpers. */
export function getPool(): Pool {
  if (!pool) {
    pool = new Pool({ connectionString: loadConfig().databaseUrl });
  }
  return pool;
}

export async function closePool(): Promise<void> {
  if (pool) {
    await pool.end();
    pool = null;
  }
}
