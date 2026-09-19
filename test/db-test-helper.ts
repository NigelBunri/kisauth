import { Pool } from 'pg';

/** Connects to the throwaway local Postgres started for this session and
 * truncates every table between tests, so suites don't leak state into
 * each other. Requires KISAUTH_TEST_DATABASE_URL to be set — tests that
 * need real Postgres are skipped (not silently faked) if it's absent.
 *
 * truncateAll() clears every table, not just the one the calling spec
 * file cares about — so DB-backed specs MUST run with `jest --runInBand`
 * (see package.json's "test" script). Running spec files in parallel
 * workers against this same shared database lets one file's beforeEach
 * truncate wipe rows another file's test just inserted, mid-test. */
export function getTestPool(): Pool | null {
  const url = process.env.KISAUTH_TEST_DATABASE_URL;
  if (!url) return null;
  return new Pool({ connectionString: url });
}

export async function truncateAll(pool: Pool): Promise<void> {
  await pool.query(
    'TRUNCATE auth_identity, client, challenge_audit RESTART IDENTITY CASCADE',
  );
}
