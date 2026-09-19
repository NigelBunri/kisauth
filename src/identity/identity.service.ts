import { Injectable } from '@nestjs/common';
import { Pool } from 'pg';

export interface AuthIdentity {
  id: string;
  provider: string;
  providerSubject: string;
  kisUserId: string;
  providerEmail: string | null;
  providerEmailVerified: boolean;
  status: 'active' | 'revoked';
}

@Injectable()
export class IdentityService {
  constructor(private readonly pool: Pool) {}

  /** The only lookup used during authentication — by (provider, subject),
   * never by email. Email is never an authorization signal. See §3 of the
   * Phase 2 design. */
  async findByProviderSubject(
    provider: string,
    providerSubject: string,
  ): Promise<AuthIdentity | null> {
    const { rows } = await this.pool.query(
      `SELECT id, provider, provider_subject, kis_user_id, provider_email, provider_email_verified, status
       FROM auth_identity WHERE provider = $1 AND provider_subject = $2`,
      [provider, providerSubject],
    );
    if (rows.length === 0) return null;
    return this.mapRow(rows[0]);
  }

  /** Explicit linking only — called from a deliberate "link this Google
   * identity" action, never inferred from matching email. The database's
   * own unique constraints (provider+subject, kis_user_id) are the actual
   * enforcement; this just surfaces conflicts as a typed result instead of
   * a raw Postgres error. */
  async link(args: {
    provider: string;
    providerSubject: string;
    kisUserId: string;
    providerEmail: string | null;
    providerEmailVerified: boolean;
  }): Promise<
    | { ok: true; identity: AuthIdentity }
    | { ok: false; reason: 'already_linked' }
  > {
    try {
      const { rows } = await this.pool.query(
        `INSERT INTO auth_identity (provider, provider_subject, kis_user_id, provider_email, provider_email_verified, last_authenticated_at)
         VALUES ($1, $2, $3, $4, $5, now())
         RETURNING id, provider, provider_subject, kis_user_id, provider_email, provider_email_verified, status`,
        [
          args.provider,
          args.providerSubject,
          args.kisUserId,
          args.providerEmail,
          args.providerEmailVerified,
        ],
      );
      return { ok: true, identity: this.mapRow(rows[0]) };
    } catch (err: any) {
      // Postgres unique_violation
      if (err?.code === '23505') {
        return { ok: false, reason: 'already_linked' };
      }
      throw err;
    }
  }

  async findById(id: string): Promise<AuthIdentity | null> {
    const { rows } = await this.pool.query(
      `SELECT id, provider, provider_subject, kis_user_id, provider_email, provider_email_verified, status
       FROM auth_identity WHERE id = $1`,
      [id],
    );
    if (rows.length === 0) return null;
    return this.mapRow(rows[0]);
  }

  async touchLastAuthenticated(id: string): Promise<void> {
    await this.pool.query(
      'UPDATE auth_identity SET last_authenticated_at = now() WHERE id = $1',
      [id],
    );
  }

  private mapRow(row: any): AuthIdentity {
    return {
      id: row.id,
      provider: row.provider,
      providerSubject: row.provider_subject,
      kisUserId: row.kis_user_id,
      providerEmail: row.provider_email,
      providerEmailVerified: row.provider_email_verified,
      status: row.status,
    };
  }
}
