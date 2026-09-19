import { Injectable } from '@nestjs/common';
import { Pool } from 'pg';

export interface RegisteredClient {
  clientId: string;
  name: string;
  status: 'active' | 'disabled';
  allowedRedirectUris: string[];
  allowedScopes: string[];
  allowedPurposes: string[];
}

@Injectable()
export class ClientService {
  constructor(private readonly pool: Pool) {}

  async findByClientId(clientId: string): Promise<RegisteredClient | null> {
    const { rows } = await this.pool.query(
      `SELECT client_id, name, status, allowed_redirect_uris, allowed_scopes, allowed_purposes
       FROM client WHERE client_id = $1`,
      [clientId],
    );
    if (rows.length === 0) return null;
    const row = rows[0];
    return {
      clientId: row.client_id,
      name: row.name,
      status: row.status,
      allowedRedirectUris: row.allowed_redirect_uris,
      allowedScopes: row.allowed_scopes,
      allowedPurposes: row.allowed_purposes,
    };
  }

  /** Exact-match only — never a prefix/wildcard match. An attacker-controlled
   * redirect_uri that merely starts with a registered value must fail. */
  isRedirectUriAllowed(client: RegisteredClient, redirectUri: string): boolean {
    return (
      client.status === 'active' &&
      client.allowedRedirectUris.includes(redirectUri)
    );
  }

  isPurposeAllowed(client: RegisteredClient, purpose: string): boolean {
    return (
      client.status === 'active' && client.allowedPurposes.includes(purpose)
    );
  }

  async register(client: {
    clientId: string;
    name: string;
    allowedRedirectUris: string[];
    allowedScopes: string[];
    allowedPurposes: string[];
  }): Promise<void> {
    await this.pool.query(
      `INSERT INTO client (client_id, name, allowed_redirect_uris, allowed_scopes, allowed_purposes)
       VALUES ($1, $2, $3, $4, $5)
       ON CONFLICT (client_id) DO UPDATE SET
         name = EXCLUDED.name,
         allowed_redirect_uris = EXCLUDED.allowed_redirect_uris,
         allowed_scopes = EXCLUDED.allowed_scopes,
         allowed_purposes = EXCLUDED.allowed_purposes,
         updated_at = now()`,
      [
        client.clientId,
        client.name,
        client.allowedRedirectUris,
        client.allowedScopes,
        client.allowedPurposes,
      ],
    );
  }
}
