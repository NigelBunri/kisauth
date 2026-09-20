import { randomBytes } from 'crypto';
import { Injectable } from '@nestjs/common';
import Redis from 'ioredis';
import type { Purpose } from '../redis/challenge-store';

const PREFIX = 'kisauth:oauthsession:';
const SESSION_TTL_SECONDS = 600; // generous — covers the user actually completing Google's own login UI

export interface OAuthSession {
  clientId: string;
  redirectUri: string;
  purpose: Purpose;
  state: string;
  nonce: string;
  clientState: string; // the caller's own opaque state, echoed back on redirect
  codeVerifier?: string; // PKCE verifier — set once /oauth/google/start runs; never leaves the server
  // Set only when purpose='link', from a verified+consumed link ticket at
  // /authorize time. Baked into the session server-side so nothing later
  // in the flow (including the browser) can influence which KIS account
  // gets linked — see LinkTicketService for how this is minted/verified.
  linkKisUserId?: string;
  // Set only for the enterprise OIDC bridge, from /authorize's own
  // `partner_slug` query param — baked into the session server-side so
  // /oauth/enterprise/:partnerSlug/start and .../callback can confirm the
  // path param actually matches what /authorize approved, rather than
  // trusting the URL alone.
  partnerSlug?: string;
}

/** Server-side storage for the in-flight browser OAuth request, referenced
 * by an httpOnly session cookie rather than round-tripping this data
 * through the browser/URL. Keeps state/nonce and the originating
 * client_id+redirect_uri+purpose bound together so /oauth/google/callback
 * can validate against exactly what /authorize actually approved. */
@Injectable()
export class OAuthSessionStore {
  constructor(private readonly redis: Redis) {}

  async create(session: OAuthSession): Promise<string> {
    const sessionId = randomBytes(32).toString('base64url');
    await this.redis.set(
      PREFIX + sessionId,
      JSON.stringify(session),
      'EX',
      SESSION_TTL_SECONDS,
    );
    return sessionId;
  }

  async get(sessionId: string): Promise<OAuthSession | null> {
    const raw = await this.redis.get(PREFIX + sessionId);
    return raw ? (JSON.parse(raw) as OAuthSession) : null;
  }

  /** Updates a session IN PLACE — same id, same cookie stays valid. Used to
   * attach the PKCE code_verifier once /oauth/google/start runs, without
   * minting a second, orphaned session the cookie never points at. */
  async update(sessionId: string, session: OAuthSession): Promise<void> {
    const ttl = await this.redis.ttl(PREFIX + sessionId);
    await this.redis.set(
      PREFIX + sessionId,
      JSON.stringify(session),
      'EX',
      ttl > 0 ? ttl : SESSION_TTL_SECONDS,
    );
  }

  async delete(sessionId: string): Promise<void> {
    await this.redis.del(PREFIX + sessionId);
  }
}
