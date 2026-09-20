// A "link ticket" lets Django prove — to kis-auth, over a public browser
// redirect — that an ALREADY-AUTHENTICATED KIS user (not an anonymous
// caller) is the one initiating an account-link. Minted by Django when a
// logged-in user taps "Link Google Account" in Settings, using the same
// KISAUTH_INTERNAL_HMAC_SECRET already shared for the exchange/security-
// event channels — no new secret to provision.
//
// This is deliberately NOT a JWT: it never needs public (JWKS)
// verifiability, only Django and kis-auth ever need to check it, so a
// plain HMAC-signed compact token keeps this symmetric with the rest of
// this codebase's internal-trust primitives (internal-signing.ts) rather
// than adding a second asymmetric-crypto path for the same problem.
//
// Format: base64url(JSON payload) + "." + hex(HMAC-SHA256(payload)).

import crypto from 'crypto';
import { Injectable } from '@nestjs/common';
import Redis from 'ioredis';

const NONCE_PREFIX = 'kisauth:linkticketnonce:';

export interface LinkTicketPayload {
  kisUserId: string;
  nonce: string;
  exp: number; // unix seconds
}

export type LinkTicketVerifyResult =
  | { ok: true; kisUserId: string }
  | { ok: false; reason: 'malformed' | 'signature_mismatch' | 'expired' | 'already_used' };

function sign(secret: string, encodedPayload: string): string {
  return crypto.createHmac('sha256', secret).update(encodedPayload).digest('hex');
}

@Injectable()
export class LinkTicketService {
  constructor(private readonly redis: Redis) {}

  /** Verifies the signature and expiry, then atomically claims the
   * ticket's nonce (Redis SET NX) so the same ticket can never be
   * consumed twice — without single-use enforcement, a leaked ticket
   * (browser history, logs, a shared device) could be replayed to link
   * an attacker's own Google identity to the victim's kis_user_id. */
  async verifyAndConsume(
    ticket: string,
    secret: string,
  ): Promise<LinkTicketVerifyResult> {
    const parts = ticket.split('.');
    if (parts.length !== 2) return { ok: false, reason: 'malformed' };
    const [encodedPayload, signature] = parts;

    const expected = sign(secret, encodedPayload);
    const expectedBuf = Buffer.from(expected);
    const signatureBuf = Buffer.from(signature);
    const validSignature =
      expectedBuf.length === signatureBuf.length &&
      crypto.timingSafeEqual(expectedBuf, signatureBuf);
    if (!validSignature) return { ok: false, reason: 'signature_mismatch' };

    let payload: LinkTicketPayload;
    try {
      payload = JSON.parse(Buffer.from(encodedPayload, 'base64url').toString('utf8'));
      if (
        typeof payload.kisUserId !== 'string' ||
        typeof payload.nonce !== 'string' ||
        typeof payload.exp !== 'number'
      ) {
        return { ok: false, reason: 'malformed' };
      }
    } catch {
      return { ok: false, reason: 'malformed' };
    }

    const now = Math.floor(Date.now() / 1000);
    if (payload.exp <= now) return { ok: false, reason: 'expired' };

    // NX = only set if absent. A second attempt with the same nonce gets 0.
    const remainingTtl = Math.max(1, payload.exp - now);
    const claimed = await this.redis.set(
      NONCE_PREFIX + payload.nonce,
      '1',
      'EX',
      remainingTtl,
      'NX',
    );
    if (claimed !== 'OK') return { ok: false, reason: 'already_used' };

    return { ok: true, kisUserId: payload.kisUserId };
  }
}
