// Shared RS256 ID-token verification core, extracted from what was
// originally google-id-token.service.ts's own verify() body so the new
// enterprise OIDC bridge (any issuer/JWKS/audience, not just Google's
// fixed ones) can reuse the EXACT SAME verification semantics — nonce
// check, subject presence, algorithm pinned to RS256 — instead of a
// second hand-rolled copy that could quietly drift from this one.
//
// GoogleIdTokenService (below, in google-id-token.service.ts) is now a
// thin wrapper around this function with Google's fixed issuer list and
// JWKS URL baked in; its public API and behavior are unchanged.

import { jwtVerify, type JWTVerifyGetKey, type JWTPayload } from 'jose';

export interface VerifiedIdToken {
  sub: string;
  email: string | null;
  emailVerified: boolean;
}

export class IdTokenVerificationError extends Error {
  constructor(public readonly reason: string) {
    super(`id_token verification failed: ${reason}`);
  }
}

export async function verifyOidcIdToken(args: {
  idToken: string;
  keyResolver: JWTVerifyGetKey;
  issuer: string | string[];
  audience: string;
  expectedNonce: string;
}): Promise<VerifiedIdToken> {
  let payload: JWTPayload;
  try {
    const result = await jwtVerify(args.idToken, args.keyResolver, {
      issuer: args.issuer,
      audience: args.audience,
      algorithms: ['RS256'],
    });
    payload = result.payload;
  } catch {
    // Never leak *why* verification failed to a caller this deep — every
    // controller turns every failure into the same generic external
    // message regardless. The specific reason is for server logs only.
    throw new IdTokenVerificationError('signature_or_claims_invalid');
  }

  if (payload.nonce !== args.expectedNonce) {
    throw new IdTokenVerificationError('nonce_mismatch');
  }
  if (typeof payload.sub !== 'string' || !payload.sub) {
    throw new IdTokenVerificationError('missing_subject');
  }

  return {
    sub: payload.sub,
    email: typeof payload.email === 'string' ? payload.email : null,
    emailVerified: payload.email_verified === true,
  };
}
