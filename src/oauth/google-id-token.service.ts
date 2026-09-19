import { Injectable, Optional } from '@nestjs/common';
import {
  jwtVerify,
  createRemoteJWKSet,
  type JWTVerifyGetKey,
  type JWTPayload,
} from 'jose';
import { loadConfig } from '../config/env';

const GOOGLE_JWKS_URL = 'https://www.googleapis.com/oauth2/v3/certs';
const GOOGLE_ISSUERS = ['https://accounts.google.com', 'accounts.google.com'];

export interface GoogleIdentity {
  sub: string;
  email: string | null;
  emailVerified: boolean;
}

export class GoogleIdTokenVerificationError extends Error {
  constructor(public readonly reason: string) {
    super(`google id_token verification failed: ${reason}`);
  }
}

let remoteJwks: JWTVerifyGetKey | null = null;
function getRemoteJwks(): JWTVerifyGetKey {
  if (!remoteJwks) remoteJwks = createRemoteJWKSet(new URL(GOOGLE_JWKS_URL));
  return remoteJwks;
}

@Injectable()
export class GoogleIdTokenService {
  private readonly keyResolver: JWTVerifyGetKey;

  /** keyResolver is injectable so tests can verify against a synthetic
   * keypair instead of real network calls to Google — the verification
   * LOGIC below (issuer/audience/nonce/expiry/signature) is exactly what
   * runs in production; only the key source differs.
   *
   * @Optional() (not a JS default parameter) because Nest's DI container
   * calls the constructor itself, explicitly, for every resolvable
   * parameter — a plain default value is silently bypassed and Nest would
   * otherwise throw trying to resolve a provider for a bare function type.
   * @Optional() tells it "inject undefined if nothing is registered,"
   * and the real default is applied here in the constructor body instead. */
  constructor(@Optional() keyResolver?: JWTVerifyGetKey) {
    this.keyResolver = keyResolver ?? getRemoteJwks();
  }

  async verify(
    idToken: string,
    expectedNonce: string,
  ): Promise<GoogleIdentity> {
    const config = loadConfig();
    let payload: JWTPayload;
    try {
      const result = await jwtVerify(idToken, this.keyResolver, {
        issuer: GOOGLE_ISSUERS,
        audience: config.googleClientId,
        algorithms: ['RS256'],
      });
      payload = result.payload;
    } catch {
      // Never leak *why* verification failed to a caller this deep — the
      // controller turns every failure into the same generic external
      // message regardless. The specific reason is for server logs only.
      throw new GoogleIdTokenVerificationError('signature_or_claims_invalid');
    }

    if (payload.nonce !== expectedNonce) {
      throw new GoogleIdTokenVerificationError('nonce_mismatch');
    }
    if (typeof payload.sub !== 'string' || !payload.sub) {
      throw new GoogleIdTokenVerificationError('missing_subject');
    }

    return {
      sub: payload.sub,
      email: typeof payload.email === 'string' ? payload.email : null,
      emailVerified: payload.email_verified === true,
    };
  }
}
