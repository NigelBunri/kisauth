import { Injectable, Optional } from '@nestjs/common';
import { createRemoteJWKSet, type JWTVerifyGetKey } from 'jose';
import { loadConfig } from '../config/env';
import {
  verifyOidcIdToken,
  IdTokenVerificationError,
  type VerifiedIdToken,
} from './id-token-verifier';

const GOOGLE_JWKS_URL = 'https://www.googleapis.com/oauth2/v3/certs';
const GOOGLE_ISSUERS = ['https://accounts.google.com', 'accounts.google.com'];

export type GoogleIdentity = VerifiedIdToken;

export class GoogleIdTokenVerificationError extends IdTokenVerificationError {}

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
   * LOGIC below (issuer/audience/nonce/expiry/signature, now shared with
   * every other IdP via id-token-verifier.ts) is exactly what runs in
   * production; only the key source differs.
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
    try {
      return await verifyOidcIdToken({
        idToken,
        keyResolver: this.keyResolver,
        issuer: GOOGLE_ISSUERS,
        audience: config.googleClientId,
        expectedNonce,
      });
    } catch (err) {
      throw new GoogleIdTokenVerificationError(
        err instanceof IdTokenVerificationError
          ? err.reason
          : 'signature_or_claims_invalid',
      );
    }
  }
}
