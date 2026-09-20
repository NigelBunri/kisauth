import { Injectable } from '@nestjs/common';
import { createRemoteJWKSet, type JWTVerifyGetKey } from 'jose';
import {
  verifyOidcIdToken,
  IdTokenVerificationError,
  type VerifiedIdToken,
} from './id-token-verifier';

export class OidcIdTokenVerificationError extends IdTokenVerificationError {}

export interface OidcVerifyArgs {
  idToken: string;
  jwksUri: string;
  issuer: string;
  audience: string;
  expectedNonce: string;
}

/** Enterprise-IdP counterpart to GoogleIdTokenService — same verification
 * core (id-token-verifier.ts), but issuer/audience/JWKS are per-tenant
 * (resolved from Django's sso-config, not a fixed constant), so the JWKS
 * resolver has to be built and cached per jwks_uri at call time instead of
 * once at construction. */
@Injectable()
export class OidcIdTokenService {
  private readonly resolverCache = new Map<string, JWTVerifyGetKey>();

  /** keyResolverOverride is test-only — production always resolves the
   * JWKS from args.jwksUri, cached per-URI for the life of the process. */
  async verify(
    args: OidcVerifyArgs,
    keyResolverOverride?: JWTVerifyGetKey,
  ): Promise<VerifiedIdToken> {
    const keyResolver =
      keyResolverOverride ?? this.getOrCreateResolver(args.jwksUri);
    try {
      return await verifyOidcIdToken({
        idToken: args.idToken,
        keyResolver,
        issuer: args.issuer,
        audience: args.audience,
        expectedNonce: args.expectedNonce,
      });
    } catch (err) {
      throw new OidcIdTokenVerificationError(
        err instanceof IdTokenVerificationError
          ? err.reason
          : 'signature_or_claims_invalid',
      );
    }
  }

  private getOrCreateResolver(jwksUri: string): JWTVerifyGetKey {
    let resolver = this.resolverCache.get(jwksUri);
    if (!resolver) {
      resolver = createRemoteJWKSet(new URL(jwksUri));
      this.resolverCache.set(jwksUri, resolver);
    }
    return resolver;
  }
}
