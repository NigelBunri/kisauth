import { randomUUID } from 'crypto';
import { SignJWT, importPKCS8, jwtVerify, type JWTPayload } from 'jose';
import { Injectable } from '@nestjs/common';
import { loadConfig } from '../config/env';
import { publicKeyToJwk } from './keys';
import type { Purpose } from '../redis/challenge-store';

export const ISSUER_BASE = 'kisauth.kingdomimpactventures.org';

export interface AuthorizationClaims {
  // Absent only for purpose='registration' — no kis_user_id exists yet at
  // the point this token is issued; Django creates the account from
  // providerSubject/providerEmail below, then links it as a separate step.
  sub?: string; // kis_user_id
  aud: string; // client_id, e.g. "kis-django"
  purpose: Purpose;
  authIdentityId?: string; // absent for purpose='registration'
  providerSubject?: string; // present only for purpose='registration'
  providerEmail: string | null;
  providerEmailVerified: boolean;
  // Present only on registration-purpose tokens. Django's
  // VerifiedRegistration defaults provider to "google" and partnerSlug to
  // null when absent, so the original Google flow's tokens (which never
  // set these) keep decoding exactly as before.
  provider?: string;
  partnerSlug?: string;
}

@Injectable()
export class AuthorizationJwtService {
  /** Signs the short-lived authorization result. The exchange endpoint's
   * own atomic single-use code consumption is the PRIMARY replay defense;
   * this signature is what lets Django verify the result's authenticity
   * independent of that call succeeding — two separate security
   * properties, not one. See Phase 2 §7 "why a signed JWT". */
  async sign(
    claims: AuthorizationClaims,
    expiresInSeconds = 60,
  ): Promise<string> {
    const config = loadConfig();
    const privateKey = await importPKCS8(
      normalizePem(config.jwtPrivateKeyPem),
      'RS256',
    );
    const now = Math.floor(Date.now() / 1000);
    const builder = new SignJWT({
      purpose: claims.purpose,
      auth_identity_id: claims.authIdentityId ?? null,
      provider_subject: claims.providerSubject ?? null,
      provider_email: claims.providerEmail,
      provider_email_verified: claims.providerEmailVerified,
      ...(claims.provider ? { provider: claims.provider } : {}),
      ...(claims.partnerSlug ? { partner_slug: claims.partnerSlug } : {}),
    })
      .setProtectedHeader({ alg: 'RS256', kid: config.jwtKid })
      .setIssuer(ISSUER_BASE)
      .setAudience(claims.aud)
      .setIssuedAt(now)
      .setExpirationTime(now + expiresInSeconds)
      .setJti(randomUUID());
    if (claims.sub) builder.setSubject(claims.sub);
    return builder.sign(privateKey);
  }

  /** Builds the current JWKS document — current key plus any keys kept
   * alive during a rotation overlap window. */
  async buildJwks() {
    const config = loadConfig();
    const keys = [await publicKeyToJwk(config.jwtPublicKeyPem, config.jwtKid)];
    for (const prev of config.jwtPreviousKeys) {
      keys.push(await publicKeyToJwk(prev.publicKeyPem, prev.kid));
    }
    return { keys };
  }
}

function normalizePem(pem: string): string {
  return pem.includes('\\n') ? pem.replace(/\\n/g, '\n') : pem;
}

/** Standalone verifier — used by tests here, and mirrors exactly what
 * Django's own verifier must implement against the published JWKS
 * (iss/aud/exp/kid all checked, algorithm pinned to RS256 so a token
 * signed with a different/weaker algorithm is never accepted). */
export async function verifyAuthorizationJwt(
  token: string,
  publicKeyPem: string,
  expectedAudience: string,
): Promise<JWTPayload> {
  const { importSPKI } = await import('jose');
  const publicKey = await importSPKI(normalizePem(publicKeyPem), 'RS256');
  const { payload } = await jwtVerify(token, publicKey, {
    issuer: ISSUER_BASE,
    audience: expectedAudience,
    algorithms: ['RS256'],
  });
  return payload;
}
