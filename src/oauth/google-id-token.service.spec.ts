import { SignJWT, importPKCS8, exportJWK, createLocalJWKSet } from 'jose';
import {
  GoogleIdTokenService,
  GoogleIdTokenVerificationError,
} from './google-id-token.service';
import { generateRs256KeyPairPem } from '../jwt/keys';
import { loadPublicKey } from '../jwt/keys';
import { resetConfigCacheForTests } from '../config/env';

const googleKeyPair = generateRs256KeyPairPem();
const attackerKeyPair = generateRs256KeyPairPem();

async function buildLocalJwks(publicKeyPem: string, kid: string) {
  const jwk = await exportJWK(loadPublicKey(publicKeyPem));
  return createLocalJWKSet({
    keys: [{ ...jwk, kid, alg: 'RS256', use: 'sig' }],
  });
}

async function signGoogleLikeToken(opts: {
  privateKeyPem: string;
  kid: string;
  issuer: string;
  audience: string;
  sub: string;
  nonce?: string;
  email?: string;
  emailVerified?: boolean;
  expiresIn?: string;
}) {
  const privateKey = await importPKCS8(opts.privateKeyPem, 'RS256');
  const builder = new SignJWT({
    ...(opts.nonce ? { nonce: opts.nonce } : {}),
    ...(opts.email
      ? { email: opts.email, email_verified: opts.emailVerified ?? true }
      : {}),
  })
    .setProtectedHeader({ alg: 'RS256', kid: opts.kid })
    .setIssuer(opts.issuer)
    .setAudience(opts.audience)
    .setSubject(opts.sub)
    .setIssuedAt()
    .setExpirationTime(opts.expiresIn ?? '5m');
  return builder.sign(privateKey);
}

describe('GoogleIdTokenService', () => {
  const CLIENT_ID = 'kis-auth-google-client-id.apps.googleusercontent.com';

  beforeEach(() => {
    process.env.GOOGLE_OAUTH_CLIENT_ID = CLIENT_ID;
    process.env.GOOGLE_OAUTH_CLIENT_SECRET = 'test';
    process.env.GOOGLE_OAUTH_REDIRECT_URI =
      'http://localhost:4100/oauth/google/callback';
    process.env.KISAUTH_BASE_URL = 'http://localhost:4100';
    process.env.KISAUTH_DATABASE_URL = 'postgres://test@localhost/test';
    process.env.KISAUTH_REDIS_URL = 'redis://localhost:6379';
    process.env.KISAUTH_INTERNAL_HMAC_SECRET = 'test-secret';
    process.env.KISAUTH_JWT_PRIVATE_KEY = googleKeyPair.privateKeyPem;
    process.env.KISAUTH_JWT_PUBLIC_KEY = googleKeyPair.publicKeyPem;
    process.env.KISAUTH_JWT_KID = 'kid-1';
    resetConfigCacheForTests();
  });

  it('accepts a validly signed token with matching issuer, audience, and nonce', async () => {
    const jwks = await buildLocalJwks(
      googleKeyPair.publicKeyPem,
      'google-kid-1',
    );
    const service = new GoogleIdTokenService(jwks);
    const token = await signGoogleLikeToken({
      privateKeyPem: googleKeyPair.privateKeyPem,
      kid: 'google-kid-1',
      issuer: 'https://accounts.google.com',
      audience: CLIENT_ID,
      sub: 'google-user-sub-123',
      nonce: 'expected-nonce',
      email: 'person@example.com',
      emailVerified: true,
    });
    const identity = await service.verify(token, 'expected-nonce');
    expect(identity.sub).toBe('google-user-sub-123');
    expect(identity.email).toBe('person@example.com');
    expect(identity.emailVerified).toBe(true);
  });

  it('accepts the alternate accounts.google.com issuer form without the scheme', async () => {
    const jwks = await buildLocalJwks(
      googleKeyPair.publicKeyPem,
      'google-kid-1',
    );
    const service = new GoogleIdTokenService(jwks);
    const token = await signGoogleLikeToken({
      privateKeyPem: googleKeyPair.privateKeyPem,
      kid: 'google-kid-1',
      issuer: 'accounts.google.com',
      audience: CLIENT_ID,
      sub: 'google-user-sub-123',
      nonce: 'n',
    });
    const identity = await service.verify(token, 'n');
    expect(identity.sub).toBe('google-user-sub-123');
  });

  it('rejects a nonce mismatch — prevents replaying a stolen id_token into a different login attempt', async () => {
    const jwks = await buildLocalJwks(
      googleKeyPair.publicKeyPem,
      'google-kid-1',
    );
    const service = new GoogleIdTokenService(jwks);
    const token = await signGoogleLikeToken({
      privateKeyPem: googleKeyPair.privateKeyPem,
      kid: 'google-kid-1',
      issuer: 'https://accounts.google.com',
      audience: CLIENT_ID,
      sub: 'google-user-sub-123',
      nonce: 'the-real-nonce',
    });
    await expect(
      service.verify(token, 'a-different-nonce'),
    ).rejects.toBeInstanceOf(GoogleIdTokenVerificationError);
  });

  it('rejects a token issued for a different Google OAuth client (wrong audience)', async () => {
    const jwks = await buildLocalJwks(
      googleKeyPair.publicKeyPem,
      'google-kid-1',
    );
    const service = new GoogleIdTokenService(jwks);
    const token = await signGoogleLikeToken({
      privateKeyPem: googleKeyPair.privateKeyPem,
      kid: 'google-kid-1',
      issuer: 'https://accounts.google.com',
      audience: 'some-other-app.apps.googleusercontent.com',
      sub: 'google-user-sub-123',
      nonce: 'n',
    });
    await expect(service.verify(token, 'n')).rejects.toBeInstanceOf(
      GoogleIdTokenVerificationError,
    );
  });

  it('rejects a token from an issuer that is not Google', async () => {
    const jwks = await buildLocalJwks(
      googleKeyPair.publicKeyPem,
      'google-kid-1',
    );
    const service = new GoogleIdTokenService(jwks);
    const token = await signGoogleLikeToken({
      privateKeyPem: googleKeyPair.privateKeyPem,
      kid: 'google-kid-1',
      issuer: 'https://evil.example.com',
      audience: CLIENT_ID,
      sub: 'google-user-sub-123',
      nonce: 'n',
    });
    await expect(service.verify(token, 'n')).rejects.toBeInstanceOf(
      GoogleIdTokenVerificationError,
    );
  });

  it('rejects an expired token', async () => {
    const jwks = await buildLocalJwks(
      googleKeyPair.publicKeyPem,
      'google-kid-1',
    );
    const service = new GoogleIdTokenService(jwks);
    const token = await signGoogleLikeToken({
      privateKeyPem: googleKeyPair.privateKeyPem,
      kid: 'google-kid-1',
      issuer: 'https://accounts.google.com',
      audience: CLIENT_ID,
      sub: 'google-user-sub-123',
      nonce: 'n',
      expiresIn: '-1s',
    });
    await expect(service.verify(token, 'n')).rejects.toBeInstanceOf(
      GoogleIdTokenVerificationError,
    );
  });

  it("rejects a token signed by a key that is not in Google's JWKS (forged token)", async () => {
    const jwks = await buildLocalJwks(
      googleKeyPair.publicKeyPem,
      'google-kid-1',
    );
    const service = new GoogleIdTokenService(jwks);
    // Signed with the ATTACKER's key but claiming the real kid.
    const token = await signGoogleLikeToken({
      privateKeyPem: attackerKeyPair.privateKeyPem,
      kid: 'google-kid-1',
      issuer: 'https://accounts.google.com',
      audience: CLIENT_ID,
      sub: 'attacker-controlled-sub',
      nonce: 'n',
    });
    await expect(service.verify(token, 'n')).rejects.toBeInstanceOf(
      GoogleIdTokenVerificationError,
    );
  });

  it('does not leak the specific failure reason from verify() — same error type for every failure mode', async () => {
    const jwks = await buildLocalJwks(
      googleKeyPair.publicKeyPem,
      'google-kid-1',
    );
    const service = new GoogleIdTokenService(jwks);
    const badToken = await signGoogleLikeToken({
      privateKeyPem: attackerKeyPair.privateKeyPem,
      kid: 'google-kid-1',
      issuer: 'https://evil.example.com',
      audience: 'wrong-audience',
      sub: 'x',
      nonce: 'n',
      expiresIn: '-1s',
    });
    try {
      await service.verify(badToken, 'n');
      fail('expected verify() to throw');
    } catch (err) {
      expect(err).toBeInstanceOf(GoogleIdTokenVerificationError);
      expect((err as GoogleIdTokenVerificationError).reason).toBe(
        'signature_or_claims_invalid',
      );
    }
  });
});
