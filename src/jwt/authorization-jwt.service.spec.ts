import { SignJWT, importPKCS8 } from 'jose';
import {
  AuthorizationJwtService,
  verifyAuthorizationJwt,
  ISSUER_BASE,
} from './authorization-jwt.service';
import { generateRs256KeyPairPem } from './keys';
import { resetConfigCacheForTests } from '../config/env';

const keyPair = generateRs256KeyPairPem();
const otherKeyPair = generateRs256KeyPairPem(); // simulates an attacker's own keypair

function setBaseEnv() {
  process.env.NODE_ENV = 'test';
  process.env.KISAUTH_BASE_URL = 'http://localhost:4100';
  process.env.GOOGLE_OAUTH_CLIENT_ID = 'test';
  process.env.GOOGLE_OAUTH_CLIENT_SECRET = 'test';
  process.env.GOOGLE_OAUTH_REDIRECT_URI =
    'http://localhost:4100/oauth/google/callback';
  process.env.KISAUTH_DATABASE_URL = 'postgres://test@localhost/test';
  process.env.KISAUTH_REDIS_URL = 'redis://localhost:6379';
  process.env.KISAUTH_INTERNAL_HMAC_SECRET = 'test-secret';
  process.env.KISAUTH_JWT_PRIVATE_KEY = keyPair.privateKeyPem;
  process.env.KISAUTH_JWT_PUBLIC_KEY = keyPair.publicKeyPem;
  process.env.KISAUTH_JWT_KID = 'kid-current';
  delete process.env.KISAUTH_JWT_PREVIOUS_KEYS;
  resetConfigCacheForTests();
}

describe('AuthorizationJwtService', () => {
  let service: AuthorizationJwtService;

  beforeEach(() => {
    setBaseEnv();
    service = new AuthorizationJwtService();
  });

  it('signs a token that verifies successfully with matching claims', async () => {
    const token = await service.sign({
      sub: 'user-1',
      aud: 'kis-django',
      purpose: 'recovery',
      authIdentityId: 'identity-1',
      providerEmail: 'person@example.com',
      providerEmailVerified: true,
    });
    const payload = await verifyAuthorizationJwt(
      token,
      keyPair.publicKeyPem,
      'kis-django',
    );
    expect(payload.sub).toBe('user-1');
    expect(payload.iss).toBe(ISSUER_BASE);
    expect(payload.purpose).toBe('recovery');
    expect(payload.jti).toBeDefined();
  });

  it('rejects verification against the wrong audience — a KIS token cannot be replayed against another client', async () => {
    const token = await service.sign({
      sub: 'user-1',
      aud: 'kis-django',
      purpose: 'recovery',
      authIdentityId: 'identity-1',
      providerEmail: null,
      providerEmailVerified: false,
    });
    await expect(
      verifyAuthorizationJwt(
        token,
        keyPair.publicKeyPem,
        'kistube-future-client',
      ),
    ).rejects.toThrow();
  });

  it('rejects an expired token', async () => {
    const token = await service.sign(
      {
        sub: 'user-1',
        aud: 'kis-django',
        purpose: 'recovery',
        authIdentityId: 'id-1',
        providerEmail: null,
        providerEmailVerified: false,
      },
      -5, // already expired
    );
    await expect(
      verifyAuthorizationJwt(token, keyPair.publicKeyPem, 'kis-django'),
    ).rejects.toThrow();
  });

  it('rejects a token signed with a different (attacker-controlled) private key', async () => {
    const attackerPrivateKey = await importPKCS8(
      otherKeyPair.privateKeyPem,
      'RS256',
    );
    const forged = await new SignJWT({ purpose: 'recovery' })
      .setProtectedHeader({ alg: 'RS256', kid: 'kid-current' }) // claims the real kid, but signed with the wrong key
      .setIssuer(ISSUER_BASE)
      .setAudience('kis-django')
      .setSubject('attacker-controlled-user')
      .setIssuedAt()
      .setExpirationTime('60s')
      .sign(attackerPrivateKey);

    // Verifying against the REAL public key must fail — kid alone proves nothing.
    await expect(
      verifyAuthorizationJwt(forged, keyPair.publicKeyPem, 'kis-django'),
    ).rejects.toThrow();
  });

  it('rejects a token signed with HS256 using the RSA public key PEM as an HMAC secret (algorithm-confusion attack)', async () => {
    const { SignJWT: SignJWT2 } = await import('jose');
    const secretKey = new TextEncoder().encode(keyPair.publicKeyPem);
    const confused = await new SignJWT2({ purpose: 'recovery' })
      .setProtectedHeader({ alg: 'HS256' })
      .setIssuer(ISSUER_BASE)
      .setAudience('kis-django')
      .setSubject('attacker')
      .setIssuedAt()
      .setExpirationTime('60s')
      .sign(secretKey);

    // verifyAuthorizationJwt pins algorithms:['RS256'] — an HS256 token
    // must be rejected outright, never even attempted against the RSA key.
    await expect(
      verifyAuthorizationJwt(confused, keyPair.publicKeyPem, 'kis-django'),
    ).rejects.toThrow();
  });

  it('rejects a token whose issuer does not match KIS Auth', async () => {
    const privateKey = await importPKCS8(keyPair.privateKeyPem, 'RS256');
    const impostor = await new SignJWT({ purpose: 'recovery' })
      .setProtectedHeader({ alg: 'RS256', kid: 'kid-current' })
      .setIssuer('https://evil.example.com')
      .setAudience('kis-django')
      .setSubject('user-1')
      .setIssuedAt()
      .setExpirationTime('60s')
      .sign(privateKey);
    await expect(
      verifyAuthorizationJwt(impostor, keyPair.publicKeyPem, 'kis-django'),
    ).rejects.toThrow();
  });

  it('serves a JWKS containing the current public key', async () => {
    const jwks = await service.buildJwks();
    expect(jwks.keys).toHaveLength(1);
    expect(jwks.keys[0].kid).toBe('kid-current');
    expect(jwks.keys[0].alg).toBe('RS256');
    // The JWKS must never contain private key material.
    expect(JSON.stringify(jwks)).not.toContain('PRIVATE KEY');
  });

  it('keeps a previous key in the JWKS during a rotation overlap window, verifiable independently of the current key', async () => {
    // Sign with the pre-rotation key FIRST — this is "a token issued just
    // before rotation happened" — then rotate, then confirm it still verifies.
    const oldToken = await service.sign({
      sub: 'user-1',
      aud: 'kis-django',
      purpose: 'recovery',
      authIdentityId: 'id-1',
      providerEmail: null,
      providerEmailVerified: false,
    });

    const rotatedKeyPair = generateRs256KeyPairPem();
    process.env.KISAUTH_JWT_PREVIOUS_KEYS = `kid-current:${Buffer.from(keyPair.publicKeyPem).toString('base64')}`;
    process.env.KISAUTH_JWT_PUBLIC_KEY = rotatedKeyPair.publicKeyPem;
    process.env.KISAUTH_JWT_PRIVATE_KEY = rotatedKeyPair.privateKeyPem;
    process.env.KISAUTH_JWT_KID = 'kid-new';
    resetConfigCacheForTests();

    const rotatedService = new AuthorizationJwtService();
    const jwks = await rotatedService.buildJwks();
    const kids = jwks.keys.map((k) => k.kid);
    expect(kids).toEqual(expect.arrayContaining(['kid-new', 'kid-current']));

    // The pre-rotation token must still verify against the OLD public key
    // (which Django would resolve via the token's kid against the JWKS
    // previous-keys entry) even though KIS Auth is now signing with a new one.
    const payload = await verifyAuthorizationJwt(
      oldToken,
      keyPair.publicKeyPem,
      'kis-django',
    );
    expect(payload.sub).toBe('user-1');

    // And the NEW key correctly signs+verifies its own tokens too.
    const newToken = await rotatedService.sign({
      sub: 'user-2',
      aud: 'kis-django',
      purpose: 'recovery',
      authIdentityId: 'id-2',
      providerEmail: null,
      providerEmailVerified: false,
    });
    const newPayload = await verifyAuthorizationJwt(
      newToken,
      rotatedKeyPair.publicKeyPem,
      'kis-django',
    );
    expect(newPayload.sub).toBe('user-2');
  });
});
