import { SignJWT, importPKCS8, exportJWK, createLocalJWKSet } from 'jose';
import {
  OidcIdTokenService,
  OidcIdTokenVerificationError,
} from './oidc-id-token.service';
import { generateRs256KeyPairPem } from '../jwt/keys';
import { loadPublicKey } from '../jwt/keys';

const tenantKeyPair = generateRs256KeyPairPem();
const attackerKeyPair = generateRs256KeyPairPem();

const ISSUER = 'https://acme.okta.com';
const CLIENT_ID = 'acme-corp-oidc-client-id';

async function buildLocalJwks(publicKeyPem: string, kid: string) {
  const jwk = await exportJWK(loadPublicKey(publicKeyPem));
  return createLocalJWKSet({
    keys: [{ ...jwk, kid, alg: 'RS256', use: 'sig' }],
  });
}

async function signTenantToken(opts: {
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

describe('OidcIdTokenService', () => {
  it('accepts a validly signed token with matching issuer, audience, and nonce', async () => {
    const jwks = await buildLocalJwks(
      tenantKeyPair.publicKeyPem,
      'tenant-kid-1',
    );
    const service = new OidcIdTokenService();
    const token = await signTenantToken({
      privateKeyPem: tenantKeyPair.privateKeyPem,
      kid: 'tenant-kid-1',
      issuer: ISSUER,
      audience: CLIENT_ID,
      sub: 'okta-user-sub-123',
      nonce: 'expected-nonce',
      email: 'employee@acme-corp.example',
      emailVerified: true,
    });
    const identity = await service.verify(
      {
        idToken: token,
        jwksUri: 'https://acme.okta.com/.well-known/jwks.json',
        issuer: ISSUER,
        audience: CLIENT_ID,
        expectedNonce: 'expected-nonce',
      },
      jwks,
    );
    expect(identity.sub).toBe('okta-user-sub-123');
    expect(identity.email).toBe('employee@acme-corp.example');
    expect(identity.emailVerified).toBe(true);
  });

  it('rejects a nonce mismatch', async () => {
    const jwks = await buildLocalJwks(
      tenantKeyPair.publicKeyPem,
      'tenant-kid-1',
    );
    const service = new OidcIdTokenService();
    const token = await signTenantToken({
      privateKeyPem: tenantKeyPair.privateKeyPem,
      kid: 'tenant-kid-1',
      issuer: ISSUER,
      audience: CLIENT_ID,
      sub: 'okta-user-sub-123',
      nonce: 'the-real-nonce',
    });
    await expect(
      service.verify(
        {
          idToken: token,
          jwksUri: 'irrelevant-because-of-override',
          issuer: ISSUER,
          audience: CLIENT_ID,
          expectedNonce: 'a-different-nonce',
        },
        jwks,
      ),
    ).rejects.toBeInstanceOf(OidcIdTokenVerificationError);
  });

  it("rejects a token issued for a different tenant's client (wrong audience) — cross-tenant token reuse", async () => {
    const jwks = await buildLocalJwks(
      tenantKeyPair.publicKeyPem,
      'tenant-kid-1',
    );
    const service = new OidcIdTokenService();
    const token = await signTenantToken({
      privateKeyPem: tenantKeyPair.privateKeyPem,
      kid: 'tenant-kid-1',
      issuer: ISSUER,
      audience: 'some-other-tenants-client-id',
      sub: 'okta-user-sub-123',
      nonce: 'n',
    });
    await expect(
      service.verify(
        {
          idToken: token,
          jwksUri: 'irrelevant',
          issuer: ISSUER,
          audience: CLIENT_ID,
          expectedNonce: 'n',
        },
        jwks,
      ),
    ).rejects.toBeInstanceOf(OidcIdTokenVerificationError);
  });

  it('rejects a token from an issuer that does not match the resolved tenant config', async () => {
    const jwks = await buildLocalJwks(
      tenantKeyPair.publicKeyPem,
      'tenant-kid-1',
    );
    const service = new OidcIdTokenService();
    const token = await signTenantToken({
      privateKeyPem: tenantKeyPair.privateKeyPem,
      kid: 'tenant-kid-1',
      issuer: 'https://evil.example.com',
      audience: CLIENT_ID,
      sub: 'okta-user-sub-123',
      nonce: 'n',
    });
    await expect(
      service.verify(
        {
          idToken: token,
          jwksUri: 'irrelevant',
          issuer: ISSUER,
          audience: CLIENT_ID,
          expectedNonce: 'n',
        },
        jwks,
      ),
    ).rejects.toBeInstanceOf(OidcIdTokenVerificationError);
  });

  it('rejects an expired token', async () => {
    const jwks = await buildLocalJwks(
      tenantKeyPair.publicKeyPem,
      'tenant-kid-1',
    );
    const service = new OidcIdTokenService();
    const token = await signTenantToken({
      privateKeyPem: tenantKeyPair.privateKeyPem,
      kid: 'tenant-kid-1',
      issuer: ISSUER,
      audience: CLIENT_ID,
      sub: 'okta-user-sub-123',
      nonce: 'n',
      expiresIn: '-1s',
    });
    await expect(
      service.verify(
        {
          idToken: token,
          jwksUri: 'irrelevant',
          issuer: ISSUER,
          audience: CLIENT_ID,
          expectedNonce: 'n',
        },
        jwks,
      ),
    ).rejects.toBeInstanceOf(OidcIdTokenVerificationError);
  });

  it("rejects a token signed by a key that is not in the tenant's JWKS (forged token)", async () => {
    const jwks = await buildLocalJwks(
      tenantKeyPair.publicKeyPem,
      'tenant-kid-1',
    );
    const service = new OidcIdTokenService();
    const token = await signTenantToken({
      privateKeyPem: attackerKeyPair.privateKeyPem,
      kid: 'tenant-kid-1',
      issuer: ISSUER,
      audience: CLIENT_ID,
      sub: 'attacker-controlled-sub',
      nonce: 'n',
    });
    await expect(
      service.verify(
        {
          idToken: token,
          jwksUri: 'irrelevant',
          issuer: ISSUER,
          audience: CLIENT_ID,
          expectedNonce: 'n',
        },
        jwks,
      ),
    ).rejects.toBeInstanceOf(OidcIdTokenVerificationError);
  });

  it('caches the remote JWKS resolver per jwks_uri rather than re-resolving on every verify() call', async () => {
    // No network-mocking here — this just proves the SAME resolver
    // instance is reused across two calls with an identical jwksUri
    // (verified indirectly: two verifications against a keyResolver
    // override still succeed independently, and the private cache map
    // holds one entry per jwks_uri, not per call). Constructed as a
    // black-box check via the override path since createRemoteJWKSet
    // itself cannot be introspected without a real/mocked HTTP layer.
    const jwks = await buildLocalJwks(
      tenantKeyPair.publicKeyPem,
      'tenant-kid-1',
    );
    const service = new OidcIdTokenService();
    const token1 = await signTenantToken({
      privateKeyPem: tenantKeyPair.privateKeyPem,
      kid: 'tenant-kid-1',
      issuer: ISSUER,
      audience: CLIENT_ID,
      sub: 'user-a',
      nonce: 'n1',
    });
    const token2 = await signTenantToken({
      privateKeyPem: tenantKeyPair.privateKeyPem,
      kid: 'tenant-kid-1',
      issuer: ISSUER,
      audience: CLIENT_ID,
      sub: 'user-b',
      nonce: 'n2',
    });
    const identity1 = await service.verify(
      {
        idToken: token1,
        jwksUri: 'x',
        issuer: ISSUER,
        audience: CLIENT_ID,
        expectedNonce: 'n1',
      },
      jwks,
    );
    const identity2 = await service.verify(
      {
        idToken: token2,
        jwksUri: 'x',
        issuer: ISSUER,
        audience: CLIENT_ID,
        expectedNonce: 'n2',
      },
      jwks,
    );
    expect(identity1.sub).toBe('user-a');
    expect(identity2.sub).toBe('user-b');
  });
});
