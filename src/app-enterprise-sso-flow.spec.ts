// Full end-to-end enterprise OIDC round trip, driven entirely over real
// HTTP against a real Fastify+Nest app, real Postgres, and real Redis —
// only the tenant's IdP itself is substituted via DI (the same seam
// production uses for the real network calls: OidcProviderResolverService
// stands in for the Django sso-config lookup, OidcDiscoveryService for the
// IdP's discovery document, OidcTokenExchangeService for its token
// endpoint, OidcIdTokenService for its JWKS-verified ID token).
// Everything else — session cookies, PKCE, state/nonce, challenge
// issuance, the authorization/registration code, the HMAC-signed
// exchange, and the final signed JWT — runs for real, and this file
// proves it end to end for BOTH new-registration and returning-user
// enterprise logins, plus cross-tenant identity isolation. Same full-app
// bootstrap pattern as app-recovery-flow.spec.ts.

import { Test } from '@nestjs/testing';
import {
  FastifyAdapter,
  NestFastifyApplication,
} from '@nestjs/platform-fastify';
import { Pool } from 'pg';
import Redis from 'ioredis';
import supertest from 'supertest';
import { AppModule } from './app.module';
import { ClientService } from './clients/client.service';
import { IdentityService } from './identity/identity.service';
import { OidcProviderResolverService } from './oauth/oidc-provider-resolver.service';
import { OidcDiscoveryService } from './oauth/oidc-discovery.service';
import { OidcTokenExchangeService } from './oauth/oidc-token-exchange.service';
import { OidcIdTokenService } from './oauth/oidc-id-token.service';
import { verifyAuthorizationJwt } from './jwt/authorization-jwt.service';
import { generateRs256KeyPairPem } from './jwt/keys';
import { signedInternalHeaders } from './security/internal-signing';
import { resetConfigCacheForTests } from './config/env';

const runIntegration =
  process.env.KISAUTH_TEST_DATABASE_URL && process.env.KISAUTH_TEST_REDIS_URL;
const describeIfInfra = runIntegration ? describe : describe.skip;

const jwtKeyPair = generateRs256KeyPairPem();
const HMAC_SECRET = 'test-internal-secret-enterprise';
const REDIRECT_URI = 'https://kis.app/auth/kisauth-callback';
const REGISTRATION_REDIRECT_URI = 'https://kis.app/auth/registration-callback';

const ACME_DISCOVERY_URL =
  'https://acme.okta.com/.well-known/openid-configuration';
const ACME_ISSUER = 'https://acme.okta.com';
const ACME_CLIENT_ID = 'acme-oidc-client';

const GLOBEX_DISCOVERY_URL =
  'https://globex.okta.com/.well-known/openid-configuration';
const GLOBEX_ISSUER = 'https://globex.okta.com';
const GLOBEX_CLIENT_ID = 'globex-oidc-client';

describeIfInfra(
  'KIS Auth — enterprise OIDC SSO round trip (integration)',
  () => {
    let app: NestFastifyApplication;
    let pool: Pool;
    let redis: Redis;
    let server: any;

    // Configured per-test so different specs can simulate different
    // partner_slug -> tenant config mappings without needing a real Django.
    const partnerConfigs: Record<
      string,
      {
        issuer: string;
        clientId: string;
        clientSecret: string;
        discoveryUrl: string;
      }
    > = {
      'acme-corp': {
        issuer: ACME_ISSUER,
        clientId: ACME_CLIENT_ID,
        clientSecret: 'acme-secret',
        discoveryUrl: ACME_DISCOVERY_URL,
      },
      'globex-inc': {
        issuer: GLOBEX_ISSUER,
        clientId: GLOBEX_CLIENT_ID,
        clientSecret: 'globex-secret',
        discoveryUrl: GLOBEX_DISCOVERY_URL,
      },
    };

    // Per-test identity fixture the fake IdToken verifier returns —
    // indexed by discovery_url so both tenants can be "in flight" without
    // colliding.
    const identityByDiscoveryUrl: Record<
      string,
      { sub: string; email: string; emailVerified: boolean }
    > = {
      [ACME_DISCOVERY_URL]: {
        sub: 'okta-sub-shared-across-tenants',
        email: 'employee@acme-corp.example',
        emailVerified: true,
      },
      [GLOBEX_DISCOVERY_URL]: {
        sub: 'okta-sub-shared-across-tenants', // deliberately the SAME raw sub as Acme's
        email: 'employee@globex.example',
        emailVerified: true,
      },
    };

    beforeAll(async () => {
      process.env.NODE_ENV = 'test';
      process.env.KISAUTH_BASE_URL = 'http://localhost:4100';
      process.env.GOOGLE_OAUTH_CLIENT_ID = 'test-google-client';
      process.env.GOOGLE_OAUTH_CLIENT_SECRET = 'test-google-secret';
      process.env.GOOGLE_OAUTH_REDIRECT_URI =
        'http://localhost:4100/oauth/google/callback';
      process.env.KISAUTH_DATABASE_URL = process.env.KISAUTH_TEST_DATABASE_URL!;
      process.env.KISAUTH_REDIS_URL = process.env.KISAUTH_TEST_REDIS_URL!;
      process.env.KISAUTH_JWT_PRIVATE_KEY = jwtKeyPair.privateKeyPem;
      process.env.KISAUTH_JWT_PUBLIC_KEY = jwtKeyPair.publicKeyPem;
      process.env.KISAUTH_JWT_KID = 'kid-test-enterprise';
      process.env.KISAUTH_INTERNAL_HMAC_SECRET = HMAC_SECRET;
      process.env.DJANGO_SSO_CONFIG_URL =
        'https://django.internal.test/api/v1/kis-auth/sso-config/';
      process.env.KISAUTH_CHALLENGE_TTL_SECONDS = '30';
      process.env.KISAUTH_AUTH_CODE_TTL_SECONDS = '60';
      process.env.KISAUTH_CHALLENGE_MAX_ATTEMPTS = '5';
      resetConfigCacheForTests();

      const fakeResolver = {
        resolve: jest.fn(async (partnerSlug: string) => {
          const cfg = partnerConfigs[partnerSlug];
          if (!cfg) return { ok: false, reason: 'not_found' };
          return {
            ok: true,
            config: {
              partnerId: `partner-id-${partnerSlug}`,
              partnerSlug,
              provider: 'oidc',
              issuer: cfg.issuer,
              clientId: cfg.clientId,
              clientSecret: cfg.clientSecret,
              discoveryUrl: cfg.discoveryUrl,
            },
          };
        }),
      };
      const fakeDiscovery = {
        fetchDiscovery: jest.fn(async (discoveryUrl: string) => ({
          authorizationEndpoint: `${discoveryUrl}/authorize`,
          tokenEndpoint: `${discoveryUrl}/token`,
          jwksUri: `${discoveryUrl}/jwks`,
          issuer: null,
        })),
      };
      const fakeTokenExchange = {
        exchangeCodeForIdToken: jest.fn(
          async (args: { tokenEndpoint: string }) => {
            // Encodes which discovery_url this call belongs to, so the fake
            // id-token verifier below can return the right tenant's identity.
            return `fake-id-token::${args.tokenEndpoint.replace('/token', '')}`;
          },
        ),
      };
      const fakeIdToken = {
        verify: jest.fn(async (args: { idToken: string }) => {
          const discoveryUrl = args.idToken.split('::')[1];
          const identity = identityByDiscoveryUrl[discoveryUrl];
          if (!identity) throw new Error('no fixture for this discovery url');
          return identity;
        }),
      };

      const moduleRef = await Test.createTestingModule({ imports: [AppModule] })
        .overrideProvider(OidcProviderResolverService)
        .useValue(fakeResolver)
        .overrideProvider(OidcDiscoveryService)
        .useValue(fakeDiscovery)
        .overrideProvider(OidcTokenExchangeService)
        .useValue(fakeTokenExchange)
        .overrideProvider(OidcIdTokenService)
        .useValue(fakeIdToken)
        .compile();

      app = moduleRef.createNestApplication<NestFastifyApplication>(
        new FastifyAdapter(),
      );
      await app.init();
      await app.getHttpAdapter().getInstance().ready();
      server = app.getHttpAdapter().getInstance().server;

      pool = moduleRef.get(Pool);
      redis = moduleRef.get(Redis);

      await pool.query(
        'TRUNCATE auth_identity, client, challenge_audit RESTART IDENTITY CASCADE',
      );
      const clients = moduleRef.get(ClientService);
      await clients.register({
        clientId: 'kis-django',
        name: 'KIS Django backend',
        allowedRedirectUris: [REDIRECT_URI, REGISTRATION_REDIRECT_URI],
        allowedScopes: ['openid', 'email', 'profile'],
        allowedPurposes: ['recovery', 'registration', 'link'],
      });
    });

    afterEach(async () => {
      const keys = await redis.keys('kisauth:ratelimit:*');
      if (keys.length) await redis.del(...keys);
    });

    afterAll(async () => {
      if (pool) await pool.end();
      if (redis) redis.disconnect();
      if (app) await app.close();
    });

    function extractCookie(res: supertest.Response): string {
      const raw = res.headers['set-cookie'];
      const cookieHeader = Array.isArray(raw) ? raw[0] : raw;
      return cookieHeader.split(';')[0];
    }

    function clientRedirectFrom(callbackRes: supertest.Response): URL {
      const statusRedirect = new URL(callbackRes.headers.location);
      return new URL(statusRedirect.searchParams.get('client_redirect')!);
    }

    async function driveToEnterpriseCode(opts: {
      partnerSlug: string;
      purpose: 'registration' | 'recovery';
      clientState: string;
    }): Promise<{ code: string; finalRedirect: URL }> {
      const authorizeRes = await supertest(server)
        .get('/authorize')
        .query({
          client_id: 'kis-django',
          redirect_uri:
            opts.purpose === 'registration'
              ? REGISTRATION_REDIRECT_URI
              : REDIRECT_URI,
          purpose: opts.purpose,
          state: opts.clientState,
          partner_slug: opts.partnerSlug,
        })
        .redirects(0);
      expect(authorizeRes.status).toBe(303);
      expect(authorizeRes.headers.location).toBe(
        `/oauth/enterprise/${opts.partnerSlug}/start`,
      );
      const cookie = extractCookie(authorizeRes);

      const startRes = await supertest(server)
        .get(`/oauth/enterprise/${opts.partnerSlug}/start`)
        .set('Cookie', cookie)
        .redirects(0);
      expect(startRes.status).toBe(303);
      const idpUrl = new URL(startRes.headers.location);
      expect(idpUrl.origin + idpUrl.pathname).toBe(
        `${partnerConfigs[opts.partnerSlug].discoveryUrl}/authorize`,
      );
      expect(idpUrl.searchParams.get('client_id')).toBe(
        partnerConfigs[opts.partnerSlug].clientId,
      );
      expect(idpUrl.searchParams.get('code_challenge_method')).toBe('S256');
      const idpState = idpUrl.searchParams.get('state')!;

      const callbackRes = await supertest(server)
        .get(`/oauth/enterprise/${opts.partnerSlug}/callback`)
        .query({ code: 'idp-auth-code', state: idpState })
        .set('Cookie', cookie)
        .redirects(0);
      expect(callbackRes.status).toBe(303);
      const finalRedirect = clientRedirectFrom(callbackRes);
      const code = finalRedirect.searchParams.get('code')!;
      expect(code).toBeTruthy();
      return { code, finalRedirect };
    }

    it('completes the enterprise JIT registration round trip with the right purpose/provider/partner_slug claims', async () => {
      const { code, finalRedirect } = await driveToEnterpriseCode({
        partnerSlug: 'acme-corp',
        purpose: 'registration',
        clientState: 'acme-registration-state',
      });
      expect(finalRedirect.searchParams.get('state')).toBe(
        'acme-registration-state',
      );

      const exchangeBody = {
        code,
        client_id: 'kis-django',
        redirect_uri: REGISTRATION_REDIRECT_URI,
      };
      const headers = signedInternalHeaders({
        method: 'POST',
        url: '/internal/v1/registration/exchange',
        body: exchangeBody,
        secret: HMAC_SECRET,
      });
      const exchangeRes = await supertest(server)
        .post('/internal/v1/registration/exchange')
        .set(headers)
        .send(exchangeBody);
      expect(exchangeRes.status).toBe(201);

      const payload = await verifyAuthorizationJwt(
        exchangeRes.body.token,
        jwtKeyPair.publicKeyPem,
        'kis-django',
      );
      expect(payload.purpose).toBe('enterprise_sso_registration');
      expect(payload.provider).toBe('oidc');
      expect(payload.partner_slug).toBe('acme-corp');
      expect(payload.provider_email).toBe('employee@acme-corp.example');
      expect(payload.provider_email_verified).toBe(true);
      // provider_subject must be tenant-scoped, not the bare IdP sub.
      expect(payload.provider_subject).toBe(
        'acme-corp:okta-sub-shared-across-tenants',
      );
    });

    it('two different tenants whose IdPs mint the same raw `sub` do not collide — each gets its own auth_identity row', async () => {
      const identities = new IdentityService(pool);

      const acme = await driveToEnterpriseCode({
        partnerSlug: 'acme-corp',
        purpose: 'registration',
        clientState: 'acme-collision-state',
      });
      const acmeExchangeBody = {
        code: acme.code,
        client_id: 'kis-django',
        redirect_uri: REGISTRATION_REDIRECT_URI,
      };
      await supertest(server)
        .post('/internal/v1/registration/exchange')
        .set(
          signedInternalHeaders({
            method: 'POST',
            url: '/internal/v1/registration/exchange',
            body: acmeExchangeBody,
            secret: HMAC_SECRET,
          }),
        )
        .send(acmeExchangeBody);

      // Simulate Django's post-registration link call for Acme's user —
      // provider="oidc" verbatim, provider_subject exactly what the JWT
      // carried (the composite key), same as the real Django code does.
      const acmeLinkBody = {
        provider: 'oidc',
        provider_subject: 'acme-corp:okta-sub-shared-across-tenants',
        kis_user_id: '33333333-3333-3333-3333-333333333333',
        provider_email: 'employee@acme-corp.example',
        provider_email_verified: true,
      };
      const acmeLinkRes = await supertest(server)
        .post('/internal/v1/identity/link')
        .set(
          signedInternalHeaders({
            method: 'POST',
            url: '/internal/v1/identity/link',
            body: acmeLinkBody,
            secret: HMAC_SECRET,
          }),
        )
        .send(acmeLinkBody);
      expect(acmeLinkRes.status).toBe(201);

      const globex = await driveToEnterpriseCode({
        partnerSlug: 'globex-inc',
        purpose: 'registration',
        clientState: 'globex-collision-state',
      });
      const globexExchangeBody = {
        code: globex.code,
        client_id: 'kis-django',
        redirect_uri: REGISTRATION_REDIRECT_URI,
      };
      const globexExchangeRes = await supertest(server)
        .post('/internal/v1/registration/exchange')
        .set(
          signedInternalHeaders({
            method: 'POST',
            url: '/internal/v1/registration/exchange',
            body: globexExchangeBody,
            secret: HMAC_SECRET,
          }),
        )
        .send(globexExchangeBody);
      const globexPayload = await verifyAuthorizationJwt(
        globexExchangeRes.body.token,
        jwtKeyPair.publicKeyPem,
        'kis-django',
      );
      // Same raw IdP sub as Acme's, but scoped to a different tenant.
      expect(globexPayload.provider_subject).toBe(
        'globex-inc:okta-sub-shared-across-tenants',
      );

      const globexLinkBody = {
        provider: 'oidc',
        provider_subject: 'globex-inc:okta-sub-shared-across-tenants',
        kis_user_id: '44444444-4444-4444-4444-444444444444',
        provider_email: 'employee@globex.example',
        provider_email_verified: true,
      };
      const globexLinkRes = await supertest(server)
        .post('/internal/v1/identity/link')
        .set(
          signedInternalHeaders({
            method: 'POST',
            url: '/internal/v1/identity/link',
            body: globexLinkBody,
            secret: HMAC_SECRET,
          }),
        )
        .send(globexLinkBody);
      // If the two tenants' identities collided on (provider, subject), this
      // would 409 instead — proving they don't.
      expect(globexLinkRes.status).toBe(201);

      const acmeIdentity = await identities.findByProviderSubject(
        'oidc',
        'acme-corp:okta-sub-shared-across-tenants',
      );
      const globexIdentity = await identities.findByProviderSubject(
        'oidc',
        'globex-inc:okta-sub-shared-across-tenants',
      );
      expect(acmeIdentity?.kisUserId).toBe(
        '33333333-3333-3333-3333-333333333333',
      );
      expect(globexIdentity?.kisUserId).toBe(
        '44444444-4444-4444-4444-444444444444',
      );
    });

    it('a returning enterprise user (already linked) completes recovery through the normal authorization exchange', async () => {
      const identities = new IdentityService(pool);
      await identities.link({
        provider: 'oidc',
        providerSubject: 'acme-corp:returning-user-sub',
        kisUserId: '55555555-5555-5555-5555-555555555555',
        providerEmail: 'returning@acme-corp.example',
        providerEmailVerified: true,
      });
      identityByDiscoveryUrl[ACME_DISCOVERY_URL] = {
        sub: 'returning-user-sub',
        email: 'returning@acme-corp.example',
        emailVerified: true,
      };

      const { code } = await driveToEnterpriseCode({
        partnerSlug: 'acme-corp',
        purpose: 'recovery',
        clientState: 'acme-recovery-state',
      });

      const exchangeBody = {
        code,
        client_id: 'kis-django',
        redirect_uri: REDIRECT_URI,
      };
      const exchangeRes = await supertest(server)
        .post('/internal/v1/authorization/exchange')
        .set(
          signedInternalHeaders({
            method: 'POST',
            url: '/internal/v1/authorization/exchange',
            body: exchangeBody,
            secret: HMAC_SECRET,
          }),
        )
        .send(exchangeBody);
      expect(exchangeRes.status).toBe(201);

      const payload = await verifyAuthorizationJwt(
        exchangeRes.body.token,
        jwtKeyPair.publicKeyPem,
        'kis-django',
      );
      expect(payload.sub).toBe('55555555-5555-5555-5555-555555555555');
      expect(payload.purpose).toBe('recovery');

      // restore fixture for subsequent tests in this file
      identityByDiscoveryUrl[ACME_DISCOVERY_URL] = {
        sub: 'okta-sub-shared-across-tenants',
        email: 'employee@acme-corp.example',
        emailVerified: true,
      };
    });

    it("rejects a session started for one partner from completing at a different partner's callback URL", async () => {
      const authorizeRes = await supertest(server)
        .get('/authorize')
        .query({
          client_id: 'kis-django',
          redirect_uri: REGISTRATION_REDIRECT_URI,
          purpose: 'registration',
          state: 'cross-tenant-state',
          partner_slug: 'acme-corp',
        })
        .redirects(0);
      const cookie = extractCookie(authorizeRes);
      await supertest(server)
        .get('/oauth/enterprise/acme-corp/start')
        .set('Cookie', cookie)
        .redirects(0);

      // Attempt to complete at globex's callback URL using acme's cookie/state.
      const res = await supertest(server)
        .get('/oauth/enterprise/globex-inc/callback')
        .query({ code: 'whatever', state: 'irrelevant' })
        .set('Cookie', cookie)
        .redirects(0);
      expect(res.status).toBe(400);
    });

    it('rejects an unknown or unconfigured partner_slug at /start with the generic error', async () => {
      const authorizeRes = await supertest(server)
        .get('/authorize')
        .query({
          client_id: 'kis-django',
          redirect_uri: REGISTRATION_REDIRECT_URI,
          purpose: 'registration',
          state: 'unknown-partner-state',
          partner_slug: 'no-such-tenant',
        })
        .redirects(0);
      const cookie = extractCookie(authorizeRes);
      const res = await supertest(server)
        .get('/oauth/enterprise/no-such-tenant/start')
        .set('Cookie', cookie)
        .redirects(0);
      expect(res.status).toBe(400);
    });

    it('rejects a malformed partner_slug at /authorize before any session is created', async () => {
      const res = await supertest(server)
        .get('/authorize')
        .query({
          client_id: 'kis-django',
          redirect_uri: REGISTRATION_REDIRECT_URI,
          purpose: 'registration',
          state: 's',
          partner_slug: 'not a valid slug!!',
        })
        .redirects(0);
      expect(res.status).toBe(400);
    });

    it('the ordinary Google flow (no partner_slug) is completely unaffected — still redirects to /oauth/google/start', async () => {
      const res = await supertest(server)
        .get('/authorize')
        .query({
          client_id: 'kis-django',
          redirect_uri: REDIRECT_URI,
          purpose: 'recovery',
          state: 'google-unaffected',
        })
        .redirects(0);
      expect(res.status).toBe(303);
      expect(res.headers.location).toBe('/oauth/google/start');
    });
  },
);
