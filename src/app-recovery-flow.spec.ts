// Full end-to-end recovery round trip, driven entirely over real HTTP
// against a real Fastify+Nest app, real Postgres, and real Redis — only
// Google itself is substituted via DI (GoogleTokenExchangeService and
// GoogleIdTokenService), the same seam production uses for the real
// network calls. Everything else — session cookies, PKCE, state/nonce,
// challenge issuance, the authorization code, the HMAC-signed exchange,
// and the final signed JWT — runs for real.

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
import { GoogleTokenExchangeService } from './oauth/google-token-exchange.service';
import { GoogleIdTokenService } from './oauth/google-id-token.service';
import { verifyAuthorizationJwt } from './jwt/authorization-jwt.service';
import { generateRs256KeyPairPem } from './jwt/keys';
import { signedInternalHeaders } from './security/internal-signing';
import { resetConfigCacheForTests } from './config/env';

const runIntegration =
  process.env.KISAUTH_TEST_DATABASE_URL && process.env.KISAUTH_TEST_REDIS_URL;
const describeIfInfra = runIntegration ? describe : describe.skip;

const jwtKeyPair = generateRs256KeyPairPem();
const HMAC_SECRET = 'test-internal-secret';
const GOOGLE_SUB = 'google-sub-recovery-user';
const KIS_USER_ID = '11111111-1111-1111-1111-111111111111';
const REDIRECT_URI = 'https://kis.app/auth/kisauth-callback';

describeIfInfra('KIS Auth — full recovery round trip (integration)', () => {
  let app: NestFastifyApplication;
  let pool: Pool;
  let redis: Redis;
  let server: any;

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
    process.env.KISAUTH_JWT_KID = 'kid-test';
    process.env.KISAUTH_INTERNAL_HMAC_SECRET = HMAC_SECRET;
    process.env.KISAUTH_CHALLENGE_TTL_SECONDS = '30';
    process.env.KISAUTH_AUTH_CODE_TTL_SECONDS = '60';
    process.env.KISAUTH_CHALLENGE_MAX_ATTEMPTS = '5';
    resetConfigCacheForTests();

    // Fake "Google": token-exchange returns a fixed marker; id-token
    // verification returns a fixed identity — this is the ONLY seam
    // that's substituted. Everything downstream is real.
    const fakeExchange = {
      exchangeCodeForIdToken: jest.fn(async () => 'fake-id-token'),
    };
    const fakeIdToken = {
      verify: jest.fn(async (_token: string, _nonce: string) => ({
        sub: GOOGLE_SUB,
        email: 'recovered-user@example.com',
        emailVerified: true,
      })),
    };

    const moduleRef = await Test.createTestingModule({ imports: [AppModule] })
      .overrideProvider(GoogleTokenExchangeService)
      .useValue(fakeExchange)
      .overrideProvider(GoogleIdTokenService)
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
      allowedRedirectUris: [REDIRECT_URI],
      allowedScopes: ['openid', 'email', 'profile'],
      allowedPurposes: ['recovery'],
    });

    const identities = moduleRef.get(IdentityService);
    await identities.link({
      provider: 'google',
      providerSubject: GOOGLE_SUB,
      kisUserId: KIS_USER_ID,
      providerEmail: 'recovered-user@example.com',
      providerEmailVerified: true,
    });
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

  it('completes the full recovery round trip: authorize -> Google -> code -> s2s exchange -> signed JWT', async () => {
    // 1. /authorize — client + redirect_uri + purpose validated, session cookie issued.
    const authorizeRes = await supertest(server)
      .get('/authorize')
      .query({
        client_id: 'kis-django',
        redirect_uri: REDIRECT_URI,
        purpose: 'recovery',
        state: 'client-own-csrf-state',
      })
      .redirects(0);
    expect(authorizeRes.status).toBe(303);
    expect(authorizeRes.headers.location).toBe('/oauth/google/start');
    const cookie = extractCookie(authorizeRes);

    // 2. /oauth/google/start — PKCE verifier attached to session, redirects to Google.
    const startRes = await supertest(server)
      .get('/oauth/google/start')
      .set('Cookie', cookie)
      .redirects(0);
    expect(startRes.status).toBe(303);
    expect(startRes.headers.location).toContain('accounts.google.com');
    const googleUrl = new URL(startRes.headers.location);
    expect(googleUrl.searchParams.get('code_challenge_method')).toBe('S256');
    const stateSentToGoogle = googleUrl.searchParams.get('state')!;

    // 3. /oauth/google/callback — simulates Google redirecting back with its own code + our state.
    const callbackRes = await supertest(server)
      .get('/oauth/google/callback')
      .query({ code: 'google-auth-code-abc', state: stateSentToGoogle })
      .set('Cookie', cookie)
      .redirects(0);
    expect(callbackRes.status).toBe(303);
    const finalRedirect = new URL(callbackRes.headers.location);
    expect(finalRedirect.origin + finalRedirect.pathname).toBe(REDIRECT_URI);
    expect(finalRedirect.searchParams.get('state')).toBe(
      'client-own-csrf-state',
    ); // the ORIGINAL client state, not KIS Auth's internal one
    const authorizationCode = finalRedirect.searchParams.get('code')!;
    expect(authorizationCode).toBeTruthy();

    // 4. Django redeems the code server-to-server, HMAC-signed.
    const exchangeBody = {
      code: authorizationCode,
      client_id: 'kis-django',
      redirect_uri: REDIRECT_URI,
    };
    const signedHeaders = signedInternalHeaders({
      method: 'POST',
      url: '/internal/v1/authorization/exchange',
      body: exchangeBody,
      secret: HMAC_SECRET,
    });
    const exchangeRes = await supertest(server)
      .post('/internal/v1/authorization/exchange')
      .set(signedHeaders)
      .send(exchangeBody);
    expect(exchangeRes.status).toBe(201);
    expect(exchangeRes.body.token).toBeTruthy();

    // 5. The resulting JWT verifies, carries the right claims, and is
    // scoped to exactly this operation.
    const payload = await verifyAuthorizationJwt(
      exchangeRes.body.token,
      jwtKeyPair.publicKeyPem,
      'kis-django',
    );
    expect(payload.sub).toBe(KIS_USER_ID);
    expect(payload.purpose).toBe('recovery');
    expect(payload.provider_email).toBe('recovered-user@example.com');
    expect(payload.provider_email_verified).toBe(true);
  });

  it('rejects redeeming the same authorization code twice — replay is structurally impossible', async () => {
    const authorizeRes = await supertest(server)
      .get('/authorize')
      .query({
        client_id: 'kis-django',
        redirect_uri: REDIRECT_URI,
        purpose: 'recovery',
        state: 's2',
      })
      .redirects(0);
    const cookie = extractCookie(authorizeRes);
    const startRes = await supertest(server)
      .get('/oauth/google/start')
      .set('Cookie', cookie)
      .redirects(0);
    const state = new URL(startRes.headers.location).searchParams.get('state')!;
    const callbackRes = await supertest(server)
      .get('/oauth/google/callback')
      .query({ code: 'g-code-2', state })
      .set('Cookie', cookie)
      .redirects(0);
    const code = new URL(callbackRes.headers.location).searchParams.get(
      'code',
    )!;

    const body = { code, client_id: 'kis-django', redirect_uri: REDIRECT_URI };
    const headers1 = signedInternalHeaders({
      method: 'POST',
      url: '/internal/v1/authorization/exchange',
      body,
      secret: HMAC_SECRET,
    });
    const first = await supertest(server)
      .post('/internal/v1/authorization/exchange')
      .set(headers1)
      .send(body);
    expect(first.status).toBe(201);

    const headers2 = signedInternalHeaders({
      method: 'POST',
      url: '/internal/v1/authorization/exchange',
      body,
      secret: HMAC_SECRET,
    });
    const second = await supertest(server)
      .post('/internal/v1/authorization/exchange')
      .set(headers2)
      .send(body);
    expect(second.status).toBe(400);
  });

  it('rejects an exchange call without a valid HMAC signature — code possession alone is not enough', async () => {
    const body = {
      code: 'whatever-code',
      client_id: 'kis-django',
      redirect_uri: REDIRECT_URI,
    };
    const res = await supertest(server)
      .post('/internal/v1/authorization/exchange')
      .send(body); // no signature headers at all
    expect(res.status).toBe(401);
  });

  it('rejects an exchange call signed with the wrong HMAC secret', async () => {
    const body = {
      code: 'whatever-code',
      client_id: 'kis-django',
      redirect_uri: REDIRECT_URI,
    };
    const headers = signedInternalHeaders({
      method: 'POST',
      url: '/internal/v1/authorization/exchange',
      body,
      secret: 'wrong-secret-entirely',
    });
    const res = await supertest(server)
      .post('/internal/v1/authorization/exchange')
      .set(headers)
      .send(body);
    expect(res.status).toBe(401);
  });

  it('rejects redemption when redirect_uri does not match what /authorize originally approved', async () => {
    const authorizeRes = await supertest(server)
      .get('/authorize')
      .query({
        client_id: 'kis-django',
        redirect_uri: REDIRECT_URI,
        purpose: 'recovery',
        state: 's3',
      })
      .redirects(0);
    const cookie = extractCookie(authorizeRes);
    const startRes = await supertest(server)
      .get('/oauth/google/start')
      .set('Cookie', cookie)
      .redirects(0);
    const state = new URL(startRes.headers.location).searchParams.get('state')!;
    const callbackRes = await supertest(server)
      .get('/oauth/google/callback')
      .query({ code: 'g-code-3', state })
      .set('Cookie', cookie)
      .redirects(0);
    const code = new URL(callbackRes.headers.location).searchParams.get(
      'code',
    )!;

    // Attempt to redeem it against a DIFFERENT redirect_uri than was approved.
    const body = {
      code,
      client_id: 'kis-django',
      redirect_uri: 'https://attacker.example.com/steal',
    };
    const headers = signedInternalHeaders({
      method: 'POST',
      url: '/internal/v1/authorization/exchange',
      body,
      secret: HMAC_SECRET,
    });
    const res = await supertest(server)
      .post('/internal/v1/authorization/exchange')
      .set(headers)
      .send(body);
    expect(res.status).toBe(400);
  });

  it('rejects an /authorize request for an unregistered client', async () => {
    const res = await supertest(server)
      .get('/authorize')
      .query({
        client_id: 'not-a-real-client',
        redirect_uri: REDIRECT_URI,
        purpose: 'recovery',
        state: 's',
      })
      .redirects(0);
    expect(res.status).toBe(400);
  });

  it('rejects an /authorize request with a redirect_uri that merely starts with the registered one', async () => {
    const res = await supertest(server)
      .get('/authorize')
      .query({
        client_id: 'kis-django',
        redirect_uri: REDIRECT_URI + '.evil.com',
        purpose: 'recovery',
        state: 's',
      })
      .redirects(0);
    expect(res.status).toBe(400);
  });

  it('rejects an /authorize request for a purpose the client is not allowed to use', async () => {
    const res = await supertest(server)
      .get('/authorize')
      .query({
        client_id: 'kis-django',
        redirect_uri: REDIRECT_URI,
        purpose: 'registration',
        state: 's',
      })
      .redirects(0);
    expect(res.status).toBe(400);
  });

  it('rejects the Google callback if the state does not match the session', async () => {
    const authorizeRes = await supertest(server)
      .get('/authorize')
      .query({
        client_id: 'kis-django',
        redirect_uri: REDIRECT_URI,
        purpose: 'recovery',
        state: 's4',
      })
      .redirects(0);
    const cookie = extractCookie(authorizeRes);
    await supertest(server)
      .get('/oauth/google/start')
      .set('Cookie', cookie)
      .redirects(0);

    const res = await supertest(server)
      .get('/oauth/google/callback')
      .query({ code: 'g-code-4', state: 'completely-wrong-state' })
      .set('Cookie', cookie)
      .redirects(0);
    expect(res.status).toBe(400);
  });

  it('serves a JWKS document with no private key material', async () => {
    const res = await supertest(server).get('/.well-known/jwks.json');
    expect(res.status).toBe(200);
    expect(res.body.keys[0].kid).toBe('kid-test');
    expect(JSON.stringify(res.body)).not.toMatch(/PRIVATE/);
  });

  it('reports healthy readiness against the real Postgres and Redis', async () => {
    const res = await supertest(server).get('/readyz');
    expect(res.status).toBe(200);
    expect(res.body.checks).toEqual({ database: 'ok', redis: 'ok' });
  });
});
