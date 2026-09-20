import { OidcProviderResolverService } from './oidc-provider-resolver.service';
import { verifyInternalSignature } from '../security/internal-signing';
import { resetConfigCacheForTests } from '../config/env';

const HMAC_SECRET = 'test-sso-config-secret';
const SSO_CONFIG_URL =
  'https://django.internal.test/api/v1/kis-auth/sso-config/';

function setBaseEnv() {
  process.env.NODE_ENV = 'test';
  process.env.KISAUTH_BASE_URL = 'http://localhost:4100';
  process.env.GOOGLE_OAUTH_CLIENT_ID = 'test';
  process.env.GOOGLE_OAUTH_CLIENT_SECRET = 'test';
  process.env.GOOGLE_OAUTH_REDIRECT_URI =
    'http://localhost:4100/oauth/google/callback';
  process.env.KISAUTH_DATABASE_URL = 'postgres://test@localhost/test';
  process.env.KISAUTH_REDIS_URL = 'redis://localhost:6379';
  process.env.KISAUTH_INTERNAL_HMAC_SECRET = HMAC_SECRET;
  process.env.KISAUTH_JWT_PRIVATE_KEY = 'irrelevant-for-this-suite';
  process.env.KISAUTH_JWT_PUBLIC_KEY = 'irrelevant-for-this-suite';
  process.env.KISAUTH_JWT_KID = 'kid-1';
  process.env.DJANGO_SSO_CONFIG_URL = SSO_CONFIG_URL;
  resetConfigCacheForTests();
}

const VALID_BODY = {
  partner_id: '11111111-1111-1111-1111-111111111111',
  partner_slug: 'acme-corp',
  provider: 'oidc',
  issuer: 'https://acme.okta.com',
  client_id: 'acme-client-id',
  client_secret: 'acme-client-secret',
  discovery_url: 'https://acme.okta.com/.well-known/openid-configuration',
};

function jsonResponse(status: number, body: unknown): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
  } as unknown as Response;
}

describe('OidcProviderResolverService', () => {
  beforeEach(() => {
    setBaseEnv();
  });

  it('resolves a partner config and signs the request the same way every other internal call is signed', async () => {
    const fetchImpl = jest.fn(async (url: string, init: RequestInit) => {
      expect(url).toBe(`${SSO_CONFIG_URL}?partner_slug=acme-corp`);
      const headers = init.headers as Record<string, string>;
      const verification = verifyInternalSignature({
        method: 'GET',
        url,
        headers: {
          'x-internal-timestamp': headers['X-Internal-Timestamp'],
          'x-internal-nonce': headers['X-Internal-Nonce'],
          'x-internal-signature': headers['X-Internal-Signature'],
        },
        secret: HMAC_SECRET,
        maxSkewSeconds: 300,
      });
      expect(verification.ok).toBe(true);
      return jsonResponse(200, VALID_BODY);
    });

    const service = new OidcProviderResolverService(
      fetchImpl as unknown as typeof fetch,
    );
    const result = await service.resolve('acme-corp');
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.config).toEqual({
        partnerId: VALID_BODY.partner_id,
        partnerSlug: 'acme-corp',
        provider: 'oidc',
        issuer: VALID_BODY.issuer,
        clientId: VALID_BODY.client_id,
        clientSecret: VALID_BODY.client_secret,
        discoveryUrl: VALID_BODY.discovery_url,
      });
    }
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it('caches a successful lookup — a second resolve() within the TTL does not hit Django again', async () => {
    const fetchImpl = jest.fn(async () => jsonResponse(200, VALID_BODY));
    const service = new OidcProviderResolverService(
      fetchImpl as unknown as typeof fetch,
    );
    await service.resolve('acme-corp');
    await service.resolve('acme-corp');
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it('does not cache a 404 — a partner that just enabled SSO is picked up on the very next call', async () => {
    let call = 0;
    const fetchImpl = jest.fn(async () => {
      call += 1;
      return call === 1
        ? jsonResponse(404, { detail: 'unknown partner' })
        : jsonResponse(200, VALID_BODY);
    });
    const service = new OidcProviderResolverService(
      fetchImpl as unknown as typeof fetch,
    );
    const first = await service.resolve('acme-corp');
    expect(first).toEqual({ ok: false, reason: 'not_found' });
    const second = await service.resolve('acme-corp');
    expect(second.ok).toBe(true);
    expect(fetchImpl).toHaveBeenCalledTimes(2);
  });

  it('maps a 409 (enabled but misconfigured) to reason misconfigured', async () => {
    const fetchImpl = jest.fn(async () =>
      jsonResponse(409, { detail: 'sso misconfigured for this partner' }),
    );
    const service = new OidcProviderResolverService(
      fetchImpl as unknown as typeof fetch,
    );
    const result = await service.resolve('broken-corp');
    expect(result).toEqual({ ok: false, reason: 'misconfigured' });
  });

  it('maps a 401 (bad signature) to reason unauthorized', async () => {
    const fetchImpl = jest.fn(async () =>
      jsonResponse(401, { detail: 'invalid signature' }),
    );
    const service = new OidcProviderResolverService(
      fetchImpl as unknown as typeof fetch,
    );
    const result = await service.resolve('acme-corp');
    expect(result).toEqual({ ok: false, reason: 'unauthorized' });
  });

  it("maps a 503 (Django's own shared secret not configured) to reason unavailable", async () => {
    const fetchImpl = jest.fn(async () =>
      jsonResponse(503, { detail: 'not configured' }),
    );
    const service = new OidcProviderResolverService(
      fetchImpl as unknown as typeof fetch,
    );
    const result = await service.resolve('acme-corp');
    expect(result).toEqual({ ok: false, reason: 'unavailable' });
  });

  it('fails closed with reason unavailable when DJANGO_SSO_CONFIG_URL is not configured, without making a request', async () => {
    delete process.env.DJANGO_SSO_CONFIG_URL;
    resetConfigCacheForTests();
    const fetchImpl = jest.fn();
    const service = new OidcProviderResolverService(
      fetchImpl as unknown as typeof fetch,
    );
    const result = await service.resolve('acme-corp');
    expect(result).toEqual({ ok: false, reason: 'unavailable' });
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it('fails closed with reason request_failed on a network error', async () => {
    const fetchImpl = jest.fn(async () => {
      throw new Error('ECONNREFUSED');
    });
    const service = new OidcProviderResolverService(
      fetchImpl as unknown as typeof fetch,
    );
    const result = await service.resolve('acme-corp');
    expect(result).toEqual({ ok: false, reason: 'request_failed' });
  });

  it('treats a 200 response missing required fields as misconfigured rather than trusting it', async () => {
    const fetchImpl = jest.fn(async () =>
      jsonResponse(200, { ...VALID_BODY, client_secret: undefined }),
    );
    const service = new OidcProviderResolverService(
      fetchImpl as unknown as typeof fetch,
    );
    const result = await service.resolve('acme-corp');
    expect(result).toEqual({ ok: false, reason: 'misconfigured' });
  });

  it('resolves different partners independently — one being cached does not answer for another', async () => {
    const fetchImpl = jest.fn(async (url: string) => {
      const slug = new URL(url).searchParams.get('partner_slug');
      return jsonResponse(200, {
        ...VALID_BODY,
        partner_slug: slug,
        client_id: `${slug}-client-id`,
      });
    });
    const service = new OidcProviderResolverService(
      fetchImpl as unknown as typeof fetch,
    );
    const acme = await service.resolve('acme-corp');
    const globex = await service.resolve('globex-inc');
    expect(acme.ok && acme.config.clientId).toBe('acme-corp-client-id');
    expect(globex.ok && globex.config.clientId).toBe('globex-inc-client-id');
    expect(fetchImpl).toHaveBeenCalledTimes(2);
  });
});
