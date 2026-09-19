import { SecurityEventService } from './security-event.service';
import { resetConfigCacheForTests } from '../config/env';

function setBaseEnv(overrides: Record<string, string> = {}) {
  process.env.NODE_ENV = 'test';
  process.env.KISAUTH_BASE_URL = 'http://localhost:4100';
  process.env.GOOGLE_OAUTH_CLIENT_ID = 'test';
  process.env.GOOGLE_OAUTH_CLIENT_SECRET = 'test';
  process.env.GOOGLE_OAUTH_REDIRECT_URI =
    'http://localhost:4100/oauth/google/callback';
  process.env.KISAUTH_DATABASE_URL = 'postgres://test@localhost/test';
  process.env.KISAUTH_REDIS_URL = 'redis://localhost:6379';
  process.env.KISAUTH_JWT_PRIVATE_KEY = 'x';
  process.env.KISAUTH_JWT_PUBLIC_KEY = 'x';
  process.env.KISAUTH_JWT_KID = 'test';
  process.env.KISAUTH_INTERNAL_HMAC_SECRET = 'test-secret';
  process.env.DJANGO_SECURITY_EVENT_URL = '';
  Object.assign(process.env, overrides);
  resetConfigCacheForTests();
}

describe('SecurityEventService', () => {
  afterEach(() => {
    delete process.env.DJANGO_SECURITY_EVENT_URL;
  });

  it('does nothing when DJANGO_SECURITY_EVENT_URL is not configured — no network call attempted', async () => {
    setBaseEnv({ DJANGO_SECURITY_EVENT_URL: '' });
    const fetchMock = jest.fn();
    const service = new SecurityEventService(
      fetchMock as unknown as typeof fetch,
    );
    await service.emit({ eventType: 'exchange.succeeded', outcome: 'success' });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('POSTs a signed request with the expected shape when configured', async () => {
    setBaseEnv({
      DJANGO_SECURITY_EVENT_URL:
        'http://django.test/api/v1/kis-auth/security-event/',
    });
    const fetchMock = jest.fn().mockResolvedValue({ ok: true, status: 201 });
    const service = new SecurityEventService(
      fetchMock as unknown as typeof fetch,
    );

    await service.emit({
      eventType: 'exchange.succeeded',
      outcome: 'success',
      kisUserId: 'user-1',
      clientId: 'kis-django',
      metadata: { purpose: 'recovery' },
    });

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe('http://django.test/api/v1/kis-auth/security-event/');
    expect(init.method).toBe('POST');
    expect(init.headers['X-Internal-Signature']).toBeDefined();
    expect(init.headers['X-Internal-Timestamp']).toBeDefined();
    expect(init.headers['X-Internal-Nonce']).toBeDefined();
    const body = JSON.parse(init.body);
    expect(body).toEqual({
      event_type: 'exchange.succeeded',
      outcome: 'success',
      kis_user_id: 'user-1',
      client_id: 'kis-django',
      reason: null,
      ip: null,
      metadata: { purpose: 'recovery' },
    });
  });

  it('never throws when the forward call rejects (network failure)', async () => {
    setBaseEnv({
      DJANGO_SECURITY_EVENT_URL:
        'http://django.test/api/v1/kis-auth/security-event/',
    });
    const fetchMock = jest.fn().mockRejectedValue(new Error('ECONNREFUSED'));
    const service = new SecurityEventService(
      fetchMock as unknown as typeof fetch,
    );
    await expect(
      service.emit({ eventType: 'exchange.failed', outcome: 'failure' }),
    ).resolves.toBeUndefined();
  });

  it('never throws when Django responds with a non-2xx status', async () => {
    setBaseEnv({
      DJANGO_SECURITY_EVENT_URL:
        'http://django.test/api/v1/kis-auth/security-event/',
    });
    const fetchMock = jest.fn().mockResolvedValue({ ok: false, status: 401 });
    const service = new SecurityEventService(
      fetchMock as unknown as typeof fetch,
    );
    await expect(
      service.emit({ eventType: 'exchange.failed', outcome: 'failure' }),
    ).resolves.toBeUndefined();
  });

  it('never includes raw secrets or tokens in the forwarded body — only the fields the type allows', async () => {
    setBaseEnv({
      DJANGO_SECURITY_EVENT_URL:
        'http://django.test/api/v1/kis-auth/security-event/',
    });
    const fetchMock = jest.fn().mockResolvedValue({ ok: true, status: 201 });
    const service = new SecurityEventService(
      fetchMock as unknown as typeof fetch,
    );
    await service.emit({
      eventType: 'exchange.failed',
      outcome: 'failure',
      reason: 'signature_mismatch',
      metadata: { attempted_code_prefix: 'ab12' },
    });
    const body = JSON.parse(fetchMock.mock.calls[0][1].body);
    expect(JSON.stringify(body)).not.toContain('test-secret');
    expect(body.reason).toBe('signature_mismatch');
  });
});
