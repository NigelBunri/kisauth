import { Pool } from 'pg';
import { ClientService } from './client.service';
import { getTestPool, truncateAll } from '../../test/db-test-helper';

const pool: Pool | null = getTestPool();
const describeIfDb = pool ? describe : describe.skip;

describeIfDb('ClientService (against real Postgres)', () => {
  let service: ClientService;

  beforeAll(() => {
    service = new ClientService(pool as Pool);
  });

  beforeEach(async () => {
    await truncateAll(pool as Pool);
  });

  afterAll(async () => {
    await (pool as Pool).end();
  });

  it('registers a client and allows only its exact registered redirect URI', async () => {
    await service.register({
      clientId: 'kis-django',
      name: 'KIS Django backend',
      allowedRedirectUris: ['https://kis.app/auth/callback'],
      allowedScopes: ['openid', 'email', 'profile'],
      allowedPurposes: ['recovery'],
    });
    const client = await service.findByClientId('kis-django');
    expect(client).not.toBeNull();
    expect(
      service.isRedirectUriAllowed(client!, 'https://kis.app/auth/callback'),
    ).toBe(true);
  });

  it('rejects a redirect URI that merely starts with the registered value', async () => {
    await service.register({
      clientId: 'kis-django',
      name: 'KIS Django backend',
      allowedRedirectUris: ['https://kis.app/auth/callback'],
      allowedScopes: ['openid'],
      allowedPurposes: ['recovery'],
    });
    const client = await service.findByClientId('kis-django');
    expect(
      service.isRedirectUriAllowed(
        client!,
        'https://kis.app/auth/callback.evil.example.com',
      ),
    ).toBe(false);
    expect(
      service.isRedirectUriAllowed(client!, 'https://attacker.example.com'),
    ).toBe(false);
  });

  it('rejects a purpose the client was never granted — a recovery-only client cannot request registration', async () => {
    await service.register({
      clientId: 'kis-django',
      name: 'KIS Django backend',
      allowedRedirectUris: ['https://kis.app/auth/callback'],
      allowedScopes: ['openid'],
      allowedPurposes: ['recovery'],
    });
    const client = await service.findByClientId('kis-django');
    expect(service.isPurposeAllowed(client!, 'recovery')).toBe(true);
    expect(service.isPurposeAllowed(client!, 'registration')).toBe(false);
  });

  it('rejects every operation for a disabled client, even with a previously-valid redirect URI', async () => {
    await service.register({
      clientId: 'kis-django',
      name: 'KIS Django backend',
      allowedRedirectUris: ['https://kis.app/auth/callback'],
      allowedScopes: ['openid'],
      allowedPurposes: ['recovery'],
    });
    await (pool as Pool).query(
      "UPDATE client SET status = 'disabled' WHERE client_id = 'kis-django'",
    );
    const client = await service.findByClientId('kis-django');
    expect(
      service.isRedirectUriAllowed(client!, 'https://kis.app/auth/callback'),
    ).toBe(false);
    expect(service.isPurposeAllowed(client!, 'recovery')).toBe(false);
  });

  it('returns null for an unregistered client_id', async () => {
    const client = await service.findByClientId('unknown-client');
    expect(client).toBeNull();
  });
});
