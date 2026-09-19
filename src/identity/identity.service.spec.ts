import { randomUUID } from 'crypto';
import { Pool } from 'pg';
import { IdentityService } from './identity.service';
import { getTestPool, truncateAll } from '../../test/db-test-helper';

const pool: Pool | null = getTestPool();
const describeIfDb = pool ? describe : describe.skip;

describeIfDb('IdentityService (against real Postgres)', () => {
  let service: IdentityService;

  beforeAll(() => {
    service = new IdentityService(pool as Pool);
  });

  beforeEach(async () => {
    await truncateAll(pool as Pool);
  });

  afterAll(async () => {
    await (pool as Pool).end();
  });

  it('links a Google identity to a KIS account and finds it back by (provider, subject)', async () => {
    const kisUserId = randomUUID();
    const linked = await service.link({
      provider: 'google',
      providerSubject: 'google-sub-1',
      kisUserId,
      providerEmail: 'person@example.com',
      providerEmailVerified: true,
    });
    expect(linked.ok).toBe(true);

    const found = await service.findByProviderSubject('google', 'google-sub-1');
    expect(found?.kisUserId).toBe(kisUserId);
    expect(found?.providerEmailVerified).toBe(true);
  });

  it('returns null for an identity that was never linked — never invents a match', async () => {
    const found = await service.findByProviderSubject(
      'google',
      'never-seen-sub',
    );
    expect(found).toBeNull();
  });

  it('refuses to link the same Google identity to a second KIS account', async () => {
    await service.link({
      provider: 'google',
      providerSubject: 'shared-sub',
      kisUserId: randomUUID(),
      providerEmail: 'a@example.com',
      providerEmailVerified: true,
    });
    const second = await service.link({
      provider: 'google',
      providerSubject: 'shared-sub',
      kisUserId: randomUUID(),
      providerEmail: 'b@example.com',
      providerEmailVerified: true,
    });
    expect(second).toEqual({ ok: false, reason: 'already_linked' });
  });

  it('refuses to link a second Google identity to the same KIS account', async () => {
    const kisUserId = randomUUID();
    await service.link({
      provider: 'google',
      providerSubject: 'first-sub',
      kisUserId,
      providerEmail: 'a@example.com',
      providerEmailVerified: true,
    });
    const second = await service.link({
      provider: 'google',
      providerSubject: 'second-sub',
      kisUserId,
      providerEmail: 'b@example.com',
      providerEmailVerified: true,
    });
    expect(second).toEqual({ ok: false, reason: 'already_linked' });
  });

  it('never matches two different Google identities that merely share an email', async () => {
    await service.link({
      provider: 'google',
      providerSubject: 'sub-with-shared-email-a',
      kisUserId: randomUUID(),
      providerEmail: 'shared@example.com',
      providerEmailVerified: true,
    });
    // A second, completely different Google subject with the SAME email
    // string must link fine as its own separate identity — email equality
    // must never be treated as identity equality.
    const second = await service.link({
      provider: 'google',
      providerSubject: 'sub-with-shared-email-b',
      kisUserId: randomUUID(),
      providerEmail: 'shared@example.com',
      providerEmailVerified: true,
    });
    expect(second.ok).toBe(true);

    const a = await service.findByProviderSubject(
      'google',
      'sub-with-shared-email-a',
    );
    const b = await service.findByProviderSubject(
      'google',
      'sub-with-shared-email-b',
    );
    expect(a?.kisUserId).not.toBe(b?.kisUserId);
  });
});
