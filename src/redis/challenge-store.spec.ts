import Redis from 'ioredis';
import { ChallengeStore } from './challenge-store';

const redisUrl = process.env.KISAUTH_TEST_REDIS_URL;
const describeIfRedis = redisUrl ? describe : describe.skip;

describeIfRedis('ChallengeStore (against real Redis)', () => {
  let redis: Redis;
  let store: ChallengeStore;

  beforeAll(() => {
    redis = new Redis(redisUrl as string);
    store = new ChallengeStore(redis);
  });

  afterEach(async () => {
    const keys = await redis.keys('kisauth:*');
    if (keys.length) await redis.del(...keys);
  });

  afterAll(async () => {
    await redis.quit();
  });

  it('round-trips a challenge record', async () => {
    await store.createChallenge(
      'c1',
      {
        purpose: 'recovery',
        clientId: 'kis-django',
        kisUserId: 'user-1',
        authIdentityId: 'identity-1',
        attemptCount: 0,
        maxAttempts: 5,
        used: false,
      },
      30,
    );
    const found = await store.getChallenge('c1');
    expect(found?.purpose).toBe('recovery');
    expect(found?.attemptCount).toBe(0);
  });

  it('expires a challenge after its TTL — simulated via a 1s TTL', async () => {
    await store.createChallenge(
      'c-expiring',
      {
        purpose: 'recovery',
        clientId: 'kis-django',
        kisUserId: 'user-1',
        authIdentityId: 'identity-1',
        attemptCount: 0,
        maxAttempts: 5,
        used: false,
      },
      1,
    );
    await new Promise((r) => setTimeout(r, 1300));
    const found = await store.getChallenge('c-expiring');
    expect(found).toBeNull();
  });

  it('increments attempt count and returns null once the challenge is gone', async () => {
    await store.createChallenge(
      'c2',
      {
        purpose: 'recovery',
        clientId: 'kis-django',
        kisUserId: 'user-1',
        authIdentityId: 'identity-1',
        attemptCount: 0,
        maxAttempts: 5,
        used: false,
      },
      30,
    );
    expect(await store.incrementAttempts('c2')).toBe(1);
    expect(await store.incrementAttempts('c2')).toBe(2);
    await store.deleteChallenge('c2');
    expect(await store.incrementAttempts('c2')).toBeNull();
  });

  it('issues and consumes a single-use authorization code exactly once', async () => {
    const code = await store.issueAuthorizationCode(
      {
        purpose: 'recovery',
        clientId: 'kis-django',
        kisUserId: 'user-1',
        authIdentityId: 'identity-1',
        redirectUri: 'https://kis.app/cb',
      },
      60,
    );
    const first = await store.consumeAuthorizationCode(code);
    expect(first?.kisUserId).toBe('user-1');

    const second = await store.consumeAuthorizationCode(code);
    expect(second).toBeNull();
  });

  it('never lets two concurrent redemption attempts both succeed — the core replay-safety guarantee', async () => {
    const code = await store.issueAuthorizationCode(
      {
        purpose: 'recovery',
        clientId: 'kis-django',
        kisUserId: 'user-1',
        authIdentityId: 'identity-1',
        redirectUri: 'https://kis.app/cb',
      },
      60,
    );
    // Fire 20 concurrent redemption attempts for the SAME code — exactly
    // one must win. This is the scenario a get-then-delete pair (instead
    // of a single atomic Lua script) would fail under load.
    const results = await Promise.all(
      Array.from({ length: 20 }, () => store.consumeAuthorizationCode(code)),
    );
    const successes = results.filter((r) => r !== null);
    expect(successes.length).toBe(1);
  });

  it('returns null for a code that was never issued', async () => {
    const result = await store.consumeAuthorizationCode('never-issued-code');
    expect(result).toBeNull();
  });
});
