import Redis from 'ioredis';
import { RateLimiter } from './rate-limit';

const redisUrl = process.env.KISAUTH_TEST_REDIS_URL;
const describeIfRedis = redisUrl ? describe : describe.skip;

describeIfRedis('RateLimiter (against real Redis)', () => {
  let redis: Redis;
  let limiter: RateLimiter;

  beforeAll(() => {
    redis = new Redis(redisUrl as string);
    limiter = new RateLimiter(redis);
  });

  afterEach(async () => {
    const keys = await redis.keys('kisauth:ratelimit:*');
    if (keys.length) await redis.del(...keys);
  });

  afterAll(async () => {
    await redis.quit();
  });

  it('allows requests under the limit', async () => {
    for (let i = 1; i <= 5; i++) {
      const result = await limiter.check('test-scope', '1.2.3.4', 5, 60);
      expect(result.allowed).toBe(true);
      expect(result.count).toBe(i);
    }
  });

  it('blocks the request that crosses the limit, and every one after it in the window', async () => {
    for (let i = 1; i <= 5; i++) {
      expect(
        (await limiter.check('test-scope', '1.2.3.4', 5, 60)).allowed,
      ).toBe(true);
    }
    expect((await limiter.check('test-scope', '1.2.3.4', 5, 60)).allowed).toBe(
      false,
    );
    expect((await limiter.check('test-scope', '1.2.3.4', 5, 60)).allowed).toBe(
      false,
    );
  });

  it('tracks different identifiers independently — one IP hitting the limit does not affect another', async () => {
    for (let i = 1; i <= 5; i++) {
      await limiter.check('test-scope', 'ip-a', 5, 60);
    }
    expect((await limiter.check('test-scope', 'ip-a', 5, 60)).allowed).toBe(
      false,
    );
    expect((await limiter.check('test-scope', 'ip-b', 5, 60)).allowed).toBe(
      true,
    );
  });

  it('tracks different scopes independently — the same identifier on two endpoints has two separate budgets', async () => {
    for (let i = 1; i <= 5; i++) {
      await limiter.check('endpoint-a', 'shared-ip', 5, 60);
    }
    expect(
      (await limiter.check('endpoint-a', 'shared-ip', 5, 60)).allowed,
    ).toBe(false);
    expect(
      (await limiter.check('endpoint-b', 'shared-ip', 5, 60)).allowed,
    ).toBe(true);
  });

  it('resets after the window expires', async () => {
    for (let i = 1; i <= 3; i++) {
      await limiter.check('test-scope', 'expiring-ip', 3, 1);
    }
    expect(
      (await limiter.check('test-scope', 'expiring-ip', 3, 1)).allowed,
    ).toBe(false);
    await new Promise((r) => setTimeout(r, 1300));
    expect(
      (await limiter.check('test-scope', 'expiring-ip', 3, 1)).allowed,
    ).toBe(true);
  });

  it('counts correctly under real concurrency — 50 simultaneous requests against a limit of 10 let through exactly 10', async () => {
    const results = await Promise.all(
      Array.from({ length: 50 }, () =>
        limiter.check('concurrent-scope', 'burst-ip', 10, 60),
      ),
    );
    const allowedCount = results.filter((r) => r.allowed).length;
    expect(allowedCount).toBe(10);
  });
});
