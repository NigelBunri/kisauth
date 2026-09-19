import { Injectable } from '@nestjs/common';
import Redis from 'ioredis';

const KEY_PREFIX = 'kisauth:ratelimit:';

// Atomic increment-with-expire-on-first-hit. Setting EXPIRE only when the
// counter is freshly created (rather than on every call) is what makes
// this a real fixed window instead of an accidental sliding one — a
// separate INCR-then-EXPIRE pair from the client would also have a race
// where a crash between the two calls leaves a key with no TTL at all
// (a permanent lockout), which this single script can't do.
const INCR_SCRIPT = `
local current = redis.call('INCR', KEYS[1])
if current == 1 then
  redis.call('EXPIRE', KEYS[1], ARGV[1])
end
return current
`;

export interface RateLimitResult {
  allowed: boolean;
  count: number;
  limit: number;
}

@Injectable()
export class RateLimiter {
  constructor(private readonly redis: Redis) {}

  /**
   * Fixed-window counter, not sliding. Tradeoff, deliberately accepted:
   * a caller can get up to ~2x `limit` requests through across a window
   * boundary (limit at the end of one window, limit again at the start
   * of the next). A sliding-window-log implementation would close that
   * gap but costs a sorted-set entry per request instead of one INCR —
   * not worth it for these limits, which exist to catch abuse/flooding,
   * not to meter fairness to the request.
   */
  async check(
    scope: string,
    identifier: string,
    limit: number,
    windowSeconds: number,
  ): Promise<RateLimitResult> {
    const key = `${KEY_PREFIX}${scope}:${identifier}`;
    const count = (await this.redis.eval(
      INCR_SCRIPT,
      1,
      key,
      windowSeconds,
    )) as number;
    return { allowed: count <= limit, count, limit };
  }
}
