import crypto from 'crypto';
import Redis from 'ioredis';
import { LinkTicketService } from './link-ticket';

const redisUrl = process.env.KISAUTH_TEST_REDIS_URL;
const describeIfRedis = redisUrl ? describe : describe.skip;

const SECRET = 'test-internal-hmac-secret';

function mintTicket(
  payload: { kisUserId: string; nonce?: string; exp?: number },
  secret = SECRET,
): string {
  const full = {
    kisUserId: payload.kisUserId,
    nonce: payload.nonce ?? crypto.randomUUID(),
    exp: payload.exp ?? Math.floor(Date.now() / 1000) + 300,
  };
  const encoded = Buffer.from(JSON.stringify(full)).toString('base64url');
  const signature = crypto
    .createHmac('sha256', secret)
    .update(encoded)
    .digest('hex');
  return `${encoded}.${signature}`;
}

describeIfRedis('LinkTicketService (against real Redis)', () => {
  let redis: Redis;
  let service: LinkTicketService;

  beforeAll(() => {
    redis = new Redis(redisUrl as string);
    service = new LinkTicketService(redis);
  });

  afterEach(async () => {
    const keys = await redis.keys('kisauth:linkticketnonce:*');
    if (keys.length) await redis.del(...keys);
  });

  afterAll(async () => {
    await redis.quit();
  });

  it('accepts a validly signed, unexpired ticket', async () => {
    const ticket = mintTicket({ kisUserId: 'user-1' });
    const result = await service.verifyAndConsume(ticket, SECRET);
    expect(result).toEqual({ ok: true, kisUserId: 'user-1' });
  });

  it('rejects a ticket signed with the wrong secret', async () => {
    const ticket = mintTicket({ kisUserId: 'user-1' }, 'wrong-secret');
    const result = await service.verifyAndConsume(ticket, SECRET);
    expect(result).toEqual({ ok: false, reason: 'signature_mismatch' });
  });

  it('rejects a tampered payload even if the signature was valid for the original', async () => {
    const ticket = mintTicket({ kisUserId: 'user-1' });
    const [encoded, signature] = ticket.split('.');
    const tamperedPayload = JSON.parse(
      Buffer.from(encoded, 'base64url').toString('utf8'),
    );
    tamperedPayload.kisUserId = 'attacker-controlled-user';
    const tamperedEncoded = Buffer.from(JSON.stringify(tamperedPayload)).toString(
      'base64url',
    );
    const result = await service.verifyAndConsume(
      `${tamperedEncoded}.${signature}`,
      SECRET,
    );
    expect(result).toEqual({ ok: false, reason: 'signature_mismatch' });
  });

  it('rejects an expired ticket', async () => {
    const ticket = mintTicket({
      kisUserId: 'user-1',
      exp: Math.floor(Date.now() / 1000) - 10,
    });
    const result = await service.verifyAndConsume(ticket, SECRET);
    expect(result).toEqual({ ok: false, reason: 'expired' });
  });

  it('rejects malformed tickets', async () => {
    expect(await service.verifyAndConsume('not-a-ticket', SECRET)).toEqual({
      ok: false,
      reason: 'malformed',
    });
    expect(await service.verifyAndConsume('a.b.c', SECRET)).toEqual({
      ok: false,
      reason: 'malformed',
    });
  });

  it('rejects a second use of the same ticket — the core replay defense', async () => {
    const ticket = mintTicket({ kisUserId: 'user-1' });
    const first = await service.verifyAndConsume(ticket, SECRET);
    expect(first.ok).toBe(true);
    const second = await service.verifyAndConsume(ticket, SECRET);
    expect(second).toEqual({ ok: false, reason: 'already_used' });
  });

  it('does not let two different tickets for the same user collide', async () => {
    const ticketA = mintTicket({ kisUserId: 'user-1' });
    const ticketB = mintTicket({ kisUserId: 'user-1' });
    expect((await service.verifyAndConsume(ticketA, SECRET)).ok).toBe(true);
    expect((await service.verifyAndConsume(ticketB, SECRET)).ok).toBe(true);
  });
});
