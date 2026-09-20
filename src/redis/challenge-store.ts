import { randomBytes } from 'crypto';
import { Injectable } from '@nestjs/common';
import Redis from 'ioredis';

// All keys namespaced under kisauth: so this store can safely share a
// Redis instance with other infrastructure without key collisions.
const KEY_PREFIX = 'kisauth:challenge:';
const CODE_PREFIX = 'kisauth:code:';
const REG_TICKET_PREFIX = 'kisauth:regticket:';

export type Purpose =
  | 'recovery'
  | 'registration'
  | 'link'
  | 'device_verify'
  | 'sensitive_change'
  // Enterprise-IdP (Okta/Azure AD/Google Workspace/etc.) JIT registration
  // via the generic OIDC bridge — see oidc-enterprise.controller.ts.
  // Django's exchange_client.VerifiedRegistration treats this the same as
  // 'registration' except it skips phone collection.
  | 'enterprise_sso_registration';

export interface ChallengeRecord {
  purpose: Purpose;
  clientId: string;
  kisUserId: string | null;
  authIdentityId: string | null;
  attemptCount: number;
  maxAttempts: number;
  used: boolean;
}

export interface AuthorizationCodePayload {
  purpose: Purpose;
  clientId: string;
  kisUserId: string;
  authIdentityId: string;
  redirectUri: string;
}

/** Issued when purpose='registration' and no existing identity matched —
 * there is deliberately no kisUserId here, since none exists yet. Carries
 * just enough of the Google-verified identity for Django to create the
 * account and then link it, without kis-auth ever holding KIS account
 * fields (phone, etc.) itself. */
export interface RegistrationTicketPayload {
  clientId: string;
  // Carried through so RegistrationExchangeController mints the JWT with
  // the right `purpose` claim instead of hardcoding 'registration' — see
  // Purpose above for 'enterprise_sso_registration'.
  purpose: Purpose;
  provider: string;
  providerSubject: string;
  providerEmail: string | null;
  providerEmailVerified: boolean;
  // Set only for enterprise_sso_registration — the tenant the IdP config
  // belongs to. null for the original Google flow.
  partnerSlug: string | null;
  redirectUri: string;
}

/** Atomic get-and-delete: consumes an authorization code exactly once.
 * Two simultaneous redemption attempts must not both succeed — this is
 * the property the entire replay-protection story rests on, so it's a
 * single Lua script (server-side atomic), not a get-then-delete pair from
 * the client (which would have a race window between the two commands). */
const CONSUME_SCRIPT = `
local value = redis.call('GET', KEYS[1])
if value then
  redis.call('DEL', KEYS[1])
end
return value
`;

@Injectable()
export class ChallengeStore {
  constructor(private readonly redis: Redis) {}

  async createChallenge(
    id: string,
    record: ChallengeRecord,
    ttlSeconds: number,
  ): Promise<void> {
    await this.redis.set(
      KEY_PREFIX + id,
      JSON.stringify(record),
      'EX',
      ttlSeconds,
    );
  }

  async getChallenge(id: string): Promise<ChallengeRecord | null> {
    const raw = await this.redis.get(KEY_PREFIX + id);
    return raw ? (JSON.parse(raw) as ChallengeRecord) : null;
  }

  /** Returns the new attempt count, or null if the challenge doesn't exist
   * (expired or never created) — callers treat null as "reject, generic
   * error" rather than distinguishing expired-vs-never-existed. */
  async incrementAttempts(id: string): Promise<number | null> {
    const key = KEY_PREFIX + id;
    const raw = await this.redis.get(key);
    if (!raw) return null;
    const record = JSON.parse(raw) as ChallengeRecord;
    record.attemptCount += 1;
    const ttl = await this.redis.ttl(key);
    if (ttl <= 0) return null; // expired between GET and here — fail closed
    await this.redis.set(key, JSON.stringify(record), 'EX', ttl);
    return record.attemptCount;
  }

  async markChallengeUsed(id: string): Promise<void> {
    const key = KEY_PREFIX + id;
    const raw = await this.redis.get(key);
    if (!raw) return;
    const record = JSON.parse(raw) as ChallengeRecord;
    record.used = true;
    const ttl = await this.redis.ttl(key);
    if (ttl <= 0) return;
    await this.redis.set(key, JSON.stringify(record), 'EX', ttl);
  }

  async deleteChallenge(id: string): Promise<void> {
    await this.redis.del(KEY_PREFIX + id);
  }

  /** Mints a single-use authorization code — ≥128 bits of CSPRNG entropy,
   * URL-safe, short TTL. */
  async issueAuthorizationCode(
    payload: AuthorizationCodePayload,
    ttlSeconds: number,
  ): Promise<string> {
    const code = randomBytes(32).toString('base64url'); // 256 bits
    await this.redis.set(
      CODE_PREFIX + code,
      JSON.stringify(payload),
      'EX',
      ttlSeconds,
    );
    return code;
  }

  /** Atomically consumes the code — a second call for the same code
   * returns null. This is what makes code replay structurally
   * impossible rather than merely checked-for. */
  async consumeAuthorizationCode(
    code: string,
  ): Promise<AuthorizationCodePayload | null> {
    const raw = (await this.redis.eval(
      CONSUME_SCRIPT,
      1,
      CODE_PREFIX + code,
    )) as string | null;
    return raw ? (JSON.parse(raw) as AuthorizationCodePayload) : null;
  }

  /** Same single-use CSPRNG-code pattern as issueAuthorizationCode, for the
   * registration branch — kept as a distinct method/prefix rather than
   * overloading AuthorizationCodePayload, since callers of the existing
   * type correctly assume kisUserId is always present. */
  async issueRegistrationTicket(
    payload: RegistrationTicketPayload,
    ttlSeconds: number,
  ): Promise<string> {
    const code = randomBytes(32).toString('base64url');
    await this.redis.set(
      REG_TICKET_PREFIX + code,
      JSON.stringify(payload),
      'EX',
      ttlSeconds,
    );
    return code;
  }

  async consumeRegistrationTicket(
    code: string,
  ): Promise<RegistrationTicketPayload | null> {
    const raw = (await this.redis.eval(
      CONSUME_SCRIPT,
      1,
      REG_TICKET_PREFIX + code,
    )) as string | null;
    return raw ? (JSON.parse(raw) as RegistrationTicketPayload) : null;
  }
}
