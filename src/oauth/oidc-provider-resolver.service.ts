import { Injectable, Optional, Inject } from '@nestjs/common';
import { loadConfig } from '../config/env';
import { signedInternalHeaders } from '../security/internal-signing';
import { FETCH_IMPL } from './google-token-exchange.service';

export interface OidcPartnerConfig {
  partnerId: string;
  partnerSlug: string;
  provider: string;
  issuer: string;
  clientId: string;
  clientSecret: string;
  discoveryUrl: string;
}

export type OidcProviderResolveResult =
  | { ok: true; config: OidcPartnerConfig }
  | {
      ok: false;
      // 'not_found': no such partner, or SSO isn't enabled for it (404).
      // 'misconfigured': enabled but missing required fields (409), or a
      //   200 response that's missing fields we require (defensive).
      // 'unauthorized': our HMAC signature was rejected (401) — should
      //   never happen in production; treated as fail-closed, not fatal.
      // 'unavailable': DJANGO_SSO_CONFIG_URL isn't configured here, or
      //   Django reports its own shared secret isn't configured (503).
      // 'request_failed': network error, or an unexpected status/body.
      reason:
        | 'not_found'
        | 'misconfigured'
        | 'unauthorized'
        | 'unavailable'
        | 'request_failed';
    };

const CACHE_TTL_MS = 60_000;

/** Resolves an enterprise tenant's OIDC config from Django's
 * GET /api/v1/kis-auth/sso-config/?partner_slug=... — HMAC-signed the
 * same way as every other kis-auth -> Django internal call, reusing
 * internal-signing.ts verbatim rather than a second signing scheme.
 *
 * Only successful, complete lookups are cached, briefly and in-memory —
 * appropriate for a single-instance service today. A partner who just
 * enabled or fixed their SSO config should not have to wait out a stale
 * failure, so failures are never cached. */
@Injectable()
export class OidcProviderResolverService {
  private readonly cache = new Map<
    string,
    { config: OidcPartnerConfig; expiresAt: number }
  >();

  constructor(
    @Optional() @Inject(FETCH_IMPL) private readonly fetchImpl?: typeof fetch,
  ) {}

  async resolve(partnerSlug: string): Promise<OidcProviderResolveResult> {
    const cached = this.cache.get(partnerSlug);
    if (cached && cached.expiresAt > Date.now()) {
      return { ok: true, config: cached.config };
    }

    const config = loadConfig();
    if (!config.djangoSsoConfigUrl) {
      return { ok: false, reason: 'unavailable' };
    }

    const url = new URL(config.djangoSsoConfigUrl);
    url.searchParams.set('partner_slug', partnerSlug);
    const headers = signedInternalHeaders({
      method: 'GET',
      url: url.toString(),
      secret: config.internalHmacSecret,
    });

    const doFetch = this.fetchImpl ?? fetch;
    let response: Response;
    try {
      response = await doFetch(url.toString(), { method: 'GET', headers });
    } catch {
      return { ok: false, reason: 'request_failed' };
    }

    if (response.status === 404) return { ok: false, reason: 'not_found' };
    if (response.status === 409) return { ok: false, reason: 'misconfigured' };
    if (response.status === 401) return { ok: false, reason: 'unauthorized' };
    if (response.status === 503) return { ok: false, reason: 'unavailable' };
    if (!response.ok) return { ok: false, reason: 'request_failed' };

    let body: Record<string, unknown>;
    try {
      body = (await response.json()) as Record<string, unknown>;
    } catch {
      return { ok: false, reason: 'request_failed' };
    }

    const {
      partner_id: partnerId,
      partner_slug: partnerSlugField,
      provider,
      issuer,
      client_id: clientId,
      client_secret: clientSecret,
      discovery_url: discoveryUrl,
    } = body;

    if (
      typeof partnerId !== 'string' ||
      typeof partnerSlugField !== 'string' ||
      typeof issuer !== 'string' ||
      typeof clientId !== 'string' ||
      typeof clientSecret !== 'string' ||
      typeof discoveryUrl !== 'string'
    ) {
      // A 200 with an incomplete body should be impossible given Django's
      // own contract (it 409s instead) — but never trust that from this
      // side; fail closed rather than proceed with an undefined field.
      return { ok: false, reason: 'misconfigured' };
    }

    const resolved: OidcPartnerConfig = {
      partnerId,
      partnerSlug: partnerSlugField,
      provider: typeof provider === 'string' ? provider : 'oidc',
      issuer,
      clientId,
      clientSecret,
      discoveryUrl,
    };

    this.cache.set(partnerSlug, {
      config: resolved,
      expiresAt: Date.now() + CACHE_TTL_MS,
    });
    return { ok: true, config: resolved };
  }
}
