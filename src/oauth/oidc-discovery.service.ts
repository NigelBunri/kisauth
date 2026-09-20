import { Injectable, Optional, Inject } from '@nestjs/common';
import { FETCH_IMPL } from './google-token-exchange.service';

export class OidcDiscoveryError extends Error {}

export interface OidcDiscoveryDocument {
  authorizationEndpoint: string;
  tokenEndpoint: string;
  jwksUri: string;
  issuer: string | null;
}

const CACHE_TTL_MS = 5 * 60 * 1000; // discovery documents change rarely

/** Fetches and caches an IdP's `/.well-known/openid-configuration`
 * document. Cached per discovery_url (not per partner) since two tenants
 * could in principle share the same discovery document, and it keeps the
 * cache trivially simple — an in-memory Map with a short TTL, same shape
 * as OidcProviderResolverService's own cache, appropriate for a
 * single-instance service. */
@Injectable()
export class OidcDiscoveryService {
  private readonly cache = new Map<
    string,
    { doc: OidcDiscoveryDocument; expiresAt: number }
  >();

  constructor(
    @Optional() @Inject(FETCH_IMPL) private readonly fetchImpl?: typeof fetch,
  ) {}

  async fetchDiscovery(discoveryUrl: string): Promise<OidcDiscoveryDocument> {
    const cached = this.cache.get(discoveryUrl);
    if (cached && cached.expiresAt > Date.now()) {
      return cached.doc;
    }

    const doFetch = this.fetchImpl ?? fetch;
    let response: Response;
    try {
      response = await doFetch(discoveryUrl);
    } catch {
      throw new OidcDiscoveryError('discovery_request_failed');
    }
    if (!response.ok) {
      throw new OidcDiscoveryError(
        `discovery endpoint returned ${response.status}`,
      );
    }

    let body: Record<string, unknown>;
    try {
      body = (await response.json()) as Record<string, unknown>;
    } catch {
      throw new OidcDiscoveryError('discovery_response_not_json');
    }

    const authorizationEndpoint = body.authorization_endpoint;
    const tokenEndpoint = body.token_endpoint;
    const jwksUri = body.jwks_uri;
    if (
      typeof authorizationEndpoint !== 'string' ||
      typeof tokenEndpoint !== 'string' ||
      typeof jwksUri !== 'string'
    ) {
      throw new OidcDiscoveryError('discovery_document_incomplete');
    }

    const doc: OidcDiscoveryDocument = {
      authorizationEndpoint,
      tokenEndpoint,
      jwksUri,
      issuer: typeof body.issuer === 'string' ? body.issuer : null,
    };
    this.cache.set(discoveryUrl, { doc, expiresAt: Date.now() + CACHE_TTL_MS });
    return doc;
  }
}
