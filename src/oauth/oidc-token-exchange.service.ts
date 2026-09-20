import { Injectable, Optional, Inject } from '@nestjs/common';
import { FETCH_IMPL } from './google-token-exchange.service';

export class OidcTokenExchangeError extends Error {}

/** Exchanges an enterprise IdP's authorization `code` for tokens,
 * server-to-server — the tenant's client_secret (resolved fresh from
 * Django for every callback, never persisted in the browser session) is
 * used here and only here. Same shape as GoogleTokenExchangeService, but
 * every endpoint/credential is a per-tenant parameter instead of a fixed
 * env value, since this one call serves every enterprise IdP. */
@Injectable()
export class OidcTokenExchangeService {
  constructor(
    @Optional() @Inject(FETCH_IMPL) private readonly fetchImpl?: typeof fetch,
  ) {}

  async exchangeCodeForIdToken(args: {
    tokenEndpoint: string;
    code: string;
    codeVerifier: string;
    clientId: string;
    clientSecret: string;
    redirectUri: string;
  }): Promise<string> {
    const doFetch = this.fetchImpl ?? fetch;
    let response: Response;
    try {
      response = await doFetch(args.tokenEndpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          code: args.code,
          client_id: args.clientId,
          client_secret: args.clientSecret,
          redirect_uri: args.redirectUri,
          grant_type: 'authorization_code',
          code_verifier: args.codeVerifier,
        }).toString(),
      });
    } catch {
      throw new OidcTokenExchangeError('token_request_failed');
    }
    if (!response.ok) {
      throw new OidcTokenExchangeError(
        `oidc token endpoint returned ${response.status}`,
      );
    }
    const body = (await response.json()) as { id_token?: string };
    if (!body.id_token) {
      throw new OidcTokenExchangeError('oidc token response missing id_token');
    }
    return body.id_token;
  }
}
