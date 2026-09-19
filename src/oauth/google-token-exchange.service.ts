import { Injectable, Optional, Inject } from '@nestjs/common';
import { loadConfig } from '../config/env';

const GOOGLE_TOKEN_URL = 'https://oauth2.googleapis.com/token';
export const FETCH_IMPL = Symbol('FETCH_IMPL');

export class GoogleTokenExchangeError extends Error {}

/** Exchanges Google's authorization `code` for tokens, server-to-server —
 * KIS Auth's Google client secret is used here and only here; it never
 * reaches the browser. Injectable fetch implementation so tests can
 * substitute a fake Google without a real network call, while production
 * hits the real endpoint. */
@Injectable()
export class GoogleTokenExchangeService {
  private readonly fetchImpl: typeof fetch;

  // @Optional() + an explicit @Inject(FETCH_IMPL) token (not a bare `typeof
  // fetch` default parameter) — Nest's DI calls this constructor directly
  // for every resolvable parameter, bypassing plain JS defaults, and a raw
  // function-typed parameter has no usable design:paramtype token to
  // resolve against. A dedicated injection token plus @Optional() lets
  // tests supply a fake via a TestingModule override while production
  // falls back to the real global fetch here in the constructor body.
  constructor(@Optional() @Inject(FETCH_IMPL) fetchImpl?: typeof fetch) {
    this.fetchImpl = fetchImpl ?? fetch;
  }

  async exchangeCodeForIdToken(
    code: string,
    codeVerifier: string,
  ): Promise<string> {
    const config = loadConfig();
    const response = await this.fetchImpl(GOOGLE_TOKEN_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        code,
        client_id: config.googleClientId,
        client_secret: config.googleClientSecret,
        redirect_uri: config.googleRedirectUri,
        grant_type: 'authorization_code',
        code_verifier: codeVerifier,
      }).toString(),
    });
    if (!response.ok) {
      throw new GoogleTokenExchangeError(
        `google token endpoint returned ${response.status}`,
      );
    }
    const body = (await response.json()) as { id_token?: string };
    if (!body.id_token) {
      throw new GoogleTokenExchangeError(
        'google token response missing id_token',
      );
    }
    return body.id_token;
  }
}
