import {
  Controller,
  Get,
  Param,
  Query,
  Req,
  Res,
  BadRequestException,
  HttpException,
  HttpStatus,
} from '@nestjs/common';
import type { FastifyReply, FastifyRequest } from 'fastify';
import { loadConfig } from '../config/env';
import { IdentityService } from '../identity/identity.service';
import { OAuthSessionStore } from './oauth-session.store';
import { generateCodeVerifier, codeChallengeS256 } from './pkce';
import { parseCookieHeader } from '../http/cookies';
import { RateLimiter } from '../security/rate-limit';
import { RATE_LIMITS, RATE_LIMIT_ERROR } from '../security/rate-limit-policy';
import { SecurityEventService } from '../security/security-event.service';
import { OAuthOutcomeService } from './oauth-outcome.service';
import { statusRedirectUrl } from './status-redirect';
import {
  OidcProviderResolverService,
  type OidcPartnerConfig,
} from './oidc-provider-resolver.service';
import { OidcDiscoveryService } from './oidc-discovery.service';
import { OidcTokenExchangeService } from './oidc-token-exchange.service';
import {
  OidcIdTokenService,
  OidcIdTokenVerificationError,
} from './oidc-id-token.service';
import { OIDC_PROVIDER, compositeOidcSubject } from './oidc-identity-key';

const SESSION_COOKIE = 'kisauth_session';
const GENERIC_ERROR = 'We could not complete this authentication request.';

/** Generic OIDC bridge for enterprise IdPs (Okta, Azure AD/Entra ID,
 * Google Workspace, etc.) — the same PKCE + state/nonce authorization-code
 * flow oauth.controller.ts already runs for Google, extended to a
 * per-tenant issuer/JWKS/client resolved from Django rather than one
 * fixed configuration. Kept as a sibling controller (not folded into
 * oauth.controller.ts) purely to keep that file's size from growing
 * unboundedly — every piece of shared logic (session store, PKCE,
 * rate-limit/security-event primitives, and the link/registration/
 * recovery outcome semantics in OAuthOutcomeService) is reused verbatim,
 * not reimplemented. */
@Controller('oauth/enterprise/:partnerSlug')
export class OidcEnterpriseController {
  constructor(
    private readonly identities: IdentityService,
    private readonly sessions: OAuthSessionStore,
    private readonly resolver: OidcProviderResolverService,
    private readonly discovery: OidcDiscoveryService,
    private readonly oidcTokenExchange: OidcTokenExchangeService,
    private readonly oidcIdToken: OidcIdTokenService,
    private readonly rateLimiter: RateLimiter,
    private readonly securityEvents: SecurityEventService,
    private readonly outcome: OAuthOutcomeService,
  ) {}

  private async enforceRateLimit(
    req: FastifyRequest,
    policy: { scope: string; limit: number; windowSeconds: number },
  ): Promise<void> {
    const result = await this.rateLimiter.check(
      policy.scope,
      req.ip,
      policy.limit,
      policy.windowSeconds,
    );
    if (!result.allowed) {
      throw new HttpException(RATE_LIMIT_ERROR, HttpStatus.TOO_MANY_REQUESTS);
    }
  }

  /** The redirect_uri registered on the tenant's IdP application must be
   * exactly this — stable per partner, never influenced by anything in
   * the request, so it can be configured once on the IdP side and never
   * needs to change. */
  private enterpriseRedirectUri(partnerSlug: string): string {
    return new URL(
      `/oauth/enterprise/${encodeURIComponent(partnerSlug)}/callback`,
      loadConfig().baseUrl,
    ).toString();
  }

  private async resolveOrFail(
    partnerSlug: string,
    session: { clientId: string },
    sessionId: string,
    req: FastifyRequest,
  ): Promise<OidcPartnerConfig> {
    const resolved = await this.resolver.resolve(partnerSlug);
    if (!resolved.ok) {
      void this.securityEvents.emit({
        eventType: 'oauth.enterprise_config_failed',
        outcome: 'failure',
        clientId: session.clientId,
        reason: `sso_config_${resolved.reason}`,
        ip: req.ip,
        metadata: { provider: OIDC_PROVIDER, partner_slug: partnerSlug },
      });
      await this.sessions.delete(sessionId);
      throw new BadRequestException(GENERIC_ERROR);
    }
    return resolved.config;
  }

  @Get('start')
  async start(
    @Param('partnerSlug') partnerSlug: string,
    @Req() req: FastifyRequest,
    @Res({ passthrough: true }) res: FastifyReply,
  ) {
    await this.enforceRateLimit(req, RATE_LIMITS.OAUTH_ENTERPRISE_START);

    const sessionId = parseCookieHeader(req.headers.cookie)[SESSION_COOKIE];
    const session = sessionId ? await this.sessions.get(sessionId) : null;
    // The session must exist (created by /authorize), and must have been
    // created FOR this exact partner — a session minted for tenant A can
    // never be walked over to tenant B's start/callback URLs.
    if (!session || !sessionId || session.partnerSlug !== partnerSlug) {
      throw new BadRequestException(GENERIC_ERROR);
    }

    const partnerConfig = await this.resolveOrFail(
      partnerSlug,
      session,
      sessionId,
      req,
    );

    let discoveryDoc;
    try {
      discoveryDoc = await this.discovery.fetchDiscovery(
        partnerConfig.discoveryUrl,
      );
    } catch {
      void this.securityEvents.emit({
        eventType: 'oauth.enterprise_config_failed',
        outcome: 'failure',
        clientId: session.clientId,
        reason: 'discovery_failed',
        ip: req.ip,
        metadata: { provider: OIDC_PROVIDER, partner_slug: partnerSlug },
      });
      await this.sessions.delete(sessionId);
      throw new BadRequestException(GENERIC_ERROR);
    }

    const codeVerifier = generateCodeVerifier();
    // PKCE verifier is attached to the server-side session IN PLACE (same
    // session id, same cookie) — the IdP only ever sees the derived S256
    // challenge; the verifier itself never touches the browser. Identical
    // pattern to oauth/google/start.
    await this.sessions.update(sessionId, { ...session, codeVerifier });

    const url = new URL(discoveryDoc.authorizationEndpoint);
    url.searchParams.set('client_id', partnerConfig.clientId);
    url.searchParams.set(
      'redirect_uri',
      this.enterpriseRedirectUri(partnerSlug),
    );
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('scope', 'openid email profile');
    url.searchParams.set('state', session.state);
    url.searchParams.set('nonce', session.nonce);
    url.searchParams.set('code_challenge', codeChallengeS256(codeVerifier));
    url.searchParams.set('code_challenge_method', 'S256');
    return res.redirect(url.toString(), 303);
  }

  @Get('callback')
  async callback(
    @Param('partnerSlug') partnerSlug: string,
    @Query('code') code: string,
    @Query('state') state: string,
    @Query('error') error: string | undefined,
    @Req() req: FastifyRequest,
    @Res({ passthrough: true }) res: FastifyReply,
  ) {
    await this.enforceRateLimit(req, RATE_LIMITS.OAUTH_ENTERPRISE_CALLBACK);

    const sessionId = parseCookieHeader(req.headers.cookie)[SESSION_COOKIE];
    const session = sessionId ? await this.sessions.get(sessionId) : null;

    // Same "user declined consent" handling as the Google callback — a
    // normal, expected outcome, surfaced as error=access_denied on the
    // client's own redirect_uri rather than the generic message.
    if (error) {
      if (
        session &&
        session.partnerSlug === partnerSlug &&
        state === session.state
      ) {
        await this.sessions.delete(sessionId!);
        void this.securityEvents.emit({
          eventType: 'oauth.cancelled',
          outcome: 'failure',
          clientId: session.clientId,
          reason: error,
          ip: req.ip,
          metadata: { provider: OIDC_PROVIDER, partner_slug: partnerSlug },
        });
        const target = new URL(session.redirectUri);
        target.searchParams.set(
          'error',
          error === 'access_denied' ? 'access_denied' : 'authentication_failed',
        );
        target.searchParams.set('state', session.clientState);
        return res.redirect(
          statusRedirectUrl('cancelled', target.toString()),
          303,
        );
      }
      throw new BadRequestException(GENERIC_ERROR);
    }

    if (
      !session ||
      !code ||
      !state ||
      state !== session.state ||
      !session.codeVerifier ||
      session.partnerSlug !== partnerSlug
    ) {
      throw new BadRequestException(GENERIC_ERROR);
    }

    const partnerConfig = await this.resolveOrFail(
      partnerSlug,
      session,
      sessionId!,
      req,
    );

    let discoveryDoc;
    try {
      discoveryDoc = await this.discovery.fetchDiscovery(
        partnerConfig.discoveryUrl,
      );
    } catch {
      void this.securityEvents.emit({
        eventType: 'oauth.enterprise_config_failed',
        outcome: 'failure',
        clientId: session.clientId,
        reason: 'discovery_failed',
        ip: req.ip,
        metadata: { provider: OIDC_PROVIDER, partner_slug: partnerSlug },
      });
      await this.sessions.delete(sessionId!);
      throw new BadRequestException(GENERIC_ERROR);
    }

    let verified;
    try {
      const idToken = await this.oidcTokenExchange.exchangeCodeForIdToken({
        tokenEndpoint: discoveryDoc.tokenEndpoint,
        code,
        codeVerifier: session.codeVerifier,
        clientId: partnerConfig.clientId,
        clientSecret: partnerConfig.clientSecret,
        redirectUri: this.enterpriseRedirectUri(partnerSlug),
      });
      verified = await this.oidcIdToken.verify({
        idToken,
        jwksUri: discoveryDoc.jwksUri,
        issuer: partnerConfig.issuer,
        audience: partnerConfig.clientId,
        expectedNonce: session.nonce,
      });
    } catch (err) {
      void this.securityEvents.emit({
        eventType: 'oauth.callback_failed',
        outcome: 'failure',
        clientId: session.clientId,
        reason:
          err instanceof OidcIdTokenVerificationError
            ? 'id_token_verification_failed'
            : 'token_exchange_failed',
        ip: req.ip,
        metadata: { provider: OIDC_PROVIDER, partner_slug: partnerSlug },
      });
      await this.sessions.delete(sessionId!);
      const target = new URL(session.redirectUri);
      target.searchParams.set('error', 'authentication_failed');
      target.searchParams.set('state', session.clientState);
      return res.redirect(
        statusRedirectUrl('invalid_request', target.toString()),
        303,
      );
    }

    // Composite provider_subject — see oidc-identity-key.ts for why this,
    // not a "oidc:<slug>" provider column value, is the actual tenant-
    // disambiguation mechanism (Django's link_identity_server_to_server
    // forwards `provider` verbatim as the literal "oidc" for every
    // tenant, so the provider column alone can't disambiguate).
    const providerSubject = compositeOidcSubject(partnerSlug, verified.sub);
    const verifiedIdentity = {
      sub: providerSubject,
      email: verified.email,
      emailVerified: verified.emailVerified,
    };

    if (session.purpose === 'link') {
      return this.outcome.finalizeLink({
        provider: OIDC_PROVIDER,
        verifiedIdentity,
        session,
        sessionId: sessionId!,
        req,
        res,
      });
    }

    const identity = await this.identities.findByProviderSubject(
      OIDC_PROVIDER,
      providerSubject,
    );

    if (session.purpose === 'registration') {
      return this.outcome.finalizeRegistration({
        provider: OIDC_PROVIDER,
        verifiedIdentity,
        identity,
        session,
        sessionId: sessionId!,
        req,
        res,
        registrationPurpose: 'enterprise_sso_registration',
        partnerSlug,
      });
    }

    return this.outcome.finalizeReturningUser({
      provider: OIDC_PROVIDER,
      providerSubject,
      identity,
      session,
      sessionId: sessionId!,
      req,
      res,
    });
  }
}
