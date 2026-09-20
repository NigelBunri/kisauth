import {
  Controller,
  Get,
  Query,
  Req,
  Res,
  BadRequestException,
  HttpException,
  HttpStatus,
} from '@nestjs/common';
import type { FastifyReply, FastifyRequest } from 'fastify';
import { loadConfig } from '../config/env';
import { ClientService } from '../clients/client.service';
import { IdentityService } from '../identity/identity.service';
import { ChallengeStore, type Purpose } from '../redis/challenge-store';
import { OAuthSessionStore } from './oauth-session.store';
import { GoogleTokenExchangeService } from './google-token-exchange.service';
import {
  GoogleIdTokenService,
  GoogleIdTokenVerificationError,
} from './google-id-token.service';
import {
  generateState,
  generateNonce,
  generateCodeVerifier,
  codeChallengeS256,
} from './pkce';
import { parseCookieHeader, serializeSessionCookie } from '../http/cookies';
import { RateLimiter } from '../security/rate-limit';
import { RATE_LIMITS, RATE_LIMIT_ERROR } from '../security/rate-limit-policy';
import { SecurityEventService } from '../security/security-event.service';
import { LinkTicketService } from '../security/link-ticket';
import { OAuthOutcomeService } from './oauth-outcome.service';
import { statusRedirectUrl } from './status-redirect';

const SESSION_COOKIE = 'kisauth_session';
const GENERIC_ERROR = 'We could not complete this authentication request.';

// Same shape as a client_id/redirect_uri — loose enough for a real slug
// (letters, digits, hyphens), tight enough that it can never smuggle a
// path segment, query string, or anything else into the redirect this
// value later drives (/oauth/enterprise/<slug>/start). Existence/config
// validity is checked separately, against Django, in that route.
const PARTNER_SLUG_PATTERN = /^[a-z0-9-]{1,64}$/;

@Controller()
export class OAuthController {
  constructor(
    private readonly clients: ClientService,
    private readonly identities: IdentityService,
    private readonly challenges: ChallengeStore,
    private readonly sessions: OAuthSessionStore,
    private readonly googleTokenExchange: GoogleTokenExchangeService,
    private readonly googleIdToken: GoogleIdTokenService,
    private readonly rateLimiter: RateLimiter,
    private readonly securityEvents: SecurityEventService,
    private readonly linkTickets: LinkTicketService,
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

  @Get('authorize')
  async authorize(
    @Query('client_id') clientId: string,
    @Query('redirect_uri') redirectUri: string,
    @Query('purpose') purpose: string,
    @Query('state') clientState: string,
    @Query('link_ticket') linkTicket: string | undefined,
    // Enterprise OIDC bridge entry point: when present, this is a login
    // against a specific tenant's IdP rather than Google, and /authorize
    // redirects into /oauth/enterprise/:partnerSlug/start instead of
    // /oauth/google/start once every check below (client/redirect_uri/
    // purpose/link_ticket) has passed — identically to the Google path.
    @Query('partner_slug') partnerSlug: string | undefined,
    @Req() req: FastifyRequest,
    @Res({ passthrough: true }) res: FastifyReply,
  ) {
    await this.enforceRateLimit(req, RATE_LIMITS.AUTHORIZE);

    const client = await this.clients.findByClientId(clientId ?? '');
    if (
      !client ||
      !this.clients.isRedirectUriAllowed(client, redirectUri ?? '')
    ) {
      // Deliberately identical error for "unknown client" and "wrong
      // redirect_uri" — distinguishing them would help an attacker probe
      // the registry.
      throw new BadRequestException(GENERIC_ERROR);
    }
    if (!this.clients.isPurposeAllowed(client, purpose as Purpose)) {
      throw new BadRequestException(GENERIC_ERROR);
    }
    if (!clientState) {
      throw new BadRequestException(GENERIC_ERROR);
    }
    if (partnerSlug !== undefined && !PARTNER_SLUG_PATTERN.test(partnerSlug)) {
      throw new BadRequestException(GENERIC_ERROR);
    }

    // purpose='link' requires proof — minted by Django, for an already-
    // authenticated KIS user — that THIS KIS account is the one being
    // linked. Without this, an unauthenticated caller could pass an
    // arbitrary kis_user_id and link their own identity to someone else's
    // account. See LinkTicketService for the single-use + expiry
    // guarantees.
    let linkKisUserId: string | undefined;
    if (purpose === 'link') {
      if (!linkTicket) {
        throw new BadRequestException(GENERIC_ERROR);
      }
      const config = loadConfig();
      const verified = await this.linkTickets.verifyAndConsume(
        linkTicket,
        config.internalHmacSecret,
      );
      if (!verified.ok) {
        void this.securityEvents.emit({
          eventType: 'link.failed',
          outcome: 'failure',
          clientId,
          reason: `link_ticket_${verified.reason}`,
          ip: req.ip,
        });
        throw new BadRequestException(GENERIC_ERROR);
      }
      linkKisUserId = verified.kisUserId;
    }

    const sessionId = await this.sessions.create({
      clientId,
      redirectUri,
      purpose: purpose as Purpose,
      state: generateState(),
      nonce: generateNonce(),
      clientState,
      ...(linkKisUserId ? { linkKisUserId } : {}),
      ...(partnerSlug ? { partnerSlug } : {}),
    });

    res.header(
      'set-cookie',
      serializeSessionCookie(SESSION_COOKIE, sessionId, {
        secure: loadConfig().nodeEnv === 'production',
        maxAgeSeconds: 600,
      }),
    );
    return res.redirect(
      partnerSlug
        ? `/oauth/enterprise/${encodeURIComponent(partnerSlug)}/start`
        : '/oauth/google/start',
      303,
    );
  }

  @Get('oauth/google/start')
  async start(
    @Req() req: FastifyRequest,
    @Res({ passthrough: true }) res: FastifyReply,
  ) {
    await this.enforceRateLimit(req, RATE_LIMITS.OAUTH_GOOGLE_START);

    const sessionId = parseCookieHeader(req.headers.cookie)[SESSION_COOKIE];
    const session = sessionId ? await this.sessions.get(sessionId) : null;
    if (!session || !sessionId) throw new BadRequestException(GENERIC_ERROR);

    const config = loadConfig();
    const codeVerifier = generateCodeVerifier();
    // PKCE verifier is attached to the server-side session IN PLACE (same
    // session id, same cookie) — Google only ever sees the derived S256
    // challenge; the verifier itself never touches the browser.
    await this.sessions.update(sessionId, { ...session, codeVerifier });

    const url = new URL('https://accounts.google.com/o/oauth2/v2/auth');
    url.searchParams.set('client_id', config.googleClientId);
    url.searchParams.set('redirect_uri', config.googleRedirectUri);
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('scope', 'openid email profile');
    url.searchParams.set('state', session.state);
    url.searchParams.set('nonce', session.nonce);
    url.searchParams.set('code_challenge', codeChallengeS256(codeVerifier));
    url.searchParams.set('code_challenge_method', 'S256');
    return res.redirect(url.toString(), 303);
  }

  @Get('oauth/google/callback')
  async callback(
    @Query('code') code: string,
    @Query('state') state: string,
    @Query('error') error: string | undefined,
    @Req() req: FastifyRequest,
    @Res({ passthrough: true }) res: FastifyReply,
  ) {
    await this.enforceRateLimit(req, RATE_LIMITS.OAUTH_GOOGLE_CALLBACK);

    const sessionId = parseCookieHeader(req.headers.cookie)[SESSION_COOKIE];
    const session = sessionId ? await this.sessions.get(sessionId) : null;

    // The user declining Google's consent screen is a normal, expected
    // outcome — not a technical failure. Google still sends its own
    // `state`, which we DO still check against the session, so this
    // can't be used to spray a redirect at an attacker-chosen target;
    // the redirect_uri always comes from OUR stored session, never from
    // the request. Surfaced as a distinct `error=access_denied` on the
    // client's own redirect_uri (standard OAuth convention) rather than
    // GENERIC_ERROR, so the app can show "you cancelled" instead of a
    // scary technical message.
    if (error) {
      if (session && state === session.state) {
        await this.sessions.delete(sessionId!);
        void this.securityEvents.emit({
          eventType: 'oauth.cancelled',
          outcome: 'failure',
          clientId: session.clientId,
          reason: error,
          ip: req.ip,
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
      // No valid session to redirect through safely — same generic
      // response as every other "can't proceed" case.
      throw new BadRequestException(GENERIC_ERROR);
    }

    if (
      !session ||
      !code ||
      !state ||
      state !== session.state ||
      !session.codeVerifier
    ) {
      throw new BadRequestException(GENERIC_ERROR);
    }

    let googleIdentity;
    try {
      const idToken = await this.googleTokenExchange.exchangeCodeForIdToken(
        code,
        session.codeVerifier,
      );
      googleIdentity = await this.googleIdToken.verify(idToken, session.nonce);
    } catch (err) {
      void this.securityEvents.emit({
        eventType: 'oauth.callback_failed',
        outcome: 'failure',
        clientId: session.clientId,
        reason:
          err instanceof GoogleIdTokenVerificationError
            ? 'id_token_verification_failed'
            : 'token_exchange_failed',
        ip: req.ip,
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

    // purpose='link' never does a find-by-subject lookup first — the
    // database's own (provider, provider_subject) and kis_user_id unique
    // constraints ARE the "already linked" check, surfaced as a typed
    // result rather than raced against with a separate SELECT.
    if (session.purpose === 'link') {
      return this.outcome.finalizeLink({
        provider: 'google',
        verifiedIdentity: googleIdentity,
        session,
        sessionId: sessionId!,
        req,
        res,
      });
    }

    const identity = await this.identities.findByProviderSubject(
      'google',
      googleIdentity.sub,
    );

    if (session.purpose === 'registration') {
      return this.outcome.finalizeRegistration({
        provider: 'google',
        verifiedIdentity: googleIdentity,
        identity,
        session,
        sessionId: sessionId!,
        req,
        res,
        registrationPurpose: 'registration',
      });
    }

    // Everything below is the original recovery behavior — unchanged.
    return this.outcome.finalizeReturningUser({
      provider: 'google',
      providerSubject: googleIdentity.sub,
      identity,
      session,
      sessionId: sessionId!,
      req,
      res,
    });
  }
}
