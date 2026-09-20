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
import { randomUUID } from 'crypto';
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

const SESSION_COOKIE = 'kisauth_session';
const GENERIC_ERROR = 'We could not complete this authentication request.';

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
  ) {}

  /** Every terminal outcome (success or failure) routes through kis-auth's
   * own /status page rather than redirecting straight to the client's
   * redirect_uri — this is what lets the user see a clear "what just
   * happened" message instead of either a raw JSON blob or a silent
   * hand-off to a universal link that may not be verified on their
   * device. The page itself auto-refreshes to clientTarget (already
   * carrying code/error+state) after a couple seconds, with a manual
   * button as the fallback that never depends on JavaScript. */
  private statusRedirectUrl(state: string, clientTarget: string): string {
    const url = new URL('/status', loadConfig().baseUrl);
    url.searchParams.set('state', state);
    url.searchParams.set('client_redirect', clientTarget);
    return url.toString();
  }

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

    // purpose='link' requires proof — minted by Django, for an already-
    // authenticated KIS user — that THIS KIS account is the one being
    // linked. Without this, an unauthenticated caller could pass an
    // arbitrary kis_user_id and link their own Google identity to
    // someone else's account. See LinkTicketService for the single-use
    // + expiry guarantees.
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
    });

    res.header(
      'set-cookie',
      serializeSessionCookie(SESSION_COOKIE, sessionId, {
        secure: loadConfig().nodeEnv === 'production',
        maxAgeSeconds: 600,
      }),
    );
    return res.redirect('/oauth/google/start', 303);
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
          this.statusRedirectUrl('cancelled', target.toString()),
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
        this.statusRedirectUrl('invalid_request', target.toString()),
        303,
      );
    }

    // purpose='link' never does a find-by-subject lookup first — the
    // database's own (provider, provider_subject) and kis_user_id unique
    // constraints ARE the "already linked" check, surfaced as a typed
    // result rather than raced against with a separate SELECT.
    if (session.purpose === 'link') {
      return this.handleLinkCallback(googleIdentity, session, sessionId!, req, res);
    }

    const identity = await this.identities.findByProviderSubject(
      'google',
      googleIdentity.sub,
    );

    if (session.purpose === 'registration') {
      return this.handleRegistrationCallback(
        googleIdentity,
        identity,
        session,
        sessionId!,
        req,
        res,
      );
    }

    // Everything below is the original recovery behavior — unchanged.
    if (!identity) {
      // Explicit link-or-create — never silently linked. Routed through
      // /status rather than returned as raw JSON: Linking.openURL (the
      // mobile app's entry mechanism) is a full browser navigation, not
      // a fetch — a bare JSON body would just render as unstyled text
      // with no way back into the app.
      await this.sessions.delete(sessionId!);
      void this.securityEvents.emit({
        eventType: 'oauth.identity_not_linked',
        outcome: 'failure',
        clientId: session.clientId,
        ip: req.ip,
      });
      const target = new URL(session.redirectUri);
      target.searchParams.set('error', 'not_linked');
      target.searchParams.set('provider_subject', googleIdentity.sub);
      target.searchParams.set('state', session.clientState);
      return res.redirect(
        this.statusRedirectUrl('not_linked', target.toString()),
        303,
      );
    }

    await this.identities.touchLastAuthenticated(identity.id);
    void this.securityEvents.emit({
      eventType: 'oauth.callback_succeeded',
      outcome: 'success',
      kisUserId: identity.kisUserId,
      clientId: session.clientId,
      ip: req.ip,
      metadata: { purpose: session.purpose },
    });

    const challengeId = randomUUID();
    await this.challenges.createChallenge(
      challengeId,
      {
        purpose: session.purpose,
        clientId: session.clientId,
        kisUserId: identity.kisUserId,
        authIdentityId: identity.id,
        attemptCount: 0,
        maxAttempts: loadConfig().challengeMaxAttempts,
        used: false,
      },
      loadConfig().challengeTtlSeconds,
    );

    await this.sessions.delete(sessionId!);

    // Phase B ships without a manual fallback code (Phase 2 open question
    // #2) — Google-authenticated proof is already the primary mechanism,
    // so the challenge is confirmed immediately rather than making the
    // user additionally copy a 6-digit code. The challenge_id is still
    // minted and attempt-tracked so the confirm step below stays a real,
    // independently testable seam rather than being inlined away.
    return this.confirmInternal(
      challengeId,
      session.redirectUri,
      session.clientState,
      res,
      'recovery_success',
    );
  }

  /** purpose='link': attach googleIdentity to session.linkKisUserId (set
   * at /authorize from a Django-signed, already-consumed link ticket —
   * never trusted from this request). On success, issues a normal
   * authorization code through the exact same challenge/confirm path
   * recovery uses, so Django's existing exchange endpoint needs no
   * changes to redeem it. */
  private async handleLinkCallback(
    googleIdentity: { sub: string; email: string | null; emailVerified: boolean },
    session: NonNullable<Awaited<ReturnType<OAuthSessionStore['get']>>>,
    sessionId: string,
    req: FastifyRequest,
    res: FastifyReply,
  ) {
    const kisUserId = session.linkKisUserId;
    if (!kisUserId) {
      // Should be unreachable — /authorize refuses to create a
      // purpose='link' session without a verified ticket. Fail closed.
      await this.sessions.delete(sessionId);
      throw new BadRequestException(GENERIC_ERROR);
    }

    const result = await this.identities.link({
      provider: 'google',
      providerSubject: googleIdentity.sub,
      kisUserId,
      providerEmail: googleIdentity.email,
      providerEmailVerified: googleIdentity.emailVerified,
    });

    await this.sessions.delete(sessionId);

    if (!result.ok) {
      void this.securityEvents.emit({
        eventType: 'link.already_linked',
        outcome: 'failure',
        kisUserId,
        clientId: session.clientId,
        ip: req.ip,
      });
      const target = new URL(session.redirectUri);
      target.searchParams.set('error', 'already_linked');
      target.searchParams.set('state', session.clientState);
      return res.redirect(
        this.statusRedirectUrl('already_linked', target.toString()),
        303,
      );
    }

    void this.securityEvents.emit({
      eventType: 'link.succeeded',
      outcome: 'success',
      kisUserId,
      clientId: session.clientId,
      ip: req.ip,
    });

    const challengeId = randomUUID();
    await this.challenges.createChallenge(
      challengeId,
      {
        purpose: 'link',
        clientId: session.clientId,
        kisUserId,
        authIdentityId: result.identity.id,
        attemptCount: 0,
        maxAttempts: loadConfig().challengeMaxAttempts,
        used: false,
      },
      loadConfig().challengeTtlSeconds,
    );

    return this.confirmInternal(
      challengeId,
      session.redirectUri,
      session.clientState,
      res,
      'success',
    );
  }

  /** purpose='registration': an existing identity match means this Google
   * account is already registered — redirect with a distinct error so the
   * app can offer sign-in/recovery instead of silently creating a second
   * account. No match is the expected success case: issue a short-lived
   * registration ticket (no kis_user_id exists yet) for Django to redeem
   * via the separate /internal/v1/registration/exchange endpoint. */
  private async handleRegistrationCallback(
    googleIdentity: { sub: string; email: string | null; emailVerified: boolean },
    identity: { kisUserId: string } | null,
    session: NonNullable<Awaited<ReturnType<OAuthSessionStore['get']>>>,
    sessionId: string,
    req: FastifyRequest,
    res: FastifyReply,
  ) {
    await this.sessions.delete(sessionId);

    if (identity) {
      void this.securityEvents.emit({
        eventType: 'registration.already_registered',
        outcome: 'failure',
        kisUserId: identity.kisUserId,
        clientId: session.clientId,
        ip: req.ip,
      });
      const target = new URL(session.redirectUri);
      target.searchParams.set('error', 'already_registered');
      target.searchParams.set('state', session.clientState);
      return res.redirect(
        this.statusRedirectUrl('already_registered', target.toString()),
        303,
      );
    }

    const ticket = await this.challenges.issueRegistrationTicket(
      {
        clientId: session.clientId,
        provider: 'google',
        providerSubject: googleIdentity.sub,
        providerEmail: googleIdentity.email,
        providerEmailVerified: googleIdentity.emailVerified,
        redirectUri: session.redirectUri,
      },
      loadConfig().authCodeTtlSeconds,
    );

    void this.securityEvents.emit({
      eventType: 'registration.ticket_issued',
      outcome: 'success',
      clientId: session.clientId,
      ip: req.ip,
    });

    const target = new URL(session.redirectUri);
    target.searchParams.set('code', ticket);
    target.searchParams.set('state', session.clientState);
    return res.redirect(
      this.statusRedirectUrl('registration_continue', target.toString()),
      303,
    );
  }

  // Deliberately no public /challenge/confirm route. An earlier draft of
  // this file exposed one that took redirect_uri straight from a query
  // param with no validation against the client's registered URIs — an
  // open-redirect-plus-code-injection bug (the redirect target and the
  // authorization code would both be attacker-directed). Phase B's flow
  // never needs a standalone confirm step — the callback above calls
  // confirmInternal() directly, using ONLY the redirect_uri and
  // clientState from the server-side session that /authorize already
  // validated against the client registry. If Phase D ever needs a real
  // multi-step challenge (e.g. a manual code entry screen between Google
  // auth and confirmation), add it as a POST bound to that same signed
  // session — never a bare GET trusting caller-supplied redirect state.

  private async confirmInternal(
    challengeId: string,
    redirectUri: string,
    clientState: string,
    res: FastifyReply,
    successState: string,
  ) {
    const record = await this.challenges.getChallenge(challengeId);
    if (!record || record.used || !record.kisUserId || !record.authIdentityId) {
      throw new BadRequestException(GENERIC_ERROR);
    }
    if (record.attemptCount >= record.maxAttempts) {
      throw new BadRequestException(GENERIC_ERROR);
    }

    await this.challenges.markChallengeUsed(challengeId);
    const authCode = await this.challenges.issueAuthorizationCode(
      {
        purpose: record.purpose,
        clientId: record.clientId,
        kisUserId: record.kisUserId,
        authIdentityId: record.authIdentityId,
        redirectUri,
      },
      loadConfig().authCodeTtlSeconds,
    );

    const target = new URL(redirectUri);
    target.searchParams.set('code', authCode);
    target.searchParams.set('state', clientState);
    return res.redirect(this.statusRedirectUrl(successState, target.toString()), 303);
  }
}
