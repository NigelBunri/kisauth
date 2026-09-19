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

    const sessionId = await this.sessions.create({
      clientId,
      redirectUri,
      purpose: purpose as Purpose,
      state: generateState(),
      nonce: generateNonce(),
      clientState,
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
        return res.redirect(target.toString(), 303);
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
      throw new BadRequestException(GENERIC_ERROR);
    }

    const identity = await this.identities.findByProviderSubject(
      'google',
      googleIdentity.sub,
    );
    if (!identity) {
      // Explicit link-or-create — never silently linked. The frontend
      // renders this as its own screen; the backend contract is just
      // "not linked yet" plus enough context to start that flow.
      await this.sessions.delete(sessionId!);
      void this.securityEvents.emit({
        eventType: 'oauth.identity_not_linked',
        outcome: 'failure',
        clientId: session.clientId,
        ip: req.ip,
      });
      return { status: 'not_linked', providerSubject: googleIdentity.sub };
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
    return res.redirect(target.toString(), 303);
  }
}
