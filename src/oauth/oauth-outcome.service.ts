import { randomUUID } from 'crypto';
import { Injectable, BadRequestException } from '@nestjs/common';
import type { FastifyReply, FastifyRequest } from 'fastify';
import { loadConfig } from '../config/env';
import { IdentityService } from '../identity/identity.service';
import { ChallengeStore, type Purpose } from '../redis/challenge-store';
import { OAuthSessionStore, type OAuthSession } from './oauth-session.store';
import { SecurityEventService } from '../security/security-event.service';
import { statusRedirectUrl } from './status-redirect';

const GENERIC_ERROR = 'We could not complete this authentication request.';

export interface VerifiedProviderIdentity {
  sub: string;
  email: string | null;
  emailVerified: boolean;
}

/** Shared outcome logic for every provider's OAuth/OIDC callback, once an
 * IdP's identity has been verified — extracted from what was originally
 * private methods on OAuthController (Google-only) so the enterprise OIDC
 * bridge (oidc-enterprise.controller.ts) reuses the EXACT SAME
 * link/registration/recovery semantics — single-use challenge issuance,
 * already-linked/already-registered/not-linked handling, security event
 * emission — rather than a second, parallel implementation. Google's own
 * callback path was refactored to call through this service too; its
 * behavior is unchanged (see app-recovery-flow.spec.ts and
 * app-security-hardening.spec.ts, which cover it end-to-end and were not
 * modified by this refactor). */
@Injectable()
export class OAuthOutcomeService {
  constructor(
    private readonly identities: IdentityService,
    private readonly challenges: ChallengeStore,
    private readonly sessions: OAuthSessionStore,
    private readonly securityEvents: SecurityEventService,
  ) {}

  /** purpose='link': attach verifiedIdentity to session.linkKisUserId (set
   * at /authorize from a Django-signed, already-consumed link ticket —
   * never trusted from this request). On success, issues a normal
   * authorization code through the exact same challenge/confirm path
   * recovery uses, so Django's existing exchange endpoint needs no
   * changes to redeem it. */
  async finalizeLink(args: {
    provider: string;
    verifiedIdentity: VerifiedProviderIdentity;
    session: OAuthSession;
    sessionId: string;
    req: FastifyRequest;
    res: FastifyReply;
  }) {
    const { provider, verifiedIdentity, session, sessionId, req, res } = args;
    const kisUserId = session.linkKisUserId;
    if (!kisUserId) {
      // Should be unreachable — /authorize refuses to create a
      // purpose='link' session without a verified ticket. Fail closed.
      await this.sessions.delete(sessionId);
      throw new BadRequestException(GENERIC_ERROR);
    }

    const result = await this.identities.link({
      provider,
      providerSubject: verifiedIdentity.sub,
      kisUserId,
      providerEmail: verifiedIdentity.email,
      providerEmailVerified: verifiedIdentity.emailVerified,
    });

    await this.sessions.delete(sessionId);

    if (!result.ok) {
      void this.securityEvents.emit({
        eventType: 'link.already_linked',
        outcome: 'failure',
        kisUserId,
        clientId: session.clientId,
        ip: req.ip,
        metadata: { provider },
      });
      const target = new URL(session.redirectUri);
      target.searchParams.set('error', 'already_linked');
      target.searchParams.set('state', session.clientState);
      return res.redirect(
        statusRedirectUrl('already_linked', target.toString()),
        303,
      );
    }

    void this.securityEvents.emit({
      eventType: 'link.succeeded',
      outcome: 'success',
      kisUserId,
      clientId: session.clientId,
      ip: req.ip,
      metadata: { provider },
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

    return this.confirmAndRedirect(
      challengeId,
      session.redirectUri,
      session.clientState,
      res,
      'success',
    );
  }

  /** purpose='registration' (or its enterprise-SSO variant): an existing
   * identity match means this IdP account is already registered — redirect
   * with a distinct error so the app can offer sign-in/recovery instead of
   * silently creating a second account. No match is the expected success
   * case: issue a short-lived registration ticket (no kis_user_id exists
   * yet) for Django to redeem via /internal/v1/registration/exchange. */
  async finalizeRegistration(args: {
    provider: string;
    verifiedIdentity: VerifiedProviderIdentity;
    identity: { kisUserId: string } | null;
    session: OAuthSession;
    sessionId: string;
    req: FastifyRequest;
    res: FastifyReply;
    registrationPurpose: Purpose;
    partnerSlug?: string;
  }) {
    const {
      provider,
      verifiedIdentity,
      identity,
      session,
      sessionId,
      req,
      res,
      registrationPurpose,
      partnerSlug,
    } = args;
    await this.sessions.delete(sessionId);

    if (identity) {
      void this.securityEvents.emit({
        eventType: 'registration.already_registered',
        outcome: 'failure',
        kisUserId: identity.kisUserId,
        clientId: session.clientId,
        ip: req.ip,
        metadata: { provider, partner_slug: partnerSlug ?? null },
      });
      const target = new URL(session.redirectUri);
      target.searchParams.set('error', 'already_registered');
      target.searchParams.set('state', session.clientState);
      return res.redirect(
        statusRedirectUrl('already_registered', target.toString()),
        303,
      );
    }

    const ticket = await this.challenges.issueRegistrationTicket(
      {
        clientId: session.clientId,
        purpose: registrationPurpose,
        provider,
        providerSubject: verifiedIdentity.sub,
        providerEmail: verifiedIdentity.email,
        providerEmailVerified: verifiedIdentity.emailVerified,
        partnerSlug: partnerSlug ?? null,
        redirectUri: session.redirectUri,
      },
      loadConfig().authCodeTtlSeconds,
    );

    void this.securityEvents.emit({
      eventType: 'registration.ticket_issued',
      outcome: 'success',
      clientId: session.clientId,
      ip: req.ip,
      metadata: { provider, partner_slug: partnerSlug ?? null },
    });

    const target = new URL(session.redirectUri);
    target.searchParams.set('code', ticket);
    target.searchParams.set('state', session.clientState);
    return res.redirect(
      statusRedirectUrl('registration_continue', target.toString()),
      303,
    );
  }

  /** Every other purpose (recovery, device_verify, sensitive_change, ...):
   * an existing identity is required — there is no implicit link-or-create
   * here, unlike registration. */
  async finalizeReturningUser(args: {
    provider: string;
    providerSubject: string;
    identity: { id: string; kisUserId: string } | null;
    session: OAuthSession;
    sessionId: string;
    req: FastifyRequest;
    res: FastifyReply;
  }) {
    const { providerSubject, identity, session, sessionId, req, res } = args;

    if (!identity) {
      // Explicit link-or-create — never silently linked. Routed through
      // /status rather than returned as raw JSON: Linking.openURL (the
      // mobile app's entry mechanism) is a full browser navigation, not
      // a fetch — a bare JSON body would just render as unstyled text
      // with no way back into the app.
      await this.sessions.delete(sessionId);
      void this.securityEvents.emit({
        eventType: 'oauth.identity_not_linked',
        outcome: 'failure',
        clientId: session.clientId,
        ip: req.ip,
      });
      const target = new URL(session.redirectUri);
      target.searchParams.set('error', 'not_linked');
      target.searchParams.set('provider_subject', providerSubject);
      target.searchParams.set('state', session.clientState);
      return res.redirect(
        statusRedirectUrl('not_linked', target.toString()),
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

    await this.sessions.delete(sessionId);

    // Phase B ships without a manual fallback code — IdP-authenticated
    // proof is already the primary mechanism, so the challenge is
    // confirmed immediately rather than making the user additionally copy
    // a 6-digit code. The challenge_id is still minted and attempt-tracked
    // so the confirm step below stays a real, independently testable seam
    // rather than being inlined away.
    return this.confirmAndRedirect(
      challengeId,
      session.redirectUri,
      session.clientState,
      res,
      'recovery_success',
    );
  }

  // Deliberately no public /challenge/confirm route. An earlier draft
  // exposed one that took redirect_uri straight from a query param with no
  // validation against the client's registered URIs — an open-redirect-
  // plus-code-injection bug (the redirect target and the authorization
  // code would both be attacker-directed). Every provider's callback
  // calls confirmAndRedirect() directly, using ONLY the redirect_uri and
  // clientState from the server-side session that /authorize already
  // validated against the client registry.
  private async confirmAndRedirect(
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
    return res.redirect(
      statusRedirectUrl(successState, target.toString()),
      303,
    );
  }
}
