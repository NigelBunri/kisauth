import {
  Body,
  Controller,
  Post,
  Req,
  UnauthorizedException,
  BadRequestException,
  HttpException,
  HttpStatus,
} from '@nestjs/common';
import type { FastifyRequest } from 'fastify';
import { loadConfig } from '../config/env';
import { verifyInternalSignature } from '../security/internal-signing';
import { ChallengeStore } from '../redis/challenge-store';
import { AuthorizationJwtService } from '../jwt/authorization-jwt.service';
import { IdentityService } from '../identity/identity.service';
import { RateLimiter } from '../security/rate-limit';
import { RATE_LIMITS, RATE_LIMIT_ERROR } from '../security/rate-limit-policy';
import { SecurityEventService } from '../security/security-event.service';

const GENERIC_ERROR = 'We could not complete this authentication request.';

@Controller('internal/v1')
export class ExchangeController {
  constructor(
    private readonly challenges: ChallengeStore,
    private readonly jwt: AuthorizationJwtService,
    private readonly identities: IdentityService,
    private readonly rateLimiter: RateLimiter,
    private readonly securityEvents: SecurityEventService,
  ) {}

  @Post('authorization/exchange')
  async exchange(
    @Body() body: { code?: string; client_id?: string; redirect_uri?: string },
    @Req() req: FastifyRequest,
  ) {
    const config = loadConfig();

    // Two independent axes: per-IP catches drive-by abuse from a source
    // that isn't Django at all; per-client_id catches a misbehaving or
    // compromised legitimate Django deployment. Checked before signature
    // verification so a flood of even correctly-signed requests is
    // bounded too, not just forged ones.
    const ipLimit = await this.rateLimiter.check(
      RATE_LIMITS.EXCHANGE_PER_IP.scope,
      req.ip,
      RATE_LIMITS.EXCHANGE_PER_IP.limit,
      RATE_LIMITS.EXCHANGE_PER_IP.windowSeconds,
    );
    if (!ipLimit.allowed) {
      throw new HttpException(RATE_LIMIT_ERROR, HttpStatus.TOO_MANY_REQUESTS);
    }
    if (body.client_id) {
      const clientLimit = await this.rateLimiter.check(
        RATE_LIMITS.EXCHANGE_PER_CLIENT.scope,
        body.client_id,
        RATE_LIMITS.EXCHANGE_PER_CLIENT.limit,
        RATE_LIMITS.EXCHANGE_PER_CLIENT.windowSeconds,
      );
      if (!clientLimit.allowed) {
        throw new HttpException(RATE_LIMIT_ERROR, HttpStatus.TOO_MANY_REQUESTS);
      }
    }

    // The HMAC signature is what proves this call came from Django, not
    // just from whoever happened to possess the code. Possession of a
    // valid code is necessary but not sufficient — see the threat model's
    // "stolen authorization code" row.
    const verification = verifyInternalSignature({
      method: 'POST',
      url: '/internal/v1/authorization/exchange',
      body,
      headers: req.headers as Record<string, string | string[] | undefined>,
      secret: config.internalHmacSecret,
      maxSkewSeconds: config.internalSignatureMaxSkewSeconds,
    });
    if (!verification.ok) {
      void this.securityEvents.emit({
        eventType: 'exchange.failed',
        outcome: 'failure',
        clientId: body.client_id,
        reason: 'signature_invalid',
        ip: req.ip,
      });
      throw new UnauthorizedException(GENERIC_ERROR);
    }

    if (!body.code || !body.client_id || !body.redirect_uri) {
      throw new BadRequestException(GENERIC_ERROR);
    }

    // Atomic single-use consume — a second call with the same code, even
    // concurrently, gets null. This is the primary replay defense.
    const payload = await this.challenges.consumeAuthorizationCode(body.code);
    if (!payload) {
      void this.securityEvents.emit({
        eventType: 'exchange.failed',
        outcome: 'failure',
        clientId: body.client_id,
        reason: 'code_invalid_or_reused',
        ip: req.ip,
      });
      throw new BadRequestException(GENERIC_ERROR);
    }

    // Re-validate the redirect_uri matches what /authorize originally
    // approved for this exact code — binds the code to its original
    // request, standard authorization-code-flow hardening.
    if (
      payload.clientId !== body.client_id ||
      payload.redirectUri !== body.redirect_uri
    ) {
      void this.securityEvents.emit({
        eventType: 'exchange.failed',
        outcome: 'failure',
        clientId: body.client_id,
        reason: 'redirect_uri_or_client_mismatch',
        ip: req.ip,
      });
      throw new BadRequestException(GENERIC_ERROR);
    }

    const identity = await this.identities.findById(payload.authIdentityId);
    if (
      !identity ||
      identity.status !== 'active' ||
      identity.kisUserId !== payload.kisUserId
    ) {
      // The identity could have been revoked in the window between the
      // browser round-trip and this redemption — re-check rather than
      // trusting only what was true when the code was issued.
      void this.securityEvents.emit({
        eventType: 'exchange.failed',
        outcome: 'failure',
        kisUserId: payload.kisUserId,
        clientId: body.client_id,
        reason: identity ? 'identity_revoked' : 'identity_not_found',
        ip: req.ip,
      });
      throw new BadRequestException(GENERIC_ERROR);
    }

    const token = await this.jwt.sign(
      {
        sub: payload.kisUserId,
        aud: payload.clientId,
        purpose: payload.purpose,
        authIdentityId: payload.authIdentityId,
        providerEmail: identity.providerEmail,
        providerEmailVerified: identity.providerEmailVerified,
      },
      config.authCodeTtlSeconds,
    );

    void this.securityEvents.emit({
      eventType: 'exchange.succeeded',
      outcome: 'success',
      kisUserId: payload.kisUserId,
      clientId: payload.clientId,
      ip: req.ip,
      metadata: { purpose: payload.purpose },
    });

    return { token };
  }
}
