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
import { RateLimiter } from '../security/rate-limit';
import { RATE_LIMITS, RATE_LIMIT_ERROR } from '../security/rate-limit-policy';
import { SecurityEventService } from '../security/security-event.service';

const GENERIC_ERROR = 'We could not complete this authentication request.';

/** Separate from ExchangeController deliberately — a registration ticket
 * has no kis_user_id (no KIS account exists yet), so it can't flow
 * through AuthorizationCodePayload's exchange logic without weakening
 * that type's guarantees for every other caller. Same HMAC/rate-limit/
 * single-use-consume shape, applied to a different payload. */
@Controller('internal/v1')
export class RegistrationExchangeController {
  constructor(
    private readonly challenges: ChallengeStore,
    private readonly jwt: AuthorizationJwtService,
    private readonly rateLimiter: RateLimiter,
    private readonly securityEvents: SecurityEventService,
  ) {}

  @Post('registration/exchange')
  async exchange(
    @Body() body: { code?: string; client_id?: string; redirect_uri?: string },
    @Req() req: FastifyRequest,
  ) {
    const config = loadConfig();

    const ipLimit = await this.rateLimiter.check(
      RATE_LIMITS.REGISTRATION_EXCHANGE_PER_IP.scope,
      req.ip,
      RATE_LIMITS.REGISTRATION_EXCHANGE_PER_IP.limit,
      RATE_LIMITS.REGISTRATION_EXCHANGE_PER_IP.windowSeconds,
    );
    if (!ipLimit.allowed) {
      throw new HttpException(RATE_LIMIT_ERROR, HttpStatus.TOO_MANY_REQUESTS);
    }
    if (body.client_id) {
      const clientLimit = await this.rateLimiter.check(
        RATE_LIMITS.REGISTRATION_EXCHANGE_PER_CLIENT.scope,
        body.client_id,
        RATE_LIMITS.REGISTRATION_EXCHANGE_PER_CLIENT.limit,
        RATE_LIMITS.REGISTRATION_EXCHANGE_PER_CLIENT.windowSeconds,
      );
      if (!clientLimit.allowed) {
        throw new HttpException(RATE_LIMIT_ERROR, HttpStatus.TOO_MANY_REQUESTS);
      }
    }

    const verification = verifyInternalSignature({
      method: 'POST',
      url: '/internal/v1/registration/exchange',
      body,
      headers: req.headers as Record<string, string | string[] | undefined>,
      secret: config.internalHmacSecret,
      maxSkewSeconds: config.internalSignatureMaxSkewSeconds,
    });
    if (!verification.ok) {
      void this.securityEvents.emit({
        eventType: 'registration.exchange_failed',
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

    const payload = await this.challenges.consumeRegistrationTicket(body.code);
    if (!payload) {
      void this.securityEvents.emit({
        eventType: 'registration.exchange_failed',
        outcome: 'failure',
        clientId: body.client_id,
        reason: 'ticket_invalid_or_reused',
        ip: req.ip,
      });
      throw new BadRequestException(GENERIC_ERROR);
    }

    if (
      payload.clientId !== body.client_id ||
      payload.redirectUri !== body.redirect_uri
    ) {
      void this.securityEvents.emit({
        eventType: 'registration.exchange_failed',
        outcome: 'failure',
        clientId: body.client_id,
        reason: 'redirect_uri_or_client_mismatch',
        ip: req.ip,
      });
      throw new BadRequestException(GENERIC_ERROR);
    }

    const token = await this.jwt.sign(
      {
        aud: payload.clientId,
        purpose: 'registration',
        providerSubject: payload.providerSubject,
        providerEmail: payload.providerEmail,
        providerEmailVerified: payload.providerEmailVerified,
      },
      config.authCodeTtlSeconds,
    );

    void this.securityEvents.emit({
      eventType: 'registration.exchange_succeeded',
      outcome: 'success',
      clientId: payload.clientId,
      ip: req.ip,
    });

    return { token };
  }
}
