import {
  Body,
  Controller,
  Post,
  Req,
  UnauthorizedException,
  BadRequestException,
} from '@nestjs/common';
import type { FastifyRequest } from 'fastify';
import { loadConfig } from '../config/env';
import { verifyInternalSignature } from '../security/internal-signing';
import { ChallengeStore } from '../redis/challenge-store';
import { AuthorizationJwtService } from '../jwt/authorization-jwt.service';
import { IdentityService } from '../identity/identity.service';

const GENERIC_ERROR = 'We could not complete this authentication request.';

@Controller('internal/v1')
export class ExchangeController {
  constructor(
    private readonly challenges: ChallengeStore,
    private readonly jwt: AuthorizationJwtService,
    private readonly identities: IdentityService,
  ) {}

  @Post('authorization/exchange')
  async exchange(
    @Body() body: { code?: string; client_id?: string; redirect_uri?: string },
    @Req() req: FastifyRequest,
  ) {
    const config = loadConfig();

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
      throw new UnauthorizedException(GENERIC_ERROR);
    }

    if (!body.code || !body.client_id || !body.redirect_uri) {
      throw new BadRequestException(GENERIC_ERROR);
    }

    // Atomic single-use consume — a second call with the same code, even
    // concurrently, gets null. This is the primary replay defense.
    const payload = await this.challenges.consumeAuthorizationCode(body.code);
    if (!payload) {
      throw new BadRequestException(GENERIC_ERROR);
    }

    // Re-validate the redirect_uri matches what /authorize originally
    // approved for this exact code — binds the code to its original
    // request, standard authorization-code-flow hardening.
    if (
      payload.clientId !== body.client_id ||
      payload.redirectUri !== body.redirect_uri
    ) {
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

    return { token };
  }
}
