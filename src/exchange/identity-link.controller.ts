import {
  Body,
  Controller,
  Post,
  Req,
  UnauthorizedException,
  BadRequestException,
  ConflictException,
} from '@nestjs/common';
import type { FastifyRequest } from 'fastify';
import { loadConfig } from '../config/env';
import { verifyInternalSignature } from '../security/internal-signing';
import { IdentityService } from '../identity/identity.service';
import { SecurityEventService } from '../security/security-event.service';

const GENERIC_ERROR = 'We could not complete this request.';

/** Server-to-server only — the direct link primitive for the ONE case
 * that has no browser round trip to attach to: right after Django creates
 * a new User from a redeemed registration ticket, it already holds
 * Google-verified proof (the ticket itself only existed because kis-auth
 * verified Google's ID token) and just needs to associate the two IDs.
 * The Settings "Link Google Account" flow does NOT use this endpoint —
 * it goes through the full /authorize?purpose=link browser round trip,
 * because THAT case genuinely needs a fresh, live Google sign-in to prove
 * control of the Google account. Both paths call the same
 * IdentityService.link() underneath. */
@Controller('internal/v1')
export class IdentityLinkController {
  constructor(
    private readonly identities: IdentityService,
    private readonly securityEvents: SecurityEventService,
  ) {}

  @Post('identity/link')
  async link(
    @Body()
    body: {
      provider?: string;
      provider_subject?: string;
      kis_user_id?: string;
      provider_email?: string | null;
      provider_email_verified?: boolean;
    },
    @Req() req: FastifyRequest,
  ) {
    const config = loadConfig();

    const verification = verifyInternalSignature({
      method: 'POST',
      url: '/internal/v1/identity/link',
      body,
      headers: req.headers as Record<string, string | string[] | undefined>,
      secret: config.internalHmacSecret,
      maxSkewSeconds: config.internalSignatureMaxSkewSeconds,
    });
    if (!verification.ok) {
      throw new UnauthorizedException(GENERIC_ERROR);
    }

    if (!body.provider || !body.provider_subject || !body.kis_user_id) {
      throw new BadRequestException(GENERIC_ERROR);
    }

    const result = await this.identities.link({
      provider: body.provider,
      providerSubject: body.provider_subject,
      kisUserId: body.kis_user_id,
      providerEmail: body.provider_email ?? null,
      providerEmailVerified: body.provider_email_verified ?? false,
    });

    if (!result.ok) {
      void this.securityEvents.emit({
        eventType: 'link.already_linked',
        outcome: 'failure',
        kisUserId: body.kis_user_id,
        reason: 'post_registration_link_conflict',
      });
      throw new ConflictException(GENERIC_ERROR);
    }

    void this.securityEvents.emit({
      eventType: 'link.succeeded',
      outcome: 'success',
      kisUserId: body.kis_user_id,
      metadata: { via: 'registration' },
    });

    return { ok: true, identityId: result.identity.id };
  }
}
