import { Injectable, Logger, Optional, Inject } from '@nestjs/common';
import { loadConfig } from '../config/env';
import { signedInternalHeaders } from './internal-signing';
import { FETCH_IMPL } from '../oauth/google-token-exchange.service';

export type SecurityEventType =
  | 'oauth.callback_succeeded'
  | 'oauth.callback_failed'
  | 'oauth.identity_not_linked'
  | 'oauth.cancelled'
  | 'exchange.succeeded'
  | 'exchange.failed'
  | 'link.succeeded'
  | 'link.failed'
  | 'link.already_linked'
  | 'registration.ticket_issued'
  | 'registration.already_registered'
  | 'registration.exchange_succeeded'
  | 'registration.exchange_failed'
  // Enterprise OIDC bridge only — a failure resolving the tenant's SSO
  // config from Django, or fetching/parsing its discovery document,
  // before ever reaching the IdP itself. Every other enterprise-flow
  // event reuses the existing oauth.*/link.*/registration.* types above
  // (distinguished via metadata.provider/partner_slug) rather than
  // forking a parallel event taxonomy per provider.
  | 'oauth.enterprise_config_failed';

export interface SecurityEvent {
  eventType: SecurityEventType;
  outcome: 'success' | 'failure';
  kisUserId?: string;
  clientId?: string;
  reason?: string;
  ip?: string;
  metadata?: Record<string, string | number | boolean | null>;
}

const FORWARD_TIMEOUT_MS = 3000;

/**
 * Best-effort forwarding to Django's existing log_security_event(), so
 * operators have one place to investigate a KIS account's history
 * instead of two databases that can disagree (Phase 2 §16). This is
 * explicitly NOT the authority on whether an auth operation succeeded —
 * it runs strictly after that decision is already made, and its own
 * failure (Django unreachable, timeout, whatever) must never affect the
 * response already given to the real caller. Every failure mode here is
 * caught and logged locally, never re-thrown.
 */
@Injectable()
export class SecurityEventService {
  private readonly logger = new Logger('security.kis_auth.events');

  constructor(
    @Optional() @Inject(FETCH_IMPL) private readonly fetchImpl?: typeof fetch,
  ) {}

  async emit(event: SecurityEvent): Promise<void> {
    const config = loadConfig();
    if (!config.djangoSecurityEventUrl) {
      // Not configured (e.g. local dev, tests) — silently skip rather
      // than log noise for a deliberately-optional integration point.
      return;
    }

    const body = {
      event_type: event.eventType,
      outcome: event.outcome,
      kis_user_id: event.kisUserId ?? null,
      client_id: event.clientId ?? null,
      reason: event.reason ?? null,
      ip: event.ip ?? null,
      // Metadata is caller-constructed from known-safe fields only (see
      // call sites) — never raw request bodies, tokens, or codes.
      metadata: event.metadata ?? {},
    };

    try {
      const headers = signedInternalHeaders({
        method: 'POST',
        url: '/api/v1/kis-auth/security-event/',
        body,
        secret: config.internalHmacSecret,
      });
      const doFetch = this.fetchImpl ?? fetch;
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), FORWARD_TIMEOUT_MS);
      try {
        const response = await doFetch(config.djangoSecurityEventUrl, {
          method: 'POST',
          headers: { ...headers, 'Content-Type': 'application/json' },
          body: JSON.stringify(body),
          signal: controller.signal,
        });
        if (!response.ok) {
          this.logger.warn(
            `security event forward rejected: ${response.status}`,
          );
        }
      } finally {
        clearTimeout(timeout);
      }
    } catch (err) {
      // Network failure, timeout, DNS — anything. Local log only.
      this.logger.warn(
        `security event forward failed: ${(err as Error)?.message ?? 'unknown error'}`,
      );
    }
  }
}
