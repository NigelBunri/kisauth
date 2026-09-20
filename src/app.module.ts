import { Module } from '@nestjs/common';
import { Pool } from 'pg';
import Redis from 'ioredis';
import { loadConfig } from './config/env';
import { HealthController } from './health/health.controller';
import { ClientService } from './clients/client.service';
import { IdentityService } from './identity/identity.service';
import { ChallengeStore } from './redis/challenge-store';
import { OAuthSessionStore } from './oauth/oauth-session.store';
import { GoogleTokenExchangeService } from './oauth/google-token-exchange.service';
import { GoogleIdTokenService } from './oauth/google-id-token.service';
import { OAuthController } from './oauth/oauth.controller';
import { OAuthOutcomeService } from './oauth/oauth-outcome.service';
import { OidcEnterpriseController } from './oauth/oidc-enterprise.controller';
import { OidcProviderResolverService } from './oauth/oidc-provider-resolver.service';
import { OidcDiscoveryService } from './oauth/oidc-discovery.service';
import { OidcTokenExchangeService } from './oauth/oidc-token-exchange.service';
import { OidcIdTokenService } from './oauth/oidc-id-token.service';
import { AuthorizationJwtService } from './jwt/authorization-jwt.service';
import { JwksController } from './jwt/jwks.controller';
import { ExchangeController } from './exchange/exchange.controller';
import { RegistrationExchangeController } from './exchange/registration-exchange.controller';
import { IdentityLinkController } from './exchange/identity-link.controller';
import { RateLimiter } from './security/rate-limit';
import { SecurityEventService } from './security/security-event.service';
import { LinkTicketService } from './security/link-ticket';
import { WebController } from './web/web.controller';

const POOL_PROVIDER = {
  provide: Pool,
  useFactory: () => new Pool({ connectionString: loadConfig().databaseUrl }),
};

const REDIS_PROVIDER = {
  provide: Redis,
  useFactory: () => new Redis(loadConfig().redisUrl),
};

@Module({
  controllers: [
    HealthController,
    OAuthController,
    OidcEnterpriseController,
    JwksController,
    ExchangeController,
    RegistrationExchangeController,
    IdentityLinkController,
    WebController,
  ],
  providers: [
    POOL_PROVIDER,
    REDIS_PROVIDER,
    ClientService,
    IdentityService,
    ChallengeStore,
    OAuthSessionStore,
    GoogleTokenExchangeService,
    GoogleIdTokenService,
    OAuthOutcomeService,
    OidcProviderResolverService,
    OidcDiscoveryService,
    OidcTokenExchangeService,
    OidcIdTokenService,
    AuthorizationJwtService,
    RateLimiter,
    SecurityEventService,
    LinkTicketService,
  ],
})
export class AppModule {}
