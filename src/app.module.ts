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
import { AuthorizationJwtService } from './jwt/authorization-jwt.service';
import { JwksController } from './jwt/jwks.controller';
import { ExchangeController } from './exchange/exchange.controller';

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
    JwksController,
    ExchangeController,
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
    AuthorizationJwtService,
  ],
})
export class AppModule {}
