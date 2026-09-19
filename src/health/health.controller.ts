import { Controller, Get } from '@nestjs/common';
import { Pool } from 'pg';
import Redis from 'ioredis';
import { loadConfig } from '../config/env';

@Controller()
export class HealthController {
  @Get('healthz')
  liveness() {
    return { status: 'ok' };
  }

  @Get('readyz')
  async readiness() {
    const config = loadConfig();
    const checks: Record<string, 'ok' | 'error'> = {};

    const pool = new Pool({ connectionString: config.databaseUrl, max: 1 });
    try {
      await pool.query('SELECT 1');
      checks.database = 'ok';
    } catch {
      checks.database = 'error';
    } finally {
      await pool.end();
    }

    const redis = new Redis(config.redisUrl, {
      lazyConnect: true,
      maxRetriesPerRequest: 1,
    });
    try {
      await redis.connect();
      await redis.ping();
      checks.redis = 'ok';
    } catch {
      checks.redis = 'error';
    } finally {
      redis.disconnect();
    }

    const allOk = Object.values(checks).every((v) => v === 'ok');
    return { status: allOk ? 'ok' : 'degraded', checks };
  }
}
