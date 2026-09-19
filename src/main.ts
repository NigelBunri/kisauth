import 'reflect-metadata';
import { NestFactory } from '@nestjs/core';
import {
  FastifyAdapter,
  NestFastifyApplication,
} from '@nestjs/platform-fastify';
import fastifyHelmet from '@fastify/helmet';
import fastifyCors from '@fastify/cors';
import { AppModule } from './app.module';
import { loadConfig } from './config/env';

async function bootstrap() {
  const config = loadConfig();
  const adapter = new FastifyAdapter({ logger: true });
  const app = await NestFactory.create<NestFastifyApplication>(
    AppModule,
    adapter,
  );

  await app.register(fastifyHelmet);
  await app.register(fastifyCors, {
    origin: false, // this is a server-rendered + service-to-service surface, not a browser-JS API — no cross-origin fetch access needed
  });

  await app.listen(config.port, '0.0.0.0');
}

bootstrap();
