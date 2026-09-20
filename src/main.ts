import 'reflect-metadata';
import { join } from 'path';
import { NestFactory } from '@nestjs/core';
import {
  FastifyAdapter,
  NestFastifyApplication,
} from '@nestjs/platform-fastify';
import fastifyHelmet from '@fastify/helmet';
import fastifyCors from '@fastify/cors';
import fastifyStatic from '@fastify/static';
import { AppModule } from './app.module';
import { loadConfig } from './config/env';

async function bootstrap() {
  const config = loadConfig();
  const adapter = new FastifyAdapter({ logger: true });
  const app = await NestFactory.create<NestFastifyApplication>(
    AppModule,
    adapter,
  );

  await app.register(fastifyHelmet, {
    // The web/ module's pages use a single inline <style> block each (no
    // separate CSS build step for a handful of small server-rendered
    // pages) — styleSrc needs 'unsafe-inline' for that. Everything else
    // stays locked to 'self'; scriptSrc in particular is NOT relaxed —
    // those pages use zero JavaScript (<meta http-equiv="refresh">
    // instead), specifically so this doesn't need to be any looser than
    // necessary.
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        baseUri: ["'self'"],
        objectSrc: ["'none'"],
        imgSrc: ["'self'", 'data:'],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        frameAncestors: ["'self'"],
        formAction: ["'self'"],
      },
    },
  });
  await app.register(fastifyCors, {
    origin: false, // this is a server-rendered + service-to-service surface, not a browser-JS API — no cross-origin fetch access needed
  });
  // Brand assets (favicon, og:image) for the web/ module's pages —
  // committed into the image at build time (Dockerfile COPYs public/),
  // not user content, so a plain static mount is all this needs.
  await app.register(fastifyStatic, {
    root: join(process.cwd(), 'public'),
    prefix: '/',
    decorateReply: false,
  });

  await app.listen(config.port, '0.0.0.0');
}

bootstrap();
