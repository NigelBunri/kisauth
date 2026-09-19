# Multi-stage build matching the existing backend/Nestjs Dockerfile
# convention — pnpm, prod-only node_modules in the final image, non-root
# user, small final surface.

FROM node:22-slim AS builder
RUN corepack enable
WORKDIR /app
COPY package.json pnpm-lock.yaml* ./
RUN pnpm install --frozen-lockfile
COPY . .
RUN pnpm run build

FROM node:22-slim AS production
RUN corepack enable
WORKDIR /app
COPY package.json pnpm-lock.yaml* ./
RUN pnpm install --prod --frozen-lockfile
COPY --from=builder /app/dist ./dist

RUN groupadd -r kisauth && useradd -r -g kisauth kisauth
USER kisauth

EXPOSE 4100
CMD ["node", "dist/main.js"]
