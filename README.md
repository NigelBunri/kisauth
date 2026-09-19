# KIS Auth

Central identity/authentication authority for Kingdom Impact Ventures apps.
Production domain: `https://kisauth.kingdomimpactventures.org`.

Full architecture, threat model, data model, API contract, and crypto
design: see the Phase 2 design document (KIS Auth Blueprint artifact).
This README covers running and testing the service, not the design
rationale — read the design doc first if you're new to this service.

## What this is, in one paragraph

KIS Auth answers "which Google identity is this, and which KIS account
does it map to?" — nothing more. It never decides whether a KIS operation
is *allowed*; that stays with the Django backend, exactly as before. KIS
Auth issues a short-lived, single-use, purpose-bound authorization code
after a real Google OAuth/OIDC round trip; Django redeems that code
server-to-server (HMAC-signed, reusing the same internal-signing scheme
already proven between NestJS and Django) and gets back a signed RS256
JWT it can verify independently against KIS Auth's published JWKS.

## Tech stack

NestJS on the Fastify adapter, TypeScript, pnpm — matching
`backend/Nestjs` (`chat-service`) exactly, so `internal-signing.ts` and
the existing tooling conventions carry over directly rather than being
reinvented.

- Postgres (`pg`, raw SQL, no ORM) — two tables that matter
  (`auth_identity`, `client`) plus one audit shadow (`challenge_audit`).
- Redis (`ioredis`) — the 30–60s challenge/authorization-code keyspace,
  namespaced `kisauth:`. Atomic single-use consumption via a Lua script.
- `jose` — RS256 JWT signing/verification and Google `id_token`
  verification (OIDC).

## Running locally

```bash
cp .env.example .env   # fill in real values — see comments in the file
pnpm install
pnpm run migrate        # applies src/db/migrations/*.sql
pnpm run start:dev
```

Requires a reachable Postgres and Redis — `docker-compose up db redis` if
you don't already have them running locally.

## Testing

```bash
pnpm test
```

Tests that need real Postgres/Redis are automatically skipped
(`describe.skip`, not silently faked) unless `KISAUTH_TEST_DATABASE_URL`
and `KISAUTH_TEST_REDIS_URL` are set:

```bash
export KISAUTH_TEST_DATABASE_URL=postgres://kisauth@localhost:5432/kisauth_test
export KISAUTH_TEST_REDIS_URL=redis://localhost:6379
pnpm test
```

**Tests must run with `--runInBand`** (already the default `test` script).
DB-backed specs truncate shared tables between tests; running spec files
in parallel workers lets one file's `beforeEach` wipe rows another file's
test just inserted, mid-test — see `test/db-test-helper.ts`.

The most important single test in this repo is in
`src/redis/challenge-store.spec.ts`: 20 concurrent redemption attempts
for the same authorization code, asserting exactly one succeeds. That's
the property the entire replay-protection story rests on.

`src/app-recovery-flow.spec.ts` is the capstone: a full HTTP-level
recovery round trip (`/authorize` → `/oauth/google/start` →
`/oauth/google/callback` → HMAC-signed `/internal/v1/authorization/exchange`
→ verified JWT) against real Postgres and Redis, with only Google itself
substituted via dependency injection (`GoogleTokenExchangeService`,
`GoogleIdTokenService`) — everything else in the path is real.

## Environment variables

See `.env.example` for the full list with comments. Never commit real
values. `pnpm run security:env-check` prints `SET` / `NOT SET` for every
required variable — never the value.

## What's deliberately not here yet

- The browser-facing web UI (Phase 2 §13 — welcome/consent/error screens).
  The backend endpoints exist and are fully tested; there's no HTML
  rendering layer yet.
- Registration verification, device verification, and other Phase C/D
  purposes — the `purpose` type already has room for them
  (`registration`, `device_verify`, `sensitive_change`), but only
  `recovery` has an implemented, tested flow.
- Live Google OAuth credentials — needs a real Google Cloud Console
  project (external action, can't be done from a repository).
- Production deployment wiring (DNS, TLS termination, secrets manager
  integration) — see the design doc's deployment plan for what's needed.
