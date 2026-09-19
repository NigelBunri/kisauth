# KIS Auth — Production Configuration Checklist

Everything below must be true before `KIS_AUTH_RECOVERY_ENABLED` is set to
`true` anywhere real users can reach. Nothing in this file is itself a
secret — it documents names and requirements, never values, per the
"never print secret values" rule already enforced by
`scripts/verify-production-env.js` and `src/config/env.ts`'s
`printEnvCheck()`.

## 1. Google OAuth production client

- [ ] A **dedicated production** OAuth 2.0 client exists in Google Cloud
      Console — never the same client used for local development or
      staging. Sharing a client means a compromised dev environment can
      forge production-looking Google identities.
- [ ] OAuth consent screen is configured (app name, support email, logo)
      and, if not yet Google-verified, understand that unverified apps
      show a warning interstitial to users — verify it before wide
      rollout, not after.
- [ ] Scopes requested: `openid`, `email`, `profile` only. No Gmail,
      Drive, Contacts, Calendar, or any other scope — confirm this
      directly in the Console's OAuth consent screen configuration, not
      just in code, since Google enforces what's actually configured
      there independent of what the code requests.
- [ ] **Authorized redirect URI** is set to exactly
      `https://kisauth.kingdomimpactventures.org/oauth/google/callback`
      — no trailing slash mismatch, no `http://`, no wildcard. Google
      rejects an exact-match failure at the OAuth layer itself, which is
      good — but a wrong value here means the flow simply never works,
      not a silent security gap.
- [ ] A **separate** client (or at minimum a separate authorized redirect
      URI entry) exists for staging/local development, so a compromised
      dev environment never has production Google credentials to leak.

## 2. Environment variables — presence, not values

Run `pnpm run security:env-check` in the deployed environment and
confirm every line reads `SET`, never `NOT SET`:

- [ ] `GOOGLE_OAUTH_CLIENT_ID`
- [ ] `GOOGLE_OAUTH_CLIENT_SECRET`
- [ ] `GOOGLE_OAUTH_REDIRECT_URI`
- [ ] `KISAUTH_BASE_URL` — must be `https://kisauth.kingdomimpactventures.org` exactly (used to build the JWT `iss` claim and Google's own redirect URI)
- [ ] `KISAUTH_DATABASE_URL`
- [ ] `KISAUTH_REDIS_URL`
- [ ] `KISAUTH_JWT_PRIVATE_KEY` / `KISAUTH_JWT_PUBLIC_KEY` — a **freshly generated production keypair**, never the one used in any test/dev environment (see §4)
- [ ] `KISAUTH_JWT_KID`
- [ ] `KISAUTH_INTERNAL_HMAC_SECRET` — freshly generated, **distinct** from both `DJANGO_INTERNAL_TOKEN` (the Nest↔Django secret) and any dev/staging value
- [ ] `DJANGO_SECURITY_EVENT_URL` — set to Django's real `/api/v1/kis-auth/security-event/` endpoint; the same `KISAUTH_INTERNAL_HMAC_SECRET` above must also be configured on the Django side for this to verify (it's a shared HMAC secret, not two independent ones)
- [ ] Confirm no secret above is committed to git — check with `git log -p -- .env .env.production 2>/dev/null | head` returning nothing, and confirm `.env*` (except `.env.example`) is in `.gitignore`.

## 3. PostgreSQL

- [ ] Dedicated database — **not** Django's existing Postgres instance.
      This is a deliberate trust-boundary decision (Phase 2 §32), not an
      oversight to "simplify" during deployment.
- [ ] `pnpm run migrate` has been run against production and
      `schema_migrations` shows `001_init.sql` applied.
- [ ] Connection uses TLS if the database is reachable over a network
      (not applicable for a same-host Unix socket).
- [ ] Database credentials are distinct from every other service's.
- [ ] Backups configured — this database holds `auth_identity`, the
      Google↔KIS account linkage; losing it without a backup means every
      linked user must re-link.

## 4. RSA signing keys

- [ ] Generated fresh for production:
      `openssl genrsa -out private.pem 2048 && openssl rsa -in private.pem -pubout -out public.pem`
      — RSA-2048 minimum (3072 preferred if the extra CPU cost is
      acceptable for your traffic volume).
- [ ] Private key loaded from a real secrets manager at runtime, never
      baked into the Docker image or committed to git.
- [ ] `KISAUTH_JWT_KID` uniquely identifies this key (e.g.
      `kisauth-2026-09`) — document the rotation date alongside it.
- [ ] A key-rotation runbook exists and has been rehearsed at least once
      in staging: generate new keypair → publish new key in
      `KISAUTH_JWT_PREVIOUS_KEYS` alongside the old one → flip signing to
      the new key → after the overlap window (Phase 2 recommends ~7
      days), remove the old key from the published set.
- [ ] Confirm Django's JWKS cache (`PyJWKClient(..., lifespan=600)` in
      `apps/kis_auth_bridge/exchange_client.py`) is short enough that a
      key-compromise rotation propagates within minutes, not the full
      10-minute cache lifespan if that's too slow for your incident
      response requirements — adjust `lifespan` if so.

## 5. Redis

- [ ] Dedicated instance, or a Redis instance shared with other
      infrastructure but with the `kisauth:` key prefix confirmed
      non-colliding (all kis-auth keys are namespaced under this prefix
      by construction — verify nothing else in the shared instance uses
      it).
- [ ] Persistence/eviction policy understood: losing the challenge/code
      keyspace mid-flight just means in-flight recovery attempts need to
      restart — acceptable — but losing the rate-limit keyspace resets
      abuse counters to zero, which is a minor, acceptable risk, not a
      security hole (an attacker gains at most one extra window's worth
      of budget).
- [ ] Connection uses TLS if reachable over a network.

## 6. CORS / trusted origins

- [ ] `main.ts` currently registers `@fastify/cors` with `origin: false`
      — **no cross-origin browser JS is allowed to call this service at
      all**, by design (it's a server-rendered + service-to-service
      surface). Confirm this is still true before deployment; if a
      future browser-JS integration is added, it needs an explicit,
      narrow origin allowlist, never `origin: true`/`*`.
- [ ] Django's `CORS_ALLOWED_ORIGINS` (or equivalent) does not need any
      new entry for kis-auth — the browser never makes a cross-origin
      call to Django as part of this flow; the mobile app calls Django
      directly (same as every other API call it makes) and Django calls
      kis-auth server-to-server.

## 7. HTTPS / transport

- [ ] `kisauth.kingdomimpactventures.org` serves HTTPS only — HTTP
      requests redirect or are rejected, not served in plaintext.
- [ ] HSTS is enabled **only after** confirming HTTPS works end-to-end
      (enabling it before TLS is verified is the standard footgun that
      locks out HTTP fallback during initial rollout debugging).
- [ ] `@fastify/helmet` is registered in `main.ts` (already is) — confirm
      its defaults are actually reaching responses in production (not
      stripped by a reverse proxy in front of it).
- [ ] Django↔kis-auth server-to-server calls also travel over TLS, not
      just HMAC-signed over plaintext — the signing proves authenticity,
      not confidentiality; TLS is still required for the latter.

## 8. Secure cookies

- [ ] `src/http/cookies.ts`'s `serializeSessionCookie` sets `Secure` only
      when `NODE_ENV === 'production'` — confirm `NODE_ENV=production` is
      actually set in the deployed environment (a missing/wrong
      `NODE_ENV` silently ships session cookies without the `Secure`
      flag).
- [ ] `HttpOnly` and `SameSite=Lax` are unconditional in that same
      helper — no action needed, just confirm no future edit removes
      them.

## 9. Logging

- [ ] Fastify's built-in logger (enabled via `new FastifyAdapter({ logger: true })`) is confirmed to not log full request bodies in production (it logs request/response metadata by default, not bodies — verify this hasn't been changed to a more verbose config).
- [ ] Spot-check production logs after the first real traffic: confirm no
      authorization code, JWT, Google id_token, or HMAC secret ever
      appears in a log line. Every place in the code that logs an error
      was written to log a *reason string* (e.g. `signature_invalid`),
      never the raw signed value — but a log-output audit is worth doing
      once for real, not just trusting the code review.
- [ ] `SecurityEventService`'s forwarded events (§ Django checklist
      below) are themselves free of secrets — confirmed by
      `security-event.service.spec.ts`'s "never includes raw secrets"
      test, but worth a second look at exactly what `metadata` fields
      get passed at each call site if new ones are added later.

## 10. Rate limiting

- [ ] Confirm the limits in `src/security/rate-limit-policy.ts` still
      match actual production traffic patterns after the first week —
      they were set from reasoning about the threat model, not from real
      traffic data, and may need tuning (e.g. `AUTHORIZE: 30/min` could
      be too tight for a legitimate user who fumbles the flow and
      retries by hand several times in frustration).
- [ ] Confirm Redis is reachable from every instance if this service is
      ever horizontally scaled — the rate limiter's correctness depends
      on all instances sharing the same Redis-backed counters; an
      in-memory fallback would silently make the limits per-instance
      instead of global.

## 11. Django-side configuration

- [ ] `KISAUTH_BASE_URL`, `KISAUTH_INTERNAL_HMAC_SECRET` set on Django,
      matching kis-auth's values exactly (shared secret).
- [ ] `KISAUTH_JWKS_URL` set (or left unset to fall back to
      `{KISAUTH_BASE_URL}/.well-known/jwks.json`, which is fine for a
      first deployment).
- [ ] `DJANGO_SECURITY_EVENT_URL` on the kis-auth side points at Django's
      real, reachable `/api/v1/kis-auth/security-event/`.
- [ ] `apps.kis_auth_bridge` is **not** in `INSTALLED_APPS` by design
      (see `apps/kis_auth_bridge/__init__.py`'s comment) — do not add it
      unless the app gains models/migrations that require it; adding it
      unnecessarily is not harmful but is a needless deviation worth a
      comment explaining why if someone does it later.

## 12. Feature flag rollout (mobile)

- [ ] `KIS_AUTH_RECOVERY_ENABLED` stays `false` in the shipped app build
      until every item above is confirmed **and** a real end-to-end test
      has been run against production Google credentials by hand (every
      automated test here uses a synthetic Google keypair — see the
      delivery report's "no live Google testing" risk note).
- [ ] Roll out to an internal cohort first if the build system supports
      per-build or remote-config flag overrides; a hardcoded flag flip
      ships to 100% of users simultaneously with no gradual rollout.
