-- KIS Auth — initial schema.
-- Deliberately minimal, per the Phase 2 data model: two tables that matter
-- for correctness (auth_identity, client) plus one audit shadow
-- (challenge_audit). The 30-60s challenge/code state itself lives in
-- Redis, not here — see src/redis/challenge-store.ts.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS auth_identity (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  provider text NOT NULL,
  provider_subject text NOT NULL,
  kis_user_id uuid NOT NULL,
  provider_email text,
  provider_email_verified boolean NOT NULL DEFAULT false,
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  last_authenticated_at timestamptz,

  -- One Google identity can never be linked to two KIS accounts.
  CONSTRAINT auth_identity_provider_subject_unique UNIQUE (provider, provider_subject),
  -- One KIS account maps to at most one linked identity in this phase.
  -- Deliberately simple; revisit only if a second provider is ever added.
  CONSTRAINT auth_identity_kis_user_unique UNIQUE (kis_user_id)
);

CREATE INDEX IF NOT EXISTS idx_auth_identity_kis_user_id ON auth_identity (kis_user_id);

CREATE TABLE IF NOT EXISTS client (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  client_id text NOT NULL UNIQUE,
  name text NOT NULL,
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
  allowed_redirect_uris text[] NOT NULL DEFAULT '{}',
  allowed_scopes text[] NOT NULL DEFAULT '{openid,email,profile}',
  allowed_purposes text[] NOT NULL DEFAULT '{}',
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

-- Async, best-effort audit shadow of challenge activity. Never stores the
-- OTP hash or any secret material — exists only to answer "did a challenge
-- exist for this user at this time," not to verify anything. Redis remains
-- the verification source of truth.
CREATE TABLE IF NOT EXISTS challenge_audit (
  challenge_id uuid PRIMARY KEY,
  purpose text NOT NULL,
  kis_user_id uuid,
  client_id text,
  result text NOT NULL CHECK (result IN ('issued', 'verified', 'expired', 'exceeded_attempts', 'replayed')),
  created_at timestamptz NOT NULL DEFAULT now(),
  resolved_at timestamptz
);

CREATE INDEX IF NOT EXISTS idx_challenge_audit_kis_user_id ON challenge_audit (kis_user_id);
CREATE INDEX IF NOT EXISTS idx_challenge_audit_created_at ON challenge_audit (created_at);
