// Central, typed environment access. Every other module reads config
// through here instead of touching process.env directly, so there is one
// place that knows every variable name this service depends on.

export interface KisAuthConfig {
  nodeEnv: string;
  port: number;
  baseUrl: string;

  googleClientId: string;
  googleClientSecret: string;
  googleRedirectUri: string;

  databaseUrl: string;
  redisUrl: string;

  jwtPrivateKeyPem: string;
  jwtPublicKeyPem: string;
  jwtKid: string;
  jwtPreviousKeys: Array<{ kid: string; publicKeyPem: string }>;

  internalHmacSecret: string;
  internalSignatureMaxSkewSeconds: number;

  djangoSecurityEventUrl: string;

  challengeTtlSeconds: number;
  authCodeTtlSeconds: number;
  challengeMaxAttempts: number;
}

function required(name: string): string {
  const value = process.env[name];
  if (!value || !value.trim()) {
    throw new Error(`Missing required environment variable: ${name}`);
  }
  return value;
}

function optional(name: string, fallback: string): string {
  const value = process.env[name];
  return value && value.trim() ? value : fallback;
}

function int(name: string, fallback: number): number {
  const raw = process.env[name];
  const parsed = raw ? Number(raw) : NaN;
  return Number.isFinite(parsed) ? parsed : fallback;
}

function parsePreviousKeys(
  raw: string | undefined,
): Array<{ kid: string; publicKeyPem: string }> {
  if (!raw || !raw.trim()) return [];
  return raw
    .split(',')
    .map((entry) => entry.trim())
    .filter(Boolean)
    .map((entry) => {
      const [kid, base64Pem] = entry.split(':');
      if (!kid || !base64Pem) {
        throw new Error(
          `Malformed KISAUTH_JWT_PREVIOUS_KEYS entry: "${entry}"`,
        );
      }
      return {
        kid,
        publicKeyPem: Buffer.from(base64Pem, 'base64').toString('utf8'),
      };
    });
}

let cached: KisAuthConfig | null = null;

/** Loads and validates config once per process. Throws loudly on startup
 * if something required is missing, rather than failing confusingly later
 * on the first request that needs it. */
export function loadConfig(): KisAuthConfig {
  if (cached) return cached;
  cached = {
    nodeEnv: optional('NODE_ENV', 'development'),
    port: int('PORT', 4100),
    baseUrl: required('KISAUTH_BASE_URL'),

    googleClientId: required('GOOGLE_OAUTH_CLIENT_ID'),
    googleClientSecret: required('GOOGLE_OAUTH_CLIENT_SECRET'),
    googleRedirectUri: required('GOOGLE_OAUTH_REDIRECT_URI'),

    databaseUrl: required('KISAUTH_DATABASE_URL'),
    redisUrl: required('KISAUTH_REDIS_URL'),

    jwtPrivateKeyPem: required('KISAUTH_JWT_PRIVATE_KEY'),
    jwtPublicKeyPem: required('KISAUTH_JWT_PUBLIC_KEY'),
    jwtKid: required('KISAUTH_JWT_KID'),
    jwtPreviousKeys: parsePreviousKeys(process.env.KISAUTH_JWT_PREVIOUS_KEYS),

    internalHmacSecret: required('KISAUTH_INTERNAL_HMAC_SECRET'),
    internalSignatureMaxSkewSeconds: int(
      'INTERNAL_SIGNATURE_MAX_SKEW_SECONDS',
      300,
    ),

    djangoSecurityEventUrl: optional('DJANGO_SECURITY_EVENT_URL', ''),

    challengeTtlSeconds: int('KISAUTH_CHALLENGE_TTL_SECONDS', 30),
    authCodeTtlSeconds: int('KISAUTH_AUTH_CODE_TTL_SECONDS', 60),
    challengeMaxAttempts: int('KISAUTH_CHALLENGE_MAX_ATTEMPTS', 5),
  };
  return cached;
}

/** For tests only — forces the next loadConfig() call to re-read env. */
export function resetConfigCacheForTests(): void {
  cached = null;
}

const REQUIRED_VAR_NAMES = [
  'KISAUTH_BASE_URL',
  'GOOGLE_OAUTH_CLIENT_ID',
  'GOOGLE_OAUTH_CLIENT_SECRET',
  'GOOGLE_OAUTH_REDIRECT_URI',
  'KISAUTH_DATABASE_URL',
  'KISAUTH_REDIS_URL',
  'KISAUTH_JWT_PRIVATE_KEY',
  'KISAUTH_JWT_PUBLIC_KEY',
  'KISAUTH_JWT_KID',
  'KISAUTH_INTERNAL_HMAC_SECRET',
];

/** Prints SET/NOT SET only — never a value — per the no-secrets-in-logs rule. */
export function printEnvCheck(): void {
  for (const name of REQUIRED_VAR_NAMES) {
    const isSet = Boolean(process.env[name] && process.env[name]!.trim());

    console.log(`${name}=${isSet ? 'SET' : 'NOT SET'}`);
  }
}
