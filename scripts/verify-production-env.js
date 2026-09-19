// Prints SET / NOT SET for every required variable — never the value
// itself, per the "no secrets in logs or debug output" rule. Run before
// deploying to catch a missing secret before the app crashes on it.

const REQUIRED = [
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

let missing = 0;
for (const name of REQUIRED) {
  const isSet = Boolean(process.env[name] && process.env[name].trim());
  console.log(`${name}=${isSet ? 'SET' : 'NOT SET'}`);
  if (!isSet) missing += 1;
}

if (missing > 0) {
  console.error(`\n${missing} required variable(s) missing.`);
  process.exit(1);
}
console.log('\nAll required variables are set.');
