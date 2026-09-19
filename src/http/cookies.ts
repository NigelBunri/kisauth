// Deliberately not using @fastify/cookie: its v11 line does an internal
// dynamic import() that's incompatible with Jest's CommonJS transform
// (throws "dynamic import callback was invoked without
// --experimental-vm-modules" and, worse, leaves the process hanging on
// cleanup afterwards). All this service actually needs is one plain,
// unsigned, httpOnly session cookie — not the full RFC 6265 feature set
// (signing, multi-cookie parsing edge cases) that library covers, so a
// ~20-line helper is less risk than fighting a dependency's test-runtime
// compatibility.

export function parseCookieHeader(
  header: string | undefined,
): Record<string, string> {
  if (!header) return {};
  const out: Record<string, string> = {};
  for (const part of header.split(';')) {
    const idx = part.indexOf('=');
    if (idx === -1) continue;
    const name = part.slice(0, idx).trim();
    const value = part.slice(idx + 1).trim();
    if (name) out[name] = decodeURIComponent(value);
  }
  return out;
}

export function serializeSessionCookie(
  name: string,
  value: string,
  opts: { secure: boolean; maxAgeSeconds: number },
): string {
  const parts = [
    `${name}=${encodeURIComponent(value)}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Lax',
    `Max-Age=${opts.maxAgeSeconds}`,
  ];
  if (opts.secure) parts.push('Secure');
  return parts.join('; ');
}
