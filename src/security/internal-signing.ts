// Ported from backend/Nestjs/src/security/internal-signing.ts, which is
// itself the scheme already proven in production between NestJS and
// Django (apps/chat/internal_signing.py). KIS Auth reuses it verbatim
// rather than inventing a second signing protocol for the same problem:
// method + path + timestamp + nonce + body-hash, HMAC-SHA256, constant-time
// compare, nonce replay cache, bounded clock skew.
//
// Deliberate divergence from the ported original: that version also
// accepts a legacy "plain shared secret in a header" fallback for
// backward compatibility with older callers. KIS Auth is a brand-new,
// high-value security service with no legacy callers to support, so this
// version requires the full signed form unconditionally — there is no
// weaker fallback path to disable.

import crypto from 'crypto';

export const INTERNAL_TIMESTAMP_HEADER = 'X-Internal-Timestamp';
export const INTERNAL_NONCE_HEADER = 'X-Internal-Nonce';
export const INTERNAL_SIGNATURE_HEADER = 'X-Internal-Signature';

const nonceCache = new Map<string, number>();

function stableStringify(value: unknown, parseJsonString = false): string {
  if (value === null || value === undefined) return '';
  if (Buffer.isBuffer(value))
    return stableStringify(value.toString('utf8'), true);
  if (typeof value === 'string') {
    if (parseJsonString) {
      try {
        return stableStringify(JSON.parse(value));
      } catch {
        return value;
      }
    }
    return JSON.stringify(value);
  }
  if (Array.isArray(value))
    return `[${value.map((item) => stableStringify(item)).join(',')}]`;
  if (typeof value === 'object') {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record)
      .filter((key) => record[key] !== undefined)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${stableStringify(record[key])}`)
      .join(',')}}`;
  }
  return JSON.stringify(value);
}

function bodyHash(body: unknown): string {
  return crypto
    .createHash('sha256')
    .update(stableStringify(body, typeof body === 'string'))
    .digest('hex');
}

function pathWithQuery(
  urlOrPath: string,
  params?: Record<string, unknown>,
): string {
  const parsed = new URL(urlOrPath, 'http://internal.local');
  if (params) {
    for (const key of Object.keys(params).sort()) {
      const value = params[key];
      if (value === undefined || value === null) continue;
      parsed.searchParams.set(key, String(value));
    }
  }
  const query = parsed.searchParams.toString();
  return `${parsed.pathname || '/'}${query ? `?${query}` : ''}`;
}

function signaturePayload(args: {
  method: string;
  path: string;
  timestamp: string;
  nonce: string;
  bodyHash: string;
}): string {
  return [
    args.method.toUpperCase(),
    args.path || '/',
    args.timestamp,
    args.nonce,
    args.bodyHash,
  ].join('\n');
}

function sign(secret: string, payload: string): string {
  return crypto.createHmac('sha256', secret).update(payload).digest('hex');
}

export function signedInternalHeaders(args: {
  method: string;
  url: string;
  body?: unknown;
  params?: Record<string, unknown>;
  secret: string;
}): Record<string, string> {
  const timestamp = String(Math.floor(Date.now() / 1000));
  const nonce = crypto.randomUUID().replace(/-/g, '');
  const payload = signaturePayload({
    method: args.method,
    path: pathWithQuery(args.url, args.params),
    timestamp,
    nonce,
    bodyHash: bodyHash(args.body),
  });
  return {
    [INTERNAL_TIMESTAMP_HEADER]: timestamp,
    [INTERNAL_NONCE_HEADER]: nonce,
    [INTERNAL_SIGNATURE_HEADER]: sign(args.secret, payload),
  };
}

export type VerifyResult = { ok: true } | { ok: false; reason: string };

export function verifyInternalSignature(args: {
  method: string;
  url: string;
  body?: unknown;
  headers: Record<string, string | string[] | undefined>;
  secret: string;
  maxSkewSeconds: number;
}): VerifyResult {
  const timestamp = firstHeader(
    args.headers[INTERNAL_TIMESTAMP_HEADER.toLowerCase()],
  );
  const nonce = firstHeader(args.headers[INTERNAL_NONCE_HEADER.toLowerCase()]);
  const signature = firstHeader(
    args.headers[INTERNAL_SIGNATURE_HEADER.toLowerCase()],
  );
  if (!timestamp || !nonce || !signature) {
    return { ok: false, reason: 'missing_signature_headers' };
  }

  const ts = Number(timestamp);
  if (!Number.isFinite(ts)) {
    return { ok: false, reason: 'invalid_timestamp' };
  }
  const skew = Math.max(30, Math.floor(args.maxSkewSeconds));
  if (Math.abs(Math.floor(Date.now() / 1000) - ts) > skew) {
    return { ok: false, reason: 'timestamp_outside_window' };
  }

  const now = Date.now();
  for (const [key, expiresAt] of nonceCache.entries()) {
    if (expiresAt <= now) nonceCache.delete(key);
  }
  if (nonceCache.has(nonce)) {
    return { ok: false, reason: 'replayed_nonce' };
  }

  const payload = signaturePayload({
    method: args.method,
    path: pathWithQuery(args.url),
    timestamp,
    nonce,
    bodyHash: bodyHash(args.body),
  });
  const expected = sign(args.secret, payload);
  const expectedBuf = Buffer.from(expected);
  const signatureBuf = Buffer.from(signature);
  const valid =
    expectedBuf.length === signatureBuf.length &&
    crypto.timingSafeEqual(expectedBuf, signatureBuf);
  if (!valid) return { ok: false, reason: 'signature_mismatch' };

  nonceCache.set(nonce, now + skew * 1000);
  return { ok: true };
}

function firstHeader(value: string | string[] | undefined): string | undefined {
  return Array.isArray(value) ? value[0] : value;
}

/** Test-only: clears the in-process nonce replay cache between test cases. */
export function clearNonceCacheForTests(): void {
  nonceCache.clear();
}
