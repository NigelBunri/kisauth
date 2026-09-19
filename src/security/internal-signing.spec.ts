import {
  signedInternalHeaders,
  verifyInternalSignature,
  clearNonceCacheForTests,
} from './internal-signing';

const SECRET = 'test-secret-do-not-use-in-prod';

function headersToLowercase(
  headers: Record<string, string>,
): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) out[k.toLowerCase()] = v;
  return out;
}

describe('internal-signing', () => {
  beforeEach(() => clearNonceCacheForTests());

  it('accepts a correctly signed request', () => {
    const headers = signedInternalHeaders({
      method: 'POST',
      url: '/internal/v1/authorization/exchange',
      body: { code: 'abc123' },
      secret: SECRET,
    });
    const result = verifyInternalSignature({
      method: 'POST',
      url: '/internal/v1/authorization/exchange',
      body: { code: 'abc123' },
      headers: headersToLowercase(headers),
      secret: SECRET,
      maxSkewSeconds: 300,
    });
    expect(result.ok).toBe(true);
  });

  it('rejects a request signed with the wrong secret', () => {
    const headers = signedInternalHeaders({
      method: 'POST',
      url: '/internal/v1/authorization/exchange',
      body: { code: 'abc123' },
      secret: 'wrong-secret',
    });
    const result = verifyInternalSignature({
      method: 'POST',
      url: '/internal/v1/authorization/exchange',
      body: { code: 'abc123' },
      headers: headersToLowercase(headers),
      secret: SECRET,
      maxSkewSeconds: 300,
    });
    expect(result).toEqual({ ok: false, reason: 'signature_mismatch' });
  });

  it('rejects a tampered body even with valid headers', () => {
    const headers = signedInternalHeaders({
      method: 'POST',
      url: '/internal/v1/authorization/exchange',
      body: { code: 'abc123' },
      secret: SECRET,
    });
    const result = verifyInternalSignature({
      method: 'POST',
      url: '/internal/v1/authorization/exchange',
      body: { code: 'DIFFERENT-CODE' },
      headers: headersToLowercase(headers),
      secret: SECRET,
      maxSkewSeconds: 300,
    });
    expect(result).toEqual({ ok: false, reason: 'signature_mismatch' });
  });

  it('rejects a replayed nonce even when otherwise valid', () => {
    const headers = signedInternalHeaders({
      method: 'POST',
      url: '/internal/v1/authorization/exchange',
      body: { code: 'abc123' },
      secret: SECRET,
    });
    const lower = headersToLowercase(headers);
    const first = verifyInternalSignature({
      method: 'POST',
      url: '/internal/v1/authorization/exchange',
      body: { code: 'abc123' },
      headers: lower,
      secret: SECRET,
      maxSkewSeconds: 300,
    });
    const second = verifyInternalSignature({
      method: 'POST',
      url: '/internal/v1/authorization/exchange',
      body: { code: 'abc123' },
      headers: lower,
      secret: SECRET,
      maxSkewSeconds: 300,
    });
    expect(first.ok).toBe(true);
    expect(second).toEqual({ ok: false, reason: 'replayed_nonce' });
  });

  it('rejects a timestamp outside the allowed clock-skew window', () => {
    const headers = signedInternalHeaders({
      method: 'GET',
      url: '/.well-known/jwks.json',
      secret: SECRET,
    });
    headers['X-Internal-Timestamp'] = String(
      Math.floor(Date.now() / 1000) - 10_000,
    );
    const result = verifyInternalSignature({
      method: 'GET',
      url: '/.well-known/jwks.json',
      headers: headersToLowercase(headers),
      secret: SECRET,
      maxSkewSeconds: 300,
    });
    expect(result).toEqual({ ok: false, reason: 'timestamp_outside_window' });
  });

  it('rejects requests missing signature headers entirely', () => {
    const result = verifyInternalSignature({
      method: 'POST',
      url: '/internal/v1/authorization/exchange',
      headers: {},
      secret: SECRET,
      maxSkewSeconds: 300,
    });
    expect(result).toEqual({ ok: false, reason: 'missing_signature_headers' });
  });

  it('binds the signature to the exact method and path — a mismatched path fails', () => {
    const headers = signedInternalHeaders({
      method: 'POST',
      url: '/internal/v1/authorization/exchange',
      body: { code: 'abc123' },
      secret: SECRET,
    });
    const result = verifyInternalSignature({
      method: 'POST',
      url: '/internal/v1/link', // different path than what was signed
      body: { code: 'abc123' },
      headers: headersToLowercase(headers),
      secret: SECRET,
      maxSkewSeconds: 300,
    });
    expect(result).toEqual({ ok: false, reason: 'signature_mismatch' });
  });
});
