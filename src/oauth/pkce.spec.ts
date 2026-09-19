import {
  generateState,
  generateNonce,
  generateCodeVerifier,
  codeChallengeS256,
} from './pkce';
import { createHash } from 'crypto';

describe('pkce', () => {
  it('generates state/nonce/verifier with sufficient entropy and no collisions across many calls', () => {
    const seen = new Set<string>();
    for (let i = 0; i < 1000; i++) {
      const s = generateState();
      const n = generateNonce();
      const v = generateCodeVerifier();
      expect(s.length).toBeGreaterThanOrEqual(32);
      expect(n.length).toBeGreaterThanOrEqual(32);
      expect(v.length).toBeGreaterThanOrEqual(43); // RFC 7636 minimum
      for (const val of [s, n, v]) {
        expect(seen.has(val)).toBe(false);
        seen.add(val);
      }
    }
  });

  it('computes the S256 code challenge as the base64url-SHA256 of the verifier, per RFC 7636', () => {
    const verifier = generateCodeVerifier();
    const expected = createHash('sha256').update(verifier).digest('base64url');
    expect(codeChallengeS256(verifier)).toBe(expected);
  });

  it('produces a different challenge for a different verifier (no fixed/degenerate output)', () => {
    const a = codeChallengeS256(generateCodeVerifier());
    const b = codeChallengeS256(generateCodeVerifier());
    expect(a).not.toBe(b);
  });
});
