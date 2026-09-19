import { randomBytes, createHash } from 'crypto';

export function generateState(): string {
  return randomBytes(32).toString('base64url');
}

export function generateNonce(): string {
  return randomBytes(32).toString('base64url');
}

export function generateCodeVerifier(): string {
  // RFC 7636: 43-128 characters from the unreserved URL-safe alphabet.
  return randomBytes(64).toString('base64url');
}

export function codeChallengeS256(codeVerifier: string): string {
  return createHash('sha256').update(codeVerifier).digest('base64url');
}
