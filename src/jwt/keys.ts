import {
  generateKeyPairSync,
  KeyObject,
  createPrivateKey,
  createPublicKey,
} from 'crypto';
import { importJWK, exportJWK, type JWK } from 'jose';

/** PEM values in env files often arrive with literal "\n" sequences
 * instead of real newlines (common when copy-pasting into a .env or a
 * secrets-manager UI). Normalize both forms. */
function normalizePem(pem: string): string {
  return pem.includes('\\n') ? pem.replace(/\\n/g, '\n') : pem;
}

export interface KeyPairPem {
  privateKeyPem: string;
  publicKeyPem: string;
}

export function generateRs256KeyPairPem(): KeyPairPem {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', {
    modulusLength: 2048,
  });
  return {
    privateKeyPem: privateKey
      .export({ type: 'pkcs8', format: 'pem' })
      .toString(),
    publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
  };
}

export function loadPrivateKey(pem: string): KeyObject {
  return createPrivateKey(normalizePem(pem));
}

export function loadPublicKey(pem: string): KeyObject {
  return createPublicKey(normalizePem(pem));
}

export async function publicKeyToJwk(
  publicKeyPem: string,
  kid: string,
): Promise<JWK> {
  const keyObject = loadPublicKey(publicKeyPem);
  const jwk = await exportJWK(keyObject);
  return { ...jwk, kid, alg: 'RS256', use: 'sig' };
}

export async function jwkToPublicKeyLike(jwk: JWK) {
  return importJWK(jwk, 'RS256');
}
