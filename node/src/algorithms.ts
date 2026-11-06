import { InvalidKeyError, UnsupportedAlgorithmError } from './errors.js';
import type { Curve, Key } from './key.js';

export const JWS_ALGORITHMS = [
  'HS256', 'HS384', 'HS512',
  'RS256', 'RS384', 'RS512',
  'PS256', 'PS384', 'PS512',
  'ES256', 'ES384', 'ES512',
  'EdDSA',
] as const;

export const JWE_ALGORITHMS = [
  'dir',
  'A128KW', 'A192KW', 'A256KW',
  'RSA-OAEP', 'RSA-OAEP-256',
  'ECDH-ES', 'ECDH-ES+A128KW', 'ECDH-ES+A192KW', 'ECDH-ES+A256KW',
] as const;

export const CONTENT_ENCRYPTIONS = [
  'A128GCM', 'A192GCM', 'A256GCM',
  'A128CBC-HS256', 'A192CBC-HS384', 'A256CBC-HS512',
] as const;

export type JWSAlgorithm = (typeof JWS_ALGORITHMS)[number];
export type JWEAlgorithm = (typeof JWE_ALGORITHMS)[number];
export type ContentEncryption = (typeof CONTENT_ENCRYPTIONS)[number];
export type Algorithm = JWSAlgorithm | JWEAlgorithm;

export function isJWSAlgorithm(value: unknown): value is JWSAlgorithm {
  return (JWS_ALGORITHMS as readonly unknown[]).includes(value);
}

export function isJWEAlgorithm(value: unknown): value is JWEAlgorithm {
  return (JWE_ALGORITHMS as readonly unknown[]).includes(value);
}

export function isContentEncryption(value: unknown): value is ContentEncryption {
  return (CONTENT_ENCRYPTIONS as readonly unknown[]).includes(value);
}

export function hashOf(alg: Exclude<JWSAlgorithm, 'EdDSA'>): 'sha256' | 'sha384' | 'sha512' {
  switch (alg.slice(2)) {
    case '256': return 'sha256';
    case '384': return 'sha384';
    default: return 'sha512';
  }
}

const EC_CURVES: Record<'ES256' | 'ES384' | 'ES512', Curve> = {
  ES256: 'P-256',
  ES384: 'P-384',
  ES512: 'P-521',
};

/** Key length in bytes for each content encryption (CBC-HMAC keys hold both halves). */
export const CEK_BYTES: Record<ContentEncryption, number> = {
  'A128GCM': 16,
  'A192GCM': 24,
  'A256GCM': 32,
  'A128CBC-HS256': 32,
  'A192CBC-HS384': 48,
  'A256CBC-HS512': 64,
};

export const KEK_BYTES: Record<string, number> = {
  'A128KW': 16,
  'A192KW': 24,
  'A256KW': 32,
  'ECDH-ES+A128KW': 16,
  'ECDH-ES+A192KW': 24,
  'ECDH-ES+A256KW': 32,
};

const ECDH_CURVES: readonly Curve[] = ['P-256', 'P-384', 'P-521', 'X25519'];

interface Use {
  enc?: ContentEncryption;
  needsPrivate?: boolean;
}

/** Throws InvalidKeyError unless `key` may be used with `alg` (and `enc` for `dir`). */
export function assertKeyFits(key: Key, alg: Algorithm, use: Use = {}): void {
  const problem = keyProblem(key, alg, use.enc);
  if (problem) throw new InvalidKeyError(problem);
  if (use.needsPrivate && !key.isPrivate) throw new InvalidKeyError(`${alg} needs a private key`);
}

function keyProblem(key: Key, alg: Algorithm, enc?: ContentEncryption): string | undefined {
  if (key.alg !== undefined && key.alg !== alg) return `key is restricted to ${key.alg}`;

  switch (alg) {
    case 'HS256':
    case 'HS384':
    case 'HS512': {
      const min = Number(alg.slice(2)) / 8;
      if (key.type !== 'oct') return `${alg} needs a symmetric key`;
      if (key.size < min) return `${alg} needs a key of at least ${min} bytes`;
      return undefined;
    }
    case 'dir': {
      if (!enc) throw new UnsupportedAlgorithmError('dir needs an enc');
      return exactSecret(key, alg, CEK_BYTES[enc]);
    }
    case 'A128KW':
    case 'A192KW':
    case 'A256KW':
      return exactSecret(key, alg, KEK_BYTES[alg]!);
    case 'ES256':
    case 'ES384':
    case 'ES512':
      return key.curve === EC_CURVES[alg] ? undefined : `${alg} needs a ${EC_CURVES[alg]} key`;
    case 'EdDSA':
      return key.curve === 'Ed25519' ? undefined : 'EdDSA needs an Ed25519 key';
    case 'ECDH-ES':
    case 'ECDH-ES+A128KW':
    case 'ECDH-ES+A192KW':
    case 'ECDH-ES+A256KW':
      return key.curve && ECDH_CURVES.includes(key.curve)
        ? undefined
        : `${alg} needs a P-256, P-384, P-521 or X25519 key`;
    default:
      if (key.type !== 'RSA') return `${alg} needs an RSA key`;
      if (key.size < 2048) return 'RSA keys must be at least 2048 bits';
      return undefined;
  }
}

function exactSecret(key: Key, alg: string, bytes: number): string | undefined {
  if (key.type !== 'oct') return `${alg} needs a symmetric key`;
  if (key.size !== bytes) return `${alg} needs a key of exactly ${bytes} bytes`;
  return undefined;
}
