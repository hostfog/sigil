import { createPrivateKey, createPublicKey, createSecretKey, type KeyObject } from 'node:crypto';
import * as b64 from './base64url.js';
import { InvalidKeyError } from './errors.js';
import { isObject } from './json.js';

/** A JSON Web Key (RFC 7517). Unknown members are allowed and ignored. */
export interface JWK {
  kty: string;
  kid?: string;
  alg?: string;
  crv?: string;
  k?: string;
  n?: string;
  e?: string;
  x?: string;
  y?: string;
  d?: string;
  p?: string;
  q?: string;
  dp?: string;
  dq?: string;
  qi?: string;
  [member: string]: unknown;
}

const MEMBERS: Record<string, readonly string[]> = {
  oct: ['k'],
  RSA: ['n', 'e', 'd', 'p', 'q', 'dp', 'dq', 'qi'],
  EC: ['crv', 'x', 'y', 'd'],
  OKP: ['crv', 'x', 'd'],
};

// RFC 7638 §3.2: the required public members, in lexicographic order.
const THUMBPRINT_MEMBERS: Record<string, readonly string[]> = {
  oct: ['k', 'kty'],
  RSA: ['e', 'kty', 'n'],
  EC: ['crv', 'kty', 'x', 'y'],
  OKP: ['crv', 'kty', 'x'],
};

const CURVES: Record<string, readonly string[]> = {
  EC: ['P-256', 'P-384', 'P-521'],
  OKP: ['Ed25519', 'X25519'],
};

export function parseJWK(input: JWK | string): JWK {
  let jwk: unknown = input;
  if (typeof input === 'string') {
    try {
      jwk = JSON.parse(input);
    } catch {
      throw new InvalidKeyError('JWK is not valid JSON');
    }
  }
  if (!isObject(jwk) || typeof jwk.kty !== 'string') throw new InvalidKeyError('JWK needs a kty');
  return jwk as JWK;
}

/** True when Sigil understands the key's `kty` and `crv`. */
export function isSupportedJWK(jwk: JWK): boolean {
  if (!(jwk.kty in MEMBERS)) return false;
  const curves = CURVES[jwk.kty];
  return !curves || curves.includes(jwk.crv as string);
}

export function importJWK(jwk: JWK): KeyObject {
  if (!isSupportedJWK(jwk)) throw new InvalidKeyError('unsupported key type or curve');

  const material: Record<string, unknown> = { kty: jwk.kty };
  for (const name of MEMBERS[jwk.kty]!) {
    const value = jwk[name];
    if (value === undefined) continue;
    if (typeof value !== 'string') throw new InvalidKeyError(`JWK member "${name}" must be a string`);
    material[name] = value;
  }

  try {
    if (jwk.kty === 'oct') return createSecretKey(b64.decode((material.k as string | undefined) ?? ''));
    const input = { key: material, format: 'jwk' as const };
    return material.d === undefined ? createPublicKey(input) : createPrivateKey(input);
  } catch {
    throw new InvalidKeyError('JWK could not be imported');
  }
}

export function exportJWK(object: KeyObject): JWK {
  if (object.type === 'secret') return { kty: 'oct', k: b64.encode(object.export()) };
  return object.export({ format: 'jwk' }) as JWK;
}

export function thumbprintInput(jwk: JWK): string {
  const members = THUMBPRINT_MEMBERS[jwk.kty]!;
  return JSON.stringify(Object.fromEntries(members.map((name) => [name, jwk[name]])));
}
