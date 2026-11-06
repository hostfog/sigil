import {
  X509Certificate,
  createHash,
  createPrivateKey,
  createPublicKey,
  createSecretKey,
  generateKeyPairSync,
  randomBytes,
  type KeyObject,
} from 'node:crypto';
import { CEK_BYTES, KEK_BYTES, type Algorithm } from './algorithms.js';
import * as b64 from './base64url.js';
import { InvalidKeyError, UnsupportedAlgorithmError } from './errors.js';
import { exportJWK, importJWK, parseJWK, thumbprintInput, type JWK } from './jwk.js';

export type KeyType = 'oct' | 'RSA' | 'EC' | 'OKP';
export type Curve = 'P-256' | 'P-384' | 'P-521' | 'Ed25519' | 'X25519';

export interface KeyOptions {
  kid?: string;
  alg?: Algorithm;
}

const NAMED_CURVES: Record<string, Curve> = {
  prime256v1: 'P-256',
  secp384r1: 'P-384',
  secp521r1: 'P-521',
};

/** A single symmetric or asymmetric key. */
export class Key {
  readonly type: KeyType;
  readonly kid: string | undefined;
  /** The only algorithm this key may be used with, when set. */
  readonly alg: string | undefined;
  readonly curve: Curve | undefined;
  /** @internal */
  readonly object: KeyObject;

  private constructor(object: KeyObject, kid?: string, alg?: string) {
    this.object = object;
    this.kid = kid;
    this.alg = alg;
    [this.type, this.curve] = describe(object);
  }

  /** Imports a JWK given as an object or a JSON string. */
  static fromJWK(jwk: JWK | string, options: KeyOptions = {}): Key {
    const parsed = parseJWK(jwk);
    for (const member of ['kid', 'alg'] as const) {
      if (parsed[member] !== undefined && typeof parsed[member] !== 'string') {
        throw new InvalidKeyError(`JWK member "${member}" must be a string`);
      }
    }
    return new Key(importJWK(parsed), options.kid ?? parsed.kid, options.alg ?? parsed.alg);
  }

  /** Imports a PKCS#8, PKCS#1, SEC1 or SPKI key, or the public key of an X.509 certificate. */
  static fromPEM(pem: string | Buffer, options: KeyOptions = {}): Key {
    const text = pem.toString();
    let object: KeyObject;
    try {
      if (text.includes('PRIVATE KEY-----')) object = createPrivateKey(text);
      else if (text.includes('CERTIFICATE-----')) object = new X509Certificate(text).publicKey;
      else object = createPublicKey(text);
    } catch {
      throw new InvalidKeyError('PEM could not be imported');
    }
    return new Key(object, options.kid, options.alg);
  }

  /** Wraps a symmetric key. Strings are UTF-8 encoded. */
  static secret(bytes: Uint8Array | string, options: KeyOptions = {}): Key {
    const data = typeof bytes === 'string' ? Buffer.from(bytes, 'utf8') : bytes;
    if (data.length === 0) throw new InvalidKeyError('secret must not be empty');
    return new Key(createSecretKey(data), options.kid, options.alg);
  }

  /**
   * Creates a fresh key for `alg`, restricted to that algorithm.
   * `dir` keys are 32 bytes, matching the default `A256GCM`.
   */
  static generate(alg: Algorithm, options: { kid?: string } = {}): Key {
    return new Key(generateFor(alg), options.kid, alg);
  }

  get isPrivate(): boolean {
    return this.object.type !== 'public';
  }

  /** @internal Secret length in bytes, or RSA modulus length in bits. */
  get size(): number {
    return this.object.symmetricKeySize ?? this.object.asymmetricKeyDetails?.modulusLength ?? 0;
  }

  /** The public half of an asymmetric key. */
  publicKey(): Key {
    if (this.type === 'oct') throw new InvalidKeyError('symmetric keys have no public key');
    if (!this.isPrivate) return this;
    return new Key(createPublicKey(this.object), this.kid, this.alg);
  }

  /** Exports the key as a JWK. Symmetric keys need `includePrivate`. */
  toJWK(includePrivate = false): JWK {
    if (this.type === 'oct' && !includePrivate) {
      throw new InvalidKeyError('symmetric keys can only be exported with includePrivate');
    }
    const source = includePrivate ? this : this.publicKey();
    const { kty, ...material } = exportJWK(source.object);
    const jwk: JWK = { kty };
    if (this.kid !== undefined) jwk.kid = this.kid;
    if (this.alg !== undefined) jwk.alg = this.alg;
    return Object.assign(jwk, material);
  }

  /** RFC 7638 JWK thumbprint (SHA-256, base64url). */
  thumbprint(): string {
    const jwk = exportJWK(this.type === 'oct' ? this.object : this.publicKey().object);
    return b64.encode(createHash('sha256').update(thumbprintInput(jwk)).digest());
  }
}

function describe(object: KeyObject): [KeyType, Curve | undefined] {
  if (object.type === 'secret') return ['oct', undefined];
  switch (object.asymmetricKeyType) {
    case 'rsa':
      return ['RSA', undefined];
    case 'ec': {
      const curve = NAMED_CURVES[object.asymmetricKeyDetails?.namedCurve ?? ''];
      if (curve) return ['EC', curve];
      break;
    }
    case 'ed25519':
      return ['OKP', 'Ed25519'];
    case 'x25519':
      return ['OKP', 'X25519'];
  }
  throw new InvalidKeyError('unsupported key type or curve');
}

function generateFor(alg: Algorithm): KeyObject {
  switch (alg) {
    case 'HS256':
    case 'HS384':
    case 'HS512':
      return createSecretKey(randomBytes(Number(alg.slice(2)) / 8));
    case 'dir':
      return createSecretKey(randomBytes(CEK_BYTES.A256GCM));
    case 'A128KW':
    case 'A192KW':
    case 'A256KW':
      return createSecretKey(randomBytes(KEK_BYTES[alg]!));
    case 'ES256':
    case 'ECDH-ES':
    case 'ECDH-ES+A128KW':
    case 'ECDH-ES+A192KW':
    case 'ECDH-ES+A256KW':
      return generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey;
    case 'ES384':
      return generateKeyPairSync('ec', { namedCurve: 'P-384' }).privateKey;
    case 'ES512':
      return generateKeyPairSync('ec', { namedCurve: 'P-521' }).privateKey;
    case 'EdDSA':
      return generateKeyPairSync('ed25519').privateKey;
    case 'RS256':
    case 'RS384':
    case 'RS512':
    case 'PS256':
    case 'PS384':
    case 'PS512':
    case 'RSA-OAEP':
    case 'RSA-OAEP-256':
      return generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey;
    default:
      throw new UnsupportedAlgorithmError(`cannot generate a key for ${String(alg)}`);
  }
}
