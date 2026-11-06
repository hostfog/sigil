import {
  constants,
  createHmac,
  sign as cryptoSign,
  timingSafeEqual,
  verify as cryptoVerify,
  type SignKeyObjectInput,
} from 'node:crypto';
import { assertKeyFits, hashOf, isJWSAlgorithm, type JWSAlgorithm } from './algorithms.js';
import * as b64 from './base64url.js';
import { validateClaims, type VerifyOptions } from './claims.js';
import {
  buildHeader,
  checkHeader,
  parseClaims,
  parseHeader,
  selectKeys,
  split,
  type Claims,
  type DecodedToken,
} from './compact.js';
import { InvalidKeyError, InvalidSignatureError, MalformedTokenError, UnsupportedAlgorithmError } from './errors.js';
import { isObject, type JSONObject } from './json.js';
import type { Key } from './key.js';
import type { KeySet } from './keyset.js';

export interface SignOptions {
  /** Defaults to the key's `alg`, then to the usual algorithm for the key type. */
  alg?: JWSAlgorithm;
  /** Defaults to the key's `kid`. */
  kid?: string;
  /** Defaults to `JWT`. */
  typ?: string;
  /** Extra header parameters. `alg`, `enc`, `zip` and `crit` are ignored. */
  headers?: JSONObject;
}

const ECDSA_SIGNATURE_BYTES: Record<string, number> = { ES256: 64, ES384: 96, ES512: 132 };

/** Signs `claims` as a compact JWS. */
export function sign(claims: Claims, key: Key, options: SignOptions = {}): string {
  const alg = options.alg ?? key.alg ?? defaultAlgorithm(key);
  if (!isJWSAlgorithm(alg)) throw new UnsupportedAlgorithmError(`unsupported JWS alg ${alg}`);
  if (!isObject(claims)) throw new MalformedTokenError('claims must be a JSON object');
  assertKeyFits(key, alg, { needsPrivate: true });

  const header = buildHeader({ alg, typ: options.typ, kid: options.kid ?? key.kid }, options.headers);
  const input = `${b64.encode(JSON.stringify(header))}.${b64.encode(JSON.stringify(claims))}`;
  return `${input}.${b64.encode(signBytes(alg, key, Buffer.from(input)))}`;
}

/** Verifies a compact JWS and its claims. */
export function verify(token: string, keyOrKeySet: Key | KeySet, options: VerifyOptions = {}): DecodedToken {
  const [encodedHeader, encodedPayload, encodedSignature] = split(token, 3) as [string, string, string];
  const header = parseHeader(encodedHeader);
  const claims = parseClaims(b64.decode(encodedPayload));
  const signature = b64.decode(encodedSignature);

  checkHeader(header, isJWSAlgorithm, options.algorithms);
  const alg = header.alg as JWSAlgorithm;
  const keys = selectKeys(keyOrKeySet, header, (key) => assertKeyFits(key, alg));

  const input = Buffer.from(`${encodedHeader}.${encodedPayload}`);
  if (!keys.some((key) => verifyBytes(alg, key, input, signature))) throw new InvalidSignatureError();

  validateClaims(claims, header, options);
  return { header, claims };
}

function defaultAlgorithm(key: Key): JWSAlgorithm {
  switch (key.curve ?? key.type) {
    case 'oct': return 'HS256';
    case 'RSA': return 'RS256';
    case 'P-256': return 'ES256';
    case 'P-384': return 'ES384';
    case 'P-521': return 'ES512';
    case 'Ed25519': return 'EdDSA';
    default: throw new InvalidKeyError('key cannot sign');
  }
}

function signBytes(alg: JWSAlgorithm, key: Key, data: Buffer): Buffer {
  if (alg === 'EdDSA') return cryptoSign(null, data, key.object);
  if (alg.startsWith('HS')) return createHmac(hashOf(alg), key.object).update(data).digest();
  return cryptoSign(hashOf(alg), data, signingInput(alg, key));
}

function verifyBytes(alg: JWSAlgorithm, key: Key, data: Buffer, signature: Buffer): boolean {
  if (alg.startsWith('HS')) {
    const expected = signBytes(alg, key, data);
    return expected.length === signature.length && timingSafeEqual(expected, signature);
  }
  // Node accepts some non-canonical ECDSA lengths; JWS fixes them per curve.
  if (alg in ECDSA_SIGNATURE_BYTES && signature.length !== ECDSA_SIGNATURE_BYTES[alg]) return false;
  try {
    if (alg === 'EdDSA') return cryptoVerify(null, data, key.object, signature);
    return cryptoVerify(hashOf(alg), data, signingInput(alg, key), signature);
  } catch {
    return false;
  }
}

function signingInput(alg: Exclude<JWSAlgorithm, 'EdDSA'>, key: Key): SignKeyObjectInput {
  if (alg.startsWith('ES')) return { key: key.object, dsaEncoding: 'ieee-p1363' };
  if (alg.startsWith('PS')) {
    return { key: key.object, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: constants.RSA_PSS_SALTLEN_DIGEST };
  }
  return { key: key.object, padding: constants.RSA_PKCS1_PADDING };
}
