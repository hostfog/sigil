import { constants, createPublicKey, privateDecrypt, publicEncrypt, randomBytes } from 'node:crypto';
import * as aeskw from './aeskw.js';
import {
  CEK_BYTES,
  KEK_BYTES,
  assertKeyFits,
  isContentEncryption,
  isJWEAlgorithm,
  type ContentEncryption,
  type JWEAlgorithm,
} from './algorithms.js';
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
  type Header,
} from './compact.js';
import { open, seal } from './content.js';
import { concatKDF, generateEphemeral, sharedSecret } from './ecdh.js';
import { InvalidKeyError, InvalidSignatureError, MalformedTokenError, UnsupportedAlgorithmError } from './errors.js';
import { exportJWK, type JWK } from './jwk.js';
import { isObject, type JSONObject } from './json.js';
import { Key } from './key.js';
import type { KeySet } from './keyset.js';

export interface EncryptOptions {
  /** Required unless the key carries a JWE `alg`. */
  alg?: JWEAlgorithm;
  /** Defaults to `A256GCM`. */
  enc?: ContentEncryption;
  /** Defaults to the key's `kid`. */
  kid?: string;
  /** Defaults to `JWT`. */
  typ?: string;
  /** Extra header parameters. `alg`, `enc`, `zip` and `crit` are ignored. */
  headers?: JSONObject;
}

/** Encrypts `claims` as a compact JWE. */
export function encrypt(claims: Claims, key: Key, options: EncryptOptions = {}): string {
  const alg = options.alg ?? key.alg;
  if (alg === undefined) throw new UnsupportedAlgorithmError('encrypt needs an alg');
  if (!isJWEAlgorithm(alg)) throw new UnsupportedAlgorithmError(`unsupported JWE alg ${alg}`);
  const enc = options.enc ?? 'A256GCM';
  if (!isContentEncryption(enc)) throw new UnsupportedAlgorithmError(`unsupported enc ${String(enc)}`);
  if (!isObject(claims)) throw new MalformedTokenError('claims must be a JSON object');
  assertKeyFits(key, alg, { enc });

  const header = buildHeader({ alg, enc, typ: options.typ, kid: options.kid ?? key.kid }, options.headers);
  const { cek, encryptedKey } = wrapKey(alg, enc, key, header);
  const protectedHeader = b64.encode(JSON.stringify(header));
  const sealed = seal(enc, cek, Buffer.from(JSON.stringify(claims)), Buffer.from(protectedHeader, 'ascii'));

  return [protectedHeader, ...[encryptedKey, sealed.iv, sealed.ciphertext, sealed.tag].map(b64.encode)].join('.');
}

/** Decrypts a compact JWE and verifies its claims. */
export function decrypt(token: string, keyOrKeySet: Key | KeySet, options: VerifyOptions = {}): DecodedToken {
  const [encodedHeader, ...rest] = split(token, 5) as [string, string, string, string, string];
  const header = parseHeader(encodedHeader);
  const [encryptedKey, iv, ciphertext, tag] = rest.map(b64.decode) as [Buffer, Buffer, Buffer, Buffer];

  checkHeader(header, isJWEAlgorithm, options.algorithms);
  if (typeof header.enc !== 'string') throw new MalformedTokenError('header has no enc');
  if (!isContentEncryption(header.enc)) throw new UnsupportedAlgorithmError(`unsupported enc ${header.enc}`);
  const alg = header.alg as JWEAlgorithm;
  const enc = header.enc;
  const epk = alg.startsWith('ECDH-ES') ? parseEphemeral(header.epk) : undefined;
  const keys = selectKeys(keyOrKeySet, header, (key) => {
    assertKeyFits(key, alg, { enc, needsPrivate: true });
    if (epk && epk.curve !== key.curve) throw new InvalidKeyError('key curve does not match the epk');
  });
  const recipient: Recipient = { alg, enc, header, encryptedKey, epk };

  const aad = Buffer.from(encodedHeader, 'ascii');
  let plaintext: Buffer | undefined;
  for (const key of keys) {
    try {
      plaintext = open(enc, unwrapKey(key, recipient), { iv, ciphertext, tag }, aad);
      break;
    } catch (error) {
      if (!(error instanceof InvalidSignatureError)) throw error;
    }
  }
  if (!plaintext) throw new InvalidSignatureError('decryption failed');

  const claims = parseClaims(plaintext);
  validateClaims(claims, header, options);
  return { header, claims };
}

function wrapKey(alg: JWEAlgorithm, enc: ContentEncryption, key: Key, header: Header) {
  const empty = Buffer.alloc(0);
  if (alg === 'dir') return { cek: key.object.export(), encryptedKey: empty };

  const cek = randomBytes(CEK_BYTES[enc]);
  switch (alg) {
    case 'A128KW':
    case 'A192KW':
    case 'A256KW':
      return { cek, encryptedKey: aeskw.wrap(key.object.export(), cek) };
    case 'RSA-OAEP':
    case 'RSA-OAEP-256':
      return { cek, encryptedKey: publicEncrypt(oaep(alg, key), cek) };
  }

  const ephemeral = generateEphemeral(key.curve!);
  header.epk = exportJWK(createPublicKey(ephemeral));
  const z = sharedSecret(ephemeral, key.publicKey().object);
  if (alg === 'ECDH-ES') return { cek: ecdhKey(z, enc, CEK_BYTES[enc], header), encryptedKey: empty };
  return { cek, encryptedKey: aeskw.wrap(ecdhKey(z, alg, KEK_BYTES[alg]!, header), cek) };
}

interface Recipient {
  alg: JWEAlgorithm;
  enc: ContentEncryption;
  header: Header;
  encryptedKey: Buffer;
  epk: Key | undefined;
}

function unwrapKey(key: Key, { alg, enc, header, encryptedKey, epk }: Recipient): Buffer {
  const directKey = alg === 'dir' || alg === 'ECDH-ES';
  if (directKey && encryptedKey.length > 0) throw new MalformedTokenError(`${alg} tokens have no encrypted key`);

  switch (alg) {
    case 'dir':
      return key.object.export();
    case 'A128KW':
    case 'A192KW':
    case 'A256KW':
      return unwrapChecked(key.object.export(), encryptedKey);
    case 'RSA-OAEP':
    case 'RSA-OAEP-256':
      // RFC 7516 §11.5: a failed RSA decryption continues with a random key so it looks like a bad tag.
      try {
        return privateDecrypt(oaep(alg, key), encryptedKey);
      } catch {
        return randomBytes(CEK_BYTES[enc]);
      }
  }

  let z: Buffer;
  try {
    z = sharedSecret(key.object, epk!.object);
  } catch {
    throw new InvalidSignatureError('decryption failed');
  }
  if (alg === 'ECDH-ES') return ecdhKey(z, enc, CEK_BYTES[enc], header);
  return unwrapChecked(ecdhKey(z, alg, KEK_BYTES[alg]!, header), encryptedKey);
}

function unwrapChecked(kek: Buffer, encryptedKey: Buffer): Buffer {
  try {
    return aeskw.unwrap(kek, encryptedKey);
  } catch {
    throw new InvalidSignatureError('decryption failed');
  }
}

function oaep(alg: 'RSA-OAEP' | 'RSA-OAEP-256', key: Key) {
  return {
    key: key.object,
    padding: constants.RSA_PKCS1_OAEP_PADDING,
    oaepHash: alg === 'RSA-OAEP' ? 'sha1' : 'sha256',
  };
}

function parseEphemeral(epk: unknown): Key {
  if (!isObject(epk)) throw new MalformedTokenError('header has no epk');
  try {
    return Key.fromJWK(epk as JWK).publicKey();
  } catch {
    throw new MalformedTokenError('header has an invalid epk');
  }
}

function ecdhKey(z: Buffer, algorithmId: string, bytes: number, header: Header): Buffer {
  return concatKDF(z, algorithmId, bytes, partyInfo(header, 'apu'), partyInfo(header, 'apv'));
}

function partyInfo(header: Header, name: 'apu' | 'apv'): Buffer {
  const value = header[name];
  if (value === undefined) return Buffer.alloc(0);
  if (typeof value !== 'string') throw new MalformedTokenError(`header ${name} must be a string`);
  return b64.decode(value);
}
