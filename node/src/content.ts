import {
  createCipheriv,
  createDecipheriv,
  createHmac,
  randomBytes,
  timingSafeEqual,
  type CipherGCMTypes,
} from 'node:crypto';
import type { ContentEncryption } from './algorithms.js';
import { InvalidSignatureError } from './errors.js';

export interface Sealed {
  iv: Buffer;
  ciphertext: Buffer;
  tag: Buffer;
}

export function seal(enc: ContentEncryption, cek: Buffer, plaintext: Buffer, aad: Buffer): Sealed {
  if (isGCM(enc)) {
    const iv = randomBytes(12);
    const cipher = createCipheriv(gcm(cek), cek, iv, { authTagLength: 16 });
    cipher.setAAD(aad);
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    return { iv, ciphertext, tag: cipher.getAuthTag() };
  }

  const { macKey, encKey } = splitKey(cek);
  const iv = randomBytes(16);
  const cipher = createCipheriv(`aes-${encKey.length * 8}-cbc`, encKey, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return { iv, ciphertext, tag: cbcTag(macKey, aad, iv, ciphertext) };
}

/** Throws InvalidSignatureError when the content does not authenticate. */
export function open(enc: ContentEncryption, cek: Buffer, sealed: Sealed, aad: Buffer): Buffer {
  const { iv, ciphertext, tag } = sealed;
  try {
    if (isGCM(enc)) {
      // setAuthTag accepts truncated tags, so the length is checked here.
      if (iv.length !== 12 || tag.length !== 16) throw new InvalidSignatureError();
      const decipher = createDecipheriv(gcm(cek), cek, iv, { authTagLength: 16 });
      decipher.setAAD(aad);
      decipher.setAuthTag(tag);
      return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    }

    const { macKey, encKey } = splitKey(cek);
    const expected = cbcTag(macKey, aad, iv, ciphertext);
    if (iv.length !== 16 || tag.length !== expected.length || !timingSafeEqual(tag, expected)) {
      throw new InvalidSignatureError();
    }
    const decipher = createDecipheriv(`aes-${encKey.length * 8}-cbc`, encKey, iv);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch {
    throw new InvalidSignatureError('decryption failed');
  }
}

function isGCM(enc: ContentEncryption): boolean {
  return enc.endsWith('GCM');
}

function gcm(cek: Buffer): CipherGCMTypes {
  return `aes-${cek.length * 8}-gcm` as CipherGCMTypes;
}

// RFC 7518 §5.2.2.1: the first half of the key is the MAC key, the second the AES key.
function splitKey(cek: Buffer): { macKey: Buffer; encKey: Buffer } {
  const half = cek.length / 2;
  return { macKey: cek.subarray(0, half), encKey: cek.subarray(half) };
}

function cbcTag(macKey: Buffer, aad: Buffer, iv: Buffer, ciphertext: Buffer): Buffer {
  const aadBits = Buffer.alloc(8);
  aadBits.writeBigUInt64BE(BigInt(aad.length) * 8n);
  return createHmac(`sha${macKey.length * 16}`, macKey)
    .update(aad)
    .update(iv)
    .update(ciphertext)
    .update(aadBits)
    .digest()
    .subarray(0, macKey.length);
}
