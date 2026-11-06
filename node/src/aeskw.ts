import { createCipheriv, createDecipheriv } from 'node:crypto';

// RFC 3394 default initial value. OpenSSL's id-aes*-wrap ciphers implement the algorithm itself.
const IV = Buffer.from('A6A6A6A6A6A6A6A6', 'hex');

export function wrap(kek: Buffer, cek: Buffer): Buffer {
  const cipher = createCipheriv(`id-aes${kek.length * 8}-wrap`, kek, IV);
  return Buffer.concat([cipher.update(cek), cipher.final()]);
}

/** Throws when the integrity check fails. */
export function unwrap(kek: Buffer, wrapped: Buffer): Buffer {
  const decipher = createDecipheriv(`id-aes${kek.length * 8}-wrap`, kek, IV);
  return Buffer.concat([decipher.update(wrapped), decipher.final()]);
}
