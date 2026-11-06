import { MalformedTokenError } from './errors.js';

const ALPHABET = /^[A-Za-z0-9_-]*$/;

export function encode(data: Uint8Array | string): string {
  return Buffer.from(data).toString('base64url');
}

/** Strict decode: Buffer's own decoder silently skips characters outside the alphabet. */
export function decode(value: string): Buffer {
  if (!ALPHABET.test(value) || value.length % 4 === 1) {
    throw new MalformedTokenError('invalid base64url');
  }
  return Buffer.from(value, 'base64url');
}
