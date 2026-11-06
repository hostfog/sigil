import { readFileSync } from 'node:fs';
import { KeySet, type Claims, type ContentEncryption, type JWEAlgorithm, type JWSAlgorithm, type Key } from '../dist/index.js';

const testdata = new URL('../../testdata/', import.meta.url);

export function readTestdata(name: string): string {
  return readFileSync(new URL(name, testdata), 'utf8');
}

export interface InteropCase {
  kind: 'jws' | 'jwe';
  alg: JWSAlgorithm | JWEAlgorithm;
  enc?: ContentEncryption;
  key: string;
}

export const interop: { claims: Claims; cases: InteropCase[] } = JSON.parse(readTestdata('interop.json'));
export const vectors = JSON.parse(readTestdata('vectors.json'));
export const keys = KeySet.fromJSON(readTestdata('keys.json'));

export function key(kid: string): Key {
  const found = keys.get(kid);
  if (!found) throw new Error(`missing test key ${kid}`);
  return found;
}

/** Returns the `code` of the error thrown by `fn`. */
export function code(fn: () => unknown): string {
  try {
    fn();
  } catch (error) {
    return (error as { code: string }).code;
  }
  return 'no error';
}

/** Replaces one segment of a compact token. */
export function withPart(token: string, index: number, value: string): string {
  const parts = token.split('.');
  parts[index] = value;
  return parts.join('.');
}

/** Flips the first bit of a base64url segment's decoded bytes. */
export function flip(segment: string): string {
  const bytes = Buffer.from(segment, 'base64url');
  bytes[0]! ^= 1;
  return bytes.toString('base64url');
}

export function encodeJSON(value: unknown): string {
  return Buffer.from(JSON.stringify(value)).toString('base64url');
}
