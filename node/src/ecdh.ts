import { createHash, diffieHellman, generateKeyPairSync, type KeyObject } from 'node:crypto';
import type { Curve } from './key.js';

export function generateEphemeral(curve: Curve): KeyObject {
  return curve === 'X25519'
    ? generateKeyPairSync('x25519').privateKey
    : generateKeyPairSync('ec', { namedCurve: curve }).privateKey;
}

export function sharedSecret(privateKey: KeyObject, publicKey: KeyObject): Buffer {
  return diffieHellman({ privateKey, publicKey });
}

/** Concat KDF with SHA-256 (NIST SP 800-56A), as profiled by RFC 7518 §4.6.2. */
export function concatKDF(z: Buffer, algorithmId: string, keyBytes: number, apu: Buffer, apv: Buffer): Buffer {
  const otherInfo = Buffer.concat([
    lengthPrefixed(Buffer.from(algorithmId, 'ascii')),
    lengthPrefixed(apu),
    lengthPrefixed(apv),
    uint32(keyBytes * 8),
  ]);
  const blocks: Buffer[] = [];
  for (let counter = 1; blocks.length * 32 < keyBytes; counter++) {
    blocks.push(createHash('sha256').update(uint32(counter)).update(z).update(otherInfo).digest());
  }
  return Buffer.concat(blocks).subarray(0, keyBytes);
}

function lengthPrefixed(data: Buffer): Buffer {
  return Buffer.concat([uint32(data.length), data]);
}

function uint32(value: number): Buffer {
  const out = Buffer.alloc(4);
  out.writeUInt32BE(value);
  return out;
}
