import assert from 'node:assert/strict';
import { createPrivateKey, createPublicKey } from 'node:crypto';
import { describe, it } from 'node:test';
import { Key, decrypt, encrypt, type ContentEncryption, type JWEAlgorithm } from '../dist/index.js';
import { unwrap, wrap } from '../dist/aeskw.js';
import { concatKDF, sharedSecret } from '../dist/ecdh.js';
import { code, encodeJSON, flip, interop, key, withPart } from './fixtures.js';

const claims = { sub: 'alice', n: 1 };

function header(token: string): Record<string, unknown> {
  return JSON.parse(Buffer.from(token.split('.')[0]!, 'base64url').toString());
}

describe('JWE', () => {
  for (const c of interop.cases.filter((c) => c.kind === 'jwe')) {
    it(`round trips ${c.alg} ${c.enc} with ${c.key}`, () => {
      const alg = c.alg as JWEAlgorithm;
      const k = key(c.key);
      const recipient = k.type === 'oct' ? k : k.publicKey();
      const token = encrypt(interop.claims, recipient, { alg, enc: c.enc });
      const result = decrypt(token, k, { algorithms: [alg] });
      assert.deepEqual(result.claims, interop.claims);
      assert.equal(result.header.alg, alg);
      assert.equal(result.header.enc, c.enc);
      assert.equal(result.header.kid, c.key);
    });
  }

  it('defaults enc to A256GCM and alg to the key alg', () => {
    const k = Key.generate('RSA-OAEP-256');
    const h = header(encrypt(claims, k));
    assert.deepEqual([h.alg, h.enc, h.typ], ['RSA-OAEP-256', 'A256GCM', 'JWT']);
  });

  it('needs an explicit alg when the key has no JWE alg', () => {
    assert.equal(code(() => encrypt(claims, key('rsa-2048'))), 'unsupported_alg');
    assert.equal(code(() => encrypt(claims, Key.generate('ES256'))), 'unsupported_alg');
  });

  it('puts only the public ephemeral key in epk', () => {
    const epk = header(encrypt(claims, key('ec-p256'), { alg: 'ECDH-ES' })).epk as Record<string, unknown>;
    assert.deepEqual(Object.keys(epk).sort(), ['crv', 'kty', 'x', 'y']);
  });

  it('feeds apu and apv into the key derivation', () => {
    const k = key('x25519');
    const token = encrypt(claims, k, { alg: 'ECDH-ES', headers: { apu: 'QWxpY2U', apv: 'Qm9i' } });
    assert.deepEqual(decrypt(token, k).claims, claims);
    const h = header(token);
    // Changing apv alters the derived key, so the tag no longer matches.
    assert.equal(code(() => decrypt(withPart(token, 0, encodeJSON({ ...h, apv: 'Qm9j' })), k)), 'invalid_signature');
  });

  it('rejects wrong key lengths', () => {
    assert.equal(code(() => encrypt(claims, key('dir-a128gcm'), { alg: 'dir' })), 'invalid_key');
    assert.equal(code(() => encrypt(claims, key('dir-a256gcm'), { alg: 'dir', enc: 'A128GCM' })), 'invalid_key');
    assert.equal(code(() => encrypt(claims, key('oct-a256kw'), { alg: 'A128KW' })), 'invalid_key');
    const token = encrypt(claims, key('dir-a128gcm'), { alg: 'dir', enc: 'A128GCM' });
    assert.equal(code(() => decrypt(token, key('dir-a256gcm'))), 'invalid_key');
  });

  it('rejects keys that do not match the algorithm', () => {
    assert.equal(code(() => encrypt(claims, key('ed25519'), { alg: 'ECDH-ES' })), 'invalid_key');
    assert.equal(code(() => encrypt(claims, key('ec-p256'), { alg: 'RSA-OAEP' })), 'invalid_key');
    assert.equal(code(() => encrypt(claims, key('rsa-2048'), { alg: 'A128KW' })), 'invalid_key');
    const token = encrypt(claims, key('ec-p256'), { alg: 'ECDH-ES' });
    assert.equal(code(() => decrypt(token, key('ec-p384'))), 'invalid_key');
  });

  it('needs a private key to decrypt', () => {
    const k = key('rsa-2048');
    const token = encrypt(claims, k, { alg: 'RSA-OAEP' });
    assert.equal(code(() => decrypt(token, k.publicKey())), 'invalid_key');
  });

  it('rejects unsupported and disallowed headers', () => {
    const k = key('oct-a128kw');
    const token = encrypt(claims, k, { alg: 'A128KW' });
    const h = header(token);
    assert.equal(code(() => decrypt(withPart(token, 0, encodeJSON({ ...h, zip: 'DEF' })), k)), 'unsupported_alg');
    assert.equal(code(() => decrypt(withPart(token, 0, encodeJSON({ ...h, crit: ['x'] })), k)), 'unsupported_alg');
    assert.equal(code(() => decrypt(withPart(token, 0, encodeJSON({ ...h, enc: 'A128CTR' })), k)), 'unsupported_alg');
    assert.equal(code(() => decrypt(withPart(token, 0, encodeJSON({ ...h, alg: 'none' })), k)), 'unsupported_alg');
    assert.equal(code(() => decrypt(token, k, { algorithms: ['A256KW'] })), 'unsupported_alg');
    assert.equal(code(() => encrypt(claims, k, { alg: 'A128KW', enc: 'A128CTR' as ContentEncryption })), 'unsupported_alg');
    assert.equal(code(() => decrypt(token.split('.').slice(0, 3).join('.'), k)), 'malformed');
  });

  it('rejects tampered tokens', () => {
    const cases: [string, JWEAlgorithm, ContentEncryption][] = [
      ['dir-a256gcm', 'dir', 'A256GCM'],
      ['dir-a128cbc-hs256', 'dir', 'A128CBC-HS256'],
      ['oct-a128kw', 'A128KW', 'A128CBC-HS256'],
      ['rsa-2048', 'RSA-OAEP-256', 'A256GCM'],
      ['ec-p256', 'ECDH-ES+A128KW', 'A128GCM'],
    ];
    for (const [kid, alg, enc] of cases) {
      const k = key(kid);
      const token = encrypt(claims, k, { alg, enc });
      const parts = token.split('.');
      for (const index of [2, 3, 4]) {
        assert.equal(code(() => decrypt(withPart(token, index, flip(parts[index]!)), k)), 'invalid_signature');
      }
      assert.equal(code(() => decrypt(withPart(token, 4, parts[4]!.slice(0, 8)), k)), 'invalid_signature');
      if (parts[1]) {
        assert.equal(code(() => decrypt(withPart(token, 1, flip(parts[1]!)), k)), 'invalid_signature');
      }
      const otherHeader = encodeJSON({ ...header(token), typ: 'other' });
      assert.equal(code(() => decrypt(withPart(token, 0, otherHeader), k)), 'invalid_signature');
    }
  });

  it('wraps keys per the RFC 3394 4.1 vector', () => {
    const kek = Buffer.from('000102030405060708090A0B0C0D0E0F', 'hex');
    const cek = Buffer.from('00112233445566778899AABBCCDDEEFF', 'hex');
    const wrapped = wrap(kek, cek);
    assert.equal(wrapped.toString('hex').toUpperCase(), '1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5');
    assert.deepEqual(unwrap(kek, wrapped), cek);
  });

  it('derives the RFC 7518 C key with Concat KDF', () => {
    const alice = createPrivateKey({
      format: 'jwk',
      key: {
        kty: 'EC',
        crv: 'P-256',
        x: 'gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0',
        y: 'SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps',
        d: '0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo',
      },
    });
    const bob = createPublicKey({
      format: 'jwk',
      key: {
        kty: 'EC',
        crv: 'P-256',
        x: 'weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ',
        y: 'e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck',
      },
    });
    const z = sharedSecret(alice, bob);
    const derived = concatKDF(z, 'A128GCM', 16, Buffer.from('Alice'), Buffer.from('Bob'));
    assert.equal(derived.toString('base64url'), 'VqqN6vgjbSBcIijNcacQGg');
  });
});
