import assert from 'node:assert/strict';
import { createPrivateKey, generateKeyPairSync, sign as cryptoSign } from 'node:crypto';
import { describe, it } from 'node:test';
import { Key, decode, sign, verify, type JWSAlgorithm } from '../dist/index.js';
import { code, encodeJSON, flip, interop, key, vectors, withPart } from './fixtures.js';

const claims = { sub: 'alice', n: 1 };

describe('JWS', () => {
  it('verifies the RFC 7515 A.1 example', () => {
    const { key: jwk, token, now, claims: expected } = vectors.rfc7515_a1;
    const result = verify(token, Key.fromJWK(jwk), { now });
    assert.deepEqual(result.claims, expected);
    assert.equal(result.header.alg, 'HS256');
  });

  for (const c of interop.cases.filter((c) => c.kind === 'jws')) {
    it(`round trips ${c.alg} with ${c.key}`, () => {
      const alg = c.alg as JWSAlgorithm;
      const token = sign(interop.claims, key(c.key), { alg });
      const result = verify(token, key(c.key).type === 'oct' ? key(c.key) : key(c.key).publicKey(), {
        algorithms: [alg],
      });
      assert.deepEqual(result.claims, interop.claims);
      assert.deepEqual(result.header, { alg, typ: 'JWT', kid: c.key });
    });
  }

  it('picks the default algorithm from the key', () => {
    const cases: [string, string][] = [
      ['oct-hs256', 'HS256'],
      ['rsa-2048', 'RS256'],
      ['ec-p256', 'ES256'],
      ['ec-p384', 'ES384'],
      ['ec-p521', 'ES512'],
      ['ed25519', 'EdDSA'],
    ];
    for (const [kid, alg] of cases) assert.equal(decode(sign(claims, key(kid))).header.alg, alg);
    assert.equal(decode(sign(claims, Key.generate('PS384'))).header.alg, 'PS384');
  });

  it('writes the header in order and keeps reserved names', () => {
    const token = sign(claims, key('oct-hs256'), {
      kid: 'other',
      typ: 'at+jwt',
      headers: { alg: 'none', crit: ['x'], zip: 'DEF', enc: 'A256GCM', cty: 'x' },
    });
    const header = JSON.parse(Buffer.from(token.split('.')[0]!, 'base64url').toString());
    assert.deepEqual(Object.entries(header), [['alg', 'HS256'], ['typ', 'at+jwt'], ['kid', 'other'], ['cty', 'x']]);
  });

  it('rejects malformed tokens', () => {
    const k = key('oct-hs256');
    const token = sign(claims, k);
    assert.equal(code(() => verify('a.b', k)), 'malformed');
    assert.equal(code(() => verify(`${token}.x`, k)), 'malformed');
    assert.equal(code(() => verify(withPart(token, 0, 'e30+'), k)), 'malformed');
    assert.equal(code(() => verify(withPart(token, 0, encodeJSON([1])), k)), 'malformed');
    assert.equal(code(() => verify(withPart(token, 1, encodeJSON('x')), k)), 'malformed');
    assert.equal(code(() => decode('x.y.z')), 'malformed');
  });

  it('rejects none in any casing', () => {
    const body = encodeJSON(claims);
    for (const alg of ['none', 'None', 'NONE']) {
      assert.equal(code(() => verify(`${encodeJSON({ alg })}.${body}.`, key('oct-hs256'))), 'unsupported_alg');
    }
    assert.equal(code(() => sign(claims, key('oct-hs256'), { alg: 'none' as JWSAlgorithm })), 'unsupported_alg');
  });

  it('rejects crit and zip headers', () => {
    const k = key('oct-hs256');
    assert.equal(code(() => verify(withPart(sign(claims, k), 0, encodeJSON({ alg: 'HS256', crit: ['exp'] })), k)), 'unsupported_alg');
    assert.equal(code(() => verify(withPart(sign(claims, k), 0, encodeJSON({ alg: 'HS256', zip: 'DEF' })), k)), 'unsupported_alg');
  });

  it('rejects algorithms outside the allowed list', () => {
    const token = sign(claims, key('rsa-2048'), { alg: 'PS256' });
    assert.equal(code(() => verify(token, key('rsa-2048'), { algorithms: ['RS256'] })), 'unsupported_alg');
    const restricted = Key.fromJWK(key('rsa-2048').toJWK(), { alg: 'RS256' });
    assert.equal(code(() => verify(token, restricted)), 'invalid_key');
  });

  it('rejects HS256 signed with an RSA public key as the secret', () => {
    const rsa = key('rsa-2048').publicKey();
    const forged = sign(claims, Key.secret(JSON.stringify(rsa.toJWK())), { alg: 'HS256' });
    assert.equal(code(() => verify(forged, rsa)), 'invalid_key');
    assert.equal(code(() => verify(forged, rsa, { algorithms: ['HS256'] })), 'invalid_key');
  });

  it('rejects keys that do not match the algorithm', () => {
    assert.equal(code(() => sign(claims, key('oct-hs256'), { alg: 'RS256' })), 'invalid_key');
    assert.equal(code(() => sign(claims, key('ec-p384'), { alg: 'ES256' })), 'invalid_key');
    assert.equal(code(() => sign(claims, key('x25519'), { alg: 'EdDSA' })), 'invalid_key');
    assert.equal(code(() => sign(claims, key('x25519'))), 'invalid_key');
    assert.equal(code(() => verify(sign(claims, key('ec-p256')), key('ec-p384'))), 'invalid_key');
  });

  it('rejects short HMAC keys', () => {
    assert.equal(code(() => sign(claims, Key.secret('too short'))), 'invalid_key');
    assert.equal(code(() => sign(claims, key('oct-hs256'), { alg: 'HS384' })), 'invalid_key');
    const token = sign(claims, key('oct-hs256'));
    assert.equal(code(() => verify(token, Key.secret(Buffer.alloc(31)))), 'invalid_key');
  });

  it('rejects RSA keys under 2048 bits', () => {
    const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 1024 });
    const weak = Key.fromJWK(privateKey.export({ format: 'jwk' }) as never);
    assert.equal(code(() => sign(claims, weak)), 'invalid_key');
    const token = `${encodeJSON({ alg: 'RS256' })}.${encodeJSON(claims)}`;
    const signature = cryptoSign('sha256', Buffer.from(token), privateKey).toString('base64url');
    assert.equal(code(() => verify(`${token}.${signature}`, weak.publicKey())), 'invalid_key');
  });

  it('needs a private key to sign', () => {
    assert.equal(code(() => sign(claims, key('ec-p256').publicKey())), 'invalid_key');
  });

  it('rejects tampered signatures and payloads', () => {
    for (const kid of ['oct-hs256', 'rsa-2048', 'ec-p256', 'ed25519']) {
      const k = key(kid);
      const token = sign(claims, k);
      assert.equal(code(() => verify(withPart(token, 2, flip(token.split('.')[2]!)), k)), 'invalid_signature');
      assert.equal(code(() => verify(withPart(token, 1, encodeJSON({ sub: 'mallory' })), k)), 'invalid_signature');
    }
  });

  it('rejects DER encoded ECDSA signatures', () => {
    const k = key('ec-p256');
    const input = `${encodeJSON({ alg: 'ES256' })}.${encodeJSON(claims)}`;
    const privateKey = createPrivateKey({ key: k.toJWK(true) as never, format: 'jwk' });
    const der = cryptoSign('sha256', Buffer.from(input), privateKey).toString('base64url');
    assert.equal(code(() => verify(`${input}.${der}`, k)), 'invalid_signature');
  });
});
