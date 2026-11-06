import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createPrivateKey, createPublicKey, generateKeyPairSync } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import {
  JWE_ALGORITHMS,
  JWS_ALGORITHMS,
  Key,
  KeySet,
  decode,
  decrypt,
  encrypt,
  sign,
  verify,
} from '../dist/index.js';
import { code, key, keys, readTestdata, vectors } from './fixtures.js';

const claims = { sub: 'alice' };

describe('Key', () => {
  it('computes the RFC 7638 thumbprint', () => {
    const { key: jwk, thumbprint } = vectors.rfc7638_thumbprint;
    assert.equal(Key.fromJWK(jwk).thumbprint(), thumbprint);
    assert.equal(Key.fromJWK(JSON.stringify(jwk)).thumbprint(), thumbprint);
  });

  it('uses the public key for thumbprints', () => {
    const rsa = key('rsa-2048');
    assert.equal(rsa.thumbprint(), rsa.publicKey().thumbprint());
  });

  it('describes keys', () => {
    const cases: [string, string, string | undefined][] = [
      ['oct-hs256', 'oct', undefined],
      ['rsa-2048', 'RSA', undefined],
      ['ec-p521', 'EC', 'P-521'],
      ['ed25519', 'OKP', 'Ed25519'],
      ['x25519', 'OKP', 'X25519'],
    ];
    for (const [kid, type, curve] of cases) {
      const k = key(kid);
      assert.deepEqual([k.type, k.curve, k.kid, k.isPrivate], [type, curve, kid, true]);
    }
    const pub = key('ec-p256').publicKey();
    assert.equal(pub.isPrivate, false);
    assert.equal(pub.kid, 'ec-p256');
    assert.equal(pub.publicKey(), pub);
  });

  it('exports JWKs', () => {
    const jwks = JSON.parse(readTestdata('keys.json')).keys;
    for (const jwk of jwks) {
      const k = Key.fromJWK(jwk);
      assert.deepEqual(k.toJWK(true), jwk);
      if (k.type === 'oct') {
        assert.equal(code(() => k.toJWK()), 'invalid_key');
      } else {
        const { d, p, q, dp, dq, qi, ...pub } = jwk;
        assert.deepEqual(k.toJWK(), pub);
      }
    }
  });

  it('lets options override kid and alg', () => {
    const k = Key.fromJWK({ kty: 'oct', kid: 'a', k: key('oct-hs256').toJWK(true).k! }, { kid: 'b', alg: 'HS256' });
    assert.deepEqual([k.kid, k.alg], ['b', 'HS256']);
    assert.deepEqual(Object.keys(k.toJWK(true)), ['kty', 'kid', 'alg', 'k']);
  });

  it('rejects bad JWKs', () => {
    assert.equal(code(() => Key.fromJWK('{')), 'invalid_key');
    assert.equal(code(() => Key.fromJWK({ kty: 'oct', k: 'a+b' })), 'invalid_key');
    assert.equal(code(() => Key.fromJWK({ kty: 'EC', crv: 'secp256k1', x: 'AA', y: 'AA' })), 'invalid_key');
    assert.equal(code(() => Key.fromJWK({ kty: 'EC', crv: 'P-256', x: 'AA', y: 'AA' })), 'invalid_key');
    assert.equal(code(() => Key.fromJWK({ kty: 'foo' })), 'invalid_key');
    assert.equal(code(() => Key.secret('')), 'invalid_key');
    assert.equal(code(() => key('oct-hs256').publicKey()), 'invalid_key');
  });

  it('encodes string secrets as UTF-8', () => {
    assert.equal(Key.secret('héllo').toJWK(true).k, Buffer.from('héllo').toString('base64url'));
  });

  it('generates a usable key for every algorithm', () => {
    for (const alg of JWS_ALGORITHMS) {
      const k = Key.generate(alg, { kid: 'g' });
      assert.equal(k.alg, alg);
      assert.equal(k.kid, 'g');
      assert.deepEqual(verify(sign(claims, k), k).claims, claims);
    }
    for (const alg of JWE_ALGORITHMS) {
      const k = Key.generate(alg);
      assert.deepEqual(decrypt(encrypt(claims, k), k).claims, claims);
    }
    assert.equal(code(() => Key.generate('none' as never)), 'unsupported_alg');
  });
});

describe('PEM', () => {
  const rsa = key('rsa-2048');

  it('loads the shared PKCS#8 and SPKI files', () => {
    const priv = Key.fromPEM(readTestdata('rsa-2048.pem'));
    const pub = Key.fromPEM(readTestdata('rsa-2048.pub.pem'), { kid: 'pem' });
    assert.equal(priv.isPrivate, true);
    assert.equal(pub.isPrivate, false);
    assert.equal(pub.kid, 'pem');
    assert.equal(priv.thumbprint(), rsa.thumbprint());
    assert.deepEqual(verify(sign(claims, priv), pub).claims, claims);
  });

  it('loads PKCS#1 and SEC1 keys', () => {
    const object = createPrivateKey({ key: rsa.toJWK(true) as never, format: 'jwk' });
    const pkcs1 = Key.fromPEM(object.export({ type: 'pkcs1', format: 'pem' }));
    const pkcs1Public = Key.fromPEM(createPublicKey(object).export({ type: 'pkcs1', format: 'pem' }));
    assert.equal(pkcs1.thumbprint(), rsa.thumbprint());
    assert.equal(pkcs1Public.thumbprint(), rsa.thumbprint());

    const ec = key('ec-p384');
    const sec1 = createPrivateKey({ key: ec.toJWK(true) as never, format: 'jwk' }).export({ type: 'sec1', format: 'pem' });
    const loaded = Key.fromPEM(sec1);
    assert.deepEqual([loaded.type, loaded.curve, loaded.isPrivate], ['EC', 'P-384', true]);
    assert.equal(loaded.thumbprint(), ec.thumbprint());
  });

  it('loads OKP keys', () => {
    const { privateKey, publicKey } = generateKeyPairSync('ed25519');
    const priv = Key.fromPEM(privateKey.export({ type: 'pkcs8', format: 'pem' }));
    const pub = Key.fromPEM(publicKey.export({ type: 'spki', format: 'pem' }));
    assert.deepEqual(verify(sign(claims, priv), pub).claims, claims);
  });

  it('loads the public key of a certificate', () => {
    const dir = mkdtempSync(join(tmpdir(), 'sigil-'));
    try {
      const cert = join(dir, 'cert.pem');
      const keyFile = fileURLToPath(new URL('../../testdata/rsa-2048.pem', import.meta.url));
      execFileSync('openssl', ['req', '-x509', '-new', '-key', keyFile, '-subj', '/CN=sigil', '-days', '1', '-out', cert]);
      const pub = Key.fromPEM(readFileSync(cert));
      assert.equal(pub.isPrivate, false);
      assert.equal(pub.thumbprint(), rsa.thumbprint());
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('rejects garbage and unsupported key types', () => {
    assert.equal(code(() => Key.fromPEM('nope')), 'invalid_key');
    const { privateKey } = generateKeyPairSync('ed448');
    assert.equal(code(() => Key.fromPEM(privateKey.export({ type: 'pkcs8', format: 'pem' }))), 'invalid_key');
  });
});

describe('KeySet', () => {
  it('skips unsupported key types and curves', () => {
    const set = KeySet.fromJSON({
      keys: [
        { kty: 'oct', kid: 'a', k: key('oct-hs256').toJWK(true).k! },
        { kty: 'PQC', kid: 'b' },
        { kty: 'OKP', crv: 'Ed448', kid: 'c', x: 'AA' },
      ],
    });
    assert.deepEqual(set.keys.map((k) => k.kid), ['a']);
    assert.equal(code(() => KeySet.fromJSON('{"keys": 1}')), 'invalid_key');
  });

  it('selects the key named by kid', () => {
    const token = sign(claims, key('ec-p256'));
    assert.deepEqual(verify(token, keys).claims, claims);
    const other = sign(claims, key('ec-p256'), { kid: 'missing' });
    assert.equal(code(() => verify(other, keys)), 'key_not_found');
    const wrongKid = sign(claims, key('ec-p256'), { kid: 'ec-p384' });
    assert.equal(code(() => verify(wrongKid, keys)), 'invalid_key');
  });

  it('tries every fitting key when the token has no kid', () => {
    const second = Key.generate('ES256');
    const set = new KeySet([Key.generate('ES256'), key('rsa-2048'), second.publicKey()]);
    const token = sign(claims, second);
    assert.equal(decode(token).header.kid, undefined);
    assert.deepEqual(verify(token, set).claims, claims);
    assert.equal(code(() => verify(sign(claims, Key.generate('ES256')), set)), 'invalid_signature');
    assert.equal(code(() => verify(sign(claims, Key.generate('ES384')), set)), 'key_not_found');

    const jweSet = new KeySet([key('x25519'), key('ec-p256')]);
    const recipient = Key.fromJWK({ ...key('ec-p256').toJWK(), kid: undefined });
    const jwe = encrypt(claims, recipient, { alg: 'ECDH-ES' });
    assert.equal(JSON.parse(Buffer.from(jwe.split('.')[0]!, 'base64url').toString()).kid, undefined);
    assert.deepEqual(decrypt(jwe, jweSet).claims, claims);
  });

  it('exports public JWKS without secrets', () => {
    const set = new KeySet([key('oct-hs256'), key('ec-p256')]).add(key('ed25519'));
    assert.deepEqual(set.toJSON().keys.map((k) => k.kid), ['ec-p256', 'ed25519']);
    assert.equal(set.toJSON().keys[0]!.d, undefined);
    assert.equal(set.toJSON(true).keys.length, 3);
    assert.equal(JSON.parse(JSON.stringify(set)).keys.length, 2);
    assert.equal(set.get('ed25519')?.curve, 'Ed25519');
  });
});
