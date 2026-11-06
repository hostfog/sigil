import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  InvalidClaimError,
  SigilError,
  TokenExpiredError,
  decrypt,
  encrypt,
  sign,
  verify,
  type Claims,
  type VerifyOptions,
} from '../dist/index.js';
import { code, key } from './fixtures.js';

const now = 1_800_000_000;
const k = key('oct-hs256');

function check(claims: Claims, options: VerifyOptions = {}, typ?: string): string {
  return code(() => verify(sign(claims, k, { typ }), k, { now, ...options }));
}

function claimOf(claims: Claims, options: VerifyOptions): string | undefined {
  try {
    verify(sign(claims, k), k, { now, ...options });
  } catch (error) {
    return error instanceof InvalidClaimError ? error.claim : undefined;
  }
  return undefined;
}

describe('claims', () => {
  it('checks exp', () => {
    assert.equal(check({ exp: now + 1 }), 'no error');
    assert.equal(check({ exp: now }), 'expired');
    assert.equal(check({ exp: now }, { leeway: 1 }), 'no error');
    assert.equal(check({ exp: now - 1 }, { leeway: 1 }), 'expired');
  });

  it('checks nbf', () => {
    assert.equal(check({ nbf: now }), 'no error');
    assert.equal(check({ nbf: now + 1 }), 'not_yet_valid');
    assert.equal(check({ nbf: now + 5 }, { leeway: 5 }), 'no error');
  });

  it('rejects iat in the future beyond leeway', () => {
    assert.equal(check({ iat: now }), 'no error');
    assert.equal(check({ iat: now + 1 }), 'invalid_claim');
    assert.equal(check({ iat: now + 1 }, { leeway: 1 }), 'no error');
    assert.equal(claimOf({ iat: now + 1 }, {}), 'iat');
  });

  it('requires numeric dates', () => {
    for (const name of ['exp', 'nbf', 'iat']) {
      assert.equal(claimOf({ [name]: String(now) }, {}), name);
    }
  });

  it('checks maxAge', () => {
    assert.equal(check({ iat: now - 60 }, { maxAge: 60 }), 'no error');
    assert.equal(check({ iat: now - 61 }, { maxAge: 60 }), 'expired');
    assert.equal(check({ iat: now - 61 }, { maxAge: 60, leeway: 1 }), 'no error');
    assert.equal(claimOf({}, { maxAge: 60 }), 'iat');
  });

  it('checks required claims', () => {
    assert.equal(check({ jti: 'x' }, { required: ['jti'] }), 'no error');
    assert.equal(claimOf({}, { required: ['jti'] }), 'jti');
  });

  it('checks issuer', () => {
    assert.equal(check({ iss: 'a' }, { issuer: 'a' }), 'no error');
    assert.equal(check({ iss: 'b' }, { issuer: ['a', 'b'] }), 'no error');
    assert.equal(claimOf({ iss: 'c' }, { issuer: ['a', 'b'] }), 'iss');
    assert.equal(claimOf({}, { issuer: 'a' }), 'iss');
  });

  it('checks audience as a string or a list', () => {
    assert.equal(check({ aud: 'a' }, { audience: 'a' }), 'no error');
    assert.equal(check({ aud: ['x', 'a'] }, { audience: 'a' }), 'no error');
    assert.equal(check({ aud: 'b' }, { audience: ['a', 'b'] }), 'no error');
    assert.equal(claimOf({ aud: ['x', 'y'] }, { audience: ['a', 'b'] }), 'aud');
    assert.equal(claimOf({ aud: 1 }, { audience: 'a' }), 'aud');
    assert.equal(claimOf({}, { audience: 'a' }), 'aud');
  });

  it('checks subject', () => {
    assert.equal(check({ sub: 'a' }, { subject: 'a' }), 'no error');
    assert.equal(claimOf({ sub: 'b' }, { subject: 'a' }), 'sub');
  });

  it('checks typ case-insensitively', () => {
    assert.equal(check({}, { typ: 'jwt' }), 'no error');
    assert.equal(check({}, { typ: 'at+jwt' }, 'AT+JWT'), 'no error');
    assert.equal(claimOf({}, { typ: 'at+jwt' }), 'typ');
  });

  it('applies the same rules to JWE', () => {
    const dir = key('dir-a256gcm');
    const token = encrypt({ exp: now }, dir, { alg: 'dir' });
    assert.equal(code(() => decrypt(token, dir, { now })), 'expired');
  });

  it('throws typed errors', () => {
    try {
      verify(sign({ exp: now }, k), k, { now });
      assert.fail('expected an error');
    } catch (error) {
      assert.ok(error instanceof TokenExpiredError);
      assert.ok(error instanceof SigilError);
      assert.equal(error.name, 'TokenExpiredError');
    }
  });

  it('round trips JSON number types', () => {
    const claims = { int: 1, float: 1.5, negative: -2, big: 2 ** 53 - 1, nested: { list: [0, 0.25] } };
    assert.deepEqual(verify(sign(claims, k), k).claims, claims);
  });
});
