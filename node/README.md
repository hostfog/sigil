# @hostfog/sigil

JWT, JWS, JWE and JWK for Node.js 18+, built on `node:crypto` with no runtime dependencies.
Behaviour is shared with the Go, PHP and Python versions; see [SPEC.md](../SPEC.md).

```sh
npm install @hostfog/sigil
```

## Sign and verify

```ts
import { Key, sign, verify } from '@hostfog/sigil';

const key = Key.generate('ES256', { kid: 'main' });
const token = sign({ sub: 'alice', iss: 'sigil', exp: Math.floor(Date.now() / 1000) + 3600 }, key);

const { claims } = verify(token, key.publicKey(), { issuer: 'sigil', leeway: 30 });
```

## Encrypt and decrypt

```ts
import { Key, decrypt, encrypt } from '@hostfog/sigil';

const key = Key.fromPEM(privatePem);
const token = encrypt({ sub: 'alice' }, key.publicKey(), { alg: 'RSA-OAEP-256', enc: 'A256GCM' });

const { claims } = decrypt(token, key);
```

## JWKS

```ts
import { KeySet, verify } from '@hostfog/sigil';

const jwks = KeySet.fromJSON(await (await fetch('https://example.com/.well-known/jwks.json')).text());
const { header, claims } = verify(token, jwks, { algorithms: ['RS256'], audience: 'api' });
```

The token's `kid` picks the key; without a `kid`, every key that fits the algorithm is tried.

Errors extend `SigilError` and carry a stable `code` such as `expired` or `invalid_signature`.

## Development

```sh
npm test                          # build, then run the test suite
node interop.mjs gen out.json     # cross-language tokens for testdata/interop.json
node interop.mjs check out.json
```
