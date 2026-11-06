# Sigil specification

Sigil is one JWT library with the same API and behaviour in Go, TypeScript (Node), PHP and Python.
This file is the contract every implementation follows. Names below are shown in camelCase;
each language uses its own convention (Go `PascalCase` exports, Python `snake_case`).

## Standards

- RFC 7515 (JWS), RFC 7516 (JWE), RFC 7517 (JWK), RFC 7518 (JWA), RFC 7519 (JWT)
- RFC 7638 (JWK thumbprint), RFC 8037 (OKP keys: Ed25519, X25519), RFC 8725 (JWT best practice)
- Compact serialization only.

## Algorithms

JWS: `HS256 HS384 HS512 RS256 RS384 RS512 PS256 PS384 PS512 ES256 ES384 ES512 EdDSA`

- `EdDSA` means Ed25519.
- ECDSA signatures use the raw `r || s` format (fixed length per curve), never DER.
- PS* use MGF1 with the same hash and salt length equal to the hash size.

JWE `alg`: `dir A128KW A192KW A256KW RSA-OAEP RSA-OAEP-256 ECDH-ES ECDH-ES+A128KW ECDH-ES+A192KW ECDH-ES+A256KW`

JWE `enc`: `A128GCM A192GCM A256GCM A128CBC-HS256 A192CBC-HS384 A256CBC-HS512`

- ECDH-ES curves: P-256, P-384, P-521, X25519. Concat KDF per RFC 7518 §4.6.2 with SHA-256;
  `apu`/`apv` are read from the header when present (empty otherwise).
  AlgorithmID is the `enc` value for direct ECDH-ES and the `alg` value for the key-wrap variants.
- AES key wrap is RFC 3394 (default IV `A6A6A6A6A6A6A6A6`).
- CBC-HMAC tag check must be constant time.
- `zip` is not supported; a token with `zip` is rejected.

`none` is never supported, in any form or casing.

## Keys

`Key` wraps one key. Constructors:

| name | input |
|---|---|
| `Key.fromJWK(jwk)` | object or JSON string |
| `Key.fromPEM(pem)` | PKCS#8, PKCS#1 RSA, SEC1 EC private keys, SPKI public keys, X.509 certificate |
| `Key.secret(bytes)` | symmetric key; strings are UTF-8 encoded |
| `Key.generate(alg)` | fresh key suited to a JWS or JWE algorithm name |

Properties / methods: `type` (`oct`, `RSA`, `EC`, `OKP`), `kid`, `alg`, `curve`, `isPrivate`,
`publicKey()`, `toJWK(includePrivate = false)`, `thumbprint()` (RFC 7638, SHA-256, base64url).
Optional constructor options: `kid`, `alg`.

Default algorithm for `sign` when none is given: the key's `alg` if set, else
oct → `HS256`, RSA → `RS256`, EC P-256 → `ES256`, P-384 → `ES384`, P-521 → `ES512`, Ed25519 → `EdDSA`.

`encrypt` needs an explicit `alg` unless the key carries a JWE `alg`; `enc` defaults to `A256GCM`.

Key rules (reject with `InvalidKeyError`):

- HMAC key shorter than the hash output (32/48/64 bytes) is rejected.
- RSA modulus under 2048 bits is rejected.
- Algorithm must match key type and curve (no HS with an RSA key, no ES256 with P-384, ...).
- Signing / decrypting needs a private key (or secret).
- Exact key length for `dir` (16/24/32/32/48/64 per enc) and AxxxKW (16/24/32).

`KeySet` holds many keys (a JWKS): `KeySet.fromJSON(jwks)`, `add(key)`, `get(kid)`, `keys`,
`toJSON(includePrivate = false)`. Unknown `kty` entries in a JWKS are skipped, not fatal.

## Tokens

```
sign(claims, key, { alg, kid, typ = "JWT", headers })            -> string
verify(token, keyOrKeySet, options)                              -> { header, claims }
encrypt(claims, key, { alg, enc = "A256GCM", kid, typ = "JWT", headers }) -> string
decrypt(token, keyOrKeySet, options)                             -> { header, claims }
decode(token)                                                    -> { header, claims }  // no checks
```

- `kid` defaults to the key's `kid`. Extra `headers` cannot override `alg`, `enc`, `zip`, `crit`.
- Header JSON order: `alg`, then `enc` (JWE), `typ`, `kid`, then extras. Not required for interop.
- Payload is a JSON object. Number types round-trip as JSON numbers.

### Verify / decrypt options

| option | meaning |
|---|---|
| `algorithms` | allowed `alg` list. Default: the key's `alg` if set, else every alg valid for that key type. |
| `issuer` | string or list; `iss` must equal one |
| `audience` | string or list; `aud` (string or array) must contain one |
| `subject` | exact `sub` |
| `typ` | exact header `typ` (case-insensitive) |
| `leeway` | seconds, default 0, applied to `exp`, `nbf`, `iat` |
| `maxAge` | seconds; requires `iat`, rejects if `now - iat > maxAge + leeway` |
| `required` | claim names that must be present |
| `now` | override current time (unix seconds) |

Checks, in order: format → header (`alg` allowed, no `crit`, no `zip`) → key selection →
signature / decryption → claims.

Claims rules: `exp` → reject when `now >= exp + leeway`. `nbf` → reject when `now < nbf - leeway`.
`iat` in the future beyond leeway → reject. `exp`, `nbf`, `iat` must be numbers when present.

Key selection with a `KeySet`: header `kid` → that key (missing → `KeyNotFoundError`).
No `kid` → try each key compatible with `alg`; first that verifies wins.

## Errors

One base type `SigilError`, with these subtypes. Each carries a stable `code`.

| type | code |
|---|---|
| `MalformedTokenError` | `malformed` |
| `UnsupportedAlgorithmError` | `unsupported_alg` |
| `InvalidKeyError` | `invalid_key` |
| `KeyNotFoundError` | `key_not_found` |
| `InvalidSignatureError` | `invalid_signature` (also failed JWE decryption) |
| `TokenExpiredError` | `expired` |
| `TokenNotYetValidError` | `not_yet_valid` |
| `InvalidClaimError` | `invalid_claim` (field: `claim`) |

Messages never contain key material or token contents.

Which error applies where:

- `alg` not in `algorithms`, unknown `enc`, any `crit` or `zip` header → `unsupported_alg`.
- Key cannot be used with the algorithm (type, curve, length, its own `alg`, public-only for
  sign/decrypt), ECDH-ES key on a different curve from `epk` → `invalid_key`.
  A key's own `alg` is always enforced, even when `algorithms` is given.
- `encrypt` without `alg` and the key has no JWE `alg` → `unsupported_alg`.
- `iat` in the future, `maxAge` without `iat`, `iss`/`aud`/`sub` missing or wrong when that option
  is set, header `typ` mismatch → `invalid_claim` naming the claim (`typ` for the header).
  Token older than `maxAge` → `expired`.
- Missing/invalid `epk`, `decode()` given a JWE → `malformed`.
- RSA-OAEP unwrap failure continues with a random CEK (RFC 7516 §11.5) → `invalid_signature`.

Other details:

- `headers` may override `typ` and `kid`; `alg`, `enc`, `zip`, `crit` in `headers` are dropped.
- `toJWK()` of a symmetric key without `includePrivate` → `invalid_key`;
  `KeySet.toJSON()` without `includePrivate` leaves symmetric keys out.
- `KeySet.fromJSON` also skips unsupported curves.
- `Key.generate(alg)` binds the key to `alg`; a `dir` key is 32 bytes.
- In interop output, JWS entries have no `enc` field.

## Shared test data (`testdata/`)

- `keys.json` — JWKS of fixed keys used by every implementation's tests.
- `rsa-2048.pem`, `rsa-2048.pub.pem` — same RSA key as PEM.
- `vectors.json` — RFC 7515 A.1 HS256 token (verify with `now`), RFC 7638 thumbprint.
- `interop.json` — cases + claims for cross-language tests.

## Interop contract

Each implementation ships `interop` entry point with two commands:

```
gen   <out.json>   # for every case in testdata/interop.json, produce a token
check <in.json>    # verify/decrypt every token, compare claims, exit 1 on any failure
```

`out.json` is `[{"kind","alg","enc","key","token"}]`. `check` uses `now = 1800000000`,
`issuer = "sigil"`, `audience = "all"`, and checks claims deep-equal `interop.json` claims.
`interop/run.sh` runs every `gen` against every `check`.
