# hostfog-sigil

JWT, JWS, JWE and JWK for Python 3.10+, built on [cryptography](https://cryptography.io).
Part of [Sigil](../README.md); behaviour is defined in [SPEC.md](../SPEC.md).

```sh
pip install hostfog-sigil
```

## Sign and verify

```python
import time
import sigil

key = sigil.Key.secret(b"a secret of at least thirty-two bytes")
token = sigil.sign({"sub": "42", "aud": "api", "exp": int(time.time()) + 3600}, key)

claims = sigil.verify(token, key, audience="api").claims
```

Asymmetric keys load from PEM or JWK:

```python
private = sigil.Key.from_pem(open("rsa.pem").read(), kid="2026-01")
token = sigil.sign({"sub": "42"}, private, alg="PS256")
sigil.verify(token, private.public_key(), algorithms=["PS256"], issuer="https://id.example")
```

## Encrypt and decrypt

```python
key = sigil.Key.generate("ECDH-ES+A256KW")
token = sigil.encrypt({"card": "4242"}, key.public_key(), enc="A256GCM")
claims = sigil.decrypt(token, key).claims
```

## JWKS

```python
keys = sigil.KeySet.from_json(jwks_text)          # unsupported entries are skipped
token = sigil.verify(token, keys, issuer="https://id.example", audience="api")

published = sigil.KeySet([signing_key]).to_json()  # public keys only
```

With a `KeySet`, the header `kid` picks the key; without one, every key compatible with the
`alg` is tried.

## Errors

Everything raised is a `sigil.SigilError` with a stable `code`: `MalformedTokenError`,
`UnsupportedAlgorithmError`, `InvalidKeyError`, `KeyNotFoundError`, `InvalidSignatureError`,
`TokenExpiredError`, `TokenNotYetValidError` and `InvalidClaimError` (which has `.claim`).

## Development

```sh
pip install -e '.[test]'
pytest
mypy
python interop.py gen out.json && python interop.py check out.json
```

`interop.py` puts `src/` on `sys.path` itself, so it runs without installing the package.
