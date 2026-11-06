from __future__ import annotations

from typing import Any, Dict

import pytest

import sigil
from sigil import Key, KeySet

from .conftest import CLAIMS, INTEROP, NOW, load_key

JWS_CASES = [case for case in INTEROP["cases"] if case["kind"] == "jws"]
JWE_CASES = [case for case in INTEROP["cases"] if case["kind"] == "jwe"]


def _id(case: Dict[str, Any]) -> str:
    return "-".join(filter(None, (case["alg"], case.get("enc"), case["key"])))


@pytest.mark.parametrize("case", JWS_CASES, ids=_id)
def test_jws(case: Dict[str, Any], keys: KeySet) -> None:
    key = load_key(case["key"])
    token = sigil.sign(CLAIMS, key, alg=case["alg"])
    verifier = key if key.type == "oct" else key.public_key()

    result = sigil.verify(token, verifier, issuer="sigil", audience="all", now=NOW)
    assert result.claims == CLAIMS
    assert result.header == {"alg": case["alg"], "typ": "JWT", "kid": case["key"]}
    assert sigil.verify(token, keys, now=NOW).claims == CLAIMS


@pytest.mark.parametrize("case", JWE_CASES, ids=_id)
def test_jwe(case: Dict[str, Any], keys: KeySet) -> None:
    key = load_key(case["key"])
    recipient = key if key.type == "oct" else key.public_key()
    token = sigil.encrypt(CLAIMS, recipient, alg=case["alg"], enc=case["enc"])

    result = sigil.decrypt(token, key, issuer="sigil", audience="all", now=NOW)
    assert result.claims == CLAIMS
    assert result.header["enc"] == case["enc"]
    assert sigil.decrypt(token, keys, now=NOW).claims == CLAIMS


@pytest.mark.parametrize(
    "alg",
    ["HS256", "HS384", "HS512", "RS256", "PS512", "ES256", "ES384", "ES512", "EdDSA"],
)
def test_generated_signing_keys(alg: str) -> None:
    key = Key.generate(alg)
    assert key.alg == alg
    token = sigil.sign({"n": 1}, key)
    assert sigil.decode(token).header["alg"] == alg
    verifier = key if key.type == "oct" else key.public_key()
    assert sigil.verify(token, verifier).claims == {"n": 1}


@pytest.mark.parametrize(
    "alg",
    ["dir", "A128KW", "A192KW", "A256KW", "RSA-OAEP", "RSA-OAEP-256", "ECDH-ES", "ECDH-ES+A256KW"],
)
def test_generated_encryption_keys(alg: str) -> None:
    key = Key.generate(alg)
    recipient = key if key.type == "oct" else key.public_key()
    token = sigil.encrypt({"n": 1}, recipient)
    assert sigil.decrypt(token, key).claims == {"n": 1}


@pytest.mark.parametrize(
    ("kid", "alg"),
    [
        ("oct-hs256", "HS256"),
        ("rsa-2048", "RS256"),
        ("ec-p256", "ES256"),
        ("ec-p384", "ES384"),
        ("ec-p521", "ES512"),
        ("ed25519", "EdDSA"),
    ],
)
def test_default_signing_algorithm(kid: str, alg: str) -> None:
    assert sigil.decode(sigil.sign({}, load_key(kid))).header["alg"] == alg


def test_x25519_cannot_sign() -> None:
    with pytest.raises(sigil.InvalidKeyError):
        sigil.sign({}, load_key("x25519"))


def test_encrypt_needs_alg() -> None:
    key = load_key("oct-a128kw")
    with pytest.raises(sigil.UnsupportedAlgorithmError):
        sigil.encrypt({}, key)
    with pytest.raises(sigil.UnsupportedAlgorithmError):
        sigil.encrypt({}, key, alg="HS256")


def test_encrypt_uses_key_alg() -> None:
    key = Key.secret(b"k" * 16, alg="A128KW")
    token = sigil.encrypt({"a": 1}, key)
    assert sigil.decrypt(token, key).header["alg"] == "A128KW"


def test_header_order_and_extras() -> None:
    key = Key.secret(b"s" * 32, kid="k1")
    token = sigil.sign({}, key, headers={"x5t": "abc", "typ": "at+jwt"})
    assert list(sigil.decode(token).header.items()) == [
        ("alg", "HS256"),
        ("typ", "at+jwt"),
        ("kid", "k1"),
        ("x5t", "abc"),
    ]

    token = sigil.encrypt({}, Key.secret(b"s" * 32), alg="dir", kid="other", typ=None)
    header = sigil.decrypt(token, Key.secret(b"s" * 32)).header
    assert list(header) == ["alg", "enc", "kid"]


def test_protected_headers_are_dropped() -> None:
    key = Key.secret(b"s" * 32)
    extras = {"alg": "none", "enc": "x", "zip": "DEF", "crit": ["x"], "cty": "JWT"}
    assert sigil.verify(sigil.sign({}, key, headers=extras), key).header == {"alg": "HS256", "typ": "JWT", "cty": "JWT"}
    header = sigil.decrypt(sigil.encrypt({}, key, alg="dir", headers=extras), key).header
    assert header == {"alg": "dir", "enc": "A256GCM", "typ": "JWT", "cty": "JWT"}


def test_numbers_round_trip() -> None:
    key = Key.secret(b"s" * 32)
    claims = {"int": 2**70, "float": 1.5, "neg": -3, "nested": {"list": [1, 2.25, None, True]}}
    assert sigil.verify(sigil.sign(claims, key), key).claims == claims
    assert sigil.decrypt(sigil.encrypt(claims, key, alg="dir"), key).claims == claims


def test_decode_skips_checks() -> None:
    token = sigil.sign({"exp": 1}, Key.secret(b"s" * 32))
    assert sigil.decode(token).claims == {"exp": 1}
