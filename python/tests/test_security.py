from __future__ import annotations

from typing import Type

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

import sigil
from sigil import Key, KeySet
from sigil._b64 import b64encode

from .conftest import TESTDATA, hs256, load_key, tamper

SECRET = b"s" * 32


@pytest.mark.parametrize(
    ("error", "code"),
    [
        (sigil.MalformedTokenError, "malformed"),
        (sigil.UnsupportedAlgorithmError, "unsupported_alg"),
        (sigil.InvalidKeyError, "invalid_key"),
        (sigil.KeyNotFoundError, "key_not_found"),
        (sigil.InvalidSignatureError, "invalid_signature"),
        (sigil.TokenExpiredError, "expired"),
        (sigil.TokenNotYetValidError, "not_yet_valid"),
        (sigil.InvalidClaimError, "invalid_claim"),
    ],
)
def test_error_codes(error: Type[sigil.SigilError], code: str) -> None:
    assert issubclass(error, sigil.SigilError)
    assert error.code == code


@pytest.mark.parametrize("alg", ["none", "None", "NONE", "nOnE"])
def test_none_is_rejected(alg: str) -> None:
    header = b64encode(f'{{"alg":"{alg}"}}'.encode())
    payload = b64encode(b'{"sub":"x"}')
    for token in (f"{header}.{payload}.", f"{header}.{payload}.{b64encode(b'sig')}"):
        with pytest.raises(sigil.UnsupportedAlgorithmError):
            sigil.verify(token, Key.secret(SECRET))
        with pytest.raises(sigil.UnsupportedAlgorithmError):
            sigil.verify(token, Key.secret(SECRET), algorithms=[alg])
    with pytest.raises(sigil.UnsupportedAlgorithmError):
        sigil.sign({}, Key.secret(SECRET), alg=alg)


def test_algorithm_allow_list() -> None:
    token = sigil.sign({}, Key.secret(b"s" * 64), alg="HS512")
    with pytest.raises(sigil.UnsupportedAlgorithmError):
        sigil.verify(token, Key.secret(b"s" * 64), algorithms=["HS256"])
    with pytest.raises(sigil.UnsupportedAlgorithmError):
        sigil.verify(token, Key.secret(b"s" * 64, alg="HS256"))
    assert sigil.verify(token, Key.secret(b"s" * 64), algorithms="HS512").claims == {}


def test_hs256_with_rsa_public_key_is_rejected() -> None:
    public = load_key("rsa-2048").public_key()
    pem = (TESTDATA / "rsa-2048.pub.pem").read_bytes()
    forged = hs256({"alg": "HS256", "typ": "JWT"}, {"sub": "admin"}, pem)
    with pytest.raises(sigil.UnsupportedAlgorithmError):
        sigil.verify(forged, public)
    with pytest.raises(sigil.InvalidKeyError):
        sigil.verify(forged, public, algorithms=["HS256"])
    with pytest.raises(sigil.InvalidKeyError):
        sigil.verify(forged, Key.from_pem(pem), algorithms=["HS256"])


@pytest.mark.parametrize(
    ("kid", "alg"),
    [
        ("rsa-2048", "HS256"),
        ("rsa-2048", "ES256"),
        ("ec-p384", "ES256"),
        ("ec-p256", "ES384"),
        ("ec-p256", "EdDSA"),
        ("ed25519", "ES256"),
        ("x25519", "EdDSA"),
        ("oct-hs256", "RS256"),
    ],
)
def test_key_algorithm_mismatch(kid: str, alg: str) -> None:
    with pytest.raises(sigil.InvalidKeyError):
        sigil.sign({}, load_key(kid), alg=alg)


@pytest.mark.parametrize(
    ("kid", "alg"),
    [("rsa-2048", "dir"), ("rsa-2048", "A128KW"), ("oct-a128kw", "RSA-OAEP"), ("ed25519", "ECDH-ES")],
)
def test_jwe_key_algorithm_mismatch(kid: str, alg: str) -> None:
    with pytest.raises(sigil.InvalidKeyError):
        sigil.encrypt({}, load_key(kid), alg=alg)


def test_key_alg_restricts_use() -> None:
    key = Key.from_jwk(load_key("rsa-2048").to_jwk(include_private=True), alg="RS256")
    with pytest.raises(sigil.InvalidKeyError):
        sigil.sign({}, key, alg="PS256")
    with pytest.raises(sigil.InvalidKeyError):
        Key.secret(SECRET, alg="RS256")
    with pytest.raises(sigil.UnsupportedAlgorithmError):
        Key.secret(SECRET, alg="HS1")


@pytest.mark.parametrize(("alg", "size"), [("HS256", 32), ("HS384", 48), ("HS512", 64)])
def test_short_hmac_key(alg: str, size: int) -> None:
    short = Key.secret(b"k" * (size - 1))
    with pytest.raises(sigil.InvalidKeyError):
        sigil.sign({}, short, alg=alg)
    token = sigil.sign({}, Key.secret(b"k" * size), alg=alg)
    with pytest.raises(sigil.InvalidKeyError):
        sigil.verify(token, short)


def test_small_rsa_key() -> None:
    small = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    with pytest.raises(sigil.InvalidKeyError):
        Key(small)
    pem = small.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    with pytest.raises(sigil.InvalidKeyError):
        Key.from_pem(pem)


def test_signing_needs_private_key() -> None:
    with pytest.raises(sigil.InvalidKeyError):
        sigil.sign({}, load_key("ec-p256").public_key())


def test_decrypting_needs_private_key() -> None:
    public = load_key("rsa-2048").public_key()
    token = sigil.encrypt({}, public, alg="RSA-OAEP")
    with pytest.raises(sigil.InvalidKeyError):
        sigil.decrypt(token, public)


@pytest.mark.parametrize(
    ("enc", "size"),
    [
        ("A128GCM", 16),
        ("A192GCM", 24),
        ("A256GCM", 32),
        ("A128CBC-HS256", 32),
        ("A192CBC-HS384", 48),
        ("A256CBC-HS512", 64),
    ],
)
def test_dir_key_length(enc: str, size: int) -> None:
    for wrong in (size - 1, size + 1):
        with pytest.raises(sigil.InvalidKeyError):
            sigil.encrypt({}, Key.secret(b"k" * wrong), alg="dir", enc=enc)
    token = sigil.encrypt({}, Key.secret(b"k" * size), alg="dir", enc=enc)
    with pytest.raises(sigil.InvalidKeyError):
        sigil.decrypt(token, Key.secret(b"k" * (size + 8)))


@pytest.mark.parametrize(("alg", "size"), [("A128KW", 16), ("A192KW", 24), ("A256KW", 32)])
def test_key_wrap_length(alg: str, size: int) -> None:
    for wrong in (size - 8, size + 8):
        with pytest.raises(sigil.InvalidKeyError):
            sigil.encrypt({}, Key.secret(b"k" * wrong), alg=alg)


def test_crit_is_rejected() -> None:
    token = hs256({"alg": "HS256", "crit": ["exp"]}, {}, SECRET)
    with pytest.raises(sigil.UnsupportedAlgorithmError):
        sigil.verify(token, Key.secret(SECRET))


def test_zip_is_rejected() -> None:
    with pytest.raises(sigil.UnsupportedAlgorithmError):
        sigil.verify(hs256({"alg": "HS256", "zip": "DEF"}, {}, SECRET), Key.secret(SECRET))

    header = b64encode(b'{"alg":"dir","enc":"A256GCM","zip":"DEF"}')
    with pytest.raises(sigil.UnsupportedAlgorithmError):
        sigil.decrypt(f"{header}..AAAAAAAAAAAAAAAA.AA.AAAAAAAAAAAAAAAAAAAAAA", Key.secret(SECRET))


def test_unknown_enc_is_rejected() -> None:
    header = b64encode(b'{"alg":"dir","enc":"A256CTR"}')
    with pytest.raises(sigil.UnsupportedAlgorithmError):
        sigil.decrypt(f"{header}..AA.AA.AA", Key.secret(SECRET))
    with pytest.raises(sigil.UnsupportedAlgorithmError):
        sigil.encrypt({}, Key.secret(SECRET), alg="dir", enc="A256CTR")


@pytest.mark.parametrize("kid", ["oct-hs256", "rsa-2048", "ec-p256", "ec-p521", "ed25519"])
@pytest.mark.parametrize("segment", [0, 1, 2])
def test_tampered_jws(kid: str, segment: int) -> None:
    key = load_key(kid)
    token = tamper(sigil.sign({"sub": "x"}, key), segment)
    with pytest.raises((sigil.InvalidSignatureError, sigil.MalformedTokenError)):
        sigil.verify(token, key)


def test_truncated_ecdsa_signature() -> None:
    key = load_key("ec-p256")
    token = sigil.sign({}, key)
    with pytest.raises(sigil.InvalidSignatureError):
        sigil.verify(token[:-4], key)


@pytest.mark.parametrize(
    ("kid", "alg", "enc"),
    [
        ("dir-a256gcm", "dir", "A256GCM"),
        ("dir-a128cbc-hs256", "dir", "A128CBC-HS256"),
        ("oct-a256kw", "A256KW", "A256CBC-HS512"),
        ("rsa-2048", "RSA-OAEP-256", "A192GCM"),
        ("ec-p384", "ECDH-ES+A192KW", "A128CBC-HS256"),
        ("x25519", "ECDH-ES", "A256GCM"),
    ],
)
@pytest.mark.parametrize("segment", [1, 2, 3, 4])
def test_tampered_jwe(kid: str, alg: str, enc: str, segment: int) -> None:
    key = load_key(kid)
    token = sigil.encrypt({"sub": "x"}, key, alg=alg, enc=enc)
    if segment == 1 and alg in ("dir", "ECDH-ES"):
        with pytest.raises(sigil.MalformedTokenError):
            sigil.decrypt(token.replace("..", ".AAAA.", 1), key)
        return
    with pytest.raises(sigil.InvalidSignatureError):
        sigil.decrypt(tamper(token, segment), key)


def test_tampered_jwe_header() -> None:
    key = load_key("dir-a256gcm")
    token = sigil.encrypt({}, key, alg="dir")
    header, rest = token.split(".", 1)
    swapped = b64encode(b'{"alg":"dir","enc":"A256GCM","kid":"dir-a256gcm","typ":"JWT"}')
    assert swapped != header
    with pytest.raises(sigil.InvalidSignatureError):
        sigil.decrypt(f"{swapped}.{rest}", key)


def test_invalid_epk_is_rejected() -> None:
    key = load_key("ec-p256")
    other = load_key("ec-p384")
    token = sigil.encrypt({}, other.public_key(), alg="ECDH-ES")
    with pytest.raises(sigil.InvalidKeyError):
        sigil.decrypt(token, Key.from_jwk(key.to_jwk(include_private=True)), algorithms=["ECDH-ES"])

    header = b64encode(b'{"alg":"ECDH-ES","enc":"A256GCM","epk":{"kty":"EC","crv":"P-256","x":"AA","y":"AA"}}')
    with pytest.raises(sigil.MalformedTokenError):
        sigil.decrypt(f"{header}..AAAAAAAAAAAAAAAA.AA.AAAAAAAAAAAAAAAAAAAAAA", key)


@pytest.mark.parametrize(
    "token",
    [
        "",
        "a.b",
        "a.b.c.d",
        "eyJhbGciOiJIUzI1NiJ9.e30=.AA",
        "eyJhbGciOiJIUzI1NiJ9.e30.A+A",
        "eyJhbGciOiJIUzI1NiJ9.WzFd.AA",
        "bm90IGpzb24.e30.AA",
        "eyJhbGciOiJIUzI1NiJ9.e30.A",
    ],
)
def test_malformed_tokens(token: str) -> None:
    with pytest.raises(sigil.MalformedTokenError):
        sigil.verify(token, Key.secret(SECRET))


def test_malformed_input_types() -> None:
    with pytest.raises(sigil.MalformedTokenError):
        sigil.verify(b"a.b.c", Key.secret(SECRET))  # type: ignore[arg-type]
    with pytest.raises(sigil.MalformedTokenError):
        sigil.decrypt("a.b.c", Key.secret(SECRET))
    with pytest.raises(sigil.MalformedTokenError):
        sigil.decode("a.b.c.d.e")


def test_messages_do_not_leak_token_contents() -> None:
    secret_alg = "SECRET-ALG-VALUE"
    token = hs256({"alg": secret_alg}, {}, SECRET)
    with pytest.raises(sigil.UnsupportedAlgorithmError) as info:
        sigil.verify(token, Key.secret(SECRET))
    assert secret_alg not in str(info.value)


class TestKeySetSelection:
    def test_kid_selects_key(self) -> None:
        a, b = Key.secret(b"a" * 32, kid="a"), Key.secret(b"b" * 32, kid="b")
        keys = KeySet([a, b])
        assert sigil.verify(sigil.sign({"k": "b"}, b), keys).claims == {"k": "b"}
        assert sigil.decrypt(sigil.encrypt({"k": "a"}, a, alg="dir"), keys).claims == {"k": "a"}

    def test_unknown_kid(self) -> None:
        keys = KeySet([Key.secret(b"a" * 32, kid="a")])
        with pytest.raises(sigil.KeyNotFoundError):
            sigil.verify(sigil.sign({}, Key.secret(b"a" * 32, kid="missing")), keys)

    def test_kid_with_wrong_key_type(self) -> None:
        keys = KeySet([load_key("ec-p256")])
        token = hs256({"alg": "HS256", "kid": "ec-p256"}, {}, SECRET)
        with pytest.raises(sigil.InvalidKeyError):
            sigil.verify(token, keys, algorithms=["HS256"])

    def test_non_string_kid(self) -> None:
        keys = KeySet([Key.secret(SECRET, kid="a")])
        with pytest.raises(sigil.MalformedTokenError):
            sigil.verify(hs256({"alg": "HS256", "kid": 1}, {}, SECRET), keys)

    def test_kidless_fallback(self) -> None:
        signer = Key.secret(b"c" * 32)
        keys = KeySet([Key.secret(b"a" * 32, kid="a"), Key.secret(b"short"), load_key("ec-p256"), signer])
        assert sigil.verify(sigil.sign({"n": 1}, signer), keys).claims == {"n": 1}

        rsa_key = load_key("rsa-2048")
        anonymous = Key.from_jwk({k: v for k, v in rsa_key.to_jwk().items() if k != "kid"})
        token = sigil.encrypt({"n": 2}, anonymous, alg="RSA-OAEP")
        keys = KeySet([load_key("oct-a128kw"), Key.generate("RSA-OAEP", kid="other"), rsa_key])
        assert sigil.decrypt(token, keys).claims == {"n": 2}

    def test_kidless_fallback_fails(self) -> None:
        keys = KeySet([Key.secret(b"a" * 32), Key.secret(b"b" * 32)])
        with pytest.raises(sigil.InvalidSignatureError):
            sigil.verify(sigil.sign({}, Key.secret(b"c" * 32)), keys)

    def test_kidless_no_compatible_key(self) -> None:
        keys = KeySet([load_key("ec-p256"), load_key("ed25519")])
        with pytest.raises(sigil.KeyNotFoundError):
            sigil.verify(sigil.sign({}, Key.secret(SECRET)), keys, algorithms=["HS256"])
