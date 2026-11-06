from __future__ import annotations

import datetime
import json
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, x25519
from cryptography.x509.oid import NameOID

import sigil
from sigil import Key, KeySet

from .conftest import TESTDATA, load_key

PEM = serialization.Encoding.PEM
NO_PASSWORD = serialization.NoEncryption()


def private_pem(key: Any, fmt: serialization.PrivateFormat) -> bytes:
    data: bytes = key.private_bytes(PEM, fmt, NO_PASSWORD)
    return data


def public_pem(key: Any, fmt: serialization.PublicFormat) -> bytes:
    data: bytes = key.public_bytes(PEM, fmt)
    return data


def self_signed(key: ec.EllipticCurvePrivateKey) -> bytes:
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "sigil test")])
    start = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(start)
        .not_valid_after(start + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(PEM)


class TestPem:
    def test_fixture_files_match_jwk(self) -> None:
        jwk_key = load_key("rsa-2048")
        private = Key.from_pem((TESTDATA / "rsa-2048.pem").read_bytes())
        public = Key.from_pem((TESTDATA / "rsa-2048.pub.pem").read_text())
        assert private.is_private and not public.is_private
        assert private.thumbprint() == public.thumbprint() == jwk_key.thumbprint()
        assert private.to_jwk(include_private=True) == {
            k: v for k, v in jwk_key.to_jwk(include_private=True).items() if k != "kid"
        }

    def test_pkcs1(self) -> None:
        source = Key.from_pem((TESTDATA / "rsa-2048.pem").read_bytes())
        raw = source._material
        traditional = private_pem(raw, serialization.PrivateFormat.TraditionalOpenSSL)
        assert traditional.startswith(b"-----BEGIN RSA PRIVATE KEY-----")
        pkcs1_public = public_pem(source.public_key()._material, serialization.PublicFormat.PKCS1)
        assert pkcs1_public.startswith(b"-----BEGIN RSA PUBLIC KEY-----")

        signer = Key.from_pem(traditional, kid="r")
        token = sigil.sign({"a": 1}, signer, alg="PS256")
        assert sigil.verify(token, Key.from_pem(pkcs1_public)).claims == {"a": 1}
        assert sigil.decode(token).header["kid"] == "r"

    @pytest.mark.parametrize("curve", [ec.SECP256R1(), ec.SECP384R1(), ec.SECP521R1()])
    def test_ec_sec1_pkcs8_spki(self, curve: ec.EllipticCurve) -> None:
        raw = ec.generate_private_key(curve)
        sec1 = private_pem(raw, serialization.PrivateFormat.TraditionalOpenSSL)
        assert sec1.startswith(b"-----BEGIN EC PRIVATE KEY-----")
        pkcs8 = private_pem(raw, serialization.PrivateFormat.PKCS8)
        spki = public_pem(raw.public_key(), serialization.PublicFormat.SubjectPublicKeyInfo)

        public = Key.from_pem(spki)
        for pem in (sec1, pkcs8):
            key = Key.from_pem(pem)
            assert key.type == "EC" and key.is_private
            assert sigil.verify(sigil.sign({}, key), public).claims == {}

    def test_okp_pkcs8(self) -> None:
        signer = Key.from_pem(private_pem(ed25519.Ed25519PrivateKey.generate(), serialization.PrivateFormat.PKCS8))
        assert signer.curve == "Ed25519"
        assert sigil.verify(sigil.sign({}, signer), signer.public_key()).header["alg"] == "EdDSA"

        raw = x25519.X25519PrivateKey.generate()
        recipient = Key.from_pem(public_pem(raw.public_key(), serialization.PublicFormat.SubjectPublicKeyInfo))
        token = sigil.encrypt({"x": 1}, recipient, alg="ECDH-ES")
        decrypter = Key.from_pem(private_pem(raw, serialization.PrivateFormat.PKCS8))
        assert sigil.decrypt(token, decrypter).claims == {"x": 1}

    def test_certificate(self) -> None:
        raw = ec.generate_private_key(ec.SECP256R1())
        key = Key.from_pem(self_signed(raw).decode())
        assert key.type == "EC" and key.curve == "P-256" and not key.is_private
        signer = Key.from_pem(private_pem(raw, serialization.PrivateFormat.PKCS8))
        assert sigil.verify(sigil.sign({}, signer), key).claims == {}

    def test_encrypted_pem(self) -> None:
        raw = ec.generate_private_key(ec.SECP256R1())
        pem = raw.private_bytes(PEM, serialization.PrivateFormat.PKCS8, serialization.BestAvailableEncryption(b"pw"))
        with pytest.raises(sigil.InvalidKeyError):
            Key.from_pem(pem)

    def test_garbage(self) -> None:
        with pytest.raises(sigil.InvalidKeyError):
            Key.from_pem("-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n")
        with pytest.raises(sigil.InvalidKeyError):
            Key.from_pem(b"not a pem")

    def test_unsupported_key_type(self) -> None:
        raw = dsa.generate_private_key(2048)
        with pytest.raises(sigil.UnsupportedAlgorithmError):
            Key.from_pem(private_pem(raw, serialization.PrivateFormat.PKCS8))


class TestJwk:
    @pytest.mark.parametrize(
        "kid", ["oct-hs256", "rsa-2048", "ec-p256", "ec-p384", "ec-p521", "ed25519", "x25519"]
    )
    def test_round_trip(self, kid: str) -> None:
        source = json.loads((TESTDATA / "keys.json").read_text())
        expected = next(entry for entry in source["keys"] if entry["kid"] == kid)
        key = load_key(kid)
        assert key.kid == kid and key.alg is None and key.is_private
        assert key.to_jwk(include_private=True) == expected
        assert Key.from_jwk(json.dumps(expected)).thumbprint() == key.thumbprint()

    @pytest.mark.parametrize("kid", ["rsa-2048", "ec-p521", "ed25519", "x25519"])
    def test_public_export(self, kid: str) -> None:
        key = load_key(kid)
        public = key.public_key()
        assert not public.is_private
        assert public.kid == kid
        assert "d" not in key.to_jwk()
        assert public.to_jwk() == key.to_jwk()
        assert public.thumbprint() == key.thumbprint()
        assert public.public_key() is public

    def test_properties(self) -> None:
        key = load_key("ec-p384")
        assert (key.type, key.curve) == ("EC", "P-384")
        assert (load_key("rsa-2048").type, load_key("rsa-2048").curve) == ("RSA", None)
        assert (load_key("x25519").type, load_key("x25519").curve) == ("OKP", "X25519")

    def test_symmetric_export(self) -> None:
        key = Key.secret("pässword-that-is-long-enough-ok!", kid="s", alg="HS256")
        assert key.is_private
        assert key.to_jwk(include_private=True) == {
            "kty": "oct",
            "k": "cMOkc3N3b3JkLXRoYXQtaXMtbG9uZy1lbm91Z2gtb2sh",
            "kid": "s",
            "alg": "HS256",
        }
        with pytest.raises(sigil.InvalidKeyError):
            key.to_jwk()
        with pytest.raises(sigil.InvalidKeyError):
            key.public_key()

    def test_options_override_members(self) -> None:
        key = Key.from_jwk({"kty": "oct", "k": "c2VjcmV0", "kid": "a", "alg": "A128KW"}, kid="b", alg="dir")
        assert (key.kid, key.alg) == ("b", "dir")

    def test_rsa_without_crt_parameters(self) -> None:
        full = load_key("rsa-2048").to_jwk(include_private=True)
        minimal = {name: full[name] for name in ("kty", "n", "e", "d")}
        key = Key.from_jwk(minimal)
        assert key.to_jwk(include_private=True) == {k: v for k, v in full.items() if k != "kid"}

    def test_okp_mismatched_private_key(self) -> None:
        jwk = load_key("ed25519").to_jwk(include_private=True)
        jwk["x"] = load_key("x25519").to_jwk()["x"]
        with pytest.raises(sigil.InvalidKeyError):
            Key.from_jwk(jwk)

    def test_point_not_on_curve(self) -> None:
        jwk = load_key("ec-p256").to_jwk()
        jwk["y"] = jwk["x"]
        with pytest.raises(sigil.InvalidKeyError):
            Key.from_jwk(jwk)

    @pytest.mark.parametrize(
        "jwk",
        [
            {"kty": "RSA", "n": "AQAB"},
            {"kty": "EC", "crv": "P-256", "x": "AA", "y": "AA"},
            {"kty": "oct", "k": ""},
            {"kty": "oct", "k": "a+b"},
            {"kty": "oct", "k": "c2VjcmV0", "kid": 5},
            [],
        ],
    )
    def test_invalid(self, jwk: Any) -> None:
        with pytest.raises(sigil.InvalidKeyError):
            Key.from_jwk(jwk)
        with pytest.raises(sigil.InvalidKeyError):
            Key.from_jwk("{not json")

    @pytest.mark.parametrize(
        "jwk",
        [
            {"kty": "DSA"},
            {"kty": "EC", "crv": "secp256k1", "x": "AA", "y": "AA"},
            {"kty": "OKP", "crv": "Ed448", "x": "AA"},
            {"kty": "oct", "k": "c2VjcmV0", "alg": "none"},
        ],
    )
    def test_unsupported(self, jwk: Any) -> None:
        with pytest.raises(sigil.UnsupportedAlgorithmError):
            Key.from_jwk(jwk)

    def test_repr_hides_material(self) -> None:
        key = Key.secret(b"super-secret-value-0123456789abcdef", kid="k")
        assert "super-secret" not in repr(key)
        assert repr(key) == "Key(type='oct', kid='k', alg=None, private=True)"


class TestGenerate:
    @pytest.mark.parametrize(
        ("alg", "kty", "curve"),
        [
            ("HS384", "oct", None),
            ("A192KW", "oct", None),
            ("dir", "oct", None),
            ("RS256", "RSA", None),
            ("RSA-OAEP-256", "RSA", None),
            ("ES512", "EC", "P-521"),
            ("EdDSA", "OKP", "Ed25519"),
            ("ECDH-ES+A128KW", "EC", "P-256"),
        ],
    )
    def test_key_shape(self, alg: str, kty: str, curve: Any) -> None:
        key = Key.generate(alg, kid="g")
        assert (key.type, key.curve, key.alg, key.kid, key.is_private) == (kty, curve, alg, "g", True)

    def test_secret_sizes(self) -> None:
        assert len(Key.generate("HS512").to_jwk(include_private=True)["k"]) == 86
        assert len(Key.generate("A128KW").to_jwk(include_private=True)["k"]) == 22

    @pytest.mark.parametrize("alg", ["none", "RSA1_5", "A256GCM", "ES256K"])
    def test_unsupported(self, alg: str) -> None:
        with pytest.raises(sigil.UnsupportedAlgorithmError):
            Key.generate(alg)


class TestKeySet:
    def test_from_json(self) -> None:
        text = (TESTDATA / "keys.json").read_text()
        keys = KeySet.from_json(text)
        assert len(keys.keys) == 18
        assert keys.get("ec-p256") is not None
        assert keys.get("nope") is None
        assert KeySet.from_json(json.loads(text)).to_json(include_private=True) == json.loads(text)

    def test_skips_unsupported_entries(self) -> None:
        keys = KeySet.from_json(
            {
                "keys": [
                    {"kty": "DSA", "kid": "old"},
                    {"kty": "EC", "crv": "secp256k1", "x": "AA", "y": "AA", "kid": "k1"},
                    {"kty": "oct", "k": "c2VjcmV0", "kid": "ok"},
                ]
            }
        )
        assert [key.kid for key in keys.keys] == ["ok"]

    def test_invalid_entry_is_fatal(self) -> None:
        with pytest.raises(sigil.InvalidKeyError):
            KeySet.from_json({"keys": [{"kty": "oct"}]})

    @pytest.mark.parametrize("jwks", [{}, {"keys": {}}, "[]", "nope"])
    def test_invalid_document(self, jwks: Any) -> None:
        with pytest.raises(sigil.InvalidKeyError):
            KeySet.from_json(jwks)

    def test_public_export(self) -> None:
        keys = KeySet([load_key("oct-hs256"), load_key("rsa-2048"), load_key("ed25519")])
        exported = keys.to_json()
        assert [jwk["kid"] for jwk in exported["keys"]] == ["rsa-2048", "ed25519"]
        assert all("d" not in jwk for jwk in exported["keys"])

    def test_add(self) -> None:
        keys = KeySet()
        keys.add(Key.secret(b"x" * 32, kid="x"))
        assert keys.get("x") is keys.keys[0]
