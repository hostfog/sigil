"""Conversion between JWK members and cryptography key objects."""

from __future__ import annotations

from typing import Any, Dict, Mapping, Optional, Type, Union

from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa, x25519

from ._b64 import b64_to_int, b64decode, b64encode, int_to_b64
from .errors import InvalidKeyError, UnsupportedAlgorithmError

PrivateKey = Union[
    rsa.RSAPrivateKey,
    ec.EllipticCurvePrivateKey,
    ed25519.Ed25519PrivateKey,
    x25519.X25519PrivateKey,
]
PublicKey = Union[
    rsa.RSAPublicKey,
    ec.EllipticCurvePublicKey,
    ed25519.Ed25519PublicKey,
    x25519.X25519PublicKey,
]
Material = Union[bytes, PrivateKey, PublicKey]

EC_CURVES: Dict[str, Type[ec.EllipticCurve]] = {
    "P-256": ec.SECP256R1,
    "P-384": ec.SECP384R1,
    "P-521": ec.SECP521R1,
}
_CURVE_NAMES = {cls().name: name for name, cls in EC_CURVES.items()}


def key_type(material: Material) -> str:
    if isinstance(material, bytes):
        return "oct"
    if isinstance(material, (rsa.RSAPrivateKey, rsa.RSAPublicKey)):
        return "RSA"
    if isinstance(material, (ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey)):
        return "EC"
    return "OKP"


def curve_name(material: Material) -> Optional[str]:
    if isinstance(material, (ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey)):
        name = _CURVE_NAMES.get(material.curve.name)
        if name is None:
            raise UnsupportedAlgorithmError("unsupported EC curve")
        return name
    if isinstance(material, (ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey)):
        return "Ed25519"
    if isinstance(material, (x25519.X25519PrivateKey, x25519.X25519PublicKey)):
        return "X25519"
    return None


def from_jwk(jwk: Mapping[str, Any]) -> Material:
    kty = jwk.get("kty")
    try:
        if kty == "oct":
            secret = _bytes(jwk, "k")
            if not secret:
                raise InvalidKeyError("empty symmetric key")
            return secret
        if kty == "RSA":
            return _rsa_from_jwk(jwk)
        if kty == "EC":
            return _ec_from_jwk(jwk)
        if kty == "OKP":
            return _okp_from_jwk(jwk)
    except ValueError:
        raise InvalidKeyError(f"invalid {kty} JWK") from None
    raise UnsupportedAlgorithmError("unsupported key type")


def to_jwk(material: Material, include_private: bool) -> Dict[str, str]:
    if isinstance(material, bytes):
        return {"kty": "oct", "k": b64encode(material)}

    if isinstance(material, (rsa.RSAPrivateKey, rsa.RSAPublicKey)):
        public = material.public_key() if isinstance(material, rsa.RSAPrivateKey) else material
        numbers = public.public_numbers()
        jwk = {"kty": "RSA", "n": int_to_b64(numbers.n), "e": int_to_b64(numbers.e)}
        if include_private and isinstance(material, rsa.RSAPrivateKey):
            private = material.private_numbers()
            jwk.update(
                d=int_to_b64(private.d),
                p=int_to_b64(private.p),
                q=int_to_b64(private.q),
                dp=int_to_b64(private.dmp1),
                dq=int_to_b64(private.dmq1),
                qi=int_to_b64(private.iqmp),
            )
        return jwk

    crv = curve_name(material)
    assert crv is not None

    if isinstance(material, (ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey)):
        size = (material.curve.key_size + 7) // 8
        if isinstance(material, ec.EllipticCurvePrivateKey):
            point = material.public_key().public_numbers()
        else:
            point = material.public_numbers()
        jwk = {
            "kty": "EC",
            "crv": crv,
            "x": int_to_b64(point.x, size),
            "y": int_to_b64(point.y, size),
        }
        if include_private and isinstance(material, ec.EllipticCurvePrivateKey):
            jwk["d"] = int_to_b64(material.private_numbers().private_value, size)
        return jwk

    if isinstance(material, (ed25519.Ed25519PrivateKey, x25519.X25519PrivateKey)):
        jwk = {"kty": "OKP", "crv": crv, "x": b64encode(material.public_key().public_bytes_raw())}
        if include_private:
            jwk["d"] = b64encode(material.private_bytes_raw())
        return jwk
    return {"kty": "OKP", "crv": crv, "x": b64encode(material.public_bytes_raw())}


def _member(jwk: Mapping[str, Any], name: str) -> str:
    value = jwk.get(name)
    if not isinstance(value, str):
        raise InvalidKeyError(f"JWK member {name!r} is missing or not a string")
    return value


def _bytes(jwk: Mapping[str, Any], name: str, size: Optional[int] = None) -> bytes:
    value = b64decode(_member(jwk, name))
    if size is not None and len(value) != size:
        raise InvalidKeyError(f"JWK member {name!r} has the wrong length")
    return value


def _rsa_from_jwk(jwk: Mapping[str, Any]) -> Material:
    n = b64_to_int(_member(jwk, "n"))
    e = b64_to_int(_member(jwk, "e"))
    public = rsa.RSAPublicNumbers(e, n)
    if "d" not in jwk:
        return public.public_key()

    d = b64_to_int(_member(jwk, "d"))
    if all(name in jwk for name in ("p", "q", "dp", "dq", "qi")):
        p, q, dp, dq, qi = (b64_to_int(_member(jwk, name)) for name in ("p", "q", "dp", "dq", "qi"))
    else:
        # RFC 7518 §6.3.2 lets a private RSA JWK omit the CRT parameters.
        p, q = rsa.rsa_recover_prime_factors(n, e, d)
        dp, dq, qi = rsa.rsa_crt_dmp1(d, p), rsa.rsa_crt_dmq1(d, q), rsa.rsa_crt_iqmp(p, q)
    return rsa.RSAPrivateNumbers(p, q, d, dp, dq, qi, public).private_key()


def _ec_from_jwk(jwk: Mapping[str, Any]) -> Material:
    crv = jwk.get("crv")
    curve_cls = EC_CURVES.get(crv) if isinstance(crv, str) else None
    if curve_cls is None:
        raise UnsupportedAlgorithmError("unsupported EC curve")
    curve = curve_cls()
    size = (curve.key_size + 7) // 8
    x = int.from_bytes(_bytes(jwk, "x", size), "big")
    y = int.from_bytes(_bytes(jwk, "y", size), "big")
    public = ec.EllipticCurvePublicNumbers(x, y, curve)
    if "d" not in jwk:
        return public.public_key()
    d = int.from_bytes(_bytes(jwk, "d", size), "big")
    return ec.EllipticCurvePrivateNumbers(d, public).private_key()


def _okp_from_jwk(jwk: Mapping[str, Any]) -> Material:
    crv = jwk.get("crv")
    if crv not in ("Ed25519", "X25519"):
        raise UnsupportedAlgorithmError("unsupported OKP curve")
    x = _bytes(jwk, "x", 32)
    private: Union[ed25519.Ed25519PrivateKey, x25519.X25519PrivateKey]
    if crv == "Ed25519":
        if "d" not in jwk:
            return ed25519.Ed25519PublicKey.from_public_bytes(x)
        private = ed25519.Ed25519PrivateKey.from_private_bytes(_bytes(jwk, "d", 32))
    else:
        if "d" not in jwk:
            return x25519.X25519PublicKey.from_public_bytes(x)
        private = x25519.X25519PrivateKey.from_private_bytes(_bytes(jwk, "d", 32))

    if private.public_key().public_bytes_raw() != x:
        raise InvalidKeyError("OKP private key does not match its public key")
    return private
