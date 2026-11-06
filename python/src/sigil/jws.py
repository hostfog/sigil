from __future__ import annotations

import hmac
from typing import Any, Collection, Iterable, Mapping, Optional, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature

from ._b64 import b64encode
from ._select import Keys, allowed_algorithms, candidates, first_success
from .algorithms import ECDSA, HMAC, JWS_ALGORITHMS, RSA_PKCS1, RSA_PSS
from .claims import Number, OneOrMany, validate
from .errors import InvalidKeyError, InvalidSignatureError
from .jwk import Material
from .keys import Key
from .token import Token, build_header, check_header, decode_segment, encode_json, parse_object, split

_DEFAULT_ALGORITHMS = {
    "oct": "HS256",
    "RSA": "RS256",
    "P-256": "ES256",
    "P-384": "ES384",
    "P-521": "ES512",
    "Ed25519": "EdDSA",
}


def sign(
    claims: Mapping[str, Any],
    key: Key,
    *,
    alg: Optional[str] = None,
    kid: Optional[str] = None,
    typ: Optional[str] = "JWT",
    headers: Optional[Mapping[str, Any]] = None,
) -> str:
    """Sign `claims` and return a compact JWS."""
    alg = alg or key.alg or _default_algorithm(key)
    material = key._use(alg, private=True)
    header = build_header(alg, None, typ, kid if kid is not None else key.kid, headers)
    signing_input = f"{b64encode(encode_json(header))}.{b64encode(encode_json(dict(claims)))}"
    signature = _sign(alg, material, signing_input.encode("ascii"))
    return f"{signing_input}.{b64encode(signature)}"


def verify(
    token: str,
    keys: Keys,
    *,
    algorithms: Optional[Collection[str]] = None,
    issuer: Optional[OneOrMany] = None,
    audience: Optional[OneOrMany] = None,
    subject: Optional[str] = None,
    typ: Optional[str] = None,
    leeway: Number = 0,
    max_age: Optional[Number] = None,
    required: Iterable[str] = (),
    now: Optional[Number] = None,
) -> Token:
    """Verify a compact JWS and its claims; `keys` is a Key or a KeySet."""
    header_segment, payload_segment, signature_segment = split(token, 3)
    header = parse_object(decode_segment(header_segment), "header")
    claims = parse_object(decode_segment(payload_segment), "payload")
    signature = decode_segment(signature_segment)

    alg = check_header(header, JWS_ALGORITHMS, allowed_algorithms(keys, algorithms, JWS_ALGORITHMS))
    signing_input = f"{header_segment}.{payload_segment}".encode("ascii")
    first_success(candidates(keys, header, alg), lambda key: _verify(alg, key, signing_input, signature))

    validate(
        header,
        claims,
        issuer=issuer,
        audience=audience,
        subject=subject,
        typ=typ,
        leeway=leeway,
        max_age=max_age,
        required=required,
        now=now,
    )
    return Token(header, claims)


def _default_algorithm(key: Key) -> str:
    alg = _DEFAULT_ALGORITHMS.get(key.curve or key.type)
    if alg is None:
        raise InvalidKeyError(f"{key.curve} keys cannot sign")
    return alg


def _sign(alg: str, material: Material, data: bytes) -> bytes:
    if isinstance(material, bytes):
        return _hmac(alg, material, data)
    if isinstance(material, rsa.RSAPrivateKey):
        pad, digest = _rsa_scheme(alg)
        return material.sign(data, pad, digest)
    if isinstance(material, ec.EllipticCurvePrivateKey):
        r, s = decode_dss_signature(material.sign(data, ec.ECDSA(ECDSA[alg][1]())))
        size = _coordinate_size(material.curve)
        return r.to_bytes(size, "big") + s.to_bytes(size, "big")
    if isinstance(material, ed25519.Ed25519PrivateKey):
        return material.sign(data)
    raise InvalidKeyError(f"{alg} cannot be used with this key")


def _verify(alg: str, key: Key, data: bytes, signature: bytes) -> None:
    material = key._use(alg) if key.type == "oct" else key.public_key()._use(alg)
    try:
        if isinstance(material, bytes):
            if not hmac.compare_digest(_hmac(alg, material, data), signature):
                raise InvalidSignature
        elif isinstance(material, rsa.RSAPublicKey):
            pad, digest = _rsa_scheme(alg)
            material.verify(signature, data, pad, digest)
        elif isinstance(material, ec.EllipticCurvePublicKey):
            size = _coordinate_size(material.curve)
            if len(signature) != 2 * size:
                raise InvalidSignature
            r = int.from_bytes(signature[:size], "big")
            s = int.from_bytes(signature[size:], "big")
            material.verify(encode_dss_signature(r, s), data, ec.ECDSA(ECDSA[alg][1]()))
        elif isinstance(material, ed25519.Ed25519PublicKey):
            material.verify(signature, data)
        else:
            raise InvalidKeyError(f"{alg} cannot be used with this key")
    except InvalidSignature:
        raise InvalidSignatureError("signature verification failed") from None


def _hmac(alg: str, secret: bytes, data: bytes) -> bytes:
    digest = HMAC[alg]()
    if len(secret) < digest.digest_size:
        raise InvalidKeyError(f"{alg} needs a key of at least {digest.digest_size} bytes")
    return hmac.new(secret, data, digest.name).digest()


def _rsa_scheme(alg: str) -> Tuple[padding.AsymmetricPadding, hashes.HashAlgorithm]:
    if alg in RSA_PKCS1:
        return padding.PKCS1v15(), RSA_PKCS1[alg]()
    digest = RSA_PSS[alg]()
    return padding.PSS(mgf=padding.MGF1(digest), salt_length=digest.digest_size), digest


def _coordinate_size(curve: ec.EllipticCurve) -> int:
    return (curve.key_size + 7) // 8
