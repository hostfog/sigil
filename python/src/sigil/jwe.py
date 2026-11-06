from __future__ import annotations

import os
from typing import Any, Collection, Dict, Iterable, Mapping, Optional, Tuple

from cryptography.hazmat.primitives import keywrap
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, x25519

from . import cipher, ecdh
from . import jwk as _jwk
from ._b64 import b64decode, b64encode
from ._select import Keys, allowed_algorithms, candidates, first_success
from .algorithms import ECDH, ENCRYPTION, JWE_ALGORITHMS, KEY_WRAP, RSA_OAEP
from .claims import Number, OneOrMany, validate
from .errors import (
    InvalidKeyError,
    InvalidSignatureError,
    MalformedTokenError,
    SigilError,
    UnsupportedAlgorithmError,
)
from .jwk import Material
from .keys import Key
from .token import Token, build_header, check_header, decode_segment, encode_json, parse_object, split


def encrypt(
    claims: Mapping[str, Any],
    key: Key,
    *,
    alg: Optional[str] = None,
    enc: str = "A256GCM",
    kid: Optional[str] = None,
    typ: Optional[str] = "JWT",
    headers: Optional[Mapping[str, Any]] = None,
) -> str:
    """Encrypt `claims` for `key` and return a compact JWE."""
    alg = alg or key.alg
    if alg is None or alg not in JWE_ALGORITHMS:
        raise UnsupportedAlgorithmError("encrypt needs a JWE key management algorithm")
    if enc not in ENCRYPTION:
        raise UnsupportedAlgorithmError("unsupported content encryption")

    recipient = key if key.type == "oct" else key.public_key()
    material = recipient._use(alg)
    header = build_header(alg, enc, typ, kid if kid is not None else key.kid, headers)
    cek, encrypted_key = _wrap_key(alg, enc, material, header)

    protected = b64encode(encode_json(header))
    iv, ciphertext, tag = cipher.encrypt(enc, cek, encode_json(dict(claims)), protected.encode("ascii"))
    return ".".join((protected, *(b64encode(part) for part in (encrypted_key, iv, ciphertext, tag))))


def decrypt(
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
    """Decrypt a compact JWE and check its claims; `keys` is a Key or a KeySet."""
    protected, *segments = split(token, 5)
    header = parse_object(decode_segment(protected), "header")
    encrypted_key, iv, ciphertext, tag = (decode_segment(segment) for segment in segments)

    alg = check_header(header, JWE_ALGORITHMS, allowed_algorithms(keys, algorithms, JWE_ALGORITHMS))
    enc = header.get("enc")
    if not isinstance(enc, str) or enc not in ENCRYPTION:
        raise UnsupportedAlgorithmError("unsupported content encryption")

    def attempt(key: Key) -> bytes:
        cek = _unwrap_key(alg, enc, key._use(alg, private=True), header, encrypted_key)
        return cipher.decrypt(enc, cek, iv, ciphertext, tag, protected.encode("ascii"))

    claims = parse_object(first_success(candidates(keys, header, alg), attempt), "payload")
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


def _wrap_key(alg: str, enc: str, material: Material, header: Dict[str, Any]) -> Tuple[bytes, bytes]:
    """Return ``(cek, encrypted_key)``. ECDH adds ``epk`` to `header`."""
    size = ENCRYPTION[enc]
    if isinstance(material, bytes):
        if alg == "dir":
            _check_length(material, size, f"dir with {enc}")
            return material, b""
        _check_length(material, KEY_WRAP[alg], alg)
        cek = os.urandom(size)
        return cek, keywrap.aes_key_wrap(material, cek)

    if isinstance(material, rsa.RSAPublicKey):
        cek = os.urandom(size)
        return cek, material.encrypt(cek, _oaep(alg))

    if isinstance(material, (ec.EllipticCurvePublicKey, x25519.X25519PublicKey)):
        ephemeral, secret = ecdh.ephemeral_agreement(material)
        header["epk"] = _jwk.to_jwk(ephemeral.public_key(), include_private=False)
        apu, apv = _party_info(header)
        wrap_size = ECDH[alg]
        if wrap_size is None:
            return ecdh.concat_kdf(secret, enc, size, apu, apv), b""
        cek = os.urandom(size)
        return cek, keywrap.aes_key_wrap(ecdh.concat_kdf(secret, alg, wrap_size, apu, apv), cek)

    raise InvalidKeyError(f"{alg} cannot be used with this key")


def _unwrap_key(alg: str, enc: str, material: Material, header: Mapping[str, Any], encrypted_key: bytes) -> bytes:
    size = ENCRYPTION[enc]
    if isinstance(material, bytes):
        if alg == "dir":
            _check_length(material, size, f"dir with {enc}")
            _require_empty(encrypted_key)
            return material
        _check_length(material, KEY_WRAP[alg], alg)
        return _aes_unwrap(material, encrypted_key)

    if isinstance(material, rsa.RSAPrivateKey):
        try:
            return material.decrypt(encrypted_key, _oaep(alg))
        except ValueError:
            # RFC 7516 §11.5: carry on with a random CEK so an unwrap failure is
            # indistinguishable from a bad tag.
            return os.urandom(size)

    if isinstance(material, (ec.EllipticCurvePrivateKey, x25519.X25519PrivateKey)):
        secret = ecdh.shared_secret(material, _ephemeral_key(header))
        apu, apv = _party_info(header)
        wrap_size = ECDH[alg]
        if wrap_size is None:
            _require_empty(encrypted_key)
            return ecdh.concat_kdf(secret, enc, size, apu, apv)
        return _aes_unwrap(ecdh.concat_kdf(secret, alg, wrap_size, apu, apv), encrypted_key)

    raise InvalidKeyError(f"{alg} cannot be used with this key")


def _oaep(alg: str) -> padding.OAEP:
    digest = RSA_OAEP[alg]()
    return padding.OAEP(mgf=padding.MGF1(digest), algorithm=digest, label=None)


def _aes_unwrap(kek: bytes, wrapped: bytes) -> bytes:
    try:
        return keywrap.aes_key_unwrap(kek, wrapped)
    except (keywrap.InvalidUnwrap, ValueError):
        raise InvalidSignatureError("decryption failed") from None


def _check_length(secret: bytes, size: int, purpose: str) -> None:
    if len(secret) != size:
        raise InvalidKeyError(f"{purpose} needs a {size}-byte key")


def _require_empty(encrypted_key: bytes) -> None:
    if encrypted_key:
        raise MalformedTokenError("encrypted key must be empty for direct key agreement")


def _ephemeral_key(header: Mapping[str, Any]) -> ecdh.AgreementPublicKey:
    epk = header.get("epk")
    if not isinstance(epk, Mapping):
        raise MalformedTokenError("missing or invalid epk header")
    try:
        material = _jwk.from_jwk(epk)
    except SigilError:
        raise MalformedTokenError("invalid epk header") from None
    if not isinstance(material, (ec.EllipticCurvePublicKey, x25519.X25519PublicKey)):
        raise MalformedTokenError("epk must be an EC or X25519 public key")
    return material


def _party_info(header: Mapping[str, Any]) -> Tuple[bytes, bytes]:
    try:
        return b64decode(header.get("apu", "")), b64decode(header.get("apv", ""))
    except ValueError:
        raise MalformedTokenError("apu and apv must be base64url strings") from None
