"""ECDH-ES key agreement and the Concat KDF from RFC 7518 §4.6."""

from __future__ import annotations

import struct
from typing import Tuple, Union

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, x25519
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash

from .errors import InvalidKeyError

AgreementPrivateKey = Union[ec.EllipticCurvePrivateKey, x25519.X25519PrivateKey]
AgreementPublicKey = Union[ec.EllipticCurvePublicKey, x25519.X25519PublicKey]


def ephemeral_agreement(recipient: AgreementPublicKey) -> Tuple[AgreementPrivateKey, bytes]:
    """Generate an ephemeral key on the recipient's curve and return it with the shared secret."""
    ephemeral: AgreementPrivateKey
    if isinstance(recipient, x25519.X25519PublicKey):
        ephemeral = x25519.X25519PrivateKey.generate()
    else:
        ephemeral = ec.generate_private_key(recipient.curve)
    return ephemeral, shared_secret(ephemeral, recipient)


def shared_secret(private: AgreementPrivateKey, public: AgreementPublicKey) -> bytes:
    try:
        if isinstance(private, x25519.X25519PrivateKey) and isinstance(public, x25519.X25519PublicKey):
            return private.exchange(public)
        if (
            isinstance(private, ec.EllipticCurvePrivateKey)
            and isinstance(public, ec.EllipticCurvePublicKey)
            and private.curve.name == public.curve.name
        ):
            return private.exchange(ec.ECDH(), public)
    except ValueError:
        raise InvalidKeyError("key agreement failed") from None
    raise InvalidKeyError("ephemeral key does not match the recipient key")


def concat_kdf(secret: bytes, algorithm_id: str, length: int, apu: bytes, apv: bytes) -> bytes:
    other_info = b"".join(
        (
            _length_prefixed(algorithm_id.encode("ascii")),
            _length_prefixed(apu),
            _length_prefixed(apv),
            struct.pack(">I", length * 8),
        )
    )
    return ConcatKDFHash(hashes.SHA256(), length, other_info).derive(secret)


def _length_prefixed(data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + data
