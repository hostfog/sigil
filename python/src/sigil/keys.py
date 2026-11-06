from __future__ import annotations

import hashlib
import json
import os
from typing import Any, Dict, Mapping, Optional, Union

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa, x25519

from . import jwk as _jwk
from ._b64 import b64encode
from .algorithms import (
    ECDH,
    ECDSA,
    ENCRYPTION,
    HMAC,
    JWE_ALGORITHMS,
    JWS_ALGORITHMS,
    KEY_WRAP,
    RSA_OAEP,
    RSA_PKCS1,
    RSA_PSS,
    compatible,
)
from .errors import InvalidKeyError, UnsupportedAlgorithmError
from .jwk import EC_CURVES, Material

_ASYMMETRIC_TYPES = (
    rsa.RSAPrivateKey,
    rsa.RSAPublicKey,
    ec.EllipticCurvePrivateKey,
    ec.EllipticCurvePublicKey,
    ed25519.Ed25519PrivateKey,
    ed25519.Ed25519PublicKey,
    x25519.X25519PrivateKey,
    x25519.X25519PublicKey,
)
_PRIVATE_TYPES = (
    rsa.RSAPrivateKey,
    ec.EllipticCurvePrivateKey,
    ed25519.Ed25519PrivateKey,
    x25519.X25519PrivateKey,
)
_THUMBPRINT_MEMBERS = {
    "oct": ("k", "kty"),
    "RSA": ("e", "kty", "n"),
    "EC": ("crv", "kty", "x", "y"),
    "OKP": ("crv", "kty", "x"),
}


class Key:
    """One key: a symmetric secret or an RSA, EC or OKP key pair (or public half).

    Prefer the ``from_jwk``, ``from_pem``, ``secret`` and ``generate`` constructors.
    """

    def __init__(self, material: Material, *, kid: Optional[str] = None, alg: Optional[str] = None) -> None:
        if isinstance(material, bytes):
            if not material:
                raise InvalidKeyError("empty symmetric key")
        elif not isinstance(material, _ASYMMETRIC_TYPES):
            raise UnsupportedAlgorithmError("unsupported key type")
        elif isinstance(material, (rsa.RSAPrivateKey, rsa.RSAPublicKey)) and material.key_size < 2048:
            raise InvalidKeyError("RSA keys must be at least 2048 bits")

        self._material = material
        self._type = _jwk.key_type(material)
        self._curve = _jwk.curve_name(material)
        self._kid = kid
        self._alg: Optional[str] = None
        if alg is not None:
            self._use(alg)
            self._alg = alg

    @classmethod
    def from_jwk(
        cls, jwk: Union[Mapping[str, Any], str], *, kid: Optional[str] = None, alg: Optional[str] = None
    ) -> Key:
        """Load a key from a JWK object or its JSON text."""
        if isinstance(jwk, str):
            try:
                jwk = json.loads(jwk)
            except ValueError:
                raise InvalidKeyError("JWK is not valid JSON") from None
        if not isinstance(jwk, Mapping):
            raise InvalidKeyError("JWK must be a JSON object")
        for name in ("kid", "alg"):
            if name in jwk and not isinstance(jwk[name], str):
                raise InvalidKeyError(f"JWK member {name!r} must be a string")
        return cls(_jwk.from_jwk(jwk), kid=kid or jwk.get("kid"), alg=alg or jwk.get("alg"))

    @classmethod
    def from_pem(cls, pem: Union[bytes, str], *, kid: Optional[str] = None, alg: Optional[str] = None) -> Key:
        """Load a PEM private key, public key or X.509 certificate."""
        data = pem.encode("utf-8") if isinstance(pem, str) else pem
        loaded: Any
        try:
            if b"-----BEGIN CERTIFICATE-----" in data:
                loaded = x509.load_pem_x509_certificate(data).public_key()
            elif b"PRIVATE KEY-----" in data:
                loaded = serialization.load_pem_private_key(data, password=None)
            else:
                loaded = serialization.load_pem_public_key(data)
        except (ValueError, TypeError):
            # TypeError is raised for password-protected keys.
            raise InvalidKeyError("could not load PEM key") from None
        return cls(loaded, kid=kid, alg=alg)

    @classmethod
    def secret(cls, value: Union[bytes, str], *, kid: Optional[str] = None, alg: Optional[str] = None) -> Key:
        """Wrap a symmetric secret. Strings are UTF-8 encoded."""
        return cls(value.encode("utf-8") if isinstance(value, str) else bytes(value), kid=kid, alg=alg)

    @classmethod
    def generate(cls, alg: str, *, kid: Optional[str] = None) -> Key:
        """Create a fresh key for a JWS or JWE algorithm.

        ``dir`` produces a 256-bit key, which suits the default ``A256GCM``.
        """
        material: Material
        if alg in HMAC:
            material = os.urandom(HMAC[alg]().digest_size)
        elif alg in KEY_WRAP:
            material = os.urandom(KEY_WRAP[alg])
        elif alg == "dir":
            material = os.urandom(ENCRYPTION["A256GCM"])
        elif alg in RSA_PKCS1 or alg in RSA_PSS or alg in RSA_OAEP:
            material = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        elif alg in ECDSA:
            material = ec.generate_private_key(EC_CURVES[ECDSA[alg][0]]())
        elif alg == "EdDSA":
            material = ed25519.Ed25519PrivateKey.generate()
        elif alg in ECDH:
            material = ec.generate_private_key(ec.SECP256R1())
        else:
            raise UnsupportedAlgorithmError("unsupported algorithm")
        return cls(material, kid=kid, alg=alg)

    @property
    def type(self) -> str:
        """``oct``, ``RSA``, ``EC`` or ``OKP``."""
        return self._type

    @property
    def kid(self) -> Optional[str]:
        return self._kid

    @property
    def alg(self) -> Optional[str]:
        return self._alg

    @property
    def curve(self) -> Optional[str]:
        """``P-256``, ``P-384``, ``P-521``, ``Ed25519``, ``X25519`` or None."""
        return self._curve

    @property
    def is_private(self) -> bool:
        """True for private keys and symmetric secrets."""
        return isinstance(self._material, (bytes, *_PRIVATE_TYPES))

    def public_key(self) -> Key:
        """Return the public half, keeping ``kid`` and ``alg``."""
        material = self._material
        if isinstance(material, bytes):
            raise InvalidKeyError("symmetric keys have no public part")
        if isinstance(material, _PRIVATE_TYPES):
            return Key(material.public_key(), kid=self._kid, alg=self._alg)
        return self

    def to_jwk(self, include_private: bool = False) -> Dict[str, str]:
        """Export as a JWK dict. Symmetric keys require ``include_private=True``."""
        if self._type == "oct" and not include_private:
            raise InvalidKeyError("symmetric keys can only be exported with include_private=True")
        jwk = _jwk.to_jwk(self._material, include_private)
        if self._kid is not None:
            jwk["kid"] = self._kid
        if self._alg is not None:
            jwk["alg"] = self._alg
        return jwk

    def thumbprint(self) -> str:
        """RFC 7638 SHA-256 thumbprint, base64url encoded."""
        members = _jwk.to_jwk(self._material, include_private=self._type == "oct")
        required = {name: members[name] for name in _THUMBPRINT_MEMBERS[self._type]}
        canonical = json.dumps(required, separators=(",", ":"), sort_keys=True)
        return b64encode(hashlib.sha256(canonical.encode("utf-8")).digest())

    def __repr__(self) -> str:
        return f"Key(type={self._type!r}, kid={self._kid!r}, alg={self._alg!r}, private={self.is_private})"

    def _use(self, alg: str, *, private: bool = False) -> Material:
        """Check that this key may be used with `alg` and return the raw material."""
        if alg not in JWS_ALGORITHMS and alg not in JWE_ALGORITHMS:
            raise UnsupportedAlgorithmError("unsupported algorithm")
        if not compatible(alg, self._type, self._curve):
            raise InvalidKeyError(f"{alg} cannot be used with this {self._type} key")
        if self._alg is not None and self._alg != alg:
            raise InvalidKeyError(f"key is restricted to {self._alg}")
        if private and not self.is_private:
            raise InvalidKeyError(f"{alg} needs a private key")
        return self._material

    def _accepts(self, alg: str) -> bool:
        return compatible(alg, self._type, self._curve) and self._alg in (None, alg)
