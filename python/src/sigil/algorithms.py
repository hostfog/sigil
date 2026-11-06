from __future__ import annotations

from typing import Dict, Optional, Tuple, Type

from cryptography.hazmat.primitives import hashes

HashType = Type[hashes.HashAlgorithm]

HMAC: Dict[str, HashType] = {
    "HS256": hashes.SHA256,
    "HS384": hashes.SHA384,
    "HS512": hashes.SHA512,
}
RSA_PKCS1: Dict[str, HashType] = {
    "RS256": hashes.SHA256,
    "RS384": hashes.SHA384,
    "RS512": hashes.SHA512,
}
RSA_PSS: Dict[str, HashType] = {
    "PS256": hashes.SHA256,
    "PS384": hashes.SHA384,
    "PS512": hashes.SHA512,
}
ECDSA: Dict[str, Tuple[str, HashType]] = {
    "ES256": ("P-256", hashes.SHA256),
    "ES384": ("P-384", hashes.SHA384),
    "ES512": ("P-521", hashes.SHA512),
}

JWS_ALGORITHMS = (*HMAC, *RSA_PKCS1, *RSA_PSS, *ECDSA, "EdDSA")

KEY_WRAP = {"A128KW": 16, "A192KW": 24, "A256KW": 32}
RSA_OAEP: Dict[str, HashType] = {"RSA-OAEP": hashes.SHA1, "RSA-OAEP-256": hashes.SHA256}
# Value is the key-wrap key length, or None for direct key agreement.
ECDH: Dict[str, Optional[int]] = {
    "ECDH-ES": None,
    "ECDH-ES+A128KW": 16,
    "ECDH-ES+A192KW": 24,
    "ECDH-ES+A256KW": 32,
}
ECDH_CURVES = ("P-256", "P-384", "P-521", "X25519")

JWE_ALGORITHMS = ("dir", *KEY_WRAP, *RSA_OAEP, *ECDH)

# Content encryption key length in bytes.
ENCRYPTION = {
    "A128GCM": 16,
    "A192GCM": 24,
    "A256GCM": 32,
    "A128CBC-HS256": 32,
    "A192CBC-HS384": 48,
    "A256CBC-HS512": 64,
}


def compatible(alg: str, kty: str, curve: Optional[str]) -> bool:
    """Whether `alg` can be used with a key of this type and curve."""
    if alg in HMAC or alg in KEY_WRAP or alg == "dir":
        return kty == "oct"
    if alg in RSA_PKCS1 or alg in RSA_PSS or alg in RSA_OAEP:
        return kty == "RSA"
    if alg in ECDSA:
        return curve == ECDSA[alg][0]
    if alg == "EdDSA":
        return curve == "Ed25519"
    if alg in ECDH:
        return curve in ECDH_CURVES
    return False
