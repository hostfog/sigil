"""Sigil: JWT, JWS, JWE and JWK for Python."""

from .errors import (
    InvalidClaimError,
    InvalidKeyError,
    InvalidSignatureError,
    KeyNotFoundError,
    MalformedTokenError,
    SigilError,
    TokenExpiredError,
    TokenNotYetValidError,
    UnsupportedAlgorithmError,
)
from .jwe import decrypt, encrypt
from .jws import sign, verify
from .keys import Key
from .keyset import KeySet
from .token import Token, decode

__version__ = "1.0.0"

__all__ = [
    "InvalidClaimError",
    "InvalidKeyError",
    "InvalidSignatureError",
    "Key",
    "KeyNotFoundError",
    "KeySet",
    "MalformedTokenError",
    "SigilError",
    "Token",
    "TokenExpiredError",
    "TokenNotYetValidError",
    "UnsupportedAlgorithmError",
    "decode",
    "decrypt",
    "encrypt",
    "sign",
    "verify",
]
