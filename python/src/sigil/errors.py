from __future__ import annotations


class SigilError(Exception):
    """Base class for every error raised by Sigil."""

    code = "error"


class MalformedTokenError(SigilError):
    code = "malformed"


class UnsupportedAlgorithmError(SigilError):
    code = "unsupported_alg"


class InvalidKeyError(SigilError):
    code = "invalid_key"


class KeyNotFoundError(SigilError):
    code = "key_not_found"


class InvalidSignatureError(SigilError):
    """Signature mismatch, or a JWE that failed to decrypt."""

    code = "invalid_signature"


class TokenExpiredError(SigilError):
    code = "expired"


class TokenNotYetValidError(SigilError):
    code = "not_yet_valid"


class InvalidClaimError(SigilError):
    code = "invalid_claim"

    def __init__(self, message: str, claim: str) -> None:
        super().__init__(message)
        self.claim = claim
