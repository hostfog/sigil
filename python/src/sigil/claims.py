from __future__ import annotations

import time
from typing import Any, Iterable, Mapping, Optional, Sequence, Union

from .errors import InvalidClaimError, TokenExpiredError, TokenNotYetValidError

Number = Union[int, float]
OneOrMany = Union[str, Sequence[str]]


def validate(
    header: Mapping[str, Any],
    claims: Mapping[str, Any],
    *,
    issuer: Optional[OneOrMany],
    audience: Optional[OneOrMany],
    subject: Optional[str],
    typ: Optional[str],
    leeway: Number,
    max_age: Optional[Number],
    required: Iterable[str],
    now: Optional[Number],
) -> None:
    if typ is not None:
        actual = header.get("typ")
        if not isinstance(actual, str) or actual.lower() != typ.lower():
            raise InvalidClaimError("unexpected token type", "typ")

    for name in ("exp", "nbf", "iat"):
        if name in claims and not _is_number(claims[name]):
            raise InvalidClaimError(f"{name} must be a number", name)
    for name in required:
        if name not in claims:
            raise InvalidClaimError(f"missing required claim {name!r}", name)

    current = time.time() if now is None else now
    if "exp" in claims and current >= claims["exp"] + leeway:
        raise TokenExpiredError("token has expired")
    if "nbf" in claims and current < claims["nbf"] - leeway:
        raise TokenNotYetValidError("token is not valid yet")
    if "iat" in claims and claims["iat"] > current + leeway:
        raise InvalidClaimError("token was issued in the future", "iat")
    if max_age is not None:
        if "iat" not in claims:
            raise InvalidClaimError("max_age needs an iat claim", "iat")
        if current - claims["iat"] > max_age + leeway:
            raise TokenExpiredError("token is older than max_age")

    if issuer is not None and claims.get("iss") not in _as_list(issuer):
        raise InvalidClaimError("issuer is not accepted", "iss")
    if audience is not None and not _audience_matches(claims.get("aud"), _as_list(audience)):
        raise InvalidClaimError("audience is not accepted", "aud")
    if subject is not None and claims.get("sub") != subject:
        raise InvalidClaimError("subject does not match", "sub")


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _as_list(value: OneOrMany) -> Sequence[str]:
    return [value] if isinstance(value, str) else value


def _audience_matches(aud: Any, accepted: Sequence[str]) -> bool:
    if isinstance(aud, str):
        aud = [aud]
    if not isinstance(aud, list):
        return False
    return any(isinstance(item, str) and item in accepted for item in aud)
