from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Collection, Dict, List, Mapping, Optional

from ._b64 import b64decode
from .errors import MalformedTokenError, UnsupportedAlgorithmError

_PROTECTED_HEADERS = frozenset({"alg", "enc", "zip", "crit"})


@dataclass(frozen=True)
class Token:
    """A decoded token: its protected header and its claims."""

    header: Dict[str, Any]
    claims: Dict[str, Any]


def decode(token: str) -> Token:
    """Read a JWS header and claims without verifying anything."""
    header, payload, _ = split(token, 3)
    return Token(parse_object(decode_segment(header), "header"), parse_object(decode_segment(payload), "payload"))


def split(token: str, count: int) -> List[str]:
    if not isinstance(token, str):
        raise MalformedTokenError("token must be a string")
    parts = token.split(".")
    if len(parts) != count:
        raise MalformedTokenError(f"token must have {count} segments")
    return parts


def decode_segment(segment: str) -> bytes:
    try:
        return b64decode(segment)
    except ValueError:
        raise MalformedTokenError("token segment is not valid base64url") from None


def parse_object(data: bytes, name: str) -> Dict[str, Any]:
    try:
        value = json.loads(data)
    except ValueError:
        raise MalformedTokenError(f"token {name} is not valid JSON") from None
    if not isinstance(value, dict):
        raise MalformedTokenError(f"token {name} must be a JSON object")
    return value


def encode_json(value: Mapping[str, Any]) -> bytes:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def build_header(
    alg: str,
    enc: Optional[str],
    typ: Optional[str],
    kid: Optional[str],
    extra: Optional[Mapping[str, Any]],
) -> Dict[str, Any]:
    header: Dict[str, Any] = {"alg": alg}
    if enc is not None:
        header["enc"] = enc
    if typ is not None:
        header["typ"] = typ
    if kid is not None:
        header["kid"] = kid
    if extra:
        header.update((name, value) for name, value in extra.items() if name not in _PROTECTED_HEADERS)
    return header


def check_header(header: Mapping[str, Any], supported: Collection[str], allowed: Collection[str]) -> str:
    """Validate the header's ``alg``, ``crit`` and ``zip`` and return the algorithm."""
    alg = header.get("alg")
    if not isinstance(alg, str) or alg not in supported:
        raise UnsupportedAlgorithmError("unsupported algorithm")
    if alg not in allowed:
        raise UnsupportedAlgorithmError(f"{alg} is not an allowed algorithm")
    if "crit" in header:
        raise UnsupportedAlgorithmError("critical header extensions are not supported")
    if "zip" in header:
        raise UnsupportedAlgorithmError("compressed tokens are not supported")
    return alg
