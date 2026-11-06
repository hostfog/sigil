from __future__ import annotations

import base64
import re

_URLSAFE = re.compile(r"[A-Za-z0-9_-]*")


def b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64decode(data: str) -> bytes:
    """Decode unpadded base64url, rejecting padding and foreign characters."""
    if not isinstance(data, str) or not _URLSAFE.fullmatch(data) or len(data) % 4 == 1:
        raise ValueError("invalid base64url")
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def int_to_b64(value: int, length: int = 0) -> str:
    size = max(length, (value.bit_length() + 7) // 8, 1)
    return b64encode(value.to_bytes(size, "big"))


def b64_to_int(data: str) -> int:
    return int.from_bytes(b64decode(data), "big")
