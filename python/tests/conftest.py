from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path
from typing import Any, Dict, Mapping

import pytest

from sigil import Key, KeySet
from sigil._b64 import b64decode, b64encode

TESTDATA = Path(__file__).resolve().parents[2] / "testdata"
INTEROP = json.loads((TESTDATA / "interop.json").read_text(encoding="utf-8"))
VECTORS = json.loads((TESTDATA / "vectors.json").read_text(encoding="utf-8"))
CLAIMS: Dict[str, Any] = INTEROP["claims"]
NOW = 1800000000
KEYS = KeySet.from_json((TESTDATA / "keys.json").read_text(encoding="utf-8"))


@pytest.fixture
def keys() -> KeySet:
    return KEYS


def load_key(kid: str) -> Key:
    key = KEYS.get(kid)
    assert key is not None
    return key


def hs256(header: Mapping[str, Any], claims: Mapping[str, Any], secret: bytes) -> str:
    """Build an HS256 token by hand, bypassing the library's header rules."""
    signing_input = f"{b64encode(json.dumps(header).encode())}.{b64encode(json.dumps(claims).encode())}"
    signature = hmac.new(secret, signing_input.encode(), hashlib.sha256).digest()
    return f"{signing_input}.{b64encode(signature)}"


def tamper(token: str, segment: int) -> str:
    """Flip one bit in the first byte of a token segment."""
    parts = token.split(".")
    data = bytearray(b64decode(parts[segment]))
    data[0] ^= 1
    parts[segment] = b64encode(bytes(data))
    return ".".join(parts)
