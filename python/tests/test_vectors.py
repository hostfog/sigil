from __future__ import annotations

import pytest

import sigil
from sigil import Key

from .conftest import VECTORS


def test_rfc7515_a1_hs256() -> None:
    vector = VECTORS["rfc7515_a1"]
    token = sigil.verify(vector["token"], Key.from_jwk(vector["key"]), now=vector["now"])
    assert token.claims == vector["claims"]
    assert token.header == {"typ": "JWT", "alg": "HS256"}


def test_rfc7515_a1_expires() -> None:
    vector = VECTORS["rfc7515_a1"]
    with pytest.raises(sigil.TokenExpiredError):
        sigil.verify(vector["token"], Key.from_jwk(vector["key"]), now=vector["claims"]["exp"])


def test_rfc7638_thumbprint() -> None:
    vector = VECTORS["rfc7638_thumbprint"]
    assert Key.from_jwk(vector["key"]).thumbprint() == vector["thumbprint"]
