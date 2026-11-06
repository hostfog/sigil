from __future__ import annotations

from typing import Any, Dict

import pytest

import sigil
from sigil import Key

KEY = Key.secret(b"s" * 32)
NOW = 1_000_000


def check(claims: Dict[str, Any], **options: Any) -> Dict[str, Any]:
    options.setdefault("now", NOW)
    return sigil.verify(sigil.sign(claims, KEY), KEY, **options).claims


def check_encrypted(claims: Dict[str, Any], **options: Any) -> Dict[str, Any]:
    options.setdefault("now", NOW)
    return sigil.decrypt(sigil.encrypt(claims, KEY, alg="dir"), KEY, **options).claims


def invalid_claim(claim: str, claims: Dict[str, Any], **options: Any) -> None:
    with pytest.raises(sigil.InvalidClaimError) as info:
        check(claims, **options)
    assert info.value.claim == claim
    assert info.value.code == "invalid_claim"


def test_exp() -> None:
    check({"exp": NOW + 1})
    with pytest.raises(sigil.TokenExpiredError):
        check({"exp": NOW})
    with pytest.raises(sigil.TokenExpiredError):
        check_encrypted({"exp": NOW - 1})
    check({"exp": NOW - 5}, leeway=6)
    with pytest.raises(sigil.TokenExpiredError):
        check({"exp": NOW - 5}, leeway=5)


def test_nbf() -> None:
    check({"nbf": NOW})
    with pytest.raises(sigil.TokenNotYetValidError):
        check({"nbf": NOW + 1})
    check({"nbf": NOW + 10}, leeway=10)
    with pytest.raises(sigil.TokenNotYetValidError):
        check_encrypted({"nbf": NOW + 11}, leeway=10)


def test_iat_in_future() -> None:
    check({"iat": NOW})
    invalid_claim("iat", {"iat": NOW + 1})
    check({"iat": NOW + 30}, leeway=30)


@pytest.mark.parametrize("name", ["exp", "nbf", "iat"])
@pytest.mark.parametrize("value", ["1000", True, None, [1]])
def test_time_claims_must_be_numbers(name: str, value: Any) -> None:
    invalid_claim(name, {name: value})


def test_float_times() -> None:
    check({"exp": NOW + 0.5, "nbf": NOW - 0.5, "iat": NOW - 0.5})


def test_max_age() -> None:
    check({"iat": NOW - 60}, max_age=60)
    with pytest.raises(sigil.TokenExpiredError):
        check({"iat": NOW - 61}, max_age=60)
    check({"iat": NOW - 61}, max_age=60, leeway=1)
    invalid_claim("iat", {}, max_age=60)


def test_issuer() -> None:
    check({"iss": "a"}, issuer="a")
    check({"iss": "b"}, issuer=["a", "b"])
    invalid_claim("iss", {"iss": "c"}, issuer=["a", "b"])
    invalid_claim("iss", {}, issuer="a")


def test_audience() -> None:
    check({"aud": "api"}, audience="api")
    check({"aud": ["web", "api"]}, audience="api")
    check({"aud": "api"}, audience=["x", "api"])
    invalid_claim("aud", {"aud": ["web"]}, audience="api")
    invalid_claim("aud", {"aud": 5}, audience="api")
    invalid_claim("aud", {}, audience="api")


def test_subject() -> None:
    check({"sub": "42"}, subject="42")
    invalid_claim("sub", {"sub": "43"}, subject="42")
    invalid_claim("sub", {}, subject="42")


def test_typ() -> None:
    check({}, typ="jwt")
    with pytest.raises(sigil.InvalidClaimError) as info:
        sigil.verify(sigil.sign({}, KEY, typ="at+jwt"), KEY, typ="JWT")
    assert info.value.claim == "typ"
    with pytest.raises(sigil.InvalidClaimError):
        sigil.verify(sigil.sign({}, KEY, typ=None), KEY, typ="JWT")


def test_required() -> None:
    check({"jti": "x", "sub": "y"}, required=["jti", "sub"])
    invalid_claim("jti", {"sub": "y"}, required=["sub", "jti"])


def test_now_defaults_to_current_time() -> None:
    with pytest.raises(sigil.TokenExpiredError):
        sigil.verify(sigil.sign({"exp": NOW}, KEY), KEY)


def test_claims_checked_after_signature() -> None:
    token = sigil.sign({"exp": 1}, KEY)
    with pytest.raises(sigil.InvalidSignatureError):
        sigil.verify(token, Key.secret(b"t" * 32))
