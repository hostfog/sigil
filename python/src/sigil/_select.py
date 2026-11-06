"""Choosing allowed algorithms and candidate keys for verify / decrypt."""

from __future__ import annotations

from typing import Any, Callable, Collection, List, Mapping, Optional, TypeVar, Union

from .errors import InvalidKeyError, InvalidSignatureError, KeyNotFoundError, MalformedTokenError
from .keys import Key
from .keyset import KeySet

T = TypeVar("T")
Keys = Union[Key, KeySet]


def allowed_algorithms(keys: Keys, algorithms: Optional[Collection[str]], family: Collection[str]) -> Collection[str]:
    if isinstance(algorithms, str):
        return (algorithms,)
    if algorithms is not None:
        return algorithms
    pool = keys.keys if isinstance(keys, KeySet) else (keys,)
    return {alg for alg in family for key in pool if key._accepts(alg)}


def candidates(keys: Keys, header: Mapping[str, Any], alg: str) -> List[Key]:
    if isinstance(keys, Key):
        return [keys]

    kid = header.get("kid")
    if kid is not None:
        if not isinstance(kid, str):
            raise MalformedTokenError("kid must be a string")
        key = keys.get(kid)
        if key is None:
            raise KeyNotFoundError("no key matches the token's kid")
        return [key]

    matches = [key for key in keys.keys if key._accepts(alg)]
    if not matches:
        raise KeyNotFoundError(f"no key can be used with {alg}")
    return matches


def first_success(keys: List[Key], attempt: Callable[[Key], T]) -> T:
    """Run `attempt` with each key until one succeeds.

    A lone candidate raises its own error so callers see why it was rejected.
    """
    if len(keys) == 1:
        return attempt(keys[0])
    for key in keys:
        try:
            return attempt(key)
        except (InvalidSignatureError, InvalidKeyError):
            continue
    raise InvalidSignatureError("no key could verify the token")
