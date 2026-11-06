from __future__ import annotations

import json
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple, Union

from .errors import InvalidKeyError, UnsupportedAlgorithmError
from .keys import Key


class KeySet:
    """A collection of keys, as in a JWKS document."""

    def __init__(self, keys: Iterable[Key] = ()) -> None:
        self._keys: List[Key] = list(keys)

    @classmethod
    def from_json(cls, jwks: Union[Mapping[str, Any], str]) -> KeySet:
        """Load a JWKS. Entries with an unsupported key type, curve or alg are skipped."""
        if isinstance(jwks, str):
            try:
                jwks = json.loads(jwks)
            except ValueError:
                raise InvalidKeyError("JWKS is not valid JSON") from None
        entries = jwks.get("keys") if isinstance(jwks, Mapping) else None
        if not isinstance(entries, list):
            raise InvalidKeyError("JWKS must be an object with a 'keys' array")

        keys = []
        for entry in entries:
            try:
                keys.append(Key.from_jwk(entry))
            except UnsupportedAlgorithmError:
                continue
        return cls(keys)

    def add(self, key: Key) -> None:
        self._keys.append(key)

    def get(self, kid: str) -> Optional[Key]:
        """Return the first key with this ``kid``, or None."""
        return next((key for key in self._keys if key.kid == kid), None)

    @property
    def keys(self) -> Tuple[Key, ...]:
        return tuple(self._keys)

    def to_json(self, include_private: bool = False) -> Dict[str, List[Dict[str, str]]]:
        """Export as a JWKS dict. Symmetric keys are left out unless ``include_private``."""
        return {
            "keys": [
                key.to_jwk(include_private)
                for key in self._keys
                if include_private or key.type != "oct"
            ]
        }
