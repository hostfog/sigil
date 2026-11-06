"""Content encryption: AES-GCM and AES-CBC with HMAC-SHA2 (RFC 7518 §5)."""

from __future__ import annotations

import hmac
import os
import struct
from typing import Tuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.padding import PKCS7

from .algorithms import ENCRYPTION
from .errors import InvalidSignatureError

_CBC_HASHES = {"A128CBC-HS256": "sha256", "A192CBC-HS384": "sha384", "A256CBC-HS512": "sha512"}


def encrypt(enc: str, cek: bytes, plaintext: bytes, aad: bytes) -> Tuple[bytes, bytes, bytes]:
    """Return ``(iv, ciphertext, tag)``."""
    if enc not in _CBC_HASHES:
        iv = os.urandom(12)
        sealed = AESGCM(cek).encrypt(iv, plaintext, aad)
        return iv, sealed[:-16], sealed[-16:]

    mac_key, enc_key = _split(cek)
    iv = os.urandom(16)
    padder = PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    encryptor = Cipher(algorithms.AES(enc_key), modes.CBC(iv)).encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    return iv, ciphertext, _cbc_tag(enc, mac_key, aad, iv, ciphertext)


def decrypt(enc: str, cek: bytes, iv: bytes, ciphertext: bytes, tag: bytes, aad: bytes) -> bytes:
    if len(cek) != ENCRYPTION[enc]:
        raise InvalidSignatureError("content key has the wrong length")

    if enc not in _CBC_HASHES:
        if len(iv) != 12 or len(tag) != 16:
            raise InvalidSignatureError("decryption failed")
        try:
            return AESGCM(cek).decrypt(iv, ciphertext + tag, aad)
        except InvalidTag:
            raise InvalidSignatureError("decryption failed") from None

    mac_key, enc_key = _split(cek)
    if len(iv) != 16 or not hmac.compare_digest(_cbc_tag(enc, mac_key, aad, iv, ciphertext), tag):
        raise InvalidSignatureError("decryption failed")
    try:
        decryptor = Cipher(algorithms.AES(enc_key), modes.CBC(iv)).decryptor()
        padded = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = PKCS7(128).unpadder()
        return unpadder.update(padded) + unpadder.finalize()
    except ValueError:
        raise InvalidSignatureError("decryption failed") from None


def _split(cek: bytes) -> Tuple[bytes, bytes]:
    half = len(cek) // 2
    return cek[:half], cek[half:]


def _cbc_tag(enc: str, mac_key: bytes, aad: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    aad_bits = struct.pack(">Q", len(aad) * 8)
    digest = hmac.new(mac_key, aad + iv + ciphertext + aad_bits, _CBC_HASHES[enc]).digest()
    return digest[: len(mac_key)]
