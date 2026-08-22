"""
Secret encryption / decryption using symmetric group keys.

Algorithm
---------
XSalsa20-Poly1305 via ``nacl.secret.SecretBox``.

Every encryption generates a fresh 24-byte nonce with ``nacl.utils.random``.
Nonce reuse with the same key is not possible through this API: callers cannot
supply a nonce.

On-disk format (version 2)::

    {
      "version": 2,
      "type": "zhubin-secret-v1",
      "cipher": "xsalsa20poly1305",
      "nonce": "<base64 24-byte nonce>",
      "ciphertext": "<base64 ciphertext+MAC>"
    }

Version 1 files (combined nonce+ciphertext in a single field, no type label)
remain decryptable.

The authentication tag (Poly1305) is verified before any plaintext is returned.

Failure modes
-------------
* Wrong group key → AuthenticationError
* Corrupted ciphertext / nonce → AuthenticationError
* Unsupported version or type → FormatError
* Malformed JSON → FormatError

**Never** silently ignore authentication failures.
"""

from __future__ import annotations

import json
from base64 import b64decode, b64encode

import nacl.secret
import nacl.utils
from nacl.exceptions import CryptoError as NaClCryptoError

from zhubin.crypto.labels import SECRET_PREFIX, SECRET_TYPE
from zhubin.exceptions import AuthenticationError, FormatError

_SUPPORTED_VERSIONS = {1, 2}
_CIPHER = "xsalsa20poly1305"
_CURRENT_VERSION = 2


def _b64(data: bytes) -> str:
    return b64encode(data).decode()


def _unb64(s: str) -> bytes:
    return b64decode(s)


def _fresh_nonce() -> bytes:
    """Return a cryptographically random SecretBox nonce (24 bytes)."""
    return nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)


def encrypt_secret(plaintext: bytes, group_key: bytes) -> bytes:
    """
    Encrypt *plaintext* with *group_key*.

    Returns serialised JSON bytes ready to be written to a ``.secret`` file.
    A fresh random nonce is generated for every call; the nonce is never
    caller-controlled.
    """
    if len(group_key) != nacl.secret.SecretBox.KEY_SIZE:
        raise ValueError(
            f"group_key must be {nacl.secret.SecretBox.KEY_SIZE} bytes, got {len(group_key)}"
        )
    nonce = _fresh_nonce()
    box = nacl.secret.SecretBox(group_key)
    combined = box.encrypt(SECRET_PREFIX + plaintext, nonce)
    payload = {
        "version": _CURRENT_VERSION,
        "type": SECRET_TYPE,
        "cipher": _CIPHER,
        "nonce": _b64(nonce),
        "ciphertext": _b64(combined.ciphertext),
    }
    return json.dumps(payload, separators=(",", ":")).encode()


def decrypt_secret(data: bytes, group_key: bytes) -> bytes:
    """
    Decrypt a ``.secret`` file payload.

    Raises
    ------
    FormatError
        If the JSON is malformed, the version/type is unsupported, or the
        object is not a secret.
    AuthenticationError
        If the MAC verification fails (wrong key or corrupted data).
    """
    try:
        payload = json.loads(data)
    except json.JSONDecodeError as exc:
        raise FormatError("Secret file is not valid JSON") from exc

    if not isinstance(payload, dict):
        raise FormatError("Secret file JSON must be an object")

    version = payload.get("version")
    if version not in _SUPPORTED_VERSIONS:
        raise FormatError(f"Unsupported secret format version: {version!r}")

    obj_type = payload.get("type")
    if version >= 2 and obj_type != SECRET_TYPE:
        raise FormatError(
            f"Not a secret object (type={obj_type!r}). "
            "Refusing to parse a different cryptographic object as a secret."
        )

    cipher = payload.get("cipher")
    if cipher != _CIPHER:
        raise FormatError(f"Unsupported cipher: {cipher!r}")

    if len(group_key) != nacl.secret.SecretBox.KEY_SIZE:
        raise AuthenticationError(
            "Secret decryption failed — wrong group key or corrupted ciphertext."
        )

    box = nacl.secret.SecretBox(group_key)

    try:
        if version == 1:
            raw = _unb64(payload["ciphertext"])
            inner = box.decrypt(raw)
        else:
            nonce = _unb64(payload["nonce"])
            ciphertext = _unb64(payload["ciphertext"])
            if len(nonce) != nacl.secret.SecretBox.NONCE_SIZE:
                raise AuthenticationError(
                    "Secret decryption failed — wrong group key or corrupted ciphertext."
                )
            inner = box.decrypt(ciphertext, nonce)
    except (KeyError, ValueError, TypeError) as exc:
        raise FormatError("Secret file is missing required fields") from exc
    except NaClCryptoError as exc:
        raise AuthenticationError(
            "Secret decryption failed — wrong group key or corrupted ciphertext."
        ) from exc

    if inner.startswith(SECRET_PREFIX):
        return inner[len(SECRET_PREFIX) :]
    if version == 1:
        # Legacy files have no in-box type prefix.
        return inner
    raise FormatError("Secret plaintext is missing the expected type prefix.")
