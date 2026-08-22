"""
OS keyring integration with secure passphrase fallback.

This module centralises all keyring interactions.  Callers should never
access the ``keyring`` package directly.

Fallback policy
---------------
If the OS keyring is unavailable (no backend, dbus not running, etc.),
store/retrieve/delete return failure / None rather than raising, and
**never** write a plaintext private key to disk.

The encrypted-file fallback in ``crypto.identity`` is the only disk
fallback, and it always requires a passphrase.
"""

from __future__ import annotations

import contextlib
from typing import Any

_KEYRING_SERVICE = "zhubin"


def _get_keyring() -> Any:
    """Import keyring lazily; return None if unavailable."""
    try:
        import keyring

        return keyring
    except ImportError:
        return None


def store(key: str, value: str) -> bool:
    """
    Store *value* under *key* in the OS keyring.

    Returns True if successful.  Returns False if the keyring is unavailable;
    callers must then use passphrase-encrypted file storage.  This function
    never writes *value* to a disk file.
    """
    kr = _get_keyring()
    if kr is None:
        return False
    try:
        kr.set_password(_KEYRING_SERVICE, key, value)
        return True
    except Exception:
        return False


def retrieve(key: str) -> str | None:
    """
    Retrieve a value from the OS keyring.

    Returns None if unavailable or not found.
    """
    kr = _get_keyring()
    if kr is None:
        return None
    try:
        value = kr.get_password(_KEYRING_SERVICE, key)
        if value is None:
            return None
        return str(value)
    except Exception:
        return None


def delete(key: str) -> None:
    """Remove *key* from the OS keyring (best-effort)."""
    kr = _get_keyring()
    if kr is None:
        return
    with contextlib.suppress(Exception):
        kr.delete_password(_KEYRING_SERVICE, key)


def is_available() -> bool:
    """Return True if a functional keyring backend is present."""
    kr = _get_keyring()
    if kr is None:
        return False
    try:
        probe_key = "__zhubin_probe__"
        kr.set_password(_KEYRING_SERVICE, probe_key, "1")
        val = kr.get_password(_KEYRING_SERVICE, probe_key)
        kr.delete_password(_KEYRING_SERVICE, probe_key)
        return str(val) == "1"
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Session token helpers (in-memory; keyring used only as optional cache)
# ---------------------------------------------------------------------------

_session_cache: dict[str, str] = {}


def store_session(token_key: str, token: str) -> None:
    """Store a session token in memory (and optionally keyring)."""
    _session_cache[token_key] = token
    store(token_key, token)


def retrieve_session(token_key: str) -> str | None:
    """Retrieve a session token from memory or keyring."""
    if token_key in _session_cache:
        return _session_cache[token_key]
    return retrieve(token_key)


def clear_session(token_key: str) -> None:
    """Invalidate a session token."""
    _session_cache.pop(token_key, None)
    delete(token_key)
