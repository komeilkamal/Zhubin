"""
Web UI authentication.

The Web UI is a local interface — it does NOT implement a traditional
remote auth system.  Instead it uses the same device identity that
the CLI uses.

Session tokens
--------------
* Generated with ``secrets.token_urlsafe(32)`` — 192 bits of entropy.
* Stored server-side in an in-memory dict (not written to disk).
* Set as an HTTP-only cookie (``Secure`` flag is omitted because we are
  on localhost HTTP, but ``HttpOnly`` and ``SameSite=Strict`` are set).
* Session tokens are never placed in URLs.
* Short TTL (default 1 hour, matching auto_lock_timeout).
* Invalidated on lock (all sessions revoked).

Threat model
------------
This scheme protects against:

* CSRF, together with the double-submit CSRF cookie and Origin/Host checks
  in ``web.security``.
* Token leakage via Referer (tokens are not in URLs).
* Cross-origin reads (CORS is not enabled).

It does NOT protect against a local attacker who can read the cookie from
the browser process — but such an attacker already has access to the machine.
"""

from __future__ import annotations

import secrets
import time

from fastapi import Cookie, HTTPException, status

_TOKEN_TTL = 3600  # seconds
_active_sessions: dict[str, float] = {}  # token → expiry timestamp


def issue_token() -> str:
    """Issue a new session token and record its expiry."""
    token = secrets.token_urlsafe(32)
    _active_sessions[token] = time.time() + _TOKEN_TTL
    return token


def validate_token(token: str) -> bool:
    """Return True if *token* is valid and not expired."""
    expiry = _active_sessions.get(token)
    if expiry is None:
        return False
    if time.time() > expiry:
        _active_sessions.pop(token, None)
        return False
    return True


def revoke_token(token: str) -> None:
    _active_sessions.pop(token, None)


def revoke_all() -> None:
    _active_sessions.clear()


def expire_token_for_tests(token: str) -> None:
    """Mark *token* as already expired (test helper)."""
    _active_sessions[token] = 0.0


# ---------------------------------------------------------------------------
# FastAPI dependency
# ---------------------------------------------------------------------------

SESSION_COOKIE = "zhubin_session"


def require_session(
    zhubin_session: str | None = Cookie(default=None),
) -> str:
    """FastAPI dependency — raises 401 if not authenticated."""
    if not zhubin_session or not validate_token(zhubin_session):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated. Unlock the vault first.",
        )
    return zhubin_session
