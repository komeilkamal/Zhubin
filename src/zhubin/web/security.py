"""
Local Web UI request hardening: Host, Origin, CSRF, cache, CORS.

The Web UI is a privileged localhost application.  Localhost-only binding is
necessary but not sufficient: DNS rebinding and cross-site requests can still
reach 127.0.0.1 if Host/Origin are not validated.

Defenses
--------
* Host header must be a local name (or an explicitly allowed bind host).
* State-changing requests with an Origin header must come from a local origin.
* CSRF: double-submit cookie (``zhubin_csrf``) + ``X-CSRF-Token`` header.
* CORS is not enabled.  Responses never send ``Access-Control-Allow-Origin: *``.
* API responses are ``Cache-Control: no-store``.
"""

from __future__ import annotations

import secrets
from collections.abc import Awaitable, Callable
from urllib.parse import urlparse

from fastapi import FastAPI, Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from starlette.responses import Response as StarletteResponse

CSRF_COOKIE = "zhubin_csrf"
CSRF_HEADER = "X-CSRF-Token"
_UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

_DEFAULT_HOSTS = frozenset({"127.0.0.1", "localhost", "::1", "[::1]"})


def parse_host_header(host: str) -> str:
    """Return the hostname portion of a Host header (lowercase, no port)."""
    host = host.strip().lower()
    if not host:
        return ""
    if host.startswith("["):
        end = host.find("]")
        return host[1:end] if end != -1 else host
    # IPv4 or registered name with optional :port  (exactly one colon)
    if host.count(":") == 1:
        return host.split(":", 1)[0]
    return host


def origin_hostname(origin: str) -> str | None:
    """Return the hostname of an Origin URL, or None if it is not http(s)."""
    parsed = urlparse(origin)
    if parsed.scheme not in {"http", "https"}:
        return None
    if not parsed.hostname:
        return None
    return parsed.hostname.lower()


def _allowed_hosts(request: Request) -> set[str]:
    extra = getattr(request.app.state, "allowed_hosts", None)
    hosts = set(_DEFAULT_HOSTS)
    if extra:
        hosts.update(h.lower().strip("[]") for h in extra)
    return hosts


class WebSecurityMiddleware(BaseHTTPMiddleware):
    """Host, Origin, CSRF, and cache-control enforcement."""

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[StarletteResponse]],
    ) -> StarletteResponse:
        host_header = request.headers.get("host", "")
        hostname = parse_host_header(host_header)
        allowed = _allowed_hosts(request)
        if hostname not in allowed:
            return JSONResponse(
                {"detail": "Invalid Host header."},
                status_code=400,
            )

        # One token per request: reused for the CSRF cookie and /api/csrf JSON.
        csrf_token = request.cookies.get(CSRF_COOKIE) or secrets.token_urlsafe(32)
        request.state.csrf_token = csrf_token

        if request.method in _UNSAFE_METHODS:
            origin = request.headers.get("origin")
            if origin:
                oh = origin_hostname(origin)
                if oh is None or oh not in allowed:
                    return JSONResponse(
                        {"detail": "Request Origin is not allowed."},
                        status_code=403,
                    )

            cookie_token = request.cookies.get(CSRF_COOKIE)
            header_token = request.headers.get(CSRF_HEADER)
            if (
                not cookie_token
                or not header_token
                or not secrets.compare_digest(cookie_token, header_token)
            ):
                return JSONResponse(
                    {"detail": "CSRF token missing or incorrect."},
                    status_code=403,
                )

        response = await call_next(request)

        # Never advertise wildcard CORS.
        if response.headers.get("access-control-allow-origin") == "*":
            del response.headers["access-control-allow-origin"]

        if request.url.path.startswith("/api"):
            response.headers["Cache-Control"] = "no-store"
            response.headers["Pragma"] = "no-cache"
            response.headers.setdefault("X-Content-Type-Options", "nosniff")

        if CSRF_COOKIE not in request.cookies:
            response.set_cookie(
                CSRF_COOKIE,
                csrf_token,
                httponly=False,
                samesite="strict",
                max_age=3600,
                path="/",
            )
        return response


def install_security_middleware(app: FastAPI) -> None:
    """Attach WebSecurityMiddleware to *app*."""
    app.add_middleware(WebSecurityMiddleware)


def csrf_token_from_request(request: Request) -> str:
    """Return the CSRF token from the cookie, generating one if missing."""
    existing = request.cookies.get(CSRF_COOKIE)
    if existing:
        return existing
    return secrets.token_urlsafe(32)


def attach_csrf_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        CSRF_COOKIE,
        token,
        httponly=False,
        samesite="strict",
        max_age=3600,
        path="/",
    )
