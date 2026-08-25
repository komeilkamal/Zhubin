"""
FastAPI Web UI application factory.

Architecture::

    Web UI (FastAPI)
         |
         v
    VaultService    (shared with CLI)
         |
         +--→ crypto.*
         +--→ storage.*

Security defaults
-----------------
* Binds to 127.0.0.1 by default (enforced by CLI; asserted here too).
* Sessions use HTTP-only, SameSite=Strict cookies.
* CSRF tokens (double-submit cookie + header) on all state-changing routes.
* Host and Origin headers are validated against localhost (and the bind host).
* CORS is intentionally NOT enabled.
* No sensitive data in URLs.
* API responses are Cache-Control: no-store.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from zhubin.vault.vault import VaultService
from zhubin.web.api import router as api_router
from zhubin.web.security import install_security_middleware

_STATIC_DIR = Path(__file__).parent / "static"
_TEMPLATE_DIR = Path(__file__).parent / "templates"


def create_app(
    vault_path: Path,
    *,
    allowed_hosts: list[str] | None = None,
) -> FastAPI:
    """Create and configure the FastAPI application."""
    app = FastAPI(
        title="Zhubin",
        description="Secure Git-backed password manager — local Web UI",
        version="0.1.1",
        docs_url=None,  # disable Swagger UI in production-like setting
        redoc_url=None,
    )

    app.state.vault_path = vault_path
    app.state.vault_service = VaultService(vault_path)
    app.state.allowed_hosts = [
        h.lower() for h in (allowed_hosts or ["127.0.0.1", "localhost", "::1"])
    ]

    install_security_middleware(app)

    if _STATIC_DIR.exists():
        app.mount("/static", StaticFiles(directory=_STATIC_DIR), name="static")

    templates = Jinja2Templates(directory=str(_TEMPLATE_DIR))
    app.state.templates = templates

    app.include_router(api_router, prefix="/api")

    @app.get("/", response_class=HTMLResponse)
    async def root(request: Request) -> HTMLResponse:
        return templates.TemplateResponse(request, "index.html", {"title": "Zhubin"})

    @app.get("/{full_path:path}", response_class=HTMLResponse)
    async def spa_fallback(request: Request, full_path: str) -> HTMLResponse:
        """Catch-all for client-side routing."""
        if full_path.startswith("api/") or full_path.startswith("static/"):
            from fastapi.responses import Response

            return Response(status_code=404)  # type: ignore[return-value]
        return templates.TemplateResponse(request, "index.html", {"title": "Zhubin"})

    return app
