"""
Web API routes for the Zhubin Web UI.

All routes require authentication (except /api/unlock and /api/status).
The VaultService is obtained from app.state — the same instance used by
the CLI.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel

from zhubin.exceptions import DeviceNotFoundError
from zhubin.vault.vault import VaultService
from zhubin.web.auth import (
    SESSION_COOKIE,
    issue_token,
    require_session,
    revoke_all,
)
from zhubin.web.security import CSRF_COOKIE, attach_csrf_cookie, csrf_token_from_request

router = APIRouter()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _svc(request: Request) -> VaultService:
    svc = request.app.state.vault_service
    if not isinstance(svc, VaultService):
        raise HTTPException(status_code=500, detail="Vault service is not configured.")
    return svc


def _unlocked_svc(
    request: Request,
    _session: str = Depends(require_session),
) -> VaultService:
    svc: VaultService = request.app.state.vault_service
    if svc.is_locked:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Vault is locked.",
        )
    return svc


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------


@router.get("/csrf")
async def get_csrf(request: Request, response: Response) -> dict[str, str]:
    """Issue (or echo) the CSRF token used for state-changing requests."""
    token = getattr(request.state, "csrf_token", None) or csrf_token_from_request(request)
    attach_csrf_cookie(response, token)
    response.headers["Cache-Control"] = "no-store"
    return {"csrf_token": token}


class UnlockRequest(BaseModel):
    passphrase: str


@router.post("/unlock")
async def unlock(body: UnlockRequest, request: Request, response: Response) -> dict[str, str]:
    """Unlock the vault and issue a session cookie."""
    from zhubin.crypto.identity import load_device_identity

    svc = _svc(request)
    try:
        identity = load_device_identity(body.passphrase)
        svc.unlock(identity)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
        ) from exc

    token = issue_token()
    response.set_cookie(
        SESSION_COOKIE,
        token,
        httponly=True,
        samesite="strict",
        max_age=3600,
        path="/",
    )
    # Ensure a CSRF cookie exists after unlock as well.
    attach_csrf_cookie(
        response,
        getattr(request.state, "csrf_token", None)
        or request.cookies.get(CSRF_COOKIE)
        or csrf_token_from_request(request),
    )
    response.headers["Cache-Control"] = "no-store"
    return {"status": "unlocked"}


@router.post("/lock")
async def lock(
    request: Request,
    response: Response,
    _s: str = Depends(require_session),
) -> dict[str, str]:
    """Lock the vault and invalidate all sessions."""
    _svc(request).lock()
    revoke_all()
    response.delete_cookie(SESSION_COOKIE, path="/")
    response.headers["Cache-Control"] = "no-store"
    return {"status": "locked"}


# ---------------------------------------------------------------------------
# Dashboard / status
# ---------------------------------------------------------------------------


@router.get("/status")
async def api_status(request: Request) -> dict[str, Any]:
    """Return vault status (no auth required for status check)."""
    from zhubin.storage.filesystem import list_devices, list_groups
    from zhubin.storage.git import get_status

    svc = _svc(request)
    vp: Path = request.app.state.vault_path

    git_st = get_status(vp)
    groups = list_groups(vp) if not svc.is_locked else []
    devices = list_devices(vp)

    return {
        "locked": svc.is_locked,
        "vault_path": str(vp),
        "git": {
            "branch": git_st.branch,
            "remote": git_st.remote,
            "has_remote": git_st.has_remote,
            "ahead": git_st.ahead,
            "behind": git_st.behind,
            "uncommitted": len(git_st.uncommitted),
            "has_conflicts": git_st.has_conflicts,
        },
        "groups": len(groups),
        "devices": len(devices),
        "total_secrets": (
            sum(len(svc.list_secrets(g.name)) for g in groups) if not svc.is_locked else 0
        ),
    }


# ---------------------------------------------------------------------------
# Groups
# ---------------------------------------------------------------------------


@router.get("/groups")
async def list_groups_api(svc: VaultService = Depends(_unlocked_svc)) -> list[dict[str, Any]]:
    groups = svc.list_groups()
    return [
        {
            "id": g.id,
            "name": g.name,
            "created_at": g.created_at.isoformat(),
            "device_count": len(g.device_keys),
            "secret_count": len(svc.list_secrets(g.name)),
        }
        for g in groups
    ]


class CreateGroupRequest(BaseModel):
    name: str


@router.post("/groups", status_code=status.HTTP_201_CREATED)
async def create_group(
    body: CreateGroupRequest, svc: VaultService = Depends(_unlocked_svc)
) -> dict[str, Any]:
    try:
        group = svc.create_group(body.name)
        return {"id": group.id, "name": group.name}
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/groups/{name}/rotate")
async def rotate_group(name: str, svc: VaultService = Depends(_unlocked_svc)) -> dict[str, str]:
    try:
        svc.rotate_group_key(name)
        return {"status": "rotated", "group": name}
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Secrets
# ---------------------------------------------------------------------------


@router.get("/groups/{group}/secrets")
async def list_secrets(
    group: str, svc: VaultService = Depends(_unlocked_svc)
) -> list[dict[str, str]]:
    try:
        names = svc.list_secrets(group)
        return [{"group": group, "name": n} for n in names]
    except Exception as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/groups/{group}/secrets/{name:path}")
async def get_secret(
    group: str, name: str, svc: VaultService = Depends(_unlocked_svc)
) -> dict[str, Any]:
    try:
        payload = svc.get_secret(group, name)
        return {
            "group": group,
            "name": name,
            "username": payload.username,
            "url": payload.url,
            "notes": payload.notes,
            # password is never returned by GET — use POST .../copy
        }
    except Exception as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


class SecretBody(BaseModel):
    username: str = ""
    password: str | None = None
    url: str = ""
    notes: str = ""


@router.post("/groups/{group}/secrets", status_code=status.HTTP_201_CREATED)
async def create_secret(
    group: str, name: str, body: SecretBody, svc: VaultService = Depends(_unlocked_svc)
) -> dict[str, str]:
    from zhubin.vault.models import SecretPayload

    try:
        svc.add_secret(
            group,
            name,
            SecretPayload(
                username=body.username,
                password=body.password or "",
                url=body.url,
                notes=body.notes,
            ),
        )
        return {"status": "created"}
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.put("/groups/{group}/secrets/{name:path}")
async def update_secret(
    group: str, name: str, body: SecretBody, svc: VaultService = Depends(_unlocked_svc)
) -> dict[str, str]:
    from zhubin.vault.models import SecretPayload

    try:
        existing = svc.get_secret(group, name)
        password = existing.password if body.password is None else body.password
        svc.edit_secret(
            group,
            name,
            SecretPayload(
                username=body.username,
                password=password,
                url=body.url,
                notes=body.notes,
            ),
        )
        return {"status": "updated"}
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.delete("/groups/{group}/secrets/{name:path}")
async def delete_secret(
    group: str, name: str, svc: VaultService = Depends(_unlocked_svc)
) -> dict[str, str]:
    try:
        svc.delete_secret(group, name)
        return {"status": "deleted"}
    except Exception as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/groups/{group}/secrets/{name:path}/copy")
async def copy_to_clipboard(
    group: str,
    name: str,
    response: Response,
    field: str = "password",
    timeout: int = 30,
    svc: VaultService = Depends(_unlocked_svc),
) -> dict[str, str]:
    """
    Copy a secret field to the local OS clipboard (server-side).

    The field value is NOT returned in the HTTP response.  The browser
    never receives the password; it is written to the OS clipboard of the
    machine running Zhubin and scheduled for timed clear.
    """
    from zhubin.clipboard.clipboard import ClipboardError, copy

    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    try:
        payload = svc.get_secret(group, name)
        field_map = {
            "password": payload.password,
            "username": payload.username,
            "url": payload.url,
        }
        if field not in field_map:
            raise HTTPException(status_code=400, detail="Unknown field.")
        value = field_map[field]
        if not value:
            raise HTTPException(status_code=400, detail=f"Field '{field}' is empty.")
        copy(value, timeout=timeout)
        return {"status": "copied", "field": field, "timeout": str(timeout)}
    except ClipboardError as exc:
        raise HTTPException(status_code=503, detail="Clipboard unavailable.") from exc
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Copy failed.") from exc


@router.get("/search")
async def search_secrets(
    q: str, svc: VaultService = Depends(_unlocked_svc)
) -> list[dict[str, str]]:
    results = svc.find_secrets(q)
    return [{"group": g, "name": s} for g, s in results]


# ---------------------------------------------------------------------------
# Devices
# ---------------------------------------------------------------------------


@router.get("/devices")
async def list_devices_api(svc: VaultService = Depends(_unlocked_svc)) -> list[dict[str, Any]]:
    return [
        {
            "id": d.id,
            "name": d.name,
            "platform": d.platform,
            "hostname": d.hostname,
            "public_key": d.public_key,
            "fingerprint": d.fingerprint(),
            "revoked": d.revoked,
            "created_at": d.created_at.isoformat(),
        }
        for d in svc.list_devices()
    ]


@router.get("/devices/{name}")
async def get_device(name: str, svc: VaultService = Depends(_unlocked_svc)) -> dict[str, object]:
    from zhubin.vault.models import DeviceRecord

    try:
        preview = svc.preview_authorize(name)
        device = preview["device"]
        if not isinstance(device, DeviceRecord):
            raise DeviceNotFoundError(f"Device '{name}' not found.")
        groups = preview["groups"]
        fingerprint = preview["fingerprint"]
    except DeviceNotFoundError:
        target = next((d for d in svc.list_devices() if d.name == name), None)
        if target is None:
            raise HTTPException(status_code=404, detail="Device not found.") from None
        device = target
        groups = []
        fingerprint = target.fingerprint()
    return {
        "id": device.id,
        "name": device.name,
        "fingerprint": fingerprint,
        "public_key": device.public_key,
        "revoked": device.revoked,
        "groups": groups,
    }


@router.post("/devices/{name}/authorize")
async def authorize_device(
    name: str, svc: VaultService = Depends(_unlocked_svc)
) -> dict[str, object]:
    try:
        groups = svc.authorize_device(name)
        return {"status": "authorized", "device": name, "groups": groups}
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/devices/{name}/revoke")
async def revoke_device_api(
    name: str,
    rotate: bool = True,
    svc: VaultService = Depends(_unlocked_svc),
) -> dict[str, Any]:
    try:
        affected = svc.revoke_device(name, rotate_groups=rotate)
        return {"status": "revoked", "device": name, "affected_groups": affected}
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Git
# ---------------------------------------------------------------------------


@router.get("/git/status")
async def git_status(request: Request, _s: str = Depends(require_session)) -> dict[str, Any]:
    from zhubin.storage.git import get_status

    vp: Path = request.app.state.vault_path
    st = get_status(vp)
    return {
        "branch": st.branch,
        "remote": st.remote,
        "has_remote": st.has_remote,
        "ahead": st.ahead,
        "behind": st.behind,
        "uncommitted": st.uncommitted,
        "has_conflicts": st.has_conflicts,
    }


@router.post("/git/sync")
async def git_sync(request: Request, _s: str = Depends(require_session)) -> dict[str, str]:
    from zhubin.storage.git import sync

    vp: Path = request.app.state.vault_path
    try:
        results = sync(vp)
        return results
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
