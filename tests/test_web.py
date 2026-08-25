"""
Tests for Web UI: auth, CSRF, Origin/Host, CORS, copy flow, localhost defaults.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch
from urllib.parse import quote

import pytest
from fastapi.testclient import TestClient

from zhubin.crypto.identity import create_device_identity, save_device_identity, save_device_meta
from zhubin.storage.filesystem import init_vault, save_device
from zhubin.vault.models import DeviceRecord
from zhubin.web.app import create_app
from zhubin.web.auth import SESSION_COOKIE, expire_token_for_tests, issue_token, revoke_all
from zhubin.web.security import CSRF_HEADER

BASE = "http://127.0.0.1"


@pytest.fixture
def vault_path(tmp_path: Path) -> Path:
    vp = tmp_path / "vault"
    init_vault(vp)
    return vp


@pytest.fixture
def identity():
    return create_device_identity()


@pytest.fixture
def app(vault_path: Path, identity, tmp_path: Path, monkeypatch):
    """Create a test FastAPI app with a pre-unlocked vault service."""
    dr = DeviceRecord(id=identity.device_id, name="test-device", public_key=identity.public_key_b64)
    save_device(vault_path, dr)

    config_dir = tmp_path / ".config" / "zhubin"
    config_dir.mkdir(parents=True, exist_ok=True)
    pk_file = config_dir / "private_key.enc"
    dm_file = config_dir / "device.json"

    import zhubin.crypto.identity as _id_mod

    monkeypatch.setattr(_id_mod, "PRIVATE_KEY_FILE", pk_file)
    monkeypatch.setattr(_id_mod, "DEVICE_META_FILE", dm_file)

    save_device_identity(identity, "testpass", prefer_keyring=False)
    save_device_meta(identity, "test-device")

    web_app = create_app(vault_path, allowed_hosts=["127.0.0.1", "localhost", "::1"])
    web_app.state.vault_service.unlock(identity)
    return web_app


def _csrf_client(app) -> TestClient:
    client = TestClient(app, base_url=BASE)
    token = client.get("/api/csrf").json()["csrf_token"]
    client.headers[CSRF_HEADER] = token
    client.headers["Origin"] = BASE
    return client, token


@pytest.fixture
def client(app):
    c, _ = _csrf_client(app)
    return c


@pytest.fixture
def authed_client(app):
    """Client with a valid session cookie, CSRF token, and local Origin."""
    client, csrf = _csrf_client(app)
    session = issue_token()
    client.cookies.set(SESSION_COOKIE, session)
    client.headers[CSRF_HEADER] = csrf
    client.headers["Origin"] = BASE
    return client


class TestWebAuth:
    def test_unlock_with_correct_passphrase(self, client, app) -> None:
        app.state.vault_service.lock()
        response = client.post("/api/unlock", json={"passphrase": "testpass"})
        assert response.status_code == 200
        assert response.json()["status"] == "unlocked"
        # Session cookie must be HttpOnly (TestClient exposes set-cookie).
        set_cookie = response.headers.get("set-cookie", "")
        assert SESSION_COOKIE in set_cookie
        assert "httponly" in set_cookie.lower()
        assert "samesite=strict" in set_cookie.lower()

    def test_unlock_with_wrong_passphrase_returns_401(self, client, app) -> None:
        app.state.vault_service.lock()
        response = client.post("/api/unlock", json={"passphrase": "wrongpass"})
        assert response.status_code == 401

    def test_unauthenticated_request_to_protected_endpoint(self, client) -> None:
        response = client.get("/api/groups")
        assert response.status_code == 401

    def test_lock_endpoint(self, authed_client, app) -> None:
        response = authed_client.post("/api/lock")
        assert response.status_code == 200
        assert response.json()["status"] == "locked"
        assert app.state.vault_service.is_locked

    def test_session_invalid_after_lock(self, authed_client, app) -> None:
        authed_client.post("/api/lock")
        r = authed_client.get("/api/groups")
        assert r.status_code == 401

    def test_expired_session_cannot_call_privileged(self, app) -> None:
        client, csrf = _csrf_client(app)
        token = issue_token()
        expire_token_for_tests(token)
        client.cookies.set(SESSION_COOKIE, token)
        client.headers[CSRF_HEADER] = csrf
        r = client.get("/api/groups")
        assert r.status_code == 401

    def test_revoked_session_cannot_call_privileged(self, authed_client) -> None:
        revoke_all()
        r = authed_client.get("/api/groups")
        assert r.status_code == 401


class TestWebStatus:
    def test_status_available_without_auth(self, client) -> None:
        response = client.get("/api/status")
        assert response.status_code == 200
        data = response.json()
        assert "locked" in data
        assert "git" in data

    def test_status_shows_vault_path(self, client, vault_path) -> None:
        response = client.get("/api/status")
        assert response.json()["vault_path"] == str(vault_path)


class TestWebGroups:
    def test_create_and_list_groups(self, authed_client) -> None:
        r = authed_client.post("/api/groups", json={"name": "personal"})
        assert r.status_code == 201
        groups = authed_client.get("/api/groups").json()
        assert any(g["name"] == "personal" for g in groups)

    def test_create_duplicate_group_returns_400(self, authed_client) -> None:
        authed_client.post("/api/groups", json={"name": "dup"})
        r = authed_client.post("/api/groups", json={"name": "dup"})
        assert r.status_code == 400


class TestWebSecrets:
    def test_create_and_retrieve_secret(self, authed_client) -> None:
        authed_client.post("/api/groups", json={"name": "personal"})
        r = authed_client.post(
            "/api/groups/personal/secrets?name=github",
            json={"username": "alice", "password": "s3cr3t", "url": "", "notes": ""},
        )
        assert r.status_code == 201

        r = authed_client.get("/api/groups/personal/secrets/github")
        assert r.status_code == 200
        data = r.json()
        assert data["username"] == "alice"
        assert "password" not in data or data.get("password") is None

    def test_password_not_in_get_response(self, authed_client) -> None:
        authed_client.post("/api/groups", json={"name": "work"})
        authed_client.post(
            "/api/groups/work/secrets?name=jira",
            json={"username": "u", "password": "SUPER_SECRET_1234", "url": "", "notes": ""},
        )
        r = authed_client.get("/api/groups/work/secrets/jira")
        body = r.text
        assert "SUPER_SECRET_1234" not in body

    def test_delete_secret(self, authed_client) -> None:
        authed_client.post("/api/groups", json={"name": "tmp"})
        authed_client.post(
            "/api/groups/tmp/secrets?name=todel",
            json={"username": "", "password": "x", "url": "", "notes": ""},
        )
        r = authed_client.delete("/api/groups/tmp/secrets/todel")
        assert r.status_code == 200

    def test_nested_secret_crud_and_copy(self, authed_client) -> None:
        nested = "ilo/bank/s"
        encoded = quote(nested, safe="")
        authed_client.post("/api/groups", json={"name": "own"})
        r = authed_client.post(
            f"/api/groups/own/secrets?name={encoded}",
            json={"username": "alice", "password": "NESTED_WEB_SECRET", "url": "", "notes": ""},
        )
        assert r.status_code == 201

        listed = authed_client.get("/api/groups/own/secrets").json()
        assert any(item["name"] == nested for item in listed)

        r = authed_client.get(f"/api/groups/own/secrets/{encoded}")
        assert r.status_code == 200
        data = r.json()
        assert data["username"] == "alice"
        assert "NESTED_WEB_SECRET" not in r.text
        assert "password" not in data or data.get("password") is None

        with patch("zhubin.clipboard.clipboard.copy") as mock_copy:
            r = authed_client.post(f"/api/groups/own/secrets/{encoded}/copy")
        assert r.status_code == 200
        assert "NESTED_WEB_SECRET" not in r.text
        mock_copy.assert_called_once()
        assert mock_copy.call_args[0][0] == "NESTED_WEB_SECRET"

        r = authed_client.put(
            f"/api/groups/own/secrets/{encoded}",
            json={"username": "bob", "url": "", "notes": ""},
        )
        assert r.status_code == 200
        assert authed_client.get(f"/api/groups/own/secrets/{encoded}").json()["username"] == "bob"

        r = authed_client.delete(f"/api/groups/own/secrets/{encoded}")
        assert r.status_code == 200
        assert authed_client.get(f"/api/groups/own/secrets/{encoded}").status_code == 404


class TestWebLocalhostDefault:
    def test_app_created_without_exception(self, tmp_path: Path) -> None:
        vp = tmp_path / "vault"
        init_vault(vp)
        app = create_app(vp)
        assert app is not None

    def test_config_refuses_external_bind(self) -> None:
        from pydantic import ValidationError

        from zhubin.config import ZhubinConfig

        with pytest.raises(ValidationError):
            ZhubinConfig(web_host="0.0.0.0")


class TestCsrfOriginHost:
    def test_valid_same_origin_post_succeeds(self, authed_client) -> None:
        r = authed_client.post("/api/groups", json={"name": "okgroup"})
        assert r.status_code == 201

    def test_missing_csrf_token_fails(self, app) -> None:
        client = TestClient(app, base_url=BASE)
        client.get("/api/csrf")  # set cookie
        session = issue_token()
        client.cookies.set(SESSION_COOKIE, session)
        # Origin set, but no CSRF header
        r = client.post("/api/groups", json={"name": "x"}, headers={"Origin": BASE})
        assert r.status_code == 403
        assert "CSRF" in r.json()["detail"]

    def test_incorrect_csrf_token_fails(self, app) -> None:
        client, _ = _csrf_client(app)
        session = issue_token()
        client.cookies.set(SESSION_COOKIE, session)
        client.headers[CSRF_HEADER] = "totally-wrong-token"
        r = client.post("/api/groups", json={"name": "x"})
        assert r.status_code == 403

    def test_malicious_origin_fails(self, authed_client) -> None:
        r = authed_client.post(
            "/api/groups",
            json={"name": "pwned"},
            headers={"Origin": "http://evil.example"},
        )
        assert r.status_code == 403
        assert "Origin" in r.json()["detail"]

    def test_unexpected_host_fails(self, authed_client) -> None:
        r = authed_client.get("/api/status", headers={"Host": "evil.example"})
        assert r.status_code == 400
        assert "Host" in r.json()["detail"]

    def test_arbitrary_cors_origin_rejected(self, authed_client) -> None:
        r = authed_client.get("/api/status", headers={"Origin": "http://evil.example"})
        assert r.status_code == 200
        acao = r.headers.get("access-control-allow-origin")
        assert acao not in {"*", "http://evil.example"}
        assert acao is None


class TestCopyFlow:
    def test_copy_requires_authentication(self, client, authed_client) -> None:
        authed_client.post("/api/groups", json={"name": "personal"})
        authed_client.post(
            "/api/groups/personal/secrets?name=github",
            json={"username": "a", "password": "COPY_SECRET_VALUE", "url": "", "notes": ""},
        )
        # Unauthenticated (same CSRF cookie but no session)
        bare, _ = _csrf_client(client.app)
        r = bare.post("/api/groups/personal/secrets/github/copy")
        assert r.status_code == 401

    def test_copy_requires_csrf(self, app, authed_client) -> None:
        authed_client.post("/api/groups", json={"name": "personal"})
        authed_client.post(
            "/api/groups/personal/secrets?name=github",
            json={"username": "a", "password": "COPY_SECRET_VALUE", "url": "", "notes": ""},
        )
        client = TestClient(app, base_url=BASE)
        client.get("/api/csrf")
        client.cookies.set(SESSION_COOKIE, authed_client.cookies.get(SESSION_COOKIE) or "")
        # Re-issue a valid session instead of trying to steal the fixture's cookie.
        token = issue_token()
        client.cookies.set(SESSION_COOKIE, token)
        r = client.post(
            "/api/groups/personal/secrets/github/copy",
            headers={"Origin": BASE},
        )
        assert r.status_code == 403

    def test_copy_does_not_return_password_and_is_non_cacheable(self, authed_client) -> None:
        authed_client.post("/api/groups", json={"name": "personal"})
        password = "COPY_SECRET_VALUE_NOT_IN_BODY"
        authed_client.post(
            "/api/groups/personal/secrets?name=github",
            json={"username": "a", "password": password, "url": "", "notes": ""},
        )
        with patch("zhubin.clipboard.clipboard.copy") as mock_copy:
            r = authed_client.post("/api/groups/personal/secrets/github/copy")
        assert r.status_code == 200
        body = r.json()
        assert password not in r.text
        assert "password" not in body or body.get("password") is None
        assert body["status"] == "copied"
        assert "no-store" in r.headers.get("cache-control", "").lower()
        mock_copy.assert_called_once()
        assert mock_copy.call_args[0][0] == password

    def test_secret_not_in_html_shell(self, client) -> None:
        r = client.get("/")
        assert r.status_code == 200
        # The SPA shell must not embed any vault secret.
        assert "COPY_SECRET" not in r.text
        assert "<script" in r.text.lower() or "app.js" in r.text

    def test_frontend_does_not_use_web_storage(self) -> None:
        js = (
            Path(__file__).resolve().parents[1]
            / "src"
            / "zhubin"
            / "web"
            / "static"
            / "js"
            / "app.js"
        )
        source = js.read_text()
        assert "localStorage" not in source
        assert "sessionStorage" not in source
        assert "indexedDB" not in source
        assert "navigator.clipboard" not in source  # copy is server-side
