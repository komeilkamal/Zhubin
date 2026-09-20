"""
Tests for CLI Tab completion of group and secret paths.

Completers must:
- Match group/secret names one segment at a time.
- Work on a locked vault (no identity, no passphrase prompt).
- Never read secret file bytes.
- Fail closed to an empty list when the vault is missing.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import typer

from zhubin.cli.completion import (
    _next_path_segments,
    _zsh_compadd_script,
    complete_cp_field,
    complete_group_name,
    complete_secret_path,
)
from zhubin.crypto.identity import create_device_identity
from zhubin.storage.filesystem import init_vault, load_secret_raw, save_device
from zhubin.vault.models import DeviceRecord, SecretPayload
from zhubin.vault.vault import VaultService

_KNOWN_PASSWORD = "PLAINTEXT_PASSWORD_NEVER_ON_DISK_98765"


@pytest.fixture
def vault_path(tmp_path: Path) -> Path:
    """Return an initialised vault directory."""
    vp = tmp_path / "vault"
    init_vault(vp)
    return vp


@pytest.fixture
def identity():
    return create_device_identity()


@pytest.fixture
def svc(vault_path: Path, identity) -> VaultService:
    """Return an unlocked VaultService with a registered device."""
    dr = DeviceRecord(
        id=identity.device_id,
        name="test-device",
        public_key=identity.public_key_b64,
    )
    save_device(vault_path, dr)
    return VaultService(vault_path, identity)


@pytest.fixture
def populated(svc: VaultService, vault_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Vault with groups and nested secrets; ZHUBIN_VAULT points at it."""
    svc.create_group("personal")
    svc.create_group("own")
    svc.create_group("work")
    svc.add_secret("personal", "github", SecretPayload(password=_KNOWN_PASSWORD))
    svc.add_secret("personal", "gitlab", SecretPayload(password="other"))
    svc.add_secret("personal", "ilo/bank/s", SecretPayload(password="bank"))
    svc.add_secret("own", "ilo/bank/s", SecretPayload(password="own-bank"))
    monkeypatch.setenv("ZHUBIN_VAULT", str(vault_path))
    return vault_path


class TestNextPathSegments:
    def test_empty_prefix_offers_leaves_and_folders(self) -> None:
        assert _next_path_segments("", ["ilo/bank/s", "github"]) == ["ilo/", "github"]

    def test_partial_folder_completes_through_slash(self) -> None:
        assert _next_path_segments("ilo/ba", ["ilo/bank/s", "ilo/other"]) == ["ilo/bank/"]

    def test_exact_leaf_has_no_trailing_slash(self) -> None:
        assert _next_path_segments("github", ["github"]) == ["github"]


class TestCompleteSecretPath:
    def test_non_vault_returns_empty(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("ZHUBIN_VAULT", str(tmp_path / "missing"))
        assert complete_secret_path("per") == []
        assert complete_secret_path("") == []

    def test_group_prefix(self, populated: Path) -> None:
        assert complete_secret_path("per") == ["personal/"]

    def test_empty_incomplete_lists_groups(self, populated: Path) -> None:
        assert complete_secret_path("") == ["own/", "personal/", "work/"]

    def test_group_slash_lists_next_segments(self, populated: Path) -> None:
        assert complete_secret_path("personal/") == [
            "personal/github",
            "personal/gitlab",
            "personal/ilo/",
        ]

    def test_nested_folder_prefix(self, populated: Path) -> None:
        assert complete_secret_path("own/ilo/ba") == ["own/ilo/bank/"]

    def test_exact_leaf_has_no_trailing_slash(self, populated: Path) -> None:
        assert complete_secret_path("personal/github") == ["personal/github"]

    def test_unknown_group_returns_empty(self, populated: Path) -> None:
        assert complete_secret_path("nope/") == []

    def test_locked_vault_still_completes(
        self, populated: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def _no_identity(*_args: object, **_kwargs: object) -> None:
            raise AssertionError("completer must not load a device identity")

        monkeypatch.setattr("zhubin.crypto.identity.load_device_identity", _no_identity)
        monkeypatch.setattr("zhubin.crypto.identity.identity_exists", lambda: False)
        assert complete_secret_path("per") == ["personal/"]
        assert complete_secret_path("own/ilo/") == ["own/ilo/bank/"]

    def test_does_not_prompt(self, populated: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        def _no_prompt(*_args: object, **_kwargs: object) -> str:
            raise AssertionError("completer must not prompt")

        monkeypatch.setattr(typer, "prompt", _no_prompt)
        assert complete_secret_path("personal/git") == [
            "personal/github",
            "personal/gitlab",
        ]

    def test_does_not_read_secret_bytes(
        self, populated: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        original = Path.read_bytes

        def guarded(self: Path) -> bytes:
            if self.suffix == ".secret":
                raise AssertionError("completer must not read secret files")
            return original(self)

        monkeypatch.setattr(Path, "read_bytes", guarded)
        matches = complete_secret_path("personal/")
        assert "personal/github" in matches
        assert _KNOWN_PASSWORD not in "".join(matches)

    def test_plaintext_stays_encrypted(self, populated: Path) -> None:
        raw = load_secret_raw(populated, "personal", "github")
        assert _KNOWN_PASSWORD.encode() not in raw
        complete_secret_path("personal/github")
        raw_after = load_secret_raw(populated, "personal", "github")
        assert _KNOWN_PASSWORD.encode() not in raw_after


class TestCompleteGroupName:
    def test_prefix(self, populated: Path) -> None:
        assert complete_group_name("per") == ["personal"]

    def test_all_groups(self, populated: Path) -> None:
        assert complete_group_name("") == ["own", "personal", "work"]

    def test_non_vault_returns_empty(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("ZHUBIN_VAULT", str(tmp_path / "missing"))
        assert complete_group_name("per") == []


class TestCompleteCpField:
    def test_password_prefix(self) -> None:
        assert complete_cp_field("pass") == ["password"]

    def test_u_prefix(self) -> None:
        assert complete_cp_field("u") == ["username", "url"]

    def test_no_match(self) -> None:
        assert complete_cp_field("x") == []


class TestZshCompaddScript:
    def test_folder_uses_empty_suffix(self) -> None:
        script = _zsh_compadd_script(["myket/"])
        assert script == "compadd -U -S '' -- 'myket/'"
        assert "_arguments" not in script

    def test_leaf_keeps_default_space_suffix(self) -> None:
        script = _zsh_compadd_script(["personal/github"])
        assert script == "compadd -U -- 'personal/github'"
        assert "-S ''" not in script

    def test_mixed_folders_and_leaves(self) -> None:
        script = _zsh_compadd_script(["personal/ilo/", "personal/github"])
        assert "compadd -U -S '' -- 'personal/ilo/'" in script
        assert "compadd -U -- 'personal/github'" in script

    def test_empty_falls_back_to_files(self) -> None:
        assert _zsh_compadd_script([]) == "_files"

    def test_typer_zsh_complete_omits_space_after_group(
        self, populated: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from typer._completion_classes import ZshComplete
        from typer.main import get_command

        from zhubin.cli.app import app

        monkeypatch.setenv("_TYPER_COMPLETE_ARGS", "zhubin show per")
        cli = get_command(app)
        result = ZshComplete(cli, {}, "zhubin", "_ZHUBIN_COMPLETE").complete()
        assert "compadd -U -S '' -- 'personal/'" in result
        assert "_arguments" not in result
