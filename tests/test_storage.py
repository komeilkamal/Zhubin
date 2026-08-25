"""
Tests for storage layer: filesystem, path safety, vault init.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from zhubin.exceptions import (
    GroupNotFoundError,
    PathTraversalError,
    SecretNotFoundError,
    VaultAlreadyExistsError,
    VaultNotFoundError,
)
from zhubin.storage.filesystem import (
    assert_vault,
    delete_secret,
    init_vault,
    list_groups,
    list_secrets,
    load_secret_raw,
    save_group,
    save_secret,
)
from zhubin.vault.models import GroupRecord


@pytest.fixture
def vault_path(tmp_path: Path) -> Path:
    vp = tmp_path / "vault"
    init_vault(vp)
    return vp


class TestVaultInit:
    def test_creates_expected_directories(self, tmp_path: Path) -> None:
        vp = tmp_path / "vault"
        init_vault(vp)
        assert (vp / "config.yaml").exists()
        assert (vp / "devices").is_dir()
        assert (vp / "groups").is_dir()
        assert (vp / ".gitignore").exists()
        assert (vp / ".gitattributes").exists()
        ga = (vp / ".gitattributes").read_text()
        assert "*.secret binary" in ga
        assert "group.json" in ga

    def test_double_init_raises(self, tmp_path: Path) -> None:
        vp = tmp_path / "vault"
        init_vault(vp)
        with pytest.raises(VaultAlreadyExistsError):
            init_vault(vp)

    def test_gitignore_contains_private_key_patterns(self, tmp_path: Path) -> None:
        vp = tmp_path / "vault"
        init_vault(vp)
        gi = (vp / ".gitignore").read_text()
        assert "private_key" in gi
        assert "*.key" in gi


class TestAssertVault:
    def test_missing_vault_raises(self, tmp_path: Path) -> None:
        with pytest.raises(VaultNotFoundError):
            assert_vault(tmp_path / "nonexistent")


class TestGroupStorage:
    def test_save_and_load_group(self, vault_path: Path) -> None:
        from zhubin.storage.filesystem import load_group

        group = GroupRecord(id="abc", name="personal")
        save_group(vault_path, group)
        loaded = load_group(vault_path, "personal")
        assert loaded.name == "personal"
        assert loaded.id == "abc"

    def test_load_nonexistent_group_raises(self, vault_path: Path) -> None:
        from zhubin.storage.filesystem import load_group

        with pytest.raises(GroupNotFoundError):
            load_group(vault_path, "nonexistent")

    def test_list_groups(self, vault_path: Path) -> None:
        save_group(vault_path, GroupRecord(id="1", name="work"))
        save_group(vault_path, GroupRecord(id="2", name="home"))
        groups = list_groups(vault_path)
        names = {g.name for g in groups}
        assert names == {"work", "home"}


class TestSecretStorage:
    def test_save_and_load_secret(self, vault_path: Path) -> None:
        save_group(vault_path, GroupRecord(id="1", name="personal"))
        encrypted = b'{"version":1,"cipher":"xsalsa20poly1305","ciphertext":"dGVzdA=="}'
        save_secret(vault_path, "personal", "github", encrypted)
        raw = load_secret_raw(vault_path, "personal", "github")
        assert raw == encrypted

    def test_load_nonexistent_secret_raises(self, vault_path: Path) -> None:
        save_group(vault_path, GroupRecord(id="1", name="personal"))
        with pytest.raises(SecretNotFoundError):
            load_secret_raw(vault_path, "personal", "nope")

    def test_list_secrets(self, vault_path: Path) -> None:
        save_group(vault_path, GroupRecord(id="1", name="personal"))
        save_secret(vault_path, "personal", "a", b"data1")
        save_secret(vault_path, "personal", "b", b"data2")
        names = list_secrets(vault_path, "personal")
        assert "a" in names
        assert "b" in names

    def test_atomic_write_does_not_leave_temp_file(self, vault_path: Path) -> None:
        save_group(vault_path, GroupRecord(id="1", name="personal"))
        save_secret(vault_path, "personal", "atomic", b"data")
        tmps = list((vault_path / "groups" / "personal" / "secrets").glob(".tmp.*"))
        assert tmps == []

    def test_nested_secret_roundtrip(self, vault_path: Path) -> None:
        save_group(vault_path, GroupRecord(id="1", name="own"))
        save_secret(vault_path, "own", "ilo/bank/s", b"nested-data")
        expected = vault_path / "groups" / "own" / "secrets" / "ilo" / "bank" / "s.secret"
        assert expected.is_file()
        assert expected.read_bytes() == b"nested-data"
        assert load_secret_raw(vault_path, "own", "ilo/bank/s") == b"nested-data"
        assert "ilo/bank/s" in list_secrets(vault_path, "own")

    def test_list_mixes_flat_and_nested(self, vault_path: Path) -> None:
        save_group(vault_path, GroupRecord(id="1", name="own"))
        save_secret(vault_path, "own", "github", b"flat")
        save_secret(vault_path, "own", "ilo/bank/s", b"nested")
        names = list_secrets(vault_path, "own")
        assert names == ["github", "ilo/bank/s"]

    def test_delete_nested_prunes_empty_dirs(self, vault_path: Path) -> None:
        save_group(vault_path, GroupRecord(id="1", name="own"))
        save_secret(vault_path, "own", "ilo/bank/s", b"nested")
        save_secret(vault_path, "own", "ilo/other", b"keep")
        delete_secret(vault_path, "own", "ilo/bank/s")
        secrets_dir = vault_path / "groups" / "own" / "secrets"
        assert not (secrets_dir / "ilo" / "bank").exists()
        assert (secrets_dir / "ilo" / "other.secret").is_file()
        delete_secret(vault_path, "own", "ilo/other")
        assert not (secrets_dir / "ilo").exists()
        assert secrets_dir.is_dir()


class TestPathSafety:
    def test_traversal_in_secret_name(self, vault_path: Path) -> None:
        save_group(vault_path, GroupRecord(id="1", name="personal"))
        with pytest.raises((PathTraversalError, Exception)):
            save_secret(vault_path, "personal", "../../../evil", b"x")

    def test_traversal_in_group_name(self, vault_path: Path) -> None:
        from zhubin.storage.filesystem import load_group

        with pytest.raises((PathTraversalError, Exception)):
            load_group(vault_path, "../../etc")

    def test_absolute_path_in_secret_name(self, vault_path: Path) -> None:
        save_group(vault_path, GroupRecord(id="1", name="personal"))
        with pytest.raises((PathTraversalError, Exception)):
            save_secret(vault_path, "personal", "/etc/passwd", b"x")

    @pytest.mark.parametrize(
        "bad_name",
        [
            "../evil",
            "ilo/../../etc/passwd",
            "/etc/passwd",
            "ilo//s",
            "ilo/.",
            "ilo/..",
            r"ilo\bank",
        ],
    )
    def test_nested_secret_traversal_rejected(self, vault_path: Path, bad_name: str) -> None:
        save_group(vault_path, GroupRecord(id="1", name="personal"))
        with pytest.raises(PathTraversalError):
            save_secret(vault_path, "personal", bad_name, b"x")
