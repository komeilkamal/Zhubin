"""
Tests for vault-level operations (VaultService).

Security invariants verified:
- Secrets are stored encrypted — plaintext never appears on disk.
- Wrong device (no group key) → UnauthorizedDeviceError.
- Group key rotation re-encrypts all secrets and updates device_keys.
- Device revocation removes device from group.device_keys.
- Path traversal attempts are rejected.
- Malformed vault files are safely rejected.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from zhubin.crypto.identity import create_device_identity
from zhubin.exceptions import (
    GroupAlreadyExistsError,
    KeyNotFoundError,
    PathTraversalError,
    SecretAlreadyExistsError,
    SecretNotFoundError,
    UnauthorizedDeviceError,
)
from zhubin.storage.filesystem import (
    init_vault,
    load_group,
    load_secret_raw,
    save_device,
)
from zhubin.vault.models import DeviceRecord, SecretPayload
from zhubin.vault.vault import VaultService

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


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
def svc(vault_path: Path, identity):
    """Return an unlocked VaultService with a registered device."""
    dr = DeviceRecord(
        id=identity.device_id,
        name="test-device",
        public_key=identity.public_key_b64,
    )
    save_device(vault_path, dr)
    return VaultService(vault_path, identity)


# ---------------------------------------------------------------------------
# Group management
# ---------------------------------------------------------------------------


class TestGroups:
    def test_create_group(self, svc: VaultService) -> None:
        group = svc.create_group("personal")
        assert group.name == "personal"
        assert svc.identity_device_id in group.device_keys

    def test_create_duplicate_group_raises(self, svc: VaultService) -> None:
        svc.create_group("personal")
        with pytest.raises(GroupAlreadyExistsError):
            svc.create_group("personal")

    def test_list_groups(self, svc: VaultService) -> None:
        svc.create_group("work")
        svc.create_group("home")
        groups = svc.list_groups()
        names = [g.name for g in groups]
        assert "work" in names
        assert "home" in names

    def test_delete_group_removes_secrets(self, svc: VaultService, vault_path: Path) -> None:
        svc.create_group("personal")
        svc.add_secret("personal", "github", SecretPayload(password="a"))
        svc.add_secret("personal", "ilo/bank/s", SecretPayload(password="b"))
        deleted = svc.delete_group("personal")
        assert deleted == 2
        assert "personal" not in {g.name for g in svc.list_groups()}
        assert not (vault_path / "groups" / "personal").exists()

    def test_delete_empty_group(self, svc: VaultService) -> None:
        svc.create_group("empty")
        assert svc.delete_group("empty") == 0
        assert "empty" not in {g.name for g in svc.list_groups()}

    def test_delete_nonexistent_group_raises(self, svc: VaultService) -> None:
        from zhubin.exceptions import GroupNotFoundError

        with pytest.raises(GroupNotFoundError):
            svc.delete_group("missing")


# ---------------------------------------------------------------------------
# Secret management
# ---------------------------------------------------------------------------


class TestSecrets:
    def test_add_and_get_secret(self, svc: VaultService, vault_path: Path) -> None:
        svc.create_group("personal")
        payload = SecretPayload(username="alice", password="s3cr3t", url="https://example.com")
        svc.add_secret("personal", "github", payload)

        recovered = svc.get_secret("personal", "github")
        assert recovered.username == "alice"
        assert recovered.password == "s3cr3t"
        assert recovered.url == "https://example.com"

    def test_plaintext_not_in_secret_file(self, svc: VaultService, vault_path: Path) -> None:
        svc.create_group("personal")
        secret_password = "PLAINTEXT_PASSWORD_NEVER_STORED_12345"
        payload = SecretPayload(password=secret_password)
        svc.add_secret("personal", "test-secret", payload)

        raw = load_secret_raw(vault_path, "personal", "test-secret")
        assert secret_password.encode() not in raw
        assert b"PLAINTEXT_PASSWORD_NEVER_STORED" not in raw

    def test_edit_secret(self, svc: VaultService) -> None:
        svc.create_group("personal")
        svc.add_secret("personal", "gmail", SecretPayload(password="old"))
        svc.edit_secret("personal", "gmail", SecretPayload(password="new"))
        assert svc.get_secret("personal", "gmail").password == "new"

    def test_delete_secret(self, svc: VaultService) -> None:
        svc.create_group("personal")
        svc.add_secret("personal", "todelete", SecretPayload(password="x"))
        svc.delete_secret("personal", "todelete")
        with pytest.raises(SecretNotFoundError):
            svc.get_secret("personal", "todelete")

    def test_duplicate_secret_raises(self, svc: VaultService) -> None:
        svc.create_group("personal")
        svc.add_secret("personal", "dup", SecretPayload(password="x"))
        with pytest.raises(SecretAlreadyExistsError):
            svc.add_secret("personal", "dup", SecretPayload(password="y"))

    def test_list_secrets(self, svc: VaultService) -> None:
        svc.create_group("work")
        svc.add_secret("work", "jira", SecretPayload(password="a"))
        svc.add_secret("work", "confluence", SecretPayload(password="b"))
        names = svc.list_secrets("work")
        assert "jira" in names
        assert "confluence" in names

    def test_find_secrets(self, svc: VaultService) -> None:
        svc.create_group("personal")
        svc.create_group("work")
        svc.add_secret("personal", "github", SecretPayload(password="a"))
        svc.add_secret("work", "github-enterprise", SecretPayload(password="b"))
        results = svc.find_secrets("github")
        assert ("personal", "github") in results
        assert ("work", "github-enterprise") in results

    def test_nested_secret_roundtrip(self, svc: VaultService, vault_path: Path) -> None:
        svc.create_group("own")
        payload = SecretPayload(username="alice", password="NESTED_PLAINTEXT_SCAN_999")
        svc.add_secret("own", "ilo/bank/s", payload)

        recovered = svc.get_secret("own", "ilo/bank/s")
        assert recovered.username == "alice"
        assert recovered.password == "NESTED_PLAINTEXT_SCAN_999"

        secret_file = vault_path / "groups" / "own" / "secrets" / "ilo" / "bank" / "s.secret"
        assert secret_file.is_file()
        raw = secret_file.read_bytes()
        assert b"NESTED_PLAINTEXT_SCAN_999" not in raw
        assert b"alice" not in raw
        assert "ilo/bank/s" in svc.list_secrets("own")

    def test_nested_secret_edit_and_delete(self, svc: VaultService, vault_path: Path) -> None:
        svc.create_group("own")
        svc.add_secret("own", "ilo/bank/s", SecretPayload(password="old"))
        svc.edit_secret("own", "ilo/bank/s", SecretPayload(password="new"))
        assert svc.get_secret("own", "ilo/bank/s").password == "new"
        svc.delete_secret("own", "ilo/bank/s")
        with pytest.raises(SecretNotFoundError):
            svc.get_secret("own", "ilo/bank/s")
        assert not (vault_path / "groups" / "own" / "secrets" / "ilo").exists()

    def test_unauthorized_device_cannot_read(self, vault_path: Path) -> None:
        """A device with no group-key entry cannot decrypt secrets."""
        id1 = create_device_identity()
        id2 = create_device_identity()
        # Register both devices
        for i, ident in enumerate([id1, id2]):
            save_device(
                vault_path,
                DeviceRecord(id=ident.device_id, name=f"dev{i}", public_key=ident.public_key_b64),
            )

        svc1 = VaultService(vault_path, id1)
        svc1.create_group("personal")
        svc1.add_secret("personal", "secret", SecretPayload(password="hidden"))

        # id2 was never authorized — should raise
        svc2 = VaultService(vault_path, id2)
        with pytest.raises(UnauthorizedDeviceError):
            svc2.get_secret("personal", "secret")


# ---------------------------------------------------------------------------
# Group key rotation
# ---------------------------------------------------------------------------


class TestKeyRotation:
    def test_rotate_group_key(self, svc: VaultService, vault_path: Path) -> None:
        svc.create_group("personal")
        svc.add_secret("personal", "gmail", SecretPayload(password="mypass"))
        svc.add_secret("personal", "twitter", SecretPayload(password="bird"))

        old_group = load_group(vault_path, "personal")
        old_wrapped = old_group.device_keys[svc.identity_device_id].wrapped_key

        svc.rotate_group_key("personal")

        new_group = load_group(vault_path, "personal")
        new_wrapped = new_group.device_keys[svc.identity_device_id].wrapped_key

        # Wrapped key must have changed (new group key)
        assert old_wrapped != new_wrapped

        # Secrets must still be readable
        assert svc.get_secret("personal", "gmail").password == "mypass"
        assert svc.get_secret("personal", "twitter").password == "bird"

    def test_rotate_nested_secret(self, svc: VaultService) -> None:
        svc.create_group("own")
        svc.add_secret("own", "ilo/bank/s", SecretPayload(password="nested-pw"))
        svc.rotate_group_key("own")
        assert svc.get_secret("own", "ilo/bank/s").password == "nested-pw"

    def test_old_group_key_cannot_decrypt_rotated_secrets(
        self, svc: VaultService, vault_path: Path
    ) -> None:
        """After rotation, old group key must not decrypt new ciphertexts."""
        from zhubin.crypto.encrypt import decrypt_secret as ds
        from zhubin.crypto.identity import unwrap_group_key_with_identity
        from zhubin.exceptions import AuthenticationError

        svc.create_group("personal")
        svc.add_secret("personal", "secret", SecretPayload(password="before"))

        # Capture old group key
        old_group = load_group(vault_path, "personal")
        old_wrapped = old_group.device_keys[svc.identity_device_id].wrapped_key
        old_key = unwrap_group_key_with_identity(old_wrapped, svc._identity)

        svc.rotate_group_key("personal")

        # Try to decrypt new ciphertext with old key
        raw = load_secret_raw(vault_path, "personal", "secret")
        with pytest.raises(AuthenticationError):
            ds(raw, old_key)


# ---------------------------------------------------------------------------
# Device authorization
# ---------------------------------------------------------------------------


class TestDeviceAuthorization:
    def test_authorize_new_device(self, svc: VaultService, vault_path: Path) -> None:
        id2 = create_device_identity()
        save_device(
            vault_path,
            DeviceRecord(id=id2.device_id, name="device2", public_key=id2.public_key_b64),
        )

        svc.create_group("personal")
        svc.add_secret("personal", "secret", SecretPayload(password="shared"))

        svc.authorize_device("device2")

        svc2 = VaultService(vault_path, id2)
        recovered = svc2.get_secret("personal", "secret")
        assert recovered.password == "shared"

    def test_revoke_device_removes_keys(self, svc: VaultService, vault_path: Path) -> None:
        id2 = create_device_identity()
        save_device(
            vault_path,
            DeviceRecord(id=id2.device_id, name="bad-device", public_key=id2.public_key_b64),
        )

        svc.create_group("personal")
        svc.authorize_device("bad-device")

        svc.revoke_device("bad-device", rotate_groups=False)

        group = load_group(vault_path, "personal")
        assert id2.device_id not in group.device_keys

    def test_revoke_with_rotation_semantics(self, svc: VaultService, vault_path: Path) -> None:
        from zhubin.crypto.encrypt import decrypt_secret as ds
        from zhubin.crypto.identity import unwrap_group_key_with_identity
        from zhubin.exceptions import AuthenticationError
        from zhubin.storage.filesystem import load_device

        id2 = create_device_identity()
        save_device(
            vault_path,
            DeviceRecord(id=id2.device_id, name="lost-laptop", public_key=id2.public_key_b64),
        )
        svc.create_group("personal")
        svc.add_secret("personal", "github", SecretPayload(password="historical"))
        svc.authorize_device("lost-laptop")

        old_group = load_group(vault_path, "personal")
        old_wrapped = old_group.device_keys[id2.device_id].wrapped_key
        old_key = unwrap_group_key_with_identity(old_wrapped, id2)
        old_ciphertext = load_secret_raw(vault_path, "personal", "github")

        # Historical ciphertext remains decryptable with the old group key.
        recovered = SecretPayload.from_bytes(ds(old_ciphertext, old_key))
        assert recovered.password == "historical"

        affected = svc.revoke_device("lost-laptop", rotate_groups=True)
        assert "personal" in affected

        # Current metadata no longer lists the revoked device.
        new_group = load_group(vault_path, "personal")
        assert id2.device_id not in new_group.device_keys
        rec = load_device(vault_path, "lost-laptop")
        assert rec.revoked is True

        # Rotation produced a new wrapped key for the remaining device.
        assert svc.identity_device_id in new_group.device_keys
        old_wrap = old_group.device_keys[svc.identity_device_id].wrapped_key
        new_wrap = new_group.device_keys[svc.identity_device_id].wrapped_key
        assert new_wrap != old_wrap

        # Revoked device cannot read current ciphertext with the old group key.
        new_ciphertext = load_secret_raw(vault_path, "personal", "github")
        with pytest.raises(AuthenticationError):
            ds(new_ciphertext, old_key)

        svc2 = VaultService(vault_path, id2)
        with pytest.raises(UnauthorizedDeviceError):
            svc2.get_secret("personal", "github")

        # Currently authorized device still works; historical blob still matches old key.
        assert svc.get_secret("personal", "github").password == "historical"
        assert SecretPayload.from_bytes(ds(old_ciphertext, old_key)).password == "historical"

    def test_rotation_does_not_authorize_unrelated_device(
        self, svc: VaultService, vault_path: Path
    ) -> None:
        outsider = create_device_identity()
        save_device(
            vault_path,
            DeviceRecord(
                id=outsider.device_id, name="never-authorized", public_key=outsider.public_key_b64
            ),
        )
        svc.create_group("personal")
        svc.add_secret("personal", "x", SecretPayload(password="p"))
        svc.rotate_group_key("personal")
        group = load_group(vault_path, "personal")
        assert outsider.device_id not in group.device_keys
        with pytest.raises(UnauthorizedDeviceError):
            VaultService(vault_path, outsider).get_secret("personal", "x")


# ---------------------------------------------------------------------------
# Path traversal
# ---------------------------------------------------------------------------


class TestPathTraversal:
    def test_group_name_traversal(self, vault_path: Path) -> None:
        from zhubin.storage.filesystem import load_group

        with pytest.raises((PathTraversalError, Exception)):
            load_group(vault_path, "../../../etc")

    def test_secret_name_traversal(self, svc: VaultService) -> None:
        svc.create_group("personal")
        with pytest.raises((PathTraversalError, Exception)):
            svc.add_secret("personal", "../../etc/passwd", SecretPayload(password="x"))

    def test_nested_secret_name_traversal(self, svc: VaultService) -> None:
        svc.create_group("personal")
        with pytest.raises(PathTraversalError):
            svc.add_secret("personal", "ilo/../../etc/passwd", SecretPayload(password="x"))

    def test_group_name_absolute_path(self, vault_path: Path) -> None:
        from zhubin.storage.filesystem import load_group

        with pytest.raises((PathTraversalError, Exception)):
            load_group(vault_path, "/etc/passwd")


# ---------------------------------------------------------------------------
# Vault state
# ---------------------------------------------------------------------------


class TestVaultState:
    def test_locked_vault_cannot_read(self, vault_path: Path) -> None:
        svc = VaultService(vault_path)  # no identity → locked
        assert svc.is_locked
        with pytest.raises(KeyNotFoundError):
            svc.get_secret("personal", "anything")

    def test_malformed_secret_file_raises(self, svc: VaultService, vault_path: Path) -> None:
        from zhubin.exceptions import FormatError

        svc.create_group("personal")
        # Write garbage directly
        from zhubin.storage.filesystem import _secret_path

        p = _secret_path(vault_path, "personal", "bad")
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(b"THIS IS NOT VALID JSON OR CIPHERTEXT")

        with pytest.raises((FormatError, Exception)):
            svc.get_secret("personal", "bad")


# ---------------------------------------------------------------------------
# Plaintext scan helper
# ---------------------------------------------------------------------------


def scan_vault_for_plaintext(vault_path: Path, known_plaintext: str) -> list[Path]:
    """Return a list of vault files that contain *known_plaintext*."""
    found = []
    for f in vault_path.rglob("*"):
        if f.is_file():
            try:
                if known_plaintext.encode() in f.read_bytes():
                    found.append(f)
            except Exception:
                pass
    return found


class TestPlaintextScan:
    def test_no_plaintext_in_vault_files(self, svc: VaultService, vault_path: Path) -> None:
        svc.create_group("personal")
        secret_password = "UNIQUE_TEST_SECRET_NEVER_STORE_PLAINTEXT_XYZZY"
        svc.add_secret("personal", "test", SecretPayload(password=secret_password))
        found = scan_vault_for_plaintext(vault_path, secret_password)
        assert found == [], f"Plaintext found in: {found}"
