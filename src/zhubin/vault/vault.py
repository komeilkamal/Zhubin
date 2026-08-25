"""
Vault service layer — the single authoritative interface for vault operations.

CLI and Web UI must go through this module.  Neither the CLI nor the Web
layer may perform cryptographic operations directly.

Architecture::

    CLI / Web UI
        |
        v
    VaultService          ← this module
        |
        +--→ crypto.identity   (device keys, group-key wrap/unwrap)
        +--→ crypto.encrypt    (secret encrypt/decrypt)
        +--→ storage.filesystem (file I/O)
        +--→ storage.git        (Git operations)

Session / unlock
----------------
``VaultService`` holds the unlocked ``DeviceIdentity`` in memory for the
duration of a session.  It is never serialised or written to disk.

When the service is locked, group keys cannot be decrypted and secrets
cannot be read.  The ``is_locked`` property reflects this state.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, TypedDict

from zhubin.crypto.encrypt import decrypt_secret, encrypt_secret
from zhubin.crypto.identity import (
    DeviceIdentity,
    generate_group_key,
    public_key_fingerprint,
    unwrap_group_key_with_identity,
    wrap_group_key_for_device,
)
from zhubin.exceptions import (
    DeviceNotFoundError,
    GroupAlreadyExistsError,
    KeyNotFoundError,
    UnauthorizedDeviceError,
)
from zhubin.storage.filesystem import (
    assert_vault,
    delete_group,
    delete_secret,
    group_exists,
    iter_all_secrets,
    list_devices,
    list_groups,
    list_secrets,
    load_device_by_id,
    load_group,
    load_secret_raw,
    save_device,
    save_group,
    save_secret,
    secret_exists,
)
from zhubin.vault.models import (
    DeviceKeyEntry,
    DeviceRecord,
    GroupRecord,
    SecretPayload,
)

if TYPE_CHECKING:
    from zhubin.storage.git import GitStatus


class AuthorizePreview(TypedDict):
    """Verification details shown before wrapping group keys for a device."""

    device: DeviceRecord
    fingerprint: str
    groups: list[str]


class VaultService:
    """
    High-level vault operations.

    Parameters
    ----------
    vault_path : Path
        Root of the Zhubin vault repository.
    identity : DeviceIdentity | None
        Unlocked device identity.  If None the vault is locked.
    """

    def __init__(self, vault_path: Path, identity: DeviceIdentity | None = None) -> None:
        self._vault_path = vault_path
        self._identity = identity

    # ------------------------------------------------------------------
    # Lock state
    # ------------------------------------------------------------------

    @property
    def is_locked(self) -> bool:
        return self._identity is None

    def unlock(self, identity: DeviceIdentity) -> None:
        self._identity = identity

    def lock(self) -> None:
        self._identity = None

    @property
    def identity_device_id(self) -> str | None:
        """Return the unlocked device id, or None if the vault is locked."""
        return self._identity.device_id if self._identity else None

    def _require_unlocked(self) -> DeviceIdentity:
        if self._identity is None:
            raise KeyNotFoundError("Vault is locked. Unlock with 'zhubin unlock'.")
        return self._identity

    # ------------------------------------------------------------------
    # Group key helpers
    # ------------------------------------------------------------------

    def _get_group_key(self, group_name: str) -> bytes:
        """Decrypt and return the group key for *group_name*."""
        identity = self._require_unlocked()
        group = load_group(self._vault_path, group_name)
        entry = group.device_keys.get(identity.device_id)
        if entry is None:
            raise UnauthorizedDeviceError(
                f"This device is not authorized for group '{group_name}'."
            )
        return unwrap_group_key_with_identity(entry.wrapped_key, identity)

    # ------------------------------------------------------------------
    # Group management
    # ------------------------------------------------------------------

    def create_group(self, name: str) -> GroupRecord:
        """
        Create a new group and wrap its key for the current device.

        Raises GroupAlreadyExistsError if the group exists.
        """
        identity = self._require_unlocked()
        if group_exists(self._vault_path, name):
            raise GroupAlreadyExistsError(f"Group '{name}' already exists.")

        group_key = generate_group_key()
        wrapped = wrap_group_key_for_device(group_key, identity.public_key_b64)

        group = GroupRecord(
            id=str(uuid.uuid4()),
            name=name,
            device_keys={identity.device_id: DeviceKeyEntry(wrapped_key=wrapped)},
        )
        save_group(self._vault_path, group)
        return group

    def list_groups(self) -> list[GroupRecord]:
        assert_vault(self._vault_path)
        return list_groups(self._vault_path)

    def delete_group(self, group_name: str) -> int:
        """
        Delete a group and all of its secrets.

        Returns the number of secrets that were removed with the group.
        Raises GroupNotFoundError if the group does not exist.

        Note: ciphertext may remain in Git history until rewritten.
        """
        assert_vault(self._vault_path)
        secret_count = len(list_secrets(self._vault_path, group_name))
        delete_group(self._vault_path, group_name)
        return secret_count

    def rotate_group_key(self, group_name: str) -> GroupRecord:
        """
        Generate a new group key, re-encrypt all secrets, wrap the new key
        for all currently authorized (non-revoked) devices.

        All transformations happen in memory.  No plaintext is written to disk.
        Atomic: the old group file is replaced only after all secrets are
        successfully re-encrypted.
        """
        self._require_unlocked()

        old_group_key = self._get_group_key(group_name)
        new_group_key = generate_group_key()

        # Re-encrypt all secrets
        secret_names = list_secrets(self._vault_path, group_name)
        new_encrypted: dict[str, bytes] = {}
        for sname in secret_names:
            raw = load_secret_raw(self._vault_path, group_name, sname)
            plaintext = decrypt_secret(raw, old_group_key)
            new_encrypted[sname] = encrypt_secret(plaintext, new_group_key)

        # Wrap the new key only for devices that currently have access to this
        # group and have not been revoked.  Registered-but-unauthorized devices
        # must not gain access as a side effect of rotation.
        old_group = load_group(self._vault_path, group_name)
        new_device_keys: dict[str, DeviceKeyEntry] = {}
        for device_id in list(old_group.device_keys):
            dev = load_device_by_id(self._vault_path, device_id)
            if dev is None or dev.revoked:
                continue
            wrapped = wrap_group_key_for_device(new_group_key, dev.public_key)
            new_device_keys[dev.id] = DeviceKeyEntry(wrapped_key=wrapped)

        # Persist atomically: secrets first, then group record
        for sname, data in new_encrypted.items():
            save_secret(self._vault_path, group_name, sname, data, overwrite=True)

        new_group = GroupRecord(
            id=old_group.id,
            name=group_name,
            created_at=old_group.created_at,
            device_keys=new_device_keys,
        )
        save_group(self._vault_path, new_group)
        return new_group

    # ------------------------------------------------------------------
    # Secret management
    # ------------------------------------------------------------------

    def add_secret(
        self,
        group_name: str,
        secret_name: str,
        payload: SecretPayload,
    ) -> None:
        """Encrypt and store a new secret."""
        group_key = self._get_group_key(group_name)
        encrypted = encrypt_secret(payload.to_bytes(), group_key)
        save_secret(self._vault_path, group_name, secret_name, encrypted)

    def get_secret(self, group_name: str, secret_name: str) -> SecretPayload:
        """Decrypt and return a secret payload."""
        group_key = self._get_group_key(group_name)
        raw = load_secret_raw(self._vault_path, group_name, secret_name)
        plaintext = decrypt_secret(raw, group_key)
        return SecretPayload.from_bytes(plaintext)

    def edit_secret(
        self,
        group_name: str,
        secret_name: str,
        payload: SecretPayload,
    ) -> None:
        """Replace an existing secret with new encrypted content."""
        group_key = self._get_group_key(group_name)
        encrypted = encrypt_secret(payload.to_bytes(), group_key)
        save_secret(self._vault_path, group_name, secret_name, encrypted, overwrite=True)

    def delete_secret(self, group_name: str, secret_name: str) -> None:
        delete_secret(self._vault_path, group_name, secret_name)

    def list_secrets(self, group_name: str) -> list[str]:
        return list_secrets(self._vault_path, group_name)

    def list_all_secrets(self) -> list[tuple[str, str]]:
        """Return list of (group_name, secret_name) for all secrets."""
        return list(iter_all_secrets(self._vault_path))

    def find_secrets(self, query: str) -> list[tuple[str, str]]:
        """Case-insensitive substring search over group/secret names."""
        q = query.lower()
        return [
            (g, s)
            for g, s in iter_all_secrets(self._vault_path)
            if q in g.lower() or q in s.lower()
        ]

    def secret_exists(self, group_name: str, secret_name: str) -> bool:
        return secret_exists(self._vault_path, group_name, secret_name)

    # ------------------------------------------------------------------
    # Device management
    # ------------------------------------------------------------------

    def register_device(self, device: DeviceRecord) -> None:
        """Add a device record to the vault (public info only)."""
        save_device(self._vault_path, device)

    def _find_device(self, device_name: str) -> DeviceRecord:
        for dev in list_devices(self._vault_path):
            if dev.name == device_name:
                return dev
        raise DeviceNotFoundError(f"Device '{device_name}' not found.")

    def preview_authorize(self, device_name: str) -> AuthorizePreview:
        """
        Return verification details for authorizing *device_name*.

        Presence of a public key in Git is not treated as proof of identity;
        the caller must display the fingerprint and obtain explicit confirmation
        before calling ``authorize_device``.
        """
        identity = self._require_unlocked()
        target = self._find_device(device_name)
        if target.revoked:
            raise DeviceNotFoundError(f"Device '{device_name}' has been revoked.")
        groups = [
            g.name for g in list_groups(self._vault_path) if identity.device_id in g.device_keys
        ]
        return {
            "device": target,
            "fingerprint": public_key_fingerprint(target.public_key),
            "groups": groups,
        }

    def authorize_device(self, device_name: str) -> list[str]:
        """
        Authorize a device for all groups the current device has access to.

        This wraps group keys for the new device without requiring secret
        re-encryption.  Callers must have verified the device fingerprint.
        Returns the list of groups the device was authorized for.
        """
        identity = self._require_unlocked()
        target = self._find_device(device_name)
        if target.revoked:
            raise DeviceNotFoundError(f"Device '{device_name}' has been revoked.")

        authorized: list[str] = []
        for group in list_groups(self._vault_path):
            if identity.device_id not in group.device_keys:
                continue
            try:
                group_key = self._get_group_key(group.name)
            except UnauthorizedDeviceError:
                continue

            wrapped = wrap_group_key_for_device(group_key, target.public_key)
            group.device_keys[target.id] = DeviceKeyEntry(wrapped_key=wrapped)
            save_group(self._vault_path, group)
            authorized.append(group.name)
        return authorized

    def revoke_device(
        self,
        device_name: str,
        *,
        rotate_groups: bool = True,
    ) -> list[str]:
        """
        Revoke a device.

        Returns list of group names that were affected (and optionally rotated).
        """
        identity = self._require_unlocked()
        target = self._find_device(device_name)

        # Mark revoked in device record
        target.revoked = True
        target.revoked_at = datetime.now(tz=UTC)
        save_device(self._vault_path, target)

        # Find affected groups (current authorization metadata)
        affected = [g.name for g in list_groups(self._vault_path) if target.id in g.device_keys]

        # Remove device keys from groups (prevents *future* wraps for this device)
        for group in list_groups(self._vault_path):
            if target.id in group.device_keys:
                del group.device_keys[target.id]
                save_group(self._vault_path, group)

        # Cryptographic revocation: rotate affected groups so historical wrapped
        # keys in Git history cannot decrypt newly written ciphertext.
        # Rotation failures fail closed (they are not swallowed).
        if rotate_groups:
            for gname in affected:
                current = load_group(self._vault_path, gname)
                if identity.device_id in current.device_keys:
                    self.rotate_group_key(gname)

        return affected

    def list_devices(self) -> list[DeviceRecord]:
        return list_devices(self._vault_path)

    # ------------------------------------------------------------------
    # Git integration
    # ------------------------------------------------------------------

    def git_status(self) -> GitStatus:
        from zhubin.storage.git import get_status

        return get_status(self._vault_path)

    def git_sync(self, message: str = "zhubin: sync vault") -> dict[str, str]:
        from zhubin.storage.git import sync

        return sync(self._vault_path, message)
