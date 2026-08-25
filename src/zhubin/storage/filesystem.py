"""
Filesystem storage layer for the Zhubin vault.

All file I/O for vault objects is centralised here.  Callers never
manipulate vault paths directly.

Path safety
-----------
All group names and each segment of a (possibly nested) secret name are
validated by ``_validate_simple_name`` / ``_validate_secret_name`` AND by
``_safe_join`` before any filesystem access.  ``..``, absolute paths and
symlink traversals are rejected.  Nested secret paths stay under the
group's ``secrets/`` directory.

Atomic writes
-------------
New or updated files are written to a ``.tmp.<random>`` sibling, then
renamed atomically.  Only encrypted data is ever written to disk.
"""

from __future__ import annotations

import contextlib
import os
import re
import secrets
import shutil
from collections.abc import Iterator
from pathlib import Path

from zhubin.exceptions import (
    GroupNotFoundError,
    PathTraversalError,
    SecretAlreadyExistsError,
    SecretNotFoundError,
    VaultAlreadyExistsError,
    VaultNotFoundError,
)
from zhubin.vault.models import DeviceRecord, GroupRecord

# File names
_GROUP_FILE = "group.json"
_SECRET_EXT = ".secret"
_DEVICE_DIR = "devices"
_GROUP_DIR = "groups"
_SECRETS_DIR = "secrets"
_CONFIG_FILE = "config.yaml"
_GITIGNORE_FILE = ".gitignore"
_GITATTRIBUTES_FILE = ".gitattributes"

_NAME_RE = re.compile(r"^[a-zA-Z0-9_\-\.]+$")
_MAX_NAME_LEN = 64
_MAX_SECRET_DEPTH = 32
_MAX_SECRET_PATH_LEN = 512


# ---------------------------------------------------------------------------
# Path helpers
# ---------------------------------------------------------------------------


def _safe_join(base: Path, *parts: str) -> Path:
    """
    Safely join *parts* under *base*, rejecting traversal attempts.

    Raises PathTraversalError if the resolved path escapes *base*.
    """
    try:
        target = base.joinpath(*parts).resolve()
    except Exception as exc:
        raise PathTraversalError(f"Invalid path components: {parts!r}") from exc
    base_resolved = base.resolve()
    if not str(target).startswith(str(base_resolved) + os.sep) and target != base_resolved:
        raise PathTraversalError(f"Path traversal detected: {parts!r} escapes vault root.")
    return target


def _atomic_write(path: Path, data: bytes) -> None:
    """
    Write *data* to *path* atomically via a temporary sibling file.

    Only encrypted data should be passed here.  The temp file is created
    with mode 0600 and is deleted if the write fails.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".tmp.{secrets.token_hex(8)}")
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except Exception:
        tmp.unlink(missing_ok=True)
        raise


# ---------------------------------------------------------------------------
# Vault root helpers
# ---------------------------------------------------------------------------


def assert_vault(vault_path: Path) -> None:
    """Raise VaultNotFoundError if *vault_path* is not a valid Zhubin vault."""
    if not (vault_path / _CONFIG_FILE).exists():
        raise VaultNotFoundError(
            f"No Zhubin vault found at {vault_path}. Run 'zhubin init' to initialise one."
        )


def init_vault(vault_path: Path) -> None:
    """
    Initialise the vault directory structure.

    Raises VaultAlreadyExistsError if the vault already exists.
    """
    config_file = vault_path / _CONFIG_FILE
    if config_file.exists():
        raise VaultAlreadyExistsError(f"A Zhubin vault already exists at {vault_path}.")

    vault_path.mkdir(parents=True, exist_ok=True)
    (vault_path / _DEVICE_DIR).mkdir(exist_ok=True)
    (vault_path / _GROUP_DIR).mkdir(exist_ok=True)

    # Write default config
    config_file.write_text(
        "version: 1\n"
        "clipboard_timeout: 30\n"
        'web_host: "127.0.0.1"\n'
        "web_port: 8787\n"
        "auto_lock_timeout: 900\n"
    )

    # Write .gitignore to help prevent accidental private-key commits
    gitignore_content = (
        "# Zhubin vault .gitignore\n"
        "# Private keys and decrypted data MUST NOT be committed.\n"
        "*.key\n"
        "*.pem\n"
        "*.dec\n"
        "private_key*\n"
        ".session\n"
        "*.tmp.*\n"
        ".tmp.*\n"
    )
    (vault_path / _GITIGNORE_FILE).write_text(gitignore_content)
    write_gitattributes(vault_path)


def write_gitattributes(vault_path: Path) -> None:
    """Write merge-safety attributes so encrypted objects never auto-merge."""
    gitattributes = (
        "# Zhubin: treat encrypted objects as binary so Git will not\n"
        "# silently merge concurrent writes to the same secret or group key.\n"
        "*.secret binary\n"
        "**/group.json merge=binary\n"
        "devices/*.json merge=binary\n"
    )
    (vault_path / _GITATTRIBUTES_FILE).write_text(gitattributes)


def ensure_gitattributes(vault_path: Path) -> None:
    """Create ``.gitattributes`` if an older vault is missing it."""
    path = vault_path / _GITATTRIBUTES_FILE
    if not path.exists():
        write_gitattributes(vault_path)


# ---------------------------------------------------------------------------
# Device storage
# ---------------------------------------------------------------------------


def save_device(vault_path: Path, device: DeviceRecord) -> None:
    """Write a DeviceRecord to vault/devices/<name>.json."""
    assert_vault(vault_path)
    devices_dir = vault_path / _DEVICE_DIR
    path = _safe_join(devices_dir, f"{device.name}.json")
    _atomic_write(path, device.to_json().encode())


def load_device(vault_path: Path, name: str) -> DeviceRecord:
    """Load a device by its human-readable name."""
    assert_vault(vault_path)
    devices_dir = vault_path / _DEVICE_DIR
    path = _safe_join(devices_dir, f"{name}.json")
    if not path.exists():
        from zhubin.exceptions import DeviceNotFoundError

        raise DeviceNotFoundError(f"Device '{name}' not found.")
    return DeviceRecord.from_json(path.read_bytes())


def load_device_by_id(vault_path: Path, device_id: str) -> DeviceRecord | None:
    """Find a device by its UUID.  Returns None if not found."""
    for dev in list_devices(vault_path):
        if dev.id == device_id:
            return dev
    return None


def list_devices(vault_path: Path) -> list[DeviceRecord]:
    """List all registered devices (including revoked)."""
    assert_vault(vault_path)
    devices_dir = vault_path / _DEVICE_DIR
    result: list[DeviceRecord] = []
    for p in sorted(devices_dir.glob("*.json")):
        with contextlib.suppress(Exception):
            result.append(DeviceRecord.from_json(p.read_bytes()))
    return result


def active_devices(vault_path: Path) -> list[DeviceRecord]:
    """Return only non-revoked devices."""
    return [d for d in list_devices(vault_path) if not d.revoked]


# ---------------------------------------------------------------------------
# Group storage
# ---------------------------------------------------------------------------


def save_group(vault_path: Path, group: GroupRecord) -> None:
    """Write a GroupRecord to vault/groups/<name>/group.json."""
    assert_vault(vault_path)
    groups_dir = vault_path / _GROUP_DIR
    group_dir = _safe_join(groups_dir, group.name)
    group_dir.mkdir(parents=True, exist_ok=True)
    (group_dir / _SECRETS_DIR).mkdir(exist_ok=True)
    path = group_dir / _GROUP_FILE
    _atomic_write(path, group.to_json().encode())


def load_group(vault_path: Path, name: str) -> GroupRecord:
    """Load a group by name."""
    assert_vault(vault_path)
    groups_dir = vault_path / _GROUP_DIR
    path = _safe_join(groups_dir, name, _GROUP_FILE)
    if not path.exists():
        raise GroupNotFoundError(f"Group '{name}' not found.")
    return GroupRecord.from_json(path.read_bytes())


def list_groups(vault_path: Path) -> list[GroupRecord]:
    """List all groups."""
    assert_vault(vault_path)
    groups_dir = vault_path / _GROUP_DIR
    result: list[GroupRecord] = []
    for p in sorted(groups_dir.iterdir()):
        if p.is_dir():
            gf = p / _GROUP_FILE
            if gf.exists():
                with contextlib.suppress(Exception):
                    result.append(GroupRecord.from_json(gf.read_bytes()))
    return result


def group_exists(vault_path: Path, name: str) -> bool:
    groups_dir = vault_path / _GROUP_DIR
    return (groups_dir / name / _GROUP_FILE).exists()


def delete_group(vault_path: Path, name: str) -> None:
    """
    Delete a group directory and all secrets under it.

    Raises GroupNotFoundError if the group does not exist.
    Path components are validated to prevent traversal outside ``groups/``.
    """
    assert_vault(vault_path)
    _validate_simple_name(name, field="group name")
    groups_dir = vault_path / _GROUP_DIR
    group_dir = _safe_join(groups_dir, name)
    if not (group_dir / _GROUP_FILE).exists():
        raise GroupNotFoundError(f"Group '{name}' not found.")
    shutil.rmtree(group_dir)


# ---------------------------------------------------------------------------
# Secret storage
# ---------------------------------------------------------------------------


def _validate_simple_name(name: str, *, field: str = "name") -> None:
    """
    Reject names that contain directory separators or path traversal components.

    A valid simple name contains only alphanumeric characters, hyphens,
    underscores, and dots.  It must not be ``.`` or ``..``, must not
    contain path separators, and must be at most 64 characters.
    """
    if not name or name in (".", ".."):
        raise PathTraversalError(f"Invalid {field}: {name!r}")
    if len(name) > _MAX_NAME_LEN:
        raise PathTraversalError(f"{field} exceeds maximum length of {_MAX_NAME_LEN}: {name!r}")
    if "/" in name or "\\" in name or "\x00" in name:
        raise PathTraversalError(f"Path separators not allowed in {field}: {name!r}")
    if not _NAME_RE.match(name):
        raise PathTraversalError(f"Invalid characters in {field}: {name!r}")


def _validate_secret_name(name: str) -> tuple[str, ...]:
    """
    Validate a possibly nested secret name and return its path segments.

    Nested names use ``/`` as a folder separator (e.g. ``ilo/bank/s``).
    Each segment must be a valid simple name.  Leading, trailing, and
    empty segments are rejected.
    """
    if not name:
        raise PathTraversalError("Invalid secret name: ''")
    if "\\" in name or "\x00" in name:
        raise PathTraversalError(f"Path separators not allowed in secret name: {name!r}")
    if name.startswith("/") or name.endswith("/") or "//" in name:
        raise PathTraversalError(f"Invalid secret name: {name!r}")
    if len(name) > _MAX_SECRET_PATH_LEN:
        raise PathTraversalError(
            f"secret name exceeds maximum length of {_MAX_SECRET_PATH_LEN}: {name!r}"
        )
    parts = tuple(name.split("/"))
    if len(parts) > _MAX_SECRET_DEPTH:
        raise PathTraversalError(
            f"secret name exceeds maximum depth of {_MAX_SECRET_DEPTH}: {name!r}"
        )
    for part in parts:
        _validate_simple_name(part, field="secret name")
    return parts


def _secret_path(vault_path: Path, group_name: str, secret_name: str) -> Path:
    _validate_simple_name(group_name, field="group name")
    segments = _validate_secret_name(secret_name)
    groups_dir = vault_path / _GROUP_DIR
    secrets_dir = _safe_join(groups_dir, group_name, _SECRETS_DIR)
    return _safe_join(secrets_dir, *segments[:-1], segments[-1] + _SECRET_EXT)


def _prune_empty_secret_dirs(secret_file: Path, secrets_dir: Path) -> None:
    """Remove empty parent directories of *secret_file* up to *secrets_dir*."""
    try:
        current = secret_file.parent.resolve()
        stop = secrets_dir.resolve()
    except OSError:
        return
    while True:
        if current == stop:
            break
        try:
            current.relative_to(stop)
        except ValueError:
            break
        try:
            current.rmdir()
        except OSError:
            break
        current = current.parent


def save_secret(
    vault_path: Path,
    group_name: str,
    secret_name: str,
    encrypted_data: bytes,
    *,
    overwrite: bool = False,
) -> None:
    """Write an encrypted secret blob to disk."""
    assert_vault(vault_path)
    path = _secret_path(vault_path, group_name, secret_name)
    if path.exists() and not overwrite:
        raise SecretAlreadyExistsError(f"Secret '{group_name}/{secret_name}' already exists.")
    _atomic_write(path, encrypted_data)


def load_secret_raw(vault_path: Path, group_name: str, secret_name: str) -> bytes:
    """Return the raw encrypted bytes of a secret file."""
    assert_vault(vault_path)
    path = _secret_path(vault_path, group_name, secret_name)
    if not path.exists():
        raise SecretNotFoundError(f"Secret '{group_name}/{secret_name}' not found.")
    return path.read_bytes()


def delete_secret(vault_path: Path, group_name: str, secret_name: str) -> None:
    """Delete a secret file and prune empty parent directories."""
    assert_vault(vault_path)
    path = _secret_path(vault_path, group_name, secret_name)
    if not path.exists():
        raise SecretNotFoundError(f"Secret '{group_name}/{secret_name}' not found.")
    groups_dir = vault_path / _GROUP_DIR
    secrets_dir = _safe_join(groups_dir, group_name, _SECRETS_DIR)
    path.unlink()
    _prune_empty_secret_dirs(path, secrets_dir)


def list_secrets(vault_path: Path, group_name: str) -> list[str]:
    """List secret names (without extension) in a group, including nested paths."""
    assert_vault(vault_path)
    _validate_simple_name(group_name, field="group name")
    groups_dir = vault_path / _GROUP_DIR
    secrets_dir = _safe_join(groups_dir, group_name, _SECRETS_DIR)
    if not secrets_dir.exists():
        return []
    names: list[str] = []
    for p in secrets_dir.rglob(f"*{_SECRET_EXT}"):
        if not p.is_file():
            continue
        if p.name.startswith(".tmp."):
            continue
        rel = p.relative_to(secrets_dir)
        names.append(rel.with_suffix("").as_posix())
    return sorted(names)


def secret_exists(vault_path: Path, group_name: str, secret_name: str) -> bool:
    return _secret_path(vault_path, group_name, secret_name).exists()


# ---------------------------------------------------------------------------
# Iterator: all secrets across groups
# ---------------------------------------------------------------------------


def iter_all_secrets(vault_path: Path) -> Iterator[tuple[str, str]]:
    """Yield (group_name, secret_name) for every secret in the vault."""
    assert_vault(vault_path)
    for group in list_groups(vault_path):
        for name in list_secrets(vault_path, group.name):
            yield group.name, name
