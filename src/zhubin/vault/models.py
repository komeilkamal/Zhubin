"""
Domain models for Zhubin vault entities.

All models use Pydantic v2.  Serialisation to/from JSON is handled here so
callers don't need to know the on-disk format.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Annotated, Any

from pydantic import BaseModel, Field, field_validator

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_NAME_RE = re.compile(r"^[a-zA-Z0-9_\-\.]+$")
_MAX_NAME_LEN = 64


def _validate_name(value: str, *, field: str = "name") -> str:
    """
    Validate a group or secret name.

    Allowed characters: alphanumeric, hyphen, underscore, dot.
    Max length: 64.
    Must not be '.' or '..'.
    """
    if not value:
        raise ValueError(f"{field} must not be empty")
    if len(value) > _MAX_NAME_LEN:
        raise ValueError(f"{field} exceeds maximum length of {_MAX_NAME_LEN}")
    if value in (".", ".."):
        raise ValueError(f"{field} must not be '.' or '..'")
    if not _NAME_RE.match(value):
        raise ValueError(
            f"{field} contains invalid characters. Allowed: alphanumeric, hyphen, underscore, dot."
        )
    return value


def now_utc() -> datetime:
    return datetime.now(tz=UTC)


# ---------------------------------------------------------------------------
# Device model
# ---------------------------------------------------------------------------


class DeviceRecord(BaseModel):
    """
    Public device information stored in vault/devices/<name>.json.

    Private keys are NEVER stored here.
    """

    version: int = 1
    id: str
    name: str
    public_key: str  # base64-encoded X25519 public key
    created_at: datetime = Field(default_factory=now_utc)
    hostname: str = ""
    platform: str = ""
    revoked: bool = False
    revoked_at: datetime | None = None

    @field_validator("name")
    @classmethod
    def _validate_name(cls, v: str) -> str:
        return _validate_name(v, field="device name")

    def to_json(self) -> str:
        return self.model_dump_json(indent=2)

    @classmethod
    def from_json(cls, data: str | bytes) -> DeviceRecord:
        return cls.model_validate_json(data)

    def fingerprint(self) -> str:
        """SHA-256 fingerprint of this device's canonical public key."""
        from zhubin.crypto.identity import public_key_fingerprint

        return public_key_fingerprint(self.public_key)


# ---------------------------------------------------------------------------
# Group model
# ---------------------------------------------------------------------------


class DeviceKeyEntry(BaseModel):
    """An encrypted copy of the group key for one device."""

    type: str = "zhubin-wrapped-group-key-v1"
    wrapped_key: str  # base64-encoded SealedBox(group_key)
    cipher: str = "x25519-xsalsa20poly1305-sealed"
    added_at: datetime = Field(default_factory=now_utc)


class GroupRecord(BaseModel):
    """
    Group metadata stored in vault/groups/<name>/group.json.

    device_keys maps device_id → encrypted group key.
    """

    version: int = 1
    id: str
    name: str
    created_at: datetime = Field(default_factory=now_utc)
    device_keys: dict[str, DeviceKeyEntry] = Field(default_factory=dict)

    @field_validator("name")
    @classmethod
    def _validate_name(cls, v: str) -> str:
        return _validate_name(v, field="group name")

    def to_json(self) -> str:
        return self.model_dump_json(indent=2)

    @classmethod
    def from_json(cls, data: str | bytes) -> GroupRecord:
        return cls.model_validate_json(data)


# ---------------------------------------------------------------------------
# Secret payload model (plaintext, in-memory only)
# ---------------------------------------------------------------------------


class SecretPayload(BaseModel):
    """
    In-memory representation of a secret's decrypted contents.

    This object must NEVER be written to disk unencrypted.
    """

    username: str = ""
    password: str = ""
    url: str = ""
    notes: str = ""
    extra: dict[str, str] = Field(default_factory=dict)

    def to_bytes(self) -> bytes:
        """Serialise to JSON bytes for encryption."""
        return self.model_dump_json().encode()

    @classmethod
    def from_bytes(cls, data: bytes) -> SecretPayload:
        return cls.model_validate_json(data)

    def redacted(self) -> dict[str, Any]:
        """Return a dict safe for logging (password replaced by ****)."""
        d = self.model_dump()
        if d.get("password"):
            d["password"] = "****"
        for k in d.get("extra", {}):
            d["extra"][k] = "****"
        return d


# ---------------------------------------------------------------------------
# Config model
# ---------------------------------------------------------------------------


class VaultConfig(BaseModel):
    """
    vault/config.yaml top-level structure.
    """

    version: int = 1
    clipboard_timeout: Annotated[int, Field(ge=5, le=3600)] = 30
    web_host: str = "127.0.0.1"
    web_port: Annotated[int, Field(ge=1024, le=65535)] = 8787
    auto_lock_timeout: Annotated[int, Field(ge=0)] = 900
