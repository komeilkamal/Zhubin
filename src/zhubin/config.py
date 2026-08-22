"""
Zhubin configuration.

Loaded from:
  1. Vault-local  ``config.yaml``  (vault-specific settings).
  2. ``~/.config/zhubin/config.yaml``  (user-wide defaults).
  3. Environment variables prefixed with  ``ZHUBIN_``.

Security-sensitive defaults are deliberately conservative.
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import yaml
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_USER_CONFIG_DIR = Path.home() / ".config" / "zhubin"
_USER_CONFIG_FILE = _USER_CONFIG_DIR / "config.yaml"

# Private-key directory and filenames
PRIVATE_KEY_DIR: Path = _USER_CONFIG_DIR
PRIVATE_KEY_FILE: Path = PRIVATE_KEY_DIR / "private_key.enc"
DEVICE_META_FILE: Path = PRIVATE_KEY_DIR / "device.json"
SESSION_FILE: Path = PRIVATE_KEY_DIR / "session.json"

# Permissions for sensitive files
SENSITIVE_FILE_MODE = 0o600
SENSITIVE_DIR_MODE = 0o700


class ZhubinConfig(BaseSettings):
    """Runtime configuration for Zhubin."""

    model_config = SettingsConfigDict(
        env_prefix="ZHUBIN_",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Clipboard
    clipboard_timeout: Annotated[int, Field(ge=5, le=3600)] = 30

    # Web UI
    web_host: str = "127.0.0.1"
    web_port: Annotated[int, Field(ge=1024, le=65535)] = 8787

    # Auto-lock after this many idle seconds (0 = disabled)
    auto_lock_timeout: Annotated[int, Field(ge=0)] = 900

    # Git
    git_auto_commit: bool = False

    @field_validator("web_host")
    @classmethod
    def _refuse_external_bind(cls, v: str) -> str:
        """Refuse 0.0.0.0 silently upgrading to an external binding."""
        if v == "0.0.0.0":
            raise ValueError(
                "web_host='0.0.0.0' would expose the Web UI externally. "
                "Set ZHUBIN_ALLOW_EXTERNAL_WEB=1 explicitly to override."
            )
        return v


def _load_yaml_file(path: Path) -> dict:  # type: ignore[type-arg]
    if path.exists():
        with path.open() as fh:
            return yaml.safe_load(fh) or {}
    return {}


def load_config(vault_path: Path | None = None) -> ZhubinConfig:
    """Load merged configuration (user-wide + vault-local + env vars)."""
    merged: dict = {}  # type: ignore[type-arg]
    merged.update(_load_yaml_file(_USER_CONFIG_FILE))
    if vault_path is not None:
        merged.update(_load_yaml_file(vault_path / "config.yaml"))
    return ZhubinConfig(**merged)


def save_config(config: ZhubinConfig, vault_path: Path) -> None:
    """Persist config to vault-local config.yaml."""
    data = config.model_dump()
    target = vault_path / "config.yaml"
    target.write_text(yaml.safe_dump(data, default_flow_style=False))


def ensure_config_dir() -> Path:
    """Create ~/.config/zhubin/ with restrictive permissions."""
    _USER_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    _USER_CONFIG_DIR.chmod(SENSITIVE_DIR_MODE)
    return _USER_CONFIG_DIR
