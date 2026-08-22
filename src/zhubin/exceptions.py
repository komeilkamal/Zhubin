"""
Zhubin exceptions.

All exceptions derive from ZhubinError.  Sub-classes indicate the
category so callers can handle specific failure modes without catching
broad base exceptions.
"""

from __future__ import annotations


class ZhubinError(Exception):
    """Base class for all Zhubin errors."""


class CryptoError(ZhubinError):
    """Raised when a cryptographic operation fails (decrypt, verify, etc.)."""


class AuthenticationError(CryptoError):
    """MAC/authentication tag verification failed."""


class KeyNotFoundError(ZhubinError):
    """A required key (device private key, group key) is not available."""


class VaultError(ZhubinError):
    """Vault-level structural or consistency error."""


class VaultNotFoundError(VaultError):
    """No Zhubin vault found at the expected path."""


class VaultAlreadyExistsError(VaultError):
    """Vault already exists; refusing to overwrite."""


class DeviceError(ZhubinError):
    """Device identity or authorization error."""


class DeviceNotFoundError(DeviceError):
    """The requested device is not registered."""


class DeviceAlreadyExistsError(DeviceError):
    """A device with this ID already exists."""


class UnauthorizedDeviceError(DeviceError):
    """This device is not authorized for the requested group."""


class GroupError(ZhubinError):
    """Group-level error."""


class GroupNotFoundError(GroupError):
    """The requested group does not exist."""


class GroupAlreadyExistsError(GroupError):
    """A group with this name already exists."""


class SecretError(ZhubinError):
    """Secret-level error."""


class SecretNotFoundError(SecretError):
    """The requested secret does not exist."""


class SecretAlreadyExistsError(SecretError):
    """A secret with this name already exists."""


class StorageError(ZhubinError):
    """File-system / storage layer error."""


class GitError(ZhubinError):
    """Git operation failed."""


class GitConflictError(GitError):
    """Git merge/rebase conflict detected — manual resolution required."""


class GitUnsafeStateError(GitError):
    """Repository is not in a state that is safe to sync."""


class PathTraversalError(ZhubinError):
    """Path traversal attempt detected."""


class ConfigError(ZhubinError):
    """Configuration is invalid or missing."""


class FormatError(ZhubinError):
    """Vault file format is unrecognised or invalid."""
