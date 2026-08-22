"""
Cryptographic identity management for Zhubin devices.

Design
------
Each device has an X25519 key pair (via PyNaCl's nacl.public).

Private key at rest
~~~~~~~~~~~~~~~~~~~
The private key is stored in one of two ways, in order of preference:

1. OS keyring  (via ``crypto.keyring_store``).
   The raw private-key bytes are stored under the service/username pair
   ``zhubin/<device-id>``.

2. Passphrase-encrypted file at  ``~/.config/zhubin/private_key.enc``.
   The file uses Argon2id to derive an encryption key from the user's
   passphrase, then XSalsa20-Poly1305 (NaCl SecretBox) to encrypt the
   private-key bytes.  All KDF parameters required to decrypt are stored
   in the file so they can be upgraded later.

There is no plaintext-on-disk fallback.  If neither the OS keyring nor a
passphrase-encrypted file can be used, identity persistence fails closed.

Group-key wrapping
~~~~~~~~~~~~~~~~~~
To wrap a symmetric group key *for a device*, Zhubin uses
``nacl.public.SealedBox`` (X25519 ECDH with an ephemeral sender key +
XSalsa20-Poly1305).  Only the recipient device with its private key can
decrypt.

This follows a recipient-based envelope-encryption model using libsodium
primitives.  It is conceptually similar to the ``age`` recipient model but is
NOT ``age``-compatible and must not be treated as protocol-equivalent to ``age``.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import stat
from base64 import b64decode, b64encode
from pathlib import Path

import nacl.public
import nacl.secret
import nacl.utils
from nacl.exceptions import CryptoError as NaClCryptoError

from zhubin.config import (
    DEVICE_META_FILE,
    PRIVATE_KEY_FILE,
    SENSITIVE_DIR_MODE,
    SENSITIVE_FILE_MODE,
    ensure_config_dir,
)
from zhubin.crypto.labels import DEVICE_KEY_PREFIX, DEVICE_KEY_TYPE, GROUP_KEY_PREFIX
from zhubin.exceptions import (
    AuthenticationError,
    CryptoError,
    DeviceAlreadyExistsError,
    FormatError,
    KeyNotFoundError,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

X25519_KEY_SIZE = 32
_FINGERPRINT_HASH = "sha256"

# RFC 9106 second recommended Argon2id parameterization for interactive use:
# 64 MiB memory, time cost 3, parallelism 4.
_ARGON2_NAME = "argon2id"
_ARGON2_MEMORY_KIB = 65536
_ARGON2_TIME_COST = 3
_ARGON2_PARALLELISM = 4
_ARGON2_HASH_LEN = 32
_ARGON2_SALT_LEN = 16

# Fail-closed bounds applied when *reading* stored parameters.
_ARGON2_MIN_MEMORY_KIB = 8192
_ARGON2_MAX_MEMORY_KIB = 2 * 1024 * 1024
_ARGON2_MIN_TIME = 1
_ARGON2_MAX_TIME = 32
_ARGON2_MIN_PARALLELISM = 1
_ARGON2_MAX_PARALLELISM = 16
_ARGON2_MIN_SALT_LEN = 8
_ARGON2_MIN_HASH_LEN = 32
_ARGON2_MAX_HASH_LEN = 32

_PRIVATE_KEY_FORMAT_V1 = 1
_PRIVATE_KEY_FORMAT_V2 = 2
_CIPHER_NAME = "xsalsa20poly1305"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _b64(data: bytes) -> str:
    return b64encode(data).decode()


def _unb64(s: str) -> bytes:
    return b64decode(s)


def _write_secret_file(path: Path, data: bytes | str) -> None:
    """Write *path* with mode 0600 using a same-directory temp + rename."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.parent.chmod(SENSITIVE_DIR_MODE)
    raw = data if isinstance(data, bytes) else data.encode()
    tmp = path.with_name(f".tmp.{nacl.utils.random(8).hex()}")
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL, SENSITIVE_FILE_MODE)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(raw)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
        os.chmod(path, SENSITIVE_FILE_MODE)
    except Exception:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def _check_permissions(path: Path) -> None:
    """Warn if a sensitive file has overly permissive mode."""
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & 0o177:  # Any bits beyond owner r/w
        import warnings

        warnings.warn(
            f"Sensitive file {path} has mode {oct(mode)}, expected 0600.",
            stacklevel=2,
        )


# ---------------------------------------------------------------------------
# Public-key fingerprints
# ---------------------------------------------------------------------------


def canonical_public_key_bytes(public_key: bytes | str) -> bytes:
    """
    Return the canonical 32-byte X25519 public key.

    Accepts raw bytes or standard base64.  Device names and other metadata
    are not part of the canonical form.
    """
    if isinstance(public_key, str):
        try:
            raw = _unb64(public_key.strip())
        except Exception as exc:
            raise FormatError("Public key is not valid base64") from exc
    else:
        raw = public_key
    if len(raw) != X25519_KEY_SIZE:
        raise FormatError(f"X25519 public key must be {X25519_KEY_SIZE} bytes, got {len(raw)}")
    return raw


def public_key_fingerprint(public_key: bytes | str) -> str:
    """
    Return a deterministic, human-comparable fingerprint of a device public key.

    The fingerprint is the SHA-256 digest of the canonical 32-byte X25519
    public key, formatted as colon-separated uppercase hex pairs (32 pairs).
    It does not depend on the device name or any other mutable metadata.
    """
    digest = hashlib.sha256(canonical_public_key_bytes(public_key)).digest()
    hexstr = digest.hex().upper()
    return ":".join(hexstr[i : i + 2] for i in range(0, len(hexstr), 2))


def format_fingerprint_display(fingerprint: str) -> str:
    """Split a colon-separated fingerprint into two 16-pair lines for comparison."""
    pairs = fingerprint.split(":")
    if len(pairs) != 32:
        return fingerprint
    return ":".join(pairs[:16]) + "\n" + ":".join(pairs[16:])


# ---------------------------------------------------------------------------
# Key derivation (passphrase → encryption key)
# ---------------------------------------------------------------------------


def _validate_argon2_params(
    *,
    name: str,
    memory_kib: int,
    time_cost: int,
    parallelism: int,
    salt: bytes,
    hash_len: int,
) -> None:
    """Fail closed on unsupported or unsafe KDF parameters."""
    if name.lower() != _ARGON2_NAME:
        raise CryptoError(f"Unsupported KDF: {name!r}. Expected '{_ARGON2_NAME}'.")
    if not (_ARGON2_MIN_MEMORY_KIB <= memory_kib <= _ARGON2_MAX_MEMORY_KIB):
        raise CryptoError(
            f"Argon2id memory_kib={memory_kib} is outside the accepted range "
            f"[{_ARGON2_MIN_MEMORY_KIB}, {_ARGON2_MAX_MEMORY_KIB}]."
        )
    if not (_ARGON2_MIN_TIME <= time_cost <= _ARGON2_MAX_TIME):
        raise CryptoError(
            f"Argon2id time_cost={time_cost} is outside the accepted range "
            f"[{_ARGON2_MIN_TIME}, {_ARGON2_MAX_TIME}]."
        )
    if not (_ARGON2_MIN_PARALLELISM <= parallelism <= _ARGON2_MAX_PARALLELISM):
        raise CryptoError(
            f"Argon2id parallelism={parallelism} is outside the accepted range "
            f"[{_ARGON2_MIN_PARALLELISM}, {_ARGON2_MAX_PARALLELISM}]."
        )
    if len(salt) < _ARGON2_MIN_SALT_LEN:
        raise CryptoError(
            f"Argon2id salt is too short ({len(salt)} bytes); minimum is {_ARGON2_MIN_SALT_LEN}."
        )
    if not (_ARGON2_MIN_HASH_LEN <= hash_len <= _ARGON2_MAX_HASH_LEN):
        raise CryptoError(f"Argon2id hash_len={hash_len} is not supported.")


def derive_key_from_passphrase(
    passphrase: str,
    salt: bytes,
    *,
    time_cost: int = _ARGON2_TIME_COST,
    memory_kib: int = _ARGON2_MEMORY_KIB,
    parallelism: int = _ARGON2_PARALLELISM,
    hash_len: int = _ARGON2_HASH_LEN,
    kdf_name: str = _ARGON2_NAME,
) -> bytes:
    """
    Derive a 32-byte symmetric key from *passphrase* using Argon2id.

    The passphrase is never logged.  Parameters are validated and then passed
    to argon2-cffi; unsupported combinations fail closed.
    """
    if not passphrase:
        raise CryptoError("Passphrase must not be empty.")
    _validate_argon2_params(
        name=kdf_name,
        memory_kib=memory_kib,
        time_cost=time_cost,
        parallelism=parallelism,
        salt=salt,
        hash_len=hash_len,
    )
    from argon2.low_level import Type, hash_secret_raw

    return hash_secret_raw(
        secret=passphrase.encode("utf-8"),
        salt=salt,
        time_cost=time_cost,
        memory_cost=memory_kib,
        parallelism=parallelism,
        hash_len=hash_len,
        type=Type.ID,
    )


# ---------------------------------------------------------------------------
# Private-key storage / retrieval
# ---------------------------------------------------------------------------


def _try_keyring_get(device_id: str) -> bytes | None:
    """Return private-key bytes from OS keyring, or None on failure."""
    from zhubin.crypto import keyring_store

    value = keyring_store.retrieve(device_id)
    if value:
        try:
            return _unb64(value)
        except Exception:
            return None
    return None


def _try_keyring_set(device_id: str, key_bytes: bytes) -> bool:
    """Store private-key bytes in OS keyring.  Returns True on success."""
    from zhubin.crypto import keyring_store

    return keyring_store.store(device_id, _b64(key_bytes))


def encrypt_private_key(key_bytes: bytes, passphrase: str) -> bytes:
    """
    Return a versioned JSON blob encrypting the device private key.

    Each call uses a fresh random salt and a fresh random nonce.  Encrypting
    the same key with the same passphrase therefore produces different files.
    """
    if not passphrase:
        raise CryptoError("Passphrase must not be empty.")
    if len(key_bytes) != X25519_KEY_SIZE:
        raise CryptoError(f"Private key must be {X25519_KEY_SIZE} bytes, got {len(key_bytes)}.")

    salt = nacl.utils.random(_ARGON2_SALT_LEN)
    enc_key = derive_key_from_passphrase(passphrase, salt)
    nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
    box = nacl.secret.SecretBox(enc_key)
    combined = box.encrypt(DEVICE_KEY_PREFIX + key_bytes, nonce)
    payload = {
        "version": _PRIVATE_KEY_FORMAT_V2,
        "type": DEVICE_KEY_TYPE,
        "kdf": {
            "name": _ARGON2_NAME,
            "memory_kib": _ARGON2_MEMORY_KIB,
            "time_cost": _ARGON2_TIME_COST,
            "parallelism": _ARGON2_PARALLELISM,
            "salt": _b64(salt),
            "hash_len": _ARGON2_HASH_LEN,
        },
        "cipher": {
            "name": _CIPHER_NAME,
            "nonce": _b64(nonce),
            "ciphertext": _b64(combined.ciphertext),
        },
    }
    return json.dumps(payload, separators=(",", ":")).encode()


def _decrypt_private_key_v1(payload: dict[str, object], passphrase: str) -> bytes:
    """Decrypt a version-1 private-key file (combined nonce+ciphertext)."""
    kdf = payload.get("kdf")
    if kdf not in (_ARGON2_NAME, None):
        raise CryptoError(f"Unsupported KDF in private-key file: {kdf!r}")
    params = payload.get("kdf_params") or {}
    if not isinstance(params, dict):
        raise CryptoError("Malformed kdf_params in private-key file.")
    try:
        salt = _unb64(str(payload["salt"]))
        memory_kib = int(
            str(params.get("memory_cost", params.get("memory_kib", _ARGON2_MEMORY_KIB)))
        )
        time_cost = int(str(params.get("time_cost", _ARGON2_TIME_COST)))
        parallelism = int(str(params.get("parallelism", 1)))
        hash_len = int(str(params.get("hash_len", _ARGON2_HASH_LEN)))
        ciphertext = _unb64(str(payload["ciphertext"]))
    except (KeyError, ValueError, TypeError) as exc:
        raise CryptoError("Malformed version-1 private-key file.") from exc

    enc_key = derive_key_from_passphrase(
        passphrase,
        salt,
        time_cost=time_cost,
        memory_kib=memory_kib,
        parallelism=parallelism,
        hash_len=hash_len,
        kdf_name=_ARGON2_NAME,
    )
    try:
        box = nacl.secret.SecretBox(enc_key)
        inner = box.decrypt(ciphertext)
    except NaClCryptoError as exc:
        raise AuthenticationError("Private key decryption failed — wrong passphrase?") from exc
    if inner.startswith(DEVICE_KEY_PREFIX):
        inner = inner[len(DEVICE_KEY_PREFIX) :]
    if len(inner) != X25519_KEY_SIZE:
        raise CryptoError("Decrypted private key has unexpected length.")
    return inner


def _decrypt_private_key_v2(payload: dict[str, object], passphrase: str) -> bytes:
    """Decrypt a version-2 private-key file (explicit KDF + cipher objects)."""
    obj_type = payload.get("type")
    if obj_type != DEVICE_KEY_TYPE:
        raise FormatError(
            f"Not an encrypted device key (type={obj_type!r}). "
            "Refusing to parse a different cryptographic object as an identity."
        )
    kdf = payload.get("kdf")
    cipher = payload.get("cipher")
    if not isinstance(kdf, dict) or not isinstance(cipher, dict):
        raise CryptoError("Malformed version-2 private-key file.")
    try:
        kdf_name = str(kdf.get("name", ""))
        memory_kib = int(kdf["memory_kib"])
        time_cost = int(kdf["time_cost"])
        parallelism = int(kdf["parallelism"])
        hash_len = int(kdf.get("hash_len", _ARGON2_HASH_LEN))
        salt = _unb64(str(kdf["salt"]))
        cipher_name = str(cipher.get("name", ""))
        nonce = _unb64(str(cipher["nonce"]))
        ciphertext = _unb64(str(cipher["ciphertext"]))
    except (KeyError, ValueError, TypeError) as exc:
        raise CryptoError("Malformed version-2 private-key file.") from exc

    if cipher_name != _CIPHER_NAME:
        raise CryptoError(f"Unsupported private-key cipher: {cipher_name!r}")
    if len(nonce) != nacl.secret.SecretBox.NONCE_SIZE:
        raise CryptoError("Private-key nonce has unexpected length.")

    enc_key = derive_key_from_passphrase(
        passphrase,
        salt,
        time_cost=time_cost,
        memory_kib=memory_kib,
        parallelism=parallelism,
        hash_len=hash_len,
        kdf_name=kdf_name,
    )
    try:
        box = nacl.secret.SecretBox(enc_key)
        inner = box.decrypt(ciphertext, nonce)
    except NaClCryptoError as exc:
        raise AuthenticationError("Private key decryption failed — wrong passphrase?") from exc

    if not inner.startswith(DEVICE_KEY_PREFIX):
        raise FormatError("Encrypted identity is missing the expected type prefix.")
    key_bytes = inner[len(DEVICE_KEY_PREFIX) :]
    if len(key_bytes) != X25519_KEY_SIZE:
        raise CryptoError("Decrypted private key has unexpected length.")
    return key_bytes


def decrypt_private_key(blob: bytes, passphrase: str) -> bytes:
    """Decrypt an encrypted private-key blob produced by *encrypt_private_key*."""
    try:
        payload = json.loads(blob)
    except json.JSONDecodeError as exc:
        raise CryptoError("Malformed private-key file") from exc
    if not isinstance(payload, dict):
        raise CryptoError("Malformed private-key file")

    version = payload.get("version")
    if version == _PRIVATE_KEY_FORMAT_V1:
        return _decrypt_private_key_v1(payload, passphrase)
    if version == _PRIVATE_KEY_FORMAT_V2:
        return _decrypt_private_key_v2(payload, passphrase)
    raise CryptoError(f"Unsupported private-key format version: {version!r}")


# ---------------------------------------------------------------------------
# Device identity
# ---------------------------------------------------------------------------


class DeviceIdentity:
    """
    Represents a Zhubin device cryptographic identity.

    Attributes
    ----------
    device_id : str
        Stable UUID for this device.
    private_key : nacl.public.PrivateKey
        X25519 private key (never leaves the device).
    public_key : nacl.public.PublicKey
        Corresponding X25519 public key (safe to share / commit to Git).
    """

    def __init__(self, device_id: str, private_key: nacl.public.PrivateKey) -> None:
        self.device_id = device_id
        self.private_key = private_key
        self.public_key: nacl.public.PublicKey = private_key.public_key

    @property
    def public_key_b64(self) -> str:
        return _b64(bytes(self.public_key))

    @property
    def fingerprint(self) -> str:
        """SHA-256 fingerprint of this device's canonical public key."""
        return public_key_fingerprint(bytes(self.public_key))

    def wrap_group_key(self, group_key: bytes, recipient_public_key_b64: str) -> str:
        """
        Encrypt *group_key* for a recipient device using X25519 SealedBox.

        Any device with the recipient's public key can wrap a key for that
        device.  Only the recipient's private key can unwrap it.

        Returns base64-encoded ciphertext.
        """
        return wrap_group_key_for_device(group_key, recipient_public_key_b64)

    def unwrap_group_key(self, wrapped_b64: str) -> bytes:
        """
        Decrypt a wrapped group key using this device's private key.

        Raises AuthenticationError on failure (wrong key or tampering).
        """
        return unwrap_group_key_with_identity(wrapped_b64, self)


# ---------------------------------------------------------------------------
# Identity persistence
# ---------------------------------------------------------------------------


def generate_device_id() -> str:
    """Generate a stable UUID for a new device."""
    import uuid

    return str(uuid.uuid4())


def create_device_identity() -> DeviceIdentity:
    """Generate a fresh X25519 key pair and return a DeviceIdentity."""
    private_key = nacl.public.PrivateKey.generate()
    device_id = generate_device_id()
    return DeviceIdentity(device_id=device_id, private_key=private_key)


def save_device_identity(
    identity: DeviceIdentity,
    passphrase: str,
    *,
    prefer_keyring: bool = True,
    force: bool = False,
) -> dict[str, object]:
    """
    Persist a device identity to local storage.

    Storage policy (never silently reduced):

    * OS keyring (optional, preferred) **and/or**
    * Passphrase-encrypted file (always written; Argon2id + SecretBox)

    A plaintext private key is never written to disk.  If the encrypted file
    cannot be written, this function fails rather than falling back to
    plaintext.  An empty passphrase is rejected.
    """
    if not passphrase:
        raise CryptoError("Passphrase must not be empty.")

    ensure_config_dir()

    if PRIVATE_KEY_FILE.exists() and not force:
        raise DeviceAlreadyExistsError(
            f"Private key already exists at {PRIVATE_KEY_FILE}. Use --force to overwrite."
        )

    private_key_bytes = bytes(identity.private_key)
    used_keyring = False

    if prefer_keyring:
        used_keyring = _try_keyring_set(identity.device_id, private_key_bytes)

    blob = encrypt_private_key(private_key_bytes, passphrase)
    _write_secret_file(PRIVATE_KEY_FILE, blob)

    if not PRIVATE_KEY_FILE.exists():
        raise CryptoError("Failed to write encrypted private-key file.")

    return {"keyring": used_keyring, "file": PRIVATE_KEY_FILE}


def load_device_identity(passphrase: str | None = None) -> DeviceIdentity:
    """
    Load the device identity from local storage.

    Tries keyring first, falls back to passphrase-encrypted file.
    Raises KeyNotFoundError if no identity is found.
    Raises AuthenticationError if the passphrase is wrong.
    Never reads a plaintext private-key file.
    """
    if not DEVICE_META_FILE.exists():
        raise KeyNotFoundError(
            "No device identity found. Run 'zhubin init' or 'zhubin device init' first."
        )

    meta = json.loads(DEVICE_META_FILE.read_text())
    device_id = meta["id"]

    key_bytes = _try_keyring_get(device_id)
    if key_bytes is not None and len(key_bytes) == X25519_KEY_SIZE:
        try:
            return DeviceIdentity(
                device_id=device_id, private_key=nacl.public.PrivateKey(key_bytes)
            )
        except Exception:
            pass  # fall through to encrypted file

    if not PRIVATE_KEY_FILE.exists():
        raise KeyNotFoundError(
            f"Private key file not found at {PRIVATE_KEY_FILE}. "
            "The OS keyring is unavailable and no encrypted identity file exists. "
            "Refusing to load a plaintext key."
        )

    if passphrase is None:
        raise KeyNotFoundError(
            "Keyring unavailable and passphrase not provided. "
            "Provide a passphrase to unlock the encrypted private key. "
            "Zhubin will not load an unencrypted private key from disk."
        )

    _check_permissions(PRIVATE_KEY_FILE)
    blob = PRIVATE_KEY_FILE.read_bytes()
    key_bytes = decrypt_private_key(blob, passphrase)
    return DeviceIdentity(device_id=device_id, private_key=nacl.public.PrivateKey(key_bytes))


def save_device_meta(
    identity: DeviceIdentity,
    name: str,
    hostname: str = "",
    platform: str = "",
) -> None:
    """Write device metadata (id, name, public key) to local config dir."""
    ensure_config_dir()
    import platform as platform_mod

    meta = {
        "version": 1,
        "id": identity.device_id,
        "name": name,
        "public_key": identity.public_key_b64,
        "hostname": hostname or platform_mod.node(),
        "platform": platform or platform_mod.system(),
    }
    _write_secret_file(DEVICE_META_FILE, json.dumps(meta, indent=2))


def load_device_meta() -> dict[str, object]:
    """Load local device metadata.  Raises KeyNotFoundError if missing."""
    if not DEVICE_META_FILE.exists():
        raise KeyNotFoundError("No device metadata found. Run 'zhubin init' first.")
    raw = json.loads(DEVICE_META_FILE.read_text())
    if not isinstance(raw, dict):
        raise KeyNotFoundError("Device metadata is malformed.")
    return raw


def identity_exists() -> bool:
    """Return True if a device identity has been initialized locally."""
    return DEVICE_META_FILE.exists()


# ---------------------------------------------------------------------------
# Group-key helpers (stateless)
# ---------------------------------------------------------------------------


def generate_group_key() -> bytes:
    """Return a fresh 32-byte cryptographically random symmetric key."""
    return nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)


def wrap_group_key_for_device(group_key: bytes, device_public_key_b64: str) -> str:
    """Wrap *group_key* for a device identified by its public key (base64)."""
    if len(group_key) != nacl.secret.SecretBox.KEY_SIZE:
        raise CryptoError(
            f"Group key must be {nacl.secret.SecretBox.KEY_SIZE} bytes, got {len(group_key)}."
        )
    pub = nacl.public.PublicKey(canonical_public_key_bytes(device_public_key_b64))
    box = nacl.public.SealedBox(pub)
    return _b64(box.encrypt(GROUP_KEY_PREFIX + group_key))


def unwrap_group_key_with_identity(wrapped_b64: str, identity: DeviceIdentity) -> bytes:
    """Unwrap a group key ciphertext using *identity*'s private key."""
    try:
        box = nacl.public.SealedBox(identity.private_key)
        plain = box.decrypt(_unb64(wrapped_b64))
    except (NaClCryptoError, ValueError) as exc:
        raise AuthenticationError(
            "Group key decryption failed — wrong device key or corrupted ciphertext."
        ) from exc

    if plain.startswith(GROUP_KEY_PREFIX):
        key = plain[len(GROUP_KEY_PREFIX) :]
    elif len(plain) == nacl.secret.SecretBox.KEY_SIZE:
        # Legacy wraps stored the raw 32-byte group key with no type prefix.
        key = plain
    else:
        raise AuthenticationError(
            "Group key decryption failed — wrong device key or corrupted ciphertext."
        )
    if len(key) != nacl.secret.SecretBox.KEY_SIZE:
        raise CryptoError("Unwrapped group key has unexpected length.")
    return key
