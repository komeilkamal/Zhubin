"""
Cryptographic object type labels and in-box domain prefixes.

These strings identify serialized objects so that a secret blob, an encrypted
device key, and a wrapped group key cannot be confused with each other.
They are not a substitute for authentication tags; they provide explicit
format identification and in-plaintext domain separation.

KDF domain separation is not required for independent random keys (group keys
are CSPRNG output, not derived from a shared IKM).  When a KDF *is* used
(Argon2id for the device private key), the resulting key is used only for
that one SecretBox.
"""

from __future__ import annotations

# JSON ``type`` fields (human-readable, versioned)
SECRET_TYPE = "zhubin-secret-v1"
DEVICE_KEY_TYPE = "zhubin-device-key-v1"
GROUP_KEY_TYPE = "zhubin-group-key-v1"
WRAPPED_GROUP_KEY_TYPE = "zhubin-wrapped-group-key-v1"

# Prefixes authenticated inside SecretBox / SealedBox plaintext
SECRET_PREFIX = b"zhubin-secret-v1\x00"
DEVICE_KEY_PREFIX = b"zhubin-device-key-v1\x00"
GROUP_KEY_PREFIX = b"zhubin-group-key-v1\x00"
