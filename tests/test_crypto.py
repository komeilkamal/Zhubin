"""
Tests for the cryptographic core.

Security invariants verified:
- Encrypt/decrypt round trips succeed with the correct key.
- Wrong group key → AuthenticationError (never returns plaintext).
- Tampered ciphertext → AuthenticationError.
- Device key wrapping/unwrapping works correctly.
- Wrong device key → AuthenticationError.
- Private key encryption/decryption round trip.
- Wrong passphrase → AuthenticationError.
- Group key generation produces random 32-byte keys.
- Plaintext never appears in encrypted output.
"""

from __future__ import annotations

import json
from base64 import b64decode

import nacl.public
import nacl.secret
import nacl.utils
import pytest

from zhubin.crypto.encrypt import decrypt_secret, encrypt_secret
from zhubin.crypto.identity import (
    create_device_identity,
    decrypt_private_key,
    encrypt_private_key,
    generate_group_key,
    unwrap_group_key_with_identity,
    wrap_group_key_for_device,
)
from zhubin.exceptions import AuthenticationError

# ---------------------------------------------------------------------------
# Symmetric secret encryption
# ---------------------------------------------------------------------------


class TestSecretEncryption:
    def test_round_trip(self) -> None:
        key = generate_group_key()
        plaintext = b'{"username":"alice","password":"s3cr3t"}'
        encrypted = encrypt_secret(plaintext, key)
        decrypted = decrypt_secret(encrypted, key)
        assert decrypted == plaintext

    def test_wrong_key_raises(self) -> None:
        key = generate_group_key()
        other_key = generate_group_key()
        assert key != other_key
        encrypted = encrypt_secret(b"supersecret", key)
        with pytest.raises(AuthenticationError):
            decrypt_secret(encrypted, other_key)

    def test_tampered_ciphertext_raises(self) -> None:
        key = generate_group_key()
        encrypted = encrypt_secret(b"supersecret", key)
        payload = json.loads(encrypted)
        raw = bytearray(b64decode(payload["ciphertext"]))
        raw[40] ^= 0xFF  # flip a byte
        payload["ciphertext"] = __import__("base64").b64encode(bytes(raw)).decode()
        tampered = json.dumps(payload).encode()
        with pytest.raises(AuthenticationError):
            decrypt_secret(tampered, key)

    def test_plaintext_not_in_ciphertext(self) -> None:
        key = generate_group_key()
        secret = b"THIS_IS_A_TEST_PASSWORD_12345"
        encrypted = encrypt_secret(secret, key)
        assert b"THIS_IS_A_TEST_PASSWORD_12345" not in encrypted
        assert b"THIS_IS_A_TEST_PASSWORD_12345" not in b64decode(
            json.loads(encrypted)["ciphertext"]
        )

    def test_encrypted_output_is_json_with_version(self) -> None:
        key = generate_group_key()
        enc = encrypt_secret(b"test", key)
        payload = json.loads(enc)
        assert payload["version"] == 2
        assert "ciphertext" in payload
        assert payload["cipher"] == "xsalsa20poly1305"
        assert payload["type"] == "zhubin-secret-v1"

    def test_each_encryption_produces_unique_ciphertext(self) -> None:
        key = generate_group_key()
        plain = b"same plaintext"
        enc1 = encrypt_secret(plain, key)
        enc2 = encrypt_secret(plain, key)
        # Due to random nonce, same plaintext should produce different ciphertext
        assert json.loads(enc1)["ciphertext"] != json.loads(enc2)["ciphertext"]

    def test_malformed_json_raises_format_error(self) -> None:
        from zhubin.exceptions import FormatError

        key = generate_group_key()
        with pytest.raises(FormatError):
            decrypt_secret(b"not json at all", key)

    def test_unsupported_version_raises_format_error(self) -> None:
        from zhubin.exceptions import FormatError

        key = generate_group_key()
        enc = encrypt_secret(b"test", key)
        payload = json.loads(enc)
        payload["version"] = 99
        with pytest.raises(FormatError):
            decrypt_secret(json.dumps(payload).encode(), key)


# ---------------------------------------------------------------------------
# Group key generation
# ---------------------------------------------------------------------------


class TestGroupKeyGeneration:
    def test_key_is_32_bytes(self) -> None:
        key = generate_group_key()
        assert len(key) == nacl.secret.SecretBox.KEY_SIZE == 32

    def test_keys_are_unique(self) -> None:
        keys = {generate_group_key() for _ in range(20)}
        assert len(keys) == 20  # all unique


# ---------------------------------------------------------------------------
# Device identity and key wrapping
# ---------------------------------------------------------------------------


class TestDeviceIdentity:
    def test_create_identity(self) -> None:
        identity = create_device_identity()
        assert identity.device_id
        assert identity.private_key
        assert identity.public_key

    def test_public_key_b64_roundtrip(self) -> None:
        identity = create_device_identity()
        from base64 import b64decode

        raw = b64decode(identity.public_key_b64)
        assert len(raw) == 32  # X25519 public key is 32 bytes

    def test_wrap_and_unwrap_group_key(self) -> None:
        recipient = create_device_identity()
        group_key = generate_group_key()
        wrapped = wrap_group_key_for_device(group_key, recipient.public_key_b64)
        recovered = unwrap_group_key_with_identity(wrapped, recipient)
        assert recovered == group_key

    def test_wrong_private_key_fails(self) -> None:
        recipient = create_device_identity()
        attacker = create_device_identity()
        group_key = generate_group_key()
        wrapped = wrap_group_key_for_device(group_key, recipient.public_key_b64)
        with pytest.raises(AuthenticationError):
            unwrap_group_key_with_identity(wrapped, attacker)

    def test_tampered_wrapped_key_fails(self) -> None:
        recipient = create_device_identity()
        group_key = generate_group_key()
        wrapped = wrap_group_key_for_device(group_key, recipient.public_key_b64)
        raw = bytearray(b64decode(wrapped))
        raw[10] ^= 0xAA
        tampered = __import__("base64").b64encode(bytes(raw)).decode()
        with pytest.raises(AuthenticationError):
            unwrap_group_key_with_identity(tampered, recipient)


# ---------------------------------------------------------------------------
# Private key at-rest encryption
# ---------------------------------------------------------------------------


class TestPrivateKeyEncryption:
    def test_round_trip(self) -> None:
        identity = create_device_identity()
        passphrase = "correct-horse-battery-staple"
        blob = encrypt_private_key(bytes(identity.private_key), passphrase)
        recovered = decrypt_private_key(blob, passphrase)
        assert recovered == bytes(identity.private_key)

    def test_wrong_passphrase_raises(self) -> None:
        identity = create_device_identity()
        blob = encrypt_private_key(bytes(identity.private_key), "right-pass")
        with pytest.raises(AuthenticationError):
            decrypt_private_key(blob, "wrong-pass")

    def test_private_key_not_in_blob(self) -> None:
        identity = create_device_identity()
        private_key_bytes = bytes(identity.private_key)
        blob = encrypt_private_key(private_key_bytes, "test-pass")
        assert private_key_bytes not in blob

    def test_blob_is_valid_json(self) -> None:
        identity = create_device_identity()
        blob = encrypt_private_key(bytes(identity.private_key), "pass")
        payload = json.loads(blob)
        assert payload["version"] == 2
        assert payload["kdf"]["name"] == "argon2id"
        assert "salt" in payload["kdf"]
        assert "ciphertext" in payload["cipher"]
