"""
Regression tests for the security-hardening pass:

* device public-key fingerprints
* Argon2id private-key format (v1 + v2)
* keyring / encrypted-file storage (no plaintext fallback)
* SecretBox nonces
* cryptographic domain / type separation
"""

from __future__ import annotations

import json
import stat
from base64 import b64decode, b64encode
from pathlib import Path
from unittest.mock import patch

import nacl.public
import nacl.secret
import nacl.utils
import pytest

from zhubin.crypto.encrypt import decrypt_secret, encrypt_secret
from zhubin.crypto.identity import (
    X25519_KEY_SIZE,
    canonical_public_key_bytes,
    create_device_identity,
    decrypt_private_key,
    encrypt_private_key,
    generate_group_key,
    public_key_fingerprint,
    unwrap_group_key_with_identity,
    wrap_group_key_for_device,
)
from zhubin.crypto.labels import DEVICE_KEY_TYPE, SECRET_TYPE
from zhubin.exceptions import AuthenticationError, CryptoError, FormatError

# ---------------------------------------------------------------------------
# Fingerprints
# ---------------------------------------------------------------------------


class TestPublicKeyFingerprint:
    def test_deterministic_and_stable(self) -> None:
        identity = create_device_identity()
        raw = bytes(identity.public_key)
        fp1 = public_key_fingerprint(raw)
        fp2 = public_key_fingerprint(identity.public_key_b64)
        fp3 = public_key_fingerprint(raw)
        assert fp1 == fp2 == fp3
        assert identity.fingerprint == fp1

    def test_canonical_bytes_only(self) -> None:
        identity = create_device_identity()
        raw = canonical_public_key_bytes(identity.public_key_b64)
        assert len(raw) == X25519_KEY_SIZE
        # Device name is not an input: hashing the name must not match.
        name_fp = public_key_fingerprint(b"home-pc".ljust(32, b"\x00"))
        assert name_fp != public_key_fingerprint(raw)

    def test_modified_public_key_changes_fingerprint(self) -> None:
        identity = create_device_identity()
        raw = bytearray(bytes(identity.public_key))
        original = public_key_fingerprint(bytes(raw))
        raw[0] ^= 0xFF
        assert public_key_fingerprint(bytes(raw)) != original

    def test_format_is_colon_separated_uppercase_hex(self) -> None:
        fp = public_key_fingerprint(bytes(create_device_identity().public_key))
        pairs = fp.split(":")
        assert len(pairs) == 32
        assert all(len(p) == 2 and p == p.upper() for p in pairs)
        int(fp.replace(":", ""), 16)  # valid hex

    def test_base64_padding_variants_match(self) -> None:
        identity = create_device_identity()
        raw = bytes(identity.public_key)
        # Standard b64 and the library's own encoding must agree.
        assert public_key_fingerprint(raw) == public_key_fingerprint(b64encode(raw).decode())


# ---------------------------------------------------------------------------
# Argon2id private-key format
# ---------------------------------------------------------------------------


def _legacy_v1_blob(key_bytes: bytes, passphrase: str) -> bytes:
    """Construct a version-1 encrypted identity (combined nonce+ciphertext)."""
    from argon2.low_level import Type, hash_secret_raw

    salt = nacl.utils.random(32)
    enc_key = hash_secret_raw(
        secret=passphrase.encode("utf-8"),
        salt=salt,
        time_cost=3,
        memory_cost=65536,
        parallelism=1,
        hash_len=32,
        type=Type.ID,
    )
    box = nacl.secret.SecretBox(enc_key)
    combined = box.encrypt(key_bytes)
    return json.dumps(
        {
            "version": 1,
            "kdf": "argon2id",
            "kdf_params": {
                "time_cost": 3,
                "memory_cost": 65536,
                "parallelism": 1,
                "hash_len": 32,
            },
            "salt": b64encode(salt).decode(),
            "cipher": "xsalsa20poly1305",
            "ciphertext": b64encode(combined).decode(),
        }
    ).encode()


class TestArgon2PrivateKeyFormat:
    def test_v2_contains_required_fields(self) -> None:
        identity = create_device_identity()
        blob = encrypt_private_key(bytes(identity.private_key), "a-passphrase")
        payload = json.loads(blob)
        assert payload["version"] == 2
        assert payload["type"] == DEVICE_KEY_TYPE
        kdf = payload["kdf"]
        assert kdf["name"] == "argon2id"
        assert "memory_kib" in kdf
        assert "time_cost" in kdf
        assert "parallelism" in kdf
        assert "salt" in kdf
        assert kdf["hash_len"] == 32
        cipher = payload["cipher"]
        assert cipher["name"] == "xsalsa20poly1305"
        assert "nonce" in cipher
        assert "ciphertext" in cipher
        nonce = b64decode(cipher["nonce"])
        assert len(nonce) == nacl.secret.SecretBox.NONCE_SIZE

    def test_same_key_same_passphrase_different_blob(self) -> None:
        identity = create_device_identity()
        key = bytes(identity.private_key)
        a = encrypt_private_key(key, "same-pass")
        b = encrypt_private_key(key, "same-pass")
        assert a != b
        pa, pb = json.loads(a), json.loads(b)
        assert pa["kdf"]["salt"] != pb["kdf"]["salt"]
        assert pa["cipher"]["nonce"] != pb["cipher"]["nonce"]
        assert decrypt_private_key(a, "same-pass") == key
        assert decrypt_private_key(b, "same-pass") == key

    def test_wrong_passphrase_fails(self) -> None:
        identity = create_device_identity()
        blob = encrypt_private_key(bytes(identity.private_key), "right")
        with pytest.raises(AuthenticationError):
            decrypt_private_key(blob, "wrong")

    def test_modified_kdf_metadata_fails_closed(self) -> None:
        identity = create_device_identity()
        blob = encrypt_private_key(bytes(identity.private_key), "pass")
        payload = json.loads(blob)
        payload["kdf"]["salt"] = b64encode(nacl.utils.random(16)).decode()
        with pytest.raises(AuthenticationError):
            decrypt_private_key(json.dumps(payload).encode(), "pass")

    def test_unsupported_kdf_name_fails(self) -> None:
        identity = create_device_identity()
        blob = encrypt_private_key(bytes(identity.private_key), "pass")
        payload = json.loads(blob)
        payload["kdf"]["name"] = "pbkdf2"
        with pytest.raises(CryptoError, match="Unsupported KDF"):
            decrypt_private_key(json.dumps(payload).encode(), "pass")

    def test_unsupported_version_fails(self) -> None:
        identity = create_device_identity()
        blob = encrypt_private_key(bytes(identity.private_key), "pass")
        payload = json.loads(blob)
        payload["version"] = 99
        with pytest.raises(CryptoError, match="Unsupported private-key format version"):
            decrypt_private_key(json.dumps(payload).encode(), "pass")

    def test_legacy_v1_still_decrypts(self) -> None:
        identity = create_device_identity()
        key = bytes(identity.private_key)
        blob = _legacy_v1_blob(key, "legacy-pass")
        assert json.loads(blob)["version"] == 1
        assert decrypt_private_key(blob, "legacy-pass") == key

    def test_empty_passphrase_rejected(self) -> None:
        identity = create_device_identity()
        with pytest.raises(CryptoError, match="empty"):
            encrypt_private_key(bytes(identity.private_key), "")

    def test_passphrase_not_in_blob(self) -> None:
        identity = create_device_identity()
        passphrase = "UNIQUE_PASSPHRASE_SHOULD_NOT_APPEAR"
        blob = encrypt_private_key(bytes(identity.private_key), passphrase)
        assert passphrase.encode() not in blob


# ---------------------------------------------------------------------------
# Keyring / file storage
# ---------------------------------------------------------------------------


class TestPrivateKeyStorage:
    def test_keyring_failure_does_not_write_plaintext(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import zhubin.crypto.identity as idmod

        pk = tmp_path / "private_key.enc"
        meta = tmp_path / "device.json"
        monkeypatch.setattr(idmod, "PRIVATE_KEY_FILE", pk)
        monkeypatch.setattr(idmod, "DEVICE_META_FILE", meta)
        monkeypatch.setattr(idmod, "ensure_config_dir", lambda: tmp_path)

        identity = create_device_identity()
        raw = bytes(identity.private_key)

        with patch("zhubin.crypto.keyring_store.store", return_value=False):
            from zhubin.crypto.identity import save_device_identity

            save_device_identity(identity, "file-pass", prefer_keyring=True)

        assert pk.exists()
        data = pk.read_bytes()
        assert raw not in data
        payload = json.loads(data)
        assert payload["version"] == 2
        assert payload["kdf"]["name"] == "argon2id"
        for path in tmp_path.rglob("*"):
            if path.is_file():
                assert raw not in path.read_bytes()
        mode = stat.S_IMODE(pk.stat().st_mode)
        assert mode == 0o600

    def test_encrypted_file_roundtrip(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import zhubin.crypto.identity as idmod
        from zhubin.crypto.identity import (
            load_device_identity,
            save_device_identity,
            save_device_meta,
        )

        pk = tmp_path / "private_key.enc"
        meta = tmp_path / "device.json"
        monkeypatch.setattr(idmod, "PRIVATE_KEY_FILE", pk)
        monkeypatch.setattr(idmod, "DEVICE_META_FILE", meta)
        monkeypatch.setattr(idmod, "ensure_config_dir", lambda: tmp_path)

        identity = create_device_identity()
        save_device_meta(identity, "testdev")
        save_device_identity(identity, "roundtrip-pass", prefer_keyring=False)

        with patch("zhubin.crypto.keyring_store.retrieve", return_value=None):
            loaded = load_device_identity("roundtrip-pass")
        assert loaded.device_id == identity.device_id
        assert bytes(loaded.private_key) == bytes(identity.private_key)

    def test_no_temp_files_left_after_save(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import zhubin.crypto.identity as idmod
        from zhubin.crypto.identity import save_device_identity

        pk = tmp_path / "private_key.enc"
        monkeypatch.setattr(idmod, "PRIVATE_KEY_FILE", pk)
        monkeypatch.setattr(idmod, "ensure_config_dir", lambda: tmp_path)
        identity = create_device_identity()
        save_device_identity(identity, "pass", prefer_keyring=False)
        tmps = list(tmp_path.glob(".tmp.*"))
        assert tmps == []


# ---------------------------------------------------------------------------
# Nonce handling
# ---------------------------------------------------------------------------


class TestNonceHandling:
    def test_encrypt_twice_different_ciphertext(self) -> None:
        key = generate_group_key()
        a = encrypt_secret(b"same", key)
        b = encrypt_secret(b"same", key)
        pa, pb = json.loads(a), json.loads(b)
        assert pa["nonce"] != pb["nonce"]
        assert pa["ciphertext"] != pb["ciphertext"]
        assert decrypt_secret(a, key) == decrypt_secret(b, key) == b"same"

    def test_nonce_has_correct_length(self) -> None:
        payload = json.loads(encrypt_secret(b"x", generate_group_key()))
        nonce = b64decode(payload["nonce"])
        assert len(nonce) == nacl.secret.SecretBox.NONCE_SIZE == 24

    def test_corrupted_nonce_fails(self) -> None:
        key = generate_group_key()
        payload = json.loads(encrypt_secret(b"secret", key))
        nonce = bytearray(b64decode(payload["nonce"]))
        nonce[0] ^= 0xFF
        payload["nonce"] = b64encode(bytes(nonce)).decode()
        with pytest.raises(AuthenticationError):
            decrypt_secret(json.dumps(payload).encode(), key)

    def test_corrupted_ciphertext_fails(self) -> None:
        key = generate_group_key()
        payload = json.loads(encrypt_secret(b"secret", key))
        ct = bytearray(b64decode(payload["ciphertext"]))
        ct[0] ^= 0xFF
        payload["ciphertext"] = b64encode(bytes(ct)).decode()
        with pytest.raises(AuthenticationError):
            decrypt_secret(json.dumps(payload).encode(), key)

    def test_encrypt_secret_does_not_accept_nonce(self) -> None:
        import inspect

        from zhubin.crypto.encrypt import encrypt_secret as es

        params = inspect.signature(es).parameters
        assert "nonce" not in params

    def test_roundtrip_preserves_nonce_field(self) -> None:
        key = generate_group_key()
        enc = encrypt_secret(b"hello", key)
        payload = json.loads(enc)
        enc2 = json.dumps(payload).encode()
        assert decrypt_secret(enc2, key) == b"hello"


# ---------------------------------------------------------------------------
# Domain / type separation
# ---------------------------------------------------------------------------


class TestDomainSeparation:
    def test_secret_type_field(self) -> None:
        payload = json.loads(encrypt_secret(b"x", generate_group_key()))
        assert payload["type"] == SECRET_TYPE
        assert payload["version"] == 2

    def test_parsing_secret_as_identity_fails(self) -> None:
        blob = encrypt_secret(b"not-an-identity", generate_group_key())
        with pytest.raises((CryptoError, FormatError, AuthenticationError)):
            decrypt_private_key(blob, "pass")

    def test_parsing_identity_as_secret_fails(self) -> None:
        identity = create_device_identity()
        blob = encrypt_private_key(bytes(identity.private_key), "pass")
        with pytest.raises(FormatError):
            decrypt_secret(blob, generate_group_key())

    def test_parsing_wrapped_key_as_secret_fails(self) -> None:
        recipient = create_device_identity()
        wrapped = wrap_group_key_for_device(generate_group_key(), recipient.public_key_b64)
        with pytest.raises(FormatError):
            decrypt_secret(wrapped.encode(), generate_group_key())

    def test_wrong_secret_type_label_fails(self) -> None:
        key = generate_group_key()
        payload = json.loads(encrypt_secret(b"x", key))
        payload["type"] = DEVICE_KEY_TYPE
        with pytest.raises(FormatError, match="Not a secret"):
            decrypt_secret(json.dumps(payload).encode(), key)

    def test_legacy_secret_v1_still_decrypts(self) -> None:
        key = generate_group_key()
        box = nacl.secret.SecretBox(key)
        combined = box.encrypt(b"legacy-secret")
        blob = json.dumps(
            {
                "version": 1,
                "cipher": "xsalsa20poly1305",
                "ciphertext": b64encode(combined).decode(),
            }
        ).encode()
        assert decrypt_secret(blob, key) == b"legacy-secret"

    def test_legacy_wrapped_group_key_without_prefix(self) -> None:
        recipient = create_device_identity()
        group_key = generate_group_key()
        pub = nacl.public.PublicKey(bytes(recipient.public_key))
        raw_wrap = nacl.public.SealedBox(pub).encrypt(group_key)
        wrapped = b64encode(raw_wrap).decode()
        assert unwrap_group_key_with_identity(wrapped, recipient) == group_key

    def test_new_wrap_has_type_prefix_and_roundtrips(self) -> None:
        recipient = create_device_identity()
        group_key = generate_group_key()
        wrapped = wrap_group_key_for_device(group_key, recipient.public_key_b64)
        assert unwrap_group_key_with_identity(wrapped, recipient) == group_key
        # Ciphertext is longer than a raw 32-byte seal of 32 bytes (prefix added).
        raw_new = b64decode(wrapped)
        raw_old = nacl.public.SealedBox(recipient.public_key).encrypt(group_key)
        assert len(raw_new) > len(raw_old)
