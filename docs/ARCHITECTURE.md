# Zhubin Architecture

## Overview

Zhubin is a modular Python application following a layered architecture where
cryptographic operations are strictly separated from I/O and user interface
concerns.

```
┌─────────────────────────────────────────────────────────────────┐
│                        User Interface                            │
│                                                                  │
│   CLI (Typer / Rich)              Web UI (FastAPI + vanilla JS) │
│         │                                  │                     │
│         └──────────────┬───────────────────┘                    │
│                        │                                         │
└────────────────────────┼─────────────────────────────────────── ┘
                         │
                         ▼
              ┌──────────────────────┐
              │     VaultService     │  ← Single authoritative API
              └──────────────────────┘
                /        |         \
               /         |          \
              ▼          ▼           ▼
     ┌─────────────┐  ┌──────────┐  ┌──────────────┐
     │   crypto/   │  │  vault/  │  │   storage/   │
     │  identity   │  │  models  │  │  filesystem  │
     │  encrypt    │  │          │  │  git         │
     │  keyring    │  │          │  │              │
     └─────────────┘  └──────────┘  └──────────────┘
```

## Directory Structure

```
src/zhubin/
├── __init__.py
├── config.py           ← Configuration loading and defaults
├── exceptions.py       ← Exception hierarchy
│
├── cli/
│   ├── app.py          ← Main Typer app, top-level commands
│   ├── group.py        ← `zhubin group` sub-commands
│   ├── device.py       ← `zhubin device` (init, list, show, fingerprint, authorize, revoke)
│   └── git.py          ← Git CLI sub-app (currently unused; status/sync are top-level)
│
├── crypto/
│   ├── identity.py     ← Device key generation, storage, group key wrap/unwrap
│   ├── encrypt.py      ← Symmetric secret encryption/decryption
│   └── keyring_store.py ← OS keyring integration and session tokens
│
├── vault/
│   ├── models.py       ← Pydantic domain models (DeviceRecord, GroupRecord, SecretPayload)
│   └── vault.py        ← VaultService — orchestration layer
│
├── storage/
│   ├── filesystem.py   ← File I/O with atomic writes and path safety
│   └── git.py          ← Git subprocess integration
│
├── clipboard/
│   └── clipboard.py    ← Clipboard copy with timed auto-clear
│
├── web/
    ├── app.py          ← FastAPI application factory
    ├── auth.py         ← Session token management
    ├── security.py     ← Host / Origin / CSRF middleware
    ├── api/
    │   └── __init__.py ← REST API routes
    ├── templates/
    │   └── index.html  ← SPA shell template
    └── static/
        ├── css/style.css
        └── js/app.js
```

## Module Responsibilities

### `config.py`

- Loads configuration from vault `config.yaml`, user `~/.config/zhubin/config.yaml`,
  and `ZHUBIN_*` environment variables.
- Defines paths for sensitive local files.
- Validates that `web_host` is never `0.0.0.0` (security invariant).

### `exceptions.py`

- Defines the full exception hierarchy.
- `CryptoError` and its subclasses (`AuthenticationError`, `KeyNotFoundError`)
  are used for all cryptographic failures.
- Callers should never catch bare `Exception` around crypto operations.

### `crypto/identity.py`

**Security-critical.** Modifications require additional review and tests.

- Device key pair generation (X25519).
- Public-key fingerprints (SHA-256 of canonical 32-byte public keys).
- Private key encryption at rest (Argon2id → XSalsa20-Poly1305).
- OS keyring integration (store/retrieve private key bytes).
- Group key wrapping for devices (X25519 SealedBox).
- Group key unwrapping with private key.

### `crypto/encrypt.py`

**Security-critical.** Modifications require additional review and tests.

- Secret encryption: XSalsa20-Poly1305 via `nacl.secret.SecretBox`.
- Produces a versioned JSON blob safe for disk storage.
- Returns `AuthenticationError` (not `None`, not partial plaintext) on failure.

### `crypto/keyring_store.py`

- Thin wrapper around the `keyring` package.
- Gracefully handles unavailable backends.
- Stores/retrieves session tokens for the Web UI.

### `vault/models.py`

- Pydantic v2 domain models.
- `DeviceRecord`: public device info (no private key).
- `GroupRecord`: group metadata with `device_keys` mapping.
- `SecretPayload`: in-memory only — **never written to disk directly**.
- `DeviceKeyEntry`: wrapped group key per device.
- All names are validated to prevent path traversal via model validators.

### `vault/vault.py`

- `VaultService`: the single authoritative interface for all vault operations.
- Holds the `DeviceIdentity` in memory when unlocked; `None` when locked.
- All secret operations decrypt/encrypt via `crypto/encrypt.py`.
- All group key operations use `crypto/identity.py`.
- Group rotation is performed entirely in memory with atomic final writes.

### `storage/filesystem.py`

- All file I/O for vault objects.
- Atomic writes via `.tmp.<random>` sibling + rename.
- `_safe_join`: rejects path traversal (absolute paths, `..` components,
  separator characters in names).
- `_validate_simple_name`: rejects single path components with `/`, `\`, or `..`.
- `_validate_secret_name`: allows `/`-separated nested folders under a group's
  `secrets/` directory; each segment is validated with `_validate_simple_name`.

### `storage/git.py`

- Wraps `git` subprocess calls (never `shell=True`).
- Detects Git repos, branches, remote tracking status.
- `sync()`: pull → stage → commit → push with conflict detection.
- Never auto-resolves conflicts.

### `clipboard/clipboard.py`

- Copies value to clipboard via `pyperclip`.
- Starts background thread to clear after timeout.
- Clears only if clipboard still contains the placed value.

### `web/app.py`

- FastAPI application factory.
- Attaches `VaultService` to `app.state` (shared with CLI session).
- Installs Host / Origin / CSRF / `Cache-Control: no-store` middleware.
- Mounts static files and Jinja2 templates.

### `web/auth.py`

- Issues and validates session tokens (192-bit random, in-memory store).
- TTL enforcement; all sessions revoked on lock.
- FastAPI dependency `require_session` used on all protected routes.

### `web/security.py`

- Host header allowlist (localhost / bind host).
- Origin check on state-changing requests.
- Double-submit CSRF cookie + `X-CSRF-Token` header.
- Strips wildcard CORS headers if a dependency ever set them.

### `web/api/__init__.py`

- REST API routes.
- `GET /api/status` and `GET /api/csrf` are unauthenticated.
- All other routes require a valid session cookie.
- Passwords are **never** returned by `GET /api/groups/{group}/secrets/{name}`.
- Clipboard copy is server-side via `POST .../copy` (password not in the response).

## Key Design Decisions

### Why not `age` directly?

The spec recommends `age`. Zhubin instead uses the underlying NaCl/libsodium
primitives via PyNaCl:

- `SealedBox` for group key wrapping — a recipient-based envelope-encryption
  model using `crypto_box_seal` (X25519 ECDH + XSalsa20-Poly1305).
- `SecretBox` for symmetric secret encryption.

This design is conceptually similar to the `age` X25519 recipient model but
is **not `age`-compatible** and must not be considered protocol-equivalent to
`age`.  The wire format, framing, and HKDF derivation differ.

This avoids a dependency on `pyrage` (which had availability concerns) while
using well-reviewed libsodium constructions directly.

### Why envelope encryption?

Direct per-device encryption of every secret would require re-encrypting all
secrets when adding a device. Envelope encryption only requires wrapping the
group key for the new device — O(groups) work instead of O(secrets).

### Why not a database?

Git provides versioning, synchronization, and conflict detection for free.
Plain files are human-inspectable, versionable, and portable.

### Atomic writes

All vault file updates use the write-to-temp-then-rename pattern to ensure
that a crash during a write leaves the vault in a consistent prior state, not
a partial new state. This is especially important for group key rotation, which
writes multiple files.

## Data Flow: Adding a Secret

```
CLI `zhubin add personal/github`
  │
  ├─► get_service() → load DeviceIdentity from keyring/file
  │
  ├─► VaultService.add_secret("personal", "github", SecretPayload(...))
  │     │
  │     ├─► _get_group_key("personal")
  │     │     ├─► load_group("personal") → GroupRecord
  │     │     └─► SealedBox(device_privkey).decrypt(wrapped_key) → group_key
  │     │
  │     ├─► encrypt_secret(payload.to_bytes(), group_key)
  │     │     └─► SecretBox(group_key).encrypt(plaintext) → JSON blob
  │     │
  │     └─► save_secret("personal", "github", encrypted_blob)
  │           └─► atomic write to groups/personal/secrets/github.secret
  │
  └─► Console: "✓ Secret personal/github added."
```

## Testing Strategy

Security-critical tests (`tests/test_crypto.py`, `tests/test_vault.py`):

- Round-trip encryption/decryption with correct key.
- Wrong key → `AuthenticationError`.
- Tampered ciphertext → `AuthenticationError`.
- `test_plaintext_not_in_secret_file`: encrypts a known plaintext and scans
  the vault directory to confirm the plaintext does not appear.
- `scan_vault_for_plaintext`: utility used by tests to scan vault files.
- Unauthorized device → `UnauthorizedDeviceError`.
- Path traversal → `PathTraversalError`.
- Malformed vault files → appropriate errors.

## Adding Features Safely

When adding features:

1. **New crypto operations**: must go in `crypto/` and be tested in
   `tests/test_crypto.py`. Treat all changes to `crypto/` as
   security-sensitive.

2. **New CLI commands**: use `get_service()` to get an unlocked
   `VaultService`. Never perform crypto in the CLI layer directly.

3. **New API routes**: use `_unlocked_svc()` dependency. Never return
   plaintext passwords in GET responses.

4. **New vault file formats**: increment the `version` field. Add a
   migration path. Test with the old and new format.

5. **New configuration options**: add to `ZhubinConfig` with safe defaults.
   Validate security-relevant options in `field_validator`.
