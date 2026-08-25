# AGENTS.md — Guide for AI Coding Agents

This file is for AI coding agents (Cursor, Copilot, etc.) working on Zhubin.
Read this before making any changes.

---

## What is Zhubin?

Zhubin is a **secure, Git-backed password manager** written in Python.

- Secrets are stored as encrypted files in a Git repository.
- The repository can be public; confidentiality is guaranteed by cryptography,
  not access control.
- Every device has its own X25519 key pair (device identity).
- Envelope encryption: secrets are encrypted with a symmetric group key; group
  keys are individually wrapped for each authorized device using X25519 SealedBox.

## Project Goals

1. **Security**: The highest priority. Never compromise security for convenience.
2. **Correctness**: Operations must be atomic and crash-safe.
3. **Maintainability**: Clean architecture, separation of concerns.
4. **Usability**: Polished CLI and local Web UI.

---

## Security Invariants

**The following rules must NEVER be violated.**

1. **Plaintext secrets must never be committed to the vault repository.**
   No secret content (username, password, URL, notes) may appear in any
   file that could be committed. Only encrypted blobs are written to disk.

2. **Private device keys must never enter the vault repository.**
   Private keys live in `~/.config/zhubin/`, not in the vault directory.
   The vault `.gitignore` must always prevent this.

3. **Group keys must never be stored unencrypted in the vault.**
   Every `group.json` stores only SealedBox-wrapped copies of the group key.

4. **Cryptographic failures must fail closed.**
   If decryption fails, raise `AuthenticationError` or `CryptoError`.
   Never return partial plaintext. Never return `None` as a success.

5. **Authentication/integrity failures must never return plaintext.**
   The Poly1305 MAC is verified before any plaintext is produced. Do not
   add any "ignore MAC" or "best effort" decryption path.

6. **Sensitive temporary files must not be created.**
   Operations like group key rotation must be performed in memory. If a
   temporary file is absolutely necessary, it must contain only ciphertext
   and must be deleted before the function returns.

7. **Secrets must not be written to logs.**
   Do not log passwords, group keys, private keys, or decrypted payloads
   at any log level. Use `SecretPayload.redacted()` when logging is needed.

8. **Secrets must not appear in exception messages.**
   Exception messages must not include secret values. Catch secrets before
   they propagate up in exception contexts.

9. **Passwords must not be passed as command-line arguments.**
   Use `typer.prompt(..., hide_input=True)` or interactive prompts.
   Never add `--password <value>` arguments.

10. **Git operations must never stage files outside the vault.**
    All `git add` calls must target the vault path specifically.

11. **The Web UI must default to localhost only.**
    `web_host` defaults to `127.0.0.1`. The `ZhubinConfig.web_host`
    validator rejects `0.0.0.0`. Do not remove this validation.

12. **Tests must never rely on real user secrets or real private keys.**
    All tests use ephemeral keys generated in-memory or in `tmp_path`.
    Tests must not read `~/.config/zhubin/`.

---

## Threat Model Summary

An attacker may have:
- Full access to the Git repository and history.
- All encrypted secrets.
- All public device keys.
- All wrapped group keys (ciphertext).

An attacker does NOT have:
- Private device keys (stored only on authorized devices).

See `docs/SECURITY.md` for the complete threat model.

---

## Architecture

```
CLI / Web UI  →  VaultService  →  crypto/  +  storage/
```

**Critical rule**: CLI and Web UI must NEVER contain cryptographic logic.
All crypto goes through `VaultService`, which delegates to `crypto/`.

### Module ownership

| Module | Responsibility |
|--------|----------------|
| `crypto/identity.py` | Device keys, group key wrap/unwrap, private key storage |
| `crypto/encrypt.py` | Secret encryption/decryption |
| `crypto/keyring_store.py` | OS keyring integration |
| `vault/models.py` | Pydantic domain models |
| `vault/vault.py` | VaultService — all vault operations |
| `storage/filesystem.py` | Atomic file I/O, path safety |
| `storage/git.py` | Git subprocess integration |
| `clipboard/clipboard.py` | Clipboard with timed clear |
| `web/app.py` | FastAPI app factory |
| `web/auth.py` | Session token management |
| `web/security.py` | Host, Origin, CSRF, cache-control middleware |
| `web/api/` | REST API routes |
| `cli/app.py` | CLI commands |

---

## Cryptographic Design

### Algorithms

| Use | Algorithm | Library |
|-----|-----------|---------|
| Device key pair | X25519 | libsodium (PyNaCl) |
| Group key generation | `nacl.utils.random(32)` | libsodium |
| Secret encryption | XSalsa20-Poly1305 | `nacl.secret.SecretBox` |
| Group key wrapping | X25519 SealedBox | `nacl.public.SealedBox` |
| Private key KDF | Argon2id | argon2-cffi |
| Private key encryption | XSalsa20-Poly1305 | `nacl.secret.SecretBox` |

### Never implement custom crypto

Do not replace or supplement the above with custom implementations.
If a new algorithm is needed, consult the security documentation and
use an established, reviewed library.

---

## Directory Responsibilities

### `vault/` (vault root)

Contains only:
- `config.yaml` — configuration
- `.gitignore` — prevents private key commits
- `devices/*.json` — public device info only
- `groups/<name>/group.json` — encrypted group keys
- `groups/<name>/secrets/*.secret` — encrypted secrets

Never contains:
- Private keys
- Plaintext secrets
- Decrypted temporary files

### `~/.config/zhubin/` (local, never committed)

Contains:
- `private_key.enc` — Argon2id-encrypted private key (mode 0600)
- `device.json` — local device metadata (mode 0600)

---

## Coding Conventions

1. Use Python 3.11+ features. All new code must include type annotations.
2. Use Pydantic v2 for all data models.
3. Use `from __future__ import annotations` in all modules.
4. Raise specific exceptions from `zhubin.exceptions`, not `ValueError` or
   generic `Exception`.
5. Use `nacl.utils.random()` for all cryptographic randomness, not
   `os.urandom()` or `random`.
6. Write atomic file operations using `_atomic_write()` in
   `storage/filesystem.py`.
7. Group names must be validated by `_validate_simple_name()` before filesystem
   operations. Secret names must be validated by `_validate_secret_name()`,
   which splits on `/` and validates each segment with `_validate_simple_name()`.
8. Format with `ruff format`. Lint with `ruff check`. No warnings allowed.
9. All public functions must have docstrings.
10. Do not add logging of sensitive values at any log level.

---

## Testing Requirements

New features must include tests for:

1. **Happy path**: the feature works correctly.
2. **Wrong key**: confirm `AuthenticationError` is raised.
3. **Tampered data**: confirm `AuthenticationError` is raised.
4. **Edge cases**: empty names, large secrets, etc.
5. **Plaintext scan**: if the feature writes files, add a test that confirms
   known plaintext does not appear in those files.

For crypto changes, also test:
- All serialization format versions (old formats still parse correctly).
- New format version is stored correctly.

---

## How to Run Tests

```bash
source .venv/bin/activate
pytest
pytest --cov=zhubin --cov-report=term-missing
```

## How to Run Linting / Type Checking

```bash
ruff check .
ruff format --check .
# mypy is configured but optional for now:
# mypy src/
```

---

## How to Safely Modify Cryptographic Code

Changes to `src/zhubin/crypto/` are **security-sensitive**. Before modifying:

1. Read `docs/SECURITY.md` to understand the current design.
2. Document the change in `docs/SECURITY.md` if it affects the crypto design.
3. Write tests before changing code (TDD for crypto).
4. Ensure all existing tests still pass.
5. Add new tests for the changed behavior.
6. Confirm the plaintext-scan test passes.
7. Consider whether backward compatibility is needed for existing encrypted
   vaults.

Never:
- Remove MAC verification.
- Add an "unsafe" or "legacy" decryption mode.
- Use a non-CSPRNG for key or nonce generation.
- Hardcode keys or nonces.

---

## How to Safely Modify Vault Formats

Vault file formats are versioned. When changing a format:

1. Increment the `version` field in the new format.
2. Add a migration path in the relevant module.
3. Ensure old-format files can still be read (backward compatibility).
4. Document the new format in `docs/SECURITY.md` and `docs/ARCHITECTURE.md`.
5. Add tests for both old and new formats.
6. Never silently upgrade a format without explicit user action.

---

## Backward Compatibility

Zhubin guarantees that vault files created by older versions can be read by
newer versions. New versions may write new formats, but must be able to read
old ones.

Breaking changes to vault formats require a migration tool.

---

## Git Integration Rules

1. All `git` calls must use `subprocess.run(["git", ...], shell=False)`.
2. Never use `shell=True` for Git operations.
3. Never handle Git credentials in Zhubin code.
4. `git add` must target only the vault directory.
5. Conflict detection must happen before any auto-commit.
6. Auto-resolution of conflicts is forbidden — stop and require human intervention.

---

## Web Security Rules

1. `web_host` must default to `127.0.0.1`. Never `0.0.0.0`.
2. Session cookies must be HTTP-only and SameSite=Strict.
3. Session tokens must be cryptographically random (`secrets.token_urlsafe(32)`).
4. Passwords must not appear in `GET` API responses (use `/copy` endpoint).
5. The API must not return any field from `SecretPayload` marked sensitive
   unless the client explicitly requests it through the copy mechanism.
   `POST .../copy` writes to the OS clipboard and must not return the password
   in the response body.
6. CORS must not be enabled (localhost only). Never send
   `Access-Control-Allow-Origin: *`.
7. State-changing requests must require a CSRF token and reject non-local
   Origin / Host headers.
8. Locking the vault must invalidate all sessions.

---

## Private Key Handling Rules

1. `DeviceIdentity.private_key` must never be serialized to JSON or logged.
2. Private key bytes must be zeroed from memory after use where possible
   (Python's GC does not guarantee this, but avoid keeping references).
3. `PRIVATE_KEY_FILE` must have mode `0600`.
4. `~/.config/zhubin/` must have mode `0700`.
5. Never add the private key to `app.state`, a class attribute, or any
   object that might be serialized.
6. The encrypted private key file is required as the disk fallback — always
   attempt the OS keyring first, but **never** write a plaintext private key
   to disk if the keyring fails.
7. Device authorization must display a public-key fingerprint and require
   confirmation. A public key in Git is not proof of identity.

---

## Command Inventory

Authoritative list (generated from the Typer app; keep docs in sync):

1. `init`
2. `add`
3. `edit`
4. `delete`
5. `cp`
6. `show`
7. `list`
8. `find`
9. `group create`
10. `group list`
11. `group rotate`
12. `group delete`
13. `device init`
14. `device list`
15. `device fingerprint`
16. `device show`
17. `device authorize`
18. `device revoke`
19. `status`
20. `sync`
21. `lock`
22. `unlock`
23. `web`

Do not document a command that does not exist. Do not leave a user-facing
command undocumented.

---

## Known Limitations and Deferred Features (V1)

- **Metadata leakage**: Group names and secret names are visible in Git.
  Encrypted indexes are a future feature.
- **Git history**: Deleted secrets remain in history as ciphertext.
- **Password history UI**: Not implemented.
- **Browser extension**: Not implemented.
- **TOTP**: Not implemented.
- **Automatic Git conflict resolution**: Explicitly not implemented (safety).
- **Hidden metadata indexes**: Not implemented.
- **`mypy --strict` full compliance**: Types are annotated but not enforced
  strictly throughout the web/API layer.
