# Security Audit Report

Date: 2026-08-22

This pass reviewed and hardened the existing Zhubin implementation. No unrelated
features were added. All 135 tests pass; `ruff check`, `ruff format --check`,
and `mypy src/zhubin` succeed.

---

## 1. Device Authorization

### Findings

- `zhubin device authorize` wrapped group keys as soon as a matching
  `devices/<name>.json` existed in Git.
- The Git repository is untrusted: an attacker who can modify it can add
  `devices/attacker-laptop.json` containing their own public key.
- There was no user-verifiable fingerprint and no confirmation step before
  wrapping keys.

### Changes

- Fingerprints are SHA-256 of the canonical 32-byte X25519 public key,
  formatted as 32 colon-separated uppercase hex pairs. Device names and other
  metadata are not inputs.
- New commands: `zhubin device fingerprint [name]` and `zhubin device show <name>`.
- `authorize` shows device name, full fingerprint, and groups that will be
  granted, and requires explicit confirmation (`--yes` skips it for scripts).
- The Web UI shows the fingerprint and a confirmation dialog before authorize.

### Tests

- Deterministic fingerprints; base64 vs raw bytes agree.
- Modified public keys produce different fingerprints.
- Canonical serialization is stable.

---

## 2. Revocation and Rotation

### Findings

- Revoke removed wrapped keys from current `group.json` but rotation errors
  were swallowed (`contextlib.suppress(Exception)`).
- Rotation wrapped the new group key for **all** active registered devices,
  including devices that had never been authorized for that group.
- Documentation did not clearly separate metadata revocation from
  cryptographic revocation via rotation.

### Changes

- Rotation wraps the new key only for devices that currently have access to
  that group and are not revoked.
- Rotation failures fail closed (they are not swallowed).
- CLI revoke warns that Git history may still contain wrapped keys and
  defaults to rotating affected groups.
- Docs state: revocation prevents future wraps; it does not invalidate
  historical wrapped keys in Git history.

### Tests

- Revoked device removed from current group metadata.
- Old group key still decrypts captured historical ciphertext.
- After rotation, the old group key cannot decrypt new ciphertext.
- Revoked device is not included when wrapping the new key.
- Currently authorized devices still work.
- Never-authorized registered devices do not gain access on rotation.

---

## 3. Argon2id

### Findings

- Encrypted identity files stored KDF parameters, but the layout was not
  fully specified (flat fields, combined nonce+ciphertext).
- `derive_key_from_passphrase` ignored stored parameters on a dead code path
  (`__wrapped__` hack).
- Parallelism was 1; documentation did not list every field needed for
  future upgrades.
- Empty passphrases were accepted.

### Changes

- Version-2 format stores `version`, `type`, nested `kdf` (name, memory_kib,
  time_cost, parallelism, salt, hash_len) and nested `cipher` (name, nonce,
  ciphertext).
- Defaults follow RFC 9106's second recommended Argon2id set: 64 MiB,
  time_cost 3, parallelism 4, 16-byte random salt.
- Version-1 files remain decryptable.
- Unsupported KDF names/versions and out-of-range parameters fail closed.
- Empty passphrases are rejected. Passphrases are never written into the blob.

### Tests

- Same key + passphrase produces different files (random salt and nonce).
- Wrong passphrase fails.
- Modified KDF metadata fails closed.
- Unsupported KDF / version fail clearly.
- Version-1 blobs still decrypt.

---

## 4. Private Key Storage

### Findings

- There was already no plaintext-on-disk fallback, but keyring access was
  duplicated instead of going through `keyring_store`.
- Sensitive files were written then `chmod`'d, so a brief umask window existed.
- Temp files for identity writes were not created with `0600` via `os.open`.

### Changes

- Policy is: OS keyring **and/or** Argon2id-encrypted file. Never a plaintext
  private-key file. If neither can be used, the operation fails.
- Identity files are written via `os.open(..., 0600)` + fsync + rename.
- Keyring operations go through `keyring_store` (which never writes disk files).
- README describes this storage behavior exactly.

### Tests

- Keyring failure does not write plaintext.
- Private-key bytes never appear under the config directory or leftover temps.
- Generated identity files are mode `0600` where testable.
- Encrypted-file round-trip works without the keyring.

---

## 5. Web Security

### Findings

- Localhost binding and SameSite=Strict cookies existed.
- There was no CSRF token, no Host allowlist, and no Origin check.
- CORS was not enabled, but that was not tested.
- Lock invalidated in-process sessions; expired/revoked session tests were
  missing.
- `TemplateResponse` used the old positional signature (broken on current
  Starlette).

### Changes

- Middleware: Host allowlist, Origin check on unsafe methods, double-submit
  CSRF cookie (`zhubin_csrf`) + `X-CSRF-Token` header.
- API responses set `Cache-Control: no-store`. Wildcard CORS headers are
  stripped if present.
- Lock still calls `revoke_all()`. Session cookies remain HttpOnly +
  SameSite=Strict and are not placed in URLs.
- Local Web threat model documented in `docs/SECURITY.md`.

### Tests

- Valid same-origin POST succeeds.
- Missing / incorrect CSRF fails.
- Malicious Origin fails.
- Unexpected Host fails.
- Arbitrary CORS origin is not reflected.
- Session invalid after lock; expired/revoked session cannot call privileged
  endpoints.

---

## 6. Clipboard Web Flow

### Findings

- GET secret responses already omitted the password.
- `POST .../copy` already copied **server-side** via `pyperclip` and did not
  return the password. Documentation over-claimed "passwords never appear in
  GET responses" without describing that copy still decrypts in the server
  process and writes the OS clipboard.
- Edit UI kept `window._editOriginal.password`, which was always empty (GET
  omits it) and could wipe passwords; it also suggested the password lived in
  JS state.

### Changes

- Copy remains server-side OS clipboard; the HTTP body is `{status, field,
  timeout}` only. Errors do not include the secret value.
- Copy requires session + CSRF; responses are `no-store`.
- Edit omits password when unchanged so the server keeps the existing value.
- Frontend does not use `localStorage` / `sessionStorage` / `indexedDB` and
  does not call `navigator.clipboard`.
- Docs describe the actual flow, including that create/edit POST bodies still
  carry the password over localhost HTTP.

### Tests

- Password not in GET APIs.
- Copy requires auth and CSRF.
- Copy response is non-cacheable and does not contain the password.
- SPA HTML shell has no vault secrets.
- Frontend source does not use web storage for secrets.

---

## 7. Nonce Handling

### Findings

- `SecretBox.encrypt()` already generated random nonces, but they were not
  explicit in the API or on-disk format (v1 combined blob).
- Callers could not pass a nonce (good), but this was not tested via signature.

### Changes

- Every SecretBox encryption generates a fresh `nacl.utils.random(24)` nonce.
- Version-2 secrets store nonce and ciphertext separately.
- `encrypt_secret` has no nonce parameter.

### Tests

- Encrypting the same plaintext twice yields different ciphertext.
- Nonce length is 24 bytes.
- Corrupted nonce/ciphertext fail authentication.
- No caller-controlled nonce parameter.
- Serialization preserves the nonce field.

---

## 8. Crypto Domain Separation

### Findings

- Secrets, identities, and wrapped keys were structurally different JSON, but
  type labels were not explicit.
- Docs already avoided claiming age-protocol equivalence in most places; the
  remaining "similar to age" wording was tightened.

### Changes

- Type labels: `zhubin-secret-v1`, `zhubin-device-key-v1`,
  `zhubin-wrapped-group-key-v1`, plus authenticated in-box prefixes for new
  wraps/encryptions.
- Parsing the wrong object type fails closed. Legacy v1 secrets and unprefixed
  wrapped keys still decrypt.
- Docs: recipient-based envelope encryption using libsodium; conceptually
  similar to age, **not** age-compatible, not protocol-equivalent.

### Tests

- Secret parsed as identity fails; identity parsed as secret fails.
- Wrapped key parsed as secret fails.
- Wrong `type` label fails.
- Legacy v1 secret and unprefixed wrap still work.

---

## 9. Git Sync

### Findings

- `shell=True` was already unused, but coverage of unsafe states was thin.
- `git add` targeted the vault path.
- Concurrent edits to JSON could theoretically auto-merge; encrypted objects
  were not marked binary.
- Detached HEAD, missing git, missing upstream, and push rejection were not
  all tested.

### Changes

- `.gitattributes` marks `*.secret`, `group.json`, and `devices/*.json` as
  binary / `merge=binary`.
- Sync refuses detached HEAD, merge/rebase in progress, unresolved conflicts,
  missing upstream, missing git, and uninitialized repos.
- Pull never uses `-X ours` / `-X theirs`. Push never force-pushes.
- After pull, JSON vault files are checked for conflict markers / invalid JSON.
- README documents conflict behavior.

### Tests

- Scenario A: concurrent edits of the same secret → conflict, no silent
  overwrite.
- Scenario B: push rejection when remote advanced.
- Scenario C: unresolved conflicts → sync refused.
- Scenario D: concurrent group.json changes → conflict.
- Detached HEAD, missing upstream, git unavailable.

---

## 10. Documentation Accuracy

### Findings

- The implementation had 20 user-facing commands (not 18). After this pass
  there are **22** (`device fingerprint`, `device show` added).
- Command lists in docs were hand-maintained.

### Changes

- Authoritative inventory is `iter_cli_command_paths()` from the Typer app.
- README, AGENTS.md, ARCHITECTURE.md, and SECURITY.md updated.
- Drift test compares CLI help / inventory against README.

### Tests

- `test_cli_docs.py`: implemented ↔ documented inventory, `--help` subcommands,
  no "semantically equivalent to age" claim.

---

## Files Changed

### Core

- `src/zhubin/crypto/labels.py` (new)
- `src/zhubin/crypto/encrypt.py`
- `src/zhubin/crypto/identity.py`
- `src/zhubin/crypto/keyring_store.py`
- `src/zhubin/vault/models.py`
- `src/zhubin/vault/vault.py`
- `src/zhubin/storage/filesystem.py`
- `src/zhubin/storage/git.py`
- `src/zhubin/exceptions.py`
- `src/zhubin/cli/app.py`
- `src/zhubin/cli/device.py`
- `src/zhubin/web/security.py` (new)
- `src/zhubin/web/app.py`
- `src/zhubin/web/auth.py`
- `src/zhubin/web/api/__init__.py`
- `src/zhubin/web/static/js/app.js`

### Docs

- `README.md`
- `AGENTS.md`
- `docs/SECURITY.md`
- `docs/ARCHITECTURE.md`
- `docs/SECURITY_AUDIT.md` (this file)

### Tests

- `tests/test_crypto.py`
- `tests/test_crypto_hardening.py` (new)
- `tests/test_vault.py`
- `tests/test_web.py`
- `tests/test_git_sync.py` (new)
- `tests/test_cli_docs.py` (new)
- `tests/test_storage.py`

---

## New Tests Added

- Fingerprint determinism / uniqueness / canonical bytes
- Argon2id v2 format, salt/nonce uniqueness, wrong passphrase, tampered KDF,
  unsupported version, v1 compatibility
- Keyring failure → no plaintext; 0600 permissions; no leftover temps
- Nonce length, corruption, no caller-controlled nonce
- Type-confusion across secret / identity / wrapped group key
- Revocation + rotation historical-access model
- Rotation does not authorize outsiders
- CSRF / Origin / Host / CORS / session lock / expiry
- Copy: auth, CSRF, no-store, password not in body/HTML/JS storage
- Git scenarios A–D plus detached HEAD / missing upstream / no git
- CLI/docs drift

---

## Remaining Risks

- Plaintext exists in process memory while the vault is unlocked.
- OS clipboard and third-party clipboard managers may retain copied secrets.
- DNS rebinding is mitigated by Host/Origin checks, not eliminated if the
  user binds the Web UI to a non-local address after confirming the CLI
  warning.
- CSRF double-submit cookies are readable by JS on the same origin (required
  for the SPA); a same-origin XSS would still be fatal.
- Create/edit HTTP bodies still carry passwords over localhost.
- Git history still contains old wrapped group keys after rotation; that is
  the documented model, not a bug.

---

## Known Limitations

Unchanged V1 limitations: metadata leakage of group/secret names, ciphertext
in Git history, no TOTP, no browser extension, no automatic conflict
resolution, no encrypted indexes.

---

## Breaking Changes

- New secret files are version 2 (`type`, separate nonce). Version 1 remains
  readable.
- New private-key files are version 2 (nested KDF/cipher). Version 1 remains
  readable.
- New wrapped group keys include an in-box type prefix. Old 32-byte wraps
  remain unwrap-able.
- `device authorize` now requires confirmation unless `--yes`.
- Web UI state-changing requests require `X-CSRF-Token` matching the CSRF
  cookie. The bundled SPA sends this automatically.
- Argon2id parallelism default is 4 (was 1). Old files store parallelism=1
  and still decrypt.
- New vaults include `.gitattributes` so encrypted objects merge as binary.
