# Zhubin Security Documentation

This document describes the cryptographic design, threat model, known
limitations, and security invariants of Zhubin.

---

## Threat Model

### Attacker capabilities

Zhubin is designed to be secure against an attacker who can obtain:

- The complete Git repository and its entire commit history.
- Every encrypted secret file.
- Every `group.json` file (containing wrapped group keys).
- Every `devices/<name>.json` file (containing public device keys).
- Deleted encrypted secrets from Git history.

Under these conditions, the attacker **cannot decrypt any stored secret**
without access to an authorized device's private key.

### Trusted elements

The following are considered trusted:

- Authorized devices.
- Private device keys that remain on those devices.
- The user's local OS account while the vault is unlocked.

---

## Cryptographic Design

### Device Identity

Every device has an X25519 key pair generated using
`nacl.public.PrivateKey.generate()` (libsodium via PyNaCl).

- **Private key**: 32 bytes, stored only on the local device.
- **Public key**: 32 bytes, stored in `vault/devices/<name>.json` and
  committed to the Git repository.

The X25519 key exchange is the basis for group key wrapping.

### Private Key Storage

Private keys must never be written to disk in plaintext.

**Preferred storage: OS keyring**

The private key bytes are stored in the OS keyring under the service name
`zhubin` and key `<device-id>` (via the `keyring` Python package). The OS
keyring is unlocked by the user's session credentials.

**Fallback: Passphrase-encrypted file**

If the OS keyring is unavailable, the private key is encrypted using Argon2id
and XSalsa20-Poly1305.  Defaults follow RFC 9106's second recommended
Argon2id parameterization:

| Parameter | Default | Notes |
|---|---|---|
| KDF | Argon2id | Only supported KDF |
| `memory_kib` | 65536 (64 MiB) | Stored in the file |
| `time_cost` | 3 | Stored in the file |
| `parallelism` | 4 | Stored in the file |
| `hash_len` | 32 | SecretBox key size |
| salt | 16 random bytes | Unique per encrypted identity |

The on-disk format (version 2) stores every parameter required to decrypt,
so parameters can be upgraded later while remaining able to read older files:

```json
{
  "version": 2,
  "type": "zhubin-device-key-v1",
  "kdf": {
    "name": "argon2id",
    "memory_kib": 65536,
    "time_cost": 3,
    "parallelism": 4,
    "salt": "<base64>",
    "hash_len": 32
  },
  "cipher": {
    "name": "xsalsa20poly1305",
    "nonce": "<base64 24-byte nonce>",
    "ciphertext": "<base64>"
  }
}
```

Version-1 files (flat `kdf` / `kdf_params` / combined nonce+ciphertext) remain
decryptable.  Unsupported KDF names or versions fail closed.  Each encryption
uses a fresh random salt and nonce; the same private key and passphrase never
produce the same ciphertext twice.

The encrypted blob is stored at `~/.config/zhubin/private_key.enc` with
file permissions `0600`. The containing directory has permissions `0700`.
Sensitive files are created with `os.open(..., 0600)` so the umask cannot
leave them world-readable even briefly.

Zhubin **never silently falls back to plaintext private key storage**.
If the OS keyring is unavailable, a passphrase is required.  If neither
secure keyring storage nor an encrypted file can be written, the operation
fails.

### Public Keys

Public keys are stored in `vault/devices/<name>.json` and are safe to commit
to Git. An attacker with public keys cannot derive private keys (X25519 is a
one-way function).

### Group Keys

Each group has a random 32-byte symmetric key generated using
`nacl.utils.random(32)` (libsodium CSPRNG).

Group keys are **never stored in plaintext** anywhere in the vault repository.

### Secret Encryption

Each secret is encrypted using:

- **Cipher**: XSalsa20-Poly1305 (`nacl.secret.SecretBox`)
- **Key**: The group's 32-byte symmetric key
- **Nonce**: 24 bytes from `nacl.utils.random` generated for **every**
  encryption. Callers cannot supply a nonce. The same plaintext and key
  therefore always produce different ciphertext.
- **Authentication**: Poly1305 MAC (16 bytes) appended by PyNaCl

The nonce and ciphertext are stored as separate base64 fields in version-2
secret files (`type: zhubin-secret-v1`). Version-1 files (combined
nonce+ciphertext, no type label) remain decryptable.

The Poly1305 MAC is verified before **any** plaintext is returned. If
verification fails, `AuthenticationError` is raised and no plaintext is
exposed.

### Group Key Wrapping

To encrypt a group key for a device, Zhubin uses `nacl.public.SealedBox`:

```
SealedBox(device_public_key).encrypt(group_key)
```

This is the libsodium `crypto_box_seal` construction:

1. Generate an ephemeral X25519 key pair.
2. Perform X25519 ECDH between the ephemeral private key and the recipient's
   public key to derive a shared secret.
3. Derive an encryption key using HSalsa20.
4. Encrypt the group key with XSalsa20-Poly1305.
5. Prepend the ephemeral public key to the ciphertext.

Only the recipient device with its private key can decrypt the wrapped key:

```
SealedBox(device_private_key).decrypt(wrapped_key)
```

This follows a recipient-based envelope-encryption model using libsodium
primitives (`crypto_box_seal`).  It is conceptually similar to the `age`
X25519 recipient model but is **not `age`-compatible** and must not be
considered protocol-equivalent to `age`.

Each device gets an independently wrapped copy of the group key. The wrapping
is stored in `group.json`:

```json
{
  "device_keys": {
    "<device-uuid>": {
      "type": "zhubin-wrapped-group-key-v1",
      "wrapped_key": "<base64-SealedBox-ciphertext>",
      "cipher": "x25519-xsalsa20poly1305-sealed"
    }
  }
}
```

### Authentication and Integrity

All ciphertext includes an authenticated encryption tag (Poly1305 for
XSalsa20-Poly1305). This provides:

- **Confidentiality**: Only the key holder can read the plaintext.
- **Integrity**: Any modification to the ciphertext (even a single bit flip)
  will cause decryption to fail with `AuthenticationError`.

Zhubin **never continues after a MAC verification failure**. There is no
`ignore_mac` or `best_effort_decrypt` mode.

### Format identification

Serialized cryptographic objects carry an explicit `version` and `type` so
they cannot be confused with each other:

| Object | `type` label |
|---|---|
| Encrypted secret | `zhubin-secret-v1` |
| Encrypted device private key | `zhubin-device-key-v1` |
| Wrapped group key | `zhubin-wrapped-group-key-v1` |

Version-2 SecretBox plaintexts also include an authenticated prefix. Parsing
a wrapped group key as a secret, or a secret as an encrypted identity, fails
closed. Unsupported types and versions fail closed.

Group keys themselves are independent CSPRNG output, not derived from a shared
IKM, so a KDF info-string is not required for them. Argon2id is used only to
protect the device private key.

### Key Rotation

`zhubin group rotate <name>` performs:

1. Derives the old group key using the current device's private key.
2. Generates a new random 32-byte group key.
3. Decrypts all secrets in the group **in memory** (no plaintext temp files).
4. Re-encrypts all secrets with the new group key.
5. Wraps the new group key for all currently active (non-revoked) devices.
6. Writes new encrypted secrets atomically.
7. Writes the new `group.json` atomically.

A failed rotation does not leave the vault in a partial state because new
secrets are written before the group record is updated, and atomic renames
are used.

### Device Authorization

When a new device is added:

1. The new device runs `zhubin device init` to generate its key pair.
2. The public key is added to `vault/devices/<name>.json`.
3. Both devices display a SHA-256 fingerprint of the **canonical 32-byte
   public key** (`zhubin device fingerprint`). The fingerprint does not
   depend on the device name or other metadata.
4. A trusted device pulls the vault, compares fingerprints out-of-band, and
   runs `zhubin device authorize <name>` only after explicit confirmation.
5. The trusted device wraps the group key for all accessible groups for the
   new device and updates `group.json`.

The Git repository is untrusted. Presence of a public key in Git is **not**
sufficient evidence that the device is legitimate.

No existing secrets need to be re-encrypted.

### Device Revocation

When a device is revoked:

1. The device record is marked `revoked: true` in `devices/<name>.json`.
2. The device's wrapped keys are removed from all current `group.json` files
   (revocation of *future* wraps).
3. The user is warned that Git history may still contain Group Keys encrypted
   for this device, and is prompted to rotate all affected groups (default:
   yes).

**Revocation** prevents future Group Keys from being issued to that device.
**Cryptographic revocation** requires rotating the affected Group Keys so
that newly written ciphertext cannot be decrypted with a key recovered from
Git history.

If a device already has a copy of a group key (obtained before revocation),
it retains the ability to decrypt **historical** ciphertext until the group
key is rotated. Rotation wraps the new key only for devices that currently
have access to that group (revoked and never-authorized devices are excluded).

### Git History Implications

The Git repository retains all previous versions of files. This means:

- Deleted secrets remain in Git history as ciphertext.
- Previous `group.json` versions (with old wrapped keys) remain in history.

If a device is compromised and an attacker has a copy of an old wrapped
group key from Git history, and if the group key was never rotated, the
attacker can decrypt all historical secrets for that group.

**Mitigation**: Always rotate group keys after revoking a compromised device.

### Passphrase Protection

The vault passphrase is used solely to encrypt/decrypt the private key file.
It is **never**:

- Stored anywhere (not on disk, not in memory beyond the decryption call).
- Sent anywhere.
- Logged.

Argon2id is used with parameters that make brute-force attacks expensive.

### Cryptographic Parameters Summary

| Component | Algorithm | Library |
|---|---|---|
| Device key pair | X25519 | libsodium (PyNaCl) |
| Group key generation | CSPRNG | libsodium (PyNaCl) |
| Secret encryption | XSalsa20-Poly1305 | libsodium (PyNaCl) |
| Group key wrapping | X25519 SealedBox | libsodium (PyNaCl) |
| Private key KDF | Argon2id | argon2-cffi |
| Private key encryption | XSalsa20-Poly1305 | libsodium (PyNaCl) |

---

## Metadata Leakage (V1 Limitation)

In V1, group names and secret names are stored as plaintext file paths in the
Git repository. An attacker with repository access can see:

- How many groups exist and their names (e.g., `personal`, `work`).
- How many secrets exist per group and their names (e.g., `github`, `jira`).
- Creation and modification timestamps from Git commit history.

Only the **contents** of secrets (username, password, URL, notes) are
encrypted.

This is a known and documented limitation. Future versions could implement
encrypted indexes or metadata hiding, but this would significantly increase
complexity.

---

## Web UI Security

The Web UI is a **local privileged application**. Binding to localhost is
necessary but not sufficient (DNS rebinding and cross-site requests can
still target 127.0.0.1).

### Binding and CORS

- The Web UI binds to `127.0.0.1` by default. Binding to `0.0.0.0` is
  explicitly rejected by configuration validation.
- CORS is **not** enabled. Responses never send
  `Access-Control-Allow-Origin: *`.

### Host and Origin

- The `Host` header must be a local name (`127.0.0.1`, `localhost`, `::1`)
  or the explicitly configured bind host.
- State-changing requests that include an `Origin` header must come from a
  local origin. Other origins are rejected.

### CSRF and sessions

- State-changing requests require a double-submit CSRF cookie
  (`zhubin_csrf`) matching the `X-CSRF-Token` header.
- Session tokens are 192-bit cryptographically random values
  (`secrets.token_urlsafe(32)`), stored only in memory.
- Session cookies are HTTP-only, `SameSite=Strict`, and are never placed in
  URLs.
- Locking the vault invalidates **all** sessions.

### Clipboard (`POST .../copy`)

Passwords never appear in GET responses. Copying a password uses
`POST /api/groups/{group}/secrets/{name}/copy`, which:

- Requires a valid session and a valid CSRF token.
- Decrypts the secret on the server.
- Writes the requested field to the **OS clipboard** of the machine running
  Zhubin (via `pyperclip`).
- Does **not** return the password in the HTTP body, so it never enters
  frontend JavaScript, page HTML, URLs, or `localStorage` / `sessionStorage`.
- Sets `Cache-Control: no-store`.

The password therefore **does** exist briefly in the Zhubin server process
and the OS clipboard; it does not cross HTTP as response JSON. This document
does not claim that plaintext never crosses HTTP for other endpoints (create
and edit send the password in the POST/PUT body over localhost).

The Web UI does not implement its own cryptography — it uses the same
`VaultService` layer as the CLI.

---

## What Zhubin Does Not Protect

- **Memory**: Plaintext secrets exist briefly in process memory during
  decryption. Memory dumps or a local attacker with ptrace access could
  recover secrets while the vault is unlocked.
- **Swap**: If the OS swaps process memory, secrets could be written to disk.
  Consider using encrypted swap.
- **Clipboard history**: Third-party clipboard managers may retain the
  password after Zhubin clears the clipboard.
- **Terminal scrollback**: `zhubin show` prints the password; terminal
  history/scrollback may retain it.
- **Passphrase**: A keylogger or shoulder-surfing attacker can capture the
  passphrase.
- **Compromised device**: If the device is compromised while the vault is
  unlocked, secrets are exposed.
- **Git history + compromised key**: Historical ciphertext in Git becomes
  decryptable if the corresponding group key is obtained.
