# Zhubin

**Secure Git-backed password manager**

Zhubin stores encrypted secrets as regular files in a Git repository. The entire
repository can safely be public — an attacker with full access to the repository
and its entire history cannot recover any secret without access to an authorized
device's private key.

---

## Table of Contents

- [What is Zhubin?](#what-is-zhubin)
- [Security Model](#security-model)
- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Creating Your First Vault](#creating-your-first-vault)
- [Creating Your Device Key](#creating-your-device-key)
- [Creating Groups](#creating-groups)
- [Adding Secrets](#adding-secrets)
- [Retrieving Secrets](#retrieving-secrets)
- [Clipboard Usage](#clipboard-usage)
- [Searching Secrets](#searching-secrets)
- [Git Setup](#git-setup)
- [Connecting a New Git Repository](#connecting-a-new-git-repository)
- [Cloning an Existing Vault](#cloning-an-existing-vault)
- [Adding a New Device](#adding-a-new-device)
- [Authorizing a Device](#authorizing-a-device)
- [Revoking a Device](#revoking-a-device)
- [Lost or Stolen Devices](#lost-or-stolen-devices)
- [Rotating Group Keys](#rotating-group-keys)
- [Synchronizing with Git](#synchronizing-with-git)
- [Web UI](#web-ui)
- [Locking and Unlocking](#locking-and-unlocking)
- [Private Key Storage](#private-key-storage)
- [Configuration](#configuration)
- [Command Reference](#command-reference)
- [Repository Format](#repository-format)
- [Security Considerations](#security-considerations)
- [Git History](#git-history)
- [Backup and Recovery](#backup-and-recovery)
- [Development](#development)
- [Running Tests](#running-tests)
- [Architecture](#architecture)
- [License](#license)

---



## What is Zhubin?

Zhubin is a command-line password manager that:

- Stores secrets as **encrypted files** in a regular directory.
- Uses **Git** for synchronization and version control.
- Uses a **device-based encryption model** where every device has its own
X25519 key pair.
- Uses **envelope encryption**: secrets are encrypted with a symmetric group
key; group keys are individually encrypted/wrapped for each authorized device.
- Requires **no central server**, no database, and no cloud account.
- Provides a **local Web UI** for visual access.

The vault can live in any Git repository — public or private — without
compromising the confidentiality of stored secrets.

---



## Security Model



### What Zhubin protects against

An attacker who obtains the complete Git repository — including its entire
commit history — and all encrypted blobs cannot recover stored secrets without
access to an authorized device's private key.

### What Zhubin does NOT protect against

Zhubin **cannot** fully protect secrets if an attacker:

- Compromises an authorized device **while the vault is unlocked** (process
memory, swap, core dumps).
- Steals an unlocked private key from `~/.config/zhubin/`.
- Installs malware capable of reading process memory or clipboard contents.
- Records the user's passphrase (via keylogger, shoulder-surfing, etc.).
- Obtains a previously authorized private key **and** historical encrypted
group key versions (before rotation) — historical ciphertext in Git may
then become decryptable.



### Metadata leakage

Group names and secret names (e.g. `personal/github`) are visible in the
repository. Only secret **contents** (username, password, URL, notes) are
encrypted. This is a known limitation of V1; see `docs/SECURITY.md`.

---



## Features

- ✅ Encrypted secrets stored as files (XSalsa20-Poly1305)
- ✅ Envelope encryption with per-device wrapped group keys (X25519 SealedBox)
- ✅ Multiple groups (namespaces)
- ✅ Multiple authorized devices
- ✅ Private keys never enter the Git repository
- ✅ Passphrase-protected private keys (Argon2id KDF)
- ✅ OS keyring integration
- ✅ Clipboard copy with configurable auto-clear timeout
- ✅ Group key rotation
- ✅ Device authorization and revocation (with rotation prompt)
- ✅ Git pull / commit / push integration
- ✅ Local Web UI (localhost-only by default)
- ✅ Atomic file writes (crash-safe)
- ✅ Path traversal protection

---



## Installation

```bash
# Using pipx (recommended)
pipx install .

# Or directly with pip
pip install -e .
```

After installation, both `zhubin` and `z` (convenience alias) are available.

**Dependencies for clipboard on Linux:**

```bash
# X11
sudo apt install xclip

# Wayland
sudo apt install wl-clipboard
```

---



## Quick Start

```bash
# Install Zhubin
pipx install .

# Create a vault directory and initialize
mkdir ~/my-passwords
cd ~/my-passwords
zhubin init

# Create a group
zhubin group create personal

# Add a secret
zhubin add personal/github

# Copy the password to clipboard (clears in 30 seconds)
zhubin cp personal/github
```



### Set up Git synchronization

```bash
git init
git add .
git commit -m "Initialize Zhubin vault"

git remote add origin git@github.com:USER/my-passwords.git
git branch -M main
git push -u origin main
```

After that, use:

```bash
zhubin sync
```

for normal operation.

---



## Creating Your First Vault

```bash
mkdir ~/passwords
cd ~/passwords
zhubin init
```

`zhubin init` will:

1. Create the vault directory structure (`config.yaml`, `devices/`, `groups/`).
2. Generate a `.gitignore` that prevents accidental private key commits.
3. Prompt for a device name (defaults to your hostname).
4. Prompt for a vault passphrase (used to protect your private key at rest).
5. Generate an X25519 key pair for this device.
6. Store the **private key** encrypted at `~/.config/zhubin/private_key.enc`.
7. Register the **public key** in `vault/devices/<name>.json`.

---



## Creating Your Device Key

Your device key is created automatically during `zhubin init`.

If you need to create a key on a new device for an existing vault:

```bash
cd ~/passwords     # inside the vault
zhubin device init
```

This creates a local identity without modifying existing encrypted secrets.
The new device must then be **authorized** by a trusted device.

---



## Creating Groups

Groups are namespaces for organizing secrets. Each group has its own encryption
key.

```bash
zhubin group create personal
zhubin group create work
zhubin group create home
```

---



## Adding Secrets

```bash
zhubin add personal/github
```

Zhubin will prompt for:

```
Username:
Password:       (not echoed)
URL:
Notes:
```

The secret is encrypted with the group's key before being written to disk.

---



## Retrieving Secrets

**Show all fields (including password):**

```bash
zhubin show personal/github
```

**Copy password to clipboard (safer):**

```bash
zhubin cp personal/github
```

**Copy a specific field:**

```bash
zhubin cp personal/github password
zhubin cp personal/github username
zhubin cp personal/github url
```

**List all secrets:**

```bash
zhubin list
```

**Edit a secret:**

```bash
zhubin edit personal/github
```

**Delete a secret:**

```bash
zhubin delete personal/github
```

---



## Clipboard Usage

The primary way to retrieve passwords is:

```bash
zhubin cp personal/github
```

This copies the password to the clipboard without printing it, then
automatically clears the clipboard after the configured timeout (default 30
seconds):

```
✓ Password copied to clipboard.
  Clipboard will be cleared in 30 seconds.
```

**Safety behavior:** Before clearing, Zhubin checks whether the clipboard
still contains the value it placed there. If another application has replaced
the clipboard content in the meantime, Zhubin does NOT clear it.

**Configure the timeout:**

```yaml
# config.yaml
clipboard_timeout: 60
```

**Platform limitations:**

- Linux X11: requires `xclip` or `xsel`.
- Linux Wayland: requires `wl-clipboard`.
- macOS: works out of the box.
- Windows: works out of the box.
- Clipboard history managers (KDE Klipper, GNOME clipboard daemon) may
retain the password after Zhubin clears the clipboard.

---



## Searching Secrets

```bash
zhubin find github
zhubin find postgres
```

Case-insensitive search over group and secret names.

---



## Git Setup

Zhubin uses your existing Git installation for synchronization. It never
handles Git credentials itself.

### New local vault + new Git repository

```bash
mkdir ~/passwords
cd ~/passwords

zhubin init

git init
git add .
git commit -m "Initialize Zhubin vault"

git remote add origin git@github.com:USER/passwords.git
git branch -M main
git push -u origin main
```

Then use `zhubin sync` for ongoing synchronization.

---



## Connecting a New Git Repository

```bash
# If you already have an initialized vault
cd ~/passwords

git remote add origin git@github.com:USER/passwords.git
git branch -M main
git push -u origin main
```

---



## Cloning an Existing Vault

On a new machine with an existing vault in a remote repository:

```bash
git clone git@github.com:USER/passwords.git
cd passwords
```

Then initialize your device identity on this machine:

```bash
zhubin device init
```

This creates your device's key pair locally. The private key is stored in
`~/.config/zhubin/`, not in the repository.

Commit and push the new device record:

```bash
git add devices/
git commit -m "Add new device: my-new-laptop"
git push
```

Then ask a trusted device owner to authorize your device:

```bash
# On the trusted device (after pulling):
zhubin device authorize my-new-laptop
git add .
git commit -m "Authorize my-new-laptop"
git push
```

Back on the new device, pull the vault:

```bash
git pull
```

Your device can now decrypt secrets from the groups you were authorized for.

---



## Adding a New Device

1. On the new device, clone or pull the vault.
2. Run `zhubin device init` to create the device identity.
3. Commit and push the new `devices/<name>.json` file.
4. On a trusted device, pull and run `zhubin device authorize <name>`.
5. Commit and push.
6. Pull on the new device.

---



## Authorizing a Device

The Git repository is **untrusted**. A file such as `devices/home-pc.json` in
Git is not proof that the device is legitimate — an attacker who can modify
the repository can insert their own public key.

Every device has a deterministic **SHA-256 fingerprint** of its X25519 public
key (colon-separated uppercase hex, derived only from the 32-byte key, never
from the device name). Compare fingerprints out-of-band before authorizing.

On the new device:

```bash
zhubin device fingerprint
```

```
Device: home-pc

Public Key Fingerprint (SHA-256):
8F:92:31:AD:...
```

On the trusted device, after pulling:

```bash
zhubin device fingerprint home-pc
# or
zhubin device show home-pc
zhubin device authorize home-pc
```

Authorization displays a confirmation screen:

```
You are about to authorize:

  Device: home-pc
  Fingerprint:
  8F:92:31:AD:...

This device will receive access to:
  - personal
  - myket
  - home

The Git repository is untrusted. Compare this fingerprint with
`zhubin device fingerprint` on the target device.
```

You must confirm before any group keys are wrapped. Existing secrets do
**not** need to be re-encrypted.

---



## Revoking a Device

```bash
zhubin device revoke stolen-laptop
```

Zhubin will:

1. Mark the device as revoked in `devices/stolen-laptop.json`.
2. Remove the device's wrapped group keys from all groups.
3. Prompt whether to rotate affected group keys (strongly recommended).

```
Device revoked.

The following groups were accessible by this device:

  personal
  work
  home

Rotate affected group keys now? [Y/n]
```

**Important:** Revoking a device prevents *future* Group Keys from being issued
to that device, but does **not** invalidate historical wrapped Group Keys
already available in Git history. If the device may be compromised, rotate
the affected groups (the default).

---



## Lost or Stolen Devices

If a device is lost or stolen:

```bash
# From another authorized device
zhubin device revoke lost-device
# Choose Y to rotate all affected group keys
```

Then commit and push the vault. The lost device will be unable to read secrets
encrypted after the rotation.

**If the private key was exposed** (e.g., the device was seized and the
passphrase obtained), rotate group keys immediately and consider all historical
secrets encrypted with the old group keys potentially compromised.

---



## Rotating Group Keys

```bash
zhubin group rotate personal
```

This:

1. Generates a new 32-byte random group key.
2. Decrypts all secrets in the group in memory.
3. Re-encrypts them with the new key.
4. Wraps the new key for all currently authorized (non-revoked) devices.
5. Atomically replaces the old group configuration.

No plaintext is ever written to disk during rotation.

**Note:** Old group keys and old ciphertext remain in Git history. Rotation
only protects secrets going forward.

---



## Synchronizing with Git

```bash
zhubin sync
```

This performs:

1. `git pull` (aborts on conflicts).
2. `git add <vault>`.
3. `git commit`.
4. `git push`.

If merge conflicts are detected, Zhubin stops and asks you to resolve them
manually — it will **never** auto-resolve conflicts that could lose secrets.
Encrypted secret files and `group.json` files are marked as binary in
`.gitattributes`, so concurrent edits to the same object produce a conflict
instead of a silent merge. Zhubin never chooses "ours" or "theirs".

`zhubin sync` also refuses to run when:

- Git is not installed or the directory is not a repository
- HEAD is detached
- a merge or rebase is already in progress
- unresolved conflicts exist
- no upstream remote is configured
- a push is rejected because the remote has new commits (no force-push)

**Status:**

```bash
zhubin status
```

Shows vault path, Git branch, remote tracking status, uncommitted changes,
and conflict state.

---



## Web UI

```bash
zhubin web
```

Starts the local Web UI at `http://127.0.0.1:8787` by default.

The Web UI is **localhost-only** by default. Binding to `0.0.0.0` is refused.

Features:

- Dashboard with vault stats and Git status.
- Secret listing, search, create, edit, delete.
- Copy password/username to clipboard.
- Group management and key rotation.
- Device listing, authorization, revocation.
- Git status and sync trigger.

**Authentication:** The Web UI uses the same device passphrase as the CLI.
Enter your passphrase in the unlock screen. Sessions use HTTP-only,
`SameSite=Strict` cookies with a 1-hour TTL. State-changing requests require
a CSRF token and a local Origin/Host. CORS is not enabled.

**Copying passwords:** `POST /api/groups/{group}/secrets/{name}/copy` decrypts
the secret on the server and writes the field to the **OS clipboard** of the
machine running Zhubin. The password is **not** returned in the HTTP response
and is not placed in page HTML, URLs, or browser storage. Responses use
`Cache-Control: no-store`.

---



## Locking and Unlocking

```bash
zhubin lock       # Clear in-memory keys and invalidate sessions
zhubin unlock     # Load device identity (prompts for passphrase if needed)
```

When locked, no secrets can be decrypted.

---



## Private Key Storage

The private key never leaves the local device and is never committed to Git.

**Storage locations:**

1. **OS keyring** (preferred when available): stored under
   `zhubin/<device-id>`. This is OS-protected storage, not a disk file.
2. **Passphrase-encrypted file** (always written as well, and used when the
   keyring is unavailable): `~/.config/zhubin/private_key.enc`, mode `0600`.
   The file is encrypted with Argon2id (parameters stored in the file) →
   XSalsa20-Poly1305 with a fresh random nonce.

There is **no plaintext private-key file**. If the keyring is unavailable, a
passphrase is required. If neither the keyring nor an encrypted file can be
used, Zhubin fails instead of reducing security.

The `~/.config/zhubin/` directory has mode `0700`.

**What is stored in the vault repository:**

- `devices/<name>.json` — device name, public key, hostname, platform, timestamps.

**What is NEVER stored in the vault repository:**

- Private keys.
- Group keys (in plaintext).
- Decrypted secrets.
- Passphrases.

---



## Configuration

`config.yaml` at the vault root (or `~/.config/zhubin/config.yaml` for
user-wide defaults):

```yaml
version: 1
clipboard_timeout: 30        # seconds before clipboard is cleared
web_host: "127.0.0.1"        # Web UI bind address (never 0.0.0.0)
web_port: 8787               # Web UI port
auto_lock_timeout: 900       # seconds of inactivity before auto-lock (0=disabled)
```

Environment variables override config files (prefix `ZHUBIN_`):

```bash
ZHUBIN_CLIPBOARD_TIMEOUT=60 zhubin cp personal/github
ZHUBIN_VAULT=/path/to/vault  zhubin list
```

---



## Command Reference



### Initialization

```
zhubin init [--vault PATH] [--name NAME]
```

Initialize a new vault and device identity. Safe to run in an existing
directory — will not overwrite an existing vault or identity.

---



### Secrets

```
zhubin add <group>/<name>
```

Add a new secret interactively. Prompts for username, password (hidden),
URL, notes.

```
zhubin edit <group>/<name>
```

Edit an existing secret. Press Enter to keep current values.

```
zhubin delete <group>/<name> [--yes]
```

Delete a secret. Prompts for confirmation unless `--yes`.

```
zhubin show <group>/<name>
```

Display all fields of a secret including the password in the terminal.
Use `cp` for safer access.

```
zhubin cp <group>/<name> [FIELD] [--timeout SECONDS]
```

Copy a field to the clipboard (default: `password`). Other fields:
`username`, `url`. Clipboard auto-clears after timeout seconds.

```
zhubin list [--group GROUP]
```

List all secrets in a tree view. Optionally filter by group.

```
zhubin find <query>
```

Case-insensitive substring search over group and secret names.

---



### Groups

```
zhubin group create <name>
```

Create a group and generate its encryption key.

```
zhubin group list
```

List all groups with secret count and device count.

```
zhubin group rotate <name> [--yes]
```

Rotate the group encryption key. Re-encrypts all secrets in memory.

---



### Device Management

```
zhubin device init [--name NAME]
```

Create a local device identity without reinitializing the vault. Use this
when joining an existing vault on a new device.

```
zhubin device list
```

List all registered devices and their status (fingerprint abbreviated).

```
zhubin device fingerprint [device-name]
```

Show the full SHA-256 public-key fingerprint of this device, or of a named
device in the vault. Compare fingerprints during onboarding.

```
zhubin device show <device-name>
```

Show public details and the full fingerprint of a registered device.

```
zhubin device authorize <device-name>
```

Authorize a device for all groups the current device can access. Displays the
fingerprint and requires confirmation before wrapping any group keys.

```
zhubin device revoke <device-name> [--yes] [--rotate/--no-rotate]
```

Revoke a device. Offers group key rotation after revocation (default: yes).

---



### Git

```
zhubin status
```

Show vault path, Git branch, remote tracking, uncommitted changes, conflicts.

```
zhubin sync [--message MESSAGE] [--no-push]
```

Pull, stage, commit, and push the vault. Stops on conflicts. Refuses to run
on detached HEAD, mid-merge, or when Git is unavailable. Never force-pushes.
Never auto-resolves encrypted objects.


---



### Vault State

```
zhubin lock
```

Clear in-memory keys and invalidate web sessions.

```
zhubin unlock
```

Load device identity and unlock the vault.

```
zhubin web [--host HOST] [--port PORT] [--open/--no-open]
```

Start the local Web UI (localhost only by default).

---



## Repository Format

```
vault/
├── .gitignore
├── config.yaml
├── devices/
│   ├── laptop.json
│   └── workstation.json
│
└── groups/
    ├── personal/
    │   ├── group.json
    │   └── secrets/
    │       ├── github.secret
    │       └── gmail.secret
    │
    └── work/
        ├── group.json
        └── secrets/
            └── jira.secret
```

`devices/<name>.json` — public device info only:

```json
{
  "version": 1,
  "id": "<uuid>",
  "name": "laptop",
  "public_key": "<base64-X25519-public-key>",
  "created_at": "2026-01-01T00:00:00+00:00",
  "hostname": "my-laptop",
  "platform": "Linux"
}
```

`groups/<name>/group.json` — encrypted group keys per device:

```json
{
  "version": 1,
  "id": "<uuid>",
  "name": "personal",
  "created_at": "2026-01-01T00:00:00+00:00",
  "device_keys": {
    "<device-uuid>": {
      "type": "zhubin-wrapped-group-key-v1",
      "wrapped_key": "<base64-SealedBox-ciphertext>",
      "cipher": "x25519-xsalsa20poly1305-sealed",
      "added_at": "2026-01-01T00:00:00+00:00"
    }
  }
}
```

`groups/<name>/secrets/<name>.secret` — encrypted secret:

```json
{
  "version": 2,
  "type": "zhubin-secret-v1",
  "cipher": "xsalsa20poly1305",
  "nonce": "<base64-24-byte-nonce>",
  "ciphertext": "<base64-ciphertext-plus-mac>"
}
```

No plaintext credentials appear anywhere in this directory.

---



## Security Considerations

See `docs/SECURITY.md` for the full cryptographic design.

- Secret names and group names are visible in the repository (metadata
leakage). Only contents are encrypted. See the [Security Model](#security-model)
section above.
- Deleting a secret removes it from the current vault, but its encrypted
form may persist in Git history.
- Clipboard history managers may retain passwords after Zhubin clears the
clipboard.
- Process memory may briefly contain plaintext during decryption.

---



## Git History

When you delete a secret:

```bash
zhubin delete personal/github
```

The current version is removed, but the encrypted ciphertext remains in Git
commits. This is normally acceptable because the data is encrypted.

However, if a group key is ever compromised, historical ciphertext in Git
becomes decryptable. This is why **group key rotation is critical after a
device compromise**.

To remove historical ciphertext from Git history, you would need to rewrite
the Git history (`git filter-repo` or similar). This is not currently
automated by Zhubin.

---



## Backup and Recovery

**Your private key** is stored at `~/.config/zhubin/private_key.enc`
(mode 0600). Back this up securely.

If your **private key is deleted**:

- If the encrypted backup file is lost, you can no longer decrypt any
group keys for which your device was authorized.
- Other authorized devices can still access all secrets.
- You must generate a new identity (`zhubin device init`) and have it
authorized from another device.

If you **lose all authorized devices**: Secrets are unrecoverable. There
is no backdoor or master key.

---



## Development

```bash
git clone <repo>
cd zhubin-vault

# Set up virtual environment
uv venv .venv
source .venv/bin/activate
uv pip install -e ".[dev]"
```

---



## Running Tests

```bash
pytest

# With coverage
pytest --cov=zhubin --cov-report=term-missing
```

---



## Architecture

```
CLI / Web UI
    |
    v
VaultService              ← sole entry point for vault operations
    |
    +--→ crypto/identity  ← device key generation, group key wrap/unwrap
    +--→ crypto/encrypt   ← secret encryption/decryption (XSalsa20-Poly1305)
    +--→ storage/filesystem ← atomic file I/O, path safety
    +--→ storage/git        ← git subprocess integration
```

CLI and Web never contain cryptographic logic. All encryption/decryption
goes through the shared `VaultService`.

See `docs/ARCHITECTURE.md` for details.

---



## License

MIT — see `LICENSE`.