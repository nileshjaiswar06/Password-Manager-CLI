# Password-Manager-CLI

A memory-safe Rust CLI vault that generates, encrypts, and stores passwords locally.

[![CI](https://github.com/nileshjaiswar06/Password-Manager-CLI/actions/workflows/ci.yml/badge.svg)](https://github.com/nileshjaiswar06/Password-Manager-CLI/actions/workflows/ci.yml)

Quick usage (build & run):

```powershell
# Build release
cargo build --release

# Run help
cargo run -- --help
```

This project demonstrates secure, offline password management using Rust's safety guarantees. It uses Argon2id for key derivation and AES-256-GCM for authenticated encryption.

Purpose & goals
---------------

This project is an educational, practical reference implementation of a local, encrypted password vault implemented in Rust. The goals are:

- Demonstrate how to derive encryption keys safely from a master password using Argon2id and store parameters needed for reproducible decryption.
- Show how to perform authenticated encryption with AES-256-GCM and store ciphertext in a small, versioned JSON envelope.
- Provide a simple, scriptable CLI for common password-manager flows (init, add, get, rm, list, generate).
- Illustrate safe I/O patterns (atomic writes, backups) and memory-hygiene practices (zeroizing derived keys) suitable for a small production or educational project.

This repository is not intended to be a fully-featured production password manager (no sync, no clipboard integration, limited zeroization). Treat it as a building block and learning artifact.

Project structure (current)
--------------------------

High-level file layout (important files):

- `Cargo.toml` — dependency manifest and dependencies.
- `src/main.rs` — CLI parsing and top-level wiring (subcommands, global flags like `--file`, `--no-backup`).
- `src/models.rs` — serde data models for vault envelope and entries.
- `src/crypto.rs` — KDF (Argon2) and AES-GCM encrypt/decrypt helpers.
- `src/storage.rs` — disk I/O helpers for reading/writing the JSON envelope, atomic writes and backups.

# Password-Manager-CLI

[![CI](https://github.com/nileshjaiswar06/Password-Manager-CLI/actions/workflows/ci.yml/badge.svg)](https://github.com/nileshjaiswar06/Password-Manager-CLI/actions/workflows/ci.yml)

A compact, memory-safe Rust CLI that manages a local encrypted password vault (Argon2id + AES‑GCM).

Quick start
-----------
- Build (release):

```powershell
cargo build --release
```

- Show help / commands:

```powershell
cargo run -- --help
```

Common commands (examples)
--------------------------
- Initialize a vault (prompts for master password):

```powershell
cargo run -- init --file C:\path\to\vault.json.enc
```

- Add an entry (interactive):

```powershell
cargo run -- add -n mysite --file C:\path\to\vault.json.enc
```

- Get an entry (prints password to stdout):

```powershell
cargo run -- get -n mysite --file C:\path\to\vault.json.enc
```

- List entries:

```powershell
cargo run -- list --file C:\path\to\vault.json.enc
```

- Remove an entry:

```powershell
cargo run -- rm -n mysite --file C:\path\to\vault.json.enc
```

Defaults
--------
- Default vault path:
  - Windows: %APPDATA%/vault.json.enc
  - Unix: $HOME/.vault.json.enc
  - Override with `--file PATH`.

Security note (short)
---------------------
This is an educational prototype. It uses Argon2id and AES‑GCM and applies basic zeroization for key material, but it is not a drop-in replacement for a production password manager. Audit and harden before storing real secrets.

Project layout (important files)
--------------------------------
- `src/main.rs` — CLI entrypoint
- `src/lib.rs` — public library exports
- `src/vault.rs`, `src/crypto.rs`, `src/storage.rs`, `src/models.rs` — core logic
- `tests/cli_flow.rs` — integration flow

Contributing & license
----------------------
PRs welcome. See `CONTRIBUTING.md` and `LICENSE` (MIT) for details.

Release
-------
Local tag `v0.1.0` has been created. To publish it to GitHub:

```powershell
git push origin v0.1.0
# or, using GitHub CLI to create a release from RELEASE.md:
gh release create v0.1.0 --title "v0.1.0" --notes-file RELEASE.md
```

Contact
-------
See repository metadata.

All commands
------------
Global flags (before subcommand):

- `-f, --file <PATH>` — path to the vault file (defaults to OS-specific path)
- `--no-clipboard` — disable clipboard operations (if present)
- `--no-backup` — disable creating a `.bak` backup when writing the vault

Subcommands:

- `init [--force]` — initialize a new vault; use `--force` to overwrite
- `add -n, --name <NAME>` — add a new entry with the given name
- `get -n, --name <NAME>` — retrieve an entry (prints password)
- `rm -n, --name <NAME>` — remove an entry
- `list` — list all entry names
- `gen -l, --length <N> [--symbols]` — generate a password of length N (default 16); `--symbols` includes symbols
