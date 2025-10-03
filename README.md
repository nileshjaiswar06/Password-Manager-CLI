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
- `src/vault.rs` — high-level vault operations implementing `init`, `add`, `get`, `rm`, `list`, and `gen` commands.
- `README.md` / `SPEC.md` — documentation and spec for the vault format and CLI behavior.

Repository layout (on-disk)
---------------------------

A quick tree of important files and folders in this repository (top-level):

```
Password-Manager-CLI/
├── Cargo.toml                # Rust manifest (dependencies & features)
├── README.md                 # Project documentation (this file)
├── SPEC.md                   # Vault format and CLI spec
├── LICENSE                   # Project license (MIT)
├── src/
│   ├── main.rs               # CLI wiring and entrypoint
│   ├── vault.rs              # High-level vault operations and command handlers
│   ├── crypto.rs             # KDF (Argon2) + AEAD (AES-GCM) helpers
│   ├── storage.rs            # Read/write envelope, atomic write helpers
│   └── models.rs             # serde data models for entries and envelope
├── .github/                  # (optional) CI workflows (not present yet)
└── tests/                    # (optional) integration tests (not present yet)
```

Feel free to add example configs, workflows, or an `examples/` folder for sample vault files.

How it works (execution flow)
----------------------------

Typical operation flow (e.g., `get`):

1. CLI parses arguments and locates the vault file (default OS path or `--file`).
2. The code reads the JSON envelope and extracts KDF parameters and salt.
3. The user is prompted for the master password (hidden). The code derives a 256-bit key using Argon2id and the stored salt/params.
4. The key is used with AES-256-GCM and the stored nonce to decrypt the ciphertext into a JSON payload.
5. The decrypted payload (a JSON array of entries) is parsed and the requested entry is printed to stdout.

On `add` or `rm`, the code performs the reverse: decrypts the payload, modifies the entries, re-encrypts the new payload with a fresh nonce, and performs an atomic write to replace the vault file (with a best-effort `.bak` copy of the previous file).

Why this project exists (motivation)
-----------------------------------

There are many mature password managers; this project exists to:

- Teach and document the core primitives of a secure, offline vault in a compact codebase.
- Demonstrate safe Rust patterns for handling secrets, I/O, and error handling with clear ownership.
- Provide a scaffold for further experimentation (rekeying, sync adapters, hardware-backed keys) without starting from scratch.

Dependency & design rationale
-----------------------------

Why these specific crates and choices were made (concise rationale):

- `clap` (derive): industry-standard CLI parsing; expressive, well-tested and ergonomic for subcommands and flags.
- `argon2`: provides Argon2id KDF; Argon2id is a modern, recommended KDF for password-based key derivation and is resistant to GPU/ASIC optimizations when configured correctly.
- `aes-gcm`: provides a safe AEAD implementation (AES-256-GCM) for authenticated encryption — chosen because AEAD avoids silent tampering and provides both confidentiality and integrity.
- `serde` / `serde_json`: easy, interoperable JSON serialization and parsing for the envelope; keeps the on-disk format readable and versionable.
- `zeroize`: provides the `Zeroizing` wrapper to reduce the lifetime of sensitive key material in memory and zero it on drop.
- `rpassword`: small, cross-platform prompt for hidden master-password input.
- `rand`: secure randomness for salts, nonces, and password generation.
- `base64`: compact encoding of binary fields for a JSON envelope.
- `anyhow`: ergonomic error handling with context to produce helpful error messages during development and in logs.


Design trade-offs and notes:

- JSON envelope (human-readable) was chosen for simplicity and inspectability; a binary format could be more compact but harder to debug during development.
- Argon2 params are stored in the envelope to allow reproducible decryption and to enable a future `rekey` migration path.
- AES-GCM requires a unique nonce for each encryption; the code uses a random nonce per write and stores it in the envelope.

Improvements, follow-ups & roadmap
----------------------------------

Short-term/practical improvements (low-risk):

- Add unit and integration tests covering encrypt/decrypt round-trips, `init` -> `add` -> `get` -> `rm` flows, and error cases.
- Add a GitHub Actions workflow to run `cargo fmt -- --check`, `cargo clippy`, and `cargo test` on every PR.
- Systematically wrap decrypted payloads and other transient secret buffers with `Zeroizing` to reduce secret lifetime in memory.

Mid-term/security improvements:

- Implement a `rekey` command that allows migrating KDF parameters and rotating the master password without losing entries.

- Support hardware-backed keys (YubiKey or TPM) as an optional unlock mechanism.

Long-term/advanced features:

- Add an optional authenticated sync adapter (git-backed or server) and conflict resolution for multi-device usage.
- Add a plugin system or extension API so different storage backends or KDFs can be experimented with safely.
- Formal audits and hardened release builds targeting secure deployment scenarios.

Quick start
-----------

Build (release):

```powershell
cargo build --release
```

Run help (development):

```powershell
cargo run -- --help
```



Status (current)
----------------
- Core CLI and command wiring implemented: `init`, `add`, `get`, `rm`, `list`, `gen`.
- Encryption & KDF integrated: Argon2id-derived key and AES-256-GCM encrypt/decrypt implemented.
- Vault envelope format implemented and read/write implemented.
- Atomic write is used (`tmp` + `rename`) and a best-effort `.bak` copy is created when overwriting the vault.

What works now
--------------
- `vault init [--file PATH] [--force]` — initialize vault and set master password. Requires `--force` to overwrite existing vault.
- `vault add -n NAME` — add an entry (prompts for username, URL, notes, password; auto-generate if empty).
- `vault get -n NAME` — retrieve an entry and print password to stdout.
- `vault rm -n NAME` — remove an entry.
- `vault list` — list entry names.
- `vault gen --length N [--symbols]` — generate a password locally.

Default vault path
------------------
- Windows: `%APPDATA%/vault.json.enc`
- Unix: `$HOME/.vault.json.enc`
- Override with `--file PATH` on the CLI.

Storage envelope (required fields)
---------------------------------
The vault file is a JSON envelope. The current code expects all of the following fields to be present. Missing or malformed fields will cause decryption to fail with a descriptive error.

Top-level fields (all required):

- `version` (string): vault format version, for example `"1.0"`. Used for future format migrations.
- `kdf` (object): KDF descriptor object. The code currently understands the following shape:
  - `type` (string): currently must be the literal string `"argon2id"`.
  - `params` (object): Argon2 parameter object (all integers):
    - `mem_kib` (integer): memory cost in KiB (e.g. `65536` for 64 MiB).
    - `iterations` (integer): number of iterations (e.g. `3`).
    - `parallelism` (integer): parallelism degree (e.g. `1`).
  - `salt` (string): base64-encoded salt used by Argon2 (must be present and valid base64).
- `nonce` (string): base64-encoded AES-GCM nonce used to encrypt the ciphertext (must decode to the expected nonce length for AES-GCM).
- `ciphertext` (string): base64-encoded AES-GCM ciphertext. When decrypted with the derived key and nonce this yields the JSON payload described below.

Notes:
- The `kdf` object is read and used to derive the encryption key; its `salt` and `params` must match what was used at `init` time.
- The code does not attempt to be clever about missing fields: if any required field is absent or invalid the operation will fail with an explanatory error. This keeps the runtime checks explicit and auditable.

Entry JSON structure (decrypted)
--------------------------------
When decrypted, the vault contains a JSON array of entries. The code reads and writes entries using serde, so the JSON payload must be a top-level array. Each array element (entry) must have the following fields:

- `name` (string) — unique identifier for the entry (used with `get`, `rm`). It is expected to be unique within the vault; duplicate names may lead to surprising behavior.
- `username` (string|null) — optional username. Use JSON `null` for absent values.
- `url` (string|null) — optional URL for the site/service.
- `notes` (string|null) — optional notes.
- `password` (string) — the password stored for this entry.

Implementation note: entries are serialized/deserialized using serde; types and missing fields should match the struct definitions in `src/models.rs`.

Security & limitations (current)
--------------------------------

The project aims to demonstrate secure vault primitives and a usable CLI. That said, this is an early-stage implementation and has known limitations you should be aware of before trusting it with real secrets.

What is implemented (positive guarantees):

- Argon2id key derivation: Argon2id (via the `argon2` crate) is used to derive a 256-bit key from the master password and a per-vault salt. The used Argon2 parameters are stored in the `kdf.params` object in the envelope so that decryption can re-derive the key.
- AES-256-GCM authenticated encryption: all secrets are encrypted using AES-GCM (via the `aes-gcm` crate) and a random nonce. The `nonce` and the ciphertext are stored in the envelope.
- Atomic writes: writes are performed by writing a temporary file and renaming it into place. This provides atomic replacement on most filesystems.
- Backups: when overwriting an existing vault file the code attempts to create a `.bak` copy of the previous file (best-effort).
- Memory hygiene: derived keys are wrapped in `Zeroizing` to reduce their lifetime in memory; master password strings are dropped promptly after use.

Known limitations and caveats (please read carefully):

- Partial zeroization: while the derived key is zeroized on drop, not every transient plaintext buffer is currently wrapped with `Zeroizing` in every code path. Some decrypted bytes and intermediate Strings may remain in memory until the OS reclaims them. We plan to strengthen zeroization in a follow-up.

- Backup policy is configurable at runtime: you can opt out of creating `.bak` files using the `--no-backup` flag on the CLI. (This flag is implemented.)
- Cross-filesystem atomicity: the current atomic write uses `rename` which is atomic on the same filesystem but may fail or fall back to non-atomic behavior across mounted filesystems. The code attempts parent directory creation but does not handle every cross-filesystem edge case.
- No rekey/migration utility: there is no `rekey` command yet. If you change KDF parameters in code or want to rotate your master password you'll need to implement a migration path or wait for the planned `rekey` command.
- No remote or multi-device sync: this project is strictly local and does not attempt to sync vault files across machines.
- Limited testing: unit and integration tests are not included yet. Before using this in production add tests covering serialization, encrypt/decrypt round-trips, and end-to-end CLI flows.

Security recommendation: Treat this project as an educational prototype. If you plan to use it for real secrets, audit the code, add comprehensive tests, and consider platform-specific secure-erase strategies for memory handling.

Usage examples
--------------

Initialize a vault (won't overwrite unless `--force`):

```powershell
cargo run -- init --file C:\path\to\vault.json.enc
```

Force initialize and overwrite existing vault:

```powershell
cargo run -- init --force
```

Add an entry:

```powershell
cargo run -- add -n mysite
```

Get an entry and print password:

```powershell
cargo run -- get -n mysite
```

List entries:

```powershell
cargo run -- list
```

Remove an entry:

```powershell
cargo run -- rm -n mysite
```

Try it (quick commands)
-----------------------

These commands are quick, copy-paste friendly ways to exercise the main flows locally. They run the dev binary via `cargo run` so you can inspect behaviour and logs. Adjust `--file` to avoid clobbering any existing vault.

```powershell
# Initialize a new vault at a temporary path (prompts for master password)
cargo run -- init --file C:\temp\vault.test.json.enc

# Add an entry interactively (prompts; leave password blank to auto-generate)
cargo run -- add -n testsite --file C:\temp\vault.test.json.enc

# List entries
cargo run -- list --file C:\temp\vault.test.json.enc

# Get an entry and print password
cargo run -- get -n testsite --file C:\temp\vault.test.json.enc

# Remove the test entry
cargo run -- rm -n testsite --file C:\temp\vault.test.json.enc

# Clean up: remove the test vault file
Remove-Item C:\temp\vault.test.json.enc -ErrorAction SilentlyContinue
```

Developer notes & next steps
---------------------------
- Add tests (unit + integration) covering: serialization, encrypt/decrypt round-trip, init->add->get->rm flow.
- Add `rekey` to migrate KDF params and re-encrypt with a new key.
- Harden zeroization: wrap decrypted plaintext buffers in `Zeroizing` and scrub temporary variables.
- Add optional `--no-backup` and make backup behavior configurable.

- Add GitHub Actions for `cargo fmt -- --check`, `cargo clippy`, and `cargo test`.

Contributing
------------
PRs are welcome. If you submit security-sensitive changes (crypto/KDF/IO), please include rationale and tests. Avoid printing secrets in logs or CI.

Contact / License
-----------------
See repository metadata. This project is intended for educational/demonstration use; treat generated vaults carefully and audit before using in production.

Thank you — next I can add tests, tighten zeroization, or implement `rekey` on request.
