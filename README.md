# Password-Manager-CLI

A memory-safe Rust CLI vault that generates, encrypts, and stores passwords locally.

This project demonstrates secure, offline password management using Rust's safety guarantees. It uses Argon2id for key derivation and AES-256-GCM for authenticated encryption.

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

If you want clipboard support, build with the optional feature:

```powershell
cargo run --features clipboard -- get -n NAME --copy --timeout 10
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
- `vault get -n NAME [--copy] [--timeout N]` — retrieve an entry; prints password or copies to clipboard (if built with `clipboard` feature). `--timeout` is intended to clear the clipboard after N seconds (best-effort).
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
- Clipboard behavior is best-effort: clipboard support is optional and only available when you build with the `clipboard` cargo feature. The `--timeout` option spawns a background thread that attempts to clear the clipboard after the requested seconds; this is best-effort and platform-dependent. For security-critical uses do not rely solely on this mechanism.
- Backup policy is configurable at runtime: you can opt out of creating `.bak` files using the `--no-backup` flag on the CLI. (This flag is implemented.)
- Cross-filesystem atomicity: the current atomic write uses `rename` which is atomic on the same filesystem but may fail or fall back to non-atomic behavior across mounted filesystems. The code attempts parent directory creation but does not handle every cross-filesystem edge case.
- No rekey/migration utility: there is no `rekey` command yet. If you change KDF parameters in code or want to rotate your master password you'll need to implement a migration path or wait for the planned `rekey` command.
- No remote or multi-device sync: this project is strictly local and does not attempt to sync vault files across machines.
- Limited testing: unit and integration tests are not included yet. Before using this in production add tests covering serialization, encrypt/decrypt round-trips, and end-to-end CLI flows.

Security recommendation: Treat this project as an educational prototype. If you plan to use it for real secrets, audit the code, add comprehensive tests, and consider platform-specific secure-erase strategies for cleared clipboard contents and memory.

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

Get an entry and copy to clipboard (requires building with clipboard feature):

```powershell
cargo run --features clipboard -- get -n mysite --copy --timeout 10
```

List entries:

```powershell
cargo run -- list
```

Remove an entry:

```powershell
cargo run -- rm -n mysite
```

Developer notes & next steps
---------------------------
- Add tests (unit + integration) covering: serialization, encrypt/decrypt round-trip, init->add->get->rm flow.
- Add `rekey` to migrate KDF params and re-encrypt with a new key.
- Harden zeroization: wrap decrypted plaintext buffers in `Zeroizing` and scrub temporary variables.
- Add optional `--no-backup` and make backup behavior configurable.
- Improve clipboard clearing (OS-specific implementations behind feature flags).
- Add GitHub Actions for `cargo fmt -- --check`, `cargo clippy`, and `cargo test`.

Contributing
------------
PRs are welcome. If you submit security-sensitive changes (crypto/KDF/IO), please include rationale and tests. Avoid printing secrets in logs or CI.

Contact / License
-----------------
See repository metadata. This project is intended for educational/demonstration use; treat generated vaults carefully and audit before using in production.

Thank you — next I can add tests, tighten zeroization, or implement `rekey` on request.
