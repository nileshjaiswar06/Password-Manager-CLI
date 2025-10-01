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
The vault file is a JSON envelope with these required fields (all required by current code):

- `version` (string): vault format version, e.g. `"1.0"`.
- `kdf` (object): KDF descriptor object, contains:
  - `type` (string): currently `"argon2id"`.
  - `params` (object): Argon2 params (current keys used):
    - `mem_kib` (integer): memory cost in KiB (e.g. `65536` for 64 MiB).
    - `iterations` (integer): number of iterations (e.g. `3`).
    - `parallelism` (integer): parallelism degree (e.g. `1`).
  - `salt` (string): base64-encoded salt used by Argon2.
- `nonce` (string): base64-encoded AES-GCM nonce used for the ciphertext.
- `ciphertext` (string): base64-encoded AES-GCM ciphertext (this encrypts the JSON list of entries).

Entry JSON structure (decrypted)
--------------------------------
When decrypted, the vault contains a JSON array of entries. Each entry has these fields:

- `name` (string) — unique identifier for the entry (used with `get`, `rm`).
- `username` (string|null) — optional username.
- `url` (string|null) — optional URL for the site/service.
- `notes` (string|null) — optional notes.
- `password` (string) — the password stored for this entry.

Security & limitations (current)
--------------------------------
- KDF defaults: Argon2id with mem_kib=65536 (64 MiB), iterations=3, parallelism=1. These are currently the defaults used at `init` and stored in the envelope. You can change them in code; a future `rekey` command will let you migrate.
- Zeroization: the derived key is wrapped in `Zeroizing` so it is zeroed on drop. The master password string is dropped as soon as the key is derived. However, decrypted plaintext buffers are not yet fully wrapped in `Zeroizing` in every place — we'll add that in the next iteration.
- Clipboard: clipboard support is optional and enabled via the `clipboard` cargo feature. Copying to clipboard prints a short security warning. Clipboard clearing after `--timeout` is best-effort using a spawned thread — platform-specific secure clearing is planned as an optional enhancement.
- Backups: a best-effort `.bak` copy is made before overwriting the vault file. This behavior is automatic; a configurable `--no-backup` option is not implemented yet.
- Atomic writes: the vault write uses a temporary file and rename for atomicity on the same filesystem, but cross-filesystem rename/edge-cases are not handled.
- No `rekey` command yet: migrating to new KDF params or re-encrypting with a new master password is a planned future feature.
- Tests and CI: the test suite and GitHub Actions are not yet added. Integration tests for encryption/decryption and end-to-end flows will be added next.

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
