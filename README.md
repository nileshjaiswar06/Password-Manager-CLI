# Vault - Secure Password Manager CLI

This repository contains a Rust CLI for a local encrypted password vault. It uses Argon2id for key derivation and AES-GCM for authenticated encryption.

Quick start
-----------

Build:

```powershell
cargo build --release
```

Run help:

```powershell
cargo run -- --help
```

Current status
--------------
- Project scaffolded with CLI subcommands and design `SPEC.md`.
- Next: implement encryption, KDF, file I/O, and entry management.

Security
--------
Follow `SPEC.md` for security-sensitive implementation details.
