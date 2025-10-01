# Password-Manager-CLI

A memory-safe Rust CLI for secure password generation, AES-256 encryption, and offline storage. Tackles 2025's breach epidemic (1.35B+ US victims) and $4.44M avg costs, fueled by 275% remote work growth since 2019. Ideal for fintech/security resumes.

This repository contains a Rust CLI for a local encrypted password vault. It uses Argon2id for key derivation and AES-GCM for authenticated encryption.

Quick start
-----------

Build:

`powershell
cargo build --release
`

Run help:

`powershell
cargo run -- --help
`

Current status
--------------
- Project scaffolded with CLI subcommands and design SPEC.md.
- Next: implement encryption, KDF, file I/O, and entry management.

Security
--------
Follow SPEC.md for security-sensitive implementation details.
