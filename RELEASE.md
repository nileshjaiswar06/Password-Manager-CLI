# Release v0.1.0

This initial release marks a compact, educational Rust password manager implementation. Highlights:

- Core cryptography: Argon2id for key derivation and AES-256-GCM for authenticated encryption.
- Versioned JSON vault envelope with KDF params, nonce and ciphertext.
- CLI with `init`, `add`, `get`, `rm`, `list`, and `gen` commands.
- Tests (unit + integration) and CI workflow to validate behavior on push/PR.

Learning goals for this release:

- Demonstrate secure-by-design primitives in Rust (KDF, AEAD, zeroization patterns).
- Show how to design a small library that is usable both as a CLI and as a dependency for other programs.
- Provide a scaffold for further improvements: rekeying, hardware-backed keys, secure clipboard handling, and sync adapters.

Notes:
- This project is educational; audit and harden before storing real secrets.
