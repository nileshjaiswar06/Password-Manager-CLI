Secure Password Manager CLI - Spec

Overview
--------
Command-line vault that stores entries (name, username, password, url, notes) encrypted with AES-GCM. Key derived from master password with Argon2id.

Commands
--------
- `vault init [--file PATH]` - initialize a vault and set master password
- `vault add -n NAME` - add entry; prompts for username, password (or generate), url, notes
- `vault get -n NAME [--copy] [--timeout N]` - retrieve entry; prints password or copies to clipboard
- `vault rm -n NAME` - remove entry
- `vault list` - list entry names
- `vault gen --length 16 [--symbols]` - generate a password

Storage envelope (JSON)
-----------------------
{
  "version": "1.0",
  "kdf": { "type": "argon2id", "salt": "base64..", "params": { "m": ..., "t": ..., "p": ... } },
  "nonce": "base64...",
  "ciphertext": "base64..."
}

On-disk vault content is the AES-GCM ciphertext of a JSON structure of entries. The KDF params must be stored to allow re-deriving the key.

Security notes
--------------
- Use Argon2id with reasonable memory/iterations (configurable when initializing).
- Use AES-GCM for AEAD.
- Zeroize sensitive buffers after use.
- Do not log secrets; log only metadata like operation and timestamp.

Crates (confirmed)
------------------
clap, serde, serde_json, rpassword, rand, argon2, aes-gcm, base64, zeroize, clipboard (optional)

Testing & CI
------------
- Unit tests for serialization and password generation.
- Integration tests for encryption/decryption round-trips.
- GitHub Actions: cargo test, cargo clippy, cargo fmt.
