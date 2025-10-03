# Security

This project is a small, educational local password vault. The following notes describe a minimal threat model and operational cautions.

## Threat model (high level)

- Adversary with access to your unlocked machine can read process memory, files and clipboard. Do not treat this project as hardened against local attackers.
- Adversary with access to the vault file (at rest) cannot decrypt entries without the master password if Argon2 and AES-GCM are used with sufficient parameters.
- This project does not provide networked sync; remote attacker surface is out-of-scope.

## Operational cautions

- Environment variables (e.g., `VAULT_PASSWORD`) are convenient for CI and automation. However, they may be visible to other processes and logs on some systems. Prefer secure secret storage provided by your CI runner or platform when running in CI.
- Clipboard use is intentionally disabled in this minimal build. Avoid copying secrets to shared clipboards.
- Consider system-level protections to limit other processes' access to memory and files if you plan to use this on a shared machine.

## Suggestions for production hardening

- Add more aggressive zeroization for decrypted payloads and temporary buffers.
- Implement platform-specific secure clipboard clearing if clipboard support is restored.
- Consider hardware-backed key storage (TPM, YubiKey) for unlocking on sensitive deployments.

If you discover a security issue, open an issue and mark it appropriately; we will respond and triage promptly.