# Contributing to Password-Manager-CLI

Thank you for considering contributing to this project! This is an educational Rust password manager demonstrating secure vault primitives.

## Development Setup

1. **Prerequisites**: Rust 1.70+ with Cargo
2. **Clone and build**:
   ```bash
   git clone https://github.com/nileshjaiswar06/Password-Manager-CLI.git
   cd Password-Manager-CLI
   cargo build
   ```

3. **Run tests**:
   ```bash
   export VAULT_PASSWORD='test-password'  # Unix
   # or
   $env:VAULT_PASSWORD = 'test-password'  # PowerShell
   
   cargo test --verbose
   ```

## Before Submitting

Run the full development checklist:
```bash
cargo fmt
cargo clippy -- -D warnings
cargo test --verbose
cargo build --release
```

## Pull Request Guidelines

- **Security changes**: Include rationale and tests for crypto/KDF/I/O modifications
- **Small PRs**: Focus on one feature/fix per PR for easier review
- **No secrets**: Avoid printing secrets in logs, tests, or CI output
- **Documentation**: Update README.md if you change CLI behavior or add dependencies

## Security Considerations

This project handles cryptographic secrets. Please:
- Review memory handling patterns (zeroization, buffer lifetimes)
- Test edge cases around file I/O and atomic writes
- Consider cross-platform implications for security features
- Follow secure coding practices for error messages (avoid leaking secrets)

## Testing

- Unit tests: `crypto` and `storage` modules have tests covering round-trips
- Integration tests: `tests/` directory contains CLI flow tests
- CI runs on Linux and Windows to catch platform-specific issues

## Questions?

Open an issue for questions about architecture, security design, or contribution ideas.

## License

By contributing, you agree that your contributions will be licensed under the same terms as the project (MIT License).