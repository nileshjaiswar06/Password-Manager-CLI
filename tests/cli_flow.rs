use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::NamedTempFile;

// Integration test for CLI flow using VAULT_PASSWORD env var for non-interactive testing
#[test]
fn init_add_list_remove_flow() -> anyhow::Result<()> {
    // Use a temp file for the vault
    let tmp = NamedTempFile::new()?;
    let path = tmp.path().to_str().unwrap();

    // Ensure the path does not exist so `init` can create it
    std::fs::remove_file(path).ok();

    // init - uses VAULT_PASSWORD env var, no stdin required
    let mut cmd = Command::cargo_bin("vault")?;
    cmd.env("VAULT_PASSWORD", "test-master-password")
        .arg("-f")
        .arg(path)
        .arg("init")
        .assert()
        .success()
        .stdout(predicate::str::contains("Vault initialized"));

    // add - provide entry details via stdin, master password from env
    let mut cmd = Command::cargo_bin("vault")?;
    cmd.env("VAULT_PASSWORD", "test-master-password")
        .env("ENTRY_PASSWORD", "test-entry-password")
        .arg("-f")
        .arg(path)
        .arg("add")
        .arg("-n")
        .arg("testentry")
        .write_stdin("alice\nhttps://example.com\ntest notes\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("Entry added"));

    // list
    let mut cmd = Command::cargo_bin("vault")?;
    cmd.env("VAULT_PASSWORD", "test-master-password")
        .arg("-f")
        .arg(path)
        .arg("list")
        .assert()
        .success()
        .stdout(predicate::str::contains("- testentry"));

    // get
    let mut cmd = Command::cargo_bin("vault")?;
    cmd.env("VAULT_PASSWORD", "test-master-password")
        .arg("-f")
        .arg(path)
        .arg("get")
        .arg("-n")
        .arg("testentry")
        .assert()
        .success()
        .stdout(predicate::str::contains("Password: test-entry-password"));

    // rm
    let mut cmd = Command::cargo_bin("vault")?;
    cmd.env("VAULT_PASSWORD", "test-master-password")
        .arg("-f")
        .arg(path)
        .arg("rm")
        .arg("-n")
        .arg("testentry")
        .assert()
        .success()
        .stdout(predicate::str::contains("Entry removed"));

    Ok(())
}
