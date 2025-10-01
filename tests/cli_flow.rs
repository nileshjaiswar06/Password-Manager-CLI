use assert_cmd::Command;
use tempfile::NamedTempFile;
use predicates::prelude::*;

// Note: This test is ignored because rpassword::read_password() requires a TTY and hangs when stdin is piped in automated tests. To test manually, run:
// cargo build && target/debug/vault.exe -f test.enc init
#[test]
#[ignore]
fn init_add_list_remove_flow() -> anyhow::Result<()> {
    // Use a temp file for the vault
    let tmp = NamedTempFile::new()?;
    let path = tmp.path().to_str().unwrap();

    // Ensure the path does not exist so `init` can create it
    std::fs::remove_file(path).ok();

    // init
    let mut cmd = Command::cargo_bin("vault")?;
    cmd.arg("-f").arg(path).arg("init");
    cmd.write_stdin("password\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("Vault initialized"));

    // add (we'll provide username, url, notes, empty password to auto-gen)
    let mut cmd = Command::cargo_bin("vault")?;
    cmd.arg("-f").arg(path).arg("add").arg("-n").arg("t1");
    cmd.write_stdin("password\nalice\nhttps://example.com\nnotes\n\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("Entry added"));

    // list
    let mut cmd = Command::cargo_bin("vault")?;
    cmd.arg("-f").arg(path).arg("list");
    cmd.write_stdin("password\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("- t1"));

    // rm
    let mut cmd = Command::cargo_bin("vault")?;
    cmd.arg("-f").arg(path).arg("rm").arg("-n").arg("t1");
    cmd.write_stdin("password\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("Entry removed"));

    Ok(())
}
