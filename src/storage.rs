use crate::models::VaultFile;
use anyhow::{Context, Result};
use std::ffi::OsStr;
use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

pub fn write_envelope(path: &Path, envelope: &VaultFile, no_backup: bool) -> Result<()> {
    let s = serde_json::to_string_pretty(envelope).context("serializing vault envelope to JSON")?;
    // ensure parent dir exists
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("creating parent directory {}", parent.display()))?;
    }
    // create backup if exists (best-effort) unless no_backup
    if !no_backup && path.exists() {
        let mut bak = path.to_path_buf();
        bak.set_extension(format!(
            "{}.bak",
            path.extension().and_then(OsStr::to_str).unwrap_or("")
        ));
        let _ = fs::copy(path, &bak);
    }

    // atomic write: write to temp file then rename
    let tmp = path.with_extension("tmp");
    let mut f = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&tmp)
        .with_context(|| format!("opening temporary file {}", tmp.display()))?;
    f.write_all(s.as_bytes())
        .with_context(|| format!("writing to temp file {}", tmp.display()))?;
    f.flush().context("flushing temp file")?;
    drop(f);
    fs::rename(&tmp, path)
        .with_context(|| format!("renaming {} to {}", tmp.display(), path.display()))?;
    Ok(())
}

pub fn read_envelope(path: &Path) -> Result<VaultFile> {
    let s = fs::read_to_string(path)
        .with_context(|| format!("reading vault file {}", path.display()))?;
    let v: VaultFile = serde_json::from_str(&s).context("parsing vault file JSON")?;
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::VaultFile;
    use base64::{engine::general_purpose, Engine as _};
    use serde_json::json;
    use tempfile::NamedTempFile;

    #[test]
    fn write_and_read_envelope() -> anyhow::Result<()> {
        let salt = b"testsalt12345678";
        let envelope = VaultFile {
            version: "1.0".to_string(),
            kdf: json!({"type": "argon2id", "salt": general_purpose::STANDARD.encode(salt)}),
            nonce: general_purpose::STANDARD.encode(b"somenonce123"),
            ciphertext: general_purpose::STANDARD.encode(b"cipher"),
        };
        let tmp = NamedTempFile::new()?;
        write_envelope(tmp.path(), &envelope, true)?;
        let read = read_envelope(tmp.path())?;
        assert_eq!(read.version, "1.0");
        Ok(())
    }
}
