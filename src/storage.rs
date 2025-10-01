use crate::models::VaultFile;
use anyhow::{Context, Result};
use std::fs;
use std::path::Path;
use std::io::Write;
use std::fs::OpenOptions;
use std::ffi::OsStr;

pub fn write_envelope(path: &Path, envelope: &VaultFile, no_backup: bool) -> Result<()> {
        let s = serde_json::to_string_pretty(envelope).context("serializing vault envelope to JSON")?;
    // ensure parent dir exists
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("creating parent directory {}", parent.display()))?;
    }
    // create backup if exists (best-effort) unless no_backup
    if !no_backup && path.exists() {
        let mut bak = path.to_path_buf();
        bak.set_extension(format!("{}.bak", path.extension().and_then(OsStr::to_str).unwrap_or("")));
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
    f.write_all(s.as_bytes()).with_context(|| format!("writing to temp file {}", tmp.display()))?;
    f.flush().context("flushing temp file")?;
    drop(f);
    fs::rename(&tmp, path).with_context(|| format!("renaming {} to {}", tmp.display(), path.display()))?;
    Ok(())
}

pub fn read_envelope(path: &Path) -> Result<VaultFile> {
    let s = fs::read_to_string(path).with_context(|| format!("reading vault file {}", path.display()))?;
    let v: VaultFile = serde_json::from_str(&s).context("parsing vault file JSON")?;
    Ok(v)
}
