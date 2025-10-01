use crate::models::VaultFile;
use anyhow::Result;
use std::fs;
use std::path::Path;
use std::io::Write;
use std::fs::OpenOptions;
use std::ffi::OsStr;

pub fn write_envelope(path: &Path, envelope: &VaultFile) -> Result<()> {
    let s = serde_json::to_string_pretty(envelope)?;
    // create backup if exists
    if path.exists() {
        let mut bak = path.to_path_buf();
        bak.set_extension(format!("{}.bak", path.extension().and_then(OsStr::to_str).unwrap_or("")));
        // best effort copy
        let _ = fs::copy(path, bak);
    }
    // atomic write: write to temp file then rename
    let tmp = path.with_extension("tmp");
    let mut f = OpenOptions::new().create(true).write(true).truncate(true).open(&tmp)?;
    f.write_all(s.as_bytes())?;
    f.flush()?;
    drop(f);
    fs::rename(&tmp, path)?;
    Ok(())
}

pub fn read_envelope(path: &Path) -> Result<VaultFile> {
    let s = fs::read_to_string(path)?;
    let v: VaultFile = serde_json::from_str(&s)?;
    Ok(v)
}
