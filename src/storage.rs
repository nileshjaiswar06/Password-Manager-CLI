use crate::models::VaultFile;
use anyhow::Result;
use std::fs;
use std::path::Path;

pub fn write_envelope(path: &Path, envelope: &VaultFile) -> Result<()> {
    let s = serde_json::to_string_pretty(envelope)?;
    fs::write(path, s)?;
    Ok(())
}

pub fn read_envelope(path: &Path) -> Result<VaultFile> {
    let s = fs::read_to_string(path)?;
    let v: VaultFile = serde_json::from_str(&s)?;
    Ok(v)
}
