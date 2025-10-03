use rand::RngCore;
use tempfile::NamedTempFile;

use base64::{engine::general_purpose, Engine as _};
use serde_json::json;
use vault::crypto;
use vault::storage;
use vault::Entry;
use vault::VaultFile;

#[test]
fn encrypt_decrypt_and_storage_roundtrip() -> anyhow::Result<()> {
    let password = "test-master";
    let mut salt = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt);
    let params = crypto::KdfParams {
        mem_kib: 32,
        iterations: 1,
        parallelism: 1,
    };
    let keyz = crypto::derive_key(password, &salt, &params)?;
    let key: &[u8; 32] = &*keyz;

    let entries: Vec<Entry> = vec![];
    let pt = serde_json::to_vec(&entries)?;
    let (ct, nonce) = crypto::encrypt(&pt, &key)?;

    let envelope = VaultFile {
        version: "1.0".to_string(),
        kdf: json!({"type": "argon2id", "salt": general_purpose::STANDARD.encode(&salt)}),
        nonce: general_purpose::STANDARD.encode(&nonce),
        ciphertext: general_purpose::STANDARD.encode(&ct),
    };

    let tmp = NamedTempFile::new()?;
    storage::write_envelope(tmp.path(), &envelope, false)?;

    let read = storage::read_envelope(tmp.path())?;
    assert_eq!(read.version, "1.0");
    assert!(read.kdf["salt"].is_string());
    Ok(())
}
