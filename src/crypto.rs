use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use anyhow::Result;
use argon2::{Algorithm, Argon2, Params, Version};
use rand::RngCore;
use zeroize::Zeroizing;

#[derive(Debug, Clone)]
pub struct KdfParams {
    pub mem_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

pub fn generate_salt(len: usize) -> Vec<u8> {
    let mut v = vec![0u8; len];
    rand::thread_rng().fill_bytes(&mut v);
    v
}

// aes-256-gcm is used for encryption and decryption of data
// argon2 is used for key derivation from the master password
pub fn derive_key(password: &str, salt: &[u8], params: &KdfParams) -> Result<Zeroizing<[u8; 32]>> {
    // Build Argon2 instance with provided params
    let params_obj = Params::new(params.mem_kib, params.iterations, params.parallelism, None)
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params_obj);
    let mut out = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut out)
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    Ok(Zeroizing::new(out))
}

pub fn encrypt(plaintext: &[u8], key: &[u8; 32]) -> Result<(Vec<u8>, Vec<u8>)> {
    let cipher = Aes256Gcm::new_from_slice(key)?;
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce);
    let nonce_obj = Nonce::from_slice(&nonce);
    let ct = cipher
        .encrypt(nonce_obj, plaintext)
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    Ok((ct, nonce.to_vec()))
}

pub fn decrypt(ciphertext: &[u8], key: &[u8; 32], nonce: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key)?;
    let nonce_obj = Nonce::from_slice(nonce);
    let pt = cipher
        .decrypt(nonce_obj, ciphertext)
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    Ok(pt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::VaultFile;
    use crate::storage;
    use base64::{engine::general_purpose, Engine as _};
    use serde_json::json;
    use tempfile::NamedTempFile;

    #[test]
    fn crypto_roundtrip() -> anyhow::Result<()> {
        let password = "unit-test";
        let salt = generate_salt(16);
        let params = KdfParams {
            mem_kib: 32,
            iterations: 1,
            parallelism: 1,
        };
        let keyz = derive_key(password, &salt, &params)?;
        let key: &[u8; 32] = &*keyz;

        let plaintext = b"hello world";
        let (ct, nonce) = encrypt(plaintext, key)?;
        let pt = decrypt(&ct, key, &nonce)?;
        assert_eq!(pt, plaintext);
        Ok(())
    }

    #[test]
    fn storage_roundtrip_with_envelope() -> anyhow::Result<()> {
        let entries: Vec<crate::models::Entry> = vec![];
        let pt = serde_json::to_vec(&entries)?;
        let key = [0u8; 32];
        let (ct, nonce) = encrypt(&pt, &key)?;
        let salt = generate_salt(16);
        let envelope = VaultFile {
            version: "1.0".to_string(),
            kdf: json!({"type": "argon2id", "salt": general_purpose::STANDARD.encode(&salt)}),
            nonce: general_purpose::STANDARD.encode(&nonce),
            ciphertext: general_purpose::STANDARD.encode(&ct),
        };

        let tmp = NamedTempFile::new()?;
        storage::write_envelope(tmp.path(), &envelope, true)?;
        let read = storage::read_envelope(tmp.path())?;
        assert_eq!(read.version, "1.0");
        Ok(())
    }
}
