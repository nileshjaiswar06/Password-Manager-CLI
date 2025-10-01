use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use aes_gcm::aead::Aead;
use argon2::Argon2;
use rand::RngCore;
use anyhow::Result;

pub fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; 32]> {
    // Derive a 32-byte key using Argon2id with default params for now
    let argon2 = Argon2::default();
    let mut out = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut out)
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    Ok(out)
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
