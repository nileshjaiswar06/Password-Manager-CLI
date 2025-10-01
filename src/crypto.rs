use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use aes_gcm::aead::Aead;
use argon2::{Argon2, Params, Version, Algorithm};
use rand::RngCore;
use anyhow::Result;
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
