use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
// Serialize - turn a Rust struct into JSON (or bytes).
// Deserialize - turn JSON (or bytes) into a Rust struct.
// Debug - turn a Rust struct into a string.
// Clone - copy a Rust struct.
pub struct Entry {
    pub name: String,
    pub username: Option<String>,
    pub url: Option<String>,
    pub notes: Option<String>,
    pub password: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct VaultFile {
    pub version: String,
    pub kdf: serde_json::Value,
    pub nonce: String,
    pub ciphertext: String,
}
