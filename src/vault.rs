use crate::models::{Entry, VaultFile};
use crate::storage;
use crate::crypto;
use anyhow::Result;
use std::path::PathBuf;
use rpassword::read_password;
use rand::RngCore;
use base64::{engine::general_purpose, Engine as _};
use serde_json::json;

pub struct VaultApp {
    path: PathBuf,
}

impl VaultApp {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    pub fn init(&self) -> Result<()> {
        println!("Initializing vault at {}", self.path.display());
        println!("Master password:");
        let pw = read_password()?;
        // generate salt
        let mut salt = vec![0u8; 16];
        rand::thread_rng().fill_bytes(&mut salt);
        let key = crypto::derive_key(&pw, &salt)?;
        // empty entries
        let entries: Vec<Entry> = Vec::new();
        let pt = serde_json::to_vec(&entries)?;
        let (ct, nonce) = crypto::encrypt(&pt, &key)?;
        let envelope = VaultFile {
            version: "1.0".to_string(),
            kdf: json!({"type": "argon2id", "salt": general_purpose::STANDARD.encode(&salt)}),
            nonce: general_purpose::STANDARD.encode(&nonce),
            ciphertext: general_purpose::STANDARD.encode(&ct),
        };
        storage::write_envelope(&self.path, &envelope)?;
        println!("Vault initialized.");
        Ok(())
    }

    pub fn add(&self, name: &str) -> Result<()> {
        println!("Adding entry '{}'", name);
        println!("Master password:");
        let pw = read_password()?;
        let envelope = storage::read_envelope(&self.path)?;
        let salt_b = base64::engine::general_purpose::STANDARD.decode(envelope.kdf["salt"].as_str().unwrap())?;
        let key = crypto::derive_key(&pw, &salt_b)?;
        let nonce = general_purpose::STANDARD.decode(&envelope.nonce)?;
        let ct = general_purpose::STANDARD.decode(&envelope.ciphertext)?;
        let pt = crypto::decrypt(&ct, &key, &nonce)?;
        let mut entries: Vec<Entry> = serde_json::from_slice(&pt)?;
        // prompt for fields

        println!("username (empty to skip):");
        let mut username = String::new();
        std::io::stdin().read_line(&mut username)?;
        let username = username.trim().to_string();

        println!("url (empty to skip):");
        let mut url = String::new();
        std::io::stdin().read_line(&mut url)?;
        let url = url.trim().to_string();

        println!("notes (empty to skip):");
        let mut notes = String::new();
        std::io::stdin().read_line(&mut notes)?;
        let notes = notes.trim().to_string();

        println!("password (leave empty to auto-generate):");
        let mut password = String::new();
        std::io::stdin().read_line(&mut password)?;
        let password = password.trim().to_string();

    let password = if password.is_empty() { password_generator(16, true) } else { password };
        let entry = Entry {
            name: name.to_string(),
            username: if username.is_empty() { None } else { Some(username) },
            url: if url.is_empty() { None } else { Some(url) },
            notes: if notes.is_empty() { None } else { Some(notes) },
            password,
        };

        entries.push(entry);

        let pt = serde_json::to_vec(&entries)?;
        let (ct, nonce) = crypto::encrypt(&pt, &key)?;
        let envelope = VaultFile {
            version: "1.0".to_string(),
            kdf: json!({"type": "argon2id", "salt": general_purpose::STANDARD.encode(&salt_b)}),
            nonce: general_purpose::STANDARD.encode(&nonce),
            ciphertext: general_purpose::STANDARD.encode(&ct),
        };

        storage::write_envelope(&self.path, &envelope)?;
        println!("Entry added.");
        Ok(())
    }

    pub fn get(&self, name: &str, copy: bool, timeout: Option<u64>) -> Result<()> {
    let pw = read_password()?;
        let envelope = storage::read_envelope(&self.path)?;
        let salt_b = base64::engine::general_purpose::STANDARD.decode(envelope.kdf["salt"].as_str().unwrap())?;
        let key = crypto::derive_key(&pw, &salt_b)?;
        let nonce = general_purpose::STANDARD.decode(&envelope.nonce)?;
        let ct = general_purpose::STANDARD.decode(&envelope.ciphertext)?;
        let pt = crypto::decrypt(&ct, &key, &nonce)?;
        let entries: Vec<Entry> = serde_json::from_slice(&pt)?;

        if let Some(e) = entries.into_iter().find(|e| e.name == name) {
            if copy {
                #[cfg(feature = "clipboard")]
                {
                    use clipboard::ClipboardProvider;
                    use clipboard::ClipboardContext;
                    let mut ctx: ClipboardContext = ClipboardProvider::new().map_err(|e| anyhow::anyhow!(e.to_string()))?;
                    ctx.set_contents(e.password.clone()).map_err(|e| anyhow::anyhow!(e.to_string()))?;
                    println!("Password copied to clipboard");
                    if let Some(sec) = timeout {
                        std::thread::spawn(move || {
                            std::thread::sleep(std::time::Duration::from_secs(sec));
                            // clear clipboard
                            let mut ctx: ClipboardContext = ClipboardProvider::new().unwrap();
                            let _ = ctx.set_contents(String::new());
                        });
                    }
                }
                #[cfg(not(feature = "clipboard"))]
                {
                    println!("Clipboard feature not enabled. Printing to stdout:");
                    println!("{}", e.password);
                }
            } else {
                println!("Password: {}", e.password);
            }
        } else {
            println!("Entry not found");
        }
        Ok(())
    }

    pub fn rm(&self, name: &str) -> Result<()> {
    let pw = read_password()?;
        let envelope = storage::read_envelope(&self.path)?;
        let salt_b = base64::engine::general_purpose::STANDARD.decode(envelope.kdf["salt"].as_str().unwrap())?;
        let key = crypto::derive_key(&pw, &salt_b)?;
        let nonce = general_purpose::STANDARD.decode(&envelope.nonce)?;
        let ct = general_purpose::STANDARD.decode(&envelope.ciphertext)?;
        let pt = crypto::decrypt(&ct, &key, &nonce)?;
        let mut entries: Vec<Entry> = serde_json::from_slice(&pt)?;
        let before = entries.len();
        entries.retain(|e| e.name != name);
        
        if entries.len() == before {
            println!("Entry not found");
            return Ok(());
        }

        let pt = serde_json::to_vec(&entries)?;
        let (ct, nonce) = crypto::encrypt(&pt, &key)?;
        let envelope = VaultFile {
            version: "1.0".to_string(),
            kdf: json!({"type": "argon2id", "salt": general_purpose::STANDARD.encode(&salt_b)}),
            nonce: general_purpose::STANDARD.encode(&nonce),
            ciphertext: general_purpose::STANDARD.encode(&ct),
        };
        storage::write_envelope(&self.path, &envelope)?;
        println!("Entry removed.");
        Ok(())
    }

    pub fn list(&self) -> Result<()> {
    let pw = read_password()?;
        let envelope = storage::read_envelope(&self.path)?;
        let salt_b = base64::engine::general_purpose::STANDARD.decode(envelope.kdf["salt"].as_str().unwrap())?;
        let key = crypto::derive_key(&pw, &salt_b)?;
        let nonce = general_purpose::STANDARD.decode(&envelope.nonce)?;
        let ct = general_purpose::STANDARD.decode(&envelope.ciphertext)?;
        let pt = crypto::decrypt(&ct, &key, &nonce)?;
        let entries: Vec<Entry> = serde_json::from_slice(&pt)?;
        for e in entries {
            println!("- {}", e.name);
        }
        Ok(())
    }
}

pub fn password_generator(length: usize, symbols: bool) -> String {
    use rand::Rng;
    const ALPHANUM: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    const SYMBOLS: &[u8] = b"!@#$%^&*()-_=+[]{};:,.<>?/";

    let mut rng = rand::thread_rng();
    let pool: Vec<u8> = if symbols {
        [ALPHANUM, SYMBOLS].concat()
    } else {
        ALPHANUM.to_vec()
    };

    (0..length)
        .map(|_| {
            let idx = rng.gen_range(0..pool.len());
            pool[idx] as char
        })
        .collect()
 }
