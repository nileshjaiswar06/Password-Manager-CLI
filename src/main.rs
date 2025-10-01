mod vault;
mod storage;
mod crypto;
mod models;

use clap::{Parser, Subcommand};
use std::path::PathBuf;

use crate::vault::VaultApp;

#[derive(Parser)]
#[command(name = "vault")]
#[command(about = "Secure Password Manager CLI", long_about = None)]
struct Cli {
    /// Path to the vault file (defaults to OS-specific location)
    #[arg(short, long)]
    file: Option<PathBuf>,
    /// Disable clipboard operations (even if compiled with clipboard feature)
    #[arg(long)]
    no_clipboard: bool,
    /// Disable creating a .bak backup when writing the vault
    #[arg(long)]
    no_backup: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new vault
    Init { #[arg(long)] force: bool },
    /// Add an entry
    Add {
        #[arg(short, long)]
        name: String,
    },
    /// Get an entry
    Get {
        #[arg(short, long)]
        name: String,
        /// Copy password to clipboard
        #[arg(long)]
        copy: bool,
        /// Timeout in seconds to clear clipboard
        #[arg(long)]
        timeout: Option<u64>,
    },
    /// Remove an entry
    Rm { #[arg(short, long)] name: String },
    /// List entries
    List,
    /// Generate a password
    Gen {
        #[arg(short, long, default_value_t = 16)]
        length: usize,
        #[arg(long)]
        symbols: bool,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Resolve vault file path
    let vault_path = match cli.file {
        Some(p) => p,
        None => default_vault_path(),
    };

    let mut app = VaultApp::new(vault_path);
    app.set_no_clipboard(cli.no_clipboard);
    app.set_no_backup(cli.no_backup);

    match cli.command {
    Commands::Init { force } => app.init(force)?,
        Commands::Add { name } => app.add(&name)?,
        Commands::Get { name, copy, timeout } => app.get(&name, copy, timeout)?,
        Commands::Rm { name } => app.rm(&name)?,
        Commands::List => app.list()?,
        Commands::Gen { length, symbols } => {
            let pw = vault::password_generator(length, symbols);
            println!("{}", pw);
        }
    }

    Ok(())
}

fn default_vault_path() -> PathBuf {
    if cfg!(windows) {
        if let Some(appdata) = std::env::var_os("APPDATA") {
            let mut p = PathBuf::from(appdata);
            p.push("vault.json.enc");
            return p;
        }
    }
    // Fallback to home directory
    if let Some(home) = dirs::home_dir() {
        let mut mutp = home;
        mutp.push(".vault.json.enc");
        return mutp;
    }
    PathBuf::from("vault.json.enc")
}
