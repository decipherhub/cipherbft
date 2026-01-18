//! Unified Key Management CLI for CipherBFT
//!
//! This module provides secure key management commands for validator keys:
//!
//! - `generate`: Create new validator keys from a mnemonic phrase
//! - `import`: Import validator keys from an existing mnemonic
//! - `export`: Export public key information (never exports private keys)
//! - `list`: List all keystores in a directory
//!
//! # Security Features
//!
//! - Keys are stored in EIP-2335 encrypted keystores
//! - Passphrases are read securely from terminal (not echoed)
//! - Mnemonic phrases support optional BIP-39 passphrases
//! - Memory is zeroed when keys go out of scope

pub mod common;
pub mod export;
pub mod generate;
pub mod import;
pub mod list;

use anyhow::Result;
use clap::Subcommand;
use std::path::PathBuf;

/// Key management subcommands
#[derive(Subcommand)]
pub enum KeysCommand {
    /// Generate new validator keys from a fresh mnemonic phrase
    ///
    /// Creates a new 24-word BIP-39 mnemonic and derives validator keys
    /// (Ed25519 for consensus, BLS12-381 for data chain). Keys are stored
    /// in EIP-2335 encrypted keystores protected by a passphrase.
    ///
    /// IMPORTANT: The mnemonic phrase is shown ONCE. Write it down and
    /// store it securely - it's the only way to recover your keys.
    Generate {
        /// Account index for key derivation (default: 0)
        #[arg(long, default_value = "0")]
        account: u32,

        /// Output directory for keystore files
        #[arg(long)]
        output_dir: Option<PathBuf>,

        /// Use an existing mnemonic instead of generating a new one
        ///
        /// The mnemonic will be read interactively from the terminal.
        #[arg(long)]
        mnemonic: bool,

        /// Read passphrase from file instead of prompting
        #[arg(long)]
        passphrase_file: Option<PathBuf>,

        /// Dry run: show what would be created without writing files
        #[arg(long)]
        dry_run: bool,
    },

    /// Import validator keys from an existing mnemonic phrase
    ///
    /// Reads a mnemonic phrase and derives validator keys at the specified
    /// account index. Use this to recover keys or set up a new node from
    /// an existing mnemonic.
    Import {
        /// Account index for key derivation (default: 0)
        #[arg(long, default_value = "0")]
        account: u32,

        /// Output directory for keystore files
        #[arg(long)]
        output_dir: Option<PathBuf>,

        /// Read mnemonic from file instead of prompting
        #[arg(long)]
        mnemonic_file: Option<PathBuf>,

        /// Read passphrase from file instead of prompting
        #[arg(long)]
        passphrase_file: Option<PathBuf>,

        /// Overwrite existing keystores
        #[arg(long)]
        force: bool,
    },

    /// Export public key information
    ///
    /// Outputs validator public keys and IDs. Never exports private keys.
    /// Useful for sharing validator info with others or for configuration.
    Export {
        /// Output format (json, text)
        #[arg(long, default_value = "text")]
        format: String,

        /// Directory containing keystore files
        #[arg(long)]
        keys_dir: Option<PathBuf>,

        /// Output file (stdout if not specified)
        #[arg(long)]
        output: Option<PathBuf>,
    },

    /// List all keystores in a directory
    ///
    /// Shows validator IDs and public keys for all keystores found.
    /// Does not require passphrases (only reads public information).
    List {
        /// Directory containing keystore files
        #[arg(long)]
        keys_dir: Option<PathBuf>,

        /// Output format (text, json)
        #[arg(long, default_value = "text")]
        format: String,
    },
}

/// Execute a keys command
pub fn execute_keys_command(home: &std::path::Path, command: KeysCommand) -> Result<()> {
    match command {
        KeysCommand::Generate {
            account,
            output_dir,
            mnemonic,
            passphrase_file,
            dry_run,
        } => generate::execute(
            home,
            account,
            output_dir,
            mnemonic,
            passphrase_file,
            dry_run,
        ),

        KeysCommand::Import {
            account,
            output_dir,
            mnemonic_file,
            passphrase_file,
            force,
        } => import::execute(
            home,
            account,
            output_dir,
            mnemonic_file,
            passphrase_file,
            force,
        ),

        KeysCommand::Export {
            format,
            keys_dir,
            output,
        } => export::execute(home, &format, keys_dir, output),

        KeysCommand::List { keys_dir, format } => list::execute(home, keys_dir, &format),
    }
}
