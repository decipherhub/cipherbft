//! Unified Key Management CLI for CipherBFT
//!
//! This module provides secure key management commands following Cosmos SDK patterns:
//!
//! - `add`: Create new keys from a mnemonic phrase (or recover with --recover)
//! - `export`: Export public key information (never exports private keys)
//! - `list`: List all keystores in a directory
//!
//! # Security Features
//!
//! - Keys are stored using pluggable keyring backends
//! - Passphrases are read securely from terminal (not echoed)
//! - Mnemonic phrases support optional BIP-39 passphrases
//! - Memory is zeroed when keys go out of scope
//!
//! # Keyring Backends
//!
//! - `file` (default): EIP-2335 encrypted keystores - most secure for production
//! - `os`: Operating system's native keyring (macOS Keychain, Windows Credential Manager, Linux Secret Service)
//! - `test`: Unencrypted storage - **ONLY for development/testing**
//!
//! # Key Types
//!
//! By default, only an Ed25519 key is created (sufficient for most users).
//! Validators should use the `--validator` flag to also create a BLS key
//! required for threshold signatures in the Data Chain Layer.

pub mod add;
pub mod common;
pub mod export;
pub mod list;

// Keep generate and import for backward compatibility (they redirect to add)
pub mod generate;
pub mod import;

use anyhow::Result;
use cipherbft_crypto::KeyringBackend;
use clap::{Subcommand, ValueEnum};
use std::path::PathBuf;

/// Keyring backend selection for CLI
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, ValueEnum)]
pub enum KeyringBackendArg {
    /// File-based encrypted keystore (EIP-2335 format) - most secure
    #[default]
    File,
    /// Operating system's native keyring (macOS Keychain, Windows Credential Manager, etc.)
    Os,
    /// Unencrypted storage for testing - NOT safe for production!
    Test,
}

impl From<KeyringBackendArg> for KeyringBackend {
    fn from(arg: KeyringBackendArg) -> Self {
        match arg {
            KeyringBackendArg::File => KeyringBackend::File,
            KeyringBackendArg::Os => KeyringBackend::Os,
            KeyringBackendArg::Test => KeyringBackend::Test,
        }
    }
}

/// Key management subcommands (Cosmos SDK style)
#[derive(Subcommand)]
pub enum KeysCommand {
    /// Add a new key or recover existing key from mnemonic
    ///
    /// Creates a new key with a fresh mnemonic, or recovers an existing key
    /// using --recover. By default, only creates an Ed25519 key. Validators
    /// should use --validator to also create a BLS key for threshold signatures.
    ///
    /// Examples:
    ///   cipherd keys add mykey                     # New key, Ed25519 only
    ///   cipherd keys add mykey --validator         # New validator key (Ed25519 + BLS)
    ///   cipherd keys add mykey --recover           # Recover from mnemonic
    ///   cipherd keys add mykey --recover --validator  # Recover validator key
    Add {
        /// Name for the key (e.g., "my-key", "validator", "default")
        name: String,

        /// Keyring backend for storing keys
        ///
        /// - file: EIP-2335 encrypted keystores (default, recommended)
        /// - os: OS native keyring (macOS Keychain, Windows Credential Manager)
        /// - test: Unencrypted storage (development only!)
        #[arg(long, default_value = "file", value_enum)]
        keyring_backend: KeyringBackendArg,

        /// Account index for HD key derivation (default: 0)
        #[arg(long, default_value = "0")]
        account: u32,

        /// Output directory for keystore files
        #[arg(long)]
        output_dir: Option<PathBuf>,

        /// Recover key from existing mnemonic phrase
        ///
        /// Instead of generating a new mnemonic, prompts for an existing one.
        /// Use this to recover keys or set up a new node from an existing mnemonic.
        #[arg(long)]
        recover: bool,

        /// Create BLS key in addition to Ed25519 (required for validators)
        ///
        /// Validators need both Ed25519 (for consensus signing and p2p identity)
        /// and BLS12-381 (for DCL threshold signatures). Regular users/nodes
        /// only need Ed25519.
        #[arg(long)]
        validator: bool,

        /// Read mnemonic from file instead of prompting (for --recover)
        #[arg(long)]
        mnemonic_file: Option<PathBuf>,

        /// Read passphrase from file instead of prompting
        #[arg(long)]
        passphrase_file: Option<PathBuf>,

        /// Overwrite existing keys
        #[arg(long)]
        force: bool,

        /// Dry run: show what would be created without writing files
        #[arg(long)]
        dry_run: bool,
    },

    /// [Deprecated] Generate new validator keys - use 'add --validator' instead
    #[command(hide = true)]
    Generate {
        #[arg(long, default_value = "file", value_enum)]
        keyring_backend: KeyringBackendArg,
        #[arg(long, default_value = "0")]
        account: u32,
        #[arg(long)]
        output_dir: Option<PathBuf>,
        #[arg(long)]
        mnemonic: bool,
        #[arg(long)]
        passphrase_file: Option<PathBuf>,
        #[arg(long)]
        dry_run: bool,
    },

    /// [Deprecated] Import keys from mnemonic - use 'add --recover' instead
    #[command(hide = true)]
    Import {
        #[arg(long, default_value = "file", value_enum)]
        keyring_backend: KeyringBackendArg,
        #[arg(long, default_value = "0")]
        account: u32,
        #[arg(long)]
        output_dir: Option<PathBuf>,
        #[arg(long)]
        mnemonic_file: Option<PathBuf>,
        #[arg(long)]
        passphrase_file: Option<PathBuf>,
        #[arg(long)]
        force: bool,
    },

    /// Export public key information
    ///
    /// Outputs key public keys and IDs. Never exports private keys.
    /// Useful for sharing validator info with others or for configuration.
    Export {
        /// Keyring backend to read keys from
        #[arg(long, default_value = "file", value_enum)]
        keyring_backend: KeyringBackendArg,

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
    /// Shows key names and public keys for all keystores found.
    /// Does not require passphrases (only reads public information).
    List {
        /// Keyring backend to list keys from
        #[arg(long, default_value = "file", value_enum)]
        keyring_backend: KeyringBackendArg,

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
        KeysCommand::Add {
            name,
            keyring_backend,
            account,
            output_dir,
            recover,
            validator,
            mnemonic_file,
            passphrase_file,
            force,
            dry_run,
        } => add::execute(
            home,
            keyring_backend.into(),
            &name,
            account,
            output_dir,
            recover,
            validator,
            mnemonic_file,
            passphrase_file,
            force,
            dry_run,
        ),

        // Deprecated: redirect to add with --validator
        KeysCommand::Generate {
            keyring_backend,
            account,
            output_dir,
            mnemonic,
            passphrase_file,
            dry_run,
        } => {
            eprintln!("WARNING: 'keys generate' is deprecated. Use 'keys add --validator' instead.");
            add::execute(
                home,
                keyring_backend.into(),
                "validator", // default name for backward compatibility
                account,
                output_dir,
                mnemonic,   // recover flag
                true,       // validator flag (generate always created both keys)
                None,       // mnemonic_file
                passphrase_file,
                false, // force
                dry_run,
            )
        }

        // Deprecated: redirect to add with --recover --validator
        KeysCommand::Import {
            keyring_backend,
            account,
            output_dir,
            mnemonic_file,
            passphrase_file,
            force,
        } => {
            eprintln!(
                "WARNING: 'keys import' is deprecated. Use 'keys add --recover --validator' instead."
            );
            add::execute(
                home,
                keyring_backend.into(),
                "validator", // default name for backward compatibility
                account,
                output_dir,
                true, // recover flag
                true, // validator flag (import was for validators)
                mnemonic_file,
                passphrase_file,
                force,
                false, // dry_run
            )
        }

        KeysCommand::Export {
            keyring_backend,
            format,
            keys_dir,
            output,
        } => export::execute(home, keyring_backend.into(), &format, keys_dir, output),

        KeysCommand::List {
            keyring_backend,
            keys_dir,
            format,
        } => list::execute(home, keyring_backend.into(), keys_dir, &format),
    }
}
