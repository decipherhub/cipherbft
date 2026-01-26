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
use clap::{Args, Subcommand, ValueEnum};
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

/// Common arguments shared across key commands
///
/// These arguments can be provided at either the parent `keys` command level
/// or at the individual subcommand level.
#[derive(Args, Debug, Clone)]
pub struct KeysCommonArgs {
    /// Keyring backend for storing keys
    ///
    /// - file: EIP-2335 encrypted keystores (default, recommended)
    /// - os: OS native keyring (macOS Keychain, Windows Credential Manager)
    /// - test: Unencrypted storage (development only!)
    #[arg(long, default_value = "file", value_enum, global = true)]
    pub keyring_backend: KeyringBackendArg,

    /// Directory containing keystore files (overrides default: {home}/keys)
    #[arg(long, global = true)]
    pub keys_dir: Option<PathBuf>,
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

    /// Export key information (public key by default, or private key with --unsafe-export-private-key)
    ///
    /// By default, exports only public key information. Use --unsafe-export-private-key
    /// to export the private key (requires confirmation for file backend).
    ///
    /// Examples:
    ///   cipherd keys export                                          # Export all public keys
    ///   cipherd keys export validator-0                              # Export specific key public info
    ///   cipherd keys export validator-0 --unsafe-export-private-key  # Export private key (DANGEROUS!)
    ///   cipherd keys export validator-0 --format json                # Export in JSON format
    Export {
        /// Name of the key to export (required for private key export)
        ///
        /// The key name should match the name used when the key was created
        /// (e.g., "validator-0_0_ed25519", "default_0_bls"). For private key export,
        /// this must be the exact key name (not a prefix).
        name: Option<String>,

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

        /// Export the private key (DANGEROUS - use with extreme caution!)
        ///
        /// This will export the raw private key in hex format. The private key
        /// gives full control over the associated account. Never share it!
        #[arg(long)]
        unsafe_export_private_key: bool,

        /// Read passphrase from file instead of prompting (for file backend)
        ///
        /// Required when exporting private keys from the file backend,
        /// as the keystore must be decrypted.
        #[arg(long)]
        passphrase_file: Option<PathBuf>,
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

/// Helper function to resolve keyring backend with parent-level fallback
///
/// Subcommand-level args take precedence over parent-level args.
/// If neither is specified, uses the default (File).
fn resolve_keyring_backend(
    parent_backend: Option<KeyringBackendArg>,
    subcommand_backend: KeyringBackendArg,
) -> KeyringBackend {
    // If subcommand explicitly set (not default), use it
    // Otherwise, use parent-level if set, else use subcommand's default
    if let Some(parent) = parent_backend {
        // Parent was explicitly set - use it as override for subcommand default
        // But if subcommand was also explicitly set, subcommand wins
        // Since we can't detect "explicitly set vs default" in clap easily,
        // we'll use parent only if subcommand is at default (File)
        if subcommand_backend == KeyringBackendArg::File {
            parent.into()
        } else {
            subcommand_backend.into()
        }
    } else {
        subcommand_backend.into()
    }
}

/// Helper function to resolve keys_dir with parent-level fallback
fn resolve_keys_dir_option(
    parent_dir: Option<PathBuf>,
    subcommand_dir: Option<PathBuf>,
) -> Option<PathBuf> {
    // Subcommand takes precedence
    subcommand_dir.or(parent_dir)
}

/// Execute a keys command
///
/// # Arguments
///
/// * `home` - Home directory path
/// * `parent_keyring_backend` - Parent-level keyring backend (from `cipherd keys --keyring-backend`)
/// * `parent_keys_dir` - Parent-level keys directory (from `cipherd keys --keys-dir`)
/// * `command` - The subcommand to execute
pub fn execute_keys_command(
    home: &std::path::Path,
    parent_keyring_backend: Option<KeyringBackendArg>,
    parent_keys_dir: Option<PathBuf>,
    command: KeysCommand,
) -> Result<()> {
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
        } => {
            let effective_backend =
                resolve_keyring_backend(parent_keyring_backend, keyring_backend);
            let effective_dir = resolve_keys_dir_option(parent_keys_dir, output_dir);
            add::execute(
                home,
                effective_backend,
                &name,
                account,
                effective_dir,
                recover,
                validator,
                mnemonic_file,
                passphrase_file,
                force,
                dry_run,
            )
        }

        // Deprecated: redirect to add with --validator
        KeysCommand::Generate {
            keyring_backend,
            account,
            output_dir,
            mnemonic,
            passphrase_file,
            dry_run,
        } => {
            eprintln!(
                "WARNING: 'keys generate' is deprecated. Use 'keys add --validator' instead."
            );
            let effective_backend =
                resolve_keyring_backend(parent_keyring_backend, keyring_backend);
            let effective_dir = resolve_keys_dir_option(parent_keys_dir, output_dir);
            add::execute(
                home,
                effective_backend,
                "validator", // default name for backward compatibility
                account,
                effective_dir,
                mnemonic, // recover flag
                true,     // validator flag (generate always created both keys)
                None,     // mnemonic_file
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
            let effective_backend =
                resolve_keyring_backend(parent_keyring_backend, keyring_backend);
            let effective_dir = resolve_keys_dir_option(parent_keys_dir, output_dir);
            add::execute(
                home,
                effective_backend,
                "validator", // default name for backward compatibility
                account,
                effective_dir,
                true, // recover flag
                true, // validator flag (import was for validators)
                mnemonic_file,
                passphrase_file,
                force,
                false, // dry_run
            )
        }

        KeysCommand::Export {
            name,
            keyring_backend,
            format,
            keys_dir,
            output,
            unsafe_export_private_key,
            passphrase_file,
        } => {
            let effective_backend =
                resolve_keyring_backend(parent_keyring_backend, keyring_backend);
            let effective_dir = resolve_keys_dir_option(parent_keys_dir, keys_dir);
            export::execute(
                home,
                effective_backend,
                name,
                &format,
                effective_dir,
                output,
                unsafe_export_private_key,
                passphrase_file,
            )
        }

        KeysCommand::List {
            keyring_backend,
            keys_dir,
            format,
        } => {
            let effective_backend =
                resolve_keyring_backend(parent_keyring_backend, keyring_backend);
            let effective_dir = resolve_keys_dir_option(parent_keys_dir, keys_dir);
            list::execute(home, effective_backend, effective_dir, &format)
        }
    }
}
