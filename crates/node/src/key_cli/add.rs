//! Key add command implementation (Cosmos SDK style)
//!
//! Creates new keys or recovers existing keys from a mnemonic phrase.
//! By default, only creates an Ed25519 key. Use --validator to also create BLS key.

use super::common::{
    display_mnemonic_warning, ensure_keys_dir, get_mnemonic, get_passphrase, resolve_keys_dir,
    validate_passphrase_strength,
};
use crate::client_config::ClientConfig;
use anyhow::{anyhow, bail, Context, Result};
use cipherbft_crypto::{derive_validator_keys, KeyMetadata, Keyring, KeyringBackend, Mnemonic};
use std::path::{Path, PathBuf};

/// Execute the add command
///
/// # Arguments
/// * `home` - Home directory for cipherd
/// * `keyring_backend` - Backend for key storage
/// * `key_name` - Name for the key (e.g., "my-key", "validator")
/// * `account` - Account index for HD derivation
/// * `output_dir` - Optional custom output directory for keys
/// * `recover` - If true, recover from existing mnemonic instead of generating new
/// * `validator` - If true, create BLS key in addition to Ed25519
/// * `mnemonic_file` - Optional file to read mnemonic from
/// * `passphrase_file` - Optional file to read passphrase from
/// * `force` - If true, overwrite existing keys
/// * `dry_run` - If true, don't actually store keys
#[allow(clippy::too_many_arguments)]
pub fn execute(
    home: &Path,
    keyring_backend: KeyringBackend,
    key_name: &str,
    account: u32,
    output_dir: Option<PathBuf>,
    recover: bool,
    validator: bool,
    mnemonic_file: Option<PathBuf>,
    passphrase_file: Option<PathBuf>,
    force: bool,
    dry_run: bool,
) -> Result<()> {
    let keys_dir = resolve_keys_dir(home, output_dir);

    // Warn if using test backend
    if !keyring_backend.is_production_safe() {
        eprintln!(
            "WARNING: Using '{}' backend which is NOT safe for production!",
            keyring_backend
        );
    }

    // Get or generate mnemonic
    let mnemonic = if recover {
        let phrase = get_mnemonic(mnemonic_file.as_deref())?;
        Mnemonic::from_phrase(&phrase).map_err(|e| anyhow!("Invalid mnemonic: {}", e))?
    } else {
        println!("Generating new 24-word mnemonic phrase...");
        Mnemonic::generate().map_err(|e| anyhow!("Failed to generate mnemonic: {}", e))?
    };

    // Display mnemonic warning (this is the only time it's shown!)
    if !recover {
        display_mnemonic_warning(mnemonic.phrase());
    }

    // Get passphrase for keystore encryption (only if backend requires it)
    let passphrase = if keyring_backend.requires_passphrase() {
        let pass = get_passphrase(
            passphrase_file.as_deref(),
            "Enter passphrase for keystore encryption: ",
            passphrase_file.is_none(), // Only confirm if prompting
        )?;
        validate_passphrase_strength(&pass)?;
        Some(pass)
    } else {
        println!(
            "Note: '{}' backend does not use a passphrase.",
            keyring_backend
        );
        None
    };

    // Derive keys
    println!("Deriving keys for account {}...", account);
    let validator_keys = derive_validator_keys(&mnemonic, account, None)
        .map_err(|e| anyhow!("Key derivation failed: {}", e))?;

    let consensus_pubkey_hex = hex::encode(validator_keys.consensus_pubkey().to_bytes());
    let data_chain_pubkey_hex = hex::encode(validator_keys.data_chain_pubkey().to_bytes());
    let validator_id = validator_keys.validator_id();

    if dry_run {
        println!();
        println!("=== DRY RUN - No keys will be stored ===");
        println!();
        println!("Keyring backend: {}", keyring_backend);
        println!("Keys directory:  {}", keys_dir.display());
        println!("Key name:        {}", key_name);
        println!();
        println!("Key Information:");
        println!("  Account:        {}", account);
        println!(
            "  Ed25519 Pubkey: {}...",
            &consensus_pubkey_hex[..32.min(consensus_pubkey_hex.len())]
        );
        if validator {
            println!("  Validator ID:   0x{}", hex::encode(validator_id.0));
            println!(
                "  BLS Pubkey:     {}...",
                &data_chain_pubkey_hex[..32.min(data_chain_pubkey_hex.len())]
            );
        }
        println!();

        if let Some(info) = validator_keys.derivation_info() {
            println!("Derivation Paths:");
            println!("  Ed25519:    {}", info.consensus_path);
            if validator {
                println!("  BLS:        {}", info.data_chain_path);
            }
        }

        return Ok(());
    }

    // Ensure keys directory exists
    ensure_keys_dir(&keys_dir)?;

    // Create keyring
    let keyring =
        Keyring::new(keyring_backend, &keys_dir).context("Failed to initialize keyring backend")?;

    // Key names
    let ed25519_key_name = format!("{}_{}_ed25519", key_name, account);
    let bls_key_name = format!("{}_{}_bls", key_name, account);

    // Check if keys already exist
    let ed25519_exists = keyring.key_exists(&ed25519_key_name);
    let bls_exists = validator && keyring.key_exists(&bls_key_name);

    if !force && (ed25519_exists || bls_exists) {
        bail!(
            "Key '{}' already exists for account {}. Use --force to overwrite.",
            key_name,
            account
        );
    }

    // Store Ed25519 (consensus) key
    let ed25519_secret_bytes = validator_keys.consensus_secret().to_bytes();
    let ed25519_description = if validator {
        format!(
            "CipherBFT Ed25519 Key - Validator {} - Account {}",
            hex::encode(&validator_id.0[..8]),
            account
        )
    } else {
        format!("CipherBFT Ed25519 Key - {} - Account {}", key_name, account)
    };

    let mut ed25519_metadata =
        KeyMetadata::new(&ed25519_key_name, "ed25519", &consensus_pubkey_hex)
            .with_description(&ed25519_description);

    if let Some(info) = validator_keys.derivation_info() {
        ed25519_metadata = ed25519_metadata.with_path(&info.consensus_path);
    }

    keyring
        .store_key(
            &ed25519_metadata,
            &ed25519_secret_bytes,
            passphrase.as_deref(),
        )
        .context("Failed to store Ed25519 key")?;

    // Store BLS key only if --validator flag is set
    if validator {
        let bls_secret_bytes = validator_keys.data_chain_secret().to_bytes();
        let mut bls_metadata = KeyMetadata::new(&bls_key_name, "bls12-381", &data_chain_pubkey_hex)
            .with_description(&format!(
                "CipherBFT BLS Key (BLS12-381) - Validator {} - Account {}",
                hex::encode(&validator_id.0[..8]),
                account
            ));

        if let Some(info) = validator_keys.derivation_info() {
            bls_metadata = bls_metadata.with_path(&info.data_chain_path);
        }

        keyring
            .store_key(&bls_metadata, &bls_secret_bytes, passphrase.as_deref())
            .context("Failed to store BLS key")?;
    }

    // Write a metadata file for easy reference (public info only) - only for file backend
    if keyring_backend == KeyringBackend::File {
        let key_dir = keys_dir.join(format!("{}_{}", key_name, account));
        ensure_keys_dir(&key_dir)?;

        let metadata = if validator {
            serde_json::json!({
                "key_name": key_name,
                "account_index": account,
                "validator_id": format!("0x{}", hex::encode(validator_id.0)),
                "ed25519_pubkey": consensus_pubkey_hex,
                "bls_pubkey": data_chain_pubkey_hex,
                "keyring_backend": keyring_backend.to_string(),
                "is_validator": true,
                "derivation": validator_keys.derivation_info().map(|info| {
                    serde_json::json!({
                        "ed25519_path": info.consensus_path,
                        "bls_path": info.data_chain_path,
                    })
                }),
            })
        } else {
            serde_json::json!({
                "key_name": key_name,
                "account_index": account,
                "ed25519_pubkey": consensus_pubkey_hex,
                "keyring_backend": keyring_backend.to_string(),
                "is_validator": false,
                "derivation": validator_keys.derivation_info().map(|info| {
                    serde_json::json!({
                        "ed25519_path": info.consensus_path,
                    })
                }),
            })
        };

        let metadata_path = key_dir.join("key_info.json");
        std::fs::write(&metadata_path, serde_json::to_string_pretty(&metadata)?)?;
    }

    // Persist keyring backend to client.toml for consistency with `cipherd start`
    // This ensures that keys created with a specific backend will be found by start command
    let mut client_config = ClientConfig::load(home).unwrap_or_default();
    if client_config.keyring_backend != keyring_backend.to_string() {
        client_config.keyring_backend = keyring_backend.to_string();
        if let Err(e) = client_config.save(home) {
            eprintln!(
                "Warning: Failed to update client.toml with keyring backend: {}",
                e
            );
        } else {
            println!(
                "Updated client.toml with keyring-backend = \"{}\"",
                keyring_backend
            );
        }
    }

    // Print summary
    println!();
    if validator {
        println!("Validator keys created successfully!");
    } else {
        println!("Key created successfully!");
    }
    println!();
    println!("Keyring backend: {}", keyring_backend);
    println!("Keys directory:  {}", keys_dir.display());
    println!();
    println!("Keys stored:");
    println!("  - {}", ed25519_key_name);
    if validator {
        println!("  - {}", bls_key_name);
    }
    println!();
    println!("Key Information:");
    println!("  Name:           {}", key_name);
    println!("  Account:        {}", account);
    println!(
        "  Ed25519 Pubkey: {}...",
        &consensus_pubkey_hex[..32.min(consensus_pubkey_hex.len())]
    );
    if validator {
        println!("  Validator ID:   0x{}", hex::encode(validator_id.0));
        println!(
            "  BLS Pubkey:     {}...",
            &data_chain_pubkey_hex[..32.min(data_chain_pubkey_hex.len())]
        );
    }
    println!();

    if !recover {
        println!("REMINDER: Make sure you've saved your mnemonic phrase securely!");
    }

    Ok(())
}
