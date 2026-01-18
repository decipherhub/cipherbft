//! Key generation command implementation
//!
//! Generates new validator keys from a BIP-39 mnemonic phrase.

use super::common::{
    display_mnemonic_warning, ensure_keys_dir, get_mnemonic, get_passphrase, resolve_keys_dir,
    validate_passphrase_strength,
};
use anyhow::{anyhow, bail, Context, Result};
use cipherbft_crypto::{derive_validator_keys, KeyMetadata, Keyring, KeyringBackend, Mnemonic};
use std::path::{Path, PathBuf};

/// Execute the generate command
pub fn execute(
    home: &Path,
    keyring_backend: KeyringBackend,
    account: u32,
    output_dir: Option<PathBuf>,
    use_existing_mnemonic: bool,
    passphrase_file: Option<PathBuf>,
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
    let mnemonic = if use_existing_mnemonic {
        let phrase = get_mnemonic(None)?;
        Mnemonic::from_phrase(&phrase).map_err(|e| anyhow!("Invalid mnemonic: {}", e))?
    } else {
        println!("Generating new 24-word mnemonic phrase...");
        Mnemonic::generate().map_err(|e| anyhow!("Failed to generate mnemonic: {}", e))?
    };

    // Display mnemonic warning (this is the only time it's shown!)
    if !use_existing_mnemonic {
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

    // Derive validator keys
    println!("Deriving validator keys for account {}...", account);
    let validator_keys = derive_validator_keys(&mnemonic, account, None)
        .map_err(|e| anyhow!("Key derivation failed: {}", e))?;

    let validator_id = validator_keys.validator_id();
    let consensus_pubkey_hex = hex::encode(validator_keys.consensus_pubkey().to_bytes());
    let data_chain_pubkey_hex = hex::encode(validator_keys.data_chain_pubkey().to_bytes());

    if dry_run {
        println!();
        println!("=== DRY RUN - No keys will be stored ===");
        println!();
        println!("Keyring backend: {}", keyring_backend);
        println!("Keys directory:  {}", keys_dir.display());
        println!();
        println!("Validator Information:");
        println!("  Account:        {}", account);
        println!("  Validator ID:   0x{}", hex::encode(validator_id.0));
        println!(
            "  Consensus Key:  {}...",
            &consensus_pubkey_hex[..32.min(consensus_pubkey_hex.len())]
        );
        println!(
            "  Data Chain Key: {}...",
            &data_chain_pubkey_hex[..32.min(data_chain_pubkey_hex.len())]
        );
        println!();

        if let Some(info) = validator_keys.derivation_info() {
            println!("Derivation Paths:");
            println!("  Consensus:   {}", info.consensus_path);
            println!("  Data Chain:  {}", info.data_chain_path);
        }

        return Ok(());
    }

    // Ensure keys directory exists
    ensure_keys_dir(&keys_dir)?;

    // Create keyring
    let keyring =
        Keyring::new(keyring_backend, &keys_dir).context("Failed to initialize keyring backend")?;

    // Key names
    let consensus_key_name = format!("validator_{}_consensus", account);
    let data_chain_key_name = format!("validator_{}_data_chain", account);

    // Check if keys already exist
    if keyring.key_exists(&consensus_key_name) || keyring.key_exists(&data_chain_key_name) {
        bail!(
            "Keys for account {} already exist. Use --force with import to overwrite, or choose a different account.",
            account
        );
    }

    // Store consensus (Ed25519) key
    let consensus_secret_bytes = validator_keys.consensus_secret().to_bytes();
    let consensus_metadata =
        KeyMetadata::new(&consensus_key_name, "ed25519", &consensus_pubkey_hex).with_description(
            &format!(
                "CipherBFT Consensus Key (Ed25519) - Validator {} - Account {}",
                hex::encode(&validator_id.0[..8]),
                account
            ),
        );

    if let Some(info) = validator_keys.derivation_info() {
        let consensus_metadata = consensus_metadata.with_path(&info.consensus_path);
        keyring
            .store_key(
                &consensus_metadata,
                &consensus_secret_bytes,
                passphrase.as_deref(),
            )
            .context("Failed to store consensus key")?;
    } else {
        keyring
            .store_key(
                &consensus_metadata,
                &consensus_secret_bytes,
                passphrase.as_deref(),
            )
            .context("Failed to store consensus key")?;
    }

    // Store data chain (BLS) key
    let data_chain_secret_bytes = validator_keys.data_chain_secret().to_bytes();
    let data_chain_metadata =
        KeyMetadata::new(&data_chain_key_name, "bls12-381", &data_chain_pubkey_hex)
            .with_description(&format!(
                "CipherBFT Data Chain Key (BLS12-381) - Validator {} - Account {}",
                hex::encode(&validator_id.0[..8]),
                account
            ));

    if let Some(info) = validator_keys.derivation_info() {
        let data_chain_metadata = data_chain_metadata.with_path(&info.data_chain_path);
        keyring
            .store_key(
                &data_chain_metadata,
                &data_chain_secret_bytes,
                passphrase.as_deref(),
            )
            .context("Failed to store data chain key")?;
    } else {
        keyring
            .store_key(
                &data_chain_metadata,
                &data_chain_secret_bytes,
                passphrase.as_deref(),
            )
            .context("Failed to store data chain key")?;
    }

    // Write a metadata file for easy reference (public info only) - only for file backend
    if keyring_backend == KeyringBackend::File {
        let validator_dir = keys_dir.join(format!("validator_{}", account));
        ensure_keys_dir(&validator_dir)?;

        let metadata_path = validator_dir.join("validator_info.json");
        let metadata = serde_json::json!({
            "validator_id": format!("0x{}", hex::encode(validator_id.0)),
            "account_index": account,
            "consensus_pubkey": consensus_pubkey_hex,
            "data_chain_pubkey": data_chain_pubkey_hex,
            "keyring_backend": keyring_backend.to_string(),
            "derivation": validator_keys.derivation_info().map(|info| {
                serde_json::json!({
                    "consensus_path": info.consensus_path,
                    "data_chain_path": info.data_chain_path,
                })
            }),
        });

        std::fs::write(&metadata_path, serde_json::to_string_pretty(&metadata)?)?;
    }

    // Print summary
    println!();
    println!("Validator keys generated successfully!");
    println!();
    println!("Keyring backend: {}", keyring_backend);
    println!("Keys directory:  {}", keys_dir.display());
    println!();
    println!("Keys stored:");
    println!("  - {}", consensus_key_name);
    println!("  - {}", data_chain_key_name);
    println!();
    println!("Validator Information:");
    println!("  Account:        {}", account);
    println!("  Validator ID:   0x{}", hex::encode(validator_id.0));
    println!(
        "  Consensus Key:  {}...",
        &consensus_pubkey_hex[..32.min(consensus_pubkey_hex.len())]
    );
    println!(
        "  Data Chain Key: {}...",
        &data_chain_pubkey_hex[..32.min(data_chain_pubkey_hex.len())]
    );
    println!();

    if !use_existing_mnemonic {
        println!("REMINDER: Make sure you've saved your mnemonic phrase securely!");
    }

    Ok(())
}
