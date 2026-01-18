//! Key generation command implementation
//!
//! Generates new validator keys from a BIP-39 mnemonic phrase.

use super::common::{
    display_mnemonic_warning, ensure_keys_dir, get_mnemonic, get_passphrase, keystore_path,
    resolve_keys_dir, validate_passphrase_strength,
};
use anyhow::{anyhow, Context, Result};
use cipherbft_crypto::{derive_validator_keys, KeystoreBuilder, Mnemonic};
use std::path::{Path, PathBuf};

/// Execute the generate command
pub fn execute(
    home: &Path,
    account: u32,
    output_dir: Option<PathBuf>,
    use_existing_mnemonic: bool,
    passphrase_file: Option<PathBuf>,
    dry_run: bool,
) -> Result<()> {
    let keys_dir = resolve_keys_dir(home, output_dir);

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

    // Get passphrase for keystore encryption
    let passphrase = get_passphrase(
        passphrase_file.as_deref(),
        "Enter passphrase for keystore encryption: ",
        passphrase_file.is_none(), // Only confirm if prompting
    )?;

    validate_passphrase_strength(&passphrase)?;

    // Derive validator keys
    println!("Deriving validator keys for account {}...", account);
    let validator_keys = derive_validator_keys(&mnemonic, account, None)
        .map_err(|e| anyhow!("Key derivation failed: {}", e))?;

    let validator_id = validator_keys.validator_id();

    if dry_run {
        println!();
        println!("=== DRY RUN - No files will be written ===");
        println!();
        println!("Would create keystores in: {}", keys_dir.display());
        println!();
        println!("Validator Information:");
        println!("  Account:        {}", account);
        println!("  Validator ID:   0x{}", hex::encode(validator_id.0));
        println!(
            "  Consensus Key:  {}...",
            &hex::encode(validator_keys.consensus_pubkey().to_bytes())[..32]
        );
        println!(
            "  Data Chain Key: {}...",
            &hex::encode(validator_keys.data_chain_pubkey().to_bytes())[..32]
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

    // Create validator subdirectory
    let validator_dir = keys_dir.join(format!("validator_{}", account));
    ensure_keys_dir(&validator_dir)?;

    // Create consensus (Ed25519) keystore
    let consensus_path = keystore_path(&keys_dir, account, "consensus");
    let consensus_secret_bytes = validator_keys.consensus_secret().to_bytes();
    let consensus_pubkey_hex = hex::encode(validator_keys.consensus_pubkey().to_bytes());

    let consensus_keystore = KeystoreBuilder::new()
        .secret(&consensus_secret_bytes)
        .passphrase(&passphrase)
        .pubkey(&consensus_pubkey_hex)
        .description(&format!(
            "CipherBFT Consensus Key (Ed25519) - Validator {} - Account {}",
            hex::encode(&validator_id.0[..8]),
            account
        ))
        .build()
        .context("Failed to encrypt consensus key")?;

    consensus_keystore
        .save(&consensus_path)
        .context("Failed to save consensus keystore")?;

    // Create data chain (BLS) keystore
    let data_chain_path = keystore_path(&keys_dir, account, "data_chain");
    let data_chain_secret_bytes = validator_keys.data_chain_secret().to_bytes();
    let data_chain_pubkey_hex = hex::encode(validator_keys.data_chain_pubkey().to_bytes());

    let data_chain_keystore = KeystoreBuilder::new()
        .secret(&data_chain_secret_bytes)
        .passphrase(&passphrase)
        .pubkey(&data_chain_pubkey_hex)
        .description(&format!(
            "CipherBFT Data Chain Key (BLS12-381) - Validator {} - Account {}",
            hex::encode(&validator_id.0[..8]),
            account
        ))
        .build()
        .context("Failed to encrypt data chain key")?;

    data_chain_keystore
        .save(&data_chain_path)
        .context("Failed to save data chain keystore")?;

    // Write a metadata file for easy reference (public info only)
    let metadata_path = validator_dir.join("validator_info.json");
    let metadata = serde_json::json!({
        "validator_id": format!("0x{}", hex::encode(validator_id.0)),
        "account_index": account,
        "consensus_pubkey": consensus_pubkey_hex,
        "data_chain_pubkey": data_chain_pubkey_hex,
        "derivation": validator_keys.derivation_info().map(|info| {
            serde_json::json!({
                "consensus_path": info.consensus_path,
                "data_chain_path": info.data_chain_path,
            })
        }),
        "keystores": {
            "consensus": consensus_path.file_name().and_then(|s| s.to_str()),
            "data_chain": data_chain_path.file_name().and_then(|s| s.to_str()),
        }
    });

    std::fs::write(&metadata_path, serde_json::to_string_pretty(&metadata)?)?;

    // Print summary
    println!();
    println!("Validator keys generated successfully!");
    println!();
    println!("Files created:");
    println!("  {}", consensus_path.display());
    println!("  {}", data_chain_path.display());
    println!("  {}", metadata_path.display());
    println!();
    println!("Validator Information:");
    println!("  Account:        {}", account);
    println!("  Validator ID:   0x{}", hex::encode(validator_id.0));
    println!("  Consensus Key:  {}...", &consensus_pubkey_hex[..32]);
    println!("  Data Chain Key: {}...", &data_chain_pubkey_hex[..32]);
    println!();
    println!("To use these keys, update your node config with:");
    println!("  keystore_dir = \"{}\"", keys_dir.display());
    println!();

    if !use_existing_mnemonic {
        println!("REMINDER: Make sure you've saved your mnemonic phrase securely!");
    }

    Ok(())
}
