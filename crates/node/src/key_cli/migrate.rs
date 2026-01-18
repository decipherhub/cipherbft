//! Key migration command implementation
//!
//! Migrates plaintext keys from old config format to EIP-2335 encrypted keystores.

use super::common::{
    ensure_keys_dir, get_passphrase, keystore_path, resolve_keys_dir, validate_passphrase_strength,
};
use anyhow::{anyhow, Context, Result};
use cipherbft_crypto::{BlsSecretKey, Ed25519SecretKey, KeystoreBuilder};
use std::fs;
use std::path::{Path, PathBuf};

/// Plaintext key data extracted from old config
struct PlaintextKeys {
    bls_secret_key_hex: String,
    ed25519_secret_key_hex: String,
    validator_id: Option<String>,
}

/// Execute the migrate command
pub fn execute(
    home: &Path,
    output_dir: Option<PathBuf>,
    passphrase_file: Option<PathBuf>,
    dry_run: bool,
    output_config: Option<PathBuf>,
) -> Result<()> {
    let keys_dir = resolve_keys_dir(home, output_dir.clone());
    let config_path = home.join("config/node.json");

    // Load and parse old config
    if !config_path.exists() {
        return Err(anyhow!(
            "Configuration file not found: {}\nNothing to migrate.",
            config_path.display()
        ));
    }

    println!("Scanning configuration for plaintext keys...");

    let config_content = fs::read_to_string(&config_path)
        .context("Failed to read configuration file")?;

    let config: serde_json::Value = serde_json::from_str(&config_content)
        .context("Failed to parse configuration file")?;

    // Check for plaintext keys
    let plaintext_keys = detect_plaintext_keys(&config)?;

    if plaintext_keys.is_none() {
        println!("No plaintext keys found in configuration.");
        println!();
        println!("Your configuration appears to already use secure key storage.");
        return Ok(());
    }

    let keys = plaintext_keys.unwrap();

    println!("Found plaintext keys in configuration!");
    println!();
    println!("  BLS Secret Key:     {}...", &keys.bls_secret_key_hex[..16]);
    println!("  Ed25519 Secret Key: {}...", &keys.ed25519_secret_key_hex[..16]);
    if let Some(vid) = &keys.validator_id {
        println!("  Validator ID:       {}", vid);
    }

    if dry_run {
        println!();
        println!("=== DRY RUN - No files will be written ===");
        println!();
        println!("Would create keystores in: {}", keys_dir.display());
        println!("Would create:");
        println!("  {}/validator_0/consensus.json", keys_dir.display());
        println!("  {}/validator_0/data_chain.json", keys_dir.display());
        println!();

        if output_config.is_some() {
            println!("Would write updated config with 'keystore_dir' field.");
        }

        println!();
        println!("After migration, manually:");
        println!("  1. Verify the migrated keys work correctly");
        println!("  2. Remove 'bls_secret_key_hex' and 'ed25519_secret_key_hex' from your config");
        println!("  3. Add 'keystore_dir' pointing to {}", keys_dir.display());
        println!("  4. Securely delete any backups containing plaintext keys");

        return Ok(());
    }

    // Get passphrase for keystore encryption
    let passphrase = get_passphrase(
        passphrase_file.as_deref(),
        "Enter passphrase for keystore encryption: ",
        passphrase_file.is_none(),
    )?;

    validate_passphrase_strength(&passphrase)?;

    // Parse the secret keys
    let bls_bytes: [u8; 32] = hex::decode(&keys.bls_secret_key_hex)
        .context("Invalid BLS secret key hex")?
        .try_into()
        .map_err(|_| anyhow!("BLS secret key must be 32 bytes"))?;
    let ed25519_bytes: [u8; 32] = hex::decode(&keys.ed25519_secret_key_hex)
        .context("Invalid Ed25519 secret key hex")?
        .try_into()
        .map_err(|_| anyhow!("Ed25519 secret key must be 32 bytes"))?;

    // Validate by creating key objects
    let bls_secret = BlsSecretKey::from_bytes(&bls_bytes)
        .map_err(|e| anyhow!("Invalid BLS secret key: {}", e))?;
    let ed25519_secret = Ed25519SecretKey::from_bytes(&ed25519_bytes);

    // Get public keys for metadata
    let bls_pubkey = bls_secret.public_key();
    let ed25519_pubkey = ed25519_secret.public_key();
    let validator_id = ed25519_pubkey.validator_id();

    // Ensure keys directory exists
    ensure_keys_dir(&keys_dir)?;

    // Create validator subdirectory (use account 0 for migrated keys)
    let account = 0u32;
    let validator_dir = keys_dir.join(format!("validator_{}", account));
    ensure_keys_dir(&validator_dir)?;

    // Create consensus (Ed25519) keystore
    let consensus_path = keystore_path(&keys_dir, account, "consensus");
    let consensus_pubkey_hex = hex::encode(ed25519_pubkey.to_bytes());
    let consensus_keystore = KeystoreBuilder::new()
        .secret(&ed25519_bytes)
        .passphrase(&passphrase)
        .pubkey(&consensus_pubkey_hex)
        .description(&format!(
            "CipherBFT Consensus Key (Ed25519) - Validator {} (Migrated)",
            hex::encode(&validator_id.0[..8])
        ))
        .build()
        .context("Failed to encrypt consensus key")?;

    consensus_keystore
        .save(&consensus_path)
        .context("Failed to save consensus keystore")?;

    // Create data chain (BLS) keystore
    let data_chain_path = keystore_path(&keys_dir, account, "data_chain");
    let data_chain_pubkey_hex = hex::encode(bls_pubkey.to_bytes());
    let data_chain_keystore = KeystoreBuilder::new()
        .secret(&bls_bytes)
        .passphrase(&passphrase)
        .pubkey(&data_chain_pubkey_hex)
        .description(&format!(
            "CipherBFT Data Chain Key (BLS12-381) - Validator {} (Migrated)",
            hex::encode(&validator_id.0[..8])
        ))
        .build()
        .context("Failed to encrypt data chain key")?;

    data_chain_keystore
        .save(&data_chain_path)
        .context("Failed to save data chain keystore")?;

    // Write metadata file
    let metadata_path = validator_dir.join("validator_info.json");
    let metadata = serde_json::json!({
        "validator_id": format!("0x{}", hex::encode(validator_id.0)),
        "account_index": account,
        "consensus_pubkey": hex::encode(ed25519_pubkey.to_bytes()),
        "data_chain_pubkey": hex::encode(bls_pubkey.to_bytes()),
        "keystores": {
            "consensus": "consensus.json",
            "data_chain": "data_chain.json",
        },
        "migrated_from": "plaintext_config"
    });

    fs::write(&metadata_path, serde_json::to_string_pretty(&metadata)?)?;

    // Optionally write updated config
    if let Some(output_config_path) = output_config {
        let mut new_config = config.clone();

        // Remove plaintext keys
        if let Some(obj) = new_config.as_object_mut() {
            obj.remove("bls_secret_key_hex");
            obj.remove("ed25519_secret_key_hex");
            obj.insert(
                "keystore_dir".to_string(),
                serde_json::Value::String(keys_dir.display().to_string()),
            );
        }

        fs::write(
            &output_config_path,
            serde_json::to_string_pretty(&new_config)?,
        )?;

        println!("Updated config written to: {}", output_config_path.display());
    }

    // Print summary
    println!();
    println!("Migration completed successfully!");
    println!();
    println!("Files created:");
    println!("  {}", consensus_path.display());
    println!("  {}", data_chain_path.display());
    println!("  {}", metadata_path.display());
    println!();
    println!("Validator Information:");
    println!("  Validator ID:   0x{}", hex::encode(validator_id.0));
    println!(
        "  Consensus Key:  {}...",
        &hex::encode(ed25519_pubkey.to_bytes())[..32]
    );
    println!(
        "  Data Chain Key: {}...",
        &hex::encode(bls_pubkey.to_bytes())[..32]
    );
    println!();
    println!("IMPORTANT: Complete the migration by:");
    println!("  1. Verify the migrated keys work: cipherd keys list --keys-dir {}", keys_dir.display());
    println!("  2. Update your config to use:");
    println!("     keystore_dir = \"{}\"", keys_dir.display());
    println!("  3. Remove 'bls_secret_key_hex' and 'ed25519_secret_key_hex' from your config");
    println!("  4. Securely delete any backups containing plaintext keys");

    Ok(())
}

/// Detect plaintext keys in configuration
fn detect_plaintext_keys(config: &serde_json::Value) -> Result<Option<PlaintextKeys>> {
    let bls_key = config.get("bls_secret_key_hex").and_then(|v| v.as_str());
    let ed25519_key = config.get("ed25519_secret_key_hex").and_then(|v| v.as_str());
    let validator_id = config.get("validator_id").and_then(|v| v.as_str());

    match (bls_key, ed25519_key) {
        (Some(bls), Some(ed25519)) => Ok(Some(PlaintextKeys {
            bls_secret_key_hex: bls.to_string(),
            ed25519_secret_key_hex: ed25519.to_string(),
            validator_id: validator_id.map(String::from),
        })),
        (Some(_), None) => Err(anyhow!(
            "Configuration has 'bls_secret_key_hex' but missing 'ed25519_secret_key_hex'"
        )),
        (None, Some(_)) => Err(anyhow!(
            "Configuration has 'ed25519_secret_key_hex' but missing 'bls_secret_key_hex'"
        )),
        (None, None) => Ok(None),
    }
}
