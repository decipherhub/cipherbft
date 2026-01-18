//! Key export command implementation
//!
//! Exports public key information (never exports private keys).

use super::common::resolve_keys_dir;
use anyhow::{anyhow, Context, Result};
use cipherbft_crypto::{Keyring, KeyringBackend};
use std::fs;
use std::path::{Path, PathBuf};

/// Execute the export command
pub fn execute(
    home: &Path,
    keyring_backend: KeyringBackend,
    format: &str,
    keys_dir: Option<PathBuf>,
    output: Option<PathBuf>,
) -> Result<()> {
    let keys_dir = resolve_keys_dir(home, keys_dir);

    if !keys_dir.exists() {
        return Err(anyhow!(
            "Keys directory not found: {}\nRun 'cipherd keys generate' or 'cipherd keys import' first.",
            keys_dir.display()
        ));
    }

    // Warn if using test backend
    if !keyring_backend.is_production_safe() {
        eprintln!(
            "WARNING: Using '{}' backend which is NOT safe for production!",
            keyring_backend
        );
    }

    // Collect validator info - strategy depends on backend
    let validators = match keyring_backend {
        KeyringBackend::File => collect_validators_from_files(&keys_dir)?,
        _ => collect_validators_from_keyring(&keys_dir, keyring_backend)?,
    };

    if validators.is_empty() {
        return Err(anyhow!(
            "No validator keys found in {}\nRun 'cipherd keys generate' or 'cipherd keys import' first.",
            keys_dir.display()
        ));
    }

    // Format output
    let output_content = match format {
        "json" => format_json(&validators)?,
        _ => format_text(&validators)?,
    };

    // Write to file or stdout
    if let Some(output_path) = output {
        fs::write(&output_path, &output_content)
            .with_context(|| format!("Failed to write to {}", output_path.display()))?;
        println!(
            "Exported {} validator(s) to {}",
            validators.len(),
            output_path.display()
        );
    } else {
        print!("{}", output_content);
    }

    Ok(())
}

/// Collect validator info from validator_info.json files (file backend)
fn collect_validators_from_files(keys_dir: &Path) -> Result<Vec<serde_json::Value>> {
    let mut validators = Vec::new();

    for entry in fs::read_dir(keys_dir)? {
        let entry = entry?;
        let path = entry.path();

        if path.is_dir() {
            // Look for validator_info.json
            let info_path = path.join("validator_info.json");
            if info_path.exists() {
                let content = fs::read_to_string(&info_path)
                    .with_context(|| format!("Failed to read {}", info_path.display()))?;
                let info: serde_json::Value = serde_json::from_str(&content)?;
                validators.push(info);
            }
        }
    }

    // Sort by account index
    validators.sort_by(|a, b| {
        let a_idx = a["account_index"].as_u64().unwrap_or(0);
        let b_idx = b["account_index"].as_u64().unwrap_or(0);
        a_idx.cmp(&b_idx)
    });

    Ok(validators)
}

/// Collect validator info from keyring metadata (os/test backends)
fn collect_validators_from_keyring(
    keys_dir: &Path,
    keyring_backend: KeyringBackend,
) -> Result<Vec<serde_json::Value>> {
    let keyring =
        Keyring::new(keyring_backend, keys_dir).context("Failed to initialize keyring backend")?;

    let keys = keyring.list_keys().context("Failed to list keys")?;
    let mut validators_map: std::collections::HashMap<u32, serde_json::Value> =
        std::collections::HashMap::new();

    for key_name in keys {
        // Parse account index from key name (e.g., "validator_0_consensus")
        if let Some(account) = parse_account_from_key_name(&key_name) {
            let metadata = keyring
                .get_metadata(&key_name)
                .context(format!("Failed to get metadata for {}", key_name))?;

            let entry = validators_map.entry(account).or_insert_with(|| {
                serde_json::json!({
                    "account_index": account,
                    "keyring_backend": keyring_backend.to_string(),
                })
            });

            // Add key info based on type
            if key_name.ends_with("_consensus") {
                entry["consensus_pubkey"] = serde_json::Value::String(metadata.pubkey.clone());
                if let Some(path) = &metadata.path {
                    if entry.get("derivation").is_none() {
                        entry["derivation"] = serde_json::json!({});
                    }
                    entry["derivation"]["consensus_path"] = serde_json::Value::String(path.clone());
                }
            } else if key_name.ends_with("_data_chain") {
                entry["data_chain_pubkey"] = serde_json::Value::String(metadata.pubkey.clone());
                if let Some(path) = &metadata.path {
                    if entry.get("derivation").is_none() {
                        entry["derivation"] = serde_json::json!({});
                    }
                    entry["derivation"]["data_chain_path"] =
                        serde_json::Value::String(path.clone());
                }
            }
        }
    }

    // Convert to sorted vector
    let mut validators: Vec<serde_json::Value> = validators_map.into_values().collect();
    validators.sort_by(|a, b| {
        let a_idx = a["account_index"].as_u64().unwrap_or(0);
        let b_idx = b["account_index"].as_u64().unwrap_or(0);
        a_idx.cmp(&b_idx)
    });

    Ok(validators)
}

/// Parse account index from key name (e.g., "validator_0_consensus" -> Some(0))
fn parse_account_from_key_name(name: &str) -> Option<u32> {
    if name.starts_with("validator_") {
        let rest = name.strip_prefix("validator_")?;
        let account_str = rest.split('_').next()?;
        account_str.parse().ok()
    } else {
        None
    }
}

fn format_json(validators: &[serde_json::Value]) -> Result<String> {
    // Create export-safe version (ensure no secret data)
    let export_data: Vec<serde_json::Value> = validators
        .iter()
        .map(|v| {
            serde_json::json!({
                "validator_id": v.get("validator_id"),
                "account_index": v["account_index"],
                "consensus_pubkey": v.get("consensus_pubkey"),
                "data_chain_pubkey": v.get("data_chain_pubkey"),
                "derivation": v.get("derivation"),
                "keyring_backend": v.get("keyring_backend"),
            })
        })
        .collect();

    Ok(serde_json::to_string_pretty(&export_data)?)
}

fn format_text(validators: &[serde_json::Value]) -> Result<String> {
    let mut output = String::new();

    output.push_str("CipherBFT Validator Public Keys\n");
    output.push_str("================================\n\n");

    for v in validators {
        let validator_id = v
            .get("validator_id")
            .and_then(|v| v.as_str())
            .unwrap_or("N/A");
        let account = v["account_index"].as_u64().unwrap_or(0);
        let consensus = v
            .get("consensus_pubkey")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let data_chain = v
            .get("data_chain_pubkey")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        output.push_str(&format!("Account {}\n", account));
        output.push_str(&format!("  Validator ID:   {}\n", validator_id));
        output.push_str(&format!("  Consensus Key:  {}\n", consensus));
        output.push_str(&format!("  Data Chain Key: {}\n", data_chain));

        if let Some(derivation) = v.get("derivation") {
            if let Some(consensus_path) = derivation.get("consensus_path") {
                output.push_str(&format!(
                    "  Derivation:     {} / {}\n",
                    consensus_path.as_str().unwrap_or(""),
                    derivation
                        .get("data_chain_path")
                        .and_then(|p| p.as_str())
                        .unwrap_or("")
                ));
            }
        }

        if let Some(backend) = v.get("keyring_backend").and_then(|v| v.as_str()) {
            output.push_str(&format!("  Backend:        {}\n", backend));
        }

        output.push('\n');
    }

    Ok(output)
}
