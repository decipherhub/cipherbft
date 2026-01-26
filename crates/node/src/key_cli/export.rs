//! Key export command implementation
//!
//! Exports public key information (never exports private keys).

use super::common::resolve_keys_dir;
use anyhow::{anyhow, Context, Result};
use cipherbft_crypto::{Keyring, KeyringBackend};
use std::fs;
use std::path::{Path, PathBuf};

/// Execute the export command
///
/// # Arguments
///
/// * `home` - Home directory path
/// * `keyring_backend` - The keyring backend to use
/// * `name` - Optional key name to export (exports all if None)
/// * `format` - Output format ("json" or "text")
/// * `keys_dir` - Optional custom keys directory
/// * `output` - Optional output file path (stdout if None)
pub fn execute(
    home: &Path,
    keyring_backend: KeyringBackend,
    name: Option<String>,
    format: &str,
    keys_dir: Option<PathBuf>,
    output: Option<PathBuf>,
) -> Result<()> {
    let keys_dir = resolve_keys_dir(home, keys_dir);

    if !keys_dir.exists() {
        return Err(anyhow!(
            "Keys directory not found: {}\nRun 'cipherd keys add' to create keys first.",
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

    // If a specific key name is provided, export only that key
    if let Some(ref key_name) = name {
        return export_single_key(home, &keys_dir, keyring_backend, key_name, format, output);
    }

    // Otherwise, collect all validator info - strategy depends on backend
    let validators = match keyring_backend {
        KeyringBackend::File => collect_validators_from_files(&keys_dir)?,
        _ => collect_validators_from_keyring(&keys_dir, keyring_backend)?,
    };

    if validators.is_empty() {
        return Err(anyhow!(
            "No keys found in {}\nRun 'cipherd keys add' to create keys first.",
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
            "Exported {} key(s) to {}",
            validators.len(),
            output_path.display()
        );
    } else {
        print!("{}", output_content);
    }

    Ok(())
}

/// Export a single key by name
fn export_single_key(
    _home: &Path,
    keys_dir: &Path,
    keyring_backend: KeyringBackend,
    key_name: &str,
    format: &str,
    output: Option<PathBuf>,
) -> Result<()> {
    // Use keyring to get key metadata
    let keyring = Keyring::new(keyring_backend, keys_dir)
        .context("Failed to initialize keyring backend")?;

    // List all keys and find matching ones
    let all_keys = keyring.list_keys().context("Failed to list keys")?;

    // Find keys that match the given name pattern
    // Key names follow patterns like:
    // - {name}_{account}_{type} (e.g., "validator-0_0_ed25519", "default_0_bls")
    // - validator_{account}_{type} (legacy format)
    let matching_keys: Vec<&String> = all_keys
        .iter()
        .filter(|k| key_matches(k, key_name))
        .collect();

    if matching_keys.is_empty() {
        return Err(anyhow!(
            "Key '{}' not found in {}\n\
             Available keys: {}\n\
             Run 'cipherd keys list' to see all available keys.",
            key_name,
            keys_dir.display(),
            if all_keys.is_empty() {
                "(none)".to_string()
            } else {
                all_keys.join(", ")
            }
        ));
    }

    // Collect key information
    let mut key_info = serde_json::json!({
        "name": key_name,
        "keyring_backend": keyring_backend.to_string(),
        "keys_dir": keys_dir.display().to_string(),
    });

    let mut keys_array = Vec::new();
    for key_full_name in &matching_keys {
        let metadata = keyring
            .get_metadata(key_full_name)
            .with_context(|| format!("Failed to get metadata for '{}'", key_full_name))?;

        keys_array.push(serde_json::json!({
            "full_name": key_full_name,
            "key_type": metadata.key_type,
            "pubkey": metadata.pubkey,
            "description": metadata.description,
            "derivation_path": metadata.path,
        }));
    }
    key_info["keys"] = serde_json::Value::Array(keys_array);

    // Format output
    let output_content = match format {
        "json" => serde_json::to_string_pretty(&key_info)?,
        _ => format_single_key_text(&key_info)?,
    };

    // Write to file or stdout
    if let Some(output_path) = output {
        fs::write(&output_path, &output_content)
            .with_context(|| format!("Failed to write to {}", output_path.display()))?;
        println!("Exported key '{}' to {}", key_name, output_path.display());
    } else {
        print!("{}", output_content);
    }

    Ok(())
}

/// Check if a full key name matches the given search name
///
/// Supports matching:
/// - Exact match: "validator-0_0_ed25519" matches "validator-0_0_ed25519"
/// - Prefix match: "validator-0" matches "validator-0_0_ed25519" and "validator-0_0_bls"
/// - Base name match: "validator-0" matches keys starting with "validator-0_"
fn key_matches(full_name: &str, search_name: &str) -> bool {
    // Exact match
    if full_name == search_name {
        return true;
    }

    // Prefix match with underscore separator
    // e.g., "validator-0" should match "validator-0_0_ed25519"
    if full_name.starts_with(&format!("{}_", search_name)) {
        return true;
    }

    // For legacy format: "validator_0" should match "validator_0_consensus"
    if full_name.starts_with(&format!("{}_", search_name)) {
        return true;
    }

    false
}

/// Format single key info as text
fn format_single_key_text(info: &serde_json::Value) -> Result<String> {
    let mut output = String::new();

    let name = info["name"].as_str().unwrap_or("unknown");
    let backend = info["keyring_backend"].as_str().unwrap_or("unknown");

    output.push_str(&format!("Key: {}\n", name));
    output.push_str(&format!("Backend: {}\n", backend));
    output.push_str("─".repeat(50).as_str());
    output.push('\n');

    if let Some(keys) = info["keys"].as_array() {
        for key in keys {
            let full_name = key["full_name"].as_str().unwrap_or("unknown");
            let key_type = key["key_type"].as_str().unwrap_or("unknown");
            let pubkey = key["pubkey"].as_str().unwrap_or("unknown");
            let description = key["description"].as_str();
            let path = key["derivation_path"].as_str();

            output.push_str(&format!("\n  {} ({})\n", full_name, key_type));
            output.push_str(&format!("    Public Key: {}\n", pubkey));
            if let Some(desc) = description {
                output.push_str(&format!("    Description: {}\n", desc));
            }
            if let Some(p) = path {
                output.push_str(&format!("    Derivation: {}\n", p));
            }
        }
    }

    output.push('\n');
    Ok(output)
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
