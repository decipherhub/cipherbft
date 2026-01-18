//! Key list command implementation
//!
//! Lists all keystores in a directory with their public information.

use super::common::resolve_keys_dir;
use anyhow::{anyhow, Context, Result};
use cipherbft_crypto::{EncryptedKeystore, Keyring, KeyringBackend};
use std::fs;
use std::path::{Path, PathBuf};

/// Information about a discovered keystore
#[derive(Debug)]
struct KeystoreInfo {
    account: u32,
    validator_id: Option<String>,
    key_type: String,
    path: Option<PathBuf>,
    uuid: Option<String>,
    description: Option<String>,
    pubkey: Option<String>,
    backend: KeyringBackend,
}

/// Execute the list command
pub fn execute(
    home: &Path,
    keyring_backend: KeyringBackend,
    keys_dir: Option<PathBuf>,
    format: &str,
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

    // Collect keystores based on backend type
    let keystores = match keyring_backend {
        KeyringBackend::File => list_file_keystores(&keys_dir)?,
        _ => list_keyring_keys(&keys_dir, keyring_backend)?,
    };

    if keystores.is_empty() {
        println!(
            "No keystores found in {} (backend: {})",
            keys_dir.display(),
            keyring_backend
        );
        println!();
        println!("Run 'cipherd keys generate' to create new validator keys.");
        return Ok(());
    }

    // Format output
    match format {
        "json" => print_json(&keystores)?,
        _ => print_text(&keystores, &keys_dir, keyring_backend)?,
    }

    Ok(())
}

/// List keystores from file backend (EIP-2335 JSON files)
///
/// Supports two naming patterns:
/// 1. New pattern: `{name}_{account}_{type}.json` files directly in keys_dir
///    (e.g., `default_0_ed25519.json`, `default_0_bls.json`)
/// 2. Legacy pattern: `validator_{account}/` directories with keystore files inside
fn list_file_keystores(keys_dir: &Path) -> Result<Vec<KeystoreInfo>> {
    let mut keystores = Vec::new();

    for entry in fs::read_dir(keys_dir)? {
        let entry = entry?;
        let path = entry.path();

        if path.is_file() && path.extension().is_some_and(|ext| ext == "json") {
            // New pattern: {name}_{account}_{type}.json files directly in keys_dir
            let file_stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");

            // Parse file name pattern: {name}_{account}_{type}
            // e.g., "default_0_ed25519" -> name="default", account=0, type="ed25519"
            let parts: Vec<&str> = file_stem.rsplitn(3, '_').collect();
            if parts.len() >= 2 {
                let key_type = parts[0].to_string(); // "ed25519" or "bls"
                let account: u32 = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
                let key_name = if parts.len() >= 3 {
                    parts[2]
                } else {
                    "unknown"
                };

                // Try to parse as keystore to get UUID and description
                if let Ok(keystore) = EncryptedKeystore::load(&path) {
                    // Try to get validator_id from key_info.json in the corresponding directory
                    let info_dir = keys_dir.join(format!("{}_{}", key_name, account));
                    let info_path = info_dir.join("key_info.json");
                    let validator_id = if info_path.exists() {
                        fs::read_to_string(&info_path)
                            .ok()
                            .and_then(|content| {
                                serde_json::from_str::<serde_json::Value>(&content).ok()
                            })
                            .and_then(|v| v["validator_id"].as_str().map(String::from))
                    } else {
                        None
                    };

                    keystores.push(KeystoreInfo {
                        account,
                        validator_id,
                        key_type,
                        path: Some(path),
                        uuid: Some(keystore.uuid().to_string()),
                        description: keystore.description().map(String::from),
                        pubkey: Some(keystore.pubkey().to_string()),
                        backend: KeyringBackend::File,
                    });
                }
            }
        } else if path.is_dir() {
            // Legacy pattern: validator_{account}/ directories
            let dir_name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
            let account = if dir_name.starts_with("validator_") {
                dir_name
                    .strip_prefix("validator_")
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0)
            } else {
                // Skip non-validator directories (like default_0/ which contains key_info.json)
                continue;
            };

            // Try to read validator_info.json for the validator ID
            let info_path = path.join("validator_info.json");
            let validator_id = if info_path.exists() {
                fs::read_to_string(&info_path)
                    .ok()
                    .and_then(|content| serde_json::from_str::<serde_json::Value>(&content).ok())
                    .and_then(|v| v["validator_id"].as_str().map(String::from))
            } else {
                None
            };

            // Look for keystore files
            for keystore_entry in fs::read_dir(&path)? {
                let keystore_entry = keystore_entry?;
                let keystore_path = keystore_entry.path();

                if keystore_path.extension().is_some_and(|ext| ext == "json") {
                    let file_name = keystore_path
                        .file_stem()
                        .and_then(|s| s.to_str())
                        .unwrap_or("");

                    // Skip validator_info.json
                    if file_name == "validator_info" {
                        continue;
                    }

                    // Try to parse as keystore to get UUID and description
                    if let Ok(keystore) = EncryptedKeystore::load(&keystore_path) {
                        keystores.push(KeystoreInfo {
                            account,
                            validator_id: validator_id.clone(),
                            key_type: file_name.to_string(),
                            path: Some(keystore_path),
                            uuid: Some(keystore.uuid().to_string()),
                            description: keystore.description().map(String::from),
                            pubkey: Some(keystore.pubkey().to_string()),
                            backend: KeyringBackend::File,
                        });
                    }
                }
            }
        }
    }

    // Sort by account then key type
    keystores.sort_by(|a, b| {
        a.account
            .cmp(&b.account)
            .then_with(|| a.key_type.cmp(&b.key_type))
    });

    Ok(keystores)
}

/// List keys from OS or test keyring backend
fn list_keyring_keys(
    keys_dir: &Path,
    keyring_backend: KeyringBackend,
) -> Result<Vec<KeystoreInfo>> {
    let keyring =
        Keyring::new(keyring_backend, keys_dir).context("Failed to initialize keyring backend")?;

    let keys = keyring.list_keys().context("Failed to list keys")?;
    let mut keystores = Vec::new();

    for key_name in keys {
        // Parse account index from key name (e.g., "validator_0_consensus")
        let account = parse_account_from_key_name(&key_name).unwrap_or(0);
        let key_type = parse_key_type_from_name(&key_name);

        let metadata = keyring
            .get_metadata(&key_name)
            .context(format!("Failed to get metadata for {}", key_name))?;

        keystores.push(KeystoreInfo {
            account,
            validator_id: None, // OS/test backends don't store validator_id separately
            key_type,
            path: None,
            uuid: None,
            description: metadata.description,
            pubkey: Some(metadata.pubkey),
            backend: keyring_backend,
        });
    }

    // Sort by account then key type
    keystores.sort_by(|a, b| {
        a.account
            .cmp(&b.account)
            .then_with(|| a.key_type.cmp(&b.key_type))
    });

    Ok(keystores)
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

/// Parse key type from name (e.g., "validator_0_consensus" -> "consensus")
fn parse_key_type_from_name(name: &str) -> String {
    if let Some(rest) = name.strip_prefix("validator_") {
        // Skip account number and get the rest (e.g., "0_consensus" -> "consensus")
        if let Some(idx) = rest.find('_') {
            return rest[idx + 1..].to_string();
        }
    }
    name.to_string()
}

fn print_text(keystores: &[KeystoreInfo], keys_dir: &Path, backend: KeyringBackend) -> Result<()> {
    println!("Keystores in {} (backend: {})", keys_dir.display(), backend);
    println!();

    let mut current_account: Option<u32> = None;

    for ks in keystores {
        if current_account != Some(ks.account) {
            if current_account.is_some() {
                println!();
            }
            println!(
                "Account {} {}",
                ks.account,
                ks.validator_id
                    .as_ref()
                    .map(|id| format!("({})", id))
                    .unwrap_or_default()
            );
            current_account = Some(ks.account);
        }

        let identifier = ks
            .uuid
            .as_ref()
            .map(|u| format!("uuid: {}", u))
            .or_else(|| {
                ks.pubkey
                    .as_ref()
                    .map(|p| format!("pubkey: {}...", &p[..32.min(p.len())]))
            })
            .unwrap_or_default();

        println!("  {} ({})", ks.key_type, identifier);
        if let Some(desc) = &ks.description {
            if !desc.is_empty() {
                println!("    {}", desc);
            }
        }
    }

    println!();
    println!("Total: {} key(s)", keystores.len());

    Ok(())
}

fn print_json(keystores: &[KeystoreInfo]) -> Result<()> {
    let json_data: Vec<serde_json::Value> = keystores
        .iter()
        .map(|ks| {
            serde_json::json!({
                "account": ks.account,
                "validator_id": ks.validator_id,
                "key_type": ks.key_type,
                "path": ks.path.as_ref().map(|p| p.display().to_string()),
                "uuid": ks.uuid,
                "pubkey": ks.pubkey,
                "description": ks.description,
                "backend": ks.backend.to_string(),
            })
        })
        .collect();

    println!("{}", serde_json::to_string_pretty(&json_data)?);

    Ok(())
}
