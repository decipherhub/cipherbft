//! Key list command implementation
//!
//! Lists all keystores in a directory with their public information.

use super::common::resolve_keys_dir;
use anyhow::{anyhow, Result};
use cipherbft_crypto::EncryptedKeystore;
use std::fs;
use std::path::{Path, PathBuf};

/// Information about a discovered keystore
#[derive(Debug)]
struct KeystoreInfo {
    account: u32,
    validator_id: Option<String>,
    key_type: String,
    path: PathBuf,
    uuid: String,
    description: Option<String>,
}

/// Execute the list command
pub fn execute(home: &Path, keys_dir: Option<PathBuf>, format: &str) -> Result<()> {
    let keys_dir = resolve_keys_dir(home, keys_dir);

    if !keys_dir.exists() {
        return Err(anyhow!(
            "Keys directory not found: {}\nRun 'cipherd keys generate' or 'cipherd keys import' first.",
            keys_dir.display()
        ));
    }

    // Collect keystore info from all subdirectories
    let mut keystores = Vec::new();

    for entry in fs::read_dir(&keys_dir)? {
        let entry = entry?;
        let path = entry.path();

        if path.is_dir() {
            // Parse account from directory name (e.g., "validator_0")
            let dir_name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
            let account = if dir_name.starts_with("validator_") {
                dir_name
                    .strip_prefix("validator_")
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0)
            } else {
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
                            path: keystore_path,
                            uuid: keystore.uuid().to_string(),
                            description: keystore.description().map(String::from),
                        });
                    }
                }
            }
        }
    }

    if keystores.is_empty() {
        println!("No keystores found in {}", keys_dir.display());
        println!();
        println!("Run 'cipherd keys generate' to create new validator keys.");
        return Ok(());
    }

    // Sort by account then key type
    keystores.sort_by(|a, b| {
        a.account
            .cmp(&b.account)
            .then_with(|| a.key_type.cmp(&b.key_type))
    });

    // Format output
    match format {
        "json" => print_json(&keystores)?,
        _ => print_text(&keystores, &keys_dir)?,
    }

    Ok(())
}

fn print_text(keystores: &[KeystoreInfo], keys_dir: &Path) -> Result<()> {
    println!("Keystores in {}", keys_dir.display());
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

        println!("  {} ({})", ks.key_type, ks.uuid);
        if let Some(desc) = &ks.description {
            if !desc.is_empty() {
                println!("    {}", desc);
            }
        }
    }

    println!();
    println!("Total: {} keystore(s)", keystores.len());

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
                "path": ks.path.display().to_string(),
                "uuid": ks.uuid,
                "description": ks.description,
            })
        })
        .collect();

    println!("{}", serde_json::to_string_pretty(&json_data)?);

    Ok(())
}
