//! Key export command implementation
//!
//! Exports public key information (never exports private keys).

use super::common::resolve_keys_dir;
use anyhow::{anyhow, Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

/// Execute the export command
pub fn execute(
    home: &Path,
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

    // Collect validator info from all subdirectories
    let mut validators = Vec::new();

    for entry in fs::read_dir(&keys_dir)? {
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

    if validators.is_empty() {
        return Err(anyhow!(
            "No validator keys found in {}\nRun 'cipherd keys generate' or 'cipherd keys import' first.",
            keys_dir.display()
        ));
    }

    // Sort by account index
    validators.sort_by(|a, b| {
        let a_idx = a["account_index"].as_u64().unwrap_or(0);
        let b_idx = b["account_index"].as_u64().unwrap_or(0);
        a_idx.cmp(&b_idx)
    });

    // Format output
    let output_content = match format {
        "json" => format_json(&validators)?,
        _ => format_text(&validators)?,
    };

    // Write to file or stdout
    if let Some(output_path) = output {
        fs::write(&output_path, &output_content)
            .with_context(|| format!("Failed to write to {}", output_path.display()))?;
        println!("Exported {} validator(s) to {}", validators.len(), output_path.display());
    } else {
        print!("{}", output_content);
    }

    Ok(())
}

fn format_json(validators: &[serde_json::Value]) -> Result<String> {
    // Create export-safe version (ensure no secret data)
    let export_data: Vec<serde_json::Value> = validators
        .iter()
        .map(|v| {
            serde_json::json!({
                "validator_id": v["validator_id"],
                "account_index": v["account_index"],
                "consensus_pubkey": v["consensus_pubkey"],
                "data_chain_pubkey": v["data_chain_pubkey"],
                "derivation": v["derivation"],
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
        let validator_id = v["validator_id"].as_str().unwrap_or("unknown");
        let account = v["account_index"].as_u64().unwrap_or(0);
        let consensus = v["consensus_pubkey"].as_str().unwrap_or("unknown");
        let data_chain = v["data_chain_pubkey"].as_str().unwrap_or("unknown");

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

        output.push('\n');
    }

    Ok(output)
}
