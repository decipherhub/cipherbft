//! CLI integration tests for `cipherd genesis generate --extra-alloc` flag.
//!
//! These tests verify that the --extra-alloc flag correctly adds non-validator
//! accounts to the genesis allocation.

#![allow(deprecated)] // Command::cargo_bin is deprecated but still works

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

#[test]
fn test_genesis_generate_with_extra_alloc() {
    let temp_dir = TempDir::new().unwrap();
    let output_path = temp_dir.path().join("genesis.json");

    Command::cargo_bin("cipherd")
        .unwrap()
        .args([
            "genesis",
            "generate",
            "--validators",
            "1",
            "--extra-alloc",
            "0x3E54B36f4F8EFaa017888E66fb6dB17098437ac7:1000",
            "--output",
            output_path.to_str().unwrap(),
            "--no-keys",
        ])
        .assert()
        .success();

    // Read and verify genesis
    let genesis_json = std::fs::read_to_string(&output_path).unwrap();
    let genesis: serde_json::Value = serde_json::from_str(&genesis_json).unwrap();

    // Check the extra account exists (lowercase address without 0x prefix as per geth format)
    let alloc = genesis["alloc"].as_object().unwrap();
    assert!(
        alloc.contains_key("0x3e54b36f4f8efaa017888e66fb6db17098437ac7"),
        "Expected extra alloc address to be in genesis alloc"
    );
}

#[test]
fn test_genesis_generate_with_multiple_extra_alloc() {
    let temp_dir = TempDir::new().unwrap();
    let output_path = temp_dir.path().join("genesis.json");

    Command::cargo_bin("cipherd")
        .unwrap()
        .args([
            "genesis",
            "generate",
            "--validators",
            "1",
            "--extra-alloc",
            "0x3E54B36f4F8EFaa017888E66fb6dB17098437ac7:1000",
            "--extra-alloc",
            "0xAb5801a7D398351b8bE11C439e05C5B3259aeC9B:500",
            "--output",
            output_path.to_str().unwrap(),
            "--no-keys",
        ])
        .assert()
        .success();

    // Read and verify genesis
    let genesis_json = std::fs::read_to_string(&output_path).unwrap();
    let genesis: serde_json::Value = serde_json::from_str(&genesis_json).unwrap();

    let alloc = genesis["alloc"].as_object().unwrap();

    // Check both extra accounts exist
    assert!(
        alloc.contains_key("0x3e54b36f4f8efaa017888e66fb6db17098437ac7"),
        "Expected first extra alloc address to be in genesis alloc"
    );
    assert!(
        alloc.contains_key("0xab5801a7d398351b8be11c439e05c5b3259aec9b"),
        "Expected second extra alloc address to be in genesis alloc"
    );

    // We should have 1 validator + 2 extra allocs = 3 total entries
    assert_eq!(
        alloc.len(),
        3,
        "Expected 3 alloc entries (1 validator + 2 extra)"
    );
}

#[test]
fn test_genesis_generate_extra_alloc_balance_conversion() {
    let temp_dir = TempDir::new().unwrap();
    let output_path = temp_dir.path().join("genesis.json");

    Command::cargo_bin("cipherd")
        .unwrap()
        .args([
            "genesis",
            "generate",
            "--validators",
            "1",
            "--extra-alloc",
            "0x3E54B36f4F8EFaa017888E66fb6dB17098437ac7:100",
            "--output",
            output_path.to_str().unwrap(),
            "--no-keys",
        ])
        .assert()
        .success();

    // Read and verify genesis
    let genesis_json = std::fs::read_to_string(&output_path).unwrap();
    let genesis: serde_json::Value = serde_json::from_str(&genesis_json).unwrap();

    let alloc = genesis["alloc"].as_object().unwrap();
    let entry = alloc
        .get("0x3e54b36f4f8efaa017888e66fb6db17098437ac7")
        .unwrap();

    // 100 ETH = 100 * 10^18 wei = 0x56bc75e2d63100000
    let balance = entry["balance"].as_str().unwrap();
    assert_eq!(
        balance, "0x56bc75e2d63100000",
        "Expected 100 ETH in wei (hex)"
    );
}

#[test]
fn test_genesis_generate_extra_alloc_invalid_format() {
    let temp_dir = TempDir::new().unwrap();
    let output_path = temp_dir.path().join("genesis.json");

    // Missing colon separator
    Command::cargo_bin("cipherd")
        .unwrap()
        .args([
            "genesis",
            "generate",
            "--validators",
            "1",
            "--extra-alloc",
            "0x3E54B36f4F8EFaa017888E66fb6dB17098437ac71000",
            "--output",
            output_path.to_str().unwrap(),
            "--no-keys",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Invalid extra-alloc format"));
}

#[test]
fn test_genesis_generate_extra_alloc_invalid_address() {
    let temp_dir = TempDir::new().unwrap();
    let output_path = temp_dir.path().join("genesis.json");

    // Invalid address (too short)
    Command::cargo_bin("cipherd")
        .unwrap()
        .args([
            "genesis",
            "generate",
            "--validators",
            "1",
            "--extra-alloc",
            "0x123:1000",
            "--output",
            output_path.to_str().unwrap(),
            "--no-keys",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Invalid address"));
}

#[test]
fn test_genesis_generate_extra_alloc_invalid_balance() {
    let temp_dir = TempDir::new().unwrap();
    let output_path = temp_dir.path().join("genesis.json");

    // Invalid balance (not a number)
    Command::cargo_bin("cipherd")
        .unwrap()
        .args([
            "genesis",
            "generate",
            "--validators",
            "1",
            "--extra-alloc",
            "0x3E54B36f4F8EFaa017888E66fb6dB17098437ac7:notanumber",
            "--output",
            output_path.to_str().unwrap(),
            "--no-keys",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Invalid balance"));
}

// =============================================================================
// Devnet/Testnet init-files tests
// =============================================================================

#[test]
fn test_devnet_init_files_with_extra_alloc() {
    let temp_dir = TempDir::new().unwrap();

    Command::cargo_bin("cipherd")
        .unwrap()
        .args([
            "devnet",
            "init-files",
            "--validators",
            "1",
            "--extra-alloc",
            "0x3E54B36f4F8EFaa017888E66fb6dB17098437ac7:1000",
            "--output",
            temp_dir.path().to_str().unwrap(),
        ])
        .assert()
        .success();

    // Read and verify genesis
    let genesis_path = temp_dir.path().join("genesis.json");
    let genesis_json = std::fs::read_to_string(&genesis_path).unwrap();
    let genesis: serde_json::Value = serde_json::from_str(&genesis_json).unwrap();

    // Check the extra account exists
    let alloc = genesis["alloc"].as_object().unwrap();
    assert!(
        alloc.contains_key("0x3e54b36f4f8efaa017888e66fb6db17098437ac7"),
        "Expected extra alloc address to be in genesis alloc"
    );
}

#[test]
fn test_devnet_init_files_with_multiple_extra_alloc() {
    let temp_dir = TempDir::new().unwrap();

    Command::cargo_bin("cipherd")
        .unwrap()
        .args([
            "devnet",
            "init-files",
            "--validators",
            "1",
            "--extra-alloc",
            "0x3E54B36f4F8EFaa017888E66fb6dB17098437ac7:1000",
            "--extra-alloc",
            "0xAb5801a7D398351b8bE11C439e05C5B3259aeC9B:500",
            "--output",
            temp_dir.path().to_str().unwrap(),
        ])
        .assert()
        .success();

    // Read and verify genesis
    let genesis_path = temp_dir.path().join("genesis.json");
    let genesis_json = std::fs::read_to_string(&genesis_path).unwrap();
    let genesis: serde_json::Value = serde_json::from_str(&genesis_json).unwrap();

    let alloc = genesis["alloc"].as_object().unwrap();

    // Check both extra accounts exist
    assert!(
        alloc.contains_key("0x3e54b36f4f8efaa017888e66fb6db17098437ac7"),
        "Expected first extra alloc address to be in genesis alloc"
    );
    assert!(
        alloc.contains_key("0xab5801a7d398351b8be11c439e05c5b3259aec9b"),
        "Expected second extra alloc address to be in genesis alloc"
    );

    // We should have 1 validator + 2 extra allocs = 3 total entries
    assert_eq!(
        alloc.len(),
        3,
        "Expected 3 alloc entries (1 validator + 2 extra)"
    );
}

#[test]
fn test_testnet_init_files_with_extra_alloc() {
    // Test using "testnet" alias instead of "devnet"
    let temp_dir = TempDir::new().unwrap();

    Command::cargo_bin("cipherd")
        .unwrap()
        .args([
            "testnet",
            "init-files",
            "--validators",
            "1",
            "--extra-alloc",
            "0x3E54B36f4F8EFaa017888E66fb6dB17098437ac7:1000",
            "--output",
            temp_dir.path().to_str().unwrap(),
        ])
        .assert()
        .success();

    // Read and verify genesis
    let genesis_path = temp_dir.path().join("genesis.json");
    let genesis_json = std::fs::read_to_string(&genesis_path).unwrap();
    let genesis: serde_json::Value = serde_json::from_str(&genesis_json).unwrap();

    // Check the extra account exists
    let alloc = genesis["alloc"].as_object().unwrap();
    assert!(
        alloc.contains_key("0x3e54b36f4f8efaa017888e66fb6db17098437ac7"),
        "Expected extra alloc address to be in genesis alloc"
    );
}

#[test]
fn test_devnet_init_files_extra_alloc_invalid_format() {
    let temp_dir = TempDir::new().unwrap();

    // Missing colon separator
    Command::cargo_bin("cipherd")
        .unwrap()
        .args([
            "devnet",
            "init-files",
            "--validators",
            "1",
            "--extra-alloc",
            "0x3E54B36f4F8EFaa017888E66fb6dB17098437ac71000",
            "--output",
            temp_dir.path().to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Invalid extra-alloc format"));
}

#[test]
fn test_devnet_init_files_extra_alloc_invalid_address() {
    let temp_dir = TempDir::new().unwrap();

    // Invalid address (too short)
    Command::cargo_bin("cipherd")
        .unwrap()
        .args([
            "devnet",
            "init-files",
            "--validators",
            "1",
            "--extra-alloc",
            "0x123:1000",
            "--output",
            temp_dir.path().to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Invalid address"));
}
