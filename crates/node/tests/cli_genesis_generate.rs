//! CLI integration tests for `cipherd genesis generate` command (T052-T053).
//!
//! These tests verify that the genesis generate command:
//! - Generates valid genesis files that pass validation
//! - Creates validator key files with correct structure
//! - Supports all CLI options (validators, chain-id, network-id, etc.)
//! - Performs generation in under 5 seconds for 100 validators

#![allow(deprecated)] // Command::cargo_bin is deprecated but still works

use assert_cmd::Command;
use predicates::prelude::*;
use std::time::Instant;
use tempfile::TempDir;

// ============================================================================
// T052: Integration test: generate and immediately validate genesis
// ============================================================================

#[test]
fn test_cli_genesis_generate_creates_valid_genesis() {
    let temp_dir = TempDir::new().expect("create temp dir");
    let genesis_path = temp_dir.path().join("genesis.json");
    let keys_path = temp_dir.path().join("keys");

    // Generate genesis
    let mut cmd = Command::cargo_bin("cipherd").expect("find cipherd binary");
    cmd.arg("genesis")
        .arg("generate")
        .arg("--validators")
        .arg("4")
        .arg("--output")
        .arg(&genesis_path)
        .arg("--keys-dir")
        .arg(&keys_path)
        .assert()
        .success()
        .stdout(predicate::str::contains("Genesis generation complete"));

    // Verify genesis file exists
    assert!(genesis_path.exists(), "genesis.json should be created");

    // Validate the generated genesis
    let mut validate_cmd = Command::cargo_bin("cipherd").expect("find cipherd binary");
    validate_cmd
        .arg("validate")
        .arg("--genesis")
        .arg(&genesis_path)
        .assert()
        .success()
        .stdout(predicate::str::contains("is valid"))
        .stdout(predicate::str::contains("Validators:  4"));
}

#[test]
fn test_cli_genesis_generate_with_custom_chain_id() {
    let temp_dir = TempDir::new().expect("create temp dir");
    let genesis_path = temp_dir.path().join("genesis.json");

    let mut cmd = Command::cargo_bin("cipherd").expect("find cipherd binary");
    cmd.arg("genesis")
        .arg("generate")
        .arg("--validators")
        .arg("2")
        .arg("--chain-id")
        .arg("12345")
        .arg("--output")
        .arg(&genesis_path)
        .arg("--no-keys")
        .assert()
        .success()
        .stdout(predicate::str::contains("Chain ID:    12345"));

    // Validate shows the custom chain ID
    let mut validate_cmd = Command::cargo_bin("cipherd").expect("find cipherd binary");
    validate_cmd
        .arg("validate")
        .arg("--genesis")
        .arg(&genesis_path)
        .assert()
        .success()
        .stdout(predicate::str::contains("Chain ID:    12345"));
}

#[test]
fn test_cli_genesis_generate_with_custom_network_id() {
    let temp_dir = TempDir::new().expect("create temp dir");
    let genesis_path = temp_dir.path().join("genesis.json");

    let mut cmd = Command::cargo_bin("cipherd").expect("find cipherd binary");
    cmd.arg("genesis")
        .arg("generate")
        .arg("--validators")
        .arg("2")
        .arg("--network-id")
        .arg("my-custom-testnet")
        .arg("--output")
        .arg(&genesis_path)
        .arg("--no-keys")
        .assert()
        .success()
        .stdout(predicate::str::contains("Network ID:  my-custom-testnet"));

    // Validate shows the custom network ID
    let mut validate_cmd = Command::cargo_bin("cipherd").expect("find cipherd binary");
    validate_cmd
        .arg("validate")
        .arg("--genesis")
        .arg(&genesis_path)
        .assert()
        .success()
        .stdout(predicate::str::contains("Network ID:  my-custom-testnet"));
}

#[test]
fn test_cli_genesis_generate_creates_key_files() {
    let temp_dir = TempDir::new().expect("create temp dir");
    let genesis_path = temp_dir.path().join("genesis.json");
    let keys_path = temp_dir.path().join("keys");

    let mut cmd = Command::cargo_bin("cipherd").expect("find cipherd binary");
    cmd.arg("genesis")
        .arg("generate")
        .arg("--validators")
        .arg("3")
        .arg("--output")
        .arg(&genesis_path)
        .arg("--keys-dir")
        .arg(&keys_path)
        .assert()
        .success();

    // Verify key files exist
    assert!(keys_path.join("validator-0.json").exists());
    assert!(keys_path.join("validator-1.json").exists());
    assert!(keys_path.join("validator-2.json").exists());

    // Verify key file structure
    let key_content = std::fs::read_to_string(keys_path.join("validator-0.json"))
        .expect("read validator key file");
    let key_json: serde_json::Value =
        serde_json::from_str(&key_content).expect("parse validator key JSON");

    assert_eq!(key_json["index"], 0);
    assert!(key_json["address"].is_string());
    assert!(key_json["ed25519_pubkey"].is_string());
    assert!(key_json["ed25519_secret"].is_string());
    assert!(key_json["bls_pubkey"].is_string());
    assert!(key_json["bls_secret"].is_string());

    // Verify key lengths
    let ed25519_pubkey = key_json["ed25519_pubkey"].as_str().unwrap();
    let bls_pubkey = key_json["bls_pubkey"].as_str().unwrap();
    assert_eq!(
        ed25519_pubkey.len(),
        64,
        "Ed25519 pubkey should be 64 hex chars"
    );
    assert_eq!(bls_pubkey.len(), 96, "BLS pubkey should be 96 hex chars");
}

#[test]
fn test_cli_genesis_generate_no_keys_flag() {
    let temp_dir = TempDir::new().expect("create temp dir");
    let genesis_path = temp_dir.path().join("genesis.json");
    let keys_path = temp_dir.path().join("keys");

    let mut cmd = Command::cargo_bin("cipherd").expect("find cipherd binary");
    cmd.arg("genesis")
        .arg("generate")
        .arg("--validators")
        .arg("2")
        .arg("--output")
        .arg(&genesis_path)
        .arg("--keys-dir")
        .arg(&keys_path)
        .arg("--no-keys")
        .assert()
        .success();

    // Genesis should exist
    assert!(genesis_path.exists());
    // Keys directory should NOT exist
    assert!(!keys_path.exists());
}

#[test]
fn test_cli_genesis_generate_custom_stake() {
    let temp_dir = TempDir::new().expect("create temp dir");
    let genesis_path = temp_dir.path().join("genesis.json");

    let mut cmd = Command::cargo_bin("cipherd").expect("find cipherd binary");
    cmd.arg("genesis")
        .arg("generate")
        .arg("--validators")
        .arg("2")
        .arg("--initial-stake-eth")
        .arg("100")
        .arg("--output")
        .arg(&genesis_path)
        .arg("--no-keys")
        .assert()
        .success()
        .stdout(predicate::str::contains("Total Stake: 200 ETH")); // 2 validators * 100 ETH
}

// ============================================================================
// T053: Performance test: genesis generation < 5 seconds for 100 validators
// ============================================================================

#[test]
fn test_cli_genesis_generate_performance_100_validators() {
    let temp_dir = TempDir::new().expect("create temp dir");
    let genesis_path = temp_dir.path().join("genesis.json");

    let start = Instant::now();

    let mut cmd = Command::cargo_bin("cipherd").expect("find cipherd binary");
    cmd.arg("genesis")
        .arg("generate")
        .arg("--validators")
        .arg("100")
        .arg("--output")
        .arg(&genesis_path)
        .arg("--no-keys") // Skip key file I/O for cleaner timing
        .assert()
        .success()
        .stdout(predicate::str::contains("Validators:  100"));

    let duration = start.elapsed();

    // Performance requirement: < 5 seconds for 100 validators
    assert!(
        duration.as_secs() < 5,
        "Genesis generation for 100 validators took {} seconds, expected < 5 seconds",
        duration.as_secs()
    );

    // Validate the generated genesis is correct
    let mut validate_cmd = Command::cargo_bin("cipherd").expect("find cipherd binary");
    validate_cmd
        .arg("validate")
        .arg("--genesis")
        .arg(&genesis_path)
        .assert()
        .success()
        .stdout(predicate::str::contains("Validators:  100"));
}

#[test]
fn test_cli_genesis_generate_validators_are_unique() {
    let temp_dir = TempDir::new().expect("create temp dir");
    let genesis_path = temp_dir.path().join("genesis.json");

    let mut cmd = Command::cargo_bin("cipherd").expect("find cipherd binary");
    cmd.arg("genesis")
        .arg("generate")
        .arg("--validators")
        .arg("10")
        .arg("--output")
        .arg(&genesis_path)
        .arg("--no-keys")
        .assert()
        .success();

    // Read and parse the genesis file
    let genesis_content = std::fs::read_to_string(&genesis_path).expect("read genesis file");
    let genesis_json: serde_json::Value =
        serde_json::from_str(&genesis_content).expect("parse genesis JSON");

    let validators = genesis_json["cipherbft"]["validators"]
        .as_array()
        .expect("validators array");

    assert_eq!(validators.len(), 10);

    // Collect addresses and verify uniqueness
    let addresses: Vec<&str> = validators
        .iter()
        .map(|v| v["address"].as_str().unwrap())
        .collect();

    let unique_addresses: std::collections::HashSet<_> = addresses.iter().collect();
    assert_eq!(
        addresses.len(),
        unique_addresses.len(),
        "All validator addresses should be unique"
    );

    // Collect ed25519 pubkeys and verify uniqueness
    let pubkeys: Vec<&str> = validators
        .iter()
        .map(|v| v["ed25519_pubkey"].as_str().unwrap())
        .collect();

    let unique_pubkeys: std::collections::HashSet<_> = pubkeys.iter().collect();
    assert_eq!(
        pubkeys.len(),
        unique_pubkeys.len(),
        "All validator Ed25519 pubkeys should be unique"
    );
}
