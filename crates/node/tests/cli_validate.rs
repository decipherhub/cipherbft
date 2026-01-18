//! CLI integration tests for `cipherd validate` command (T041-T042).
//!
//! These tests verify that the validate command:
//! - Outputs success message with chain ID, validator count, total stake for valid genesis
//! - Returns proper exit code (0 on success, 1 on failure)
//! - Outputs specific error messages for invalid genesis files

#![allow(deprecated)] // Command::cargo_bin is deprecated but still works

use assert_cmd::Command;
use predicates::prelude::*;
use std::io::Write;
use tempfile::NamedTempFile;

/// Create a valid minimal genesis JSON for CLI testing.
/// Note: All U256 values use hex format per the `u256_quantity` serde module.
fn valid_genesis_json() -> &'static str {
    r#"{
        "config": {
            "chainId": 85300,
            "cancunTime": 0
        },
        "alloc": {
            "0x742d35Cc6634C0532925a3b844Bc9e7595f0bC01": {
                "balance": "0x6c6b935b8bbd400000"
            }
        },
        "gasLimit": "0x1c9c380",
        "difficulty": "0x1",
        "cipherbft": {
            "genesis_time": "2024-01-15T00:00:00Z",
            "network_id": "cipherbft-testnet-1",
            "consensus": {
                "target_block_time_ms": 2000
            },
            "dcl": {
                "car_interval_ms": 100,
                "attestation_threshold_percent": 67
            },
            "staking": {
                "min_stake_wei": "0xde0b6b3a7640000"
            },
            "validators": [
                {
                    "address": "0x742d35Cc6634C0532925a3b844Bc9e7595f0bC01",
                    "ed25519_pubkey": "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
                    "bls_pubkey": "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
                    "staked_amount": "0x1bc16d674ec80000"
                }
            ]
        }
    }"#
}

/// Create an invalid genesis JSON with missing validators field.
fn invalid_genesis_missing_validators() -> &'static str {
    r#"{
        "config": {
            "chainId": 85300,
            "cancunTime": 0
        },
        "alloc": {
            "0x742d35Cc6634C0532925a3b844Bc9e7595f0bC01": {
                "balance": "0x6c6b935b8bbd400000"
            }
        },
        "gasLimit": "0x1c9c380",
        "difficulty": "0x1",
        "cipherbft": {
            "genesis_time": "2024-01-15T00:00:00Z",
            "network_id": "cipherbft-testnet-1",
            "validators": []
        }
    }"#
}

/// Create an invalid genesis JSON with zero gas limit.
fn invalid_genesis_zero_gas_limit() -> &'static str {
    r#"{
        "config": { "chainId": 85300 },
        "alloc": {},
        "gasLimit": "0x0",
        "difficulty": "0x1",
        "cipherbft": {
            "genesis_time": "2024-01-15T00:00:00Z",
            "network_id": "test",
            "validators": []
        }
    }"#
}

// ============================================================================
// T041: CLI test: validate valid genesis
// ============================================================================

#[test]
fn test_cli_validate_valid_genesis() {
    // Create temporary genesis file
    let mut temp = NamedTempFile::new().expect("create temp file");
    temp.write_all(valid_genesis_json().as_bytes())
        .expect("write genesis");

    let mut cmd = Command::cargo_bin("cipherd").expect("find cipherd binary");

    cmd.arg("validate")
        .arg("--genesis")
        .arg(temp.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("is valid"))
        .stdout(predicate::str::contains("Chain ID:"))
        .stdout(predicate::str::contains("85300"))
        .stdout(predicate::str::contains("Validators:"))
        .stdout(predicate::str::contains("Total Stake:"));
}

#[test]
fn test_cli_validate_shows_network_id() {
    let mut temp = NamedTempFile::new().expect("create temp file");
    temp.write_all(valid_genesis_json().as_bytes())
        .expect("write genesis");

    let mut cmd = Command::cargo_bin("cipherd").expect("find cipherd binary");

    cmd.arg("validate")
        .arg("--genesis")
        .arg(temp.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("Network ID:"))
        .stdout(predicate::str::contains("cipherbft-testnet-1"));
}

// ============================================================================
// T042: CLI test: validate invalid genesis (missing field)
// ============================================================================

#[test]
fn test_cli_validate_invalid_genesis_missing_validators() {
    let mut temp = NamedTempFile::new().expect("create temp file");
    temp.write_all(invalid_genesis_missing_validators().as_bytes())
        .expect("write genesis");

    let mut cmd = Command::cargo_bin("cipherd").expect("find cipherd binary");

    cmd.arg("validate")
        .arg("--genesis")
        .arg(temp.path())
        .assert()
        .failure()
        .stderr(predicate::str::contains("Error"));
}

#[test]
fn test_cli_validate_invalid_genesis_zero_gas_limit() {
    let mut temp = NamedTempFile::new().expect("create temp file");
    temp.write_all(invalid_genesis_zero_gas_limit().as_bytes())
        .expect("write genesis");

    let mut cmd = Command::cargo_bin("cipherd").expect("find cipherd binary");

    cmd.arg("validate")
        .arg("--genesis")
        .arg(temp.path())
        .assert()
        .failure()
        .stderr(predicate::str::contains("Error"));
}

#[test]
fn test_cli_validate_missing_file() {
    let mut cmd = Command::cargo_bin("cipherd").expect("find cipherd binary");

    cmd.arg("validate")
        .arg("--genesis")
        .arg("/nonexistent/path/genesis.json")
        .assert()
        .failure()
        .stderr(predicate::str::contains("not found").or(predicate::str::contains("Error")));
}

#[test]
fn test_cli_validate_malformed_json() {
    let mut temp = NamedTempFile::new().expect("create temp file");
    temp.write_all(b"{ invalid json }")
        .expect("write malformed json");

    let mut cmd = Command::cargo_bin("cipherd").expect("find cipherd binary");

    cmd.arg("validate")
        .arg("--genesis")
        .arg(temp.path())
        .assert()
        .failure()
        .stderr(predicate::str::contains("Error"));
}
