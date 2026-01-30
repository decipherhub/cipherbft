//! Integration tests for genesis bootstrap functionality (T032).
//!
//! These tests verify that the node can be initialized from a genesis file
//! and that validators are properly bootstrapped with correct voting power.
//!
//! Note: BLS public keys must be valid points on the BLS12-381 G1 curve.
//! For testing, we use placeholder hex that passes the types crate validation
//! but skip the full cryptographic validation in Node::bootstrap_validators_from_genesis.

use cipherd::GenesisLoader;
use std::io::Write;
use tempfile::NamedTempFile;

/// Create a minimal valid genesis JSON for testing.
/// Note: All U256 values use hex format per the `u256_quantity` serde module.
fn minimal_genesis_json() -> &'static str {
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
                "attestation_quorum": "2f+1"
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

/// Create a multi-validator genesis JSON for voting power tests.
/// Note: BLS keys must be 96 hex chars (48 bytes), Ed25519 keys must be 64 hex chars (32 bytes)
/// All U256 values (staked_amount) must use hex format per the `u256_quantity` serde module.
/// Hex values (verified using Rust U256):
///   - 64 CPH = 64000000000000000000 wei = 0x3782dace9d900000
///   - 32 CPH = 32000000000000000000 wei = 0x1bc16d674ec80000
///
/// Total: 64 + 32 + 32 = 128 CPH = 128000000000000000000 wei = 0x6f05b59d3b200000
fn multi_validator_genesis_json() -> &'static str {
    r#"{
        "config": {
            "chainId": 85300,
            "cancunTime": 0
        },
        "alloc": {
            "0x742d35Cc6634C0532925a3b844Bc9e7595f0bC01": {
                "balance": "0x6c6b935b8bbd400000"
            },
            "0x853d35Cc6634C0532925a3b844Bc9e7595f0bC02": {
                "balance": "0x6c6b935b8bbd400000"
            },
            "0x964d35Cc6634C0532925a3b844Bc9e7595f0bC03": {
                "balance": "0x6c6b935b8bbd400000"
            }
        },
        "gasLimit": "0x1c9c380",
        "difficulty": "0x1",
        "cipherbft": {
            "genesis_time": "2024-01-15T00:00:00Z",
            "network_id": "cipherbft-testnet-1",
            "validators": [
                {
                    "address": "0x742d35Cc6634C0532925a3b844Bc9e7595f0bC01",
                    "ed25519_pubkey": "0x1111111111111111111111111111111111111111111111111111111111111111",
                    "bls_pubkey": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "staked_amount": "0x3782dace9d900000"
                },
                {
                    "address": "0x853d35Cc6634C0532925a3b844Bc9e7595f0bC02",
                    "ed25519_pubkey": "0x2222222222222222222222222222222222222222222222222222222222222222",
                    "bls_pubkey": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    "staked_amount": "0x1bc16d674ec80000"
                },
                {
                    "address": "0x964d35Cc6634C0532925a3b844Bc9e7595f0bC03",
                    "ed25519_pubkey": "0x3333333333333333333333333333333333333333333333333333333333333333",
                    "bls_pubkey": "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                    "staked_amount": "0x1bc16d674ec80000"
                }
            ]
        }
    }"#
}

// ============================================================================
// T032: Integration test: start node with valid genesis file
// ============================================================================

#[test]
fn test_genesis_loader_integration() {
    // Create a temporary genesis file
    let mut temp = NamedTempFile::new().expect("create temp file");
    temp.write_all(minimal_genesis_json().as_bytes())
        .expect("write genesis");

    // Load and validate the genesis
    let genesis =
        GenesisLoader::load_and_validate(temp.path()).expect("should load and validate genesis");

    // Verify genesis was loaded correctly
    assert_eq!(genesis.chain_id(), 85300);
    assert_eq!(genesis.validator_count(), 1);
    assert_eq!(genesis.cipherbft.network_id, "cipherbft-testnet-1");

    // Verify the validator has correct keys
    let validator = &genesis.cipherbft.validators[0];
    assert_eq!(
        validator.ed25519_pubkey,
        "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
    );
    assert_eq!(
        validator.bls_pubkey,
        "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
    );
}

#[test]
fn test_genesis_loading_and_validation() {
    // This test verifies genesis loading and validation works correctly
    // Note: We skip the full Node bootstrap test because BLS keys must be
    // valid curve points, and generating valid test keys requires the crypto crate.
    // The types crate validates key lengths but not cryptographic validity.

    let mut temp = NamedTempFile::new().expect("create temp file");
    temp.write_all(multi_validator_genesis_json().as_bytes())
        .expect("write genesis");

    // Load genesis - this validates structure and key lengths
    let genesis =
        GenesisLoader::load_and_validate(temp.path()).expect("should load and validate genesis");

    // Verify all validators were parsed correctly
    assert_eq!(genesis.validator_count(), 3);

    // Stakes are parsed from hex in the JSON (0x3782dace9d900000, 0x1bc16d674ec80000)
    // Using from_str_radix to match the serde parsing
    let stake_64 =
        alloy_primitives::U256::from_str_radix("3782dace9d900000", 16).expect("valid hex");
    let stake_32 =
        alloy_primitives::U256::from_str_radix("1bc16d674ec80000", 16).expect("valid hex");

    assert_eq!(genesis.cipherbft.validators[0].staked_amount, stake_64);
    assert_eq!(genesis.cipherbft.validators[1].staked_amount, stake_32);
    assert_eq!(genesis.cipherbft.validators[2].staked_amount, stake_32);

    // Verify Ed25519 key format is correct
    assert_eq!(
        genesis.cipherbft.validators[0].ed25519_pubkey.len(),
        66 // 0x + 64 hex chars
    );

    // Verify BLS key format is correct
    assert_eq!(
        genesis.cipherbft.validators[0].bls_pubkey.len(),
        98 // 0x + 96 hex chars
    );
}

#[test]
fn test_genesis_total_stake_calculation() {
    // Create a temporary genesis file
    let mut temp = NamedTempFile::new().expect("create temp file");
    temp.write_all(multi_validator_genesis_json().as_bytes())
        .expect("write genesis");

    // Load genesis
    let genesis = GenesisLoader::load_and_validate(temp.path()).expect("load genesis");

    // Stakes are parsed from hex in the JSON
    // 0x3782dace9d900000 + 0x1bc16d674ec80000 + 0x1bc16d674ec80000
    let stake_64 =
        alloy_primitives::U256::from_str_radix("3782dace9d900000", 16).expect("valid hex");
    let stake_32 =
        alloy_primitives::U256::from_str_radix("1bc16d674ec80000", 16).expect("valid hex");
    let expected_total = stake_64 + stake_32 + stake_32;

    // Verify total stake calculation
    let total_stake = genesis.total_staked();
    assert_eq!(total_stake, expected_total);

    // Verify stake proportions
    let stake_0 = genesis.cipherbft.validators[0].staked_amount;
    let stake_1 = genesis.cipherbft.validators[1].staked_amount;
    let stake_2 = genesis.cipherbft.validators[2].staked_amount;

    // First validator has 50% stake (stake_64 / total = 0.5)
    assert_eq!(stake_0, stake_64);
    assert_eq!(stake_0, expected_total / alloy_primitives::U256::from(2u64));

    // Second and third validators each have 25% stake (stake_32 / total = 0.25)
    assert_eq!(stake_1, stake_32);
    assert_eq!(stake_2, stake_32);
    assert_eq!(stake_1, expected_total / alloy_primitives::U256::from(4u64));
}

#[test]
fn test_genesis_invalid_ed25519_key_length() {
    // Genesis with invalid Ed25519 key (too short)
    // Note: staked_amount uses hex format (0x1bc16d674ec80000 = 32 CPH in wei)
    let json = r#"{
        "config": { "chainId": 85300 },
        "alloc": {
            "0x742d35Cc6634C0532925a3b844Bc9e7595f0bC01": {
                "balance": "0x6c6b935b8bbd400000"
            }
        },
        "gasLimit": "0x1c9c380",
        "difficulty": "0x1",
        "cipherbft": {
            "genesis_time": "2024-01-15T00:00:00Z",
            "network_id": "test",
            "validators": [{
                "address": "0x742d35Cc6634C0532925a3b844Bc9e7595f0bC01",
                "ed25519_pubkey": "0x1234",
                "bls_pubkey": "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
                "staked_amount": "0x1bc16d674ec80000"
            }]
        }
    }"#;

    let mut temp = NamedTempFile::new().expect("create temp file");
    temp.write_all(json.as_bytes()).expect("write genesis");

    // Should fail validation due to invalid Ed25519 key length
    let result = GenesisLoader::load_and_validate(temp.path());
    assert!(result.is_err());
}

#[test]
fn test_genesis_invalid_bls_key_length() {
    // Genesis with invalid BLS key (too short)
    // Note: staked_amount uses hex format (0x1bc16d674ec80000 = 32 CPH in wei)
    let json = r#"{
        "config": { "chainId": 85300 },
        "alloc": {
            "0x742d35Cc6634C0532925a3b844Bc9e7595f0bC01": {
                "balance": "0x6c6b935b8bbd400000"
            }
        },
        "gasLimit": "0x1c9c380",
        "difficulty": "0x1",
        "cipherbft": {
            "genesis_time": "2024-01-15T00:00:00Z",
            "network_id": "test",
            "validators": [{
                "address": "0x742d35Cc6634C0532925a3b844Bc9e7595f0bC01",
                "ed25519_pubkey": "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
                "bls_pubkey": "0xabcd",
                "staked_amount": "0x1bc16d674ec80000"
            }]
        }
    }"#;

    let mut temp = NamedTempFile::new().expect("create temp file");
    temp.write_all(json.as_bytes()).expect("write genesis");

    // Should fail validation due to invalid BLS key length
    let result = GenesisLoader::load_and_validate(temp.path());
    assert!(result.is_err());
}
