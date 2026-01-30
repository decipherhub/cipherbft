//! Genesis bootstrap logic for CipherBFT node.
//!
//! This module handles loading, parsing, and validating genesis files,
//! as well as bootstrapping the node's initial state from genesis.
//!
//! # Responsibilities
//!
//! - Load genesis JSON from file system
//! - Parse and validate genesis structure
//! - Initialize validator sets (consensus and DCL layers)
//! - Bootstrap EVM state from genesis alloc
//!
//! # Usage
//!
//! ```rust,ignore
//! use cipherd::genesis_bootstrap::GenesisLoader;
//!
//! let genesis = GenesisLoader::load_from_file(path)?;
//! GenesisLoader::validate(&genesis)?;
//! ```

use alloy_primitives::{Address, U256};
use cipherbft_crypto::{
    mnemonic::{derive_validator_keys, Mnemonic},
    ValidatorKeys,
};
use cipherbft_types::genesis::{
    CipherBftConfig, ConsensusParams, DclParams, Genesis, GenesisError, GenesisValidator,
    NativeTokenConfig, StakingParams,
};
use cipherbft_types::geth::{AllocEntry, GethConfig};
use cipherbft_types::ValidatorId;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use tracing::{debug, info};

/// Standard test mnemonic for devnet deterministic key generation.
///
/// DO NOT USE IN PRODUCTION - This is a publicly known test mnemonic
/// used by Hardhat, Foundry, and other Ethereum testing tools.
///
/// The same mnemonic derives different keys for each validator using
/// different account indices (0, 1, 2, 3...).
const DEVNET_TEST_MNEMONIC: &str = "test test test test test test test test test test test junk";

/// Genesis loader for CipherBFT node.
///
/// Provides a unified API for loading and validating genesis files.
/// This is the main entry point for genesis handling in the node.
///
/// # Example
///
/// ```rust,ignore
/// use cipherd::genesis_bootstrap::GenesisLoader;
/// use std::path::Path;
///
/// let path = Path::new("genesis.json");
/// let genesis = GenesisLoader::load_and_validate(path)?;
///
/// println!("Chain ID: {}", genesis.chain_id());
/// println!("Validators: {}", genesis.validator_count());
/// ```
pub struct GenesisLoader;

impl GenesisLoader {
    /// Parse genesis from a JSON string.
    ///
    /// This method only parses the JSON; it does not validate the genesis.
    /// Use [`validate`] or [`load_and_validate`] for full validation.
    ///
    /// # Arguments
    ///
    /// * `json` - JSON string containing the genesis file contents
    ///
    /// # Returns
    ///
    /// Returns the parsed [`Genesis`] or an error if parsing fails.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let json = std::fs::read_to_string("genesis.json")?;
    /// let genesis = GenesisLoader::parse_json(&json)?;
    /// ```
    pub fn parse_json(json: &str) -> Result<Genesis, GenesisError> {
        debug!("Parsing genesis JSON ({} bytes)", json.len());
        Genesis::from_json(json)
    }

    /// Load genesis from a file.
    ///
    /// Reads the file and parses its JSON content. Does not validate
    /// the genesis structure. Use [`validate`] or [`load_and_validate`]
    /// for full validation.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the genesis JSON file
    ///
    /// # Returns
    ///
    /// Returns the parsed [`Genesis`] or an error.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - File cannot be read (I/O error)
    /// - JSON is malformed (parse error)
    pub fn load_from_file(path: &Path) -> Result<Genesis, GenesisError> {
        info!("Loading genesis from: {}", path.display());
        Genesis::load(path)
    }

    /// Validate a genesis structure.
    ///
    /// Performs comprehensive validation including:
    /// - Chain configuration (non-zero chain ID, fork ordering)
    /// - Gas limit > 0
    /// - At least one validator
    /// - No duplicate validators
    /// - All validators present in alloc
    /// - Valid Ed25519 key lengths (64 hex chars)
    /// - Valid BLS key lengths (96 hex chars)
    /// - Stake >= minimum per validator
    /// - Non-zero total stake
    /// - Valid RFC3339 genesis_time
    ///
    /// # Arguments
    ///
    /// * `genesis` - The genesis structure to validate
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if valid, or an error describing the validation failure.
    pub fn validate(genesis: &Genesis) -> Result<(), GenesisError> {
        debug!("Validating genesis...");
        genesis.validate()?;
        debug!(
            "Genesis validation successful: chain_id={}, validators={}, total_stake={}",
            genesis.chain_id(),
            genesis.validator_count(),
            genesis.total_staked()
        );
        Ok(())
    }

    /// Load and validate genesis from a file.
    ///
    /// This is the preferred method for loading genesis files as it
    /// combines loading and validation in a single call.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the genesis JSON file
    ///
    /// # Returns
    ///
    /// Returns the validated [`Genesis`] or an error.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - File cannot be read
    /// - JSON is malformed
    /// - Validation fails (any validation rule violated)
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let genesis = GenesisLoader::load_and_validate(Path::new("genesis.json"))?;
    /// println!("Loaded {} validators", genesis.validator_count());
    /// ```
    pub fn load_and_validate(path: &Path) -> Result<Genesis, GenesisError> {
        let genesis = Self::load_from_file(path)?;
        Self::validate(&genesis)?;
        Self::log_summary(&genesis);
        Ok(genesis)
    }

    /// Log a summary of the genesis configuration.
    ///
    /// Outputs key information for operator visibility:
    /// - Chain ID
    /// - Network ID
    /// - Validator count
    /// - Total staked amount
    pub fn log_summary(genesis: &Genesis) {
        info!("Genesis loaded successfully:");
        info!("  Chain ID:    {}", genesis.chain_id());
        info!("  Network ID:  {}", genesis.cipherbft.network_id);
        info!("  Validators:  {}", genesis.validator_count());
        info!("  Total Stake: {} wei", genesis.total_staked());
        info!("  Genesis Time: {}", genesis.cipherbft.genesis_time);
    }
}

// ============================================================================
// Genesis Generation (US3: Testnet Genesis Generation)
// ============================================================================

/// Configuration options for genesis generation.
#[derive(Debug, Clone)]
pub struct GenesisGeneratorConfig {
    /// Number of validators to generate.
    pub num_validators: usize,
    /// Chain ID for the network.
    pub chain_id: u64,
    /// Network identifier (e.g., "cipherbft-testnet-1").
    pub network_id: String,
    /// Initial stake per validator in wei (default: 32 CPH).
    pub initial_stake: U256,
    /// Initial balance for validator accounts in wei (default: 100 CPH).
    pub initial_balance: U256,
    /// Gas limit for genesis block (default: 30M).
    pub gas_limit: U256,
    /// Extra accounts to allocate balances to (address, balance_wei) pairs.
    pub extra_alloc: Vec<(Address, U256)>,
}

impl Default for GenesisGeneratorConfig {
    fn default() -> Self {
        Self {
            num_validators: 4,
            chain_id: 85300,
            network_id: "cipherbft-testnet-1".to_string(),
            // 32 CPH = 32 * 10^18 wei = 0x1bc16d674ec80000
            initial_stake: U256::from(32_000_000_000_000_000_000u128),
            // 100 CPH = 100 * 10^18 wei
            initial_balance: U256::from(100_000_000_000_000_000_000u128),
            gas_limit: U256::from(30_000_000u64),
            extra_alloc: Vec::new(),
        }
    }
}

/// Generated validator key set with metadata.
///
/// Contains the full key set for a validator plus its derived address
/// and public key hex strings for inclusion in genesis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneratedValidator {
    /// Validator's EVM address (derived from secp256k1 public key).
    /// This is the Ethereum-compatible address used for rewards, staking, etc.
    pub address: Address,
    /// Validator ID (for internal use, derived from Ed25519 pubkey).
    #[serde(skip)]
    pub validator_id: ValidatorId,
    /// Ed25519 public key as hex string (64 chars, no 0x prefix stored).
    pub ed25519_pubkey_hex: String,
    /// BLS12-381 public key as hex string (96 chars, no 0x prefix stored).
    pub bls_pubkey_hex: String,
    /// Secp256k1 public key as hex string (66 chars compressed, no 0x prefix stored).
    pub secp256k1_pubkey_hex: String,
    /// Ed25519 secret key as hex string (for secure storage).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ed25519_secret_hex: Option<String>,
    /// BLS12-381 secret key as hex string (for secure storage).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bls_secret_hex: Option<String>,
    /// Secp256k1 secret key as hex string (for EVM transactions).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secp256k1_secret_hex: Option<String>,
}

/// Result of genesis generation.
#[derive(Debug, Clone)]
pub struct GenesisGenerationResult {
    /// The generated genesis configuration.
    pub genesis: Genesis,
    /// The generated validators with their keys.
    pub validators: Vec<GeneratedValidator>,
}

/// Genesis file generator for testnet deployment.
///
/// Generates complete genesis files with auto-generated keypairs and
/// sensible defaults for local or testnet deployment.
///
/// # Example
///
/// ```rust,ignore
/// use cipherd::genesis_bootstrap::{GenesisGenerator, GenesisGeneratorConfig};
///
/// let config = GenesisGeneratorConfig {
///     num_validators: 4,
///     chain_id: 85300,
///     ..Default::default()
/// };
///
/// let result = GenesisGenerator::generate(&mut rand::thread_rng(), config)?;
/// result.genesis.save(Path::new("genesis.json"))?;
/// ```
pub struct GenesisGenerator;

impl GenesisGenerator {
    /// Generate a complete genesis file with the specified configuration.
    ///
    /// # Arguments
    ///
    /// * `rng` - Cryptographically secure random number generator
    /// * `config` - Genesis generation configuration
    ///
    /// # Returns
    ///
    /// Returns a `GenesisGenerationResult` containing:
    /// - The complete genesis configuration ready for serialization
    /// - The list of generated validators with their key material
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let mut rng = rand::thread_rng();
    /// let config = GenesisGeneratorConfig::default();
    /// let result = GenesisGenerator::generate(&mut rng, config)?;
    /// ```
    pub fn generate<R: CryptoRng + RngCore>(
        _rng: &mut R,
        config: GenesisGeneratorConfig,
    ) -> Result<GenesisGenerationResult, GenesisError> {
        debug!(
            "Generating genesis with {} validators, chain_id={}",
            config.num_validators, config.chain_id
        );

        if config.num_validators == 0 {
            return Err(GenesisError::InvalidField {
                field: "num_validators",
                reason: "must be greater than zero".into(),
            });
        }

        // Generate validator keys
        let mut validators = Vec::with_capacity(config.num_validators);
        let mut genesis_validators = Vec::with_capacity(config.num_validators);
        let mut alloc = HashMap::new();

        // Parse test mnemonic for deterministic devnet keys
        // This ensures reproducible addresses matching Ethereum testing tools (Hardhat, Foundry)
        let mnemonic = Mnemonic::from_phrase(DEVNET_TEST_MNEMONIC)
            .expect("hardcoded test mnemonic should be valid");

        for i in 0..config.num_validators {
            // Derive keys from mnemonic at account index i
            // Each validator gets unique keys:
            // - Ed25519: m/12381/8888/{i}/0 (consensus)
            // - BLS: m/12381/8888/{i}/1 (DCL)
            // - Secp256k1: m/44'/60'/0'/0/{i} (EVM)
            let keys = derive_validator_keys(&mnemonic, i as u32, None)
                .expect("key derivation from valid mnemonic should succeed");

            // Use secp256k1-derived EVM address as the validator's primary address
            // This allows validators to control their rewards via standard EVM transactions
            let address = keys.evm_address();
            let validator_id = keys.validator_id();

            // Convert keys to hex strings
            let ed25519_pubkey_hex = hex::encode(keys.consensus_pubkey().to_bytes());
            let bls_pubkey_hex = hex::encode(keys.data_chain_pubkey().to_bytes());
            let secp256k1_pubkey_hex = hex::encode(keys.evm_pubkey().to_bytes());
            let ed25519_secret_hex = hex::encode(keys.consensus_secret().to_bytes());
            let bls_secret_hex = hex::encode(keys.data_chain_secret().to_bytes());
            let secp256k1_secret_hex = hex::encode(keys.evm_secret().to_bytes());

            debug!(
                "Derived validator {} from test mnemonic: evm_address={}, validator_id={:?}",
                i, address, validator_id
            );

            // Create genesis validator entry
            genesis_validators.push(GenesisValidator {
                address,
                name: Some(format!("validator-{}", i)),
                ed25519_pubkey: format!("0x{}", ed25519_pubkey_hex),
                bls_pubkey: format!("0x{}", bls_pubkey_hex),
                staked_amount: config.initial_stake,
                commission_rate_percent: 10,
            });

            // Add to alloc with initial balance
            alloc.insert(address, AllocEntry::new(config.initial_balance));

            // Store generated validator info
            validators.push(GeneratedValidator {
                address,
                validator_id,
                ed25519_pubkey_hex,
                bls_pubkey_hex,
                secp256k1_pubkey_hex,
                ed25519_secret_hex: Some(ed25519_secret_hex),
                bls_secret_hex: Some(bls_secret_hex),
                secp256k1_secret_hex: Some(secp256k1_secret_hex),
            });
        }

        // Add extra alloc accounts
        for (address, balance) in &config.extra_alloc {
            alloc.insert(*address, AllocEntry::new(*balance));
        }

        // Create the genesis structure
        let genesis_time = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();

        let genesis = Genesis {
            config: GethConfig::new(config.chain_id),
            alloc,
            gas_limit: config.gas_limit,
            difficulty: U256::from(1u64),
            nonce: Some(U256::ZERO),
            timestamp: Some(U256::ZERO),
            extra_data: None,
            mix_hash: None,
            coinbase: None,
            cipherbft: CipherBftConfig {
                genesis_time,
                network_id: config.network_id,
                native_token: NativeTokenConfig::default(),
                consensus: ConsensusParams::default(),
                dcl: DclParams::default(),
                staking: StakingParams::default(),
                validators: genesis_validators,
            },
        };

        // Validate the generated genesis
        genesis.validate()?;

        info!(
            "Genesis generated successfully: {} validators, chain_id={}, total_stake={} wei",
            validators.len(),
            config.chain_id,
            genesis.total_staked()
        );

        Ok(GenesisGenerationResult {
            genesis,
            validators,
        })
    }

    /// Create a default genesis template with sensible defaults.
    ///
    /// This creates a minimal genesis configuration without any validators,
    /// which can be customized before adding validators.
    ///
    /// # Arguments
    ///
    /// * `chain_id` - The EVM chain ID
    /// * `network_id` - The network identifier string
    pub fn default_template(chain_id: u64, network_id: &str) -> Genesis {
        Genesis {
            config: GethConfig::new(chain_id),
            alloc: HashMap::new(),
            gas_limit: U256::from(30_000_000u64),
            difficulty: U256::from(1u64),
            nonce: Some(U256::ZERO),
            timestamp: Some(U256::ZERO),
            extra_data: None,
            mix_hash: None,
            coinbase: None,
            cipherbft: CipherBftConfig {
                genesis_time: chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
                network_id: network_id.to_string(),
                native_token: NativeTokenConfig::default(),
                consensus: ConsensusParams::default(),
                dcl: DclParams::default(),
                staking: StakingParams::default(),
                validators: vec![],
            },
        }
    }

    /// Generate a genesis file from ValidatorKeys.
    ///
    /// This creates a single-validator genesis using the provided ValidatorKeys.
    /// Useful for `cipherd init` when generating genesis from keystore-derived keys.
    ///
    /// # Arguments
    ///
    /// * `validator_keys` - The validator keys (Ed25519 + BLS)
    /// * `chain_id` - The EVM chain ID (e.g., 85300)
    /// * `network_id` - The network identifier string (e.g., "cipherbft-testnet-1")
    /// * `initial_stake` - Initial stake per validator in wei
    /// * `initial_balance` - Initial balance for validator account in wei
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use cipherd::genesis_bootstrap::GenesisGenerator;
    /// use cipherbft_crypto::{Mnemonic, derive_validator_keys};
    ///
    /// let mnemonic = Mnemonic::generate().unwrap();
    /// let keys = derive_validator_keys(&mnemonic, 0, None).unwrap();
    /// let genesis = GenesisGenerator::generate_from_validator_keys(
    ///     &keys,
    ///     85300,
    ///     "cipherbft-testnet-1",
    ///     32_000_000_000_000_000_000u128.into(),  // 32 CPH
    ///     100_000_000_000_000_000_000u128.into(), // 100 CPH
    /// )?;
    /// ```
    pub fn generate_from_validator_keys(
        validator_keys: &ValidatorKeys,
        chain_id: u64,
        network_id: &str,
        initial_stake: U256,
        initial_balance: U256,
    ) -> Result<Genesis, GenesisError> {
        debug!(
            "Generating genesis from ValidatorKeys, chain_id={}, network_id={}",
            chain_id, network_id
        );

        // Extract public keys from ValidatorKeys
        let bls_pubkey_hex = hex::encode(validator_keys.data_chain_pubkey().to_bytes());
        let ed25519_pubkey_hex = hex::encode(validator_keys.consensus_pubkey().to_bytes());

        // Use secp256k1-derived EVM address as the validator's primary address
        let address = validator_keys.evm_address();

        debug!(
            "Validator: evm_address={}, ed25519={:.16}..., bls={:.16}...",
            address, ed25519_pubkey_hex, bls_pubkey_hex
        );

        // Create genesis validator entry
        let genesis_validator = GenesisValidator {
            address,
            name: Some("validator-0".to_string()),
            ed25519_pubkey: format!("0x{}", ed25519_pubkey_hex),
            bls_pubkey: format!("0x{}", bls_pubkey_hex),
            staked_amount: initial_stake,
            commission_rate_percent: 10,
        };

        // Create alloc with initial balance
        let mut alloc = HashMap::new();
        alloc.insert(address, AllocEntry::new(initial_balance));

        // Create the genesis structure
        let genesis_time = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();

        let genesis = Genesis {
            config: GethConfig::new(chain_id),
            alloc,
            gas_limit: U256::from(30_000_000u64),
            difficulty: U256::from(1u64),
            nonce: Some(U256::ZERO),
            timestamp: Some(U256::ZERO),
            extra_data: None,
            mix_hash: None,
            coinbase: None,
            cipherbft: CipherBftConfig {
                genesis_time,
                network_id: network_id.to_string(),
                native_token: NativeTokenConfig::default(),
                consensus: ConsensusParams::default(),
                dcl: DclParams::default(),
                staking: StakingParams::default(),
                validators: vec![genesis_validator],
            },
        };

        // Validate the generated genesis
        genesis.validate()?;

        info!(
            "Genesis generated from ValidatorKeys: chain_id={}, validator={}",
            chain_id, address
        );

        Ok(genesis)
    }
}

/// Validator key file for secure storage.
///
/// This structure is serialized to JSON for each validator's key file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorKeyFile {
    /// Validator index in the genesis set.
    pub index: usize,
    /// Validator's EVM address (derived from secp256k1 public key).
    pub address: String,
    /// Ed25519 public key (hex, for consensus layer).
    pub ed25519_pubkey: String,
    /// Ed25519 secret key (hex, for consensus layer).
    pub ed25519_secret: String,
    /// BLS12-381 public key (hex, for DCL layer).
    pub bls_pubkey: String,
    /// BLS12-381 secret key (hex, for DCL layer).
    pub bls_secret: String,
    /// Secp256k1 public key (hex, compressed, for EVM layer).
    pub secp256k1_pubkey: String,
    /// Secp256k1 secret key (hex, for EVM transactions).
    pub secp256k1_secret: String,
}

impl ValidatorKeyFile {
    /// Create from a GeneratedValidator.
    pub fn from_generated(index: usize, validator: &GeneratedValidator) -> Self {
        Self {
            index,
            address: format!("{:?}", validator.address),
            ed25519_pubkey: validator.ed25519_pubkey_hex.clone(),
            ed25519_secret: validator.ed25519_secret_hex.clone().unwrap_or_default(),
            bls_pubkey: validator.bls_pubkey_hex.clone(),
            bls_secret: validator.bls_secret_hex.clone().unwrap_or_default(),
            secp256k1_pubkey: validator.secp256k1_pubkey_hex.clone(),
            secp256k1_secret: validator.secp256k1_secret_hex.clone().unwrap_or_default(),
        }
    }

    /// Serialize to pretty JSON.
    pub fn to_json(&self) -> Result<String, GenesisError> {
        serde_json::to_string_pretty(self).map_err(|e| GenesisError::SerdeError(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Address, U256};
    use cipherbft_types::genesis::{
        AttestationQuorum, CipherBftConfig, ConsensusParams, DclParams, GenesisValidator,
        NativeTokenConfig, StakingParams,
    };
    use cipherbft_types::geth::{AllocEntry, GethConfig};
    use std::collections::HashMap;
    use std::io::Write;
    use tempfile::NamedTempFile;

    /// Create a minimal valid genesis for testing.
    fn create_test_genesis() -> Genesis {
        let validator_addr: Address = "0x742d35Cc6634C0532925a3b844Bc9e7595f0bC01"
            .parse()
            .unwrap();

        let mut alloc = HashMap::new();
        alloc.insert(
            validator_addr,
            AllocEntry::new(U256::from(1000000000000000000u128)),
        );

        Genesis {
            config: GethConfig::new(85300),
            alloc,
            gas_limit: U256::from(30_000_000u64),
            difficulty: U256::from(1u64),
            nonce: None,
            timestamp: None,
            extra_data: None,
            mix_hash: None,
            coinbase: None,
            cipherbft: CipherBftConfig {
                genesis_time: "2024-01-15T00:00:00Z".to_string(),
                network_id: "cipherbft-testnet-1".to_string(),
                native_token: NativeTokenConfig::default(),
                consensus: ConsensusParams::default(),
                dcl: DclParams::default(),
                staking: StakingParams::default(),
                validators: vec![GenesisValidator {
                    address: validator_addr,
                    name: None,
                    ed25519_pubkey: "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_string(),
                    bls_pubkey: "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890".to_string(),
                    staked_amount: U256::from(32000000000000000000u128),
                    commission_rate_percent: 5,
                }],
            },
        }
    }

    /// Create minimal valid JSON from the data model example.
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
                    "min_stake_wei": "1000000000000000000"
                },
                "validators": [
                    {
                        "address": "0x742d35Cc6634C0532925a3b844Bc9e7595f0bC01",
                        "ed25519_pubkey": "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
                        "bls_pubkey": "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
                        "staked_amount": "32000000000000000000"
                    }
                ]
            }
        }"#
    }

    // ========================================================================
    // T021: Unit test for Genesis JSON parsing
    // ========================================================================

    #[test]
    fn test_parse_json_valid_minimal_genesis() {
        let json = minimal_genesis_json();
        let genesis = GenesisLoader::parse_json(json).expect("should parse valid genesis");

        assert_eq!(genesis.chain_id(), 85300);
        assert_eq!(genesis.validator_count(), 1);
        assert_eq!(genesis.cipherbft.network_id, "cipherbft-testnet-1");
    }

    #[test]
    fn test_parse_json_invalid_json() {
        let json = "{ invalid json }";
        let result = GenesisLoader::parse_json(json);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, GenesisError::ParseError(_)));
    }

    #[test]
    fn test_parse_json_missing_required_field() {
        // Missing cipherbft field
        let json = r#"{
            "config": { "chainId": 85300 },
            "alloc": {},
            "gasLimit": "0x1c9c380",
            "difficulty": "0x1"
        }"#;
        let result = GenesisLoader::parse_json(json);

        assert!(result.is_err());
    }

    // ========================================================================
    // T022: Unit test for hex U256 serde round-trip (delegated to types crate)
    // Note: Primary tests are in crates/types/src/geth.rs and genesis.rs
    // ========================================================================

    #[test]
    fn test_genesis_round_trip() {
        let genesis = create_test_genesis();

        // Serialize to JSON
        let json = genesis.to_json().expect("should serialize");

        // Parse back
        let parsed = GenesisLoader::parse_json(&json).expect("should parse serialized genesis");

        // Verify key fields
        assert_eq!(parsed.chain_id(), genesis.chain_id());
        assert_eq!(parsed.gas_limit, genesis.gas_limit);
        assert_eq!(parsed.difficulty, genesis.difficulty);
        assert_eq!(parsed.validator_count(), genesis.validator_count());
    }

    // ========================================================================
    // T023: Unit test for GethConfig fork block ordering validation
    // Note: Primary tests are in crates/types/src/geth.rs
    // ========================================================================

    #[test]
    fn test_validate_fork_order_via_genesis() {
        // Invalid fork ordering through genesis validation
        let json = r#"{
            "config": {
                "chainId": 85300,
                "homesteadBlock": 100,
                "eip150Block": 50
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
                "network_id": "test",
                "validators": [{
                    "address": "0x742d35Cc6634C0532925a3b844Bc9e7595f0bC01",
                    "ed25519_pubkey": "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
                    "bls_pubkey": "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
                    "staked_amount": "32000000000000000000"
                }]
            }
        }"#;

        let genesis = GenesisLoader::parse_json(json).expect("should parse");
        let result = GenesisLoader::validate(&genesis);

        assert!(result.is_err());
        let err = result.unwrap_err();
        // Should be a config error about fork ordering
        assert!(matches!(err, GenesisError::Config(_)));
    }

    // ========================================================================
    // T024/T025: load_from_file tests
    // ========================================================================

    #[test]
    fn test_load_from_file_valid() {
        // Create a temporary file with valid genesis
        let mut temp = NamedTempFile::new().expect("create temp file");
        temp.write_all(minimal_genesis_json().as_bytes())
            .expect("write genesis");

        let genesis =
            GenesisLoader::load_from_file(temp.path()).expect("should load valid genesis");

        assert_eq!(genesis.chain_id(), 85300);
    }

    #[test]
    fn test_load_from_file_not_found() {
        let result = GenesisLoader::load_from_file(Path::new("/nonexistent/genesis.json"));

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, GenesisError::Io { .. }));
    }

    #[test]
    fn test_load_from_file_invalid_json() {
        let mut temp = NamedTempFile::new().expect("create temp file");
        temp.write_all(b"{ not valid json }")
            .expect("write invalid json");

        let result = GenesisLoader::load_from_file(temp.path());

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), GenesisError::ParseError(_)));
    }

    // ========================================================================
    // T028: Validate tests
    // ========================================================================

    #[test]
    fn test_validate_success() {
        let genesis = create_test_genesis();
        let result = GenesisLoader::validate(&genesis);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_missing_validators() {
        let mut genesis = create_test_genesis();
        genesis.cipherbft.validators.clear();

        let result = GenesisLoader::validate(&genesis);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), GenesisError::MissingField(_)));
    }

    #[test]
    fn test_validate_validator_not_in_alloc() {
        let mut genesis = create_test_genesis();
        genesis.alloc.clear(); // Remove validator from alloc

        let result = GenesisLoader::validate(&genesis);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            GenesisError::ValidatorNotInAlloc(_)
        ));
    }

    #[test]
    fn test_validate_zero_chain_id() {
        let mut genesis = create_test_genesis();
        genesis.config.chain_id = 0;

        let result = GenesisLoader::validate(&genesis);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), GenesisError::Config(_)));
    }

    #[test]
    fn test_validate_zero_gas_limit() {
        let mut genesis = create_test_genesis();
        genesis.gas_limit = U256::ZERO;

        let result = GenesisLoader::validate(&genesis);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            GenesisError::InvalidField { .. }
        ));
    }

    // ========================================================================
    // T035: Duplicate validator error test
    // ========================================================================

    #[test]
    fn test_validate_duplicate_validator() {
        let mut genesis = create_test_genesis();
        // Add a duplicate validator with the same address
        let duplicate = genesis.cipherbft.validators[0].clone();
        genesis.cipherbft.validators.push(duplicate);

        let result = GenesisLoader::validate(&genesis);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            GenesisError::DuplicateValidator(_)
        ));
    }

    // ========================================================================
    // T036: Zero total stake error test
    // ========================================================================

    #[test]
    fn test_validate_zero_total_stake() {
        let mut genesis = create_test_genesis();
        // Set all validators to zero stake
        for validator in &mut genesis.cipherbft.validators {
            validator.staked_amount = U256::ZERO;
        }
        // Also need to lower min_stake_wei to allow zero stake past the min check
        genesis.cipherbft.staking.min_stake_wei = U256::ZERO;

        let result = GenesisLoader::validate(&genesis);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), GenesisError::ZeroTotalStake));
    }

    // ========================================================================
    // Load and validate combined
    // ========================================================================

    #[test]
    fn test_load_and_validate_success() {
        let mut temp = NamedTempFile::new().expect("create temp file");
        temp.write_all(minimal_genesis_json().as_bytes())
            .expect("write genesis");

        let genesis =
            GenesisLoader::load_and_validate(temp.path()).expect("should load and validate");

        assert_eq!(genesis.chain_id(), 85300);
        assert_eq!(genesis.validator_count(), 1);
    }

    #[test]
    fn test_load_and_validate_invalid() {
        // Valid JSON but invalid genesis (zero gas limit)
        let json = r#"{
            "config": { "chainId": 85300 },
            "alloc": {},
            "gasLimit": "0x0",
            "difficulty": "0x1",
            "cipherbft": {
                "genesis_time": "2024-01-15T00:00:00Z",
                "network_id": "test",
                "validators": []
            }
        }"#;

        let mut temp = NamedTempFile::new().expect("create temp file");
        temp.write_all(json.as_bytes()).expect("write genesis");

        let result = GenesisLoader::load_and_validate(temp.path());
        assert!(result.is_err());
    }

    // ========================================================================
    // T044: Unit tests for GenesisGenerator
    // ========================================================================

    #[test]
    fn test_genesis_generator_default_config() {
        let config = GenesisGeneratorConfig::default();

        assert_eq!(config.num_validators, 4);
        assert_eq!(config.chain_id, 85300);
        assert_eq!(config.network_id, "cipherbft-testnet-1");
        // 32 CPH in wei
        assert_eq!(
            config.initial_stake,
            U256::from(32_000_000_000_000_000_000u128)
        );
        // 100 CPH in wei
        assert_eq!(
            config.initial_balance,
            U256::from(100_000_000_000_000_000_000u128)
        );
        // 30M gas
        assert_eq!(config.gas_limit, U256::from(30_000_000u64));
    }

    #[test]
    fn test_genesis_generator_generates_valid_genesis() {
        let mut rng = rand::thread_rng();
        let config = GenesisGeneratorConfig::default();

        let result = GenesisGenerator::generate(&mut rng, config.clone())
            .expect("should generate valid genesis");

        // Verify basic structure
        assert_eq!(result.genesis.chain_id(), config.chain_id);
        assert_eq!(result.genesis.validator_count(), config.num_validators);
        assert_eq!(result.genesis.cipherbft.network_id, config.network_id);
        assert_eq!(result.validators.len(), config.num_validators);

        // Verify the genesis is valid
        assert!(result.genesis.validate().is_ok());
    }

    #[test]
    fn test_genesis_generator_custom_validator_count() {
        let mut rng = rand::thread_rng();
        let config = GenesisGeneratorConfig {
            num_validators: 7,
            ..Default::default()
        };

        let result = GenesisGenerator::generate(&mut rng, config)
            .expect("should generate genesis with 7 validators");

        assert_eq!(result.genesis.validator_count(), 7);
        assert_eq!(result.validators.len(), 7);
    }

    #[test]
    fn test_genesis_generator_custom_chain_id() {
        let mut rng = rand::thread_rng();
        let config = GenesisGeneratorConfig {
            chain_id: 12345,
            ..Default::default()
        };

        let result = GenesisGenerator::generate(&mut rng, config)
            .expect("should generate genesis with custom chain ID");

        assert_eq!(result.genesis.chain_id(), 12345);
    }

    #[test]
    fn test_genesis_generator_zero_validators_fails() {
        let mut rng = rand::thread_rng();
        let config = GenesisGeneratorConfig {
            num_validators: 0,
            ..Default::default()
        };

        let result = GenesisGenerator::generate(&mut rng, config);

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            GenesisError::InvalidField {
                field: "num_validators",
                ..
            }
        ));
    }

    #[test]
    fn test_genesis_generator_validator_keys_are_unique() {
        let mut rng = rand::thread_rng();
        let config = GenesisGeneratorConfig {
            num_validators: 10,
            ..Default::default()
        };

        let result = GenesisGenerator::generate(&mut rng, config).expect("should generate genesis");

        // Collect all addresses
        let addresses: Vec<_> = result.validators.iter().map(|v| v.address).collect();
        let unique_addresses: std::collections::HashSet<_> = addresses.iter().collect();

        // All addresses should be unique
        assert_eq!(addresses.len(), unique_addresses.len());

        // Collect all ed25519 pubkeys
        let pubkeys: Vec<_> = result
            .validators
            .iter()
            .map(|v| &v.ed25519_pubkey_hex)
            .collect();
        let unique_pubkeys: std::collections::HashSet<_> = pubkeys.iter().collect();

        // All pubkeys should be unique
        assert_eq!(pubkeys.len(), unique_pubkeys.len());
    }

    #[test]
    fn test_genesis_generator_validator_key_lengths() {
        let mut rng = rand::thread_rng();
        let config = GenesisGeneratorConfig::default();

        let result = GenesisGenerator::generate(&mut rng, config).expect("should generate genesis");

        for validator in &result.validators {
            // Ed25519 pubkey: 32 bytes = 64 hex chars
            assert_eq!(validator.ed25519_pubkey_hex.len(), 64);
            // BLS pubkey: 48 bytes = 96 hex chars
            assert_eq!(validator.bls_pubkey_hex.len(), 96);
            // Secret keys should be present
            assert!(validator.ed25519_secret_hex.is_some());
            assert!(validator.bls_secret_hex.is_some());
        }
    }

    #[test]
    fn test_genesis_generator_alloc_entries() {
        let mut rng = rand::thread_rng();
        let config = GenesisGeneratorConfig {
            num_validators: 3,
            initial_balance: U256::from(50_000_000_000_000_000_000u128), // 50 CPH
            ..Default::default()
        };

        let result =
            GenesisGenerator::generate(&mut rng, config.clone()).expect("should generate genesis");

        // Each validator should have an alloc entry
        for validator in &result.validators {
            let alloc_entry = result.genesis.alloc.get(&validator.address);
            assert!(alloc_entry.is_some());
            assert_eq!(alloc_entry.unwrap().balance, config.initial_balance);
        }
    }

    #[test]
    fn test_genesis_generator_total_stake() {
        let mut rng = rand::thread_rng();
        let config = GenesisGeneratorConfig {
            num_validators: 5,
            initial_stake: U256::from(10_000_000_000_000_000_000u128), // 10 CPH each
            ..Default::default()
        };

        let result = GenesisGenerator::generate(&mut rng, config).expect("should generate genesis");

        // Total stake should be 5 * 10 CPH = 50 CPH
        let expected_total = U256::from(50_000_000_000_000_000_000u128);
        assert_eq!(result.genesis.total_staked(), expected_total);
    }

    #[test]
    fn test_genesis_generator_genesis_time_is_set() {
        let mut rng = rand::thread_rng();
        let config = GenesisGeneratorConfig::default();

        let result = GenesisGenerator::generate(&mut rng, config).expect("should generate genesis");

        // Genesis time should be a valid RFC3339 timestamp
        let genesis_time = &result.genesis.cipherbft.genesis_time;
        assert!(!genesis_time.is_empty());
        assert!(genesis_time.contains("T")); // RFC3339 format
        assert!(genesis_time.ends_with("Z")); // UTC timezone
    }

    // ========================================================================
    // T044: Unit tests for default_template
    // ========================================================================

    #[test]
    fn test_default_template_basic_structure() {
        let template = GenesisGenerator::default_template(99999, "test-network");

        assert_eq!(template.chain_id(), 99999);
        assert_eq!(template.cipherbft.network_id, "test-network");
        assert_eq!(template.validator_count(), 0); // No validators by default
        assert!(template.alloc.is_empty());
    }

    #[test]
    fn test_default_template_default_gas_limit() {
        let template = GenesisGenerator::default_template(1, "net");

        // Default gas limit should be 30M
        assert_eq!(template.gas_limit, U256::from(30_000_000u64));
    }

    #[test]
    fn test_default_template_has_genesis_time() {
        let template = GenesisGenerator::default_template(1, "net");

        // Genesis time should be set
        assert!(!template.cipherbft.genesis_time.is_empty());
        assert!(template.cipherbft.genesis_time.contains("T"));
    }

    #[test]
    fn test_default_template_has_default_params() {
        let template = GenesisGenerator::default_template(1, "net");

        // Default consensus params
        assert!(template.cipherbft.consensus.target_block_time_ms > 0);

        // Default DCL params
        assert!(template.cipherbft.dcl.car_interval_ms > 0);
        assert_eq!(
            template.cipherbft.dcl.attestation_quorum,
            AttestationQuorum::TwoFPlusOne
        );

        // Default staking params
        assert!(template.cipherbft.staking.min_stake_wei > U256::ZERO);
    }

    // ========================================================================
    // ValidatorKeyFile tests
    // ========================================================================

    #[test]
    fn test_validator_key_file_from_generated() {
        let mut rng = rand::thread_rng();
        let config = GenesisGeneratorConfig {
            num_validators: 1,
            ..Default::default()
        };

        let result = GenesisGenerator::generate(&mut rng, config).expect("should generate genesis");

        let key_file = ValidatorKeyFile::from_generated(0, &result.validators[0]);

        assert_eq!(key_file.index, 0);
        assert!(!key_file.address.is_empty());
        assert_eq!(key_file.ed25519_pubkey.len(), 64);
        assert_eq!(key_file.bls_pubkey.len(), 96);
        assert!(!key_file.ed25519_secret.is_empty());
        assert!(!key_file.bls_secret.is_empty());
    }

    #[test]
    fn test_validator_key_file_to_json() {
        let mut rng = rand::thread_rng();
        let config = GenesisGeneratorConfig {
            num_validators: 1,
            ..Default::default()
        };

        let result = GenesisGenerator::generate(&mut rng, config).expect("should generate genesis");

        let key_file = ValidatorKeyFile::from_generated(0, &result.validators[0]);
        let json = key_file.to_json().expect("should serialize to JSON");

        // Verify JSON structure
        assert!(json.contains("\"index\": 0"));
        assert!(json.contains("\"address\""));
        assert!(json.contains("\"ed25519_pubkey\""));
        assert!(json.contains("\"bls_pubkey\""));
        assert!(json.contains("\"ed25519_secret\""));
        assert!(json.contains("\"bls_secret\""));
    }

    #[test]
    fn test_validator_key_file_roundtrip() {
        let mut rng = rand::thread_rng();
        let config = GenesisGeneratorConfig {
            num_validators: 1,
            ..Default::default()
        };

        let result = GenesisGenerator::generate(&mut rng, config).expect("should generate genesis");

        let key_file = ValidatorKeyFile::from_generated(0, &result.validators[0]);
        let json = key_file.to_json().expect("should serialize");

        // Parse back
        let parsed: ValidatorKeyFile = serde_json::from_str(&json).expect("should deserialize");

        assert_eq!(parsed.index, key_file.index);
        assert_eq!(parsed.address, key_file.address);
        assert_eq!(parsed.ed25519_pubkey, key_file.ed25519_pubkey);
        assert_eq!(parsed.bls_pubkey, key_file.bls_pubkey);
    }

    #[test]
    fn test_genesis_generator_config_with_extra_alloc() {
        let extra = vec![(
            "0x3E54B36f4F8EFaa017888E66fb6dB17098437ac7"
                .parse()
                .unwrap(),
            U256::from(1_000_000_000_000_000_000_000_u128), // 1000 ETH
        )];
        let config = GenesisGeneratorConfig {
            extra_alloc: extra.clone(),
            ..Default::default()
        };
        assert_eq!(config.extra_alloc.len(), 1);
        assert_eq!(
            config.extra_alloc[0].0,
            "0x3E54B36f4F8EFaa017888E66fb6dB17098437ac7"
                .parse::<Address>()
                .unwrap()
        );
    }

    #[test]
    fn test_genesis_generator_includes_extra_alloc() {
        let extra_addr: Address = "0x3E54B36f4F8EFaa017888E66fb6dB17098437ac7"
            .parse()
            .unwrap();
        let extra_balance = U256::from(500_000_000_000_000_000_000u128); // 500 ETH

        let config = GenesisGeneratorConfig {
            num_validators: 1,
            extra_alloc: vec![(extra_addr, extra_balance)],
            ..Default::default()
        };

        let mut rng = rand::thread_rng();
        let result = GenesisGenerator::generate(&mut rng, config).unwrap();

        // Verify extra account is in alloc
        assert!(result.genesis.alloc.contains_key(&extra_addr));
        assert_eq!(
            result.genesis.alloc.get(&extra_addr).unwrap().balance,
            extra_balance
        );

        // Verify we have 2 accounts total (1 validator + 1 extra)
        assert_eq!(result.genesis.alloc.len(), 2);
    }
}
