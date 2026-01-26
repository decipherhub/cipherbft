//! Genesis file types for CipherBFT.
//!
//! This module provides Geth-compatible genesis file types with CipherBFT extensions.
//! The genesis format supports standard Ethereum tooling (Foundry, Hardhat) while
//! including BFT consensus and DCL configuration in a `cipherbft` namespace.
//!
//! # Format
//!
//! ```json
//! {
//!   "config": { "chainId": 85300, ... },
//!   "alloc": { "0x...": { "balance": "0x..." } },
//!   "gasLimit": "0x1c9c380",
//!   "difficulty": "0x1",
//!   "cipherbft": {
//!     "genesis_time": "2024-01-15T00:00:00Z",
//!     "network_id": "cipherbft-testnet-1",
//!     "validators": [...]
//!   }
//! }
//! ```
//!
//! # Key Features
//!
//! - **Geth-compatible**: Top-level fields work with standard EVM tooling
//! - **Dual-key validators**: Ed25519 (Malachite) + BLS12-381 (DCL attestations)
//! - **Voting power derivation**: Proportional to staked amounts

use alloy_primitives::{Address, B256, U256};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::geth::{AllocEntry, GethConfig, GethConfigError};

// Re-export key types for convenience
pub use crate::geth::{AllocEntry as GenesisAllocEntry, GethConfig as ChainConfig};

// ============================================================================
// Custom serde modules for hex quantities
// ============================================================================

mod u256_quantity {
    use alloy_primitives::U256;
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &U256, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let hex = format!("{:#x}", value);
        serializer.serialize_str(&hex)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<U256, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        U256::from_str_radix(s.trim_start_matches("0x"), 16).map_err(serde::de::Error::custom)
    }
}

mod opt_u256_quantity {
    use alloy_primitives::U256;
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &Option<U256>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(v) => {
                let hex = format!("{:#x}", v);
                serializer.serialize_str(&hex)
            }
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<U256>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt: Option<String> = Option::deserialize(deserializer)?;
        match opt {
            Some(s) => {
                let v = U256::from_str_radix(s.trim_start_matches("0x"), 16)
                    .map_err(serde::de::Error::custom)?;
                Ok(Some(v))
            }
            None => Ok(None),
        }
    }
}

// ============================================================================
// Root Genesis Structure (Geth-compatible + CipherBFT extension)
// ============================================================================

/// Complete genesis file structure.
///
/// Combines Geth-compatible fields for EVM tooling with CipherBFT-specific
/// configuration in the `cipherbft` namespace.
///
/// # Example
///
/// ```rust,ignore
/// use cipherbft_types::genesis::Genesis;
///
/// let genesis = Genesis::load(Path::new("genesis.json"))?;
/// println!("Chain ID: {}", genesis.config.chain_id);
/// println!("Validators: {}", genesis.cipherbft.validators.len());
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Genesis {
    /// EVM chain configuration (fork blocks, chain ID).
    pub config: GethConfig,

    /// Initial account states (balances, code, storage).
    pub alloc: HashMap<Address, AllocEntry>,

    /// Block gas limit.
    #[serde(with = "u256_quantity")]
    pub gas_limit: U256,

    /// Block difficulty (typically "0x1" for PoS chains).
    #[serde(with = "u256_quantity")]
    pub difficulty: U256,

    /// Genesis nonce (optional).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "opt_u256_quantity"
    )]
    pub nonce: Option<U256>,

    /// Genesis timestamp in seconds since epoch.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "opt_u256_quantity"
    )]
    pub timestamp: Option<U256>,

    /// Extra data field (optional, max 32 bytes).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extra_data: Option<String>,

    /// Mix hash (optional, typically zeros).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mix_hash: Option<B256>,

    /// Coinbase / beneficiary address (optional).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coinbase: Option<Address>,

    /// CipherBFT-specific configuration.
    pub cipherbft: CipherBftConfig,
}

impl Genesis {
    /// Load genesis from a JSON file.
    pub fn load(path: &Path) -> Result<Self, GenesisError> {
        let content = std::fs::read_to_string(path).map_err(|e| GenesisError::Io {
            path: path.to_path_buf(),
            message: e.to_string(),
        })?;
        Self::from_json(&content)
    }

    /// Parse genesis from JSON string.
    pub fn from_json(json: &str) -> Result<Self, GenesisError> {
        serde_json::from_str(json).map_err(|e| GenesisError::ParseError(e.to_string()))
    }

    /// Serialize to JSON string.
    pub fn to_json(&self) -> Result<String, GenesisError> {
        serde_json::to_string_pretty(self).map_err(|e| GenesisError::SerdeError(e.to_string()))
    }

    /// Save genesis to a file.
    pub fn save(&self, path: &Path) -> Result<(), GenesisError> {
        let json = self.to_json()?;
        std::fs::write(path, json).map_err(|e| GenesisError::Io {
            path: path.to_path_buf(),
            message: e.to_string(),
        })
    }

    /// Get the chain ID from config.
    pub fn chain_id(&self) -> u64 {
        self.config.chain_id
    }

    /// Get the total staked amount across all validators.
    pub fn total_staked(&self) -> U256 {
        self.cipherbft
            .validators
            .iter()
            .map(|v| v.staked_amount)
            .fold(U256::ZERO, |acc, x| acc + x)
    }

    /// Get the number of validators.
    pub fn validator_count(&self) -> usize {
        self.cipherbft.validators.len()
    }

    /// Get the native token name (e.g., "Cipher").
    pub fn native_token_name(&self) -> &str {
        &self.cipherbft.native_token.name
    }

    /// Get the native token symbol (e.g., "CPH").
    pub fn native_token_symbol(&self) -> &str {
        &self.cipherbft.native_token.symbol
    }

    /// Get the native token decimals (typically 18).
    pub fn native_token_decimals(&self) -> u8 {
        self.cipherbft.native_token.decimals
    }

    /// Validate the genesis file for consistency.
    ///
    /// # Errors
    ///
    /// Returns errors for:
    /// - Zero or invalid chain ID
    /// - Zero gas limit
    /// - Invalid fork block ordering
    /// - Missing validators
    /// - Validator address not in alloc
    /// - Duplicate validator addresses
    /// - Zero total stake
    /// - Invalid key lengths
    /// - Stake below minimum
    pub fn validate(&self) -> Result<(), GenesisError> {
        // Validate Geth config
        self.config.validate().map_err(GenesisError::Config)?;

        // Gas limit must be > 0
        if self.gas_limit == U256::ZERO {
            return Err(GenesisError::InvalidField {
                field: "gasLimit",
                reason: "must be greater than zero".into(),
            });
        }

        // Must have at least one validator
        if self.cipherbft.validators.is_empty() {
            return Err(GenesisError::MissingField("cipherbft.validators"));
        }

        // Check for duplicate validators
        let mut seen_addresses = std::collections::HashSet::new();
        for validator in &self.cipherbft.validators {
            if !seen_addresses.insert(validator.address) {
                return Err(GenesisError::DuplicateValidator(validator.address));
            }
        }

        // Validate each validator
        for validator in &self.cipherbft.validators {
            // Validator must be in alloc
            if !self.alloc.contains_key(&validator.address) {
                return Err(GenesisError::ValidatorNotInAlloc(validator.address));
            }

            // Validate Ed25519 key length (32 bytes = 64 hex chars, or 66 with 0x prefix)
            let ed_key = validator.ed25519_pubkey.trim_start_matches("0x");
            if ed_key.len() != 64 {
                return Err(GenesisError::InvalidEd25519Key(
                    validator.address,
                    format!("expected 64 hex chars, got {}", ed_key.len()),
                ));
            }

            // Validate BLS key length (48 bytes = 96 hex chars, or 98 with 0x prefix)
            let bls_key = validator.bls_pubkey.trim_start_matches("0x");
            if bls_key.len() != 96 {
                return Err(GenesisError::InvalidBlsKey(
                    validator.address,
                    format!("expected 96 hex chars, got {}", bls_key.len()),
                ));
            }

            // Check stake meets minimum
            if validator.staked_amount < self.cipherbft.staking.min_stake_wei {
                return Err(GenesisError::StakeBelowMinimum {
                    addr: validator.address,
                    stake: validator.staked_amount,
                    min: self.cipherbft.staking.min_stake_wei,
                });
            }
        }

        // Total stake must be > 0
        if self.total_staked() == U256::ZERO {
            return Err(GenesisError::ZeroTotalStake);
        }

        // Validate CipherBFT config
        self.cipherbft.validate()?;

        Ok(())
    }
}

// ============================================================================
// CipherBFT Extension Types
// ============================================================================

/// Native token metadata configuration.
///
/// Similar to ERC20's `name()`, `symbol()`, and `decimals()` methods,
/// this provides standard metadata for the chain's native token.
/// This allows block explorers, wallets, and other tools to correctly
/// identify and display the native token.
///
/// # Example
///
/// ```json
/// {
///   "native_token": {
///     "name": "Cipher",
///     "symbol": "CPH",
///     "decimals": 18
///   }
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeTokenConfig {
    /// Human-readable name of the native token (e.g., "Cipher", "Ether").
    #[serde(default = "default_native_token_name")]
    pub name: String,

    /// Token symbol for display (e.g., "CPH", "ETH").
    /// Typically 3-5 uppercase characters.
    #[serde(default = "default_native_token_symbol")]
    pub symbol: String,

    /// Number of decimal places (standard: 18 for EVM compatibility).
    #[serde(default = "default_native_token_decimals")]
    pub decimals: u8,
}

impl Default for NativeTokenConfig {
    fn default() -> Self {
        Self {
            name: default_native_token_name(),
            symbol: default_native_token_symbol(),
            decimals: default_native_token_decimals(),
        }
    }
}

fn default_native_token_name() -> String {
    "Cipher".to_string()
}

fn default_native_token_symbol() -> String {
    "CPH".to_string()
}

fn default_native_token_decimals() -> u8 {
    18
}

/// CipherBFT-specific configuration namespace.
///
/// Contains BFT consensus, DCL, staking parameters, and the initial validator set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CipherBftConfig {
    /// Network genesis timestamp in RFC3339 format.
    pub genesis_time: String,

    /// Network identifier (e.g., "cipherbft-mainnet-1").
    pub network_id: String,

    /// Native token metadata (name, symbol, decimals).
    /// Provides ERC20-like identity for the chain's native currency.
    #[serde(default)]
    pub native_token: NativeTokenConfig,

    /// BFT consensus parameters.
    #[serde(default)]
    pub consensus: ConsensusParams,

    /// Data Chain Layer parameters.
    #[serde(default)]
    pub dcl: DclParams,

    /// Staking system parameters.
    #[serde(default)]
    pub staking: StakingParams,

    /// Initial validator set.
    pub validators: Vec<GenesisValidator>,
}

impl CipherBftConfig {
    /// Validate the CipherBFT configuration.
    pub fn validate(&self) -> Result<(), GenesisError> {
        // Network ID must not be empty
        if self.network_id.is_empty() {
            return Err(GenesisError::InvalidField {
                field: "cipherbft.network_id",
                reason: "cannot be empty".into(),
            });
        }

        // Genesis time should be valid RFC3339
        chrono::DateTime::parse_from_rfc3339(&self.genesis_time).map_err(|_| {
            GenesisError::InvalidField {
                field: "cipherbft.genesis_time",
                reason: "must be valid RFC3339 format".into(),
            }
        })?;

        // DCL attestation threshold must be valid
        if self.dcl.attestation_threshold_percent == 0
            || self.dcl.attestation_threshold_percent > 100
        {
            return Err(GenesisError::InvalidField {
                field: "cipherbft.dcl.attestation_threshold_percent",
                reason: "must be between 1 and 100".into(),
            });
        }

        Ok(())
    }
}

/// Malachite BFT consensus parameters (T010).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsensusParams {
    /// Target block production interval in milliseconds.
    #[serde(default = "default_target_block_time_ms")]
    pub target_block_time_ms: u64,

    /// Propose phase timeout in milliseconds.
    #[serde(default = "default_timeout_propose_ms")]
    pub timeout_propose_ms: u64,

    /// Prevote phase timeout in milliseconds.
    #[serde(default = "default_timeout_prevote_ms")]
    pub timeout_prevote_ms: u64,

    /// Precommit phase timeout in milliseconds.
    #[serde(default = "default_timeout_precommit_ms")]
    pub timeout_precommit_ms: u64,
}

impl Default for ConsensusParams {
    fn default() -> Self {
        Self {
            target_block_time_ms: default_target_block_time_ms(),
            timeout_propose_ms: default_timeout_propose_ms(),
            timeout_prevote_ms: default_timeout_prevote_ms(),
            timeout_precommit_ms: default_timeout_precommit_ms(),
        }
    }
}

fn default_target_block_time_ms() -> u64 {
    2000
}
fn default_timeout_propose_ms() -> u64 {
    3000
}
fn default_timeout_prevote_ms() -> u64 {
    1000
}
fn default_timeout_precommit_ms() -> u64 {
    1000
}

/// Data Chain Layer parameters (T011).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DclParams {
    /// Enable DCL features.
    #[serde(default = "default_dcl_enabled")]
    pub enabled: bool,

    /// CAR creation interval in milliseconds.
    #[serde(default = "default_car_interval_ms")]
    pub car_interval_ms: u64,

    /// Maximum transactions per batch.
    #[serde(default = "default_max_batch_txs")]
    pub max_batch_txs: u64,

    /// Maximum batch size in bytes.
    #[serde(default = "default_max_batch_bytes")]
    pub max_batch_bytes: u64,

    /// BFT attestation threshold percentage (1-100).
    #[serde(default = "default_attestation_threshold_percent")]
    pub attestation_threshold_percent: u8,
}

impl Default for DclParams {
    fn default() -> Self {
        Self {
            enabled: default_dcl_enabled(),
            car_interval_ms: default_car_interval_ms(),
            max_batch_txs: default_max_batch_txs(),
            max_batch_bytes: default_max_batch_bytes(),
            attestation_threshold_percent: default_attestation_threshold_percent(),
        }
    }
}

fn default_dcl_enabled() -> bool {
    true
}
fn default_car_interval_ms() -> u64 {
    100
}
fn default_max_batch_txs() -> u64 {
    100
}
fn default_max_batch_bytes() -> u64 {
    1_048_576 // 1 MB
}
fn default_attestation_threshold_percent() -> u8 {
    67
}

/// Staking system parameters (T012).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StakingParams {
    /// Minimum stake in wei (default: 1 CPH).
    #[serde(default = "default_min_stake_wei", with = "u256_quantity")]
    pub min_stake_wei: U256,

    /// Unbonding period in seconds (default: 7 days).
    #[serde(default = "default_unbonding_period_seconds")]
    pub unbonding_period_seconds: u64,

    /// Slashing penalty percentage (0-100).
    #[serde(default = "default_slashing_fraction_percent")]
    pub slashing_fraction_percent: u8,

    /// Block reward per epoch in wei (default: 2 CPH per epoch).
    /// This is the total reward minted and distributed to validators at each epoch boundary.
    /// CPH is the native token of the CipherBFT network (symbol: $CPH).
    #[serde(default = "default_epoch_block_reward_wei", with = "u256_quantity")]
    pub epoch_block_reward_wei: U256,

    /// Fee distribution mode: "burn" (EIP-1559 style) or "distribute" (to validators).
    /// - "burn": Transaction fees are burned, reducing total supply
    /// - "distribute": Transaction fees are distributed to validators proportionally
    #[serde(default = "default_fee_distribution_mode")]
    pub fee_distribution_mode: String,

    /// Treasury address for ecosystem funding (optional).
    /// If set, initial supply will be minted to this address at genesis.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub treasury_address: Option<Address>,

    /// Initial treasury supply in wei (optional).
    /// Only used if treasury_address is also set.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "opt_u256_quantity"
    )]
    pub initial_treasury_supply_wei: Option<U256>,
}

impl Default for StakingParams {
    fn default() -> Self {
        Self {
            min_stake_wei: default_min_stake_wei(),
            unbonding_period_seconds: default_unbonding_period_seconds(),
            slashing_fraction_percent: default_slashing_fraction_percent(),
            epoch_block_reward_wei: default_epoch_block_reward_wei(),
            fee_distribution_mode: default_fee_distribution_mode(),
            treasury_address: None,
            initial_treasury_supply_wei: None,
        }
    }
}

fn default_min_stake_wei() -> U256 {
    U256::from(1_000_000_000_000_000_000u128) // 1 CPH
}
fn default_unbonding_period_seconds() -> u64 {
    604_800 // 7 days
}
fn default_slashing_fraction_percent() -> u8 {
    1
}
fn default_epoch_block_reward_wei() -> U256 {
    U256::from(2_000_000_000_000_000_000u128) // 2 CPH per epoch
}
fn default_fee_distribution_mode() -> String {
    "distribute".to_string()
}

/// Genesis validator definition with dual cryptographic keys (T013).
///
/// Each validator has:
/// - Ed25519 key for Malachite consensus (32 bytes)
/// - BLS12-381 key for DCL attestations (48 bytes)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenesisValidator {
    /// Validator's EVM address (20 bytes).
    pub address: Address,

    /// Human-readable name/moniker (optional).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Ed25519 public key for consensus (hex encoded, 64 chars / 32 bytes).
    pub ed25519_pubkey: String,

    /// BLS12-381 public key for DCL attestations (hex encoded, 96 chars / 48 bytes).
    pub bls_pubkey: String,

    /// Staked amount in wei.
    #[serde(with = "u256_quantity")]
    pub staked_amount: U256,

    /// Commission rate percentage (0-100, default: 10).
    #[serde(default = "default_commission_rate_percent")]
    pub commission_rate_percent: u8,
}

fn default_commission_rate_percent() -> u8 {
    10
}

// ============================================================================
// Error Types (T017)
// ============================================================================

/// Genesis file errors.
///
/// Provides structured error types for all genesis-related operations,
/// with actionable error messages per SC-007.
#[derive(Debug, thiserror::Error)]
pub enum GenesisError {
    /// File not found or I/O error.
    #[error("Genesis file I/O error: {path}: {message}")]
    Io { path: PathBuf, message: String },

    /// JSON parsing error.
    #[error("Failed to parse genesis JSON: {0}")]
    ParseError(String),

    /// JSON serialization error.
    #[error("Failed to serialize genesis: {0}")]
    SerdeError(String),

    /// Missing required field.
    #[error("Missing required field: {0}")]
    MissingField(&'static str),

    /// Invalid field value.
    #[error("Invalid {field}: {reason}")]
    InvalidField { field: &'static str, reason: String },

    /// Validator address not in alloc.
    #[error("Validator {0} not found in alloc")]
    ValidatorNotInAlloc(Address),

    /// Duplicate validator address.
    #[error("Duplicate validator address: {0}")]
    DuplicateValidator(Address),

    /// Stake below minimum.
    #[error("Validator {addr} stake {stake} below minimum {min}")]
    StakeBelowMinimum {
        addr: Address,
        stake: U256,
        min: U256,
    },

    /// Zero total stake.
    #[error("Total stake cannot be zero")]
    ZeroTotalStake,

    /// Invalid Ed25519 public key.
    #[error("Invalid Ed25519 public key for validator {0}: {1}")]
    InvalidEd25519Key(Address, String),

    /// Invalid BLS public key.
    #[error("Invalid BLS public key for validator {0}: {1}")]
    InvalidBlsKey(Address, String),

    /// Geth config validation error.
    #[error("Invalid chain config: {0}")]
    Config(#[from] GethConfigError),
}

// ============================================================================
// Bootstrap Result (T018)
// ============================================================================

/// Result of genesis bootstrap operation.
///
/// Returned by `GenesisBootstrap::bootstrap()` after successful system initialization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapResult {
    /// Number of validators registered.
    pub validator_count: usize,

    /// Total staked amount (wei).
    pub total_staked: U256,

    /// Number of accounts initialized from alloc.
    pub account_count: usize,

    /// EVM chain ID.
    pub chain_id: u64,

    /// Genesis block hash.
    pub genesis_hash: B256,
}

impl BootstrapResult {
    /// Create a new bootstrap result.
    pub fn new(
        validator_count: usize,
        total_staked: U256,
        account_count: usize,
        chain_id: u64,
        genesis_hash: B256,
    ) -> Self {
        Self {
            validator_count,
            total_staked,
            account_count,
            chain_id,
            genesis_hash,
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn sample_validator() -> GenesisValidator {
        GenesisValidator {
            address: Address::from_str("0x742d35Cc6634C0532925a3b844Bc9e7595f0bC01").unwrap(),
            name: Some("validator-1".to_string()),
            ed25519_pubkey: "0x".to_owned() + &"a".repeat(64), // 32 bytes
            bls_pubkey: "0x".to_owned() + &"b".repeat(96),     // 48 bytes
            staked_amount: U256::from(32_000_000_000_000_000_000u128), // 32 CPH
            commission_rate_percent: 10,
        }
    }

    fn sample_genesis() -> Genesis {
        let validator = sample_validator();
        let mut alloc = HashMap::new();
        alloc.insert(
            validator.address,
            AllocEntry::new(U256::from(100_000_000_000_000_000_000u128)),
        );

        Genesis {
            config: GethConfig::new(85300),
            alloc,
            gas_limit: U256::from(30_000_000u64),
            difficulty: U256::from(1u64),
            nonce: Some(U256::ZERO),
            timestamp: Some(U256::ZERO),
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
                validators: vec![validator],
            },
        }
    }

    #[test]
    fn test_genesis_serialization() {
        let genesis = sample_genesis();
        let json = genesis.to_json().unwrap();
        assert!(json.contains("\"chainId\": 85300"));
        assert!(json.contains("\"cipherbft\""));
        assert!(json.contains("\"validators\""));
    }

    #[test]
    fn test_genesis_deserialization() {
        let genesis = sample_genesis();
        let json = genesis.to_json().unwrap();
        let parsed = Genesis::from_json(&json).unwrap();
        assert_eq!(parsed.config.chain_id, 85300);
        assert_eq!(parsed.cipherbft.validators.len(), 1);
        assert_eq!(parsed.cipherbft.network_id, "cipherbft-testnet-1");
    }

    #[test]
    fn test_genesis_validation_success() {
        let genesis = sample_genesis();
        assert!(genesis.validate().is_ok());
    }

    #[test]
    fn test_genesis_validation_missing_validator() {
        let mut genesis = sample_genesis();
        genesis.cipherbft.validators = vec![];
        assert!(matches!(
            genesis.validate(),
            Err(GenesisError::MissingField(_))
        ));
    }

    #[test]
    fn test_genesis_validation_validator_not_in_alloc() {
        let mut genesis = sample_genesis();
        genesis.alloc.clear();
        assert!(matches!(
            genesis.validate(),
            Err(GenesisError::ValidatorNotInAlloc(_))
        ));
    }

    #[test]
    fn test_genesis_validation_duplicate_validator() {
        let mut genesis = sample_genesis();
        let validator = genesis.cipherbft.validators[0].clone();
        genesis.cipherbft.validators.push(validator);
        assert!(matches!(
            genesis.validate(),
            Err(GenesisError::DuplicateValidator(_))
        ));
    }

    #[test]
    fn test_genesis_validation_invalid_ed25519_key() {
        let mut genesis = sample_genesis();
        genesis.cipherbft.validators[0].ed25519_pubkey = "0xshort".to_string();
        assert!(matches!(
            genesis.validate(),
            Err(GenesisError::InvalidEd25519Key(_, _))
        ));
    }

    #[test]
    fn test_genesis_validation_invalid_bls_key() {
        let mut genesis = sample_genesis();
        genesis.cipherbft.validators[0].bls_pubkey = "0xshort".to_string();
        assert!(matches!(
            genesis.validate(),
            Err(GenesisError::InvalidBlsKey(_, _))
        ));
    }

    #[test]
    fn test_genesis_validation_stake_below_minimum() {
        let mut genesis = sample_genesis();
        genesis.cipherbft.validators[0].staked_amount = U256::from(1u64); // Far below 1 CPH
        assert!(matches!(
            genesis.validate(),
            Err(GenesisError::StakeBelowMinimum { .. })
        ));
    }

    #[test]
    fn test_total_staked() {
        let genesis = sample_genesis();
        assert_eq!(
            genesis.total_staked(),
            U256::from(32_000_000_000_000_000_000u128)
        );
    }

    #[test]
    fn test_validator_count() {
        let genesis = sample_genesis();
        assert_eq!(genesis.validator_count(), 1);
    }

    #[test]
    fn test_native_token_metadata() {
        let genesis = sample_genesis();

        // Default native token should be CPH
        assert_eq!(genesis.native_token_name(), "Cipher");
        assert_eq!(genesis.native_token_symbol(), "CPH");
        assert_eq!(genesis.native_token_decimals(), 18);

        // Custom native token config
        let custom = NativeTokenConfig {
            name: "TestToken".to_string(),
            symbol: "TST".to_string(),
            decimals: 6,
        };
        assert_eq!(custom.name, "TestToken");
        assert_eq!(custom.symbol, "TST");
        assert_eq!(custom.decimals, 6);
    }

    #[test]
    fn test_consensus_params_defaults() {
        let params = ConsensusParams::default();
        assert_eq!(params.target_block_time_ms, 2000);
        assert_eq!(params.timeout_propose_ms, 3000);
    }

    #[test]
    fn test_dcl_params_defaults() {
        let params = DclParams::default();
        assert!(params.enabled);
        assert_eq!(params.car_interval_ms, 100);
        assert_eq!(params.attestation_threshold_percent, 67);
    }

    #[test]
    fn test_staking_params_defaults() {
        let params = StakingParams::default();
        assert_eq!(
            params.min_stake_wei,
            U256::from(1_000_000_000_000_000_000u128)
        );
        assert_eq!(params.unbonding_period_seconds, 604_800);
    }

    #[test]
    fn test_bootstrap_result() {
        let result = BootstrapResult::new(
            4,
            U256::from(128_000_000_000_000_000_000u128),
            10,
            85300,
            B256::ZERO,
        );
        assert_eq!(result.validator_count, 4);
        assert_eq!(result.chain_id, 85300);
    }

    #[test]
    fn test_geth_compatible_json_format() {
        let genesis = sample_genesis();
        let json = genesis.to_json().unwrap();

        // Verify Geth-compatible top-level structure
        assert!(json.contains("\"config\""));
        assert!(json.contains("\"alloc\""));
        assert!(json.contains("\"gasLimit\""));
        assert!(json.contains("\"difficulty\""));

        // Verify CipherBFT extension
        assert!(json.contains("\"cipherbft\""));
        assert!(json.contains("\"genesis_time\""));
        assert!(json.contains("\"network_id\""));
        assert!(json.contains("\"validators\""));
    }
}
