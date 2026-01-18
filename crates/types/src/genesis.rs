//! Genesis file types for CipherBFT.
//!
//! Defines the structure of the genesis file which specifies the initial state
//! of the blockchain network including validators, accounts, and chain parameters.
//!
//! # Format
//!
//! The genesis file uses JSON format for human readability and tooling support.
//! Large integers (U256) are encoded as hex strings to avoid precision loss.
//!
//! # Example
//!
//! ```json
//! {
//!   "genesis_time": "2024-01-15T00:00:00Z",
//!   "chain_id": "cipherbft-testnet-1",
//!   "validators": [...],
//!   "accounts": [...]
//! }
//! ```

use serde::{Deserialize, Serialize};

/// Complete genesis file structure.
///
/// Contains all information needed to initialize a new CipherBFT network.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Genesis {
    /// JSON Schema URL for validation (optional).
    #[serde(rename = "$schema", skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,

    /// Genesis time in RFC3339 format with nanosecond precision.
    ///
    /// Example: "2024-01-15T00:00:00.000000000Z"
    pub genesis_time: String,

    /// Unique identifier for this blockchain network.
    ///
    /// Format: `{name}-{network}-{version}` (e.g., "cipherbft-mainnet-1")
    pub chain_id: String,

    /// Initial block height (usually 1, can be higher for chain migrations).
    #[serde(default = "default_initial_height")]
    pub initial_height: u64,

    /// Consensus layer parameters (Malachite BFT).
    pub consensus_params: ConsensusParams,

    /// Execution layer parameters (EVM).
    pub execution_params: ExecutionParams,

    /// Staking system parameters.
    pub staking_params: StakingParams,

    /// Data Chain Layer parameters.
    pub dcl_params: DclParams,

    /// Initial validator set.
    pub validators: Vec<GenesisValidator>,

    /// Initial account balances.
    #[serde(default)]
    pub accounts: Vec<GenesisAccount>,

    /// Pre-deployed contracts (optional, for testnets).
    #[serde(default)]
    pub contracts: Vec<GenesisContract>,

    /// Initial app state hash (usually zeros for fresh chains).
    #[serde(default = "default_app_hash")]
    pub app_hash: String,
}

fn default_initial_height() -> u64 {
    1
}

fn default_app_hash() -> String {
    "0x0000000000000000000000000000000000000000000000000000000000000000".to_string()
}

/// Consensus layer parameters for Malachite BFT.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusParams {
    /// Block-related parameters.
    pub block: BlockParams,

    /// Evidence handling parameters.
    pub evidence: EvidenceParams,

    /// Validator configuration.
    pub validator: ValidatorParams,

    /// Protocol version info.
    #[serde(default)]
    pub version: VersionParams,
}

/// Block production parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockParams {
    /// Maximum gas per block.
    #[serde(default = "default_max_gas")]
    pub max_gas: u64,

    /// Minimum time between blocks in milliseconds.
    #[serde(default = "default_time_iota_ms")]
    pub time_iota_ms: u64,

    /// Target block time in milliseconds (for timeout calculations).
    #[serde(default = "default_target_block_time_ms")]
    pub target_block_time_ms: u64,
}

fn default_max_gas() -> u64 {
    30_000_000
}

fn default_time_iota_ms() -> u64 {
    1000
}

fn default_target_block_time_ms() -> u64 {
    2000
}

/// Evidence handling parameters for Byzantine behavior detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceParams {
    /// Maximum age of evidence in blocks.
    #[serde(default = "default_max_age_num_blocks")]
    pub max_age_num_blocks: u64,

    /// Maximum age of evidence in nanoseconds.
    #[serde(default = "default_max_age_duration_ns")]
    pub max_age_duration_ns: u64,
}

fn default_max_age_num_blocks() -> u64 {
    100_000
}

fn default_max_age_duration_ns() -> u64 {
    172_800_000_000_000 // 2 days
}

/// Validator cryptographic configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorParams {
    /// Supported public key types.
    ///
    /// CipherBFT requires both "ed25519" (consensus) and "bls12-381" (DCL).
    #[serde(default = "default_pub_key_types")]
    pub pub_key_types: Vec<String>,
}

fn default_pub_key_types() -> Vec<String> {
    vec!["ed25519".to_string(), "bls12-381".to_string()]
}

/// Protocol version parameters.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VersionParams {
    /// Application version string.
    #[serde(default)]
    pub app: String,
}

/// Execution layer (EVM) parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionParams {
    /// EVM chain ID for transaction signing (default: 31337).
    #[serde(default = "default_evm_chain_id")]
    pub chain_id: u64,

    /// Block gas limit (default: 30M).
    #[serde(default = "default_block_gas_limit")]
    pub block_gas_limit: u64,

    /// Base fee per gas in wei (EIP-1559, default: 1 gwei).
    ///
    /// Stored as string to avoid JSON precision issues with large numbers.
    #[serde(default = "default_base_fee")]
    pub base_fee_per_gas: String,

    /// State root computation interval in blocks (default: 100).
    #[serde(default = "default_state_root_interval")]
    pub state_root_interval: u64,

    /// Delayed commitment depth (default: 2).
    ///
    /// Block N includes the hash of block N-2 for finality.
    #[serde(default = "default_delayed_commitment_depth")]
    pub delayed_commitment_depth: u64,

    /// EVM version / hard fork (default: "cancun").
    ///
    /// Supported: "shanghai", "cancun"
    #[serde(default = "default_evm_version")]
    pub evm_version: String,
}

fn default_evm_chain_id() -> u64 {
    31337
}

fn default_block_gas_limit() -> u64 {
    30_000_000
}

fn default_base_fee() -> String {
    "1000000000".to_string() // 1 gwei
}

fn default_state_root_interval() -> u64 {
    100
}

fn default_delayed_commitment_depth() -> u64 {
    2
}

fn default_evm_version() -> String {
    "cancun".to_string()
}

/// Staking system parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StakingParams {
    /// Minimum stake amount in wei (default: 1 ETH = 1e18).
    ///
    /// Stored as string for U256 precision.
    #[serde(default = "default_min_stake")]
    pub min_stake_wei: String,

    /// Unbonding period in seconds (default: 3 days = 259200).
    #[serde(default = "default_unbonding_period")]
    pub unbonding_period_seconds: u64,

    /// Maximum number of active validators.
    #[serde(default = "default_max_validators")]
    pub max_validators: u32,

    /// Slashing fraction for double-signing (default: 1% = "0.01").
    #[serde(default = "default_slashing_fraction")]
    pub slashing_fraction: String,

    /// Jail duration for slashed validators in seconds.
    #[serde(default = "default_jail_duration")]
    pub jail_duration_seconds: u64,
}

fn default_min_stake() -> String {
    "1000000000000000000".to_string() // 1 ETH
}

fn default_unbonding_period() -> u64 {
    259_200 // 3 days
}

fn default_max_validators() -> u32 {
    100
}

fn default_slashing_fraction() -> String {
    "0.01".to_string()
}

fn default_jail_duration() -> u64 {
    86_400 // 1 day
}

/// Data Chain Layer parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DclParams {
    /// CAR creation interval in milliseconds.
    #[serde(default = "default_car_interval")]
    pub car_interval_ms: u64,

    /// Maximum transactions per batch.
    #[serde(default = "default_max_batch_txs")]
    pub max_batch_txs: u64,

    /// Maximum batch size in bytes.
    #[serde(default = "default_max_batch_bytes")]
    pub max_batch_bytes: u64,

    /// Attestation threshold (fraction of voting power required).
    ///
    /// Default: "0.67" (2/3+1 for BFT)
    #[serde(default = "default_attestation_threshold")]
    pub attestation_threshold: String,

    /// Number of worker threads per node.
    #[serde(default = "default_num_workers")]
    pub num_workers: u32,
}

fn default_car_interval() -> u64 {
    100
}

fn default_max_batch_txs() -> u64 {
    100
}

fn default_max_batch_bytes() -> u64 {
    1_048_576 // 1 MB
}

fn default_attestation_threshold() -> String {
    "0.67".to_string()
}

fn default_num_workers() -> u32 {
    4
}

/// Genesis validator definition.
///
/// Each validator has dual keys: Ed25519 for consensus and BLS for DCL.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisValidator {
    /// Validator's Ethereum-style address (20 bytes hex).
    pub address: String,

    /// Human-readable name/moniker.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Ed25519 public key for Malachite consensus (base64 encoded, 32 bytes).
    pub ed25519_pubkey: String,

    /// BLS12-381 public key for DCL attestations (hex encoded, 48 bytes).
    pub bls_pubkey: String,

    /// Voting power (stake weight).
    pub power: String,

    /// Commission rate as decimal string (e.g., "0.10" = 10%).
    #[serde(default = "default_commission_rate")]
    pub commission_rate: String,
}

fn default_commission_rate() -> String {
    "0.10".to_string()
}

/// Genesis account with initial balance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisAccount {
    /// Account address (0x-prefixed hex, 20 bytes).
    pub address: String,

    /// Initial balance in wei (string for U256 precision).
    pub balance: String,

    /// Account nonce (optional, default 0).
    #[serde(default)]
    pub nonce: u64,
}

/// Pre-deployed contract in genesis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisContract {
    /// Contract address.
    pub address: String,

    /// Contract bytecode (hex encoded).
    pub code: String,

    /// Initial storage (key-value pairs, both hex encoded).
    #[serde(default)]
    pub storage: Vec<StorageEntry>,

    /// Initial balance in wei.
    #[serde(default)]
    pub balance: String,
}

/// Storage entry for pre-deployed contracts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageEntry {
    /// Storage slot key (hex encoded, 32 bytes).
    pub key: String,

    /// Storage value (hex encoded, 32 bytes).
    pub value: String,
}

impl Genesis {
    /// Load genesis from a JSON file.
    pub fn load(path: &std::path::Path) -> Result<Self, GenesisError> {
        let content = std::fs::read_to_string(path).map_err(|e| GenesisError::Io(e.to_string()))?;
        Self::from_json(&content)
    }

    /// Parse genesis from JSON string.
    pub fn from_json(json: &str) -> Result<Self, GenesisError> {
        serde_json::from_str(json).map_err(|e| GenesisError::Parse(e.to_string()))
    }

    /// Serialize to JSON string.
    pub fn to_json(&self) -> Result<String, GenesisError> {
        serde_json::to_string_pretty(self).map_err(|e| GenesisError::Serialize(e.to_string()))
    }

    /// Save genesis to a file.
    pub fn save(&self, path: &std::path::Path) -> Result<(), GenesisError> {
        let json = self.to_json()?;
        std::fs::write(path, json).map_err(|e| GenesisError::Io(e.to_string()))
    }

    /// Validate the genesis file for consistency.
    pub fn validate(&self) -> Result<(), GenesisError> {
        // Chain ID must not be empty
        if self.chain_id.is_empty() {
            return Err(GenesisError::Validation("chain_id cannot be empty".into()));
        }

        // Must have at least one validator
        if self.validators.is_empty() {
            return Err(GenesisError::Validation(
                "genesis must have at least one validator".into(),
            ));
        }

        // Validate each validator
        for (i, v) in self.validators.iter().enumerate() {
            // Address must be valid hex
            if !v.address.starts_with("0x") || v.address.len() != 42 {
                return Err(GenesisError::Validation(format!(
                    "validator {} has invalid address format",
                    i
                )));
            }

            // Ed25519 key must be valid base64 (32 bytes = ~44 chars)
            if v.ed25519_pubkey.is_empty() {
                return Err(GenesisError::Validation(format!(
                    "validator {} missing ed25519_pubkey",
                    i
                )));
            }

            // BLS key must be valid hex (48 bytes = 96 hex chars)
            if v.bls_pubkey.len() != 96 && !v.bls_pubkey.starts_with("0x") {
                // Allow 0x prefix
                if v.bls_pubkey.len() != 98 {
                    return Err(GenesisError::Validation(format!(
                        "validator {} has invalid bls_pubkey length (expected 48 bytes)",
                        i
                    )));
                }
            }

            // Power must be positive
            if v.power.parse::<u64>().unwrap_or(0) == 0 {
                return Err(GenesisError::Validation(format!(
                    "validator {} must have positive voting power",
                    i
                )));
            }
        }

        // Validate accounts
        for (i, a) in self.accounts.iter().enumerate() {
            if !a.address.starts_with("0x") || a.address.len() != 42 {
                return Err(GenesisError::Validation(format!(
                    "account {} has invalid address format",
                    i
                )));
            }
        }

        Ok(())
    }

    /// Get total voting power of all validators.
    pub fn total_voting_power(&self) -> u64 {
        self.validators
            .iter()
            .filter_map(|v| v.power.parse::<u64>().ok())
            .sum()
    }

    /// Create a minimal genesis for testing.
    pub fn testnet(chain_id: &str, validators: Vec<GenesisValidator>) -> Self {
        Self {
            schema: None,
            genesis_time: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Nanos, true),
            chain_id: chain_id.to_string(),
            initial_height: 1,
            consensus_params: ConsensusParams {
                block: BlockParams {
                    max_gas: default_max_gas(),
                    time_iota_ms: default_time_iota_ms(),
                    target_block_time_ms: default_target_block_time_ms(),
                },
                evidence: EvidenceParams {
                    max_age_num_blocks: default_max_age_num_blocks(),
                    max_age_duration_ns: default_max_age_duration_ns(),
                },
                validator: ValidatorParams {
                    pub_key_types: default_pub_key_types(),
                },
                version: VersionParams::default(),
            },
            execution_params: ExecutionParams {
                chain_id: default_evm_chain_id(),
                block_gas_limit: default_block_gas_limit(),
                base_fee_per_gas: default_base_fee(),
                state_root_interval: default_state_root_interval(),
                delayed_commitment_depth: default_delayed_commitment_depth(),
                evm_version: default_evm_version(),
            },
            staking_params: StakingParams {
                min_stake_wei: default_min_stake(),
                unbonding_period_seconds: default_unbonding_period(),
                max_validators: default_max_validators(),
                slashing_fraction: default_slashing_fraction(),
                jail_duration_seconds: default_jail_duration(),
            },
            dcl_params: DclParams {
                car_interval_ms: default_car_interval(),
                max_batch_txs: default_max_batch_txs(),
                max_batch_bytes: default_max_batch_bytes(),
                attestation_threshold: default_attestation_threshold(),
                num_workers: default_num_workers(),
            },
            validators,
            accounts: vec![],
            contracts: vec![],
            app_hash: default_app_hash(),
        }
    }
}

/// Genesis file errors.
#[derive(Debug, Clone)]
pub enum GenesisError {
    /// I/O error reading/writing file.
    Io(String),
    /// JSON parsing error.
    Parse(String),
    /// JSON serialization error.
    Serialize(String),
    /// Validation error.
    Validation(String),
}

impl std::fmt::Display for GenesisError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error: {}", e),
            Self::Parse(e) => write!(f, "Parse error: {}", e),
            Self::Serialize(e) => write!(f, "Serialize error: {}", e),
            Self::Validation(e) => write!(f, "Validation error: {}", e),
        }
    }
}

impl std::error::Error for GenesisError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_genesis() -> Genesis {
        Genesis::testnet(
            "cipherbft-test-1",
            vec![GenesisValidator {
                address: "0x1234567890abcdef1234567890abcdef12345678".to_string(),
                name: Some("validator-0".to_string()),
                ed25519_pubkey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string(),
                bls_pubkey: "0".repeat(96),
                power: "100".to_string(),
                commission_rate: "0.10".to_string(),
            }],
        )
    }

    #[test]
    fn test_genesis_serialization() {
        let genesis = sample_genesis();
        let json = genesis.to_json().unwrap();
        assert!(json.contains("cipherbft-test-1"));
        assert!(json.contains("validators"));
    }

    #[test]
    fn test_genesis_deserialization() {
        let genesis = sample_genesis();
        let json = genesis.to_json().unwrap();
        let parsed = Genesis::from_json(&json).unwrap();
        assert_eq!(parsed.chain_id, genesis.chain_id);
        assert_eq!(parsed.validators.len(), 1);
    }

    #[test]
    fn test_genesis_validation() {
        let genesis = sample_genesis();
        assert!(genesis.validate().is_ok());
    }

    #[test]
    fn test_genesis_validation_empty_chain_id() {
        let mut genesis = sample_genesis();
        genesis.chain_id = "".to_string();
        assert!(genesis.validate().is_err());
    }

    #[test]
    fn test_genesis_validation_no_validators() {
        let mut genesis = sample_genesis();
        genesis.validators = vec![];
        assert!(genesis.validate().is_err());
    }

    #[test]
    fn test_total_voting_power() {
        let genesis = sample_genesis();
        assert_eq!(genesis.total_voting_power(), 100);
    }

    #[test]
    fn test_default_params() {
        let genesis = sample_genesis();
        assert_eq!(genesis.execution_params.chain_id, 31337);
        assert_eq!(genesis.execution_params.block_gas_limit, 30_000_000);
        assert_eq!(genesis.staking_params.max_validators, 100);
        assert_eq!(genesis.dcl_params.car_interval_ms, 100);
    }
}
