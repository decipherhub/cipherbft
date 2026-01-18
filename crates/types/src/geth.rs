//! Geth-compatible types for CipherBFT genesis files.
//!
//! This module provides types that are compatible with Ethereum Geth's genesis format,
//! allowing CipherBFT genesis files to be used with standard EVM tooling like Foundry
//! and Hardhat.
//!
//! # Design
//!
//! The Geth genesis format is extended with a `cipherbft` namespace that contains
//! BFT consensus and DCL-specific configuration. Geth tools ignore unknown fields,
//! so our extension is backward-compatible.
//!
//! # Example
//!
//! ```json
//! {
//!   "config": { "chainId": 85300 },
//!   "alloc": { "0x...": { "balance": "0x..." } },
//!   "gasLimit": "0x1c9c380",
//!   "difficulty": "0x1",
//!   "cipherbft": { ... }
//! }
//! ```

use alloy_primitives::{Bytes, B256, U256};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// Custom serde module for U256 as hex quantity (Geth-compatible format)
mod u256_quantity {
    use alloy_primitives::U256;
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &U256, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Serialize as "0x..." hex string without leading zeros
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

// Custom serde module for optional nonce as hex quantity
mod opt_nonce {
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &Option<u64>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(n) => serializer.serialize_str(&format!("{:#x}", n)),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt: Option<String> = Option::deserialize(deserializer)?;
        match opt {
            Some(s) => {
                let n = u64::from_str_radix(s.trim_start_matches("0x"), 16)
                    .map_err(serde::de::Error::custom)?;
                Ok(Some(n))
            }
            None => Ok(None),
        }
    }
}

/// Geth-compatible chain configuration.
///
/// Follows the structure of go-ethereum's `params.ChainConfig`. All fork blocks
/// default to 0 (enabled from genesis) for CipherBFT chains.
///
/// # Validation
///
/// - `chain_id` must be non-zero
/// - Fork blocks must be in non-decreasing order
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GethConfig {
    /// EVM chain ID for replay protection (EIP-155).
    pub chain_id: u64,

    /// Homestead hard fork block number.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub homestead_block: Option<u64>,

    /// EIP-150 (Gas price changes) hard fork block number.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub eip150_block: Option<u64>,

    /// EIP-155 (Replay protection) hard fork block number.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub eip155_block: Option<u64>,

    /// EIP-158 (State clearing) hard fork block number.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub eip158_block: Option<u64>,

    /// Byzantium hard fork block number.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub byzantium_block: Option<u64>,

    /// Constantinople hard fork block number.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub constantinople_block: Option<u64>,

    /// Petersburg hard fork block number.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub petersburg_block: Option<u64>,

    /// Istanbul hard fork block number.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub istanbul_block: Option<u64>,

    /// Berlin hard fork block number.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub berlin_block: Option<u64>,

    /// London (EIP-1559) hard fork block number.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub london_block: Option<u64>,

    /// Shanghai hard fork timestamp (seconds since epoch).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shanghai_time: Option<u64>,

    /// Cancun hard fork timestamp (seconds since epoch).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cancun_time: Option<u64>,
}

impl Default for GethConfig {
    fn default() -> Self {
        Self {
            chain_id: 31337, // Default local chain ID
            homestead_block: Some(0),
            eip150_block: Some(0),
            eip155_block: Some(0),
            eip158_block: Some(0),
            byzantium_block: Some(0),
            constantinople_block: Some(0),
            petersburg_block: Some(0),
            istanbul_block: Some(0),
            berlin_block: Some(0),
            london_block: Some(0),
            shanghai_time: Some(0),
            cancun_time: Some(0),
        }
    }
}

impl GethConfig {
    /// Create a new GethConfig with the specified chain ID and all forks enabled at genesis.
    pub fn new(chain_id: u64) -> Self {
        Self {
            chain_id,
            ..Default::default()
        }
    }

    /// Validate the chain configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `chain_id` is zero
    /// - Fork blocks are not in non-decreasing order
    pub fn validate(&self) -> Result<(), GethConfigError> {
        if self.chain_id == 0 {
            return Err(GethConfigError::ZeroChainId);
        }

        // Collect fork blocks in order for validation
        let fork_blocks: Vec<(&str, Option<u64>)> = vec![
            ("homesteadBlock", self.homestead_block),
            ("eip150Block", self.eip150_block),
            ("eip155Block", self.eip155_block),
            ("eip158Block", self.eip158_block),
            ("byzantiumBlock", self.byzantium_block),
            ("constantinopleBlock", self.constantinople_block),
            ("petersburgBlock", self.petersburg_block),
            ("istanbulBlock", self.istanbul_block),
            ("berlinBlock", self.berlin_block),
            ("londonBlock", self.london_block),
        ];

        let mut prev_block: Option<u64> = None;
        let mut prev_name: &str = "";

        for (name, block) in fork_blocks {
            if let (Some(prev), Some(curr)) = (prev_block, block) {
                if curr < prev {
                    return Err(GethConfigError::ForkOrderViolation {
                        earlier_fork: prev_name.to_string(),
                        earlier_block: prev,
                        later_fork: name.to_string(),
                        later_block: curr,
                    });
                }
            }
            if block.is_some() {
                prev_block = block;
                prev_name = name;
            }
        }

        Ok(())
    }
}

/// Errors that can occur when validating GethConfig.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GethConfigError {
    /// Chain ID cannot be zero.
    #[error("chain_id cannot be zero")]
    ZeroChainId,

    /// Fork blocks must be in non-decreasing order.
    #[error("{later_fork} ({later_block}) is before {earlier_fork} ({earlier_block})")]
    ForkOrderViolation {
        earlier_fork: String,
        earlier_block: u64,
        later_fork: String,
        later_block: u64,
    },
}

/// Initial account state in Geth genesis format.
///
/// Used in the `alloc` section to specify account balances, nonces, code,
/// and storage at genesis.
///
/// # Example
///
/// ```json
/// {
///   "balance": "0x6c6b935b8bbd400000",
///   "nonce": "0x0",
///   "code": "0x...",
///   "storage": { "0x0": "0x1" }
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct AllocEntry {
    /// Account balance in wei.
    #[serde(with = "u256_quantity")]
    pub balance: U256,

    /// Account nonce (transaction count).
    #[serde(default, skip_serializing_if = "is_zero_u64", with = "opt_nonce")]
    pub nonce: Option<u64>,

    /// Contract bytecode (empty for EOA accounts).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<Bytes>,

    /// Contract storage (key-value pairs).
    /// Keys and values are 32-byte hex strings.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub storage: HashMap<B256, B256>,
}

fn is_zero_u64(value: &Option<u64>) -> bool {
    value.is_none() || *value == Some(0)
}

impl AllocEntry {
    /// Create a new AllocEntry with the specified balance.
    pub fn new(balance: U256) -> Self {
        Self {
            balance,
            nonce: None,
            code: None,
            storage: HashMap::new(),
        }
    }

    /// Create a new contract AllocEntry with bytecode.
    pub fn contract(balance: U256, code: Bytes) -> Self {
        Self {
            balance,
            nonce: None,
            code: Some(code),
            storage: HashMap::new(),
        }
    }

    /// Add storage entries to this alloc entry.
    pub fn with_storage(mut self, storage: HashMap<B256, B256>) -> Self {
        self.storage = storage;
        self
    }

    /// Set the nonce for this alloc entry.
    pub fn with_nonce(mut self, nonce: u64) -> Self {
        self.nonce = Some(nonce);
        self
    }

    /// Check if this is a contract account (has code).
    pub fn is_contract(&self) -> bool {
        self.code.is_some() && !self.code.as_ref().unwrap().is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_geth_config_default() {
        let config = GethConfig::default();
        assert_eq!(config.chain_id, 31337);
        assert_eq!(config.cancun_time, Some(0));
    }

    #[test]
    fn test_geth_config_validation_zero_chain_id() {
        let config = GethConfig {
            chain_id: 0,
            ..Default::default()
        };
        assert_eq!(config.validate(), Err(GethConfigError::ZeroChainId));
    }

    #[test]
    fn test_geth_config_validation_fork_order() {
        let config = GethConfig {
            chain_id: 1,
            homestead_block: Some(100),
            eip150_block: Some(50), // Before homestead - invalid!
            ..Default::default()
        };
        let err = config.validate().unwrap_err();
        assert!(matches!(err, GethConfigError::ForkOrderViolation { .. }));
    }

    #[test]
    fn test_geth_config_serialization() {
        let config = GethConfig::new(85300);
        let json = serde_json::to_string_pretty(&config).unwrap();
        assert!(json.contains("\"chainId\": 85300"));
        assert!(json.contains("\"cancunTime\": 0"));
    }

    #[test]
    fn test_geth_config_deserialization() {
        let json = r#"{
            "chainId": 85300,
            "homesteadBlock": 0,
            "cancunTime": 0
        }"#;
        let config: GethConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.chain_id, 85300);
        assert_eq!(config.cancun_time, Some(0));
    }

    #[test]
    fn test_alloc_entry_balance_hex() {
        let entry = AllocEntry::new(U256::from(1000000000000000000u128)); // 1 ETH
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("\"balance\":\"0xde0b6b3a7640000\"")); // 1 ETH in hex
    }

    #[test]
    fn test_alloc_entry_deserialization() {
        let json = r#"{
            "balance": "0x6c6b935b8bbd400000",
            "nonce": "0x1"
        }"#;
        let entry: AllocEntry = serde_json::from_str(json).unwrap();
        // 2000 ETH = 2000 * 10^18 = 0x6c6b935b8bbd400000
        assert_eq!(
            entry.balance,
            U256::from_str("0x6c6b935b8bbd400000").unwrap()
        );
        assert_eq!(entry.nonce, Some(1));
    }

    #[test]
    fn test_alloc_entry_with_storage() {
        let json = r#"{
            "balance": "0x0",
            "code": "0x6080",
            "storage": {
                "0x0000000000000000000000000000000000000000000000000000000000000000": "0x0000000000000000000000000000000000000000000000000000000000000001"
            }
        }"#;
        let entry: AllocEntry = serde_json::from_str(json).unwrap();
        assert!(entry.is_contract());
        assert_eq!(entry.storage.len(), 1);
    }

    #[test]
    fn test_alloc_entry_eoa() {
        let entry = AllocEntry::new(U256::from(100));
        assert!(!entry.is_contract());
    }
}
