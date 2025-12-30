//! EVM configuration and transaction execution.
//!
//! This module provides the EVM setup for CipherBFT, including:
//! - Chain configuration (Chain ID 31337)
//! - Staking precompile at address 0x100
//! - Transaction execution with revm
//! - Environment configuration (block, tx, cfg)

use crate::{
    error::ExecutionError,
    precompiles::StakingPrecompile,
    types::{Cut, Log},
    Result,
};
use alloy_eips::eip2718::Decodable2718;
use alloy_primitives::{Address, Bytes, B256, U256};
use revm::{
    primitives::{
        AccessListItem, BlobExcessGasAndPrice, BlockEnv, CfgEnv, Env,
        ExecutionResult as RevmResult, Output, SpecId, TxEnv, TxKind,
    },
    Database, Evm,
};

/// CipherBFT Chain ID (31337 - Ethereum testnet/development chain ID).
///
/// This can be configured for different networks but defaults to 31337.
pub const CIPHERBFT_CHAIN_ID: u64 = 31337;

/// Staking precompile address (0x0000000000000000000000000000000000000100).
///
/// This precompile handles validator staking operations:
/// - stake(uint256 amount)
/// - unstake(uint256 amount)
/// - delegate(address validator, uint256 amount)
/// - queryStake(address account) returns uint256
pub const STAKING_PRECOMPILE_ADDRESS: Address = Address::new([
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x01, 0x00,
]);

/// Default block gas limit (30 million gas).
pub const DEFAULT_BLOCK_GAS_LIMIT: u64 = 30_000_000;

/// Default base fee per gas (1 gwei).
pub const DEFAULT_BASE_FEE_PER_GAS: u64 = 1_000_000_000;

/// Minimum stake amount (1 ETH in wei).
pub const MIN_STAKE_AMOUNT: u128 = 1_000_000_000_000_000_000;

/// Unbonding period in seconds (3 days).
pub const UNBONDING_PERIOD_SECONDS: u64 = 259_200; // 3 days = 3 * 24 * 60 * 60

/// EVM configuration for CipherBFT.
///
/// Provides methods to create EVM environments and execute transactions.
#[derive(Debug, Clone)]
pub struct CipherBftEvmConfig {
    /// Chain ID for transaction signing and replay protection.
    pub chain_id: u64,

    /// EVM specification ID (Cancun hard fork).
    pub spec_id: SpecId,

    /// Block gas limit.
    pub block_gas_limit: u64,

    /// Base fee per gas (EIP-1559).
    pub base_fee_per_gas: u64,
}

impl Default for CipherBftEvmConfig {
    fn default() -> Self {
        Self {
            chain_id: CIPHERBFT_CHAIN_ID,
            spec_id: SpecId::CANCUN,
            block_gas_limit: DEFAULT_BLOCK_GAS_LIMIT,
            base_fee_per_gas: DEFAULT_BASE_FEE_PER_GAS,
        }
    }
}

impl CipherBftEvmConfig {
    /// Create a new EVM configuration.
    pub fn new(
        chain_id: u64,
        spec_id: SpecId,
        block_gas_limit: u64,
        base_fee_per_gas: u64,
    ) -> Self {
        Self {
            chain_id,
            spec_id,
            block_gas_limit,
            base_fee_per_gas,
        }
    }

    /// Create configuration environment for the EVM.
    ///
    /// This sets up chain-specific parameters like Chain ID and spec version.
    pub fn cfg_env(&self) -> CfgEnv {
        let mut cfg = CfgEnv::default();
        cfg.chain_id = self.chain_id;
        cfg
    }

    /// Create block environment for the EVM.
    ///
    /// # Arguments
    /// * `block_number` - Current block number
    /// * `timestamp` - Block timestamp (Unix timestamp in seconds)
    /// * `parent_hash` - Parent block hash (used as prevrandao in PoS)
    /// * `gas_limit` - Block gas limit (optional, uses config default if None)
    pub fn block_env(
        &self,
        block_number: u64,
        timestamp: u64,
        parent_hash: B256,
        gas_limit: Option<u64>,
    ) -> BlockEnv {
        BlockEnv {
            number: U256::from(block_number),
            coinbase: Address::ZERO, // No coinbase rewards in PoS
            timestamp: U256::from(timestamp),
            gas_limit: U256::from(gas_limit.unwrap_or(self.block_gas_limit)),
            basefee: U256::from(self.base_fee_per_gas),
            difficulty: U256::ZERO, // Always zero in PoS
            prevrandao: Some(parent_hash), // Use parent hash as randomness source
            blob_excess_gas_and_price: Some(BlobExcessGasAndPrice::new(0, false)), // EIP-4844, not prague
        }
    }

    /// Create block environment from a finalized Cut.
    ///
    /// This is a convenience method that extracts block parameters from a Cut
    /// and creates the appropriate BlockEnv for transaction execution.
    ///
    /// # Arguments
    /// * `cut` - Finalized Cut from the consensus layer
    ///
    /// # Returns
    /// * BlockEnv configured for the Cut's block
    pub fn block_env_from_cut(&self, cut: &Cut) -> BlockEnv {
        self.block_env(
            cut.block_number,
            cut.timestamp,
            cut.parent_hash,
            Some(cut.gas_limit),
        )
    }

    /// Create transaction environment from raw transaction bytes.
    ///
    /// Decodes the transaction and creates a TxEnv for execution.
    ///
    /// # Arguments
    /// * `tx_bytes` - RLP-encoded transaction bytes
    ///
    /// # Returns
    /// * `TxEnv` for execution
    /// * Transaction hash
    /// * Sender address
    /// * Optional recipient address (None for contract creation)
    pub fn tx_env(&self, tx_bytes: &Bytes) -> Result<(TxEnv, B256, Address, Option<Address>)> {
        // Decode transaction using alloy-consensus
        let tx_envelope = alloy_consensus::TxEnvelope::decode_2718(&mut tx_bytes.as_ref())
            .map_err(|e| ExecutionError::invalid_transaction(format!("Failed to decode transaction: {}", e)))?;

        // Compute transaction hash
        let tx_hash = tx_envelope.tx_hash();

        // Recover sender address from signature using alloy-primitives signature recovery
        use alloy_primitives::SignatureError;

        let sender = match &tx_envelope {
            alloy_consensus::TxEnvelope::Legacy(signed) => {
                let sig_hash = signed.signature_hash();
                signed.signature().recover_address_from_prehash(&sig_hash)
                    .map_err(|e: SignatureError| ExecutionError::invalid_transaction(format!("Failed to recover sender: {}", e)))?
            }
            alloy_consensus::TxEnvelope::Eip2930(signed) => {
                let sig_hash = signed.signature_hash();
                signed.signature().recover_address_from_prehash(&sig_hash)
                    .map_err(|e: SignatureError| ExecutionError::invalid_transaction(format!("Failed to recover sender: {}", e)))?
            }
            alloy_consensus::TxEnvelope::Eip1559(signed) => {
                let sig_hash = signed.signature_hash();
                signed.signature().recover_address_from_prehash(&sig_hash)
                    .map_err(|e: SignatureError| ExecutionError::invalid_transaction(format!("Failed to recover sender: {}", e)))?
            }
            alloy_consensus::TxEnvelope::Eip4844(signed) => {
                let sig_hash = signed.signature_hash();
                signed.signature().recover_address_from_prehash(&sig_hash)
                    .map_err(|e: SignatureError| ExecutionError::invalid_transaction(format!("Failed to recover sender: {}", e)))?
            }
            _ => {
                return Err(ExecutionError::invalid_transaction(
                    "Unsupported transaction type for sender recovery",
                ))
            }
        };

        // Build TxEnv based on transaction type
        let tx_env = match &tx_envelope {
            alloy_consensus::TxEnvelope::Legacy(tx) => {
                let tx = tx.tx();
                TxEnv {
                    caller: sender,
                    gas_limit: tx.gas_limit,
                    gas_price: U256::from(tx.gas_price),
                    transact_to: match tx.to {
                        alloy_primitives::TxKind::Call(to) => TxKind::Call(to),
                        alloy_primitives::TxKind::Create => TxKind::Create,
                    },
                    value: tx.value,
                    data: tx.input.clone(),
                    nonce: Some(tx.nonce),
                    chain_id: tx.chain_id,
                    access_list: vec![],
                    gas_priority_fee: None,
                    blob_hashes: vec![],
                    max_fee_per_blob_gas: None,
                    authorization_list: None,
                }
            }
            alloy_consensus::TxEnvelope::Eip2930(tx) => {
                let tx = tx.tx();
                TxEnv {
                    caller: sender,
                    gas_limit: tx.gas_limit,
                    gas_price: U256::from(tx.gas_price),
                    transact_to: match tx.to {
                        alloy_primitives::TxKind::Call(to) => TxKind::Call(to),
                        alloy_primitives::TxKind::Create => TxKind::Create,
                    },
                    value: tx.value,
                    data: tx.input.clone(),
                    nonce: Some(tx.nonce),
                    chain_id: Some(tx.chain_id),
                    access_list: tx
                        .access_list
                        .0
                        .iter()
                        .map(|item| AccessListItem {
                            address: item.address,
                            storage_keys: item.storage_keys.clone(),
                        })
                        .collect(),
                    gas_priority_fee: None,
                    blob_hashes: vec![],
                    max_fee_per_blob_gas: None,
                    authorization_list: None,
                }
            }
            alloy_consensus::TxEnvelope::Eip1559(tx) => {
                let tx = tx.tx();
                TxEnv {
                    caller: sender,
                    gas_limit: tx.gas_limit,
                    gas_price: U256::from(tx.max_fee_per_gas),
                    transact_to: match tx.to {
                        alloy_primitives::TxKind::Call(to) => TxKind::Call(to),
                        alloy_primitives::TxKind::Create => TxKind::Create,
                    },
                    value: tx.value,
                    data: tx.input.clone(),
                    nonce: Some(tx.nonce),
                    chain_id: Some(tx.chain_id),
                    access_list: tx
                        .access_list
                        .0
                        .iter()
                        .map(|item| AccessListItem {
                            address: item.address,
                            storage_keys: item.storage_keys.clone(),
                        })
                        .collect(),
                    gas_priority_fee: Some(U256::from(tx.max_priority_fee_per_gas)),
                    blob_hashes: vec![],
                    max_fee_per_blob_gas: None,
                    authorization_list: None,
                }
            }
            alloy_consensus::TxEnvelope::Eip4844(tx) => {
                let tx = tx.tx().tx();
                TxEnv {
                    caller: sender,
                    gas_limit: tx.gas_limit,
                    gas_price: U256::from(tx.max_fee_per_gas),
                    transact_to: TxKind::Call(tx.to),
                    value: tx.value,
                    data: tx.input.clone(),
                    nonce: Some(tx.nonce),
                    chain_id: Some(tx.chain_id),
                    access_list: tx
                        .access_list
                        .0
                        .iter()
                        .map(|item| AccessListItem {
                            address: item.address,
                            storage_keys: item.storage_keys.clone(),
                        })
                        .collect(),
                    gas_priority_fee: Some(U256::from(tx.max_priority_fee_per_gas)),
                    blob_hashes: tx.blob_versioned_hashes.clone(),
                    max_fee_per_blob_gas: Some(U256::from(tx.max_fee_per_blob_gas)),
                    authorization_list: None,
                }
            }
            _ => {
                return Err(ExecutionError::invalid_transaction(
                    "Unsupported transaction type",
                ))
            }
        };

        // Extract recipient address (to) from transaction
        let to_addr = match &tx_envelope {
            alloy_consensus::TxEnvelope::Legacy(tx) => match tx.tx().to {
                alloy_primitives::TxKind::Call(to) => Some(to),
                alloy_primitives::TxKind::Create => None,
            },
            alloy_consensus::TxEnvelope::Eip2930(tx) => match tx.tx().to {
                alloy_primitives::TxKind::Call(to) => Some(to),
                alloy_primitives::TxKind::Create => None,
            },
            alloy_consensus::TxEnvelope::Eip1559(tx) => match tx.tx().to {
                alloy_primitives::TxKind::Call(to) => Some(to),
                alloy_primitives::TxKind::Create => None,
            },
            alloy_consensus::TxEnvelope::Eip4844(tx) => Some(tx.tx().tx().to),
            _ => None,
        };

        Ok((tx_env, *tx_hash, sender, to_addr))
    }

    /// Build an EVM instance with the given database.
    ///
    /// This creates a configured EVM ready for transaction execution.
    ///
    /// # Type Parameters
    /// * `DB` - Database type implementing the revm Database trait
    ///
    /// # Arguments
    /// * `database` - Database backend for state access
    /// * `block_number` - Current block number
    /// * `timestamp` - Block timestamp
    /// * `parent_hash` - Parent block hash
    pub fn build_evm<DB: Database>(
        &self,
        database: DB,
        block_number: u64,
        timestamp: u64,
        parent_hash: B256,
    ) -> Evm<'static, (), DB> {
        let env = Env {
            cfg: self.cfg_env(),
            block: self.block_env(block_number, timestamp, parent_hash, None),
            tx: TxEnv::default(),
        };

        Evm::builder()
            .with_db(database)
            .with_env(Box::new(env))
            .build()
    }

    /// Install custom precompiles (staking precompile at 0x100).
    ///
    /// This method should be called after building the EVM to register
    /// the staking precompile at address 0x100.
    ///
    /// Note: In the current implementation, precompiles are statically configured.
    /// The StakingPrecompile will be integrated more deeply in Phase 4.
    ///
    /// # Returns
    /// A StakingPrecompile instance that can be used to manage validator state.
    pub fn install_precompiles(&self) -> StakingPrecompile {
        // Create and return staking precompile
        // In a full implementation, this would be registered with the EVM handler
        StakingPrecompile::new()
    }

    /// Execute a transaction and return the result.
    ///
    /// This is the main entry point for transaction execution.
    ///
    /// # Arguments
    /// * `evm` - Configured EVM instance
    /// * `tx_bytes` - RLP-encoded transaction bytes
    ///
    /// # Returns
    /// * Transaction execution result including gas used, logs, and output
    pub fn execute_transaction<DB: Database + revm::DatabaseCommit>(
        &self,
        evm: &mut Evm<'_, (), DB>,
        tx_bytes: &Bytes,
    ) -> Result<TransactionResult> {
        // Parse transaction and create TxEnv
        let (tx_env, tx_hash, sender, to_addr) = self.tx_env(tx_bytes)?;

        // Set transaction environment
        evm.context.evm.env.tx = tx_env;

        // Execute transaction and commit state changes
        // This ensures subsequent transactions in the same block see updated nonces
        let result = evm
            .transact_commit()
            .map_err(|_| ExecutionError::evm("Transaction execution failed"))?;

        // Convert revm result to our result type
        self.process_execution_result(result, tx_hash, sender, to_addr)
    }

    /// Process the execution result from revm.
    fn process_execution_result(
        &self,
        result: RevmResult,
        tx_hash: B256,
        sender: Address,
        to: Option<Address>,
    ) -> Result<TransactionResult> {
        let success = result.is_success();
        let gas_used = result.gas_used();

        // Extract output and logs
        let (output, logs) = match result {
            RevmResult::Success {
                reason: _,
                output,
                gas_used: _,
                gas_refunded: _,
                logs,
            } => {
                let output_data = match output {
                    Output::Call(data) => data,
                    Output::Create(data, addr) => {
                        // For contract creation, return address as output
                        if let Some(addr) = addr {
                            return Ok(TransactionResult {
                                tx_hash,
                                sender,
                                to: None,
                                success: true,
                                gas_used,
                                output: Bytes::new(),
                                logs: logs
                                    .into_iter()
                                    .map(|log| Log {
                                        address: log.address,
                                        topics: log.topics().to_vec(),
                                        data: log.data.data.clone(),
                                    })
                                    .collect(),
                                contract_address: Some(addr),
                                revert_reason: None,
                            });
                        }
                        data
                    }
                };

                let converted_logs = logs
                    .into_iter()
                    .map(|log| Log {
                        address: log.address,
                        topics: log.topics().to_vec(),
                        data: log.data.data.clone(),
                    })
                    .collect();

                (output_data, converted_logs)
            }
            RevmResult::Revert { gas_used: _, output } => {
                return Ok(TransactionResult {
                    tx_hash,
                    sender,
                    to: None,
                    success: false,
                    gas_used,
                    output: Bytes::new(),
                    logs: vec![],
                    contract_address: None,
                    revert_reason: Some(format!("Revert: {}", hex::encode(&output))),
                });
            }
            RevmResult::Halt { reason, gas_used: _ } => {
                return Ok(TransactionResult {
                    tx_hash,
                    sender,
                    to: None,
                    success: false,
                    gas_used,
                    output: Bytes::new(),
                    logs: vec![],
                    contract_address: None,
                    revert_reason: Some(format!("Halt: {:?}", reason)),
                });
            }
        };

        Ok(TransactionResult {
            tx_hash,
            sender,
            to,
            success,
            gas_used,
            output,
            logs,
            contract_address: None,
            revert_reason: None,
        })
    }
}

/// Result of transaction execution.
#[derive(Debug, Clone)]
pub struct TransactionResult {
    /// Transaction hash.
    pub tx_hash: B256,

    /// Sender address.
    pub sender: Address,

    /// Recipient address (None for contract creation).
    pub to: Option<Address>,

    /// Whether the transaction succeeded.
    pub success: bool,

    /// Gas used by the transaction.
    pub gas_used: u64,

    /// Output data from the transaction.
    pub output: Bytes,

    /// Logs emitted during execution.
    pub logs: Vec<Log>,

    /// Contract address if this was a contract creation.
    pub contract_address: Option<Address>,

    /// Revert reason if the transaction failed.
    pub revert_reason: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use revm::db::EmptyDB;
    use std::str::FromStr;

    #[test]
    fn test_constants() {
        assert_eq!(CIPHERBFT_CHAIN_ID, 31337);
        assert_eq!(
            STAKING_PRECOMPILE_ADDRESS,
            Address::from_str("0x0000000000000000000000000000000000000100").unwrap()
        );
        assert_eq!(DEFAULT_BLOCK_GAS_LIMIT, 30_000_000);
        assert_eq!(DEFAULT_BASE_FEE_PER_GAS, 1_000_000_000);
        assert_eq!(MIN_STAKE_AMOUNT, 1_000_000_000_000_000_000);
        assert_eq!(UNBONDING_PERIOD_SECONDS, 259_200);
    }

    #[test]
    fn test_default_config() {
        let config = CipherBftEvmConfig::default();
        assert_eq!(config.chain_id, CIPHERBFT_CHAIN_ID);
        assert_eq!(config.spec_id, SpecId::CANCUN);
        assert_eq!(config.block_gas_limit, DEFAULT_BLOCK_GAS_LIMIT);
        assert_eq!(config.base_fee_per_gas, DEFAULT_BASE_FEE_PER_GAS);
    }

    #[test]
    fn test_cfg_env() {
        let config = CipherBftEvmConfig::default();
        let cfg_env = config.cfg_env();

        assert_eq!(cfg_env.chain_id, CIPHERBFT_CHAIN_ID);
    }

    #[test]
    fn test_block_env() {
        let config = CipherBftEvmConfig::default();
        let parent_hash = B256::from([1u8; 32]);
        let block_env = config.block_env(42, 1234567890, parent_hash, None);

        assert_eq!(block_env.number, U256::from(42));
        assert_eq!(block_env.timestamp, U256::from(1234567890));
        assert_eq!(block_env.gas_limit, U256::from(DEFAULT_BLOCK_GAS_LIMIT));
        assert_eq!(block_env.basefee, U256::from(DEFAULT_BASE_FEE_PER_GAS));
        assert_eq!(block_env.coinbase, Address::ZERO);
        assert_eq!(block_env.difficulty, U256::ZERO);
        assert_eq!(block_env.prevrandao, Some(parent_hash));
    }

    #[test]
    fn test_block_env_custom_gas_limit() {
        let config = CipherBftEvmConfig::default();
        let parent_hash = B256::from([1u8; 32]);
        let custom_limit = 15_000_000;
        let block_env = config.block_env(42, 1234567890, parent_hash, Some(custom_limit));

        assert_eq!(block_env.gas_limit, U256::from(custom_limit));
    }

    #[test]
    fn test_build_evm() {
        let config = CipherBftEvmConfig::default();
        let db = EmptyDB::default();
        let parent_hash = B256::from([1u8; 32]);

        let evm = config.build_evm(db, 1, 1234567890, parent_hash);

        assert_eq!(evm.context.evm.env.cfg.chain_id, CIPHERBFT_CHAIN_ID);
        assert_eq!(evm.context.evm.env.block.number, U256::from(1));
        assert_eq!(evm.context.evm.env.block.timestamp, U256::from(1234567890));
    }

    #[test]
    fn test_block_env_from_cut() {
        use crate::types::Cut;

        let config = CipherBftEvmConfig::default();
        let parent_hash = B256::from([1u8; 32]);

        let cut = Cut {
            block_number: 100,
            timestamp: 1234567890,
            parent_hash,
            cars: vec![],
            gas_limit: 25_000_000,
            base_fee_per_gas: Some(2_000_000_000),
        };

        let block_env = config.block_env_from_cut(&cut);

        assert_eq!(block_env.number, U256::from(100));
        assert_eq!(block_env.timestamp, U256::from(1234567890));
        assert_eq!(block_env.gas_limit, U256::from(25_000_000));
        assert_eq!(block_env.prevrandao, Some(parent_hash));
    }
}
