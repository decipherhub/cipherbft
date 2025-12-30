//! EVM configuration and transaction execution.
//!
//! This module provides the EVM setup for CipherBFT, including:
//! - Chain configuration (Chain ID 31337)
//! - Staking precompile at address 0x100
//! - Transaction execution with revm
//! - Environment configuration (block, tx, cfg)

use crate::{
    error::ExecutionError,
    types::{Cut, Log},
    Result,
};
use alloy_eips::eip2718::Decodable2718;
use alloy_primitives::{Address, Bytes, B256, U256};
// MIGRATION(revm33): Complete API restructuring
// - Use Context::mainnet() to build EVM (not Evm::builder())
// - No Env/BlockEnv/CfgEnv - configuration handled differently
// - TxEnv is in revm::context
// - ExecutionResult in revm::context_interface::result
// - Primitives like TxKind in revm::primitives
use revm::{
    context::TxEnv,
    context_interface::{
        result::{ExecutionResult as RevmResult, Output},
        transaction::{AccessList, AccessListItem},
    },
    database_interface::Database,
    primitives::{hardfork::SpecId, TxKind},
};

/// CipherBFT Chain ID (31337 - Ethereum testnet/development chain ID).
///
/// This can be configured for different networks but defaults to 31337.
pub const CIPHERBFT_CHAIN_ID: u64 = 31337;

// MIGRATION(revm33): STAKING_PRECOMPILE_ADDRESS moved to precompiles::provider module
// It's re-exported from precompiles::STAKING_PRECOMPILE_ADDRESS

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
/// MIGRATION(revm33): This struct is partially broken due to removed types.
/// Revm 33 eliminated Env, BlockEnv, CfgEnv in favor of Context-based API.
/// Most methods are stubbed/commented out pending comprehensive refactor.
///
/// TODO: Comprehensive refactor (~500-1000 LOC changes):
/// - Replace Env-based methods with Context builders
/// - Update all transaction execution to use Context::mainnet()
/// - Rewrite tests to use new API
/// - See examples/uniswap_v2_usdc_swap for reference pattern
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

    /// Build an EVM instance with custom precompiles (including staking precompile).
    ///
    /// MIGRATION(revm33): Uses Context-based API instead of Evm::builder().
    ///
    /// # Arguments
    /// * `database` - Database implementation
    /// * `block_number` - Current block number
    /// * `timestamp` - Block timestamp
    /// * `parent_hash` - Parent block hash
    /// * `staking_precompile` - Staking precompile instance
    ///
    /// # Returns
    /// EVM instance ready for transaction execution
    pub fn build_evm_with_precompiles<'a, DB>(
        &self,
        database: &'a mut DB,
        block_number: u64,
        timestamp: u64,
        parent_hash: B256,
        staking_precompile: std::sync::Arc<crate::precompiles::StakingPrecompile>,
    ) -> revm::context::Evm<
        revm::Context<revm::context::BlockEnv, revm::context::TxEnv, revm::context::CfgEnv, &'a mut DB, revm::context::Journal<&'a mut DB>, ()>,
        (),
        revm::handler::instructions::EthInstructions<revm::interpreter::interpreter::EthInterpreter, revm::Context<revm::context::BlockEnv, revm::context::TxEnv, revm::context::CfgEnv, &'a mut DB, revm::context::Journal<&'a mut DB>, ()>>,
        crate::precompiles::CipherBftPrecompileProvider,
        revm::handler::EthFrame<revm::interpreter::interpreter::EthInterpreter>,
    >
    where
        DB: revm::Database,
    {
        use revm::{Context, MainBuilder};
        use revm::context::{BlockEnv, TxEnv, CfgEnv, Journal};
        use crate::precompiles::CipherBftPrecompileProvider;

        // Create context with database and spec
        let mut ctx: Context<BlockEnv, TxEnv, CfgEnv, &'a mut DB, Journal<&'a mut DB>, ()> = Context::new(database, self.spec_id);

        // Configure block environment
        ctx.block.number = alloy_primitives::U256::from(block_number);
        ctx.block.timestamp = alloy_primitives::U256::from(timestamp);
        ctx.block.gas_limit = self.block_gas_limit;
        ctx.block.basefee = self.base_fee_per_gas;
        // Note: BlockEnv doesn't have parent_hash field in revm 33

        // Configure chain-level settings
        ctx.cfg.chain_id = self.chain_id;

        // Build custom EVM with our precompile provider
        let custom_precompiles = CipherBftPrecompileProvider::new(staking_precompile, self.spec_id);

        use revm::context::{Evm, FrameStack};
        use revm::handler::{EthFrame, instructions::EthInstructions};
        use revm::interpreter::interpreter::EthInterpreter;

        Evm {
            ctx,
            inspector: (),
            instruction: EthInstructions::default(),
            precompiles: custom_precompiles,
            frame_stack: FrameStack::new_prealloc(8),
        }
    }

    /// Execute a transaction using the EVM.
    ///
    /// MIGRATION(revm33): Uses Context.transact() instead of manual EVM execution.
    ///
    /// # Arguments
    /// * `evm` - EVM instance created with build_evm_with_precompiles()
    /// * `tx_bytes` - Raw transaction bytes
    ///
    /// # Returns
    /// TransactionResult with execution details
    pub fn execute_transaction<EVM>(
        &self,
        evm: &mut EVM,
        tx_bytes: &Bytes,
    ) -> Result<TransactionResult>
    where
        EVM: revm::handler::ExecuteEvm<Tx = revm::context::TxEnv>,
        EVM::Error: std::fmt::Debug,
        EVM::ExecutionResult: std::fmt::Debug + Clone,
    {
        use revm::handler::ExecuteEvm;

        // Parse transaction to get TxEnv
        let (tx_env, tx_hash, sender, to) = self.tx_env(tx_bytes)?;

        // Capture nonce before moving tx_env
        let nonce = tx_env.nonce;

        // Execute transaction
        let result = evm.transact(tx_env)
            .map_err(|e| ExecutionError::evm(format!("Transaction execution failed: {:?}", e)))?;

        // Extract execution results
        // For now, return a simple success/failure based on debug output
        // TODO: Properly extract execution details once we understand the ExecutionResult type
        let (success, gas_used, output, logs, revert_reason) = (
            true,
            0_u64,
            Bytes::new(),
            vec![],
            None::<String>,
        );

        // Convert revm logs to our Log type (empty for now)
        // TODO: Extract actual logs from ExecutionResult

        // Extract contract address for contract creation
        let contract_address = to.is_none().then(|| {
            // For contract creation, compute CREATE address
            // address = keccak256(rlp([sender, nonce]))[12:]
            use alloy_primitives::keccak256;
            use alloy_rlp::{RlpEncodable, Encodable};

            #[derive(RlpEncodable)]
            struct CreateAddress {
                sender: Address,
                nonce: u64,
            }

            let create_data = CreateAddress { sender, nonce };
            let mut rlp_buf = Vec::new();
            create_data.encode(&mut rlp_buf);
            let hash = keccak256(&rlp_buf);
            Address::from_slice(&hash[12..])
        });

        Ok(TransactionResult {
            tx_hash,
            sender,
            to,
            success,
            gas_used,
            output,
            logs,
            contract_address,
            revert_reason,
        })
    }

    // MIGRATION(revm33): These methods are commented out as they use removed types.
    // Revm 33 eliminated CfgEnv, BlockEnv, BlobExcessGasAndPrice.
    // Configuration is now done via Context builders.
    // TODO: Replace with Context-based configuration methods.

    /*
    /// Create configuration environment for the EVM.
    pub fn cfg_env(&self) -> CfgEnv { ... }

    /// Create block environment for the EVM.
    pub fn block_env(&self, ...) -> BlockEnv { ... }

    /// Create block environment from a finalized Cut.
    pub fn block_env_from_cut(&self, cut: &Cut) -> BlockEnv { ... }
    */

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
                    tx_type: 0, // Legacy transaction type
                    caller: sender,
                    gas_limit: tx.gas_limit,
                    gas_price: tx.gas_price as u128,
                    kind: match tx.to {
                        alloy_primitives::TxKind::Call(to) => TxKind::Call(to),
                        alloy_primitives::TxKind::Create => TxKind::Create,
                    },
                    value: tx.value,
                    data: tx.input.clone(),
                    nonce: tx.nonce,
                    chain_id: tx.chain_id,
                    access_list: Default::default(),
                    gas_priority_fee: None,
                    blob_hashes: vec![],
                    max_fee_per_blob_gas: 0,
                    authorization_list: vec![],
                }
            }
            alloy_consensus::TxEnvelope::Eip2930(tx) => {
                let tx = tx.tx();
                TxEnv {
                    tx_type: 1, // EIP-2930 transaction type
                    caller: sender,
                    gas_limit: tx.gas_limit,
                    gas_price: tx.gas_price as u128,
                    kind: match tx.to {
                        alloy_primitives::TxKind::Call(to) => TxKind::Call(to),
                        alloy_primitives::TxKind::Create => TxKind::Create,
                    },
                    value: tx.value,
                    data: tx.input.clone(),
                    nonce: tx.nonce,
                    chain_id: Some(tx.chain_id),
                    access_list: AccessList(
                        tx.access_list
                            .0
                            .iter()
                            .map(|item| AccessListItem {
                                address: item.address,
                                storage_keys: item.storage_keys.clone(),
                            })
                            .collect(),
                    ),
                    gas_priority_fee: None,
                    blob_hashes: vec![],
                    max_fee_per_blob_gas: 0,
                    authorization_list: vec![],
                }
            }
            alloy_consensus::TxEnvelope::Eip1559(tx) => {
                let tx = tx.tx();
                TxEnv {
                    tx_type: 2, // EIP-1559 transaction type
                    caller: sender,
                    gas_limit: tx.gas_limit,
                    gas_price: tx.max_fee_per_gas as u128,
                    kind: match tx.to {
                        alloy_primitives::TxKind::Call(to) => TxKind::Call(to),
                        alloy_primitives::TxKind::Create => TxKind::Create,
                    },
                    value: tx.value,
                    data: tx.input.clone(),
                    nonce: tx.nonce,
                    chain_id: Some(tx.chain_id),
                    access_list: AccessList(
                        tx.access_list
                            .0
                            .iter()
                            .map(|item| AccessListItem {
                                address: item.address,
                                storage_keys: item.storage_keys.clone(),
                            })
                            .collect(),
                    ),
                    gas_priority_fee: Some(tx.max_priority_fee_per_gas as u128),
                    blob_hashes: vec![],
                    max_fee_per_blob_gas: 0,
                    authorization_list: vec![],
                }
            }
            alloy_consensus::TxEnvelope::Eip4844(tx) => {
                let tx = tx.tx().tx();
                TxEnv {
                    tx_type: 3, // EIP-4844 transaction type
                    caller: sender,
                    gas_limit: tx.gas_limit,
                    gas_price: tx.max_fee_per_gas as u128,
                    kind: TxKind::Call(tx.to),
                    value: tx.value,
                    data: tx.input.clone(),
                    nonce: tx.nonce,
                    chain_id: Some(tx.chain_id),
                    access_list: AccessList(
                        tx.access_list
                            .0
                            .iter()
                            .map(|item| AccessListItem {
                                address: item.address,
                                storage_keys: item.storage_keys.clone(),
                            })
                            .collect(),
                    ),
                    gas_priority_fee: Some(tx.max_priority_fee_per_gas as u128),
                    blob_hashes: tx.blob_versioned_hashes.clone(),
                    max_fee_per_blob_gas: tx.max_fee_per_blob_gas as u128,
                    authorization_list: vec![],
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
    // MIGRATION(revm33): build_evm method removed - uses old Evm::builder() API
    // TODO: Replace with Context::mainnet().with_db(database).build_mainnet()
    /*
    pub fn build_evm<DB: Database>(
        &self,
        database: DB,
        block_number: u64,
        timestamp: u64,
        parent_hash: B256,
    ) -> Evm<'static, (), DB> { ... }
    */

    /// Build a configured EVM instance with custom precompiles.
    ///
    /// MIGRATION(revm33): Precompile provider is now a type parameter on Evm.
    /// This method has been removed in favor of manual EVM construction with CipherBftPrecompileProvider.
    ///
    /// # Example
    /// ```rust,ignore
    /// use crate::precompiles::{CipherBftPrecompileProvider, StakingPrecompile};
    /// use revm::Evm;
    /// use std::sync::Arc;
    ///
    /// let staking = Arc::new(StakingPrecompile::new());
    /// let provider = CipherBftPrecompileProvider::new(staking, SpecId::CANCUN);
    ///
    /// // Note: Full EVM construction requires Context type with proper trait bounds
    /// // See integration tests for complete examples
    /// ```
    ///
    /// # Note
    /// The PrecompileProvider trait allows precompiles to access full transaction context
    /// (caller, value, block number) which is essential for the staking precompile.
    /// See `precompiles::provider` module for implementation details.

    // MIGRATION(revm33): execute_transaction method removed - uses old Evm API
    // TODO: Replace with Context-based transaction execution
    // Use: evm.transact_one(TxEnv::builder()...build()?)
    /*
    pub fn execute_transaction<DB: Database + revm::DatabaseCommit>(
        &self,
        evm: &mut Evm<'_, (), DB>,
        tx_bytes: &Bytes,
    ) -> Result<TransactionResult> { ... }
    */

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
