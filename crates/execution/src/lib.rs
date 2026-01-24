//! CipherBFT Execution Layer
//!
//! This crate provides the execution layer for the CipherBFT blockchain,
//! implementing deterministic EVM transaction execution, state management,
//! and integration with the consensus layer.
//!
//! # Architecture
//!
//! The execution layer follows a "consensus-then-execute" model:
//! 1. Consensus layer finalizes transaction ordering (Cut)
//! 2. Execution layer executes transactions deterministically
//! 3. Results (state root, receipts root, gas used) returned to consensus
//!
//! # Key Features
//!
//! - **Deterministic Execution**: All validators produce identical state roots
//! - **Periodic State Roots**: Computed every N blocks (default: 100) for efficiency
//! - **Delayed Commitment**: Block N includes hash of block N-2
//! - **EVM Compatibility**: Cancun hard fork (EIP-4844, EIP-1153)
//! - **Staking Precompile**: Custom precompile at 0x100 for validator staking
//!
//! # Example
//!
//! ```rust,ignore
//! use cipherbft_execution::*;
//!
//! // Create execution layer instance with in-memory storage
//! let mut execution_layer = ExecutionLayer::new(ChainConfig::default())?;
//!
//! // Execute a finalized Cut from consensus
//! let input = BlockInput {
//!     block_number: 1,
//!     timestamp: 1234567890,
//!     transactions: vec![/* ... */],
//!     parent_hash: B256::ZERO,
//!     gas_limit: 30_000_000,
//!     base_fee_per_gas: Some(1_000_000_000),
//! };
//!
//! let result = execution_layer.execute_block(input)?;
//!
//! // Use execution results
//! println!("State root: {}", result.state_root);
//! println!("Gas used: {}", result.gas_used);
//! ```

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod bridge;
pub mod database;
pub mod engine;
pub mod error;
pub mod evm;
pub mod genesis;
pub mod inspector;
pub mod mpt;
pub mod precompiles;
pub mod receipts;
pub mod rlp;
pub mod state;
pub mod types;

// Re-export main types for convenience
pub use bridge::{BatchFetcher, ExecutionBridge};
pub use database::{Account, CipherBftDatabase, InMemoryProvider, Provider};
pub use engine::{ExecutionEngine, ExecutionLayer as ExecutionLayerTrait};
pub use error::{DatabaseError, ExecutionError, Result};
pub use evm::{
    CipherBftEvmConfig, TransactionResult, CIPHERBFT_CHAIN_ID, DEFAULT_BASE_FEE_PER_GAS,
    DEFAULT_BLOCK_GAS_LIMIT, MIN_STAKE_AMOUNT, UNBONDING_PERIOD_SECONDS,
};
pub use genesis::{
    read_total_staked, read_validator_address, read_validator_count, read_validator_stake,
    GenesisInitializer,
};
pub use mpt::{compute_state_root, compute_state_root_from_entries, compute_storage_root};
pub use precompiles::{
    CipherBftPrecompileProvider, GenesisValidatorData, StakingPrecompile, StakingState,
    ValidatorInfo, STAKING_PRECOMPILE_ADDRESS,
};
pub use receipts::{
    aggregate_bloom, compute_logs_bloom_from_transactions, compute_receipts_root,
    compute_transactions_root, logs_bloom,
};
pub use rlp::{rlp_encode_account, rlp_encode_storage_value, RlpAccount, KECCAK_EMPTY};
pub use state::StateManager;

// Re-export inspector types for RPC tracing
pub use inspector::{
    CallFrame, CallLog, CallTracer, CallTracerConfig, CallType, OpcodeStep, OpcodeTracer,
    OpcodeTracerConfig, TraceOptions, TraceResult,
};
pub use types::{
    BlockHeader, BlockInput, Car, ChainConfig, ConsensusBlock, Cut, ExecutionBlock,
    ExecutionResult, Log, Receipt, SealedBlock, TransactionReceipt, DELAYED_COMMITMENT_DEPTH,
    STATE_ROOT_SNAPSHOT_INTERVAL,
};

// Re-export commonly used external types
pub use alloy_primitives::{keccak256, Address, Bloom, Bytes, B256, U256};

/// Main execution layer interface for the consensus layer.
///
/// This struct provides the primary API for executing transactions,
/// validating transactions, querying state, and managing rollbacks.
///
/// It wraps an `ExecutionEngine` and provides convenience methods for
/// working with `Cut` structures from the consensus layer.
pub struct ExecutionLayer<P: Provider + Clone = InMemoryProvider> {
    /// The underlying execution engine.
    engine: engine::ExecutionEngine<P>,
}

impl ExecutionLayer<InMemoryProvider> {
    /// Create a new execution layer instance with in-memory storage.
    ///
    /// # Arguments
    ///
    /// * `config` - Chain configuration parameters
    ///
    /// # Returns
    ///
    /// Returns an ExecutionLayer instance ready to process transactions.
    #[allow(clippy::new_without_default)]
    pub fn new(config: ChainConfig) -> Result<Self> {
        let provider = InMemoryProvider::new();
        Ok(Self {
            engine: engine::ExecutionEngine::new(config, provider),
        })
    }
}

impl<P: Provider + Clone> ExecutionLayer<P> {
    /// Create a new execution layer instance with a custom provider.
    ///
    /// # Arguments
    ///
    /// * `config` - Chain configuration parameters
    /// * `provider` - Storage provider for state persistence
    ///
    /// # Returns
    ///
    /// Returns an ExecutionLayer instance ready to process transactions.
    pub fn with_provider(config: ChainConfig, provider: P) -> Self {
        Self {
            engine: engine::ExecutionEngine::new(config, provider),
        }
    }

    /// Create a new execution layer instance with genesis validators.
    ///
    /// This is the primary constructor for production use. It initializes the
    /// staking precompile with the validator set from the genesis file.
    ///
    /// # Arguments
    ///
    /// * `config` - Chain configuration parameters
    /// * `provider` - Storage provider for state persistence
    /// * `genesis_validators` - List of validators from the genesis file
    ///
    /// # Returns
    ///
    /// Returns an ExecutionLayer instance with initialized staking state.
    pub fn with_genesis_validators(
        config: ChainConfig,
        provider: P,
        genesis_validators: Vec<GenesisValidatorData>,
    ) -> Self {
        Self {
            engine: engine::ExecutionEngine::with_genesis_validators(
                config,
                provider,
                genesis_validators,
            ),
        }
    }

    /// Execute a finalized Cut from the consensus layer.
    ///
    /// This is the main entry point for block execution. Takes a Cut with ordered
    /// transactions (grouped by validator Cars) and returns execution results
    /// including state root and receipts.
    ///
    /// # Arguments
    ///
    /// * `cut` - Finalized, ordered transactions from consensus
    ///
    /// # Returns
    ///
    /// Returns `ExecutionResult` with state root, receipts root, and gas usage.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Block number is not sequential
    /// - Gas limit is zero
    /// - Transaction execution fails
    pub fn execute_cut(&mut self, cut: Cut) -> Result<ExecutionResult> {
        // Verify Cars are sorted by validator_id (invariant from consensus layer)
        // This is a debug assertion since consensus layer guarantees ordering,
        // but we verify it in debug builds to catch integration bugs early
        debug_assert!(
            cut.cars
                .windows(2)
                .all(|w| w[0].validator_id <= w[1].validator_id),
            "Cars must be sorted by validator_id (consensus layer invariant violated)"
        );

        // Convert Cut to BlockInput by flattening Cars into ordered transactions
        let block_input = BlockInput {
            block_number: cut.block_number,
            timestamp: cut.timestamp,
            parent_hash: cut.parent_hash,
            // Flatten transactions from all Cars in order (Cars are pre-sorted by validator ID)
            transactions: cut
                .cars
                .into_iter()
                .flat_map(|car| car.transactions)
                .collect(),
            gas_limit: cut.gas_limit,
            base_fee_per_gas: cut.base_fee_per_gas,
        };

        self.engine.execute_block(block_input)
    }

    /// Validate a transaction before mempool insertion.
    ///
    /// Performs pre-execution validation including signature, nonce, balance,
    /// and gas limit checks.
    ///
    /// # Arguments
    ///
    /// * `tx` - Transaction bytes to validate
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if transaction is valid, or an error describing the validation failure.
    pub fn validate_transaction(&self, tx: &Bytes) -> Result<()> {
        self.engine.validate_transaction(tx)
    }

    /// Query account state at a specific block height.
    ///
    /// **Note:** Currently returns the current account state. Historical state queries
    /// at specific block heights will be implemented with state snapshot support.
    /// Pass `0` for the block number to query current state without a warning.
    ///
    /// # Arguments
    ///
    /// * `address` - Account address to query
    /// * `block_number` - Block height for the query (currently only 0 for "latest" is fully supported)
    ///
    /// # Returns
    ///
    /// Returns the account state (balance, nonce, code hash, storage root).
    pub fn get_account(&self, address: Address, block_number: u64) -> Result<Account> {
        // Warn if caller expects historical state (non-zero block number)
        // TODO(#issue): Support historical state queries via StateManager.get_state_at()
        // and block replay from nearest snapshot
        if block_number != 0 {
            tracing::warn!(
                block_number,
                "Historical state queries not yet supported, returning current state"
            );
        }

        self.engine
            .database()
            .get_account(address)?
            .ok_or(ExecutionError::Database(
                error::DatabaseError::AccountNotFound(address),
            ))
    }

    /// Query contract code.
    ///
    /// # Arguments
    ///
    /// * `address` - Contract address
    ///
    /// # Returns
    ///
    /// - `Ok(Bytes::new())` for EOAs (accounts with empty code hash)
    /// - `Ok(bytecode)` for contract accounts
    /// - `Err` if the account does not exist or has corrupted state
    pub fn get_code(&self, address: Address) -> Result<Bytes> {
        // First get the account to find the code hash
        let account =
            self.engine
                .database()
                .get_account(address)?
                .ok_or(ExecutionError::Database(
                    error::DatabaseError::AccountNotFound(address),
                ))?;

        // KECCAK_EMPTY is the canonical code hash for EOAs (accounts without code)
        // This is keccak256([]) = 0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
        let keccak_empty = keccak256([]);
        if account.code_hash == keccak_empty {
            return Ok(Bytes::new());
        }

        // B256::ZERO is not a valid code hash - it indicates uninitialized or corrupted state
        if account.code_hash == B256::ZERO {
            return Err(ExecutionError::Database(error::DatabaseError::Corruption(
                format!(
                    "Account {} has zero code_hash, indicating uninitialized state",
                    address
                ),
            )));
        }

        use revm::DatabaseRef;
        let bytecode = self.engine.database().code_by_hash_ref(account.code_hash)?;

        Ok(bytecode.bytecode().clone())
    }

    /// Query storage slot at a specific block height.
    ///
    /// **Note:** Currently returns the current storage value. Historical state queries
    /// at specific block heights will be implemented with state snapshot support.
    /// Pass `0` for the block number to query current state without a warning.
    ///
    /// # Arguments
    ///
    /// * `address` - Contract address
    /// * `slot` - Storage slot key
    /// * `block_number` - Block height for the query (currently only 0 for "latest" is fully supported)
    ///
    /// # Returns
    ///
    /// Returns the storage slot value.
    pub fn get_storage(&self, address: Address, slot: U256, block_number: u64) -> Result<U256> {
        // Warn if caller expects historical state (non-zero block number)
        // TODO(#issue): Support historical state queries via StateManager.get_state_at()
        // and block replay from nearest snapshot
        if block_number != 0 {
            tracing::warn!(
                block_number,
                %address,
                "Historical storage queries not yet supported, returning current value"
            );
        }

        use revm::DatabaseRef;
        Ok(self.engine.database().storage_ref(address, slot)?)
    }

    /// Rollback to a previous block for reorg handling.
    ///
    /// This operation finds the nearest snapshot at or before the target block
    /// and restores state from that snapshot.
    ///
    /// # Arguments
    ///
    /// * `target_block` - Block number to rollback to
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if rollback succeeds.
    pub fn rollback_to(&mut self, target_block: u64) -> Result<()> {
        self.engine.state_manager().rollback_to(target_block)
    }

    /// Get the current state root.
    ///
    /// # Returns
    ///
    /// Returns the current state root hash.
    pub fn state_root(&self) -> B256 {
        self.engine.state_root()
    }

    /// Execute a block with ordered transactions.
    ///
    /// This is an alternative entry point for block execution when transactions
    /// are already flattened (not grouped into Cars).
    ///
    /// # Arguments
    ///
    /// * `input` - Block input with ordered transactions
    ///
    /// # Returns
    ///
    /// Returns `ExecutionResult` with state root, receipts root, and gas usage.
    pub fn execute_block(&mut self, input: BlockInput) -> Result<ExecutionResult> {
        self.engine.execute_block(input)
    }

    /// Seal a block after execution.
    ///
    /// # Arguments
    ///
    /// * `consensus_block` - Block data from consensus
    /// * `execution_result` - Result of block execution
    ///
    /// # Returns
    ///
    /// Returns a sealed block with final hash.
    pub fn seal_block(
        &self,
        consensus_block: ConsensusBlock,
        execution_result: ExecutionResult,
    ) -> Result<SealedBlock> {
        self.engine.seal_block(consensus_block, execution_result)
    }
}

impl<P: Provider + Clone> std::fmt::Debug for ExecutionLayer<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExecutionLayer")
            .field("state_root", &self.state_root())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_execution_layer_new() {
        let config = ChainConfig::default();
        let execution_layer = ExecutionLayer::new(config).unwrap();
        assert_eq!(execution_layer.state_root(), B256::ZERO);
    }

    #[test]
    fn test_execution_layer_with_provider() {
        let config = ChainConfig::default();
        let provider = InMemoryProvider::new();
        let execution_layer = ExecutionLayer::with_provider(config, provider);
        assert_eq!(execution_layer.state_root(), B256::ZERO);
    }

    #[test]
    fn test_execute_cut() {
        let config = ChainConfig::default();
        let mut execution_layer = ExecutionLayer::new(config).unwrap();

        // Create a Cut with empty transactions
        let cut = Cut {
            block_number: 1,
            timestamp: 1234567890,
            parent_hash: B256::ZERO,
            cars: vec![],
            gas_limit: 30_000_000,
            base_fee_per_gas: Some(1_000_000_000),
        };

        let result = execution_layer.execute_cut(cut).unwrap();
        assert_eq!(result.block_number, 1);
        assert_eq!(result.gas_used, 0);
        assert!(result.receipts.is_empty());
    }

    #[test]
    fn test_execute_cut_with_multiple_cars() {
        let config = ChainConfig::default();
        let mut execution_layer = ExecutionLayer::new(config).unwrap();

        // Create a Cut with multiple empty Cars
        let cut = Cut {
            block_number: 1,
            timestamp: 1234567890,
            parent_hash: B256::ZERO,
            cars: vec![
                Car {
                    validator_id: U256::from(1),
                    transactions: vec![],
                },
                Car {
                    validator_id: U256::from(2),
                    transactions: vec![],
                },
                Car {
                    validator_id: U256::from(3),
                    transactions: vec![],
                },
            ],
            gas_limit: 30_000_000,
            base_fee_per_gas: Some(1_000_000_000),
        };

        let result = execution_layer.execute_cut(cut).unwrap();
        assert_eq!(result.block_number, 1);
        assert_eq!(result.gas_used, 0);
    }

    #[test]
    fn test_get_account_not_found() {
        let config = ChainConfig::default();
        let execution_layer = ExecutionLayer::new(config).unwrap();

        // Query a non-existent account
        let result = execution_layer.get_account(Address::ZERO, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_get_storage() {
        let config = ChainConfig::default();
        let execution_layer = ExecutionLayer::new(config).unwrap();

        // Query storage for non-existent account (returns zero)
        let result = execution_layer.get_storage(Address::ZERO, U256::ZERO, 0);
        assert_eq!(result.unwrap(), U256::ZERO);
    }

    #[test]
    fn test_get_code_no_account() {
        let config = ChainConfig::default();
        let execution_layer = ExecutionLayer::new(config).unwrap();

        // Query code for non-existent account
        let result = execution_layer.get_code(Address::ZERO);
        assert!(result.is_err());
    }

    #[test]
    fn test_rollback_no_snapshot() {
        let config = ChainConfig::default();
        let mut execution_layer = ExecutionLayer::new(config).unwrap();

        // Try to rollback without any snapshots
        let result = execution_layer.rollback_to(100);
        assert!(result.is_err());
    }

    #[test]
    fn test_debug_impl() {
        let config = ChainConfig::default();
        let execution_layer = ExecutionLayer::new(config).unwrap();

        // Verify Debug impl works
        let debug_str = format!("{:?}", execution_layer);
        assert!(debug_str.contains("ExecutionLayer"));
        assert!(debug_str.contains("state_root"));
    }

    #[test]
    fn test_execute_block_via_layer() {
        let config = ChainConfig::default();
        let mut execution_layer = ExecutionLayer::new(config).unwrap();

        let input = BlockInput {
            block_number: 1,
            timestamp: 1234567890,
            transactions: vec![],
            parent_hash: B256::ZERO,
            gas_limit: 30_000_000,
            base_fee_per_gas: Some(1_000_000_000),
        };

        let result = execution_layer.execute_block(input).unwrap();
        assert_eq!(result.block_number, 1);
    }

    #[test]
    fn test_seal_block_via_layer() {
        let config = ChainConfig::default();
        let execution_layer = ExecutionLayer::new(config).unwrap();

        let consensus_block = ConsensusBlock {
            number: 1,
            timestamp: 1234567890,
            parent_hash: B256::ZERO,
            transactions: vec![],
            gas_limit: 30_000_000,
            base_fee_per_gas: Some(1_000_000_000),
        };

        let execution_result = ExecutionResult {
            block_number: 1,
            state_root: B256::ZERO,
            receipts_root: B256::ZERO,
            transactions_root: B256::ZERO,
            gas_used: 0,
            block_hash: B256::ZERO,
            receipts: vec![],
            logs_bloom: Bloom::ZERO,
        };

        let sealed = execution_layer
            .seal_block(consensus_block, execution_result)
            .unwrap();
        assert_eq!(sealed.header.number, 1);
        assert_ne!(sealed.hash, B256::ZERO);
    }

    // ==================== Tests for with_genesis_validators ====================

    #[test]
    fn test_with_genesis_validators_empty_list() {
        let config = ChainConfig::default();
        let provider = InMemoryProvider::new();

        // Create with empty validator list (equivalent to new())
        let execution_layer = ExecutionLayer::with_genesis_validators(config, provider, vec![]);

        // Should initialize successfully with zero state root
        assert_eq!(execution_layer.state_root(), B256::ZERO);
    }

    #[test]
    fn test_with_genesis_validators_single_validator() {
        let config = ChainConfig::default();
        let provider = InMemoryProvider::new();

        let validator = GenesisValidatorData {
            address: Address::repeat_byte(0x01),
            bls_pubkey: [0u8; 48],
            stake: U256::from(32_000_000_000_000_000_000u128), // 32 ETH
        };

        let execution_layer =
            ExecutionLayer::with_genesis_validators(config, provider, vec![validator]);

        // Should initialize successfully
        assert_eq!(execution_layer.state_root(), B256::ZERO);
    }

    #[test]
    fn test_with_genesis_validators_multiple_validators() {
        let config = ChainConfig::default();
        let provider = InMemoryProvider::new();

        let validators = vec![
            GenesisValidatorData {
                address: Address::repeat_byte(0x01),
                bls_pubkey: [0u8; 48],
                stake: U256::from(32_000_000_000_000_000_000u128), // 32 ETH
            },
            GenesisValidatorData {
                address: Address::repeat_byte(0x02),
                bls_pubkey: [1u8; 48],
                stake: U256::from(64_000_000_000_000_000_000u128), // 64 ETH
            },
            GenesisValidatorData {
                address: Address::repeat_byte(0x03),
                bls_pubkey: [2u8; 48],
                stake: U256::from(100_000_000_000_000_000_000u128), // 100 ETH
            },
        ];

        let execution_layer = ExecutionLayer::with_genesis_validators(config, provider, validators);

        // Should initialize successfully
        assert_eq!(execution_layer.state_root(), B256::ZERO);
    }

    // ==================== Tests for validate_transaction ====================

    #[test]
    fn test_validate_transaction_invalid_rlp() {
        let config = ChainConfig::default();
        let execution_layer = ExecutionLayer::new(config).unwrap();

        // Invalid RLP bytes
        let invalid_tx = Bytes::from(vec![0x00, 0x01, 0x02, 0x03]);
        let result = execution_layer.validate_transaction(&invalid_tx);

        assert!(result.is_err());
        // Should fail during RLP decoding or signature recovery
    }

    #[test]
    fn test_validate_transaction_empty_bytes() {
        let config = ChainConfig::default();
        let execution_layer = ExecutionLayer::new(config).unwrap();

        // Empty transaction bytes
        let empty_tx = Bytes::new();
        let result = execution_layer.validate_transaction(&empty_tx);

        assert!(result.is_err());
    }

    #[test]
    fn test_validate_transaction_truncated_tx() {
        let config = ChainConfig::default();
        let execution_layer = ExecutionLayer::new(config).unwrap();

        // Truncated transaction (starts with valid EIP-1559 prefix but incomplete)
        let truncated_tx = Bytes::from(vec![0x02, 0xf8, 0x50]); // EIP-1559 prefix + incomplete RLP
        let result = execution_layer.validate_transaction(&truncated_tx);

        assert!(result.is_err());
    }

    // ==================== Tests for error handling improvements ====================

    #[test]
    fn test_get_account_error_contains_address() {
        let config = ChainConfig::default();
        let execution_layer = ExecutionLayer::new(config).unwrap();

        let test_address = Address::repeat_byte(0xAB);
        let result = execution_layer.get_account(test_address, 0);

        assert!(result.is_err());
        let error_msg = format!("{}", result.unwrap_err());
        // Verify error message contains the address for debugging
        assert!(
            error_msg
                .to_lowercase()
                .contains(&test_address.to_string().to_lowercase()),
            "Error should contain address: {}",
            error_msg
        );
    }

    #[test]
    fn test_rollback_error_contains_block_number() {
        let config = ChainConfig::default();
        let mut execution_layer = ExecutionLayer::new(config).unwrap();

        let result = execution_layer.rollback_to(42);

        assert!(result.is_err());
        let error_msg = format!("{}", result.unwrap_err());
        // Verify error message contains the block number for debugging
        assert!(
            error_msg.contains("42"),
            "Error should contain block number: {}",
            error_msg
        );
    }

    // ==================== Tests for execute_cut with Cars ====================

    #[test]
    fn test_execute_cut_cars_ordering_preserved() {
        let config = ChainConfig::default();
        let mut execution_layer = ExecutionLayer::new(config).unwrap();

        // Create Cars sorted by validator_id (required invariant)
        let cut = Cut {
            block_number: 1,
            timestamp: 1234567890,
            parent_hash: B256::ZERO,
            cars: vec![
                Car {
                    validator_id: U256::from(1),
                    transactions: vec![],
                },
                Car {
                    validator_id: U256::from(5),
                    transactions: vec![],
                },
                Car {
                    validator_id: U256::from(10),
                    transactions: vec![],
                },
            ],
            gas_limit: 30_000_000,
            base_fee_per_gas: Some(1_000_000_000),
        };

        // Should succeed - Cars are properly sorted
        let result = execution_layer.execute_cut(cut);
        assert!(result.is_ok());
    }
}
