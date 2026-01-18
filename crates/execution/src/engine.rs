//! Execution engine implementation.
//!
//! This module provides the core execution engine that ties together all components
//! of the execution layer: EVM execution, state management, and block processing.

use crate::{
    database::{CipherBftDatabase, Provider},
    error::{ExecutionError, Result},
    evm::CipherBftEvmConfig,
    precompiles::StakingPrecompile,
    receipts::{
        compute_logs_bloom_from_transactions, compute_receipts_root, compute_transactions_root,
    },
    state::StateManager,
    types::{
        BlockHeader, BlockInput, ChainConfig, ConsensusBlock, ExecutionResult, Log, SealedBlock,
        TransactionReceipt, DELAYED_COMMITMENT_DEPTH,
    },
};
use alloy_consensus::Header as AlloyHeader;
use alloy_primitives::{Address, Bytes, B256, B64, U256};
use parking_lot::RwLock;
use revm::primitives::hardfork::SpecId;
use std::num::NonZeroUsize;
use std::sync::Arc;

/// Number of block hashes to cache for BLOCKHASH opcode (256 per EIP-210, compile-time verified).
const BLOCK_HASH_CACHE_SIZE: NonZeroUsize = match NonZeroUsize::new(256) {
    Some(n) => n,
    None => panic!("block hash cache size must be non-zero"),
};

/// ExecutionLayer trait defines the interface for block execution.
///
/// This trait provides the core methods needed by the consensus layer to:
/// - Execute blocks with ordered transactions
/// - Validate blocks and transactions
/// - Query state and block information
/// - Manage state roots and rollbacks
pub trait ExecutionLayer {
    /// Execute a block with ordered transactions.
    ///
    /// # Arguments
    /// * `input` - Block input with ordered transactions
    ///
    /// # Returns
    /// * Execution result with state root, receipts, and gas usage
    fn execute_block(&mut self, input: BlockInput) -> Result<ExecutionResult>;

    /// Validate a block before execution.
    ///
    /// # Arguments
    /// * `input` - Block input to validate
    ///
    /// # Returns
    /// * Ok(()) if valid, error otherwise
    fn validate_block(&self, input: &BlockInput) -> Result<()>;

    /// Validate a transaction before mempool insertion.
    ///
    /// # Arguments
    /// * `tx` - Transaction bytes to validate
    ///
    /// # Returns
    /// * Ok(()) if valid, error otherwise
    fn validate_transaction(&self, tx: &Bytes) -> Result<()>;

    /// Seal a block after execution.
    ///
    /// # Arguments
    /// * `consensus_block` - Block data from consensus
    /// * `execution_result` - Result of block execution
    ///
    /// # Returns
    /// * Sealed block with final hash
    fn seal_block(
        &self,
        consensus_block: ConsensusBlock,
        execution_result: ExecutionResult,
    ) -> Result<SealedBlock>;

    /// Get the block hash at a specific height (for delayed commitment).
    ///
    /// # Arguments
    /// * `height` - Block number to query
    ///
    /// # Returns
    /// * Block hash at the given height
    fn get_delayed_block_hash(&self, height: u64) -> Result<B256>;

    /// Get the current state root.
    ///
    /// # Returns
    /// * Current state root hash
    fn state_root(&self) -> B256;
}

/// Main execution engine implementation.
///
/// ExecutionEngine coordinates all execution layer components:
/// - Database for state storage
/// - StateManager for state roots and snapshots
/// - EVM configuration for transaction execution
/// - Block processing and sealing
/// - Staking precompile for validator management
pub struct ExecutionEngine<P: Provider> {
    /// Chain configuration.
    chain_config: ChainConfig,

    /// Database for state storage.
    database: CipherBftDatabase<P>,

    /// State manager for state roots and snapshots.
    state_manager: StateManager<P>,

    /// EVM configuration.
    evm_config: CipherBftEvmConfig,

    /// Staking precompile instance (shared across all EVM instances).
    staking_precompile: Arc<StakingPrecompile>,

    /// Block hash storage (for BLOCKHASH opcode and delayed commitment).
    block_hashes: RwLock<lru::LruCache<u64, B256>>,

    /// Current block number.
    current_block: u64,
}

impl<P: Provider + Clone> ExecutionEngine<P> {
    /// Create a new execution engine.
    ///
    /// # Arguments
    /// * `chain_config` - Chain configuration parameters
    /// * `provider` - Storage provider (factory pattern)
    ///
    /// # Returns
    /// * New ExecutionEngine instance
    pub fn new(chain_config: ChainConfig, provider: P) -> Self {
        let evm_config = CipherBftEvmConfig::new(
            chain_config.chain_id,
            SpecId::CANCUN,
            chain_config.block_gas_limit,
            chain_config.base_fee_per_gas,
        );

        let database = CipherBftDatabase::new(provider.clone());
        let state_manager = StateManager::new(provider);

        // Create staking precompile instance (shared across all EVM instances)
        let staking_precompile = Arc::new(StakingPrecompile::new());

        Self {
            chain_config,
            database,
            state_manager,
            evm_config,
            staking_precompile,
            block_hashes: RwLock::new(lru::LruCache::new(BLOCK_HASH_CACHE_SIZE)),
            current_block: 0,
        }
    }

    /// Process all transactions in a block.
    fn process_transactions(
        &mut self,
        transactions: &[Bytes],
        block_number: u64,
        timestamp: u64,
        parent_hash: B256,
    ) -> Result<(Vec<TransactionReceipt>, u64, Vec<Vec<Log>>)> {
        let mut receipts = Vec::new();
        let mut cumulative_gas_used = 0u64;
        let mut all_logs = Vec::new();

        // Scope for EVM execution to ensure it's dropped before commit
        let state_changes = {
            // Build EVM instance with custom precompiles (including staking precompile at 0x100)
            let mut evm = self.evm_config.build_evm_with_precompiles(
                &mut self.database,
                block_number,
                timestamp,
                parent_hash,
                Arc::clone(&self.staking_precompile),
            );

            for (tx_index, tx_bytes) in transactions.iter().enumerate() {
                // Execute transaction
                let tx_result = self.evm_config.execute_transaction(&mut evm, tx_bytes)?;

                cumulative_gas_used += tx_result.gas_used;

                // Compute logs bloom for this transaction
                let logs_bloom = crate::receipts::logs_bloom(&tx_result.logs);

                // Create receipt
                let receipt = TransactionReceipt {
                    transaction_hash: tx_result.tx_hash,
                    transaction_index: tx_index as u64,
                    block_hash: B256::ZERO, // Will be set after block is sealed
                    block_number,
                    from: tx_result.sender,
                    to: tx_result.to,
                    cumulative_gas_used,
                    gas_used: tx_result.gas_used,
                    contract_address: tx_result.contract_address,
                    logs: tx_result.logs.clone(),
                    logs_bloom,
                    status: if tx_result.success { 1 } else { 0 },
                    effective_gas_price: self.chain_config.base_fee_per_gas,
                    transaction_type: 2, // EIP-1559
                };

                receipts.push(receipt);
                all_logs.push(tx_result.logs);
            }

            // Finalize EVM to extract journal changes
            // This is necessary to persist nonce increments and other state changes between blocks
            use revm::handler::ExecuteEvm;
            evm.finalize()
        }; // EVM is dropped here, releasing the mutable borrow

        // Apply state changes to the database using DatabaseCommit trait
        // This adds the changes to pending state
        <CipherBftDatabase<P> as revm::DatabaseCommit>::commit(&mut self.database, state_changes);

        // Commit pending state changes to persistent storage
        self.database.commit()?;

        Ok((receipts, cumulative_gas_used, all_logs))
    }

    /// Compute or retrieve state root based on block number.
    fn handle_state_root(&self, block_number: u64) -> Result<B256> {
        if self.state_manager.should_compute_state_root(block_number) {
            // Checkpoint block - compute new state root
            self.state_manager.compute_state_root(block_number)
        } else {
            // Non-checkpoint block - use current state root
            Ok(self.state_manager.current_state_root())
        }
    }

    /// Store block hash for BLOCKHASH opcode and delayed commitment.
    fn store_block_hash(&self, block_number: u64, block_hash: B256) {
        self.block_hashes.write().put(block_number, block_hash);
    }
}

impl<P: Provider + Clone> ExecutionLayer for ExecutionEngine<P> {
    fn execute_block(&mut self, input: BlockInput) -> Result<ExecutionResult> {
        tracing::info!(
            block_number = input.block_number,
            tx_count = input.transactions.len(),
            "Executing block"
        );

        // Validate block first
        self.validate_block(&input)?;

        // Process all transactions
        let (receipts, gas_used, all_logs) = self.process_transactions(
            &input.transactions,
            input.block_number,
            input.timestamp,
            input.parent_hash,
        )?;

        // Compute state root (periodic)
        let state_root = self.handle_state_root(input.block_number)?;

        // Compute receipts root
        let receipt_rlp: Vec<Bytes> = receipts
            .iter()
            .map(|r| {
                bincode::serialize(r).map(Bytes::from).map_err(|e| {
                    ExecutionError::Internal(format!("Receipt serialization failed: {e}"))
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let receipts_root = compute_receipts_root(&receipt_rlp)?;

        // Compute transactions root
        let transactions_root = compute_transactions_root(&input.transactions)?;

        // Compute logs bloom
        let logs_bloom = compute_logs_bloom_from_transactions(&all_logs);

        // Get delayed block hash (block N-2 for block N)
        let delayed_height = input.block_number.saturating_sub(DELAYED_COMMITMENT_DEPTH);
        let block_hash = if delayed_height == 0 || delayed_height < DELAYED_COMMITMENT_DEPTH {
            // Early blocks don't have enough history for delayed commitment
            B256::ZERO
        } else {
            // Try to get the hash, but if not found (e.g., not sealed yet), use zero
            self.get_delayed_block_hash(delayed_height)
                .unwrap_or(B256::ZERO)
        };

        // Update current block number
        self.current_block = input.block_number;

        tracing::info!(
            block_number = input.block_number,
            gas_used,
            receipts_count = receipts.len(),
            "Block execution complete"
        );

        Ok(ExecutionResult {
            block_number: input.block_number,
            state_root,
            receipts_root,
            transactions_root,
            gas_used,
            block_hash,
            receipts,
            logs_bloom,
        })
    }

    fn validate_block(&self, input: &BlockInput) -> Result<()> {
        // Validate block number is sequential
        if input.block_number != self.current_block + 1 && self.current_block != 0 {
            return Err(ExecutionError::InvalidBlock(format!(
                "Invalid block number: expected {}, got {}",
                self.current_block + 1,
                input.block_number
            )));
        }

        // Validate gas limit
        if input.gas_limit == 0 {
            return Err(ExecutionError::InvalidBlock(
                "Gas limit cannot be zero".to_string(),
            ));
        }

        // Validate timestamp is increasing
        // (In a full implementation, we would check against parent block timestamp)

        Ok(())
    }

    fn validate_transaction(&self, tx: &Bytes) -> Result<()> {
        // 1. Parse and recover sender (includes signature verification)
        // tx_env() internally performs:
        //   - RLP decoding of the transaction envelope
        //   - Signature hash computation
        //   - ECDSA signature recovery to get sender address
        // If any of these fail, an error is returned
        let (tx_env, _tx_hash, sender, _to) = self.evm_config.tx_env(tx)?;

        // 2. Validate chain ID (EIP-155 replay protection)
        if let Some(tx_chain_id) = tx_env.chain_id {
            if tx_chain_id != self.evm_config.chain_id {
                return Err(ExecutionError::invalid_transaction(format!(
                    "Chain ID mismatch: expected {}, got {}",
                    self.evm_config.chain_id, tx_chain_id
                )));
            }
        }

        // 3. Validate gas limit
        if tx_env.gas_limit == 0 {
            return Err(ExecutionError::invalid_transaction(
                "Gas limit cannot be zero",
            ));
        }
        if tx_env.gas_limit > self.evm_config.block_gas_limit {
            return Err(ExecutionError::invalid_transaction(format!(
                "Gas limit exceeds block limit: {} > {}",
                tx_env.gas_limit, self.evm_config.block_gas_limit
            )));
        }

        // 4. Get sender account from database
        let account = self.database.get_account(sender)?;

        // 5. Validate nonce
        // For mempool validation, we accept nonce >= account.nonce
        // (allows for pending transactions with future nonces)
        if let Some(ref acc) = account {
            if tx_env.nonce < acc.nonce {
                return Err(ExecutionError::invalid_transaction(format!(
                    "Nonce too low: have {}, want >= {}",
                    tx_env.nonce, acc.nonce
                )));
            }
        }

        // 6. Calculate effective gas price (EIP-1559 compatible)
        let effective_gas_price = match tx_env.gas_priority_fee {
            Some(priority_fee) => {
                // EIP-1559 transaction: effective = min(max_fee, base_fee + priority_fee)
                let base_fee = self.evm_config.base_fee_per_gas as u128;
                let max_fee = tx_env.gas_price;
                std::cmp::min(max_fee, base_fee + priority_fee)
            }
            None => {
                // Legacy transaction: effective = gas_price
                tx_env.gas_price
            }
        };

        // 7. Validate balance covers gas cost + transfer value
        // gas_cost = gas_limit * effective_gas_price
        // total_cost = gas_cost + value
        let gas_cost = U256::from(tx_env.gas_limit) * U256::from(effective_gas_price);
        let total_cost = gas_cost + tx_env.value;

        if let Some(ref acc) = account {
            if acc.balance < total_cost {
                return Err(ExecutionError::invalid_transaction(format!(
                    "Insufficient balance: have {}, need {}",
                    acc.balance, total_cost
                )));
            }
        } else if !total_cost.is_zero() {
            // Account doesn't exist and transaction requires funds
            return Err(ExecutionError::invalid_transaction(
                "Sender account not found",
            ));
        }

        Ok(())
    }

    fn seal_block(
        &self,
        consensus_block: ConsensusBlock,
        execution_result: ExecutionResult,
    ) -> Result<SealedBlock> {
        // Build block header
        let header = BlockHeader {
            parent_hash: consensus_block.parent_hash,
            ommers_hash: alloy_primitives::keccak256([]), // Empty ommers
            beneficiary: Address::ZERO,                   // No coinbase in PoS
            state_root: execution_result.state_root,
            transactions_root: execution_result.transactions_root,
            receipts_root: execution_result.receipts_root,
            logs_bloom: execution_result.logs_bloom,
            difficulty: U256::ZERO, // PoS has zero difficulty
            number: consensus_block.number,
            gas_limit: consensus_block.gas_limit,
            gas_used: execution_result.gas_used,
            timestamp: consensus_block.timestamp,
            extra_data: Bytes::new(),
            mix_hash: consensus_block.parent_hash, // Use parent hash as mix_hash
            nonce: B64::ZERO,                      // PoS has zero nonce
            base_fee_per_gas: consensus_block.base_fee_per_gas,
            withdrawals_root: None,
            blob_gas_used: None,
            excess_blob_gas: None,
            parent_beacon_block_root: None,
        };

        // Compute block hash
        let alloy_header: AlloyHeader = SealedBlock {
            header: header.clone(),
            hash: B256::ZERO, // Temporary
            transactions: consensus_block.transactions.clone(),
            total_difficulty: U256::ZERO,
        }
        .into();
        let block_hash = alloy_header.hash_slow();

        // Store block hash for delayed commitment
        self.store_block_hash(consensus_block.number, block_hash);

        Ok(SealedBlock {
            header,
            hash: block_hash,
            transactions: consensus_block.transactions,
            total_difficulty: U256::ZERO,
        })
    }

    fn get_delayed_block_hash(&self, height: u64) -> Result<B256> {
        self.block_hashes
            .write()
            .get(&height)
            .copied()
            .ok_or_else(|| {
                ExecutionError::InvalidBlock(format!("Block hash not found at height {height}"))
            })
    }

    fn state_root(&self) -> B256 {
        self.state_manager.current_state_root()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::InMemoryProvider;
    use alloy_primitives::Bloom;

    fn create_test_engine() -> ExecutionEngine<InMemoryProvider> {
        let provider = InMemoryProvider::new();
        let config = ChainConfig::default();
        ExecutionEngine::new(config, provider)
    }

    #[test]
    fn test_engine_creation() {
        let engine = create_test_engine();
        assert_eq!(engine.chain_config.chain_id, 85300);
        assert_eq!(engine.chain_config.block_gas_limit, 30_000_000);
    }

    #[test]
    fn test_validate_block_sequential() {
        let engine = create_test_engine();

        // First block should be valid
        let input = BlockInput {
            block_number: 1,
            timestamp: 1234567890,
            transactions: vec![],
            parent_hash: B256::ZERO,
            gas_limit: 30_000_000,
            base_fee_per_gas: Some(1_000_000_000),
        };

        assert!(engine.validate_block(&input).is_ok());
    }

    #[test]
    fn test_validate_block_non_sequential() {
        let mut engine = create_test_engine();
        engine.current_block = 5;

        // Skipping blocks should fail
        let input = BlockInput {
            block_number: 10,
            timestamp: 1234567890,
            transactions: vec![],
            parent_hash: B256::ZERO,
            gas_limit: 30_000_000,
            base_fee_per_gas: Some(1_000_000_000),
        };

        assert!(engine.validate_block(&input).is_err());
    }

    #[test]
    fn test_validate_block_zero_gas_limit() {
        let engine = create_test_engine();

        let input = BlockInput {
            block_number: 1,
            timestamp: 1234567890,
            transactions: vec![],
            parent_hash: B256::ZERO,
            gas_limit: 0,
            base_fee_per_gas: Some(1_000_000_000),
        };

        assert!(engine.validate_block(&input).is_err());
    }

    #[test]
    fn test_execute_empty_block() {
        let mut engine = create_test_engine();

        let input = BlockInput {
            block_number: 1,
            timestamp: 1234567890,
            transactions: vec![],
            parent_hash: B256::ZERO,
            gas_limit: 30_000_000,
            base_fee_per_gas: Some(1_000_000_000),
        };

        let result = engine.execute_block(input).unwrap();

        assert_eq!(result.block_number, 1);
        assert_eq!(result.gas_used, 0);
        assert_eq!(result.receipts.len(), 0);
        assert_eq!(result.logs_bloom, Bloom::ZERO);
    }

    #[test]
    fn test_seal_block() {
        let engine = create_test_engine();

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

        let sealed = engine
            .seal_block(consensus_block, execution_result)
            .unwrap();

        assert_eq!(sealed.header.number, 1);
        assert_eq!(sealed.header.gas_used, 0);
        assert_ne!(sealed.hash, B256::ZERO);
    }

    #[test]
    fn test_state_root() {
        let engine = create_test_engine();
        let state_root = engine.state_root();
        assert_eq!(state_root, B256::ZERO); // Initial state
    }

    #[test]
    fn test_delayed_block_hash() {
        let engine = create_test_engine();
        let block_hash = B256::from([42u8; 32]);

        engine.store_block_hash(100, block_hash);

        let retrieved = engine.get_delayed_block_hash(100).unwrap();
        assert_eq!(retrieved, block_hash);
    }

    #[test]
    fn test_delayed_block_hash_not_found() {
        let engine = create_test_engine();
        let result = engine.get_delayed_block_hash(999);
        assert!(result.is_err());
    }
}
