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
//! // Create execution layer instance
//! let execution_layer = ExecutionLayer::new(db_path, config)?;
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

pub mod error;
pub mod types;

// Re-export main types for convenience
pub use error::{DatabaseError, ExecutionError, Result};
pub use types::{
    Account, BlockHeader, BlockInput, Car, ChainConfig, ConsensusBlock, Cut, ExecutionBlock,
    ExecutionResult, Log, Receipt, SealedBlock, TransactionReceipt, DELAYED_COMMITMENT_DEPTH,
    STATE_ROOT_SNAPSHOT_INTERVAL,
};

// Re-export commonly used external types
pub use alloy_primitives::{Address, Bloom, Bytes, B256, U256};

/// Main execution layer interface for the consensus layer.
///
/// This struct provides the primary API for executing transactions,
/// validating transactions, querying state, and managing rollbacks.
#[derive(Debug)]
pub struct ExecutionLayer {
    // Will be populated in Phase 2 with:
    // - database provider
    // - execution engine
    // - state manager
    // - chain config
    _private: (),
}

impl ExecutionLayer {
    /// Create a new execution layer instance (placeholder for Phase 2).
    ///
    /// # Arguments
    ///
    /// * `config` - Chain configuration parameters
    ///
    /// # Returns
    ///
    /// Returns an ExecutionLayer instance ready to process transactions.
    #[allow(clippy::new_without_default)]
    pub fn new(_config: ChainConfig) -> Result<Self> {
        // Placeholder: actual initialization will happen in Phase 2
        Ok(Self { _private: () })
    }

    /// Execute a finalized Cut from the consensus layer (placeholder for Phase 3).
    ///
    /// This is the main entry point for block execution. Takes a Cut with ordered
    /// transactions and returns execution results including state root and receipts.
    ///
    /// # Arguments
    ///
    /// * `cut` - Finalized, ordered transactions from consensus
    ///
    /// # Returns
    ///
    /// Returns `ExecutionResult` with state root, receipts root, and gas usage.
    pub fn execute_cut(&mut self, _cut: Cut) -> Result<ExecutionResult> {
        // Placeholder: actual implementation in Phase 3
        Err(ExecutionError::Internal(
            "execute_cut not yet implemented".into(),
        ))
    }

    /// Validate a transaction before mempool insertion (placeholder for Phase 5).
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
    pub fn validate_transaction(&self, _tx: &Bytes) -> Result<()> {
        // Placeholder: actual implementation in Phase 5
        Err(ExecutionError::Internal(
            "validate_transaction not yet implemented".into(),
        ))
    }

    /// Query account state at a specific block height (placeholder for Phase 7).
    ///
    /// # Arguments
    ///
    /// * `address` - Account address to query
    /// * `block_number` - Block height for the query
    ///
    /// # Returns
    ///
    /// Returns the account state (balance, nonce, code hash, storage root).
    pub fn get_account(&self, _address: Address, _block_number: u64) -> Result<Account> {
        // Placeholder: actual implementation in Phase 7
        Err(ExecutionError::Internal(
            "get_account not yet implemented".into(),
        ))
    }

    /// Query contract code (placeholder for Phase 7).
    ///
    /// # Arguments
    ///
    /// * `address` - Contract address
    ///
    /// # Returns
    ///
    /// Returns the contract bytecode.
    pub fn get_code(&self, _address: Address) -> Result<Bytes> {
        // Placeholder: actual implementation in Phase 7
        Err(ExecutionError::Internal(
            "get_code not yet implemented".into(),
        ))
    }

    /// Query storage slot at a specific block height (placeholder for Phase 7).
    ///
    /// # Arguments
    ///
    /// * `address` - Contract address
    /// * `slot` - Storage slot key
    /// * `block_number` - Block height for the query
    ///
    /// # Returns
    ///
    /// Returns the storage slot value.
    pub fn get_storage(
        &self,
        _address: Address,
        _slot: U256,
        _block_number: u64,
    ) -> Result<U256> {
        // Placeholder: actual implementation in Phase 7
        Err(ExecutionError::Internal(
            "get_storage not yet implemented".into(),
        ))
    }

    /// Rollback to a previous block for reorg handling (placeholder for Phase 8).
    ///
    /// # Arguments
    ///
    /// * `target_block` - Block number to rollback to
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if rollback succeeds.
    pub fn rollback_to(&mut self, _target_block: u64) -> Result<()> {
        // Placeholder: actual implementation in Phase 8
        Err(ExecutionError::Internal(
            "rollback_to not yet implemented".into(),
        ))
    }
}
