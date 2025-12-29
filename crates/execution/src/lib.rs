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
    BlockHeader, BlockInput, ConsensusBlock, ExecutionBlock, ExecutionResult, Log, SealedBlock,
    TransactionReceipt, DELAYED_COMMITMENT_DEPTH, STATE_ROOT_SNAPSHOT_INTERVAL,
};

// Re-export commonly used external types
pub use alloy_primitives::{Address, Bloom, Bytes, B256, U256};
