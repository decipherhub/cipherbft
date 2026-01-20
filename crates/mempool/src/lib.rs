//! CipherBFT Mempool - Transaction mempool based on Reth's TransactionPool
//!
//! # Architecture
//!
//! The mempool is organized around Reth's transaction pool with CipherBFT-specific
//! wrapping for DCL/CL integration.
//!
//! ## Modules
//!
//! - `error`: Error types for mempool operations
//! - `config`: Configuration for the mempool
//! - `transaction`: Transaction metadata tracking
//! - `account`: Per-account state management
//! - `pool`: Main pool adapter over Reth's TransactionPool

pub mod config;
pub mod error;
pub mod pool;
pub mod transaction;
pub mod validator;

pub use config::MempoolConfig;
pub use error::MempoolError;
pub use pool::CipherBftPool;
pub use transaction::TransactionOrdering;
pub use validator::{CipherBftValidator, ExecutionLayerValidator, ExecutionValidationError};
