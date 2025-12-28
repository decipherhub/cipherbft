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

pub mod error;
pub mod config;
pub mod transaction;
pub mod account;
pub mod pool;

pub use error::MempoolError;
pub use config::MempoolConfig;
pub use transaction::TransactionOrdering;
pub use account::AccountValidator;
pub use pool::CipherBftPool;
