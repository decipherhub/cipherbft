//! Worker process for DCL
//!
//! The Worker is responsible for:
//! - Receiving transactions from mempool
//! - Batching transactions by size or time threshold
//! - Broadcasting batches to peer Workers
//! - Storing batches locally
//! - Reporting batch digests to Primary
//! - Responding to batch requests from peers

pub mod batch_maker;
pub mod config;
pub mod core;
pub mod state;
pub mod synchronizer;

pub use config::WorkerConfig;
pub use core::{Worker, WorkerCommand, WorkerEvent, WorkerHandle, WorkerNetwork};
pub use state::WorkerState;
