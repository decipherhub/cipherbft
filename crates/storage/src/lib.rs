//! Storage layer for CipherBFT
//!
//! This crate provides storage abstractions for the Data Chain Layer (DCL)
//! per ADR-010. It defines traits for storing and retrieving:
//! - Batches from Workers
//! - Cars from Primary
//! - Attestations
//! - Cuts (pending and finalized)
//!
//! # Architecture
//!
//! The storage layer uses trait-based abstractions to allow multiple backends:
//! - [`DclStore`]: Main trait for DCL storage operations
//! - [`InMemoryStore`]: In-memory implementation for testing
//! - [`mdbx::MdbxDclStore`]: MDBX-backed implementation for production (requires `mdbx` feature)
//!
//! # Write-Ahead Log (WAL)
//!
//! The [`Wal`] trait provides crash recovery guarantees:
//! - All state changes are logged before being applied
//! - On recovery, the WAL is replayed to restore state
//!
//! # Usage
//!
//! ## In-Memory Store (Testing)
//!
//! ```ignore
//! use cipherbft_storage::{DclStore, InMemoryStore};
//!
//! let store = InMemoryStore::new();
//! store.put_batch(batch).await?;
//! store.put_car(car).await?;
//! ```
//!
//! ## MDBX Store (Production)
//!
//! Requires the `mdbx` feature:
//!
//! ```ignore
//! use cipherbft_storage::mdbx::{Database, DatabaseConfig, MdbxDclStore};
//! use std::sync::Arc;
//!
//! let config = DatabaseConfig::new("/path/to/db");
//! let db = Arc::new(Database::open(config)?);
//! let store = MdbxDclStore::new(db);
//! store.put_batch(batch).await?;
//! ```
//!
//! # Feature Flags
//!
//! - `mdbx`: Enables the MDBX storage backend using reth-db

pub mod dcl;
pub mod error;
pub mod evm;
pub mod memory;
pub mod pruning;
pub mod staking;
pub mod tables;
pub mod wal;

// MDBX backend (requires feature flag)
#[cfg(feature = "mdbx")]
pub mod mdbx;

pub use dcl::DclStore;
pub use error::StorageError;
pub use evm::{EvmAccount, EvmBytecode, EvmStore, EvmStoreResult};
pub use memory::InMemoryStore;
pub use pruning::{PruningConfig, PruningHandle, PruningTask};
pub use staking::{StakingStore, StakingStoreResult, StoredValidator};
pub use wal::{Wal, WalEntry};

// Re-export MDBX types when feature is enabled
#[cfg(feature = "mdbx")]
pub use mdbx::{Database, DatabaseConfig, MdbxDclStore, MdbxEvmStore, MdbxStakingStore, MdbxWal};
