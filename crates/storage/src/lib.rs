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
//! - Future: RocksDB/MDBX implementation for production
//!
//! # Write-Ahead Log (WAL)
//!
//! The [`Wal`] trait provides crash recovery guarantees:
//! - All state changes are logged before being applied
//! - On recovery, the WAL is replayed to restore state
//!
//! # Usage
//!
//! ```ignore
//! use cipherbft_storage::{DclStore, InMemoryStore};
//!
//! let store = InMemoryStore::new();
//! store.put_batch(batch).await?;
//! store.put_car(car).await?;
//! ```

pub mod dcl;
pub mod error;
pub mod memory;
pub mod tables;
pub mod wal;

pub use dcl::DclStore;
pub use error::StorageError;
pub use memory::InMemoryStore;
pub use wal::{Wal, WalEntry};
