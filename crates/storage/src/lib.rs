//! Block and state storage for CipherBFT.
//!
//! This crate provides RocksDB-backed persistence with WAL for crash recovery.

#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]

pub mod blockstore;
pub mod recovery;
pub mod statestore;
pub mod wal;

pub use blockstore::BlockStore;
pub use wal::WAL;
