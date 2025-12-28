//! MDBX storage backend for CipherBFT
//!
//! This module provides persistent storage using reth-db (MDBX) per ADR-010.
//!
//! # Architecture
//!
//! The MDBX backend consists of:
//! - [`Database`]: Main database wrapper around reth-db
//! - [`Tables`]: Custom table definitions for DCL and consensus data
//! - [`MdbxDclStore`]: Implementation of [`DclStore`] trait
//! - [`MdbxWal`]: Persistent WAL implementation
//!
//! # Feature Flag
//!
//! This module is only available when the `mdbx` feature is enabled:
//! ```toml
//! cipherbft-storage = { version = "0.1", features = ["mdbx"] }
//! ```

mod database;
mod provider;
mod tables;
mod wal;

pub use database::{Database, DatabaseConfig, DatabaseEnv};
pub use provider::MdbxDclStore;
pub use tables::Tables;
pub use wal::MdbxWal;
