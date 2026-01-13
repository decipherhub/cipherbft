//! Database wrapper for MDBX backend
//!
//! This module provides a high-level wrapper around reth-db's MDBX database,
//! handling initialization, configuration, and table creation.

use crate::error::{Result, StorageError};
use reth_db::{
    mdbx::{init_db_for, DatabaseArguments},
    ClientVersion, DatabaseEnv as RethDatabaseEnv,
};
use reth_db_api::database::Database as DatabaseTrait;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::{debug, info};

use super::tables::Tables;

/// Database configuration
#[derive(Debug, Clone)]
pub struct DatabaseConfig {
    /// Path to the database directory
    pub path: PathBuf,
    /// Maximum database size in bytes (default: 1TB)
    pub max_size: usize,
    /// Maximum number of readers (default: 256)
    pub max_readers: u32,
    /// Grow step when database needs more space (default: 4GB)
    pub growth_step: usize,
    /// Enable read-only mode
    pub read_only: bool,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            path: PathBuf::from("data/cipherbft"),
            max_size: 1024 * 1024 * 1024 * 1024, // 1TB
            max_readers: 256,
            growth_step: 4 * 1024 * 1024 * 1024, // 4GB
            read_only: false,
        }
    }
}

impl DatabaseConfig {
    /// Create a new config with the given path
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            ..Default::default()
        }
    }

    /// Set read-only mode
    pub fn read_only(mut self, read_only: bool) -> Self {
        self.read_only = read_only;
        self
    }

    /// Set maximum database size
    pub fn max_size(mut self, size: usize) -> Self {
        self.max_size = size;
        self
    }
}

/// Database environment wrapper type
///
/// Uses WriteMap for writable databases, NoWriteMap for read-only.
pub type DatabaseEnv = RethDatabaseEnv;

/// CipherBFT database wrapper
///
/// Wraps reth-db's MDBX environment and provides high-level operations.
pub struct Database {
    /// The underlying reth-db environment
    env: Arc<DatabaseEnv>,
    /// Configuration used to open the database
    config: DatabaseConfig,
}

impl Database {
    /// Open a database at the specified path
    ///
    /// This creates the database if it doesn't exist and initializes all CipherBFT
    /// custom tables (Consensus, EVM, Staking) using the TableSet implementation.
    pub fn open(config: DatabaseConfig) -> Result<Self> {
        info!(path = %config.path.display(), "Opening CipherBFT database");

        // Ensure directory exists
        if !config.path.exists() {
            std::fs::create_dir_all(&config.path)?;
        }

        // Build database arguments
        let args = DatabaseArguments::new(ClientVersion::default())
            .with_max_read_transaction_duration(Some(
                reth_db::mdbx::MaxReadTransactionDuration::Set(std::time::Duration::from_secs(60)),
            ));

        // Open the environment and create CipherBFT custom tables
        // Uses init_db_for<Tables> to create all our custom tables (Consensus, EVM, Staking)
        // instead of reth's default tables
        let env = init_db_for::<_, Tables>(&config.path, args)
            .map_err(|e| StorageError::Database(format!("Failed to open database: {e}")))?;

        debug!("Database opened successfully with CipherBFT tables");

        Ok(Self {
            env: Arc::new(env),
            config,
        })
    }

    /// Open a database for testing with a temporary directory
    #[cfg(test)]
    pub fn open_temp() -> Result<(Self, tempfile::TempDir)> {
        let temp_dir = tempfile::tempdir()?;

        let config = DatabaseConfig::new(temp_dir.path());
        let db = Self::open(config)?;

        Ok((db, temp_dir))
    }

    /// Get the underlying database environment
    pub fn env(&self) -> &Arc<DatabaseEnv> {
        &self.env
    }

    /// Get the database path
    pub fn path(&self) -> &Path {
        &self.config.path
    }

    /// Check if the database is read-only
    pub fn is_read_only(&self) -> bool {
        self.config.read_only
    }

    /// Create a read transaction
    pub fn tx(&self) -> Result<impl reth_db_api::transaction::DbTx + '_> {
        self.env
            .tx()
            .map_err(|e| StorageError::Database(format!("Failed to create read transaction: {e}")))
    }

    /// Create a write transaction
    pub fn tx_mut(
        &self,
    ) -> Result<impl reth_db_api::transaction::DbTxMut + reth_db_api::transaction::DbTx + '_> {
        if self.config.read_only {
            return Err(StorageError::Database(
                "Cannot create write transaction on read-only database".into(),
            ));
        }

        self.env
            .tx_mut()
            .map_err(|e| StorageError::Database(format!("Failed to create write transaction: {e}")))
    }

    /// Get database statistics
    pub fn stats(&self) -> Result<DatabaseStats> {
        let stat = self
            .env
            .stat()
            .map_err(|e| StorageError::Database(format!("Failed to get database stats: {e}")))?;

        Ok(DatabaseStats {
            page_size: stat.page_size(),
            tree_depth: stat.depth(),
            branch_pages: stat.branch_pages() as u64,
            leaf_pages: stat.leaf_pages() as u64,
            overflow_pages: stat.overflow_pages() as u64,
            entries: stat.entries() as u64,
        })
    }
}

impl Clone for Database {
    fn clone(&self) -> Self {
        Self {
            env: Arc::clone(&self.env),
            config: self.config.clone(),
        }
    }
}

/// Database statistics
#[derive(Debug, Clone, Default)]
pub struct DatabaseStats {
    /// Page size in bytes
    pub page_size: u32,
    /// B-tree depth
    pub tree_depth: u32,
    /// Number of branch pages
    pub branch_pages: u64,
    /// Number of leaf pages
    pub leaf_pages: u64,
    /// Number of overflow pages
    pub overflow_pages: u64,
    /// Number of entries
    pub entries: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_database_config_default() {
        let config = DatabaseConfig::default();
        assert_eq!(config.max_readers, 256);
        assert!(!config.read_only);
    }

    #[test]
    fn test_database_config_builder() {
        let config = DatabaseConfig::new("/tmp/test")
            .read_only(true)
            .max_size(1024);

        assert_eq!(config.path, PathBuf::from("/tmp/test"));
        assert!(config.read_only);
        assert_eq!(config.max_size, 1024);
    }

    // Note: Actual database tests require the mdbx feature to be enabled
    // and are integration tests rather than unit tests.
}
