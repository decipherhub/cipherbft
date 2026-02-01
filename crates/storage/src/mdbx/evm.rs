//! MDBX-based implementation of EVM storage.
//!
//! This module provides the [`MdbxEvmStore`] implementation of [`EvmStore`] trait
//! using MDBX as the backing storage engine.

use std::sync::Arc;
use std::time::Instant;

use cipherbft_metrics::storage::{
    STORAGE_BATCH_COMMIT, STORAGE_READ_LATENCY, STORAGE_WRITE_LATENCY,
};
use reth_db::Database;
use reth_db_api::cursor::DbCursorRO;
use reth_db_api::transaction::{DbTx, DbTxMut};

use super::database::DatabaseEnv;
use super::tables::{
    AddressKey, BlockNumberKey, EvmAccounts, EvmBlockHashes, EvmCode, EvmMetadata, EvmStorage,
    HashKey, StorageSlotKey, StoredAccount, StoredBytecode, StoredEvmMetadata, StoredStorageValue,
    UnitKey,
};
use crate::error::StorageError;
use crate::evm::{EvmAccount, EvmBytecode, EvmStore, EvmStoreResult};

/// Helper to convert database errors to storage errors.
fn db_err(e: impl std::fmt::Display) -> StorageError {
    StorageError::Database(e.to_string())
}

/// MDBX-based EVM storage implementation.
///
/// This implementation uses reth-db (MDBX) for persistent storage of EVM state.
/// It stores accounts, code, storage slots, and block hashes in separate tables.
#[derive(Clone)]
pub struct MdbxEvmStore {
    db: Arc<DatabaseEnv>,
}

impl MdbxEvmStore {
    /// Create a new MDBX EVM store.
    ///
    /// # Arguments
    /// * `db` - Shared reference to the MDBX database environment
    pub fn new(db: Arc<DatabaseEnv>) -> Self {
        Self { db }
    }

    /// Get all accounts from the database using cursor iteration.
    ///
    /// Returns all accounts stored in the EvmAccounts table.
    /// This is useful for debugging, state export, and migration purposes.
    ///
    /// # Returns
    /// A vector of (address, account) tuples ordered by address.
    pub fn get_all_accounts(&self) -> EvmStoreResult<Vec<([u8; 20], EvmAccount)>> {
        let tx = self.db.tx().map_err(|e| db_err(e.to_string()))?;

        let mut cursor = tx
            .cursor_read::<EvmAccounts>()
            .map_err(|e| db_err(e.to_string()))?;

        let mut accounts = Vec::new();

        // Iterate through all accounts using cursor
        let mut entry = cursor.first().map_err(|e| db_err(e.to_string()))?;

        while let Some((key, stored)) = entry {
            let account = EvmAccount {
                nonce: stored.0.nonce,
                balance: stored.0.balance,
                code_hash: stored.0.code_hash,
                storage_root: stored.0.storage_root,
            };
            accounts.push((key.0, account));

            entry = cursor.next().map_err(|e| db_err(e.to_string()))?;
        }

        Ok(accounts)
    }

    /// Get all storage slots for a specific address using cursor iteration.
    ///
    /// Returns all storage slots stored for the given address in the EvmStorage table.
    /// This is useful for debugging, state export, and contract inspection.
    ///
    /// # Arguments
    /// * `address` - The 20-byte Ethereum address to get storage for
    ///
    /// # Returns
    /// A vector of (slot, value) tuples ordered by slot.
    pub fn get_all_storage(&self, address: &[u8; 20]) -> EvmStoreResult<Vec<([u8; 32], [u8; 32])>> {
        let tx = self.db.tx().map_err(|e| db_err(e.to_string()))?;

        let mut cursor = tx
            .cursor_read::<EvmStorage>()
            .map_err(|e| db_err(e.to_string()))?;

        let mut storage = Vec::new();

        // Start at the first possible key for this address
        let start_key = StorageSlotKey {
            address: *address,
            slot: [0u8; 32],
        };

        // Seek to the first entry for this address
        let mut entry = cursor.seek(start_key).map_err(|e| db_err(e.to_string()))?;

        // Iterate through all storage slots for this address
        while let Some((key, stored)) = entry {
            // Check if we've moved past this address
            if key.address != *address {
                break;
            }

            storage.push((key.slot, stored.0.value));

            entry = cursor.next().map_err(|e| db_err(e.to_string()))?;
        }

        Ok(storage)
    }
}

impl EvmStore for MdbxEvmStore {
    fn get_account(&self, address: &[u8; 20]) -> EvmStoreResult<Option<EvmAccount>> {
        let start = Instant::now();
        let tx = self.db.tx().map_err(|e| db_err(e.to_string()))?;

        let key = AddressKey(*address);
        let result = tx
            .get::<EvmAccounts>(key)
            .map_err(|e| db_err(e.to_string()))?;

        STORAGE_READ_LATENCY
            .with_label_values(&["evm_accounts"])
            .observe(start.elapsed().as_secs_f64());

        match result {
            Some(stored) => {
                let account = EvmAccount {
                    nonce: stored.0.nonce,
                    balance: stored.0.balance,
                    code_hash: stored.0.code_hash,
                    storage_root: stored.0.storage_root,
                };
                Ok(Some(account))
            }
            None => Ok(None),
        }
    }

    fn set_account(&self, address: &[u8; 20], account: EvmAccount) -> EvmStoreResult<()> {
        let start = Instant::now();
        let tx = self.db.tx_mut().map_err(|e| db_err(e.to_string()))?;

        let key = AddressKey(*address);
        let stored = StoredAccount {
            nonce: account.nonce,
            balance: account.balance,
            code_hash: account.code_hash,
            storage_root: account.storage_root,
        };

        tx.put::<EvmAccounts>(key, stored.into())
            .map_err(|e| db_err(e.to_string()))?;

        let commit_start = Instant::now();
        tx.commit().map_err(|e| db_err(e.to_string()))?;
        STORAGE_BATCH_COMMIT
            .with_label_values(&[])
            .observe(commit_start.elapsed().as_secs_f64());

        STORAGE_WRITE_LATENCY
            .with_label_values(&["evm_accounts"])
            .observe(start.elapsed().as_secs_f64());

        Ok(())
    }

    fn delete_account(&self, address: &[u8; 20]) -> EvmStoreResult<()> {
        let start = Instant::now();
        let tx = self.db.tx_mut().map_err(|e| db_err(e.to_string()))?;

        let key = AddressKey(*address);
        tx.delete::<EvmAccounts>(key, None)
            .map_err(|e| db_err(e.to_string()))?;

        let commit_start = Instant::now();
        tx.commit().map_err(|e| db_err(e.to_string()))?;
        STORAGE_BATCH_COMMIT
            .with_label_values(&[])
            .observe(commit_start.elapsed().as_secs_f64());

        STORAGE_WRITE_LATENCY
            .with_label_values(&["evm_accounts"])
            .observe(start.elapsed().as_secs_f64());

        Ok(())
    }

    fn get_code(&self, code_hash: &[u8; 32]) -> EvmStoreResult<Option<EvmBytecode>> {
        let start = Instant::now();
        let tx = self.db.tx().map_err(|e| db_err(e.to_string()))?;

        let key = HashKey(*code_hash);
        let result = tx.get::<EvmCode>(key).map_err(|e| db_err(e.to_string()))?;

        STORAGE_READ_LATENCY
            .with_label_values(&["evm_code"])
            .observe(start.elapsed().as_secs_f64());

        match result {
            Some(stored) => Ok(Some(EvmBytecode::new(stored.0.code))),
            None => Ok(None),
        }
    }

    fn set_code(&self, code_hash: &[u8; 32], bytecode: EvmBytecode) -> EvmStoreResult<()> {
        let start = Instant::now();
        let tx = self.db.tx_mut().map_err(|e| db_err(e.to_string()))?;

        let key = HashKey(*code_hash);
        let stored = StoredBytecode {
            code: bytecode.code,
        };

        tx.put::<EvmCode>(key, stored.into())
            .map_err(|e| db_err(e.to_string()))?;

        let commit_start = Instant::now();
        tx.commit().map_err(|e| db_err(e.to_string()))?;
        STORAGE_BATCH_COMMIT
            .with_label_values(&[])
            .observe(commit_start.elapsed().as_secs_f64());

        STORAGE_WRITE_LATENCY
            .with_label_values(&["evm_code"])
            .observe(start.elapsed().as_secs_f64());

        Ok(())
    }

    fn get_storage(&self, address: &[u8; 20], slot: &[u8; 32]) -> EvmStoreResult<[u8; 32]> {
        let start = Instant::now();
        let tx = self.db.tx().map_err(|e| db_err(e.to_string()))?;

        let key = StorageSlotKey {
            address: *address,
            slot: *slot,
        };
        let result = tx
            .get::<EvmStorage>(key)
            .map_err(|e| db_err(e.to_string()))?;

        STORAGE_READ_LATENCY
            .with_label_values(&["evm_storage"])
            .observe(start.elapsed().as_secs_f64());

        match result {
            Some(stored) => Ok(stored.0.value),
            None => Ok([0u8; 32]), // Return zero for non-existent storage
        }
    }

    fn set_storage(
        &self,
        address: &[u8; 20],
        slot: &[u8; 32],
        value: [u8; 32],
    ) -> EvmStoreResult<()> {
        let start = Instant::now();
        let tx = self.db.tx_mut().map_err(|e| db_err(e.to_string()))?;

        let key = StorageSlotKey {
            address: *address,
            slot: *slot,
        };

        // Delete if value is zero, otherwise store it
        if value == [0u8; 32] {
            tx.delete::<EvmStorage>(key, None)
                .map_err(|e| db_err(e.to_string()))?;
        } else {
            let stored = StoredStorageValue { value };
            tx.put::<EvmStorage>(key, stored.into())
                .map_err(|e| db_err(e.to_string()))?;
        }

        let commit_start = Instant::now();
        tx.commit().map_err(|e| db_err(e.to_string()))?;
        STORAGE_BATCH_COMMIT
            .with_label_values(&[])
            .observe(commit_start.elapsed().as_secs_f64());

        STORAGE_WRITE_LATENCY
            .with_label_values(&["evm_storage"])
            .observe(start.elapsed().as_secs_f64());

        Ok(())
    }

    fn get_block_hash(&self, number: u64) -> EvmStoreResult<Option<[u8; 32]>> {
        let start = Instant::now();
        let tx = self.db.tx().map_err(|e| db_err(e.to_string()))?;

        let key = BlockNumberKey(number);
        let result = tx
            .get::<EvmBlockHashes>(key)
            .map_err(|e| db_err(e.to_string()))?;

        STORAGE_READ_LATENCY
            .with_label_values(&["evm_block_hashes"])
            .observe(start.elapsed().as_secs_f64());

        match result {
            Some(hash_key) => Ok(Some(hash_key.0)),
            None => Ok(None),
        }
    }

    fn set_block_hash(&self, number: u64, hash: [u8; 32]) -> EvmStoreResult<()> {
        let start = Instant::now();
        let tx = self.db.tx_mut().map_err(|e| db_err(e.to_string()))?;

        let key = BlockNumberKey(number);
        let value = HashKey(hash);

        tx.put::<EvmBlockHashes>(key, value)
            .map_err(|e| db_err(e.to_string()))?;

        let commit_start = Instant::now();
        tx.commit().map_err(|e| db_err(e.to_string()))?;
        STORAGE_BATCH_COMMIT
            .with_label_values(&[])
            .observe(commit_start.elapsed().as_secs_f64());

        STORAGE_WRITE_LATENCY
            .with_label_values(&["evm_block_hashes"])
            .observe(start.elapsed().as_secs_f64());

        Ok(())
    }

    fn get_all_accounts(&self) -> EvmStoreResult<Vec<([u8; 20], EvmAccount)>> {
        // Delegate to the inherent method
        MdbxEvmStore::get_all_accounts(self)
    }

    fn get_all_storage(&self, address: &[u8; 20]) -> EvmStoreResult<Vec<([u8; 32], [u8; 32])>> {
        // Delegate to the inherent method
        MdbxEvmStore::get_all_storage(self, address)
    }

    fn get_current_block(&self) -> EvmStoreResult<Option<u64>> {
        let start = Instant::now();
        let tx = self.db.tx().map_err(|e| db_err(e.to_string()))?;

        let result = tx
            .get::<EvmMetadata>(UnitKey)
            .map_err(|e| db_err(e.to_string()))?;

        STORAGE_READ_LATENCY
            .with_label_values(&["evm_metadata"])
            .observe(start.elapsed().as_secs_f64());

        match result {
            Some(metadata) => Ok(Some(metadata.0.current_block)),
            None => Ok(None),
        }
    }

    fn set_current_block(&self, block_number: u64) -> EvmStoreResult<()> {
        let start = Instant::now();
        let tx = self.db.tx_mut().map_err(|e| db_err(e.to_string()))?;

        let metadata = StoredEvmMetadata {
            current_block: block_number,
        };

        tx.put::<EvmMetadata>(UnitKey, metadata.into())
            .map_err(|e| db_err(e.to_string()))?;

        let commit_start = Instant::now();
        tx.commit().map_err(|e| db_err(e.to_string()))?;
        STORAGE_BATCH_COMMIT
            .with_label_values(&[])
            .observe(commit_start.elapsed().as_secs_f64());

        STORAGE_WRITE_LATENCY
            .with_label_values(&["evm_metadata"])
            .observe(start.elapsed().as_secs_f64());

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mdbx::Database;
    use std::sync::Arc;

    fn create_test_db() -> (Arc<DatabaseEnv>, tempfile::TempDir) {
        let (db, temp_dir) = Database::open_temp().unwrap();
        (Arc::clone(db.env()), temp_dir)
    }

    #[test]
    fn test_account_operations() {
        let (db, _temp_dir) = create_test_db();
        let store = MdbxEvmStore::new(db);

        let address = [1u8; 20];
        let account = EvmAccount {
            nonce: 42,
            balance: [
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 100,
            ],
            code_hash: [2u8; 32],
            storage_root: [3u8; 32],
        };

        // Test set and get
        store.set_account(&address, account.clone()).unwrap();
        let retrieved = store.get_account(&address).unwrap().unwrap();
        assert_eq!(retrieved.nonce, account.nonce);
        assert_eq!(retrieved.balance, account.balance);
        assert_eq!(retrieved.code_hash, account.code_hash);

        // Test delete
        store.delete_account(&address).unwrap();
        assert!(store.get_account(&address).unwrap().is_none());
    }

    #[test]
    fn test_code_operations() {
        let (db, _temp_dir) = create_test_db();
        let store = MdbxEvmStore::new(db);

        let code_hash = [42u8; 32];
        let bytecode = EvmBytecode::new(vec![0x60, 0x00, 0x60, 0x00, 0xf3]);

        // Test set and get
        store.set_code(&code_hash, bytecode.clone()).unwrap();
        let retrieved = store.get_code(&code_hash).unwrap().unwrap();
        assert_eq!(retrieved.code, bytecode.code);

        // Test non-existent code
        let missing = [99u8; 32];
        assert!(store.get_code(&missing).unwrap().is_none());
    }

    #[test]
    fn test_storage_operations() {
        let (db, _temp_dir) = create_test_db();
        let store = MdbxEvmStore::new(db);

        let address = [1u8; 20];
        let slot = [2u8; 32];
        let value = [3u8; 32];

        // Test set and get
        store.set_storage(&address, &slot, value).unwrap();
        let retrieved = store.get_storage(&address, &slot).unwrap();
        assert_eq!(retrieved, value);

        // Test zero value (should delete)
        store.set_storage(&address, &slot, [0u8; 32]).unwrap();
        let retrieved = store.get_storage(&address, &slot).unwrap();
        assert_eq!(retrieved, [0u8; 32]);
    }

    #[test]
    fn test_block_hash_operations() {
        let (db, _temp_dir) = create_test_db();
        let store = MdbxEvmStore::new(db);

        let number = 12345u64;
        let hash = [42u8; 32];

        // Test set and get
        store.set_block_hash(number, hash).unwrap();
        let retrieved = store.get_block_hash(number).unwrap().unwrap();
        assert_eq!(retrieved, hash);

        // Test non-existent block
        assert!(store.get_block_hash(99999).unwrap().is_none());
    }

    #[test]
    fn test_get_all_accounts() {
        let (db, _temp_dir) = create_test_db();
        let store = MdbxEvmStore::new(db);

        // Initially no accounts
        let accounts = store.get_all_accounts().unwrap();
        assert!(accounts.is_empty());

        // Add some accounts
        let addr1 = [1u8; 20];
        let addr2 = [2u8; 20];
        let addr3 = [3u8; 20];

        let account1 = EvmAccount {
            nonce: 1,
            balance: [0u8; 32],
            code_hash: [0u8; 32],
            storage_root: [0u8; 32],
        };
        let account2 = EvmAccount {
            nonce: 2,
            balance: [0u8; 32],
            code_hash: [0u8; 32],
            storage_root: [0u8; 32],
        };
        let account3 = EvmAccount {
            nonce: 3,
            balance: [0u8; 32],
            code_hash: [0u8; 32],
            storage_root: [0u8; 32],
        };

        store.set_account(&addr1, account1).unwrap();
        store.set_account(&addr2, account2).unwrap();
        store.set_account(&addr3, account3).unwrap();

        // Get all accounts
        let accounts = store.get_all_accounts().unwrap();
        assert_eq!(accounts.len(), 3);

        // Verify the accounts are returned (they should be ordered by address)
        let nonces: Vec<u64> = accounts.iter().map(|(_, acc)| acc.nonce).collect();
        assert_eq!(nonces, vec![1, 2, 3]);
    }

    #[test]
    fn test_get_all_storage() {
        let (db, _temp_dir) = create_test_db();
        let store = MdbxEvmStore::new(db);

        let addr1 = [1u8; 20];
        let addr2 = [2u8; 20];

        // Initially no storage
        let storage = store.get_all_storage(&addr1).unwrap();
        assert!(storage.is_empty());

        // Add storage for addr1
        let slot1 = [0u8; 32];
        let slot2 = {
            let mut s = [0u8; 32];
            s[31] = 1;
            s
        };
        let slot3 = {
            let mut s = [0u8; 32];
            s[31] = 2;
            s
        };

        let value1 = {
            let mut v = [0u8; 32];
            v[31] = 100;
            v
        };
        let value2 = {
            let mut v = [0u8; 32];
            v[31] = 200;
            v
        };
        let value3 = {
            let mut v = [0u8; 32];
            v[31] = 42;
            v
        };

        store.set_storage(&addr1, &slot1, value1).unwrap();
        store.set_storage(&addr1, &slot2, value2).unwrap();
        // Add some storage for addr2 to ensure filtering works
        store.set_storage(&addr2, &slot3, value3).unwrap();

        // Get storage for addr1 only
        let storage = store.get_all_storage(&addr1).unwrap();
        assert_eq!(storage.len(), 2);

        // Verify the values
        assert!(storage.iter().any(|(_, v)| *v == value1));
        assert!(storage.iter().any(|(_, v)| *v == value2));

        // Verify addr2's storage is not included
        assert!(!storage.iter().any(|(_, v)| *v == value3));

        // Get storage for addr2
        let storage2 = store.get_all_storage(&addr2).unwrap();
        assert_eq!(storage2.len(), 1);
        assert_eq!(storage2[0].1, value3);
    }

    #[test]
    fn test_current_block_operations() {
        let (db, _temp_dir) = create_test_db();
        let store = MdbxEvmStore::new(db);

        // Initially no current block
        assert!(store.get_current_block().unwrap().is_none());

        // Set current block
        store.set_current_block(12345).unwrap();
        assert_eq!(store.get_current_block().unwrap(), Some(12345));

        // Update current block
        store.set_current_block(67890).unwrap();
        assert_eq!(store.get_current_block().unwrap(), Some(67890));
    }

    #[test]
    fn test_current_block_persistence() {
        use crate::mdbx::DatabaseConfig;

        let temp_dir = tempfile::tempdir().unwrap();
        let db_path = temp_dir.path();

        // First: Create store and write current block
        {
            let config = DatabaseConfig::new(db_path);
            let db = Database::open(config).unwrap();
            let store = MdbxEvmStore::new(Arc::clone(db.env()));
            store.set_current_block(138350).unwrap();
        }

        // Second: Create new store and verify current block persists
        {
            let config = DatabaseConfig::new(db_path);
            let db = Database::open(config).unwrap();
            let store = MdbxEvmStore::new(Arc::clone(db.env()));
            let retrieved = store.get_current_block().unwrap();
            assert_eq!(retrieved, Some(138350));
        }
    }
}
