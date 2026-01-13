//! MDBX-based implementation of EVM storage.
//!
//! This module provides the [`MdbxEvmStore`] implementation of [`EvmStore`] trait
//! using MDBX as the backing storage engine.

use std::sync::Arc;

use reth_db::Database;
use reth_db_api::transaction::{DbTx, DbTxMut};

use super::database::DatabaseEnv;
use super::tables::{
    AddressKey, BlockNumberKey, EvmAccounts, EvmBlockHashes, EvmCode, EvmStorage, HashKey,
    StorageSlotKey, StoredAccount, StoredBytecode, StoredStorageValue,
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
}

impl EvmStore for MdbxEvmStore {
    fn get_account(&self, address: &[u8; 20]) -> EvmStoreResult<Option<EvmAccount>> {
        let tx = self
            .db
            .tx()
            .map_err(|e| db_err(e.to_string()))?;

        let key = AddressKey(*address);
        let result = tx
            .get::<EvmAccounts>(key)
            .map_err(|e| db_err(e.to_string()))?;

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
        let tx = self
            .db
            .tx_mut()
            .map_err(|e| db_err(e.to_string()))?;

        let key = AddressKey(*address);
        let stored = StoredAccount {
            nonce: account.nonce,
            balance: account.balance,
            code_hash: account.code_hash,
            storage_root: account.storage_root,
        };

        tx.put::<EvmAccounts>(key, stored.into())
            .map_err(|e| db_err(e.to_string()))?;

        tx.commit()
            .map_err(|e| db_err(e.to_string()))?;

        Ok(())
    }

    fn delete_account(&self, address: &[u8; 20]) -> EvmStoreResult<()> {
        let tx = self
            .db
            .tx_mut()
            .map_err(|e| db_err(e.to_string()))?;

        let key = AddressKey(*address);
        tx.delete::<EvmAccounts>(key, None)
            .map_err(|e| db_err(e.to_string()))?;

        tx.commit()
            .map_err(|e| db_err(e.to_string()))?;

        Ok(())
    }

    fn get_code(&self, code_hash: &[u8; 32]) -> EvmStoreResult<Option<EvmBytecode>> {
        let tx = self
            .db
            .tx()
            .map_err(|e| db_err(e.to_string()))?;

        let key = HashKey(*code_hash);
        let result = tx
            .get::<EvmCode>(key)
            .map_err(|e| db_err(e.to_string()))?;

        match result {
            Some(stored) => Ok(Some(EvmBytecode::new(stored.0.code))),
            None => Ok(None),
        }
    }

    fn set_code(&self, code_hash: &[u8; 32], bytecode: EvmBytecode) -> EvmStoreResult<()> {
        let tx = self
            .db
            .tx_mut()
            .map_err(|e| db_err(e.to_string()))?;

        let key = HashKey(*code_hash);
        let stored = StoredBytecode { code: bytecode.code };

        tx.put::<EvmCode>(key, stored.into())
            .map_err(|e| db_err(e.to_string()))?;

        tx.commit()
            .map_err(|e| db_err(e.to_string()))?;

        Ok(())
    }

    fn get_storage(&self, address: &[u8; 20], slot: &[u8; 32]) -> EvmStoreResult<[u8; 32]> {
        let tx = self
            .db
            .tx()
            .map_err(|e| db_err(e.to_string()))?;

        let key = StorageSlotKey {
            address: *address,
            slot: *slot,
        };
        let result = tx
            .get::<EvmStorage>(key)
            .map_err(|e| db_err(e.to_string()))?;

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
        let tx = self
            .db
            .tx_mut()
            .map_err(|e| db_err(e.to_string()))?;

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

        tx.commit()
            .map_err(|e| db_err(e.to_string()))?;

        Ok(())
    }

    fn get_block_hash(&self, number: u64) -> EvmStoreResult<Option<[u8; 32]>> {
        let tx = self
            .db
            .tx()
            .map_err(|e| db_err(e.to_string()))?;

        let key = BlockNumberKey(number);
        let result = tx
            .get::<EvmBlockHashes>(key)
            .map_err(|e| db_err(e.to_string()))?;

        match result {
            Some(hash_key) => Ok(Some(hash_key.0)),
            None => Ok(None),
        }
    }

    fn set_block_hash(&self, number: u64, hash: [u8; 32]) -> EvmStoreResult<()> {
        let tx = self
            .db
            .tx_mut()
            .map_err(|e| db_err(e.to_string()))?;

        let key = BlockNumberKey(number);
        let value = HashKey(hash);

        tx.put::<EvmBlockHashes>(key, value)
            .map_err(|e| db_err(e.to_string()))?;

        tx.commit()
            .map_err(|e| db_err(e.to_string()))?;

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
    #[ignore = "Requires EVM tables to be created - pending table initialization"]
    fn test_account_operations() {
        let (db, _temp_dir) = create_test_db();
        let store = MdbxEvmStore::new(db);

        let address = [1u8; 20];
        let account = EvmAccount {
            nonce: 42,
            balance: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 100],
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
    #[ignore = "Requires EVM tables to be created - pending table initialization"]
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
    #[ignore = "Requires EVM tables to be created - pending table initialization"]
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
    #[ignore = "Requires EVM tables to be created - pending table initialization"]
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
}
