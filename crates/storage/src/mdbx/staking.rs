//! MDBX-based implementation of staking storage.
//!
//! This module provides the [`MdbxStakingStore`] implementation of [`StakingStore`] trait
//! using MDBX as the backing storage engine.

use std::sync::Arc;

use reth_db::Database;
use reth_db_api::cursor::DbCursorRO;
use reth_db_api::transaction::{DbTx, DbTxMut};

use super::database::DatabaseEnv;
use super::tables::{
    AddressKey, StakingMetadata, StakingValidators, StoredStakingMetadata, StoredValidatorInfo,
    UnitKey,
};
use crate::error::StorageError;
use crate::staking::{StakingStore, StakingStoreResult, StoredValidator};

/// Helper to convert database errors to storage errors.
fn db_err(e: impl std::fmt::Display) -> StorageError {
    StorageError::Database(e.to_string())
}

/// MDBX-based staking storage implementation.
///
/// This implementation uses reth-db (MDBX) for persistent storage of staking state.
pub struct MdbxStakingStore {
    db: Arc<DatabaseEnv>,
}

impl MdbxStakingStore {
    /// Create a new MDBX staking store.
    ///
    /// # Arguments
    /// * `db` - Shared reference to the MDBX database environment
    pub fn new(db: Arc<DatabaseEnv>) -> Self {
        Self { db }
    }
}

impl StakingStore for MdbxStakingStore {
    fn get_validator(&self, address: &[u8; 20]) -> StakingStoreResult<Option<StoredValidator>> {
        let tx = self.db.tx().map_err(|e| db_err(e.to_string()))?;

        let key = AddressKey(*address);
        let result = tx
            .get::<StakingValidators>(key)
            .map_err(|e| db_err(e.to_string()))?;

        match result {
            Some(stored) => {
                let validator = StoredValidator {
                    address: stored.0.address,
                    bls_pubkey: stored.0.bls_pubkey,
                    stake: stored.0.stake,
                    registered_at: stored.0.registered_at,
                    pending_exit: if stored.0.has_pending_exit {
                        Some(stored.0.pending_exit)
                    } else {
                        None
                    },
                };
                Ok(Some(validator))
            }
            None => Ok(None),
        }
    }

    fn set_validator(
        &self,
        address: &[u8; 20],
        validator: StoredValidator,
    ) -> StakingStoreResult<()> {
        let tx = self.db.tx_mut().map_err(|e| db_err(e.to_string()))?;

        let key = AddressKey(*address);
        let stored = StoredValidatorInfo {
            address: validator.address,
            bls_pubkey: validator.bls_pubkey,
            stake: validator.stake,
            registered_at: validator.registered_at,
            pending_exit: validator.pending_exit.unwrap_or(0),
            has_pending_exit: validator.pending_exit.is_some(),
        };

        tx.put::<StakingValidators>(key, stored.into())
            .map_err(|e| db_err(e.to_string()))?;

        tx.commit().map_err(|e| db_err(e.to_string()))?;

        Ok(())
    }

    fn delete_validator(&self, address: &[u8; 20]) -> StakingStoreResult<()> {
        let tx = self.db.tx_mut().map_err(|e| db_err(e.to_string()))?;

        let key = AddressKey(*address);
        tx.delete::<StakingValidators>(key, None)
            .map_err(|e| db_err(e.to_string()))?;

        tx.commit().map_err(|e| db_err(e.to_string()))?;

        Ok(())
    }

    fn get_all_validators(&self) -> StakingStoreResult<Vec<StoredValidator>> {
        let tx = self.db.tx().map_err(|e| db_err(e.to_string()))?;

        let mut cursor = tx
            .cursor_read::<StakingValidators>()
            .map_err(|e| db_err(e.to_string()))?;

        let mut validators = Vec::new();

        // Iterate through all validators using cursor
        let mut entry = cursor.first().map_err(|e| db_err(e.to_string()))?;

        while let Some((_, stored)) = entry {
            let validator = StoredValidator {
                address: stored.0.address,
                bls_pubkey: stored.0.bls_pubkey,
                stake: stored.0.stake,
                registered_at: stored.0.registered_at,
                pending_exit: if stored.0.has_pending_exit {
                    Some(stored.0.pending_exit)
                } else {
                    None
                },
            };
            validators.push(validator);

            entry = cursor.next().map_err(|e| db_err(e.to_string()))?;
        }

        Ok(validators)
    }

    fn get_total_stake(&self) -> StakingStoreResult<[u8; 32]> {
        let tx = self.db.tx().map_err(|e| db_err(e.to_string()))?;

        let result = tx
            .get::<StakingMetadata>(UnitKey)
            .map_err(|e| db_err(e.to_string()))?;

        match result {
            Some(stored) => Ok(stored.0.total_stake),
            None => Ok([0u8; 32]), // Default to zero
        }
    }

    fn set_total_stake(&self, stake: [u8; 32]) -> StakingStoreResult<()> {
        let tx = self.db.tx_mut().map_err(|e| db_err(e.to_string()))?;

        // Get existing metadata or create new
        let existing = tx
            .get::<StakingMetadata>(UnitKey)
            .map_err(|e| db_err(e.to_string()))?;

        let epoch = existing.map(|m| m.0.epoch).unwrap_or(0);
        let stored = StoredStakingMetadata {
            total_stake: stake,
            epoch,
        };

        tx.put::<StakingMetadata>(UnitKey, stored.into())
            .map_err(|e| db_err(e.to_string()))?;

        tx.commit().map_err(|e| db_err(e.to_string()))?;

        Ok(())
    }

    fn get_epoch(&self) -> StakingStoreResult<u64> {
        let tx = self.db.tx().map_err(|e| db_err(e.to_string()))?;

        let result = tx
            .get::<StakingMetadata>(UnitKey)
            .map_err(|e| db_err(e.to_string()))?;

        match result {
            Some(stored) => Ok(stored.0.epoch),
            None => Ok(0), // Default to epoch 0
        }
    }

    fn set_epoch(&self, epoch: u64) -> StakingStoreResult<()> {
        let tx = self.db.tx_mut().map_err(|e| db_err(e.to_string()))?;

        // Get existing metadata or create new
        let existing = tx
            .get::<StakingMetadata>(UnitKey)
            .map_err(|e| db_err(e.to_string()))?;

        let total_stake = existing.map(|m| m.0.total_stake).unwrap_or([0u8; 32]);
        let stored = StoredStakingMetadata { total_stake, epoch };

        tx.put::<StakingMetadata>(UnitKey, stored.into())
            .map_err(|e| db_err(e.to_string()))?;

        tx.commit().map_err(|e| db_err(e.to_string()))?;

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
    fn test_validator_operations() {
        let (db, _temp_dir) = create_test_db();
        let store = MdbxStakingStore::new(db);

        let address = [1u8; 20];
        let validator = StoredValidator {
            address,
            bls_pubkey: vec![2u8; 48],
            stake: [
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 100,
            ],
            registered_at: 12345,
            pending_exit: None,
        };

        // Test set and get
        store.set_validator(&address, validator.clone()).unwrap();
        let retrieved = store.get_validator(&address).unwrap().unwrap();
        assert_eq!(retrieved.address, validator.address);
        assert_eq!(retrieved.bls_pubkey, validator.bls_pubkey);
        assert_eq!(retrieved.stake, validator.stake);
        assert_eq!(retrieved.registered_at, validator.registered_at);
        assert!(retrieved.pending_exit.is_none());

        // Test delete
        store.delete_validator(&address).unwrap();
        assert!(store.get_validator(&address).unwrap().is_none());
    }

    #[test]
    fn test_get_all_validators() {
        let (db, _temp_dir) = create_test_db();
        let store = MdbxStakingStore::new(db);

        // Add multiple validators
        for i in 0..5u8 {
            let address = [i; 20];
            let validator = StoredValidator {
                address,
                bls_pubkey: vec![i; 48],
                stake: [0u8; 32],
                registered_at: i as u64,
                pending_exit: None,
            };
            store.set_validator(&address, validator).unwrap();
        }

        let all = store.get_all_validators().unwrap();
        assert_eq!(all.len(), 5);
    }

    #[test]
    fn test_staking_metadata() {
        let (db, _temp_dir) = create_test_db();
        let store = MdbxStakingStore::new(db);

        // Test epoch
        assert_eq!(store.get_epoch().unwrap(), 0);
        store.set_epoch(42).unwrap();
        assert_eq!(store.get_epoch().unwrap(), 42);

        // Test total stake
        assert_eq!(store.get_total_stake().unwrap(), [0u8; 32]);
        let stake = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 255,
        ];
        store.set_total_stake(stake).unwrap();
        assert_eq!(store.get_total_stake().unwrap(), stake);

        // Verify epoch is preserved when updating total_stake
        assert_eq!(store.get_epoch().unwrap(), 42);
    }
}
