//! Staking storage traits and types for staking precompile integration.
//!
//! This module provides the `StakingStore` trait that abstracts staking state storage,
//! allowing the staking precompile to persist validator information across restarts.

use crate::error::StorageError;

/// Validator information stored by the staking precompile.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StoredValidator {
    /// Ethereum address (20 bytes).
    pub address: [u8; 20],
    /// BLS12-381 public key (48 bytes).
    pub bls_pubkey: Vec<u8>,
    /// Staked amount (big-endian U256).
    pub stake: [u8; 32],
    /// Registration block height.
    pub registered_at: u64,
    /// Pending deregistration epoch (None if not exiting).
    pub pending_exit: Option<u64>,
}

/// Result type for staking storage operations.
pub type StakingStoreResult<T> = Result<T, StorageError>;

/// Trait for staking state storage.
///
/// This trait provides the interface for storing and retrieving staking state,
/// including validator information, total stake, and epoch number.
pub trait StakingStore: Send + Sync {
    /// Get validator information by address.
    ///
    /// # Arguments
    /// * `address` - 20-byte Ethereum address
    ///
    /// # Returns
    /// * `Ok(Some(validator))` - Validator exists
    /// * `Ok(None)` - Validator not found
    /// * `Err(e)` - Storage error
    fn get_validator(&self, address: &[u8; 20]) -> StakingStoreResult<Option<StoredValidator>>;

    /// Set validator information.
    ///
    /// # Arguments
    /// * `address` - 20-byte Ethereum address
    /// * `validator` - Validator information to store
    fn set_validator(
        &self,
        address: &[u8; 20],
        validator: StoredValidator,
    ) -> StakingStoreResult<()>;

    /// Delete a validator.
    ///
    /// # Arguments
    /// * `address` - 20-byte Ethereum address
    fn delete_validator(&self, address: &[u8; 20]) -> StakingStoreResult<()>;

    /// Get all validators.
    ///
    /// # Returns
    /// * List of all registered validators
    fn get_all_validators(&self) -> StakingStoreResult<Vec<StoredValidator>>;

    /// Get total staked amount.
    ///
    /// # Returns
    /// * Total stake as 32-byte big-endian U256
    fn get_total_stake(&self) -> StakingStoreResult<[u8; 32]>;

    /// Set total staked amount.
    ///
    /// # Arguments
    /// * `stake` - Total stake as 32-byte big-endian U256
    fn set_total_stake(&self, stake: [u8; 32]) -> StakingStoreResult<()>;

    /// Get current epoch number.
    fn get_epoch(&self) -> StakingStoreResult<u64>;

    /// Set current epoch number.
    fn set_epoch(&self, epoch: u64) -> StakingStoreResult<()>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stored_validator_default() {
        let validator = StoredValidator::default();
        assert_eq!(validator.address, [0u8; 20]);
        assert!(validator.bls_pubkey.is_empty());
        assert_eq!(validator.stake, [0u8; 32]);
        assert_eq!(validator.registered_at, 0);
        assert!(validator.pending_exit.is_none());
    }
}
