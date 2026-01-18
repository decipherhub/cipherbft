//! Validator Set Manager for dynamic validator set changes.
//!
//! This module provides epoch-based validator set management, allowing
//! the consensus layer to track validator sets across different epochs
//! and heights.
//!
//! ## Design
//!
//! - Validator sets are stored per epoch (not per height) for efficiency
//! - Epoch boundaries are defined by `epoch_length` (blocks per epoch)
//! - At each epoch boundary, the manager queries for updated validator sets
//! - Historical validator sets are retained for sync and verification
//!
//! ## Storage Integration
//!
//! The manager can optionally integrate with a storage backend through the
//! [`ValidatorSetStorageProvider`] trait. This allows validator sets to be
//! persisted across restarts and recovered during node initialization.

use std::collections::BTreeMap;
use std::sync::Arc;

use parking_lot::RwLock;

use crate::error::ConsensusError;
use crate::types::ConsensusHeight;
use crate::validator_set::{ConsensusValidator, ConsensusValidatorSet};

/// Storage provider for persisting validator sets across epochs.
///
/// Implementations of this trait allow the `ValidatorSetManager` to persist
/// validator sets to durable storage and recover them after restarts.
///
/// ## Implementation Notes
///
/// - All methods are synchronous for simplicity; async wrappers can be used if needed
/// - Implementations should handle their own error recovery
/// - The `EpochValidatorSet` type includes all necessary metadata for restoration
pub trait ValidatorSetStorageProvider: Send + Sync {
    /// Persist a validator set for a specific epoch.
    ///
    /// Called when an epoch transition occurs and the new validator set
    /// should be durably stored.
    fn persist_epoch_set(&self, epoch_set: &EpochValidatorSet) -> Result<(), ConsensusError>;

    /// Load a validator set for a specific epoch.
    ///
    /// Returns `None` if no validator set is stored for this epoch.
    fn load_epoch_set(&self, epoch: u64) -> Result<Option<EpochValidatorSet>, ConsensusError>;

    /// Load all stored validator sets.
    ///
    /// Used during initialization to restore the full epoch history.
    /// Returns validator sets ordered by epoch number.
    fn load_all_epoch_sets(&self) -> Result<Vec<EpochValidatorSet>, ConsensusError>;

    /// Persist the current epoch number.
    ///
    /// This should be called atomically with `persist_epoch_set` when possible.
    fn persist_current_epoch(&self, epoch: u64) -> Result<(), ConsensusError>;

    /// Load the current epoch number.
    ///
    /// Returns `None` if no epoch has been persisted (fresh start).
    fn load_current_epoch(&self) -> Result<Option<u64>, ConsensusError>;

    /// Delete a validator set for a specific epoch.
    ///
    /// Called during epoch pruning to clean up old data.
    fn delete_epoch_set(&self, epoch: u64) -> Result<(), ConsensusError>;
}

/// Configuration for validator set epoch transitions.
#[derive(Debug, Clone)]
pub struct EpochConfig {
    /// Number of blocks per epoch.
    ///
    /// Validator set changes take effect at epoch boundaries.
    /// Default: 100 blocks.
    pub epoch_length: u64,

    /// Maximum number of historical epochs to retain.
    ///
    /// Older epochs are pruned to save memory.
    /// Default: 1000 epochs.
    pub max_retained_epochs: u64,
}

impl Default for EpochConfig {
    fn default() -> Self {
        Self {
            epoch_length: 100,
            max_retained_epochs: 1000,
        }
    }
}

impl EpochConfig {
    /// Create a new epoch configuration.
    pub fn new(epoch_length: u64) -> Self {
        Self {
            epoch_length,
            ..Default::default()
        }
    }

    /// Calculate the epoch number for a given height.
    ///
    /// Epoch 0 contains heights 1..=epoch_length
    /// Epoch 1 contains heights (epoch_length+1)..=(2*epoch_length)
    /// etc.
    #[inline]
    pub fn epoch_for_height(&self, height: ConsensusHeight) -> u64 {
        if height.0 == 0 {
            return 0;
        }
        (height.0 - 1) / self.epoch_length
    }

    /// Get the first height of an epoch.
    #[inline]
    pub fn epoch_start_height(&self, epoch: u64) -> ConsensusHeight {
        ConsensusHeight(epoch * self.epoch_length + 1)
    }

    /// Get the last height of an epoch.
    #[inline]
    pub fn epoch_end_height(&self, epoch: u64) -> ConsensusHeight {
        ConsensusHeight((epoch + 1) * self.epoch_length)
    }

    /// Check if a height is at an epoch boundary (last block of epoch).
    #[inline]
    pub fn is_epoch_boundary(&self, height: ConsensusHeight) -> bool {
        height.0 > 0 && height.0.is_multiple_of(self.epoch_length)
    }

    /// Check if a height is the first block of an epoch.
    #[inline]
    pub fn is_epoch_start(&self, height: ConsensusHeight) -> bool {
        height.0 > 0 && (height.0 - 1).is_multiple_of(self.epoch_length)
    }
}

/// Stored validator set with metadata.
#[derive(Debug, Clone)]
pub struct EpochValidatorSet {
    /// The epoch number.
    pub epoch: u64,

    /// The validator set for this epoch.
    pub validator_set: ConsensusValidatorSet,

    /// Height at which this set became active.
    pub activated_at: ConsensusHeight,
}

/// Internal state for ValidatorSetManager.
///
/// This struct consolidates all mutable state into a single unit to prevent
/// ABBA deadlock patterns. Previously, separate RwLocks for `sets`, `current_epoch`,
/// and `pending_next_epoch` could be acquired in different orders across methods,
/// leading to potential deadlocks under concurrent access.
#[derive(Debug)]
struct ValidatorSetState {
    /// Validator sets by epoch (epoch -> EpochValidatorSet).
    sets: BTreeMap<u64, EpochValidatorSet>,

    /// The current epoch number.
    current_epoch: u64,

    /// Pending validator set for the next epoch (if any).
    pending_next_epoch: Option<ConsensusValidatorSet>,
}

/// Manages validator sets across epochs.
///
/// Thread-safe implementation using `parking_lot::RwLock` for concurrent access.
/// This avoids lock poisoning issues that can cascade node failures in BFT systems.
///
/// ## Usage
///
/// ```rust,ignore
/// use cipherbft_consensus::{ValidatorSetManager, EpochConfig};
///
/// // Create manager with genesis validator set
/// let manager = ValidatorSetManager::new(
///     EpochConfig::default(),
///     genesis_validators,
/// )?;
///
/// // Get validator set for a specific height
/// let set = manager.get_validator_set_for_height(height)?;
///
/// // Register a new validator set for the next epoch
/// manager.register_next_epoch_validators(new_validators)?;
/// ```
///
/// ## Storage Integration
///
/// For persistence across restarts, provide a storage provider:
///
/// ```rust,ignore
/// // Recover from storage
/// let manager = ValidatorSetManager::recover_from_storage(
///     EpochConfig::default(),
///     storage_provider,
/// )?;
///
/// // Or create new with storage
/// let manager = ValidatorSetManager::with_storage(
///     EpochConfig::default(),
///     genesis_validators,
///     storage_provider,
/// )?;
/// ```
pub struct ValidatorSetManager {
    /// Epoch configuration.
    config: EpochConfig,

    /// Consolidated state protected by a single lock.
    ///
    /// DEADLOCK FIX: Previously this was three separate RwLocks (sets, current_epoch,
    /// pending_next_epoch) which could be acquired in different orders across methods,
    /// causing ABBA deadlock. Now all state is protected by a single lock.
    state: RwLock<ValidatorSetState>,

    /// Optional storage provider for persistence.
    storage: Option<Arc<dyn ValidatorSetStorageProvider>>,
}

impl ValidatorSetManager {
    /// Create a new validator set manager with genesis validators.
    ///
    /// # Arguments
    ///
    /// * `config` - Epoch configuration
    /// * `genesis_validators` - Initial validator set for epoch 0
    ///
    /// # Errors
    ///
    /// Returns `ConsensusError::EmptyValidatorSet` if genesis validators is empty.
    pub fn new(
        config: EpochConfig,
        genesis_validators: Vec<ConsensusValidator>,
    ) -> Result<Self, ConsensusError> {
        let validator_set = ConsensusValidatorSet::new(genesis_validators);

        if validator_set.is_empty() {
            return Err(ConsensusError::EmptyValidatorSet);
        }

        let genesis_epoch_set = EpochValidatorSet {
            epoch: 0,
            validator_set,
            activated_at: ConsensusHeight(1),
        };

        let mut sets = BTreeMap::new();
        sets.insert(0, genesis_epoch_set);

        Ok(Self {
            config,
            state: RwLock::new(ValidatorSetState {
                sets,
                current_epoch: 0,
                pending_next_epoch: None,
            }),
            storage: None,
        })
    }

    /// Create a new validator set manager with genesis validators and storage.
    ///
    /// The genesis validator set will be persisted to storage.
    ///
    /// # Arguments
    ///
    /// * `config` - Epoch configuration
    /// * `genesis_validators` - Initial validator set for epoch 0
    /// * `storage` - Storage provider for persistence
    ///
    /// # Errors
    ///
    /// Returns `ConsensusError::EmptyValidatorSet` if genesis validators is empty.
    pub fn with_storage(
        config: EpochConfig,
        genesis_validators: Vec<ConsensusValidator>,
        storage: Arc<dyn ValidatorSetStorageProvider>,
    ) -> Result<Self, ConsensusError> {
        let validator_set = ConsensusValidatorSet::new(genesis_validators);

        if validator_set.is_empty() {
            return Err(ConsensusError::EmptyValidatorSet);
        }

        let genesis_epoch_set = EpochValidatorSet {
            epoch: 0,
            validator_set,
            activated_at: ConsensusHeight(1),
        };

        // Persist to storage
        storage.persist_epoch_set(&genesis_epoch_set)?;
        storage.persist_current_epoch(0)?;

        let mut sets = BTreeMap::new();
        sets.insert(0, genesis_epoch_set);

        Ok(Self {
            config,
            state: RwLock::new(ValidatorSetState {
                sets,
                current_epoch: 0,
                pending_next_epoch: None,
            }),
            storage: Some(storage),
        })
    }

    /// Recover validator set manager from storage.
    ///
    /// Loads all persisted epoch sets and the current epoch from storage.
    /// If storage is empty, returns an error.
    ///
    /// # Arguments
    ///
    /// * `config` - Epoch configuration
    /// * `storage` - Storage provider containing persisted data
    ///
    /// # Errors
    ///
    /// Returns `ConsensusError::EmptyValidatorSet` if no validator sets found in storage.
    pub fn recover_from_storage(
        config: EpochConfig,
        storage: Arc<dyn ValidatorSetStorageProvider>,
    ) -> Result<Self, ConsensusError> {
        // Load current epoch
        let current_epoch = storage
            .load_current_epoch()?
            .ok_or_else(|| ConsensusError::Other("No epoch found in storage".to_string()))?;

        // Load all epoch sets
        let epoch_sets = storage.load_all_epoch_sets()?;

        if epoch_sets.is_empty() {
            return Err(ConsensusError::EmptyValidatorSet);
        }

        let mut sets = BTreeMap::new();
        for epoch_set in epoch_sets {
            sets.insert(epoch_set.epoch, epoch_set);
        }

        Ok(Self {
            config,
            state: RwLock::new(ValidatorSetState {
                sets,
                current_epoch,
                pending_next_epoch: None,
            }),
            storage: Some(storage),
        })
    }

    /// Create from an existing validator set at a specific epoch.
    ///
    /// Used for recovery from storage.
    pub fn from_epoch(
        config: EpochConfig,
        epoch: u64,
        validator_set: ConsensusValidatorSet,
    ) -> Result<Self, ConsensusError> {
        if validator_set.is_empty() {
            return Err(ConsensusError::EmptyValidatorSet);
        }

        let epoch_set = EpochValidatorSet {
            epoch,
            validator_set,
            activated_at: config.epoch_start_height(epoch),
        };

        let mut sets = BTreeMap::new();
        sets.insert(epoch, epoch_set);

        Ok(Self {
            config,
            state: RwLock::new(ValidatorSetState {
                sets,
                current_epoch: epoch,
                pending_next_epoch: None,
            }),
            storage: None,
        })
    }

    /// Set the storage provider after construction.
    ///
    /// Useful for adding persistence to an existing manager.
    pub fn set_storage(&mut self, storage: Arc<dyn ValidatorSetStorageProvider>) {
        self.storage = Some(storage);
    }

    /// Check if this manager has storage enabled.
    pub fn has_storage(&self) -> bool {
        self.storage.is_some()
    }

    /// Get the epoch configuration.
    pub fn config(&self) -> &EpochConfig {
        &self.config
    }

    /// Get the current epoch number.
    pub fn current_epoch(&self) -> u64 {
        self.state.read().current_epoch
    }

    /// Get the validator set for a specific height.
    ///
    /// Returns the validator set that is active at the given height.
    /// This is determined by the epoch the height falls into.
    ///
    /// # Returns
    ///
    /// * `Ok(Some(set))` - The validator set for this height
    /// * `Ok(None)` - No validator set found for this epoch (shouldn't happen normally)
    /// * `Err(e)` - Lock error
    pub fn get_validator_set_for_height(
        &self,
        height: ConsensusHeight,
    ) -> Result<Option<ConsensusValidatorSet>, ConsensusError> {
        let epoch = self.config.epoch_for_height(height);
        self.get_validator_set_for_epoch(epoch)
    }

    /// Get the validator set for a specific epoch.
    ///
    /// If the exact epoch is not found, returns the most recent
    /// validator set before that epoch (for historical queries).
    pub fn get_validator_set_for_epoch(
        &self,
        epoch: u64,
    ) -> Result<Option<ConsensusValidatorSet>, ConsensusError> {
        let state = self.state.read();

        // First try exact match
        if let Some(epoch_set) = state.sets.get(&epoch) {
            return Ok(Some(epoch_set.validator_set.clone()));
        }

        // Fall back to the most recent epoch before the requested one
        // This handles the case where validator set didn't change for several epochs
        if let Some((_, epoch_set)) = state.sets.range(..=epoch).next_back() {
            return Ok(Some(epoch_set.validator_set.clone()));
        }

        Ok(None)
    }

    /// Register a pending validator set for the next epoch.
    ///
    /// This should be called when a validator set change is detected
    /// (e.g., from the staking precompile). The new set will become
    /// active at the next epoch boundary.
    ///
    /// # Arguments
    ///
    /// * `validators` - The new validator set
    ///
    /// # Errors
    ///
    /// Returns `ConsensusError::EmptyValidatorSet` if the new set is empty.
    pub fn register_next_epoch_validators(
        &self,
        validators: Vec<ConsensusValidator>,
    ) -> Result<(), ConsensusError> {
        let new_set = ConsensusValidatorSet::new(validators);

        if new_set.is_empty() {
            return Err(ConsensusError::EmptyValidatorSet);
        }

        let mut state = self.state.write();
        state.pending_next_epoch = Some(new_set);

        Ok(())
    }

    /// Advance to the next epoch.
    ///
    /// This should be called when a block at an epoch boundary is committed.
    /// If there's a pending validator set, it becomes active.
    /// Otherwise, the current validator set continues.
    ///
    /// If storage is configured, the new epoch set is persisted.
    ///
    /// # Returns
    ///
    /// The validator set for the new epoch.
    ///
    /// # Deadlock Fix
    ///
    /// Previously this function acquired three separate write locks in order:
    /// `current_epoch.write() -> sets.write() -> pending_next_epoch.write()`
    /// This created a potential ABBA deadlock if other code acquired locks in
    /// a different order. Now all state is protected by a single consolidated lock.
    pub fn advance_epoch(&self) -> Result<ConsensusValidatorSet, ConsensusError> {
        let mut state = self.state.write();

        let new_epoch = state.current_epoch + 1;

        // Get the new validator set (either pending or current)
        let new_set = if let Some(pending_set) = state.pending_next_epoch.take() {
            pending_set
        } else {
            // No pending change, use current epoch's set
            state
                .sets
                .get(&state.current_epoch)
                .map(|es| es.validator_set.clone())
                .ok_or(ConsensusError::EmptyValidatorSet)?
        };

        // Store the new epoch's validator set
        let epoch_set = EpochValidatorSet {
            epoch: new_epoch,
            validator_set: new_set.clone(),
            activated_at: self.config.epoch_start_height(new_epoch),
        };

        // Persist to storage if available
        if let Some(ref storage) = self.storage {
            storage.persist_epoch_set(&epoch_set)?;
            storage.persist_current_epoch(new_epoch)?;
        }

        state.sets.insert(new_epoch, epoch_set);

        // Update current epoch
        state.current_epoch = new_epoch;

        // Prune old epochs if needed
        self.prune_old_epochs_internal(&mut state, new_epoch);

        Ok(new_set)
    }

    /// Notify the manager that a block has been committed.
    ///
    /// If the block is at an epoch boundary, advances to the next epoch.
    ///
    /// # Returns
    ///
    /// `true` if an epoch transition occurred.
    pub fn on_block_committed(&self, height: ConsensusHeight) -> Result<bool, ConsensusError> {
        if self.config.is_epoch_boundary(height) {
            self.advance_epoch()?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Check if a validator set change is pending.
    pub fn has_pending_change(&self) -> bool {
        self.state.read().pending_next_epoch.is_some()
    }

    /// Get the pending validator set (if any).
    pub fn pending_validator_set(&self) -> Option<ConsensusValidatorSet> {
        self.state.read().pending_next_epoch.clone()
    }

    /// Clear any pending validator set change.
    pub fn clear_pending_change(&self) {
        let mut state = self.state.write();
        state.pending_next_epoch = None;
    }

    /// Get the number of stored epochs.
    pub fn stored_epoch_count(&self) -> usize {
        self.state.read().sets.len()
    }

    /// Import a validator set for a specific epoch.
    ///
    /// Used for syncing historical validator sets from storage or peers.
    /// If storage is configured, the imported set is also persisted.
    pub fn import_epoch_set(
        &self,
        epoch: u64,
        validator_set: ConsensusValidatorSet,
    ) -> Result<(), ConsensusError> {
        if validator_set.is_empty() {
            return Err(ConsensusError::EmptyValidatorSet);
        }

        let epoch_set = EpochValidatorSet {
            epoch,
            validator_set,
            activated_at: self.config.epoch_start_height(epoch),
        };

        // Persist to storage if available
        if let Some(ref storage) = self.storage {
            storage.persist_epoch_set(&epoch_set)?;
        }

        let mut state = self.state.write();
        state.sets.insert(epoch, epoch_set);

        Ok(())
    }

    /// Prune old epochs (internal helper).
    ///
    /// Called from within methods that already hold the state write lock.
    /// Also removes pruned epochs from storage if configured.
    fn prune_old_epochs_internal(&self, state: &mut ValidatorSetState, current_epoch: u64) {
        let min_retained = current_epoch.saturating_sub(self.config.max_retained_epochs);

        // Remove epochs older than the retention window
        let epochs_to_remove: Vec<u64> = state
            .sets
            .keys()
            .filter(|&&e| e < min_retained)
            .copied()
            .collect();

        for epoch in epochs_to_remove {
            state.sets.remove(&epoch);

            // Also remove from storage if available
            // Note: We log errors but don't fail the operation since in-memory state is authoritative
            if let Some(ref storage) = self.storage {
                if let Err(e) = storage.delete_epoch_set(epoch) {
                    tracing::warn!("Failed to delete epoch {} from storage: {}", epoch, e);
                }
            }
        }
    }
}

impl std::fmt::Debug for ValidatorSetManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let current_epoch = self.current_epoch();
        let stored_count = self.stored_epoch_count();
        let has_pending = self.has_pending_change();

        f.debug_struct("ValidatorSetManager")
            .field("epoch_length", &self.config.epoch_length)
            .field("current_epoch", &current_epoch)
            .field("stored_epochs", &stored_count)
            .field("has_pending_change", &has_pending)
            .finish()
    }
}

/// In-memory implementation of `ValidatorSetStorageProvider` for testing.
///
/// This implementation stores validator sets in memory using `parking_lot::RwLock`
/// for thread safety. It's suitable for testing and development but should not
/// be used in production.
#[derive(Debug, Default)]
pub struct InMemoryValidatorSetStorage {
    epoch_sets: RwLock<BTreeMap<u64, EpochValidatorSet>>,
    current_epoch: RwLock<Option<u64>>,
}

impl InMemoryValidatorSetStorage {
    /// Create a new in-memory storage.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get the number of stored epoch sets.
    pub fn epoch_count(&self) -> usize {
        self.epoch_sets.read().len()
    }
}

impl ValidatorSetStorageProvider for InMemoryValidatorSetStorage {
    fn persist_epoch_set(&self, epoch_set: &EpochValidatorSet) -> Result<(), ConsensusError> {
        let mut sets = self.epoch_sets.write();
        sets.insert(epoch_set.epoch, epoch_set.clone());
        Ok(())
    }

    fn load_epoch_set(&self, epoch: u64) -> Result<Option<EpochValidatorSet>, ConsensusError> {
        let sets = self.epoch_sets.read();
        Ok(sets.get(&epoch).cloned())
    }

    fn load_all_epoch_sets(&self) -> Result<Vec<EpochValidatorSet>, ConsensusError> {
        let sets = self.epoch_sets.read();
        Ok(sets.values().cloned().collect())
    }

    fn persist_current_epoch(&self, epoch: u64) -> Result<(), ConsensusError> {
        let mut current = self.current_epoch.write();
        *current = Some(epoch);
        Ok(())
    }

    fn load_current_epoch(&self) -> Result<Option<u64>, ConsensusError> {
        let current = self.current_epoch.read();
        Ok(*current)
    }

    fn delete_epoch_set(&self, epoch: u64) -> Result<(), ConsensusError> {
        let mut sets = self.epoch_sets.write();
        sets.remove(&epoch);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cipherbft_crypto::Ed25519KeyPair;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    fn make_validator(id: u8, power: u64) -> ConsensusValidator {
        // Use seeded RNG for deterministic test keypairs
        let mut rng = StdRng::seed_from_u64(id as u64);
        let keypair = Ed25519KeyPair::generate(&mut rng);
        let validator_id = keypair.validator_id();
        ConsensusValidator::new(validator_id, keypair.public_key, power)
    }

    fn make_validators(count: usize) -> Vec<ConsensusValidator> {
        (1..=count as u8).map(|i| make_validator(i, 100)).collect()
    }

    #[test]
    fn test_epoch_config_height_to_epoch() {
        let config = EpochConfig::new(100);

        assert_eq!(config.epoch_for_height(ConsensusHeight(0)), 0);
        assert_eq!(config.epoch_for_height(ConsensusHeight(1)), 0);
        assert_eq!(config.epoch_for_height(ConsensusHeight(100)), 0);
        assert_eq!(config.epoch_for_height(ConsensusHeight(101)), 1);
        assert_eq!(config.epoch_for_height(ConsensusHeight(200)), 1);
        assert_eq!(config.epoch_for_height(ConsensusHeight(201)), 2);
    }

    #[test]
    fn test_epoch_config_boundaries() {
        let config = EpochConfig::new(100);

        assert!(!config.is_epoch_boundary(ConsensusHeight(0)));
        assert!(!config.is_epoch_boundary(ConsensusHeight(99)));
        assert!(config.is_epoch_boundary(ConsensusHeight(100)));
        assert!(!config.is_epoch_boundary(ConsensusHeight(101)));
        assert!(config.is_epoch_boundary(ConsensusHeight(200)));
    }

    #[test]
    fn test_epoch_config_start_height() {
        let config = EpochConfig::new(100);

        assert!(config.is_epoch_start(ConsensusHeight(1)));
        assert!(!config.is_epoch_start(ConsensusHeight(2)));
        assert!(config.is_epoch_start(ConsensusHeight(101)));
        assert!(config.is_epoch_start(ConsensusHeight(201)));
    }

    #[test]
    fn test_manager_creation() {
        let validators = make_validators(4);
        let manager =
            ValidatorSetManager::new(EpochConfig::default(), validators).expect("should create");

        assert_eq!(manager.current_epoch(), 0);
        assert_eq!(manager.stored_epoch_count(), 1);
        assert!(!manager.has_pending_change());
    }

    #[test]
    fn test_manager_empty_validators_error() {
        let result = ValidatorSetManager::new(EpochConfig::default(), vec![]);
        assert!(matches!(result, Err(ConsensusError::EmptyValidatorSet)));
    }

    #[test]
    fn test_get_validator_set_for_height() {
        let validators = make_validators(4);
        let config = EpochConfig::new(10);
        let manager = ValidatorSetManager::new(config, validators.clone()).expect("should create");

        // All heights in epoch 0 should return the same set
        for height in 1..=10 {
            let set = manager
                .get_validator_set_for_height(ConsensusHeight(height))
                .unwrap()
                .unwrap();
            assert_eq!(set.len(), 4);
        }

        // Heights in epoch 1 should also return the set (fallback to epoch 0)
        let set = manager
            .get_validator_set_for_height(ConsensusHeight(15))
            .unwrap()
            .unwrap();
        assert_eq!(set.len(), 4);
    }

    #[test]
    fn test_register_pending_validators() {
        let validators = make_validators(4);
        let manager =
            ValidatorSetManager::new(EpochConfig::default(), validators).expect("should create");

        assert!(!manager.has_pending_change());

        let new_validators = make_validators(5);
        manager
            .register_next_epoch_validators(new_validators)
            .unwrap();

        assert!(manager.has_pending_change());
    }

    #[test]
    fn test_advance_epoch_with_pending() {
        let validators = make_validators(4);
        let config = EpochConfig::new(10);
        let manager = ValidatorSetManager::new(config.clone(), validators).expect("should create");

        // Register new validators
        let new_validators = make_validators(5);
        manager
            .register_next_epoch_validators(new_validators)
            .unwrap();

        // Advance epoch
        let new_set = manager.advance_epoch().unwrap();

        assert_eq!(new_set.len(), 5);
        assert_eq!(manager.current_epoch(), 1);
        assert!(!manager.has_pending_change());

        // Verify the new set is returned for epoch 1 heights
        let set = manager
            .get_validator_set_for_height(ConsensusHeight(15))
            .unwrap()
            .unwrap();
        assert_eq!(set.len(), 5);
    }

    #[test]
    fn test_advance_epoch_without_pending() {
        let validators = make_validators(4);
        let config = EpochConfig::new(10);
        let manager = ValidatorSetManager::new(config, validators).expect("should create");

        // Advance without pending change
        let new_set = manager.advance_epoch().unwrap();

        assert_eq!(new_set.len(), 4); // Same as before
        assert_eq!(manager.current_epoch(), 1);
    }

    #[test]
    fn test_on_block_committed() {
        let validators = make_validators(4);
        let config = EpochConfig::new(10);
        let manager = ValidatorSetManager::new(config, validators).expect("should create");

        // Non-boundary block
        assert!(!manager.on_block_committed(ConsensusHeight(5)).unwrap());
        assert_eq!(manager.current_epoch(), 0);

        // Boundary block
        assert!(manager.on_block_committed(ConsensusHeight(10)).unwrap());
        assert_eq!(manager.current_epoch(), 1);
    }

    #[test]
    fn test_import_epoch_set() {
        let validators = make_validators(4);
        let config = EpochConfig::new(10);
        let manager = ValidatorSetManager::new(config, validators).expect("should create");

        // Import a set for epoch 5
        let new_validators = make_validators(3);
        let new_set = ConsensusValidatorSet::new(new_validators);
        manager.import_epoch_set(5, new_set).unwrap();

        // Should now have 2 stored epochs
        assert_eq!(manager.stored_epoch_count(), 2);

        // Query for epoch 5 should return the imported set
        let set = manager.get_validator_set_for_epoch(5).unwrap().unwrap();
        assert_eq!(set.len(), 3);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Storage provider tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_in_memory_storage_basic() {
        let storage = InMemoryValidatorSetStorage::new();

        // Initially empty
        assert_eq!(storage.epoch_count(), 0);
        assert!(storage.load_current_epoch().unwrap().is_none());

        // Persist an epoch set
        let validators = make_validators(4);
        let validator_set = ConsensusValidatorSet::new(validators);
        let epoch_set = EpochValidatorSet {
            epoch: 0,
            validator_set,
            activated_at: ConsensusHeight(1),
        };

        storage.persist_epoch_set(&epoch_set).unwrap();
        storage.persist_current_epoch(0).unwrap();

        // Verify persistence
        assert_eq!(storage.epoch_count(), 1);
        assert_eq!(storage.load_current_epoch().unwrap(), Some(0));

        let loaded = storage.load_epoch_set(0).unwrap().unwrap();
        assert_eq!(loaded.epoch, 0);
        assert_eq!(loaded.validator_set.len(), 4);
    }

    #[test]
    fn test_manager_with_storage() {
        let storage: Arc<dyn ValidatorSetStorageProvider> =
            Arc::new(InMemoryValidatorSetStorage::new());
        let validators = make_validators(4);
        let config = EpochConfig::new(10);

        // Create manager with storage
        let manager = ValidatorSetManager::with_storage(config, validators, Arc::clone(&storage))
            .expect("should create");

        assert!(manager.has_storage());

        // Verify genesis set was persisted
        let loaded = storage.load_epoch_set(0).unwrap().unwrap();
        assert_eq!(loaded.validator_set.len(), 4);
        assert_eq!(storage.load_current_epoch().unwrap(), Some(0));

        // Advance epoch with new validators
        let new_validators = make_validators(5);
        manager
            .register_next_epoch_validators(new_validators)
            .unwrap();
        manager.advance_epoch().unwrap();

        // Verify new epoch was persisted
        assert_eq!(storage.load_current_epoch().unwrap(), Some(1));

        let epoch1_set = storage.load_epoch_set(1).unwrap().unwrap();
        assert_eq!(epoch1_set.validator_set.len(), 5);
    }

    #[test]
    fn test_manager_recover_from_storage() {
        let storage: Arc<dyn ValidatorSetStorageProvider> =
            Arc::new(InMemoryValidatorSetStorage::new());

        // Pre-populate storage with some epochs
        let validators_epoch0 = make_validators(4);
        let set0 = EpochValidatorSet {
            epoch: 0,
            validator_set: ConsensusValidatorSet::new(validators_epoch0),
            activated_at: ConsensusHeight(1),
        };
        storage.persist_epoch_set(&set0).unwrap();

        let validators_epoch1 = make_validators(5);
        let set1 = EpochValidatorSet {
            epoch: 1,
            validator_set: ConsensusValidatorSet::new(validators_epoch1),
            activated_at: ConsensusHeight(11),
        };
        storage.persist_epoch_set(&set1).unwrap();
        storage.persist_current_epoch(1).unwrap();

        // Recover manager from storage
        let config = EpochConfig::new(10);
        let manager = ValidatorSetManager::recover_from_storage(config, Arc::clone(&storage))
            .expect("should recover");

        // Verify recovered state
        assert_eq!(manager.current_epoch(), 1);
        assert_eq!(manager.stored_epoch_count(), 2);

        let current_set = manager.get_validator_set_for_epoch(1).unwrap().unwrap();
        assert_eq!(current_set.len(), 5);

        let genesis_set = manager.get_validator_set_for_epoch(0).unwrap().unwrap();
        assert_eq!(genesis_set.len(), 4);
    }

    #[test]
    fn test_storage_import_epoch_set() {
        let storage: Arc<dyn ValidatorSetStorageProvider> =
            Arc::new(InMemoryValidatorSetStorage::new());
        let validators = make_validators(4);
        let config = EpochConfig::new(10);

        let manager =
            ValidatorSetManager::with_storage(config, validators, Arc::clone(&storage)).unwrap();

        // Import a historical epoch set
        let historical_validators = make_validators(3);
        let historical_set = ConsensusValidatorSet::new(historical_validators);
        manager.import_epoch_set(5, historical_set).unwrap();

        // Verify both manager and storage have the imported set
        assert_eq!(manager.stored_epoch_count(), 2);

        let loaded = storage.load_epoch_set(5).unwrap().unwrap();
        assert_eq!(loaded.validator_set.len(), 3);
    }
}
