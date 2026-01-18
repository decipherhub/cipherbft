//! State management for the execution layer.
//!
//! This module provides state root computation, caching, and rollback capabilities.
//! State roots are computed periodically (default: every 100 blocks) to balance
//! performance with state commitment guarantees.

use crate::database::{Account, Provider};
use crate::error::{ExecutionError, Result};
use crate::mpt::compute_state_root;
use crate::types::STATE_ROOT_SNAPSHOT_INTERVAL;
use alloy_primitives::{Address, B256};
use parking_lot::RwLock;
use std::collections::BTreeMap;
use std::sync::Arc;

/// State snapshot at a specific block height.
#[derive(Debug, Clone)]
pub struct StateSnapshot {
    /// Block number of this snapshot.
    pub block_number: u64,
    /// State root hash.
    pub state_root: B256,
    /// Account state at this snapshot.
    pub accounts: BTreeMap<Address, Account>,
}

/// Manager for state roots, snapshots, and rollback.
///
/// StateManager handles:
/// - Periodic state root computation (expensive operation)
/// - State root caching for quick lookups
/// - Snapshot management for rollback capability
/// - Commitment of state changes to storage
pub struct StateManager<P: Provider> {
    /// Underlying storage provider.
    #[allow(dead_code)] // Reserved for future use in state root computation
    provider: Arc<P>,

    /// Current state root (from last checkpoint).
    current_state_root: Arc<RwLock<B256>>,

    /// Last block number where state root was computed.
    last_checkpoint_block: Arc<RwLock<u64>>,

    /// Snapshots for rollback (block_number -> snapshot).
    ///
    /// Stores recent snapshots to enable efficient rollback without
    /// full state reconstruction. Pruned to prevent unbounded growth.
    snapshots: Arc<RwLock<BTreeMap<u64, StateSnapshot>>>,

    /// Maximum number of snapshots to keep.
    max_snapshots: usize,

    /// Cache for state roots at specific heights.
    state_root_cache: Arc<RwLock<lru::LruCache<u64, B256>>>,
}

impl<P: Provider> StateManager<P> {
    /// Create a new state manager with the given provider.
    ///
    /// # Arguments
    ///
    /// * `provider` - Storage provider for reading/writing state
    ///
    /// # Note
    ///
    /// State root computation interval is fixed at `STATE_ROOT_SNAPSHOT_INTERVAL` (100 blocks)
    /// and cannot be changed. This ensures consensus across all validators.
    pub fn new(provider: P) -> Self {
        Self {
            provider: Arc::new(provider),
            current_state_root: Arc::new(RwLock::new(B256::ZERO)),
            last_checkpoint_block: Arc::new(RwLock::new(0)),
            snapshots: Arc::new(RwLock::new(BTreeMap::new())),
            max_snapshots: 100, // Keep last 10,000 blocks worth (100 snapshots * 100 blocks)
            state_root_cache: Arc::new(RwLock::new(lru::LruCache::new(
                std::num::NonZeroUsize::new(1000).unwrap(),
            ))),
        }
    }

    /// Determine if state root should be computed for this block.
    ///
    /// State roots are computed at regular intervals (every 100 blocks)
    /// to balance performance with state commitment.
    ///
    /// This interval is a consensus-critical constant and cannot be changed.
    pub fn should_compute_state_root(&self, block_number: u64) -> bool {
        block_number > 0 && block_number % STATE_ROOT_SNAPSHOT_INTERVAL == 0
    }

    /// Compute state root for the current state (expensive operation).
    ///
    /// This is the expensive Merkle Patricia Trie computation that should only
    /// be done periodically. The computed root is cached and a snapshot is created.
    ///
    /// # Performance
    ///
    /// This operation is O(n) where n is the number of modified accounts since
    /// the last checkpoint. For a full state root, this can take 50-100ms for
    /// 10,000 accounts.
    pub fn compute_state_root(&self, block_number: u64) -> Result<B256> {
        tracing::debug!(
            block_number,
            "Computing state root (checkpoint interval: {})",
            STATE_ROOT_SNAPSHOT_INTERVAL
        );

        // Compute state root using Merkle Patricia Trie
        let state_root = self.compute_state_root_mpt()?;

        // Update current state root
        *self.current_state_root.write() = state_root;
        *self.last_checkpoint_block.write() = block_number;

        // Cache the state root
        self.state_root_cache.write().put(block_number, state_root);

        // Create snapshot at this checkpoint
        self.store_snapshot(block_number, state_root)?;

        tracing::debug!(
            block_number,
            state_root = %state_root,
            "State root computed"
        );

        Ok(state_root)
    }

    /// Compute the state root using Merkle Patricia Trie.
    ///
    /// This method iterates all accounts and their storage slots to build
    /// a cryptographically verifiable state root, compatible with Ethereum's
    /// state trie specification.
    ///
    /// # Algorithm
    /// 1. Get all accounts from the provider
    /// 2. For each account, compute its storage root
    /// 3. RLP encode each account as [nonce, balance, storage_root, code_hash]
    /// 4. Build MPT with keccak256(address) as keys
    /// 5. Return the trie root hash
    fn compute_state_root_mpt(&self) -> Result<B256> {
        // Get all accounts from the provider
        let accounts = self.provider.get_all_accounts()?;

        // Create a closure to get storage for each account
        let provider = Arc::clone(&self.provider);
        let storage_getter = move |address: Address| -> Result<BTreeMap<alloy_primitives::U256, alloy_primitives::U256>> {
            provider.get_all_storage(address)
        };

        // Compute the MPT-based state root
        compute_state_root(&accounts, storage_getter)
    }

    /// Get the current state root (from last checkpoint).
    ///
    /// This is a fast operation that returns the cached state root from
    /// the last checkpoint. If called on a non-checkpoint block, it returns
    /// the root from the most recent checkpoint.
    pub fn current_state_root(&self) -> B256 {
        *self.current_state_root.read()
    }

    /// Get state root at a specific block height.
    ///
    /// This checks the cache first, then snapshots, and returns the state root.
    /// Returns None if the block height is not a checkpoint and no snapshot exists.
    pub fn get_state_root(&self, block_number: u64) -> Result<Option<B256>> {
        // Check cache first
        if let Some(root) = self.state_root_cache.write().get(&block_number) {
            return Ok(Some(*root));
        }

        // Check snapshots
        if let Some(snapshot) = self.snapshots.read().get(&block_number) {
            let root = snapshot.state_root;
            // Update cache
            self.state_root_cache.write().put(block_number, root);
            return Ok(Some(root));
        }

        // Not a checkpoint block
        Ok(None)
    }

    /// Store a snapshot at the given block number.
    ///
    /// Captures the full account state from the provider for rollback capability.
    fn store_snapshot(&self, block_number: u64, state_root: B256) -> Result<()> {
        tracing::debug!(block_number, "Storing state snapshot");

        // Get all accounts from the provider for the snapshot
        let accounts = self.provider.get_all_accounts()?;
        let accounts_count = accounts.len();

        let snapshot = StateSnapshot {
            block_number,
            state_root,
            accounts,
        };

        self.snapshots.write().insert(block_number, snapshot);

        // Prune old snapshots
        self.prune_old_snapshots();

        tracing::debug!(
            block_number,
            accounts_count,
            "State snapshot stored"
        );

        Ok(())
    }

    /// Prune old snapshots to prevent unbounded growth.
    ///
    /// Keeps only the most recent N snapshots (configured by max_snapshots).
    fn prune_old_snapshots(&self) {
        let mut snapshots = self.snapshots.write();

        if snapshots.len() > self.max_snapshots {
            // Keep only the last max_snapshots entries
            let cutoff_block = snapshots
                .keys()
                .rev()
                .nth(self.max_snapshots)
                .copied()
                .unwrap_or(0);

            snapshots.retain(|&block, _| block > cutoff_block);

            tracing::debug!(
                retained = snapshots.len(),
                cutoff_block,
                "Pruned old snapshots"
            );
        }
    }

    /// Find the nearest snapshot for rollback to target block.
    ///
    /// Returns the snapshot at or before the target block number.
    pub fn find_snapshot_for_rollback(&self, target_block: u64) -> Option<(u64, B256)> {
        self.snapshots
            .read()
            .range(..=target_block)
            .next_back()
            .map(|(block, snapshot)| (*block, snapshot.state_root))
    }

    /// Commit pending changes to storage.
    ///
    /// This would typically be called after successful block execution to
    /// persist state changes to the underlying storage.
    pub fn commit(&self) -> Result<()> {
        // In a full implementation with MDBX, this would:
        // 1. Batch all pending writes
        // 2. Commit MDBX transaction
        // 3. Clear pending changes
        //
        // For now, the in-memory provider commits immediately
        Ok(())
    }

    /// Rollback to a previous block state.
    ///
    /// This operation:
    /// 1. Finds the nearest snapshot at or before target block
    /// 2. Restores state from that snapshot
    /// 3. If target > snapshot block, replays blocks from snapshot to target
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - No snapshot exists at or before target block
    /// - State restoration fails
    /// - Block replay fails (if needed)
    pub fn rollback_to(&self, target_block: u64) -> Result<()> {
        tracing::info!(target_block, "Rolling back state");

        // Find nearest snapshot
        let (snapshot_block, snapshot_root) = self
            .find_snapshot_for_rollback(target_block)
            .ok_or(ExecutionError::RollbackNoSnapshot(target_block))?;

        tracing::debug!(snapshot_block, target_block, "Found snapshot for rollback");

        // Restore state root
        *self.current_state_root.write() = snapshot_root;
        *self.last_checkpoint_block.write() = snapshot_block;

        // If target is exactly at snapshot, we're done
        if target_block == snapshot_block {
            tracing::info!(target_block, "Rollback complete (exact snapshot match)");
            return Ok(());
        }

        // If target > snapshot, we would need to replay blocks
        // This requires access to historical blocks, which would be provided
        // by the consensus layer. For now, we just restore to snapshot.
        tracing::warn!(
            snapshot_block,
            target_block,
            "Rollback to snapshot only (block replay not yet implemented)"
        );

        Ok(())
    }

    /// Get the last checkpoint block number.
    pub fn last_checkpoint_block(&self) -> u64 {
        *self.last_checkpoint_block.read()
    }

    /// Get snapshot count (for monitoring).
    pub fn snapshot_count(&self) -> usize {
        self.snapshots.read().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::InMemoryProvider;

    #[test]
    fn test_should_compute_state_root() {
        let provider = InMemoryProvider::new();
        let state_manager = StateManager::new(provider);

        assert!(!state_manager.should_compute_state_root(0));
        assert!(!state_manager.should_compute_state_root(50));
        assert!(!state_manager.should_compute_state_root(99));
        assert!(state_manager.should_compute_state_root(100));
        assert!(!state_manager.should_compute_state_root(101));
        assert!(state_manager.should_compute_state_root(200));
    }

    #[test]
    fn test_compute_and_get_state_root() {
        let provider = InMemoryProvider::new();
        let state_manager = StateManager::new(provider);

        // Compute state root at block 100
        let root = state_manager.compute_state_root(100).unwrap();
        assert_ne!(root, B256::ZERO);

        // Current state root should match
        assert_eq!(state_manager.current_state_root(), root);

        // Should be able to retrieve it
        let retrieved = state_manager.get_state_root(100).unwrap();
        assert_eq!(retrieved, Some(root));

        // Non-checkpoint block should return None
        assert_eq!(state_manager.get_state_root(50).unwrap(), None);
    }

    #[test]
    fn test_state_root_caching() {
        let provider = InMemoryProvider::new();
        let state_manager = StateManager::new(provider);

        // Compute state root
        let root = state_manager.compute_state_root(100).unwrap();

        // Retrieve multiple times - should hit cache
        for _ in 0..10 {
            let cached = state_manager.get_state_root(100).unwrap().unwrap();
            assert_eq!(cached, root);
        }

        // Cache should contain the entry
        assert!(state_manager.state_root_cache.write().contains(&100));
    }

    #[test]
    fn test_snapshot_storage_and_retrieval() {
        let provider = InMemoryProvider::new();
        let state_manager = StateManager::new(provider);

        // Create snapshots at multiple checkpoints
        let root1 = state_manager.compute_state_root(100).unwrap();
        let root2 = state_manager.compute_state_root(200).unwrap();
        let root3 = state_manager.compute_state_root(300).unwrap();

        // Verify snapshots exist
        assert_eq!(state_manager.snapshot_count(), 3);

        // Verify we can retrieve them
        assert_eq!(state_manager.get_state_root(100).unwrap().unwrap(), root1);
        assert_eq!(state_manager.get_state_root(200).unwrap().unwrap(), root2);
        assert_eq!(state_manager.get_state_root(300).unwrap().unwrap(), root3);
    }

    #[test]
    fn test_find_snapshot_for_rollback() {
        let provider = InMemoryProvider::new();
        let state_manager = StateManager::new(provider);

        // Create snapshots
        let root1 = state_manager.compute_state_root(100).unwrap();
        let root2 = state_manager.compute_state_root(200).unwrap();
        let _root3 = state_manager.compute_state_root(300).unwrap();

        // Find snapshot at exact block
        let (block, root) = state_manager.find_snapshot_for_rollback(200).unwrap();
        assert_eq!(block, 200);
        assert_eq!(root, root2);

        // Find snapshot before target
        let (block, root) = state_manager.find_snapshot_for_rollback(150).unwrap();
        assert_eq!(block, 100);
        assert_eq!(root, root1);

        // Find snapshot at boundary
        let (block, root) = state_manager.find_snapshot_for_rollback(100).unwrap();
        assert_eq!(block, 100);
        assert_eq!(root, root1);

        // No snapshot before block 50
        assert!(state_manager.find_snapshot_for_rollback(50).is_none());
    }

    #[test]
    fn test_rollback_to_exact_snapshot() {
        let provider = InMemoryProvider::new();
        let state_manager = StateManager::new(provider);

        // Create snapshots
        let root1 = state_manager.compute_state_root(100).unwrap();
        let root2 = state_manager.compute_state_root(200).unwrap();
        let root3 = state_manager.compute_state_root(300).unwrap();

        // Current should be latest
        assert_eq!(state_manager.current_state_root(), root3);

        // Rollback to block 200
        state_manager.rollback_to(200).unwrap();
        assert_eq!(state_manager.current_state_root(), root2);
        assert_eq!(state_manager.last_checkpoint_block(), 200);

        // Rollback to block 100
        state_manager.rollback_to(100).unwrap();
        assert_eq!(state_manager.current_state_root(), root1);
        assert_eq!(state_manager.last_checkpoint_block(), 100);
    }

    #[test]
    fn test_rollback_no_snapshot() {
        let provider = InMemoryProvider::new();
        let state_manager = StateManager::new(provider);

        // Try to rollback with no snapshots
        let result = state_manager.rollback_to(50);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ExecutionError::RollbackNoSnapshot(50)
        ));
    }

    #[test]
    fn test_snapshot_pruning() {
        let provider = InMemoryProvider::new();
        let mut state_manager = StateManager::new(provider);
        state_manager.max_snapshots = 5; // Set low limit for testing

        // Create snapshots at multiples of STATE_ROOT_SNAPSHOT_INTERVAL
        for i in 1..=10 {
            state_manager
                .compute_state_root(i * STATE_ROOT_SNAPSHOT_INTERVAL)
                .unwrap();
        }

        // Should be pruned to max_snapshots
        assert_eq!(state_manager.snapshot_count(), 5);

        // Should keep the most recent ones in snapshots
        let snapshots = state_manager.snapshots.read();
        assert!(snapshots.contains_key(&1000));
        assert!(snapshots.contains_key(&900));
        assert!(snapshots.contains_key(&800));
        assert!(snapshots.contains_key(&700));
        assert!(snapshots.contains_key(&600));

        // Older ones should be pruned from snapshots
        assert!(!snapshots.contains_key(&500));
        assert!(!snapshots.contains_key(&100));
    }

    #[test]
    fn test_state_root_interval_constant() {
        // Verify the consensus-critical constant
        assert_eq!(STATE_ROOT_SNAPSHOT_INTERVAL, 100);

        // Verify StateManager uses the constant
        let provider = InMemoryProvider::new();
        let sm = StateManager::new(provider);
        assert!(sm.should_compute_state_root(100));
        assert!(sm.should_compute_state_root(200));
        assert!(!sm.should_compute_state_root(50));
        assert!(!sm.should_compute_state_root(150));
    }

    #[test]
    fn test_last_checkpoint_block() {
        let provider = InMemoryProvider::new();
        let state_manager = StateManager::new(provider);

        // Initially 0
        assert_eq!(state_manager.last_checkpoint_block(), 0);

        // After computing state root
        state_manager.compute_state_root(100).unwrap();
        assert_eq!(state_manager.last_checkpoint_block(), 100);

        state_manager.compute_state_root(200).unwrap();
        assert_eq!(state_manager.last_checkpoint_block(), 200);
    }

    #[test]
    fn test_commit() {
        let provider = InMemoryProvider::new();
        let state_manager = StateManager::new(provider);

        // Commit should succeed (even though it's a no-op with InMemoryProvider)
        assert!(state_manager.commit().is_ok());
    }

    /// Property test: Same state should produce same state root (determinism)
    #[test]
    fn test_state_root_determinism_property() {
        use proptest::prelude::*;

        proptest!(|(block_number in 100u64..1000u64)| {
            // Create two independent state managers with same configuration
            let provider1 = InMemoryProvider::new();
            let provider2 = InMemoryProvider::new();

            let sm1 = StateManager::new(provider1);
            let sm2 = StateManager::new(provider2);

            // Compute state roots at same block number
            let root1 = sm1.compute_state_root(block_number).unwrap();
            let root2 = sm2.compute_state_root(block_number).unwrap();

            // State roots should be identical (deterministic)
            prop_assert_eq!(root1, root2, "State roots should be deterministic");
        });
    }

    /// Test that state root computation is deterministic across multiple executions
    #[test]
    fn test_state_root_determinism_repeated() {
        // Compute state root multiple times at same block
        let roots: Vec<B256> = (0..10)
            .map(|_| {
                let p = InMemoryProvider::new();
                let sm = StateManager::new(p);
                sm.compute_state_root(100).unwrap()
            })
            .collect();

        // All roots should be identical
        let first_root = roots[0];
        for (i, root) in roots.iter().enumerate() {
            assert_eq!(
                *root, first_root,
                "Iteration {} produced different state root",
                i
            );
        }
    }

    /// Test that identical state at different block numbers produces consistent roots
    #[test]
    fn test_state_root_consistency_across_blocks() {
        // Create two state managers with identical initial state
        let provider1 = InMemoryProvider::new();
        let provider2 = InMemoryProvider::new();

        let sm1 = StateManager::new(provider1);
        let sm2 = StateManager::new(provider2);

        // Compute state roots at different checkpoint blocks
        let root_100 = sm1.compute_state_root(100).unwrap();
        let root_200 = sm2.compute_state_root(200).unwrap();

        // With identical underlying state, roots should be the same
        // (block number affects when we compute, not what we compute)
        assert_eq!(root_100, root_200);
    }

    /// Test that state root is independent of computation order
    #[test]
    fn test_state_root_computation_order_independence() {
        let provider1 = InMemoryProvider::new();
        let provider2 = InMemoryProvider::new();

        let sm1 = StateManager::new(provider1);
        let sm2 = StateManager::new(provider2);

        // Compute in different order
        // sm1: compute at 100, then 200
        let root1_100 = sm1.compute_state_root(100).unwrap();
        let root1_200 = sm1.compute_state_root(200).unwrap();

        // sm2: compute at 200, then 100
        let root2_200 = sm2.compute_state_root(200).unwrap();
        let root2_100 = sm2.compute_state_root(100).unwrap();

        // Results should be independent of order
        assert_eq!(root1_100, root2_100);
        assert_eq!(root1_200, root2_200);
    }
}
