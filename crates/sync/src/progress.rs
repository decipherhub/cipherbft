//! Sync progress tracking for resumability

use crate::snapshot::StateSnapshot;
use alloy_primitives::{Address, B256};
use cipherbft_storage::{
    StoredAccountProgress, StoredBlockProgress, StoredStorageProgress, StoredSyncPhase,
    StoredSyncProgress, StoredSyncSnapshot, SyncStore,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Current sync phase
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum SyncPhase {
    /// Finding peers and selecting snapshot
    Discovery,
    /// Downloading account/storage state
    SnapSync(SnapSubPhase),
    /// Downloading and executing blocks
    BlockSync,
    /// Sync complete
    Complete,
}

/// Sub-phases within snap sync
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum SnapSubPhase {
    /// Downloading accounts
    Accounts,
    /// Downloading storage for accounts
    Storage,
    /// Final state root verification
    Verification,
}

/// Progress state persisted to disk
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SyncProgressState {
    /// Current sync phase
    pub phase: SyncPhase,
    /// Target snapshot being synced to
    pub target_snapshot: Option<StateSnapshot>,
    /// Account download progress
    pub account_progress: AccountProgress,
    /// Storage download progress per account
    pub storage_progress: BTreeMap<Address, StorageProgress>,
    /// Block sync progress
    pub block_progress: BlockProgress,
}

/// Account range download progress
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AccountProgress {
    /// Last completed address (exclusive upper bound)
    pub completed_up_to: Option<Address>,
    /// Addresses that need storage downloaded
    pub accounts_needing_storage: Vec<Address>,
    /// Total accounts downloaded
    pub total_accounts: u64,
    /// Total bytes downloaded
    pub total_bytes: u64,
}

/// Storage slot download progress
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct StorageProgress {
    /// Last completed slot (exclusive upper bound)
    pub completed_up_to: Option<B256>,
    /// Total slots downloaded
    pub total_slots: u64,
}

/// Block sync progress
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct BlockProgress {
    /// First block needed (snapshot height + 1)
    pub start_height: u64,
    /// Last block successfully executed
    pub executed_up_to: u64,
    /// Target height to sync to
    pub target_height: u64,
}

impl Default for SyncProgressState {
    fn default() -> Self {
        Self {
            phase: SyncPhase::Discovery,
            target_snapshot: None,
            account_progress: AccountProgress::default(),
            storage_progress: BTreeMap::new(),
            block_progress: BlockProgress::default(),
        }
    }
}

impl SyncProgressState {
    /// Create a new progress state
    pub fn new() -> Self {
        Self::default()
    }

    /// Reset progress for fresh sync
    pub fn reset(&mut self) {
        *self = Self::default();
    }

    /// Calculate overall sync progress as percentage
    pub fn overall_progress(&self) -> f64 {
        match &self.phase {
            SyncPhase::Discovery => 0.0,
            SyncPhase::SnapSync(sub) => {
                let base = match sub {
                    SnapSubPhase::Accounts => 0.0,
                    SnapSubPhase::Storage => 33.0,
                    SnapSubPhase::Verification => 66.0,
                };
                base + self.snap_phase_progress() * 33.0 / 100.0
            }
            SyncPhase::BlockSync => {
                66.0 + self.block_sync_progress() * 34.0 / 100.0
            }
            SyncPhase::Complete => 100.0,
        }
    }

    fn snap_phase_progress(&self) -> f64 {
        // Estimate based on address space coverage
        if let Some(addr) = &self.account_progress.completed_up_to {
            let first_byte = addr.0[0] as f64;
            (first_byte / 255.0) * 100.0
        } else {
            0.0
        }
    }

    fn block_sync_progress(&self) -> f64 {
        let bp = &self.block_progress;
        if bp.target_height <= bp.start_height {
            return 100.0;
        }
        let total = bp.target_height - bp.start_height;
        let done = bp.executed_up_to.saturating_sub(bp.start_height);
        (done as f64 / total as f64) * 100.0
    }
}

// ============================================================================
// Conversion between in-memory and storage types
// ============================================================================

impl From<&SyncPhase> for StoredSyncPhase {
    fn from(phase: &SyncPhase) -> Self {
        match phase {
            SyncPhase::Discovery => StoredSyncPhase::Discovery,
            SyncPhase::SnapSync(SnapSubPhase::Accounts) => StoredSyncPhase::SnapSyncAccounts,
            SyncPhase::SnapSync(SnapSubPhase::Storage) => StoredSyncPhase::SnapSyncStorage,
            SyncPhase::SnapSync(SnapSubPhase::Verification) => StoredSyncPhase::SnapSyncVerification,
            SyncPhase::BlockSync => StoredSyncPhase::BlockSync,
            SyncPhase::Complete => StoredSyncPhase::Complete,
        }
    }
}

impl From<&StoredSyncPhase> for SyncPhase {
    fn from(phase: &StoredSyncPhase) -> Self {
        match phase {
            StoredSyncPhase::Discovery => SyncPhase::Discovery,
            StoredSyncPhase::SnapSyncAccounts => SyncPhase::SnapSync(SnapSubPhase::Accounts),
            StoredSyncPhase::SnapSyncStorage => SyncPhase::SnapSync(SnapSubPhase::Storage),
            StoredSyncPhase::SnapSyncVerification => SyncPhase::SnapSync(SnapSubPhase::Verification),
            StoredSyncPhase::BlockSync => SyncPhase::BlockSync,
            StoredSyncPhase::Complete => SyncPhase::Complete,
        }
    }
}

impl From<&SyncProgressState> for StoredSyncProgress {
    fn from(state: &SyncProgressState) -> Self {
        StoredSyncProgress {
            phase: (&state.phase).into(),
            target_snapshot: state.target_snapshot.as_ref().map(|s| StoredSyncSnapshot {
                block_number: s.block_number,
                block_hash: s.block_hash.0,
                state_root: s.state_root.0,
                timestamp: s.timestamp,
            }),
            account_progress: StoredAccountProgress {
                completed_up_to: state.account_progress.completed_up_to.map(|a| a.0 .0),
                accounts_needing_storage: state
                    .account_progress
                    .accounts_needing_storage
                    .iter()
                    .map(|a| a.0 .0)
                    .collect(),
                total_accounts: state.account_progress.total_accounts,
                total_bytes: state.account_progress.total_bytes,
            },
            storage_progress: state
                .storage_progress
                .iter()
                .map(|(addr, progress)| {
                    (
                        addr.0 .0,
                        StoredStorageProgress {
                            completed_up_to: progress.completed_up_to.map(|b| b.0),
                            total_slots: progress.total_slots,
                        },
                    )
                })
                .collect(),
            block_progress: StoredBlockProgress {
                start_height: state.block_progress.start_height,
                executed_up_to: state.block_progress.executed_up_to,
                target_height: state.block_progress.target_height,
            },
        }
    }
}

impl From<&StoredSyncProgress> for SyncProgressState {
    fn from(stored: &StoredSyncProgress) -> Self {
        SyncProgressState {
            phase: (&stored.phase).into(),
            target_snapshot: stored.target_snapshot.as_ref().map(|s| {
                StateSnapshot::new(
                    s.block_number,
                    B256::from(s.block_hash),
                    B256::from(s.state_root),
                    s.timestamp,
                )
            }),
            account_progress: AccountProgress {
                completed_up_to: stored
                    .account_progress
                    .completed_up_to
                    .map(Address::from),
                accounts_needing_storage: stored
                    .account_progress
                    .accounts_needing_storage
                    .iter()
                    .map(|a| Address::from(*a))
                    .collect(),
                total_accounts: stored.account_progress.total_accounts,
                total_bytes: stored.account_progress.total_bytes,
            },
            storage_progress: stored
                .storage_progress
                .iter()
                .map(|(addr, progress)| {
                    (
                        Address::from(*addr),
                        StorageProgress {
                            completed_up_to: progress.completed_up_to.map(B256::from),
                            total_slots: progress.total_slots,
                        },
                    )
                })
                .collect(),
            block_progress: BlockProgress {
                start_height: stored.block_progress.start_height,
                executed_up_to: stored.block_progress.executed_up_to,
                target_height: stored.block_progress.target_height,
            },
        }
    }
}

/// Progress tracker with persistence
pub struct ProgressTracker {
    state: SyncProgressState,
}

impl ProgressTracker {
    /// Create a new progress tracker
    pub fn new() -> Self {
        Self {
            state: SyncProgressState::new(),
        }
    }

    /// Load progress from storage (or create fresh)
    ///
    /// This synchronous version creates a fresh tracker.
    /// Use `load_from_store` for async loading from storage.
    pub fn load_or_create() -> Self {
        Self::new()
    }

    /// Load progress from a sync store asynchronously
    ///
    /// If progress exists in storage, loads and returns it.
    /// Otherwise, returns a fresh tracker.
    pub async fn load_from_store<S: SyncStore>(store: &S) -> crate::Result<Self> {
        match store.get_progress().await {
            Ok(Some(stored)) => {
                tracing::info!("Loaded sync progress from storage");
                Ok(Self {
                    state: (&stored).into(),
                })
            }
            Ok(None) => {
                tracing::debug!("No existing sync progress, starting fresh");
                Ok(Self::new())
            }
            Err(e) => {
                tracing::warn!("Failed to load sync progress: {}, starting fresh", e);
                Ok(Self::new())
            }
        }
    }

    /// Get current progress state
    pub fn state(&self) -> &SyncProgressState {
        &self.state
    }

    /// Get mutable progress state
    pub fn state_mut(&mut self) -> &mut SyncProgressState {
        &mut self.state
    }

    /// Persist current progress to storage (no-op without store)
    ///
    /// This synchronous version is a no-op for backwards compatibility.
    /// Use `persist_to_store` for actual persistence.
    pub fn persist(&self) -> crate::Result<()> {
        Ok(())
    }

    /// Persist current progress to a sync store asynchronously
    pub async fn persist_to_store<S: SyncStore>(&self, store: &S) -> crate::Result<()> {
        let stored: StoredSyncProgress = (&self.state).into();
        store
            .put_progress(stored)
            .await
            .map_err(|e| crate::SyncError::Storage(format!("failed to persist progress: {}", e)))?;
        tracing::trace!("Persisted sync progress");
        Ok(())
    }

    /// Clear progress from storage after successful sync completion
    pub async fn clear_from_store<S: SyncStore>(&self, store: &S) -> crate::Result<()> {
        store
            .delete_progress()
            .await
            .map_err(|e| crate::SyncError::Storage(format!("failed to clear progress: {}", e)))?;
        tracing::info!("Cleared sync progress from storage");
        Ok(())
    }

    /// Update phase and persist
    pub fn set_phase(&mut self, phase: SyncPhase) -> crate::Result<()> {
        self.state.phase = phase;
        self.persist()
    }

    /// Update phase and persist to store
    pub async fn set_phase_and_persist<S: SyncStore>(
        &mut self,
        phase: SyncPhase,
        store: &S,
    ) -> crate::Result<()> {
        self.state.phase = phase;
        self.persist_to_store(store).await
    }

    /// Mark account range as complete
    pub fn complete_account_range(
        &mut self,
        up_to: Address,
        accounts: u64,
        bytes: u64,
        needs_storage: Vec<Address>,
    ) -> crate::Result<()> {
        self.state.account_progress.completed_up_to = Some(up_to);
        self.state.account_progress.total_accounts += accounts;
        self.state.account_progress.total_bytes += bytes;
        self.state
            .account_progress
            .accounts_needing_storage
            .extend(needs_storage);
        self.persist()
    }

    /// Mark account range as complete and persist to store
    pub async fn complete_account_range_and_persist<S: SyncStore>(
        &mut self,
        up_to: Address,
        accounts: u64,
        bytes: u64,
        needs_storage: Vec<Address>,
        store: &S,
    ) -> crate::Result<()> {
        self.state.account_progress.completed_up_to = Some(up_to);
        self.state.account_progress.total_accounts += accounts;
        self.state.account_progress.total_bytes += bytes;
        self.state
            .account_progress
            .accounts_needing_storage
            .extend(needs_storage);
        self.persist_to_store(store).await
    }

    /// Mark storage range as complete for account
    pub fn complete_storage_range(
        &mut self,
        account: Address,
        up_to: Option<B256>,
        slots: u64,
    ) -> crate::Result<()> {
        let progress = self.state.storage_progress.entry(account).or_default();
        progress.completed_up_to = up_to;
        progress.total_slots += slots;
        self.persist()
    }

    /// Mark storage range as complete and persist to store
    pub async fn complete_storage_range_and_persist<S: SyncStore>(
        &mut self,
        account: Address,
        up_to: Option<B256>,
        slots: u64,
        store: &S,
    ) -> crate::Result<()> {
        let progress = self.state.storage_progress.entry(account).or_default();
        progress.completed_up_to = up_to;
        progress.total_slots += slots;
        self.persist_to_store(store).await
    }

    /// Mark block as executed
    pub fn complete_block(&mut self, height: u64) -> crate::Result<()> {
        self.state.block_progress.executed_up_to = height;
        self.persist()
    }

    /// Mark block as executed and persist to store
    pub async fn complete_block_and_persist<S: SyncStore>(
        &mut self,
        height: u64,
        store: &S,
    ) -> crate::Result<()> {
        self.state.block_progress.executed_up_to = height;
        self.persist_to_store(store).await
    }
}

impl Default for ProgressTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_progress_phases() {
        let mut state = SyncProgressState::new();
        assert_eq!(state.phase, SyncPhase::Discovery);
        assert_eq!(state.overall_progress(), 0.0);

        state.phase = SyncPhase::Complete;
        assert_eq!(state.overall_progress(), 100.0);
    }

    #[test]
    fn test_block_progress_calculation() {
        let mut state = SyncProgressState::new();
        state.phase = SyncPhase::BlockSync;
        state.block_progress = BlockProgress {
            start_height: 10000,
            executed_up_to: 15000,
            target_height: 20000,
        };

        // 50% of block sync = 66% + (50% * 34%) = 83%
        let progress = state.overall_progress();
        assert!(progress > 82.0 && progress < 84.0);
    }

    #[test]
    fn test_progress_tracker() {
        let mut tracker = ProgressTracker::new();

        tracker
            .set_phase(SyncPhase::SnapSync(SnapSubPhase::Accounts))
            .unwrap();
        assert_eq!(
            tracker.state().phase,
            SyncPhase::SnapSync(SnapSubPhase::Accounts)
        );

        tracker
            .complete_account_range(
                Address::repeat_byte(0x80),
                1000,
                50000,
                vec![Address::repeat_byte(0x01)],
            )
            .unwrap();

        assert_eq!(tracker.state().account_progress.total_accounts, 1000);
        assert_eq!(
            tracker.state().account_progress.accounts_needing_storage.len(),
            1
        );
    }

    #[test]
    fn test_progress_serialization() {
        let mut state = SyncProgressState::new();
        state.phase = SyncPhase::SnapSync(SnapSubPhase::Storage);
        state.account_progress.total_accounts = 5000;

        let encoded = bincode::serialize(&state).unwrap();
        let decoded: SyncProgressState = bincode::deserialize(&encoded).unwrap();

        assert_eq!(decoded.phase, SyncPhase::SnapSync(SnapSubPhase::Storage));
        assert_eq!(decoded.account_progress.total_accounts, 5000);
    }

    #[test]
    fn test_phase_conversion_roundtrip() {
        let phases = vec![
            SyncPhase::Discovery,
            SyncPhase::SnapSync(SnapSubPhase::Accounts),
            SyncPhase::SnapSync(SnapSubPhase::Storage),
            SyncPhase::SnapSync(SnapSubPhase::Verification),
            SyncPhase::BlockSync,
            SyncPhase::Complete,
        ];

        for phase in phases {
            let stored: StoredSyncPhase = (&phase).into();
            let back: SyncPhase = (&stored).into();
            assert_eq!(phase, back);
        }
    }

    #[test]
    fn test_progress_state_conversion_roundtrip() {
        let mut state = SyncProgressState::new();
        state.phase = SyncPhase::SnapSync(SnapSubPhase::Storage);
        state.target_snapshot = Some(StateSnapshot::new(
            10000,
            B256::repeat_byte(0xab),
            B256::repeat_byte(0xcd),
            123456,
        ));
        state.account_progress.completed_up_to = Some(Address::repeat_byte(0x42));
        state.account_progress.total_accounts = 5000;
        state.account_progress.accounts_needing_storage = vec![Address::repeat_byte(0x01)];
        state.storage_progress.insert(
            Address::repeat_byte(0x01),
            StorageProgress {
                completed_up_to: Some(B256::repeat_byte(0xff)),
                total_slots: 100,
            },
        );
        state.block_progress.start_height = 10000;
        state.block_progress.executed_up_to = 10050;
        state.block_progress.target_height = 10100;

        let stored: StoredSyncProgress = (&state).into();
        let back: SyncProgressState = (&stored).into();

        assert_eq!(state.phase, back.phase);
        assert_eq!(
            state.target_snapshot.as_ref().map(|s| s.block_number),
            back.target_snapshot.as_ref().map(|s| s.block_number)
        );
        assert_eq!(
            state.account_progress.completed_up_to,
            back.account_progress.completed_up_to
        );
        assert_eq!(
            state.account_progress.total_accounts,
            back.account_progress.total_accounts
        );
        assert_eq!(
            state.storage_progress.len(),
            back.storage_progress.len()
        );
        assert_eq!(
            state.block_progress.executed_up_to,
            back.block_progress.executed_up_to
        );
    }
}
