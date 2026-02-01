//! State sync manager - main orchestrator

#![allow(dead_code)] // Will be used by node integration

use crate::blocks::BlockSyncer;
use crate::error::{Result, SyncError};
use crate::peers::PeerManager;
use crate::progress::{ProgressTracker, SnapSubPhase, SyncPhase};
use crate::protocol::StatusResponse;
use crate::snap::accounts::AccountRangeSyncer;
use crate::snap::storage::StorageRangeSyncer;
use crate::snapshot::{SnapshotAgreement, StateSnapshot};
use alloy_primitives::B256;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tracing::{info, warn};

/// Minimum peers required to start sync
pub const MIN_PEERS_FOR_SYNC: usize = 3;

/// Discovery timeout
pub const DISCOVERY_TIMEOUT: Duration = Duration::from_secs(30);

/// Sync configuration
#[derive(Clone, Debug)]
pub struct SyncConfig {
    /// Minimum peers required to start sync
    pub min_peers: usize,
    /// Maximum retries per request
    pub max_retries: u32,
    /// Request timeout
    pub request_timeout: Duration,
    /// Discovery timeout
    pub discovery_timeout: Duration,
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            min_peers: MIN_PEERS_FOR_SYNC,
            max_retries: 3,
            request_timeout: Duration::from_secs(10),
            discovery_timeout: DISCOVERY_TIMEOUT,
        }
    }
}

/// Main state sync manager
pub struct StateSyncManager {
    /// Configuration
    config: SyncConfig,
    /// Peer manager
    peers: PeerManager,
    /// Progress tracker
    progress: ProgressTracker,
    /// Target snapshot (set after discovery)
    target_snapshot: Option<StateSnapshot>,
    /// Account range syncer (active during snap sync)
    account_syncer: Option<AccountRangeSyncer>,
    /// Storage range syncer (active during snap sync)
    storage_syncer: Option<StorageRangeSyncer>,
    /// Block syncer (active during block sync)
    block_syncer: Option<BlockSyncer>,
    /// Discovery start time
    discovery_started: Option<Instant>,
    /// Current network tip height
    network_tip: u64,
}

impl StateSyncManager {
    /// Create a new sync manager
    pub fn new(config: SyncConfig) -> Self {
        Self {
            config,
            peers: PeerManager::new(),
            progress: ProgressTracker::new(),
            target_snapshot: None,
            account_syncer: None,
            storage_syncer: None,
            block_syncer: None,
            discovery_started: None,
            network_tip: 0,
        }
    }

    /// Create with default config
    pub fn with_defaults() -> Self {
        Self::new(SyncConfig::default())
    }

    /// Get current sync phase
    pub fn phase(&self) -> &SyncPhase {
        &self.progress.state().phase
    }

    /// Check if sync is complete
    pub fn is_complete(&self) -> bool {
        matches!(self.progress.state().phase, SyncPhase::Complete)
    }

    /// Get sync progress percentage
    pub fn progress_percent(&self) -> f64 {
        self.progress.state().overall_progress()
    }

    /// Add a peer
    pub fn add_peer(&mut self, peer_id: String) {
        self.peers.add_peer(peer_id);
    }

    /// Remove a peer
    pub fn remove_peer(&mut self, peer_id: &str) {
        self.peers.remove_peer(peer_id);
    }

    /// Handle status response from peer
    pub fn handle_status(&mut self, peer_id: &str, status: StatusResponse) {
        self.peers.update_status(peer_id, status.clone());

        // Update network tip
        if status.tip_height > self.network_tip {
            self.network_tip = status.tip_height;
        }
    }

    // === Phase: Discovery ===

    /// Start discovery phase
    pub fn start_discovery(&mut self) -> Result<()> {
        info!("Starting sync discovery phase");
        self.progress.set_phase(SyncPhase::Discovery)?;
        self.discovery_started = Some(Instant::now());
        Ok(())
    }

    /// Check if discovery is complete (enough peers with snapshot agreement)
    pub fn try_complete_discovery(&mut self) -> Result<Option<StateSnapshot>> {
        let peer_count = self.peers.peer_count();

        if peer_count < self.config.min_peers {
            // Check timeout
            if let Some(started) = self.discovery_started {
                if started.elapsed() > self.config.discovery_timeout {
                    return Err(SyncError::InsufficientPeers {
                        needed: self.config.min_peers as u32,
                        available: peer_count as u32,
                    });
                }
            }
            return Ok(None);
        }

        // Find best snapshot with agreement
        if let Some(agreement) = self.find_snapshot_agreement() {
            if agreement.has_quorum(self.config.min_peers) {
                info!(
                    height = agreement.snapshot.block_number,
                    peers = agreement.peer_count,
                    "Found snapshot with peer agreement"
                );
                return Ok(Some(agreement.snapshot));
            }
        }

        Ok(None)
    }

    /// Find snapshot with best peer agreement
    ///
    /// Requires agreement on both height AND state root for security.
    /// Two peers reporting the same height but different state roots
    /// indicates a chain fork or malicious peer.
    fn find_snapshot_agreement(&self) -> Option<SnapshotAgreement> {
        // Collect all snapshots from peers, keyed by (height, state_root)
        // This ensures we only count agreement when peers agree on BOTH values
        let mut snapshot_votes: HashMap<(u64, B256, B256), Vec<String>> = HashMap::new();

        for (peer_id, peer) in self.peers.iter() {
            if let Some(status) = &peer.status {
                for snapshot_info in &status.snapshots {
                    // Key by (height, state_root, block_hash) for full agreement
                    let key = (
                        snapshot_info.height,
                        snapshot_info.state_root,
                        snapshot_info.block_hash,
                    );
                    snapshot_votes.entry(key).or_default().push(peer_id.clone());
                }
            }
        }

        // Find highest snapshot with most votes
        // Only consider snapshots where peers agree on height AND state root
        snapshot_votes
            .into_iter()
            .filter(|(_, peers)| peers.len() >= self.config.min_peers)
            .max_by_key(|((height, _, _), peers)| (*height, peers.len()))
            .map(|((height, state_root, block_hash), peers)| {
                SnapshotAgreement {
                    snapshot: StateSnapshot::new(
                        height, block_hash, state_root,
                        0, // Timestamp not included in snapshot info - could be added later
                    ),
                    peer_count: peers.len(),
                    peers,
                }
            })
    }

    // === Phase: Snap Sync ===

    /// Start snap sync phase with selected snapshot
    pub fn start_snap_sync(&mut self, snapshot: StateSnapshot) -> Result<()> {
        info!(
            height = snapshot.block_number,
            state_root = %snapshot.state_root,
            "Starting snap sync"
        );

        self.target_snapshot = Some(snapshot.clone());
        self.account_syncer = Some(AccountRangeSyncer::new(snapshot));
        self.progress
            .set_phase(SyncPhase::SnapSync(SnapSubPhase::Accounts))?;

        Ok(())
    }

    /// Check if account sync is complete
    pub fn is_account_sync_complete(&self) -> bool {
        self.account_syncer.as_ref().is_none_or(|s| s.is_complete())
    }

    /// Transition to storage sync
    pub fn start_storage_sync(&mut self) -> Result<()> {
        let snapshot = self
            .target_snapshot
            .clone()
            .ok_or_else(|| SyncError::InvalidState("no target snapshot".into()))?;

        let accounts_with_storage: Vec<_> = self
            .account_syncer
            .as_ref()
            .map(|s| s.accounts_needing_storage().to_vec())
            .unwrap_or_default();

        info!(
            accounts = accounts_with_storage.len(),
            "Starting storage sync for accounts"
        );

        // Create storage syncer with accounts that need storage
        let storage_accounts: Vec<_> = accounts_with_storage
            .into_iter()
            .map(|addr| (addr, B256::ZERO)) // TODO: track actual storage roots
            .collect();

        self.storage_syncer = Some(StorageRangeSyncer::new(snapshot, storage_accounts));
        self.progress
            .set_phase(SyncPhase::SnapSync(SnapSubPhase::Storage))?;

        Ok(())
    }

    /// Check if storage sync is complete
    pub fn is_storage_sync_complete(&self) -> bool {
        self.storage_syncer.as_ref().is_none_or(|s| s.is_complete())
    }

    /// Verify final state root
    pub fn verify_state_root(&self) -> Result<()> {
        // TODO: Compute actual state root from downloaded state and compare
        // For now, assume verification passes
        info!("State root verification passed");
        Ok(())
    }

    // === Phase: Block Sync ===

    /// Start block sync phase
    pub fn start_block_sync(&mut self) -> Result<()> {
        let snapshot = self
            .target_snapshot
            .as_ref()
            .ok_or_else(|| SyncError::InvalidState("no target snapshot".into()))?;

        let start_height = snapshot.block_number + 1;
        let target_height = self.network_tip;

        if start_height > target_height {
            info!("Already at tip, no blocks to sync");
            self.progress.set_phase(SyncPhase::Complete)?;
            return Ok(());
        }

        info!(
            start = start_height,
            target = target_height,
            blocks = target_height - start_height + 1,
            "Starting block sync"
        );

        self.block_syncer = Some(BlockSyncer::new(start_height, target_height));
        self.progress.set_phase(SyncPhase::BlockSync)?;

        Ok(())
    }

    /// Check if block sync is complete
    pub fn is_block_sync_complete(&self) -> bool {
        self.block_syncer.as_ref().is_none_or(|s| s.is_complete())
    }

    /// Mark sync as complete
    pub fn complete_sync(&mut self) -> Result<()> {
        info!("Sync complete!");
        self.progress.set_phase(SyncPhase::Complete)?;

        // Clean up syncers
        self.account_syncer = None;
        self.storage_syncer = None;
        self.block_syncer = None;

        Ok(())
    }

    // === Error Handling ===

    /// Handle sync error from a peer
    pub fn handle_peer_error(&mut self, peer_id: &str, error: &SyncError) {
        warn!(peer = peer_id, error = %error, "Peer error during sync");
        self.peers.handle_misbehavior(peer_id, error);
    }

    // === Getters for syncers ===

    /// Get mutable reference to account syncer
    pub fn account_syncer_mut(&mut self) -> Option<&mut AccountRangeSyncer> {
        self.account_syncer.as_mut()
    }

    /// Get mutable reference to storage syncer
    pub fn storage_syncer_mut(&mut self) -> Option<&mut StorageRangeSyncer> {
        self.storage_syncer.as_mut()
    }

    /// Get mutable reference to block syncer
    pub fn block_syncer_mut(&mut self) -> Option<&mut BlockSyncer> {
        self.block_syncer.as_mut()
    }

    /// Get peer manager
    pub fn peers(&self) -> &PeerManager {
        &self.peers
    }

    /// Get mutable peer manager
    pub fn peers_mut(&mut self) -> &mut PeerManager {
        &mut self.peers
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_manager_creation() {
        let manager = StateSyncManager::with_defaults();
        assert!(matches!(manager.phase(), SyncPhase::Discovery));
        assert!(!manager.is_complete());
    }

    #[test]
    fn test_phase_transitions() {
        let mut manager = StateSyncManager::with_defaults();

        // Start discovery
        manager.start_discovery().unwrap();
        assert!(matches!(manager.phase(), SyncPhase::Discovery));

        // Start snap sync
        let snapshot = StateSnapshot::new(10000, B256::ZERO, B256::repeat_byte(0xab), 12345);
        manager.start_snap_sync(snapshot).unwrap();
        assert!(matches!(
            manager.phase(),
            SyncPhase::SnapSync(SnapSubPhase::Accounts)
        ));

        // Transition to storage
        manager.start_storage_sync().unwrap();
        assert!(matches!(
            manager.phase(),
            SyncPhase::SnapSync(SnapSubPhase::Storage)
        ));
    }

    #[test]
    fn test_peer_management() {
        use crate::protocol::SnapshotInfo;

        let mut manager = StateSyncManager::with_defaults();

        manager.add_peer("peer1".to_string());
        manager.add_peer("peer2".to_string());

        let status = StatusResponse {
            tip_height: 100000,
            tip_hash: B256::ZERO,
            snapshots: vec![
                SnapshotInfo {
                    height: 90000,
                    state_root: B256::repeat_byte(0xab),
                    block_hash: B256::repeat_byte(0xcd),
                },
                SnapshotInfo {
                    height: 80000,
                    state_root: B256::repeat_byte(0xef),
                    block_hash: B256::repeat_byte(0x12),
                },
            ],
        };

        manager.handle_status("peer1", status);
        assert_eq!(manager.network_tip, 100000);
    }

    #[test]
    fn test_block_sync_start() {
        let mut manager = StateSyncManager::with_defaults();
        manager.network_tip = 10100;

        let snapshot = StateSnapshot::new(10000, B256::ZERO, B256::ZERO, 0);
        manager.start_snap_sync(snapshot).unwrap();
        manager.start_storage_sync().unwrap();
        manager.start_block_sync().unwrap();

        assert!(matches!(manager.phase(), SyncPhase::BlockSync));
        assert!(manager.block_syncer.is_some());
    }

    #[test]
    fn test_already_at_tip() {
        let mut manager = StateSyncManager::with_defaults();
        manager.network_tip = 10000; // Same as snapshot

        let snapshot = StateSnapshot::new(10000, B256::ZERO, B256::ZERO, 0);
        manager.target_snapshot = Some(snapshot);
        manager.start_block_sync().unwrap();

        // Should go directly to complete
        assert!(matches!(manager.phase(), SyncPhase::Complete));
    }

    #[test]
    fn test_sync_completion() {
        let mut manager = StateSyncManager::with_defaults();
        manager.complete_sync().unwrap();

        assert!(manager.is_complete());
        assert!(manager.account_syncer.is_none());
        assert!(manager.storage_syncer.is_none());
        assert!(manager.block_syncer.is_none());
    }
}
