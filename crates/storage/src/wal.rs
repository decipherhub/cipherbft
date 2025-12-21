//! Write-Ahead Log (WAL) for crash recovery
//!
//! The WAL ensures crash recovery by logging all state changes before
//! they are applied to the main storage.
//!
//! # Recovery Process
//!
//! On startup, the WAL is replayed to restore any uncommitted state:
//! 1. Load last committed checkpoint
//! 2. Replay all entries after the checkpoint
//! 3. Apply entries to rebuild in-memory state
//! 4. Truncate WAL after successful recovery

use crate::error::Result;
use async_trait::async_trait;
use cipherbft_data_chain::{AggregatedAttestation, Batch, Car, Cut};
use cipherbft_types::Hash;
use serde::{Deserialize, Serialize};

/// WAL entry types for DCL operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WalEntry {
    /// Batch received from Worker
    BatchReceived(Batch),

    /// Car created by Primary
    CarCreated(Car),

    /// Car received from peer
    CarReceived(Car),

    /// Attestation aggregated (reached threshold)
    AttestationAggregated(AggregatedAttestation),

    /// Cut proposed for consensus
    CutProposed(Cut),

    /// Cut finalized by consensus
    CutFinalized {
        /// Height of the finalized Cut
        height: u64,
        /// Hash of the finalized Cut
        cut_hash: Hash,
    },

    /// Checkpoint marker
    Checkpoint {
        /// Height at checkpoint
        height: u64,
        /// Number of entries before checkpoint
        entry_count: u64,
    },

    // =========================================================
    // Pipeline state entries (T114)
    // =========================================================

    /// Pipeline stage changed
    PipelineStageChanged {
        /// New stage
        stage: PipelineStage,
        /// Current height
        height: u64,
    },

    /// Attestation received for future height (stored for later)
    NextHeightAttestation {
        /// Height this attestation is for
        height: u64,
        /// The attestation
        attestation: cipherbft_data_chain::Attestation,
    },

    /// Attested Cars preserved on timeout
    PreservedAttestedCars {
        /// Preserved cars with their attestations
        cars: Vec<(cipherbft_types::ValidatorId, Car, AggregatedAttestation)>,
    },
}

/// Pipeline stage (matching PrimaryState)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PipelineStage {
    /// Collecting attestations for current height
    Collecting,
    /// Cut formed, awaiting consensus decision
    Proposing,
    /// Consensus timeout, preserving attestations
    TimedOut,
}

impl WalEntry {
    /// Get entry type name for logging
    pub fn entry_type(&self) -> &'static str {
        match self {
            WalEntry::BatchReceived(_) => "BatchReceived",
            WalEntry::CarCreated(_) => "CarCreated",
            WalEntry::CarReceived(_) => "CarReceived",
            WalEntry::AttestationAggregated(_) => "AttestationAggregated",
            WalEntry::CutProposed(_) => "CutProposed",
            WalEntry::CutFinalized { .. } => "CutFinalized",
            WalEntry::Checkpoint { .. } => "Checkpoint",
            WalEntry::PipelineStageChanged { .. } => "PipelineStageChanged",
            WalEntry::NextHeightAttestation { .. } => "NextHeightAttestation",
            WalEntry::PreservedAttestedCars { .. } => "PreservedAttestedCars",
        }
    }
}

/// Write-Ahead Log trait
#[async_trait]
pub trait Wal: Send + Sync {
    /// Append an entry to the WAL
    ///
    /// # Arguments
    /// * `entry` - The entry to append
    ///
    /// # Returns
    /// The index of the appended entry
    async fn append(&self, entry: WalEntry) -> Result<u64>;

    /// Replay WAL entries from a given index
    ///
    /// # Arguments
    /// * `start_index` - Index to start replay from
    ///
    /// # Returns
    /// Iterator over WAL entries
    async fn replay_from(&self, start_index: u64) -> Result<Vec<(u64, WalEntry)>>;

    /// Get all entries (for recovery)
    async fn replay_all(&self) -> Result<Vec<(u64, WalEntry)>> {
        self.replay_from(0).await
    }

    /// Truncate WAL entries before a given index
    ///
    /// This is called after a checkpoint to remove old entries.
    ///
    /// # Arguments
    /// * `before_index` - Truncate entries before this index
    ///
    /// # Returns
    /// Number of entries truncated
    async fn truncate_before(&self, before_index: u64) -> Result<u64>;

    /// Get the next entry index (for appending)
    async fn next_index(&self) -> Result<u64>;

    /// Sync WAL to disk (fsync)
    async fn sync(&self) -> Result<()>;

    /// Get the last checkpoint index, if any
    async fn last_checkpoint(&self) -> Result<Option<u64>>;

    /// Create a checkpoint
    ///
    /// # Arguments
    /// * `height` - Current consensus height
    ///
    /// # Returns
    /// Index of the checkpoint entry
    async fn checkpoint(&self, height: u64) -> Result<u64>;
}

/// In-memory WAL implementation for testing
pub struct InMemoryWal {
    entries: parking_lot::RwLock<Vec<(u64, WalEntry)>>,
    next_index: std::sync::atomic::AtomicU64,
}

impl InMemoryWal {
    /// Create a new in-memory WAL
    pub fn new() -> Self {
        Self {
            entries: parking_lot::RwLock::new(Vec::new()),
            next_index: std::sync::atomic::AtomicU64::new(0),
        }
    }
}

impl Default for InMemoryWal {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Wal for InMemoryWal {
    async fn append(&self, entry: WalEntry) -> Result<u64> {
        let index = self
            .next_index
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let mut entries = self.entries.write();
        entries.push((index, entry));
        Ok(index)
    }

    async fn replay_from(&self, start_index: u64) -> Result<Vec<(u64, WalEntry)>> {
        let entries = self.entries.read();
        Ok(entries
            .iter()
            .filter(|(idx, _)| *idx >= start_index)
            .cloned()
            .collect())
    }

    async fn truncate_before(&self, before_index: u64) -> Result<u64> {
        let mut entries = self.entries.write();
        let original_len = entries.len();
        entries.retain(|(idx, _)| *idx >= before_index);
        Ok((original_len - entries.len()) as u64)
    }

    async fn next_index(&self) -> Result<u64> {
        Ok(self
            .next_index
            .load(std::sync::atomic::Ordering::SeqCst))
    }

    async fn sync(&self) -> Result<()> {
        // No-op for in-memory WAL
        Ok(())
    }

    async fn last_checkpoint(&self) -> Result<Option<u64>> {
        let entries = self.entries.read();
        for (idx, entry) in entries.iter().rev() {
            if matches!(entry, WalEntry::Checkpoint { .. }) {
                return Ok(Some(*idx));
            }
        }
        Ok(None)
    }

    async fn checkpoint(&self, height: u64) -> Result<u64> {
        let entry_count = self.next_index().await?;
        let entry = WalEntry::Checkpoint {
            height,
            entry_count,
        };
        self.append(entry).await
    }
}

/// WAL recovery manager
pub struct WalRecovery<W: Wal> {
    wal: W,
}

impl<W: Wal> WalRecovery<W> {
    /// Create a new recovery manager
    pub fn new(wal: W) -> Self {
        Self { wal }
    }

    /// Recover state from WAL
    ///
    /// Returns the recovered state entries since the last checkpoint.
    pub async fn recover(&self) -> Result<RecoveredState> {
        let mut state = RecoveredState::default();

        // Find last checkpoint
        let start_index = match self.wal.last_checkpoint().await? {
            Some(idx) => idx + 1, // Start after checkpoint
            None => 0,
        };

        // Replay entries
        let entries = self.wal.replay_from(start_index).await?;

        for (_, entry) in entries {
            match entry {
                WalEntry::BatchReceived(batch) => {
                    state.batches.push(batch);
                }
                WalEntry::CarCreated(car) | WalEntry::CarReceived(car) => {
                    state.cars.push(car);
                }
                WalEntry::AttestationAggregated(att) => {
                    state.attestations.push(att);
                }
                WalEntry::CutProposed(cut) => {
                    state.pending_cuts.push(cut);
                }
                WalEntry::CutFinalized { height, .. } => {
                    state.finalized_heights.push(height);
                }
                WalEntry::Checkpoint { height, .. } => {
                    state.last_checkpoint_height = Some(height);
                }
                // Pipeline state entries (T114-T115)
                WalEntry::PipelineStageChanged { stage, height } => {
                    state.pipeline_stage = Some(stage);
                    state.pipeline_height = Some(height);
                }
                WalEntry::NextHeightAttestation { height, attestation } => {
                    state
                        .next_height_attestations
                        .entry(height)
                        .or_default()
                        .push(attestation);
                }
                WalEntry::PreservedAttestedCars { cars } => {
                    state.preserved_attested_cars = cars;
                }
            }
        }

        Ok(state)
    }

    /// Get the underlying WAL
    pub fn wal(&self) -> &W {
        &self.wal
    }
}

/// Recovered state from WAL replay
#[derive(Debug, Default)]
pub struct RecoveredState {
    /// Recovered batches
    pub batches: Vec<Batch>,
    /// Recovered Cars
    pub cars: Vec<Car>,
    /// Recovered attestations
    pub attestations: Vec<AggregatedAttestation>,
    /// Recovered pending Cuts
    pub pending_cuts: Vec<Cut>,
    /// Finalized heights
    pub finalized_heights: Vec<u64>,
    /// Last checkpoint height
    pub last_checkpoint_height: Option<u64>,

    // Pipeline state (T114-T115)

    /// Last known pipeline stage
    pub pipeline_stage: Option<PipelineStage>,
    /// Last known pipeline height
    pub pipeline_height: Option<u64>,
    /// Attestations for future heights
    pub next_height_attestations: std::collections::HashMap<u64, Vec<cipherbft_data_chain::Attestation>>,
    /// Preserved attested Cars
    pub preserved_attested_cars: Vec<(cipherbft_types::ValidatorId, Car, AggregatedAttestation)>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use cipherbft_crypto::BlsKeyPair;
    use cipherbft_data_chain::BatchDigest;
    use cipherbft_types::VALIDATOR_ID_SIZE;

    fn make_validator_id(id: u8) -> cipherbft_types::ValidatorId {
        let mut bytes = [0u8; VALIDATOR_ID_SIZE];
        bytes[0] = id;
        cipherbft_types::ValidatorId::from_bytes(bytes)
    }

    fn make_test_car() -> Car {
        let keypair = BlsKeyPair::generate(&mut rand::thread_rng());
        let validator_id = make_validator_id(1);
        let batch_digest = BatchDigest::new(0, Hash::compute(b"batch"), 10, 100);

        let mut car = Car::new(validator_id, 0, vec![batch_digest], None);
        let signing_bytes = car.signing_bytes();
        car.signature = keypair.sign_car(&signing_bytes);
        car
    }

    fn make_test_batch() -> Batch {
        Batch::new(0, vec![], 0)
    }

    #[tokio::test]
    async fn test_wal_append_and_replay() {
        let wal = InMemoryWal::new();

        // Append entries
        let idx1 = wal.append(WalEntry::BatchReceived(make_test_batch())).await.unwrap();
        let idx2 = wal.append(WalEntry::CarCreated(make_test_car())).await.unwrap();

        assert_eq!(idx1, 0);
        assert_eq!(idx2, 1);

        // Replay all
        let entries = wal.replay_all().await.unwrap();
        assert_eq!(entries.len(), 2);
        assert!(matches!(entries[0].1, WalEntry::BatchReceived(_)));
        assert!(matches!(entries[1].1, WalEntry::CarCreated(_)));
    }

    #[tokio::test]
    async fn test_wal_replay_from_index() {
        let wal = InMemoryWal::new();

        wal.append(WalEntry::BatchReceived(make_test_batch())).await.unwrap();
        wal.append(WalEntry::CarCreated(make_test_car())).await.unwrap();
        wal.append(WalEntry::BatchReceived(make_test_batch())).await.unwrap();

        // Replay from index 1
        let entries = wal.replay_from(1).await.unwrap();
        assert_eq!(entries.len(), 2);
        assert!(matches!(entries[0].1, WalEntry::CarCreated(_)));
    }

    #[tokio::test]
    async fn test_wal_truncate() {
        let wal = InMemoryWal::new();

        wal.append(WalEntry::BatchReceived(make_test_batch())).await.unwrap();
        wal.append(WalEntry::CarCreated(make_test_car())).await.unwrap();
        wal.append(WalEntry::BatchReceived(make_test_batch())).await.unwrap();

        // Truncate before index 2
        let truncated = wal.truncate_before(2).await.unwrap();
        assert_eq!(truncated, 2);

        let entries = wal.replay_all().await.unwrap();
        assert_eq!(entries.len(), 1);
    }

    #[tokio::test]
    async fn test_wal_checkpoint() {
        let wal = InMemoryWal::new();

        wal.append(WalEntry::BatchReceived(make_test_batch())).await.unwrap();
        let cp_idx = wal.checkpoint(100).await.unwrap();

        assert!(wal.last_checkpoint().await.unwrap().is_some());
        assert_eq!(wal.last_checkpoint().await.unwrap().unwrap(), cp_idx);
    }

    #[tokio::test]
    async fn test_wal_recovery() {
        let wal = InMemoryWal::new();

        // Add some entries
        wal.append(WalEntry::BatchReceived(make_test_batch())).await.unwrap();
        wal.checkpoint(1).await.unwrap();
        wal.append(WalEntry::CarCreated(make_test_car())).await.unwrap();

        // Recover
        let recovery = WalRecovery::new(wal);
        let state = recovery.recover().await.unwrap();

        // Should only see entries after checkpoint
        assert_eq!(state.batches.len(), 0); // Before checkpoint
        assert_eq!(state.cars.len(), 1);    // After checkpoint
    }

    #[tokio::test]
    async fn test_wal_entry_type() {
        assert_eq!(WalEntry::BatchReceived(make_test_batch()).entry_type(), "BatchReceived");
        assert_eq!(WalEntry::CarCreated(make_test_car()).entry_type(), "CarCreated");
        assert_eq!(WalEntry::CutFinalized { height: 1, cut_hash: Hash::compute(b"test") }.entry_type(), "CutFinalized");
    }
}
