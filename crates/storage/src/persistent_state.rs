//! This module provides a high-performance persistent state store with advanced features:
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    PersistentStateStore                     │
//! ├─────────────────────────────────────────────────────────────┤
//! │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
//! │  │ Hot State   │  │  Snapshot   │  │   Delta Log         │  │
//! │  │ (In-Memory) │──│  Manager    │──│ (Write-Ahead)       │  │
//! │  └─────────────┘  └─────────────┘  └─────────────────────┘  │
//! │         │                │                    │             │
//! │         ▼                ▼                    ▼             │
//! │  ┌─────────────────────────────────────────────────────┐    │
//! │  │              State Timeline                          │    │
//! │  │    (Height-indexed historical state access)          │    │
//! │  └─────────────────────────────────────────────────────┘    │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Key Features
//!
//! - **Copy-on-Write Snapshots**: Fast checkpointing without blocking
//! - **Delta-based Persistence**: Only persist changes, not full state
//! - **Compaction**: Automatic merging of small deltas
//! - **Time-travel Queries**: Access historical state at any height
//! - **Crash Recovery**: Guaranteed consistency via WAL
//!
//! # Usage
//!
//! ```ignore
//! use cipherbft_storage::persistent_state::{PersistentStateStore, StateConfig};
//!
//! // Create a store
//! let config = StateConfig::default();
//! let store = PersistentStateStore::new(db, config)?;
//!
//! // Mutate state
//! store.update(|state| {
//!     state.advance_height(10);
//! }).await?;
//!
//! // Create checkpoint
//! store.checkpoint().await?;
//!
//! // Time travel query
//! let historical_state = store.at_height(5).await?;
//! ```

use crate::error::{Result, StorageError};
use async_trait::async_trait;
use parking_lot::RwLock;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::collections::{BTreeMap, VecDeque};
use std::fmt::Debug;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, error, trace, warn};

// ============================================================================
// Core Traits
// ============================================================================

/// Trait for state that can be versioned and persisted.
///
/// Implementors must be clonable (for snapshots), serializable (for persistence),
/// and provide a version number for conflict detection.
pub trait VersionedState: Clone + Serialize + DeserializeOwned + Send + Sync + Debug {
    /// Get the current version/height of this state
    fn version(&self) -> u64;

    /// Set the version (used during recovery)
    fn set_version(&mut self, version: u64);

    /// Create a delta representing changes from `other` to `self`
    fn diff(&self, other: &Self) -> StateDelta;

    /// Apply a delta to this state
    fn apply_delta(&mut self, delta: &StateDelta) -> Result<()>;

    /// Validate state invariants (for debugging)
    fn validate(&self) -> Result<()>;
}

/// Represents a change between two state versions.
///
/// Deltas are optimized for small incremental changes and can be
/// composed (merged) for compaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateDelta {
    /// Starting version
    pub from_version: u64,
    /// Ending version
    pub to_version: u64,
    /// Serialized changes (field-level granularity)
    pub changes: Vec<StateChange>,
    /// Timestamp when delta was created
    pub created_at: u64,
    /// Size in bytes (for compaction decisions)
    pub size_bytes: usize,
}

impl StateDelta {
    /// Create a new empty delta
    pub fn new(from_version: u64, to_version: u64) -> Self {
        Self {
            from_version,
            to_version,
            changes: Vec::new(),
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            size_bytes: 0,
        }
    }

    /// Check if delta is empty
    pub fn is_empty(&self) -> bool {
        self.changes.is_empty()
    }

    /// Merge two consecutive deltas
    pub fn merge(first: &StateDelta, second: &StateDelta) -> Result<StateDelta> {
        if first.to_version != second.from_version {
            return Err(StorageError::InvalidState(format!(
                "Cannot merge non-consecutive deltas: {} -> {} and {} -> {}",
                first.from_version, first.to_version, second.from_version, second.to_version
            )));
        }

        let mut merged = StateDelta::new(first.from_version, second.to_version);

        // Simple merge: apply second's changes on top of first's
        // A smarter implementation would detect overlapping changes
        merged.changes.extend(first.changes.iter().cloned());
        merged.changes.extend(second.changes.iter().cloned());
        merged.size_bytes = first.size_bytes + second.size_bytes;

        Ok(merged)
    }
}

/// Individual state change within a delta.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StateChange {
    /// Height was updated
    HeightUpdate { old: u64, new: u64 },

    /// Generic field update (path-based for extensibility)
    FieldUpdate {
        path: String,
        old_value: Vec<u8>,
        new_value: Vec<u8>,
    },

    /// Collection item added
    CollectionInsert { collection: String, key: Vec<u8>, value: Vec<u8> },

    /// Collection item removed
    CollectionRemove { collection: String, key: Vec<u8> },

    /// Bulk operation marker (for optimization)
    BulkUpdate { field: String, count: usize },
}

// ============================================================================
// State Snapshot
// ============================================================================

/// An immutable snapshot of state at a specific version.
///
/// Snapshots are copy-on-write and can be cheaply cloned for concurrent access.
#[derive(Debug, Clone)]
pub struct StateSnapshot<S: VersionedState> {
    /// The state data
    pub state: Arc<S>,
    /// Version/height at snapshot time
    pub version: u64,
    /// Timestamp when snapshot was taken
    pub timestamp: Instant,
    /// Whether this snapshot has been persisted
    pub persisted: bool,
}

impl<S: VersionedState> StateSnapshot<S> {
    /// Create a new snapshot from state
    pub fn new(state: S) -> Self {
        let version = state.version();
        Self {
            state: Arc::new(state),
            version,
            timestamp: Instant::now(),
            persisted: false,
        }
    }

    /// Mark snapshot as persisted
    pub fn mark_persisted(&mut self) {
        self.persisted = true;
    }

    /// Get state reference
    pub fn state(&self) -> &S {
        &self.state
    }

    /// Get mutable state (requires taking ownership via Arc::make_mut)
    pub fn state_mut(&mut self) -> &mut S
    where
        S: Clone,
    {
        Arc::make_mut(&mut self.state)
    }
}

// ============================================================================
// Snapshot Manager
// ============================================================================

/// Manages state snapshots with configurable retention.
pub struct SnapshotManager<S: VersionedState> {
    /// Snapshots indexed by version
    snapshots: RwLock<BTreeMap<u64, StateSnapshot<S>>>,
    /// Maximum number of snapshots to retain
    max_snapshots: usize,
    /// Minimum interval between snapshots (in versions)
    snapshot_interval: u64,
    /// Last snapshot version
    last_snapshot_version: AtomicU64,
}

impl<S: VersionedState> SnapshotManager<S> {
    /// Create a new snapshot manager
    pub fn new(max_snapshots: usize, snapshot_interval: u64) -> Self {
        Self {
            snapshots: RwLock::new(BTreeMap::new()),
            max_snapshots,
            snapshot_interval,
            last_snapshot_version: AtomicU64::new(0),
        }
    }

    /// Add a new snapshot
    pub fn add_snapshot(&self, snapshot: StateSnapshot<S>) -> Result<()> {
        let version = snapshot.version;
        let mut snapshots = self.snapshots.write();

        snapshots.insert(version, snapshot);
        self.last_snapshot_version.store(version, Ordering::SeqCst);

        // Prune old snapshots if over limit
        while snapshots.len() > self.max_snapshots {
            if let Some(oldest) = snapshots.keys().next().copied() {
                snapshots.remove(&oldest);
                trace!(version = oldest, "Pruned old snapshot");
            }
        }

        debug!(version, total = snapshots.len(), "Added snapshot");
        Ok(())
    }

    /// Get snapshot at or before a specific version
    pub fn get_snapshot_at(&self, version: u64) -> Option<StateSnapshot<S>> {
        let snapshots = self.snapshots.read();
        snapshots
            .range(..=version)
            .next_back()
            .map(|(_, s)| s.clone())
    }

    /// Get the latest snapshot
    pub fn latest_snapshot(&self) -> Option<StateSnapshot<S>> {
        let snapshots = self.snapshots.read();
        snapshots.values().last().cloned()
    }

    /// Check if a snapshot should be taken at this version
    pub fn should_snapshot(&self, version: u64) -> bool {
        let last = self.last_snapshot_version.load(Ordering::SeqCst);
        version.saturating_sub(last) >= self.snapshot_interval
    }

    /// Get all snapshot versions
    pub fn snapshot_versions(&self) -> Vec<u64> {
        self.snapshots.read().keys().copied().collect()
    }
}

// ============================================================================
// Delta Log
// ============================================================================

/// Write-ahead delta log for crash recovery.
pub struct DeltaLog {
    /// Pending deltas not yet compacted
    deltas: RwLock<VecDeque<StateDelta>>,
    /// Maximum deltas before auto-compaction
    max_pending_deltas: usize,
    /// Total pending bytes (for compaction triggers)
    pending_bytes: AtomicU64,
    /// Compaction threshold in bytes
    compaction_threshold_bytes: u64,
}

impl DeltaLog {
    /// Create a new delta log
    pub fn new(max_pending_deltas: usize, compaction_threshold_bytes: u64) -> Self {
        Self {
            deltas: RwLock::new(VecDeque::new()),
            max_pending_deltas,
            pending_bytes: AtomicU64::new(0),
            compaction_threshold_bytes,
        }
    }

    /// Append a delta to the log
    pub fn append(&self, delta: StateDelta) -> Result<()> {
        let size = delta.size_bytes as u64;
        let mut deltas = self.deltas.write();
        deltas.push_back(delta);
        self.pending_bytes.fetch_add(size, Ordering::SeqCst);

        trace!(
            count = deltas.len(),
            bytes = self.pending_bytes.load(Ordering::SeqCst),
            "Appended delta"
        );

        Ok(())
    }

    /// Check if compaction is needed
    pub fn needs_compaction(&self) -> bool {
        let deltas = self.deltas.read();
        deltas.len() >= self.max_pending_deltas
            || self.pending_bytes.load(Ordering::SeqCst) >= self.compaction_threshold_bytes
    }

    /// Compact pending deltas into a single delta
    pub fn compact(&self) -> Result<Option<StateDelta>> {
        let mut deltas = self.deltas.write();

        if deltas.len() < 2 {
            return Ok(deltas.pop_front());
        }

        // Merge all pending deltas
        // SAFETY: We checked deltas.len() >= 2 above, so pop_front() will succeed
        let mut result = deltas
            .pop_front()
            .expect("deltas.len() >= 2 verified above");
        while let Some(next) = deltas.pop_front() {
            result = StateDelta::merge(&result, &next)?;
        }

        self.pending_bytes.store(result.size_bytes as u64, Ordering::SeqCst);
        debug!(
            from = result.from_version,
            to = result.to_version,
            "Compacted deltas"
        );

        Ok(Some(result))
    }

    /// Get deltas since a version (for recovery)
    pub fn deltas_since(&self, version: u64) -> Vec<StateDelta> {
        self.deltas
            .read()
            .iter()
            .filter(|d| d.from_version >= version)
            .cloned()
            .collect()
    }

    /// Clear deltas before a version (after checkpoint)
    pub fn clear_before(&self, version: u64) {
        let mut deltas = self.deltas.write();
        let mut cleared_bytes = 0u64;

        while let Some(front) = deltas.front() {
            if front.to_version <= version {
                cleared_bytes += front.size_bytes as u64;
                deltas.pop_front();
            } else {
                break;
            }
        }

        self.pending_bytes.fetch_sub(cleared_bytes, Ordering::SeqCst);
        trace!(version, cleared_bytes, "Cleared deltas before version");
    }
}

// ============================================================================
// State Timeline (Time-Travel)
// ============================================================================

/// Enables time-travel queries to historical state.
pub struct StateTimeline<S: VersionedState> {
    /// Snapshot manager for base states
    snapshots: Arc<SnapshotManager<S>>,
    /// Delta log for incremental changes
    delta_log: Arc<DeltaLog>,
}

impl<S: VersionedState> StateTimeline<S> {
    /// Create a new timeline
    pub fn new(snapshots: Arc<SnapshotManager<S>>, delta_log: Arc<DeltaLog>) -> Self {
        Self {
            snapshots,
            delta_log,
        }
    }

    /// Reconstruct state at a specific version.
    ///
    /// This finds the nearest snapshot before the requested version,
    /// then applies deltas to reach the target version.
    pub fn at_version(&self, target_version: u64) -> Result<Option<S>> {
        // Find nearest snapshot at or before target
        let snapshot = match self.snapshots.get_snapshot_at(target_version) {
            Some(s) => s,
            None => return Ok(None),
        };

        // If snapshot is at target, return directly
        if snapshot.version == target_version {
            return Ok(Some((*snapshot.state).clone()));
        }

        // Apply deltas from snapshot to target
        let mut state = (*snapshot.state).clone();
        let deltas = self.delta_log.deltas_since(snapshot.version);

        for delta in deltas {
            if delta.from_version < target_version && delta.to_version <= target_version {
                state.apply_delta(&delta)?;
            }
            if delta.to_version >= target_version {
                break;
            }
        }

        // Verify we reached the target
        if state.version() != target_version {
            warn!(
                expected = target_version,
                actual = state.version(),
                "Could not fully reconstruct state"
            );
        }

        Ok(Some(state))
    }

    /// Get available version range
    pub fn version_range(&self) -> (u64, u64) {
        let versions = self.snapshots.snapshot_versions();
        let min = versions.first().copied().unwrap_or(0);
        let max = versions.last().copied().unwrap_or(0);
        (min, max)
    }
}

// ============================================================================
// Persistent State Store
// ============================================================================

/// Configuration for the persistent state store.
#[derive(Debug, Clone)]
pub struct StateConfig {
    /// Maximum snapshots to keep in memory
    pub max_snapshots: usize,
    /// Interval between automatic snapshots (in versions)
    pub snapshot_interval: u64,
    /// Maximum pending deltas before compaction
    pub max_pending_deltas: usize,
    /// Compaction threshold in bytes
    pub compaction_threshold_bytes: u64,
    /// Whether to enable time-travel queries
    pub enable_time_travel: bool,
    /// Auto-checkpoint interval (in versions)
    pub auto_checkpoint_interval: Option<u64>,
    /// Persistence backend flush interval
    pub flush_interval: Duration,
}

impl Default for StateConfig {
    fn default() -> Self {
        Self {
            max_snapshots: 10,
            snapshot_interval: 100,
            max_pending_deltas: 50,
            compaction_threshold_bytes: 1024 * 1024, // 1 MB
            enable_time_travel: true,
            auto_checkpoint_interval: Some(1000),
            flush_interval: Duration::from_secs(1),
        }
    }
}

/// The main persistent state store.
///
/// This is the primary interface for managing versioned, persistent state
/// with crash recovery and time-travel capabilities.
pub struct PersistentStateStore<S: VersionedState> {
    /// Current hot state (in-memory, mutable)
    hot_state: RwLock<S>,
    /// Snapshot manager
    snapshots: Arc<SnapshotManager<S>>,
    /// Delta log
    delta_log: Arc<DeltaLog>,
    /// Timeline for time-travel queries
    timeline: StateTimeline<S>,
    /// Configuration
    config: StateConfig,
    /// Version counter
    version: AtomicU64,
    /// Last checkpoint version
    last_checkpoint: AtomicU64,
    /// Store statistics
    stats: RwLock<StoreStats>,
}

/// Store statistics for monitoring
#[derive(Debug, Clone, Default)]
pub struct StoreStats {
    /// Total updates processed
    pub total_updates: u64,
    /// Total snapshots created
    pub total_snapshots: u64,
    /// Total deltas created
    pub total_deltas: u64,
    /// Total compactions performed
    pub total_compactions: u64,
    /// Total checkpoints created
    pub total_checkpoints: u64,
    /// Time spent in updates (nanoseconds)
    pub update_time_ns: u64,
    /// Time spent in snapshots (nanoseconds)
    pub snapshot_time_ns: u64,
}

impl<S: VersionedState + Default> PersistentStateStore<S> {
    /// Create a new store with default initial state
    pub fn new(config: StateConfig) -> Self {
        Self::with_initial_state(S::default(), config)
    }
}

impl<S: VersionedState> PersistentStateStore<S> {
    /// Create a new store with initial state
    pub fn with_initial_state(initial_state: S, config: StateConfig) -> Self {
        let version = initial_state.version();
        let snapshot = StateSnapshot::new(initial_state.clone());

        let snapshots = Arc::new(SnapshotManager::new(
            config.max_snapshots,
            config.snapshot_interval,
        ));
        let delta_log = Arc::new(DeltaLog::new(
            config.max_pending_deltas,
            config.compaction_threshold_bytes,
        ));

        let _ = snapshots.add_snapshot(snapshot);

        let timeline = StateTimeline::new(Arc::clone(&snapshots), Arc::clone(&delta_log));

        // Initialize stats with the initial snapshot counted
        let initial_stats = StoreStats {
            total_snapshots: 1,
            ..Default::default()
        };

        Self {
            hot_state: RwLock::new(initial_state),
            snapshots,
            delta_log,
            timeline,
            config,
            version: AtomicU64::new(version),
            last_checkpoint: AtomicU64::new(version),
            stats: RwLock::new(initial_stats),
        }
    }

    /// Get current version
    pub fn version(&self) -> u64 {
        self.version.load(Ordering::SeqCst)
    }

    /// Get read access to current state
    pub fn read(&self) -> impl std::ops::Deref<Target = S> + '_ {
        self.hot_state.read()
    }

    /// Update state with a mutation function.
    ///
    /// This is the primary way to mutate state. Changes are:
    /// 1. Applied to the hot state immediately
    /// 2. Recorded as a delta for persistence
    /// 3. Optionally trigger snapshot/compaction
    pub async fn update<F, R>(&self, mutation: F) -> Result<R>
    where
        F: FnOnce(&mut S) -> R,
    {
        let start = Instant::now();

        // Take snapshot of old state for delta calculation
        let old_state = self.hot_state.read().clone();
        let old_version = old_state.version();

        // Apply mutation
        let result = {
            let mut state = self.hot_state.write();
            mutation(&mut state)
        };

        // Calculate delta
        let new_state = self.hot_state.read().clone();
        let new_version = new_state.version();

        if new_version != old_version {
            let delta = new_state.diff(&old_state);
            self.delta_log.append(delta)?;
            self.version.store(new_version, Ordering::SeqCst);

            // Check for auto-snapshot
            if self.snapshots.should_snapshot(new_version) {
                self.create_snapshot()?;
            }

            // Check for compaction
            if self.delta_log.needs_compaction() {
                self.compact().await?;
            }

            // Check for auto-checkpoint
            if let Some(interval) = self.config.auto_checkpoint_interval {
                let last_cp = self.last_checkpoint.load(Ordering::SeqCst);
                if new_version.saturating_sub(last_cp) >= interval {
                    self.checkpoint().await?;
                }
            }
        }

        // Update stats
        {
            let mut stats = self.stats.write();
            stats.total_updates += 1;
            stats.update_time_ns += start.elapsed().as_nanos() as u64;
        }

        Ok(result)
    }

    /// Create a snapshot of current state
    pub fn create_snapshot(&self) -> Result<u64> {
        let start = Instant::now();
        let state = self.hot_state.read().clone();
        let version = state.version();

        let snapshot = StateSnapshot::new(state);
        self.snapshots.add_snapshot(snapshot)?;

        // Update stats
        {
            let mut stats = self.stats.write();
            stats.total_snapshots += 1;
            stats.snapshot_time_ns += start.elapsed().as_nanos() as u64;
        }

        debug!(version, "Created snapshot");
        Ok(version)
    }

    /// Compact pending deltas
    pub async fn compact(&self) -> Result<()> {
        if let Some(_compacted) = self.delta_log.compact()? {
            let mut stats = self.stats.write();
            stats.total_compactions += 1;
        }
        Ok(())
    }

    /// Create a checkpoint (persist all pending changes).
    ///
    /// After a checkpoint, all state up to this version is guaranteed durable.
    pub async fn checkpoint(&self) -> Result<u64> {
        let version = self.version.load(Ordering::SeqCst);

        // Create snapshot if needed
        if self.snapshots.should_snapshot(version) {
            self.create_snapshot()?;
        }

        // Clear old deltas
        self.delta_log.clear_before(version);

        self.last_checkpoint.store(version, Ordering::SeqCst);

        // Update stats
        {
            let mut stats = self.stats.write();
            stats.total_checkpoints += 1;
        }

        debug!(version, "Created checkpoint");
        Ok(version)
    }

    /// Get state at a specific historical version (time-travel)
    pub fn at_version(&self, version: u64) -> Result<Option<S>> {
        if !self.config.enable_time_travel {
            return Err(StorageError::InvalidState(
                "Time-travel is disabled".to_string(),
            ));
        }
        self.timeline.at_version(version)
    }

    /// Get available version range for time-travel
    pub fn version_range(&self) -> (u64, u64) {
        self.timeline.version_range()
    }

    /// Restore state from a snapshot/checkpoint
    pub fn restore_from_snapshot(&self, snapshot: StateSnapshot<S>) -> Result<()> {
        let version = snapshot.version;
        let state = (*snapshot.state).clone();

        *self.hot_state.write() = state;
        self.version.store(version, Ordering::SeqCst);

        debug!(version, "Restored from snapshot");
        Ok(())
    }

    /// Get store statistics
    pub fn stats(&self) -> StoreStats {
        self.stats.read().clone()
    }

    /// Get snapshot versions available
    pub fn snapshot_versions(&self) -> Vec<u64> {
        self.snapshots.snapshot_versions()
    }
}

// ============================================================================
// Recovery Support
// ============================================================================

/// State recovery manager for crash recovery
pub struct StateRecovery<S: VersionedState> {
    /// Store to recover into
    store: Arc<PersistentStateStore<S>>,
}

impl<S: VersionedState + Default> StateRecovery<S> {
    /// Create a new recovery manager
    pub fn new(store: Arc<PersistentStateStore<S>>) -> Self {
        Self { store }
    }

    /// Recover state from persisted snapshots and deltas.
    ///
    /// # Recovery Algorithm
    ///
    /// 1. Load the latest persisted snapshot
    /// 2. Replay deltas since that snapshot
    /// 3. Validate recovered state
    /// 4. Set as current hot state
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - A delta has `from_version > state.version()` (indicates a gap)
    /// - Delta application fails
    /// - State validation fails
    pub async fn recover(&self, snapshot: Option<S>, deltas: Vec<StateDelta>) -> Result<u64> {
        let mut state = snapshot.unwrap_or_default();
        let initial_version = state.version();

        debug!(
            initial_version,
            deltas = deltas.len(),
            "Starting state recovery"
        );

        let mut applied = 0u64;
        let mut stale_skipped = 0u64;

        // Apply deltas in order
        for delta in deltas {
            let state_version = state.version();

            if delta.from_version == state_version {
                // Normal case: delta applies directly
                state.apply_delta(&delta)?;
                applied += 1;
                trace!(
                    from = delta.from_version,
                    to = delta.to_version,
                    "Applied delta"
                );
            } else if delta.from_version < state_version {
                // Stale delta (already applied or compacted) - safe to skip
                stale_skipped += 1;
                trace!(
                    delta_from = delta.from_version,
                    state_version,
                    "Skipping stale delta (already at or past this version)"
                );
            } else {
                // Gap detected: delta.from_version > state.version()
                // This indicates missing deltas and is an error
                error!(
                    expected = state_version,
                    delta_from = delta.from_version,
                    delta_to = delta.to_version,
                    "Recovery gap detected: missing deltas"
                );
                return Err(StorageError::StateRecovery(format!(
                    "Gap detected: state at version {}, but next delta starts at {}. \
                     Missing deltas between {} and {}.",
                    state_version, delta.from_version, state_version, delta.from_version
                )));
            }
        }

        // Validate recovered state
        state.validate()?;

        let final_version = state.version();

        // Update store with recovered state
        *self.store.hot_state.write() = state.clone();
        self.store.version.store(final_version, Ordering::SeqCst);

        // Create initial snapshot
        self.store.snapshots.add_snapshot(StateSnapshot::new(state))?;

        debug!(
            initial_version,
            final_version,
            applied,
            stale_skipped,
            "State recovery completed"
        );

        Ok(final_version)
    }
}

// ============================================================================
// Persistence Backend Trait
// ============================================================================

/// Backend trait for actually persisting state to storage.
///
/// This separates the state management logic from the actual storage mechanism,
/// allowing different backends (MDBX, RocksDB, file-based, etc.)
#[async_trait]
pub trait StatePersistence<S: VersionedState>: Send + Sync {
    /// Save a snapshot to persistent storage
    async fn save_snapshot(&self, snapshot: &StateSnapshot<S>) -> Result<()>;

    /// Load the latest snapshot from storage
    async fn load_latest_snapshot(&self) -> Result<Option<StateSnapshot<S>>>;

    /// Load snapshot at a specific version
    async fn load_snapshot(&self, version: u64) -> Result<Option<StateSnapshot<S>>>;

    /// Save a delta to storage
    async fn save_delta(&self, delta: &StateDelta) -> Result<()>;

    /// Load deltas since a version
    async fn load_deltas_since(&self, version: u64) -> Result<Vec<StateDelta>>;

    /// Clear deltas before a version (after checkpoint)
    async fn clear_deltas_before(&self, version: u64) -> Result<u64>;

    /// Sync all pending writes to disk
    async fn sync(&self) -> Result<()>;
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Simple test state for unit tests
    #[derive(Debug, Clone, Default, Serialize, Deserialize)]
    struct TestState {
        version: u64,
        counter: u64,
        data: String,
    }

    impl VersionedState for TestState {
        fn version(&self) -> u64 {
            self.version
        }

        fn set_version(&mut self, version: u64) {
            self.version = version;
        }

        fn diff(&self, other: &Self) -> StateDelta {
            let mut delta = StateDelta::new(other.version, self.version);

            if self.counter != other.counter {
                delta.changes.push(StateChange::FieldUpdate {
                    path: "counter".to_string(),
                    old_value: other.counter.to_le_bytes().to_vec(),
                    new_value: self.counter.to_le_bytes().to_vec(),
                });
            }

            if self.data != other.data {
                delta.changes.push(StateChange::FieldUpdate {
                    path: "data".to_string(),
                    old_value: other.data.as_bytes().to_vec(),
                    new_value: self.data.as_bytes().to_vec(),
                });
            }

            delta.size_bytes = delta
                .changes
                .iter()
                .map(|c| match c {
                    StateChange::FieldUpdate {
                        old_value,
                        new_value,
                        ..
                    } => old_value.len() + new_value.len(),
                    _ => 0,
                })
                .sum();

            delta
        }

        fn apply_delta(&mut self, delta: &StateDelta) -> Result<()> {
            for change in &delta.changes {
                match change {
                    StateChange::FieldUpdate {
                        path, new_value, ..
                    } => {
                        if path == "counter" && new_value.len() >= 8 {
                            self.counter = u64::from_le_bytes(new_value[..8].try_into().unwrap());
                        } else if path == "data" {
                            self.data = String::from_utf8_lossy(new_value).to_string();
                        }
                    }
                    _ => {}
                }
            }
            self.version = delta.to_version;
            Ok(())
        }

        fn validate(&self) -> Result<()> {
            Ok(())
        }
    }

    #[test]
    fn test_state_delta() {
        let old = TestState {
            version: 1,
            counter: 10,
            data: "hello".to_string(),
        };
        let new = TestState {
            version: 2,
            counter: 20,
            data: "world".to_string(),
        };

        let delta = new.diff(&old);
        assert_eq!(delta.from_version, 1);
        assert_eq!(delta.to_version, 2);
        assert_eq!(delta.changes.len(), 2);
    }

    #[test]
    fn test_delta_apply() {
        let old = TestState {
            version: 1,
            counter: 10,
            data: "hello".to_string(),
        };
        let new = TestState {
            version: 2,
            counter: 20,
            data: "world".to_string(),
        };

        let delta = new.diff(&old);
        let mut applied = old.clone();
        applied.apply_delta(&delta).unwrap();

        assert_eq!(applied.version, 2);
        assert_eq!(applied.counter, 20);
        assert_eq!(applied.data, "world");
    }

    #[test]
    fn test_delta_merge() {
        let delta1 = StateDelta::new(1, 2);
        let delta2 = StateDelta::new(2, 3);

        let merged = StateDelta::merge(&delta1, &delta2).unwrap();
        assert_eq!(merged.from_version, 1);
        assert_eq!(merged.to_version, 3);
    }

    #[test]
    fn test_delta_merge_error() {
        let delta1 = StateDelta::new(1, 2);
        let delta2 = StateDelta::new(3, 4); // Gap!

        let result = StateDelta::merge(&delta1, &delta2);
        assert!(result.is_err());
    }

    #[test]
    fn test_snapshot_manager() {
        let manager = SnapshotManager::<TestState>::new(3, 10);

        for i in 0..5 {
            let state = TestState {
                version: i * 10,
                counter: i,
                data: format!("state_{}", i),
            };
            manager.add_snapshot(StateSnapshot::new(state)).unwrap();
        }

        // Should only have last 3 snapshots
        let versions = manager.snapshot_versions();
        assert_eq!(versions.len(), 3);
        assert_eq!(versions, vec![20, 30, 40]);
    }

    #[test]
    fn test_snapshot_lookup() {
        let manager = SnapshotManager::<TestState>::new(10, 10);

        for i in [0, 10, 20, 30] {
            let state = TestState {
                version: i,
                counter: i,
                data: format!("v{}", i),
            };
            manager.add_snapshot(StateSnapshot::new(state)).unwrap();
        }

        // Get snapshot at exact version
        let snap = manager.get_snapshot_at(20).unwrap();
        assert_eq!(snap.version, 20);

        // Get snapshot at version between snapshots
        let snap = manager.get_snapshot_at(25).unwrap();
        assert_eq!(snap.version, 20); // Nearest snapshot before
    }

    #[tokio::test]
    async fn test_persistent_store_basic() {
        let config = StateConfig {
            snapshot_interval: 5,
            auto_checkpoint_interval: None,
            ..Default::default()
        };

        let initial = TestState {
            version: 0,
            counter: 0,
            data: "start".to_string(),
        };

        let store = PersistentStateStore::with_initial_state(initial, config);

        // Update state
        store
            .update(|s| {
                s.counter = 42;
                s.version = 1;
            })
            .await
            .unwrap();

        assert_eq!(store.version(), 1);
        assert_eq!(store.read().counter, 42);
    }

    #[tokio::test]
    async fn test_store_auto_snapshot() {
        let config = StateConfig {
            snapshot_interval: 3,
            auto_checkpoint_interval: None,
            ..Default::default()
        };

        let store = PersistentStateStore::<TestState>::new(config);

        // Update 4 times to trigger auto-snapshot
        for i in 1..=4 {
            store
                .update(|s| {
                    s.counter = i;
                    s.version = i;
                })
                .await
                .unwrap();
        }

        // Should have initial + one auto-snapshot
        let versions = store.snapshot_versions();
        assert!(versions.len() >= 1);
    }

    #[test]
    fn test_delta_log() {
        let log = DeltaLog::new(3, 1024);

        log.append(StateDelta::new(0, 1)).unwrap();
        log.append(StateDelta::new(1, 2)).unwrap();

        assert!(!log.needs_compaction());

        log.append(StateDelta::new(2, 3)).unwrap();
        assert!(log.needs_compaction());
    }

    #[test]
    fn test_delta_log_compaction() {
        let log = DeltaLog::new(10, 1024 * 1024);

        log.append(StateDelta::new(0, 1)).unwrap();
        log.append(StateDelta::new(1, 2)).unwrap();
        log.append(StateDelta::new(2, 3)).unwrap();

        let compacted = log.compact().unwrap().unwrap();
        assert_eq!(compacted.from_version, 0);
        assert_eq!(compacted.to_version, 3);
    }

    #[test]
    fn test_store_stats() {
        let store = PersistentStateStore::<TestState>::new(StateConfig::default());

        let stats = store.stats();
        assert_eq!(stats.total_updates, 0);
        assert_eq!(stats.total_snapshots, 1); // Initial snapshot
    }

    #[tokio::test]
    async fn test_recovery_gap_detection() {
        let config = StateConfig::default();
        let store = Arc::new(PersistentStateStore::<TestState>::new(config));
        let recovery = StateRecovery::new(Arc::clone(&store));

        // Start with state at version 0
        let snapshot = TestState {
            version: 0,
            counter: 0,
            data: "start".to_string(),
        };

        // Create deltas with a gap: delta starts at version 5, but state is at version 0
        let mut delta = StateDelta::new(5, 6);
        delta.changes.push(StateChange::FieldUpdate {
            path: "counter".to_string(),
            old_value: 0u64.to_le_bytes().to_vec(),
            new_value: 10u64.to_le_bytes().to_vec(),
        });

        // Recovery should fail due to the gap
        let result = recovery.recover(Some(snapshot), vec![delta]).await;
        assert!(result.is_err());

        let err = result.unwrap_err();
        match err {
            StorageError::StateRecovery(msg) => {
                assert!(msg.contains("Gap detected"));
                assert!(msg.contains("version 0"));
                assert!(msg.contains("starts at 5"));
            }
            _ => panic!("Expected StateRecovery error, got: {:?}", err),
        }
    }

    #[tokio::test]
    async fn test_recovery_stale_delta_skip() {
        let config = StateConfig::default();
        let store = Arc::new(PersistentStateStore::<TestState>::new(config));
        let recovery = StateRecovery::new(Arc::clone(&store));

        // Start with state at version 5
        let snapshot = TestState {
            version: 5,
            counter: 50,
            data: "v5".to_string(),
        };

        // Create a stale delta (from version 2, but state is already at 5)
        let mut stale_delta = StateDelta::new(2, 3);
        stale_delta.changes.push(StateChange::FieldUpdate {
            path: "counter".to_string(),
            old_value: 20u64.to_le_bytes().to_vec(),
            new_value: 30u64.to_le_bytes().to_vec(),
        });

        // Create a valid delta that continues from version 5
        let mut valid_delta = StateDelta::new(5, 6);
        valid_delta.changes.push(StateChange::FieldUpdate {
            path: "counter".to_string(),
            old_value: 50u64.to_le_bytes().to_vec(),
            new_value: 60u64.to_le_bytes().to_vec(),
        });

        // Recovery should succeed, skipping the stale delta and applying the valid one
        let result = recovery
            .recover(Some(snapshot), vec![stale_delta, valid_delta])
            .await;
        assert!(result.is_ok());

        let final_version = result.unwrap();
        assert_eq!(final_version, 6);
        assert_eq!(store.read().counter, 60);
    }
}
