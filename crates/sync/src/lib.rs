//! State Synchronization for CipherBFT
//!
//! Provides snap sync-based state synchronization for nodes joining the network
//! or recovering from being behind.

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod error;
pub mod execution;
pub mod metrics;
pub mod network;
pub mod progress;
pub mod protocol;
pub mod snapshot;

pub mod blocks;
mod manager;
pub mod peers;
pub mod snap;

pub use error::{Result, SyncError};
pub use execution::{MockSyncExecutor, SyncBlock, SyncExecutionResult, SyncExecutor};
pub use manager::{StateSyncManager, SyncConfig};
pub use network::{
    IncomingSnapMessage, OutgoingSnapMessage, SyncNetworkAdapter, SyncNetworkSender,
    SNAP_CHANNEL_CAPACITY,
};
pub use progress::{
    AccountProgress, BlockProgress, ProgressTracker, SnapSubPhase, StorageProgress, SyncPhase,
    SyncProgressState,
};
pub use protocol::{SnapSyncMessage, SnapshotInfo};
pub use snapshot::{SnapshotAgreement, StateSnapshot, SNAPSHOT_INTERVAL};
