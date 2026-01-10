//! WAL (Write-Ahead Log) Actor for Malachite consensus messages.
//!
//! This module implements the WAL actor that persists consensus messages
//! to disk for crash recovery and state sync.

use crate::codec::ConsensusCodec;
use crate::context::CipherBftContext;
use anyhow::Result;
use informalsystems_malachitebft_engine::wal::{Wal, WalRef};
use std::path::PathBuf;
use tracing::info;

/// Spawn a Malachite WAL actor for consensus message persistence.
///
/// # Arguments
/// * `wal_path` - Path to the WAL directory where messages will be stored
///
/// # Returns
/// * `WalRef<CipherBftContext>` - Reference to the spawned WAL actor
pub async fn spawn_wal(wal_path: PathBuf) -> Result<WalRef<CipherBftContext>> {
    info!("Spawning consensus WAL actor at {}", wal_path.display());

    // Create WAL directory if it doesn't exist
    std::fs::create_dir_all(&wal_path)?;

    // Create codec (same as network codec for consistency)
    let codec = ConsensusCodec::default();

    // Spawn WAL actor using Malachite's Wal::spawn
    // WAL will persist messages to disk for recovery
    let wal_ref = Wal::<CipherBftContext>::spawn(wal_path, codec).await?;

    info!("Consensus WAL actor spawned successfully");
    Ok(wal_ref)
}
