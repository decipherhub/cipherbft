//! WAL (Write-Ahead Log) Actor for Malachite consensus messages.
//!
//! This module implements the WAL actor that persists consensus messages
//! to disk for crash recovery and state sync.

use crate::codec::CipherBftCodec;
use crate::context::CipherBftContext;
use anyhow::Result;
use informalsystems_malachitebft_engine::wal::{Wal, WalRef};
use informalsystems_malachitebft_metrics::SharedRegistry;
use std::path::PathBuf;
use tracing::{info, info_span};

/// Spawn a Malachite WAL actor for consensus message persistence.
///
/// # Arguments
/// * `ctx` - The CipherBFT context (used for type parameter inference)
/// * `wal_path` - Path to the WAL directory where messages will be stored
/// * `metrics` - Shared metrics registry
///
/// # Returns
/// * `WalRef<CipherBftContext>` - Reference to the spawned WAL actor
pub async fn spawn_wal(
    ctx: &CipherBftContext,
    wal_path: PathBuf,
    metrics: SharedRegistry,
) -> Result<WalRef<CipherBftContext>> {
    info!("Spawning consensus WAL actor at {}", wal_path.display());

    // Create WAL directory if it doesn't exist
    std::fs::create_dir_all(&wal_path)?;

    // Create codec for message serialization (unit struct, no Default needed)
    let codec = CipherBftCodec;

    // Create tracing span for this WAL actor
    let span = info_span!("consensus-wal");

    // Spawn WAL actor using Malachite's Wal::spawn
    let wal_ref =
        Wal::<CipherBftContext, CipherBftCodec>::spawn(ctx, codec, wal_path, metrics, span).await?;

    info!("Consensus WAL actor spawned successfully");
    Ok(wal_ref)
}
