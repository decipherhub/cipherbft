//! Sync Actor for Malachite state synchronization.
//!
//! This module provides the spawn_sync function to create a Malachite Sync actor
//! that handles state synchronization between consensus peers.

use std::time::Duration;

use crate::context::CipherBftContext;
use anyhow::Result;
use informalsystems_malachitebft_engine::host::HostRef;
use informalsystems_malachitebft_engine::network::NetworkRef;
use informalsystems_malachitebft_engine::sync::{Params as SyncParams, Sync, SyncRef};
use informalsystems_malachitebft_sync::{Config as SyncConfig, Metrics as SyncMetrics};
use tracing::{info, info_span};

/// Spawn a Malachite Sync actor for state synchronization.
///
/// The sync actor handles:
/// - Broadcasting local status (tip height) to peers
/// - Requesting missing blocks from peers that are ahead
/// - Processing sync requests from peers that are behind
///
/// # Arguments
/// * `ctx` - CipherBFT consensus context
/// * `network` - Reference to the network actor for message transmission
/// * `host` - Reference to the host actor for block retrieval/storage
/// * `sync_config` - Sync configuration (request timeouts, parallelism, etc.)
///
/// # Returns
/// * `SyncRef<CipherBftContext>` - Reference to the spawned sync actor
pub async fn spawn_sync(
    ctx: CipherBftContext,
    network: NetworkRef<CipherBftContext>,
    host: HostRef<CipherBftContext>,
    sync_config: SyncConfig,
) -> Result<SyncRef<CipherBftContext>> {
    info!("Spawning sync actor for state synchronization");

    // Configure sync params for fast block production (~60ms/block)
    // - status_update_interval: Check peer status frequently to detect sync needs early
    // - request_timeout: Allow time for sync responses under load
    let params = SyncParams {
        status_update_interval: Duration::from_millis(500), // Check every 500ms instead of 5s
        request_timeout: Duration::from_secs(30),
    };

    // Create metrics for sync operations
    let metrics = SyncMetrics::default();

    // Create tracing span for this sync actor
    let span = info_span!("consensus-sync");

    // Spawn sync actor
    let sync_ref = Sync::spawn(ctx, network, host, params, sync_config, metrics, span).await?;

    info!("Sync actor spawned successfully");
    Ok(sync_ref)
}
