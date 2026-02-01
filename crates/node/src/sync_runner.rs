//! Snap sync runner for node startup
//!
//! This module provides the entry point for running snap sync during node
//! initialization. It coordinates the sync process and integrates with the
//! node's lifecycle.
//!
//! # Sync Decision Logic
//!
//! The node decides whether to run snap sync based on:
//! 1. Is snap sync enabled in config?
//! 2. How far behind is the node compared to the network tip?
//! 3. Is the gap larger than the configured threshold?
//!
//! If snap sync is needed, the node will:
//! 1. Discover peers and find a common snapshot
//! 2. Download account state from the snapshot
//! 3. Download contract storage
//! 4. Verify the state root
//! 5. Sync remaining blocks to reach the tip

use crate::config::SyncConfig as NodeSyncConfig;
use crate::sync_network::SyncNetworkAdapter;
use cipherbft_sync::protocol::{
    AccountRangeResponse, BlockRangeRequest, BlockRangeResponse, SnapSyncMessage,
    StorageRangeResponse,
};
use cipherbft_sync::snap::accounts::PendingRange;
use cipherbft_sync::snap::storage::PendingStorageRange;
use cipherbft_sync::{
    SyncBlock, SyncConfig as ManagerSyncConfig, SyncError, SyncExecutor, StateSyncManager,
};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, error, info, warn};

/// Maximum time to wait for discovery phase
const DISCOVERY_TIMEOUT: Duration = Duration::from_secs(30);

/// Interval between discovery polls
const DISCOVERY_POLL_INTERVAL: Duration = Duration::from_millis(500);

/// Maximum time to wait for a single sync request (used for reference)
#[allow(dead_code)]
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Maximum concurrent account range requests
const MAX_CONCURRENT_ACCOUNT_REQUESTS: usize = 8;

/// Maximum concurrent storage range requests
const MAX_CONCURRENT_STORAGE_REQUESTS: usize = 4;

/// Maximum concurrent block range requests
const MAX_CONCURRENT_BLOCK_REQUESTS: usize = 4;

/// Result of snap sync attempt
#[derive(Debug, Clone, PartialEq)]
pub enum SyncResult {
    /// Sync completed successfully
    Completed {
        /// Height reached after sync
        final_height: u64,
        /// Duration of sync process
        duration: Duration,
    },
    /// Node was already synced, no action needed
    AlreadySynced {
        /// Current local height
        local_tip: u64,
    },
    /// Sync was skipped (disabled or below threshold)
    Skipped {
        /// Reason for skipping
        reason: String,
    },
    /// Sync failed
    Failed {
        /// Error description
        error: String,
    },
}

/// Tracks in-flight requests for timeout handling
#[derive(Debug)]
struct InFlightRequest<T> {
    /// The range/request data
    data: T,
    /// Peer handling this request
    peer_id: String,
    /// When the request was sent
    sent_at: Instant,
}

impl<T> InFlightRequest<T> {
    fn new(data: T, peer_id: String) -> Self {
        Self {
            data,
            peer_id,
            sent_at: Instant::now(),
        }
    }

    fn is_timed_out(&self, timeout: Duration) -> bool {
        self.sent_at.elapsed() > timeout
    }
}

/// Run snap sync to completion
///
/// This function orchestrates the snap sync process, returning when sync
/// is complete or when an error occurs.
///
/// # Arguments
///
/// * `manager` - The state sync manager
/// * `network` - Network adapter for peer communication
/// * `local_tip` - Current local blockchain height
/// * `network_tip` - Network's reported tip height
/// * `config` - Sync configuration from node config
///
/// # Returns
///
/// Returns `SyncResult` indicating the outcome of the sync attempt.
///
/// # Example
///
/// ```ignore
/// let result = run_snap_sync(
///     &mut manager,
///     &mut network,
///     local_tip,
///     network_tip,
///     &config,
/// ).await;
///
/// match result {
///     SyncResult::Completed { final_height, duration } => {
///         info!("Sync completed at height {} in {:?}", final_height, duration);
///     }
///     SyncResult::AlreadySynced { local_tip } => {
///         info!("Already synced at height {}", local_tip);
///     }
///     SyncResult::Skipped { reason } => {
///         info!("Sync skipped: {}", reason);
///     }
///     SyncResult::Failed { error } => {
///         error!("Sync failed: {}", error);
///     }
/// }
/// ```
pub async fn run_snap_sync(
    manager: &mut StateSyncManager,
    network: &mut SyncNetworkAdapter,
    local_tip: u64,
    network_tip: u64,
    config: &NodeSyncConfig,
) -> SyncResult {
    // Check if snap sync is enabled
    if !config.snap_sync_enabled {
        return SyncResult::Skipped {
            reason: "snap sync is disabled in configuration".to_string(),
        };
    }

    // Check if snap sync is needed based on block gap
    let gap = network_tip.saturating_sub(local_tip);
    if gap < config.snap_sync_threshold {
        info!(
            local_tip,
            network_tip,
            gap,
            threshold = config.snap_sync_threshold,
            "Node is close to tip, skipping snap sync"
        );
        return SyncResult::Skipped {
            reason: format!(
                "block gap ({}) is below threshold ({})",
                gap, config.snap_sync_threshold
            ),
        };
    }

    info!(
        local_tip,
        network_tip,
        gap,
        threshold = config.snap_sync_threshold,
        "Starting snap sync - node is significantly behind"
    );

    let start_time = Instant::now();

    // Start discovery phase
    if let Err(e) = manager.start_discovery() {
        return SyncResult::Failed {
            error: format!("failed to start discovery: {}", e),
        };
    }

    // Phase 1: Discovery - find peers and select snapshot
    let snapshot = match run_discovery_phase(manager, network, config).await {
        Ok(snapshot) => snapshot,
        Err(e) => {
            return SyncResult::Failed {
                error: format!("discovery failed: {}", e),
            };
        }
    };

    info!(
        height = snapshot.block_number,
        state_root = %snapshot.state_root,
        "Selected snapshot for sync"
    );

    // Start snap sync with the selected snapshot
    if let Err(e) = manager.start_snap_sync(snapshot.clone()) {
        return SyncResult::Failed {
            error: format!("failed to start snap sync: {}", e),
        };
    }

    // Phase 2: Account sync
    if let Err(e) = run_account_sync_phase(manager, network, config).await {
        return SyncResult::Failed {
            error: format!("account sync failed: {}", e),
        };
    }

    // Transition to storage sync
    if let Err(e) = manager.start_storage_sync() {
        return SyncResult::Failed {
            error: format!("failed to start storage sync: {}", e),
        };
    }

    // Phase 3: Storage sync
    if let Err(e) = run_storage_sync_phase(manager, network, config).await {
        return SyncResult::Failed {
            error: format!("storage sync failed: {}", e),
        };
    }

    // Verify state root
    if let Err(e) = manager.verify_state_root() {
        return SyncResult::Failed {
            error: format!("state root verification failed: {}", e),
        };
    }

    // Start block sync
    if let Err(e) = manager.start_block_sync() {
        return SyncResult::Failed {
            error: format!("failed to start block sync: {}", e),
        };
    }

    // Check if we're already at tip (no blocks to sync)
    if manager.is_complete() {
        let duration = start_time.elapsed();
        info!(
            final_height = snapshot.block_number,
            duration_secs = duration.as_secs(),
            "Snap sync completed (no blocks to sync)"
        );
        return SyncResult::Completed {
            final_height: snapshot.block_number,
            duration,
        };
    }

    // Phase 4: Block sync - download and execute remaining blocks
    // Note: This phase requires a SyncExecutor which should be passed in
    // For now, we just download the blocks; execution is handled separately
    if let Err(e) = run_block_download_phase(manager, network, config).await {
        return SyncResult::Failed {
            error: format!("block sync failed: {}", e),
        };
    }

    // Mark sync as complete
    if let Err(e) = manager.complete_sync() {
        return SyncResult::Failed {
            error: format!("failed to complete sync: {}", e),
        };
    }

    let duration = start_time.elapsed();
    let final_height = manager
        .block_syncer_mut()
        .map(|s| s.stats().executed_up_to)
        .unwrap_or(snapshot.block_number);

    info!(
        final_height,
        duration_secs = duration.as_secs(),
        "Snap sync completed successfully"
    );

    SyncResult::Completed {
        final_height,
        duration,
    }
}

/// Run snap sync with a provided executor for block execution
///
/// This is the full-featured version that includes block execution.
pub async fn run_snap_sync_with_executor<E: SyncExecutor>(
    manager: &mut StateSyncManager,
    network: &mut SyncNetworkAdapter,
    executor: Arc<E>,
    local_tip: u64,
    network_tip: u64,
    config: &NodeSyncConfig,
) -> SyncResult {
    // Run the main sync phases (discovery, accounts, storage)
    let result = run_snap_sync(manager, network, local_tip, network_tip, config).await;

    // If we completed with blocks to execute, run the execution phase
    if let SyncResult::Completed { final_height, duration } = &result {
        // Check if block syncer exists and has blocks
        let needs_execution = manager
            .block_syncer_mut()
            .is_some_and(|s| !s.is_complete());

        if needs_execution {
            if let Err(e) = run_block_execution_phase(manager, executor).await {
                return SyncResult::Failed {
                    error: format!("block execution failed: {}", e),
                };
            }

            // Update final height after execution
            let executed_height = manager
                .block_syncer_mut()
                .map(|s| s.stats().executed_up_to)
                .unwrap_or(*final_height);

            return SyncResult::Completed {
                final_height: executed_height,
                duration: *duration,
            };
        }

        return SyncResult::Completed {
            final_height: *final_height,
            duration: *duration,
        };
    }

    result
}

/// Check if snap sync is needed for the current node state
///
/// This is a quick check that can be used before initializing the full
/// sync machinery.
///
/// # Arguments
///
/// * `local_tip` - Current local blockchain height
/// * `network_tip` - Network's reported tip height
/// * `config` - Sync configuration from node config
///
/// # Returns
///
/// `true` if snap sync should be initiated, `false` otherwise
pub fn should_snap_sync(local_tip: u64, network_tip: u64, config: &NodeSyncConfig) -> bool {
    if !config.snap_sync_enabled {
        debug!("Snap sync disabled in configuration");
        return false;
    }

    let gap = network_tip.saturating_sub(local_tip);
    let needs_sync = gap >= config.snap_sync_threshold;

    if needs_sync {
        info!(
            local_tip,
            network_tip,
            gap,
            threshold = config.snap_sync_threshold,
            "Snap sync recommended"
        );
    } else {
        debug!(
            local_tip,
            network_tip,
            gap,
            threshold = config.snap_sync_threshold,
            "Block-by-block sync sufficient"
        );
    }

    needs_sync
}

/// Create a StateSyncManager with configuration derived from NodeSyncConfig
///
/// # Arguments
///
/// * `config` - Node sync configuration
///
/// # Returns
///
/// A configured `StateSyncManager` ready for sync operations
pub fn create_sync_manager(config: &NodeSyncConfig) -> StateSyncManager {
    let manager_config = ManagerSyncConfig {
        min_peers: config.min_sync_peers,
        max_retries: 3,
        request_timeout: Duration::from_secs(config.sync_timeout_secs),
        discovery_timeout: Duration::from_secs(30),
    };

    StateSyncManager::new(manager_config)
}

// =============================================================================
// Phase Implementations
// =============================================================================

use cipherbft_sync::snapshot::StateSnapshot;

/// Run the discovery phase to find peers and select a snapshot
async fn run_discovery_phase(
    manager: &mut StateSyncManager,
    network: &mut SyncNetworkAdapter,
    config: &NodeSyncConfig,
) -> Result<StateSnapshot, SyncError> {
    info!("Starting discovery phase");

    let discovery_start = Instant::now();

    // Broadcast GetStatus to all peers
    // Using "*" as peer_id triggers broadcast in the network adapter
    if let Err(e) = network.send("*", SnapSyncMessage::GetStatus).await {
        warn!("Failed to broadcast GetStatus: {}", e);
    }

    // Poll for responses and check for snapshot agreement
    loop {
        // Check for timeout
        if discovery_start.elapsed() > DISCOVERY_TIMEOUT {
            return Err(SyncError::InsufficientPeers {
                needed: config.min_sync_peers as u32,
                available: manager.peers().peer_count() as u32,
            });
        }

        // Process incoming messages
        while let Some((peer_id, message)) = network.try_recv() {
            match message {
                SnapSyncMessage::Status(status) => {
                    debug!(
                        peer = %peer_id,
                        tip_height = status.tip_height,
                        snapshots = ?status.snapshots,
                        "Received status from peer"
                    );

                    // Add peer if not already known
                    manager.add_peer(peer_id.clone());
                    manager.handle_status(&peer_id, status);
                }
                other => {
                    debug!(
                        peer = %peer_id,
                        msg_type = other.message_type(),
                        "Ignoring non-status message during discovery"
                    );
                }
            }
        }

        // Check if we have enough peers and snapshot agreement
        match manager.try_complete_discovery()? {
            Some(snapshot) => {
                info!(
                    height = snapshot.block_number,
                    peers = manager.peers().peer_count(),
                    "Discovery complete, snapshot selected"
                );
                return Ok(snapshot);
            }
            None => {
                // Not enough peers or agreement yet, wait and retry
                tokio::time::sleep(DISCOVERY_POLL_INTERVAL).await;
            }
        }
    }
}

/// Run the account sync phase
async fn run_account_sync_phase(
    manager: &mut StateSyncManager,
    network: &mut SyncNetworkAdapter,
    config: &NodeSyncConfig,
) -> Result<(), SyncError> {
    info!("Starting account sync phase");

    let max_retries = 3u32;
    let timeout = Duration::from_secs(config.sync_timeout_secs);

    // Track in-flight requests: request_id -> (range, peer_id, sent_time)
    let mut in_flight: HashMap<u64, InFlightRequest<PendingRange>> = HashMap::new();
    let mut next_request_id: u64 = 0;

    loop {
        // Check if account sync is complete
        if manager.is_account_sync_complete() && in_flight.is_empty() {
            info!("Account sync phase complete");
            return Ok(());
        }

        // Check for timed out requests
        let timed_out: Vec<u64> = in_flight
            .iter()
            .filter(|(_, req)| req.is_timed_out(timeout))
            .map(|(id, _)| *id)
            .collect();

        for request_id in timed_out {
            if let Some(req) = in_flight.remove(&request_id) {
                warn!(
                    request_id,
                    peer = %req.peer_id,
                    "Account range request timed out"
                );
                manager.peers_mut().request_failed(&req.peer_id);

                // Re-queue the range for retry
                if let Some(account_syncer) = manager.account_syncer_mut() {
                    account_syncer.handle_failure(req.data, max_retries);
                }
            }
        }

        // Send new requests if we have capacity
        while in_flight.len() < MAX_CONCURRENT_ACCOUNT_REQUESTS {
            // Get next range to request
            let range = match manager.account_syncer_mut().and_then(|s| s.next_range()) {
                Some(r) => r,
                None => break, // No more ranges to request
            };

            // Select best peer for this request
            let peer = match manager.peers().select_peer(None) {
                Some(p) => p.peer_id.clone(),
                None => {
                    // No peers available, re-queue the range
                    if let Some(account_syncer) = manager.account_syncer_mut() {
                        account_syncer.handle_failure(range, max_retries);
                    }
                    break;
                }
            };

            // Create and send the request
            let request = manager
                .account_syncer_mut()
                .map(|s| s.create_request(&range))
                .ok_or_else(|| SyncError::InvalidState("no account syncer".into()))?;

            let msg = SnapSyncMessage::GetAccountRange(request);

            if let Err(e) = network.send(&peer, msg).await {
                warn!(peer = %peer, error = %e, "Failed to send account range request");
                manager.peers_mut().request_failed(&peer);
                if let Some(account_syncer) = manager.account_syncer_mut() {
                    account_syncer.handle_failure(range, max_retries);
                }
                continue;
            }

            // Track the in-flight request
            manager.peers_mut().request_started(&peer);
            in_flight.insert(next_request_id, InFlightRequest::new(range, peer));
            next_request_id += 1;

            debug!(request_id = next_request_id - 1, "Sent account range request");
        }

        // Process incoming responses
        while let Some((peer_id, message)) = network.try_recv() {
            match message {
                SnapSyncMessage::AccountRange(response) => {
                    // Use the echoed request_id for direct lookup
                    let request_id = response.request_id;

                    if let Some(req) = in_flight.remove(&request_id) {
                        // Verify response came from expected peer
                        if req.peer_id != peer_id {
                            warn!(
                                request_id,
                                expected = %req.peer_id,
                                actual = %peer_id,
                                "Account response from unexpected peer, ignoring"
                            );
                            // Re-insert - might still come from correct peer
                            in_flight.insert(request_id, req);
                            continue;
                        }

                        let latency = req.sent_at.elapsed();
                            let bytes = estimate_account_response_size(&response);

                            // Process the response
                            let process_result = manager
                                .account_syncer_mut()
                                .map(|s| s.process_response(req.data.clone(), response));

                            match process_result {
                                Some(Ok(())) => {
                                    manager
                                        .peers_mut()
                                        .request_completed(&peer_id, latency, bytes);
                                    debug!(
                                        peer = %peer_id,
                                        latency_ms = latency.as_millis(),
                                        "Account range response processed"
                                    );
                                }
                                Some(Err(e)) => {
                                    warn!(
                                        peer = %peer_id,
                                        error = %e,
                                        "Failed to process account range response"
                                    );
                                    manager.handle_peer_error(&peer_id, &e);
                                    if let Some(account_syncer) = manager.account_syncer_mut() {
                                        account_syncer.handle_failure(req.data, max_retries);
                                    }
                                }
                                None => {
                                    warn!("No account syncer available");
                                }
                            }
                        }
                    }
                SnapSyncMessage::Status(status) => {
                    // Update peer status even during account sync
                    manager.handle_status(&peer_id, status);
                }
                _ => {
                    debug!(
                        peer = %peer_id,
                        msg_type = message.message_type(),
                        "Ignoring unexpected message during account sync"
                    );
                }
            }
        }

        // Small delay to prevent busy-spinning
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// Run the storage sync phase
async fn run_storage_sync_phase(
    manager: &mut StateSyncManager,
    network: &mut SyncNetworkAdapter,
    config: &NodeSyncConfig,
) -> Result<(), SyncError> {
    info!("Starting storage sync phase");

    let max_retries = 3u32;
    let timeout = Duration::from_secs(config.sync_timeout_secs);

    // Track in-flight requests
    let mut in_flight: HashMap<u64, InFlightRequest<PendingStorageRange>> = HashMap::new();
    let mut next_request_id: u64 = 0;

    loop {
        // Check if storage sync is complete
        if manager.is_storage_sync_complete() && in_flight.is_empty() {
            info!("Storage sync phase complete");
            return Ok(());
        }

        // Check for timed out requests
        let timed_out: Vec<u64> = in_flight
            .iter()
            .filter(|(_, req)| req.is_timed_out(timeout))
            .map(|(id, _)| *id)
            .collect();

        for request_id in timed_out {
            if let Some(req) = in_flight.remove(&request_id) {
                warn!(
                    request_id,
                    peer = %req.peer_id,
                    account = %req.data.account,
                    "Storage range request timed out"
                );
                manager.peers_mut().request_failed(&req.peer_id);

                if let Some(storage_syncer) = manager.storage_syncer_mut() {
                    storage_syncer.handle_failure(req.data, max_retries);
                }
            }
        }

        // Send new requests if we have capacity
        while in_flight.len() < MAX_CONCURRENT_STORAGE_REQUESTS {
            let range = match manager.storage_syncer_mut().and_then(|s| s.next_range()) {
                Some(r) => r,
                None => break,
            };

            let peer = match manager.peers().select_peer(None) {
                Some(p) => p.peer_id.clone(),
                None => {
                    if let Some(storage_syncer) = manager.storage_syncer_mut() {
                        storage_syncer.handle_failure(range, max_retries);
                    }
                    break;
                }
            };

            let request = manager
                .storage_syncer_mut()
                .map(|s| s.create_request(&range))
                .ok_or_else(|| SyncError::InvalidState("no storage syncer".into()))?;

            let msg = SnapSyncMessage::GetStorageRange(request);

            if let Err(e) = network.send(&peer, msg).await {
                warn!(peer = %peer, error = %e, "Failed to send storage range request");
                manager.peers_mut().request_failed(&peer);
                if let Some(storage_syncer) = manager.storage_syncer_mut() {
                    storage_syncer.handle_failure(range, max_retries);
                }
                continue;
            }

            manager.peers_mut().request_started(&peer);
            in_flight.insert(next_request_id, InFlightRequest::new(range, peer));
            next_request_id += 1;

            debug!(request_id = next_request_id - 1, "Sent storage range request");
        }

        // Process incoming responses
        while let Some((peer_id, message)) = network.try_recv() {
            match message {
                SnapSyncMessage::StorageRange(response) => {
                    // Use the echoed request_id for direct lookup
                    let request_id = response.request_id;

                    if let Some(req) = in_flight.remove(&request_id) {
                        // Verify response came from expected peer
                        if req.peer_id != peer_id {
                            warn!(
                                request_id,
                                expected = %req.peer_id,
                                actual = %peer_id,
                                "Storage response from unexpected peer, ignoring"
                            );
                            // Re-insert - might still come from correct peer
                            in_flight.insert(request_id, req);
                            continue;
                        }

                        let latency = req.sent_at.elapsed();
                        let bytes = estimate_storage_response_size(&response);

                        let process_result = manager
                            .storage_syncer_mut()
                            .map(|s| s.process_response(req.data.clone(), response));

                        match process_result {
                            Some(Ok(())) => {
                                manager
                                    .peers_mut()
                                    .request_completed(&peer_id, latency, bytes);
                                debug!(
                                    peer = %peer_id,
                                    latency_ms = latency.as_millis(),
                                    "Storage range response processed"
                                );
                            }
                            Some(Err(e)) => {
                                warn!(
                                    peer = %peer_id,
                                    error = %e,
                                    "Failed to process storage range response"
                                );
                                manager.handle_peer_error(&peer_id, &e);
                                if let Some(storage_syncer) = manager.storage_syncer_mut() {
                                    storage_syncer.handle_failure(req.data, max_retries);
                                }
                            }
                            None => {
                                warn!("No storage syncer available");
                            }
                        }
                    }
                }
                SnapSyncMessage::Status(status) => {
                    manager.handle_status(&peer_id, status);
                }
                _ => {
                    debug!(
                        peer = %peer_id,
                        msg_type = message.message_type(),
                        "Ignoring unexpected message during storage sync"
                    );
                }
            }
        }

        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// Pending block range for tracking in-flight block requests
#[derive(Clone, Debug)]
struct PendingBlockRange {
    start: u64,
    count: u32,
    retries: u32,
}

/// Run the block download phase
async fn run_block_download_phase(
    manager: &mut StateSyncManager,
    network: &mut SyncNetworkAdapter,
    config: &NodeSyncConfig,
) -> Result<(), SyncError> {
    info!("Starting block download phase");

    let max_retries = 3u32;
    let timeout = Duration::from_secs(config.sync_timeout_secs);

    // Track in-flight block requests
    let mut in_flight: HashMap<u64, InFlightRequest<PendingBlockRange>> = HashMap::new();
    let mut next_request_id: u64 = 0;

    loop {
        // Check if block download is complete
        let block_syncer = manager
            .block_syncer_mut()
            .ok_or_else(|| SyncError::InvalidState("no block syncer".into()))?;

        // Check if we have all blocks downloaded (pending_ranges empty and no in-flight)
        let stats = block_syncer.stats();
        if stats.pending_ranges == 0 && in_flight.is_empty() {
            info!(
                downloaded = stats.total_downloaded,
                "Block download phase complete"
            );
            return Ok(());
        }

        // Check for timed out requests
        let timed_out: Vec<u64> = in_flight
            .iter()
            .filter(|(_, req)| req.is_timed_out(timeout))
            .map(|(id, _)| *id)
            .collect();

        for request_id in timed_out {
            if let Some(req) = in_flight.remove(&request_id) {
                warn!(
                    request_id,
                    peer = %req.peer_id,
                    start = req.data.start,
                    "Block range request timed out"
                );
                manager.peers_mut().request_failed(&req.peer_id);

                // Re-queue the block range
                let block_syncer = manager
                    .block_syncer_mut()
                    .ok_or_else(|| SyncError::InvalidState("no block syncer".into()))?;

                let pending = cipherbft_sync::blocks::PendingBlockRange {
                    start: req.data.start,
                    count: req.data.count,
                    retries: req.data.retries,
                };
                block_syncer.handle_download_failure(pending, max_retries);
            }
        }

        // Send new requests if we have capacity
        while in_flight.len() < MAX_CONCURRENT_BLOCK_REQUESTS {
            let block_syncer = manager
                .block_syncer_mut()
                .ok_or_else(|| SyncError::InvalidState("no block syncer".into()))?;

            let range = match block_syncer.next_range() {
                Some(r) => r,
                None => break,
            };

            let peer = match manager.peers().select_peer(None) {
                Some(p) => p.peer_id.clone(),
                None => {
                    // Re-queue the range
                    let block_syncer = manager
                        .block_syncer_mut()
                        .ok_or_else(|| SyncError::InvalidState("no block syncer".into()))?;
                    block_syncer.handle_download_failure(range, max_retries);
                    break;
                }
            };

            let request_id = next_request_id;
            next_request_id += 1;

            let request = BlockRangeRequest {
                request_id,
                start_height: range.start,
                count: range.count,
            };

            let msg = SnapSyncMessage::GetBlocks(request);

            if let Err(e) = network.send(&peer, msg).await {
                warn!(peer = %peer, error = %e, "Failed to send block range request");
                manager.peers_mut().request_failed(&peer);
                let block_syncer = manager
                    .block_syncer_mut()
                    .ok_or_else(|| SyncError::InvalidState("no block syncer".into()))?;
                block_syncer.handle_download_failure(range, max_retries);
                continue;
            }

            manager.peers_mut().request_started(&peer);

            let pending = PendingBlockRange {
                start: range.start,
                count: range.count,
                retries: range.retries,
            };
            in_flight.insert(request_id, InFlightRequest::new(pending, peer));

            debug!(
                request_id = next_request_id - 1,
                start = range.start,
                count = range.count,
                "Sent block range request"
            );
        }

        // Process incoming responses
        while let Some((peer_id, message)) = network.try_recv() {
            match message {
                SnapSyncMessage::Blocks(response) => {
                    // Use the echoed request_id for direct lookup
                    let request_id = response.request_id;

                    if let Some(req) = in_flight.remove(&request_id) {
                        // Verify response came from expected peer
                        if req.peer_id != peer_id {
                            warn!(
                                request_id,
                                expected = %req.peer_id,
                                actual = %peer_id,
                                "Response from unexpected peer, ignoring"
                            );
                            // Re-insert the request - it may still come from the right peer
                            in_flight.insert(request_id, req);
                            continue;
                        }

                        let latency = req.sent_at.elapsed();
                        let bytes = estimate_block_response_size(&response);

                        let pending = cipherbft_sync::blocks::PendingBlockRange {
                            start: req.data.start,
                            count: req.data.count,
                            retries: req.data.retries,
                        };

                        let process_result = manager
                            .block_syncer_mut()
                            .ok_or_else(|| SyncError::InvalidState("no block syncer".into()))?
                            .process_response(pending, response);

                        match process_result {
                            Ok(()) => {
                                manager
                                    .peers_mut()
                                    .request_completed(&peer_id, latency, bytes);
                                debug!(
                                    peer = %peer_id,
                                    latency_ms = latency.as_millis(),
                                    "Block range response processed"
                                );
                            }
                            Err(e) => {
                                warn!(
                                    peer = %peer_id,
                                    error = %e,
                                    "Failed to process block range response"
                                );
                                manager.handle_peer_error(&peer_id, &e);
                                let pending = cipherbft_sync::blocks::PendingBlockRange {
                                    start: req.data.start,
                                    count: req.data.count,
                                    retries: req.data.retries,
                                };
                                if let Some(block_syncer) = manager.block_syncer_mut() {
                                    block_syncer.handle_download_failure(pending, max_retries);
                                }
                            }
                        }
                    }
                }
                SnapSyncMessage::Status(status) => {
                    manager.handle_status(&peer_id, status);
                }
                _ => {
                    debug!(
                        peer = %peer_id,
                        msg_type = message.message_type(),
                        "Ignoring unexpected message during block download"
                    );
                }
            }
        }

        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// Run the block execution phase (requires a SyncExecutor)
async fn run_block_execution_phase<E: SyncExecutor>(
    manager: &mut StateSyncManager,
    executor: Arc<E>,
) -> Result<(), SyncError> {
    info!("Starting block execution phase");

    loop {
        let block_syncer = manager
            .block_syncer_mut()
            .ok_or_else(|| SyncError::InvalidState("no block syncer".into()))?;

        // Check if execution is complete
        if block_syncer.is_complete() {
            let stats = block_syncer.stats();
            info!(
                executed = stats.total_executed,
                target = stats.target_height,
                "Block execution phase complete"
            );
            return Ok(());
        }

        // Get next block to execute
        let downloaded_block = match block_syncer.next_executable_block() {
            Some(b) => b,
            None => {
                // No blocks ready yet, wait
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };

        // Deserialize and execute the block
        let sync_block = SyncBlock::from_bytes(&downloaded_block.data)
            .map_err(|e| SyncError::Storage(format!("failed to deserialize block: {}", e)))?;

        debug!(
            height = sync_block.block_number,
            txs = sync_block.transactions.len(),
            "Executing block"
        );

        match executor.execute_block(sync_block).await {
            Ok(result) => {
                let block_syncer = manager
                    .block_syncer_mut()
                    .ok_or_else(|| SyncError::InvalidState("no block syncer".into()))?;

                block_syncer.block_executed(result.block_number, result.state_root);

                debug!(
                    height = result.block_number,
                    gas_used = result.gas_used,
                    txs = result.transaction_count,
                    "Block executed successfully"
                );
            }
            Err(e) => {
                error!(
                    height = downloaded_block.height,
                    error = %e,
                    "Block execution failed"
                );

                let block_syncer = manager
                    .block_syncer_mut()
                    .ok_or_else(|| SyncError::InvalidState("no block syncer".into()))?;

                block_syncer.handle_execution_failure(downloaded_block.height);

                // For now, fail on execution error
                // In production, you might want to retry or recover
                return Err(e);
            }
        }
    }
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Estimate the size of an account range response in bytes
fn estimate_account_response_size(response: &AccountRangeResponse) -> u64 {
    // ~100 bytes per account + proof size
    let accounts_size = response.accounts.len() as u64 * 100;
    let proof_size: u64 = response.proof.iter().map(|p| p.len() as u64).sum();
    accounts_size + proof_size
}

/// Estimate the size of a storage range response in bytes
fn estimate_storage_response_size(response: &StorageRangeResponse) -> u64 {
    // 64 bytes per slot (key + value) + proof size
    let slots_size = response.slots.len() as u64 * 64;
    let proof_size: u64 = response.proof.iter().map(|p| p.len() as u64).sum();
    slots_size + proof_size
}

/// Estimate the size of a block range response in bytes
fn estimate_block_response_size(response: &BlockRangeResponse) -> u64 {
    response.blocks.iter().map(|b| b.len() as u64).sum()
}

#[cfg(test)]
mod tests {
    use super::*;
    use cipherbft_sync::SyncPhase;

    fn test_config() -> NodeSyncConfig {
        NodeSyncConfig {
            snap_sync_enabled: true,
            min_sync_peers: 3,
            sync_timeout_secs: 30,
            snap_sync_threshold: 1024,
        }
    }

    #[test]
    fn test_should_snap_sync_enabled() {
        let config = test_config();

        // Below threshold - should not sync
        assert!(!should_snap_sync(9000, 9500, &config));

        // At threshold - should sync
        assert!(should_snap_sync(9000, 10024, &config));

        // Above threshold - should sync
        assert!(should_snap_sync(1000, 10000, &config));
    }

    #[test]
    fn test_should_snap_sync_disabled() {
        let mut config = test_config();
        config.snap_sync_enabled = false;

        // Even with large gap, should not sync if disabled
        assert!(!should_snap_sync(0, 100000, &config));
    }

    #[test]
    fn test_should_snap_sync_already_synced() {
        let config = test_config();

        // Local ahead of network (shouldn't happen but handle gracefully)
        assert!(!should_snap_sync(10000, 9000, &config));

        // Exactly at tip
        assert!(!should_snap_sync(10000, 10000, &config));
    }

    #[test]
    fn test_create_sync_manager() {
        let config = test_config();
        let manager = create_sync_manager(&config);

        // Manager should start in discovery phase
        assert!(matches!(manager.phase(), SyncPhase::Discovery));
        assert!(!manager.is_complete());
    }

    #[tokio::test]
    async fn test_run_snap_sync_disabled() {
        let mut config = test_config();
        config.snap_sync_enabled = false;

        let mut manager = create_sync_manager(&config);
        let (mut adapter, _tx, _rx) = crate::sync_network::create_sync_adapter();

        let result = run_snap_sync(&mut manager, &mut adapter, 0, 100000, &config).await;

        assert!(matches!(result, SyncResult::Skipped { .. }));
    }

    #[tokio::test]
    async fn test_run_snap_sync_below_threshold() {
        let config = test_config();
        let mut manager = create_sync_manager(&config);
        let (mut adapter, _tx, _rx) = crate::sync_network::create_sync_adapter();

        let result = run_snap_sync(&mut manager, &mut adapter, 9900, 10000, &config).await;

        assert!(matches!(result, SyncResult::Skipped { .. }));
    }
}
