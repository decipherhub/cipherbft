//! Host Actor for Malachite consensus integration.
//!
//! This module implements the Host actor that handles AppMsg from Malachite
//! consensus engine and bridges to the Data Chain Layer (DCL).

use crate::context::CipherBftContext;
use crate::types::{ConsensusHeight, ConsensusValue};
use anyhow::Result;
use cipherbft_data_chain::Cut;
use informalsystems_malachitebft_engine::host::HostRef;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, warn};

/// Host actor that bridges between Malachite consensus and DCL.
///
/// This actor handles:
/// - `GetValue`: Requests a Cut from DCL for proposal
/// - `Decided`: Processes consensus decision (Cut agreed upon)
/// - `ConsensusReady`: Notification that consensus is ready
/// - `ReceivedProposalPart`: Handles received proposal parts
/// - `ProcessSyncedValue`: Processes synced values (for catch-up)
/// - `GetDecidedValue`: Retrieves previously decided values
/// - `GetHistoryMinHeight`: Gets minimum height in history
pub struct CipherBftHost {
    /// Our validator ID
    our_id: cipherbft_types::ValidatorId,
    /// Channel to receive CutReady events from DCL Primary
    cut_rx: mpsc::Receiver<Cut>,
    /// Channel to send GetValue requests to DCL (for future use)
    #[allow(dead_code)]
    get_value_tx: mpsc::Sender<ConsensusHeight>,
    /// Pending cuts by height (waiting for consensus to request)
    pending_cuts: Arc<RwLock<HashMap<ConsensusHeight, Cut>>>,
    /// Decided cuts by height (for history queries)
    decided_cuts: Arc<RwLock<HashMap<ConsensusHeight, Cut>>>,
    /// Channel to send Decided events (for future EL integration)
    #[allow(dead_code)]
    decided_tx: Option<mpsc::Sender<(ConsensusHeight, Cut)>>,
}

impl CipherBftHost {
    /// Create a new host actor.
    ///
    /// # Arguments
    /// * `our_id` - Our validator ID
    /// * `cut_rx` - Receiver for CutReady events from DCL
    /// * `decided_tx` - Optional sender for Decided events (to EL)
    pub fn new(
        our_id: cipherbft_types::ValidatorId,
        cut_rx: mpsc::Receiver<Cut>,
        decided_tx: Option<mpsc::Sender<(ConsensusHeight, Cut)>>,
    ) -> Self {
        let (get_value_tx, _) = mpsc::channel(100);

        Self {
            our_id,
            cut_rx,
            get_value_tx,
            pending_cuts: Arc::new(RwLock::new(HashMap::new())),
            decided_cuts: Arc::new(RwLock::new(HashMap::new())),
            decided_tx,
        }
    }

    /// Handle incoming Cut from DCL and store it for consensus requests.
    async fn handle_cut_ready(&self, cut: Cut) {
        let height = ConsensusHeight::from(cut.height);
        debug!(
            "Host: Received CutReady for height {} with {} cars",
            height,
            cut.cars.len()
        );

        // Store in pending cuts for GetValue requests
        {
            let mut pending = self.pending_cuts.write().await;
            pending.insert(height, cut.clone());
        }

        // Clean up old pending cuts (keep only last 10 heights)
        let mut pending = self.pending_cuts.write().await;
        if pending.len() > 10 {
            let heights: Vec<_> = pending.keys().cloned().collect();
            let min_height = heights.iter().min().copied().unwrap_or(height);
            let cutoff = min_height.0.saturating_sub(10);
            pending.retain(|h, _| h.0 > cutoff);
        }
    }

    /// Get a pending cut for the given height (for GetValue requests).
    pub async fn get_value(&self, height: ConsensusHeight) -> Option<ConsensusValue> {
        let mut pending = self.pending_cuts.write().await;
        pending.remove(&height).map(|cut| ConsensusValue(cut))
    }

    /// Process incoming cuts from DCL in the background.
    pub async fn process_dcl_cuts(mut self) {
        while let Some(cut) = self.cut_rx.recv().await {
            self.handle_cut_ready(cut).await;
        }
        warn!("Host: DCL cut receiver closed");
    }
}

// Note: Host trait implementation needs to match actual Malachite API
// For now, we'll use a simpler approach that handles AppMsg through channels
// The actual implementation will depend on informalsystems_malachitebft_app_channel::Host trait

// TODO: Implement actual Host trait once we know the exact API structure
// The Host trait might be in informalsystems_malachitebft_app_channel or a different crate
// 
// Example structure (needs verification):
// #[async_trait::async_trait]
// impl Host<CipherBftContext> for CipherBftHost {
//     async fn handle_app_msg(&mut self, msg: AppMsg<CipherBftContext>) -> Result<()> {
//         // Handle messages...
//     }
// }

/// Spawn the host actor and return a HostRef.
///
/// # Arguments
/// * `our_id` - Our validator ID
/// * `cut_rx` - Receiver for CutReady events from DCL (will be processed in background)
/// * `decided_tx` - Optional sender for Decided events
///
/// Note: This is a simplified implementation. The actual Malachite Host::spawn API
/// may have different requirements. This will need adjustment based on actual Malachite
/// documentation/examples.
pub async fn spawn_host(
    our_id: cipherbft_types::ValidatorId,
    mut cut_rx: mpsc::Receiver<Cut>,
    decided_tx: Option<mpsc::Sender<(ConsensusHeight, Cut)>>,
) -> Result<HostRef<CipherBftContext>> {
    // Create host with shared state
    let pending_cuts = Arc::new(RwLock::new(HashMap::new()));
    let decided_cuts = Arc::new(RwLock::new(HashMap::new()));

    // Spawn background task to process DCL cuts
    let pending_cuts_for_cuts = Arc::clone(&pending_cuts);
    tokio::spawn(async move {
        while let Some(cut) = cut_rx.recv().await {
            let height = ConsensusHeight::from(cut.height);
            debug!(
                "Host: Received CutReady for height {} with {} cars",
                height,
                cut.cars.len()
            );
            let mut pending = pending_cuts_for_cuts.write().await;
            pending.insert(height, cut);
            // Keep only last 10 heights
            if pending.len() > 10 {
                let heights: Vec<_> = pending.keys().cloned().collect();
                let min_height = heights.iter().min().copied().unwrap_or(height);
                let cutoff = min_height.0.saturating_sub(10);
                pending.retain(|h, _| h.0 > cutoff);
            }
        }
        warn!("Host: DCL cut receiver closed");
    });

    // Create host instance (cut_rx is consumed in background task above)
    // For now, create a dummy receiver for the host struct
    let (_, dummy_cut_rx) = mpsc::channel(100);
    let _host = CipherBftHost {
        our_id,
        cut_rx: dummy_cut_rx,
        get_value_tx: {
            let (tx, _) = mpsc::channel(100);
            tx
        },
        pending_cuts,
        decided_cuts,
        decided_tx,
    };

    // TODO: Spawn Host actor using Malachite's actual API
    // HostRef creation depends on Malachite's Host implementation
    // Need to check informalsystems_malachitebft_app_channel or similar crate
    // For now, this is a placeholder that needs actual implementation
    
    // Example (needs verification):
    // use informalsystems_malachitebft_app_channel::Host;
    // let host_ref = Host::spawn(host).await?;
    
    todo!("Implement Host spawn with actual Malachite API - check informalsystems_malachitebft_app_channel::Host")
}

