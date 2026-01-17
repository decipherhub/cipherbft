//! Host Actor for Malachite consensus integration.
//!
//! This module implements the Host actor that handles AppMsg from Malachite
//! consensus engine and bridges to the Data Chain Layer (DCL).

use crate::context::CipherBftContext;
use crate::types::{ConsensusHeight, ConsensusValue};
use anyhow::Result;
use bytes::Bytes;
use cipherbft_data_chain::Cut;
use informalsystems_malachitebft_app_channel::AppMsg;
use informalsystems_malachitebft_core_types::{Round, Validity};
use informalsystems_malachitebft_engine::host::{HostRef, Next, ProposedValue};
use informalsystems_malachitebft_sync::RawDecidedValue;
use ractor::Actor;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, Notify, RwLock};
use tracing::{debug, error, info, warn};

/// Host actor that bridges between Malachite consensus and DCL.
pub struct CipherBftHost {
    /// Our validator ID (stored for future use, e.g., leader election)
    _our_id: cipherbft_types::ValidatorId,
    /// Consensus context (contains validator set, config, etc.)
    ctx: CipherBftContext,
    /// Pending cuts by height (waiting for consensus to request)
    pending_cuts: Arc<RwLock<HashMap<ConsensusHeight, Cut>>>,
    /// Cuts by value_id (for finding cuts from certificates)
    cuts_by_value_id: Arc<RwLock<HashMap<crate::types::ConsensusValueId, Cut>>>,
    /// Decided cuts by height (for history queries)
    decided_cuts: Arc<RwLock<HashMap<ConsensusHeight, Cut>>>,
    /// Decided certificates by height (for GetDecidedValue)
    decided_certificates: Arc<
        RwLock<
            HashMap<
                ConsensusHeight,
                informalsystems_malachitebft_core_types::CommitCertificate<CipherBftContext>,
            >,
        >,
    >,
    /// Channel to send Decided events (for logging/monitoring)
    decided_tx: Option<mpsc::Sender<(ConsensusHeight, Cut)>>,
    /// Notifier for when new cuts are stored (used to wake up GetValue waiters)
    cut_notify: Arc<Notify>,
}

impl CipherBftHost {
    /// Create a new host actor.
    pub fn new(
        our_id: cipherbft_types::ValidatorId,
        ctx: CipherBftContext,
        decided_tx: Option<mpsc::Sender<(ConsensusHeight, Cut)>>,
    ) -> Self {
        Self {
            _our_id: our_id,
            ctx,
            pending_cuts: Arc::new(RwLock::new(HashMap::new())),
            cuts_by_value_id: Arc::new(RwLock::new(HashMap::new())),
            decided_cuts: Arc::new(RwLock::new(HashMap::new())),
            decided_certificates: Arc::new(RwLock::new(HashMap::new())),
            decided_tx,
            cut_notify: Arc::new(Notify::new()),
        }
    }

    /// Store a Cut for consensus requests.
    pub async fn store_cut(&self, height: ConsensusHeight, cut: Cut) {
        debug!(
            "Host: Storing Cut for height {} with {} cars",
            height,
            cut.cars.len()
        );

        {
            let mut pending = self.pending_cuts.write().await;
            pending.insert(height, cut.clone());
        }

        // Clean up old pending cuts (keep only last 10 heights)
        let mut pending = self.pending_cuts.write().await;
        if pending.len() > 10 {
            let heights: Vec<_> = pending.keys().cloned().collect();
            let max_height = heights.iter().max().copied().unwrap_or(height);
            // Keep heights within 10 of the maximum (i.e., recent heights)
            let cutoff = max_height.0.saturating_sub(10);
            pending.retain(|h, _| h.0 >= cutoff);
        }

        // Notify any waiters that a new cut is available
        self.cut_notify.notify_waiters();
    }

    /// Get a pending cut for the given height.
    /// Also stores the cut by value_id for later retrieval from certificates.
    pub async fn get_value(&self, height: ConsensusHeight) -> Option<ConsensusValue> {
        let mut pending = self.pending_cuts.write().await;
        if let Some(cut) = pending.remove(&height) {
            // Store cut by value_id for later retrieval from certificates
            use informalsystems_malachitebft_core_types::Value;
            let value = ConsensusValue(cut.clone());
            let value_id = value.id();
            let mut by_value_id = self.cuts_by_value_id.write().await;
            by_value_id.insert(value_id, cut.clone());

            // Clean up old cuts_by_value_id (keep only last 100)
            if by_value_id.len() > 100 {
                // Note: This is a simple cleanup - in practice we might want to track by height
                let keys: Vec<_> = by_value_id.keys().cloned().collect();
                for key in keys.iter().take(by_value_id.len() - 100) {
                    by_value_id.remove(key);
                }
            }

            Some(ConsensusValue(cut))
        } else {
            None
        }
    }

    /// Get a pending cut for the given height, waiting up to the specified timeout.
    ///
    /// This method:
    /// 1. First tries to get a cut immediately
    /// 2. If not available, waits for cuts to arrive (with polling and notification)
    /// 3. If timeout expires without a cut, returns an empty Cut (valid for empty blocks)
    ///
    /// This ensures the reply channel is ALWAYS fulfilled, preventing consensus stalls.
    pub async fn get_value_with_timeout(
        &self,
        height: ConsensusHeight,
        timeout: Duration,
    ) -> ConsensusValue {
        use informalsystems_malachitebft_core_types::Value;

        // Use a slightly shorter timeout to ensure we respond within Malachite's deadline
        let effective_timeout = timeout.saturating_sub(Duration::from_millis(100));
        let poll_interval = Duration::from_millis(50);
        let deadline = tokio::time::Instant::now() + effective_timeout;

        loop {
            // Try to get the cut immediately
            if let Some(value) = self.get_value(height).await {
                debug!(
                    "Host: Found Cut for height {} (value_id: {:?})",
                    height,
                    value.id()
                );
                return value;
            }

            // Check if we've exceeded the timeout
            let now = tokio::time::Instant::now();
            if now >= deadline {
                // Timeout expired - propose an empty Cut
                warn!(
                    "Host: Timeout waiting for Cut at height {} - proposing empty Cut",
                    height
                );
                let empty_cut = Cut::new(height.0);
                let value = ConsensusValue(empty_cut.clone());

                // Store the empty cut by value_id for later retrieval
                let value_id = value.id();
                let mut by_value_id = self.cuts_by_value_id.write().await;
                by_value_id.insert(value_id, empty_cut);

                return value;
            }

            // Wait for either a notification or a poll interval
            let remaining = deadline - now;
            let wait_duration = remaining.min(poll_interval);

            tokio::select! {
                _ = self.cut_notify.notified() => {
                    // A cut was stored, try to get it on next iteration
                    debug!("Host: Notified of new Cut, checking for height {}", height);
                }
                _ = tokio::time::sleep(wait_duration) => {
                    // Poll interval elapsed, check again
                }
            }
        }
    }

    /// Get a cut by its value_id (for retrieval from certificates).
    pub async fn get_cut_by_value_id(
        &self,
        value_id: &crate::types::ConsensusValueId,
    ) -> Option<Cut> {
        let by_value_id = self.cuts_by_value_id.read().await;
        by_value_id.get(value_id).cloned()
    }

    /// Handle HostMsg::Decided - store certificate and cut
    pub async fn handle_decided(
        &self,
        height: ConsensusHeight,
        cut: Cut,
        certificate: informalsystems_malachitebft_core_types::CommitCertificate<CipherBftContext>,
    ) {
        // Store in decided cuts and certificate
        {
            let mut decided = self.decided_cuts.write().await;
            decided.insert(height, cut.clone());

            let mut certificates = self.decided_certificates.write().await;
            certificates.insert(height, certificate);
        }

        // Send to channel if exists
        if let Some(ref tx) = self.decided_tx {
            let _ = tx.send((height, cut)).await;
        }
    }

    /// Get validator set from context
    pub fn validator_set(&self) -> crate::validator_set::ConsensusValidatorSet {
        self.ctx.validator_set().clone()
    }

    /// Handle AppMsg from Malachite consensus engine.
    ///
    /// NOTE: This method signature and return type need to match the actual
    /// Host trait from Malachite. The current implementation is based on
    /// compiler error messages and may need adjustment.
    pub async fn handle_app_msg(
        &mut self,
        msg: AppMsg<CipherBftContext>,
    ) -> Next<CipherBftContext> {
        match msg {
            AppMsg::ConsensusReady { reply } => {
                info!("Host: Consensus engine is ready");
                // Reply with the initial height and validator set from context
                let initial_height = self.ctx.initial_height();
                let validator_set = self.ctx.validator_set().clone();
                let _ = reply.send((initial_height, validator_set.clone()));
                Next::Start(initial_height, validator_set)
            }

            AppMsg::GetValue {
                height,
                reply,
                round,
                timeout,
            } => {
                debug!(
                    "Host: GetValue request for height {} round {} (timeout: {:?})",
                    height, round, timeout
                );

                // Use the timeout-aware method that waits for cuts to arrive
                // and proposes an empty Cut if timeout expires (preventing consensus stalls)
                let value = self.get_value_with_timeout(height, timeout).await;

                // Always reply - get_value_with_timeout guarantees a value
                use informalsystems_malachitebft_app::types::LocallyProposedValue;
                let proposed = LocallyProposedValue::new(height, round, value);
                let _ = reply.send(proposed);

                // Continue with current height and validator set
                let current_height = height;
                let validator_set = self.ctx.validator_set().clone();
                Next::Start(current_height, validator_set)
            }

            AppMsg::Decided {
                certificate,
                extensions: _extensions,
                reply,
                ..
            } => {
                // Extract cut from certificate using value_id
                // ValueId<CipherBftContext> is the same as ConsensusValueId
                let height = certificate.height;
                let value_id = &certificate.value_id; // This is ConsensusValueId

                // Try to find cut by value_id first (most reliable)
                let mut cut = self.get_cut_by_value_id(value_id).await;

                // If not found by value_id, try by height (fallback)
                if cut.is_none() {
                    let decided = self.decided_cuts.read().await;
                    if let Some(c) = decided.get(&height) {
                        cut = Some(c.clone());
                    }
                }

                // If still not found, try pending_cuts as last resort
                if cut.is_none() {
                    let pending = self.pending_cuts.read().await;
                    if let Some(c) = pending.get(&height) {
                        cut = Some(c.clone());
                    }
                }

                // If we still couldn't find it, this is an error condition
                // In practice, the Cut should have been stored when GetValue was called
                let cut = match cut {
                    Some(cut) => cut,
                    None => {
                        warn!("Host: Cannot find Cut for certificate at height {} with value_id {:?} - this should not happen", height, value_id);
                        // This should not happen in normal operation
                        // The Cut should have been stored when GetValue was called
                        // For now, we'll panic or return an error - in production this needs proper error handling
                        // TODO: Consider if we should extract from extensions or use a different strategy
                        return Next::Start(height, self.ctx.validator_set().clone());
                    }
                };

                let height = ConsensusHeight::from(cut.height);
                info!(
                    "Host: ✅ CONSENSUS DECIDED at height {} with {} cars",
                    height,
                    cut.cars.len()
                );

                // Store in decided cuts and certificate
                {
                    let mut decided = self.decided_cuts.write().await;
                    decided.insert(height, cut.clone());

                    let mut certificates = self.decided_certificates.write().await;
                    certificates.insert(height, certificate.clone());
                }

                // Send to channel if exists (for logging/monitoring)
                if let Some(ref tx) = self.decided_tx {
                    let _ = tx.send((height, cut.clone())).await;
                }

                // Clean up old decided cuts (keep only last 100 heights)
                let mut decided = self.decided_cuts.write().await;
                if decided.len() > 100 {
                    let heights: Vec<_> = decided.keys().cloned().collect();
                    let max_height = heights.iter().max().copied().unwrap_or(height);
                    // Keep heights within 100 of the maximum (i.e., recent heights)
                    let cutoff = max_height.0.saturating_sub(100);
                    decided.retain(|h, _| h.0 >= cutoff);
                }

                // Continue with next height and validator set
                let next_height = height.next();
                let validator_set = self.ctx.validator_set().clone(); // TODO: Get next validator set if it changes
                let _ = reply.send(Next::Start(next_height, validator_set.clone()));
                Next::Start(next_height, validator_set)
            }

            AppMsg::ReceivedProposalPart { reply, .. } => {
                debug!("Host: Received proposal part");
                let _ = reply.send(None); // Reply with None if not complete
                                          // Continue with current height and validator set
                                          // Note: ReceivedProposalPart doesn't have height field, use context initial height
                let current_height = self.ctx.initial_height();
                let validator_set = self.ctx.validator_set().clone();
                Next::Start(current_height, validator_set)
            }

            AppMsg::ProcessSyncedValue { height, reply, .. } => {
                debug!("Host: ProcessSyncedValue for height {}", height);
                let _ = reply.send(None); // Reply with None if value cannot be decoded
                                          // Continue with current height and validator set
                let current_height = height;
                let validator_set = self.ctx.validator_set().clone();
                Next::Start(current_height, validator_set)
            }

            AppMsg::GetDecidedValue { height, reply, .. } => {
                debug!("Host: GetDecidedValue for height {}", height);
                let decided = self.decided_cuts.read().await;
                let certificates = self.decided_certificates.read().await;

                match (decided.get(&height), certificates.get(&height)) {
                    (Some(cut), Some(certificate)) => {
                        debug!(
                            "Host: Found decided Cut and certificate for height {}",
                            height
                        );
                        use bytes::Bytes;
                        use informalsystems_malachitebft_app::types::sync::RawDecidedValue;
                        // RawDecidedValue::new expects 2 arguments: value_bytes and certificate
                        let value_bytes = Bytes::from(bincode::serialize(&cut).unwrap()); // Serialize Cut to Bytes
                        let raw = RawDecidedValue::new(value_bytes, certificate.clone());
                        let _ = reply.send(Some(raw));
                    }
                    (Some(_cut), None) => {
                        // Cut exists but no certificate - this should not happen in normal operation
                        warn!("Host: Found decided Cut for height {} but no certificate - this should not happen if Decided was processed correctly", height);
                        // TODO: Reconstruct certificate from cut if possible
                        // For now, we'll return None - this is an error condition
                        let _ = reply.send(None);
                    }
                    _ => {
                        warn!("Host: No decided Cut found for height {}", height);
                        let _ = reply.send(None);
                    }
                }
                // Continue with current height and validator set
                let current_height = height; // Use the requested height
                let validator_set = self.ctx.validator_set().clone();
                Next::Start(current_height, validator_set)
            }

            AppMsg::GetHistoryMinHeight { reply } => {
                debug!("Host: GetHistoryMinHeight");
                let decided = self.decided_cuts.read().await;
                let min_height = decided
                    .keys()
                    .min()
                    .copied()
                    .unwrap_or(ConsensusHeight::from(1));
                debug!("Host: History min height is {}", min_height);
                let _ = reply.send(min_height);
                // Continue with current height and validator set
                // Note: GetHistoryMinHeight doesn't have height field, use context initial height
                let current_height = self.ctx.initial_height();
                let validator_set = self.ctx.validator_set().clone();
                Next::Start(current_height, validator_set)
            }

            _ => {
                warn!("Host: Unhandled AppMsg variant");
                // Continue with current height and validator set
                // Note: Unknown variant doesn't have height field, use context initial height
                let current_height = self.ctx.initial_height();
                let validator_set = self.ctx.validator_set().clone();
                Next::Start(current_height, validator_set)
            }
        }
    }
}

/// Internal actor state for HostMsg handling.
struct HostActorState {
    host: Arc<RwLock<CipherBftHost>>,
}

/// Actor implementation for HostMsg handling.
///
/// This actor wraps CipherBftHost and handles HostMsg from Malachite.
/// It converts HostMsg to AppMsg internally and uses CipherBftHost::handle_app_msg.
#[derive(Clone)]
struct HostActor {
    _phantom: std::marker::PhantomData<CipherBftContext>,
}

#[async_trait::async_trait]
impl ractor::Actor for HostActor {
    type Msg = informalsystems_malachitebft_engine::host::HostMsg<CipherBftContext>;
    type State = HostActorState;
    type Arguments = HostActorState;

    async fn pre_start(
        &self,
        _myself: ractor::ActorRef<Self::Msg>,
        args: Self::Arguments,
    ) -> Result<Self::State, ractor::ActorProcessingErr> {
        Ok(args)
    }

    async fn handle(
        &self,
        _myself: ractor::ActorRef<Self::Msg>,
        msg: Self::Msg,
        state: &mut Self::State,
    ) -> Result<(), ractor::ActorProcessingErr> {
        use informalsystems_malachitebft_engine::host::HostMsg;

        // Convert HostMsg to AppMsg and handle it
        // Note: HostMsg and AppMsg have similar structure but different field names
        // For now, we'll handle HostMsg directly and use CipherBftHost internally

        let host = state.host.write().await;

        // Handle HostMsg
        match msg {
            HostMsg::ConsensusReady { reply_to } => {
                debug!("Host: ConsensusReady");
                let initial_height = host.ctx.initial_height();
                let validator_set = host.validator_set();
                let _ = reply_to.send((initial_height, validator_set));
            }
            HostMsg::StartedRound {
                height,
                round,
                proposer,
                role,
                reply_to,
            } => {
                debug!(
                    "Host: StartedRound height {} round {} proposer {:?} role {:?}",
                    height, round, proposer, role
                );
                // For recovery, we don't have undecided values to return
                let _ = reply_to.send(vec![]);
            }
            HostMsg::GetValue {
                height,
                round,
                timeout,
                reply_to,
            } => {
                debug!(
                    "Host: GetValue height {} round {} (timeout: {:?})",
                    height, round, timeout
                );
                // Use the timeout-aware method that waits for cuts to arrive
                // and proposes an empty Cut if timeout expires (preventing consensus stalls)
                let value = host.get_value_with_timeout(height, timeout).await;

                // Always reply - get_value_with_timeout guarantees a value
                use informalsystems_malachitebft_engine::host::LocallyProposedValue;
                let proposed = LocallyProposedValue::new(height, round, value);
                let _ = reply_to.send(proposed);
            }
            HostMsg::ExtendVote {
                height,
                round,
                value_id,
                reply_to,
            } => {
                debug!(
                    "Host: ExtendVote height {} round {} value_id {:?}",
                    height, round, value_id
                );
                // No vote extensions for now
                let _ = reply_to.send(None);
            }
            HostMsg::VerifyVoteExtension {
                height,
                round,
                value_id,
                extension: _,
                reply_to,
            } => {
                debug!(
                    "Host: VerifyVoteExtension height {} round {} value_id {:?}",
                    height, round, value_id
                );
                // Accept all vote extensions for now
                let _ = reply_to.send(Ok(()));
            }
            HostMsg::RestreamValue {
                height,
                round,
                valid_round,
                address,
                value_id,
            } => {
                // RestreamValue is called when a validator needs to republish a proposal
                // (e.g., during leader election when the original proposer's message was lost).
                // This requires access to the Network actor to re-publish proposal parts.
                //
                // For now, we verify the cut exists and log appropriately.
                // Full implementation requires:
                // 1. Access to NetworkRef to call PublishProposalPart
                // 2. Reconstructing the CutProposalPart from the stored Cut
                debug!(
                    %height, %round, %valid_round, 
                    ?address, ?value_id,
                    "Host: RestreamValue requested"
                );
                
                // Check if we have the value to restream
                let cut = host.get_cut_by_value_id(&value_id).await;
                if cut.is_some() {
                    // We have the cut but can't publish it without network access
                    // TODO: Store NetworkRef in HostActorState to enable restreaming
                    warn!(
                        %height, %round, ?value_id,
                        "Host: RestreamValue - found cut but network publishing not yet implemented"
                    );
                } else {
                    warn!(
                        %height, %round, ?value_id,
                        "Host: RestreamValue - cut not found, cannot restream"
                    );
                }
            }
            HostMsg::GetHistoryMinHeight { reply_to } => {
                debug!("Host: GetHistoryMinHeight");
                let decided = host.decided_cuts.read().await;
                let min_height = decided
                    .keys()
                    .min()
                    .copied()
                    .unwrap_or(ConsensusHeight::from(1));
                let _ = reply_to.send(min_height);
            }
            HostMsg::ReceivedProposalPart {
                from,
                part,
                reply_to,
            } => {
                debug!("Host: ReceivedProposalPart from {:?}", from);
                // We use single-part proposals, so each part IS the complete proposal.
                // Decode the CutProposalPart to extract the Cut and construct ProposedValue.
                use crate::proposal::CutProposalPart;
                use borsh::BorshDeserialize;
                
                // Attempt to decode the proposal part
                match CutProposalPart::try_from_slice(&part.data) {
                    Ok(proposal_part) => {
                        // For single-part proposals, first == last == true
                        if proposal_part.first && proposal_part.last {
                            let cut = proposal_part.cut;
                            let value = ConsensusValue(cut);
                            let proposed = ProposedValue {
                                height: part.height,
                                round: part.round,
                                valid_round: Round::Nil, // Not known from proposal part alone
                                proposer: part.validator,
                                value,
                                validity: Validity::Valid,
                            };
                            let _ = reply_to.send(Some(proposed));
                        } else {
                            // Multi-part proposals not yet supported
                            debug!("Host: Multi-part proposal received (first={}, last={}) - not yet supported", 
                                   proposal_part.first, proposal_part.last);
                            let _ = reply_to.send(None);
                        }
                    }
                    Err(e) => {
                        warn!("Host: Failed to decode proposal part from {:?}: {}", from, e);
                        let _ = reply_to.send(None);
                    }
                }
            }
            HostMsg::GetValidatorSet { height, reply_to } => {
                debug!("Host: GetValidatorSet height {}", height);
                let validator_set = host.validator_set();
                // TODO: Return different validator sets for different heights if validator set changes
                let _ = reply_to.send(Some(validator_set));
            }
            HostMsg::Decided {
                certificate,
                extensions: _,
                reply_to,
            } => {
                // Extract cut from certificate using value_id
                let height = certificate.height;
                let value_id = &certificate.value_id;

                let cut = host.get_cut_by_value_id(value_id).await;

                if let Some(cut) = cut {
                    let height = ConsensusHeight::from(cut.height);
                    info!(
                        "Host: ✅ CONSENSUS DECIDED at height {} with {} cars",
                        height,
                        cut.cars.len()
                    );

                    host.handle_decided(height, cut.clone(), certificate).await;

                    let next_height = height.next();
                    let validator_set = host.validator_set();
                    let _ = reply_to.send(Next::Start(next_height, validator_set));
                } else {
                    warn!("Host: Cannot find Cut for certificate at height {} with value_id {:?} - this should not happen", height, value_id);
                    let validator_set = host.validator_set();
                    let _ = reply_to.send(Next::Start(height, validator_set));
                }
            }
            HostMsg::GetDecidedValue { height, reply_to } => {
                debug!("Host: GetDecidedValue height {}", height);
                let decided_cuts = host.decided_cuts.read().await;
                let decided_certificates = host.decided_certificates.read().await;
                match (decided_cuts.get(&height), decided_certificates.get(&height)) {
                    (Some(cut), Some(certificate)) => {
                        let value_bytes = Bytes::from(bincode::serialize(&cut).unwrap());
                        let raw = RawDecidedValue::new(value_bytes, certificate.clone());
                        let _ = reply_to.send(Some(raw));
                    }
                    _ => {
                        warn!(
                            "Host: No decided Cut or Certificate found for height {}",
                            height
                        );
                        let _ = reply_to.send(None);
                    }
                }
            }
            HostMsg::ProcessSyncedValue {
                height,
                round,
                proposer,
                value_bytes,
                reply_to,
            } => {
                debug!(
                    "Host: ProcessSyncedValue height {} round {} proposer {:?}",
                    height, round, proposer
                );
                // Try to decode the value from bytes
                match bincode::deserialize::<Cut>(&value_bytes) {
                    Ok(cut) => {
                        let value = ConsensusValue(cut);
                        // ProposedValue requires height, round, valid_round, proposer, value, and validity
                        // For synced values, we don't have valid_round, so we'll use round as valid_round
                        // and Validity::Valid as a default
                        let proposed = ProposedValue {
                            height,
                            round,
                            valid_round: round, // Use current round as valid_round for synced values
                            proposer,
                            value,
                            validity: Validity::Valid, // Assume valid for synced values
                        };
                        let _ = reply_to.send(proposed);
                    }
                    Err(e) => {
                        // Log decode failure with full context for debugging.
                        // This indicates either network corruption, serialization mismatch,
                        // or a malicious peer sending invalid data.
                        error!(
                            %height,
                            %round,
                            ?proposer,
                            bytes_len = value_bytes.len(),
                            error = %e,
                            "Host: Failed to decode synced value - returning Invalid ProposedValue"
                        );

                        // Malachite's ProcessSyncedValue contract requires returning a ProposedValue.
                        // By marking it as Invalid, Malachite will:
                        // 1. Notify sync via SyncMsg::InvalidValue (peer will be marked as problematic)
                        // 2. The value_id mismatch with the certificate triggers proper error handling
                        // 3. The state machine filters out invalid values - no consensus corruption
                        let sentinel_cut = Cut {
                            height: height.0,
                            cars: HashMap::new(),
                            attestations: HashMap::new(),
                        };
                        let proposed = ProposedValue {
                            height,
                            round,
                            valid_round: Round::Nil,
                            proposer,
                            value: ConsensusValue(sentinel_cut),
                            validity: Validity::Invalid,
                        };
                        let _ = reply_to.send(proposed);
                    }
                }
            }
        }

        Ok(())
    }
}

/// Spawn the host actor and return a HostRef.
///
/// This creates a ractor actor that handles HostMsg from the Malachite engine.
/// The actor processes HostMsg and uses CipherBftHost internally.
pub async fn spawn_host(
    our_id: cipherbft_types::ValidatorId,
    ctx: CipherBftContext,
    mut cut_rx: mpsc::Receiver<Cut>,
    decided_tx: Option<mpsc::Sender<(ConsensusHeight, Cut)>>,
) -> Result<HostRef<CipherBftContext>> {
    // Create host instance
    let host_state = Arc::new(RwLock::new(CipherBftHost::new(
        our_id,
        ctx.clone(),
        decided_tx,
    )));

    // Spawn background task to process DCL cuts
    let host_for_cuts = Arc::clone(&host_state);
    tokio::spawn(async move {
        while let Some(cut) = cut_rx.recv().await {
            let height = ConsensusHeight::from(cut.height);
            let host = host_for_cuts.read().await;
            host.store_cut(height, cut).await;
        }
        warn!("Host: DCL cut receiver closed");
    });

    // Spawn HostActor using ractor
    let actor_state = HostActorState { host: host_state };

    // Spawn the actor - following Malachite's Connector::spawn pattern
    // Actor::spawn returns (ActorRef<Self::Msg>, JoinHandle)
    // HostRef<Ctx> is a type alias for ractor::ActorRef<HostMsg<Ctx>>
    let (actor_ref, _join_handle): (HostRef<CipherBftContext>, _) = Actor::spawn(
        Some("CipherBftHost".to_string()),
        HostActor {
            _phantom: std::marker::PhantomData,
        },
        actor_state,
    )
    .await
    .map_err(|e| anyhow::anyhow!("Failed to spawn HostActor: {:?}", e))?;

    info!("Host actor spawned successfully");

    // HostRef is a type alias for ractor::ActorRef<HostMsg<Ctx>>.
    // With matching ractor versions (0.14.x for both our crate and malachite),
    // actor_ref is directly compatible with HostRef<CipherBftContext>.
    Ok(actor_ref)
}
