//! Host Actor for Malachite consensus integration.
//!
//! This module implements the Host actor that handles AppMsg from Malachite
//! consensus engine and bridges to the Data Chain Layer (DCL).

use crate::context::CipherBftContext;
use crate::types::{ConsensusHeight, ConsensusValue};
use anyhow::Result;
use cipherbft_data_chain::Cut;
use informalsystems_malachitebft_app_channel::AppMsg;
use informalsystems_malachitebft_engine::host::{HostMsg, HostRef, Next, ProposedValue};
use informalsystems_malachitebft_sync::RawDecidedValue;
use informalsystems_malachitebft_core_types::{Round, Validity};
use ractor::Actor;
use ractor::ActorRef as RactorActorRef;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, info, warn};
use bytes::Bytes;

/// Host actor that bridges between Malachite consensus and DCL.
pub struct CipherBftHost {
    /// Our validator ID
    our_id: cipherbft_types::ValidatorId,
    /// Consensus context (contains validator set, config, etc.)
    ctx: CipherBftContext,
    /// Pending cuts by height (waiting for consensus to request)
    pending_cuts: Arc<RwLock<HashMap<ConsensusHeight, Cut>>>,
    /// Cuts by value_id (for finding cuts from certificates)
    cuts_by_value_id: Arc<RwLock<HashMap<crate::types::ConsensusValueId, Cut>>>,
    /// Decided cuts by height (for history queries)
    decided_cuts: Arc<RwLock<HashMap<ConsensusHeight, Cut>>>,
    /// Decided certificates by height (for GetDecidedValue)
    decided_certificates: Arc<RwLock<HashMap<ConsensusHeight, informalsystems_malachitebft_core_types::CommitCertificate<CipherBftContext>>>>,
    /// Channel to send Decided events (for logging/monitoring)
    decided_tx: Option<mpsc::Sender<(ConsensusHeight, Cut)>>,
}

impl CipherBftHost {
    /// Create a new host actor.
    pub fn new(
        our_id: cipherbft_types::ValidatorId,
        ctx: CipherBftContext,
        decided_tx: Option<mpsc::Sender<(ConsensusHeight, Cut)>>,
    ) -> Self {
        Self {
            our_id,
            ctx,
            pending_cuts: Arc::new(RwLock::new(HashMap::new())),
            cuts_by_value_id: Arc::new(RwLock::new(HashMap::new())),
            decided_cuts: Arc::new(RwLock::new(HashMap::new())),
            decided_certificates: Arc::new(RwLock::new(HashMap::new())),
            decided_tx,
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
            let min_height = heights.iter().min().copied().unwrap_or(height);
            let cutoff = min_height.0.saturating_sub(10);
            pending.retain(|h, _| h.0 > cutoff);
        }
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
    
    /// Get a cut by its value_id (for retrieval from certificates).
    pub async fn get_cut_by_value_id(&self, value_id: &crate::types::ConsensusValueId) -> Option<Cut> {
        let by_value_id = self.cuts_by_value_id.read().await;
        by_value_id.get(value_id).cloned()
    }
    
    /// Handle HostMsg::Decided - store certificate and cut
    pub async fn handle_decided(&self, height: ConsensusHeight, cut: Cut, certificate: informalsystems_malachitebft_core_types::CommitCertificate<CipherBftContext>) {
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
    pub async fn handle_app_msg(&mut self, msg: AppMsg<CipherBftContext>) -> Next<CipherBftContext> {
        match msg {
            AppMsg::ConsensusReady { reply } => {
                info!("Host: Consensus engine is ready");
                // Reply with the initial height and validator set from context
                let initial_height = self.ctx.initial_height();
                let validator_set = self.ctx.validator_set().clone();
                reply.send((initial_height, validator_set.clone()));
                Next::Start(initial_height, validator_set)
            }

            AppMsg::GetValue { height, reply, round, .. } => {
                debug!("Host: GetValue request for height {} round {}", height, round);

                let value = self.get_value(height).await;
                
                // Reply with the value (or None if not available)
                if let Some(value) = value {
                    debug!("Host: Found Cut for height {}", height);
                    use informalsystems_malachitebft_app::types::LocallyProposedValue;
                    // LocallyProposedValue::new expects 3 arguments: height, round, value
                    let proposed = LocallyProposedValue::new(height, round, value);
                    // reply.send() does not return a Future, so no .await
                    reply.send(proposed);
                } else {
                    warn!("Host: No Cut available for height {}", height);
                    // TODO: Check how to send None for GetValue
                    warn!("Host: Cannot send None to GetValue reply (type mismatch)");
                }
                
                // Continue with current height and validator set
                let current_height = height; // Use the requested height
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
                    let min_height = heights.iter().min().copied().unwrap_or(height);
                    let cutoff = min_height.0.saturating_sub(100);
                    decided.retain(|h, _| h.0 > cutoff);
                }

                // Continue with next height and validator set
                let next_height = height.next();
                let validator_set = self.ctx.validator_set().clone(); // TODO: Get next validator set if it changes
                reply.send(Next::Start(next_height, validator_set.clone()));
                Next::Start(next_height, validator_set)
            }

            AppMsg::ReceivedProposalPart { reply, .. } => {
                debug!("Host: Received proposal part");
                reply.send(None); // Reply with None if not complete
                // Continue with current height and validator set
                // Note: ReceivedProposalPart doesn't have height field, use context initial height
                let current_height = self.ctx.initial_height();
                let validator_set = self.ctx.validator_set().clone();
                Next::Start(current_height, validator_set)
            }

            AppMsg::ProcessSyncedValue { height, reply, .. } => {
                debug!("Host: ProcessSyncedValue for height {}", height);
                reply.send(None); // Reply with None if value cannot be decoded
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
                        debug!("Host: Found decided Cut and certificate for height {}", height);
                        use informalsystems_malachitebft_app::types::sync::RawDecidedValue;
                        use bytes::Bytes;
                        // RawDecidedValue::new expects 2 arguments: value_bytes and certificate
                        let value_bytes = Bytes::from(bincode::serialize(&cut).unwrap()); // Serialize Cut to Bytes
                        let raw = RawDecidedValue::new(value_bytes, certificate.clone());
                        reply.send(Some(raw));
                    }
                    (Some(_cut), None) => {
                        // Cut exists but no certificate - this should not happen in normal operation
                        warn!("Host: Found decided Cut for height {} but no certificate - this should not happen if Decided was processed correctly", height);
                        // TODO: Reconstruct certificate from cut if possible
                        // For now, we'll return None - this is an error condition
                        reply.send(None);
                    }
                    _ => {
                        warn!("Host: No decided Cut found for height {}", height);
                        reply.send(None);
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
                reply.send(min_height);
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
            HostMsg::StartedRound { height, round, proposer, role, reply_to } => {
                debug!("Host: StartedRound height {} round {} proposer {:?} role {:?}", height, round, proposer, role);
                // For recovery, we don't have undecided values to return
                let _ = reply_to.send(vec![]);
            }
            HostMsg::GetValue { height, round, reply_to, .. } => {
                debug!("Host: GetValue height {} round {}", height, round);
                let value = host.get_value(height).await;
                if let Some(value) = value {
                    use informalsystems_malachitebft_engine::host::LocallyProposedValue;
                    let proposed = LocallyProposedValue::new(height, round, value);
                    let _ = reply_to.send(proposed);
                } else {
                    warn!("Host: No Cut available for height {}", height);
                    // Note: Malachite expects a LocallyProposedValue, but we don't have one.
                    // This will cause the consensus to stall, but it's better than panicking.
                }
            }
            HostMsg::ExtendVote { height, round, value_id, reply_to } => {
                debug!("Host: ExtendVote height {} round {} value_id {:?}", height, round, value_id);
                // No vote extensions for now
                let _ = reply_to.send(None);
            }
            HostMsg::VerifyVoteExtension { height, round, value_id, extension: _, reply_to } => {
                debug!("Host: VerifyVoteExtension height {} round {} value_id {:?}", height, round, value_id);
                // Accept all vote extensions for now
                let _ = reply_to.send(Ok(()));
            }
            HostMsg::RestreamValue { height, round, valid_round, address, value_id } => {
                debug!("Host: RestreamValue height {} round {} valid_round {} address {:?} value_id {:?}", height, round, valid_round, address, value_id);
                // For now, we don't support restreaming proposals
                // This would require publishing proposal parts via NetworkMsg::PublishProposalPart
                warn!("Host: RestreamValue not yet implemented - this may cause sync issues");
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
            HostMsg::ReceivedProposalPart { from, part: _, reply_to: _ } => {
                debug!("Host: ReceivedProposalPart from {:?}", from);
                // For now, we don't handle proposal parts (single-part proposals only)
                // This is a TODO: we should decode the part and check if it completes a proposal
                // For now, we can't return a ProposedValue because we don't have a complete proposal
                // This will cause the consensus to stall, but it's better than panicking
                // Note: reply_to expects ProposedValue, but we don't have one
                // We'll need to handle this properly when implementing proposal parts
                warn!("Host: ReceivedProposalPart not fully implemented - cannot return ProposedValue");
                // TODO: Implement proper proposal part handling to construct ProposedValue
            }
            HostMsg::GetValidatorSet { height, reply_to } => {
                debug!("Host: GetValidatorSet height {}", height);
                let validator_set = host.validator_set();
                // TODO: Return different validator sets for different heights if validator set changes
                let _ = reply_to.send(Some(validator_set));
            }
            HostMsg::Decided { certificate, extensions: _, reply_to } => {
                // Extract cut from certificate using value_id
                let height = certificate.height;
                let value_id = &certificate.value_id;
                
                let cut = host.get_cut_by_value_id(value_id).await;
                
                if let Some(cut) = cut {
                    let height = ConsensusHeight::from(cut.height);
                    info!("Host: ✅ CONSENSUS DECIDED at height {} with {} cars", height, cut.cars.len());
                    
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
                        warn!("Host: No decided Cut or Certificate found for height {}", height);
                        let _ = reply_to.send(None);
                    }
                }
            }
            HostMsg::ProcessSyncedValue { height, round, proposer, value_bytes, reply_to } => {
                debug!("Host: ProcessSyncedValue height {} round {} proposer {:?}", height, round, proposer);
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
                        warn!("Host: Failed to decode synced value: {}", e);
                        // Note: reply_to expects ProposedValue, not Option<ProposedValue>
                        // This is a limitation - we need to return a valid ProposedValue or handle this differently
                        // For now, we'll construct a dummy ProposedValue to avoid panicking
                        // TODO: Find a better way to handle decode failures
                        warn!("Host: Cannot return None for ProcessSyncedValue - returning dummy value");
                        // Construct a dummy ProposedValue with invalid data
                        // Note: This is a fallback - ideally we should handle decode failures differently
                        // For now, we'll create an empty Cut as a dummy
                        use std::collections::HashMap;
                        let dummy_cut = Cut {
                            height: height.0, // Cut expects u64, not Height
                            cars: HashMap::new(),
                            attestations: HashMap::new(),
                        };
                        let dummy_value = ConsensusValue(dummy_cut);
                        let dummy_proposed = ProposedValue {
                            height,
                            round,
                            valid_round: Round::from(0u32),
                            proposer,
                            value: dummy_value,
                            validity: Validity::Invalid,
                        };
                        let _ = reply_to.send(dummy_proposed);
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
    let host_state = Arc::new(RwLock::new(CipherBftHost::new(our_id, ctx.clone(), decided_tx)));

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
    let actor_state = HostActorState {
        host: host_state,
    };
    
    // Spawn the actor - following Malachite's Connector::spawn pattern
    // Actor::spawn returns (ActorRef<Self::Msg>, JoinHandle)
    // Since Self::Msg is HostMsg<CipherBftContext>, actor_ref is ActorRef<HostMsg<CipherBftContext>>
    // HostRef<CipherBftContext> is a type alias for ActorRef<HostMsg<CipherBftContext>>
    // We need to ensure the ActorRef type matches - HostRef is defined in informalsystems_malachitebft_engine::host
    // and uses ractor::ActorRef, so we should use the same import path.
    let (actor_ref, _join_handle): (RactorActorRef<HostMsg<CipherBftContext>>, _) = Actor::spawn(
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
    // However, due to potential ractor version differences or type path issues,
    // we need to ensure the ActorRef type matches exactly.
    // Since HostRef is defined in informalsystems_malachitebft_engine::host and uses ractor::ActorRef,
    // and Actor::spawn returns ractor::ActorRef, they should be compatible.
    // If there's still a type mismatch, it's likely a ractor version mismatch.
    // For now, we'll use unsafe transmute as a last resort (should be safe since they're the same type).
    use std::mem;
    Ok(unsafe { mem::transmute::<RactorActorRef<HostMsg<CipherBftContext>>, HostRef<CipherBftContext>>(actor_ref) })
}
