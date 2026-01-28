//! CipherBFT Host Actor for Malachite consensus.
//!
//! The Host actor bridges the consensus engine and application logic,
//! handling messages like validator set queries, value building, and
//! decision processing.
//!
//! ## Key Responsibilities
//!
//! 1. **Validator Set Queries**: Return the correct validator set for each height,
//!    supporting dynamic validator set changes across epochs.
//! 2. **Value Building**: Build Cut proposals for consensus.
//! 3. **Decision Processing**: Handle finalized decisions and persist them.
//! 4. **Sync Support**: Provide historical values for node synchronization.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use informalsystems_malachitebft_app::streaming::StreamContent;
use informalsystems_malachitebft_app::types::ProposedValue;
use informalsystems_malachitebft_core_consensus::LocallyProposedValue;
use informalsystems_malachitebft_core_types::{CommitCertificate, Round, Validity};
use informalsystems_malachitebft_engine::host::{HostMsg, HostRef, Next};
use informalsystems_malachitebft_engine::network::{NetworkMsg, NetworkRef};
use informalsystems_malachitebft_engine::util::streaming::{StreamId, StreamMessage};
use informalsystems_malachitebft_sync::RawDecidedValue;
use ractor::{async_trait as ractor_async_trait, Actor, ActorProcessingErr, ActorRef};
use tokio::sync::{mpsc, Notify, RwLock};
use tracing::{debug, error, info, trace, warn};

use crate::context::CipherBftContext;
use crate::error::ConsensusError;
use crate::proposal::CutProposalPart;
use crate::types::{ConsensusHeight, ConsensusRound, ConsensusValue, ConsensusValueId};
use crate::validator_set::{ConsensusAddress, ConsensusValidatorSet};
use crate::validator_set_manager::{EpochConfig, ValidatorSetManager};
use cipherbft_data_chain::Cut;
use cipherbft_types::ValidatorId;

/// Configuration for the Host actor.
#[derive(Debug, Clone)]
pub struct HostConfig {
    /// Maximum number of proposal parts to buffer.
    pub max_proposal_parts: usize,

    /// Whether to enable strict validator set validation.
    pub strict_validator_checks: bool,

    /// Number of heights to retain pending cuts (default: 10).
    ///
    /// Higher values allow more buffer for slow consensus rounds,
    /// at the cost of increased memory usage.
    pub pending_cuts_retention: usize,

    /// Number of decisions to retain for history queries (default: 100).
    ///
    /// Higher values support longer sync windows for lagging nodes,
    /// at the cost of increased memory usage.
    pub decided_retention: usize,
}

impl Default for HostConfig {
    fn default() -> Self {
        Self {
            max_proposal_parts: 100,
            strict_validator_checks: true,
            pending_cuts_retention: 10,
            decided_retention: 100,
        }
    }
}

/// Handler for building proposal values.
///
/// Implement this trait to provide application-specific value building logic.
#[async_trait]
pub trait ValueBuilder: Send + Sync + 'static {
    /// Build a new proposal value for the given height and round.
    ///
    /// Called when this node is the proposer for a round.
    async fn build_value(
        &self,
        height: ConsensusHeight,
        round: ConsensusRound,
    ) -> Result<LocallyProposedValue<CipherBftContext>, ConsensusError>;

    /// Restream an existing proposal value.
    ///
    /// Called during sync when a peer requests a value we already have.
    /// The `value_id` is used to look up the actual value from storage.
    /// Unlike other handlers, this doesn't return a reply - it should
    /// re-publish proposal parts directly via the network channel.
    async fn restream_value(
        &self,
        height: ConsensusHeight,
        round: ConsensusRound,
        value_id: ConsensusValueId,
    ) -> Result<(), ConsensusError>;

    /// Get a value by its ID.
    ///
    /// Called when consensus decides on a value and we need to look up
    /// the actual value content from the value_id in the commit certificate.
    ///
    /// # Returns
    ///
    /// The `ConsensusValue` if found, or `None` if the value is not in the cache.
    async fn get_value_by_id(&self, value_id: &ConsensusValueId) -> Option<ConsensusValue>;

    /// Store a received proposal value.
    ///
    /// Called when this node receives a proposal from another validator.
    /// The value is stored so it can be retrieved later when consensus decides.
    /// This enables non-proposer nodes to process the decision correctly.
    async fn store_received_value(&self, value_id: ConsensusValueId, value: ConsensusValue);

    /// Wait for a cut to be available at the specified height.
    ///
    /// Called after a decision is made to ensure the next height's cut is ready
    /// before starting the next consensus round. This prevents a race condition
    /// where consensus starts requesting a value before the cut is stored.
    ///
    /// # Arguments
    /// * `height` - The height to wait for
    /// * `timeout` - Maximum time to wait
    ///
    /// # Returns
    /// * `true` if the cut is available
    /// * `false` if the timeout expired before the cut was available
    async fn wait_for_cut(&self, height: ConsensusHeight, timeout: std::time::Duration) -> bool;
}

/// Handler for processing decided values.
///
/// Implement this trait to handle consensus decisions.
#[async_trait]
pub trait DecisionHandler: Send + Sync + 'static {
    /// Called when consensus decides on a value.
    ///
    /// The implementation should persist the decision and update state.
    async fn on_decided(
        &self,
        height: ConsensusHeight,
        round: ConsensusRound,
        value: ConsensusValue,
        certificate: CommitCertificate<CipherBftContext>,
    ) -> Result<(), ConsensusError>;

    /// Get a previously decided value as raw bytes.
    ///
    /// Returns `None` if the value is not found.
    async fn get_decided_value(
        &self,
        height: ConsensusHeight,
    ) -> Result<Option<RawDecidedValue<CipherBftContext>>, ConsensusError>;

    /// Get the minimum height available in history.
    async fn get_history_min_height(&self) -> Result<ConsensusHeight, ConsensusError>;
}

/// The CipherBFT Host actor implementation.
///
/// This actor handles all `HostMsg` messages from the Malachite consensus engine,
/// with special focus on supporting dynamic validator set changes.
///
/// ## Dynamic Validator Sets
///
/// The host uses `ValidatorSetManager` to return the appropriate validator set
/// for each height based on epoch boundaries. This enables:
///
/// - Validator rotation at epoch boundaries
/// - Historical validator set queries for sync
/// - Pending validator set changes
pub struct CipherBftHost {
    /// Validator set manager for epoch-based validator sets.
    validator_set_manager: Arc<ValidatorSetManager>,

    /// Handler for building proposal values.
    value_builder: Arc<dyn ValueBuilder>,

    /// Handler for processing decisions.
    decision_handler: Arc<dyn DecisionHandler>,

    /// Host configuration.
    config: HostConfig,

    /// Tracing span for this actor.
    span: tracing::Span,
}

impl CipherBftHost {
    /// Create a new CipherBFT Host.
    ///
    /// # Arguments
    ///
    /// * `validator_set_manager` - Manager for dynamic validator sets
    /// * `value_builder` - Handler for building proposal values
    /// * `decision_handler` - Handler for processing decisions
    /// * `config` - Host configuration
    /// * `span` - Tracing span
    pub fn new(
        validator_set_manager: Arc<ValidatorSetManager>,
        value_builder: Arc<dyn ValueBuilder>,
        decision_handler: Arc<dyn DecisionHandler>,
        config: HostConfig,
        span: tracing::Span,
    ) -> Self {
        Self {
            validator_set_manager,
            value_builder,
            decision_handler,
            config,
            span,
        }
    }

    /// Get the validator set for a specific height.
    ///
    /// This method delegates to `ValidatorSetManager` to return the
    /// appropriate validator set based on the epoch the height falls into.
    pub fn get_validator_set(
        &self,
        height: ConsensusHeight,
    ) -> Result<ConsensusValidatorSet, ConsensusError> {
        self.validator_set_manager
            .get_validator_set_for_height(height)?
            .ok_or(ConsensusError::ValidatorSetNotFound { height: height.0 })
    }

    /// Notify the host that a block has been committed.
    ///
    /// This may trigger an epoch transition if the height is at an epoch boundary.
    ///
    /// # Returns
    ///
    /// `true` if an epoch transition occurred.
    pub fn on_block_committed(&self, height: ConsensusHeight) -> Result<bool, ConsensusError> {
        self.validator_set_manager.on_block_committed(height)
    }

    /// Get the current epoch number.
    pub fn current_epoch(&self) -> u64 {
        self.validator_set_manager.current_epoch()
    }

    /// Check if a validator set change is pending.
    pub fn has_pending_validator_change(&self) -> bool {
        self.validator_set_manager.has_pending_change()
    }

    /// Get a reference to the validator set manager.
    pub fn validator_set_manager(&self) -> &Arc<ValidatorSetManager> {
        &self.validator_set_manager
    }
}

impl std::fmt::Debug for CipherBftHost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CipherBftHost")
            .field("current_epoch", &self.current_epoch())
            .field("has_pending_change", &self.has_pending_validator_change())
            .field("config", &self.config)
            .finish()
    }
}

/// Arguments passed when spawning the host actor.
pub struct HostArgs {
    /// Validator set manager for dynamic validator sets.
    pub validator_set_manager: Arc<ValidatorSetManager>,

    /// Handler for building proposal values.
    pub value_builder: Arc<dyn ValueBuilder>,

    /// Handler for processing decisions.
    pub decision_handler: Arc<dyn DecisionHandler>,

    /// Host configuration.
    pub config: HostConfig,
}

/// State maintained by the host actor.
#[derive(Default)]
pub struct HostState {
    /// Current height being processed.
    current_height: Option<ConsensusHeight>,
}

/// Ractor Actor implementation for CipherBftHost.
#[ractor_async_trait]
impl Actor for CipherBftHost {
    type Msg = HostMsg<CipherBftContext>;
    type State = HostState;
    type Arguments = HostArgs;

    async fn pre_start(
        &self,
        _myself: ActorRef<Self::Msg>,
        _args: Self::Arguments,
    ) -> Result<Self::State, ActorProcessingErr> {
        info!(
            parent: &self.span,
            epoch = self.current_epoch(),
            "CipherBFT Host actor starting"
        );
        Ok(HostState::default())
    }

    async fn handle(
        &self,
        _myself: ActorRef<Self::Msg>,
        msg: Self::Msg,
        state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        match msg {
            HostMsg::ConsensusReady { reply_to } => {
                info!(parent: &self.span, "Consensus ready, returning initial height and validator set");

                // Get the validator set for height 1 (genesis)
                let height = ConsensusHeight(1);
                match self.get_validator_set(height) {
                    Ok(validator_set) => {
                        if reply_to.send((height, validator_set)).is_err() {
                            warn!(parent: &self.span, "Failed to send ConsensusReady reply");
                        }
                    }
                    Err(e) => {
                        error!(parent: &self.span, error = %e, "Failed to get initial validator set");
                    }
                }
            }

            HostMsg::StartedRound {
                height,
                round,
                proposer,
                role,
                reply_to,
            } => {
                debug!(
                    parent: &self.span,
                    height = height.0,
                    round = round.as_i64(),
                    proposer = %proposer,
                    role = ?role,
                    "Started round"
                );

                state.current_height = Some(height);

                // Reply with empty vec - no undecided values to replay
                // In a full implementation, this would check WAL for uncommitted proposals
                if reply_to.send(vec![]).is_err() {
                    warn!(parent: &self.span, "Failed to send StartedRound reply");
                }
            }

            HostMsg::GetValue {
                height,
                round,
                timeout,
                reply_to,
            } => {
                debug!(
                    parent: &self.span,
                    height = height.0,
                    round = round.as_i64(),
                    timeout = ?timeout,
                    "Building proposal value (spawning background task)"
                );

                // CRITICAL: Spawn build_value in a background task to avoid blocking the Host actor.
                // If we await build_value directly (which has a 30-second timeout), the Host actor
                // cannot process other messages like StartedRound. This causes a deadlock where:
                // 1. Consensus sends GetValue, Host blocks on build_value
                // 2. Propose timeout fires, Consensus moves to next round
                // 3. Consensus sends StartedRound (synchronous ractor::call!), blocks waiting for Host
                // 4. Host is still blocked on build_value from the previous round
                // 5. Both actors are stuck until build_value times out (~30 seconds per round)
                //
                // By spawning a background task, the Host actor can continue processing other messages
                // while build_value runs asynchronously.
                let value_builder = self.value_builder.clone();
                let span = self.span.clone();

                tokio::spawn(async move {
                    match value_builder.build_value(height, round).await {
                        Ok(value) => {
                            debug!(
                                parent: &span,
                                height = height.0,
                                "Built proposal value"
                            );
                            if reply_to.send(value).is_err() {
                                warn!(parent: &span, "Failed to send GetValue reply");
                            }
                        }
                        Err(e) => {
                            error!(
                                parent: &span,
                                height = height.0,
                                error = %e,
                                "Failed to build proposal value"
                            );
                            // Note: Not replying when build fails is intentional.
                            // The propose timeout will fire and consensus will move forward.
                        }
                    }
                });
            }

            HostMsg::ReceivedProposalPart {
                from,
                part,
                reply_to,
            } => {
                trace!(
                    parent: &self.span,
                    from = %from,
                    "Received proposal part"
                );

                // Extract the CutProposalPart from the StreamMessage
                match part.content {
                    StreamContent::Data(proposal_part) => {
                        // For single-part proposals (ProposalOnly mode), the part contains
                        // the complete proposal with first=true and last=true.
                        if proposal_part.first && proposal_part.last {
                            let height = proposal_part.height;
                            let round = proposal_part.round;
                            let valid_round = proposal_part.valid_round;
                            let proposer = proposal_part.proposer;
                            let value = ConsensusValue(proposal_part.cut);

                            debug!(
                                parent: &self.span,
                                from = %from,
                                height = height.0,
                                round = %round,
                                valid_round = %valid_round,
                                proposer = %proposer,
                                "Assembled complete proposal from single part"
                            );

                            // Store the received value so it can be found when consensus decides.
                            // Without this, non-proposer nodes can't process decisions because
                            // get_value_by_id() would return None.
                            let value_id =
                                informalsystems_malachitebft_core_types::Value::id(&value);
                            self.value_builder
                                .store_received_value(value_id, value.clone())
                                .await;

                            // Build ProposedValue for the received proposal
                            // Use the actual valid_round from the proposal (Round::Nil for fresh
                            // proposals, or the POL round for re-proposals)
                            let proposed_value = ProposedValue {
                                height,
                                round,
                                valid_round,
                                proposer,
                                value,
                                validity: Validity::Valid,
                            };

                            // Send the assembled proposal back to the consensus engine
                            if reply_to.send(proposed_value).is_err() {
                                warn!(
                                    parent: &self.span,
                                    "Failed to send ProposedValue reply"
                                );
                            }
                        } else {
                            // Multi-part proposal handling would go here.
                            // For now, we only support single-part proposals (ProposalOnly mode).
                            warn!(
                                parent: &self.span,
                                from = %from,
                                first = proposal_part.first,
                                last = proposal_part.last,
                                "Received multi-part proposal, but only single-part is supported"
                            );
                        }
                    }
                    StreamContent::Fin => {
                        // End-of-stream marker - no action needed for single-part proposals
                        trace!(
                            parent: &self.span,
                            from = %from,
                            "Received proposal stream Fin marker"
                        );
                    }
                }
            }

            HostMsg::GetValidatorSet { height, reply_to } => {
                trace!(
                    parent: &self.span,
                    height = height.0,
                    "Getting validator set for height"
                );

                match self.get_validator_set(height) {
                    Ok(set) => {
                        trace!(
                            parent: &self.span,
                            height = height.0,
                            epoch = self.validator_set_manager.config().epoch_for_height(height),
                            validators = set.len(),
                            "Returning validator set for height"
                        );
                        // HostMsg::GetValidatorSet expects Option<ValidatorSet>
                        if reply_to.send(Some(set)).is_err() {
                            warn!(parent: &self.span, "Failed to send GetValidatorSet reply");
                        }
                    }
                    Err(e) => {
                        error!(
                            parent: &self.span,
                            height = height.0,
                            error = %e,
                            "Failed to get validator set"
                        );
                    }
                }
            }

            HostMsg::Decided {
                certificate,
                extensions: _,
                reply_to,
            } => {
                let height = certificate.height;
                let round = certificate.round;
                let value_id = certificate.value_id.clone();

                info!(
                    parent: &self.span,
                    height = height.0,
                    round = round.as_i64(),
                    epoch = self.validator_set_manager.config().epoch_for_height(height),
                    "Consensus decided on value"
                );

                // Look up the actual value from value_id and call decision handler
                match self.value_builder.get_value_by_id(&value_id).await {
                    Some(value) => {
                        if let Err(e) = self
                            .decision_handler
                            .on_decided(height, round, value, certificate.clone())
                            .await
                        {
                            error!(
                                parent: &self.span,
                                height = height.0,
                                error = %e,
                                "Failed to process decided value"
                            );
                        }
                    }
                    None => {
                        error!(
                            parent: &self.span,
                            height = height.0,
                            value_id = ?value_id,
                            "Could not find decided value by value_id - decision will not be processed"
                        );
                    }
                }

                // Check for epoch transition
                let _epoch_transition = match self.on_block_committed(height) {
                    Ok(true) => {
                        info!(
                            parent: &self.span,
                            height = height.0,
                            new_epoch = self.current_epoch(),
                            "Epoch transition occurred"
                        );
                        true
                    }
                    Ok(false) => false,
                    Err(e) => {
                        error!(
                            parent: &self.span,
                            height = height.0,
                            error = %e,
                            "Error during epoch transition check"
                        );
                        false
                    }
                };

                // Reply with the next height to start
                let next_height = height.next();

                // CRITICAL: Wait for the next cut to be available before starting next height.
                //
                // This fixes a race condition where:
                // 1. on_decided() sends the decision to the node's event loop
                // 2. We immediately reply with Next::Start(next_height)
                // 3. Malachite starts next_height and requests a value
                // 4. But the node hasn't processed the decision yet, so no Cut exists
                // 5. ChannelValueBuilder times out waiting for Cut, validators vote NIL
                //
                // By waiting here, we ensure the node has processed the decision and
                // Primary has formed the next Cut before consensus starts requesting it.
                //
                // Timeout of 500ms should be sufficient for the node to process the
                // decision and form the Cut. If it times out, consensus will still
                // start but may vote NIL on the first round.
                let wait_timeout = std::time::Duration::from_millis(500);
                if !self
                    .value_builder
                    .wait_for_cut(next_height, wait_timeout)
                    .await
                {
                    warn!(
                        parent: &self.span,
                        next_height = next_height.0,
                        "Cut not ready for next height after {:?}, proceeding anyway",
                        wait_timeout
                    );
                }

                match self.get_validator_set(next_height) {
                    Ok(validator_set) => {
                        // Instruct consensus to start the next height
                        let next = Next::Start(next_height, validator_set);
                        if reply_to.send(next).is_err() {
                            warn!(parent: &self.span, "Failed to send Decided reply");
                        }
                    }
                    Err(e) => {
                        error!(
                            parent: &self.span,
                            next_height = next_height.0,
                            error = %e,
                            "Failed to get validator set for next height, restarting current"
                        );
                        // If we can't get the next validator set, try to restart
                        if let Ok(current_set) = self.get_validator_set(height) {
                            let next = Next::Restart(height, current_set);
                            if reply_to.send(next).is_err() {
                                warn!(parent: &self.span, "Failed to send Decided restart reply");
                            }
                        }
                    }
                }
            }

            HostMsg::GetDecidedValue { height, reply_to } => {
                trace!(
                    parent: &self.span,
                    height = height.0,
                    "Getting decided value"
                );

                match self.decision_handler.get_decided_value(height).await {
                    Ok(value) => {
                        trace!(
                            parent: &self.span,
                            height = height.0,
                            found = value.is_some(),
                            "Retrieved decided value"
                        );
                        if reply_to.send(value).is_err() {
                            warn!(parent: &self.span, "Failed to send GetDecidedValue reply");
                        }
                    }
                    Err(e) => {
                        error!(
                            parent: &self.span,
                            height = height.0,
                            error = %e,
                            "Failed to get decided value"
                        );
                        if reply_to.send(None).is_err() {
                            warn!(parent: &self.span, "Failed to send GetDecidedValue error reply");
                        }
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
                    parent: &self.span,
                    height = height.0,
                    round = round.as_i64(),
                    bytes_len = value_bytes.len(),
                    proposer = %proposer,
                    "Processing synced value"
                );

                // Attempt to decode the synced value
                // The value_bytes are bincode-encoded Cut from get_decided_value
                match bincode::deserialize::<Cut>(&value_bytes) {
                    Ok(cut) => {
                        let value = ConsensusValue(cut);
                        debug!(
                            parent: &self.span,
                            height = height.0,
                            "Successfully decoded synced value"
                        );

                        // Store the value so it can be retrieved when consensus decides
                        let value_id = informalsystems_malachitebft_core_types::Value::id(&value);
                        self.value_builder
                            .store_received_value(value_id, value.clone())
                            .await;

                        info!(
                            parent: &self.span,
                            height = height.0,
                            round = round.as_i64(),
                            "Synced value processed and stored"
                        );

                        // Build ProposedValue for the synced value
                        // Synced values use Round::Nil for valid_round since they come from
                        // committed blocks, not from in-progress consensus rounds
                        let proposed_value = ProposedValue {
                            height,
                            round,
                            valid_round: Round::Nil,
                            proposer,
                            value,
                            validity: Validity::Valid,
                        };

                        // Reply to the consensus engine
                        if reply_to.send(proposed_value).is_err() {
                            warn!(
                                parent: &self.span,
                                height = height.0,
                                "Failed to send ProcessSyncedValue reply"
                            );
                        }
                    }
                    Err(e) => {
                        warn!(
                            parent: &self.span,
                            height = height.0,
                            error = %e,
                            "Failed to decode synced value - cannot reply"
                        );
                        // Note: We cannot reply with None because the channel expects ProposedValue.
                        // The consensus engine will timeout and potentially retry from another peer.
                    }
                }
            }

            HostMsg::RestreamValue {
                height,
                round,
                valid_round,
                address,
                value_id,
            } => {
                debug!(
                    parent: &self.span,
                    height = height.0,
                    round = round.as_i64(),
                    valid_round = valid_round.as_i64(),
                    proposer = %address,
                    "Restreaming value"
                );

                // RestreamValue has no reply_to - the app must re-publish proposal
                // parts directly via the network channel.
                // The `round` from HostMsg is already a Round type (aliased as ConsensusRound)
                // value_id is ValueId<Ctx> which is ConsensusValueId
                if let Err(e) = self
                    .value_builder
                    .restream_value(height, round, value_id)
                    .await
                {
                    error!(
                        parent: &self.span,
                        height = height.0,
                        error = %e,
                        "Failed to restream value"
                    );
                }
            }

            HostMsg::GetHistoryMinHeight { reply_to } => {
                match self.decision_handler.get_history_min_height().await {
                    Ok(height) => {
                        if reply_to.send(height).is_err() {
                            warn!(parent: &self.span, "Failed to send GetHistoryMinHeight reply");
                        }
                    }
                    Err(e) => {
                        error!(parent: &self.span, error = %e, "Failed to get history min height");
                        if reply_to.send(ConsensusHeight(1)).is_err() {
                            warn!(parent: &self.span, "Failed to send GetHistoryMinHeight fallback reply");
                        }
                    }
                }
            }

            HostMsg::ExtendVote {
                height,
                round,
                value_id: _,
                reply_to,
            } => {
                trace!(
                    parent: &self.span,
                    height = height.0,
                    round = round.as_i64(),
                    "Extending vote"
                );
                // No vote extension for now
                if reply_to.send(None).is_err() {
                    warn!(parent: &self.span, "Failed to send ExtendVote reply");
                }
            }

            HostMsg::VerifyVoteExtension {
                height,
                round,
                value_id: _,
                extension: _,
                reply_to,
            } => {
                trace!(
                    parent: &self.span,
                    height = height.0,
                    round = round.as_i64(),
                    "Verifying vote extension"
                );
                // Accept all vote extensions for now
                if reply_to.send(Ok(())).is_err() {
                    warn!(parent: &self.span, "Failed to send VerifyVoteExtension reply");
                }
            }
        }

        Ok(())
    }
}

/// Spawn the Host actor and return a reference.
///
/// # Arguments
///
/// * `validator_set_manager` - Manager for dynamic validator sets
/// * `value_builder` - Handler for building proposal values
/// * `decision_handler` - Handler for processing decisions
/// * `config` - Host configuration
/// * `span` - Tracing span
///
/// # Returns
///
/// A `HostRef<CipherBftContext>` for sending messages to the host.
pub async fn spawn_host_actor(
    validator_set_manager: Arc<ValidatorSetManager>,
    value_builder: Arc<dyn ValueBuilder>,
    decision_handler: Arc<dyn DecisionHandler>,
    config: HostConfig,
    span: tracing::Span,
) -> Result<HostRef<CipherBftContext>, ConsensusError> {
    let host = CipherBftHost::new(
        validator_set_manager.clone(),
        value_builder.clone(),
        decision_handler.clone(),
        config.clone(),
        span.clone(),
    );

    let args = HostArgs {
        validator_set_manager,
        value_builder,
        decision_handler,
        config,
    };

    let (actor_ref, _) = Actor::spawn(None, host, args)
        .await
        .map_err(|e| ConsensusError::HostSpawnError(e.to_string()))?;

    info!(parent: &span, "Host actor spawned");
    Ok(actor_ref)
}

// ============================================================================
// Backward-Compatibility Layer
// ============================================================================

/// Channel-based value builder for backward compatibility.
///
/// This adapter implements `ValueBuilder` by receiving cuts from a channel.
/// In `ProposalAndParts` mode, it also publishes proposal parts to the network.
pub struct ChannelValueBuilder {
    /// Pending cuts by height (waiting for consensus to request)
    pending_cuts: Arc<RwLock<HashMap<ConsensusHeight, Cut>>>,
    /// Cuts by value_id (for finding cuts from certificates)
    cuts_by_value_id: Arc<RwLock<HashMap<ConsensusValueId, Cut>>>,
    /// Notifier for when new cuts are stored
    cut_notify: Arc<Notify>,
    /// Number of heights to retain pending cuts
    pending_cuts_retention: usize,
    /// Network reference for publishing proposal parts
    network: Option<NetworkRef<CipherBftContext>>,
    /// Our own address (for creating proposal parts)
    our_address: Option<ConsensusAddress>,
}

impl Default for ChannelValueBuilder {
    fn default() -> Self {
        Self::new(10) // Default retention of 10 heights
    }
}

impl ChannelValueBuilder {
    /// Create a new channel-based value builder.
    ///
    /// # Arguments
    /// * `pending_cuts_retention` - Number of heights to retain pending cuts
    pub fn new(pending_cuts_retention: usize) -> Self {
        Self {
            pending_cuts: Arc::new(RwLock::new(HashMap::new())),
            cuts_by_value_id: Arc::new(RwLock::new(HashMap::new())),
            cut_notify: Arc::new(Notify::new()),
            pending_cuts_retention,
            network: None,
            our_address: None,
        }
    }

    /// Set the network reference for publishing proposal parts.
    ///
    /// This enables `ProposalAndParts` mode where the proposer publishes
    /// proposal parts to the network, allowing non-proposers to receive
    /// and store the proposal values.
    pub fn with_network(
        mut self,
        network: NetworkRef<CipherBftContext>,
        our_address: ConsensusAddress,
    ) -> Self {
        self.network = Some(network);
        self.our_address = Some(our_address);
        self
    }

    /// Publish proposal parts to the network.
    ///
    /// Creates a single-part proposal and sends it via the network actor.
    /// This is called after building a value when in `ProposalAndParts` mode.
    async fn publish_proposal_parts(
        &self,
        height: ConsensusHeight,
        round: ConsensusRound,
        cut: &Cut,
    ) {
        let Some(network) = &self.network else {
            // No network configured - skip publishing (ProposalOnly mode)
            return;
        };
        let Some(our_address) = &self.our_address else {
            warn!("ChannelValueBuilder: No our_address set, cannot publish proposal parts");
            return;
        };

        // Create a unique stream ID based on height and round
        let stream_id_bytes = format!("{}:{}", height.0, round.as_u32().unwrap_or(0));
        let stream_id = StreamId::new(bytes::Bytes::from(stream_id_bytes));

        // Create the proposal part (single-part proposal with first=true, last=true)
        // valid_round is Round::Nil for fresh proposals (not re-proposals)
        let proposal_part = CutProposalPart::single(
            height,
            round,
            Round::Nil, // Fresh proposal, not a re-proposal
            *our_address,
            cut.clone(),
        );

        // Send the Data message (sequence 0)
        let data_msg = StreamMessage::new(
            stream_id.clone(),
            0, // First message in stream
            StreamContent::Data(proposal_part),
        );

        if let Err(e) = network.cast(NetworkMsg::PublishProposalPart(data_msg)) {
            error!("Failed to publish proposal part Data: {:?}", e);
            return;
        }

        // Send the Fin message (sequence 1)
        let fin_msg: StreamMessage<CutProposalPart> = StreamMessage::new(
            stream_id,
            1, // Second message in stream
            StreamContent::Fin,
        );

        if let Err(e) = network.cast(NetworkMsg::PublishProposalPart(fin_msg)) {
            error!("Failed to publish proposal part Fin: {:?}", e);
        }

        debug!(
            "ChannelValueBuilder: Published proposal parts for height {} round {}",
            height.0,
            round.as_u32().unwrap_or(0)
        );
    }

    /// Store a cut for consensus requests.
    ///
    /// The cut is stored by its consensus height and can be retrieved by
    /// `build_value()` when consensus requests a proposal for that height.
    pub async fn store_cut(&self, height: ConsensusHeight, cut: Cut) {
        // Log the cut being stored with diagnostic info
        let cut_dcl_height = cut.height;

        // Check for height mismatch between consensus height and DCL cut height
        if height.0 != cut_dcl_height {
            warn!(
                "ChannelValueBuilder: Height mismatch - storing cut at consensus height {} \
                 but cut's DCL height is {}. This may indicate DCL/consensus synchronization issues.",
                height.0, cut_dcl_height
            );
        }

        debug!(
            "ChannelValueBuilder: Storing Cut for consensus height {} (DCL height: {}) with {} cars",
            height.0,
            cut_dcl_height,
            cut.cars.len()
        );

        {
            let mut pending = self.pending_cuts.write().await;

            // Log if we're overwriting an existing cut (shouldn't happen normally)
            if pending.contains_key(&height) {
                warn!(
                    "ChannelValueBuilder: Overwriting existing cut at height {}. \
                     This may indicate duplicate cut production.",
                    height.0
                );
            }

            pending.insert(height, cut.clone());

            // Log available heights for debugging
            let available: Vec<u64> = pending.keys().map(|h| h.0).collect();
            trace!(
                "ChannelValueBuilder: Pending cuts available at heights: {:?}",
                available
            );
        }

        // Clean up old pending cuts (keep only last N heights based on config)
        let retention = self.pending_cuts_retention;
        let mut pending = self.pending_cuts.write().await;
        if pending.len() > retention {
            let heights: Vec<_> = pending.keys().cloned().collect();
            let max_height = heights.iter().max().copied().unwrap_or(height);
            let cutoff = max_height.0.saturating_sub(retention as u64);
            let removed_count = pending.len();
            pending.retain(|h, _| h.0 >= cutoff);
            let removed = removed_count - pending.len();
            if removed > 0 {
                debug!(
                    "ChannelValueBuilder: Cleaned up {} old cuts, retaining heights >= {}",
                    removed, cutoff
                );
            }
        }

        // Notify any waiters
        self.cut_notify.notify_waiters();
    }

    /// Get a snapshot of available pending cut heights.
    ///
    /// Useful for debugging height synchronization issues.
    pub async fn available_heights(&self) -> Vec<u64> {
        let pending = self.pending_cuts.read().await;
        let mut heights: Vec<u64> = pending.keys().map(|h| h.0).collect();
        heights.sort_unstable();
        heights
    }
}

#[async_trait]
impl ValueBuilder for ChannelValueBuilder {
    async fn build_value(
        &self,
        height: ConsensusHeight,
        round: ConsensusRound,
    ) -> Result<LocallyProposedValue<CipherBftContext>, ConsensusError> {
        // Wait for a cut at this height with timeout
        let timeout = Duration::from_secs(30);
        let start = std::time::Instant::now();
        let mut logged_waiting = false;

        loop {
            // Check if we have a cut
            // NOTE: We use get() instead of remove() to keep the cut available for
            // potential re-proposals in different rounds. Without this, if consensus
            // moves to a new round (e.g., due to timeouts) and asks for the same height
            // again, the cut would already be gone. The cut will be cleaned up by the
            // retention logic when newer heights arrive.
            {
                let pending = self.pending_cuts.read().await;
                if let Some(cut) = pending.get(&height).cloned() {
                    let value = ConsensusValue::from(cut.clone());
                    let value_id = informalsystems_malachitebft_core_types::Value::id(&value);

                    debug!(
                        "ChannelValueBuilder: Found cut for height {}, building proposal",
                        height.0
                    );

                    // Store by value_id for later lookup
                    self.cuts_by_value_id
                        .write()
                        .await
                        .insert(value_id.clone(), cut.clone());

                    // Publish proposal parts to the network for non-proposers to receive.
                    // This enables ProposalAndParts mode where non-proposers can store
                    // received values via ReceivedProposalPart handler.
                    self.publish_proposal_parts(height, round, &cut).await;

                    return Ok(LocallyProposedValue::new(height, round, value));
                }

                // Log available heights on first wait (helpful for debugging)
                if !logged_waiting {
                    let available: Vec<u64> = pending.keys().map(|h| h.0).collect();
                    if available.is_empty() {
                        debug!(
                            "ChannelValueBuilder: Waiting for cut at height {}. \
                             No cuts currently available.",
                            height.0
                        );
                    } else {
                        debug!(
                            "ChannelValueBuilder: Waiting for cut at height {}. \
                             Available heights: {:?}",
                            height.0, available
                        );
                    }
                    logged_waiting = true;
                }
            }

            // Check timeout
            if start.elapsed() > timeout {
                // Provide detailed error message for debugging
                let available = self.available_heights().await;
                let closest = if available.is_empty() {
                    "none".to_string()
                } else {
                    // Find the closest available height
                    let closest_height = available
                        .iter()
                        .min_by_key(|h| (**h as i64 - height.0 as i64).abs())
                        .copied()
                        .unwrap_or(0);
                    format!("{} (available: {:?})", closest_height, available)
                };

                return Err(ConsensusError::Other(format!(
                    "Timeout waiting for cut at height {} after {:?}. \
                     Closest available height: {}. \
                     This indicates DCL may be behind consensus or cuts are not being produced. \
                     Check DCL primary logs for batch/attestation activity.",
                    height.0, timeout, closest
                )));
            }

            // Log progress periodically (every 5 seconds)
            let elapsed = start.elapsed();
            if elapsed.as_secs() > 0 && elapsed.as_secs().is_multiple_of(5) {
                let available = self.available_heights().await;
                warn!(
                    "ChannelValueBuilder: Still waiting for cut at height {} ({:?} elapsed). \
                     Available heights: {:?}",
                    height.0, elapsed, available
                );
            }

            // Wait for notification or timeout
            tokio::select! {
                _ = self.cut_notify.notified() => {}
                _ = tokio::time::sleep(Duration::from_millis(100)) => {}
            }
        }
    }

    async fn restream_value(
        &self,
        height: ConsensusHeight,
        round: ConsensusRound,
        value_id: ConsensusValueId,
    ) -> Result<(), ConsensusError> {
        // Look up the cut by value_id and re-publish it
        let cut_opt = {
            let cuts = self.cuts_by_value_id.read().await;
            cuts.get(&value_id).cloned()
        };

        if let Some(cut) = cut_opt {
            debug!(
                "ChannelValueBuilder: Restreaming value for height {} round {}",
                height.0,
                round.as_u32().unwrap_or(0)
            );
            self.publish_proposal_parts(height, round, &cut).await;
        } else {
            warn!(
                "ChannelValueBuilder: Cannot restream value - not found for value_id {:?}",
                value_id
            );
        }
        Ok(())
    }

    async fn get_value_by_id(&self, value_id: &ConsensusValueId) -> Option<ConsensusValue> {
        let cuts = self.cuts_by_value_id.read().await;
        cuts.get(value_id)
            .map(|cut| ConsensusValue::from(cut.clone()))
    }

    async fn store_received_value(&self, value_id: ConsensusValueId, value: ConsensusValue) {
        let cut = value.0;
        debug!(
            "ChannelValueBuilder: Storing received value for height {}, value_id={:?}",
            cut.height, value_id
        );
        self.cuts_by_value_id.write().await.insert(value_id, cut);
    }

    async fn wait_for_cut(&self, height: ConsensusHeight, timeout: std::time::Duration) -> bool {
        let start = std::time::Instant::now();

        loop {
            // Check if we have a cut at this height
            {
                let pending = self.pending_cuts.read().await;
                if pending.contains_key(&height) {
                    debug!(
                        "ChannelValueBuilder: Cut available at height {} (waited {:?})",
                        height.0,
                        start.elapsed()
                    );
                    return true;
                }
            }

            // Check timeout
            if start.elapsed() > timeout {
                let available = self.available_heights().await;
                warn!(
                    "ChannelValueBuilder: Timeout waiting for cut at height {} after {:?}. \
                     Available heights: {:?}",
                    height.0, timeout, available
                );
                return false;
            }

            // Wait for notification or short sleep
            tokio::select! {
                _ = self.cut_notify.notified() => {}
                _ = tokio::time::sleep(Duration::from_millis(10)) => {}
            }
        }
    }
}

/// Type alias for the decided cuts storage (cut + commit certificate by height).
type DecidedCutsMap =
    Arc<RwLock<HashMap<ConsensusHeight, (Cut, CommitCertificate<CipherBftContext>)>>>;

/// Channel-based decision handler for backward compatibility.
///
/// This adapter implements `DecisionHandler` by sending decisions to a channel.
/// When a `DclStore` is provided, decisions are persisted to storage for durability
/// and sync support across node restarts.
pub struct ChannelDecisionHandler {
    /// Channel to send decided events
    decided_tx: Option<mpsc::Sender<(ConsensusHeight, Cut)>>,
    /// Decided cuts by height (for history queries - in-memory cache)
    decided_cuts: DecidedCutsMap,
    /// Number of decisions to retain in memory
    decided_retention: usize,
    /// Optional persistent storage for decisions (enables sync support)
    dcl_store: Option<Arc<dyn cipherbft_storage::DclStore>>,
}

impl Default for ChannelDecisionHandler {
    fn default() -> Self {
        Self::new(None, 100) // Default retention of 100 decisions
    }
}

impl ChannelDecisionHandler {
    /// Create a new channel-based decision handler.
    ///
    /// # Arguments
    /// * `decided_tx` - Optional channel to send decided events
    /// * `decided_retention` - Number of decisions to retain in memory
    pub fn new(
        decided_tx: Option<mpsc::Sender<(ConsensusHeight, Cut)>>,
        decided_retention: usize,
    ) -> Self {
        Self {
            decided_tx,
            decided_cuts: Arc::new(RwLock::new(HashMap::new())),
            decided_retention,
            dcl_store: None,
        }
    }

    /// Add persistent storage for decisions.
    ///
    /// When storage is provided, decisions are persisted to disk, enabling:
    /// - Sync support: peers can request any finalized height
    /// - Crash recovery: decisions survive node restarts
    ///
    /// Without storage, decisions are only kept in memory with retention pruning,
    /// which causes sync failures when peers request old heights.
    pub fn with_storage(mut self, store: Arc<dyn cipherbft_storage::DclStore>) -> Self {
        self.dcl_store = Some(store);
        self
    }
}

#[async_trait]
impl DecisionHandler for ChannelDecisionHandler {
    async fn on_decided(
        &self,
        height: ConsensusHeight,
        _round: ConsensusRound,
        value: ConsensusValue,
        certificate: CommitCertificate<CipherBftContext>,
    ) -> Result<(), ConsensusError> {
        let cut = value.into_cut();

        // Store to persistent storage if available (enables sync support)
        if let Some(store) = &self.dcl_store {
            // Serialize the certificate for storage using borsh
            // (Malachite types derive BorshSerialize/BorshDeserialize)
            let cert_bytes = borsh::to_vec(&certificate).map_err(|e| {
                ConsensusError::Other(format!("Failed to serialize commit certificate: {}", e))
            })?;

            // Store the certificate (Cut is stored separately by finalize_cut)
            if let Err(e) = store.put_commit_certificate(height.0, &cert_bytes).await {
                error!(
                    "Failed to persist commit certificate at height {}: {}",
                    height.0, e
                );
                // Continue - the in-memory cache will still work for the session
            } else {
                debug!(
                    "Persisted commit certificate at height {} ({} bytes)",
                    height.0,
                    cert_bytes.len()
                );
            }
        }

        // Store in memory cache for fast lookups during this session
        {
            let mut decided = self.decided_cuts.write().await;
            decided.insert(height, (cut.clone(), certificate));

            // Clean up old decisions from memory (keep only configured retention)
            // Note: Storage retains all decisions permanently for sync
            let retention = self.decided_retention;
            if decided.len() > retention {
                let heights: Vec<_> = decided.keys().cloned().collect();
                let max_height = heights.iter().max().copied().unwrap_or(height);
                let cutoff = max_height.0.saturating_sub(retention as u64);
                decided.retain(|h, _| h.0 >= cutoff);
            }
        }

        // Send to channel
        if let Some(tx) = &self.decided_tx {
            if let Err(e) = tx.send((height, cut)).await {
                warn!("Failed to send decided event: {}", e);
            }
        }

        Ok(())
    }

    async fn get_decided_value(
        &self,
        height: ConsensusHeight,
    ) -> Result<Option<RawDecidedValue<CipherBftContext>>, ConsensusError> {
        // First check in-memory cache for recent decisions
        {
            let decided = self.decided_cuts.read().await;
            if let Some((cut, cert)) = decided.get(&height) {
                // Encode cut to bytes using bincode
                let value_bytes = bincode::serialize(cut).unwrap_or_default().into();
                return Ok(Some(RawDecidedValue {
                    certificate: cert.clone(),
                    value_bytes,
                }));
            }
        }

        // Fall back to persistent storage for older decisions
        if let Some(store) = &self.dcl_store {
            // Get the finalized cut and certificate from storage
            let cut_opt = store.get_finalized_cut(height.0).await.map_err(|e| {
                ConsensusError::Other(format!("Failed to get finalized cut: {}", e))
            })?;

            let cert_bytes_opt = store.get_commit_certificate(height.0).await.map_err(|e| {
                ConsensusError::Other(format!("Failed to get commit certificate: {}", e))
            })?;

            // Both cut and certificate must exist
            if let (Some(cut), Some(cert_bytes)) = (cut_opt, cert_bytes_opt) {
                // Deserialize the certificate using borsh
                let certificate: CommitCertificate<CipherBftContext> =
                    borsh::from_slice(&cert_bytes).map_err(|e| {
                        ConsensusError::Other(format!(
                            "Failed to deserialize commit certificate: {}",
                            e
                        ))
                    })?;

                // Encode cut to bytes using bincode for RawDecidedValue
                let value_bytes = bincode::serialize(&cut).unwrap_or_default().into();

                debug!(
                    "Retrieved decided value from storage at height {}",
                    height.0
                );

                return Ok(Some(RawDecidedValue {
                    certificate,
                    value_bytes,
                }));
            }
        }

        Ok(None)
    }

    async fn get_history_min_height(&self) -> Result<ConsensusHeight, ConsensusError> {
        // Check persistent storage first for the actual minimum available height
        if let Some(store) = &self.dcl_store {
            if let Ok(Some(height)) = store.get_earliest_finalized_height().await {
                return Ok(ConsensusHeight(height));
            }
        }

        // Fall back to in-memory cache minimum
        let decided = self.decided_cuts.read().await;
        Ok(decided.keys().min().cloned().unwrap_or(ConsensusHeight(1)))
    }
}

/// Spawn the host actor using the backward-compatible channel-based API.
///
/// This function provides compatibility with the old `spawn_host` signature
/// by wrapping the new trait-based architecture.
///
/// # Arguments
///
/// * `our_id` - Our validator ID (used for publishing proposal parts)
/// * `ctx` - Consensus context containing validator set
/// * `cut_rx` - Channel to receive cuts from DCL
/// * `decided_tx` - Channel to send decided events
/// * `network` - Optional network reference for publishing proposal parts
/// * `dcl_store` - Optional persistent storage for decisions (enables sync support)
///
/// # Returns
///
/// A `HostRef<CipherBftContext>` for sending messages to the host.
///
/// # Proposal Parts Publishing
///
/// When `network` is provided, the host will publish proposal parts to the
/// network when building values. This enables `ProposalAndParts` mode where
/// non-proposer nodes can receive and store the proposal values via the
/// `ReceivedProposalPart` handler.
///
/// # Persistent Storage
///
/// When `dcl_store` is provided, decisions (cuts + certificates) are persisted
/// to storage. This enables:
/// - Sync support: peers can request historical heights for catch-up
/// - Crash recovery: decisions survive node restarts
///
/// Without storage, decisions are only kept in memory with retention pruning,
/// which causes sync failures when peers request old heights.
pub async fn spawn_host(
    our_id: ValidatorId,
    ctx: CipherBftContext,
    mut cut_rx: mpsc::Receiver<Cut>,
    decided_tx: Option<mpsc::Sender<(ConsensusHeight, Cut)>>,
    network: Option<NetworkRef<CipherBftContext>>,
    dcl_store: Option<Arc<dyn cipherbft_storage::DclStore>>,
) -> anyhow::Result<HostRef<CipherBftContext>> {
    // Extract validators from context
    let validators: Vec<_> = ctx.validator_set.as_slice().to_vec();

    // Create a simple validator set manager (single epoch, no transitions)
    let epoch_config = EpochConfig::new(u64::MAX); // Very large epoch = no transitions
    let validator_set_manager = Arc::new(
        ValidatorSetManager::new(epoch_config, validators)
            .map_err(|e| anyhow::anyhow!("Failed to create validator set manager: {}", e))?,
    );

    // Create config with default retention values
    let config = HostConfig::default();

    // Create channel-based handlers with config values
    let value_builder = if let Some(network_ref) = network {
        // ProposalAndParts mode: publish proposal parts to network
        let our_address = ConsensusAddress(our_id);
        info!(
            "Host: Enabling ProposalAndParts mode with our_address={}",
            our_address
        );
        Arc::new(
            ChannelValueBuilder::new(config.pending_cuts_retention)
                .with_network(network_ref, our_address),
        )
    } else {
        // ProposalOnly mode: no proposal parts publishing
        Arc::new(ChannelValueBuilder::new(config.pending_cuts_retention))
    };

    let decision_handler = {
        let handler = ChannelDecisionHandler::new(decided_tx, config.decided_retention);
        if let Some(store) = dcl_store {
            Arc::new(handler.with_storage(store))
        } else {
            Arc::new(handler)
        }
    };

    // Spawn background task to process DCL cuts
    let value_builder_for_cuts = Arc::clone(&value_builder);
    tokio::spawn(async move {
        while let Some(cut) = cut_rx.recv().await {
            let height = ConsensusHeight::from(cut.height);
            value_builder_for_cuts.store_cut(height, cut).await;
        }
        warn!("Host: DCL cut receiver closed");
    });

    // Spawn host actor
    let span = tracing::info_span!("CipherBftHost");
    let host_ref = spawn_host_actor(
        validator_set_manager,
        value_builder as Arc<dyn ValueBuilder>,
        decision_handler as Arc<dyn DecisionHandler>,
        config,
        span,
    )
    .await
    .map_err(|e| anyhow::anyhow!("Failed to spawn host: {}", e))?;

    info!("Host actor spawned (backward-compatible mode)");
    Ok(host_ref)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validator_set::ConsensusValidator;
    use crate::validator_set_manager::EpochConfig;
    use cipherbft_crypto::Ed25519KeyPair;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    fn make_validator(id: u8, power: u64) -> ConsensusValidator {
        // Use seeded RNG for deterministic test keypairs
        let mut rng = StdRng::seed_from_u64(id as u64);
        let keypair = Ed25519KeyPair::generate(&mut rng);
        let validator_id = keypair.validator_id();
        ConsensusValidator::new(validator_id, keypair.public_key, power)
    }

    fn make_validators(count: usize) -> Vec<ConsensusValidator> {
        (1..=count as u8).map(|i| make_validator(i, 100)).collect()
    }

    #[test]
    fn test_host_get_validator_set() {
        let validators = make_validators(4);
        let config = EpochConfig::new(10);
        let manager =
            Arc::new(ValidatorSetManager::new(config, validators).expect("should create"));

        // Create a mock host (can't test the full actor without async runtime)
        // Just test the get_validator_set method

        // Should get validator set for any height
        let set = manager
            .get_validator_set_for_height(ConsensusHeight(1))
            .unwrap()
            .unwrap();
        assert_eq!(set.len(), 4);

        let set = manager
            .get_validator_set_for_height(ConsensusHeight(50))
            .unwrap()
            .unwrap();
        assert_eq!(set.len(), 4);
    }

    #[test]
    fn test_host_epoch_transition() {
        let validators = make_validators(4);
        let config = EpochConfig::new(10);
        let manager =
            Arc::new(ValidatorSetManager::new(config, validators).expect("should create"));

        // Non-boundary block
        assert!(!manager.on_block_committed(ConsensusHeight(5)).unwrap());
        assert_eq!(manager.current_epoch(), 0);

        // Boundary block triggers epoch transition
        assert!(manager.on_block_committed(ConsensusHeight(10)).unwrap());
        assert_eq!(manager.current_epoch(), 1);
    }

    #[test]
    fn test_host_validator_set_across_epochs() {
        let validators = make_validators(4);
        let config = EpochConfig::new(10);
        let manager =
            Arc::new(ValidatorSetManager::new(config, validators).expect("should create"));

        // Register new validators for next epoch
        let new_validators = make_validators(5);
        manager
            .register_next_epoch_validators(new_validators)
            .unwrap();

        // Before epoch transition
        let set = manager
            .get_validator_set_for_height(ConsensusHeight(1))
            .unwrap()
            .unwrap();
        assert_eq!(set.len(), 4);

        // Trigger epoch transition
        manager.on_block_committed(ConsensusHeight(10)).unwrap();

        // After epoch transition - epoch 1 heights should use new set
        let set = manager
            .get_validator_set_for_height(ConsensusHeight(11))
            .unwrap()
            .unwrap();
        assert_eq!(set.len(), 5);

        // But epoch 0 heights should still return old set
        let set = manager
            .get_validator_set_for_height(ConsensusHeight(5))
            .unwrap()
            .unwrap();
        assert_eq!(set.len(), 4);
    }

    /// Helper to create a test Cut
    fn make_test_cut(height: u64) -> Cut {
        Cut::new(height)
    }

    /// Helper to create a minimal test CommitCertificate
    fn make_test_certificate(height: u64) -> CommitCertificate<CipherBftContext> {
        use informalsystems_malachitebft_core_types::Value;

        let value = ConsensusValue(make_test_cut(height));
        let value_id = Value::id(&value);

        // Create a minimal certificate with no signatures (for testing purposes)
        CommitCertificate::<CipherBftContext> {
            height: ConsensusHeight(height),
            round: Round::new(0),
            value_id,
            commit_signatures: vec![],
        }
    }

    #[tokio::test]
    async fn test_decision_handler_without_storage_prunes_old_decisions() {
        // Create handler with small retention (window of 2)
        // Pruning uses: cutoff = max_height - retention, keeps heights >= cutoff
        // With retention=2 and max_height=4: cutoff=2, keeps heights 2,3,4
        let handler = ChannelDecisionHandler::new(None, 2);
        let value1 = ConsensusValue(make_test_cut(1));
        let cert1 = make_test_certificate(1);
        let value2 = ConsensusValue(make_test_cut(2));
        let cert2 = make_test_certificate(2);
        let value3 = ConsensusValue(make_test_cut(3));
        let cert3 = make_test_certificate(3);
        let value4 = ConsensusValue(make_test_cut(4));
        let cert4 = make_test_certificate(4);

        // Store 4 decisions - this triggers pruning of height 1
        handler
            .on_decided(ConsensusHeight(1), Round::new(0), value1, cert1)
            .await
            .unwrap();
        handler
            .on_decided(ConsensusHeight(2), Round::new(0), value2, cert2)
            .await
            .unwrap();
        handler
            .on_decided(ConsensusHeight(3), Round::new(0), value3, cert3)
            .await
            .unwrap();
        handler
            .on_decided(ConsensusHeight(4), Round::new(0), value4, cert4)
            .await
            .unwrap();

        // Height 1 should be pruned (cutoff = 4 - 2 = 2)
        let result = handler.get_decided_value(ConsensusHeight(1)).await.unwrap();
        assert!(
            result.is_none(),
            "Without storage, old decisions should be pruned"
        );

        // Heights 2, 3, 4 should still be available (>= cutoff of 2)
        assert!(handler
            .get_decided_value(ConsensusHeight(2))
            .await
            .unwrap()
            .is_some());
        assert!(handler
            .get_decided_value(ConsensusHeight(3))
            .await
            .unwrap()
            .is_some());
        assert!(handler
            .get_decided_value(ConsensusHeight(4))
            .await
            .unwrap()
            .is_some());

        // Min height should be 2 (height 1 was pruned)
        let min_height = handler.get_history_min_height().await.unwrap();
        assert_eq!(min_height.0, 2);
    }

    #[tokio::test]
    async fn test_decision_handler_with_storage_retrieves_pruned_decisions() {
        use cipherbft_storage::InMemoryStore;

        // Create storage and handler with small retention (window of 2)
        // With retention=2 and max_height=4: cutoff=2, keeps heights 2,3,4 in memory
        let store: Arc<dyn cipherbft_storage::DclStore> = Arc::new(InMemoryStore::new());
        let handler = ChannelDecisionHandler::new(None, 2).with_storage(Arc::clone(&store));

        let value1 = ConsensusValue(make_test_cut(1));
        let cert1 = make_test_certificate(1);
        let value2 = ConsensusValue(make_test_cut(2));
        let cert2 = make_test_certificate(2);
        let value3 = ConsensusValue(make_test_cut(3));
        let cert3 = make_test_certificate(3);
        let value4 = ConsensusValue(make_test_cut(4));
        let cert4 = make_test_certificate(4);

        // Also store the finalized cuts directly in storage
        // (In production, this is done by the DCL layer via finalize_cut)
        store.put_finalized_cut(make_test_cut(1)).await.unwrap();
        store.put_finalized_cut(make_test_cut(2)).await.unwrap();
        store.put_finalized_cut(make_test_cut(3)).await.unwrap();
        store.put_finalized_cut(make_test_cut(4)).await.unwrap();

        // Store 4 decisions via the handler (triggers pruning of height 1 from memory)
        handler
            .on_decided(ConsensusHeight(1), Round::new(0), value1, cert1)
            .await
            .unwrap();
        handler
            .on_decided(ConsensusHeight(2), Round::new(0), value2, cert2)
            .await
            .unwrap();
        handler
            .on_decided(ConsensusHeight(3), Round::new(0), value3, cert3)
            .await
            .unwrap();
        handler
            .on_decided(ConsensusHeight(4), Round::new(0), value4, cert4)
            .await
            .unwrap();

        // Height 1 should still be retrievable from storage even though
        // it was pruned from memory (cutoff = 4 - 2 = 2)
        let result = handler.get_decided_value(ConsensusHeight(1)).await.unwrap();
        assert!(
            result.is_some(),
            "With storage, old decisions should be retrievable"
        );

        // All heights should be available
        assert!(handler
            .get_decided_value(ConsensusHeight(2))
            .await
            .unwrap()
            .is_some());
        assert!(handler
            .get_decided_value(ConsensusHeight(3))
            .await
            .unwrap()
            .is_some());
        assert!(handler
            .get_decided_value(ConsensusHeight(4))
            .await
            .unwrap()
            .is_some());

        // Min height should be 1 (from storage, not in-memory)
        let min_height = handler.get_history_min_height().await.unwrap();
        assert_eq!(min_height.0, 1);
    }
}
