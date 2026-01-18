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

use std::sync::Arc;

use async_trait::async_trait;
use informalsystems_malachitebft_core_consensus::LocallyProposedValue;
use informalsystems_malachitebft_core_types::CommitCertificate;
use informalsystems_malachitebft_engine::host::{HostMsg, HostRef, Next};
use informalsystems_malachitebft_sync::RawDecidedValue;
use ractor::{async_trait as ractor_async_trait, Actor, ActorProcessingErr, ActorRef};
use tracing::{debug, error, info, trace, warn};

use crate::context::CipherBftContext;
use crate::error::ConsensusError;
use crate::types::{ConsensusHeight, ConsensusRound, ConsensusValue, ConsensusValueId};
use crate::validator_set::ConsensusValidatorSet;
use crate::validator_set_manager::ValidatorSetManager;

/// Configuration for the Host actor.
#[derive(Debug, Clone)]
pub struct HostConfig {
    /// Maximum number of proposal parts to buffer.
    pub max_proposal_parts: usize,

    /// Whether to enable strict validator set validation.
    pub strict_validator_checks: bool,
}

impl Default for HostConfig {
    fn default() -> Self {
        Self {
            max_proposal_parts: 100,
            strict_validator_checks: true,
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
pub struct HostState {
    /// Current height being processed.
    current_height: Option<ConsensusHeight>,
}

impl Default for HostState {
    fn default() -> Self {
        Self {
            current_height: None,
        }
    }
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
                    "Building proposal value"
                );

                // The `round` from HostMsg is already a Round type (aliased as ConsensusRound)
                match self.value_builder.build_value(height, round).await {
                    Ok(value) => {
                        info!(
                            parent: &self.span,
                            height = height.0,
                            "Built proposal value"
                        );
                        if reply_to.send(value).is_err() {
                            warn!(parent: &self.span, "Failed to send GetValue reply");
                        }
                    }
                    Err(e) => {
                        error!(
                            parent: &self.span,
                            height = height.0,
                            error = %e,
                            "Failed to build proposal value"
                        );
                    }
                }
            }

            HostMsg::ReceivedProposalPart {
                from,
                part: _,
                reply_to: _,
            } => {
                trace!(
                    parent: &self.span,
                    from = %from,
                    "Received proposal part"
                );

                // For single-part proposals (ProposalOnly mode), the part contains
                // the complete proposal. Parse and return it.
                // In a full implementation, this would assemble multi-part proposals.
                // TODO: Implement proposal part handling and reply with ProposedValue
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
                let _value_id = certificate.value_id.clone();

                info!(
                    parent: &self.span,
                    height = height.0,
                    round = round.as_i64(),
                    epoch = self.validator_set_manager.config().epoch_for_height(height),
                    "Consensus decided on value"
                );

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
                proposer: _,
                value_bytes,
                reply_to: _,
            } => {
                debug!(
                    parent: &self.span,
                    height = height.0,
                    round = round.as_i64(),
                    bytes_len = value_bytes.len(),
                    "Processing synced value"
                );
                // Parse and validate the synced value
                // For now, we don't handle synced values
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
}
