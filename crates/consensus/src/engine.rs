//! Malachite engine wiring scaffold.
//!
//! This module wires CipherBFT context/types into the Malachite engine actors.
//! It expects callers to provide network/host/WAL/sync actors that already
//! satisfy Malachite's message contracts; we simply glue them together and
//! spawn the consensus + node supervisors.
//!
//! ## Components for `MalachiteEngineBuilder::new()`
//!
//! 1. `CipherBftContext` - already implemented (`create_context` helper).
//! 2. `ConsensusParams<CipherBftContext>` - helper `default_consensus_params` provided (ProposalOnly payload).
//! 3. `EngineConsensusConfig` - helper `default_engine_config_single_part` provided (ProposalOnly payload).
//! 4. `SigningProvider<CipherBftContext>` - implemented in `signing.rs` as `ConsensusSigningProvider`.
//! 5. `NetworkRef<CipherBftContext>` - still needed: create/bridge a network actor for consensus messages.
//! 6. `HostRef<CipherBftContext>` - still needed: host actor to handle `AppMsg` (DCL Cut fetch/execute, etc.).
//! 7. `WalRef<CipherBftContext>` - still needed: instantiate WAL actor with codec/path.

use anyhow::Result;
use informalsystems_malachitebft_app::types::core::SigningProvider;
use informalsystems_malachitebft_config::{
    ConsensusConfig as EngineConsensusConfig, TimeoutConfig, ValuePayload as EngineValuePayload,
};
use informalsystems_malachitebft_core_consensus::Params as ConsensusParams;
use informalsystems_malachitebft_core_driver::ThresholdParams;
use informalsystems_malachitebft_core_types::ValuePayload;
use informalsystems_malachitebft_engine::consensus::{Consensus, ConsensusRef};
use informalsystems_malachitebft_engine::host::HostRef;
use informalsystems_malachitebft_engine::network::NetworkRef;
use informalsystems_malachitebft_engine::node::{Node, NodeRef};
use informalsystems_malachitebft_engine::sync::SyncRef;
use informalsystems_malachitebft_engine::util::events::TxEvent;
use informalsystems_malachitebft_engine::wal::WalRef;
use informalsystems_malachitebft_metrics::Metrics;
use tracing::info_span;

use crate::config::ConsensusConfig;
use crate::context::CipherBftContext;
use crate::error::ConsensusError;
use crate::types::ConsensusHeight;
use crate::validator_set::{ConsensusAddress, ConsensusValidator, ConsensusValidatorSet};

/// Create a `CipherBftContext` from configuration and validators.
///
/// This is a convenience function that constructs a `CipherBftContext` with
/// sensible defaults. The validator set is created from a list of validators
/// with their Ed25519 public keys and voting power.
///
/// # Arguments
/// * `chain_id` - Chain identifier
/// * `validators` - List of validators with Ed25519 public keys and voting power
/// * `initial_height` - Starting height for consensus (defaults to 1 if None)
///
/// # Errors
/// Returns `ConsensusError::EmptyValidatorSet` if the validator list is empty.
///
/// # Example
/// ```rust,ignore
/// use cipherbft_consensus::{create_context, ConsensusValidator};
/// use cipherbft_crypto::Ed25519PublicKey;
/// use cipherbft_types::ValidatorId;
///
/// let validators = vec![
///     ConsensusValidator::new(
///         validator_id,
///         ed25519_pubkey,
///         100, // voting power
///     ),
/// ];
/// let ctx = create_context("my-chain", validators, None)?;
/// ```
pub fn create_context(
    chain_id: impl Into<String>,
    validators: Vec<ConsensusValidator>,
    initial_height: Option<ConsensusHeight>,
) -> Result<CipherBftContext, ConsensusError> {
    let config = ConsensusConfig::new(chain_id);
    let validator_set = ConsensusValidatorSet::new(validators);
    let initial_height = initial_height.unwrap_or_else(|| ConsensusHeight::from(1));

    CipherBftContext::try_new(config, validator_set, initial_height)
}

/// Create Malachite consensus params using our Context components.
///
/// - `our_address` should match the validator's ConsensusAddress (derived from our Ed25519 key).
/// - `value_payload` is set to `ProposalAndParts` so that:
///   - The proposer sends the full proposal message AND publishes proposal parts
///   - Non-proposers receive proposal parts and store them via ReceivedProposalPart
///   - This enables non-proposers to look up decided values from commit certificates
pub fn default_consensus_params(
    ctx: &CipherBftContext,
    our_address: ConsensusAddress,
) -> ConsensusParams<CipherBftContext> {
    ConsensusParams {
        initial_height: ctx.initial_height(),
        initial_validator_set: ctx.validator_set().clone(),
        address: our_address,
        threshold_params: ThresholdParams::default(),
        value_payload: ValuePayload::ProposalAndParts,
    }
}

/// Default queue capacity for buffering consensus inputs for future heights.
///
/// This allows the engine to buffer votes, proposals, and sync responses
/// that arrive for heights we haven't reached yet. Without this, such
/// messages are silently dropped, causing validators to get stuck during sync.
const DEFAULT_QUEUE_CAPACITY: usize = 10;

/// Engine config tuned for ProposalAndParts mode.
///
/// This mode sends both full proposal messages and proposal parts, enabling
/// non-proposers to store received values for decision processing.
pub fn default_engine_config_single_part() -> EngineConsensusConfig {
    EngineConsensusConfig {
        value_payload: EngineValuePayload::ProposalAndParts,
        queue_capacity: DEFAULT_QUEUE_CAPACITY,
        ..Default::default()
    }
}

/// Create engine config with timeouts from `ConsensusConfig`.
///
/// This wires the CipherBFT consensus timeouts into the Malachite engine config.
/// Uses ProposalAndParts mode to enable non-proposers to receive and store proposals.
pub fn create_engine_config(config: &ConsensusConfig) -> EngineConsensusConfig {
    let timeout_config = TimeoutConfig {
        timeout_propose: config.propose_timeout,
        timeout_prevote: config.prevote_timeout,
        timeout_precommit: config.precommit_timeout,
        ..Default::default()
    };

    EngineConsensusConfig {
        value_payload: EngineValuePayload::ProposalAndParts,
        timeouts: timeout_config,
        queue_capacity: DEFAULT_QUEUE_CAPACITY,
        ..Default::default()
    }
}

/// Bundles all actor handles returned after spawning.
pub struct EngineHandles {
    pub node: NodeRef,
    pub consensus: ConsensusRef<CipherBftContext>,
    pub network: NetworkRef<CipherBftContext>,
    pub wal: WalRef<CipherBftContext>,
    pub host: HostRef<CipherBftContext>,
    pub sync: Option<SyncRef<CipherBftContext>>,
    pub events: TxEvent<CipherBftContext>,
    pub metrics: Metrics,
}

/// Builder for spinning up Malachite consensus actors.
pub struct MalachiteEngineBuilder {
    pub ctx: CipherBftContext,
    pub params: ConsensusParams<CipherBftContext>,
    pub consensus_config: EngineConsensusConfig,
    pub signing_provider: Box<dyn SigningProvider<CipherBftContext>>,
    pub network: NetworkRef<CipherBftContext>,
    pub host: HostRef<CipherBftContext>,
    pub wal: WalRef<CipherBftContext>,
    pub sync: Option<SyncRef<CipherBftContext>>,
    pub metrics: Metrics,
    pub events: TxEvent<CipherBftContext>,
}

impl MalachiteEngineBuilder {
    /// Create a new builder with default metrics/event channels.
    pub fn new(
        ctx: CipherBftContext,
        params: ConsensusParams<CipherBftContext>,
        consensus_config: EngineConsensusConfig,
        signing_provider: Box<dyn SigningProvider<CipherBftContext>>,
        network: NetworkRef<CipherBftContext>,
        host: HostRef<CipherBftContext>,
        wal: WalRef<CipherBftContext>,
    ) -> Self {
        Self {
            ctx,
            params,
            consensus_config,
            signing_provider,
            network,
            host,
            wal,
            sync: None,
            metrics: Metrics::new(),
            events: TxEvent::new(),
        }
    }

    /// Optionally attach the sync actor.
    pub fn with_sync(mut self, sync: SyncRef<CipherBftContext>) -> Self {
        self.sync = Some(sync);
        self
    }

    /// Override metrics registry.
    pub fn with_metrics(mut self, metrics: Metrics) -> Self {
        self.metrics = metrics;
        self
    }

    /// Override event channel.
    pub fn with_events(mut self, events: TxEvent<CipherBftContext>) -> Self {
        self.events = events;
        self
    }

    /// Spawn consensus + node supervisors.
    pub async fn spawn(self) -> Result<EngineHandles> {
        let span = info_span!("cipherbft-malachite", chain_id = %self.ctx.chain_id());

        let consensus = Consensus::spawn(
            self.ctx.clone(),
            self.params,
            self.consensus_config,
            self.signing_provider,
            self.network.clone(),
            self.host.clone(),
            self.wal.clone(),
            self.sync.clone(),
            self.metrics.clone(),
            self.events.clone(),
            span.clone(),
        )
        .await?;

        let node = Node::new(
            self.ctx,
            self.network.clone(),
            consensus.clone(),
            self.wal.clone(),
            self.sync.clone(),
            self.host.clone(),
            span,
        );

        let (node_ref, _) = node.spawn().await?;

        Ok(EngineHandles {
            node: node_ref,
            consensus,
            network: self.network,
            wal: self.wal,
            host: self.host,
            sync: self.sync,
            events: self.events,
            metrics: self.metrics,
        })
    }
}
