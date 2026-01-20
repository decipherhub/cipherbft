//! Node runner - ties Primary, Workers, and Network together
//!
//! # Task Supervision
//!
//! The node uses a [`NodeSupervisor`] for structured task management:
//! - All background tasks are tracked and can be cancelled gracefully
//! - Shutdown follows a specific order to ensure clean state
//! - Critical task failures trigger coordinated shutdown
//!
//! # Shutdown Order
//!
//! 1. Stop accepting new network connections
//! 2. Drain in-flight consensus rounds (via cancellation signal)
//! 3. Flush pending storage writes
//! 4. Close database connections
//! 5. Exit

use crate::config::NodeConfig;
use crate::execution_bridge::ExecutionBridge;
use crate::network::TcpPrimaryNetwork;
use crate::supervisor::NodeSupervisor;
use crate::util::validator_id_from_bls;
use anyhow::{Context, Result};
use cipherbft_consensus::{
    create_context, default_consensus_params, default_engine_config_single_part, spawn_host,
    spawn_network, spawn_wal, ConsensusHeight, ConsensusSigner, ConsensusSigningProvider,
    ConsensusValidator, MalachiteEngineBuilder,
};
use cipherbft_crypto::{BlsKeyPair, BlsPublicKey, Ed25519KeyPair, Ed25519PublicKey};
use cipherbft_data_chain::{
    primary::{Primary, PrimaryConfig, PrimaryEvent},
    Cut, DclMessage,
};
use cipherbft_execution::ChainConfig;
use cipherbft_types::genesis::Genesis;
use cipherbft_types::ValidatorId;
use informalsystems_malachitebft_metrics::SharedRegistry;
use informalsystems_malachitebft_network::{
    Config as NetworkConfig, DiscoveryConfig, GossipSubConfig, Keypair, Multiaddr, PubSubProtocol,
    TransportProtocol,
};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

/// Validator public key information for both DCL and Consensus layers
#[derive(Clone, Debug)]
pub struct ValidatorInfo {
    /// BLS public key for DCL layer (threshold signatures)
    pub bls_public_key: BlsPublicKey,
    /// Ed25519 public key for Consensus layer (Malachite signing)
    pub ed25519_public_key: Ed25519PublicKey,
    /// Voting power for consensus
    pub voting_power: u64,
}

impl ValidatorInfo {
    /// Create a new validator info with default voting power
    pub fn new(bls_public_key: BlsPublicKey, ed25519_public_key: Ed25519PublicKey) -> Self {
        Self {
            bls_public_key,
            ed25519_public_key,
            voting_power: 100, // Default voting power
        }
    }

    /// Create with custom voting power
    pub fn with_voting_power(
        bls_public_key: BlsPublicKey,
        ed25519_public_key: Ed25519PublicKey,
        voting_power: u64,
    ) -> Self {
        Self {
            bls_public_key,
            ed25519_public_key,
            voting_power,
        }
    }
}

/// A running CipherBFT node
pub struct Node {
    /// Configuration
    config: NodeConfig,
    /// BLS keypair for DCL layer
    bls_keypair: BlsKeyPair,
    /// Ed25519 keypair for consensus layer
    ed25519_keypair: Ed25519KeyPair,
    /// Our validator ID
    validator_id: ValidatorId,
    /// Known validators with both BLS and Ed25519 public keys
    validators: HashMap<ValidatorId, ValidatorInfo>,
    /// Execution layer bridge
    execution_bridge: Option<Arc<ExecutionBridge>>,
}

impl Node {
    /// Create a new node with provided keypairs
    ///
    /// # Arguments
    ///
    /// * `config` - Node configuration
    /// * `bls_keypair` - BLS keypair for DCL layer (threshold signatures)
    /// * `ed25519_keypair` - Ed25519 keypair for consensus layer (Malachite signing)
    pub fn new(
        config: NodeConfig,
        bls_keypair: BlsKeyPair,
        ed25519_keypair: Ed25519KeyPair,
    ) -> Result<Self> {
        let validator_id = validator_id_from_bls(&bls_keypair.public_key);

        // Verify validator ID matches if configured
        // If not configured, we derive it from the BLS key
        if let Some(config_vid) = config.validator_id {
            if validator_id != config_vid {
                anyhow::bail!(
                    "Validator ID mismatch: config has {:?}, derived {:?}",
                    config_vid,
                    validator_id
                );
            }
        }

        Ok(Self {
            config,
            bls_keypair,
            ed25519_keypair,
            validator_id,
            validators: HashMap::new(),
            execution_bridge: None,
        })
    }

    /// Add a known validator with both BLS and Ed25519 public keys
    pub fn add_validator(
        &mut self,
        id: ValidatorId,
        bls_pubkey: BlsPublicKey,
        ed25519_pubkey: Ed25519PublicKey,
    ) {
        self.validators
            .insert(id, ValidatorInfo::new(bls_pubkey, ed25519_pubkey));
    }

    /// Add a known validator with custom voting power
    pub fn add_validator_with_power(
        &mut self,
        id: ValidatorId,
        bls_pubkey: BlsPublicKey,
        ed25519_pubkey: Ed25519PublicKey,
        voting_power: u64,
    ) {
        self.validators.insert(
            id,
            ValidatorInfo::with_voting_power(bls_pubkey, ed25519_pubkey, voting_power),
        );
    }

    /// Bootstrap validators from genesis file (T029).
    ///
    /// Parses validator public keys from genesis and adds them to the node's
    /// validator set with voting power derived from staked amounts.
    ///
    /// # Arguments
    ///
    /// * `genesis` - Validated genesis configuration
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Ed25519 public key parsing fails (invalid hex or length)
    /// - BLS public key parsing fails (invalid hex or length)
    pub fn bootstrap_validators_from_genesis(&mut self, genesis: &Genesis) -> Result<()> {
        let total_stake = genesis.total_staked();

        info!(
            "Bootstrapping {} validators from genesis (total stake: {} wei)",
            genesis.validator_count(),
            total_stake
        );

        for validator in &genesis.cipherbft.validators {
            // Parse Ed25519 public key (strip 0x prefix if present)
            let ed25519_hex = validator.ed25519_pubkey.trim_start_matches("0x");
            let ed25519_bytes = hex::decode(ed25519_hex).map_err(|e| {
                anyhow::anyhow!(
                    "Invalid Ed25519 public key hex for {}: {}",
                    validator.address,
                    e
                )
            })?;

            if ed25519_bytes.len() != 32 {
                anyhow::bail!(
                    "Ed25519 public key for {} must be 32 bytes, got {}",
                    validator.address,
                    ed25519_bytes.len()
                );
            }

            let mut ed25519_arr = [0u8; 32];
            ed25519_arr.copy_from_slice(&ed25519_bytes);
            let ed25519_pubkey = Ed25519PublicKey::from_bytes(&ed25519_arr).map_err(|e| {
                anyhow::anyhow!(
                    "Invalid Ed25519 public key for {}: {:?}",
                    validator.address,
                    e
                )
            })?;

            // Parse BLS public key (strip 0x prefix if present)
            let bls_hex = validator.bls_pubkey.trim_start_matches("0x");
            let bls_bytes = hex::decode(bls_hex).map_err(|e| {
                anyhow::anyhow!(
                    "Invalid BLS public key hex for {}: {}",
                    validator.address,
                    e
                )
            })?;

            if bls_bytes.len() != 48 {
                anyhow::bail!(
                    "BLS public key for {} must be 48 bytes, got {}",
                    validator.address,
                    bls_bytes.len()
                );
            }

            let mut bls_arr = [0u8; 48];
            bls_arr.copy_from_slice(&bls_bytes);
            let bls_pubkey = BlsPublicKey::from_bytes(&bls_arr).map_err(|e| {
                anyhow::anyhow!("Invalid BLS public key for {}: {:?}", validator.address, e)
            })?;

            // Derive validator ID from BLS public key
            let validator_id = validator_id_from_bls(&bls_pubkey);

            // Calculate voting power from stake (proportional to total stake)
            // Scale to reasonable voting power values (avoid overflow)
            let voting_power = if total_stake.is_zero() {
                100u64 // Default if no stake
            } else {
                // voting_power = (stake * 10000) / total_stake
                // This gives voting power proportional to stake share
                // with 10000 as the scaling factor for precision
                let stake_u128: u128 = validator.staked_amount.try_into().unwrap_or(u128::MAX);
                let total_u128: u128 = total_stake.try_into().unwrap_or(u128::MAX);
                let power = (stake_u128.saturating_mul(10000)) / total_u128.max(1);
                power.max(1) as u64 // Ensure at least 1 voting power
            };

            debug!(
                "Adding validator {} (stake: {}, voting_power: {})",
                validator.address, validator.staked_amount, voting_power
            );

            self.validators.insert(
                validator_id,
                ValidatorInfo::with_voting_power(bls_pubkey, ed25519_pubkey, voting_power),
            );
        }

        info!(
            "Bootstrapped {} validators from genesis",
            self.validators.len()
        );

        Ok(())
    }

    /// Enable execution layer integration
    ///
    /// Must be called before `run()` to enable Cut execution.
    ///
    /// # Note
    /// This creates an execution layer with an empty staking state.
    /// For production use, prefer `with_execution_layer_from_genesis` to
    /// initialize the staking state from the genesis file.
    pub fn with_execution_layer(mut self) -> Result<Self> {
        use cipherbft_storage::{DclStore, InMemoryStore};
        let chain_config = ChainConfig::default();
        let dcl_store: std::sync::Arc<dyn DclStore> = std::sync::Arc::new(InMemoryStore::new());
        let bridge = ExecutionBridge::new(chain_config, dcl_store)?;
        self.execution_bridge = Some(Arc::new(bridge));
        Ok(self)
    }

    /// Enable execution layer integration with genesis validators.
    ///
    /// This is the preferred method for production use. It initializes the
    /// staking precompile with the validator set from the genesis file,
    /// ensuring validators are correctly registered on node startup.
    ///
    /// # Arguments
    ///
    /// * `genesis` - Validated genesis configuration
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let genesis = GenesisLoader::load_and_validate(path)?;
    /// let node = Node::new(config, bls_keypair, ed25519_keypair)?
    ///     .with_execution_layer_from_genesis(&genesis)?;
    /// ```
    pub fn with_execution_layer_from_genesis(mut self, genesis: &Genesis) -> Result<Self> {
        use cipherbft_storage::{DclStore, InMemoryStore};
        let chain_config = ChainConfig::default();
        let dcl_store: std::sync::Arc<dyn DclStore> = std::sync::Arc::new(InMemoryStore::new());
        let bridge = ExecutionBridge::from_genesis(chain_config, dcl_store, genesis)?;
        self.execution_bridge = Some(Arc::new(bridge));
        info!(
            "Execution layer initialized with {} validators from genesis",
            genesis.validator_count()
        );
        Ok(self)
    }

    /// Run the node with a default supervisor.
    ///
    /// Creates a new [`NodeSupervisor`] and runs the node until shutdown is triggered
    /// (e.g., via Ctrl+C signal).
    pub async fn run(self) -> Result<()> {
        let supervisor = NodeSupervisor::new();
        self.run_with_supervisor(supervisor).await
    }

    /// Run the node with a provided supervisor.
    ///
    /// This allows external control over task supervision, useful for:
    /// - Testing with custom shutdown timing
    /// - Coordinating multiple nodes in a single process
    /// - Custom shutdown ordering
    ///
    /// # Arguments
    ///
    /// * `supervisor` - The supervisor that manages task lifecycle
    pub async fn run_with_supervisor(self, supervisor: NodeSupervisor) -> Result<()> {
        info!("Starting node with validator ID: {:?}", self.validator_id);

        // Create data directory if needed
        std::fs::create_dir_all(&self.config.data_dir)?;

        // Get cancellation token for graceful shutdown
        let cancel_token = supervisor.cancellation_token();

        // Create channels for Primary
        let (primary_incoming_tx, mut primary_incoming_rx) =
            mpsc::channel::<(ValidatorId, DclMessage)>(1000);

        // Create primary network
        let primary_network = Arc::new(TcpPrimaryNetwork::new(
            self.validator_id,
            &self.config.peers,
            primary_incoming_tx.clone(),
        ));

        // Start primary listener
        Arc::clone(&primary_network)
            .start_listener(self.config.primary_listen)
            .await
            .with_context(|| {
                format!(
                    "Failed to start primary network listener on {}",
                    self.config.primary_listen
                )
            })?;

        // Connect to peers (with retry) - supervised task
        supervisor.spawn_cancellable("peer-connector", {
            let network = Arc::clone(&primary_network);
            move |token| async move {
                // Initial delay to let other nodes start
                tokio::time::sleep(Duration::from_secs(1)).await;
                loop {
                    tokio::select! {
                        biased;
                        _ = token.cancelled() => {
                            info!("Peer connector shutting down");
                            break;
                        }
                        _ = tokio::time::sleep(Duration::from_secs(5)) => {
                            network.connect_to_all_peers().await;
                        }
                    }
                }
                Ok(())
            }
        });

        // Create Primary configuration
        let primary_config =
            PrimaryConfig::new(self.validator_id, self.bls_keypair.secret_key.clone())
                .with_car_interval(Duration::from_millis(self.config.car_interval_ms))
                .with_max_empty_cars(3);

        // Create channel for CutReady events to Consensus Host
        let (cut_tx, cut_rx) = mpsc::channel::<Cut>(100);

        // Extract BLS public keys for DCL layer (Primary uses BLS for threshold signatures)
        let bls_pubkeys: HashMap<ValidatorId, BlsPublicKey> = self
            .validators
            .iter()
            .map(|(id, info)| (*id, info.bls_public_key.clone()))
            .collect();

        // Spawn Primary task
        let (mut primary_handle, _worker_rxs) = Primary::spawn(
            primary_config,
            bls_pubkeys,
            Box::new(TcpPrimaryNetworkAdapter {
                network: primary_network,
            }),
            self.config.num_workers as u8,
        );
        let (decided_tx, mut decided_rx) = mpsc::channel::<(ConsensusHeight, Cut)>(100);

        // Get Ed25519 keypair for Consensus
        let ed25519_pubkey = self.ed25519_keypair.public_key.clone();
        // Extract secret key bytes before moving keypair (needed for libp2p Keypair)
        let ed25519_secret_bytes = self.ed25519_keypair.secret_key.to_bytes();
        let consensus_signer = ConsensusSigner::new(self.ed25519_keypair.clone());
        let signing_provider = ConsensusSigningProvider::new(consensus_signer);

        // Create Consensus context and validators
        // Build validator set from all known validators using their Ed25519 public keys
        // Chain ID: cipherbft-testnet-1 (Cosmos-style for consensus layer)
        // Note: For EVM execution layer, use numeric chain ID 84530001
        let chain_id = "cipherbft-testnet-1";

        // Look up our own voting power from the validator set (set during bootstrap_validators_from_genesis)
        // Fall back to 100 if not found (e.g., if bootstrap wasn't called)
        let our_voting_power = self
            .validators
            .get(&self.validator_id)
            .map(|info| info.voting_power)
            .unwrap_or(100);

        // Start with ourselves
        let mut consensus_validators = vec![ConsensusValidator::new(
            self.validator_id,
            ed25519_pubkey,
            our_voting_power,
        )];

        // Add all other validators from the known validator set
        for (validator_id, info) in &self.validators {
            if *validator_id != self.validator_id {
                consensus_validators.push(ConsensusValidator::new(
                    *validator_id,
                    info.ed25519_public_key.clone(),
                    info.voting_power,
                ));
            }
        }
        let ctx = create_context(chain_id, consensus_validators, None)?;
        // Find our own address in the sorted validator set by matching our validator ID.
        // Note: The validator set is sorted by voting power (desc), then address (asc),
        // so we cannot assume our position - we must search for ourselves.
        let our_address = ctx
            .validator_set()
            .as_slice()
            .iter()
            .find(|v| v.address.0 == self.validator_id)
            .expect("our validator must be in the validator set")
            .address;
        let params = default_consensus_params(&ctx, our_address);
        let consensus_config = default_engine_config_single_part();

        // Create metrics registry for consensus actors
        let metrics = SharedRegistry::global().with_moniker("cipherbft-consensus");

        // Create libp2p keypair from Ed25519 secret key for consensus network
        // This ensures deterministic PeerId across node restarts
        let consensus_keypair = Keypair::ed25519_from_bytes(ed25519_secret_bytes).map_err(|e| {
            anyhow::anyhow!("Failed to create libp2p keypair from Ed25519 key: {}", e)
        })?;
        info!(
            "Consensus network PeerId: {}",
            consensus_keypair.public().to_peer_id()
        );

        // Create network config for consensus p2p layer
        // Convert SocketAddr to Multiaddr format
        let listen_addr: Multiaddr = format!(
            "/ip4/{}/tcp/{}",
            self.config.consensus_listen.ip(),
            self.config.consensus_listen.port()
        )
        .parse()
        .expect("valid multiaddr from config");

        // Convert peer consensus addresses to Multiaddr format for libp2p
        let persistent_peers: Vec<Multiaddr> = self
            .config
            .peers
            .iter()
            .filter_map(|peer| {
                let addr = &peer.consensus_addr;
                let multiaddr_str = format!("/ip4/{}/tcp/{}", addr.ip(), addr.port());
                match multiaddr_str.parse::<Multiaddr>() {
                    Ok(multiaddr) => Some(multiaddr),
                    Err(e) => {
                        warn!(
                            "Failed to parse peer consensus address {} as Multiaddr: {}",
                            addr, e
                        );
                        None
                    }
                }
            })
            .collect();
        info!(
            "Configured {} persistent peers for consensus network",
            persistent_peers.len()
        );

        let network_config = NetworkConfig {
            listen_addr: listen_addr.clone(),
            persistent_peers,
            discovery: DiscoveryConfig::default(),
            idle_connection_timeout: Duration::from_secs(15 * 60),
            transport: TransportProtocol::Tcp,
            gossipsub: GossipSubConfig::default(),
            pubsub_protocol: PubSubProtocol::default(),
            rpc_max_size: 10 * 1024 * 1024,    // 10 MiB
            pubsub_max_size: 10 * 1024 * 1024, // 10 MiB
            enable_sync: true,
        };

        // Spawn Consensus actors
        let network = spawn_network(consensus_keypair, network_config, metrics.clone())
            .await
            .with_context(|| {
                format!(
                    "Failed to start consensus network on {}. \
                     Port {} may already be in use. \
                     Check with: lsof -i :{}",
                    listen_addr,
                    self.config.consensus_listen.port(),
                    self.config.consensus_listen.port()
                )
            })?;

        let wal_path = self.config.data_dir.join("wal");
        let wal = spawn_wal(&ctx, wal_path, metrics.clone()).await?;

        let host = spawn_host(self.validator_id, ctx.clone(), cut_rx, Some(decided_tx)).await?;

        // Build and spawn Consensus engine
        let _engine_handles = MalachiteEngineBuilder::new(
            ctx.clone(),
            params,
            consensus_config,
            Box::new(signing_provider),
            network,
            host,
            wal,
        )
        .spawn()
        .await?;

        info!("Consensus engine started");
        info!("Node started, entering main loop");

        // Clone execution bridge for use in event loop
        let execution_bridge = self.execution_bridge.clone();

        // Run the main event loop with graceful shutdown support
        let result = Self::run_event_loop(
            cancel_token,
            &mut primary_incoming_rx,
            &mut primary_handle,
            &cut_tx,
            &mut decided_rx,
            execution_bridge,
        )
        .await;

        // Graceful shutdown sequence
        info!("Shutting down node components...");

        // Step 1: Signal Primary to stop (it will stop accepting new batches)
        info!("Stopping Primary...");
        primary_handle.shutdown().await;

        // Step 2: Wait for supervisor to complete all tracked tasks
        info!("Waiting for supervised tasks to complete...");
        if let Err(e) = supervisor.shutdown().await {
            warn!("Some tasks did not complete cleanly: {}", e);
        }

        info!("Node shutdown complete");
        result
    }

    /// Internal event loop that handles messages and can be cancelled.
    async fn run_event_loop(
        cancel_token: CancellationToken,
        primary_incoming_rx: &mut mpsc::Receiver<(ValidatorId, DclMessage)>,
        primary_handle: &mut cipherbft_data_chain::primary::PrimaryHandle,
        cut_tx: &mpsc::Sender<Cut>,
        decided_rx: &mut mpsc::Receiver<(ConsensusHeight, Cut)>,
        execution_bridge: Option<Arc<ExecutionBridge>>,
    ) -> Result<()> {
        loop {
            tokio::select! {
                biased;

                // Check for shutdown signal first (high priority)
                _ = cancel_token.cancelled() => {
                    info!("Received shutdown signal, exiting event loop");
                    return Ok(());
                }

                // Incoming network messages -> forward to Primary
                Some((from, msg)) = primary_incoming_rx.recv() => {
                    debug!("Received message from {:?}: {:?}", from, msg.type_name());
                    if let Err(e) = primary_handle.send_from_peer(from, msg).await {
                        warn!("Failed to forward message to Primary: {:?}", e);
                    }
                }

                // Primary events
                Some(event) = primary_handle.recv_event() => {
                    match event {
                        PrimaryEvent::CutReady(cut) => {
                            info!(
                                "Cut ready at height {} with {} validators",
                                cut.height,
                                cut.validator_count()
                            );
                            // Send Cut to Consensus Host for ordering
                            // Consensus will decide on the cut and send it back via decided_rx
                            if let Err(e) = cut_tx.send(cut.clone()).await {
                                warn!("Failed to send Cut to Consensus Host: {}", e);
                            }
                        }
                        PrimaryEvent::CarCreated(car) => {
                            debug!(
                                "Car created at position {} with {} batches",
                                car.position,
                                car.batch_digests.len()
                            );
                        }
                        PrimaryEvent::AttestationGenerated { car_proposer, .. } => {
                            debug!("Generated attestation for Car from {:?}", car_proposer);
                        }
                        PrimaryEvent::SyncBatches { digests, target } => {
                            debug!(
                                "Need to sync {} batches from {:?}",
                                digests.len(),
                                target
                            );
                        }
                    }
                }

                // Consensus Decided events - execute the decided Cut
                Some((height, cut)) = decided_rx.recv() => {
                    info!(
                        "Consensus decided at height {} with {} cars",
                        height,
                        cut.cars.len()
                    );

                    // Execute Cut if execution layer is enabled
                    if let Some(ref bridge) = execution_bridge {
                        match bridge.execute_cut(cut).await {
                            Ok(result) => {
                                info!(
                                    "Cut executed successfully - state_root: {}, gas_used: {}",
                                    result.state_root,
                                    result.gas_used
                                );
                            }
                            Err(e) => {
                                error!("Cut execution failed: {}", e);
                            }
                        }
                    }
                }
            }
        }
    }

    /// Get the validator ID
    pub fn validator_id(&self) -> ValidatorId {
        self.validator_id
    }
}

/// Adapter to make TcpPrimaryNetwork work with PrimaryNetwork trait
struct TcpPrimaryNetworkAdapter {
    network: Arc<TcpPrimaryNetwork>,
}

#[async_trait::async_trait]
impl cipherbft_data_chain::primary::PrimaryNetwork for TcpPrimaryNetworkAdapter {
    async fn broadcast_car(&self, car: &cipherbft_data_chain::Car) {
        self.network.broadcast_car(car).await;
    }

    async fn send_attestation(
        &self,
        proposer: ValidatorId,
        attestation: &cipherbft_data_chain::Attestation,
    ) {
        self.network.send_attestation(proposer, attestation).await;
    }

    async fn broadcast(&self, message: &DclMessage) {
        self.network.broadcast(message).await;
    }

    async fn send_to(&self, peer: ValidatorId, message: &DclMessage) {
        self.network.send_to(peer, message).await;
    }
}
